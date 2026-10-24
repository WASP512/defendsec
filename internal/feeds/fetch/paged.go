package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Pager describes an API that serves one logical feed as numbered pages, as
// Rocky's Apollo errata service does. FetchPaged walks every page and stores
// the records as a single cached file, so the rest of the pipeline (parse,
// export, import, snapshot digest) treats it like any other bulk download.
//
// This is still a bulk download: the requests carry a page number and a fixed
// release filter, never a package name or anything else about the fleet.
type Pager struct {
	// URL returns the URL of page n; n starts at 0.
	URL func(n int) string
	// Records splits a page body into its records and the total number of
	// records the server says exist (0 if it does not say).
	Records func(body []byte) (records []json.RawMessage, total int, err error)
	// Key names a record. It orders the stored file, and drops a record that
	// shows up on two pages because the data moved while the walk ran.
	Key func(rec json.RawMessage) (string, error)
	// Normalize, if set, turns a record into the form that is stored: only the
	// fields the parser reads, with lists in a fixed order. APIs backed by an
	// unordered query return the members of a list in a different order from one
	// request to the next; without this the digest of an unchanged feed would
	// change on every walk, and every sync would reload it and mint a snapshot.
	// It runs before Key, so a record the server sends twice collapses.
	Normalize func(rec json.RawMessage) (json.RawMessage, error)
	// Wrap is the top-level key of the stored file: {"<Wrap>":[records...]}.
	Wrap string
	// MaxPages bounds the walk (default 2000), so a server that never returns
	// an empty page cannot loop forever.
	MaxPages int
}

const (
	pageAttempts = 3
	maxPageBytes = 64 << 20
)

// pageBackoff is the pause before retry n of a page (n times this). A variable
// so the tests need not wait.
var pageBackoff = 2 * time.Second

// FetchPaged downloads every page, de-duplicates by Key, sorts by Key and
// writes {"<Wrap>":[...]} to the cache. The stored bytes depend only on the
// records, not on how they were paged, so an unchanged upstream yields an
// unchanged digest. It refuses a walk that receives fewer records than the
// first page promised: a short list would read as "the vendor has shipped fewer
// fixes". A record the server itself sends twice counts toward that total but
// is stored once.
func (f *Fetcher) FetchPaged(ctx context.Context, name, baseURL string, p Pager) (Result, error) {
	if !ValidName(name) {
		return Result{}, fmt.Errorf("invalid feed name %q", name)
	}
	if err := CheckURL(baseURL); err != nil {
		return Result{}, err
	}
	if p.URL == nil || p.Records == nil || p.Key == nil || p.Wrap == "" {
		return Result{}, errors.New("fetch: incomplete Pager")
	}
	maxPages := p.MaxPages
	if maxPages <= 0 {
		maxPages = 2000
	}
	max := f.MaxBytes
	if max <= 0 {
		max = defaultMaxBytes
	}

	byKey := map[string]json.RawMessage{}
	var promised, received int
	var bytesRead int64
	for n := 0; ; n++ {
		if n >= maxPages {
			return Result{}, fmt.Errorf("fetch %s: still receiving records after %d pages; giving up", name, maxPages)
		}
		pageURL := p.URL(n)
		if err := CheckURL(pageURL); err != nil {
			return Result{}, err
		}
		body, err := f.getPage(ctx, name, pageURL)
		if err != nil {
			return Result{}, err
		}
		bytesRead += int64(len(body))
		if bytesRead > max {
			return Result{}, fmt.Errorf("fetch %s: more than the %d byte limit", name, max)
		}
		recs, total, err := p.Records(body)
		if err != nil {
			return Result{}, fmt.Errorf("fetch %s: page %d: %w", name, n, err)
		}
		if n == 0 {
			promised = total
		}
		if len(recs) == 0 {
			break
		}
		received += len(recs)
		for _, rec := range recs {
			if p.Normalize != nil {
				if rec, err = p.Normalize(rec); err != nil {
					return Result{}, fmt.Errorf("fetch %s: page %d: %w", name, n, err)
				}
			}
			k, err := p.Key(rec)
			if err != nil {
				return Result{}, fmt.Errorf("fetch %s: page %d: %w", name, n, err)
			}
			if _, dup := byKey[k]; !dup {
				byKey[k] = rec
			}
		}
	}
	if len(byKey) == 0 {
		return Result{}, fmt.Errorf("fetch %s: no records", name)
	}
	// The server's total counts what it sends, repeats included: Apollo reports
	// ten more advisories than it has distinct names, because it lists ten of
	// them twice. So compare what was received, not what survived de-duplication.
	if promised > 0 && received < promised {
		return Result{}, fmt.Errorf("fetch %s: received %d records but the server reported %d; the walk was cut short", name, received, promised)
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.WriteString(`{"` + p.Wrap + `":[`)
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := json.Compact(&buf, byKey[k]); err != nil {
			return Result{}, fmt.Errorf("fetch %s: record %s: %w", name, k, err)
		}
	}
	buf.WriteString("]}\n")

	return f.StoreNormalised(name, baseURL, buf.Bytes())
}

// GetBody downloads one document of a multi-document feed (one request, retried
// like a page), refusing anything but https or a loopback mirror.
func (f *Fetcher) GetBody(ctx context.Context, name, docURL string) ([]byte, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("invalid feed name %q", name)
	}
	if err := CheckURL(docURL); err != nil {
		return nil, err
	}
	return f.getPage(ctx, name, docURL)
}

// StoreNormalised writes data as the feed's cached file and records its digest,
// for a feed the caller assembled itself from several downloads. The stored
// bytes must depend only on the records, not on how they were fetched, so an
// unchanged upstream yields an unchanged digest.
func (f *Fetcher) StoreNormalised(name, baseURL string, data []byte) (Result, error) {
	if !ValidName(name) {
		return Result{}, fmt.Errorf("invalid feed name %q", name)
	}
	prev, cached, err := f.Cache.LoadMeta(name)
	if err != nil {
		return Result{}, err
	}
	dir := filepath.Join(f.Cache.Dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, err
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	part := f.Cache.Path(name) + ".part"
	if err := os.WriteFile(part, data, 0o600); err != nil {
		return Result{}, err
	}
	if err := os.Rename(part, f.Cache.Path(name)); err != nil {
		os.Remove(part)
		return Result{}, err
	}
	m := Meta{URL: baseURL, SHA256: digest, Size: int64(len(data)), FetchedAt: f.now()}
	if err := f.Cache.SaveMeta(name, m); err != nil {
		return Result{}, err
	}
	return Result{Meta: m, Path: f.Cache.Path(name), Changed: !cached || prev.SHA256 != digest}, nil
}

// getPage fetches one page, retrying a few times on a network error or a 5xx:
// a walk of a hundred pages should not fail on one slow response.
func (f *Fetcher) getPage(ctx context.Context, name, pageURL string) ([]byte, error) {
	agent := f.Agent
	if agent == "" {
		agent = "defendsec-feeds"
	}
	var lastErr error
	for attempt := 0; attempt < pageAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * pageBackoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", agent)
		req.Header.Set("Accept", "application/json")
		resp, err := f.client().Do(req)
		if err != nil {
			lastErr = fmt.Errorf("fetch %s: %w", name, scrub(err))
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes+1))
		resp.Body.Close()
		switch {
		case rerr != nil:
			lastErr = fmt.Errorf("fetch %s: page interrupted: %w", name, scrub(rerr))
		case resp.StatusCode >= 500:
			lastErr = fmt.Errorf("fetch %s: HTTP %d", name, resp.StatusCode)
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("fetch %s: HTTP %d", name, resp.StatusCode)
		case len(body) > maxPageBytes:
			return nil, fmt.Errorf("fetch %s: a single page exceeds %d bytes", name, maxPageBytes)
		default:
			return body, nil
		}
	}
	return nil, lastErr
}
