// Package fetch downloads feed files into an on-disk cache with conditional
// requests (ETag / Last-Modified) and records each file's SHA-256.
//
// Bulk downloads only: it fetches whole published files by fixed URL. It never
// sends anything about the fleet — no package names, no hostnames — because the
// URLs are fixed per feed and carry no query.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Meta is what the cache remembers about one feed file.
type Meta struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	SHA256       string    `json:"sha256"`
	Size         int64     `json:"size"`
	FetchedAt    time.Time `json:"fetched_at"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidName reports whether name is usable as a feed (and cache directory) name.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Cache is a directory holding <name>/data and <name>/meta.json per feed.
type Cache struct{ Dir string }

// Path returns where a feed's file lives.
func (c Cache) Path(name string) string { return filepath.Join(c.Dir, name, "data") }

func (c Cache) metaPath(name string) string { return filepath.Join(c.Dir, name, "meta.json") }

// LoadMeta returns the stored metadata; ok is false if the feed is not cached
// (no meta, or meta without its data file).
func (c Cache) LoadMeta(name string) (Meta, bool, error) {
	if !ValidName(name) {
		return Meta{}, false, fmt.Errorf("invalid feed name %q", name)
	}
	raw, err := os.ReadFile(c.metaPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return Meta{}, false, nil
	}
	if err != nil {
		return Meta{}, false, err
	}
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return Meta{}, false, fmt.Errorf("cache meta for %s: %w", name, err)
	}
	if _, err := os.Stat(c.Path(name)); err != nil {
		return Meta{}, false, nil
	}
	return m, true, nil
}

// SaveMeta writes metadata atomically.
func (c Cache) SaveMeta(name string, m Meta) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid feed name %q", name)
	}
	if err := os.MkdirAll(filepath.Join(c.Dir, name), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(c.metaPath(name), raw)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Install places an already-verified file into the cache as feed name,
// replacing any previous copy. data is moved (renamed) when on the same
// filesystem, otherwise copied.
func (c Cache) Install(name, dataPath string, m Meta) error {
	if !ValidName(name) {
		return fmt.Errorf("invalid feed name %q", name)
	}
	dir := filepath.Join(c.Dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := c.Path(name)
	if err := os.Rename(dataPath, dst); err != nil {
		in, oerr := os.Open(dataPath)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		tmp := dst + ".part"
		out, cerr := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if cerr != nil {
			return cerr
		}
		if _, cerr = io.Copy(out, in); cerr != nil {
			out.Close()
			os.Remove(tmp)
			return cerr
		}
		if cerr = out.Close(); cerr != nil {
			os.Remove(tmp)
			return cerr
		}
		if cerr = os.Rename(tmp, dst); cerr != nil {
			return cerr
		}
	}
	return c.SaveMeta(name, m)
}

// Result describes one Fetch.
type Result struct {
	Meta
	Path string
	// Changed is true when the file's content differs from what was cached
	// (or nothing was cached). A 304, or a 200 with an identical digest, is
	// not a change.
	Changed bool
	// NotModified is true when the server answered 304.
	NotModified bool
}

// Fetcher downloads feeds into Cache.
type Fetcher struct {
	Client   *http.Client // nil = a default client
	Cache    Cache
	MaxBytes int64            // per file; 0 = 4 GiB
	Now      func() time.Time // nil = time.Now
	Agent    string
}

const defaultMaxBytes = 4 << 30

// CheckURL accepts https URLs, and http only for loopback hosts (tests and
// local mirrors). Anything else is refused: a feed fetched over plain HTTP can
// be rewritten in transit.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("feed url: %w", err)
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("feed url %q: needs a host and no credentials", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("feed url %q: must be https (http only for loopback)", raw)
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return CheckURL(req.URL.String())
		},
	}
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now().UTC()
	}
	return time.Now().UTC()
}

// Fetch brings feed name up to date from rawURL. If the cache holds a copy for
// the same URL with a validator, the request is conditional. The file is
// written to a temporary name and renamed into place only after the whole body
// arrived and matched Content-Length, so an interrupted download never replaces
// a good copy.
func (f *Fetcher) Fetch(ctx context.Context, name, rawURL string) (Result, error) {
	if !ValidName(name) {
		return Result{}, fmt.Errorf("invalid feed name %q", name)
	}
	if err := CheckURL(rawURL); err != nil {
		return Result{}, err
	}
	prev, cached, err := f.Cache.LoadMeta(name)
	if err != nil {
		return Result{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, err
	}
	agent := f.Agent
	if agent == "" {
		agent = "defendsec-feeds"
	}
	req.Header.Set("User-Agent", agent)
	if cached && prev.URL == rawURL {
		if prev.ETag != "" {
			req.Header.Set("If-None-Match", prev.ETag)
		}
		if prev.LastModified != "" {
			req.Header.Set("If-Modified-Since", prev.LastModified)
		}
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("fetch %s: %w", name, scrub(err))
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		if !cached {
			return Result{}, fmt.Errorf("fetch %s: server sent 304 but nothing is cached", name)
		}
		prev.FetchedAt = f.now()
		if err := f.Cache.SaveMeta(name, prev); err != nil {
			return Result{}, err
		}
		return Result{Meta: prev, Path: f.Cache.Path(name), NotModified: true}, nil
	case http.StatusOK:
	default:
		return Result{}, fmt.Errorf("fetch %s: HTTP %d", name, resp.StatusCode)
	}

	max := f.MaxBytes
	if max <= 0 {
		max = defaultMaxBytes
	}
	if resp.ContentLength > max {
		return Result{}, fmt.Errorf("fetch %s: %d bytes exceeds the %d byte limit", name, resp.ContentLength, max)
	}
	dir := filepath.Join(f.Cache.Dir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Result{}, err
	}
	part := f.Cache.Path(name) + ".part"
	out, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{}, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, max+1))
	closeErr := out.Close()
	switch {
	case copyErr != nil:
		os.Remove(part)
		return Result{}, fmt.Errorf("fetch %s: download interrupted after %d bytes: %w", name, n, scrub(copyErr))
	case closeErr != nil:
		os.Remove(part)
		return Result{}, closeErr
	case n > max:
		os.Remove(part)
		return Result{}, fmt.Errorf("fetch %s: body exceeds the %d byte limit", name, max)
	case resp.ContentLength >= 0 && n != resp.ContentLength:
		os.Remove(part)
		return Result{}, fmt.Errorf("fetch %s: got %d bytes, Content-Length said %d", name, n, resp.ContentLength)
	case n == 0:
		os.Remove(part)
		return Result{}, fmt.Errorf("fetch %s: empty body", name)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if err := os.Rename(part, f.Cache.Path(name)); err != nil {
		os.Remove(part)
		return Result{}, err
	}
	m := Meta{
		URL: rawURL, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"),
		SHA256: sum, Size: n, FetchedAt: f.now(),
	}
	if err := f.Cache.SaveMeta(name, m); err != nil {
		return Result{}, err
	}
	return Result{Meta: m, Path: f.Cache.Path(name), Changed: !cached || prev.SHA256 != sum}, nil
}

// scrub strips the URL from net/url errors so a feed URL with an embedded
// token (a private mirror) is not echoed into logs.
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// FileSHA256 hashes a file on disk.
func FileSHA256(path string) (string, int64, error) {
	in, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer in.Close()
	h := sha256.New()
	n, err := io.Copy(h, in)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// RedactURL drops the query and fragment from a feed URL. A private mirror may
// carry an access token there; the URL that is stored, logged, exported in a
// bundle manifest or shown by the admin API is the redacted one.
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String()
}

// Stash keeps the current cached copy of a feed (data and metadata) aside so it
// can be put back if the replacement turns out to be unusable. It is a no-op
// when nothing is cached. The data file is hard-linked, not copied, so a stash
// of an 80 MB feed costs nothing; if linking is not possible it copies.
func (c Cache) Stash(name string) error {
	if _, ok, err := c.LoadMeta(name); err != nil || !ok {
		return err
	}
	data, prev := c.Path(name), c.Path(name)+".prev"
	os.Remove(prev)
	if err := os.Link(data, prev); err != nil {
		in, oerr := os.Open(data)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		out, cerr := os.OpenFile(prev, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if cerr != nil {
			return cerr
		}
		if _, cerr = io.Copy(out, in); cerr != nil {
			out.Close()
			return cerr
		}
		if cerr = out.Close(); cerr != nil {
			return cerr
		}
	}
	raw, err := os.ReadFile(c.metaPath(name))
	if err != nil {
		return err
	}
	return writeAtomic(c.metaPath(name)+".prev", raw)
}

// Restore puts the stashed copy back as the cached copy, discarding whatever
// replaced it. It is a no-op when there is no stash.
func (c Cache) Restore(name string) error {
	prev := c.Path(name) + ".prev"
	if _, err := os.Stat(prev); err != nil {
		return nil
	}
	if err := os.Rename(prev, c.Path(name)); err != nil {
		return err
	}
	if err := os.Rename(c.metaPath(name)+".prev", c.metaPath(name)); err != nil {
		return err
	}
	return nil
}

// Discard drops the stash once the new copy has been accepted.
func (c Cache) Discard(name string) {
	os.Remove(c.Path(name) + ".prev")
	os.Remove(c.metaPath(name) + ".prev")
}
