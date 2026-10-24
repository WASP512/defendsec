package fetch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// pagedServer serves records named r00..rNN, `size` per page, as
// {"items":[{"name":...}],"total":N}.
type pagedServer struct {
	*httptest.Server
	hits    atomic.Int32
	failing atomic.Int32 // number of upcoming requests to answer 503
	records []string
	// shift, when set, makes every page after the first start one record
	// earlier, as if a record had been added at the front mid-walk.
	shift bool
}

func newPagedServer(t *testing.T, n int) *pagedServer {
	pageBackoff = 0
	t.Cleanup(func() { pageBackoff = 2 * time.Second })
	s := &pagedServer{}
	for i := 0; i < n; i++ {
		s.records = append(s.records, fmt.Sprintf("r%02d", i))
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if s.failing.Load() > 0 {
			s.failing.Add(-1)
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		size, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		start := page * size
		if s.shift && page > 0 {
			start--
		}
		type item struct {
			Name string `json:"name"`
			Pad  string `json:"pad"`
		}
		var items []item
		for i := start; i < start+size && i < len(s.records); i++ {
			items = append(items, item{Name: s.records[i], Pad: "x"})
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "total": len(s.records)})
	}))
	t.Cleanup(s.Close)
	return s
}

func pagerFor(s *pagedServer, size int) Pager {
	return Pager{
		URL: func(n int) string { return fmt.Sprintf("%s/api?page=%d&limit=%d", s.URL, n, size) },
		Records: func(body []byte) ([]json.RawMessage, int, error) {
			var d struct {
				Items []json.RawMessage `json:"items"`
				Total int               `json:"total"`
			}
			if err := json.Unmarshal(body, &d); err != nil {
				return nil, 0, err
			}
			return d.Items, d.Total, nil
		},
		Key: func(rec json.RawMessage) (string, error) {
			var r struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(rec, &r); err != nil || r.Name == "" {
				return "", fmt.Errorf("record without name")
			}
			return r.Name, nil
		},
		Wrap: "items",
	}
}

func TestFetchPagedAssemblesOneSortedFile(t *testing.T) {
	s := newPagedServer(t, 23)
	f := fetcher(t)
	res, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", pagerFor(s, 10))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || res.NotModified {
		t.Errorf("first fetch: changed=%v notModified=%v", res.Changed, res.NotModified)
	}
	raw, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []struct{ Name string } `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("stored file is not JSON: %v", err)
	}
	if len(doc.Items) != 23 || doc.Items[0].Name != "r00" || doc.Items[22].Name != "r22" {
		t.Fatalf("stored %d items, first %v last %v", len(doc.Items), doc.Items[0], doc.Items[len(doc.Items)-1])
	}
	if hits := s.hits.Load(); hits != 4 { // 3 pages of data plus the empty page that ends the walk
		t.Errorf("requests = %d, want 4", hits)
	}
	meta, ok, _ := f.Cache.LoadMeta("paged")
	if !ok || meta.SHA256 != res.SHA256 || meta.URL != s.URL+"/api" || meta.Size != int64(len(raw)) {
		t.Errorf("meta = %+v ok=%v", meta, ok)
	}

	// Same upstream data, different page size: identical bytes, so the digest
	// (and the feed's "unchanged" decision) does not depend on paging.
	again, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", pagerFor(s, 7))
	if err != nil {
		t.Fatal(err)
	}
	if again.SHA256 != res.SHA256 || again.Changed {
		t.Errorf("same records re-paged: sha %s vs %s, changed=%v", again.SHA256, res.SHA256, again.Changed)
	}
}

// What is stored is the normalized record: the same bytes however the server
// ordered or padded the original.
func TestFetchPagedNormalizesBeforeHashing(t *testing.T) {
	s := newPagedServer(t, 6)
	f := fetcher(t)
	p := pagerFor(s, 10)
	p.Normalize = func(rec json.RawMessage) (json.RawMessage, error) {
		var r struct{ Name, Pad string }
		if err := json.Unmarshal(rec, &r); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]string{"name": r.Name}) // the stored form drops the padding
	}
	a, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(a.Path)
	if strings.Contains(string(raw), "pad") || a.SHA256 != b.SHA256 || b.Changed {
		t.Errorf("normalized file %s; digests %s / %s", raw, a.SHA256, b.SHA256)
	}
	p.Normalize = func(json.RawMessage) (json.RawMessage, error) { return nil, fmt.Errorf("bad record") }
	if _, err := f.FetchPaged(context.Background(), "paged2", s.URL+"/api", p); err == nil {
		t.Error("a normalize error was swallowed")
	}
}

func TestFetchPagedDeduplicatesShiftedPages(t *testing.T) {
	s := newPagedServer(t, 25)
	s.shift = true
	f := fetcher(t)
	res, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", pagerFor(s, 10))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(res.Path)
	if n := strings.Count(string(raw), `"name"`); n != 25 {
		t.Errorf("stored %d records, want 25 with the overlap dropped", n)
	}
}

func TestFetchPagedRetriesTransientFailures(t *testing.T) {
	s := newPagedServer(t, 5)
	s.failing.Store(2)
	f := fetcher(t)
	if _, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", pagerFor(s, 10)); err != nil {
		t.Fatalf("two 503s then success should work: %v", err)
	}
	s.failing.Store(100)
	if _, err := f.FetchPaged(context.Background(), "paged2", s.URL+"/api", pagerFor(s, 10)); err == nil {
		t.Fatal("a server that only answers 503 should fail")
	}
}

func TestFetchPagedRefusesShortWalk(t *testing.T) {
	s := newPagedServer(t, 12)
	p := pagerFor(s, 10)
	inner := p.Records
	p.Records = func(body []byte) ([]json.RawMessage, int, error) {
		recs, _, err := inner(body)
		return recs, 40, err // the server claims more records than it ever returns
	}
	f := fetcher(t)
	if _, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", p); err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Fatalf("err = %v, want a refusal for the short walk", err)
	}
	if _, ok, _ := f.Cache.LoadMeta("paged"); ok {
		t.Error("a refused walk left a cached copy")
	}
}

// Apollo's total counts ten advisories twice (the same name and content under
// two ids). Those must not read as a short walk.
func TestFetchPagedAcceptsRecordsTheServerRepeats(t *testing.T) {
	s := newPagedServer(t, 12)
	s.records = append(s.records, s.records[3], s.records[7]) // 14 sent, 12 distinct
	f := fetcher(t)
	res, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", pagerFor(s, 10))
	if err != nil {
		t.Fatalf("server-side repeats were treated as a short walk: %v", err)
	}
	raw, _ := os.ReadFile(res.Path)
	if n := strings.Count(string(raw), `"name"`); n != 12 {
		t.Errorf("stored %d records, want the 12 distinct ones", n)
	}
}

func TestFetchPagedRefusesEmptyAndBadURLs(t *testing.T) {
	s := newPagedServer(t, 0)
	f := fetcher(t)
	if _, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", pagerFor(s, 10)); err == nil {
		t.Error("an empty feed was accepted")
	}
	if _, err := f.FetchPaged(context.Background(), "paged", "http://example.com/api", pagerFor(s, 10)); err == nil {
		t.Error("plain http to a non-loopback host was accepted")
	}
	if _, err := f.FetchPaged(context.Background(), "Bad Name", s.URL+"/api", pagerFor(s, 10)); err == nil {
		t.Error("an invalid feed name was accepted")
	}
}

func TestFetchPagedStopsAtMaxPages(t *testing.T) {
	s := newPagedServer(t, 100)
	p := pagerFor(s, 1)
	p.MaxPages = 5
	f := fetcher(t)
	if _, err := f.FetchPaged(context.Background(), "paged", s.URL+"/api", p); err == nil || !strings.Contains(err.Error(), "giving up") {
		t.Fatalf("err = %v, want the page cap to stop the walk", err)
	}
}
