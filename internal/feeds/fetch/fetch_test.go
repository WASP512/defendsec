package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type server struct {
	*httptest.Server
	hits        atomic.Int32
	conditional atomic.Int32
	body        atomic.Value // string
	etag        atomic.Value
}

func newServer(t *testing.T, body string) *server {
	s := &server{}
	s.body.Store(body)
	s.etag.Store(`"v1"`)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if r.Header.Get("If-None-Match") != "" {
			s.conditional.Add(1)
		}
		etag := s.etag.Load().(string)
		switch r.URL.Path {
		case "/feed":
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", "Fri, 23 Oct 2026 19:30:18 GMT")
			w.Write([]byte(s.body.Load().(string)))
		case "/redirect":
			http.Redirect(w, r, "/feed", http.StatusFound)
		case "/boom":
			http.Error(w, "nope", http.StatusInternalServerError)
		case "/empty":
		case "/short":
			w.Header().Set("Content-Length", "100")
			w.Write([]byte("only a few bytes"))
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func fetcher(t *testing.T) *Fetcher {
	return &Fetcher{Cache: Cache{Dir: t.TempDir()}, Now: func() time.Time { return time.Date(2026, 10, 23, 20, 0, 0, 0, time.UTC) }}
}

func TestFetchThenConditionalNotModified(t *testing.T) {
	s := newServer(t, "hello feed")
	f := fetcher(t)
	ctx := context.Background()

	r, err := f.Fetch(ctx, "kev", s.URL+"/feed")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Changed || r.NotModified || r.Size != 10 || r.ETag != `"v1"` || r.LastModified == "" || len(r.SHA256) != 64 {
		t.Fatalf("first fetch = %+v", r)
	}
	got, _ := os.ReadFile(r.Path)
	if string(got) != "hello feed" {
		t.Errorf("cached body = %q", got)
	}
	sum, n, err := FileSHA256(r.Path)
	if err != nil || sum != r.SHA256 || n != 10 {
		t.Errorf("FileSHA256 = %s %d %v, meta says %s", sum, n, err, r.SHA256)
	}

	// Second fetch is conditional and the server says 304: cache stays, time moves.
	f.Now = func() time.Time { return time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC) }
	r2, err := f.Fetch(ctx, "kev", s.URL+"/feed")
	if err != nil {
		t.Fatal(err)
	}
	if !r2.NotModified || r2.Changed || r2.SHA256 != r.SHA256 || s.conditional.Load() != 1 {
		t.Fatalf("second fetch = %+v conditional=%d", r2, s.conditional.Load())
	}
	m, ok, _ := f.Cache.LoadMeta("kev")
	if !ok || !m.FetchedAt.Equal(time.Date(2026, 10, 24, 20, 0, 0, 0, time.UTC)) {
		t.Errorf("fetched_at not refreshed by a 304: %+v", m)
	}

	// Content changes upstream: new etag, new digest, Changed.
	s.body.Store("hello again")
	s.etag.Store(`"v2"`)
	r3, err := f.Fetch(ctx, "kev", s.URL+"/feed")
	if err != nil || !r3.Changed || r3.SHA256 == r.SHA256 || r3.ETag != `"v2"` {
		t.Fatalf("third fetch = %+v err=%v", r3, err)
	}
}

func TestSameBytesNewEtagIsNotAChange(t *testing.T) {
	s := newServer(t, "same")
	f := fetcher(t)
	ctx := context.Background()
	if _, err := f.Fetch(ctx, "x", s.URL+"/feed"); err != nil {
		t.Fatal(err)
	}
	s.etag.Store(`"v2"`)
	r, err := f.Fetch(ctx, "x", s.URL+"/feed")
	if err != nil || r.Changed || r.NotModified {
		t.Fatalf("result = %+v err=%v, want 200 with identical digest = not changed", r, err)
	}
}

func TestChangedURLIgnoresOldValidators(t *testing.T) {
	s := newServer(t, "body")
	f := fetcher(t)
	ctx := context.Background()
	if _, err := f.Fetch(ctx, "x", s.URL+"/feed"); err != nil {
		t.Fatal(err)
	}
	before := s.conditional.Load()
	if _, err := f.Fetch(ctx, "x", s.URL+"/redirect"); err != nil { // a different URL for the same name
		t.Fatal(err)
	}
	if s.conditional.Load() != before {
		t.Error("validators from a different URL were sent")
	}
}

func TestFailuresLeaveTheGoodCopy(t *testing.T) {
	s := newServer(t, "good copy")
	f := fetcher(t)
	ctx := context.Background()
	r, err := f.Fetch(ctx, "x", s.URL+"/feed")
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{"/boom": "HTTP 500", "/empty": "empty body", "/short": "interrupted", "/missing": "empty body"} {
		_, err := f.Fetch(ctx, "x", s.URL+path) // /missing: the handler writes nothing, an empty 200
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", path, err, want)
		}
	}
	got, _ := os.ReadFile(r.Path)
	if string(got) != "good copy" {
		t.Errorf("a failed fetch replaced the cached file: %q", got)
	}
	if _, err := os.Stat(r.Path + ".part"); err == nil {
		t.Error("partial file left behind")
	}
	if m, ok, _ := f.Cache.LoadMeta("x"); !ok || m.SHA256 != r.SHA256 {
		t.Errorf("meta changed by a failed fetch: %+v", m)
	}
}

func TestSizeLimit(t *testing.T) {
	s := newServer(t, strings.Repeat("a", 1000))
	f := fetcher(t)
	f.MaxBytes = 100
	if _, err := f.Fetch(context.Background(), "x", s.URL+"/feed"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	s := newServer(t, "x")
	f := fetcher(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Fetch(ctx, "x", s.URL+"/feed"); err == nil {
		t.Fatal("cancelled context fetched anyway")
	}
}

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"https://example.org/f.json", "http://127.0.0.1:8080/f", "http://localhost/f", "http://[::1]:9/f"} {
		if err := CheckURL(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.org/f", "ftp://example.org/f", "file:///etc/passwd", "https://user:pw@example.org/f", "https://", "", "//example.org/f", "http://10.0.0.5/f"} {
		if err := CheckURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"kev", "ubuntu-jammy", "suse-leap-16.0", "osv-pypi"} {
		if !ValidName(ok) {
			t.Errorf("%s rejected", ok)
		}
	}
	for _, bad := range []string{"", "../x", "a/b", "A", ".hidden", "-x", strings.Repeat("a", 65), "a b"} {
		if ValidName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	f := fetcher(t)
	if _, err := f.Fetch(context.Background(), "../escape", "https://example.org/x"); err == nil {
		t.Error("path-traversal name accepted")
	}
}

func TestInstall(t *testing.T) {
	c := Cache{Dir: t.TempDir()}
	src := t.TempDir() + "/in"
	os.WriteFile(src, []byte("imported"), 0o600)
	m := Meta{URL: "https://example.org/x", SHA256: strings.Repeat("a", 64), Size: 8, FetchedAt: time.Now().UTC()}
	if err := c.Install("kev", src, m); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(c.Path("kev"))
	if string(got) != "imported" {
		t.Errorf("installed body = %q", got)
	}
	if lm, ok, err := c.LoadMeta("kev"); err != nil || !ok || lm.SHA256 != m.SHA256 {
		t.Errorf("meta = %+v ok=%v err=%v", lm, ok, err)
	}
	if err := c.Install("../bad", src, m); err == nil {
		t.Error("bad name accepted")
	}
}

func TestRedactURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://mirror.example/feeds/kev.json?token=s3cret#frag": "https://mirror.example/feeds/kev.json",
		"https://u:p@mirror.example/x":                            "https://mirror.example/x",
		"https://www.cisa.gov/a/b.json":                           "https://www.cisa.gov/a/b.json",
		"::bad":                                                   "",
	} {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}
