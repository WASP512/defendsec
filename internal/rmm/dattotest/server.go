// Package dattotest is a fake Datto RMM API for tests, serving scrubbed
// fixtures (fake UIDs, hostnames and addresses) shaped like the vendor's
// documented responses. It records every request so a test can prove the client
// only ever reads.
package dattotest

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

//go:embed fixtures/*.json
var fixtures embed.FS

// Fixture UIDs.
const (
	Key, Secret = "demo-api-key", "demo-api-secret"
	Site1       = "aaaaaaaa-0000-4000-8000-000000000001"
	Site2       = "aaaaaaaa-0000-4000-8000-000000000002"
	Win10       = "dddddddd-0000-4000-8000-000000000001"
	Server2019  = "dddddddd-0000-4000-8000-000000000002"
	Printer     = "dddddddd-0000-4000-8000-000000000003"
	// FixtureToken is what the token endpoint hands out. It is not a secret.
	FixtureToken = "fixture-token-not-a-secret"
)

// Req is one request the server saw.
type Req struct {
	Method string
	Path   string
	Query  url.Values
	Auth   string
}

// Server is the fake API.
type Server struct {
	*httptest.Server
	t  *testing.T
	mu sync.Mutex

	reqs       []Req
	tokenCalls int
	// Override replaces a route's body. The key is "<path>" or, for patches,
	// "<path>?installStatus=X".
	Override map[string]string
	// Status makes a route (or "*" for every API route, not the token) answer
	// with a status: first the count of requests to let through.
	status map[string]*forced
	// RejectToken makes the token endpoint answer 400, as for a wrong pair.
	RejectToken bool
	// TokenStatus, if non-zero, is what the token endpoint answers instead.
	TokenStatus int
}

type forced struct {
	status int
	after  int // requests to let through before forcing
	times  int // how many to force (0 = forever)
	seen   int
	retry  string
}

// New starts the server; it closes with the test.
func New(t *testing.T) *Server {
	s := &Server{t: t, Override: map[string]string{}, status: map[string]*forced{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Force makes requests whose path contains substr (or every API request, for
// "*") answer status, after letting `after` through, `times` times (0 = always).
// retryAfter, if set, is sent as Retry-After.
func (s *Server) Force(substr string, status, after, times int, retryAfter string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status[substr] = &forced{status: status, after: after, times: times, retry: retryAfter}
}

// Requests returns the requests seen so far.
func (s *Server) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// TokenCalls is how many times the token endpoint was asked.
func (s *Server) TokenCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls
}

// Count counts API requests whose path contains substr.
func (s *Server) Count(substr string) int {
	n := 0
	for _, r := range s.Requests() {
		if strings.Contains(r.Path, substr) {
			n++
		}
	}
	return n
}

// Fixture returns a fixture's text with {{BASE}} replaced by the server URL.
func (s *Server) Fixture(name string) string {
	b, err := fixtures.ReadFile("fixtures/" + name)
	if err != nil {
		s.t.Fatalf("fixture %s: %v", name, err)
	}
	return strings.ReplaceAll(string(b), "{{BASE}}", s.URL)
}

var (
	reDevices   = regexp.MustCompile(`^/api/v2/site/([^/]+)/devices$`)
	reAudit     = regexp.MustCompile(`^/api/v2/audit/device/([^/]+)$`)
	reSoftware  = regexp.MustCompile(`^/api/v2/audit/device/([^/]+)/software$`)
	rePatches   = regexp.MustCompile(`^/api/v2/device/([^/]+)/patches$`)
	reRoutedGet = regexp.MustCompile(`^/api/v2/`)
)

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	rec := Req{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Auth: r.Header.Get("Authorization")}
	s.mu.Lock()
	s.reqs = append(s.reqs, rec)
	s.mu.Unlock()

	if r.URL.Path == "/auth/oauth/token" {
		s.token(w, r)
		return
	}
	if !reRoutedGet.MatchString(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		s.t.Errorf("a non-GET request reached the API: %s %s", r.Method, r.URL.Path)
		http.Error(w, "write refused", http.StatusMethodNotAllowed)
		return
	}
	if rec.Auth != "Bearer "+FixtureToken {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"status":401,"error":"Unauthorized"}`)
		return
	}
	if st, retry := s.forcedStatus(r.URL.Path); st != 0 {
		if retry != "" {
			w.Header().Set("Retry-After", retry)
		}
		w.WriteHeader(st)
		fmt.Fprintf(w, `{"status":%d}`, st)
		return
	}
	body, ok := s.route(r)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"status":404,"error":"Not Found"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, body) //nolint:errcheck
}

func (s *Server) forcedStatus(path string) (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, f := range s.status {
		if key != "*" && !strings.Contains(path, key) {
			continue
		}
		f.seen++
		if f.seen <= f.after {
			continue
		}
		if f.times > 0 && f.seen > f.after+f.times {
			continue
		}
		return f.status, f.retry
	}
	return 0, ""
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokenCalls++
	reject, status := s.RejectToken, s.TokenStatus
	s.mu.Unlock()
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	user, pass, ok := r.BasicAuth()
	if err := r.ParseForm(); err != nil || !ok || user != "public-client" || pass != "public" ||
		r.PostForm.Get("grant_type") != "password" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_request"}`)
		return
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if reject || r.PostForm.Get("username") != Key || r.PostForm.Get("password") != Secret {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
		return
	}
	io.WriteString(w, s.Fixture("token.json")) //nolint:errcheck
}

func (s *Server) override(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.Override[key]
	return strings.ReplaceAll(b, "{{BASE}}", s.URL), ok
}

func (s *Server) route(r *http.Request) (string, bool) {
	p, q := r.URL.Path, r.URL.Query()
	key := p
	if st := q.Get("installStatus"); st != "" {
		key = p + "?installStatus=" + st
	}
	page := q.Get("page")
	if page != "" {
		// A later page is served from "<key>&page=N" or the default fixtures,
		// never from the first page's override.
		if b, ok := s.override(key + "&page=" + page); ok {
			return b, true
		}
	} else if b, ok := s.override(key); ok {
		return b, true
	}
	switch {
	case p == "/api/v2/system/pagination":
		return s.Fixture("pagination.json"), true
	case p == "/api/v2/system/request_rate":
		return s.Fixture("rate.json"), true
	case p == "/api/v2/account/sites":
		if page == "1" {
			return s.Fixture("sites_page2.json"), true
		}
		return s.Fixture("sites.json"), true
	case reDevices.MatchString(p):
		if reDevices.FindStringSubmatch(p)[1] != Site1 {
			return `{"pageDetails":{"count":0,"totalCount":0,"prevPageUrl":null,"nextPageUrl":null},"devices":[]}`, true
		}
		if page == "1" {
			return s.Fixture("devices_page2.json"), true
		}
		return s.Fixture("devices_page1.json"), true
	case reSoftware.MatchString(p):
		if reSoftware.FindStringSubmatch(p)[1] != Win10 {
			return `{"pageDetails":{"count":0,"totalCount":0,"prevPageUrl":null,"nextPageUrl":null},"software":[]}`, true
		}
		if page == "1" {
			return s.Fixture("software_page2.json"), true
		}
		return s.Fixture("software_page1.json"), true
	case reAudit.MatchString(p):
		if reAudit.FindStringSubmatch(p)[1] != Win10 {
			return "", false
		}
		return s.Fixture("audit_win10.json"), true
	case rePatches.MatchString(p):
		empty := `{"pageDetails":{"count":0,"totalCount":0,"prevPageUrl":null,"nextPageUrl":null},"patches":[]}`
		if rePatches.FindStringSubmatch(p)[1] != Win10 {
			return empty, true
		}
		switch q.Get("installStatus") {
		case "APPROVED_PENDING":
			return s.Fixture("patches_approved_pending.json"), true
		case "NOT_APPROVED":
			return s.Fixture("patches_not_approved.json"), true
		case "INSTALLED":
			return s.Fixture("patches_installed.json"), true
		}
		return empty, true
	}
	return "", false
}

// JSON marshals v for an Override.
func JSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
