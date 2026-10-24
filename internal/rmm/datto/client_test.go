package datto_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/rmm/datto"
	"defendsec/internal/rmm/dattotest"
)

// clock is a fake time source: Sleep advances it and records the pauses.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newClock() *clock { return &clock{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}
func (c *clock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}
func (c *clock) total() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	var t time.Duration
	for _, d := range c.sleeps {
		t += d
	}
	return t
}

func newClient(t *testing.T, srv *dattotest.Server, clk *clock, mod func(*datto.Config)) *datto.Client {
	t.Helper()
	cfg := datto.Config{APIURL: srv.URL, Key: dattotest.Key, Secret: dattotest.Secret, UnsafeAllowAnyURL: true,
		Now: clk.Now, Sleep: clk.Sleep, RequestsPerSecond: 1000}
	if mod != nil {
		mod(&cfg)
	}
	c, err := datto.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestValidateAPIURL(t *testing.T) {
	for _, ok := range []string{"https://pinotage-api.centrastage.net", "https://merlot-api.centrastage.net/", " https://Concord-API.centrastage.net "} {
		if _, err := datto.ValidateAPIURL(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "http://pinotage-api.centrastage.net", "https://pinotage.centrastage.net", "https://evil.example.com",
		"https://pinotage-api.centrastage.net.evil.example.com", "https://user:pw@pinotage-api.centrastage.net",
		"https://pinotage-api.centrastage.net:8443", "https://pinotage-api.centrastage.net/api", "https://pinotage-api.centrastage.net/?x=1",
		"https://evil.example.com/pinotage-api.centrastage.net", "https://pinotage-api.centrastage.net@evil.example.com",
	} {
		if _, err := datto.ValidateAPIURL(bad); err == nil {
			t.Errorf("%q accepted: the key and secret could be sent there", bad)
		}
	}
	if _, err := datto.New(datto.Config{APIURL: "https://evil.example.com", Key: "k", Secret: "s"}); err == nil {
		t.Error("New accepted a non-Datto host")
	}
	if _, err := datto.New(datto.Config{APIURL: "https://pinotage-api.centrastage.net", Key: "k"}); err == nil {
		t.Error("New accepted a missing secret")
	}
}

func TestTokenFlowAndCaching(t *testing.T) {
	srv := dattotest.New(t)
	clk := newClock()
	c := newClient(t, srv, clk, nil)
	if _, err := c.Sites(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Devices(context.Background(), dattotest.Site1); err != nil {
		t.Fatal(err)
	}
	if n := srv.TokenCalls(); n != 1 {
		t.Fatalf("token requested %d times for two reads; it lasts 100 hours", n)
	}
	// The token is refreshed before it runs out (expires_in is 360000 s in the fixture).
	clk.mu.Lock()
	clk.now = clk.now.Add(360000*time.Second - 2*time.Minute)
	clk.mu.Unlock()
	if _, err := c.Sites(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := srv.TokenCalls(); n != 2 {
		t.Fatalf("token requested %d times; want a refresh within 5 minutes of expiry", n)
	}
	for _, r := range srv.Requests() {
		if strings.Contains(r.Path, "/api/") && r.Auth != "Bearer "+dattotest.FixtureToken {
			t.Errorf("API request without the bearer token: %+v", r)
		}
	}
}

func TestWrongCredentialsAreNotAssessedAndNeverEchoed(t *testing.T) {
	srv := dattotest.New(t)
	c, err := datto.New(datto.Config{APIURL: srv.URL, Key: "wrong-key-xyz", Secret: "wrong-secret-xyz", UnsafeAllowAnyURL: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Sites(context.Background())
	if datto.KindOf(err) != datto.KindAuth {
		t.Fatalf("err = %v, want an auth failure", err)
	}
	for _, s := range []string{err.Error(), datto.Reason(err)} {
		if strings.Contains(s, "wrong-key-xyz") || strings.Contains(s, "wrong-secret-xyz") {
			t.Errorf("credential in message %q", s)
		}
	}
	if !strings.Contains(datto.Reason(err), "refused the API key and secret") {
		t.Errorf("reason = %q", datto.Reason(err))
	}
}

func TestSitesPaginateAndNeverReadProxyPassword(t *testing.T) {
	srv := dattotest.New(t)
	c := newClient(t, srv, newClock(), nil)
	sites, err := c.Sites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 3 || sites[0].Name != "Demo Client One" || sites[0].Devices != 3 || sites[2].UID != "aaaaaaaa-0000-4000-8000-000000000003" {
		t.Fatalf("sites = %+v", sites)
	}
	raw, _ := json.Marshal(sites)
	if strings.Contains(string(raw), "SHOULD-NEVER-BE-READ") || strings.Contains(string(raw), "proxy") {
		t.Errorf("proxy settings reached the decoded site: %s", raw)
	}
	// The page size comes from the server's own pagination setting.
	found := false
	for _, r := range srv.Requests() {
		if r.Path == "/api/v2/account/sites" && r.Query.Get("max") == "2" {
			found = true
		}
	}
	if !found {
		t.Errorf("first page not requested with max=2: %+v", srv.Requests())
	}
}

func TestDevicesPaginateAndTimestamps(t *testing.T) {
	srv := dattotest.New(t)
	c := newClient(t, srv, newClock(), nil)
	devs, err := c.Devices(context.Background(), dattotest.Site1)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 3 {
		t.Fatalf("devices = %d, want 3 across two pages", len(devs))
	}
	w := devs[0]
	if w.UID != dattotest.Win10 || w.Hostname != "DEMO-PC-01" || w.OperatingSystem != "Microsoft Windows 10 Pro" ||
		w.DeviceClass != "device" || w.DeviceType != "Laptop" || !w.Online ||
		w.PatchStatus != "ApprovedPending" || w.PatchesApprovedPending != 2 || w.PatchesNotApproved != 1 || w.PatchesInstalled != 412 ||
		w.AntivirusProduct != "Windows Defender" || w.AntivirusStatus != "RunningAndUpToDate" {
		t.Errorf("windows 10 device = %+v", w)
	}
	if !w.LastAuditDate.Equal(time.UnixMilli(1792800000000)) || !w.LastSeen.Equal(time.UnixMilli(1792824000000)) {
		t.Errorf("timestamps: audit %v seen %v", w.LastAuditDate, w.LastSeen)
	}
	// lastSeen as a numeric string still parses; null is the zero time.
	if !devs[1].LastSeen.Equal(time.UnixMilli(1792824000000)) {
		t.Errorf("string timestamp = %v", devs[1].LastSeen)
	}
	if p := devs[2]; p.DeviceClass != "printer" || !p.LastSeen.IsZero() || !p.LastAuditDate.IsZero() || p.PatchStatus != "" {
		t.Errorf("printer = %+v", p)
	}
	// What the device record carries that we do not keep stays out of the type.
	raw, _ := json.Marshal(devs)
	for _, leak := range []string{"demo.user", "192.0.2.11", "198.51.100.7"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("%q reached the decoded device", leak)
		}
	}
}

func TestAuditSoftwarePatches(t *testing.T) {
	srv := dattotest.New(t)
	c := newClient(t, srv, newClock(), nil)
	ctx := context.Background()
	a, err := c.Audit(ctx, dattotest.Win10)
	if err != nil {
		t.Fatal(err)
	}
	if a.OSName != "Microsoft Windows 10 Pro" || a.OSVersion != "10.0.19045" || a.OSDisplay != "22H2" || a.OSInstallType != "Client" ||
		a.BIOSSerial != "DEMOSERIAL001" || a.Manufacturer != "Demo Computers" || a.Model != "DemoBook 14" {
		t.Errorf("audit = %+v", a)
	}
	raw, _ := json.Marshal(a)
	for _, leak := range []string{"00:00:5E", "192.0.2.11", "demo.user"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("%q reached the audit", leak)
		}
	}
	sw, err := c.Software(ctx, dattotest.Win10)
	if err != nil {
		t.Fatal(err)
	}
	if len(sw) != 3 || sw[0].Name != "Demo Browser" || sw[2].Version != "7.1" {
		t.Errorf("software = %+v", sw)
	}
	pend, err := c.Patches(ctx, dattotest.Win10, datto.ApprovedPending)
	if err != nil {
		t.Fatal(err)
	}
	if len(pend) != 2 || pend[0].KBArticleID != "KB5000001" || pend[0].Severity != "CRITICAL" || pend[0].InstallStatus != datto.ApprovedPending ||
		pend[1].KBArticleID != "" || !pend[0].ReleaseDate.Equal(time.UnixMilli(1789000000000)) {
		t.Errorf("approved pending = %+v", pend)
	}
	na, err := c.Patches(ctx, dattotest.Win10, datto.NotApproved)
	if err != nil {
		t.Fatal(err)
	}
	if len(na) != 1 || na[0].KBArticleID != "5000002" || na[0].ReleaseDate.UTC().Format("2006-01-02") != "2099-01-14" {
		t.Errorf("not approved = %+v", na)
	}
	inst, err := c.Patches(ctx, dattotest.Win10, datto.Installed)
	if err != nil || len(inst) != 1 || inst[0].KBArticleID != "KB4999999" {
		t.Errorf("installed = %+v %v", inst, err)
	}
	rs, err := c.RateStatus(ctx)
	if err != nil || rs.Limit != 600 || rs.Count != 12 {
		t.Errorf("rate = %+v %v", rs, err)
	}
	for _, r := range srv.Requests() {
		if r.Path == "/api/v2/device/"+dattotest.Win10+"/patches" && r.Query.Get("installStatus") == "" {
			t.Errorf("patches requested without an install status: %+v", r)
		}
	}
}

func TestBadUIDsNeverReachAURL(t *testing.T) {
	srv := dattotest.New(t)
	c := newClient(t, srv, newClock(), nil)
	for _, uid := range []string{"", "a", "../v2/account", "x/y", "x?y=1", "a b c d", strings.Repeat("a", 65)} {
		if _, err := c.Devices(context.Background(), uid); err == nil {
			t.Errorf("Devices accepted uid %q", uid)
		}
		if _, err := c.Audit(context.Background(), uid); err == nil {
			t.Errorf("Audit accepted uid %q", uid)
		}
		if _, err := c.Patches(context.Background(), uid, datto.Installed); err == nil {
			t.Errorf("Patches accepted uid %q", uid)
		}
	}
	if _, err := c.Patches(context.Background(), dattotest.Win10, datto.InstallStatus("x&y")); err == nil {
		t.Error("Patches accepted a bad install status")
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests made for invalid input", n)
	}
}

func TestExpiredTokenIsRefreshedOnce(t *testing.T) {
	srv := dattotest.New(t)
	clk := newClock()
	c := newClient(t, srv, clk, nil)
	if _, err := c.Sites(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The server forgets the token (a 401), once.
	srv.Force("/api/v2/site/", http.StatusUnauthorized, 0, 1, "")
	if _, err := c.Devices(context.Background(), dattotest.Site1); err != nil {
		t.Fatalf("a single 401 must be answered by getting a new token: %v", err)
	}
	if n := srv.TokenCalls(); n != 2 {
		t.Errorf("token calls = %d, want 2", n)
	}
	// A second 401 in a row is a refusal, not a loop.
	srv2 := dattotest.New(t)
	srv2.Force("*", http.StatusUnauthorized, 0, 0, "")
	c2 := newClient(t, srv2, newClock(), nil)
	_, err := c2.Sites(context.Background())
	if datto.KindOf(err) != datto.KindAuth {
		t.Fatalf("err = %v", err)
	}
	if n := srv2.TokenCalls(); n != 2 {
		t.Errorf("token calls = %d; want one retry and then stop", n)
	}
}

func TestForbiddenIsNotRetried(t *testing.T) {
	srv := dattotest.New(t)
	srv.Force("/api/v2/account/sites", http.StatusForbidden, 0, 0, "")
	c := newClient(t, srv, newClock(), nil)
	_, err := c.Sites(context.Background())
	if datto.KindOf(err) != datto.KindForbidden {
		t.Fatalf("err = %v", err)
	}
	if n := srv.Count("/api/v2/account/sites"); n != 1 {
		t.Errorf("a 403 was asked %d times; persisting after one earns an IP block", n)
	}
	if !strings.Contains(datto.Reason(err), "Sites > Sites: View") {
		t.Errorf("reason = %q", datto.Reason(err))
	}
}

func TestRateLimitWaitsThenRetries(t *testing.T) {
	srv := dattotest.New(t)
	srv.Force("/api/v2/account/sites", http.StatusTooManyRequests, 0, 1, "")
	clk := newClock()
	c := newClient(t, srv, clk, nil)
	if _, err := c.Sites(context.Background()); err != nil {
		t.Fatalf("one 429 should be waited out: %v", err)
	}
	if clk.total() < 60*time.Second {
		t.Errorf("waited %v after a 429; Datto says 60 s", clk.total())
	}
}

func TestRateLimitHonoursRetryAfterAndGivesUp(t *testing.T) {
	srv := dattotest.New(t)
	srv.Force("/api/v2/account/sites", http.StatusTooManyRequests, 0, 0, "120")
	clk := newClock()
	c := newClient(t, srv, clk, nil)
	_, err := c.Sites(context.Background())
	if datto.KindOf(err) != datto.KindRateLimited {
		t.Fatalf("err = %v", err)
	}
	if n := srv.Count("/api/v2/account/sites"); n != 3 {
		t.Errorf("asked %d times, want the first plus two retries", n)
	}
	if clk.total() < 240*time.Second {
		t.Errorf("waited %v; two waits of the Retry-After 120 s expected", clk.total())
	}
}

func TestServerErrorsRetryThenFail(t *testing.T) {
	srv := dattotest.New(t)
	srv.Force("/api/v2/account/sites", http.StatusBadGateway, 0, 1, "")
	clk := newClock()
	c := newClient(t, srv, clk, nil)
	if _, err := c.Sites(context.Background()); err != nil {
		t.Fatalf("one 502 should be retried: %v", err)
	}
	srv2 := dattotest.New(t)
	srv2.Force("/api/v2/account/sites", http.StatusInternalServerError, 0, 0, "")
	c2 := newClient(t, srv2, newClock(), nil)
	_, err := c2.Sites(context.Background())
	if datto.KindOf(err) != datto.KindServer {
		t.Fatalf("err = %v", err)
	}
	if n := srv2.Count("/api/v2/account/sites"); n != 3 {
		t.Errorf("asked %d times, want 3", n)
	}
}

func TestNotFoundAndGarbage(t *testing.T) {
	srv := dattotest.New(t)
	c := newClient(t, srv, newClock(), nil)
	_, err := c.Audit(context.Background(), dattotest.Server2019) // the fixture has no audit for it
	if datto.KindOf(err) != datto.KindNotFound {
		t.Fatalf("err = %v", err)
	}
	srv.Override["/api/v2/account/sites"] = `<html>not json</html>`
	_, err = c.Sites(context.Background())
	if datto.KindOf(err) != datto.KindProtocol {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "<html>") {
		t.Errorf("response body echoed: %v", err)
	}
}

// A response must not be able to steer the bearer token to another host.
func TestNextPageOnAnotherHostIsNotFollowed(t *testing.T) {
	var hits int
	var auth string
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		auth = r.Header.Get("Authorization")
		w.Write([]byte(`{"sites":[],"pageDetails":{"nextPageUrl":null}}`)) //nolint:errcheck
	}))
	defer evil.Close()
	srv := dattotest.New(t)
	srv.Override["/api/v2/account/sites"] = `{"pageDetails":{"nextPageUrl":"` + evil.URL + `/api/v2/account/sites?page=1"},"sites":[]}`
	c := newClient(t, srv, newClock(), nil)
	_, err := c.Sites(context.Background())
	if datto.KindOf(err) != datto.KindProtocol {
		t.Fatalf("err = %v", err)
	}
	if hits != 0 || auth != "" {
		t.Fatalf("the other host got %d requests, Authorization %q", hits, auth)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var gotAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte(`{}`)) //nolint:errcheck
	}))
	defer target.Close()
	srv := dattotest.New(t)
	srv.Override["/api/v2/account/sites"] = "" // replaced below by a raw redirecting front
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/oauth/token" {
			w.Write([]byte(`{"access_token":"t","expires_in":3600}`)) //nolint:errcheck
			return
		}
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer front.Close()
	c, err := datto.New(datto.Config{APIURL: front.URL, Key: "k", Secret: "s", UnsafeAllowAnyURL: true, RequestsPerSecond: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sites(context.Background()); err == nil {
		t.Fatal("a redirect was treated as success")
	}
	if gotAuth != "" {
		t.Fatalf("the bearer token followed a redirect: %q", gotAuth)
	}
}

func TestPacingSpacesRequests(t *testing.T) {
	srv := dattotest.New(t)
	clk := newClock()
	c := newClient(t, srv, clk, func(cfg *datto.Config) { cfg.RequestsPerSecond = 2 })
	for i := 0; i < 4; i++ {
		if _, err := c.Audit(context.Background(), dattotest.Win10); err != nil {
			t.Fatal(err)
		}
	}
	// Token + 4 audits = 5 requests at 2 per second: at least 4 gaps of 500 ms.
	if clk.total() < 2*time.Second {
		t.Errorf("paused only %v for 5 requests at 2 per second", clk.total())
	}
	if c.Requests() != 5 {
		t.Errorf("Requests() = %d, want 5", c.Requests())
	}
}

func TestCancelledContextStopsTheRead(t *testing.T) {
	srv := dattotest.New(t)
	c := newClient(t, srv, newClock(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.Sites(ctx)
	if err == nil || datto.KindOf(err) != datto.KindNetwork {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err does not wrap context.Canceled: %v", err)
	}
}

// The client reads. A test (and the fake server, which fails on any non-GET)
// keeps it that way: the only POST in the package is the token request.
func TestClientHasNoWriteCalls(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v %v", files, err)
	}
	write := regexp.MustCompile(`http\.Method(Post|Put|Delete|Patch)|"(POST|PUT|DELETE|PATCH)"`)
	forbidden := regexp.MustCompile(`(?i)quickjob|/job/|/component|resetApiKeys|/variable|/udf|/warranty|/site/\{?[a-z]*\}?/?settings|/mute|/resolve|/move`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, line := range strings.Split(src, "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") {
				continue
			}
			if write.MatchString(line) && !strings.Contains(line, "http.MethodPost, c.base.String()+tokenPath") {
				t.Errorf("%s: a write method outside the token request: %s", f, trim)
			}
			if forbidden.MatchString(line) {
				t.Errorf("%s: references a write or job endpoint: %s", f, trim)
			}
		}
	}
}
