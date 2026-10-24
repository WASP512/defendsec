package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/rmm"
	"defendsec/internal/rmm/datto"
	"defendsec/internal/rmm/dattotest"
	"defendsec/internal/storepg"
)

// rmmScratchServer is an apid with its own throwaway database (the RMM counts
// span the whole database) and a Datto client aimed at the fake API.
func rmmScratchServer(t *testing.T) (*Server, *storepg.Store, *pgxpool.Pool, *dattotest.Server) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck
	name := "defendsec_mig_rmmapi_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cfg := admin.Config().Copy()
	cfg.ConnConfig.Database = name
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") //nolint:errcheck
		admin.Close()
	})
	st := storepg.New(pool)
	s := &Server{adminToken: "admin-token", viewerToken: "viewer-token", log: slog.New(slog.DiscardHandler)}
	s.SetPostgres(st)

	srv := dattotest.New(t)
	now := time.UnixMilli(1792824000000 + 3600*1000).UTC()
	s.SetRMMClient(func() (rmmClient, error) {
		return datto.New(datto.Config{APIURL: srv.URL, Key: dattotest.Key, Secret: dattotest.Secret, UnsafeAllowAnyURL: true,
			RequestsPerSecond: 1000, Now: func() time.Time { return now }, Sleep: func(context.Context, time.Duration) error { return nil }})
	})
	// One Microsoft advisory, so a missing KB maps to a CVE.
	if err := st.UpsertAdvisoryWithRanges(ctx, storepg.Advisory{ID: "CVE-2099-0001", CVE: "CVE-2099-0001", Summary: "Windows kernel EoP", Severity: "high",
		Ranges: []storepg.AdvisoryRange{{Ecosystem: "MSRC", Distro: "windows", Package: "KB5000001", Fixed: "KB5000001", FixState: storepg.FixStateFixed}}}); err != nil {
		t.Fatal(err)
	}
	return s, st, pool, srv
}

func TestRMMAPIAuth(t *testing.T) {
	s := testServer() // no Postgres
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/v1/rmm/status", "", 401},
		{"GET", "/v1/rmm/status", "nope", 401},
		{"GET", "/v1/rmm/status", "viewer-token", 503},
		{"GET", "/v1/rmm/sites", "viewer-token", 403},
		{"GET", "/v1/rmm/sites", "admin-token", 503},
		{"PUT", "/v1/rmm/settings", "viewer-token", 403},
		{"POST", "/v1/rmm/settings", "admin-token", 405},
		{"POST", "/v1/rmm/sync", "viewer-token", 403},
		{"GET", "/v1/rmm/sync", "admin-token", 405},
		{"POST", "/v1/rmm/status", "admin-token", 405},
		{"GET", "/v1/rmm/devices", "", 401},
		{"GET", "/v1/rmm/devices/rmm-abcd", "viewer-token", 503},
		{"GET", "/v1/rmm/nothing", "admin-token", 404},
	} {
		rec := surfReq(t, s.HandleRMM, tc.method, tc.path, tc.token, nil)
		if rec.Code != tc.want {
			t.Errorf("%s %s token=%q: %d, want %d (%s)", tc.method, tc.path, tc.token, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func TestRMMAPIEndToEnd(t *testing.T) {
	s, _, pool, srv := rmmScratchServer(t)
	h := s.HandleRMM

	// Nothing selected yet.
	rec := surfReq(t, h, "GET", "/v1/rmm/status", "viewer-token", nil)
	if rec.Code != 200 {
		t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
	}
	status := decode[struct {
		Summary     storepg.RMMSummary  `json:"summary"`
		Credentials rmmCredentials      `json:"credentials"`
		NotAssessed []map[string]string `json:"notAssessed"`
		Running     bool                `json:"running"`
	}](t, rec)
	if status.Summary.Settings.Configured || status.Summary.Devices != 0 || !status.Credentials.Configured {
		t.Errorf("status = %+v", status)
	}
	if len(status.NotAssessed) != 2 || !strings.Contains(status.NotAssessed[0]["what"], "Third-party") {
		t.Errorf("the status must say what is not assessed: %+v", status.NotAssessed)
	}
	// A sync with no site is a 400, not a guess.
	if rec := surfReq(t, h, "POST", "/v1/rmm/sync", "admin-token", map[string]any{"wait": true}); rec.Code != 400 {
		t.Errorf("sync without a site = %d", rec.Code)
	}

	// Sites come from the live list; a viewer cannot ask for them.
	if rec := surfReq(t, h, "GET", "/v1/rmm/sites", "viewer-token", nil); rec.Code != 403 {
		t.Errorf("viewer sites = %d", rec.Code)
	}
	rec = surfReq(t, h, "GET", "/v1/rmm/sites", "admin-token", nil)
	if rec.Code != 200 {
		t.Fatalf("sites = %d %s", rec.Code, rec.Body.String())
	}
	sites := decode[struct {
		Sites []datto.Site `json:"sites"`
	}](t, rec)
	if len(sites.Sites) != 3 || sites.Sites[0].Name != "Demo Client One" {
		t.Errorf("sites = %+v", sites)
	}
	if strings.Contains(rec.Body.String(), "SHOULD-NEVER-BE-READ") {
		t.Error("a proxy password reached the API response")
	}

	// Settings: strict, validated against the live list.
	for name, c := range map[string]struct {
		body any
		want int
	}{
		"unknown field":    {map[string]any{"siteUid": dattotest.Site1, "apiKey": "x"}, 400},
		"no site":          {map[string]any{}, 400},
		"site not in RMM":  {map[string]any{"siteUid": "ffffffff-0000-4000-8000-00000000ffff"}, 400},
		"stale days = 0":   {map[string]any{"siteUid": dattotest.Site1, "staleAfterDays": 0}, 400},
		"stale days = 400": {map[string]any{"siteUid": dattotest.Site1, "staleAfterDays": 400}, 400},
	} {
		if rec := surfReq(t, h, "PUT", "/v1/rmm/settings", "admin-token", c.body); rec.Code != c.want {
			t.Errorf("%s: %d, want %d (%s)", name, rec.Code, c.want, rec.Body.String())
		}
	}
	if rec := surfReq(t, h, "PUT", "/v1/rmm/settings", "viewer-token", map[string]any{"siteUid": dattotest.Site1}); rec.Code != 403 {
		t.Errorf("viewer settings = %d", rec.Code)
	}
	rec = surfReq(t, h, "PUT", "/v1/rmm/settings", "admin-token", map[string]any{"siteUid": dattotest.Site1, "staleAfterDays": 5})
	if rec.Code != 200 {
		t.Fatalf("settings = %d %s", rec.Code, rec.Body.String())
	}
	got := decode[storepg.RMMSettings](t, rec)
	if !got.Configured || got.SiteUID != dattotest.Site1 || got.SiteName != "Demo Client One" || got.StaleAfterDays != 5 || got.SelectedBy == "" {
		t.Errorf("settings = %+v", got)
	}

	// A read, waited for.
	rec = surfReq(t, h, "POST", "/v1/rmm/sync", "admin-token", map[string]any{"wait": true})
	if rec.Code != 200 {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body.String())
	}
	res := decode[storepg.RMMSync](t, rec)
	if res.Status != "ok" || res.Windows != 2 || res.Stale != 1 || !strings.HasPrefix(res.TriggeredBy, "manual:") {
		t.Errorf("sync = %+v", res)
	}
	// Asking for a read is in the ledger with the account that asked; the site choice
	// is written once, by the store, in the settings transaction (checked below).
	{
		rows, err := s.pg.ListAudit(context.Background(), 200)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, r := range rows {
			if a, _ := r["action"].(string); a == "rmm_site_select" || a == "rmm_site_selected" || a == "rmm_sync" {
				seen[a] = true
			}
		}
		if seen["rmm_site_select"] || !seen["rmm_site_selected"] || !seen["rmm_sync"] {
			t.Errorf("ledger actions = %v, want rmm_site_selected (once, from the store) and rmm_sync, and no rmm_site_select", seen)
		}
	}
	// The same read is refused while another runs.
	if !s.claimRMM() {
		t.Fatal("could not claim")
	}
	if rec := surfReq(t, h, "POST", "/v1/rmm/sync", "admin-token", map[string]any{"wait": true}); rec.Code != 409 {
		t.Errorf("concurrent sync = %d", rec.Code)
	}
	s.releaseRMM()

	// Devices, one device, history.
	rec = surfReq(t, h, "GET", "/v1/rmm/devices", "viewer-token", nil)
	devs := decode[struct {
		Devices []storepg.RMMDeviceRow `json:"devices"`
	}](t, rec)
	if rec.Code != 200 || len(devs.Devices) != 2 {
		t.Fatalf("devices = %d %s", rec.Code, rec.Body.String())
	}
	var win storepg.RMMDeviceRow
	for _, d := range devs.Devices {
		if d.Hostname == "DEMO-PC-01" {
			win = d
		}
	}
	if win.Coverage != "covered" || win.FindingsOpen != 1 || win.OSVersion != "10.0.19045" {
		t.Errorf("windows 10 row = %+v", win)
	}
	rec = surfReq(t, h, "GET", "/v1/rmm/devices/"+win.ID, "viewer-token", nil)
	if rec.Code != 200 {
		t.Fatalf("device = %d %s", rec.Code, rec.Body.String())
	}
	d := decode[storepg.RMMDeviceDetail](t, rec)
	if d.Serial != "DEMOSERIAL001" || len(d.Patches) != 3 || len(d.Software) != 3 || !d.Patches[0].Mapped || d.Patches[0].KB != "KB5000001" || d.Patches[0].CVEs != 1 {
		t.Errorf("detail = %+v", d)
	}
	if rec := surfReq(t, h, "GET", "/v1/rmm/devices/../../etc", "viewer-token", nil); rec.Code != 400 && rec.Code != 404 {
		t.Errorf("path trick = %d", rec.Code)
	}
	if rec := surfReq(t, h, "GET", "/v1/rmm/devices/not-an-id", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("bad id = %d", rec.Code)
	}
	if rec := surfReq(t, h, "GET", "/v1/rmm/devices/rmm-ffffffff", "viewer-token", nil); rec.Code != 404 {
		t.Errorf("unknown id = %d", rec.Code)
	}
	rec = surfReq(t, h, "GET", "/v1/rmm/syncs?limit=5", "viewer-token", nil)
	hist := decode[struct {
		Syncs []storepg.RMMSync `json:"syncs"`
	}](t, rec)
	if rec.Code != 200 || len(hist.Syncs) != 1 || hist.Syncs[0].ID != res.ID {
		t.Errorf("history = %d %s", rec.Code, rec.Body.String())
	}
	if rec := surfReq(t, h, "GET", "/v1/rmm/syncs?limit=0", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("limit 0 = %d", rec.Code)
	}

	// Status now carries the counts and the last read.
	rec = surfReq(t, h, "GET", "/v1/rmm/status", "viewer-token", nil)
	status2 := decode[struct {
		Summary storepg.RMMSummary `json:"summary"`
	}](t, rec)
	if status2.Summary.Devices != 2 || status2.Summary.Covered != 1 || status2.Summary.Stale != 1 || status2.Summary.FindingsOpen != 1 ||
		status2.Summary.LastSync == nil || !status2.Summary.FeedLoaded || status2.Summary.MissingKBs != 2 || status2.Summary.MissingKBsMapped != 1 {
		t.Errorf("summary = %+v", status2.Summary)
	}

	// The ledger holds the selection and the read, with the acting account on the first.
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action IN ('rmm_site_selected','rmm_sync_recorded')`).Scan(&n); err != nil || n != 2 {
		t.Errorf("ledger entries = %d %v", n, err)
	}
	// Only GETs reached Datto: the fake fails the test on anything else.
	for _, r := range srv.Requests() {
		if r.Method != http.MethodGet && !strings.HasSuffix(r.Path, "/auth/oauth/token") {
			t.Errorf("non-GET to Datto: %s %s", r.Method, r.Path)
		}
	}
}

func TestRMMScheduleReadsWhenDueOnly(t *testing.T) {
	s, st, _, _ := rmmScratchServer(t)
	ctx := context.Background()
	if s.rmmScheduleOnce(ctx) {
		t.Fatal("the schedule read with no site selected")
	}
	if err := st.SetRMMSettings(ctx, "admin", dattotest.Site1, "Demo Client One", 7); err != nil {
		t.Fatal(err)
	}
	if !s.rmmScheduleOnce(ctx) {
		t.Fatal("a due read did not run")
	}
	if s.rmmScheduleOnce(ctx) {
		t.Error("a second read ran straight after the first")
	}
	s.rmmr.interval = time.Nanosecond // pretend 6 hours passed
	time.Sleep(5 * time.Millisecond)
	if !s.rmmScheduleOnce(ctx) {
		t.Error("an overdue read did not run")
	}
	// A different site is due at once.
	s.rmmr.interval = time.Hour
	if err := st.SetRMMSettings(ctx, "admin", dattotest.Site2, "Demo Client Two", 7); err != nil {
		t.Fatal(err)
	}
	if !s.rmmScheduleOnce(ctx) {
		t.Error("a newly selected site was not read at once")
	}
	// While one read runs, the schedule does not start another.
	if !s.claimRMM() {
		t.Fatal("claim")
	}
	s.rmmr.interval = time.Nanosecond
	time.Sleep(5 * time.Millisecond)
	if s.rmmScheduleOnce(ctx) {
		t.Error("the schedule ran over a read in progress")
	}
	s.releaseRMM()
}

func TestRMMCredentialsFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	good := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
		return p
	}
	t.Setenv("DEFENDSEC_RMM_API_URL", "")
	t.Setenv("DEFENDSEC_RMM_KEY_FILE", "")
	t.Setenv("DEFENDSEC_RMM_SECRET_FILE", "")
	if c, cr, err := rmmClientFromEnv(); err == nil || c != nil || cr.Configured || !strings.Contains(cr.Problem, "not configured") {
		t.Errorf("empty env: %v %+v", err, cr)
	}
	t.Setenv("DEFENDSEC_RMM_API_URL", "https://evil.example.com")
	t.Setenv("DEFENDSEC_RMM_KEY_FILE", good("key", "KEYVALUE12345", 0o600))
	t.Setenv("DEFENDSEC_RMM_SECRET_FILE", good("sec", "SECRETVALUE9876", 0o640))
	if _, cr, err := rmmClientFromEnv(); err == nil || !strings.Contains(cr.Problem, "DEFENDSEC_RMM_API_URL") {
		t.Errorf("a non-Datto host was accepted: %v %+v", err, cr)
	}
	t.Setenv("DEFENDSEC_RMM_API_URL", "https://pinotage-api.centrastage.net")
	c, cr, err := rmmClientFromEnv()
	if err != nil || c == nil || !cr.Configured || cr.APIURL != "https://pinotage-api.centrastage.net" {
		t.Fatalf("good env: %v %+v", err, cr)
	}
	if len(cr.Warnings) != 1 || !strings.Contains(cr.Warnings[0], "sec") {
		t.Errorf("warnings = %v (the group-readable secret file should be named)", cr.Warnings)
	}
	for _, v := range []string{"KEYVALUE12345", "SECRETVALUE9876"} {
		if strings.Contains(cr.Problem, v) || strings.Contains(strings.Join(cr.Warnings, " "), v) {
			t.Errorf("credential value %q in the status text", v)
		}
	}
	t.Setenv("DEFENDSEC_RMM_SECRET_FILE", filepath.Join(dir, "missing"))
	if _, cr, err := rmmClientFromEnv(); err == nil || !strings.Contains(cr.Problem, "DEFENDSEC_RMM_SECRET_FILE") {
		t.Errorf("a missing secret file: %v %+v", err, cr)
	}
	t.Setenv("DEFENDSEC_RMM_SECRET_FILE", good("sec2", "SECRETVALUE9876", 0o666))
	if _, cr, err := rmmClientFromEnv(); err == nil || strings.Contains(cr.Problem, "SECRETVALUE9876") {
		t.Errorf("a world-writable secret file was accepted or echoed: %v %+v", err, cr)
	}
}

var _ = httptest.NewRecorder
var _ rmm.Source
