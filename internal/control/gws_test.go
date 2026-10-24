package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/internal/gws"
	"defendsec/internal/gws/google"
	"defendsec/internal/gws/gwstest"
	"defendsec/internal/storepg"
)

// gwsScratchServer is an apid with its own throwaway database and a Google Workspace
// source aimed at the fixture Google server.
func gwsScratchServer(t *testing.T) (*Server, *pgxpool.Pool, *gwstest.Server) {
	t.Helper()
	s, pool, _ := m365ScratchServer(t)
	srv := gwstest.New(t)
	s.SetGWSSource(func(set storepg.GWSSettings) (gws.Source, error) {
		cfg := srv.Config()
		cfg.AdminEmail = set.AdminEmail
		cfg.GmailScope = set.GmailScopeURL()
		cfg.Sleep = func(context.Context, time.Duration) error { return nil }
		c, err := google.New(cfg)
		if err != nil {
			return nil, err
		}
		return gws.NewGoogleSource(c), nil
	})
	return s, pool, srv
}

type gwsStatusT struct {
	Provider    string                          `json:"provider"`
	Settings    storepg.GWSSettings             `json:"settings"`
	Credentials gwsCredentials                  `json:"credentials"`
	Summary     storepg.IdentityExposureSummary `json:"summary"`
	LatestRun   *storepg.IdentityRun            `json:"latestRun"`
	NotAssessed []gws.NotAssessed               `json:"notAssessed"`
	Permissions []gws.Permission                `json:"permissions"`
	CheckLabels map[string]string               `json:"checkLabels"`
	CheckOrder  []string                        `json:"checkOrder"`
	ReadOnly    string                          `json:"readOnlyNote"`
	Running     bool                            `json:"running"`
}

type findingsT struct {
	Findings []storepg.IdentityFinding `json:"findings"`
}

func TestGWSAPIAuth(t *testing.T) {
	s := testServer() // no Postgres
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/v1/identity/google/status", "", 401},
		{"GET", "/v1/identity/google/status", "nope", 401},
		{"GET", "/v1/identity/google/status", "viewer-token", 503},
		{"PUT", "/v1/identity/google/settings", "viewer-token", 403},
		{"PUT", "/v1/identity/google/settings", "admin-token", 503},
		{"GET", "/v1/identity/google/settings", "admin-token", 405},
		{"POST", "/v1/identity/google/sync", "viewer-token", 403},
		{"POST", "/v1/identity/google/sync", "admin-token", 503},
		{"GET", "/v1/identity/google/sync", "admin-token", 405},
		{"POST", "/v1/identity/google/status", "admin-token", 405},
		{"GET", "/v1/identity/findings?provider=google", "", 401},
		{"GET", "/v1/identity/google/nothing", "admin-token", 404},
	} {
		rec := surfReq(t, s.HandleIdentity, tc.method, tc.path, tc.token, nil)
		if rec.Code != tc.want {
			t.Errorf("%s %s token=%q: %d, want %d (%s)", tc.method, tc.path, tc.token, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func TestGWSAPIEndToEnd(t *testing.T) {
	s, pool, srv := gwsScratchServer(t)
	h := s.HandleIdentity
	getStatus := func() gwsStatusT {
		rec := surfReq(t, h, "GET", "/v1/identity/google/status", "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		return decode[gwsStatusT](t, rec)
	}
	findings := func(q string) []storepg.IdentityFinding {
		rec := surfReq(t, h, "GET", "/v1/identity/findings"+q, "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("findings%s = %d %s", q, rec.Code, rec.Body.String())
		}
		return decode[findingsT](t, rec).Findings
	}

	// Nothing set: the status says what is missing and what is never seen.
	st := getStatus()
	if st.Provider != "google" || st.Settings.Configured || st.LatestRun != nil || st.Summary.Findings != 0 || st.Summary.Provider != "google" {
		t.Errorf("empty status = %+v", st)
	}
	if len(st.NotAssessed) < 5 || !strings.Contains(st.NotAssessed[0].What, "email routing") {
		t.Errorf("the status must say what is not assessed before any run: %+v", st.NotAssessed)
	}
	var scopes []string
	for _, p := range st.Permissions {
		scopes = append(scopes, p.Name)
		if !strings.HasSuffix(p.Name, ".readonly") && p.Name != "https://www.googleapis.com/auth/gmail.settings.basic" {
			t.Errorf("scope %q is not read-only and not the documented alternative", p.Name)
		}
		if p.Name == "https://www.googleapis.com/auth/gmail.settings.basic" && p.Required {
			t.Error("the alternative scope is marked required")
		}
	}
	if len(scopes) != 3 {
		t.Errorf("scopes = %v", scopes)
	}
	if st.CheckLabels["mfa"] != "2-Step Verification" || len(st.CheckOrder) != 3 || !strings.Contains(st.ReadOnly, "never reads a message") {
		t.Errorf("labels %v order %v note %q", st.CheckLabels, st.CheckOrder, st.ReadOnly)
	}

	// A sync with no administrator is a 400, not a guess.
	if rec := surfReq(t, h, "POST", "/v1/identity/google/sync", "admin-token", map[string]any{"wait": true}); rec.Code != 400 {
		t.Errorf("sync without an administrator = %d", rec.Code)
	}

	// Settings: validated, admin only, ledgered.
	put := func(token string, body map[string]any) int {
		return surfReq(t, h, "PUT", "/v1/identity/google/settings", token, body).Code
	}
	if c := put("viewer-token", map[string]any{"adminEmail": gwstest.AdminEmail}); c != 403 {
		t.Errorf("viewer PUT = %d", c)
	}
	for name, body := range map[string]map[string]any{
		"not an address":   {"adminEmail": "alex"},
		"unknown scope":    {"adminEmail": gwstest.AdminEmail, "gmailScope": "gmail.modify"},
		"limit 0":          {"adminEmail": gwstest.AdminEmail, "superAdminMax": 0},
		"unknown field":    {"adminEmail": gwstest.AdminEmail, "privateKey": "pasted"},
		"bad trusted":      {"adminEmail": gwstest.AdminEmail, "trustedDomains": []string{"not a domain"}},
		"a key in a field": {"adminEmail": gwstest.AdminEmail, "keyFile": "/tmp/key.json"},
	} {
		if c := put("admin-token", body); c != 400 {
			t.Errorf("%s: %d, want 400", name, c)
		}
	}
	if n := idnLedger(t, pool)["identity_settings_changed"]; n != 0 {
		t.Errorf("refused settings wrote %d ledger entries", n)
	}
	rec := surfReq(t, h, "PUT", "/v1/identity/google/settings", "admin-token", map[string]any{"adminEmail": gwstest.AdminEmail})
	if rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if got := decode[storepg.GWSSettings](t, rec); !got.Configured || got.SuperAdminMax != 4 || got.GmailScope != "readonly" {
		t.Errorf("saved = %+v", got)
	}
	if c := put("admin-token", map[string]any{"superAdminMax": 3}); c != 200 {
		t.Fatalf("partial PUT = %d", c)
	}
	if got := getStatus().Settings; got.SuperAdminMax != 3 || got.AdminEmail != gwstest.AdminEmail {
		t.Errorf("after a partial PUT = %+v", got)
	}
	if put("admin-token", map[string]any{"superAdminMax": 4}) != 200 {
		t.Fatal("restoring the limit failed")
	}

	// A viewer cannot start a read; an admin can.
	if rec := surfReq(t, h, "POST", "/v1/identity/google/sync", "viewer-token", nil); rec.Code != 403 {
		t.Errorf("viewer sync = %d", rec.Code)
	}
	rec = surfReq(t, h, "POST", "/v1/identity/google/sync", "admin-token", map[string]any{"wait": true})
	if rec.Code != 200 {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body.String())
	}
	run := decode[storepg.IdentityRun](t, rec)
	if run.Status != "ok" || run.Provider != "google" || run.Tenant != "example.com" || run.Open != 9 || run.Opened != 9 || len(run.Checks) != 3 || !strings.HasPrefix(run.TriggeredBy, "manual:") {
		t.Fatalf("run = %+v", run)
	}
	if run.Counts.MailboxesRead != 8 || run.Counts.Rules != 7 || run.Counts.GlobalAdmins != 2 {
		t.Errorf("counts = %+v", run.Counts)
	}
	for _, r := range srv.Requests() {
		if r.Method != "GET" {
			t.Errorf("a %s request reached Google", r.Method)
		}
	}

	st = getStatus()
	if st.LatestRun == nil || st.Summary.Findings != 9 || st.Summary.BySeverity["critical"] != 4 || st.Summary.LastStatus != "ok" || !st.Credentials.Configured {
		t.Errorf("status after the read = %+v / %+v", st.Summary, st.Credentials)
	}
	if st.Summary.Provider != "google" || len(st.Summary.Providers) != 1 {
		t.Errorf("summary providers = %+v", st.Summary)
	}

	// Findings: by provider and check; the shared list carries them with the provider.
	all := findings("")
	if len(all) != 9 || all[0].Severity != "critical" || all[0].Provider != "google" {
		t.Fatalf("findings = %d, first %+v", len(all), all[0])
	}
	if n := len(findings("?provider=google")); n != 9 {
		t.Errorf("google findings = %d", n)
	}
	if n := len(findings("?provider=m365")); n != 0 {
		t.Errorf("m365 findings = %d: the providers must stay apart", n)
	}
	if n := len(findings("?provider=google&check=inbox-rules")); n != 5 {
		t.Errorf("inbox-rules findings = %d, want 5", n)
	}
	if n := len(findings("?provider=google&check=admin-roles")); n != 0 {
		t.Errorf("admin-roles findings = %d", n)
	}
	if rec := surfReq(t, h, "GET", "/v1/identity/findings?provider=azure", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("a bad provider = %d", rec.Code)
	}
	if rec := surfReq(t, h, "GET", "/v1/identity/findings?check=nope", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("a bad check name = %d", rec.Code)
	}
	// Runs: Microsoft's unless a provider is named.
	runs := func(q string) []storepg.IdentityRun {
		rec := surfReq(t, h, "GET", "/v1/identity/runs"+q, "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("runs%s = %d", q, rec.Code)
		}
		return decode[struct {
			Runs []storepg.IdentityRun `json:"runs"`
		}](t, rec).Runs
	}
	if n := len(runs("?provider=google")); n != 1 {
		t.Errorf("google runs = %d", n)
	}
	if n := len(runs("")); n != 0 {
		t.Errorf("default runs = %d, want Microsoft 365's (none)", n)
	}

	// Microsoft's own status does not count Google's findings.
	rec = surfReq(t, h, "GET", "/v1/identity/status", "viewer-token", nil)
	ms := decode[struct {
		Summary storepg.IdentityExposureSummary `json:"summary"`
	}](t, rec)
	if ms.Summary.Findings != 0 || ms.Summary.Provider != "m365" {
		t.Errorf("m365 status counts google: %+v", ms.Summary)
	}
	// The Fleet-wide exposure summary counts both.
	if sum, err := storepg.New(pool).IdentityExposureSummary(context.Background()); err != nil || sum.Findings != 9 {
		t.Errorf("exposure summary = %+v, %v", sum, err)
	}

	// The exposure list carries the rows, and the drawer opens one by its key.
	rec = surfReq(t, s.HandleExposure, "GET", "/v1/exposure/findings", "viewer-token", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"provider":"google"`) {
		t.Errorf("exposure list = %d, google rows present: %v", rec.Code, strings.Contains(rec.Body.String(), `"provider":"google"`))
	}

	// The ledger: the settings changes, the sync and the run are chained.
	led := idnLedger(t, pool)
	if led["identity_settings_changed"] != 3 || led["identity_sync"] != 1 || led["identity_run_recorded"] != 1 {
		t.Errorf("ledger = %v", led)
	}

	// A second read of an unchanged domain opens and closes nothing. Then casey's filter
	// is removed in the fixture: that one finding resolves.
	rec = surfReq(t, h, "POST", "/v1/identity/google/sync", "admin-token", map[string]any{"wait": true})
	run2 := decode[storepg.IdentityRun](t, rec)
	if run2.Opened != 0 || run2.Resolved != 0 || run2.Open != 9 {
		t.Errorf("run 2 = %+v", run2)
	}
	srv.Filters["casey@example.com"] = `{}`
	rec = surfReq(t, h, "POST", "/v1/identity/google/sync", "admin-token", map[string]any{"wait": true})
	run3 := decode[storepg.IdentityRun](t, rec)
	if run3.Opened != 0 || run3.Resolved != 1 || run3.Open != 8 {
		t.Errorf("run 3 = %+v", run3)
	}

	// The key is refused: the run is recorded as not assessed and resolves nothing.
	srv.RejectKey = true
	rec = surfReq(t, h, "POST", "/v1/identity/google/sync", "admin-token", map[string]any{"wait": true})
	run4 := decode[storepg.IdentityRun](t, rec)
	if run4.Status != "not_assessed" || run4.Resolved != 0 || run4.Open != 8 || !strings.Contains(run4.Reason, "refused the service account's credentials") {
		t.Errorf("run 4 = %+v", run4)
	}
	for _, f := range findings("?provider=google") {
		if !f.Unconfirmed {
			t.Errorf("%s is not marked unconfirmed after a read that assessed nothing", f.FindingID)
		}
	}
	if st := getStatus(); st.Summary.LastStatus != "not_assessed" || st.Summary.ChecksNotAssessed != 3 {
		t.Errorf("status after a refused read = %+v", st.Summary)
	}
}

func TestGWSCredentialsFromTheKeyFile(t *testing.T) {
	srv := gwstest.New(t)
	file, _ := srv.NewKey()
	var kf struct {
		PrivateKey string `json:"private_key"`
	}
	_ = json.Unmarshal(file, &kf)
	dir := t.TempDir()
	good := filepath.Join(dir, "key.json")
	if err := os.WriteFile(good, file, 0o600); err != nil {
		t.Fatal(err)
	}
	set := storepg.GWSSettings{AdminEmail: gwstest.AdminEmail, GmailScope: "readonly", SuperAdminMax: 4, Configured: true}

	t.Setenv("DEFENDSEC_GWS_KEY_FILE", "")
	if _, cr, err := gwsFromEnv(set); err == nil || cr.Configured || !strings.Contains(cr.Problem, "DEFENDSEC_GWS_KEY_FILE") {
		t.Errorf("no file: %+v %v", cr, err)
	}

	t.Setenv("DEFENDSEC_GWS_KEY_FILE", good)
	src, cr, err := gwsFromEnv(set)
	if err != nil || src == nil || !cr.Configured || cr.ClientEmail != gwstest.ServiceEmail || cr.ClientID != gwstest.ClientID || cr.KeyID == "" || cr.ProjectID != "fixture-project" {
		t.Fatalf("good file: %+v %v", cr, err)
	}
	b, _ := json.Marshal(cr)
	if strings.Contains(string(b), "BEGIN") || strings.Contains(string(b), kf.PrivateKey[30:60]) {
		t.Errorf("the credentials state holds key material: %s", b)
	}
	if len(cr.Warnings) == 0 {
		t.Error("no warning about what a key file is")
	}
	// No administrator: not configured, and it says so.
	noAdmin := set
	noAdmin.AdminEmail, noAdmin.Configured = "", false
	if _, cr, err := gwsFromEnv(noAdmin); err == nil || cr.Configured || !strings.Contains(cr.Problem, "no administrator") {
		t.Errorf("no admin: %+v %v", cr, err)
	}

	for name, tc := range map[string]struct {
		content string
		mode    os.FileMode
		want    string
	}{
		"group writable": {string(file), 0o620, "writable by group or others"},
		"not json":       {"hello", 0o600, "not a JSON object"},
		"wrong kind":     {`{"type":"authorized_user","client_email":"a@b.c"}`, 0o600, "not a service account key"},
		"empty":          {"", 0o600, "empty or larger"},
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(p, []byte(tc.content), tc.mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, tc.mode)
		t.Setenv("DEFENDSEC_GWS_KEY_FILE", p)
		_, cr, err := gwsFromEnv(set)
		if err == nil || cr.Configured || !strings.Contains(cr.Problem, tc.want) {
			t.Errorf("%s: %+v %v (want %q)", name, cr, err, tc.want)
		}
		if strings.Contains(cr.Problem, "hello") {
			t.Errorf("%s: the problem quotes the file", name)
		}
	}
	t.Setenv("DEFENDSEC_GWS_KEY_FILE", filepath.Join(dir, "missing.json"))
	if _, cr, err := gwsFromEnv(set); err == nil || !strings.Contains(cr.Problem, "missing.json") {
		t.Errorf("missing file: %+v %v", cr, err)
	}
}

func TestGWSScheduleReadsOnlyWhenDue(t *testing.T) {
	s, _, srv := gwsScratchServer(t)
	ctx := context.Background()
	s.gwsr.interval = time.Hour

	if s.gwsScheduleOnce(ctx) {
		t.Fatal("read with no administrator set")
	}
	if err := s.pg.SetGWSSettings(ctx, "admin:test", storepg.GWSSettings{AdminEmail: gwstest.AdminEmail, SuperAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	if !s.gwsScheduleOnce(ctx) {
		t.Fatal("no read although one is due")
	}
	n := len(srv.Requests())
	if s.gwsScheduleOnce(ctx) || len(srv.Requests()) != n {
		t.Error("a read that is not due was made")
	}
	run, _ := s.pg.LatestIdentityRun(ctx, "google")
	if run == nil || run.TriggeredBy != "schedule" || run.Status != "ok" {
		t.Errorf("run = %+v", run)
	}
	// A different administrator's domain makes the last read not count.
	if err := s.pg.SetGWSSettings(ctx, "admin:test", storepg.GWSSettings{AdminEmail: "alex@other.example.net", SuperAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	if !s.gwsScheduleOnce(ctx) {
		t.Error("a new domain was not read at once")
	}
	// One read at a time.
	if !s.claimGWS() {
		t.Fatal("claim")
	}
	defer s.releaseGWS()
	if s.claimGWS() {
		t.Error("two reads may run at once")
	}
	rec := surfReq(t, s.HandleIdentity, "POST", "/v1/identity/google/sync", "admin-token", map[string]any{"wait": true})
	if rec.Code != 409 {
		t.Errorf("sync while one runs = %d", rec.Code)
	}
}
