package control

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/m365"
	"defendsec/internal/m365/graph"
	"defendsec/internal/m365/m365test"
	"defendsec/internal/storepg"
)

// m365ScratchServer is an apid with its own throwaway database (the identity
// counts span the whole database) and a Microsoft 365 source aimed at the fixture
// Graph server.
func m365ScratchServer(t *testing.T) (*Server, *pgxpool.Pool, *m365test.Server) {
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
	name := "defendsec_mig_m365api_" + hex.EncodeToString(b)
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
	s := &Server{adminToken: "admin-token", viewerToken: "viewer-token", log: slog.New(slog.DiscardHandler)}
	s.SetPostgres(storepg.New(pool))

	srv := m365test.New(t)
	s.SetM365Source(func(set storepg.M365Settings) (m365.Source, error) {
		cfg := srv.Config()
		cfg.TenantID, cfg.ClientID = set.TenantID, set.ClientID
		cfg.Sleep = func(context.Context, time.Duration) error { return nil }
		c, err := graph.New(cfg)
		if err != nil {
			return nil, err
		}
		return m365.NewGraphSource(c), nil
	})
	return s, pool, srv
}

func TestIdentityAPIAuth(t *testing.T) {
	s := testServer() // no Postgres
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/v1/identity/status", "", 401},
		{"GET", "/v1/identity/status", "nope", 401},
		{"GET", "/v1/identity/status", "viewer-token", 503},
		{"PUT", "/v1/identity/m365/settings", "viewer-token", 403},
		{"PUT", "/v1/identity/m365/settings", "admin-token", 503},
		{"GET", "/v1/identity/m365/settings", "admin-token", 405},
		{"POST", "/v1/identity/m365/sync", "viewer-token", 403},
		{"GET", "/v1/identity/m365/sync", "admin-token", 405},
		{"POST", "/v1/identity/status", "admin-token", 405},
		{"GET", "/v1/identity/findings", "", 401},
		{"GET", "/v1/identity/findings", "viewer-token", 503},
		{"GET", "/v1/identity/runs", "viewer-token", 503},
		{"DELETE", "/v1/identity/runs", "admin-token", 405},
		{"GET", "/v1/identity/nothing", "admin-token", 404},
	} {
		rec := surfReq(t, s.HandleIdentity, tc.method, tc.path, tc.token, nil)
		if rec.Code != tc.want {
			t.Errorf("%s %s token=%q: %d, want %d (%s)", tc.method, tc.path, tc.token, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func idnLedger(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT action, count(*) FROM audit_log WHERE action LIKE 'identity_%' GROUP BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var a string
		var n int
		if err := rows.Scan(&a, &n); err != nil {
			t.Fatal(err)
		}
		out[a] = n
	}
	return out
}

func TestIdentityAPIEndToEnd(t *testing.T) {
	s, pool, srv := m365ScratchServer(t)
	h := s.HandleIdentity

	type statusT struct {
		Settings    storepg.M365Settings            `json:"settings"`
		Credentials m365Credentials                 `json:"credentials"`
		Summary     storepg.IdentityExposureSummary `json:"summary"`
		LatestRun   *storepg.IdentityRun            `json:"latestRun"`
		NotAssessed []m365.NotAssessed              `json:"notAssessed"`
		Permissions []m365.Permission               `json:"permissions"`
		ReadOnly    string                          `json:"readOnlyNote"`
	}
	getStatus := func() statusT {
		rec := surfReq(t, h, "GET", "/v1/identity/status", "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		return decode[statusT](t, rec)
	}

	// Nothing set yet: the status says what is missing and what is never seen.
	st := getStatus()
	if st.Settings.Configured || st.LatestRun != nil || st.Summary.Findings != 0 || st.Summary.LastStatus != "" {
		t.Errorf("empty status = %+v", st)
	}
	if len(st.NotAssessed) < 4 || !strings.Contains(st.NotAssessed[0].What, "ForwardingSmtpAddress") {
		t.Errorf("the status must say what is not assessed before any run: %+v", st.NotAssessed)
	}
	var optional []string
	for _, p := range st.Permissions {
		if !p.Required {
			optional = append(optional, p.Name)
		}
		if !strings.Contains(p.Name, ".Read") {
			t.Errorf("permission %q is not a read permission", p.Name)
		}
	}
	if len(st.Permissions) != 6 || len(optional) != 1 || optional[0] != "Mail.ReadBasic.All" {
		t.Errorf("permissions = %+v", st.Permissions)
	}
	if !strings.Contains(st.ReadOnly, "never reads a message") {
		t.Errorf("read-only note = %q", st.ReadOnly)
	}

	// A sync with no tenant is a 400, not a guess.
	if rec := surfReq(t, h, "POST", "/v1/identity/m365/sync", "admin-token", map[string]any{"wait": true}); rec.Code != 400 {
		t.Errorf("sync without a tenant = %d", rec.Code)
	}

	// Settings: validated, admin only, ledgered.
	put := func(token string, body map[string]any) int {
		return surfReq(t, h, "PUT", "/v1/identity/m365/settings", token, body).Code
	}
	if c := put("viewer-token", map[string]any{"tenantId": m365test.TenantID, "clientId": m365test.ClientID}); c != 403 {
		t.Errorf("viewer PUT = %d", c)
	}
	for name, body := range map[string]map[string]any{
		"tenant common":      {"tenantId": "common", "clientId": m365test.ClientID},
		"client not a guid":  {"tenantId": m365test.TenantID, "clientId": "x"},
		"limit 0":            {"tenantId": m365test.TenantID, "clientId": m365test.ClientID, "globalAdminMax": 0},
		"unknown field":      {"tenantId": m365test.TenantID, "clientId": m365test.ClientID, "secret": "pasted"},
		"bad trusted domain": {"tenantId": m365test.TenantID, "clientId": m365test.ClientID, "trustedDomains": []string{"not a domain"}},
	} {
		if c := put("admin-token", body); c != 400 {
			t.Errorf("%s: %d, want 400", name, c)
		}
	}
	if n := idnLedger(t, pool)["identity_settings_changed"]; n != 0 {
		t.Errorf("refused settings wrote %d ledger entries", n)
	}
	rec := surfReq(t, h, "PUT", "/v1/identity/m365/settings", "admin-token", map[string]any{"tenantId": m365test.TenantID, "clientId": m365test.ClientID, "resolveFolders": true})
	if rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if got := decode[storepg.M365Settings](t, rec); !got.Configured || got.GlobalAdminMax != 4 || !got.ResolveFolders {
		t.Errorf("saved = %+v", got)
	}
	// A second PUT with only one field keeps the rest.
	if c := put("admin-token", map[string]any{"globalAdminMax": 3}); c != 200 {
		t.Fatalf("partial PUT = %d", c)
	}
	if got := getStatus().Settings; got.GlobalAdminMax != 3 || got.TenantID != m365test.TenantID || !got.ResolveFolders {
		t.Errorf("after a partial PUT = %+v", got)
	}
	if put("admin-token", map[string]any{"globalAdminMax": 4}) != 200 {
		t.Fatal("restoring the limit failed")
	}

	// A viewer cannot start a read; an admin can.
	if rec := surfReq(t, h, "POST", "/v1/identity/m365/sync", "viewer-token", nil); rec.Code != 403 {
		t.Errorf("viewer sync = %d", rec.Code)
	}
	rec = surfReq(t, h, "POST", "/v1/identity/m365/sync", "admin-token", map[string]any{"wait": true})
	if rec.Code != 200 {
		t.Fatalf("sync = %d %s", rec.Code, rec.Body.String())
	}
	run := decode[storepg.IdentityRun](t, rec)
	if run.Status != "ok" || run.Open != 6 || run.Opened != 6 || len(run.Checks) != 4 || !strings.HasPrefix(run.TriggeredBy, "manual:") {
		t.Fatalf("run = %+v", run)
	}
	for _, r := range srv.Requests() {
		if r.Method != "GET" {
			t.Errorf("a %s request reached Graph", r.Method)
		}
	}

	st = getStatus()
	if st.LatestRun == nil || st.Summary.Findings != 6 || st.Summary.BySeverity["critical"] != 3 || st.Summary.LastStatus != "ok" || !st.Credentials.Configured {
		t.Errorf("status after the read = %+v", st.Summary)
	}

	// Findings, filtered.
	rec = surfReq(t, h, "GET", "/v1/identity/findings", "viewer-token", nil)
	fl := decode[struct {
		Findings []storepg.IdentityFinding `json:"findings"`
	}](t, rec)
	if len(fl.Findings) != 6 || fl.Findings[0].Severity != "critical" {
		t.Fatalf("findings = %d, first %s", len(fl.Findings), fl.Findings[0].Severity)
	}
	rec = surfReq(t, h, "GET", "/v1/identity/findings?check=inbox-rules", "viewer-token", nil)
	if n := len(decode[struct {
		Findings []storepg.IdentityFinding `json:"findings"`
	}](t, rec).Findings); n != 2 {
		t.Errorf("inbox-rules findings = %d, want 2", n)
	}
	if rec := surfReq(t, h, "GET", "/v1/identity/findings?check=nope", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("a bad check name = %d", rec.Code)
	}

	// The exposure list carries them, and the drawer opens one by its key.
	rec = surfReq(t, s.HandleExposure, "GET", "/v1/exposure/findings", "viewer-token", nil)
	if rec.Code != 200 {
		t.Fatalf("exposure = %d %s", rec.Code, rec.Body.String())
	}
	page := decode[storepg.ExposurePage](t, rec)
	if len(page.Findings) != 6 || page.Findings[0].Source != storepg.SourceIdentity || page.Findings[0].Identity == nil {
		t.Fatalf("exposure page = %d rows, first %+v", len(page.Findings), page.Findings[0])
	}
	key := page.Findings[0].AdvisoryID
	rec = surfReq(t, s.HandleExposure, "GET", "/v1/exposure/advisory?id="+key, "viewer-token", nil)
	if rec.Code != 200 {
		t.Fatalf("drawer = %d %s", rec.Code, rec.Body.String())
	}
	dr := decode[struct {
		Source string                 `json:"source"`
		Status string                 `json:"status"`
		Detail storepg.IdentityDetail `json:"detail"`
	}](t, rec)
	if dr.Source != "identity" || dr.Status != "open" || dr.Detail.Finding.Fix == "" || dr.Detail.CheckState == nil || len(dr.Detail.Intervals) != 1 {
		t.Errorf("drawer = %+v", dr)
	}
	if rec := surfReq(t, s.HandleExposure, "GET", "/v1/exposure/advisory?id=identity:000000999999", "viewer-token", nil); rec.Code != 404 {
		t.Errorf("a missing identity finding = %d", rec.Code)
	}
	if rec := surfReq(t, s.HandleExposure, "GET", "/v1/exposure/advisory?id=identity:12abc", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("a malformed identity key = %d", rec.Code)
	}

	// A fix lands: Casey's rule is removed. The next read resolves exactly that finding.
	srv.Override["/users/"+m365test.UserCasey+"/mailFolders/inbox/messageRules"] = `{"value":[]}`
	rec = surfReq(t, h, "POST", "/v1/identity/m365/sync", "admin-token", map[string]any{"wait": true})
	run2 := decode[storepg.IdentityRun](t, rec)
	if rec.Code != 200 || run2.Resolved != 1 || run2.Open != 5 || run2.Opened != 0 {
		t.Fatalf("second run = %d %+v", rec.Code, run2)
	}

	// The credentials are refused: the read is recorded as not assessed and resolves nothing.
	srv.RejectToken = true
	rec = surfReq(t, h, "POST", "/v1/identity/m365/sync", "admin-token", map[string]any{"wait": true})
	run3 := decode[storepg.IdentityRun](t, rec)
	if rec.Code != 200 || run3.Status != "not_assessed" || run3.Resolved != 0 || run3.Open != 5 || !strings.Contains(run3.Reason, "AADSTS7000215") {
		t.Fatalf("third run = %d %+v", rec.Code, run3)
	}
	if strings.Contains(rec.Body.String(), m365test.ClientSecret) {
		t.Error("the secret is in an API answer")
	}
	st = getStatus()
	if st.Summary.Findings != 5 || st.Summary.LastStatus != "not_assessed" || st.Summary.ChecksNotAssessed != 4 {
		t.Errorf("summary after refused credentials = %+v", st.Summary)
	}
	runs := decode[struct {
		Runs []storepg.IdentityRun `json:"runs"`
	}](t, surfReq(t, h, "GET", "/v1/identity/runs?limit=2", "viewer-token", nil))
	if len(runs.Runs) != 2 || runs.Runs[0].ID != run3.ID {
		t.Errorf("runs = %+v", runs.Runs)
	}
	if rec := surfReq(t, h, "GET", "/v1/identity/runs?limit=0", "viewer-token", nil); rec.Code != 400 {
		t.Errorf("limit 0 = %d", rec.Code)
	}

	// Only one read at a time.
	srv.RejectToken = false
	if !s.claimM365() {
		t.Fatal("could not claim")
	}
	if rec := surfReq(t, h, "POST", "/v1/identity/m365/sync", "admin-token", map[string]any{"wait": true}); rec.Code != 409 {
		t.Errorf("a second read while one runs = %d, want 409", rec.Code)
	}
	s.releaseM365()

	// The ledger holds the settings, each manual read, and each recorded run.
	led := idnLedger(t, pool)
	if led["identity_settings_changed"] != 3 || led["identity_sync"] != 3 || led["identity_run_recorded"] != 3 {
		t.Errorf("ledger = %v, want 3 settings, 3 syncs, 3 runs recorded", led)
	}
}

func TestIdentityScheduleReadsWhenDue(t *testing.T) {
	s, _, _ := m365ScratchServer(t)
	ctx := context.Background()
	if s.m365ScheduleOnce(ctx) {
		t.Fatal("the schedule read with no tenant set")
	}
	if err := s.pg.SetM365Settings(ctx, "t", storepg.M365Settings{TenantID: m365test.TenantID, ClientID: m365test.ClientID, GlobalAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	if !s.m365ScheduleOnce(ctx) {
		t.Fatal("the schedule did not read a configured tenant that was never read")
	}
	if s.m365ScheduleOnce(ctx) {
		t.Error("the schedule read again straight away")
	}
	run, _ := s.pg.LatestIdentityRun(ctx, m365.Provider)
	if run == nil || run.TriggeredBy != "schedule" || run.Status != "ok" {
		t.Errorf("run = %+v", run)
	}
	// A different tenant is read at once, whatever the interval.
	if err := s.pg.SetM365Settings(ctx, "t", storepg.M365Settings{TenantID: "other.example.com", ClientID: m365test.ClientID, GlobalAdminMax: 4}); err != nil {
		t.Fatal(err)
	}
	s.SetM365Source(func(set storepg.M365Settings) (m365.Source, error) { return nil, os.ErrNotExist })
	if s.m365ScheduleOnce(ctx) {
		t.Error("the schedule read although the credentials are missing")
	}
}

func writeTemp(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func certBundle(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "defendsec-test"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k8, _ := x509.MarshalPKCS8PrivateKey(key)
	return append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k8}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func TestM365FromEnv(t *testing.T) {
	dir := t.TempDir()
	set := storepg.M365Settings{TenantID: m365test.TenantID, ClientID: m365test.ClientID, Cloud: "global", GlobalAdminMax: 4, Configured: true}
	const secretValue = "super-secret-value-123"
	secFile := writeTemp(t, dir, "secret", []byte(secretValue+"\n"), 0o600)
	good := writeTemp(t, dir, "good.pem", certBundle(t, time.Now().Add(365*24*time.Hour)), 0o600)
	soon := writeTemp(t, dir, "soon.pem", certBundle(t, time.Now().Add(10*24*time.Hour)), 0o600)
	expired := writeTemp(t, dir, "expired.pem", certBundle(t, time.Now().Add(-time.Hour)), 0o600)
	open := writeTemp(t, dir, "open.pem", certBundle(t, time.Now().Add(365*24*time.Hour)), 0o666)
	garbage := writeTemp(t, dir, "garbage.pem", []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)

	env := func(cert, sec string) {
		t.Setenv("DEFENDSEC_M365_CERT_FILE", cert)
		t.Setenv("DEFENDSEC_M365_SECRET_FILE", sec)
	}

	env("", "")
	if _, cr, err := m365FromEnv(set); err == nil || cr.Configured || !strings.Contains(cr.Problem, "DEFENDSEC_M365_CERT_FILE") {
		t.Errorf("no credentials: %v %+v", err, cr)
	}

	env(good, "")
	src, cr, err := m365FromEnv(set)
	if err != nil || src == nil || !cr.Configured || cr.Method != "certificate" || len(cr.Thumbprint) != 64 || cr.NotAfter == nil || len(cr.Warnings) != 0 {
		t.Errorf("certificate: %v %+v", err, cr)
	}

	env(soon, "")
	if _, cr, err = m365FromEnv(set); err != nil || len(cr.Warnings) != 1 || !strings.Contains(cr.Warnings[0], "expires on") {
		t.Errorf("certificate expiring soon: %v %+v", err, cr)
	}
	env(expired, "")
	if _, cr, err = m365FromEnv(set); err == nil || cr.Configured || !strings.Contains(cr.Problem, "expired") {
		t.Errorf("expired certificate: %v %+v", err, cr)
	}
	env(open, "")
	if _, cr, err = m365FromEnv(set); err == nil || !strings.Contains(cr.Problem, "writable") {
		t.Errorf("group-writable certificate file: %v %+v", err, cr)
	}
	env(garbage, "")
	if _, cr, err = m365FromEnv(set); err == nil || cr.Configured {
		t.Errorf("garbage certificate: %v %+v", err, cr)
	}

	env("", secFile)
	if src, cr, err = m365FromEnv(set); err != nil || src == nil || cr.Method != "secret" || len(cr.Warnings) != 1 || !strings.Contains(cr.Warnings[0], "certificate is safer") {
		t.Errorf("secret: %v %+v", err, cr)
	}
	env(good, secFile)
	if _, cr, err = m365FromEnv(set); err != nil || cr.Method != "certificate" || len(cr.Warnings) != 1 || !strings.Contains(cr.Warnings[0], "both") {
		t.Errorf("both: %v %+v", err, cr)
	}

	// No tenant set: said in words.
	env(good, "")
	if _, cr, err = m365FromEnv(storepg.M365Settings{Cloud: "global"}); err == nil || !strings.Contains(cr.Problem, "tenant") {
		t.Errorf("no tenant: %v %+v", err, cr)
	}

	// No value is ever in what is reported.
	env("", secFile)
	for _, st := range []storepg.M365Settings{set, {Cloud: "global"}, {TenantID: "common", ClientID: "x", Cloud: "global"}} {
		_, cr, err := m365FromEnv(st)
		if blob := cr.Problem + strings.Join(cr.Warnings, " ") + func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(); strings.Contains(blob, secretValue) {
			t.Errorf("the secret is in %q", blob)
		}
	}
}
