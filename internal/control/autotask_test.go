package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/autotask"
	"defendsec/internal/autotask/atest"
	"defendsec/internal/autotask/client"
	"defendsec/internal/presence"
	"defendsec/internal/storepg"
	"defendsec/internal/vuln"
)

// atkScratch is an apid with its own throwaway database (the candidates are the
// whole database's findings) and an Autotask desk aimed at the fake service.
func atkScratch(t *testing.T) (*Server, *pgxpool.Pool, *atest.Server) {
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
	name := "defendsec_mig_atkapi_" + hex.EncodeToString(b)
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
	srv := atest.New()
	t.Cleanup(srv.Close)
	s.SetAutotaskDesk(func(set autotask.Settings) (autotask.Desk, error) {
		return client.New(client.Config{BaseURL: srv.BaseURL(), UserName: atest.User, Secret: atest.Secret, IntegrationCode: atest.IntegrationCode,
			Sleep: func(context.Context, time.Duration) error { return nil }})
	})
	return s, pool, srv
}

func atkLedger(t *testing.T, pool *pgxpool.Pool) map[string]int {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT action, count(*) FROM audit_log WHERE action LIKE 'autotask_%' GROUP BY action`)
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

func atkSeedVuln(t *testing.T, pg *storepg.Store, host string, kev bool) {
	t.Helper()
	ctx := context.Background()
	a := storepg.Advisory{ID: "ATK-1", CVE: "CVE-2099-7001", Severity: "high", Summary: "openssl flaw", Source: "test", KEV: kev}
	if err := pg.UpsertAdvisoryWithRanges(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := pg.UpsertDevice(ctx, presence.Device{ID: "dev-" + host, Hostname: host, Platform: "linux", LastSeen: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	f := vuln.Finding{AdvisoryID: a.ID, CVE: a.CVE, Kind: vuln.KindFinding, Basis: vuln.BasisDistro, Package: "openssl", Installed: "1.0", Fixed: "1.1", FixState: "fixed",
		Severity: "high", Summary: a.Summary, KEV: kev, Feed: "ubuntu-jammy"}
	if err := pg.RecordFindings(ctx, "dev-"+host, vuln.Result{Coverage: vuln.CoverageFull, Findings: []vuln.Finding{f}}, nil); err != nil {
		t.Fatal(err)
	}
}

func atkSettingsBody() map[string]any {
	return map[string]any{
		"apiUser": atest.User, "companyId": 3001, "queueId": "101", "status": "1", "source": "7", "issueType": "20", "subIssueType": "200",
		"priorityCritical": "1", "priorityHigh": "2", "priorityMedium": "3", "noteType": "1", "notePublish": "2", "completeStatus": "5",
		"consoleUrl": "https://defendsec.example.net",
	}
}

func TestAutotaskAPIAuth(t *testing.T) {
	s := testServer() // no Postgres
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{"GET", "/v1/autotask/status", "", 401},
		{"GET", "/v1/autotask/status", "viewer-token", 503},
		{"PUT", "/v1/autotask/settings", "viewer-token", 403},
		{"PUT", "/v1/autotask/settings", "admin-token", 503},
		{"GET", "/v1/autotask/picklists", "viewer-token", 403},
		{"GET", "/v1/autotask/companies", "viewer-token", 403},
		{"POST", "/v1/autotask/run", "viewer-token", 403},
		{"POST", "/v1/autotask/run", "admin-token", 503},
		{"GET", "/v1/autotask/run", "admin-token", 405},
		{"GET", "/v1/autotask/runs", "viewer-token", 503},
		{"GET", "/v1/autotask/runs/1", "viewer-token", 503},
		{"GET", "/v1/autotask/tickets", "viewer-token", 503},
		{"DELETE", "/v1/autotask/tickets", "admin-token", 405},
		{"GET", "/v1/autotask/nothing", "admin-token", 404},
	} {
		rec := surfReq(t, s.HandleAutotask, tc.method, tc.path, tc.token, nil)
		if rec.Code != tc.want {
			t.Errorf("%s %s token=%q: %d, want %d (%s)", tc.method, tc.path, tc.token, rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
		}
	}
}

func TestAutotaskCredentialsComeFromFilesAndNeverShow(t *testing.T) {
	s, _, _ := atkScratch(t)
	s.SetAutotaskDesk(nil) // the production path: files named in the environment
	h := s.HandleAutotask
	get := func() (string, map[string]any) {
		rec := surfReq(t, h, "GET", "/v1/autotask/status", "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		return rec.Body.String(), decode[map[string]any](t, rec)
	}
	t.Setenv("DEFENDSEC_AUTOTASK_SECRET_FILE", "")
	t.Setenv("DEFENDSEC_AUTOTASK_CODE_FILE", "")
	_, st := get()
	cr := st["credentials"].(map[string]any)
	if cr["configured"] != false || !strings.Contains(cr["problem"].(string), "DEFENDSEC_AUTOTASK_SECRET_FILE") {
		t.Fatalf("credentials = %+v", cr)
	}
	dir := t.TempDir()
	sec, code := filepath.Join(dir, "secret"), filepath.Join(dir, "code")
	const secretValue, codeValue = "super-secret-value-123", "INTEGRATIONCODE9999"
	if err := os.WriteFile(sec, []byte(secretValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(code, []byte(codeValue+"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENDSEC_AUTOTASK_SECRET_FILE", sec)
	t.Setenv("DEFENDSEC_AUTOTASK_CODE_FILE", code)
	_, st = get()
	if cr := st["credentials"].(map[string]any); cr["configured"] != false || !strings.Contains(cr["problem"].(string), "writable by group or others") {
		t.Errorf("a world-writable credential file was accepted: %+v", cr)
	}
	if err := os.Chmod(code, 0o600); err != nil {
		t.Fatal(err)
	}
	body, st := get()
	if cr := st["credentials"].(map[string]any); cr["configured"] != false || !strings.Contains(cr["problem"].(string), "user's name is not set") {
		t.Errorf("no API user yet: %+v", cr)
	}
	if rec := surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", map[string]any{"apiUser": atest.User}); rec.Code != 200 {
		t.Fatalf("settings = %d %s", rec.Code, rec.Body.String())
	}
	body, st = get()
	if cr := st["credentials"].(map[string]any); cr["configured"] != true {
		t.Errorf("credentials = %+v", cr)
	}
	for _, leak := range []string{secretValue, codeValue} {
		if strings.Contains(body, leak) {
			t.Errorf("the status shows a credential")
		}
	}
	// A credential is never accepted over the API.
	for _, field := range []string{"secret", "integrationCode", "password"} {
		if rec := surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", map[string]any{field: "pasted"}); rec.Code != 400 {
			t.Errorf("PUT with %q = %d, want 400", field, rec.Code)
		}
	}
}

func TestAutotaskPicklistsAndCompanySearch(t *testing.T) {
	s, _, srv := atkScratch(t)
	h := s.HandleAutotask
	rec := surfReq(t, h, "GET", "/v1/autotask/picklists", "admin-token", nil)
	if rec.Code != 200 {
		t.Fatalf("picklists = %d %s", rec.Code, rec.Body.String())
	}
	pl := decode[map[string]any](t, rec)
	queues := pl["queues"].([]any)
	if len(queues) != 2 || queues[1].(map[string]any)["label"] != "Service Desk" {
		t.Errorf("queues = %+v", queues)
	}
	if n := len(pl["priorities"].([]any)); n != 3 { // the inactive one is not offered
		t.Errorf("%d priorities offered, want the 3 active", n)
	}
	subs := pl["subIssueTypes"].([]any)
	if len(subs) != 3 || subs[0].(map[string]any)["parent"] == "" {
		t.Errorf("sub-issue types carry their parent: %+v", subs)
	}
	if pl["titleLength"].(float64) != 255 || pl["descriptionLength"].(float64) != 8000 {
		t.Errorf("limits = %v %v", pl["titleLength"], pl["descriptionLength"])
	}
	if _, has := pl["company"]; has {
		t.Error("a company before one is chosen")
	}
	if rec := surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", atkSettingsBody()); rec.Code != 200 {
		t.Fatalf("settings = %d %s", rec.Code, rec.Body.String())
	}
	pl = decode[map[string]any](t, surfReq(t, h, "GET", "/v1/autotask/picklists", "admin-token", nil))
	if co, _ := pl["company"].(map[string]any); co == nil || co["name"] != "Example Client LLC" || co["active"] != true {
		t.Errorf("company = %+v", pl["company"])
	}

	rec = surfReq(t, h, "GET", "/v1/autotask/companies?q=example", "admin-token", nil)
	cs := decode[map[string][]map[string]any](t, rec)["companies"]
	if rec.Code != 200 || len(cs) != 2 || cs[0]["id"].(float64) != 3001 {
		t.Errorf("companies = %d %+v", rec.Code, cs)
	}
	if rec := surfReq(t, h, "GET", "/v1/autotask/companies?q=e", "admin-token", nil); rec.Code != 400 {
		t.Errorf("a one-letter search = %d, want 400", rec.Code)
	}
	// Refused credentials are 403, said plainly, with no credential in the text.
	srv.AddFault(atest.Fault{Match: "GET /Tickets/entityInformation", Status: 401, Body: `{"errors":["bad"]}`})
	rec = surfReq(t, h, "GET", "/v1/autotask/picklists", "admin-token", nil)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "auth") || strings.Contains(rec.Body.String(), atest.Secret) {
		t.Errorf("refused = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAutotaskDryRunFirstThenLiveThenIdempotent(t *testing.T) {
	s, pool, srv := atkScratch(t)
	h := s.HandleAutotask
	atkSeedVuln(t, s.pg, "web-01", true)
	atkSeedVuln(t, s.pg, "web-02", true)

	put := func(body map[string]any) int {
		return surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", body).Code
	}
	type statusT struct {
		Settings     storepg.AutotaskSettings `json:"settings"`
		Missing      []string                 `json:"missing"`
		LiveUnlocked bool                     `json:"liveUnlocked"`
		Counts       storepg.AutotaskCounts   `json:"counts"`
		LatestRun    *storepg.AutotaskRun     `json:"latestRun"`
		LatestDryRun *storepg.AutotaskRun     `json:"latestDryRun"`
	}
	status := func() statusT {
		rec := surfReq(t, h, "GET", "/v1/autotask/status", "viewer-token", nil)
		if rec.Code != 200 {
			t.Fatalf("status = %d %s", rec.Code, rec.Body.String())
		}
		return decode[statusT](t, rec)
	}
	run := func(body map[string]any) (int, storepg.AutotaskRun) {
		rec := surfReq(t, h, "POST", "/v1/autotask/run", "admin-token", body)
		var r storepg.AutotaskRun
		if rec.Code == 200 {
			r = decode[storepg.AutotaskRun](t, rec)
		}
		return rec.Code, r
	}

	// Nothing chosen yet: the status names what, a run says so and sends nothing.
	if st := status(); len(st.Missing) < 4 || st.Settings.Mode != "dry_run" || st.LiveUnlocked {
		t.Fatalf("empty status = %+v", st)
	}
	code, r := run(map[string]any{"wait": true})
	if code != 200 || r.Status != "not_run" || len(r.Problems) != 1 || !strings.Contains(r.Problems[0], "Choose") || len(srv.Requests()) != 0 {
		t.Fatalf("run with nothing chosen: %d %+v", code, r)
	}

	if c := put(atkSettingsBody()); c != 200 {
		t.Fatalf("settings = %d", c)
	}
	// Live is refused before a dry run, both ways.
	live := atkSettingsBody()
	live["mode"] = "live"
	if c := put(live); c != 400 {
		t.Errorf("live without a dry run = %d, want 400", c)
	}
	if code, _ := run(map[string]any{"dryRun": false, "wait": true}); code != 409 {
		t.Errorf("a live run in dry-run mode = %d, want 409", code)
	}

	// The dry run: the exact ticket, nothing sent.
	code, dry := run(map[string]any{"wait": true})
	if code != 200 || dry.Mode != "dry_run" || !dry.Verified || dry.Status != "ok" || dry.CompanyName != "Example Client LLC" || dry.Groups != 1 {
		t.Fatalf("dry run = %d %+v", code, dry)
	}
	if len(dry.Ops) != 1 || dry.Ops[0].Kind != "create" || dry.Ops[0].Status != "planned" || dry.Ops[0].Create == nil ||
		!strings.HasPrefix(dry.Ops[0].Title, "Update openssl on 2 hosts [DS-") || dry.Ops[0].Create.Priority != 1 {
		t.Fatalf("ops = %+v", dry.Ops)
	}
	for _, q := range srv.Requests() {
		if q.Method == "PATCH" || (q.Method == "POST" && q.Path != "/Tickets/query") {
			t.Errorf("a dry run sent %s %s", q.Method, q.Path)
		}
	}
	if len(srv.Tickets()) != 0 {
		t.Fatal("a dry run made a ticket")
	}
	st := status()
	if !st.LiveUnlocked || st.LatestDryRun == nil || len(st.LatestDryRun.Ops) != 1 || st.LatestRun == nil {
		t.Fatalf("status after the dry run: %+v", st)
	}
	if got := atkLedger(t, pool); got["autotask_dry_run"] != 2 || got["autotask_ticket_created"] != 0 || got["autotask_settings_changed"] != 1 || got["autotask_sync"] != 2 {
		t.Fatalf("ledger = %v", got)
	}

	// Changing anything locks live again; the same settings unlock it.
	changed := atkSettingsBody()
	changed["queueId"] = "100"
	if c := put(changed); c != 200 {
		t.Fatal("dry-run settings need no gate")
	}
	if status().LiveUnlocked {
		t.Fatal("changed settings kept live unlocked")
	}
	live = atkSettingsBody()
	live["queueId"] = "100"
	live["mode"] = "live"
	if c := put(live); c != 400 {
		t.Fatalf("live on the old dry run = %d", c)
	}
	if code, _ = run(map[string]any{"wait": true}); code != 200 {
		t.Fatal("second dry run")
	}
	if c := put(live); c != 200 {
		t.Fatalf("live after the dry run = %d", c)
	}
	if st := status(); st.Settings.Mode != "live" || !st.LiveUnlocked {
		t.Fatalf("status = %+v", st.Settings)
	}

	// The live run creates exactly what the dry run showed.
	code, lr := run(map[string]any{"dryRun": false, "wait": true})
	if code != 200 || lr.Mode != "live" || lr.Status != "ok" || lr.Created != 1 || len(srv.Tickets()) != 1 {
		t.Fatalf("live run = %d %+v", code, lr)
	}
	if srv.Tickets()[0].Title != lr.Ops[0].Title || *srv.Tickets()[0].QueueID != 100 {
		t.Errorf("ticket = %+v", srv.Tickets()[0])
	}
	// A second live run changes nothing.
	code, again := run(map[string]any{"dryRun": false, "wait": true})
	if code != 200 || len(again.Ops) != 0 || len(srv.Tickets()) != 1 {
		t.Fatalf("second live run: %d %+v", code, again)
	}
	if got := atkLedger(t, pool); got["autotask_ticket_created"] != 1 || got["autotask_run"] != 2 {
		t.Fatalf("ledger = %v", got)
	}

	// A change after going live blocks the next live run until a dry run shows it.
	other := atkSettingsBody()
	other["queueId"] = "100"
	other["mode"] = "live"
	other["minUrgency"] = "medium"
	if c := put(other); c != 400 {
		t.Fatalf("changed settings went live without a dry run: %d", c)
	}
	cur := atkSettingsBody()
	cur["queueId"] = "100"
	cur["mode"] = "dry_run"
	cur["minUrgency"] = "medium"
	put(cur)
	if code, r := run(map[string]any{"dryRun": false, "wait": true}); code != 409 {
		t.Fatalf("live run with dry-run settings = %d %+v", code, r)
	}

	// History and detail.
	rec := surfReq(t, h, "GET", "/v1/autotask/runs?limit=10", "viewer-token", nil)
	runs := decode[map[string][]storepg.AutotaskRun](t, rec)["runs"]
	if rec.Code != 200 || len(runs) < 5 || len(runs[0].Ops) != 0 {
		t.Fatalf("runs = %d (%d)", rec.Code, len(runs))
	}
	one := decode[storepg.AutotaskRun](t, surfReq(t, h, "GET", fmt.Sprintf("/v1/autotask/runs/%d", lr.ID), "viewer-token", nil))
	if one.ID != lr.ID || len(one.Ops) != 1 || one.Ops[0].TicketID == 0 {
		t.Fatalf("detail = %+v", one)
	}
	if c := surfReq(t, h, "GET", "/v1/autotask/runs/999999", "viewer-token", nil).Code; c != 404 {
		t.Errorf("unknown run = %d", c)
	}
	if c := surfReq(t, h, "GET", "/v1/autotask/runs/x", "viewer-token", nil).Code; c != 400 {
		t.Errorf("bad run id = %d", c)
	}
	rec = surfReq(t, h, "GET", "/v1/autotask/tickets", "viewer-token", nil)
	tk := decode[map[string][]map[string]any](t, rec)["tickets"]
	if rec.Code != 200 || len(tk) != 1 || tk[0]["state"] != "open" || tk[0]["members"].(float64) != 2 {
		t.Errorf("tickets = %d %+v", rec.Code, tk)
	}
}

func TestAutotaskNewHostAndFixedHostThroughTheAPI(t *testing.T) {
	s, pool, srv := atkScratch(t)
	h := s.HandleAutotask
	atkSeedVuln(t, s.pg, "web-01", true)
	body := atkSettingsBody()
	surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", body)
	surfReq(t, h, "POST", "/v1/autotask/run", "admin-token", map[string]any{"wait": true})
	body["mode"] = "live"
	if rec := surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", body); rec.Code != 200 {
		t.Fatalf("live = %d %s", rec.Code, rec.Body.String())
	}
	live := func() storepg.AutotaskRun {
		rec := surfReq(t, h, "POST", "/v1/autotask/run", "admin-token", map[string]any{"dryRun": false, "wait": true})
		if rec.Code != 200 {
			t.Fatalf("run = %d %s", rec.Code, rec.Body.String())
		}
		return decode[storepg.AutotaskRun](t, rec)
	}
	if r := live(); r.Created != 1 {
		t.Fatalf("%+v", r)
	}
	id := srv.Tickets()[0].ID

	atkSeedVuln(t, s.pg, "web-02", true) // a new host joins
	if r := live(); r.Noted != 1 || r.Created != 0 || len(srv.Tickets()) != 1 {
		t.Fatalf("%+v", r)
	}
	if n := srv.Notes(id); len(n) != 1 || !strings.Contains(n[0].Description, "web-02") {
		t.Fatalf("notes = %+v", n)
	}

	// web-02 is fixed: the real evidence from DefendSec's own record is in the note.
	if err := s.pg.RecordFindingsFor(context.Background(), "dev-web-02", vuln.Result{Coverage: vuln.CoverageFull}, nil,
		&storepg.Inventory{Scheme: vuln.SchemeDpkg, Versions: map[string]string{"openssl": "1.1"}}); err != nil {
		t.Fatal(err)
	}
	if r := live(); r.Noted != 1 {
		t.Fatalf("%+v", r)
	}
	n := srv.Notes(id)
	if len(n) != 2 || !strings.Contains(n[1].Description, "web-02: openssl 1.1 observed, at or above the fixed version 1.1 (1 finding closed)") {
		t.Fatalf("notes = %+v", n)
	}
	got := atkLedger(t, pool)
	if got["autotask_ticket_created"] != 1 || got["autotask_ticket_note_added"] != 2 {
		t.Fatalf("ledger = %v", got)
	}
	if err := s.pg.RecordFindingsFor(context.Background(), "dev-web-01", vuln.Result{Coverage: vuln.CoverageFull}, nil,
		&storepg.Inventory{Scheme: vuln.SchemeDpkg, Versions: map[string]string{"openssl": "1.1"}}); err != nil {
		t.Fatal(err)
	}
	if r := live(); r.Noted != 1 || srv.Tickets()[0].CompletedDate != nil {
		t.Fatalf("%+v: all fixed, ticket left open (auto-complete is off)", r)
	}
	var state string
	if err := pool.QueryRow(context.Background(), `SELECT state FROM autotask_tickets`).Scan(&state); err != nil || state != "resolved" {
		t.Errorf("state = %q, %v", state, err)
	}
}

func TestAutotaskDryRunWithoutCredentialsIsShownUnverified(t *testing.T) {
	s, _, srv := atkScratch(t)
	s.SetAutotaskDesk(func(autotask.Settings) (autotask.Desk, error) { return nil, os.ErrNotExist })
	atkSeedVuln(t, s.pg, "web-01", true)
	surfReq(t, s.HandleAutotask, "PUT", "/v1/autotask/settings", "admin-token", atkSettingsBody())
	rec := surfReq(t, s.HandleAutotask, "POST", "/v1/autotask/run", "admin-token", map[string]any{"wait": true})
	r := decode[storepg.AutotaskRun](t, rec)
	if rec.Code != 200 || r.Verified || !strings.Contains(r.UnverifiedWhy, "Autotask was not read") || len(r.Ops) != 1 || r.Ops[0].Create == nil {
		t.Fatalf("run = %d %+v", rec.Code, r)
	}
	if len(srv.Requests()) != 0 {
		t.Error("requests without credentials")
	}
	// It cannot unlock live, and a live run without credentials is not attempted.
	st := decode[map[string]any](t, surfReq(t, s.HandleAutotask, "GET", "/v1/autotask/status", "viewer-token", nil))
	if st["liveUnlocked"] != false {
		t.Error("an unverified dry run unlocked live")
	}
	body := atkSettingsBody()
	body["mode"] = "live"
	if c := surfReq(t, s.HandleAutotask, "PUT", "/v1/autotask/settings", "admin-token", body).Code; c != 400 {
		t.Errorf("live = %d", c)
	}
}

func TestAutotaskOnlyOneRunAtATimeAndAsyncAnswers202(t *testing.T) {
	s, _, _ := atkScratch(t)
	h := s.HandleAutotask
	surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", atkSettingsBody())
	if !s.claimAutotask() {
		t.Fatal("claim")
	}
	if c := surfReq(t, h, "POST", "/v1/autotask/run", "admin-token", map[string]any{"wait": true}).Code; c != 409 {
		t.Errorf("a run during a run = %d, want 409", c)
	}
	s.releaseAutotask()
	rec := surfReq(t, h, "POST", "/v1/autotask/run", "admin-token", nil)
	if rec.Code != 202 || !strings.Contains(rec.Body.String(), `"dryRun":true`) {
		t.Fatalf("async run = %d %s: a run with no body is a dry run", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.atkr.mu.Lock()
		running := s.atkr.running
		s.atkr.mu.Unlock()
		if !running {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	list, _ := s.pg.ListAutotaskRuns(context.Background(), 5)
	if len(list) != 1 || list[0].Mode != "dry_run" {
		t.Fatalf("runs = %+v", list)
	}
}

func TestAutotaskScheduleActsOnlyForLiveInstances(t *testing.T) {
	s, _, srv := atkScratch(t)
	h := s.HandleAutotask
	ctx := context.Background()
	atkSeedVuln(t, s.pg, "web-01", true)

	if s.autotaskScheduleOnce(ctx) {
		t.Fatal("the schedule ran with nothing configured")
	}
	body := atkSettingsBody()
	surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", body)
	if s.autotaskScheduleOnce(ctx) || len(srv.Requests()) != 0 {
		t.Fatal("the schedule touched a dry-run instance")
	}
	surfReq(t, h, "POST", "/v1/autotask/run", "admin-token", map[string]any{"wait": true})
	body["mode"] = "live"
	if c := surfReq(t, h, "PUT", "/v1/autotask/settings", "admin-token", body).Code; c != 200 {
		t.Fatal("live")
	}
	if len(srv.Tickets()) != 0 {
		t.Fatal("going live made a ticket by itself")
	}
	if !s.autotaskScheduleOnce(ctx) || len(srv.Tickets()) != 1 {
		t.Fatalf("a live instance was not reconciled: %d tickets", len(srv.Tickets()))
	}
	if s.autotaskScheduleOnce(ctx) {
		t.Fatal("the schedule ran again inside its interval")
	}
	runs, _ := s.pg.ListAutotaskRuns(ctx, 10)
	if runs[0].TriggeredBy != "schedule" || runs[0].Mode != "live" {
		t.Errorf("run = %+v", runs[0])
	}
	// Credentials gone: nothing is attempted.
	s.atkr.interval = time.Nanosecond
	s.SetAutotaskDesk(func(autotask.Settings) (autotask.Desk, error) { return nil, os.ErrNotExist })
	time.Sleep(2 * time.Millisecond)
	if s.autotaskScheduleOnce(ctx) {
		t.Fatal("the schedule ran without credentials")
	}
}
