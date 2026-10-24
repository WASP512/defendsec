package rmm_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/feeds"
	"defendsec/internal/presence"
	"defendsec/internal/rmm"
	"defendsec/internal/rmm/datto"
	"defendsec/internal/rmm/dattotest"
	"defendsec/internal/storepg"
)

// scratch gives each test its own database: the exposure queries count the
// whole database, so tests cannot share one.
func scratch(t *testing.T) (*storepg.Store, *pgxpool.Pool) {
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
	name := "defendsec_mig_rmm_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Fatalf("create database: %v", err)
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
	return storepg.New(pool), pool
}

// seedMSRC loads what the Microsoft feed would: two CVEs fixed by KB5000001
// (one of them on the KEV list) and one fixed by KB5000002.
func seedMSRC(t *testing.T, st *storepg.Store) {
	t.Helper()
	ctx := context.Background()
	snap, err := st.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "msrc", URL: "https://api.msrc.microsoft.com/cvrf/v3.0",
		FetchedAt: time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC), SHA256: strings.Repeat("a", 64), RecordCount: 3}})
	if err != nil {
		t.Fatal(err)
	}
	load, err := st.BeginFeedLoad(ctx, "msrc", []storepg.RangeScope{{Distro: "windows"}}, snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	score := 8.8
	rng := func(kb string) feeds.Range {
		return feeds.Range{Ecosystem: "MSRC", Distro: "windows", Package: kb, Fixed: kb, State: feeds.Fixed, Issued: "2026-10-13"}
	}
	for _, a := range []feeds.Advisory{
		{ID: "CVE-2099-0001", CVE: "CVE-2099-0001", Summary: "Windows Kernel Elevation of Privilege", Severity: "high", CVSSScore: &score, Ranges: []feeds.Range{rng("KB5000001")}},
		{ID: "CVE-2099-0002", CVE: "CVE-2099-0002", Summary: "NTFS Information Disclosure", Severity: "medium", Ranges: []feeds.Range{rng("KB5000001")}},
		{ID: "CVE-2099-0003", CVE: "CVE-2099-0003", Summary: ".NET Denial of Service", Severity: "medium", Ranges: []feeds.Range{rng("KB5000002")}},
	} {
		if err := load.Add(ctx, storepgAdvisory(a)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := load.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyKEV(ctx, []storepg.KEVRow{{CVE: "CVE-2099-0001", Added: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), Name: "Windows kernel EoP"}}, snap.ID); err != nil {
		t.Fatal(err)
	}
}

func storepgAdvisory(a feeds.Advisory) storepg.Advisory {
	out := storepg.Advisory{ID: a.ID, CVE: a.CVE, Summary: a.Summary, Severity: a.Severity, CVSSScore: a.CVSSScore, CVSSVector: a.CVSSVector}
	for _, r := range a.Ranges {
		out.Ranges = append(out.Ranges, storepg.AdvisoryRange{Ecosystem: r.Ecosystem, Distro: r.Distro, Release: r.Release, Package: r.Package,
			Fixed: r.Fixed, FixState: storepg.FixState(r.State), Issued: r.Issued})
	}
	return out
}

type rig struct {
	t      *testing.T
	store  *storepg.Store
	pool   *pgxpool.Pool
	srv    *dattotest.Server
	client *datto.Client
	syncer *rmm.Syncer
	now    time.Time
}

// newRig wires a Syncer to a fake Datto API and a scratch database, with the
// Microsoft feed seeded and Site1 selected. "now" is a few hours after the
// fixture's Windows 10 audit, so that device is fresh and the server's audit
// (33 days old) is stale.
func newRig(t *testing.T) *rig {
	t.Helper()
	store, pool := scratch(t)
	seedMSRC(t, store)
	srv := dattotest.New(t)
	now := time.UnixMilli(1792824000000 + 3600*1000).UTC()
	c, err := datto.New(datto.Config{APIURL: srv.URL, Key: dattotest.Key, Secret: dattotest.Secret, UnsafeAllowAnyURL: true,
		RequestsPerSecond: 1000, Now: func() time.Time { return now }, Sleep: func(context.Context, time.Duration) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRMMSettings(context.Background(), "admin", dattotest.Site1, "Demo Client One", 7); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, store: store, pool: pool, srv: srv, client: c, now: now}
	r.syncer = &rmm.Syncer{Src: c, Store: store, Now: func() time.Time { return r.now }, Sleep: func(context.Context, time.Duration) error { return nil }}
	return r
}

func (r *rig) sync() storepg.RMMSync {
	r.t.Helper()
	out, err := r.syncer.Sync(context.Background(), "test")
	if err != nil {
		r.t.Fatalf("sync: %v", err)
	}
	return out
}

func (r *rig) count(sql string, args ...any) int {
	r.t.Helper()
	var n int
	if err := r.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		r.t.Fatal(err)
	}
	return n
}

func (r *rig) text(sql string, args ...any) string {
	r.t.Helper()
	var s string
	if err := r.pool.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		r.t.Fatal(err)
	}
	return s
}

var win10ID = storepg.RMMDeviceID(dattotest.Win10)
var srvID = storepg.RMMDeviceID(dattotest.Server2019)

func TestSyncReadsTheSiteAndMapsMissingKBsToCVEs(t *testing.T) {
	r := newRig(t)
	got := r.sync()
	if got.Status != "ok" || got.Devices != 3 || got.Windows != 2 || got.Skipped != 1 || got.Stale != 1 || got.Unreadable != 0 {
		t.Fatalf("sync = %+v", got)
	}
	if got.KBsMissing != 2 || got.KBsUnmapped != 0 || got.FindingsOpen != 3 || got.Requests == 0 {
		t.Errorf("sync counts = %+v", got)
	}

	// The device row: Windows 10, built from the audit, with the software and the pending list.
	var os, ver, serial, plat, src, model string
	var online bool
	if err := r.pool.QueryRow(context.Background(), `SELECT os_name, os_version, serial, platform, source, hardware_model, connected FROM devices WHERE id = $1`, win10ID).
		Scan(&os, &ver, &serial, &plat, &src, &model, &online); err != nil {
		t.Fatal(err)
	}
	if os != "Microsoft Windows 10 Pro" || ver != "10.0.19045" || serial != "DEMOSERIAL001" || plat != "windows" || src != "rmm" || model != "Demo Computers DemoBook 14" || !online {
		t.Errorf("device row: %q %q %q %q %q %q %v", os, ver, serial, plat, src, model, online)
	}
	if n := r.count(`SELECT jsonb_array_length(software) FROM devices WHERE id = $1`, win10ID); n != 3 {
		t.Errorf("software = %d, want 3 across two pages", n)
	}
	if n := r.count(`SELECT jsonb_array_length(pending_updates) FROM devices WHERE id = $1`, win10ID); n != 3 {
		t.Errorf("pending updates = %d, want 3 (two approved-pending and one not approved)", n)
	}
	// RMM's own facts, and the per-KB list, with the update that has no KB kept but unmapped.
	if r.text(`SELECT patch_status FROM rmm_devices WHERE device_id = $1`, win10ID) != "ApprovedPending" ||
		r.count(`SELECT patches_installed FROM rmm_devices WHERE device_id = $1`, win10ID) != 412 ||
		r.text(`SELECT os_build || '/' || os_display FROM rmm_devices WHERE device_id = $1`, win10ID) != "19045/22H2" {
		t.Error("rmm_devices facts missing")
	}
	if n := r.count(`SELECT count(*) FROM rmm_patches WHERE device_id = $1`, win10ID); n != 3 {
		t.Errorf("rmm_patches = %d", n)
	}
	if n := r.count(`SELECT count(*) FROM rmm_patches WHERE device_id = $1 AND kb = ''`, win10ID); n != 1 {
		t.Errorf("the definition update has no KB and must be stored with none, got %d", n)
	}
	if n := r.count(`SELECT count(*) FROM rmm_patches WHERE device_id = $1 AND kb = 'KB5000002' AND install_status = 'NOT_APPROVED' AND release_date = DATE '2099-01-14'`, win10ID); n != 1 {
		t.Errorf("KB5000002 not stored as not approved with its date")
	}

	// Findings: vendor fix, one per (CVE, KB), straight from the KB list.
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND kind = 'finding' AND basis = 'distro' AND feed = 'msrc' AND resolved_at IS NULL AND fixed = package AND installed = 'not installed'`, win10ID); n != 3 {
		t.Errorf("findings = %d, want 3", n)
	}
	if !strings.Contains(r.text(`SELECT reason FROM vuln_findings WHERE device_id = $1 AND cve = 'CVE-2099-0002'`, win10ID), "approved in the RMM patch policy and waiting to install") {
		t.Errorf("reason does not say how RMM classes the update")
	}
	if r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, win10ID) != "covered" {
		t.Error("the fresh device is not covered")
	}
	if r.count(`SELECT kbs_missing * 10 + kbs_mapped FROM host_patch_state WHERE device_id = $1`, win10ID) != 22 {
		t.Error("kbs missing/mapped not recorded")
	}

	// The stale server is stored, not assessed, and has no findings.
	if r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, srvID) != "stale" {
		t.Error("the server with a 33-day-old audit is not marked stale")
	}
	if !strings.Contains(r.text(`SELECT reason FROM host_patch_state WHERE device_id = $1`, srvID), "missing, not clean") {
		t.Errorf("stale reason = %q", r.text(`SELECT reason FROM host_patch_state WHERE device_id = $1`, srvID))
	}
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1`, srvID); n != 0 {
		t.Errorf("a stale device has %d findings", n)
	}
	// Nothing was read for it beyond the device list: no audit, software or patches.
	for _, req := range r.srv.Requests() {
		if strings.Contains(req.Path, dattotest.Server2019) || strings.Contains(req.Path, dattotest.Printer) {
			t.Errorf("a stale or non-Windows device was read: %s", req.Path)
		}
	}
	// The printer is not a host.
	if n := r.count(`SELECT count(*) FROM devices WHERE id = $1`, storepg.RMMDeviceID(dattotest.Printer)); n != 0 {
		t.Error("a printer became a host")
	}

	// The sync is on the record and in the audit chain.
	if r.count(`SELECT count(*) FROM rmm_syncs WHERE status = 'ok' AND windows = 2`) != 1 {
		t.Error("sync not recorded")
	}
	if r.count(`SELECT count(*) FROM audit_log WHERE action = 'rmm_sync_recorded' AND actor = 'system:rmm-collector'`) != 1 {
		t.Error("sync not chained in the audit log")
	}
	if r.count(`SELECT count(*) FROM audit_log WHERE action = 'rmm_site_selected'`) != 1 {
		t.Error("site selection not chained in the audit log")
	}
	// Datto saw no secret in a URL and only reads: the fake fails the test on any non-GET.
	for _, req := range r.srv.Requests() {
		if strings.Contains(req.Path, dattotest.Secret) {
			t.Errorf("secret in a path: %s", req.Path)
		}
	}
}

func TestMissingKBThatFixesKEVRanksFirstInFixThisWeek(t *testing.T) {
	r := newRig(t)
	r.sync()
	page, err := r.store.ListExposure(context.Background(), storepg.ExposureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 3 || page.Total != 3 {
		t.Fatalf("exposure = %d rows, total %d", len(page.Findings), page.Total)
	}
	top := page.Findings[0]
	if top.AdvisoryID != "CVE-2099-0001" || !top.KEV {
		t.Fatalf("first row = %+v; a missing KB that fixes a KEV CVE must be on top", top)
	}
	if len(top.Hosts) != 1 || top.Hosts[0].Hostname != "DEMO-PC-01" || len(top.Packages) != 1 || top.Packages[0] != "KB5000001" {
		t.Errorf("top row hosts %+v packages %+v", top.Hosts, top.Packages)
	}
	// And it counts in the fixable summary and the KEV part of it.
	sum, err := r.store.ExposureSummary(context.Background(), r.now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Fixable.Findings != 3 || sum.Fixable.KEV.Findings != 1 {
		t.Errorf("summary fixable = %+v", sum.Fixable)
	}
	// Hosts: both RMM hosts count. The fresh one is assessed; the stale one is not.
	if sum.Hosts.Total != 2 || sum.Hosts.Assessed != 1 || sum.Hosts.NotAssessed != 1 {
		t.Errorf("hosts = %+v", sum.Hosts)
	}
	// The trend sees them too.
	// The fixture's clock is fixed, but the database stamps first-seen with its own
	// clock, so the trend is asked about the real today.
	real := time.Now().UTC()
	tr, err := r.store.ExposureTrend(context.Background(), real.AddDate(0, 0, -3), real, real.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	last := tr.Points[len(tr.Points)-1]
	if last.Open != 3 || last.KEV != 1 {
		t.Errorf("trend today = %+v", last)
	}
}

func TestFixedPatchClosesTheFindingAsFixed(t *testing.T) {
	r := newRig(t)
	r.sync()
	// KB5000001 gets installed; the RMM now lists only the not-approved .NET update.
	r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=APPROVED_PENDING"] =
		`{"pageDetails":{"count":0,"totalCount":0,"prevPageUrl":null,"nextPageUrl":null},"patches":[]}`
	r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=INSTALLED"] =
		`{"pageDetails":{"nextPageUrl":null},"patches":[{"patchId":"p-0001","kbArticleId":"KB5000001","installStatus":"INSTALLED"}]}`
	r.now = r.now.Add(time.Hour)
	got := r.sync()
	if got.FindingsOpen != 1 {
		t.Fatalf("open findings = %d, want only the .NET one", got.FindingsOpen)
	}
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND package = 'KB5000001' AND resolved_at IS NOT NULL AND resolution = 'fixed' AND resolved_installed = 'installed'`, win10ID); n != 2 {
		t.Errorf("closed-as-fixed findings = %d, want 2 (two CVEs)", n)
	}
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND package = 'KB5000002' AND resolved_at IS NULL`, win10ID); n != 1 {
		t.Errorf("the still-missing KB lost its finding")
	}
	installed := 0
	for _, req := range r.srv.Requests() {
		if req.Query.Get("installStatus") == "INSTALLED" {
			installed++
		}
	}
	if installed != 1 {
		t.Errorf("installed patches requested %d times; once, to say why a finding closed", installed)
	}
	// The closed KEV finding is off the list; open on A, closed on B is in the intervals/resolved list.
	page, err := r.store.ListExposure(context.Background(), storepg.ExposureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 1 || page.Findings[0].AdvisoryID != "CVE-2099-0003" {
		t.Errorf("open list after the fix = %+v", page.Findings)
	}
	resolved, err := r.store.ListExposure(context.Background(), storepg.ExposureQuery{Status: storepg.ExposureResolved, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Findings) != 2 {
		t.Errorf("resolved list = %d rows, want 2", len(resolved.Findings))
	}
}

func TestPatchNoLongerListedAndNotInstalledIsNoLongerAffected(t *testing.T) {
	r := newRig(t)
	r.sync()
	r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=APPROVED_PENDING"] =
		`{"pageDetails":{"nextPageUrl":null},"patches":[]}`
	// INSTALLED does not list it: it was superseded or withdrawn.
	r.now = r.now.Add(time.Hour)
	r.sync()
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND package = 'KB5000001' AND resolution = 'no_longer_affected'`, win10ID); n != 2 {
		t.Errorf("no_longer_affected = %d, want 2", n)
	}
}

func TestStaleAuditKeepsFindingsAndIsNeverClean(t *testing.T) {
	r := newRig(t)
	r.sync()
	if r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID) != 3 {
		t.Fatal("setup: three open findings")
	}
	// Eight days later RMM has not audited the PC again. The device list still says
	// the old audit date, and the (now empty) patch list must not be believed.
	r.now = r.now.Add(8 * 24 * time.Hour)
	r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=APPROVED_PENDING"] =
		`{"pageDetails":{"nextPageUrl":null},"patches":[]}`
	r.srv.Override["/api/v2/device/"+dattotest.Win10+"/patches?installStatus=NOT_APPROVED"] =
		`{"pageDetails":{"nextPageUrl":null},"patches":[]}`
	got := r.sync()
	if got.Stale != 2 || got.Status != "ok" {
		t.Fatalf("sync = %+v", got)
	}
	if r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, win10ID) != "stale" {
		t.Error("a device with an 8-day-old audit is not stale")
	}
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID); n != 3 {
		t.Errorf("open findings = %d: stale evidence must not close findings", n)
	}
	sum, err := r.store.ExposureSummary(context.Background(), r.now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts.Assessed != 0 || sum.Hosts.NotAssessed != 2 {
		t.Errorf("hosts = %+v: a stale device is not assessed", sum.Hosts)
	}
	rs, err := r.store.RMMSummary(context.Background(), r.now)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Stale != 2 || rs.Covered != 0 {
		t.Errorf("rmm summary = %+v", rs)
	}
}

// A device that was covered at the last read ages out between reads: the stored
// coverage says what the last read saw, the summary says what may be said today.
func TestCoveredEvidenceAgesOutBetweenReads(t *testing.T) {
	r := newRig(t)
	r.sync()
	sum, _ := r.store.ExposureSummary(context.Background(), r.now)
	if sum.Hosts.Assessed != 1 {
		t.Fatalf("setup: assessed = %d", sum.Hosts.Assessed)
	}
	later := r.now.Add(9 * 24 * time.Hour) // no sync ran: the RMM could not be reached for days
	sum, err := r.store.ExposureSummary(context.Background(), later)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts.Assessed != 0 {
		t.Errorf("assessed = %d nine days after the last audit", sum.Hosts.Assessed)
	}
	rs, _ := r.store.RMMSummary(context.Background(), later)
	if rs.Covered != 0 || rs.Stale != 2 {
		t.Errorf("rmm summary after 9 days = covered %d stale %d", rs.Covered, rs.Stale)
	}
	rows, _ := r.store.ListRMMDevices(context.Background(), later, 10)
	for _, row := range rows {
		if row.Coverage != "stale" {
			t.Errorf("%s coverage %q", row.Hostname, row.Coverage)
		}
	}
}

func TestWrongCredentialsAreNotAssessedAndLeaveEvidenceAlone(t *testing.T) {
	r := newRig(t)
	r.sync()
	bad, err := datto.New(datto.Config{APIURL: r.srv.URL, Key: "wrong", Secret: "wrong", UnsafeAllowAnyURL: true, RequestsPerSecond: 1000})
	if err != nil {
		t.Fatal(err)
	}
	r.syncer.Src = bad
	got := r.sync()
	if got.Status != "not_assessed" || !strings.Contains(got.Reason, "refused the API key and secret") || got.Devices != 0 {
		t.Fatalf("sync = %+v", got)
	}
	if strings.Contains(got.Reason, "wrong") && strings.Contains(got.Reason, "secret wrong") {
		t.Errorf("reason echoes a credential: %q", got.Reason)
	}
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID); n != 3 {
		t.Errorf("a failed read changed findings: %d open", n)
	}
	if n := r.count(`SELECT count(*) FROM devices WHERE source = 'rmm' AND NOT revoked`); n != 2 {
		t.Errorf("a failed read retired devices: %d live", n)
	}
	latest, err := r.store.LatestRMMSync(context.Background())
	if err != nil || latest == nil || latest.Status != "not_assessed" {
		t.Errorf("latest sync = %+v %v", latest, err)
	}
}

func windowsDevices(n int) string {
	var devs []string
	for i := 1; i <= n; i++ {
		devs = append(devs, fmt.Sprintf(`{"uid":"dddddddd-0000-4000-8000-0000000001%02d","hostname":"BULK-%02d","operatingSystem":"Microsoft Windows 11 Pro","deviceClass":"device","online":true,"lastSeen":1792824000000,"lastAuditDate":1792800000000}`, i, i))
	}
	return `{"pageDetails":{"nextPageUrl":null},"devices":[` + strings.Join(devs, ",") + `]}`
}

func TestForbiddenStopsAfterThreeInARow(t *testing.T) {
	r := newRig(t)
	r.srv.Override["/api/v2/site/"+dattotest.Site1+"/devices"] = windowsDevices(6)
	r.srv.Force("/api/v2/audit/device/", http.StatusForbidden, 0, 0, "")
	got := r.sync()
	if got.Status != "not_assessed" || got.Windows != 6 || got.Unreadable != 6 {
		t.Fatalf("sync = %+v", got)
	}
	if !strings.Contains(got.Reason, "403 Forbidden") {
		t.Errorf("reason = %q", got.Reason)
	}
	if n := r.srv.Count("/api/v2/audit/device/"); n != 3 {
		t.Errorf("audit requests = %d; after three 403s in a row the collector must stop asking (Datto blocks the address)", n)
	}
}

func TestRateLimitStopsTheRunWithAPartialResult(t *testing.T) {
	r := newRig(t)
	r.srv.Override["/api/v2/site/"+dattotest.Site1+"/devices"] = windowsDevices(4)
	for i := 1; i <= 4; i++ {
		r.srv.Override[fmt.Sprintf("/api/v2/audit/device/dddddddd-0000-4000-8000-0000000001%02d", i)] = r.srv.Fixture("audit_win10.json")
	}
	// Two devices are read (two patch requests each), then Datto answers 429 and keeps doing so.
	r.srv.Force("/patches", http.StatusTooManyRequests, 4, 0, "")
	got := r.sync()
	if got.Status != "partial" || got.Windows != 4 {
		t.Fatalf("sync = %+v", got)
	}
	if !strings.Contains(got.Reason, "rate limiting") {
		t.Errorf("reason = %q", got.Reason)
	}
	if got.Unreadable != 2 {
		t.Errorf("unreadable = %d, want the device that hit the limit and the one after it", got.Unreadable)
	}
	// The cut-off devices are still on record, not retired for being unseen, and the
	// run did not start asking again after the limit: three attempts on the third device, none after.
	if n := r.count(`SELECT count(*) FROM devices WHERE source = 'rmm' AND NOT revoked`); n != 3 {
		t.Errorf("live devices = %d, want the two that were read and the one that hit the limit", n)
	}
	if n := r.srv.Count("/patches"); n != 4+3 {
		t.Errorf("patch requests = %d, want 4 and then the 429 retried twice", n)
	}
}

func TestDeviceThatCannotBeReadKeepsItsFindingsAndTheRunIsPartial(t *testing.T) {
	r := newRig(t)
	r.sync()
	r.srv.Force("/api/v2/audit/device/"+dattotest.Win10, http.StatusInternalServerError, 0, 0, "")
	r.now = r.now.Add(time.Hour)
	got := r.sync()
	if got.Status != "partial" || got.Unreadable != 1 || len(got.Errors) != 1 || !strings.Contains(got.Errors[0], "audit") {
		t.Fatalf("sync = %+v", got)
	}
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID); n != 3 {
		t.Errorf("a read error closed findings: %d open", n)
	}
	if r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, win10ID) != "no_data" {
		t.Error("an unreadable device is not marked no_data")
	}
	if r.text(`SELECT collect_error FROM rmm_devices WHERE device_id = $1`, win10ID) == "" {
		t.Error("the reason is not stored on the device")
	}
}

func TestSoftwareFailureDoesNotStopThePatchMatch(t *testing.T) {
	r := newRig(t)
	r.srv.Force("/software", http.StatusInternalServerError, 0, 0, "")
	got := r.sync()
	if got.Status != "ok" || got.FindingsOpen != 3 {
		t.Fatalf("sync = %+v", got)
	}
	if !strings.Contains(r.text(`SELECT collect_error FROM rmm_devices WHERE device_id = $1`, win10ID), "software") {
		t.Error("the software failure is not noted on the device")
	}
	if n := r.count(`SELECT jsonb_array_length(software) FROM devices WHERE id = $1`, win10ID); n != 0 {
		t.Errorf("software = %d with nothing read", n)
	}
}

func TestNoMicrosoftFeedIsNoFeedNotClean(t *testing.T) {
	store, pool := scratch(t)
	srv := dattotest.New(t)
	now := time.UnixMilli(1792824000000 + 3600*1000).UTC()
	c, _ := datto.New(datto.Config{APIURL: srv.URL, Key: dattotest.Key, Secret: dattotest.Secret, UnsafeAllowAnyURL: true, RequestsPerSecond: 1000,
		Sleep: func(context.Context, time.Duration) error { return nil }})
	if err := store.SetRMMSettings(context.Background(), "admin", dattotest.Site1, "x", 7); err != nil {
		t.Fatal(err)
	}
	s := &rmm.Syncer{Src: c, Store: store, Now: func() time.Time { return now }}
	got, err := s.Sync(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ok" || got.FindingsOpen != 0 {
		t.Fatalf("sync = %+v", got)
	}
	var cov, reason string
	if err := pool.QueryRow(context.Background(), `SELECT coverage, reason FROM host_patch_state WHERE device_id = $1`, win10ID).Scan(&cov, &reason); err != nil {
		t.Fatal(err)
	}
	if cov != "no_feed" || !strings.Contains(reason, "no Microsoft update feed") {
		t.Errorf("coverage %q reason %q", cov, reason)
	}
	sum, _ := store.ExposureSummary(context.Background(), now)
	if sum.Hosts.Assessed != 0 {
		t.Errorf("assessed = %d with no feed", sum.Hosts.Assessed)
	}
}

func TestSyncWithNoSiteSelected(t *testing.T) {
	store, _ := scratch(t)
	s := &rmm.Syncer{Src: nil, Store: store}
	if _, err := s.Sync(context.Background(), "test"); err != rmm.ErrNoSite {
		t.Fatalf("err = %v", err)
	}
}

func TestDeviceThatLeftTheSiteIsRetired(t *testing.T) {
	r := newRig(t)
	r.sync()
	// The server and the PC both leave the site's device list.
	r.srv.Override["/api/v2/site/"+dattotest.Site1+"/devices"] = windowsDevices(1)
	r.now = r.now.Add(time.Hour)
	r.sync()
	if n := r.count(`SELECT count(*) FROM devices WHERE id = $1 AND revoked`, win10ID); n != 1 {
		t.Error("the PC that left the site was not retired")
	}
	page, err := r.store.ListExposure(context.Background(), storepg.ExposureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 0 {
		t.Errorf("a retired device still has %d advisories in Fix this week", len(page.Findings))
	}
	// The rows stay as evidence.
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1`, win10ID); n != 3 {
		t.Errorf("findings of the retired device were deleted: %d", n)
	}
	// It comes back if it comes back.
	r.srv.Override["/api/v2/site/"+dattotest.Site1+"/devices"] = r.srv.Fixture("devices_page1.json")
	r.sync()
	if n := r.count(`SELECT count(*) FROM devices WHERE id = $1 AND NOT revoked`, win10ID); n != 1 {
		t.Error("a returning device stayed retired")
	}
}

func TestChangingSiteRetiresTheOldSitesDevices(t *testing.T) {
	r := newRig(t)
	r.sync()
	if err := r.store.SetRMMSettings(context.Background(), "admin", dattotest.Site2, "Demo Client Two", 7); err != nil {
		t.Fatal(err)
	}
	got := r.sync()
	if got.SiteUID != dattotest.Site2 || got.Windows != 0 {
		t.Fatalf("sync = %+v", got)
	}
	if n := r.count(`SELECT count(*) FROM devices WHERE source = 'rmm' AND NOT revoked`); n != 0 {
		t.Errorf("%d devices of the previous site are still live", n)
	}
}

func TestAgentAndRMMReportingTheSameMachineAreOneHost(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	// The DefendSec Windows agent on the same laptop, enrolled earlier.
	if err := r.store.UpsertDevice(ctx, presence.Device{ID: "agent-win-1", Hostname: "demo-pc-01.corp.example", Platform: "windows",
		Serial: "demoserial001", OSName: "Windows 10 Pro", OSVersion: "10.0.19045", LastSeen: r.now.Format(time.RFC3339), Transport: "mtls-grpc"}); err != nil {
		t.Fatal(err)
	}
	// An unrelated agent with the same name and another serial must not be taken for the laptop.
	if err := r.store.UpsertDevice(ctx, presence.Device{ID: "agent-win-2", Hostname: "demo-pc-01", Platform: "windows", Serial: "SOMEONEELSE",
		LastSeen: r.now.Format(time.RFC3339), Transport: "mtls-grpc"}); err != nil {
		t.Fatal(err)
	}
	got := r.sync()
	if got.Merged != 1 {
		t.Fatalf("merged = %d, want 1", got.Merged)
	}
	if r.text(`SELECT merged_into FROM devices WHERE id = $1`, win10ID) != "agent-win-1" ||
		r.text(`SELECT dedupe_basis FROM rmm_devices WHERE device_id = $1`, win10ID) != "serial" {
		t.Error("the RMM device is not merged into the agent by serial")
	}
	if n := r.count(`SELECT count(*) FROM devices WHERE id = $1 AND merged_into IS NULL`, srvID); n != 1 {
		t.Error("the server was merged into an agent")
	}
	// One host in the list and the counts, though both sources keep their rows and facts.
	page, err := r.store.ListDevices(ctx, storepg.DeviceQuery{Limit: 50, Now: r.now})
	if err != nil {
		t.Fatal(err)
	}
	var hostnames []string
	for _, d := range page.Devices {
		hostnames = append(hostnames, d.Hostname+"/"+d.Source)
	}
	if page.Total != 3 {
		t.Errorf("host list = %v, want agent-win-1, agent-win-2 and the server (3 machines, not 4)", hostnames)
	}
	counts, _ := r.store.CountDevices(ctx, r.now)
	if counts.Total != 2 {
		t.Errorf("fleet counts total = %d: only agents are enrolled hosts", counts.Total)
	}
	sum, err := r.store.ExposureSummary(ctx, r.now)
	if err != nil {
		t.Fatal(err)
	}
	// agent-win-1 (assessed through its RMM twin), agent-win-2 (not assessed), the stale server (not assessed).
	if sum.Hosts.Total != 3 || sum.Hosts.Assessed != 1 {
		t.Errorf("hosts = %+v", sum.Hosts)
	}
	// The findings are still there, on the RMM row, and the RMM page says whose they are.
	if n := r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID); n != 3 {
		t.Errorf("findings = %d", n)
	}
	d, err := r.store.GetRMMDevice(ctx, r.now, win10ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.AgentDeviceID != "agent-win-1" || d.MergedInto != "agent-win-1" || d.DedupeBasis != "serial" {
		t.Errorf("detail = %+v", d.RMMDeviceRow)
	}
	// If the agent is revoked or gone the merge is undone on the next read.
	if _, err := r.pool.Exec(ctx, `UPDATE devices SET revoked = true WHERE id IN ('agent-win-1','agent-win-2')`); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(time.Minute)
	got = r.sync()
	if got.Merged != 0 || r.text(`SELECT COALESCE(merged_into, '') FROM devices WHERE id = $1`, win10ID) != "" {
		t.Errorf("merge not undone: %+v", got)
	}
}

func TestMatchAgent(t *testing.T) {
	agents := []storepg.AgentIdentity{
		{ID: "a1", Hostname: "PC-ONE.corp.example", Serial: "ABC12345"},
		{ID: "a2", Hostname: "pc-two", Serial: "To Be Filled By O.E.M."},
		{ID: "a3", Hostname: "pc-three", Serial: "ZZZZZZZZ"},
		{ID: "a4", Hostname: "twin", Serial: "TWIN0001"},
		{ID: "a5", Hostname: "twin", Serial: "TWIN0002"},
		{ID: "a6", Hostname: "clone-a", Serial: "CLONE999"},
		{ID: "a7", Hostname: "clone-b", Serial: "CLONE999"},
	}
	for name, c := range map[string]struct{ serial, host, id, basis string }{
		"serial, case and domain ignored":                          {"abc12345", "x", "a1", "serial"},
		"hostname with FQDN":                                       {"", "PC-ONE", "a1", "hostname"},
		"junk serial falls to hostname":                            {"To Be Filled By O.E.M.", "PC-TWO", "a2", "hostname"},
		"all-same serial is junk":                                  {"00000000", "pc-three", "a3", "hostname"},
		"a different serial is another machine with a reused name": {"OTHER9999", "pc-one", "", ""},
		"two agents with one name":                                 {"", "twin", "", ""},
		"one serial on two agents":                                 {"CLONE999", "clone-a", "", ""},
		"no match":                                                 {"NOSUCH123", "nosuch", "", ""},
		"nothing to match on":                                      {"", "", "", ""},
	} {
		id, basis := rmm.MatchAgent(c.serial, c.host, agents)
		if id != c.id || basis != c.basis {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", name, id, basis, c.id, c.basis)
		}
	}
}

func TestNormalizeOSVersion(t *testing.T) {
	for in, want := range map[string][2]string{
		"10.0.19045":      {"10.0.19045", "19045"},
		"10.0.19045.5247": {"10.0.19045", "19045"},
		" 6.3.9600 ":      {"6.3.9600", "9600"},
		"10.0":            {"", ""},
		"":                {"", ""},
		"Windows 10":      {"", ""},
	} {
		v, b := rmm.NormalizeOSVersion(in)
		if v != want[0] || b != want[1] {
			t.Errorf("%q: got (%q, %q), want %v", in, v, b, want)
		}
	}
}

func TestNeverReadAuditOrSoftwareOfAnUnauditedDevice(t *testing.T) {
	r := newRig(t)
	r.srv.Override["/api/v2/site/"+dattotest.Site1+"/devices"] =
		`{"pageDetails":{"nextPageUrl":null},"devices":[{"uid":"dddddddd-0000-4000-8000-000000000009","hostname":"NEW-PC","operatingSystem":"Microsoft Windows 11 Pro","deviceClass":"device","online":true,"lastSeen":1792824000000,"lastAuditDate":null}]}`
	got := r.sync()
	if got.Windows != 1 || got.Stale != 0 {
		t.Fatalf("sync = %+v", got)
	}
	id := storepg.RMMDeviceID("dddddddd-0000-4000-8000-000000000009")
	if r.text(`SELECT coverage FROM host_patch_state WHERE device_id = $1`, id) != "no_data" {
		t.Error("a never-audited device is not no_data")
	}
	if r.srv.Count("/audit/") != 0 || r.srv.Count("/patches") != 0 {
		t.Error("evidence was requested for a device RMM never audited")
	}
}

// A new KEV listing lands in the findings without waiting for the next read of
// the RMM: the stored missing-update list is matched again against the new
// snapshot.
func TestRematchPicksUpANewKEVListingWithoutAskingTheRMM(t *testing.T) {
	r := newRig(t)
	r.sync()
	ctx := context.Background()
	if r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND cve = 'CVE-2099-0002' AND kev`, win10ID) != 0 {
		t.Fatal("setup: CVE-2099-0002 is not on the KEV list yet")
	}
	if n, err := rmm.Rematch(ctx, r.store, r.now); err != nil || n != 0 {
		t.Fatalf("nothing changed, yet Rematch matched %d (%v)", n, err)
	}
	snap, err := r.store.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "kev", URL: "https://example.invalid/kev", FetchedAt: r.now, SHA256: strings.Repeat("b", 64), RecordCount: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.ApplyKEV(ctx, []storepg.KEVRow{
		{CVE: "CVE-2099-0001", Added: r.now.AddDate(0, 0, -4), Name: "a"}, {CVE: "CVE-2099-0002", Added: r.now, Name: "b"}}, snap.ID); err != nil {
		t.Fatal(err)
	}
	before := r.srv.Requests()
	n, err := rmm.Rematch(ctx, r.store, r.now)
	if err != nil || n != 1 {
		t.Fatalf("Rematch = %d, %v; want the one covered device", n, err)
	}
	if len(r.srv.Requests()) != len(before) {
		t.Error("Rematch asked the RMM for something")
	}
	if r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND cve = 'CVE-2099-0002' AND kev AND resolved_at IS NULL`, win10ID) != 1 {
		t.Error("the new KEV listing did not reach the finding")
	}
	if r.count(`SELECT count(*) FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL`, win10ID) != 3 {
		t.Error("re-matching changed the set of open findings")
	}
	if n, _ := rmm.Rematch(ctx, r.store, r.now); n != 0 {
		t.Errorf("a second Rematch matched %d devices again for the same snapshot", n)
	}
	// A device whose evidence has aged out is left alone.
	snap2, _ := r.store.RecordFeedSnapshot(ctx, []storepg.FeedRef{{Name: "kev", URL: "https://example.invalid/kev", FetchedAt: r.now, SHA256: strings.Repeat("c", 64), RecordCount: 2}})
	_ = snap2
	if n, _ := rmm.Rematch(ctx, r.store, r.now.AddDate(0, 0, 10)); n != 0 {
		t.Errorf("a stale device was re-matched (%d)", n)
	}
}
