package storepg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/internal/evidence"
	"defendsec/internal/exposure"
	"defendsec/internal/surface"
	"defendsec/internal/vuln"
)

// Slice 7b: surface findings in the exposure view. Every test runs in a
// throwaway database (scratchStore) because the list, summary and trend count
// the whole database.

// seedMixed puts four vulnerabilities and an external surface (two assets, one
// not confirmed) into s and returns the key of each surface finding by
// "<finding id>/<subject>".
func seedMixed(t *testing.T, s *Store, now time.Time) map[string]string {
	t.Helper()
	ctx := context.Background()
	advs := []expoAdv{
		{"V-kev", "CVE-2099-1001", "high", true, "2026-09-01", f64(0.10), f64(7.0)},
		{"V-epss", "CVE-2099-1002", "medium", false, "", f64(0.60), f64(4.0)},
		{"V-cvss6", "CVE-2099-1003", "medium", false, "", nil, f64(6.0)},
		{"V-cvss4", "CVE-2099-1004", "low", false, "", nil, f64(4.0)},
	}
	seedExposure(t, s, advs)
	expoHost(t, s, "h1", "alpha")
	var fs []vuln.Finding
	for i, a := range advs {
		fs = append(fs, expoFinding(a, vuln.KindFinding, "pkg"+itoa(i), "1.0", "1.1"))
	}
	expoRecord(t, s, "h1", fs...)

	dom := surfaceAsset(t, s, "domain", "client.example.com", true)
	ip := surfaceAsset(t, s, "ip", "192.0.2.10", true)
	unconfirmed := surfaceAsset(t, s, "domain", "unconfirmed.example.net", false) // never scanned
	_ = unconfirmed

	t0 := now.Add(-72 * time.Hour)
	if _, err := s.RecordSurfaceScan(ctx, dom.ID, "schedule", report(dom, t0,
		result("spf", true, "", finding("spf", "spf.plus_all", "client.example.com", surface.SevCritical)),
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "client.example.com", surface.SevMedium)),
		result("caa", true, "", finding("caa", "caa.missing", "client.example.com", surface.SevLow)),
		result("dnssec", true, "", finding("dnssec", "dnssec.unsigned", "client.example.com", surface.SevInfo)),
		result("dkim", false, "no selector found among 9 checked"),
	)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSurfaceScan(ctx, ip.ID, "schedule", report(ip, t0.Add(time.Minute),
		result("ports", true, "",
			finding("ports", "ports.open", "445/tcp", surface.SevCritical),
			finding("ports", "ports.open", "3389/tcp", surface.SevHigh),
			finding("ports", "ports.open", "22/tcp", surface.SevInfo)),
	)); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListSurfaceFindings(ctx, SurfaceFindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, f := range list {
		keys[f.FindingID+"/"+f.Subject] = SurfaceKey(f.ID)
	}
	return keys
}

func labelOf(g ExposureGroup) string {
	if g.Surface != nil {
		return g.Surface.ID + "/" + g.Surface.Subject
	}
	return g.AdvisoryID
}

func labels(p ExposurePage) []string {
	var out []string
	for _, g := range p.Findings {
		out = append(out, labelOf(g))
	}
	return out
}

func TestSurfaceFindingsAreRankedWithVulnerabilities(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	keys := seedMixed(t, s, time.Now().UTC())

	page, err := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	// KEV first; then the critical and high surface findings (critical before
	// high, the older finding first among equals) above every vulnerability that
	// is not on KEV; then the rest by EPSS, CVSS-or-equivalent and severity:
	// DMARC p=none (5.0) sits between the CVSS-6 and CVSS-4 vulnerabilities,
	// and the low CAA finding (2.0) after them. Info is never listed.
	want := []string{
		"V-kev",
		"spf.plus_all/client.example.com",
		"ports.open/445/tcp",
		"ports.open/3389/tcp",
		"V-epss",
		"V-cvss6",
		"dmarc.p_none/client.example.com",
		"V-cvss4",
		"caa.missing/client.example.com",
	}
	if got := labels(page); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("order\n got %v\nwant %v", got, want)
	}
	if page.Total != len(want) {
		t.Fatalf("total = %d, want %d", page.Total, len(want))
	}
	for _, g := range page.Findings {
		if g.Surface != nil && (g.Surface.ID == "dnssec.unsigned" || g.Surface.Subject == "22/tcp") {
			t.Fatalf("an info finding is never listed: %+v", g)
		}
	}

	// A surface row carries what the console needs, and no host.
	for _, g := range page.Findings {
		if g.Surface == nil {
			if g.Source != SourceVulnerability {
				t.Fatalf("source of %s = %q", g.AdvisoryID, g.Source)
			}
			continue
		}
		if g.Source != SourceSurface || g.AdvisoryID != keys[g.Surface.ID+"/"+g.Surface.Subject] || g.HostCount != 0 || len(g.Hosts) != 0 {
			t.Fatalf("surface row: %+v", g)
		}
		if g.KEV || g.EPSS != nil || g.CVSS != nil || g.Kinds[0] != "surface" || g.Summary == "" || g.Surface.Fix == "" || g.Surface.AssetValue == "" {
			t.Fatalf("surface row: %+v %+v", g, g.Surface)
		}
	}
}

// The order the database produces is the order internal/exposure defines, and
// paging by cursor returns every row once in that order whatever the page size.
func TestSurfaceOrderMatchesRankingRuleAndPagesByKeyset(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	seedMixed(t, s, time.Now().UTC())

	full, err := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	items := make([]exposure.Item, 0, len(full.Findings))
	byID := map[string]ExposureGroup{}
	for _, g := range full.Findings {
		it := exposure.Item{AdvisoryID: g.AdvisoryID, Severity: g.Severity, KEV: g.KEV, EPSS: g.EPSS, CVSS: g.CVSS, Surface: g.Source == SourceSurface}
		if g.EOL != nil {
			it.EOLStage = g.EOL.Stage
		}
		if g.KEVAdded != nil {
			it.KEVAdded = day(*g.KEVAdded)
		}
		items = append(items, it)
		byID[g.AdvisoryID] = g
	}
	sorted := append([]exposure.Item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return exposure.Compare(sorted[i], sorted[j]) < 0 })
	for i := range items {
		if items[i].AdvisoryID != sorted[i].AdvisoryID {
			t.Fatalf("SQL order differs from exposure.Compare at %d: SQL %s, Go %s", i, items[i].AdvisoryID, sorted[i].AdvisoryID)
		}
	}

	for _, size := range []int{1, 2, 4, 200} {
		var got []string
		cursor := ""
		for pages := 0; pages < 20; pages++ {
			p, err := s.ListExposure(ctx, ExposureQuery{Limit: size, Cursor: cursor})
			if err != nil {
				t.Fatalf("limit %d: %v", size, err)
			}
			got = append(got, labels(p)...)
			if p.Next == "" {
				break
			}
			cursor = p.Next
		}
		if strings.Join(got, "|") != strings.Join(labels(full), "|") {
			t.Fatalf("limit %d paged to\n %v\nwant\n %v", size, got, labels(full))
		}
	}
}

func TestSurfaceFindingsNeverEnterWatchKEVOrOtherLists(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	seedMixed(t, s, time.Now().UTC())

	watch, err := s.ListExposure(ctx, ExposureQuery{Bucket: BucketWatch, Limit: 200})
	if err != nil || len(watch.Findings) != 0 {
		t.Fatalf("surface findings are work, never 'nothing to install': %v %v", err, labels(watch))
	}
	kev, err := s.ListExposure(ctx, ExposureQuery{KEVOnly: true, Limit: 200})
	if err != nil || strings.Join(labels(kev), "|") != "V-kev" {
		t.Fatalf("kevOnly must keep only exploited vulnerabilities: %v %v", err, labels(kev))
	}
	resolved, err := s.ListExposure(ctx, ExposureQuery{Status: ExposureResolved, Limit: 200})
	if err != nil || len(resolved.Findings) != 0 {
		t.Fatalf("nothing is resolved yet: %v %v", err, labels(resolved))
	}
}

func TestSurfaceFindingsResolveRemoveAndStayOutOfCounts(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedMixed(t, s, now)

	// A later scan sees DMARC fixed: it moves to the Resolved list.
	assets, _ := s.ListSurfaceAssets(ctx)
	var dom, ip SurfaceAsset
	for _, a := range assets {
		switch a.Value {
		case "client.example.com":
			dom = a
		case "192.0.2.10":
			ip = a
		}
	}
	if _, err := s.RecordSurfaceScan(ctx, dom.ID, "manual", report(dom, now.Add(-time.Hour),
		result("spf", true, "", finding("spf", "spf.plus_all", "client.example.com", surface.SevCritical)),
		result("dmarc", true, ""),
		result("caa", true, "", finding("caa", "caa.missing", "client.example.com", surface.SevLow)),
	)); err != nil {
		t.Fatal(err)
	}
	open, _ := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	for _, l := range labels(open) {
		if strings.HasPrefix(l, "dmarc.p_none") {
			t.Fatalf("a resolved finding must leave the fix list: %v", labels(open))
		}
	}
	resolved, err := s.ListExposure(ctx, ExposureQuery{Status: ExposureResolved, Limit: 200})
	if err != nil || strings.Join(labels(resolved), "|") != "dmarc.p_none/client.example.com" || resolved.Findings[0].ResolvedAt == nil {
		t.Fatalf("resolved list: %v %v", err, labels(resolved))
	}

	// Removing an asset hides its findings from the list and the counts but keeps the rows.
	if err := s.RemoveSurfaceAsset(ctx, ip.ID); err != nil {
		t.Fatal(err)
	}
	open, _ = s.ListExposure(ctx, ExposureQuery{Limit: 200})
	for _, l := range labels(open) {
		if strings.HasPrefix(l, "ports.open") {
			t.Fatalf("a removed asset's findings must not be listed: %v", labels(open))
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM surface_findings WHERE asset_id = $1`, ip.ID).Scan(&n); err != nil || n != 3 {
		t.Fatalf("a removed asset keeps its findings as evidence: %d %v", n, err)
	}
	sum, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Surface.Findings != 2 || sum.Surface.Assets != 1 || sum.Fixable.Surface != 2 || sum.Fixable.Total != sum.Fixable.Advisories+2 {
		t.Fatalf("%+v", sum.Surface)
	}
}

// Missing evidence never ranks: a check that could not run produces no finding,
// and a finding whose check now could not run is shown from its last
// confirmation, marked unconfirmed, not dropped and not refreshed.
func TestSurfaceMissingEvidenceNeverRanks(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedMixed(t, s, now)

	page, _ := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	for _, g := range page.Findings {
		if g.Surface != nil && (g.Surface.Check == "dkim" || g.Surface.Unconfirmed) {
			t.Fatalf("the DKIM check could not run and must not appear: %+v", g.Surface)
		}
	}

	dom, _ := s.ListSurfaceAssets(ctx)
	var d SurfaceAsset
	for _, a := range dom {
		if a.Value == "client.example.com" {
			d = a
		}
	}
	if _, err := s.RecordSurfaceScan(ctx, d.ID, "manual", report(d, now.Add(-time.Hour), result("dmarc", false, "SERVFAIL"))); err != nil {
		t.Fatal(err)
	}
	page, _ = s.ListExposure(ctx, ExposureQuery{Limit: 200})
	found := false
	for _, g := range page.Findings {
		if g.Surface != nil && g.Surface.ID == "dmarc.p_none" {
			found = true
			if !g.Surface.Unconfirmed {
				t.Fatalf("the latest DMARC check could not run: the finding must say so: %+v", g.Surface)
			}
			if !g.Surface.LastSeen.Before(now.Add(-48 * time.Hour)) {
				t.Fatalf("last_seen must stay at the last real confirmation: %v", g.Surface.LastSeen)
			}
		}
	}
	if !found {
		t.Fatal("a finding is not dropped because its check could not run today")
	}
	sum, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Surface.ChecksNotAssessed != 2 { // dkim (first scan) and dmarc (just now)
		t.Fatalf("checks not assessed = %d", sum.Surface.ChecksNotAssessed)
	}
}

func TestSurfaceSummaryCounts(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	empty, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Surface.Assets != 0 || empty.Surface.Findings != 0 || empty.Surface.LastScanAt != nil || empty.Surface.BySeverity == nil {
		t.Fatalf("no assets declared: %+v", empty.Surface)
	}

	seedMixed(t, s, now)
	sum, err := s.ExposureSummary(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	sf := sum.Surface
	if sf.Assets != 2 || sf.Unauthorised != 1 || sf.Scanned != 2 || sf.Findings != 5 || sf.Info != 2 || sf.AssetsAffected != 2 {
		t.Fatalf("%+v", sf)
	}
	if sf.BySeverity["critical"] != 2 || sf.BySeverity["high"] != 1 || sf.BySeverity["medium"] != 1 || sf.BySeverity["low"] != 1 {
		t.Fatalf("by severity: %+v", sf.BySeverity)
	}
	if sf.LastScanAt == nil || sf.LastScanAt.Before(now.Add(-72*time.Hour)) || sf.LastScanAt.After(now) {
		t.Fatalf("last scan: %v", sf.LastScanAt)
	}
	if sum.Fixable.Advisories != 4 || sum.Fixable.Surface != 5 || sum.Fixable.Total != 9 {
		t.Fatalf("fixable: %+v", sum.Fixable)
	}
	if sf.ChecksNotAssessed != 1 { // dkim
		t.Fatalf("not assessed: %d", sf.ChecksNotAssessed)
	}
}

func TestSurfaceDetailKeepsEvidenceAndHistory(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	keys := seedMixed(t, s, now)

	d, err := s.GetSurfaceDetail(ctx, keys["spf.plus_all/client.example.com"])
	if err != nil {
		t.Fatal(err)
	}
	if d.Finding.FindingID != "spf.plus_all" || d.Finding.Evidence["record"] != "v=DMARC1; p=none" || d.Finding.Fix == "" {
		t.Fatalf("%+v", d.Finding)
	}
	if d.Confirmed == nil || d.Confirmed.Check != "spf" || !d.Confirmed.Assessed || d.Confirmed.Observed["raw"] != "text of spf" || d.Unconfirmed {
		t.Fatalf("the drawer shows the raw observation behind the finding: %+v", d.Confirmed)
	}
	if len(d.Intervals) != 1 || d.Intervals[0].ClosedAt != nil {
		t.Fatalf("intervals: %+v", d.Intervals)
	}
	for _, bad := range []string{"", "CVE-2099-1", "surface:1", "surface:abc123456789", "surface:000000000000"} {
		if _, err := s.GetSurfaceDetail(ctx, bad); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, err := s.GetSurfaceDetail(ctx, SurfaceKey(999999)); err != ErrNoSurfaceFinding {
		t.Errorf("unknown finding: %v", err)
	}
	if _, err := s.GetExposureDetail(ctx, keys["spf.plus_all/client.example.com"], "", ""); err == nil {
		t.Error("the vulnerability drawer must not accept a surface key")
	}
}

// The surface series is its own line in the trend, from the first surface scan;
// before it, the days are unknown. A finding that closed and came back does not
// count as open while it was closed.
func TestSurfaceTrendHasItsOwnSeries(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	a := surfaceAsset(t, s, "domain", "trend.example.com", true)
	at := func(daysAgo int, hour int) time.Time {
		return now.AddDate(0, 0, -daysAgo).Truncate(24 * time.Hour).Add(time.Duration(hour) * time.Hour)
	}
	rec := func(when time.Time, rs ...surface.CheckResult) {
		t.Helper()
		if _, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, when, rs...)); err != nil {
			t.Fatal(err)
		}
	}
	dm := finding("dmarc", "dmarc.p_none", "trend.example.com", surface.SevMedium)
	smb := finding("ports", "ports.open", "445/tcp", surface.SevCritical)
	// Day -6: DMARC p=none and an open SMB port. Day -4: SMB closed. Day -3:
	// DMARC fixed. Day -1: DMARC back.
	rec(at(6, 6), result("dmarc", true, "", dm), result("ports", true, "", smb))
	rec(at(4, 6), result("dmarc", true, "", dm), result("ports", true, ""))
	rec(at(3, 6), result("dmarc", true, ""), result("ports", true, ""))
	rec(at(1, 6), result("dmarc", true, "", dm), result("ports", true, ""))

	tr, err := s.ExposureTrend(ctx, at(9, 0), now, now)
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]TrendPoint{}
	for _, p := range tr.Points {
		by[p.Day] = p
	}
	d := func(daysAgo int) TrendPoint { return by[at(daysAgo, 0).Format("2006-01-02")] }
	type want struct {
		surface, high int
		known         bool
	}
	for daysAgo, w := range map[int]want{
		9: {0, 0, false}, 7: {0, 0, false}, // before the first surface scan: no data, not a clean surface
		6: {2, 1, true}, 5: {2, 1, true}, // dmarc + smb
		4: {1, 0, true}, // smb closed
		3: {0, 0, true}, // dmarc closed: clean
		2: {0, 0, true}, // still closed (the gap must not count as open)
		1: {1, 0, true}, // dmarc back
		0: {1, 0, true},
	} {
		p := d(daysAgo)
		if p.Surface != w.surface || p.SurfaceHigh != w.high || p.SurfaceKnown != w.known {
			t.Errorf("day -%d: surface %d (high %d, known %v), want %+v", daysAgo, p.Surface, p.SurfaceHigh, p.SurfaceKnown, w)
		}
		// The vulnerability series is not touched by surface findings.
		if p.Open != 0 || p.Watch != 0 {
			t.Errorf("day -%d: surface findings leaked into the vulnerability series: %+v", daysAgo, p)
		}
	}
	if tr.SurfaceSince == nil {
		t.Fatal("surfaceSince must say when surface history begins")
	}
}

// The chain attests every scan, and a bundle exported from a real database
// verifies: dates recomputed from the attested scans match the stored ones.
func TestSurfaceEvidenceExportVerifiesAndCatchesTampering(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	a := surfaceAsset(t, s, "domain", "evidence.example.com", true)
	rec := func(when time.Time, rs ...surface.CheckResult) {
		t.Helper()
		if _, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, when, rs...)); err != nil {
			t.Fatal(err)
		}
	}
	dm := finding("dmarc", "dmarc.p_none", "evidence.example.com", surface.SevMedium)
	rec(now.AddDate(0, 0, -5), result("dmarc", true, "", dm), result("dkim", false, "no selector found"))
	rec(now.AddDate(0, 0, -4), result("dmarc", true, ""), result("dkim", false, "no selector found"))
	rec(now.AddDate(0, 0, -1), result("dmarc", true, "", dm), result("dkim", false, "no selector found"))

	pemKey := testPubPEM(t)

	export := func() *evidence.Bundle {
		t.Helper()
		b, err := s.ExportEvidence(ctx, pemKey, "test", "surface", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b := export()
	if b.Surface == nil || len(b.Surface.Scans) != 3 || len(b.Surface.Findings) != 1 || len(b.Surface.Assets) != 1 {
		t.Fatalf("surface section: %+v", b.Surface)
	}
	f := b.Surface.Findings[0]
	if len(f.Intervals) != 2 || f.Intervals[0].ClosedAt == nil || f.Intervals[1].ClosedAt != nil {
		t.Fatalf("open on A, closed on B, open again: %+v", f.Intervals)
	}
	if got := b.Surface.Scans[0].Observations; len(got) != 2 || got[0].Check != "dkim" || got[0].Assessed || string(got[1].Observed) == "" {
		t.Fatalf("the raw observations ride along, and a check that could not run says so: %+v", got)
	}

	rep := evidence.Verify(b)
	if rep.Surface.ScansAttested != 3 || rep.Surface.ScansUnattested != 0 || rep.Surface.ScansFailed != 0 || rep.Surface.FindingsVerified != 1 || rep.Surface.FindingsFailed != 0 {
		t.Fatalf("a freshly exported bundle must verify: %+v\n%+v", rep.Surface, rep.Checks)
	}
	for _, c := range rep.Checks {
		if strings.HasPrefix(c.Name, "surface") && !c.OK {
			t.Fatalf("%+v", c)
		}
	}

	// A scan stored by editing the database after the fact is caught: change an
	// observation behind the scanner's back and the digest no longer matches.
	var origObserved []byte
	if err := pool.QueryRow(ctx, `SELECT observed FROM surface_observations WHERE check_group = 'dmarc'
		AND scan_id = (SELECT min(id) FROM surface_scans)`).Scan(&origObserved); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE surface_observations SET observed = '{"check":"dmarc","raw":"edited"}'::jsonb
		WHERE check_group = 'dmarc' AND scan_id = (SELECT min(id) FROM surface_scans)`); err != nil {
		t.Fatal(err)
	}
	rep = evidence.Verify(export())
	if rep.Surface.ScansFailed != 1 {
		t.Fatalf("an edited observation must fail its scan: %+v", rep.Surface)
	}

	// Put the observation back: the bundle verifies again, so the failure above
	// was the edit and nothing else.
	if _, err := pool.Exec(ctx, `UPDATE surface_observations SET observed = $1::jsonb
		WHERE check_group = 'dmarc' AND observed->>'raw' = 'edited'`, string(origObserved)); err != nil {
		t.Fatal(err)
	}
	if rep = evidence.Verify(export()); rep.Surface.ScansFailed != 0 || rep.Surface.FindingsVerified != 1 {
		t.Fatalf("restored: %+v", rep.Surface)
	}

	// Moving a finding's open date in the database is caught the same way: the
	// attested scans say it opened on the third day before, not the ninth.
	if _, err := pool.Exec(ctx, `UPDATE surface_findings SET first_seen = first_seen - interval '4 days' WHERE finding_id = 'dmarc.p_none'`); err != nil {
		t.Fatal(err)
	}
	rep = evidence.Verify(export())
	if rep.Surface.FindingsFailed != 1 || rep.Surface.FindingsVerified != 0 {
		t.Fatalf("a moved open date must fail the finding: %+v", rep.Surface)
	}
}

// Scans stored before attestation existed (no chained entry) are exported, and
// named unattested; they are not failures and their findings are not claimed.
func TestSurfaceEvidenceNamesScansTheChainDoesNotVouchFor(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	a := surfaceAsset(t, s, "domain", "old.example.com", true)
	// Simulate a scan stored by slice 7a: rows, but no chained entry.
	t0 := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
	var scanID int64
	if err := pool.QueryRow(ctx, `INSERT INTO surface_scans (asset_id, triggered_by, started_at, finished_at) VALUES ($1,'schedule',$2,$2) RETURNING id`, a.ID, t0).Scan(&scanID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO surface_findings (asset_id, check_group, finding_id, subject, severity, title, first_seen, last_seen, first_scan_id, last_scan_id)
		VALUES ($1,'dmarc','dmarc.p_none','old.example.com','medium','p=none',$2,$2,$3,$3)`, a.ID, t0, scanID); err != nil {
		t.Fatal(err)
	}
	b, err := s.ExportEvidence(ctx, testPubPEM(t), "test", "surface", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Surface.Scans) != 1 || len(b.Surface.Findings) != 1 {
		t.Fatalf("%+v", b.Surface)
	}
	rep := evidence.Verify(b)
	if rep.Surface.ScansUnattested != 1 || rep.Surface.ScansFailed != 0 || rep.Surface.FindingsUnattested != 1 || rep.Surface.FindingsVerified != 0 {
		t.Fatalf("%+v", rep.Surface)
	}
}

// testPubPEM is a control public key in the form Verify parses.
func testPubPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestSurfaceExportIsNilWithoutAssets(t *testing.T) {
	s, _ := scratchStore(t)
	b, err := s.ExportEvidence(context.Background(), "unused", "test", "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Surface != nil {
		t.Fatalf("an instance with no declared asset has no surface section: %+v", b.Surface)
	}
}

// The trend's day boundaries are UTC days whatever time zone the database
// session runs in. (Until slice 7b they followed the session's: with the server
// on America/Denver a finding first seen at 03:00 UTC on the 5th was counted
// on the 4th.)
func TestTrendDayBoundariesIgnoreSessionTimezone(t *testing.T) {
	_, base := scratchStore(t)
	ctx := context.Background()
	cfg := base.Config().Copy()
	cfg.ConnConfig.RuntimeParams["timezone"] = "America/Denver"
	denver, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(denver.Close)
	var tz string
	if err := denver.QueryRow(ctx, `SHOW timezone`).Scan(&tz); err != nil || tz != "America/Denver" {
		t.Fatalf("session timezone = %q (%v): the test would prove nothing", tz, err)
	}
	s := New(denver)

	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	adv := expoAdv{"V-tz", "CVE-2099-2001", "high", false, "", f64(0.5), f64(7.0)}
	seedExposure(t, s, []expoAdv{adv})
	expoHost(t, s, "tz1", "tzhost")
	expoRecord(t, s, "tz1", expoFinding(adv, vuln.KindFinding, "pkg", "1.0", "1.1"))
	if _, err := denver.Exec(ctx, `INSERT INTO feed_snapshots (id, created_at, feeds) OVERRIDING SYSTEM VALUE VALUES (-1, $1, '[]'::jsonb)
		ON CONFLICT (id) DO NOTHING`, now.AddDate(0, 0, -20)); err != nil {
		t.Fatal(err)
	}
	// Opened at 03:00 UTC on the 22nd: it is open at the end of the 22nd, not of the 21st.
	opened := time.Date(2026, 10, 22, 3, 0, 0, 0, time.UTC)
	if _, err := denver.Exec(ctx, `UPDATE vuln_findings SET first_seen = $1`, opened); err != nil {
		t.Fatal(err)
	}

	a := surfaceAsset(t, s, "domain", "tz.example.com", true)
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "schedule", report(a, opened,
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "tz.example.com", surface.SevMedium)))); err != nil {
		t.Fatal(err)
	}

	tr, err := s.ExposureTrend(ctx, now.AddDate(0, 0, -5), now, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range tr.Points {
		wantOpen := 0
		if p.Day >= "2026-10-22" {
			wantOpen = 1
		}
		if p.Open != wantOpen || p.Surface != wantOpen {
			t.Errorf("%s: open %d, surface %d, want %d each", p.Day, p.Open, p.Surface, wantOpen)
		}
	}
}

// Every timestamp the API returns is UTC. surfaceSince used to come back in the
// zone of the process (a -06:00 offset on a server set to America/Denver).
func TestSurfaceTrendSinceIsUTCWhateverTheProcessZone(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	denver := time.FixedZone("MDT", -6*3600)
	saved := time.Local
	time.Local = denver
	t.Cleanup(func() { time.Local = saved })

	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	a := surfaceAsset(t, s, "domain", "zone.example.com", true)
	if _, err := s.RecordSurfaceScan(ctx, a.ID, "manual", report(a, now.Add(-30*time.Hour),
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "zone.example.com", surface.SevMedium)))); err != nil {
		t.Fatal(err)
	}
	tr, err := s.ExposureTrend(ctx, now.AddDate(0, 0, -5), now, now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.SurfaceSince == nil {
		t.Fatal("surfaceSince missing")
	}
	if tr.SurfaceSince.Location() != time.UTC {
		t.Fatalf("surfaceSince is in %v, want UTC", tr.SurfaceSince.Location())
	}
	raw, err := json.Marshal(tr)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		SurfaceSince string `json:"surfaceSince"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(back.SurfaceSince, "Z") || strings.Contains(back.SurfaceSince, "-06:00") {
		t.Fatalf("surfaceSince on the wire = %q, want a UTC time ending in Z", back.SurfaceSince)
	}
}
