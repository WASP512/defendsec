package storepg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/exposure"
	"defendsec/internal/presence"
	"defendsec/internal/vuln"
)

// The exposure queries count the whole database, so these tests run in a
// throwaway database of their own (the role has CREATEDB, as the feed runner
// tests rely on) instead of sharing rows with other tests.
func scratchStore(t *testing.T) (*Store, *pgxpool.Pool) {
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
	name := "defendsec_mig_expo_" + hex.EncodeToString(b)
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
	return New(pool), pool
}

func day(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

type expoAdv struct {
	id, cve, sev string
	kev          bool
	kevAdded     string
	epss, cvss   *float64
}

func seedExposure(t *testing.T, s *Store, advs []expoAdv) {
	t.Helper()
	ctx := context.Background()
	for _, a := range advs {
		adv := Advisory{ID: a.id, CVE: a.cve, Severity: a.sev, Summary: "summary of " + a.id, Source: "test",
			KEV: a.kev, EPSS: a.epss, CVSSScore: a.cvss}
		if a.kevAdded != "" {
			adv.KEVAdded = day(a.kevAdded)
		}
		if err := s.UpsertAdvisoryWithRanges(ctx, adv); err != nil {
			t.Fatal(err)
		}
	}
}

func expoFinding(a expoAdv, kind vuln.Kind, pkg, installed, fixed string) vuln.Finding {
	return vuln.Finding{
		AdvisoryID: a.id, CVE: a.cve, Kind: kind, Basis: vuln.BasisDistro, Package: pkg, Installed: installed,
		Fixed: fixed, FixState: "fixed", Severity: a.sev, Summary: "summary of " + a.id, KEV: a.kev,
		EPSS: a.epss, CVSS: a.cvss, Feed: "ubuntu-jammy",
	}
}

func expoHost(t *testing.T, s *Store, id, name string) {
	t.Helper()
	if err := s.UpsertDevice(context.Background(), presence.Device{ID: id, Hostname: name, Platform: "linux",
		LastSeen: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
}

func expoRecord(t *testing.T, s *Store, dev string, fs ...vuln.Finding) {
	t.Helper()
	if err := s.RecordFindings(context.Background(), dev, vuln.Result{Coverage: vuln.CoverageFull, Findings: fs}, nil); err != nil {
		t.Fatal(err)
	}
}

// The order the database produces is the order internal/exposure defines, and
// paging by cursor returns every row once, in that order, whatever the page size.
func TestExposureOrderMatchesRankingRuleAndPagesByKeyset(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	advs := []expoAdv{
		{"A-kev-old", "CVE-2099-0001", "high", true, "2024-03-01", f64(0.10), f64(7.0)},
		{"A-kev-new-lowepss", "CVE-2099-0002", "medium", true, "2026-09-14", f64(0.02), f64(5.0)},
		{"A-kev-new-highepss", "CVE-2099-0003", "medium", true, "2026-09-14", f64(0.71), f64(5.0)},
		{"A-kev-undated", "CVE-2099-0004", "critical", true, "", f64(0.99), f64(9.8)},
		{"A-epss-high", "CVE-2099-0005", "medium", false, "", f64(0.60), f64(4.0)},
		{"A-epss-high-cvss-low", "CVE-2099-0006", "medium", false, "", f64(0.60), f64(3.0)},
		{"A-epss-low-cvss-crit", "CVE-2099-0007", "critical", false, "", f64(0.01), f64(9.9)},
		{"A-cvss-only-9", "CVE-2099-0008", "critical", false, "", nil, f64(9.0)},
		{"A-cvss-only-6", "CVE-2099-0009", "medium", false, "", nil, f64(6.0)},
		{"A-nothing-high", "CVE-2099-0010", "high", false, "", nil, nil},
		{"A-nothing-low", "CVE-2099-0011", "low", false, "", nil, nil},
		{"A-nothing-low-b", "CVE-2099-0012", "low", false, "", nil, nil},
	}
	seedExposure(t, s, advs)
	expoHost(t, s, "h1", "alpha")
	expoHost(t, s, "h2", "bravo")
	for i, a := range advs {
		// Every advisory on host h1; every other one also on h2.
		fs := []vuln.Finding{expoFinding(a, vuln.KindFinding, "pkg"+itoa(i), "1.0", "1.1")}
		expoRecord(t, s, "h1", append(listFindings(t, s, "h1"), fs...)...)
		if i%2 == 0 {
			expoRecord(t, s, "h2", append(listFindings(t, s, "h2"), fs...)...)
		}
	}

	var items []exposure.Item
	for _, a := range advs {
		it := exposure.Item{AdvisoryID: a.id, Severity: a.sev, KEV: a.kev, EPSS: a.epss, CVSS: a.cvss}
		if a.kevAdded != "" {
			it.KEVAdded = day(a.kevAdded)
		}
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool { return exposure.Compare(items[i], items[j]) < 0 })
	var want []string
	for _, it := range items {
		want = append(want, it.AdvisoryID)
	}

	for _, size := range []int{1, 3, 5, 200} {
		var got []string
		cursor := ""
		for pages := 0; pages < 100; pages++ {
			page, err := s.ListExposure(ctx, ExposureQuery{Limit: size, Cursor: cursor})
			if err != nil {
				t.Fatalf("limit %d: %v", size, err)
			}
			if page.Total != len(advs) {
				t.Fatalf("total = %d, want %d", page.Total, len(advs))
			}
			for _, g := range page.Findings {
				got = append(got, g.AdvisoryID)
			}
			if page.Next == "" {
				break
			}
			cursor = page.Next
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("limit %d order:\n got %v\nwant %v", size, got, want)
		}
	}

	// Host counts, the sampled host list and the KEV date come through.
	page, err := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	first := page.Findings[0]
	if first.AdvisoryID != "A-kev-new-highepss" || !first.KEV || first.KEVAdded == nil || *first.KEVAdded != "2026-09-14" {
		t.Fatalf("first = %+v", first)
	}
	if first.HostCount != 2 {
		t.Fatalf("host count = %d", first.HostCount)
	}
	for _, g := range page.Findings {
		if g.AdvisoryID == "A-kev-old" {
			if g.HostCount != 2 || len(g.Hosts) != 2 || g.Hosts[0].Hostname != "alpha" || g.Hosts[1].Hostname != "bravo" {
				t.Fatalf("A-kev-old hosts = %+v", g)
			}
		}
		if !g.KEV && g.KEVAdded != nil {
			t.Fatalf("non-KEV row carries a KEV date: %+v", g)
		}
	}

	kev, err := s.ListExposure(ctx, ExposureQuery{KEVOnly: true, Limit: 200})
	if err != nil || kev.Total != 4 {
		t.Fatalf("kev only = %d, %v", kev.Total, err)
	}

	// A cursor this code did not produce, and bad parameters, are refused.
	for _, c := range []string{"nonsense", "e30"} {
		if _, err := s.ListExposure(ctx, ExposureQuery{Cursor: c}); !errors.Is(err, ErrBadCursor) {
			t.Errorf("cursor %q: err = %v, want ErrBadCursor", c, err)
		}
	}
	for _, q := range []ExposureQuery{{Bucket: "x"}, {Status: "x"}, {Limit: -1}, {Limit: MaxExposurePage + 1}} {
		if _, err := s.ListExposure(ctx, q); !errors.Is(err, ErrBadExposureQuery) {
			t.Errorf("%+v: err = %v, want ErrBadExposureQuery", q, err)
		}
	}
}

func listFindings(t *testing.T, s *Store, dev string) []vuln.Finding {
	t.Helper()
	rows, err := s.ListFindings(context.Background(), FindingFilter{DeviceID: dev})
	if err != nil {
		t.Fatal(err)
	}
	var out []vuln.Finding
	for _, r := range rows {
		out = append(out, vuln.Finding{
			AdvisoryID: r.AdvisoryID, CVE: r.CVE, Kind: vuln.Kind(r.Kind), Basis: vuln.Basis(r.Basis), Package: r.Package,
			SourcePackage: r.SourcePackage, Installed: r.Installed, Fixed: r.Fixed, FixState: r.FixState,
			Severity: r.Severity, Summary: r.Summary, KEV: r.KEV, EPSS: r.EPSS, CVSS: r.CVSS, Feed: r.Feed,
		})
	}
	return out
}

// Fixable findings are the Fix-this-week list; no-fix and awaiting-vendor ones
// are the watch bucket; informational ones are in neither and are never counted.
func TestExposureBucketsAndSummary(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	fixable := expoAdv{"B-fix", "CVE-2099-1001", "high", false, "", f64(0.5), f64(8)}
	fixableKEV := expoAdv{"B-fix-kev", "CVE-2099-1002", "medium", true, "2026-10-01", f64(0.2), f64(6)}
	noFix := expoAdv{"B-nofix", "CVE-2099-1003", "high", false, "", nil, f64(7)}
	noFixKEV := expoAdv{"B-nofix-kev", "CVE-2099-1004", "high", true, "2026-10-02", f64(0.9), f64(8)}
	awaiting := expoAdv{"B-await", "CVE-2099-1005", "high", false, "", nil, f64(7)}
	awaitingKEV := expoAdv{"B-await-kev", "CVE-2099-1006", "high", true, "2026-10-03", nil, nil}
	info := expoAdv{"B-info", "CVE-2099-1007", "critical", true, "2026-10-04", f64(0.99), f64(9.9)}
	seedExposure(t, s, []expoAdv{fixable, fixableKEV, noFix, noFixKEV, awaiting, awaitingKEV, info})
	expoHost(t, s, "h1", "alpha")
	expoHost(t, s, "h2", "bravo")
	expoHost(t, s, "h3", "charlie")
	expoRecord(t, s, "h1",
		expoFinding(fixable, vuln.KindFinding, "a", "1", "2"),
		expoFinding(fixableKEV, vuln.KindFinding, "b", "1", "2"),
		expoFinding(noFix, vuln.KindUnfixed, "c", "1", ""),
		expoFinding(noFixKEV, vuln.KindUnfixed, "d", "1", ""),
		expoFinding(info, vuln.KindInformational, "e", "1", ""),
	)
	expoRecord(t, s, "h2",
		expoFinding(fixable, vuln.KindFinding, "a", "1", "2"),
		withUpstream(expoFinding(awaiting, vuln.KindAwaitingVendor, "f", "1", "2"), "2026-10-20"),
		withUpstream(expoFinding(awaitingKEV, vuln.KindAwaitingVendor, "g", "1", "2"), "2026-10-22"),
	)
	// h3 was matched, found nothing, and has not reported for ten days.
	expoRecord(t, s, "h3")
	if _, err := pool.Exec(ctx, `UPDATE devices SET last_seen = now() - interval '10 days' WHERE id = 'h3'`); err != nil {
		t.Fatal(err)
	}
	// An open failed configuration check on h1; a closed one and a non-SCA
	// alert are not counted.
	for _, a := range []struct{ id, kind, sev, status string }{
		{"a1", "sca", "high", "open"}, {"a2", "sca", "high", "open"}, {"a3", "sca", "low", "open"},
		{"a4", "sca", "high", "resolved"}, {"a5", "vuln", "high", "open"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO alerts (id, device_id, kind, severity, title, status) VALUES ($1,'h1',$2,$3,'t',$4)`,
			a.id, a.kind, a.sev, a.status); err != nil {
			t.Fatal(err)
		}
	}

	fix, err := s.ListExposure(ctx, ExposureQuery{Bucket: BucketFix, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if ids := groupIDs(fix); ids != "B-fix-kev,B-fix" || fix.Total != 2 {
		t.Fatalf("fix bucket = %s (total %d)", ids, fix.Total)
	}
	if fix.Findings[1].HostCount != 2 || fix.Findings[1].FindingCount != 2 {
		t.Fatalf("B-fix = %+v", fix.Findings[1])
	}
	watch, err := s.ListExposure(ctx, ExposureQuery{Bucket: BucketWatch, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if ids := groupIDs(watch); ids != "B-await-kev,B-nofix-kev,B-await,B-nofix" {
		t.Fatalf("watch bucket = %s", ids)
	}
	for _, g := range watch.Findings {
		want := map[string]string{"B-await": "2026-10-20", "B-await-kev": "2026-10-22"}[g.AdvisoryID]
		switch {
		case want == "" && g.AwaitingSince != nil:
			t.Errorf("%s: awaitingSince = %v, want none", g.AdvisoryID, *g.AwaitingSince)
		case want != "" && (g.AwaitingSince == nil || *g.AwaitingSince != want):
			t.Errorf("%s: awaitingSince = %v, want %s", g.AdvisoryID, g.AwaitingSince, want)
		}
	}
	kevWatch, err := s.ListExposure(ctx, ExposureQuery{Bucket: BucketWatch, KEVOnly: true, Limit: 50})
	if err != nil || groupIDs(kevWatch) != "B-await-kev,B-nofix-kev" {
		t.Fatalf("kev watch = %s, %v", groupIDs(kevWatch), err)
	}

	sum, err := s.ExposureSummary(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Hosts.Total != 3 || sum.Hosts.Assessed != 3 || sum.Hosts.NotAssessed != 0 {
		t.Errorf("hosts = %+v", sum.Hosts)
	}
	if sum.Hosts.Silent != 1 || len(sum.Hosts.SilentList) != 1 || sum.Hosts.SilentList[0].DeviceID != "h3" {
		t.Errorf("silent = %+v", sum.Hosts)
	}
	if sum.Fixable.Findings != 3 || sum.Fixable.Advisories != 2 || sum.Fixable.Hosts != 2 ||
		sum.Fixable.KEV.Findings != 1 || sum.Fixable.KEV.Advisories != 1 {
		t.Errorf("fixable = %+v", sum.Fixable)
	}
	if sum.Watch.Unfixed != (ExposureCount{2, 2}) || sum.Watch.AwaitingVendor != (ExposureCount{2, 2}) || sum.Watch.KEV != (ExposureCount{2, 2}) {
		t.Errorf("watch = %+v", sum.Watch)
	}
	if sum.SCA.Total != 3 || sum.SCA.Hosts != 1 || sum.SCA.Severity["high"] != 2 || sum.SCA.Severity["low"] != 1 {
		t.Errorf("sca = %+v", sum.SCA)
	}

	// A host that never reported inventory is not "assessed".
	expoHost(t, s, "h4", "delta")
	sum, err = s.ExposureSummary(ctx, time.Now())
	if err != nil || sum.Hosts.Total != 4 || sum.Hosts.NotAssessed != 1 {
		t.Errorf("after unassessed host: %+v, %v", sum.Hosts, err)
	}
}

func withUpstream(f vuln.Finding, date string) vuln.Finding {
	f.UpstreamFixedOn = date
	return f
}

func groupIDs(p ExposurePage) string {
	var ids []string
	for _, g := range p.Findings {
		ids = append(ids, g.AdvisoryID)
	}
	return strings.Join(ids, ",")
}

// A finding closes with the reason the inventory gives: the host has the fixed
// version, the package went away, or the advisory data changed. Without an
// inventory the reason is not recorded rather than guessed.
func TestFindingResolutionRecordsHowItClosed(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	a := expoAdv{"R-adv", "CVE-2099-2001", "high", false, "", f64(0.3), f64(7)}
	seedExposure(t, s, []expoAdv{a})
	hosts := []string{"fixed", "removed", "reclassified", "blind", "rpmfixed"}
	for _, h := range hosts {
		expoHost(t, s, h, "host-"+h)
	}
	open := func(h, pkg, installed, fixed string) {
		expoRecord(t, s, h, expoFinding(a, vuln.KindFinding, pkg, installed, fixed))
	}
	open("fixed", "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15")
	open("removed", "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15")
	open("reclassified", "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15")
	open("blind", "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15")
	open("rpmfixed", "kernel-core", "0:5.14.0-687.59.1.el9_8", "0:5.14.0-687.60.1.el9_8")

	closeWith := func(h string, inv *Inventory) {
		t.Helper()
		if err := s.RecordFindingsFor(ctx, h, vuln.Result{Coverage: vuln.CoverageFull}, nil, inv); err != nil {
			t.Fatal(err)
		}
	}
	dpkg := func(pkg, v string) *Inventory {
		return &Inventory{Scheme: vuln.SchemeDpkg, Versions: map[string]string{pkg: v}}
	}
	closeWith("fixed", dpkg("openssl", "3.0.2-0ubuntu1.15"))
	closeWith("removed", dpkg("curl", "7.81.0"))
	closeWith("reclassified", dpkg("openssl", "3.0.2-0ubuntu1.14"))
	closeWith("blind", nil)
	closeWith("rpmfixed", &Inventory{Scheme: vuln.SchemeRPM, Versions: map[string]string{"kernel-core": "5.14.0-687.60.1.el9_8"}})

	res, err := s.GetExposureDetail(ctx, "R-adv", BucketFix, ExposureResolved)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][2]string{}
	for _, f := range res.Findings {
		if f.ResolvedAt == nil {
			t.Errorf("%s: resolved_at is nil", f.DeviceID)
		}
		got[f.DeviceID] = [2]string{f.Resolution, f.ResolvedInstalled}
	}
	want := map[string][2]string{
		"fixed":        {ResolutionFixed, "3.0.2-0ubuntu1.15"},
		"removed":      {ResolutionPackageRemoved, ""},
		"reclassified": {ResolutionNoLongerAffects, "3.0.2-0ubuntu1.14"},
		"blind":        {ResolutionUnknown, ""},
		"rpmfixed":     {ResolutionFixed, "5.14.0-687.60.1.el9_8"},
	}
	for h, w := range want {
		if got[h] != w {
			t.Errorf("%s: resolution %v, want %v", h, got[h], w)
		}
	}
	if open, _ := s.GetExposureDetail(ctx, "R-adv", BucketFix, ExposureOpen); len(open.Findings) != 0 {
		t.Errorf("closed findings still listed as open: %d", len(open.Findings))
	}
	// Coming back clears the resolution.
	open("fixed", "openssl", "3.0.2-0ubuntu1.14", "3.0.2-0ubuntu1.15")
	again, err := s.GetExposureDetail(ctx, "R-adv", BucketFix, ExposureOpen)
	if err != nil || len(again.Findings) != 1 || again.Findings[0].Resolution != "" || again.Findings[0].ResolvedAt != nil {
		t.Errorf("reopened = %+v, %v", again.Findings, err)
	}
}

// The trend is computed from first_seen and resolved_at, a recurrence keeps its
// earlier interval, and days before any feed snapshot are unknown, not zero.
func TestExposureTrendFromFirstSeenAndResolvedAt(t *testing.T) {
	s, pool := scratchStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	at := func(d string) time.Time { return day(d).Add(10 * time.Hour) }

	kev := expoAdv{"T-kev", "CVE-2099-3001", "high", true, "2026-10-01", f64(0.5), f64(8)}
	plain := expoAdv{"T-plain", "CVE-2099-3002", "high", false, "", f64(0.1), f64(6)}
	later := expoAdv{"T-later", "CVE-2099-3003", "medium", false, "", nil, nil}
	nofix := expoAdv{"T-nofix", "CVE-2099-3004", "medium", false, "", nil, nil}
	seedExposure(t, s, []expoAdv{kev, plain, later, nofix})
	expoHost(t, s, "h1", "alpha")
	if _, err := pool.Exec(ctx, `INSERT INTO feed_snapshots (created_at, feeds) VALUES ($1, '[]')`, at("2026-10-02")); err != nil {
		t.Fatal(err)
	}
	expoRecord(t, s, "h1",
		expoFinding(kev, vuln.KindFinding, "a", "1", "2"),
		expoFinding(plain, vuln.KindFinding, "b", "1", "2"),
		expoFinding(later, vuln.KindFinding, "c", "1", "2"),
		expoFinding(nofix, vuln.KindUnfixed, "d", "1", ""),
	)
	set := func(adv, firstSeen, resolvedAt string) {
		t.Helper()
		var closed *time.Time
		if resolvedAt != "" {
			c := at(resolvedAt)
			closed = &c
		}
		if _, err := pool.Exec(ctx, `UPDATE vuln_findings SET first_seen = $2, resolved_at = $3, last_seen = $2 WHERE advisory_id = $1`,
			adv, at(firstSeen), closed); err != nil {
			t.Fatal(err)
		}
	}
	// T-kev: open 10-03, closed 10-10, comes back 10-15 (the old interval is archived on return).
	set("T-kev", "2026-10-03", "2026-10-10")
	set("T-plain", "2026-10-05", "")
	set("T-later", "2026-10-12", "2026-10-14")
	set("T-nofix", "2026-10-06", "")
	// The recurrence: the matcher confirms T-kev again, which archives the closed interval and restarts first_seen.
	expoRecord(t, s, "h1",
		expoFinding(kev, vuln.KindFinding, "a", "1", "2"),
		expoFinding(plain, vuln.KindFinding, "b", "1", "2"),
		expoFinding(nofix, vuln.KindUnfixed, "d", "1", ""),
	)
	if _, err := pool.Exec(ctx, `UPDATE vuln_findings SET first_seen = $1 WHERE advisory_id = 'T-kev'`, at("2026-10-15")); err != nil {
		t.Fatal(err)
	}

	tr, err := s.ExposureTrend(ctx, *day("2026-10-01"), *day("2026-10-20"), now)
	if err != nil {
		t.Fatal(err)
	}
	if tr.HistorySince == nil || len(tr.Points) != 20 {
		t.Fatalf("trend = %d points, since %v", len(tr.Points), tr.HistorySince)
	}
	byDay := map[string]TrendPoint{}
	for _, p := range tr.Points {
		byDay[p.Day] = p
	}
	check := func(d string, known bool, open, kevN, watch int) {
		t.Helper()
		p := byDay[d]
		if p.Known != known || p.Open != open || p.KEV != kevN || p.Watch != watch {
			t.Errorf("%s = %+v, want known=%v open=%d kev=%d watch=%d", d, p, known, open, kevN, watch)
		}
	}
	check("2026-10-01", false, 0, 0, 0) // before the first snapshot: no data, not "clean"
	check("2026-10-02", true, 0, 0, 0)
	check("2026-10-03", true, 1, 1, 0) // T-kev opens
	check("2026-10-05", true, 2, 1, 0) // T-plain
	check("2026-10-06", true, 2, 1, 1) // T-nofix joins the watch series
	check("2026-10-10", true, 1, 0, 1) // T-kev closes at 10:00 that day; T-later not yet
	check("2026-10-12", true, 2, 0, 1) // T-later opens
	check("2026-10-14", true, 1, 0, 1) // T-later closes
	check("2026-10-15", true, 2, 1, 1) // T-kev is back: its earlier interval was not lost
	check("2026-10-20", true, 2, 1, 1)

	// Today's point is the live count, the same one the summary reports.
	last := tr.Points[len(tr.Points)-1]
	sum, err := s.ExposureSummary(ctx, now)
	if err != nil || last.Open != sum.Fixable.Findings {
		t.Errorf("last point open %d, summary %d (%v)", last.Open, sum.Fixable.Findings, err)
	}

	var intervals int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vuln_finding_intervals WHERE advisory_id = 'T-kev'`).Scan(&intervals); err != nil || intervals != 1 {
		t.Errorf("intervals for T-kev = %d, %v", intervals, err)
	}

	for _, w := range [][2]time.Time{
		{*day("2026-10-10"), *day("2026-10-01")},
		{*day("2025-01-01"), *day("2026-10-20")},
		{*day("2026-11-01"), *day("2026-11-05")},
	} {
		if _, err := s.ExposureTrend(ctx, w[0], w[1], now); !errors.Is(err, ErrBadTrendWindow) {
			t.Errorf("window %v: err = %v, want ErrBadTrendWindow", w, err)
		}
	}
	// A window running past now stops at now.
	cut, err := s.ExposureTrend(ctx, *day("2026-10-18"), *day("2026-12-31"), now)
	if err != nil || len(cut.Points) != 3 {
		t.Errorf("window past now: %d points, %v", len(cut.Points), err)
	}
}
