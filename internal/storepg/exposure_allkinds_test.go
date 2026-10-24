package storepg

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/exposure"
	"defendsec/internal/m365"
	"defendsec/internal/repohealth"
	"defendsec/internal/surface"
	"defendsec/internal/vuln"
)

// Every kind of row that the exposure list holds, in one database: a KEV
// vulnerability, EPSS-scored and CVSS-only and unscored ones, critical, high and
// medium surface findings, high and medium identity findings, software past
// security support and past active support, and a repository with a dead key
// and one with a stale index. The merge of slices 11 and 12 is where one rule
// could quietly stop covering the other, so this test puts them side by side:
// the SQL order must equal exposure.Compare and the written order, and keyset
// paging at several sizes must walk the same list.
//
// The ties are on purpose. At 8.0 in the urgent band sit an EOL release, a dead
// repository, a high identity finding and a high surface finding, told apart
// only by the row id ("EOL:" < "REPO:" < "identity:" < "surface:", bytewise); at
// 5.0 sit a CVSS-only CVE and a medium row of each of the other three kinds. A
// wrong constant for any one of them moves a row.
func TestEveryKindOfRowRanksTogether(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	eolSetup(t, s)
	adv := []expoAdv{
		{"A-kev", "CVE-2099-2000", "high", true, "2026-10-01", f64(0.5), f64(8.0)},
		{"B-scored", "CVE-2099-2001", "medium", false, "", f64(0.0002), f64(4.0)},
		{"C-unscored-medium", "CVE-2099-2002", "medium", false, "", nil, nil},
		{"D-unscored-high", "CVE-2099-2003", "high", false, "", nil, nil},
		{"E-cvss-only-5", "CVE-2099-2004", "medium", false, "", nil, f64(5.0)},
		{"F-cvss-only-3", "CVE-2099-2005", "low", false, "", nil, f64(3.0)},
	}
	seedExposure(t, s, adv)
	expoHost(t, s, "dev-1", "host-1")

	// EOL PHP 8.0 (security support ended: urgent, 8.0), Node 22 (active support
	// ended: 2.0), a dead repository (high: urgent, 8.0) and a stale one (medium: 5.0).
	h := eolHost("debian", "dpkg", "php8.0-cli", "8.0.30-3", "deb.sury.org", "nodejs", "22.1.0-1nodesource1", "deb.nodesource.com")
	h.RepoHealth = repoReport(repoBroken, func() repohealth.Repo {
		r := repoHealthy
		r.ID, r.Label, r.ReleaseDate = "http://stale.example.invalid/apt stable", "http://stale.example.invalid/apt stable", rtm("2022-01-01")
		return r
	}())
	h.RepoHealth.LastRefresh = rtm("2026-09-01")
	res, err := vuln.Match(ctx, s, h)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range adv {
		res.Findings = append(res.Findings, expoFinding(a, vuln.KindFinding, "pkg-"+a.id, "1", "2"))
	}
	if err := s.RecordFindings(ctx, "dev-1", res, nil); err != nil {
		t.Fatal(err)
	}

	// Surface: critical, high, medium.
	dom := surfaceAsset(t, s, "domain", "client.example.com", true)
	ip := surfaceAsset(t, s, "ip", "192.0.2.10", true)
	if _, err := s.RecordSurfaceScan(ctx, dom.ID, "schedule", report(dom, repoNow.Add(-time.Hour),
		result("spf", true, "", finding("spf", "spf.plus_all", "client.example.com", surface.SevCritical)),
		result("dmarc", true, "", finding("dmarc", "dmarc.p_none", "client.example.com", surface.SevMedium)))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSurfaceScan(ctx, ip.ID, "schedule", report(ip, repoNow.Add(-time.Hour),
		result("ports", true, "", finding("ports", "ports.open", "3389/tcp", surface.SevHigh)))); err != nil {
		t.Fatal(err)
	}

	// Identity: high and medium.
	if _, err := s.RecordIdentityRun(ctx, "m365", "t", "schedule", idnReport(time.Now().UTC(),
		idnCheck(m365.GroupMFA, true, "",
			idnFinding("mfa.not_registered", "u1", "high-user", m365.SevHigh),
			idnFinding("mfa.not_registered", "u2", "medium-user", m365.SevMedium)))); err != nil {
		t.Fatal(err)
	}

	page, err := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	label := func(g ExposureGroup) string {
		switch {
		case g.Repo != nil:
			return "repo:" + g.Severity
		case g.Identity != nil:
			return "identity:" + g.Severity
		case g.Surface != nil:
			return "surface:" + g.Severity
		}
		return g.AdvisoryID
	}
	var order []string
	for _, g := range page.Findings {
		order = append(order, label(g))
	}
	want := []string{
		"A-kev",                                                     // band 0
		"surface:critical",                                          // band 1, 9.5
		"EOL:php:8.0", "repo:high", "identity:high", "surface:high", // band 1, 8.0: by row id
		"B-scored",                                                          // band 2, EPSS
		"E-cvss-only-5", "repo:medium", "identity:medium", "surface:medium", // band 2, 5.0: by row id
		"F-cvss-only-3",                        // 3.0
		"EOL:nodejs:22",                        // 2.0, active support ended
		"D-unscored-high", "C-unscored-medium", // no score at all, by severity
	}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v\nwant    %v", order, want)
	}
	if page.Total != len(want) {
		t.Errorf("total = %d, want %d", page.Total, len(want))
	}

	// The Go rule over the same rows gives the same order.
	items := make([]exposure.Item, 0, len(page.Findings))
	for _, g := range page.Findings {
		it := exposure.Item{AdvisoryID: g.AdvisoryID, Severity: g.Severity, KEV: g.KEV, EPSS: g.EPSS, CVSS: g.CVSS,
			Surface: g.Source == SourceSurface, Identity: g.Source == SourceIdentity, RepoHealth: g.Repo != nil}
		if g.EOL != nil {
			it.EOLStage = g.EOL.Stage
		}
		if g.KEVAdded != nil {
			it.KEVAdded = day(*g.KEVAdded)
		}
		items = append(items, it)
	}
	sorted := append([]exposure.Item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return exposure.Compare(sorted[i], sorted[j]) < 0 })
	for i := range items {
		if items[i].AdvisoryID != sorted[i].AdvisoryID {
			t.Fatalf("SQL order differs from exposure.Compare at %d: SQL %s, Go %s", i, items[i].AdvisoryID, sorted[i].AdvisoryID)
		}
	}

	// Keyset paging at several sizes walks the same list, no row twice or missed.
	var all []string
	for _, g := range page.Findings {
		all = append(all, g.AdvisoryID)
	}
	for _, size := range []int{1, 2, 3, 4, 5, 7, 200} {
		var got []string
		cursor := ""
		for pages := 0; pages < 40; pages++ {
			p, err := s.ListExposure(ctx, ExposureQuery{Limit: size, Cursor: cursor})
			if err != nil {
				t.Fatalf("limit %d: %v", size, err)
			}
			for _, g := range p.Findings {
				got = append(got, g.AdvisoryID)
			}
			if p.Next == "" {
				break
			}
			cursor = p.Next
		}
		if strings.Join(got, ",") != strings.Join(all, ",") {
			t.Fatalf("limit %d paged to\n %v\nwant\n %v", size, got, all)
		}
	}
}
