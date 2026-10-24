package storepg

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/exposure"
	"defendsec/internal/vuln"
)

func eolRows() []EOLRow {
	return []EOLRow{
		{Product: "php", Label: "PHP", Cycle: "8.5", EoasFrom: "2027-12-31", EolFrom: "2029-12-31", Latest: "8.5.12"},
		{Product: "php", Label: "PHP", Cycle: "8.4", EoasFrom: "2026-12-31", EolFrom: "2028-12-31", Latest: "8.4.27"},
		{Product: "php", Label: "PHP", Cycle: "8.0", EoasFrom: "2022-11-26", EolFrom: "2023-11-26", Latest: "8.0.30", ReleaseDate: "2020-11-26"},
		{Product: "nodejs", Label: "Node.js", Cycle: "22", EoasFrom: "2025-10-21", EolFrom: "2027-04-30", IsLTS: true},
		{Product: "nodejs", Label: "Node.js", Cycle: "16", EoasFrom: "2022-10-18", EolFrom: "2023-09-11", IsLTS: true},
		{Product: "python", Label: "Python", Cycle: "3.10", EoasFrom: "2023-04-05", EolFrom: "2026-10-01"},
	}
}

// eolSetup loads a calendar under a feed snapshot, as the runner does.
func eolSetup(t *testing.T, s *Store) (snapID int64, fetched time.Time) {
	t.Helper()
	ctx := context.Background()
	fetched = time.Date(2026, 10, 24, 0, 8, 55, 0, time.UTC)
	snap, err := s.RecordFeedSnapshot(ctx, []FeedRef{{Name: EOLFeedName, URL: "https://endoflife.date/api/v1/products/full",
		FetchedAt: fetched, SHA256: strings.Repeat("ab", 32), RecordCount: len(eolRows())}})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ApplyEOL(ctx, eolRows(), snap.ID); err != nil || n != len(eolRows()) {
		t.Fatalf("ApplyEOL = %d, %v", n, err)
	}
	return snap.ID, fetched
}

func TestEOLCalendarLoadsReplacesAndRefusesEmpty(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	snapID, fetched := eolSetup(t, s)

	rels, err := s.EOLReleases(ctx, []string{"php"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 3 {
		t.Fatalf("php releases = %d, want 3", len(rels))
	}
	var php80 *struct{ eol, eoas, latest string }
	for _, r := range rels {
		if r.Cycle == "8.0" {
			php80 = &struct{ eol, eoas, latest string }{r.EolFrom, r.EoasFrom, r.Latest}
			if r.SnapshotID == nil || *r.SnapshotID != snapID || r.FeedDate == nil || !r.FeedDate.Equal(fetched) {
				t.Errorf("php 8.0 snapshot = %v feed date = %v, want %d / %s", r.SnapshotID, r.FeedDate, snapID, fetched)
			}
		}
	}
	if php80 == nil || php80.eol != "2023-11-26" || php80.eoas != "2022-11-26" || php80.latest != "8.0.30" {
		t.Errorf("php 8.0 = %+v", php80)
	}
	if none, _ := s.EOLReleases(ctx, nil); none != nil {
		t.Errorf("no products asked, got %v", none)
	}

	// An empty calendar would make everything look supported: refused, and the
	// loaded one stays.
	if _, err := s.ApplyEOL(ctx, nil, 0); err == nil {
		t.Fatal("empty calendar accepted")
	}
	if again, _ := s.EOLReleases(ctx, []string{"php"}); len(again) != 3 {
		t.Fatalf("a refused load changed the calendar: %d rows", len(again))
	}
	// A reload replaces the whole calendar, it does not merge.
	if _, err := s.ApplyEOL(ctx, []EOLRow{{Product: "php", Cycle: "9.0", Label: "PHP"}}, 0); err != nil {
		t.Fatal(err)
	}
	after, _ := s.EOLReleases(ctx, []string{"php", "nodejs"})
	if len(after) != 1 || after[0].Cycle != "9.0" || after[0].SnapshotID != nil || after[0].FeedDate != nil {
		t.Errorf("after reload = %+v", after)
	}
}

func eolHost(distro, manager string, pk ...string) vuln.Host {
	h := vuln.Host{Distro: distro, PackageManager: manager, AsOf: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)}
	for i := 0; i+2 < len(pk); i += 3 {
		h.Packages = append(h.Packages, vuln.Package{Name: pk[i], Version: pk[i+1], Origin: pk[i+2]})
	}
	return h
}

// The whole path on a real database: calendar, matcher, findings, exposure
// list and summary, resolution when the host upgrades.
func TestEOLFindingEndToEnd(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	eolSetup(t, s)
	expoHost(t, s, "dev-casper", "casper-like")
	expoHost(t, s, "dev-ubuntu", "ubuntu-like")

	// client-like: PHP 8.0 from Sury on Debian. Ubuntu-like: python3.10 from
	// Ubuntu itself, upstream end-of-life and Canonical-supported.
	php := eolHost("debian", "dpkg",
		"php8.0-cli", "8.0.30-3+0~2023", "deb.sury.org",
		"php8.0-common", "8.0.30-3+0~2023", "deb.sury.org",
		"openssl", "1.1.1w-0+deb11u1", "Debian")
	ubu := eolHost("ubuntu", "dpkg", "python3.10", "3.10.12-1~22.04.12", "Ubuntu", "libpython3.10-stdlib", "3.10.12-1~22.04.12", "Ubuntu")

	phpRes, err := vuln.Match(ctx, s, php)
	if err != nil {
		t.Fatal(err)
	}
	ubuRes, err := vuln.Match(ctx, s, ubu)
	if err != nil {
		t.Fatal(err)
	}
	// exactly one EOL finding on the Sury host, none on the Ubuntu host
	if n := countKind(phpRes, vuln.KindEOL); n != 1 {
		t.Fatalf("php host eol findings = %d: %+v", n, phpRes.Findings)
	}
	if n := countKind(ubuRes, vuln.KindEOL); n != 0 {
		t.Fatalf("ubuntu host eol findings = %d, want 0 (origin decides)", n)
	}
	if ubuRes.Stats.EOLMapped != 2 || ubuRes.Stats.EOLDistroOrigin != 2 {
		t.Errorf("ubuntu stats = %+v", ubuRes.Stats)
	}
	f := phpRes.Findings[0]
	if f.Kind != vuln.KindEOL || f.AdvisoryID != "EOL:php:8.0" || f.EOL == nil || f.EOL.EolFrom != "2023-11-26" || f.EOL.Origin != "deb.sury.org" ||
		f.EOL.UpgradeTo != "8.4" || f.Severity != "high" || f.Feed != "endoflife" || f.FeedDate == nil || f.SnapshotID == nil {
		t.Fatalf("finding = %+v eol=%+v", f, f.EOL)
	}

	inv := &Inventory{Versions: map[string]string{"php8.0-cli": "8.0.30-3+0~2023", "php8.0-common": "8.0.30-3+0~2023", "openssl": "1.1.1w-0+deb11u1"}}
	if err := s.RecordFindingsFor(ctx, "dev-casper", phpRes, nil, inv); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFindingsFor(ctx, "dev-ubuntu", ubuRes, nil, nil); err != nil {
		t.Fatal(err)
	}

	// stored, with the evidence the card asks for
	got, err := s.ListFindings(ctx, FindingFilter{Kind: "eol"})
	if err != nil || len(got) != 1 {
		t.Fatalf("eol findings = %v, %v", got, err)
	}
	sf := got[0]
	if sf.Origin != "deb.sury.org" || sf.EOL == nil || sf.EOL.Product != "php" || sf.EOL.Cycle != "8.0" || sf.EOL.Stage != "eol" ||
		sf.EOL.StageFrom != "2023-11-26" || len(sf.EOL.Packages) != 2 || sf.Basis != "lifecycle" || sf.Family != "php" {
		t.Errorf("stored finding = %+v eol=%+v", sf, sf.EOL)
	}
	// control tags come from the catalog: CIS v8 2.2 and NIST SI-2
	for _, want := range []string{"cis-v8:2.2", "nist-800-53:SI-2"} {
		found := false
		for _, c := range sf.Controls {
			found = found || c == want
		}
		if !found {
			t.Errorf("controls = %v, want %s among them", sf.Controls, want)
		}
	}
	st, _, _ := s.GetHostVulnState(ctx, "dev-ubuntu")
	if st.EOLMapped != 2 || st.EOLDistro != 2 || st.EOLUnknown != 0 {
		t.Errorf("host state = %+v", st)
	}

	// the exposure list: one row, fix bucket, naming the release
	page, err := s.ListExposure(ctx, ExposureQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || len(page.Findings) != 1 {
		t.Fatalf("fix bucket = %+v", page)
	}
	g := page.Findings[0]
	if g.AdvisoryID != "EOL:php:8.0" || g.EOL == nil || g.EOL.Product != "php" || g.EOL.Cycle != "8.0" || g.EOL.Stage != "eol" ||
		g.EOL.Date != "2023-11-26" || g.EOL.UpgradeTo != "8.4" || g.EOL.ProductLabel != "PHP" ||
		len(g.EOL.Origins) != 1 || g.EOL.Origins[0] != "deb.sury.org" || g.Severity != "high" || g.KEV || g.HostCount != 1 {
		t.Errorf("group = %+v eol=%+v", g, g.EOL)
	}
	if !strings.Contains(g.Summary, "PHP 8.0 reached end of life on 2023-11-26") {
		t.Errorf("summary = %q", g.Summary)
	}
	if w, _ := s.ListExposure(ctx, ExposureQuery{Bucket: BucketWatch}); w.Total != 0 {
		t.Errorf("an eol finding leaked into the watch bucket: %+v", w)
	}
	sum, err := s.ExposureSummary(ctx, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Fixable.Findings != 1 || sum.Fixable.Advisories != 1 || sum.Fixable.EOL.Findings != 1 || sum.Fixable.EOL.Advisories != 1 || sum.Fixable.KEV.Findings != 0 {
		t.Errorf("summary fixable = %+v", sum.Fixable)
	}
	// the drawer: an EOL group has no advisory row, and that is not an error
	det, err := s.GetExposureDetail(ctx, "EOL:php:8.0", BucketFix, ExposureOpen)
	if err != nil || len(det.Findings) != 1 || det.Advisory != nil || det.Findings[0].EOL == nil {
		t.Fatalf("detail = %+v, %v", det, err)
	}
	fs, _ := s.FindingsSummary(ctx, "dev-casper")
	if len(fs) != 1 || fs[0].Open != 1 || len(fs[0].SeriousKeys) != 1 {
		t.Errorf("host summary = %+v", fs)
	}

	// a second identical run keeps one open row and its first_seen
	first := sf.FirstSeen
	if err := s.RecordFindingsFor(ctx, "dev-casper", phpRes, nil, inv); err != nil {
		t.Fatal(err)
	}
	again, _ := s.ListFindings(ctx, FindingFilter{Kind: "eol"})
	if len(again) != 1 || !again[0].FirstSeen.Equal(first) {
		t.Errorf("rerun changed the finding: %+v", again)
	}

	// the host moves to PHP 8.4: the old packages are gone, the finding closes
	upgraded := eolHost("debian", "dpkg", "php8.4-cli", "8.4.1-1", "deb.sury.org", "openssl", "1.1.1w-0+deb11u1", "Debian")
	upRes, err := vuln.Match(ctx, s, upgraded)
	if err != nil {
		t.Fatal(err)
	}
	if n := countKind(upRes, vuln.KindEOL); n != 0 || upRes.Stats.EOLSupported != 1 {
		t.Fatalf("after upgrade: %d eol, stats %+v", n, upRes.Stats)
	}
	invUp := &Inventory{Versions: map[string]string{"php8.4-cli": "8.4.1-1", "openssl": "1.1.1w-0+deb11u1"}}
	if err := s.RecordFindingsFor(ctx, "dev-casper", upRes, nil, invUp); err != nil {
		t.Fatal(err)
	}
	closed, _ := s.ListFindings(ctx, FindingFilter{Kind: "eol", IncludeResolved: true})
	if len(closed) != 1 || closed[0].ResolvedAt == nil || closed[0].Resolution != ResolutionPackageRemoved {
		t.Fatalf("closed = %+v", closed)
	}
	if open, _ := s.ListExposure(ctx, ExposureQuery{}); open.Total != 0 {
		t.Errorf("open fix list after upgrade = %d", open.Total)
	}
	if res, _ := s.ListExposure(ctx, ExposureQuery{Status: ExposureResolved}); res.Total != 1 {
		t.Errorf("resolved list = %d, want 1", res.Total)
	}
}

// An upgrade that keeps the package name (nodejs 16 to 22) is recorded as the
// host fixing it, not as the data changing.
func TestEOLResolutionDistinguishesUpgradeFromDataChange(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	eolSetup(t, s)
	expoHost(t, s, "dev-node", "node-host")
	node16 := eolHost("debian", "dpkg", "nodejs", "16.20.2-1nodesource1", "deb.nodesource.com")
	r16, _ := vuln.Match(ctx, s, node16)
	if countKind(r16, vuln.KindEOL) != 1 {
		t.Fatalf("node 16 findings: %+v", r16.Findings)
	}
	if err := s.RecordFindingsFor(ctx, "dev-node", r16, nil, &Inventory{Versions: map[string]string{"nodejs": "16.20.2-1nodesource1"}}); err != nil {
		t.Fatal(err)
	}

	// same package, new version: fixed
	node22 := eolHost("debian", "dpkg", "nodejs", "22.1.0-1nodesource1", "deb.nodesource.com")
	r22, _ := vuln.Match(ctx, s, node22)
	// node 22 is past active support (2025-10-21) but not past security support: a different finding
	if countKind(r22, vuln.KindEOL) != 1 || r22.Findings[0].EOL.Stage != "eoas" || r22.Findings[0].Severity != "low" {
		t.Fatalf("node 22 findings: %+v", r22.Findings)
	}
	if err := s.RecordFindingsFor(ctx, "dev-node", r22, nil, &Inventory{Versions: map[string]string{"nodejs": "22.1.0-1nodesource1"}}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.ListFindings(ctx, FindingFilter{Kind: "eol", IncludeResolved: true})
	byID := map[string]VulnFinding{}
	for _, f := range all {
		byID[f.AdvisoryID] = f
	}
	old := byID["EOL:nodejs:16"]
	if old.ResolvedAt == nil || old.Resolution != ResolutionFixed || old.ResolvedInstalled != "22.1.0-1nodesource1" {
		t.Errorf("node 16 finding = %+v", old)
	}
	if cur := byID["EOL:nodejs:22"]; cur.ResolvedAt != nil || cur.Severity != "low" || cur.EOL.Stage != "eoas" {
		t.Errorf("node 22 finding = %+v", cur)
	}

	// the same package at the same version, but the origin now reads as the
	// distribution's: closed because the data changed, not because it was fixed
	dist := eolHost("debian", "dpkg", "nodejs", "22.1.0-1nodesource1", "Debian")
	rd, _ := vuln.Match(ctx, s, dist)
	if countKind(rd, vuln.KindEOL) != 0 {
		t.Fatalf("distro-origin node produced a finding: %+v", rd.Findings)
	}
	if err := s.RecordFindingsFor(ctx, "dev-node", rd, nil, &Inventory{Versions: map[string]string{"nodejs": "22.1.0-1nodesource1"}}); err != nil {
		t.Fatal(err)
	}
	all, _ = s.ListFindings(ctx, FindingFilter{Kind: "eol", IncludeResolved: true})
	for _, f := range all {
		if f.AdvisoryID == "EOL:nodejs:22" && (f.ResolvedAt == nil || f.Resolution != ResolutionNoLongerAffects) {
			t.Errorf("node 22 closed as %q, want no_longer_affected", f.Resolution)
		}
	}
}

// End-of-life findings rank next to the high vulnerabilities: past security
// support is in the urgent band, right after KEV and before every vulnerability
// that is not on KEV, even one with an EPSS score; past active support only
// ranks with the low CVSS-only ones, below the security-EOL finding and below
// every scored vulnerability. The database order must be exposure.Compare's, at
// every page size, with eol rows among them.
func TestEOLRanksNextToHighVulnerabilities(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	eolSetup(t, s)
	adv := []expoAdv{
		{"A-kev", "CVE-2099-1000", "high", true, "2026-10-01", f64(0.5), f64(8.0)},
		{"B-scored", "CVE-2099-1001", "medium", false, "", f64(0.0002), f64(4.0)},
		{"C-unscored-medium", "CVE-2099-1002", "medium", false, "", nil, nil},
		{"D-unscored-high", "CVE-2099-1003", "high", false, "", nil, nil},
		{"E-cvss-only-5", "CVE-2099-1004", "medium", false, "", nil, f64(5.0)},
	}
	seedExposure(t, s, adv)
	expoHost(t, s, "dev-1", "host-1")
	h := eolHost("debian", "dpkg", "php8.0-cli", "8.0.30-3", "deb.sury.org", "php8.4-cli", "8.4.1-1", "deb.sury.org", "nodejs", "22.1.0-1nodesource1", "deb.nodesource.com")
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
	page, err := s.ListExposure(ctx, ExposureQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, g := range page.Findings {
		order = append(order, g.AdvisoryID)
	}
	// KEV, then past-security-support PHP 8.0 above the EPSS-scored (0.0002) CVE,
	// then the CVSS-only 5.0 CVE, then past-active-support Node 22 (2.0
	// equivalent) below it but above the CVEs with no score at all, which keep
	// their severity order.
	want := []string{"A-kev", "EOL:php:8.0", "B-scored", "E-cvss-only-5", "EOL:nodejs:22", "D-unscored-high", "C-unscored-medium"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v\nwant    %v", order, want)
	}
	for _, g := range page.Findings {
		if strings.HasPrefix(g.AdvisoryID, "EOL:") && (g.EOL == nil || g.KEV || g.EPSS != nil || g.CVSS != nil) {
			t.Errorf("%s: eol row carries %+v kev=%v epss=%v cvss=%v", g.AdvisoryID, g.EOL, g.KEV, g.EPSS, g.CVSS)
		}
	}

	// The same order from the Go rule, over the whole list, and by keyset at
	// several page sizes.
	items := make([]exposure.Item, 0, len(page.Findings))
	for _, g := range page.Findings {
		it := exposure.Item{AdvisoryID: g.AdvisoryID, Severity: g.Severity, KEV: g.KEV, EPSS: g.EPSS, CVSS: g.CVSS}
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
	for _, size := range []int{1, 2, 3, 200} {
		var got []string
		cursor := ""
		for pages := 0; pages < 20; pages++ {
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
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("limit %d paged to\n %v\nwant\n %v", size, got, want)
		}
	}
}

func countKind(r vuln.Result, k vuln.Kind) int {
	n := 0
	for _, f := range r.Findings {
		if f.Kind == k {
			n++
		}
	}
	return n
}
