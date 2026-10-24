package storepg

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"defendsec/internal/controls"
	"defendsec/internal/exposure"
	"defendsec/internal/presence"
	"defendsec/internal/repohealth"
	"defendsec/internal/surface"
	"defendsec/internal/vuln"
)

// Slice 11: repository health in the findings store and the exposure list.
// Every test that counts the whole database runs in a throwaway one.

var repoNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func rtm(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func repoReport(repos ...repohealth.Repo) *repohealth.Report {
	return &repohealth.Report{Manager: repohealth.ManagerApt, LastRefresh: rtm("2026-10-23"), LastRefreshSource: "update-success-stamp", Repos: repos}
}

var (
	repoBroken = repohealth.Repo{ID: "file:/srv/lab dstest", Label: "file:/srv/lab dstest", URI: "file:/srv/lab", Suite: "dstest",
		Signature: repohealth.SigExpiredKey, KeyID: "13EDAB264F59ECF5", Detail: "gpgv checked the index in place."}
	repoHealthy = repohealth.Repo{ID: "http://archive.ubuntu.com/ubuntu jammy", Label: "http://archive.ubuntu.com/ubuntu jammy",
		Signature: repohealth.SigGood, ReleaseDate: rtm("2022-04-21")}
)

func repoMatch(t *testing.T, s *Store, dev string, rep *repohealth.Report) vuln.Result {
	t.Helper()
	h := vuln.Host{RepoHealth: rep, AsOf: repoNow}
	res, err := vuln.Match(context.Background(), s, h)
	if err != nil {
		t.Fatal(err)
	}
	inv := &Inventory{}
	if rep != nil && !rep.Empty() {
		inv.Repos = map[string]bool{}
		for _, r := range rep.Repos {
			inv.Repos[r.ID] = true
		}
	}
	if err := s.RecordFindingsFor(context.Background(), dev, res, nil, inv); err != nil {
		t.Fatal(err)
	}
	return res
}

func openRepoFindings(t *testing.T, s *Store, dev string, resolved bool) []VulnFinding {
	t.Helper()
	all, err := s.ListFindings(context.Background(), FindingFilter{DeviceID: dev, Kind: "repo_health", IncludeResolved: true})
	if err != nil {
		t.Fatal(err)
	}
	var out []VulnFinding
	for _, f := range all {
		if (f.ResolvedAt != nil) == resolved {
			out = append(out, f)
		}
	}
	return out
}

// The whole path on a real database: the matcher judges the agent's report, the
// store keeps one finding per broken repository, the exposure list ranks it, and
// it resolves when the repository is put right.
func TestRepoHealthFindingEndToEnd(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	expoHost(t, s, "dev-1", "host-1")

	res := repoMatch(t, s, "dev-1", repoReport(repoBroken, repoHealthy))
	if !res.RepoHealthAssessed || res.Stats.RepoHealthChecked != 2 || res.Stats.RepoHealthFindings != 1 {
		t.Fatalf("stats = %+v assessed=%v", res.Stats, res.RepoHealthAssessed)
	}
	open := openRepoFindings(t, s, "dev-1", false)
	if len(open) != 1 {
		t.Fatalf("open repo findings = %d, want exactly the broken repository", len(open))
	}
	f := open[0]
	if f.Severity != "high" || f.Kind != "repo_health" || f.Basis != "host" || !strings.HasPrefix(f.AdvisoryID, "REPO:") || len(f.AdvisoryID) != 17 {
		t.Errorf("finding = %+v", f)
	}
	if f.Repo == nil || f.Repo.Label != repoBroken.Label || f.Repo.Signature != "expired_key" || f.Repo.KeyID != "13EDAB264F59ECF5" ||
		len(f.Repo.Problems) != 1 || f.Repo.Problems[0].Code != "key_expired" || !strings.Contains(f.Repo.Fix, "signed-by=") || f.Repo.StaleAfterDays != 7 {
		t.Errorf("repo detail = %+v", f.Repo)
	}
	// Control tags: NIST SI-2 and CM-6, CIS v8 7.3 and 7.4.
	for _, want := range []string{"nist-800-53:SI-2", "nist-800-53:CM-6", "cis-v8:7.3", "cis-v8:7.4"} {
		found := false
		for _, c := range f.Controls {
			found = found || c == want
		}
		if !found {
			t.Errorf("controls %v lack %s", f.Controls, want)
		}
	}
	if len(controls.Tag(controls.SignalRepoHealth)) < 4 {
		t.Errorf("repo.health signal maps to %v", controls.Tag(controls.SignalRepoHealth))
	}
	// The same finding again is the same row, not a second one.
	repoMatch(t, s, "dev-1", repoReport(repoBroken, repoHealthy))
	if n := len(openRepoFindings(t, s, "dev-1", false)); n != 1 {
		t.Errorf("after re-match: %d open", n)
	}

	page, err := s.ListExposure(ctx, ExposureQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Findings) != 1 || page.Findings[0].Repo == nil || page.Findings[0].Repo.Label != repoBroken.Label ||
		page.Findings[0].Repo.Code != "key_expired" || page.Findings[0].KEV {
		t.Fatalf("exposure = %+v", page.Findings)
	}
	sum, err := s.ExposureSummary(ctx, repoNow)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Fixable.RepoHealth.Findings != 1 || sum.Fixable.RepoHealth.Advisories != 1 || sum.Fixable.Advisories != 1 || sum.Fixable.Hosts != 1 {
		t.Errorf("summary fixable = %+v", sum.Fixable)
	}
	det, err := s.GetExposureDetail(ctx, f.AdvisoryID, "", "")
	if err != nil || len(det.Findings) != 1 || det.Findings[0].Repo == nil {
		t.Fatalf("detail = %+v err=%v", det, err)
	}

	// A report that says nothing (an old agent, a collector failure) leaves the
	// finding open: missing evidence is not a repaired repository.
	res = repoMatch(t, s, "dev-1", nil)
	if res.RepoHealthAssessed {
		t.Error("a missing report was treated as assessed")
	}
	if n := len(openRepoFindings(t, s, "dev-1", false)); n != 1 {
		t.Errorf("a missing report closed the finding: %d open", n)
	}

	// The repository is fixed: the finding closes, as fixed.
	fixed := repoBroken
	fixed.Signature, fixed.KeyID = repohealth.SigGood, ""
	repoMatch(t, s, "dev-1", repoReport(fixed, repoHealthy))
	if n := len(openRepoFindings(t, s, "dev-1", false)); n != 0 {
		t.Fatalf("still open after the repository was fixed: %d", n)
	}
	closed := openRepoFindings(t, s, "dev-1", true)
	if len(closed) != 1 || closed[0].Resolution != ResolutionFixed {
		t.Fatalf("closed = %+v", closed)
	}

	// It breaks again: reopened, and the interval that ended is kept.
	repoMatch(t, s, "dev-1", repoReport(repoBroken, repoHealthy))
	if n := len(openRepoFindings(t, s, "dev-1", false)); n != 1 {
		t.Fatalf("not reopened: %d", n)
	}
	var intervals int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM vuln_finding_intervals WHERE device_id='dev-1' AND kind='repo_health'`).Scan(&intervals); err != nil || intervals != 1 {
		t.Errorf("intervals = %d err=%v", intervals, err)
	}

	// The repository is removed from the host: closed as no longer affected.
	repoMatch(t, s, "dev-1", repoReport(repoHealthy))
	closed = openRepoFindings(t, s, "dev-1", true)
	if len(closed) != 1 || closed[0].Resolution != ResolutionNoLongerAffects {
		t.Fatalf("after removal: %+v", closed)
	}
}

// An expired key and a stale index on one repository are one finding at the
// higher severity, listing both problems.
func TestRepoHealthSeveralProblemsOneFinding(t *testing.T) {
	s, _ := scratchStore(t)
	expoHost(t, s, "dev-1", "host-1")
	r := repoBroken
	r.ReleaseDate = rtm("2026-09-01")
	rep := repoReport(r)
	rep.LastRefresh = rtm("2026-09-02")
	repoMatch(t, s, "dev-1", rep)
	open := openRepoFindings(t, s, "dev-1", false)
	if len(open) != 1 || open[0].Severity != "high" || len(open[0].Repo.Problems) != 2 {
		t.Fatalf("%+v", open)
	}
	// The stale index alone is medium.
	healthy := r
	healthy.Signature, healthy.KeyID = repohealth.SigGood, ""
	rep = repoReport(healthy)
	rep.LastRefresh = rtm("2026-09-02")
	repoMatch(t, s, "dev-1", rep)
	open = openRepoFindings(t, s, "dev-1", false)
	if len(open) != 1 || open[0].Severity != "medium" || open[0].Repo.Problems[0].Code != "index_stale" {
		t.Fatalf("%+v", open)
	}
}

// Repository rows share the order with vulnerabilities, end-of-life releases and
// surface findings, in SQL and in Go. The rows are chosen so that changing any
// one band, score or tie-break constant reorders the list: an EOL release, a
// dead repository and a high surface finding all sit at 8.0 in the urgent band
// and are told apart only by the id (EOL: < REPO: < surface:).
func TestRepoHealthRanksWithEverythingElse(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	eolSetup(t, s)
	adv := []expoAdv{
		{"A-kev", "CVE-2099-1000", "high", true, "2026-10-01", f64(0.5), f64(8.0)},
		{"B-scored", "CVE-2099-1001", "medium", false, "", f64(0.0002), f64(4.0)},
		{"E-cvss-only-5", "CVE-2099-1004", "medium", false, "", nil, f64(5.0)},
		{"F-cvss-only-3", "CVE-2099-1005", "low", false, "", nil, f64(3.0)},
	}
	seedExposure(t, s, adv)
	expoHost(t, s, "dev-1", "host-1")
	expoHost(t, s, "dev-2", "host-2")

	// EOL PHP 8.0 (urgent, 8.0).
	h := eolHost("debian", "dpkg", "php8.0-cli", "8.0.30-3", "deb.sury.org")
	h.RepoHealth = repoReport(repoBroken, func() repohealth.Repo { // medium: a stale index
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
	// A high surface finding (urgent, 8.0).
	dom := surfaceAsset(t, s, "ip", "192.0.2.10", true)
	if _, err := s.RecordSurfaceScan(ctx, dom.ID, "schedule", report(dom, repoNow.Add(-time.Hour),
		result("ports", true, "", finding("ports", "ports.open", "3389/tcp", surface.SevHigh)))); err != nil {
		t.Fatal(err)
	}

	page, err := s.ListExposure(ctx, ExposureQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	for _, g := range page.Findings {
		switch {
		case g.Repo != nil:
			order = append(order, "repo:"+g.Severity)
		case g.Surface != nil:
			order = append(order, "surface:"+g.Severity)
		default:
			order = append(order, g.AdvisoryID)
		}
	}
	// KEV; then the 8.0 urgent group in id order (EOL:, REPO:, surface:);
	// then EPSS-scored; then the CVSS-only 5.0 CVE with the medium repo row
	// (equal 5.0 and equal "medium" for both, so the id order: E-cvss before REPO:
	// is false bytewise ('E' < 'R') and the CVE comes first); then the 3.0 one.
	want := []string{"A-kev", "EOL:php:8.0", "repo:high", "surface:high", "B-scored", "E-cvss-only-5", "repo:medium", "F-cvss-only-3"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v\nwant    %v", order, want)
	}

	// The Go rule over the same rows gives the same order, and keyset paging
	// at several sizes reproduces it.
	items := make([]exposure.Item, 0, len(page.Findings))
	for _, g := range page.Findings {
		it := exposure.Item{AdvisoryID: g.AdvisoryID, Severity: g.Severity, KEV: g.KEV, EPSS: g.EPSS, CVSS: g.CVSS,
			Surface: g.Source == SourceSurface, RepoHealth: g.Repo != nil}
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
		var all []string
		for _, g := range page.Findings {
			all = append(all, g.AdvisoryID)
		}
		if strings.Join(got, ",") != strings.Join(all, ",") {
			t.Fatalf("limit %d paged to\n %v\nwant\n %v", size, got, all)
		}
	}
}

// The agent's report, with the server's verdict, survives the database: apid
// restarts read it back, and the console export carries it.
func TestRepoHealthReportPersistsWithItsVerdict(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	rep := repoReport(repoBroken, repoHealthy)
	a := repohealth.Assess(*rep, repoNow, 0)
	rep.Assessment, rep.AssessedAt = &a, repoNow.Format(time.RFC3339)
	d := presence.Device{ID: "dev-1", Hostname: "host-1", Platform: "linux", LastSeen: repoNow.Format(time.RFC3339),
		Transport: "mtls-grpc", RepoHealth: rep}
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	devs, err := s.LoadDevices(ctx)
	if err != nil || len(devs) != 1 {
		t.Fatalf("load: %v %d", err, len(devs))
	}
	got := devs[0].RepoHealth
	if got == nil || got.Assessment == nil || got.Assessment.Reliability != repohealth.Unreliable || len(got.Repos) != 2 ||
		got.Repos[0].Signature != repohealth.SigExpiredKey || got.Repos[0].KeyID != "13EDAB264F59ECF5" {
		t.Fatalf("loaded = %+v", got)
	}
	raw, err := s.ExportAgentsJSON(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Devices []presence.Device }
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Devices) != 1 || doc.Devices[0].RepoHealth == nil ||
		doc.Devices[0].RepoHealth.Assessment == nil || doc.Devices[0].RepoHealth.Assessment.Reliability != repohealth.Unreliable {
		t.Fatalf("export = %s", raw)
	}

	// A later inventory with no repository evidence replaces the verdict with
	// nothing: the console must not keep showing last week's "reliable".
	d.RepoHealth = nil
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	devs, _ = s.LoadDevices(ctx)
	if devs[0].RepoHealth != nil {
		t.Errorf("stale verdict kept: %+v", devs[0].RepoHealth)
	}
}
