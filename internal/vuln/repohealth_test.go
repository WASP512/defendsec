package vuln

import (
	"context"
	"strings"
	"testing"
	"time"

	"defendsec/internal/repohealth"
)

// noRanges is a RangeSource with nothing in it: repository health is judged
// from what the host reports and needs no feed.
type noRanges struct{}

func (noRanges) DistroRanges(context.Context, string, string, []string) ([]Candidate, error) {
	return nil, nil
}
func (noRanges) UpstreamRanges(context.Context, []string) ([]Candidate, error) { return nil, nil }
func (noRanges) DistroCovered(context.Context, string, string) (bool, error)   { return false, nil }

var asOf = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func day(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func report(repos ...repohealth.Repo) *repohealth.Report {
	return &repohealth.Report{Manager: repohealth.ManagerApt, LastRefresh: day("2026-10-23"), LastRefreshSource: "update-success-stamp", Repos: repos}
}

func repoFindings(r Result) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Kind == KindRepoHealth {
			out = append(out, f)
		}
	}
	return out
}

func TestRepoHealthFindingPerBrokenRepository(t *testing.T) {
	h := Host{AsOf: asOf, RepoHealth: report(
		repohealth.Repo{ID: "http://a.invalid/apt stable", Label: "http://a.invalid/apt stable", Signature: repohealth.SigExpiredKey, KeyID: "EEEE"},
		repohealth.Repo{ID: "http://b.invalid/apt stable", Label: "http://b.invalid/apt stable", Signature: repohealth.SigGood, ReleaseDate: day("2026-10-20")},
		repohealth.Repo{ID: "http://c.invalid/apt stable", Label: "http://c.invalid/apt stable", Signature: repohealth.SigNoPubkey, KeyID: "FFFF"},
	)}
	res, err := Match(context.Background(), noRanges{}, h)
	if err != nil {
		t.Fatal(err)
	}
	got := repoFindings(res)
	if len(got) != 2 {
		t.Fatalf("got %d repo findings, want one per broken repository: %+v", len(got), got)
	}
	if !res.RepoHealthAssessed || res.Stats.RepoHealthChecked != 3 || res.Stats.RepoHealthFindings != 2 {
		t.Errorf("stats = %+v assessed = %v", res.Stats, res.RepoHealthAssessed)
	}
	for _, f := range got {
		if f.Severity != "high" || f.Basis != BasisHost || f.Repo == nil || f.Fixed != "" || f.KEV || f.CVE != "" {
			t.Errorf("finding = %+v", f)
		}
		if !strings.HasPrefix(f.AdvisoryID, RepoAdvisoryPrefix) || len(f.AdvisoryID) != len(RepoAdvisoryPrefix)+12 {
			t.Errorf("advisory id = %q", f.AdvisoryID)
		}
		if f.SourcePackage != f.Repo.RepoID || f.Package != f.Repo.Label {
			t.Errorf("family/label = %q %q", f.SourcePackage, f.Package)
		}
	}
	if got[0].AdvisoryID == got[1].AdvisoryID {
		t.Error("two repositories share an advisory id")
	}
	if got[0].Repo.Fix == "" || !strings.Contains(got[0].Repo.Fix, "signed-by") {
		t.Errorf("fix = %q", got[0].Repo.Fix)
	}
}

func TestRepoHealthNeedsNoFeedAndNoDistro(t *testing.T) {
	res, err := Match(context.Background(), noRanges{}, Host{AsOf: asOf, RepoHealth: report(
		repohealth.Repo{ID: "r", Label: "r", Signature: repohealth.SigExpiredKey})})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageNoDistro || len(repoFindings(res)) != 1 {
		t.Errorf("coverage %v findings %d", res.Coverage, len(repoFindings(res)))
	}
}

func TestRepoHealthAbsentOrEmptyReportIsNotAssessed(t *testing.T) {
	for name, rep := range map[string]*repohealth.Report{"nil": nil, "empty": {}} {
		res, err := Match(context.Background(), noRanges{}, Host{AsOf: asOf, RepoHealth: rep})
		if err != nil {
			t.Fatal(err)
		}
		if res.RepoHealthAssessed || len(repoFindings(res)) != 0 {
			t.Errorf("%s report was treated as assessed: %+v", name, res)
		}
	}
	// A host that reports no repositories at all was assessed: there is nothing wrong.
	res, _ := Match(context.Background(), noRanges{}, Host{AsOf: asOf, RepoHealth: report()})
	if !res.RepoHealthAssessed || len(repoFindings(res)) != 0 {
		t.Errorf("empty repository list: %+v", res)
	}
}

func TestRepoHealthStaleIndexIsMediumAndUsesTheHostsThreshold(t *testing.T) {
	r := repohealth.Repo{ID: "r", Label: "r", Signature: repohealth.SigGood, ReleaseDate: day("2026-10-01")}
	rep := report(r)
	rep.LastRefresh = day("2026-10-18") // refreshed 6 days ago
	res, _ := Match(context.Background(), noRanges{}, Host{AsOf: asOf, RepoHealth: rep})
	if len(repoFindings(res)) != 0 {
		t.Fatalf("default 7-day threshold flagged a 6-day-old refresh: %+v", repoFindings(res))
	}
	res, _ = Match(context.Background(), noRanges{}, Host{AsOf: asOf, RepoHealth: rep, StaleAfter: 5 * 24 * time.Hour})
	got := repoFindings(res)
	if len(got) != 1 || got[0].Severity != "medium" || got[0].FixState != repohealth.CodeIndexStale || got[0].Repo.StaleAfterDays != 5 {
		t.Fatalf("5-day threshold: %+v", got)
	}
}

// A repository id is an address, with slashes and spaces: the advisory id that
// travels in URLs is a hash of it, stable and distinct.
func TestRepoAdvisoryIDIsStableAndDistinct(t *testing.T) {
	a := RepoAdvisoryID("https://ppa.example.invalid/ondrej/php jammy")
	if a != RepoAdvisoryID("https://ppa.example.invalid/ondrej/php jammy") {
		t.Error("not stable")
	}
	if a == RepoAdvisoryID("https://ppa.example.invalid/ondrej/php noble") {
		t.Error("two suites share an id")
	}
	if strings.ContainsAny(a, "/ ?#") {
		t.Errorf("id %q is not URL-safe", a)
	}
}
