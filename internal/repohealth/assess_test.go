package repohealth

import (
	"strings"
	"testing"
	"time"
)

var asOf = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func tm(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func aptReport(refresh *time.Time, repos ...Repo) Report {
	return Report{Manager: ManagerApt, LastRefresh: refresh, LastRefreshSource: "update-success-stamp", Repos: repos}
}

func codes(a Assessment, id string) []string {
	var out []string
	for _, p := range a.ForRepo(id) {
		out = append(out, p.Code+":"+p.Severity)
	}
	return out
}

func TestAssessKeyProblemsAreHigh(t *testing.T) {
	for _, tc := range []struct {
		sig  Sig
		code string
	}{
		{SigExpiredKey, CodeKeyExpired}, {SigNoPubkey, CodeKeyMissing}, {SigRevoked, CodeKeyRevoked},
		{SigBad, CodeSigBad}, {SigUnsigned, CodeUnsigned}, {SigNoIndex, CodeNoIndex},
	} {
		a := Assess(aptReport(tm("2026-10-23"), Repo{ID: "r", Label: "r", Signature: tc.sig, KeyID: "ABCD"}), asOf, 0)
		if got := codes(a, "r"); len(got) != 1 || got[0] != tc.code+":high" {
			t.Errorf("%s: %v", tc.sig, got)
		}
		if a.Reliability != Unreliable || len(a.Reasons) == 0 {
			t.Errorf("%s: reliability %v reasons %v", tc.sig, a.Reliability, a.Reasons)
		}
	}
}

func TestAssessHealthyRepositoryIsReliable(t *testing.T) {
	a := Assess(aptReport(tm("2026-10-23"), Repo{ID: "r", Label: "r", Signature: SigGood, ReleaseDate: tm("2026-10-22")}), asOf, 0)
	if a.Reliability != Reliable || len(a.Problems) != 0 || a.Checked != 1 {
		t.Errorf("%+v", a)
	}
}

// Ubuntu's base pocket says 2022-04-21 for years. An old Date on a host that
// refreshes is not a finding; the same Date on a host that has not refreshed
// is, because then nothing says the index is current.
func TestAssessOldDateNeedsAnOldRefresh(t *testing.T) {
	base := Repo{ID: "u", Label: "u", Signature: SigGood, ReleaseDate: tm("2022-04-21")}
	if a := Assess(aptReport(tm("2026-10-23"), base), asOf, 0); a.Reliability != Reliable {
		t.Errorf("refreshed host flagged: %+v", a.Problems)
	}
	a := Assess(aptReport(tm("2026-10-01"), base), asOf, 0)
	if got := codes(a, "u"); len(got) != 1 || got[0] != CodeIndexStale+":medium" {
		t.Errorf("unrefreshed host: %v", got)
	}
	// No record of a refresh at all counts as an old one.
	if got := codes(Assess(aptReport(nil, base), asOf, 0), "u"); len(got) != 1 || got[0] != CodeIndexStale+":medium" {
		t.Errorf("no refresh evidence: %v", got)
	}
	// A recent Date on a host with an old stamp is not stale: the index is current.
	fresh := base
	fresh.ReleaseDate = tm("2026-10-22")
	if a := Assess(aptReport(tm("2026-10-01"), fresh), asOf, 0); a.Reliability != Reliable {
		t.Errorf("recent date flagged: %+v", a.Problems)
	}
}

func TestAssessThresholdIsConfigurable(t *testing.T) {
	r := Repo{ID: "u", Label: "u", Signature: SigGood, ReleaseDate: tm("2026-10-01")}
	rep := aptReport(tm("2026-10-20"), r) // refreshed 4 days ago
	if a := Assess(rep, asOf, 0); a.Reliability != Reliable {
		t.Errorf("default threshold: %+v", a.Problems)
	}
	if got := codes(Assess(rep, asOf, 3*24*time.Hour), "u"); len(got) != 1 {
		t.Errorf("3-day threshold: %v", got)
	}
}

func TestAssessValidUntilPassedIsMediumAndHonoursTheOptOut(t *testing.T) {
	r := Repo{ID: "d", Label: "d", Signature: SigGood, ReleaseDate: tm("2026-10-10"), ValidUntil: tm("2026-10-17")}
	if got := codes(Assess(aptReport(tm("2026-10-23"), r), asOf, 0), "d"); len(got) != 1 || got[0] != CodeIndexExpired+":medium" {
		t.Errorf("valid-until: %v", got)
	}
	r.IgnoreValidUntil = true
	if a := Assess(aptReport(tm("2026-10-23"), r), asOf, 0); len(a.Problems) != 0 {
		t.Errorf("Check-Valid-Until: no still flagged: %+v", a.Problems)
	}
}

func TestAssessSeveralProblemsOneRepo(t *testing.T) {
	r := Repo{ID: "r", Label: "r", Signature: SigExpiredKey, KeyID: "K", ReleaseDate: tm("2026-09-01")}
	a := Assess(aptReport(tm("2026-09-02"), r), asOf, 0)
	got := codes(a, "r")
	if len(got) != 2 || got[0] != CodeKeyExpired+":high" || got[1] != CodeIndexStale+":medium" {
		t.Errorf("%v", got)
	}
	if top, _ := Highest(a.ForRepo("r")); top.Code != CodeKeyExpired {
		t.Errorf("highest = %+v", top)
	}
}

func TestAssessUnverifiedAndLimitsTaintReliabilityWithoutFindings(t *testing.T) {
	rep := aptReport(tm("2026-10-23"), Repo{ID: "r", Label: "r", Signature: SigUnverified, Detail: "gpgv could not be run"})
	rep.Limits = []string{"cannot read /etc/apt/sources.list.d/x.list"}
	a := Assess(rep, asOf, 0)
	if len(a.Problems) != 0 {
		t.Errorf("could-not-check became a finding: %+v", a.Problems)
	}
	if a.Reliability != Unreliable || len(a.Reasons) != 2 {
		t.Errorf("%v %v", a.Reliability, a.Reasons)
	}
	if !strings.Contains(a.Reasons[0], "could not be verified") {
		t.Errorf("reason = %q", a.Reasons[0])
	}
}

func TestAssessNotCheckedDoesNotTaint(t *testing.T) {
	a := Assess(aptReport(tm("2026-10-23"), Repo{ID: "r", Label: "r", Signature: SigNotChecked}), asOf, 0)
	if a.Reliability != Reliable {
		t.Errorf("%+v", a)
	}
}

func TestAssessEmptyReportIsUnassessedNeverReliable(t *testing.T) {
	if a := Assess(Report{}, asOf, 0); a.Reliability != Unassessed {
		t.Errorf("reliability = %v", a.Reliability)
	}
	// A manager that reported no repositories at all is still a report.
	if a := Assess(Report{Manager: ManagerApt}, asOf, 0); a.Reliability != Reliable || a.Checked != 0 {
		t.Errorf("%+v", a)
	}
}

func TestAssessRPMMetadataAgeAndNoCache(t *testing.T) {
	rep := Report{Manager: ManagerDNF, Repos: []Repo{
		{ID: "baseos", Label: "baseos", Signature: SigGood, MetadataTime: tm("2026-10-23")},
		{ID: "epel", Label: "epel", Signature: SigGood, MetadataTime: tm("2026-09-01")},
		{ID: "new", Label: "new", Signature: SigNoIndex},
		{ID: "old", Label: "old", Signature: SigExpiredKey, KeyID: "K", MetadataTime: tm("2026-10-23")},
	}}
	a := Assess(rep, asOf, 0)
	if got := codes(a, "baseos"); len(got) != 0 {
		t.Errorf("baseos: %v", got)
	}
	if got := codes(a, "epel"); len(got) != 1 || got[0] != CodeIndexStale+":medium" {
		t.Errorf("epel: %v", got)
	}
	if got := codes(a, "new"); len(got) != 1 || got[0] != CodeNoIndex+":medium" {
		t.Errorf("new: %v", got)
	}
	if got := codes(a, "old"); len(got) != 1 || got[0] != CodeKeyExpired+":high" {
		t.Errorf("old: %v", got)
	}
}

func TestFixTextNamesSignedByAndForbidsAptKey(t *testing.T) {
	fix := Fix(ManagerApt, CodeKeyExpired)
	for _, want := range []string{"signed-by=", "/etc/apt/keyrings", "apt-key", "apt-get update"} {
		if !strings.Contains(fix, want) {
			t.Errorf("apt fix lacks %q: %s", want, fix)
		}
	}
	if f := Fix(ManagerDNF, CodeKeyExpired); !strings.Contains(f, "rpm --import") || !strings.Contains(f, "dnf makecache") {
		t.Errorf("dnf fix = %s", f)
	}
	if Fix("pacman", CodeKeyExpired) != "" {
		t.Error("unknown manager got a fix")
	}
}
