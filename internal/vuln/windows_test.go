package vuln

import (
	"context"
	"errors"
	"testing"
)

func winRange(cve, kb string, kev bool) Candidate {
	return rng(Candidate{CVE: cve, Ecosystem: "MSRC", Distro: WindowsDistro, Package: kb, Fixed: kb,
		State: StateFixed, Feed: "msrc", KEV: kev, Severity: "critical"})
}

func TestNormalizeKB(t *testing.T) {
	for in, want := range map[string]string{
		"5122876": "KB5122876", "KB5122876": "KB5122876", "kb5122876": "KB5122876", " KB 5122876 ": "KB5122876",
		"": "", "KB": "", "KB12": "", "Security Intelligence Update": "", "KB5122876x": "", "KB1234567890": "",
	} {
		if got := NormalizeKB(in); got != want {
			t.Errorf("NormalizeKB(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchWindowsMissingKBFixesCVEs(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{
		winRange("CVE-2099-0001", "KB5000001", true),
		winRange("CVE-2099-0002", "KB5000001", false),
		winRange("CVE-2099-0003", "KB5000002", false),
		winRange("CVE-2099-0004", "KB5000099", false), // a KB the device does not miss
	}}
	res, err := MatchWindows(context.Background(), src, []MissingPatch{
		{KB: "5000001", Title: "2099-01 Cumulative Update", Status: "approved_pending"},
		{KB: "KB5000002", Status: "not_approved"},
		{KB: "", Title: "Security Intelligence Update"}, // no KB: examined, nothing to map
		{KB: "KB5000777"}, // unknown to the feed
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageFull || res.Distro != "windows" {
		t.Fatalf("coverage %s distro %s", res.Coverage, res.Distro)
	}
	if len(res.Findings) != 3 {
		t.Fatalf("findings = %+v", res.Findings)
	}
	for _, f := range res.Findings {
		if f.Kind != KindFinding || f.Basis != BasisDistro || f.Installed != "not installed" || f.Fixed != f.Package {
			t.Errorf("finding %+v", f)
		}
		if f.Key() != f.AdvisoryID+"\x00"+f.Package {
			t.Errorf("key %q", f.Key())
		}
	}
	first := res.Findings[0]
	if first.CVE != "CVE-2099-0001" || !first.KEV || first.Package != "KB5000001" ||
		first.Reason != "KB5000001 fixes this and is approved in the RMM patch policy and waiting to install (2099-01 Cumulative Update)" {
		t.Errorf("first = %+v", first)
	}
	if res.Findings[2].Reason != "KB5000002 fixes this and is not yet approved in the RMM patch policy" {
		t.Errorf("third reason = %q", res.Findings[2].Reason)
	}
	// Two KBs with a KB each, one of which the feed knows nothing about.
	if res.Stats.Packages != 3 || res.Stats.DistroMapped != 2 || res.Stats.Advisories != 3 {
		t.Errorf("stats = %+v", res.Stats)
	}
}

func TestMatchWindowsNoFeedIsNotClean(t *testing.T) {
	// A feed for another distro only: the Windows space is empty.
	src := &fakeSource{ranges: []Candidate{rng(Candidate{CVE: "CVE-2099-0100", Distro: "ubuntu", Release: "22.04",
		Package: "openssl", Fixed: "1", State: StateFixed})}}
	res, err := MatchWindows(context.Background(), src, []MissingPatch{{KB: "KB5000001"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageNoFeed || len(res.Findings) != 0 {
		t.Fatalf("a device with no feed to match against must be no_feed, got %s with %d findings", res.Coverage, len(res.Findings))
	}
}

func TestMatchWindowsNothingMissingIsCoveredAndEmpty(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{winRange("CVE-2099-0001", "KB5000001", false)}}
	res, err := MatchWindows(context.Background(), src, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage != CoverageFull || len(res.Findings) != 0 || res.Stats.Packages != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestMatchWindowsIgnoresNonFixedRanges(t *testing.T) {
	c := winRange("CVE-2099-0001", "KB5000001", false)
	c.State = StateAffected
	src := &fakeSource{ranges: []Candidate{c, winRange("CVE-2099-0002", "KB5000001", false)}}
	res, err := MatchWindows(context.Background(), src, []MissingPatch{{KB: "KB5000001"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].CVE != "CVE-2099-0002" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestMatchWindowsPrefersApprovedStatusForDuplicateKB(t *testing.T) {
	src := &fakeSource{ranges: []Candidate{winRange("CVE-2099-0001", "KB5000001", false)}}
	res, err := MatchWindows(context.Background(), src, []MissingPatch{
		{KB: "KB5000001", Status: "not_approved"}, {KB: "5000001", Status: "approved_pending"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Reason != "KB5000001 fixes this and is approved in the RMM patch policy and waiting to install" {
		t.Fatalf("findings = %+v", res.Findings)
	}
}

func TestMatchWindowsStoreErrors(t *testing.T) {
	boom := errors.New("db down")
	if _, err := MatchWindows(context.Background(), &fakeSource{err: boom, ranges: []Candidate{winRange("CVE-2099-0001", "KB5000001", false)}},
		[]MissingPatch{{KB: "KB5000001"}}); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}
