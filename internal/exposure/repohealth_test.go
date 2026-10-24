package exposure

import (
	"sort"
	"testing"
)

// Repository-health rows (slice 11) rank like surface findings of the same
// severity: a high one in the urgent band at 8.0, a medium one in the rest band
// at 5.0, and their KEV, EPSS and CVSS (none) never matter.
func TestRepoHealthRanksWithTheUrgentBandAndTheMediumRest(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	items := []Item{
		{AdvisoryID: "F-cvss-3", Severity: "low", CVSS: f(3)},
		{AdvisoryID: "REPO:aaaaaaaaaaaa", Severity: "medium", RepoHealth: true},
		{AdvisoryID: "E-cvss-5", Severity: "medium", CVSS: f(5)},
		{AdvisoryID: "B-epss", Severity: "medium", EPSS: f(0.0002), CVSS: f(4)},
		{AdvisoryID: "surface:1", Severity: "high", Surface: true},
		{AdvisoryID: "REPO:bbbbbbbbbbbb", Severity: "high", RepoHealth: true},
		{AdvisoryID: "EOL:php:8.0", Severity: "high", EOLStage: EOLStageEOL},
		{AdvisoryID: "A-kev", Severity: "high", KEV: true, EPSS: f(0.5), CVSS: f(8)},
	}
	sort.Slice(items, func(i, j int) bool { return Compare(items[i], items[j]) < 0 })
	var got []string
	for _, i := range items {
		got = append(got, i.AdvisoryID)
	}
	want := []string{"A-kev", "EOL:php:8.0", "REPO:bbbbbbbbbbbb", "surface:1", "B-epss", "E-cvss-5", "REPO:aaaaaaaaaaaa", "F-cvss-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v\nwant    %v", got, want)
		}
	}
}

func TestRepoHealthIgnoresVulnerabilityFieldsAndKEVStillWins(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	// Scores handed to a repository row do not lift it above a KEV vulnerability or change its band.
	repo := Item{AdvisoryID: "REPO:x", Severity: "high", RepoHealth: true, EPSS: f(0.99), CVSS: f(10)}
	if Band(repo) != BandUrgent {
		t.Errorf("band = %d", Band(repo))
	}
	if Compare(Item{AdvisoryID: "z-kev", KEV: true, Severity: "low"}, repo) >= 0 {
		t.Error("a KEV vulnerability must rank above a repository row")
	}
	if Compare(repo, Item{AdvisoryID: "a-cve", EPSS: f(0.999), CVSS: f(10), Severity: "critical"}) >= 0 {
		t.Error("a high repository row must rank above a non-KEV vulnerability, whatever its EPSS")
	}
	if Band(Item{AdvisoryID: "REPO:y", Severity: "medium", RepoHealth: true}) != BandRest {
		t.Error("a medium repository row is in the rest band")
	}
}
