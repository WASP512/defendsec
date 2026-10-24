package exposure

import (
	"sort"
	"testing"
)

// The tie-break is a stated rule (TieRank), not the byte order of the ids: two
// rows that agree on everything the ranking measures are ordered by the kind of
// row, whatever their ids look like.
func TestTieRankOrdersKindsAtEqualScoreAndSeverity(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	// Rest band, CVSS-equivalent 5.0, severity medium: a CVE with no EPSS, a stale
	// repository, an identity finding and a surface finding. The ids are chosen so
	// that the id order is the reverse of the rule's.
	rest := []Item{
		{AdvisoryID: SurfaceKeyPrefix + "000000000001", Severity: "medium", Surface: true},
		{AdvisoryID: IdentityKeyPrefix + "000000000001", Severity: "medium", Identity: true},
		{AdvisoryID: RepoKeyPrefix + "aaaaaaaaaaaa", Severity: "medium", RepoHealth: true},
		{AdvisoryID: "zzz-lowercase-vulnerability-id", Severity: "medium", CVSS: f(5.0)},
	}
	// Urgent band, 8.0 and high: security-EOL, a dead repository, an identity
	// finding, an exposed surface finding.
	urgent := []Item{
		{AdvisoryID: SurfaceKeyPrefix + "000000000001", Severity: "high", Surface: true},
		{AdvisoryID: IdentityKeyPrefix + "000000000001", Severity: "high", Identity: true},
		{AdvisoryID: RepoKeyPrefix + "aaaaaaaaaaaa", Severity: "high", RepoHealth: true},
		{AdvisoryID: "EOL:zzz:1", Severity: "high", EOLStage: EOLStageEOL},
	}
	// Rest band, 2.0 and low: a CVSS-only vulnerability, then past-active-support.
	low := []Item{
		{AdvisoryID: "EOL:a:1", Severity: "low", EOLStage: EOLStageEOAS},
		{AdvisoryID: "zzz", Severity: "low", CVSS: f(2.0)},
	}
	for name, c := range map[string]struct {
		items []Item
		want  []string
	}{
		"rest 5.0 medium": {rest, []string{"zzz-lowercase-vulnerability-id", RepoKeyPrefix + "aaaaaaaaaaaa", IdentityKeyPrefix + "000000000001", SurfaceKeyPrefix + "000000000001"}},
		"urgent 8.0 high": {urgent, []string{"EOL:zzz:1", RepoKeyPrefix + "aaaaaaaaaaaa", IdentityKeyPrefix + "000000000001", SurfaceKeyPrefix + "000000000001"}},
		"rest 2.0 low":    {low, []string{"zzz", "EOL:a:1"}},
	} {
		for shift := 0; shift < len(c.items); shift++ {
			items := append(append([]Item(nil), c.items[shift:]...), c.items[:shift]...)
			sort.Slice(items, func(i, j int) bool { return Compare(items[i], items[j]) < 0 })
			for i, w := range c.want {
				if items[i].AdvisoryID != w {
					t.Fatalf("%s (rotation %d): position %d is %s, want %s\nfull order %v", name, shift, i, items[i].AdvisoryID, w, ids(items))
				}
			}
		}
	}
}

func TestTieRankValuesAndPrecedence(t *testing.T) {
	cases := []struct {
		name string
		item Item
		want int
	}{
		{"vulnerability", Item{AdvisoryID: "CVE-1"}, TieVulnerability},
		{"kev", Item{AdvisoryID: "CVE-1", KEV: true}, TieVulnerability},
		{"eol", Item{EOLStage: EOLStageEOL}, TieEOL},
		{"eoas", Item{EOLStage: EOLStageEOAS}, TieEOL},
		{"unknown stage is no eol row", Item{EOLStage: "other"}, TieVulnerability},
		{"repository", Item{RepoHealth: true}, TieRepository},
		{"identity", Item{Identity: true}, TieIdentity},
		{"surface", Item{Surface: true}, TieSurface},
		// A row carrying two flags is the kind Band and effective treat it as.
		{"surface beats repository", Item{Surface: true, RepoHealth: true}, TieSurface},
		{"repository beats eol", Item{RepoHealth: true, EOLStage: EOLStageEOL}, TieRepository},
	}
	for _, c := range cases {
		if got := TieRank(c.item); got != c.want {
			t.Errorf("%s: TieRank = %d, want %d", c.name, got, c.want)
		}
	}
	if !(TieVulnerability < TieEOL && TieEOL < TieRepository && TieRepository < TieIdentity && TieIdentity < TieSurface) {
		t.Fatal("the documented order is vulnerability, end-of-life, repository, identity, surface")
	}
}

// Within one kind the id decides, bytewise, and the order stays total.
func TestTieWithinAKindFallsToTheIDBytewise(t *testing.T) {
	a := Item{AdvisoryID: SurfaceKeyPrefix + "000000000001", Severity: "high", Surface: true}
	b := Item{AdvisoryID: SurfaceKeyPrefix + "000000000002", Severity: "high", Surface: true}
	if Compare(a, b) >= 0 || Compare(b, a) <= 0 || Compare(a, a) != 0 {
		t.Fatal("the older (lower) surface finding first, and equal only to itself")
	}
}
