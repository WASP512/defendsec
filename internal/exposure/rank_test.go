package exposure

import (
	"sort"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

func d(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func TestCompareOrder(t *testing.T) {
	// Listed in the order the rule must produce.
	want := []Item{
		{AdvisoryID: "kev-newest", KEV: true, KEVAdded: d("2026-09-14"), EPSS: f(0.71), CVSS: f(5)},
		{AdvisoryID: "kev-newest-lower-epss", KEV: true, KEVAdded: d("2026-09-14"), EPSS: f(0.02), CVSS: f(9.8)},
		{AdvisoryID: "kev-older-but-critical", KEV: true, KEVAdded: d("2021-11-03"), EPSS: f(0.97), CVSS: f(10), Severity: "critical"},
		{AdvisoryID: "kev-undated", KEV: true, EPSS: f(0.99), CVSS: f(10)},
		{AdvisoryID: "epss-high", EPSS: f(0.60), CVSS: f(3)},
		{AdvisoryID: "epss-high-cvss-higher-loses-tie-to-id", EPSS: f(0.60), CVSS: f(3)},
		{AdvisoryID: "epss-mid-cvss-critical", EPSS: f(0.30), CVSS: f(9.9), Severity: "critical"},
		{AdvisoryID: "no-epss-cvss-9", CVSS: f(9.0)},
		{AdvisoryID: "no-epss-cvss-6", CVSS: f(6.0)},
		{AdvisoryID: "no-scores-critical", Severity: "critical"},
		{AdvisoryID: "no-scores-low", Severity: "low"},
		{AdvisoryID: "no-scores-unknown"},
	}
	got := append([]Item(nil), want...)
	// Shuffle deterministically, then sort by the rule.
	for i := range got {
		j := (i*7 + 3) % len(got)
		got[i], got[j] = got[j], got[i]
	}
	sort.Slice(got, func(i, j int) bool { return Compare(got[i], got[j]) < 0 })
	for i := range want {
		if got[i].AdvisoryID != want[i].AdvisoryID {
			t.Fatalf("position %d = %s, want %s\nfull order: %v", i, got[i].AdvisoryID, want[i].AdvisoryID, ids(got))
		}
	}
}

func TestKEVBeatsEverythingElse(t *testing.T) {
	kev := Item{AdvisoryID: "z", KEV: true, KEVAdded: d("2020-01-01"), EPSS: f(0.001), CVSS: f(1)}
	scary := Item{AdvisoryID: "a", EPSS: f(0.999), CVSS: f(10), Severity: "critical"}
	if Compare(kev, scary) >= 0 || Compare(scary, kev) <= 0 {
		t.Fatal("a KEV advisory must rank above a non-KEV one whatever the scores")
	}
}

func TestKEVDateComparesByDayNotInstant(t *testing.T) {
	a := time.Date(2026, 9, 14, 23, 0, 0, 0, time.UTC)
	b := time.Date(2026, 9, 14, 1, 0, 0, 0, time.UTC)
	x := Item{AdvisoryID: "a", KEV: true, KEVAdded: &a, EPSS: f(0.1)}
	y := Item{AdvisoryID: "b", KEV: true, KEVAdded: &b, EPSS: f(0.9)}
	// Same day: EPSS decides, not the hour.
	if Compare(y, x) >= 0 {
		t.Fatal("same KEV day must fall through to EPSS")
	}
}

func TestMissingScoresRankLastNotZero(t *testing.T) {
	zero := Item{AdvisoryID: "zero", EPSS: f(0)}
	none := Item{AdvisoryID: "none"}
	if Compare(zero, none) >= 0 {
		t.Fatal("a real EPSS of 0 must rank above no EPSS")
	}
}

func TestCompareIsATotalOrder(t *testing.T) {
	items := []Item{
		{AdvisoryID: "a", KEV: true, KEVAdded: d("2026-01-01"), EPSS: f(0.5), CVSS: f(5), Severity: "high"},
		{AdvisoryID: "b", KEV: true, KEVAdded: d("2026-01-01"), EPSS: f(0.5), CVSS: f(5), Severity: "high"},
		{AdvisoryID: "c", EPSS: f(0.5), CVSS: f(5), Severity: "high"},
		{AdvisoryID: "d"},
	}
	for _, x := range items {
		if Compare(x, x) != 0 {
			t.Errorf("%s vs itself != 0", x.AdvisoryID)
		}
		for _, y := range items {
			if x.AdvisoryID != y.AdvisoryID && Compare(x, y) == 0 {
				t.Errorf("%s and %s compare equal", x.AdvisoryID, y.AdvisoryID)
			}
			if Compare(x, y) != -Compare(y, x) && (Compare(x, y) < 0) != (Compare(y, x) > 0) {
				t.Errorf("%s/%s not antisymmetric", x.AdvisoryID, y.AdvisoryID)
			}
		}
	}
}

func ids(items []Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.AdvisoryID)
	}
	return out
}
