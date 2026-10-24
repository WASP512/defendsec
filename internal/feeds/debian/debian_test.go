package debian

import (
	"os"
	"strings"
	"testing"

	"defendsec/internal/feeds"
)

func parseFixture(t *testing.T, wanted map[string]string) (map[string][]feeds.Advisory, feeds.Stats) {
	t.Helper()
	f, err := os.Open("testdata/tracker.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string][]feeds.Advisory{}
	st, err := Parse(f, wanted, func(a feeds.Advisory) error {
		got[a.ID] = append(got[a.ID], a)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, st
}

func only(t *testing.T, got map[string][]feeds.Advisory, id string) feeds.Advisory {
	t.Helper()
	if len(got[id]) != 1 {
		t.Fatalf("%s emitted %d times", id, len(got[id]))
	}
	return got[id][0]
}

func TestStatesMapToFixStates(t *testing.T) {
	got, st := parseFixture(t, map[string]string{"bookworm": "12", "trixie": "13"})

	cases := []struct {
		id    string
		rel   string
		state feeds.FixState
		fixed string
	}{
		{"CVE-2012-0833", "12", feeds.NotAffected, ""}, // resolved, fixed_version "0"
		{"CVE-2012-4450", "12", feeds.Fixed, "1.2.11.15-1"},
		{"CVE-2012-4450", "13", feeds.Fixed, "1.2.11.15-1"},
		{"CVE-2023-1055", "12", feeds.Affected, ""},    // open + nodsa "Minor issue"
		{"CVE-2016-5416", "12", feeds.WillNotFix, ""},  // open + unimportant
		{"CVE-2017-7475", "12", feeds.WillNotFix, ""},  // open + nodsa_reason ignored
		{"CVE-2023-44487", "12", feeds.WillNotFix, ""}, // open + end-of-life
		{"CVE-2026-110875", "12", feeds.UnderInvestigation, ""},
		{"CVE-2026-11332", "12", feeds.Fixed, "5.4.0-1"}, // resolved + postponed nodsa
		{"CVE-2005-1854", "12", feeds.Fixed, "0.9.10"},
	}
	for _, tc := range cases {
		var found *feeds.Range
		for _, a := range got[tc.id] {
			for i, r := range a.Ranges {
				if r.Release == tc.rel {
					found = &a.Ranges[i]
				}
			}
		}
		if found == nil {
			t.Errorf("%s release %s: no range", tc.id, tc.rel)
			continue
		}
		if found.State != tc.state || found.Fixed != tc.fixed {
			t.Errorf("%s release %s: state=%s fixed=%q, want %s %q", tc.id, tc.rel, found.State, found.Fixed, tc.state, tc.fixed)
		}
		if found.Distro != "debian" || found.Ecosystem != "Debian" || found.Package == "" || found.SourcePackage != found.Package {
			t.Errorf("%s: range identity = %+v", tc.id, *found)
		}
	}

	// A CVE resolved in only bookworm and trixie gets both; sid is never emitted.
	for _, a := range got["CVE-2012-0833"] {
		if len(a.Ranges) != 2 {
			t.Errorf("CVE-2012-0833 ranges = %d, want 2 (bookworm, trixie; sid excluded)", len(a.Ranges))
		}
		for _, r := range a.Ranges {
			if r.Release != "12" && r.Release != "13" {
				t.Errorf("unexpected release %q", r.Release)
			}
		}
	}

	if got["TEMP-0000000-ABCDEF"] != nil {
		t.Error("TEMP-* identifier produced an advisory")
	}
	if st.Skipped["non-CVE identifier"] != 1 {
		t.Errorf("skipped = %v", st.Skipped)
	}
	if st.Skipped["unrecognised status deferred"] != 1 {
		t.Errorf("unknown status not counted: %v", st.Skipped)
	}
}

func TestSeverityIsHighestUrgencyAcrossReleases(t *testing.T) {
	got, _ := parseFixture(t, map[string]string{"bookworm": "12", "bullseye": "11"})
	a := only(t, got, "CVE-2023-44487")
	if a.Severity != "high" {
		t.Errorf("severity = %q, want high (bullseye urgency high beats bookworm end-of-life)", a.Severity)
	}
	if len(a.Ranges) != 2 || a.Ranges[0].Release != "11" || a.Ranges[1].Release != "12" {
		t.Errorf("ranges = %+v, want bullseye then bookworm", a.Ranges)
	}
	// Only bookworm wanted: end-of-life maps to unknown, not a guess.
	got, _ = parseFixture(t, map[string]string{"bookworm": "12"})
	if s := only(t, got, "CVE-2023-44487").Severity; s != "unknown" {
		t.Errorf("severity = %q, want unknown", s)
	}
	if s := only(t, got, "CVE-2005-1854").Severity; s != "high" {
		t.Errorf("CVE-2005-1854 severity = %q", s)
	}
}

func TestUnwantedReleasesProduceNothing(t *testing.T) {
	got, st := parseFixture(t, map[string]string{"bullseye": "11"})
	if len(got) != 1 || got["CVE-2023-44487"] == nil {
		t.Errorf("got %d advisories, want only the one with a bullseye entry", len(got))
	}
	if st.Advisories != 1 {
		t.Errorf("advisories = %d", st.Advisories)
	}
}

func TestBadDocuments(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"not json":    {"<html>", "debian"},
		"array":       {"[1,2]", "expected"},
		"empty":       {"{}", "no packages"},
		"cut off":     {`{"a":{"CVE-2020-0001":{"releases":{`, "debian"},
		"bad package": {`{"a":5}`, "package"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.in), Releases, func(feeds.Advisory) error { return nil })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestSummaryIsTrimmedOnRuneBoundary(t *testing.T) {
	long := strings.Repeat("é", 300) // 600 bytes
	if s := summarize(long); !strings.HasSuffix(s, "…") || len(s) > 404 {
		t.Errorf("len=%d suffix ok=%v", len(s), strings.HasSuffix(s, "…"))
	}
	if s := summarize("  a \n b  "); s != "a b" {
		t.Errorf("summarize = %q", s)
	}
}
