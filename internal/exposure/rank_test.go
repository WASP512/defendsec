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

// Surface findings join the same order (slice 7b): KEV vulnerabilities first,
// then critical and high surface findings, then everything else by EPSS, CVSS
// and severity, with a medium surface finding among the medium vulnerabilities.
func TestSurfaceFindingsJoinTheOrder(t *testing.T) {
	sf := func(id, sev string) Item {
		return Item{AdvisoryID: SurfaceKeyPrefix + id, Severity: sev, Surface: true}
	}
	want := []Item{
		{AdvisoryID: "kev", KEV: true, KEVAdded: d("2021-01-01"), EPSS: f(0.001), CVSS: f(1)},
		sf("000000000002", "critical"), // SMB reachable, expired certificate, SPF +all; lower id (older) first
		sf("000000000007", "critical"),
		sf("000000000001", "high"), // RDP, a database port, DMARC missing
		sf("000000000009", "high"),
		{AdvisoryID: "epss-0.9", EPSS: f(0.9), CVSS: f(2)}, // a non-KEV CVE with a high EPSS ranks below an exposed port
		{AdvisoryID: "epss-0.003", EPSS: f(0.003), CVSS: f(9.8), Severity: "critical"},
		{AdvisoryID: "cvss-only-9.8", CVSS: f(9.8), Severity: "critical"},
		{AdvisoryID: "cvss-only-7.5", CVSS: f(7.5), Severity: "high"},
		sf("000000000003", "medium"), // DMARC p=none: with the medium vulnerabilities (5.0)
		{AdvisoryID: "cvss-only-4.3", CVSS: f(4.3), Severity: "medium"},
		sf("000000000004", "low"), // 2.0
		{AdvisoryID: "cvss-only-1.0", CVSS: f(1.0), Severity: "low"},
		{AdvisoryID: "no-scores-critical", Severity: "critical"}, // no score at all ranks after every scored row
	}
	got := append([]Item(nil), want...)
	for i := range got {
		j := (i*5 + 2) % len(got)
		got[i], got[j] = got[j], got[i]
	}
	sort.Slice(got, func(i, j int) bool { return Compare(got[i], got[j]) < 0 })
	for i := range want {
		if got[i].AdvisoryID != want[i].AdvisoryID {
			t.Fatalf("position %d = %s, want %s\nfull order: %v", i, got[i].AdvisoryID, want[i].AdvisoryID, ids(got))
		}
	}
}

func TestSurfaceIgnoresVulnerabilityFields(t *testing.T) {
	// A surface item never reads KEV, EPSS or CVSS, whatever a caller put in them.
	odd := Item{AdvisoryID: "surface:000000000001", Severity: "medium", Surface: true, KEV: true, EPSS: f(0.99), CVSS: f(10)}
	vuln := Item{AdvisoryID: "v", EPSS: f(0.01), CVSS: f(1)}
	if Compare(odd, vuln) <= 0 {
		t.Fatal("a medium surface finding must rank after a vulnerability that has an EPSS score")
	}
	if Band(odd) != BandRest {
		t.Fatalf("a medium surface finding is in band %d, want %d", Band(odd), BandRest)
	}
}

func TestKEVStillBeatsAnUrgentSurfaceFinding(t *testing.T) {
	kev := Item{AdvisoryID: "z", KEV: true, KEVAdded: d("2019-01-01"), EPSS: f(0.001), CVSS: f(1)}
	smb := Item{AdvisoryID: "surface:000000000001", Severity: "critical", Surface: true}
	if Compare(kev, smb) >= 0 || Compare(smb, kev) <= 0 {
		t.Fatal("an exploited-in-the-wild vulnerability must rank above an exposed port")
	}
}

func TestSurfaceScoreRanksEveryRankedSeverityAndNotInfo(t *testing.T) {
	prev := 100.0
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		s, ok := SurfaceScore(sev)
		if !ok || s >= prev {
			t.Fatalf("%s: score %v ok=%v, want a ranked score below %v", sev, s, ok, prev)
		}
		prev = s
	}
	if _, ok := SurfaceScore("info"); ok {
		t.Fatal("info is an observation and must never rank")
	}
	if _, ok := SurfaceScore(""); ok {
		t.Fatal("an empty severity must never rank")
	}
}

// End-of-life findings (slice 10) join the order next to the high
// vulnerabilities: software past end of security support is in the urgent band
// with the critical and high surface findings, after KEV and before every
// vulnerability that is not on KEV, whatever its EPSS; software past end of
// active support ranks with the low CVSS-only ones, below every vulnerability
// that has an EPSS score.
func TestEOLJoinsTheOrderNextToHighVulnerabilities(t *testing.T) {
	eol := func(id, stage, sev string) Item {
		return Item{AdvisoryID: id, Severity: sev, EOLStage: stage}
	}
	sf := func(id, sev string) Item {
		return Item{AdvisoryID: SurfaceKeyPrefix + id, Severity: sev, Surface: true}
	}
	want := []Item{
		{AdvisoryID: "kev", KEV: true, KEVAdded: d("2021-01-01"), EPSS: f(0.001), CVSS: f(1)},
		sf("000000000002", "critical"),                                            // CVSS-equivalent 9.5: above an EOL release (8.0)
		eol("EOL:php:8.0", EOLStageEOL, "high"),                                   // 8.0, high: ties with a high surface finding; the id breaks it ("EOL:" < "surface:")
		eol("EOL:php:8.1", EOLStageEOL, "high"),                                   // and the lower id first among EOL rows
		sf("000000000001", "high"),                                                // 8.0, high
		{AdvisoryID: "epss-0.9", EPSS: f(0.9), CVSS: f(2)},                        // a scored CVE ranks below software no one patches
		{AdvisoryID: "epss-0.0005", EPSS: f(0.0005), CVSS: f(3), Severity: "low"}, // even a tiny EPSS ranks above past-active-support
		{AdvisoryID: "cvss-only-9.8", CVSS: f(9.8), Severity: "critical"},
		{AdvisoryID: "cvss-only-4.3", CVSS: f(4.3), Severity: "medium"},
		eol("EOL:nodejs:22", EOLStageEOAS, "low"), // 2.0 equivalent; ties with the next on severity, the id breaks it
		{AdvisoryID: "cvss-only-2.0", CVSS: f(2.0), Severity: "low"},
		{AdvisoryID: "cvss-only-1.0", CVSS: f(1.0), Severity: "low"},
		{AdvisoryID: "no-scores-critical", Severity: "critical"},
	}
	got := append([]Item(nil), want...)
	for i := range got {
		j := (i*5 + 3) % len(got)
		got[i], got[j] = got[j], got[i]
	}
	sort.Slice(got, func(i, j int) bool { return Compare(got[i], got[j]) < 0 })
	for i := range want {
		if got[i].AdvisoryID != want[i].AdvisoryID {
			t.Fatalf("position %d = %s, want %s\nfull order: %v", i, got[i].AdvisoryID, want[i].AdvisoryID, ids(got))
		}
	}
}

func TestSecurityEOLRanksAboveActiveSupportEOLWhateverTheLabels(t *testing.T) {
	// The stage decides, not the severity label a caller put on the row.
	eol := Item{AdvisoryID: "EOL:php:8.0", Severity: "low", EOLStage: EOLStageEOL}
	eoas := Item{AdvisoryID: "EOL:php:8.4", Severity: "critical", EOLStage: EOLStageEOAS}
	if Compare(eol, eoas) >= 0 || Compare(eoas, eol) <= 0 {
		t.Fatal("past end of security support must rank above past end of active support")
	}
	if Band(eol) != BandUrgent || Band(eoas) != BandRest {
		t.Fatalf("bands: eol %d, eoas %d; want %d and %d", Band(eol), Band(eoas), BandUrgent, BandRest)
	}
	scored := Item{AdvisoryID: "cve", EPSS: f(0.5), CVSS: f(9)}
	if Compare(eoas, scored) <= 0 {
		t.Fatal("past end of active support ranks below a vulnerability that has an EPSS score")
	}
	if Compare(eol, scored) >= 0 {
		t.Fatal("past end of security support ranks above a vulnerability that is not on KEV")
	}
}

func TestEOLIgnoresVulnerabilityFieldsAndKEVStillWins(t *testing.T) {
	// An eol item never reads KEV, EPSS or CVSS, whatever a caller put in them.
	odd := Item{AdvisoryID: "EOL:php:8.4", Severity: "low", EOLStage: EOLStageEOAS, KEV: true, EPSS: f(0.99), CVSS: f(10)}
	vuln := Item{AdvisoryID: "v", EPSS: f(0.01), CVSS: f(1)}
	if Compare(odd, vuln) <= 0 {
		t.Fatal("an EOAS item must rank after a vulnerability that has an EPSS score")
	}
	kev := Item{AdvisoryID: "z", KEV: true, KEVAdded: d("2019-01-01"), EPSS: f(0.001), CVSS: f(1)}
	eol := Item{AdvisoryID: "EOL:php:8.0", Severity: "high", EOLStage: EOLStageEOL}
	if Compare(kev, eol) >= 0 || Compare(eol, kev) <= 0 {
		t.Fatal("an exploited-in-the-wild vulnerability must rank above end-of-life software")
	}
}

func TestEOLScoreRanksOnlyKnownStages(t *testing.T) {
	hi, ok := EOLScore(EOLStageEOL)
	lo, ok2 := EOLScore(EOLStageEOAS)
	if !ok || !ok2 || hi <= lo {
		t.Fatalf("scores eol %v/%v eoas %v/%v: want eol above eoas", hi, ok, lo, ok2)
	}
	if hi != 8.0 {
		t.Fatalf("security-EOL must sit at the level of a high vulnerability (8.0), got %v", hi)
	}
	if _, ok := EOLScore(""); ok {
		t.Fatal("a row that is not end-of-life has no end-of-life score")
	}
	if _, ok := EOLScore("supported"); ok {
		t.Fatal("an unknown stage must not rank")
	}
}

// Identity findings (slice 12) rank by severity under the surface rules: after
// KEV, before every non-KEV vulnerability when critical or high, and among the
// scored vulnerabilities when medium or low. Nothing but severity is read.
func TestIdentityFindingsJoinTheOrder(t *testing.T) {
	idf := func(id, sev string) Item {
		return Item{AdvisoryID: IdentityKeyPrefix + id, Severity: sev, Identity: true}
	}
	sf := func(id, sev string) Item {
		return Item{AdvisoryID: SurfaceKeyPrefix + id, Severity: sev, Surface: true}
	}
	want := []Item{
		{AdvisoryID: "kev", KEV: true, KEVAdded: d("2021-01-01"), EPSS: f(0.001), CVSS: f(1)},
		idf("000000000005", "critical"), // a Global Administrator with no MFA; the older finding first
		idf("000000000009", "critical"),
		sf("000000000002", "critical"), // same band and score: identity: sorts before surface:
		idf("000000000001", "high"),    // an administrator with no MFA, a rule forwarding outside
		sf("000000000001", "high"),
		{AdvisoryID: "epss-0.9", EPSS: f(0.9), CVSS: f(2)}, // a non-KEV CVE with a high EPSS ranks below an account takeover risk
		{AdvisoryID: "cvss-only-9.8", CVSS: f(9.8), Severity: "critical"},
		idf("000000000003", "medium"), // a user with no MFA: with the medium vulnerabilities (5.0)
		{AdvisoryID: "cvss-only-4.3", CVSS: f(4.3), Severity: "medium"},
		idf("000000000004", "low"), // 2.0
		{AdvisoryID: "cvss-only-1.0", CVSS: f(1.0), Severity: "low"},
	}
	got := append([]Item(nil), want...)
	for i := range got {
		j := (i*5 + 2) % len(got)
		got[i], got[j] = got[j], got[i]
	}
	sort.Slice(got, func(i, j int) bool { return Compare(got[i], got[j]) < 0 })
	for i := range want {
		if got[i].AdvisoryID != want[i].AdvisoryID {
			t.Fatalf("position %d = %s, want %s\nfull order: %v", i, got[i].AdvisoryID, want[i].AdvisoryID, ids(got))
		}
	}
}

func TestIdentityIgnoresVulnerabilityFieldsAndBands(t *testing.T) {
	odd := Item{AdvisoryID: IdentityKeyPrefix + "000000000001", Severity: "medium", Identity: true, KEV: true, EPSS: f(0.99), CVSS: f(10)}
	vuln := Item{AdvisoryID: "v", EPSS: f(0.01), CVSS: f(1)}
	if Compare(odd, vuln) <= 0 || Band(odd) != BandRest {
		t.Fatalf("a medium identity finding must rank after a vulnerability with an EPSS score (band %d)", Band(odd))
	}
	for sev, band := range map[string]int{"critical": BandUrgent, "high": BandUrgent, "medium": BandRest, "low": BandRest} {
		if b := Band(Item{AdvisoryID: IdentityKeyPrefix + "1", Severity: sev, Identity: true}); b != band {
			t.Errorf("identity %s in band %d, want %d", sev, b, band)
		}
	}
	kev := Item{AdvisoryID: "z", KEV: true, KEVAdded: d("2019-01-01"), EPSS: f(0.001), CVSS: f(1)}
	crit := Item{AdvisoryID: IdentityKeyPrefix + "000000000001", Severity: "critical", Identity: true}
	if Compare(kev, crit) >= 0 {
		t.Fatal("an exploited-in-the-wild vulnerability must rank above an identity finding")
	}
}
