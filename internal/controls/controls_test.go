package controls

import (
	"strings"
	"testing"
)

func TestParseID(t *testing.T) {
	good := map[string]ID{
		"nist-800-53:AU-9(3)": "nist-800-53:AU-9(3)",
		"NIST-800-53:AU-10":   "nist-800-53:AU-10",
		"  cis-v8:5.4  ":      "cis-v8:5.4",
		"cjis-v6:4":           "cjis-v6:4",
		"nist-800-171:3.3.2":  "nist-800-171:3.3.2",
		"cmmc-l2:3.13.11":     "cmmc-l2:3.13.11",
		"nist-800-53 : AU-2 ": "nist-800-53:AU-2",
	}
	for raw, want := range good {
		got, err := ParseID(raw)
		if err != nil {
			t.Errorf("ParseID(%q) = %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("ParseID(%q) = %q, want %q", raw, got, want)
		}
	}

	// The control half keeps its case, because it belongs to the catalog and
	// 800-53 writes "AU-9(3)", not "au-9(3)".
	if got := MustParseID("nist-800-53:AU-9(3)").Control(); got != "AU-9(3)" {
		t.Errorf("control part = %q, want AU-9(3)", got)
	}

	bad := []string{
		"",
		"AU-9",                // no framework
		"nist-800-53:",        // no control
		":AU-9",               // no framework
		"made-up-framework:1", // unknown framework, so a typo cannot create an invisible catalog
		"nist-800-53:AU 9",    // space in the control part
		"nist-800-53:../etc",  // path-ish
		"nist-800-53:a;b",
	}
	for _, raw := range bad {
		if id, err := ParseID(raw); err == nil {
			t.Errorf("ParseID(%q) accepted, returning %q", raw, id)
		}
	}
}

func TestParseIDsReportsEveryFailure(t *testing.T) {
	_, err := ParseIDs([]string{"nist-800-53:AU-10", "bogus", "also-bogus:1", "cis-v8:5.4"})
	if err == nil {
		t.Fatal("expected an error")
	}
	// One pass should surface both problems, not just the first.
	if !strings.Contains(err.Error(), "bogus") || !strings.Contains(err.Error(), "also-bogus") {
		t.Errorf("error names only some failures: %v", err)
	}

	ids, err := ParseIDs([]string{"cis-v8:5.4", "  ", "nist-800-53:AU-10", "cis-v8:5.4"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("got %v, want the blank skipped and the duplicate collapsed", ids)
	}
}

// The catalog is built by an init-time expression that panics on a bad entry.
// If this package compiles and its tests run, that has already held; these
// assert the invariants it enforces are the ones we think they are.
func TestCatalogIsWellFormed(t *testing.T) {
	if len(Catalog()) == 0 {
		t.Fatal("the catalog is empty")
	}
	for _, c := range Catalog() {
		if _, err := ParseID(string(c.ID)); err != nil {
			t.Errorf("%s is not a parseable id: %v", c.ID, err)
		}
		if strings.TrimSpace(c.Title) == "" {
			t.Errorf("%s has no title", c.ID)
		}
		if c.Coverage != CoverageEvidenced && strings.TrimSpace(c.Note) == "" {
			t.Errorf("%s is %s but says nothing about why", c.ID, c.Coverage)
		}
		if c.Coverage == CoverageNone && len(c.Signals) > 0 {
			t.Errorf("%s is marked not-evidenced but claims signals %v", c.ID, c.Signals)
		}
		if c.Coverage != CoverageNone && len(c.Signals) == 0 {
			t.Errorf("%s claims coverage %s with no signals behind it", c.ID, c.Coverage)
		}
		for _, s := range c.Signals {
			if !KnownSignal(s) {
				t.Errorf("%s maps unknown signal %q", c.ID, s)
			}
		}
		if !KnownFramework(c.ID.Framework()) {
			t.Errorf("%s is in an unknown framework", c.ID)
		}
	}
}

// The honesty claim the whole positioning rests on: controls DefendSec cannot
// evidence are present and say so, rather than being absent and reading as
// "no finding".
func TestCatalogListsWhatItCannotEvidence(t *testing.T) {
	var none int
	for _, c := range Catalog() {
		if c.Coverage == CoverageNone {
			none++
		}
	}
	if none == 0 {
		t.Fatal("no control is marked not-evidenced, which cannot be true of any product")
	}

	// Specific cases the roadmap commits to in writing.
	for _, raw := range []string{
		"cjis-v6:13",          // mobile devices: MDM, declined on purpose
		"cjis-v6:2",           // security awareness training
		"cjis-v6:9",           // physical protection
		"cis-v8:10.1",         // anti-malware
		"nist-800-171:3.14.2", // malicious code
	} {
		c, ok := Lookup(MustParseID(raw))
		if !ok {
			t.Errorf("%s is missing from the catalog", raw)
			continue
		}
		if c.Coverage != CoverageNone {
			t.Errorf("%s = %s, want not-evidenced", raw, c.Coverage)
		}
	}

	// Mobile devices must say it is a deliberate decision, not an oversight.
	if c, _ := Lookup(MustParseID("cjis-v6:13")); !strings.Contains(strings.ToLower(c.Note), "deliberate") {
		t.Errorf("the mobile devices note reads as an omission rather than a decision: %q", c.Note)
	}
}

// A derived control must never look better evidenced than its weakest
// dependency. Taking the strongest is how compliance dashboards become
// untrustworthy.
func TestCrosswalkTakesTheWeakestCoverage(t *testing.T) {
	for _, c := range Catalog() {
		if len(c.DerivedFrom) == 0 {
			continue
		}
		weakest := CoverageEvidenced
		for _, hid := range c.DerivedFrom {
			h, ok := Lookup(hid)
			if !ok {
				t.Errorf("%s derives from %s, which is not in the catalog", c.ID, hid)
				continue
			}
			if h.Coverage.Rank() < weakest.Rank() {
				weakest = h.Coverage
			}
		}
		if c.Coverage != weakest {
			t.Errorf("%s = %s, but its weakest dependency is %s", c.ID, c.Coverage, weakest)
		}
	}
}

// CMMC 2.0 Level 2 adopts 800-171's requirements wholesale, so an assessor
// working from either identifier must get the same answer.
func TestCMMCMirrors800171(t *testing.T) {
	a := ForFramework(NIST800171)
	b := ForFramework(CMMCL2)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("800-171 has %d controls, CMMC L2 has %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID.Control() != b[i].ID.Control() {
			t.Fatalf("mismatch at %d: %s vs %s", i, a[i].ID, b[i].ID)
		}
		if a[i].Coverage != b[i].Coverage {
			t.Errorf("%s: 800-171 says %s, CMMC says %s", a[i].ID.Control(), a[i].Coverage, b[i].Coverage)
		}
	}
}

func TestForSignal(t *testing.T) {
	ids := ForSignal(SignalIdentityMFA)
	if len(ids) == 0 {
		t.Fatal("MFA maps to no control")
	}
	var sawCIS, saw80053 bool
	for _, id := range ids {
		switch id.Framework() {
		case CISv8:
			sawCIS = true
		case NIST80053:
			saw80053 = true
		}
	}
	if !sawCIS || !saw80053 {
		t.Errorf("one signal should reach several frameworks, got %v", ids)
	}

	if got := ForSignal(Signal("nonsense")); len(got) != 0 {
		t.Errorf("unknown signal mapped to %v", got)
	}

	// The union must be deduplicated and sorted, because these end up in
	// signed bundles where an unstable order changes a hash for no reason.
	union := ForSignals(SignalIdentityMFA, SignalIdentityMFA, SignalIdentityRoles)
	seen := map[ID]bool{}
	for i, id := range union {
		if seen[id] {
			t.Errorf("duplicate %s", id)
		}
		seen[id] = true
		if i > 0 && union[i-1] > id {
			t.Errorf("out of order at %d: %s before %s", i, union[i-1], id)
		}
	}
}

// Every signal must reach at least one control. A signal that maps nowhere is
// a record type being tagged with something the compliance view ignores.
func TestEverySignalIsMapped(t *testing.T) {
	for _, s := range Signals() {
		if len(ForSignal(s)) == 0 {
			t.Errorf("signal %q maps to no control", s)
		}
	}
}

func TestFrameworkTitles(t *testing.T) {
	for _, f := range Frameworks() {
		if FrameworkTitle(f) == string(f) {
			t.Errorf("framework %q has no full title", f)
		}
		if len(ForFramework(f)) == 0 {
			t.Errorf("framework %q has no controls", f)
		}
	}
	if !KnownFramework(NIST80053) || KnownFramework(Framework("nope")) {
		t.Error("KnownFramework is wrong")
	}
}

// The audit tag is stored alongside hashed fields but is not itself hashed.
// That is only safe because it is a pure function of the action, so a verifier
// can recompute it. This asserts that property directly.
func TestAuditActionTagsAreDeterministic(t *testing.T) {
	for action := range auditActionSignals {
		a := TagAuditAction(action)
		b := TagAuditAction(action)
		if len(a) != len(b) {
			t.Fatalf("%s: unstable tag length", action)
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("%s: unstable tag order %v vs %v", action, a, b)
			}
		}
		if len(a) == 0 {
			t.Errorf("%s maps to signals that reach no control", action)
		}
		if AuditActionSignalName(action) == "" {
			t.Errorf("%s has no primary signal", action)
		}
	}

	// An action nobody mapped must produce nothing rather than a guess: a
	// wrong tag puts a record behind a control it does not speak to, and an
	// assessor has no way to tell.
	if got := TagAuditAction("some_action_nobody_mapped"); got != nil {
		t.Errorf("unmapped action produced %v", got)
	}
	if got := AuditActionSignalName("some_action_nobody_mapped"); got != "" {
		t.Errorf("unmapped action produced signal %q", got)
	}
}

func TestSignalForAlertKind(t *testing.T) {
	for kind, want := range map[string]Signal{
		"fim":  SignalFIM,
		"sca":  SignalSCA,
		"vuln": SignalVulnAssessment,
	} {
		got, ok := SignalForAlertKind(kind)
		if !ok || got != want {
			t.Errorf("kind %q = (%q, %v), want %q", kind, got, ok, want)
		}
	}
	if _, ok := SignalForAlertKind("something-else"); ok {
		t.Error("an unrecognised alert kind must not be guessed at")
	}
}

func TestTagMergesExtrasAndDropsBadOnes(t *testing.T) {
	base := Tag(SignalSCA)
	if len(base) == 0 {
		t.Fatal("the SCA signal maps to no control")
	}

	// An extra that is already implied must not appear twice.
	withDup := Tag(SignalSCA, base[0])
	if len(withDup) != len(base) {
		t.Errorf("a redundant extra changed the tag: %v vs %v", withDup, base)
	}

	// A genuinely new one is added...
	withNew := Tag(SignalSCA, "cjis-v6:5")
	if len(withNew) != len(base)+1 {
		t.Errorf("extra not added: %v", withNew)
	}

	// ...and a bad one is dropped rather than failing the write. The pack
	// loader rejects these where the error is actionable; here, a mis-tagged
	// pack must not stop a real finding from being recorded.
	if got := Tag(SignalSCA, "not a control id"); len(got) != len(base) {
		t.Errorf("a bad extra changed the tag: %v", got)
	}

	// The result must stay sorted, because it lands in signed bundles.
	for i := 1; i < len(withNew); i++ {
		if withNew[i-1] > withNew[i] {
			t.Fatalf("tag is not sorted: %v", withNew)
		}
	}
}
