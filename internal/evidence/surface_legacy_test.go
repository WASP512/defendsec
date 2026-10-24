package evidence

import (
	"strings"
	"testing"
	"time"
)

// Bundles from before slice 7c: scans chained with the v1 digest carry no Seen,
// so a finding's dates are proven and its title and severity are not. The
// report says so (FindingsDatesOnly) and the findings list is still complete.

func TestVerifySurfaceLegacyV1ScansProveDatesAndPresenceOnly(t *testing.T) {
	b := surfaceBundleDigests(t, DigestV1, DigestV1, DigestV1, nil)
	// The v1 fixture's finding says what scan 3 would have said; with no Seen the
	// verifier cannot know, which is the point.
	r := Verify(b)
	if !r.OK() {
		t.Fatalf("an intact v1 bundle must verify: %+v", r.Checks)
	}
	if r.Surface.FindingsVerified != 0 || r.Surface.FindingsDatesOnly != 1 {
		t.Fatalf("a v1 finding is dates-only: %+v", r.Surface)
	}
	if c := check(t, r, "surface findings"); !strings.Contains(c.Detail, "1 with dates only") {
		t.Fatalf("%+v", c)
	}

	// Completeness holds for v1 too: dropping, inventing or moving a date fails.
	cases := map[string]func(b *Bundle){
		"emptied":    func(b *Bundle) { b.Surface.Findings = nil },
		"injected":   func(b *Bundle) { b.Surface.Findings = append(b.Surface.Findings, injectedFinding(nil)) },
		"duplicated": func(b *Bundle) { b.Surface.Findings = append(b.Surface.Findings, b.Surface.Findings[0]) },
		"closed moved": func(b *Bundle) {
			later := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
			b.Surface.Findings[0].Intervals[0].ClosedAt = &later
		},
	}
	for name, mutate := range cases {
		b := surfaceBundleDigests(t, DigestV1, DigestV1, DigestV1, nil)
		mutate(b)
		if r := Verify(b); r.OK() {
			t.Errorf("v1, %s: must fail", name)
		}
	}
	// What v1 cannot do, stated as a test so nobody assumes it can: a title
	// edit on a dates-only finding goes unnoticed.
	b = surfaceBundleDigests(t, DigestV1, DigestV1, DigestV1, nil)
	b.Surface.Findings[0].Title = "edited"
	if r := Verify(b); !r.OK() || r.Surface.FindingsDatesOnly != 1 {
		t.Fatalf("v1 does not attest titles; the finding must be reported as dates-only: %+v", r.Surface)
	}
}

// Scans 1 and 2 were chained before the upgrade, scan 3 after it. Scan 3 saw the
// finding, so its title and severity are attested; a finding last seen before
// the upgrade stays dates-only.
func TestVerifySurfaceMixedDigestsAttestWhatTheNewestScanSaw(t *testing.T) {
	b := surfaceBundleDigests(t, DigestV1, DigestV1, DigestV2, nil)
	r := Verify(b)
	if !r.OK() || r.Surface.FindingsVerified != 1 || r.Surface.FindingsDatesOnly != 0 {
		t.Fatalf("seen by a v2 scan after the last v1 scan: %+v %+v", r.Surface, r.Checks)
	}
	b.Surface.Findings[0].Title = "edited"
	if r := Verify(b); r.OK() {
		t.Fatal("a title edit must fail once a v2 scan attested it")
	}

	// A v1 scan after the v2 one: nothing says what it saw, so dates only.
	b = surfaceBundleDigests(t, DigestV2, DigestV2, DigestV1, nil)
	if r := Verify(b); !r.OK() || r.Surface.FindingsDatesOnly != 1 {
		t.Fatalf("%+v %+v", r.Surface, r.Checks)
	}
}

func TestVerifySurfaceSeenIsPartOfTheScanDigest(t *testing.T) {
	cases := map[string]func(b *Bundle){
		"seen title edited":    func(b *Bundle) { b.Surface.Scans[2].Seen[0].Title = "edited" },
		"seen severity edited": func(b *Bundle) { b.Surface.Scans[2].Seen[0].Severity = "low" },
		"seen content edited":  func(b *Bundle) { b.Surface.Scans[2].Seen[0].Content = "00" },
		"seen dropped":         func(b *Bundle) { b.Surface.Scans[2].Seen = nil },
		"seen injected":        func(b *Bundle) { b.Surface.Scans[1].Seen = []SurfaceSeen{{FindingID: "x", Subject: "y"}} },
	}
	for name, mutate := range cases {
		b := surfaceBundle(t)
		mutate(b)
		r := Verify(b)
		if r.OK() || r.Surface.ScansFailed == 0 {
			t.Errorf("%s: must fail, got %+v", name, r.Surface)
		}
	}
}

func TestVerifySurfaceUnknownDigestVersionFails(t *testing.T) {
	b := surfaceBundleDigests(t, 9, DigestV2, DigestV2, nil) // chained under a version this verifier does not know
	r := Verify(b)
	c := check(t, r, "surface scans")
	if r.OK() || c.OK || !strings.Contains(c.Detail, "digest version 9") {
		t.Fatalf("%+v", c)
	}
}

// A scan whose attested record contradicts itself (opened a finding it did not
// see) was chained faithfully and is still refused.
func TestVerifySurfaceSelfContradictoryScanFails(t *testing.T) {
	cases := map[string]func(scans []SurfaceScan){
		"opened but not seen": func(s []SurfaceScan) { s[2].Seen = nil },
		"opened as other severity": func(s []SurfaceScan) {
			s[2].Seen = append([]SurfaceSeen(nil), s[2].Seen...)
			s[2].Seen[0].Severity = "high"
		},
		"resolved but seen": func(s []SurfaceScan) { s[1].Seen = append([]SurfaceSeen(nil), s[2].Seen...) },
		"seen twice":        func(s []SurfaceScan) { s[2].Seen = append(s[2].Seen, s[2].Seen[0]) },
	}
	for name, edit := range cases {
		b := surfaceBundleDigests(t, DigestV2, DigestV2, DigestV2, edit)
		r := Verify(b)
		c := check(t, r, "surface scans")
		if r.OK() || c.OK || !strings.Contains(c.Detail, "contradicts itself") {
			t.Errorf("%s: %+v", name, c)
		}
	}
}

// A scan chained under a version number this verifier does not know cannot be
// recomputed, so it fails rather than passing unchecked.
func TestScanDigestVersionUnknownMatchesNothing(t *testing.T) {
	b := surfaceBundle(t)
	if ScanDigestVersion(3, b.Surface.Scans[0]) != "" || ScanDigestVersion(0, b.Surface.Scans[0]) != "" {
		t.Fatal("an unknown version must return no digest")
	}
	if ScanDigestVersion(DigestV1, b.Surface.Scans[2]) == ScanDigestVersion(DigestV2, b.Surface.Scans[2]) {
		t.Fatal("v1 and v2 digests of a scan that saw a finding must differ")
	}
}

// Findings of an asset that has a scan the chain does not hold cannot be
// recomputed, so they are unattested, but a finding an attested scan opened is
// still required to be present.
func TestVerifySurfaceWithheldFindingOfPartlyAttestedAsset(t *testing.T) {
	b := surfaceBundle(t)
	extra := b.Surface.Scans[0]
	extra.ScanID = 99 // same asset, no chained entry
	extra.FinishedAt = extra.FinishedAt.Add(96 * time.Hour)
	b.Surface.Scans = append(b.Surface.Scans, extra)
	if r := Verify(b); !r.OK() || r.Surface.FindingsUnattested != 1 {
		t.Fatalf("%+v %+v", r.Surface, r.Checks)
	}
	b.Surface.Findings = nil
	r := Verify(b)
	if c := check(t, r, "surface findings"); r.OK() || c.OK || !strings.Contains(c.Detail, "withheld") {
		t.Fatalf("a finding an attested scan opened cannot be left out: %+v", c)
	}
}

// Dropping the section from the bundle is what an attacker does when emptying
// the findings is too visible; the chain still shows the scans.
func TestVerifySurfaceSectionRemovedNamesTheChain(t *testing.T) {
	b := surfaceBundle(t)
	b.Surface = nil
	r := Verify(b)
	c := check(t, r, "surface evidence")
	if r.OK() || c.OK || !strings.Contains(c.Detail, "3 surface scan(s)") {
		t.Fatalf("%+v", c)
	}
}

// Bundles written before slice 7c carry the earlier provenance sentence; they
// are checked by this Verify all the same.
func TestVerifySurfaceAcceptsTheEarlierProvenanceSentence(t *testing.T) {
	b := surfaceBundle(t)
	b.Surface.Provenance = surfaceProvenanceV1
	if r := Verify(b); !r.OK() {
		t.Fatalf("%+v", r.Checks)
	}
}

func TestFindingContentDigestIgnoresNilVersusEmptyAndKeyOrder(t *testing.T) {
	a := FindingContentDigest("d", "f", nil, nil)
	if a != FindingContentDigest("d", "f", map[string]any{}, []string{}) {
		t.Fatal("nil and empty must hash alike")
	}
	x := FindingContentDigest("d", "f", map[string]any{"a": 1, "b": []any{"x", "y"}}, []string{"CC1.1", "CC2.1"})
	y := FindingContentDigest("d", "f", map[string]any{"b": []any{"x", "y"}, "a": 1}, []string{"CC1.1", "CC2.1"})
	if x != y {
		t.Fatal("key order must not matter")
	}
	if x == FindingContentDigest("d", "f", map[string]any{"a": 1, "b": []any{"x", "y"}}, []string{"CC2.1", "CC1.1"}) {
		t.Fatal("control order is part of the content")
	}
	if a == FindingContentDigest("d", "g", nil, nil) || a == FindingContentDigest("e", "f", nil, nil) {
		t.Fatal("detail and fix are part of the content")
	}
}
