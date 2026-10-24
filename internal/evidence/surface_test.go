package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"defendsec/internal/auditchain"
)

// surfaceBundle builds a bundle whose chain attests three scans of one asset:
// scan 1 opens a finding, scan 2 closes it, scan 3 opens it again. Everything
// is example.com / RFC 5737 data.
func surfaceBundle(t *testing.T) *Bundle {
	t.Helper()
	return surfaceBundleDigests(t, DigestV2, DigestV2, DigestV2, nil)
}

// surfaceBundleDigests is surfaceBundle with the digest version of each of the
// three scans chosen (a v1 scan carries no Seen, as scans recorded before slice
// 7c did) and an optional change to the scans before they are chained.
func surfaceBundleDigests(t *testing.T, v1, v2, v3 int, edit func(scans []SurfaceScan)) *Bundle {
	t.Helper()
	b, key := testBundle(t)
	t0 := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
	// The finding as the control plane stored it after scan 3, which saw it.
	stored := SurfaceFinding{
		AssetID: 7, AssetKind: "domain", AssetValue: "example.com", Check: "dmarc", FindingID: "dmarc.p_none", Subject: "example.com",
		Severity: "medium", Title: "DMARC policy is p=none", Evidence: map[string]any{"record": "v=DMARC1; p=none"},
		FirstScan: 3, LastScan: 3,
	}
	scan := func(id int64, at time.Time, finding, change string) SurfaceScan {
		s := SurfaceScan{
			ScanID: id, AssetID: 7, AssetKind: "domain", AssetValue: "example.com", TriggeredBy: "schedule",
			StartedAt: at.Add(-4 * time.Second), FinishedAt: at,
			Observations: []SurfaceObservation{
				{Check: "dmarc", Assessed: true, Observed: json.RawMessage(`{"record":"v=DMARC1; p=none","host":"_dmarc.example.com"}`), ObservedAt: at},
				{Check: "dkim", Assessed: false, Reason: "no selector found", Observed: json.RawMessage(`{"checked":["google","selector1"]}`), ObservedAt: at},
			},
			Changes: []SurfaceChange{},
		}
		if change != "" {
			s.Changes = append(s.Changes, SurfaceChange{FindingID: finding, Subject: "example.com", Severity: "medium", Change: change})
		}
		if change == SurfaceOpened {
			s.Seen = []SurfaceSeen{SeenFromFinding(stored)}
		}
		return s
	}
	scans := []SurfaceScan{
		scan(1, t0, "dmarc.p_none", SurfaceOpened),
		scan(2, t0.Add(24*time.Hour), "dmarc.p_none", SurfaceResolved),
		scan(3, t0.Add(48*time.Hour), "dmarc.p_none", SurfaceOpened),
	}

	versions := []int{v1, v2, v3}
	for i := range scans {
		if versions[i] == DigestV1 {
			scans[i].Seen = nil
		}
	}
	if edit != nil {
		edit(scans)
	}
	var entries []auditchain.Entry
	prev := auditchain.Genesis
	for i, s := range scans {
		ev := versions[i]
		if ev == DigestV1 {
			ev = 0 // an entry written before slice 7c has no version
		}
		d, _ := json.Marshal(SurfaceScanEntry{Version: ev, ScanID: s.ScanID, AssetID: s.AssetID, Digest: ScanDigestVersion(versions[i], s), FinishedAt: s.FinishedAt.Format(time.RFC3339Nano)})
		e := auditchain.Link(prev, auditchain.Entry{
			Seq: int64(i + 1), At: s.FinishedAt.Add(time.Second), Actor: "system:surface-scanner", Action: SurfaceScanAction, Detail: string(d),
		})
		prev = e.EntryHash
		entries = append(entries, e)
	}
	last := entries[len(entries)-1]
	b.Audit = entries
	b.Commands = nil
	b.Manifest.FromSeq, b.Manifest.ThroughSeq, b.Manifest.PrevHash = 1, last.Seq, auditchain.Genesis
	b.Checkpoints = []auditchain.Checkpoint{auditchain.SignCheckpoint(key.Private, auditchain.Checkpoint{
		ThroughSeq: last.Seq, EntryHash: last.EntryHash, At: last.At.Add(time.Minute), SigningKeyID: key.KeyID(),
	})}

	t1, t2 := scans[1].FinishedAt, scans[2].FinishedAt
	b.Surface = &SurfaceScope{
		Assets: []SurfaceAsset{{ID: 7, Kind: "domain", Value: "example.com", Authorised: true, AuthorisedBy: "tester"}},
		Scans:  scans,
		Findings: []SurfaceFinding{func() SurfaceFinding {
			f := stored
			f.Intervals = []SurfaceInterval{{OpenedAt: t0, ClosedAt: &t1}, {OpenedAt: t2}}
			return f
		}()},
		Provenance: SurfaceProvenance,
	}
	return b
}

func check(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q check in %+v", name, r.Checks)
	return Check{}
}

func TestVerifySurfaceAttestedScansAndIntervals(t *testing.T) {
	b := surfaceBundle(t)
	r := Verify(b)
	if !r.OK() {
		t.Fatalf("an intact bundle must verify: %+v", r.Checks)
	}
	if r.Surface.ScansAttested != 3 || r.Surface.ScansUnattested != 0 || r.Surface.FindingsVerified != 1 {
		t.Fatalf("%+v", r.Surface)
	}
	if c := check(t, r, "surface findings"); !strings.Contains(c.Detail, "1 with open and closed dates recomputed") || !strings.Contains(c.Detail, "0 with dates only") {
		t.Fatalf("%+v", c)
	}
}

// The part of the section that is "open on date A, closed on date B": changing
// either date, or the number of intervals, must fail.
func TestVerifySurfaceCatchesAlteredFindingDates(t *testing.T) {
	later := time.Date(2026, 10, 25, 6, 0, 0, 0, time.UTC)
	cases := map[string]func(b *Bundle){
		"closed date moved":    func(b *Bundle) { b.Surface.Findings[0].Intervals[0].ClosedAt = &later },
		"opened date moved":    func(b *Bundle) { b.Surface.Findings[0].Intervals[0].OpenedAt = later.Add(-96 * time.Hour) },
		"closed gap removed":   func(b *Bundle) { b.Surface.Findings[0].Intervals = b.Surface.Findings[0].Intervals[1:] },
		"still open, was shut": func(b *Bundle) { b.Surface.Findings[0].Intervals[1].ClosedAt = &later },
		"invented finding": func(b *Bundle) {
			f := b.Surface.Findings[0]
			f.FindingID = "spf.plus_all"
			b.Surface.Findings = append(b.Surface.Findings, f)
		},
	}
	for name, mutate := range cases {
		b := surfaceBundle(t)
		mutate(b)
		r := Verify(b)
		if r.OK() || r.Surface.FindingsFailed == 0 {
			t.Errorf("%s: must fail, got %+v %+v", name, r.Surface, r.Checks)
		}
		if c := check(t, r, "surface findings"); c.OK {
			t.Errorf("%s: the surface findings check passed", name)
		}
	}
}

func TestVerifySurfaceCatchesAlteredObservations(t *testing.T) {
	cases := map[string]func(b *Bundle){
		"record text edited": func(b *Bundle) {
			b.Surface.Scans[1].Observations[0].Observed = json.RawMessage(`{"record":"v=DMARC1; p=reject"}`)
		},
		"not assessed turned into assessed":     func(b *Bundle) { b.Surface.Scans[0].Observations[1].Assessed = true },
		"observation dropped":                   func(b *Bundle) { b.Surface.Scans[2].Observations = b.Surface.Scans[2].Observations[:1] },
		"change dropped":                        func(b *Bundle) { b.Surface.Scans[1].Changes = nil },
		"change turned from resolved to opened": func(b *Bundle) { b.Surface.Scans[1].Changes[0].Change = SurfaceOpened },
		"change severity edited":                func(b *Bundle) { b.Surface.Scans[1].Changes[0].Severity = "low" },
		"scan date moved":                       func(b *Bundle) { b.Surface.Scans[1].FinishedAt = b.Surface.Scans[1].FinishedAt.Add(time.Hour) },
		"asset renamed":                         func(b *Bundle) { b.Surface.Scans[0].AssetValue = "example.net" },
	}
	for name, mutate := range cases {
		b := surfaceBundle(t)
		mutate(b)
		r := Verify(b)
		if r.OK() || r.Surface.ScansFailed == 0 {
			t.Errorf("%s: must fail, got %+v", name, r.Surface)
		}
		if c := check(t, r, "surface scans"); c.OK {
			t.Errorf("%s: the surface scans check passed", name)
		}
	}
}

func TestVerifySurfaceObservationKeyOrderAndWhitespaceDoNotMatter(t *testing.T) {
	b := surfaceBundle(t)
	// The same JSON, reformatted: what a bundle looks like after a round trip.
	b.Surface.Scans[0].Observations[0].Observed = json.RawMessage("{\n  \"host\": \"_dmarc.example.com\",\n  \"record\": \"v=DMARC1; p=none\"\n}")
	if r := Verify(b); !r.OK() {
		t.Fatalf("reformatted JSON must hash the same: %+v", r.Checks)
	}
}

func TestVerifySurfaceScanWithheldFromBundle(t *testing.T) {
	b := surfaceBundle(t)
	b.Surface.Scans = b.Surface.Scans[:2] // scan 3 is in the chain, not in the bundle
	r := Verify(b)
	if r.OK() {
		t.Fatal("a scan in the chain but missing from the bundle must fail")
	}
	if c := check(t, r, "surface scans"); c.OK || !strings.Contains(c.Detail, "scan 3 is recorded in the chain but missing from the bundle") {
		t.Fatalf("%+v", c)
	}
}

// A scan with no chained entry (it ran before attestation existed) is reported
// as unattested, not failed, and so are the findings of its asset: their
// history cannot be recomputed completely.
func TestVerifySurfaceUnattestedScansAreNamedNotFailed(t *testing.T) {
	b := surfaceBundle(t)
	old := b.Surface.Scans[0]
	old.ScanID = 99
	old.AssetID = 8
	old.AssetValue = "example.net"
	b.Surface.Scans = append(b.Surface.Scans, old)
	b.Surface.Findings = append(b.Surface.Findings, SurfaceFinding{
		AssetID: 8, AssetKind: "domain", AssetValue: "example.net", Check: "dmarc", FindingID: "dmarc.p_none", Subject: "example.net",
		Severity: "medium", Title: "DMARC policy is p=none", Intervals: []SurfaceInterval{{OpenedAt: old.FinishedAt}},
	})
	r := Verify(b)
	if !r.OK() {
		t.Fatalf("an unattested scan is not a failure: %+v", r.Checks)
	}
	if r.Surface.ScansAttested != 3 || r.Surface.ScansUnattested != 1 || r.Surface.FindingsVerified != 1 || r.Surface.FindingsUnattested != 1 {
		t.Fatalf("%+v", r.Surface)
	}
	if c := check(t, r, "surface scans"); !strings.Contains(c.Detail, "1 unattested") {
		t.Fatalf("the report must say how many scans are unattested: %+v", c)
	}
}

func TestVerifySurfaceProvenanceTextCannotBeEdited(t *testing.T) {
	b := surfaceBundle(t)
	b.Surface.Provenance = "Everything here is cryptographically proven."
	r := Verify(b)
	if r.OK() {
		t.Fatal("an edited provenance statement must fail")
	}
	if c := check(t, r, "surface evidence"); c.OK {
		t.Fatalf("%+v", c)
	}
}

func TestVerifyNoSurfaceSectionAddsNoChecks(t *testing.T) {
	b, _ := testBundle(t)
	r := Verify(b)
	for _, c := range r.Checks {
		if strings.HasPrefix(c.Name, "surface") {
			t.Fatalf("a bundle with no surface section must carry no surface check: %+v", c)
		}
	}
}

func TestScanDigestIsStableAcrossObservationOrder(t *testing.T) {
	b := surfaceBundle(t)
	s := b.Surface.Scans[0]
	want := ScanDigest(s)
	s.Observations = []SurfaceObservation{s.Observations[1], s.Observations[0]}
	if got := ScanDigest(s); got != want {
		t.Fatalf("digest depends on the order observations were read in: %s vs %s", got, want)
	}
	s.TriggeredBy = "manual"
	if ScanDigest(s) == want {
		t.Fatal("the trigger is part of the scan and must change the digest")
	}
}

// A scan that fails its digest is the failure; the findings of its asset are then
// unattested rather than a second, confusing failure.
func TestVerifySurfaceFailedScanDoesNotCascadeIntoFindings(t *testing.T) {
	b := surfaceBundle(t)
	b.Surface.Scans[1].Observations[0].Observed = json.RawMessage(`{"record":"v=DMARC1; p=reject"}`)
	r := Verify(b)
	if r.Surface.ScansFailed != 1 || r.Surface.FindingsFailed != 0 || r.Surface.FindingsUnattested != 1 {
		t.Fatalf("%+v", r.Surface)
	}
	b = surfaceBundle(t)
	b.Surface.Scans = b.Surface.Scans[:2]
	r = Verify(b)
	if r.Surface.ScansFailed != 1 || r.Surface.FindingsFailed != 0 || r.Surface.FindingsUnattested != 1 {
		t.Fatalf("a withheld scan: %+v", r.Surface)
	}
}
