package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// External surface evidence (slice 7b).
//
// A bundle can carry the external surface scanner's record: the assets the
// operator declared, every scan with the raw observation of every check, and
// the findings with the intervals they were open. It is exported with the same
// rule as the compliance assessment: say exactly which part is verifiable.
//
// # What is and is not proven
//
// The findings, the observations and the asset list are rows in Postgres, not
// entries of the hash chain, so on their own they prove nothing. What makes
// them checkable is that the control plane appends one chained audit entry,
// "surface_scan_recorded", in the same database transaction that stores a scan.
// The entry holds the SHA-256 digest (ScanDigest) of the scan as stored: the
// asset, the times, every observation, and every finding that scan opened or
// closed. Verify recomputes the digest from the bundle's own copy and compares
// it with the chained entry:
//
//   - A scan whose digest matches is attested: its observations (the record text,
//     the certificate fields), the findings it opened or closed and, since the
//     v2 digest, every finding it saw (id, subject, check, severity, title and a
//     digest of detail, fix, evidence and controls) are exactly what the control
//     plane stored when it ran, and the chain fixes the date.
//   - A finding's open and closed dates are then recomputed from the attested
//     scans and compared with the dates the bundle claims. A match proves "this
//     finding was open on date A and closed on date B" under the chain's weight.
//   - The findings list is cross-checked both ways. Every finding an attested scan
//     opened or closed must be in the bundle (a withheld finding fails), and, when
//     every scan of an asset is attested, every finding the bundle lists for that
//     asset must have been opened by one (an invented or duplicated finding
//     fails). A finding's severity, title, check, detail, fix, evidence and
//     controls must equal what the latest scan that saw it recorded; an edit to
//     any of them fails. Findings whose last sighting predates the v2 digest are
//     verified for their dates only, and the report counts them separately.
//   - A scan with no chained entry (it ran before attestation existed, or lies
//     outside the exported audit range) is reported as unattested, not failed:
//     the bundle carries it, but nothing in the bundle vouches for it. Findings
//     of an asset with any unattested scan are unattested too, because their
//     history cannot be recomputed completely.
//   - A chained entry whose scan is missing from the bundle, or whose digest does
//     not match, is a failure: the bundle withheld or altered a scan.
//
// The assets' own list (which values were declared, who authorised them) is
// context. The chain records "surface_asset_add" and "surface_asset_authorise"
// entries with the same facts; they are not cross-checked here.

// SurfaceScanAction is the audit action under which a recorded scan's digest is
// chained.
const SurfaceScanAction = "surface_scan_recorded"

// SurfaceProvenance is the sentence every bundle with a surface section carries.
const SurfaceProvenance = "Each scan's digest is recomputed from this bundle's copy of its observations and of the findings it saw, opened or closed, " +
	"and compared with the chained 'surface_scan_recorded' entry written when the scan was stored; a finding's open and closed dates, " +
	"severity, title and content are recomputed from the attested scans, and a finding that is missing from, or extra in, this list fails. " +
	"Scans without a matching chained entry are reported as unattested and prove nothing. " +
	"A check that could not run is recorded as not assessed and is never a pass."

// surfaceProvenanceV1 is the sentence bundles carried before slice 7c. It stays
// accepted so an older bundle still reads; the checks that run are the ones in
// this version of Verify, whatever sentence the bundle carries.
const surfaceProvenanceV1 = "Each scan's digest is recomputed from this bundle's copy of its observations and findings and compared with " +
	"the chained 'surface_scan_recorded' entry written when the scan was stored; a finding's open and closed dates are recomputed from " +
	"the attested scans. Scans without a matching chained entry are reported as unattested and prove nothing. " +
	"A check that could not run is recorded as not assessed and is never a pass."

const (
	surfaceDigestDomainV1 = "defendsec-surface-scan-v1"
	surfaceDigestDomainV2 = "defendsec-surface-scan-v2"

	// DigestV1 covers a scan's observations and the findings it opened or
	// closed. DigestV2 adds every finding the scan saw. A chained entry
	// without a version is v1.
	DigestV1 = 1
	DigestV2 = 2
)

// SurfaceAsset is a declared asset, as context for the scans and findings.
type SurfaceAsset struct {
	ID           int64      `json:"id"`
	Kind         string     `json:"kind"`
	Value        string     `json:"value"`
	Label        string     `json:"label,omitempty"`
	Authorised   bool       `json:"authorised"`
	AuthorisedBy string     `json:"authorisedBy,omitempty"`
	AuthorisedAt *time.Time `json:"authorisedAt,omitempty"`
	// Removed assets are kept: their findings and observations are evidence.
	Removed bool `json:"removed,omitempty"`
}

// SurfaceObservation is the raw record of one check group in one scan.
type SurfaceObservation struct {
	Check    string `json:"check"`
	Assessed bool   `json:"assessed"`
	Reason   string `json:"reason,omitempty"`
	// Observed is the record text, certificate fields and so on, as JSON.
	Observed   json.RawMessage `json:"observed"`
	ObservedAt time.Time       `json:"observedAt"`
}

// Surface finding changes a scan made.
const (
	SurfaceOpened   = "opened"   // new, or came back after being resolved
	SurfaceResolved = "resolved" // a check that ran no longer saw it
)

// SurfaceChange is one finding a scan opened or closed.
type SurfaceChange struct {
	FindingID string `json:"findingId"`
	Subject   string `json:"subject"`
	Severity  string `json:"severity"`
	Change    string `json:"change"`
}

// SurfaceScan is one recorded scan of one asset.
type SurfaceScan struct {
	ScanID       int64                `json:"scanId"`
	AssetID      int64                `json:"assetId"`
	AssetKind    string               `json:"assetKind"`
	AssetValue   string               `json:"assetValue"`
	TriggeredBy  string               `json:"triggeredBy"`
	StartedAt    time.Time            `json:"startedAt"`
	FinishedAt   time.Time            `json:"finishedAt"`
	Observations []SurfaceObservation `json:"observations"`
	Changes      []SurfaceChange      `json:"changes"`
	// Seen is every finding this scan's checks reported, opened or not (v2
	// digest). Scans recorded before slice 7c carry none.
	Seen []SurfaceSeen `json:"seen,omitempty"`
}

// SurfaceSeen is one finding as a scan reported it. Title and severity change
// from scan to scan (a certificate's days left), so a finding's identity is
// what the latest scan that saw it recorded.
type SurfaceSeen struct {
	FindingID string `json:"findingId"`
	Subject   string `json:"subject"`
	Check     string `json:"check"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	// Content is FindingContentDigest of the detail, fix, evidence and controls.
	Content string `json:"content"`
}

// FindingContentDigest is the SHA-256 (hex) of the parts of a finding that are
// too long to repeat in every scan: detail, fix, evidence (canonical JSON, so a
// jsonb round trip does not change it) and the control tags, in order. A nil
// evidence map and an empty one hash alike.
func FindingContentDigest(detail, fix string, evidence map[string]any, controls []string) string {
	if evidence == nil {
		evidence = map[string]any{}
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		raw = []byte("unmarshalable")
	}
	var b bytes.Buffer
	b.WriteString("defendsec-surface-finding-v1\n")
	writeDigestField(&b, detail)
	writeDigestField(&b, fix)
	writeDigestField(&b, canonicalJSON(raw))
	writeDigestField(&b, strconv.Itoa(len(controls)))
	for _, c := range controls {
		writeDigestField(&b, c)
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// SeenFromFinding is the attested record of a stored finding.
func SeenFromFinding(f SurfaceFinding) SurfaceSeen {
	return SurfaceSeen{
		FindingID: f.FindingID, Subject: f.Subject, Check: f.Check, Severity: f.Severity, Title: f.Title,
		Content: FindingContentDigest(f.Detail, f.Fix, f.Evidence, f.Controls),
	}
}

// SurfaceInterval is a span a finding was open; ClosedAt is nil while it is.
type SurfaceInterval struct {
	OpenedAt time.Time  `json:"openedAt"`
	ClosedAt *time.Time `json:"closedAt,omitempty"`
}

// SurfaceFinding is a finding with every interval it was open.
type SurfaceFinding struct {
	AssetID    int64          `json:"assetId"`
	AssetKind  string         `json:"assetKind"`
	AssetValue string         `json:"assetValue"`
	Check      string         `json:"check"`
	FindingID  string         `json:"findingId"`
	Subject    string         `json:"subject"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail,omitempty"`
	Fix        string         `json:"fix,omitempty"`
	Evidence   map[string]any `json:"evidence"`
	Controls   []string       `json:"controls,omitempty"`
	FirstScan  int64          `json:"firstScanId,omitempty"`
	LastScan   int64          `json:"lastScanId,omitempty"`
	// Intervals are every span the finding was open, oldest first: the closed
	// ones, then the current one if it is open.
	Intervals []SurfaceInterval `json:"intervals"`
}

// SurfaceScope is the surface section of a bundle.
type SurfaceScope struct {
	Assets     []SurfaceAsset   `json:"assets"`
	Scans      []SurfaceScan    `json:"scans"`
	Findings   []SurfaceFinding `json:"findings"`
	Provenance string           `json:"provenance"`
}

// canonicalJSON renders a JSON value with sorted keys and no insignificant
// space, so a value read back from Postgres jsonb hashes like the value that
// was written.
func canonicalJSON(raw []byte) string {
	var v any
	if len(bytes.TrimSpace(raw)) == 0 {
		return "null"
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		// Not JSON: hash the bytes as they are, so a corrupted value still
		// changes the digest rather than being skipped.
		return string(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

func writeDigestField(b *bytes.Buffer, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
	b.WriteByte('\n')
}

func digestTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ScanDigest is the current (v2) digest of a scan; see ScanDigestVersion.
func ScanDigest(s SurfaceScan) string { return ScanDigestVersion(DigestV2, s) }

// ScanDigestVersion is the SHA-256 (hex) of a scan as stored: its identity, the
// asset, both times, every observation and every change, each length-prefixed
// so no two different scans can render the same bytes; v2 adds every finding
// the scan saw. Observations, changes and findings are sorted first, so the
// digest does not depend on the order they were read in. An unknown version
// returns "", which matches nothing.
func ScanDigestVersion(version int, s SurfaceScan) string {
	var b bytes.Buffer
	switch version {
	case DigestV1:
		b.WriteString(surfaceDigestDomainV1)
	case DigestV2:
		b.WriteString(surfaceDigestDomainV2)
	default:
		return ""
	}
	b.WriteByte('\n')
	writeDigestField(&b, strconv.FormatInt(s.ScanID, 10))
	writeDigestField(&b, strconv.FormatInt(s.AssetID, 10))
	writeDigestField(&b, s.AssetKind)
	writeDigestField(&b, s.AssetValue)
	writeDigestField(&b, s.TriggeredBy)
	writeDigestField(&b, digestTime(s.StartedAt))
	writeDigestField(&b, digestTime(s.FinishedAt))

	obs := append([]SurfaceObservation(nil), s.Observations...)
	sort.Slice(obs, func(i, j int) bool { return obs[i].Check < obs[j].Check })
	writeDigestField(&b, strconv.Itoa(len(obs)))
	for _, o := range obs {
		writeDigestField(&b, o.Check)
		writeDigestField(&b, strconv.FormatBool(o.Assessed))
		writeDigestField(&b, o.Reason)
		writeDigestField(&b, canonicalJSON(o.Observed))
		writeDigestField(&b, digestTime(o.ObservedAt))
	}

	ch := append([]SurfaceChange(nil), s.Changes...)
	sort.Slice(ch, func(i, j int) bool {
		a, c := ch[i], ch[j]
		if a.FindingID != c.FindingID {
			return a.FindingID < c.FindingID
		}
		if a.Subject != c.Subject {
			return a.Subject < c.Subject
		}
		return a.Change < c.Change
	})
	writeDigestField(&b, strconv.Itoa(len(ch)))
	for _, c := range ch {
		writeDigestField(&b, c.FindingID)
		writeDigestField(&b, c.Subject)
		writeDigestField(&b, c.Severity)
		writeDigestField(&b, c.Change)
	}

	if version == DigestV2 {
		seen := append([]SurfaceSeen(nil), s.Seen...)
		sort.Slice(seen, func(i, j int) bool {
			if seen[i].FindingID != seen[j].FindingID {
				return seen[i].FindingID < seen[j].FindingID
			}
			return seen[i].Subject < seen[j].Subject
		})
		writeDigestField(&b, strconv.Itoa(len(seen)))
		for _, f := range seen {
			writeDigestField(&b, f.FindingID)
			writeDigestField(&b, f.Subject)
			writeDigestField(&b, f.Check)
			writeDigestField(&b, f.Severity)
			writeDigestField(&b, f.Title)
			writeDigestField(&b, f.Content)
		}
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// SurfaceScanEntry is the detail of a chained "surface_scan_recorded" entry.
type SurfaceScanEntry struct {
	// Version is the digest version (DigestV2 since slice 7c); absent means v1.
	Version    int    `json:"v,omitempty"`
	ScanID     int64  `json:"scanId"`
	AssetID    int64  `json:"assetId"`
	Digest     string `json:"digest"`
	FinishedAt string `json:"finishedAt"`
	Opened     int    `json:"opened"`
	Resolved   int    `json:"resolved"`
}

// SurfaceReport counts what Verify found in the surface section. Unattested
// numbers matter as much as failures.
type SurfaceReport struct {
	Scans           int `json:"scans"`
	ScansAttested   int `json:"scansAttested"`
	ScansUnattested int `json:"scansUnattested"`
	ScansFailed     int `json:"scansFailed"`
	Findings        int `json:"findings"`
	// FindingsVerified are findings whose dates and identity fields (severity,
	// title, check, detail, fix, evidence, controls) match the attested scans.
	FindingsVerified int `json:"findingsVerified"`
	// FindingsDatesOnly are findings whose dates match but whose last sighting
	// predates the v2 digest, so their title and severity are not attested.
	FindingsDatesOnly  int `json:"findingsDatesOnly"`
	FindingsUnattested int `json:"findingsUnattested"`
	FindingsFailed     int `json:"findingsFailed"`
}

type findingKey struct {
	asset   int64
	finding string
	subject string
}

// verifySurface checks the surface section against the chain. See the package
// comment above for exactly what it does and does not prove.
func verifySurface(b *Bundle, rep *Report) {
	sc := b.Surface

	// The chain's side: one entry per attested scan.
	entries := map[int64][]SurfaceScanEntry{}
	chained, unreadable := 0, 0
	for _, e := range b.Audit {
		if e.Action != SurfaceScanAction {
			continue
		}
		chained++
		var d SurfaceScanEntry
		if err := json.Unmarshal([]byte(e.Detail), &d); err != nil || d.ScanID == 0 {
			unreadable++
			if sc != nil {
				rep.add("surface scans", false, "chained entry %d (%s) has an unreadable detail", e.Seq, SurfaceScanAction)
				rep.Surface.ScansFailed++
			}
			continue
		}
		entries[d.ScanID] = append(entries[d.ScanID], d)
	}

	if sc == nil {
		// A bundle without the section is not a bundle of an instance that never
		// scanned: the chain would say so. Dropping the section must not read as
		// "nothing was found".
		if chained > 0 {
			rep.add("surface evidence", false, "the chain records %d surface scan(s) but the bundle carries no surface section: the scans, observations and findings were left out", chained)
		}
		return
	}
	sr := &rep.Surface
	sr.Scans, sr.Findings = len(sc.Scans), len(sc.Findings)

	if sc.Provenance != SurfaceProvenance && sc.Provenance != surfaceProvenanceV1 {
		rep.add("surface evidence", false, "the surface section's provenance statement does not match the expected text")
		return
	}

	var problems []string
	attested := map[int64]int{} // scan id -> digest version
	unattestedAssets := map[int64]bool{}
	byID := map[int64]bool{}
	for _, s := range sc.Scans {
		if byID[s.ScanID] {
			sr.ScansFailed++
			unattestedAssets[s.AssetID] = true
			problems = append(problems, fmt.Sprintf("scan %d appears more than once in the bundle", s.ScanID))
			continue
		}
		byID[s.ScanID] = true
		es := entries[s.ScanID]
		switch {
		case len(es) == 0:
			sr.ScansUnattested++
			unattestedAssets[s.AssetID] = true
		case len(es) > 1:
			sr.ScansFailed++
			unattestedAssets[s.AssetID] = true
			problems = append(problems, fmt.Sprintf("scan %d is attested by %d chained entries", s.ScanID, len(es)))
		default:
			v := es[0].Version
			if v == 0 {
				v = DigestV1
			}
			want := ScanDigestVersion(v, s)
			switch {
			case want == "":
				sr.ScansFailed++
				unattestedAssets[s.AssetID] = true
				problems = append(problems, fmt.Sprintf("scan %d is attested with digest version %d, which this verifier does not know", s.ScanID, es[0].Version))
			case es[0].Digest != want || es[0].AssetID != s.AssetID:
				sr.ScansFailed++
				// Nothing vouches for this asset's history any more; the failed scan is
				// the finding, and recomputing dates from the rest would only add noise.
				unattestedAssets[s.AssetID] = true
				problems = append(problems, fmt.Sprintf("scan %d does not match its chained digest: the observations or findings in this bundle differ from what was recorded", s.ScanID))
			default:
				if msg := seenInconsistency(s, v); msg != "" {
					sr.ScansFailed++
					unattestedAssets[s.AssetID] = true
					problems = append(problems, fmt.Sprintf("scan %d: the attested record contradicts itself (%s)", s.ScanID, msg))
					continue
				}
				sr.ScansAttested++
				attested[s.ScanID] = v
			}
		}
	}
	for id, es := range entries {
		if !byID[id] {
			sr.ScansFailed++
			unattestedAssets[es[0].AssetID] = true
			problems = append(problems, fmt.Sprintf("scan %d is recorded in the chain but missing from the bundle", id))
		}
	}
	sort.Strings(problems)
	if len(problems) > 0 {
		rep.add("surface scans", false, "%s", joinProblems(problems))
	} else {
		rep.add("surface scans", true,
			"%d scans: %d attested (digest recomputed from the bundle and matched to its chained entry), %d unattested (no chained entry: recorded before attestation existed, or outside the exported audit range).",
			sr.Scans, sr.ScansAttested, sr.ScansUnattested)
	}

	// Findings. Walk the attested scans oldest first and build, for every
	// finding they opened, closed or saw: its events, the latest sighting, and
	// where that sighting is.
	type event struct {
		at     time.Time
		scan   int64
		change string
	}
	type state struct {
		events   []event
		seen     *SurfaceSeen // latest sighting in a v2 scan
		seenIdx  int          // its position in the oldest-first order
		seenScan int64
	}
	var ordered []SurfaceScan
	for _, s := range sc.Scans {
		if _, ok := attested[s.ScanID]; ok {
			ordered = append(ordered, s)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		if !ordered[i].FinishedAt.Equal(ordered[j].FinishedAt) {
			return ordered[i].FinishedAt.Before(ordered[j].FinishedAt)
		}
		return ordered[i].ScanID < ordered[j].ScanID
	})
	states := map[findingKey]*state{}
	lastV1 := map[int64]int{} // asset -> position of its newest scan without a v2 digest
	assetOf := map[int64][2]string{}
	get := func(k findingKey) *state {
		if states[k] == nil {
			states[k] = &state{seenIdx: -1}
		}
		return states[k]
	}
	for i, s := range ordered {
		assetOf[s.AssetID] = [2]string{s.AssetKind, s.AssetValue}
		if attested[s.ScanID] == DigestV1 {
			lastV1[s.AssetID] = i
		}
		for _, c := range s.Changes {
			st := get(findingKey{s.AssetID, c.FindingID, c.Subject})
			st.events = append(st.events, event{s.FinishedAt.UTC(), s.ScanID, c.Change})
		}
		if attested[s.ScanID] == DigestV2 {
			for j := range s.Seen {
				f := s.Seen[j]
				st := get(findingKey{s.AssetID, f.FindingID, f.Subject})
				st.seen, st.seenIdx, st.seenScan = &f, i, s.ScanID
			}
		}
	}

	var fproblems []string
	listed := map[findingKey]bool{}
	for _, f := range sc.Findings {
		k := findingKey{f.AssetID, f.FindingID, f.Subject}
		name := fmt.Sprintf("%s %s on %s", f.FindingID, f.Subject, f.AssetValue)
		if listed[k] {
			sr.FindingsFailed++
			fproblems = append(fproblems, name+": listed more than once")
			continue
		}
		listed[k] = true
		if unattestedAssets[f.AssetID] {
			sr.FindingsUnattested++
			continue
		}
		st := states[k]
		if st == nil || len(st.events) == 0 {
			sr.FindingsFailed++
			fproblems = append(fproblems, name+": no attested scan opened this finding (it is not in the record the chain attests)")
			continue
		}
		ev := st.events
		sort.SliceStable(ev, func(i, j int) bool {
			if !ev[i].at.Equal(ev[j].at) {
				return ev[i].at.Before(ev[j].at)
			}
			return ev[i].scan < ev[j].scan
		})
		var got []SurfaceInterval
		var openedScan, closedScan int64
		for _, e := range ev {
			switch e.change {
			case SurfaceOpened:
				got = append(got, SurfaceInterval{OpenedAt: e.at})
				openedScan, closedScan = e.scan, 0
			case SurfaceResolved:
				if n := len(got); n > 0 && got[n-1].ClosedAt == nil {
					t := e.at
					got[n-1].ClosedAt = &t
					closedScan = e.scan
				}
			}
		}
		claimed := append([]SurfaceInterval(nil), f.Intervals...)
		sort.SliceStable(claimed, func(i, j int) bool { return claimed[i].OpenedAt.Before(claimed[j].OpenedAt) })
		if !intervalsEqual(got, claimed) {
			sr.FindingsFailed++
			fproblems = append(fproblems, fmt.Sprintf("%s: the bundle claims %s, the attested scans give %s",
				name, describeIntervals(claimed), describeIntervals(got)))
			continue
		}
		if a := assetOf[f.AssetID]; a[0] != f.AssetKind || a[1] != f.AssetValue {
			sr.FindingsFailed++
			fproblems = append(fproblems, fmt.Sprintf("%s: the bundle puts it on %s %s, the attested scans of asset %d are of %s %s",
				name, f.AssetKind, f.AssetValue, f.AssetID, a[0], a[1]))
			continue
		}
		if st.seen == nil || st.seenIdx <= lastV1[f.AssetID] && hasKey(lastV1, f.AssetID) {
			// Dates are proven; what the finding said is not (its last sighting was
			// recorded before scans attested the findings they saw).
			sr.FindingsDatesOnly++
			continue
		}
		var diff []string
		if f.Check != st.seen.Check {
			diff = append(diff, "check")
		}
		if f.Severity != st.seen.Severity {
			diff = append(diff, fmt.Sprintf("severity (bundle %q, scan %d recorded %q)", f.Severity, st.seenScan, st.seen.Severity))
		}
		if f.Title != st.seen.Title {
			diff = append(diff, "title")
		}
		if FindingContentDigest(f.Detail, f.Fix, f.Evidence, f.Controls) != st.seen.Content {
			diff = append(diff, "detail, fix, evidence or controls")
		}
		wantLast := st.seenScan
		if closedScan != 0 {
			wantLast = closedScan
		}
		if f.FirstScan != openedScan {
			diff = append(diff, fmt.Sprintf("first scan (bundle %d, attested %d)", f.FirstScan, openedScan))
		}
		if f.LastScan != wantLast {
			diff = append(diff, fmt.Sprintf("last scan (bundle %d, attested %d)", f.LastScan, wantLast))
		}
		if len(diff) > 0 {
			sr.FindingsFailed++
			fproblems = append(fproblems, fmt.Sprintf("%s: %s differ from what scan %d recorded", name, strings.Join(diff, ", "), st.seenScan))
			continue
		}
		sr.FindingsVerified++
	}
	// The other direction: a finding an attested scan opened or closed cannot be
	// absent. (Rows are never deleted, so a missing one was left out.)
	var keys []findingKey
	for k, st := range states {
		if len(st.events) > 0 && !listed[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if a.asset != c.asset {
			return a.asset < c.asset
		}
		if a.finding != c.finding {
			return a.finding < c.finding
		}
		return a.subject < c.subject
	})
	for _, k := range keys {
		sr.FindingsFailed++
		fproblems = append(fproblems, fmt.Sprintf("%s %s on %s: an attested scan recorded it, but the bundle does not list it (withheld)",
			k.finding, k.subject, assetOf[k.asset][1]))
	}
	sort.Strings(fproblems)
	if len(fproblems) > 0 {
		rep.add("surface findings", false, "%s", joinProblems(fproblems))
		return
	}
	rep.add("surface findings", true,
		"%d findings: %d with open and closed dates recomputed from attested scans and matched, and severity, title, detail, fix, evidence and controls matched to the latest attested scan that saw them; %d with dates only (last seen before scans attested what they saw: severity and title are not proven); %d unattested (their asset has a scan the chain does not vouch for).",
		sr.Findings, sr.FindingsVerified, sr.FindingsDatesOnly, sr.FindingsUnattested)
}

func hasKey(m map[int64]int, k int64) bool { _, ok := m[k]; return ok }

// seenInconsistency reports a v2 scan whose own record contradicts itself: a
// finding opened without being seen, closed while seen, or seen twice. Such a
// scan was attested faithfully and still cannot be trusted to say anything.
func seenInconsistency(s SurfaceScan, version int) string {
	if version != DigestV2 {
		return ""
	}
	seen := map[[2]string]string{}
	for _, f := range s.Seen {
		k := [2]string{f.FindingID, f.Subject}
		if _, dup := seen[k]; dup {
			return fmt.Sprintf("%s %s is listed twice as seen", f.FindingID, f.Subject)
		}
		seen[k] = f.Severity
	}
	for _, c := range s.Changes {
		sev, ok := seen[[2]string{c.FindingID, c.Subject}]
		switch c.Change {
		case SurfaceOpened:
			if !ok {
				return fmt.Sprintf("%s %s was opened but not seen", c.FindingID, c.Subject)
			}
			if sev != c.Severity {
				return fmt.Sprintf("%s %s was opened as %s but seen as %s", c.FindingID, c.Subject, c.Severity, sev)
			}
		case SurfaceResolved:
			if ok {
				return fmt.Sprintf("%s %s was resolved but also seen", c.FindingID, c.Subject)
			}
		}
	}
	return ""
}

func joinProblems(p []string) string {
	const max = 5
	out := ""
	for i, s := range p {
		if i == max {
			out += fmt.Sprintf("; and %d more", len(p)-max)
			break
		}
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

func intervalsEqual(a, b []SurfaceInterval) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].OpenedAt.Equal(b[i].OpenedAt) {
			return false
		}
		switch {
		case a[i].ClosedAt == nil && b[i].ClosedAt == nil:
		case a[i].ClosedAt == nil || b[i].ClosedAt == nil:
			return false
		case !a[i].ClosedAt.Equal(*b[i].ClosedAt):
			return false
		}
	}
	return true
}

func describeIntervals(iv []SurfaceInterval) string {
	if len(iv) == 0 {
		return "no interval"
	}
	out := ""
	for i, x := range iv {
		if i > 0 {
			out += ", "
		}
		out += x.OpenedAt.UTC().Format("2006-01-02T15:04:05Z") + " to "
		if x.ClosedAt == nil {
			out += "now"
		} else {
			out += x.ClosedAt.UTC().Format("2006-01-02T15:04:05Z")
		}
	}
	return out
}
