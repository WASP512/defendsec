package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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
//     the certificate fields) and the findings it opened or closed are exactly
//     what the control plane stored when it ran, and the chain fixes the date.
//   - A finding's open and closed dates are then recomputed from the attested
//     scans and compared with the dates the bundle claims. A match proves "this
//     finding was open on date A and closed on date B" under the chain's weight.
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
const SurfaceProvenance = "Each scan's digest is recomputed from this bundle's copy of its observations and findings and compared with " +
	"the chained 'surface_scan_recorded' entry written when the scan was stored; a finding's open and closed dates are recomputed from " +
	"the attested scans. Scans without a matching chained entry are reported as unattested and prove nothing. " +
	"A check that could not run is recorded as not assessed and is never a pass."

const surfaceDigestDomain = "defendsec-surface-scan-v1"

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

// ScanDigest is the SHA-256 (hex) of a scan as stored: its identity, the asset,
// both times, every observation and every change, each length-prefixed so no
// two different scans can render the same bytes. Observations and changes are
// sorted first, so the digest does not depend on the order they were read in.
func ScanDigest(s SurfaceScan) string {
	var b bytes.Buffer
	b.WriteString(surfaceDigestDomain)
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
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// SurfaceScanEntry is the detail of a chained "surface_scan_recorded" entry.
type SurfaceScanEntry struct {
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
	Scans              int `json:"scans"`
	ScansAttested      int `json:"scansAttested"`
	ScansUnattested    int `json:"scansUnattested"`
	ScansFailed        int `json:"scansFailed"`
	Findings           int `json:"findings"`
	FindingsVerified   int `json:"findingsVerified"`
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
	if sc == nil {
		return
	}
	sr := &rep.Surface
	sr.Scans, sr.Findings = len(sc.Scans), len(sc.Findings)

	if sc.Provenance != SurfaceProvenance {
		rep.add("surface evidence", false, "the surface section's provenance statement does not match the expected text")
		return
	}

	// The chain's side: one entry per attested scan.
	entries := map[int64][]SurfaceScanEntry{}
	for _, e := range b.Audit {
		if e.Action != SurfaceScanAction {
			continue
		}
		var d SurfaceScanEntry
		if err := json.Unmarshal([]byte(e.Detail), &d); err != nil || d.ScanID == 0 {
			rep.add("surface scans", false, "chained entry %d (%s) has an unreadable detail", e.Seq, SurfaceScanAction)
			sr.ScansFailed++
			continue
		}
		entries[d.ScanID] = append(entries[d.ScanID], d)
	}

	var problems []string
	attested := map[int64]bool{}
	unattestedAssets := map[int64]bool{}
	byID := map[int64]bool{}
	for _, s := range sc.Scans {
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
		case es[0].Digest != ScanDigest(s) || es[0].AssetID != s.AssetID:
			sr.ScansFailed++
			// Nothing vouches for this asset's history any more; the failed scan is
			// the finding, and recomputing dates from the rest would only add noise.
			unattestedAssets[s.AssetID] = true
			problems = append(problems, fmt.Sprintf("scan %d does not match its chained digest: the observations or findings in this bundle differ from what was recorded", s.ScanID))
		default:
			sr.ScansAttested++
			attested[s.ScanID] = true
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

	// Findings: recompute each finding's intervals from the attested scans of
	// its asset, when every scan of that asset is attested.
	type event struct {
		at     time.Time
		scan   int64
		change string
	}
	events := map[findingKey][]event{}
	for _, s := range sc.Scans {
		if !attested[s.ScanID] {
			continue
		}
		for _, c := range s.Changes {
			k := findingKey{s.AssetID, c.FindingID, c.Subject}
			events[k] = append(events[k], event{s.FinishedAt.UTC(), s.ScanID, c.Change})
		}
	}
	var fproblems []string
	for _, f := range sc.Findings {
		if unattestedAssets[f.AssetID] {
			sr.FindingsUnattested++
			continue
		}
		k := findingKey{f.AssetID, f.FindingID, f.Subject}
		ev := events[k]
		sort.Slice(ev, func(i, j int) bool {
			if !ev[i].at.Equal(ev[j].at) {
				return ev[i].at.Before(ev[j].at)
			}
			return ev[i].scan < ev[j].scan
		})
		var got []SurfaceInterval
		for _, e := range ev {
			switch e.change {
			case SurfaceOpened:
				got = append(got, SurfaceInterval{OpenedAt: e.at})
			case SurfaceResolved:
				if n := len(got); n > 0 && got[n-1].ClosedAt == nil {
					t := e.at
					got[n-1].ClosedAt = &t
				}
			}
		}
		if intervalsEqual(got, f.Intervals) {
			sr.FindingsVerified++
			continue
		}
		sr.FindingsFailed++
		fproblems = append(fproblems, fmt.Sprintf("%s %s on %s: the bundle claims %s, the attested scans give %s",
			f.FindingID, f.Subject, f.AssetValue, describeIntervals(f.Intervals), describeIntervals(got)))
	}
	sort.Strings(fproblems)
	if len(fproblems) > 0 {
		rep.add("surface findings", false, "%s", joinProblems(fproblems))
		return
	}
	rep.add("surface findings", true,
		"%d findings: %d with open and closed dates recomputed from attested scans and matched, %d unattested (their asset has a scan the chain does not vouch for).",
		sr.Findings, sr.FindingsVerified, sr.FindingsUnattested)
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
