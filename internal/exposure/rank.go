// Package exposure holds the ranking rule of the exposure view: what the
// "Fix this week" list puts first. The rule lives here once, as code, and the
// SQL in storepg (which pages the list in the database) is tested against it.
//
// Ranking, most urgent first:
//
//  1. Exploited in the wild: advisories on the CISA KEV list come before all
//     others. Among them, the most recently added to KEV first (an entry added
//     last week is newer news than one added in 2021); an entry with no
//     recorded date goes last.
//  2. External surface findings of critical or high severity (slice 7b): a
//     reachable SMB port, a certificate that has expired, an SPF record that
//     lets anyone send as the domain. See "Surface findings" below.
//  3. EPSS, highest first: the probability of exploitation in the next 30 days.
//     No score goes last.
//  4. CVSS base score, highest first. No score goes last.
//  5. The vendor's severity label (critical, high, medium, low, unknown), so
//     rows with no scores at all still order sensibly.
//  6. Advisory id, so the order is total and a keyset cursor is stable.
//
// EPSS and CVSS order the KEV group too, after the date. CVSS is last among the
// scores on purpose: severity says what could happen, EPSS and KEV say what is
// happening.
//
// # Surface findings
//
// A surface finding has no KEV flag, no EPSS and no CVSS: nobody scores "DMARC
// is p=none". It enters the same order by the one thing it has, its severity,
// under rules that keep the principle of the vulnerability rule (what is
// happening now outranks what could happen):
//
//   - Critical and high findings are in effect now and reachable by anyone: no
//     foothold and no exploit is needed. They rank right after the KEV
//     vulnerabilities and before every vulnerability that is not on KEV,
//     whatever its EPSS. Among themselves: critical before high, then the lower
//     identifier (the older finding) first. The price of this rule is that a
//     non-KEV CVE with a very high EPSS ranks below an exposed RDP port; revisit
//     it with real data.
//   - Medium and low findings carry no exploitation signal, so they rank like a
//     vulnerability with no EPSS score and a CVSS equivalent to their severity
//     (SurfaceScore): after every vulnerability that has an EPSS score,
//     interleaved with the CVSS-only ones, so DMARC p=none sits with the medium
//     vulnerabilities.
//   - Info findings (DNSSEC unsigned, SSH reachable on a server) are
//     observations, not work: they are never ranked and never counted, like an
//     informational vulnerability.
//   - Missing evidence never ranks. A check that could not run produces no
//     finding, so there is nothing to rank; the store only hands this package
//     findings that a check actually confirmed.
package exposure

import (
	"strings"
	"time"
)

// Item is what the ranking looks at.
type Item struct {
	// AdvisoryID is the unique id of the row: the advisory id of a
	// vulnerability, or SurfaceKeyPrefix plus the zero-padded finding id of a
	// surface finding. It is the last tie-breaker.
	AdvisoryID string
	Severity   string
	KEV        bool
	// KEVAdded is the date the advisory entered the KEV catalog; meaningful
	// only when KEV is true.
	KEVAdded *time.Time
	EPSS     *float64
	CVSS     *float64
	// Surface marks an external-surface finding. Its KEV, EPSS and CVSS are
	// ignored: it ranks by Severity under the surface rules above.
	Surface bool
}

// The bands an item falls into; a lower band ranks first.
const (
	BandKEV           = 0 // a vulnerability on the CISA KEV list
	BandSurfaceUrgent = 1 // a critical or high surface finding
	BandRest          = 2 // everything else: EPSS, then CVSS, then severity
)

// SurfaceKeyPrefix starts the AdvisoryID of every surface row; no advisory id
// of any feed starts with it.
const SurfaceKeyPrefix = "surface:"

// SurfaceScore is the CVSS-equivalent a surface finding of this severity ranks
// by when it is not urgent, and whether the severity ranks at all (info does
// not). It exists so the surface and vulnerability orders are one order, not to
// pretend a DMARC policy has a CVSS score; the console never shows it.
func SurfaceScore(severity string) (score float64, ranked bool) {
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5, true
	case "high":
		return 8.0, true
	case "medium":
		return 5.0, true
	case "low":
		return 2.0, true
	}
	return 0, false
}

// Band says which band an item falls into.
func Band(i Item) int {
	if i.Surface {
		switch strings.ToLower(i.Severity) {
		case "critical", "high":
			return BandSurfaceUrgent
		}
		return BandRest
	}
	if i.KEV {
		return BandKEV
	}
	return BandRest
}

// effective is what the order actually compares: a surface finding has no
// exploitation signal and the CVSS-equivalent of its severity.
func effective(i Item) Item {
	if !i.Surface {
		return i
	}
	score, _ := SurfaceScore(i.Severity)
	return Item{AdvisoryID: i.AdvisoryID, Severity: i.Severity, CVSS: &score, Surface: true}
}

// SeverityRank orders the vendor's labels, most severe first; anything else
// is "unknown".
func SeverityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

// Compare orders two items: negative if a ranks before b, positive if after,
// zero only for the same advisory.
func Compare(a, b Item) int {
	if c := Band(a) - Band(b); c != 0 {
		return c
	}
	a, b = effective(a), effective(b)
	if a.KEV && b.KEV {
		if c := cmpDateDesc(a.KEVAdded, b.KEVAdded); c != 0 {
			return c
		}
	}
	if c := cmpScoreDesc(a.EPSS, b.EPSS); c != 0 {
		return c
	}
	if c := cmpScoreDesc(a.CVSS, b.CVSS); c != 0 {
		return c
	}
	if c := SeverityRank(a.Severity) - SeverityRank(b.Severity); c != 0 {
		return c
	}
	return strings.Compare(a.AdvisoryID, b.AdvisoryID)
}

// cmpScoreDesc puts the higher score first and a missing score last.
func cmpScoreDesc(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	case *a > *b:
		return -1
	case *a < *b:
		return 1
	}
	return 0
}

// cmpDateDesc puts the later date first and a missing date last. Dates compare
// by calendar day, as KEV publishes them.
func cmpDateDesc(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	}
	da, db := a.UTC().Truncate(24*time.Hour), b.UTC().Truncate(24*time.Hour)
	switch {
	case da.After(db):
		return -1
	case da.Before(db):
		return 1
	}
	return 0
}
