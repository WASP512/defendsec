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
//  2. EPSS, highest first: the probability of exploitation in the next 30 days.
//     No score goes last.
//  3. CVSS base score, highest first. No score goes last.
//  4. The vendor's severity label (critical, high, medium, low, unknown), so
//     rows with no scores at all still order sensibly.
//  5. Advisory id, so the order is total and a keyset cursor is stable.
//
// EPSS and CVSS order the KEV group too, after the date. CVSS is last among the
// scores on purpose: severity says what could happen, EPSS and KEV say what is
// happening.
package exposure

import (
	"strings"
	"time"
)

// Item is what the ranking looks at.
type Item struct {
	AdvisoryID string
	Severity   string
	KEV        bool
	// KEVAdded is the date the advisory entered the KEV catalog; meaningful
	// only when KEV is true.
	KEVAdded *time.Time
	EPSS     *float64
	CVSS     *float64
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
	if c := cmpBool(a.KEV, b.KEV); c != 0 {
		return c
	}
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

// cmpBool puts true first.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	}
	return 1
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
