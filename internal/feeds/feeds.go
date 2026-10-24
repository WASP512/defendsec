// Package feeds holds the neutral record types the feed parsers emit. Each
// parser lives in its own subpackage (kev, epss, ubuntu, debian, rhel, suse,
// osv); none of them touches a database or the network. internal/feeds/sync
// fetches, parses and loads them.
package feeds

import (
	"regexp"
	"strconv"
	"strings"
)

// FixState mirrors storepg.FixState; the strings are the database values.
type FixState string

const (
	Affected           FixState = "affected"
	Fixed              FixState = "fixed"
	WillNotFix         FixState = "will_not_fix"
	NotAffected        FixState = "not_affected"
	UnderInvestigation FixState = "under_investigation"
)

// Range is one affected range for one package.
//
// Empty Distro means "not distro-specific" (upstream ecosystems); empty Release
// with a Distro means "every release". Empty Introduced means "from the first
// version" and empty Fixed means "no fix published". Distro is the os-release
// ID of the target ("ubuntu", "debian", "rhel", "opensuse-leap") and Release is
// its VERSION_ID ("22.04", "12", "9", "16.0"), so a matcher can key straight off
// /etc/os-release.
type Range struct {
	Ecosystem     string
	Distro        string
	Release       string
	Package       string
	SourcePackage string
	Introduced    string
	Fixed         string
	State         FixState
}

// Advisory is one vulnerability (keyed by CVE where a CVE exists) with the
// ranges one feed asserts for it.
type Advisory struct {
	ID         string
	CVE        string
	Summary    string
	Severity   string // critical|high|medium|low|unknown
	CVSSScore  *float64
	CVSSVector string
	CWE        []string
	Ranges     []Range
}

// Stats is what a parser reports about a run. Skipped counts things the feed
// contained that this parser deliberately does not turn into a range, keyed by
// reason, so a silent gap shows up in the sync output.
type Stats struct {
	Advisories int // advisories emitted (one per CVE per definition/record)
	Ranges     int // ranges emitted before de-duplication
	Skipped    map[string]int
}

// Skip records one skipped item.
func (s *Stats) Skip(reason string) {
	if s.Skipped == nil {
		s.Skipped = map[string]int{}
	}
	s.Skipped[reason]++
}

var cveRe = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// IsCVE reports whether s is a well-formed CVE identifier.
func IsCVE(s string) bool { return cveRe.MatchString(s) }

// NormalizeSeverity folds vendor vocabularies into critical|high|medium|low|
// unknown. Unrecognised and empty values become "unknown", never a guess.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "negligible", "unimportant":
		return "low"
	}
	return "unknown"
}

// SeverityRank orders normalised severities, highest first.
func SeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// SplitCVSS splits the "<score>/<vector>" form Red Hat and SUSE use
// ("4.4/CVSS:3.1/AV:L/...") into its parts. ok is false if s has no score.
func SplitCVSS(s string) (score float64, vector string, ok bool) {
	head, rest, found := strings.Cut(strings.TrimSpace(s), "/")
	if !found {
		return 0, "", false
	}
	f, err := strconv.ParseFloat(head, 64)
	if err != nil || f < 0 || f > 10 {
		return 0, "", false
	}
	return f, rest, true
}
