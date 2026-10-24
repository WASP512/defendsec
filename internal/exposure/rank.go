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
//  2. The urgent band, after KEV: external surface findings of critical or
//     high severity (slice 7b), identity findings of critical or high severity
//     (slice 12: an administrator with no MFA, a rule forwarding a mailbox
//     outside), a reachable SMB port, a certificate that has
//     expired, an SPF record that lets anyone send as the domain; software
//     past the end of its security support (slice 10), a PHP 8.0 from a third
//     party repository that no one patches any more; and a package repository
//     whose signing key has expired or is missing (slice 11), from which the
//     host has silently stopped receiving updates. See "Surface findings",
//     "End-of-life findings" and "Repository-health findings" below.
//  3. EPSS, highest first: the probability of exploitation in the next 30 days.
//     No score goes last.
//  4. CVSS base score, highest first. No score goes last.
//  5. The vendor's severity label (critical, high, medium, low, unknown), so
//     rows with no scores at all still order sensibly.
//  6. The kind of row (TieRank): a vulnerability, then end-of-life software, then
//     a repository, then an identity finding, then an external surface finding.
//  7. Advisory id, bytewise, so the order is total and a keyset cursor is stable.
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
//
// # Identity findings
//
// A finding of the identity source (slice 12: Microsoft 365, and Google
// Workspace after it) is a condition of a client's own tenant: an account with
// no second factor, an inbox rule that forwards mail outside or hides it. Like a
// surface finding it has no KEV flag, no EPSS and no CVSS, and it ranks by
// severity under exactly the surface rules: critical and high are in effect now
// (an intruder with a password needs no exploit) and rank right after KEV and
// before every vulnerability that is not on KEV; medium and low rank like a
// vulnerability with no EPSS and the CVSS-equivalent of their severity
// (SurfaceScore). Missing evidence never ranks: a check that could not run
// produces no finding.
//
// # End-of-life findings
//
// A finding of kind eol (slice 10) is software from outside the distribution
// whose upstream has stopped supporting the release. It has no CVE, no KEV flag,
// no EPSS and no CVSS, and, unlike a vulnerability, nothing will ever fix it but
// an upgrade: leaving it at the bottom with the unscored would hide the risk. It
// enters the order at the level of a high vulnerability, the way a surface
// finding does:
//
//   - Past end of security support (stage "eol", severity high): the urgent
//     band, after KEV, together with the critical and high surface findings and
//     before every vulnerability that is not on KEV, whatever its EPSS. Inside
//     the band the CVSS-equivalent of high (8.0) puts it after a critical surface
//     finding, and the severity label then the row id break ties with a high
//     surface finding. The price is the same as for surface findings: a non-KEV
//     CVE with a very high EPSS ranks below an unpatched EOL release; revisit it
//     with real data.
//   - Past end of active support only (stage "eoas", severity low): security
//     fixes still arrive, so there is nothing to do this week that outranks an
//     exploited or scored vulnerability. It has no EPSS and the CVSS-equivalent
//     of low (2.0): the rest band, after every vulnerability with an EPSS score,
//     with the CVSS-only ones, below the security-EOL findings.
//
// # Repository-health findings
//
// A finding of kind repo_health (slice 11) is a package repository on a host
// whose signing key has expired or is missing (severity high), whose index is
// expired or has gone stale (medium), or for which the host holds no index. It
// has no KEV flag, no EPSS and no CVSS, and it is not itself exploited: it is
// the reason nothing the repository publishes is being installed or matched.
// It ranks the way a surface finding of the same severity does, by the
// CVSS-equivalent of its severity (SurfaceScore):
//
//   - High: the urgent band, after KEV, with the critical and high surface
//     findings and the security-EOL ones, before every vulnerability that is not
//     on KEV. The reasoning is the lesson from a client host: a dead repository hides the
//     vulnerabilities it would have fixed, so leaving this at the bottom of a
//     list of scored CVEs puts the cause below the symptoms. The price is the
//     one the other urgent rows pay: a non-KEV CVE with a very high EPSS ranks
//     below it; revisit it with real data.
//   - Medium (a stale index): the rest band as a vulnerability with no EPSS and
//     a CVSS of 5.0.
//
// # Tie-break
//
// Two rows that agree on the band, the KEV date, EPSS, the CVSS-equivalent and
// the severity label are ordered by the kind of row, then by id. The kind order
// is a stated rule, not a by-product of how the ids happen to sort (it used to be
// the id's bytes: "EOL:" before "REPO:" before "identity:" before "surface:",
// which put a lowercase advisory id anywhere). It is, first to last:
//
//  0. a vulnerability: a vendor-confirmed advisory with a fix path;
//  1. software past its end of life: no one will ever patch it;
//  2. a package repository that has stopped delivering updates;
//  3. an identity finding (a client's tenant);
//  4. an external surface finding.
//
// So in the urgent band, at 8.0 and high, an end-of-life release comes first, then
// a dead repository, then an identity finding, then an exposed surface finding;
// and in the rest band a CVSS-only vulnerability of 5.0 comes before a stale
// repository or DMARC p=none of the same 5.0. Among rows of one kind the id
// decides, bytewise (a surface or identity id carries its zero-padded finding id,
// so the older finding is first). The same rule is k6 in the SQL of
// internal/storepg (a digit and the id, collated "C") and tieRank in
// lib/exposure-model.ts; each is tested against this one with a row of every kind.
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
	// Identity marks an identity finding (slice 12). Like Surface, its KEV,
	// EPSS and CVSS are ignored: it ranks by Severity under the same rules.
	Identity bool
	// EOLStage is "eol" or "eoas" on an end-of-life finding and empty on every
	// other. Its KEV, EPSS and CVSS are ignored: it ranks by stage under the
	// end-of-life rules above.
	EOLStage string
	// RepoHealth marks a repository-health finding. Its KEV, EPSS and CVSS are
	// ignored: it ranks by Severity under the repository-health rules above,
	// which are the surface rules.
	RepoHealth bool
}

// The bands an item falls into; a lower band ranks first.
const (
	BandKEV    = 0 // a vulnerability on the CISA KEV list
	BandUrgent = 1 // a critical or high surface finding, or software past end of security support
	BandRest   = 2 // everything else: EPSS, then CVSS, then severity
)

// The two stages of an end-of-life finding.
const (
	EOLStageEOL  = "eol"  // security support ended
	EOLStageEOAS = "eoas" // active support ended; security fixes continue
)

// EOLScore is the CVSS-equivalent an end-of-life finding ranks by: that of a
// high vulnerability past end of security support, of a low one past end of
// active support. Like SurfaceScore it makes one order of the two kinds of row;
// the console never shows it. Any other stage does not rank.
func EOLScore(stage string) (score float64, ranked bool) {
	switch stage {
	case EOLStageEOL:
		return 8.0, true
	case EOLStageEOAS:
		return 2.0, true
	}
	return 0, false
}

// SurfaceKeyPrefix starts the AdvisoryID of every surface row; no advisory id
// of any feed starts with it.
const SurfaceKeyPrefix = "surface:"

// RepoKeyPrefix starts the AdvisoryID of every repository-health row.
const RepoKeyPrefix = "REPO:"

// IdentityKeyPrefix starts the AdvisoryID of every identity row (the zero-padded
// finding id follows); like SurfaceKeyPrefix, no advisory id starts with it.
const IdentityKeyPrefix = "identity:"

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
	if i.Surface || i.Identity || i.RepoHealth {
		switch strings.ToLower(i.Severity) {
		case "critical", "high":
			return BandUrgent
		}
		return BandRest
	}
	if _, eol := EOLScore(i.EOLStage); eol {
		if i.EOLStage == EOLStageEOL {
			return BandUrgent
		}
		return BandRest
	}
	if i.KEV {
		return BandKEV
	}
	return BandRest
}

// effective is what the order actually compares: a surface or end-of-life
// finding has no exploitation signal and the CVSS-equivalent of its severity or
// stage.
func effective(i Item) Item {
	if i.Surface || i.Identity || i.RepoHealth {
		score, _ := SurfaceScore(i.Severity)
		return Item{AdvisoryID: i.AdvisoryID, Severity: i.Severity, CVSS: &score, Surface: i.Surface, Identity: i.Identity, RepoHealth: i.RepoHealth}
	}
	if score, ok := EOLScore(i.EOLStage); ok {
		return Item{AdvisoryID: i.AdvisoryID, Severity: i.Severity, CVSS: &score, EOLStage: i.EOLStage}
	}
	return i
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
	if c := TieRank(a) - TieRank(b); c != 0 {
		return c
	}
	return strings.Compare(a.AdvisoryID, b.AdvisoryID)
}

// The kinds of row, in the order they win a tie (see the package comment).
const (
	TieVulnerability = 0
	TieEOL           = 1
	TieRepository    = 2
	TieIdentity      = 3
	TieSurface       = 4
)

// TieRank is the kind of row, which orders two rows that tie on everything the
// ranking measures. The checks are in the order Band and effective use, so a row
// is the kind they treat it as.
func TieRank(i Item) int {
	switch {
	case i.Surface:
		return TieSurface
	case i.Identity:
		return TieIdentity
	case i.RepoHealth:
		return TieRepository
	}
	if _, eol := EOLScore(i.EOLStage); eol {
		return TieEOL
	}
	return TieVulnerability
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
