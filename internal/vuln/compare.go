package vuln

import "strings"

// Scheme selects the version-ordering rules to apply.
type Scheme int

const (
	// SchemeAuto guesses from the shape of the version strings. It is a
	// fallback: the reliable source is the host's package manager, which the
	// agent already determines. Plumbing that through the inventory report is
	// part of the advisory data-model work (roadmap 0.4).
	SchemeAuto Scheme = iota
	SchemeDpkg
	SchemeRPM
)

// rpmReleaseMarkers are distro tags that only ever appear in an RPM release.
var rpmReleaseMarkers = []string{
	".el", ".fc", ".amzn", ".sles", ".suse", ".oe", ".ky", ".ocs", ".rocky", ".alma",
}

// dpkgRevisionMarkers are substrings that only ever appear in a Debian or
// Ubuntu revision.
var dpkgRevisionMarkers = []string{"ubuntu", "deb", "+really", "~bpo", "build"}

// DetectScheme makes a best-effort guess at the packaging scheme. When nothing
// distinctive is present it returns SchemeDpkg, whose ordering agrees with RPM
// on plain dotted-numeric versions.
func DetectScheme(versions ...string) Scheme {
	for _, v := range versions {
		lower := strings.ToLower(v)
		for _, m := range rpmReleaseMarkers {
			if strings.Contains(lower, m) {
				return SchemeRPM
			}
		}
	}
	for _, v := range versions {
		lower := strings.ToLower(v)
		for _, m := range dpkgRevisionMarkers {
			if strings.Contains(lower, m) {
				return SchemeDpkg
			}
		}
	}
	return SchemeDpkg
}

// Compare orders two versions under the given scheme, returning -1, 0 or 1.
func Compare(a, b string, scheme Scheme) int {
	switch scheme {
	case SchemeRPM:
		return CompareRPM(a, b)
	case SchemeDpkg:
		return CompareDpkg(a, b)
	default:
		return Compare(a, b, DetectScheme(a, b))
	}
}

// Verdict is the outcome of comparing an installed version against an advisory
// floor. It is deliberately three-valued: reporting a distro-packaged build as
// vulnerable because its upstream version sits below an upstream floor is the
// dominant false-positive source on Linux, and guessing is worse than saying so.
type Verdict int

const (
	// VerdictUnknown means the comparison cannot be made safely, almost always
	// because a distro-packaged build may carry a backported fix that leaves
	// the upstream version untouched. Resolving these needs a distro security
	// feed keyed on (distro, release, source package, CVE) — roadmap 0.3.
	VerdictUnknown Verdict = iota
	VerdictVulnerable
	VerdictNotVulnerable
)

func (v Verdict) String() string {
	switch v {
	case VerdictVulnerable:
		return "vulnerable"
	case VerdictNotVulnerable:
		return "not-vulnerable"
	default:
		return "unknown"
	}
}

// Assessment carries a verdict and the reason behind it, so the console can
// explain why something was or was not flagged.
type Assessment struct {
	Verdict Verdict
	Reason  string
}

// hasDistroRevision reports whether a version carries a distro revision or
// release field, which is where Debian, Ubuntu and the RHEL family record
// backported security fixes without moving the upstream version.
func hasDistroRevision(version string, scheme Scheme) bool {
	if scheme == SchemeRPM {
		return ParseRPM(version).HasRelease()
	}
	return ParseDpkg(version).HasRevision()
}

// upstreamOf returns the version with its distro revision stripped.
func upstreamOf(version string, scheme Scheme) string {
	if scheme == SchemeRPM {
		return ParseRPM(version).Version
	}
	return ParseDpkg(version).Upstream
}

// Assess reports whether an installed version sits below an advisory floor.
//
// The floor is assumed to be an upstream version, which is what OSV, NVD and
// the CVE record publish. When the installed build is distro-packaged and its
// upstream version is below that floor, the answer is genuinely unknown: the
// distro may have backported the fix. Ubuntu 22.04 shipped the fix for
// CVE-2024-6387 in openssh 1:8.9p1-3ubuntu0.10 without ever moving to 9.8p1,
// so a version comparison alone cannot tell a patched host from an exposed one.
func Assess(installed, floor string, scheme Scheme) Assessment {
	installed = strings.TrimSpace(installed)
	floor = strings.TrimSpace(floor)
	if installed == "" || floor == "" {
		return Assessment{VerdictUnknown, "missing version or advisory floor"}
	}
	if scheme == SchemeAuto {
		scheme = DetectScheme(installed, floor)
	}

	// Compare upstream to upstream. The floor carries no distro revision, so
	// including the installed one would compare unlike things.
	upstreamCmp := Compare(upstreamOf(installed, scheme), upstreamOf(floor, scheme), scheme)
	if upstreamCmp >= 0 {
		return Assessment{VerdictNotVulnerable, "installed version is at or above the advisory floor"}
	}

	if hasDistroRevision(installed, scheme) && !hasDistroRevision(floor, scheme) {
		return Assessment{
			VerdictUnknown,
			"distro-packaged build below an upstream floor; a backported fix cannot be ruled out without a distro security feed",
		}
	}

	return Assessment{VerdictVulnerable, "installed version is below the advisory floor"}
}
