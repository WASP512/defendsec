// Package lifecycle judges application end-of-life: software whose upstream has
// stopped issuing security fixes, taken from endoflife.date.
//
// One rule decides everything here: origin decides. Software that comes from
// the host's own distribution follows the distribution's support lifecycle
// (the Supported-OS policy and the distro trackers already cover it), so an
// upstream end-of-life date must not raise a finding on it: Ubuntu 22.04 ships
// python3.10 and OpenSSL 3.0, both past upstream end-of-life and both patched
// by Canonical. Only software from a third-party repository, or installed
// outside a package manager, is judged against the upstream lifecycle, because
// nobody else is backporting fixes to it. Software whose origin cannot be told
// is not assessed, never "clean" and never "end of life".
package lifecycle

import (
	"regexp"
	"strings"
)

// Origin classes.
type Origin string

const (
	// OriginDistro: the host's own distribution built and ships this package.
	OriginDistro Origin = "distro"
	// OriginThirdParty: a repository that is not the distribution's (Sury, PGDG,
	// NodeSource, a PPA), or no package manager at all (Windows).
	OriginThirdParty Origin = "third_party"
	// OriginUnknown: the agent could not read where the package came from.
	OriginUnknown Origin = "unknown"
)

// Package managers a host can have; "" is a host with none (Windows).
const (
	ManagerDPKG = "dpkg"
	ManagerRPM  = "rpm"
)

// distroLabels are the apt Origin: and rpm Vendor: strings each distribution
// stamps on its own packages, lower case. A host whose distribution is not in
// the table cannot be told apart from its repositories, so its packages stay
// "unknown" instead of being guessed at.
//
// apt: `apt-cache policy` prints "release o=<Origin>,..." for every source.
// Debian's archive and its security archive both say "Debian"; Ubuntu's
// archive and security pocket both say "Ubuntu", and Ubuntu Pro (ESM) says
// "UbuntuESM" or "UbuntuESMApps". rpm: the Vendor tag of a Rocky package is the
// Rocky Enterprise Software Foundation, of a RHEL package "Red Hat, Inc.".
// EPEL builds say "Fedora Project", which on a Rocky or RHEL host is a third
// party and is treated as one.
var distroLabels = map[string][]string{
	"debian": {"debian"},
	"ubuntu": {"ubuntu", "ubuntuesm", "ubuntuesmapps"},
	// Raspberry Pi OS ships Debian's archive plus its own.
	"raspbian":            {"raspbian", "debian"},
	"rocky":               {"rocky enterprise software foundation", "rocky linux", "rocky"},
	"almalinux":           {"almalinux", "almalinux os foundation"},
	"rhel":                {"red hat, inc.", "red hat"},
	"centos":              {"centos", "red hat, inc."},
	"ol":                  {"oracle america", "oracle"},
	"fedora":              {"fedora project", "fedora"},
	"amzn":                {"amazon linux", "amazon.com", "amazon"},
	"opensuse-leap":       {"suse llc", "suse", "opensuse"},
	"opensuse-tumbleweed": {"suse llc", "suse", "opensuse"},
	"sles":                {"suse llc", "suse"},
}

// KnownDistro reports whether labels are known for the distribution, so a
// package's label can be sorted into "its own" and "somebody else's".
func KnownDistro(distro string) bool {
	_, ok := distroLabels[strings.ToLower(strings.TrimSpace(distro))]
	return ok
}

// OwnLabel reports whether label is one the distribution stamps on its own
// packages. An empty label or an unknown distribution is never "own".
func OwnLabel(distro, label string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return false
	}
	for _, l := range distroLabels[strings.ToLower(strings.TrimSpace(distro))] {
		if label == l {
			return true
		}
	}
	return false
}

// thirdPartyMarkers are version-string signatures of well known third-party
// builds. They are consulted only when the agent could not read the package's
// repository (the installed version is no longer listed in any apt index, or an
// agent predates origin reporting): the strongest evidence, the repository
// itself, always wins.
var thirdPartyMarkers = []struct {
	re    *regexp.Regexp
	label string
}{
	{regexp.MustCompile(`(?i)sury`), "Sury"},
	{regexp.MustCompile(`(?i)nodesource`), "NodeSource"},
	{regexp.MustCompile(`(?i)pgdg`), "PostgreSQL (PGDG)"},
	{regexp.MustCompile(`(?i)\+maria~`), "MariaDB"},
	{regexp.MustCompile(`(?i)\.remi(\.|$)`), "Remi"},
	{regexp.MustCompile(`(?i)1rl1`), "Redis"},
	{regexp.MustCompile(`(?i)\+ppa\d|~ppa\d|ppa\d+~`), "PPA"},
}

// ClassifyOrigin sorts one package into distro, third party or unknown.
//
// distro is the os-release ID of the host ("" on a host without one), manager
// its package manager, label and repo what the agent read: the apt Origin: (or
// rpm Vendor) and the repository it came from. A host with no package manager
// (Windows) has no distribution to be "own" of: everything on it was installed
// by hand, so it is third party.
func ClassifyOrigin(distro, manager, version, label, repo string) (Origin, string) {
	label, repo = strings.TrimSpace(label), strings.TrimSpace(repo)
	if manager == "" && strings.TrimSpace(distro) == "" {
		return OriginThirdParty, "installed outside a package manager"
	}
	if label != "" {
		if !KnownDistro(distro) {
			return OriginUnknown, label
		}
		if OwnLabel(distro, label) {
			return OriginDistro, label
		}
		return OriginThirdParty, label
	}
	for _, m := range thirdPartyMarkers {
		if m.re.MatchString(version) {
			return OriginThirdParty, m.label
		}
	}
	return OriginUnknown, ""
}
