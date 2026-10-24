// Package repohealth answers one question about a host's package repositories:
// can the host's idea of "pending updates" be trusted?
//
// The lesson from a client host (2026-10-22): a repository's signing key had expired, and
// apt kept using the index it had downloaded while the key was valid. apt printed
// one warning, `apt-get update` still succeeded for the other repositories, and
// "no pending updates" was a lie. A scanner that takes pending updates from the
// package manager repeats that lie unless it also asks whether each enabled
// repository is actually being refreshed and verified.
//
// The package has three parts:
//
//   - Evidence (Report, Repo): what the agent read on the host, without changing
//     it. Parsers for apt sources, Release files, gpgv status output, yum/zypp
//     repository files and OpenPGP key expiry live here so they can be tested
//     against fixtures; the file and process access is in internal/hostinv.
//   - Judgement (Assess): evidence plus a clock and a staleness threshold give
//     problems (an expired key, a missing key, a stale index) and a verdict on
//     whether the host's pending-updates list is reliable. The server judges,
//     not the agent, so the threshold is one setting for the whole fleet and a
//     change of it re-judges what the hosts already reported.
//   - Wording: the finding title, explanation and fix text.
package repohealth

import "time"

// Manager names the package manager whose repositories a Report describes.
const (
	ManagerApt    = "apt"
	ManagerDNF    = "dnf" // dnf and yum
	ManagerZypper = "zypper"
)

// Sig is the state of a repository's signature or signing key.
type Sig string

const (
	// SigGood: the index verifies against a trusted, unexpired key.
	SigGood Sig = "good"
	// SigExpiredKey: the signature is by a key that has expired (gpgv
	// EXPKEYSIG), or, for an rpm repository, every key in its gpgkey files has.
	SigExpiredKey Sig = "expired_key"
	// SigNoPubkey: the signing key is not in any keyring the repository's
	// source trusts (gpgv NO_PUBKEY).
	SigNoPubkey Sig = "no_pubkey"
	// SigBad: the signature does not match the index (BADSIG), or it has itself
	// expired (EXPSIG).
	SigBad Sig = "bad_signature"
	// SigRevoked: the signing key has been revoked (REVKEYSIG).
	SigRevoked Sig = "revoked_key"
	// SigUnsigned: the index carries no signature apt would accept.
	SigUnsigned Sig = "unsigned"
	// SigNoIndex: the host holds no index for this enabled repository: apt has
	// no Release file for it (never fetched, or fetched and refused, which an
	// expired or untrusted key causes), or dnf has no cached metadata.
	SigNoIndex Sig = "no_index"
	// SigNotChecked: the repository is configured so that no signature is
	// checked ([trusted=yes], gpgcheck=0): there is nothing to verify.
	SigNotChecked Sig = "not_checked"
	// SigUnverified: the agent could not check (no gpgv, a key it cannot read,
	// a mirror method). Never a finding by itself, but it keeps the host's
	// pending updates from being called reliable.
	SigUnverified Sig = "unverified"
)

// Repo is the evidence about one enabled repository.
type Repo struct {
	// ID identifies the repository on the host and across runs: for apt
	// "<uri> <suite>" (credentials removed), for dnf and zypper the repo id. It
	// is the key of the finding.
	ID    string `json:"id"`
	Label string `json:"label"`
	URI   string `json:"uri,omitempty"`
	// Suite is the apt suite or codename; empty for rpm repositories.
	Suite string `json:"suite,omitempty"`
	// Source is the configuration file that enables the repository.
	Source string `json:"source,omitempty"`

	Signature Sig `json:"signature"`
	// KeyID is the key gpgv named (EXPKEYSIG, NO_PUBKEY, BADSIG), or the rpm key
	// id; Detail is a short human note (the key's user id, why it could not be
	// checked, where the index was verified).
	KeyID  string `json:"keyId,omitempty"`
	Detail string `json:"detail,omitempty"`
	// SignedBy is how the source names its keyring: "signed-by" paths,
	// "trusted.gpg(.d)" for the legacy default, "gpgkey" for rpm. Paths only.
	SignedBy string `json:"signedBy,omitempty"`

	// ReleaseDate and ValidUntil are the Date: and Valid-Until: headers of the
	// apt Release file; zero when there is none.
	ReleaseDate *time.Time `json:"releaseDate,omitempty"`
	ValidUntil  *time.Time `json:"validUntil,omitempty"`
	// IgnoreValidUntil is set when the source says Check-Valid-Until: no.
	IgnoreValidUntil bool `json:"ignoreValidUntil,omitempty"`
	// MetadataTime is when the cached repomd.xml of an rpm repository was
	// fetched or last revalidated (dnf and zypper touch it).
	MetadataTime *time.Time `json:"metadataTime,omitempty"`
	// KeyExpires is, for an rpm repository, when the latest-lived key in its
	// gpgkey files expires (or expired); nil when no key expires or none was
	// readable.
	KeyExpires *time.Time `json:"keyExpires,omitempty"`
}

// Report is what the agent read about the host's repositories. Nothing in it
// was obtained by refreshing, downloading or changing anything.
type Report struct {
	// Manager is "apt", "dnf" or "zypper"; empty means the host's package
	// manager is not one the agent knows, and nothing was assessed.
	Manager string `json:"manager"`
	// LastRefresh is when the host last completed (or, failing that, attempted)
	// a refresh of its indexes, and LastRefreshSource says what that time is:
	// "update-success-stamp" or "lists directory". nil when unknown.
	LastRefresh       *time.Time `json:"lastRefresh,omitempty"`
	LastRefreshSource string     `json:"lastRefreshSource,omitempty"`
	Repos             []Repo     `json:"repos"`
	// Limits are the checks the agent could not make on this host, each one a
	// reason the pending-updates list cannot be called reliable ("gpgv is not
	// installed", "sources.list.d is unreadable").
	Limits []string `json:"limits,omitempty"`
	// Assessment is the server's verdict on this report as of when it was
	// received (see Assess). The agent never sets it. It is stored with the
	// report so the console shows, beside a host's pending updates, whether they
	// can be believed, without judging the evidence a second time.
	Assessment *Assessment `json:"assessment,omitempty"`
	// AssessedAt is when Assessment was made, RFC 3339.
	AssessedAt string `json:"assessedAt,omitempty"`
}

// Empty reports whether the agent assessed anything (an agent older than slice
// 11, or a host without apt/dnf/zypper, sends no report).
func (r Report) Empty() bool { return r.Manager == "" }

// Severities of repository findings.
const (
	SeverityHigh   = "high"
	SeverityMedium = "medium"
)

// DefaultStaleAfter is how old an index may be before it is a finding.
const DefaultStaleAfter = 7 * 24 * time.Hour
