package identity

import (
	"crypto/fips140"
	"os"
	"strings"
)

// FIPS 140-3 posture (roadmap 1.8).
//
// Go 1.24 and later can route the standard library's cryptography through a
// validated module, selected with GODEBUG=fips140=on or =only. What that does
// and does not do was established by probing this codebase rather than by
// reading the release notes, because the difference matters:
//
//   - fips140=on routes stdlib crypto through the validated module. It does
//     NOT reject non-approved algorithms. Argon2id kept working under it,
//     because its Blake2b comes from golang.org/x/crypto and never enters the
//     module boundary at all. So a deployment can believe it is running in
//     FIPS mode while hashing passwords with an algorithm SP 800-132 does not
//     approve, and nothing anywhere reports a problem.
//
//   - fips140=only additionally rejects non-approved use. Under it the whole
//     signing surface — Ed25519 command signatures, ECDSA P-256
//     acknowledgement signatures, SHA-256, the audit chain and its
//     checkpoints — passed unchanged. Only HMAC-SHA1 panicked, because Go's
//     only-mode restricts HMAC to SHA-2 and SHA-3.
//
// So two things need handling, and neither is the signing path:
//
//  1. Password hashing. Argon2id is the better choice against offline
//     cracking and stays the default. SP 800-132 specifies PBKDF2, so a
//     deployment that must be FIPS-validated selects it instead.
//  2. TOTP. HMAC-SHA1 is approved for HMAC under SP 800-131A; Go's only-mode
//     is stricter than the standard requires. Rather than break every
//     authenticator app, the HMAC is computed inside
//     fips140.WithoutEnforcement, which marks the boundary explicitly instead
//     of crashing or silently pretending.

// KDF names the password-hashing algorithm in use.
type KDF string

const (
	// KDFArgon2id is the default. Memory-hard, and the right answer when
	// FIPS validation is not a requirement.
	KDFArgon2id KDF = "argon2id"
	// KDFPBKDF2 is PBKDF2-HMAC-SHA256, the SP 800-132 approved option.
	KDFPBKDF2 KDF = "pbkdf2-sha256"
)

// fipsRequired reports whether this process must restrict itself to
// FIPS-approved algorithms.
//
// Go's own flag is honoured, so a deployment that sets GODEBUG=fips140 gets
// approved password hashing without having to know about a second switch.
// DEFENDSEC_FIPS_MODE exists for the case where the operator is required to
// use approved algorithms but is not running the Go module in FIPS mode.
func fipsRequired() bool {
	if fips140.Enabled() {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("DEFENDSEC_FIPS_MODE"))) {
	case "1", "true", "yes", "on", "only":
		return true
	}
	return false
}

// ActiveKDF is the algorithm new password hashes will use.
func ActiveKDF() KDF {
	if fipsRequired() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

// FIPSStatus describes the cryptographic posture, for the console and for an
// assessor who needs to know what is actually in force rather than what was
// intended.
type FIPSStatus struct {
	// GoModuleEnabled is true when Go routes stdlib crypto through the
	// validated module (GODEBUG=fips140=on or =only).
	GoModuleEnabled bool `json:"goModuleEnabled"`
	// GoModuleEnforced is true under =only, where non-approved use is
	// rejected rather than merely unrouted.
	GoModuleEnforced bool `json:"goModuleEnforced"`
	// ApprovedAlgorithmsRequired is what DefendSec itself acts on.
	ApprovedAlgorithmsRequired bool `json:"approvedAlgorithmsRequired"`
	// PasswordKDF is the algorithm new passwords are hashed with.
	PasswordKDF string `json:"passwordKdf"`
	// Notes records the deviations plainly, so nothing is implied by silence.
	Notes []string `json:"notes"`
}

// Status reports the current posture.
func Status() FIPSStatus {
	st := FIPSStatus{
		GoModuleEnabled:            fips140.Enabled(),
		GoModuleEnforced:           fips140.Enforced(),
		ApprovedAlgorithmsRequired: fipsRequired(),
		PasswordKDF:                string(ActiveKDF()),
	}

	if st.ApprovedAlgorithmsRequired {
		st.Notes = append(st.Notes,
			"Passwords are hashed with PBKDF2-HMAC-SHA256 (SP 800-132). Existing Argon2id hashes still verify, and are re-hashed on the owner's next password change.")
	} else {
		st.Notes = append(st.Notes,
			"Passwords are hashed with Argon2id, which resists offline cracking better than PBKDF2 but is not FIPS-approved. Set DEFENDSEC_FIPS_MODE=1, or run with GODEBUG=fips140=on, where validation is required.")
	}
	st.Notes = append(st.Notes,
		"Second-factor codes use HMAC-SHA1, as every authenticator app expects. HMAC-SHA1 is approved for HMAC under SP 800-131A; Go's fips140=only mode is stricter than the standard, so this one call runs outside enforcement.")
	st.Notes = append(st.Notes,
		"Command signatures (Ed25519), acknowledgement signatures (ECDSA P-256), the audit chain and its checkpoints (SHA-256) all use approved algorithms and were verified to work under GODEBUG=fips140=only.")

	if st.GoModuleEnabled && !st.GoModuleEnforced {
		st.Notes = append(st.Notes,
			"GODEBUG=fips140=on routes standard-library cryptography through the validated module but does not reject non-approved algorithms. Use =only to have them rejected.")
	}
	return st
}
