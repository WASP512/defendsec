// Package identity owns user accounts, password verification, second-factor
// codes and session tokens.
//
// It lives in the Go control plane rather than the console because the audit
// ledger lives here and has to reference real user ids. Until this package
// exists, every action is recorded against the string "shared-admin-token" —
// a role, not a person — which makes non-repudiation impossible no matter how
// good the signing path is (roadmap 1.0).
package identity

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, following the second recommended configuration in
// RFC 9106: 64 MiB of memory, one pass, four lanes. Memory hardness is what
// makes offline cracking expensive, so it is preferred over more passes.
//
// The parameters are stored in the hash string rather than assumed, so they
// can be raised later without invalidating existing credentials.
const (
	argonMemoryKiB  = 64 * 1024
	argonTime       = 1
	argonThreads    = 4
	argonKeyLength  = 32
	argonSaltLength = 16
)

// PBKDF2 parameters for the FIPS path. SP 800-132 sets no iteration count, so
// this follows OWASP's current guidance for PBKDF2-HMAC-SHA256. It is a weaker
// defence against offline cracking than Argon2id at any iteration count, which
// is why it is not the default — only the approved one.
const (
	pbkdf2Iterations = 600_000
	pbkdf2KeyLength  = 32
	pbkdf2SaltLength = 16
)

// HashPassword returns a PHC-format hash using whichever algorithm this
// deployment requires. The algorithm is named in the output, so a store can
// hold both and verification does not need to be told which is which.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	if ActiveKDF() == KDFPBKDF2 {
		salt := make([]byte, pbkdf2SaltLength)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("generate salt: %w", err)
		}
		return encodePBKDF2(password, salt, pbkdf2Iterations), nil
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return encodeHash(password, salt, argonMemoryKiB, argonTime, argonThreads), nil
}

func encodePBKDF2(password string, salt []byte, iterations int) string {
	// pbkdf2.Key only errors on a nil hash constructor or a non-positive key
	// length, neither of which can happen here.
	key, _ := pbkdf2.Key(sha256.New, password, salt, iterations, pbkdf2KeyLength)
	return fmt.Sprintf("$pbkdf2-sha256$i=%d$%s$%s", iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// verifyPBKDF2 checks a $pbkdf2-sha256$ hash.
func verifyPBKDF2(password string, parts []string) bool {
	// ["", "pbkdf2-sha256", "i=N", salt, hash]
	if len(parts) != 5 {
		return false
	}
	var iterations int
	if _, err := fmt.Sscanf(parts[2], "i=%d", &iterations); err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether a stored hash uses a different algorithm than
// this deployment now requires. Existing credentials keep working; they are
// upgraded the next time the owner sets a password, because re-hashing needs
// the plaintext and silently forcing a reset would lock people out.
func NeedsRehash(encoded string) bool {
	want := ActiveKDF()
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		return want != KDFArgon2id
	case strings.HasPrefix(encoded, "$pbkdf2-sha256$"):
		return want != KDFPBKDF2
	default:
		return true
	}
}

func encodeHash(password string, salt []byte, memory uint32, time, threads uint8) string {
	key := argon2.IDKey([]byte(password), salt, uint32(time), memory, threads, argonKeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

// VerifyPassword reports whether password matches the stored hash. It compares
// in constant time and returns false rather than an error for a malformed
// hash, so a corrupted record cannot become an authentication bypass.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) < 2 {
		return false
	}
	// Both algorithms are accepted whatever the current mode, so switching a
	// deployment to FIPS does not lock out every existing account.
	if parts[1] == "pbkdf2-sha256" {
		return verifyPBKDF2(password, parts)
	}
	// ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var timeCost, threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false
	}
	if memory == 0 || timeCost == 0 || threads == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, uint32(timeCost), memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHashes are verified against when a login names an account that does
// not exist, so an unknown username costs the same work as a wrong password
// and the response does not leak which accounts are real.
//
// One per algorithm: burning Argon2id time while real verifications run
// PBKDF2 (or the reverse) would reintroduce exactly the timing difference
// this exists to remove. A fixed salt is fine — these are never credentials,
// they only spend the same CPU a real verification would.
var dummyHashes = map[KDF]string{
	KDFArgon2id: encodeHash("defendsec-timing-equalizer",
		make([]byte, argonSaltLength), argonMemoryKiB, argonTime, argonThreads),
	KDFPBKDF2: encodePBKDF2("defendsec-timing-equalizer",
		make([]byte, pbkdf2SaltLength), pbkdf2Iterations),
}

// BurnPasswordComparison performs a verification whose result is discarded.
// Call it on the no-such-user path to keep login timing uniform.
func BurnPasswordComparison(password string) {
	_ = VerifyPassword(password, dummyHashes[ActiveKDF()])
}
