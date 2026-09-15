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
	"crypto/rand"
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

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return encodeHash(password, salt, argonMemoryKiB, argonTime, argonThreads), nil
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

// dummyHash is verified against when a login names an account that does not
// exist, so an unknown username costs the same work as a wrong password and
// the response does not leak which accounts are real.
var dummyHash = func() string {
	salt := make([]byte, argonSaltLength)
	// A fixed salt is fine: this hash is never a credential, it only burns
	// the same CPU a real verification would.
	return encodeHash("defendsec-timing-equalizer", salt, argonMemoryKiB, argonTime, argonThreads)
}()

// BurnPasswordComparison performs a verification whose result is discarded.
// Call it on the no-such-user path to keep login timing uniform.
func BurnPasswordComparison(password string) {
	_ = VerifyPassword(password, dummyHash)
}
