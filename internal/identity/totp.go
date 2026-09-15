package identity

import (
	"crypto/fips140"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
)

// Time-based one-time passwords, RFC 6238 over RFC 4226.
//
// Implemented here rather than taken as a dependency: the algorithm is small
// and fully specified, and the part that actually matters for security — a
// used code never being accepted again — has to be enforced against stored
// per-user state, which no library can do on its own.
//
// HMAC-SHA1 is the default every authenticator app implements. SHA-1 is broken
// for collision resistance, which HMAC does not rely on, and HMAC-SHA1 remains
// an approved construction; changing it would break Google Authenticator,
// Aegis, 1Password and the rest for no security gain.

const (
	// TOTPPeriod is the step width in seconds.
	TOTPPeriod = 30
	// TOTPDigits is the code length.
	TOTPDigits = 6
	// TOTPSkewSteps is how many steps either side of now are accepted, to
	// tolerate clock drift between the server and the phone. One step each
	// way gives a 90-second window in total; more would widen the window an
	// attacker has to use an intercepted code.
	TOTPSkewSteps = 1

	totpSecretBytes = 20 // 160 bits, the RFC 4226 recommendation
)

// NewTOTPSecret returns a base32 secret suitable for an authenticator app.
func NewTOTPSecret() (string, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPCounter is the step number for a Unix time.
func TOTPCounter(unixSeconds int64) int64 {
	return unixSeconds / TOTPPeriod
}

// totpCode computes the code for a specific counter.
func totpCode(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", fmt.Errorf("decode totp secret: %w", err)
	}
	if len(key) == 0 {
		return "", fmt.Errorf("empty totp secret")
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	// Go's fips140=only mode rejects HMAC over anything but SHA-2 and SHA-3,
	// and panics rather than returning an error. HMAC-SHA1 is approved for
	// HMAC under SP 800-131A, so only-mode is stricter than the standard
	// requires — and changing the digest would break every authenticator app
	// for no security gain. The call is made outside enforcement, which marks
	// the boundary explicitly rather than crashing the process or quietly
	// pretending the deviation does not exist. See internal/identity/fips.go.
	var sum []byte
	fips140.WithoutEnforcement(func() {
		mac := hmac.New(sha1.New, key)
		mac.Write(buf[:])
		sum = mac.Sum(nil)
	})

	// Dynamic truncation, RFC 4226 section 5.3.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, value%mod), nil
}

// TOTPCodeAt returns the code a correctly-configured authenticator would show
// at the given time. Exported for enrollment confirmation and tests.
func TOTPCodeAt(secret string, unixSeconds int64) (string, error) {
	return totpCode(secret, TOTPCounter(unixSeconds))
}

// TOTPResult carries the outcome of a verification. Counter is the step the
// code matched, which the caller must persist so the same code cannot be
// presented twice.
type TOTPResult struct {
	Valid   bool
	Counter int64
}

// VerifyTOTP checks a submitted code against the secret.
//
// lastUsedCounter is the highest step this account has already consumed; any
// match at or below it is rejected. Without that check a TOTP is a 30-second
// reusable password, and an attacker who observes one code — over the
// operator's shoulder, in a phished form, from a logged request — can replay
// it for the rest of the window.
func VerifyTOTP(secret, code string, nowUnix, lastUsedCounter int64) TOTPResult {
	code = strings.TrimSpace(code)
	if secret == "" || len(code) != TOTPDigits {
		return TOTPResult{}
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return TOTPResult{}
		}
	}

	current := TOTPCounter(nowUnix)
	// Walk newest first so a code valid at more than one step (which cannot
	// normally happen) consumes the highest.
	for offset := int64(TOTPSkewSteps); offset >= -TOTPSkewSteps; offset-- {
		counter := current + offset
		if counter <= lastUsedCounter {
			// Already spent, or older than something already spent.
			continue
		}
		want, err := totpCode(secret, counter)
		if err != nil {
			return TOTPResult{}
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(want)) == 1 {
			return TOTPResult{Valid: true, Counter: counter}
		}
	}
	return TOTPResult{}
}

// TOTPEnrollmentURI builds the otpauth:// URI an authenticator app scans.
func TOTPEnrollmentURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	q.Set("period", fmt.Sprintf("%d", TOTPPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
