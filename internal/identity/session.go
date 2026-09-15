package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Roles. Admin may mutate; viewer may only read. These mirror the two tokens
// the console used before per-user accounts existed.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// ValidRole reports whether role is one this system recognises.
func ValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleViewer:
		return true
	default:
		return false
	}
}

// SessionTTL is how long a session stays valid without re-authentication.
// The shared-token cookie previously lasted 14 days; a real session that
// carries a named identity and admin authority should not.
const SessionTTL = 12 * time.Hour

// sessionTokenBytes is the entropy in a session token. 256 bits leaves
// guessing out of the question.
const sessionTokenBytes = 32

// User is an account. PasswordHash and TOTPSecret never leave the control
// plane; the JSON tags exist only for internal admin-API responses that
// deliberately omit them.
type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName,omitempty"`
	Role        string    `json:"role"`
	Disabled    bool      `json:"disabled,omitempty"`
	TOTPEnabled bool      `json:"totpEnabled"`
	CreatedAt   time.Time `json:"createdAt"`
	LastLoginAt time.Time `json:"lastLoginAt,omitempty"`

	PasswordHash    string `json:"-"`
	TOTPSecret      string `json:"-"`
	TOTPLastCounter int64  `json:"-"`
	FailedAttempts  int    `json:"-"`
	LockedUntil     time.Time
}

// Locked reports whether the account is currently barred from logging in.
func (u User) Locked(now time.Time) bool {
	return !u.LockedUntil.IsZero() && now.Before(u.LockedUntil)
}

// Lockout policy. Failed attempts are counted per account and cleared on a
// successful login. This is deliberately account-scoped rather than
// IP-scoped: the console already rate-limits by source, and an attacker
// spreading a password-spray across addresses is the case that needs
// catching here.
const (
	MaxFailedAttempts = 8
	LockoutDuration   = 15 * time.Minute
)

// NewSessionToken returns a token to hand the browser, and the hash to store.
//
// Only the hash is persisted. A read of the sessions table then yields
// nothing usable — which matters because the threat model this whole phase is
// built around includes someone with database access.
func NewSessionToken() (token, hash string, err error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, HashSessionToken(token), nil
}

// HashSessionToken derives the stored form of a session token.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Session is an authenticated browser session.
type Session struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	// Attributed is false for a session created from the bootstrap shared
	// token rather than a named account. Actions taken under one cannot be
	// traced to a person, and the ledger must say so rather than implying an
	// attribution it does not have.
	Attributed bool
}

// Expired reports whether the session is past its lifetime.
func (s Session) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
}

// ActorIdentity is the string recorded in the audit ledger and on signed
// commands. It names the person where one is known, and says plainly when one
// is not, so a reader never has to guess whether attribution is real.
func ActorIdentity(u *User, attributed bool) string {
	if u == nil || !attributed {
		return "unattributed:shared-bootstrap-token"
	}
	return "user:" + u.Username
}

// NormalizeUsername lowercases and trims, so usernames are unique
// case-insensitively and cannot be shadowed by a differently-cased twin.
func NormalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// ValidUsername enforces a conservative character set. Usernames end up in
// audit records and evidence bundles, so they stay to characters that cannot
// be confused with structure in those formats.
func ValidUsername(name string) error {
	if len(name) < 2 || len(name) > 64 {
		return fmt.Errorf("username must be between 2 and 64 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '@':
		default:
			return fmt.Errorf("username may only contain lowercase letters, digits, and . - _ @")
		}
	}
	return nil
}

// MinPasswordLength is the floor. Length is the only property worth enforcing
// mechanically; composition rules push people toward predictable substitutions
// without adding real entropy, and NIST SP 800-63B advises against them.
const MinPasswordLength = 12

// ValidPassword checks the password policy.
func ValidPassword(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > 1024 {
		// Bounded so a very long input cannot be used to burn CPU in argon2.
		return fmt.Errorf("password must be at most 1024 bytes")
	}
	return nil
}
