package identity

import (
	"strings"
	"testing"
	"time"
)

// --- passwords -----------------------------------------------------------

func TestHashAndVerifyPassword(t *testing.T) {
	const pw = "correct horse battery staple"
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if strings.Contains(hash, pw) {
		t.Fatal("hash must not contain the password")
	}
	if !VerifyPassword(pw, hash) {
		t.Fatal("the correct password must verify")
	}
	if VerifyPassword(pw+"x", hash) {
		t.Fatal("a wrong password must not verify")
	}
	if VerifyPassword("", hash) {
		t.Fatal("an empty password must not verify")
	}
}

func TestHashesAreSaltedPerCall(t *testing.T) {
	a, err := HashPassword("same password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("same password")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("identical passwords must not produce identical hashes")
	}
	if !VerifyPassword("same password", a) || !VerifyPassword("same password", b) {
		t.Fatal("both hashes must verify")
	}
}

// A malformed or truncated hash must never be treated as a match. This is the
// classic authentication bypass: a corrupted row that compares equal to
// anything.
func TestVerifyPasswordRejectsMalformedHashes(t *testing.T) {
	good, err := HashPassword("a real password here")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(good, "$")

	cases := map[string]string{
		"empty":            "",
		"not a hash":       "hunter2",
		"bcrypt":           "$2y$10$abcdefghijklmnopqrstuv",
		"wrong algorithm":  "$argon2i$v=19$m=65536,t=1,p=4$c2FsdA$aGFzaA",
		"wrong version":    "$argon2id$v=18$m=65536,t=1,p=4$c2FsdA$aGFzaA",
		"no params":        "$argon2id$v=19$$c2FsdA$aGFzaA",
		"zero memory":      "$argon2id$v=19$m=0,t=1,p=4$c2FsdA$aGFzaA",
		"zero time":        "$argon2id$v=19$m=65536,t=0,p=4$c2FsdA$aGFzaA",
		"zero threads":     "$argon2id$v=19$m=65536,t=1,p=0$c2FsdA$aGFzaA",
		"empty salt":       "$argon2id$v=19$m=65536,t=1,p=4$$aGFzaA",
		"empty hash":       "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$",
		"bad base64 salt":  "$argon2id$v=19$m=65536,t=1,p=4$!!!!$aGFzaA",
		"bad base64 hash":  "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$!!!!",
		"truncated fields": strings.Join(parts[:4], "$"),
		"extra fields":     good + "$extra",
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			if VerifyPassword("a real password here", encoded) {
				t.Error("a malformed hash must not verify")
			}
			if VerifyPassword("anything at all", encoded) {
				t.Error("a malformed hash must not verify against arbitrary input")
			}
		})
	}
}

// Parameters live in the hash, so raising them later must not invalidate
// credentials already stored under the old cost.
func TestVerifyPasswordHonoursStoredParameters(t *testing.T) {
	salt := make([]byte, argonSaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}
	weaker := encodeHash("legacy password ok", salt, 8*1024, 1, 1)
	if !VerifyPassword("legacy password ok", weaker) {
		t.Fatal("a hash stored with lower cost parameters must still verify")
	}
	if VerifyPassword("wrong", weaker) {
		t.Fatal("a wrong password must not verify at any cost")
	}
}

func TestHashPasswordRejectsEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("an empty password must be rejected at hashing time")
	}
}

func TestBurnPasswordComparisonDoesNotPanic(t *testing.T) {
	BurnPasswordComparison("")
	BurnPasswordComparison("whatever was submitted")
}

// --- TOTP ----------------------------------------------------------------

func TestTOTPCodeMatchesAuthenticator(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 15, 17, 30, 0, 0, time.UTC).Unix()
	code, err := TOTPCodeAt(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != TOTPDigits {
		t.Fatalf("code %q is not %d digits", code, TOTPDigits)
	}
	if got := VerifyTOTP(secret, code, now, 0); !got.Valid {
		t.Fatal("a freshly generated code must verify")
	}
	// Same step, same code.
	again, _ := TOTPCodeAt(secret, now+TOTPPeriod-1)
	if again != code {
		t.Error("codes must be stable within a step")
	}
	// Next step, different code.
	next, _ := TOTPCodeAt(secret, now+TOTPPeriod)
	if next == code {
		t.Error("codes must change between steps")
	}
}

// The property that makes TOTP a second factor rather than a 30-second
// reusable password. An observed code must be spent.
func TestVerifyTOTPRejectsReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 15, 17, 30, 0, 0, time.UTC).Unix()
	code, _ := TOTPCodeAt(secret, now)

	first := VerifyTOTP(secret, code, now, 0)
	if !first.Valid {
		t.Fatal("first use must succeed")
	}
	if first.Counter != TOTPCounter(now) {
		t.Fatalf("counter = %d, want %d", first.Counter, TOTPCounter(now))
	}

	// Presenting it again, with the counter the caller is expected to have
	// stored, must fail — even though the code is still within its window.
	if again := VerifyTOTP(secret, code, now, first.Counter); again.Valid {
		t.Fatal("a spent code must not be accepted a second time")
	}
	if again := VerifyTOTP(secret, code, now+5, first.Counter); again.Valid {
		t.Fatal("a spent code must not be accepted later in the same window")
	}
}

// An older code must not be accepted after a newer one has been used, or an
// attacker holding a stale code could still spend it.
func TestVerifyTOTPRejectsCodesOlderThanLastUsed(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Date(2026, 9, 15, 17, 30, 0, 0, time.UTC).Unix()
	older, _ := TOTPCodeAt(secret, now-TOTPPeriod)
	current := TOTPCounter(now)

	if r := VerifyTOTP(secret, older, now, current); r.Valid {
		t.Fatal("a previous step's code must not be accepted once the current step is spent")
	}
}

func TestVerifyTOTPToleratesClockSkew(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Date(2026, 9, 15, 17, 30, 0, 0, time.UTC).Unix()

	behind, _ := TOTPCodeAt(secret, now-TOTPPeriod)
	if r := VerifyTOTP(secret, behind, now, 0); !r.Valid {
		t.Error("a code one step behind must be accepted")
	}
	ahead, _ := TOTPCodeAt(secret, now+TOTPPeriod)
	if r := VerifyTOTP(secret, ahead, now, 0); !r.Valid {
		t.Error("a code one step ahead must be accepted")
	}

	// Beyond the skew window it must not be.
	tooOld, _ := TOTPCodeAt(secret, now-(TOTPSkewSteps+1)*TOTPPeriod)
	if r := VerifyTOTP(secret, tooOld, now, 0); r.Valid {
		t.Error("a code beyond the skew window must be rejected")
	}
	tooNew, _ := TOTPCodeAt(secret, now+(TOTPSkewSteps+2)*TOTPPeriod)
	if r := VerifyTOTP(secret, tooNew, now, 0); r.Valid {
		t.Error("a code beyond the skew window must be rejected")
	}
}

func TestVerifyTOTPRejectsMalformedInput(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Now().Unix()
	for name, code := range map[string]string{
		"empty":       "",
		"too short":   "12345",
		"too long":    "1234567",
		"letters":     "12a456",
		"whitespace":  "12 456",
		"unicode":     "１２３４５６",
		"sql-ish":     "' or 1",
		"all zeroes*": "000000", // valid shape, but must only pass if it is the real code
	} {
		t.Run(name, func(t *testing.T) {
			r := VerifyTOTP(secret, code, now, 0)
			if r.Valid {
				real, _ := TOTPCodeAt(secret, now)
				if code != real {
					t.Errorf("malformed code %q must not verify", code)
				}
			}
		})
	}
	// An empty secret must never verify anything, including a well-formed code.
	if r := VerifyTOTP("", "123456", now, 0); r.Valid {
		t.Error("an empty secret must not verify")
	}
	if r := VerifyTOTP("not!base32!", "123456", now, 0); r.Valid {
		t.Error("an undecodable secret must not verify")
	}
}

func TestTOTPSecretsAreDistinctAndDecodable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		s, err := NewTOTPSecret()
		if err != nil {
			t.Fatal(err)
		}
		if seen[s] {
			t.Fatal("secrets must not repeat")
		}
		seen[s] = true
		if _, err := TOTPCodeAt(s, 0); err != nil {
			t.Fatalf("generated secret must be usable: %v", err)
		}
	}
}

func TestTOTPEnrollmentURI(t *testing.T) {
	uri := TOTPEnrollmentURI("DefendSec", "alice", "ABCDEFGHIJKLMNOP")
	for _, want := range []string{
		"otpauth://totp/", "secret=ABCDEFGHIJKLMNOP", "issuer=DefendSec",
		"digits=6", "period=30", "algorithm=SHA1",
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("enrollment URI missing %q: %s", want, uri)
		}
	}
}

// --- sessions ------------------------------------------------------------

func TestSessionTokensAreRandomAndStoredHashed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		token, hash, err := NewSessionToken()
		if err != nil {
			t.Fatal(err)
		}
		if seen[token] {
			t.Fatal("session tokens must not repeat")
		}
		seen[token] = true
		if token == hash {
			t.Fatal("the stored value must not be the token itself")
		}
		if strings.Contains(hash, token) {
			t.Fatal("the stored hash must not contain the token")
		}
		if hash != HashSessionToken(token) {
			t.Fatal("hashing must be deterministic")
		}
	}
	// A database read yields hashes; those must not be usable as tokens.
	token, hash, _ := NewSessionToken()
	if HashSessionToken(hash) == hash {
		t.Fatal("a stored hash must not authenticate as its own token")
	}
	_ = token
}

func TestSessionExpiry(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	s := Session{CreatedAt: now, ExpiresAt: now.Add(SessionTTL)}
	if s.Expired(now) {
		t.Error("a fresh session must not be expired")
	}
	if s.Expired(now.Add(SessionTTL - time.Minute)) {
		t.Error("a session inside its TTL must not be expired")
	}
	if !s.Expired(now.Add(SessionTTL + time.Second)) {
		t.Error("a session past its TTL must be expired")
	}
}

func TestUserLockout(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	var u User
	if u.Locked(now) {
		t.Error("an account with no lockout must not be locked")
	}
	u.LockedUntil = now.Add(LockoutDuration)
	if !u.Locked(now) {
		t.Error("an account within its lockout must be locked")
	}
	if u.Locked(now.Add(LockoutDuration + time.Second)) {
		t.Error("a lockout must expire")
	}
}

// The ledger must never imply an attribution it does not have.
func TestActorIdentity(t *testing.T) {
	u := &User{Username: "alice"}
	if got := ActorIdentity(u, true); got != "user:alice" {
		t.Errorf("ActorIdentity = %q, want user:alice", got)
	}
	for name, got := range map[string]string{
		"nil user":         ActorIdentity(nil, true),
		"not attributed":   ActorIdentity(u, false),
		"nil and unattrib": ActorIdentity(nil, false),
	} {
		if !strings.HasPrefix(got, "unattributed:") {
			t.Errorf("%s: ActorIdentity = %q, want an unattributed marker", name, got)
		}
	}
}

func TestUsernameRules(t *testing.T) {
	if got := NormalizeUsername("  AliCe  "); got != "alice" {
		t.Errorf("NormalizeUsername = %q, want alice", got)
	}
	for _, ok := range []string{"al", "alice", "a.b-c_d@e", "user123"} {
		if err := ValidUsername(ok); err != nil {
			t.Errorf("ValidUsername(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"", "a", strings.Repeat("a", 65),
		"Alice",   // uppercase would shadow a lowercase twin
		"al ice",  // whitespace
		"al:ice",  // colon is the actor-identity separator
		"al\nice", // newline could forge structure in a canonical encoding
		"al,ice", "al/ice", "al*ice", "álice",
	} {
		if err := ValidUsername(bad); err == nil {
			t.Errorf("ValidUsername(%q) = nil, want an error", bad)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := ValidPassword(strings.Repeat("a", MinPasswordLength)); err != nil {
		t.Errorf("a password at the minimum length must be accepted: %v", err)
	}
	if err := ValidPassword(strings.Repeat("a", MinPasswordLength-1)); err == nil {
		t.Error("a password below the minimum must be rejected")
	}
	if err := ValidPassword(strings.Repeat("a", 1025)); err == nil {
		t.Error("an unbounded password must be rejected so argon2 cost stays bounded")
	}
}

func TestValidRole(t *testing.T) {
	if !ValidRole(RoleAdmin) || !ValidRole(RoleViewer) {
		t.Error("admin and viewer must be valid roles")
	}
	for _, bad := range []string{"", "Admin", "root", "superuser", "admin "} {
		if ValidRole(bad) {
			t.Errorf("ValidRole(%q) = true, want false", bad)
		}
	}
}
