package storepg

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"defendsec/internal/identity"
)

// Integration tests against a real Postgres, skipped unless
// TEST_DATABASE_URL is set.

func resetUsers(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `TRUNCATE users, user_sessions CASCADE`); err != nil {
		t.Fatalf("reset users: %v", err)
	}
}

const testPassword = "a sufficiently long password"

func seedUser(t *testing.T, s *Store, username, role string) identity.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), randID(t), username, "Test "+username, role, testPassword)
	if err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return u
}

func TestCreateUserAndLookup(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)

	u := seedUser(t, s, "alice", identity.RoleAdmin)
	if u.Username != "alice" || u.Role != identity.RoleAdmin {
		t.Fatalf("unexpected user: %+v", u)
	}
	if u.PasswordHash == "" {
		t.Fatal("password hash should be populated on the freshly created record")
	}
	if strings.Contains(u.PasswordHash, testPassword) {
		t.Fatal("the stored hash must not contain the password")
	}

	// Lookup is case-insensitive.
	for _, name := range []string{"alice", "Alice", "ALICE", "  alice  "} {
		if _, err := s.GetUserByUsername(ctx, name); err != nil {
			t.Errorf("GetUserByUsername(%q) = %v", name, err)
		}
	}

	// ListUsers must not leak secrets.
	list, err := s.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("want 1 user, got %d", len(list))
	}
	if list[0].PasswordHash != "" || list[0].TOTPSecret != "" {
		t.Error("ListUsers must not return password hashes or TOTP secrets")
	}
}

// A differently-cased twin must not be creatable, or two ledger actors could
// look like one person.
func TestCreateUserRejectsDuplicateUsernameCaseInsensitively(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	seedUser(t, s, "alice", identity.RoleAdmin)

	for _, dup := range []string{"alice", "Alice", "ALICE"} {
		if _, err := s.CreateUser(ctx, randID(t), dup, "", identity.RoleAdmin, testPassword); err == nil {
			t.Errorf("creating %q should collide with the existing alice", dup)
		}
	}
}

func TestCreateUserValidatesInput(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)

	cases := map[string]struct{ username, role, password string }{
		"bad username":   {"Not Valid", identity.RoleAdmin, testPassword},
		"unknown role":   {"bob", "superuser", testPassword},
		"short password": {"bob", identity.RoleAdmin, "short"},
		"empty password": {"bob", identity.RoleAdmin, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := s.CreateUser(ctx, randID(t), tc.username, "", tc.role, tc.password); err == nil {
				t.Error("expected validation to reject this input")
			}
		})
	}
}

func TestAuthenticateIssuesUsableSession(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	u, token, err := s.Authenticate(ctx, "alice", testPassword, "", now)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if token == "" {
		t.Fatal("a session token must be issued")
	}
	if u.PasswordHash != "" || u.TOTPSecret != "" {
		t.Error("the authenticated user must not carry secrets back to the caller")
	}

	got, sess, err := s.LookupSession(ctx, token, now)
	if err != nil {
		t.Fatalf("lookup session: %v", err)
	}
	if got.Username != "alice" || !sess.Attributed {
		t.Errorf("unexpected session: user=%q attributed=%v", got.Username, sess.Attributed)
	}
	if identity.ActorIdentity(&got, sess.Attributed) != "user:alice" {
		t.Error("an authenticated session must produce a named actor identity")
	}

	// Only the hash is stored, so the raw token must not appear in the table.
	var stored string
	if err := s.pool.QueryRow(ctx, `SELECT token_hash FROM user_sessions LIMIT 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token {
		t.Fatal("the session table must store a hash, not the token")
	}
	// And the stored hash must not itself work as a token.
	if _, _, err := s.LookupSession(ctx, stored, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("a stored hash must not authenticate as a token")
	}
}

func TestAuthenticateFailuresAreIndistinguishable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	cases := map[string]struct{ user, pass string }{
		"unknown user":   {"nobody", testPassword},
		"wrong password": {"alice", "the wrong password here"},
		"empty password": {"alice", ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, token, err := s.Authenticate(ctx, tc.user, tc.pass, "", now)
			if !errors.Is(err, ErrInvalidCredentials) {
				t.Errorf("err = %v, want ErrInvalidCredentials", err)
			}
			if token != "" {
				t.Error("no session may be issued on a failed login")
			}
		})
	}
}

// A disabled account must fail like a wrong password, and its live sessions
// must stop working immediately rather than at the next expiry.
func TestDisabledUserCannotAuthenticateAndLosesSessions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	u := seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	_, token, err := s.Authenticate(ctx, "alice", testPassword, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.LookupSession(ctx, token, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("disabling an account must invalidate its sessions at once")
	}
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "", now); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("a disabled account must not authenticate")
	}
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	for i := 0; i < identity.MaxFailedAttempts; i++ {
		if _, _, err := s.Authenticate(ctx, "alice", "wrong password attempt", "", now); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: err = %v", i, err)
		}
	}
	// Now locked — and the correct password must not get in either.
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "", now); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("err = %v, want ErrAccountLocked", err)
	}
	// The lockout expires.
	later := now.Add(identity.LockoutDuration + time.Minute)
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "", later); err != nil {
		t.Fatalf("after the lockout expires the correct password must work: %v", err)
	}
	// A successful login clears the counter.
	u, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.FailedAttempts != 0 || !u.LockedUntil.IsZero() {
		t.Errorf("a successful login must clear the failure state: %+v", u)
	}
}

func TestSetUserPasswordClearsLockout(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	u := seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	for i := 0; i < identity.MaxFailedAttempts; i++ {
		_, _, _ = s.Authenticate(ctx, "alice", "wrong password attempt", "", now)
	}
	const replacement = "an entirely new password"
	if err := s.SetUserPassword(ctx, u.ID, replacement); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Authenticate(ctx, "alice", replacement, "", now); err != nil {
		t.Fatalf("the new password must work and the lockout must be cleared: %v", err)
	}
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "", now); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("the old password must stop working")
	}
	if err := s.SetUserPassword(ctx, u.ID, "short"); err == nil {
		t.Error("the password policy must apply to changes too")
	}
}

// --- second factor -------------------------------------------------------

func TestTOTPRequiredAndVerified(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	u := seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	secret, err := identity.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnrollTOTP(ctx, u.ID, secret, 0); err != nil {
		t.Fatal(err)
	}

	// Password alone is no longer enough.
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "", now); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("err = %v, want ErrTOTPRequired", err)
	}
	// A wrong code fails like any other bad credential.
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "000000", now); !errors.Is(err, ErrInvalidCredentials) {
		// 000000 could legitimately be the code; only fail if it is not.
		if code, _ := identity.TOTPCodeAt(secret, now.Unix()); code != "000000" {
			t.Fatalf("err = %v, want ErrInvalidCredentials", err)
		}
	}

	code, err := identity.TOTPCodeAt(secret, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, code, now); err != nil {
		t.Fatalf("the correct code must authenticate: %v", err)
	}
}

// The property that makes TOTP a second factor rather than a short-lived
// shared password: a code, once used, is spent. This is the end-to-end version
// of the unit test, checked against the counter actually persisted.
func TestTOTPCodeCannotBeReplayedAgainstTheDatabase(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	u := seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	secret, _ := identity.NewTOTPSecret()
	if err := s.EnrollTOTP(ctx, u.ID, secret, 0); err != nil {
		t.Fatal(err)
	}
	code, _ := identity.TOTPCodeAt(secret, now.Unix())

	if _, _, err := s.Authenticate(ctx, "alice", testPassword, code, now); err != nil {
		t.Fatalf("first use must succeed: %v", err)
	}
	// Same code, same window, second attempt.
	if _, _, err := s.Authenticate(ctx, "alice", testPassword, code, now.Add(2*time.Second)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatal("a spent code must not be accepted again")
	}

	stored, err := s.GetUserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if stored.TOTPLastCounter != identity.TOTPCounter(now.Unix()) {
		t.Errorf("last counter = %d, want %d — the spend was not persisted",
			stored.TOTPLastCounter, identity.TOTPCounter(now.Unix()))
	}
}

// --- sessions ------------------------------------------------------------

func TestSessionExpiryAndLogout(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	_, token, err := s.Authenticate(ctx, "alice", testPassword, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LookupSession(ctx, token, now.Add(identity.SessionTTL+time.Minute)); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("an expired session must not resolve")
	}

	// A fresh session, then an explicit logout.
	_, token2, err := s.Authenticate(ctx, "alice", testPassword, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSession(ctx, token2); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LookupSession(ctx, token2, now); !errors.Is(err, ErrInvalidCredentials) {
		t.Error("a logged-out session must not resolve")
	}
}

func TestLookupSessionRejectsUnknownTokens(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	now := time.Now().UTC()

	for _, bad := range []string{"", "not-a-token", strings.Repeat("a", 64)} {
		if _, _, err := s.LookupSession(ctx, bad, now); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("LookupSession(%q) = %v, want ErrInvalidCredentials", bad, err)
		}
	}
}

func TestPruneExpiredSessions(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)
	seedUser(t, s, "alice", identity.RoleAdmin)
	now := time.Now().UTC()

	if _, _, err := s.Authenticate(ctx, "alice", testPassword, "", now); err != nil {
		t.Fatal(err)
	}
	// Nothing to prune yet.
	if n, err := s.PruneExpiredSessions(ctx, now); err != nil || n != 0 {
		t.Fatalf("PruneExpiredSessions = %d, %v; want 0, nil", n, err)
	}
	if n, err := s.PruneExpiredSessions(ctx, now.Add(identity.SessionTTL+time.Minute)); err != nil || n != 1 {
		t.Fatalf("PruneExpiredSessions = %d, %v; want 1, nil", n, err)
	}
}

func TestCountUsersDrivesBootstrap(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resetUsers(t, s)

	if n, err := s.CountUsers(ctx); err != nil || n != 0 {
		t.Fatalf("CountUsers = %d, %v; want 0 on a fresh install", n, err)
	}
	seedUser(t, s, "alice", identity.RoleAdmin)
	if n, err := s.CountUsers(ctx); err != nil || n != 1 {
		t.Fatalf("CountUsers = %d, %v; want 1", n, err)
	}
}
