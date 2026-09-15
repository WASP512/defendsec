package storepg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/identity"
)

// User accounts and sessions (roadmap 1.0).
//
// Authentication decisions live here rather than in the console because the
// audit ledger is written from this process and has to record a real user id.
// The console becomes a client of this, not a second source of truth.

// ErrInvalidCredentials is returned for any failed login. It is deliberately
// the same error for an unknown username, a wrong password, a wrong code and a
// disabled account: the caller must not be able to tell which accounts exist.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrAccountLocked is returned when too many failures have locked the account.
// It is distinguishable from ErrInvalidCredentials because the lockout is
// already observable by the legitimate owner, and hiding it only confuses them.
var ErrAccountLocked = errors.New("account temporarily locked")

// ErrTOTPRequired is returned when the password was correct but a second
// factor is enrolled and no code was supplied.
var ErrTOTPRequired = errors.New("second factor required")

const userColumns = `id, username, display_name, role, password_hash, disabled,
	totp_secret, totp_enabled, totp_last_counter, failed_attempts, locked_until,
	last_login_at, created_at`

func scanUser(row pgx.Row) (identity.User, error) {
	var u identity.User
	var lockedUntil, lastLogin *time.Time
	var created time.Time
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.PasswordHash, &u.Disabled,
		&u.TOTPSecret, &u.TOTPEnabled, &u.TOTPLastCounter, &u.FailedAttempts, &lockedUntil,
		&lastLogin, &created)
	if err != nil {
		return identity.User{}, err
	}
	if lockedUntil != nil {
		u.LockedUntil = lockedUntil.UTC()
	}
	if lastLogin != nil {
		u.LastLoginAt = lastLogin.UTC()
	}
	u.CreatedAt = created.UTC()
	return u, nil
}

// CreateUser inserts an account. The password is hashed here so a plaintext
// password never reaches the database layer's caller twice.
func (s *Store) CreateUser(ctx context.Context, id, username, displayName, role, password string) (identity.User, error) {
	username = identity.NormalizeUsername(username)
	if err := identity.ValidUsername(username); err != nil {
		return identity.User{}, err
	}
	if !identity.ValidRole(role) {
		return identity.User{}, fmt.Errorf("unknown role %q", role)
	}
	if err := identity.ValidPassword(password); err != nil {
		return identity.User{}, err
	}
	hash, err := identity.HashPassword(password)
	if err != nil {
		return identity.User{}, err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO users (id, username, display_name, role, password_hash)
		VALUES ($1,$2,$3,$4,$5)
	`, id, username, displayName, role, hash)
	if err != nil {
		if strings.Contains(err.Error(), "users_username_key") {
			return identity.User{}, fmt.Errorf("username %q is already taken", username)
		}
		return identity.User{}, err
	}
	return s.GetUserByUsername(ctx, username)
}

// GetUserByUsername looks an account up case-insensitively.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (identity.User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(username) = lower($1)`,
		identity.NormalizeUsername(username))
	return scanUser(row)
}

// GetUser looks an account up by id.
func (s *Store) GetUser(ctx context.Context, id string) (identity.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// ListUsers returns every account, without secrets.
func (s *Store) ListUsers(ctx context.Context) ([]identity.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []identity.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = ""
		u.TOTPSecret = ""
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountUsers reports how many accounts exist, which decides whether the
// bootstrap shared token is still permitted.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// SetUserPassword replaces a password and clears any lockout.
func (s *Store) SetUserPassword(ctx context.Context, id, password string) error {
	if err := identity.ValidPassword(password); err != nil {
		return err
	}
	hash, err := identity.HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE users SET password_hash=$2, failed_attempts=0, locked_until=NULL, updated_at=now()
		WHERE id=$1
	`, id, hash)
	return err
}

// SetUserDisabled enables or disables an account. Disabling also drops every
// session it holds, so revocation is immediate rather than taking effect at
// the next expiry.
func (s *Store) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx,
		`UPDATE users SET disabled=$2, updated_at=now() WHERE id=$1`, id, disabled); err != nil {
		return err
	}
	if disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM user_sessions WHERE user_id=$1`, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// EnrollTOTP stores a secret and marks the second factor active. The caller
// must have confirmed a code against the secret first, so an operator cannot
// lock themselves out with a mis-scanned QR code.
func (s *Store) EnrollTOTP(ctx context.Context, id, secret string, firstCounter int64) error {
	if secret == "" {
		return fmt.Errorf("totp secret must not be empty")
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET totp_secret=$2, totp_enabled=TRUE, totp_last_counter=$3, updated_at=now()
		WHERE id=$1
	`, id, secret, firstCounter)
	return err
}

// Authenticate verifies a username, password and optional second-factor code,
// and on success returns a session token to give the browser.
//
// The returned token is not stored; only its hash is. Failures are
// indistinguishable from each other by design, and an unknown username still
// costs a password verification so timing does not reveal which accounts exist.
func (s *Store) Authenticate(ctx context.Context, username, password, totpCode string, now time.Time) (identity.User, string, error) {
	u, err := s.GetUserByUsername(ctx, username)
	if errors.Is(err, pgx.ErrNoRows) {
		// Burn the same work a real verification would, then fail identically.
		identity.BurnPasswordComparison(password)
		return identity.User{}, "", ErrInvalidCredentials
	}
	if err != nil {
		return identity.User{}, "", err
	}

	if u.Locked(now) {
		return identity.User{}, "", ErrAccountLocked
	}

	if !identity.VerifyPassword(password, u.PasswordHash) {
		if err := s.recordLoginFailure(ctx, u, now); err != nil {
			return identity.User{}, "", err
		}
		return identity.User{}, "", ErrInvalidCredentials
	}

	// A disabled account is checked only after the password, so probing does
	// not reveal that a username exists but is switched off.
	if u.Disabled {
		return identity.User{}, "", ErrInvalidCredentials
	}

	if u.TOTPEnabled {
		if strings.TrimSpace(totpCode) == "" {
			return identity.User{}, "", ErrTOTPRequired
		}
		res := identity.VerifyTOTP(u.TOTPSecret, totpCode, now.Unix(), u.TOTPLastCounter)
		if !res.Valid {
			if err := s.recordLoginFailure(ctx, u, now); err != nil {
				return identity.User{}, "", err
			}
			return identity.User{}, "", ErrInvalidCredentials
		}
		// Spend the code before issuing the session. If this write fails the
		// login fails, because accepting it would leave the code replayable.
		if _, err := s.pool.Exec(ctx,
			`UPDATE users SET totp_last_counter=$2 WHERE id=$1 AND totp_last_counter < $2`,
			u.ID, res.Counter); err != nil {
			return identity.User{}, "", err
		}
		u.TOTPLastCounter = res.Counter
	}

	// The password is in hand and correct, which is the only moment a hash can
	// be upgraded without forcing a reset. A deployment that switches to FIPS
	// therefore migrates as people sign in, rather than locking anyone out.
	if identity.NeedsRehash(u.PasswordHash) {
		if rehashed, err := identity.HashPassword(password); err == nil {
			if _, err := s.pool.Exec(ctx,
				`UPDATE users SET password_hash=$2, updated_at=now() WHERE id=$1`, u.ID, rehashed); err != nil {
				// Not fatal: the login is valid and the old hash still works.
				// Failing here would deny access over a housekeeping problem.
				_ = err
			}
		}
	}

	token, hash, err := identity.NewSessionToken()
	if err != nil {
		return identity.User{}, "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return identity.User{}, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, attributed)
		VALUES ($1,$2,$3::timestamptz,$4::timestamptz,TRUE)
	`, hash, u.ID, now.UTC(), now.Add(identity.SessionTTL).UTC()); err != nil {
		return identity.User{}, "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE users SET failed_attempts=0, locked_until=NULL, last_login_at=$2::timestamptz, updated_at=now()
		WHERE id=$1
	`, u.ID, now.UTC()); err != nil {
		return identity.User{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return identity.User{}, "", err
	}

	u.FailedAttempts = 0
	u.LockedUntil = time.Time{}
	u.LastLoginAt = now.UTC()
	u.PasswordHash = ""
	u.TOTPSecret = ""
	return u, token, nil
}

// recordLoginFailure increments the counter and locks the account once it
// crosses the threshold.
func (s *Store) recordLoginFailure(ctx context.Context, u identity.User, now time.Time) error {
	attempts := u.FailedAttempts + 1
	if attempts >= identity.MaxFailedAttempts {
		_, err := s.pool.Exec(ctx, `
			UPDATE users SET failed_attempts=$2, locked_until=$3::timestamptz, updated_at=now()
			WHERE id=$1
		`, u.ID, attempts, now.Add(identity.LockoutDuration).UTC())
		return err
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET failed_attempts=$2, updated_at=now() WHERE id=$1`, u.ID, attempts)
	return err
}

// LookupSession resolves a session token to its user, or returns
// ErrInvalidCredentials if it is unknown, expired, or the account is disabled.
// An expired row is deleted on the way out rather than left to accumulate.
func (s *Store) LookupSession(ctx context.Context, token string, now time.Time) (identity.User, identity.Session, error) {
	if token == "" {
		return identity.User{}, identity.Session{}, ErrInvalidCredentials
	}
	hash := identity.HashSessionToken(token)

	var sess identity.Session
	var created, expires time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT user_id, created_at, expires_at, attributed FROM user_sessions WHERE token_hash=$1
	`, hash).Scan(&sess.UserID, &created, &expires, &sess.Attributed)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, identity.Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return identity.User{}, identity.Session{}, err
	}
	sess.TokenHash = hash
	sess.CreatedAt = created.UTC()
	sess.ExpiresAt = expires.UTC()

	if sess.Expired(now) {
		_, _ = s.pool.Exec(ctx, `DELETE FROM user_sessions WHERE token_hash=$1`, hash)
		return identity.User{}, identity.Session{}, ErrInvalidCredentials
	}

	u, err := s.GetUser(ctx, sess.UserID)
	if err != nil {
		return identity.User{}, identity.Session{}, ErrInvalidCredentials
	}
	if u.Disabled {
		return identity.User{}, identity.Session{}, ErrInvalidCredentials
	}
	u.PasswordHash = ""
	u.TOTPSecret = ""
	return u, sess, nil
}

// DeleteSession logs a session out.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM user_sessions WHERE token_hash=$1`, identity.HashSessionToken(token))
	return err
}

// PruneExpiredSessions removes sessions past their expiry. Called alongside
// the other retention pruning at startup.
func (s *Store) PruneExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM user_sessions WHERE expires_at < $1::timestamptz`, now.UTC())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
