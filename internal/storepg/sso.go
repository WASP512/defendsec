package storepg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/identity"
)

// Single sign-on accounts (roadmap 5.4).

// SSOPasswordMarker is stored as the password hash of an SSO-provisioned
// account. It is not a valid encoding of any hash, so identity.VerifyPassword
// rejects every password against it: an SSO account cannot be signed into
// through the password form, and disabling someone at the identity provider
// is not undone by a password nobody set.
const SSOPasswordMarker = "!sso"

// ErrUsernameTaken reports an SSO sign-in whose username collides with an
// existing account that is not linked to that identity.
var ErrUsernameTaken = errors.New("username belongs to a different account")

// SSOIdentity is what the identity provider asserted, after verification.
type SSOIdentity struct {
	Issuer      string
	Subject     string
	Username    string
	DisplayName string
	// Role is already decided from group membership by the caller.
	Role string
}

// SignInSSO finds or provisions the account for a verified SSO identity and
// opens a session for it.
//
// The role is rewritten on every sign-in from the identity provider's
// current groups, so removing someone from the admin group takes effect at
// their next sign-in rather than never. A locally disabled account stays
// disabled whatever the IdP says: the control plane can always withdraw
// access, and an IdP misconfiguration should not be able to restore it.
func (s *Store) SignInSSO(ctx context.Context, id SSOIdentity, now time.Time) (identity.User, string, error) {
	if id.Issuer == "" || id.Subject == "" {
		return identity.User{}, "", fmt.Errorf("an SSO identity needs an issuer and a subject")
	}
	if !identity.ValidRole(id.Role) {
		return identity.User{}, "", fmt.Errorf("unknown role %q", id.Role)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return identity.User{}, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID string
	var disabled bool
	err = tx.QueryRow(ctx,
		`SELECT id, disabled FROM users WHERE sso_issuer=$1 AND sso_subject=$2`,
		id.Issuer, id.Subject).Scan(&userID, &disabled)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		username := identity.NormalizeUsername(id.Username)
		if verr := identity.ValidUsername(username); verr != nil {
			return identity.User{}, "", fmt.Errorf("the identity provider's username %q cannot be used: %w", id.Username, verr)
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM users WHERE lower(username)=lower($1))`,
			username).Scan(&exists); err != nil {
			return identity.User{}, "", err
		}
		if exists {
			// Never linked by name. A local account called "alice" and an
			// IdP user called "alice" are not known to be the same person.
			return identity.User{}, "", ErrUsernameTaken
		}
		userID, err = newID()
		if err != nil {
			return identity.User{}, "", err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, username, display_name, role, password_hash, sso_issuer, sso_subject)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
		`, userID, username, strings.TrimSpace(id.DisplayName), id.Role,
			SSOPasswordMarker, id.Issuer, id.Subject); err != nil {
			return identity.User{}, "", err
		}
	case err != nil:
		return identity.User{}, "", err
	default:
		if disabled {
			return identity.User{}, "", ErrInvalidCredentials
		}
		if _, err := tx.Exec(ctx,
			`UPDATE users SET role=$2, display_name=COALESCE(NULLIF($3,''), display_name), updated_at=now() WHERE id=$1`,
			userID, id.Role, strings.TrimSpace(id.DisplayName)); err != nil {
			return identity.User{}, "", err
		}
	}

	token, hash, err := identity.NewSessionToken()
	if err != nil {
		return identity.User{}, "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, attributed)
		VALUES ($1,$2,$3::timestamptz,$4::timestamptz,TRUE)
	`, hash, userID, now.UTC(), now.Add(identity.SessionTTL).UTC()); err != nil {
		return identity.User{}, "", err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE users SET last_login_at=$2::timestamptz WHERE id=$1`, userID, now.UTC()); err != nil {
		return identity.User{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return identity.User{}, "", err
	}

	u, err := s.GetUser(ctx, userID)
	if err != nil {
		return identity.User{}, "", err
	}
	u.PasswordHash = ""
	u.TOTPSecret = ""
	return u, token, nil
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
