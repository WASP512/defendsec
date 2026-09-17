package storepg

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AI agent principals (roadmap 4.1).
//
// An agent is a principal and deliberately not a user. The alternative was a
// third role on the users table, which would have been less code and a worse
// design: a role is a string compared at every call site, and the guarantee
// this phase sells — that an agent cannot sign its own authority — would then
// rest on every one of those comparisons being written correctly, forever.
//
// Agents live here instead, and the admin API resolves callers only against
// users and sessions. An agent token presented to the command endpoint is not
// an under-privileged caller; it is not a caller the admin API can see at all.

// AgentPrincipal is a registered AI agent.
type AgentPrincipal struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Model       string    `json:"model,omitempty"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	CreatedBy   string    `json:"createdBy,omitempty"`
	Disabled    bool      `json:"disabled,omitempty"`
	LastSeenAt  time.Time `json:"lastSeenAt,omitempty"`
	RevokedAt   time.Time `json:"revokedAt,omitempty"`
	RevokedBy   string    `json:"revokedBy,omitempty"`
}

// Identity is how this principal appears in the ledger.
//
// Prefixed so no audit reader can mistake an agent for a person. "user:alice"
// and "agent:triage" are different kinds of actor and the ledger says which.
func (a AgentPrincipal) Identity() string { return "agent:" + a.Name }

// Active reports whether the principal may authenticate.
func (a AgentPrincipal) Active() bool {
	return !a.Disabled && a.RevokedAt.IsZero()
}

// ErrAgentInactive reports a principal that exists but may not be used.
var ErrAgentInactive = errors.New("agent principal is disabled or revoked")

// agentTokenBytes is the entropy in an agent token. Same as a session token:
// an agent credential reaches a control surface, so guessing is out of the
// question.
const agentTokenBytes = 32

// hashToken is how a token is stored. SHA-256 with no salt is right here and
// wrong for a password: the input is 256 bits of entropy rather than
// something a person chose, so there is no dictionary to attack and no work
// factor worth paying on every request.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ValidAgentName enforces a conservative character set. Agent names end up in
// audit records and evidence bundles alongside usernames, so they stay to
// characters that cannot be confused with structure in those formats — and
// cannot be made to look like a "user:" identity.
func ValidAgentName(name string) error {
	if len(name) < 2 || len(name) > 64 {
		return fmt.Errorf("an agent name must be between 2 and 64 characters")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("an agent name may contain only lowercase letters, digits, hyphen, underscore and dot")
		}
	}
	return nil
}

// CreateAgentPrincipal registers an agent and returns its one-time token.
//
// The token is returned once and never stored, only its hash. A database copy
// therefore yields no working credential — which matters more for an agent
// than for a person, because an agent token is used unattended and nobody
// notices it being replayed.
func (s *Store) CreateAgentPrincipal(ctx context.Context, name, model, description, createdBy string) (AgentPrincipal, string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if err := ValidAgentName(name); err != nil {
		return AgentPrincipal{}, "", err
	}
	if strings.TrimSpace(model) == "" {
		// Required, not optional. The whole audit value of Phase 4 is being
		// able to answer "what recommended this", and an agent with no
		// declared model makes that unanswerable from the start.
		return AgentPrincipal{}, "", fmt.Errorf("an agent principal must declare the model behind it")
	}

	var raw [agentTokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return AgentPrincipal{}, "", fmt.Errorf("generate agent token: %w", err)
	}
	token := "dsa_" + base64.RawURLEncoding.EncodeToString(raw[:])

	var idBytes [16]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return AgentPrincipal{}, "", fmt.Errorf("generate agent id: %w", err)
	}
	id := hex.EncodeToString(idBytes[:])

	now := time.Now().UTC()
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO agent_principals (id, name, token_hash, model, description, created_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, id, name, hashToken(token), strings.TrimSpace(model),
		strings.TrimSpace(description), now, createdBy); err != nil {
		return AgentPrincipal{}, "", err
	}
	return AgentPrincipal{
		ID: id, Name: name, Model: strings.TrimSpace(model),
		Description: strings.TrimSpace(description),
		CreatedAt:   now, CreatedBy: createdBy,
	}, token, nil
}

const agentColumns = `id, name, model, description, created_at, created_by,
	disabled, last_seen_at, revoked_at, revoked_by`

func scanAgent(row pgx.Row) (AgentPrincipal, error) {
	var a AgentPrincipal
	var lastSeen, revokedAt *time.Time
	if err := row.Scan(&a.ID, &a.Name, &a.Model, &a.Description, &a.CreatedAt,
		&a.CreatedBy, &a.Disabled, &lastSeen, &revokedAt, &a.RevokedBy); err != nil {
		return AgentPrincipal{}, err
	}
	a.CreatedAt = a.CreatedAt.UTC()
	if lastSeen != nil {
		a.LastSeenAt = lastSeen.UTC()
	}
	if revokedAt != nil {
		a.RevokedAt = revokedAt.UTC()
	}
	return a, nil
}

// LookupAgentToken resolves a bearer token to its principal.
//
// A disabled or revoked principal returns ErrAgentInactive rather than
// ErrNotFound, so a caller can log the difference between an unknown token
// and a withdrawn one — the second is worth an operator's attention.
func (s *Store) LookupAgentToken(ctx context.Context, token string) (AgentPrincipal, error) {
	if strings.TrimSpace(token) == "" {
		return AgentPrincipal{}, ErrNotFound
	}
	a, err := scanAgent(s.pool.QueryRow(ctx,
		`SELECT `+agentColumns+` FROM agent_principals WHERE token_hash=$1`,
		hashToken(token)))
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentPrincipal{}, ErrNotFound
	}
	if err != nil {
		return AgentPrincipal{}, err
	}
	if !a.Active() {
		return a, ErrAgentInactive
	}
	return a, nil
}

// TouchAgent records that a principal was used.
//
// Best-effort and deliberately not part of the authentication transaction: a
// write failure here must not turn into an authentication failure, and an
// agent's last-seen time is operational nicety rather than evidence.
func (s *Store) TouchAgent(ctx context.Context, id string) {
	_, _ = s.pool.Exec(ctx,
		`UPDATE agent_principals SET last_seen_at=now() WHERE id=$1`, id)
}

// ListAgentPrincipals returns every principal, revoked ones included.
//
// Revoked principals are listed rather than hidden: an operator asking "what
// could reach this fleet" needs the history, and an auditor asking "what was
// withdrawn and when" needs it more.
func (s *Store) ListAgentPrincipals(ctx context.Context) ([]AgentPrincipal, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+agentColumns+` FROM agent_principals ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AgentPrincipal
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RevokeAgentPrincipal withdraws a principal permanently.
//
// The row is kept. "Trivially revocable" is part of the Phase 4 claim, and a
// deleted row would leave no evidence the principal ever existed — which is
// exactly the record an auditor wants after an agent is withdrawn.
func (s *Store) RevokeAgentPrincipal(ctx context.Context, name, by string) (AgentPrincipal, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	tag, err := s.pool.Exec(ctx, `
		UPDATE agent_principals
		SET revoked_at=now(), revoked_by=$2, disabled=true
		WHERE name=$1 AND revoked_at IS NULL
	`, name, by)
	if err != nil {
		return AgentPrincipal{}, err
	}
	if tag.RowsAffected() == 0 {
		// Either it does not exist or it was already revoked. Both mean the
		// caller's intent already holds, so this is reported as not-found
		// rather than as an error to retry.
		return AgentPrincipal{}, ErrNotFound
	}
	return s.GetAgentPrincipal(ctx, name)
}

// GetAgentPrincipal returns one principal by name.
func (s *Store) GetAgentPrincipal(ctx context.Context, name string) (AgentPrincipal, error) {
	a, err := scanAgent(s.pool.QueryRow(ctx,
		`SELECT `+agentColumns+` FROM agent_principals WHERE name=$1`,
		strings.ToLower(strings.TrimSpace(name))))
	if errors.Is(err, pgx.ErrNoRows) {
		return AgentPrincipal{}, ErrNotFound
	}
	return a, err
}
