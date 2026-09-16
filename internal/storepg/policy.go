package storepg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/policy"
)

// Storage for policy-governed response (roadmap 2.1-2.4).

// PolicyDecision is one recorded evaluation.
type PolicyDecision struct {
	ID            string        `json:"id"`
	At            time.Time     `json:"at"`
	Actor         string        `json:"actor"`
	Role          string        `json:"role,omitempty"`
	CommandType   string        `json:"commandType"`
	DeviceID      string        `json:"deviceId,omitempty"`
	Hostname      string        `json:"hostname,omitempty"`
	HostClasses   []string      `json:"hostClasses,omitempty"`
	Effect        policy.Effect `json:"effect"`
	RuleID        string        `json:"ruleId,omitempty"`
	Reason        string        `json:"reason"`
	PolicyName    string        `json:"policyName,omitempty"`
	PolicyHash    string        `json:"policyHash,omitempty"`
	LimitExceeded string        `json:"limitExceeded,omitempty"`
	BreakGlassID  string        `json:"breakGlassId,omitempty"`
	CommandID     string        `json:"commandId,omitempty"`
}

// RecordPolicyDecision stores an evaluation, permit or deny.
//
// Denials are evidence. A tool that records only what it did cannot answer
// "did anyone try", which is the question asked after an incident and the one
// a deny-by-default engine is uniquely placed to answer.
func (s *Store) RecordPolicyDecision(ctx context.Context, d PolicyDecision) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policy_decisions
			(id, at, actor, role, command_type, device_id, hostname, host_classes,
			 effect, rule_id, reason, policy_name, policy_hash, limit_exceeded,
			 break_glass_id, command_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (id) DO NOTHING
	`, d.ID, d.At, d.Actor, d.Role, d.CommandType, d.DeviceID, d.Hostname,
		controlIDs(d.HostClasses), string(d.Effect), d.RuleID, d.Reason,
		d.PolicyName, d.PolicyHash, d.LimitExceeded, d.BreakGlassID, d.CommandID)
	return err
}

// ListPolicyDecisions returns decisions, newest first.
func (s *Store) ListPolicyDecisions(ctx context.Context, effect string, limit int) ([]PolicyDecision, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, actor, role, command_type, device_id, hostname, host_classes,
		       effect, rule_id, reason, policy_name, policy_hash, limit_exceeded,
		       break_glass_id, command_id
		FROM policy_decisions
		WHERE ($1 = '' OR effect = $1)
		ORDER BY at DESC
		LIMIT $2
	`, effect, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PolicyDecision{}
	for rows.Next() {
		var d PolicyDecision
		var effect string
		if err := rows.Scan(&d.ID, &d.At, &d.Actor, &d.Role, &d.CommandType,
			&d.DeviceID, &d.Hostname, &d.HostClasses, &effect, &d.RuleID, &d.Reason,
			&d.PolicyName, &d.PolicyHash, &d.LimitExceeded, &d.BreakGlassID, &d.CommandID); err != nil {
			return nil, err
		}
		d.Effect = policy.Effect(effect)
		d.At = d.At.UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

// CommandUsage counts commands issued since a moment, fleet-wide and for one
// host, which is what blast-radius limits are checked against.
//
// It counts the commands table rather than policy decisions: what matters for
// a limit is what was actually issued, not what was evaluated. Counting
// evaluations would let a caller exhaust a limit with requests that were all
// denied anyway.
func (s *Store) CommandUsage(ctx context.Context, commandTypes []string, since time.Time, deviceID string) (policy.Usage, error) {
	var u policy.Usage
	err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE device_id = $3)
		FROM commands
		WHERE type = ANY($1) AND created_at >= $2
	`, commandTypes, since, deviceID).Scan(&u.FleetCount, &u.HostCount)
	if err != nil {
		return policy.Usage{}, err
	}
	return u, nil
}

// SetDeviceClasses replaces a host's classes.
func (s *Store) SetDeviceClasses(ctx context.Context, deviceID string, classes []string) error {
	res, err := s.pool.Exec(ctx,
		`UPDATE devices SET classes = $2 WHERE id = $1`, deviceID, controlIDs(classes))
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeviceClasses reads a host's classes.
//
// A host the database has never seen returns no classes and no error: policy
// then evaluates it as an unclassified host, which the deny-by-default rules
// handle. Failing the lookup instead would make an unknown host unmanageable
// at exactly the moment somebody needs to isolate it.
func (s *Store) DeviceClasses(ctx context.Context, deviceID string) ([]string, error) {
	var classes []string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(classes, '{}') FROM devices WHERE id = $1`, deviceID).Scan(&classes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return classes, nil
}

// PendingCommand is a command awaiting a second approver.
type PendingCommand struct {
	ID                string    `json:"id"`
	CreatedAt         time.Time `json:"createdAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
	DeviceID          string    `json:"deviceId"`
	Hostname          string    `json:"hostname,omitempty"`
	CommandType       string    `json:"commandType"`
	Payload           string    `json:"payload"`
	RequestedBy       string    `json:"requestedBy"`
	RequiredApprovals int       `json:"requiredApprovals"`
	RuleID            string    `json:"ruleId,omitempty"`
	PolicyHash        string    `json:"policyHash,omitempty"`
	Status            string    `json:"status"`
	CommandID         string    `json:"commandId,omitempty"`
	Approvals         []string  `json:"approvals"`
}

// Approved reports whether the pending command has the approvals it needs.
func (p PendingCommand) Approved() bool {
	return len(p.Approvals) >= p.RequiredApprovals
}

// CreatePendingCommand records a command awaiting approval.
//
// It carries no signature. A pending command is deliberately not a signed
// command with a flag: an attacker who flips a status column still has nothing
// an agent will execute, because the signature is only produced once the
// approvals are in.
func (s *Store) CreatePendingCommand(ctx context.Context, p PendingCommand) (PendingCommand, error) {
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.RequestedBy) == "" {
		return PendingCommand{}, fmt.Errorf("a pending command needs an id and a requester")
	}
	if !p.ExpiresAt.After(p.CreatedAt) {
		return PendingCommand{}, fmt.Errorf("a pending command must expire after it is created")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PendingCommand{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, `
		INSERT INTO pending_commands
			(id, created_at, expires_at, device_id, hostname, command_type, payload,
			 requested_by, required_approvals, rule_id, policy_hash, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'pending')
	`, p.ID, p.CreatedAt, p.ExpiresAt, p.DeviceID, p.Hostname, p.CommandType,
		p.Payload, p.RequestedBy, p.RequiredApprovals, p.RuleID, p.PolicyHash); err != nil {
		return PendingCommand{}, err
	}
	// The requester's own approval counts as one. They asked for it; making
	// them click approve afterwards adds a step and no safety.
	if _, err := tx.Exec(ctx,
		`INSERT INTO pending_command_approvals (pending_id, actor) VALUES ($1,$2)`,
		p.ID, p.RequestedBy); err != nil {
		return PendingCommand{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PendingCommand{}, err
	}
	return s.GetPendingCommand(ctx, p.ID)
}

const pendingColumns = `id, created_at, expires_at, device_id, hostname, command_type,
	payload, requested_by, required_approvals, rule_id, policy_hash, status, command_id`

func scanPending(row pgx.Row) (PendingCommand, error) {
	var p PendingCommand
	if err := row.Scan(&p.ID, &p.CreatedAt, &p.ExpiresAt, &p.DeviceID, &p.Hostname,
		&p.CommandType, &p.Payload, &p.RequestedBy, &p.RequiredApprovals,
		&p.RuleID, &p.PolicyHash, &p.Status, &p.CommandID); err != nil {
		return PendingCommand{}, err
	}
	p.CreatedAt, p.ExpiresAt = p.CreatedAt.UTC(), p.ExpiresAt.UTC()
	return p, nil
}

// GetPendingCommand returns one pending command with its approvals.
func (s *Store) GetPendingCommand(ctx context.Context, id string) (PendingCommand, error) {
	p, err := scanPending(s.pool.QueryRow(ctx,
		`SELECT `+pendingColumns+` FROM pending_commands WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return PendingCommand{}, ErrNotFound
	}
	if err != nil {
		return PendingCommand{}, err
	}
	p.Approvals, err = s.pendingApprovals(ctx, id)
	return p, err
}

func (s *Store) pendingApprovals(ctx context.Context, id string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT actor FROM pending_command_approvals WHERE pending_id=$1 ORDER BY at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ApprovePendingCommand adds an approval.
//
// The primary key on (pending_id, actor) is what enforces two-person
// integrity: the same administrator approving twice is one row, not two, so
// the count cannot be inflated by clicking again.
func (s *Store) ApprovePendingCommand(ctx context.Context, id, actor string, now time.Time) (PendingCommand, error) {
	p, err := s.GetPendingCommand(ctx, id)
	if err != nil {
		return PendingCommand{}, err
	}
	if p.Status != "pending" {
		return PendingCommand{}, fmt.Errorf("this request is already %s", p.Status)
	}
	if !now.Before(p.ExpiresAt) {
		return PendingCommand{}, fmt.Errorf("this request expired at %s", p.ExpiresAt.Format(time.RFC3339))
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO pending_command_approvals (pending_id, actor) VALUES ($1,$2)
		ON CONFLICT (pending_id, actor) DO NOTHING
	`, id, actor); err != nil {
		return PendingCommand{}, err
	}
	return s.GetPendingCommand(ctx, id)
}

// ListPendingCommands returns requests awaiting approval.
func (s *Store) ListPendingCommands(ctx context.Context, now time.Time) ([]PendingCommand, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+pendingColumns+` FROM pending_commands
		 WHERE status = 'pending' AND expires_at > $1
		 ORDER BY created_at DESC LIMIT 200`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingCommand
	for rows.Next() {
		p, err := scanPending(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Approvals, err = s.pendingApprovals(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	if out == nil {
		out = []PendingCommand{}
	}
	return out, nil
}

// ResolvePendingCommand marks a request issued or rejected.
//
// The status moves only from pending, so two approvers racing to the final
// approval cannot both issue the command.
func (s *Store) ResolvePendingCommand(ctx context.Context, id, status, commandID string) error {
	res, err := s.pool.Exec(ctx,
		`UPDATE pending_commands SET status=$2, command_id=$3 WHERE id=$1 AND status='pending'`,
		id, status, commandID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// OpenBreakGlass records a time-boxed emergency bypass.
func (s *Store) OpenBreakGlass(ctx context.Context, b policy.BreakGlass) (policy.BreakGlass, error) {
	if strings.TrimSpace(b.Justification) == "" {
		// An emergency nobody wrote down is indistinguishable from an abuse
		// afterwards.
		return policy.BreakGlass{}, fmt.Errorf("break-glass requires a written justification")
	}
	if !b.ExpiresAt.After(b.OpenedAt) {
		return policy.BreakGlass{}, fmt.Errorf("break-glass must expire after it is opened")
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO break_glass (id, justification, opened_by, opened_at, expires_at)
		VALUES ($1,$2,$3,$4,$5)
	`, b.ID, b.Justification, b.OpenedBy, b.OpenedAt, b.ExpiresAt); err != nil {
		return policy.BreakGlass{}, err
	}
	return b, nil
}

// ActiveBreakGlass returns the bypass in force, if any.
func (s *Store) ActiveBreakGlass(ctx context.Context, now time.Time) (*policy.BreakGlass, error) {
	var b policy.BreakGlass
	var closedAt *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT id, justification, opened_by, opened_at, expires_at, closed_at
		FROM break_glass
		WHERE closed_at IS NULL AND opened_at <= $1 AND expires_at > $1
		ORDER BY opened_at DESC LIMIT 1
	`, now).Scan(&b.ID, &b.Justification, &b.OpenedBy, &b.OpenedAt, &b.ExpiresAt, &closedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.OpenedAt, b.ExpiresAt = b.OpenedAt.UTC(), b.ExpiresAt.UTC()
	if closedAt != nil {
		utc := closedAt.UTC()
		b.ClosedAt = &utc
	}
	return &b, nil
}

// CloseBreakGlass ends a bypass early.
func (s *Store) CloseBreakGlass(ctx context.Context, id, actor string) error {
	res, err := s.pool.Exec(ctx,
		`UPDATE break_glass SET closed_at=now(), closed_by=$2 WHERE id=$1 AND closed_at IS NULL`,
		id, actor)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListBreakGlass returns bypasses, newest first.
func (s *Store) ListBreakGlass(ctx context.Context, limit int) ([]policy.BreakGlass, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, justification, opened_by, opened_at, expires_at, closed_at
		FROM break_glass ORDER BY opened_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []policy.BreakGlass{}
	for rows.Next() {
		var b policy.BreakGlass
		var closedAt *time.Time
		if err := rows.Scan(&b.ID, &b.Justification, &b.OpenedBy,
			&b.OpenedAt, &b.ExpiresAt, &closedAt); err != nil {
			return nil, err
		}
		b.OpenedAt, b.ExpiresAt = b.OpenedAt.UTC(), b.ExpiresAt.UTC()
		if closedAt != nil {
			utc := closedAt.UTC()
			b.ClosedAt = &utc
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
