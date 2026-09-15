package storepg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/auditlayer"
	"defendsec/internal/controls"
	"defendsec/internal/evidence"
)

// Storage for the audit layer (roadmap 1.9).

// ErrNotFound is returned when a period or exception does not exist. It is
// distinguished from a database failure so a handler can answer 404 rather
// than 500 — a missing period is a normal outcome, not a fault.
var ErrNotFound = errors.New("not found")

// CreateAuditPeriod records a window under review.
func (s *Store) CreateAuditPeriod(ctx context.Context, p auditlayer.Period) (auditlayer.Period, error) {
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.Name) == "" {
		return auditlayer.Period{}, fmt.Errorf("an audit period needs an id and a name")
	}
	if !controls.KnownFramework(controls.Framework(p.Framework)) {
		return auditlayer.Period{}, fmt.Errorf("unknown framework %q", p.Framework)
	}
	if !p.EndsAt.After(p.StartsAt) {
		return auditlayer.Period{}, fmt.Errorf("an audit period must end after it starts")
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO audit_periods (id, name, framework, starts_at, ends_at, notes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, p.ID, p.Name, p.Framework, p.StartsAt, p.EndsAt, p.Notes, p.CreatedBy); err != nil {
		return auditlayer.Period{}, err
	}
	return s.GetAuditPeriod(ctx, p.ID)
}

const auditPeriodColumns = `id, name, framework, starts_at, ends_at, notes, created_at,
	COALESCE(created_by,''), closed_at, COALESCE(closed_by,'')`

func scanAuditPeriod(row pgx.Row) (auditlayer.Period, error) {
	var p auditlayer.Period
	var closedAt *time.Time
	if err := row.Scan(&p.ID, &p.Name, &p.Framework, &p.StartsAt, &p.EndsAt,
		&p.Notes, &p.CreatedAt, &p.CreatedBy, &closedAt, &p.ClosedBy); err != nil {
		return auditlayer.Period{}, err
	}
	if closedAt != nil {
		utc := closedAt.UTC()
		p.ClosedAt = &utc
	}
	p.StartsAt, p.EndsAt, p.CreatedAt = p.StartsAt.UTC(), p.EndsAt.UTC(), p.CreatedAt.UTC()
	return p, nil
}

// GetAuditPeriod returns one period.
func (s *Store) GetAuditPeriod(ctx context.Context, id string) (auditlayer.Period, error) {
	p, err := scanAuditPeriod(s.pool.QueryRow(ctx,
		`SELECT `+auditPeriodColumns+` FROM audit_periods WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return auditlayer.Period{}, ErrNotFound
	}
	return p, err
}

// ListAuditPeriods returns periods, most recent window first.
func (s *Store) ListAuditPeriods(ctx context.Context) ([]auditlayer.Period, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+auditPeriodColumns+` FROM audit_periods ORDER BY starts_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auditlayer.Period{}
	for rows.Next() {
		p, err := scanAuditPeriod(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CloseAuditPeriod declares a window final, or reopens it.
//
// Reopening is allowed but is an action, not an oversight: the caller records
// it in the ledger, so a period that was closed and later reopened leaves a
// trace rather than quietly becoming editable again.
func (s *Store) CloseAuditPeriod(ctx context.Context, id, actor string, closed bool) (auditlayer.Period, error) {
	sql := `UPDATE audit_periods SET closed_at=now(), closed_by=$2 WHERE id=$1`
	args := []any{id, actor}
	if !closed {
		sql = `UPDATE audit_periods SET closed_at=NULL, closed_by='' WHERE id=$1`
		args = args[:1]
	}
	res, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return auditlayer.Period{}, err
	}
	if res.RowsAffected() == 0 {
		return auditlayer.Period{}, ErrNotFound
	}
	return s.GetAuditPeriod(ctx, id)
}

// CreateControlException records a documented, time-limited acceptance.
func (s *Store) CreateControlException(ctx context.Context, e auditlayer.Exception) (auditlayer.Exception, error) {
	if strings.TrimSpace(e.ID) == "" {
		return auditlayer.Exception{}, fmt.Errorf("an exception needs an id")
	}
	if _, err := controls.ParseID(e.ControlID); err != nil {
		return auditlayer.Exception{}, err
	}
	// An exception with no reason is an undocumented one, which is the thing
	// this table exists to replace.
	if strings.TrimSpace(e.Reason) == "" {
		return auditlayer.Exception{}, fmt.Errorf("an exception must record why the deficiency is accepted")
	}
	if e.OpenedAt.IsZero() {
		e.OpenedAt = time.Now().UTC()
	}
	// An exception with no expiry is a permanent excuse.
	if !e.ExpiresAt.After(e.OpenedAt) {
		return auditlayer.Exception{}, fmt.Errorf("an exception must expire after it is opened")
	}

	var periodID any
	if strings.TrimSpace(e.PeriodID) != "" {
		periodID = e.PeriodID
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO control_exceptions
			(id, control_id, period_id, reason, remediation, owner, opened_at, opened_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, e.ID, e.ControlID, periodID, e.Reason, e.Remediation, e.Owner,
		e.OpenedAt, e.OpenedBy, e.ExpiresAt); err != nil {
		return auditlayer.Exception{}, err
	}
	return s.GetControlException(ctx, e.ID)
}

const exceptionColumns = `id, control_id, COALESCE(period_id,''), reason,
	COALESCE(remediation,''), COALESCE(owner,''), opened_at, COALESCE(opened_by,''),
	expires_at, closed_at, COALESCE(closed_by,'')`

func scanException(row pgx.Row) (auditlayer.Exception, error) {
	var e auditlayer.Exception
	var closedAt *time.Time
	if err := row.Scan(&e.ID, &e.ControlID, &e.PeriodID, &e.Reason, &e.Remediation,
		&e.Owner, &e.OpenedAt, &e.OpenedBy, &e.ExpiresAt, &closedAt, &e.ClosedBy); err != nil {
		return auditlayer.Exception{}, err
	}
	if closedAt != nil {
		utc := closedAt.UTC()
		e.ClosedAt = &utc
	}
	e.OpenedAt, e.ExpiresAt = e.OpenedAt.UTC(), e.ExpiresAt.UTC()
	return e, nil
}

// GetControlException returns one exception.
func (s *Store) GetControlException(ctx context.Context, id string) (auditlayer.Exception, error) {
	e, err := scanException(s.pool.QueryRow(ctx,
		`SELECT `+exceptionColumns+` FROM control_exceptions WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return auditlayer.Exception{}, ErrNotFound
	}
	return e, err
}

// ListControlExceptions returns exceptions overlapping a window.
//
// Lapsed and closed exceptions inside the window are included on purpose. A
// reader should see that an exception existed and ended, not be left to infer
// that there never was one.
func (s *Store) ListControlExceptions(ctx context.Context, from, to time.Time) ([]auditlayer.Exception, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+exceptionColumns+`
		FROM control_exceptions
		WHERE opened_at < $2 AND (closed_at IS NULL OR closed_at > $1)
		ORDER BY opened_at, id
	`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auditlayer.Exception{}
	for rows.Next() {
		e, err := scanException(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CloseControlException ends an exception early.
func (s *Store) CloseControlException(ctx context.Context, id, actor string) (auditlayer.Exception, error) {
	res, err := s.pool.Exec(ctx,
		`UPDATE control_exceptions SET closed_at=now(), closed_by=$2 WHERE id=$1 AND closed_at IS NULL`,
		id, actor)
	if err != nil {
		return auditlayer.Exception{}, err
	}
	if res.RowsAffected() == 0 {
		return auditlayer.Exception{}, ErrNotFound
	}
	return s.GetControlException(ctx, id)
}

// AssessPeriod gathers everything for one framework over one window and runs
// the assessment. The counting and the judging stay in separate packages: the
// rules about what counts as satisfied are worth testing without a database.
func (s *Store) AssessPeriod(ctx context.Context, framework controls.Framework, p auditlayer.Period, now time.Time) (auditlayer.Assessment, error) {
	counts, err := s.CountControlRecords(ctx,
		p.StartsAt.Format(time.RFC3339Nano), p.EndsAt.Format(time.RFC3339Nano))
	if err != nil {
		return auditlayer.Assessment{}, err
	}
	evidence := make(map[string]auditlayer.Evidence, len(counts))
	for id, c := range counts {
		evidence[id] = auditlayer.Evidence{
			Alerts: c.Alerts, OpenAlerts: c.OpenAlerts, OpenAtEnd: c.OpenAtEnd,
			Commands: c.Commands, AuditEntries: c.AuditEntries,
		}
	}
	exceptions, err := s.ListControlExceptions(ctx, p.StartsAt, p.EndsAt)
	if err != nil {
		return auditlayer.Assessment{}, err
	}
	return auditlayer.Assess(auditlayer.Input{
		Framework: framework, Period: p, Evidence: evidence,
		Exceptions: exceptions, Now: now,
	}), nil
}

// ExportScopedEvidence produces an evidence bundle carrying a framework
// assessment alongside the cryptographic proof (roadmap 1.9, §3.6 item 4).
//
// The audit range is not narrowed to the window. Narrowing it would break the
// chain verification that makes the bundle worth anything — a hash chain
// filtered by content is not a chain. The scope is expressed by what the
// bundle asserts, not by what it withholds.
func (s *Store) ExportScopedEvidence(
	ctx context.Context,
	controlPubPEM, server string,
	framework controls.Framework,
	p auditlayer.Period,
	now time.Time,
) (*evidence.Bundle, error) {
	assessment, err := s.AssessPeriod(ctx, framework, p, now)
	if err != nil {
		return nil, err
	}

	scope := fmt.Sprintf("%s over %s", controls.FrameworkTitle(framework), p.Name)
	b, err := s.ExportEvidence(ctx, controlPubPEM, server, scope, "", 0)
	if err != nil {
		return nil, err
	}

	summaries := make([]evidence.ControlSummary, 0, len(assessment.Controls))
	for _, cs := range assessment.Controls {
		summary := evidence.ControlSummary{
			ID: string(cs.Control.ID), Title: cs.Control.Title,
			Coverage: string(cs.Control.Coverage), Status: string(cs.Status),
			Statement: cs.Statement, Note: cs.Control.Note,
			AuditEntries: cs.Evidence.AuditEntries,
			Alerts:       cs.Evidence.Alerts,
			OpenAtEnd:    cs.Evidence.OpenAtEnd,
			Commands:     cs.Evidence.Commands,
		}
		for _, e := range cs.Exceptions {
			summary.Exceptions = append(summary.Exceptions, evidence.ExceptionRecord{
				ID: e.ID, Reason: e.Reason, Remediation: e.Remediation, Owner: e.Owner,
				OpenedAt: e.OpenedAt, OpenedBy: e.OpenedBy,
				ExpiresAt: e.ExpiresAt, ClosedAt: e.ClosedAt,
			})
		}
		summaries = append(summaries, summary)
	}
	evidence.SortControlSummaries(summaries)

	b.Compliance = &evidence.ComplianceScope{
		Framework:      string(framework),
		FrameworkTitle: controls.FrameworkTitle(framework),
		PeriodID:       p.ID,
		PeriodName:     p.Name,
		From:           p.StartsAt,
		To:             p.EndsAt,
		Controls:       summaries,
		Caveats:        assessment.Caveats,
		Provenance:     evidence.ComplianceProvenance,
	}
	return b, nil
}
