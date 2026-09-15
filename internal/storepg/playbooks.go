package storepg

import (
	"context"
	"time"
)

// Storage for playbook runs (roadmap 2.5-2.6).

// PlaybookRun records one execution of a sequence.
type PlaybookRun struct {
	ID           string            `json:"id"`
	PlaybookID   string            `json:"playbookId"`
	PlaybookHash string            `json:"playbookHash,omitempty"`
	DeviceID     string            `json:"deviceId,omitempty"`
	Hostname     string            `json:"hostname,omitempty"`
	StartedAt    time.Time         `json:"startedAt"`
	FinishedAt   *time.Time        `json:"finishedAt,omitempty"`
	Status       string            `json:"status"`
	Origin       string            `json:"origin"`
	Actor        string            `json:"actor,omitempty"`
	AlertID      string            `json:"alertId,omitempty"`
	Detail       string            `json:"detail,omitempty"`
	Steps        []PlaybookRunStep `json:"steps,omitempty"`
}

// PlaybookRunStep is one step's outcome.
type PlaybookRunStep struct {
	Position    int       `json:"position"`
	StepID      string    `json:"stepId"`
	CommandType string    `json:"commandType"`
	Status      string    `json:"status"`
	CommandID   string    `json:"commandId,omitempty"`
	PendingID   string    `json:"pendingId,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	At          time.Time `json:"at"`
}

// StartPlaybookRun opens a run record.
func (s *Store) StartPlaybookRun(ctx context.Context, r PlaybookRun) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO playbook_runs
			(id, playbook_id, playbook_hash, device_id, hostname, started_at, status, origin, actor, alert_id)
		VALUES ($1,$2,$3,$4,$5,$6,'running',$7,$8,$9)
	`, r.ID, r.PlaybookID, r.PlaybookHash, r.DeviceID, r.Hostname,
		r.StartedAt, r.Origin, r.Actor, r.AlertID)
	return err
}

// RecordPlaybookStep appends a step outcome.
func (s *Store) RecordPlaybookStep(ctx context.Context, runID string, step PlaybookRunStep) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO playbook_run_steps
			(run_id, position, step_id, command_type, status, command_id, pending_id, detail, at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (run_id, position) DO NOTHING
	`, runID, step.Position, step.StepID, step.CommandType, step.Status,
		step.CommandID, step.PendingID, step.Detail, step.At)
	return err
}

// FinishPlaybookRun closes a run.
func (s *Store) FinishPlaybookRun(ctx context.Context, runID, status, detail string, at time.Time) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE playbook_runs SET status=$2, detail=$3, finished_at=$4 WHERE id=$1`,
		runID, status, detail, at)
	return err
}

// ListPlaybookRuns returns runs with their steps, newest first.
func (s *Store) ListPlaybookRuns(ctx context.Context, limit int) ([]PlaybookRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, playbook_id, playbook_hash, device_id, hostname, started_at,
		       finished_at, status, origin, actor, alert_id, detail
		FROM playbook_runs ORDER BY started_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlaybookRun{}
	for rows.Next() {
		var r PlaybookRun
		var finished *time.Time
		if err := rows.Scan(&r.ID, &r.PlaybookID, &r.PlaybookHash, &r.DeviceID,
			&r.Hostname, &r.StartedAt, &finished, &r.Status, &r.Origin,
			&r.Actor, &r.AlertID, &r.Detail); err != nil {
			return nil, err
		}
		r.StartedAt = r.StartedAt.UTC()
		if finished != nil {
			utc := finished.UTC()
			r.FinishedAt = &utc
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Steps, err = s.playbookRunSteps(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) playbookRunSteps(ctx context.Context, runID string) ([]PlaybookRunStep, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT position, step_id, command_type, status, command_id, pending_id, detail, at
		FROM playbook_run_steps WHERE run_id=$1 ORDER BY position
	`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PlaybookRunStep{}
	for rows.Next() {
		var st PlaybookRunStep
		if err := rows.Scan(&st.Position, &st.StepID, &st.CommandType, &st.Status,
			&st.CommandID, &st.PendingID, &st.Detail, &st.At); err != nil {
			return nil, err
		}
		st.At = st.At.UTC()
		out = append(out, st)
	}
	return out, rows.Err()
}

// CountRecentAutomaticRuns is how many automatic runs of a playbook have
// started against a host recently.
//
// This is a second brake, independent of policy's blast-radius limits. A
// playbook that triggers on a finding it also causes would otherwise loop: FIM
// detects a change, the playbook quarantines the file, quarantining changes
// the filesystem, FIM detects that. Policy limits would eventually stop it,
// but only after spending the fleet-wide budget that a real incident needs.
func (s *Store) CountRecentAutomaticRuns(ctx context.Context, playbookID, deviceID string, since time.Time) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM playbook_runs
		WHERE playbook_id=$1 AND device_id=$2 AND origin='automatic' AND started_at >= $3
	`, playbookID, deviceID, since).Scan(&n)
	return n, err
}
