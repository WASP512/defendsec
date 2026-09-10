package storepg

import (
	"context"
	"encoding/json"
	"time"
)

type Alert struct {
	ID         string
	CreatedAt  string
	UpdatedAt  string
	DeviceID   string
	Hostname   string
	Kind       string
	Severity   string
	Title      string
	Summary    string
	Status     string
	SourceType string
	SourceID   string
	Detail     json.RawMessage
}

type AlertFilters struct {
	Status   string
	Kind     string
	DeviceID string
	Limit    int
}

func (s *Store) InsertAlert(ctx context.Context, a Alert) error {
	detail := a.Detail
	if len(detail) == 0 {
		detail = []byte("{}")
	}
	created := a.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	updated := a.UpdatedAt
	if updated == "" {
		updated = created
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO alerts (
			id, created_at, updated_at, device_id, hostname, kind, severity,
			title, summary, status, source_type, source_id, detail
		) VALUES (
			$1, $2::timestamptz, $3::timestamptz, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13::jsonb
		)
		ON CONFLICT (id) DO NOTHING
	`, a.ID, created, updated, a.DeviceID, a.Hostname, a.Kind, a.Severity,
		a.Title, a.Summary, a.Status, a.SourceType, a.SourceID, string(detail))
	return err
}

func (s *Store) ListAlerts(ctx context.Context, f AlertFilters) ([]Alert, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, created_at, updated_at, device_id, hostname, kind, severity,
		       title, summary, status, source_type, source_id, detail
		FROM alerts
		WHERE ($1 = '' OR status = $1)
		  AND ($2 = '' OR kind = $2)
		  AND ($3 = '' OR device_id = $3)
		ORDER BY created_at DESC
		LIMIT $4
	`, f.Status, f.Kind, f.DeviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var created, updated time.Time
		var detail []byte
		if err := rows.Scan(
			&a.ID, &created, &updated, &a.DeviceID, &a.Hostname, &a.Kind, &a.Severity,
			&a.Title, &a.Summary, &a.Status, &a.SourceType, &a.SourceID, &detail,
		); err != nil {
			return nil, err
		}
		a.CreatedAt = created.UTC().Format(time.RFC3339)
		a.UpdatedAt = updated.UTC().Format(time.RFC3339)
		a.Detail = detail
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) UpdateAlertStatus(ctx context.Context, id, status string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status=$2, updated_at=now() WHERE id=$1
	`, id, status)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) HasOpenAlert(ctx context.Context, deviceID, kind, sourceID string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT COUNT(1) FROM alerts
		WHERE device_id=$1 AND kind=$2 AND source_id=$3 AND status IN ('open', 'acknowledged')
	`, deviceID, kind, sourceID).Scan(&n)
	return n > 0, err
}

func (s *Store) ResolveOpenAlerts(ctx context.Context, deviceID, kind, sourceID string) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE alerts SET status='resolved', updated_at=now()
		WHERE device_id=$1 AND kind=$2 AND source_id=$3 AND status IN ('open', 'acknowledged')
	`, deviceID, kind, sourceID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
