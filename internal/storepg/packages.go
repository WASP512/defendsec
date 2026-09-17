package storepg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"defendsec/internal/presence"
)

// Package change history (roadmap 4.3).
//
// Software inventory is a snapshot overwritten on every heartbeat, so the
// question triage needs — "did anything upgrade this package, and when?" — had
// no answer in stored data. These rows are that answer.

// PackageChange is one recorded version transition.
type PackageChange struct {
	ID              string `json:"id"`
	DeviceID        string `json:"deviceId"`
	Hostname        string `json:"hostname,omitempty"`
	Package         string `json:"package"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	NewVersion      string `json:"newVersion,omitempty"`
	// ObservedAt is when DefendSec noticed, not when the upgrade happened.
	// Inventory arrives on a heartbeat interval, so the real change is
	// somewhere in the preceding window.
	ObservedAt time.Time `json:"observedAt"`
}

// Upgrade reports a version change rather than an install or a removal.
func (c PackageChange) Upgrade() bool {
	return c.PreviousVersion != "" && c.NewVersion != "" && c.PreviousVersion != c.NewVersion
}

// RecordPackageChanges appends observed transitions.
//
// Best-effort by design: this is triage context, and failing a host's
// heartbeat because its package history could not be written would trade the
// security function for a nicety.
func (s *Store) RecordPackageChanges(ctx context.Context, deviceID, hostname string, changes []presence.PackageChange) error {
	if len(changes) == 0 {
		return nil
	}
	now := time.Now().UTC()
	batch := make([][]any, 0, len(changes))
	for _, c := range changes {
		var raw [12]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return err
		}
		batch = append(batch, []any{
			hex.EncodeToString(raw[:]), deviceID, hostname,
			c.Package, c.PreviousVersion, c.NewVersion, now,
		})
	}
	for _, row := range batch {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO package_changes
				(id, device_id, hostname, package, previous_version, new_version, observed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
		`, row...); err != nil {
			return err
		}
	}
	return nil
}

// PackageChangesSince returns a host's transitions observed at or after a
// moment, newest first.
func (s *Store) PackageChangesSince(ctx context.Context, deviceID string, since time.Time) ([]PackageChange, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, hostname, package, previous_version, new_version, observed_at
		FROM package_changes
		WHERE device_id=$1 AND observed_at >= $2
		ORDER BY observed_at DESC
	`, deviceID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PackageChange
	for rows.Next() {
		var c PackageChange
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.Hostname, &c.Package,
			&c.PreviousVersion, &c.NewVersion, &c.ObservedAt); err != nil {
			return nil, err
		}
		c.ObservedAt = c.ObservedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// RecentPackageChanges returns a host's most recent transitions.
func (s *Store) RecentPackageChanges(ctx context.Context, deviceID string, limit int) ([]PackageChange, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, hostname, package, previous_version, new_version, observed_at
		FROM package_changes
		WHERE device_id=$1
		ORDER BY observed_at DESC
		LIMIT $2
	`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PackageChange
	for rows.Next() {
		var c PackageChange
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.Hostname, &c.Package,
			&c.PreviousVersion, &c.NewVersion, &c.ObservedAt); err != nil {
			return nil, err
		}
		c.ObservedAt = c.ObservedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}
