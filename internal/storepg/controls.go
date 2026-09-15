package storepg

import (
	"context"
	"fmt"

	"defendsec/internal/controls"
)

// The control catalog lives in Go and is materialised here so it can be
// joined in SQL. The Go registry stays the single source of truth: this table
// is rebuilt from it, never edited in place, so a row that somebody changed by
// hand is replaced on the next start rather than silently outliving the code.

// SyncControlCatalog replaces the materialised catalog with the compiled-in
// one. It runs inside a transaction, so a reader either sees the whole old
// catalog or the whole new one and never a half-written mixture.
func (s *Store) SyncControlCatalog(ctx context.Context) (int, error) {
	catalog := controls.Catalog()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Serialise against another instance starting at the same moment, which
	// would otherwise interleave the delete and the inserts.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('defendsec:control_catalog'))`); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM control_catalog`); err != nil {
		return 0, err
	}
	for _, c := range catalog {
		signals := make([]string, len(c.Signals))
		for i, sig := range c.Signals {
			signals[i] = string(sig)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO control_catalog (id, framework, control, title, family, coverage, note, signals, derived_from)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		`, string(c.ID), string(c.ID.Framework()), c.ID.Control(), c.Title, c.Family,
			string(c.Coverage), c.Note, controlIDs(signals),
			controlIDs(controls.Strings(c.DerivedFrom))); err != nil {
			return 0, fmt.Errorf("sync control %s: %w", c.ID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return len(catalog), nil
}

// ControlRecordCounts is how many tagged records reference each control in a
// window. It answers the compliance view's first question — is there anything
// behind this control at all — without pulling the records themselves.
type ControlRecordCounts struct {
	ControlID    string `json:"controlId"`
	Alerts       int    `json:"alerts"`
	OpenAlerts   int    `json:"openAlerts"`
	Commands     int    `json:"commands"`
	AuditEntries int    `json:"auditEntries"`
}

// CountControlRecords counts tagged records per control between from and to.
//
// The bounds are half-open, [from, to): an audit period that ends at midnight
// must not also count the first record of the next day, and two adjacent
// periods must not both claim a record on the boundary.
func (s *Store) CountControlRecords(ctx context.Context, from, to string) (map[string]ControlRecordCounts, error) {
	out := map[string]ControlRecordCounts{}

	bump := func(id string, f func(*ControlRecordCounts)) {
		c := out[id]
		c.ControlID = id
		f(&c)
		out[id] = c
	}

	rows, err := s.pool.Query(ctx, `
		SELECT unnest(control_ids) AS control_id,
		       count(*) AS total,
		       count(*) FILTER (WHERE status = 'open') AS open
		FROM alerts
		WHERE COALESCE(detected_at, created_at) >= $1::timestamptz
		  AND COALESCE(detected_at, created_at) <  $2::timestamptz
		GROUP BY 1
	`, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id string
		var total, open int
		if err := rows.Scan(&id, &total, &open); err != nil {
			rows.Close()
			return nil, err
		}
		bump(id, func(c *ControlRecordCounts) { c.Alerts = total; c.OpenAlerts = open })
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, q := range []struct {
		sql   string
		apply func(*ControlRecordCounts, int)
	}{
		{`SELECT unnest(control_ids), count(*) FROM commands
		   WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz GROUP BY 1`,
			func(c *ControlRecordCounts, n int) { c.Commands = n }},
		{`SELECT unnest(control_ids), count(*) FROM audit_log
		   WHERE at >= $1::timestamptz AND at < $2::timestamptz GROUP BY 1`,
			func(c *ControlRecordCounts, n int) { c.AuditEntries = n }},
	} {
		rows, err := s.pool.Query(ctx, q.sql, from, to)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var n int
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return nil, err
			}
			apply := q.apply
			bump(id, func(c *ControlRecordCounts) { apply(c, n) })
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
