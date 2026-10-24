package storepg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/lifecycle"
)

// Store implements lifecycle.Source, so the end-of-life judgement runs straight
// off the release calendar the endoflife feed loaded.
var _ lifecycle.Source = (*Store)(nil)

// EOLFeedName is the feed that loads the release calendar.
const EOLFeedName = "endoflife"

// EOLRow is one release cycle to load. Dates are "YYYY-MM-DD" or "".
type EOLRow struct {
	Product, Label, Cycle                    string
	ReleaseDate, EoasFrom, EolFrom, EoesFrom string
	IsEol, IsLTS                             bool
	Latest, Link                             string
}

// ApplyEOL replaces the release calendar with rows. An empty set is refused: it
// would make every product look supported. snapshotID (0 for none) is the feed
// snapshot the rows belong to.
func (s *Store) ApplyEOL(ctx context.Context, rows []EOLRow, snapshotID int64) (int, error) {
	if len(rows) == 0 {
		return 0, errors.New("refusing to apply an empty end-of-life calendar (it would make every release look supported)")
	}
	var snap *int64
	if snapshotID != 0 {
		snap = &snapshotID
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM eol_releases`); err != nil {
		return 0, fmt.Errorf("clear eol_releases: %w", err)
	}
	batch := &pgx.Batch{}
	for _, r := range rows {
		batch.Queue(`
			INSERT INTO eol_releases (product, cycle, label, release_date, eoas_from, eol_from, eoes_from,
			                          is_eol, is_lts, latest, link, snapshot_id)
			VALUES ($1, $2, $3, NULLIF($4,'')::date, NULLIF($5,'')::date, NULLIF($6,'')::date, NULLIF($7,'')::date,
			        $8, $9, $10, $11, $12)
			ON CONFLICT (product, cycle) DO NOTHING`,
			r.Product, r.Cycle, r.Label, r.ReleaseDate, r.EoasFrom, r.EolFrom, r.EoesFrom, r.IsEol, r.IsLTS, r.Latest, r.Link, snap)
	}
	br := tx.SendBatch(ctx, batch)
	for range rows {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return 0, fmt.Errorf("insert eol_releases: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM eol_releases`).Scan(&n); err != nil {
		return 0, err
	}
	return n, tx.Commit(ctx)
}

// EOLReleases implements lifecycle.Source: every release cycle of the given
// products, each stamped with the feed fetch it came from.
func (s *Store) EOLReleases(ctx context.Context, products []string) ([]lifecycle.Release, error) {
	if len(products) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT product, cycle, label, COALESCE(release_date::text,''), COALESCE(eoas_from::text,''),
		       COALESCE(eol_from::text,''), COALESCE(eoes_from::text,''), is_eol, is_lts, latest, link, snapshot_id
		FROM eol_releases WHERE product = ANY($1) ORDER BY product, cycle`, products)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []lifecycle.Release
	for rows.Next() {
		var r lifecycle.Release
		if err := rows.Scan(&r.Product, &r.Cycle, &r.Label, &r.ReleaseDate, &r.EoasFrom, &r.EolFrom, &r.EoesFrom,
			&r.IsEol, &r.IsLTS, &r.Latest, &r.Link, &r.SnapshotID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, s.stampEOLDates(ctx, out)
}

// EOLProducts lists the products the stored calendar holds.
func (s *Store) EOLProducts(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT product FROM eol_releases ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// stampEOLDates fills in each release's feed date from the snapshot that
// loaded it, as stampFeedDates does for advisory ranges.
func (s *Store) stampEOLDates(ctx context.Context, rels []lifecycle.Release) error {
	dates := map[int64]time.Time{}
	for i := range rels {
		r := &rels[i]
		if r.SnapshotID == nil {
			continue
		}
		at, ok := dates[*r.SnapshotID]
		if !ok {
			snap, err := s.GetFeedSnapshot(ctx, *r.SnapshotID)
			if err != nil {
				return fmt.Errorf("snapshot %d: %w", *r.SnapshotID, err)
			}
			at = snap.CreatedAt
			for _, f := range snap.Feeds {
				if f.Name == EOLFeedName {
					at = f.FetchedAt
				}
			}
			at = at.UTC()
			dates[*r.SnapshotID] = at
		}
		t := at
		r.FeedDate = &t
	}
	return nil
}
