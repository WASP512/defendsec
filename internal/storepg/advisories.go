package storepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Advisory data model (migration 019). The legacy single-floor methods
// (UpsertAdvisory / ListAdvisories in store.go) are unchanged; the matcher
// still reads those until the distro-aware matcher lands.

// FixState is what a distro or upstream says about a (package, range).
type FixState string

const (
	FixStateAffected           FixState = "affected"
	FixStateFixed              FixState = "fixed"
	FixStateWillNotFix         FixState = "will_not_fix"
	FixStateNotAffected        FixState = "not_affected"
	FixStateUnderInvestigation FixState = "under_investigation"
)

func (f FixState) valid() bool {
	switch f {
	case FixStateAffected, FixStateFixed, FixStateWillNotFix, FixStateNotAffected, FixStateUnderInvestigation:
		return true
	}
	return false
}

// legacyEcosystem marks ranges mirrored from advisories.package/below by the
// migration trigger. Callers may not write it.
const legacyEcosystem = "legacy"

// FeedRef records one fetched feed inside a snapshot.
type FeedRef struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	FetchedAt   time.Time `json:"fetched_at"`
	SHA256      string    `json:"sha256"`
	RecordCount int       `json:"record_count"`
}

// FeedSnapshot is one sync run. Findings reference its ID so a result can be
// reproduced against the exact feed digests it was computed from.
type FeedSnapshot struct {
	ID        int64
	CreatedAt time.Time
	Feeds     []FeedRef
}

// AdvisoryRange is one affected range. Empty strings are stored as NULL for
// Distro, Release, SourcePackage, Introduced and Fixed: an empty Distro means
// "not distro-specific", an empty Release means "every release of Distro",
// an empty Introduced means "from the first version" and an empty Fixed means
// "no fix published".
type AdvisoryRange struct {
	ID            int64
	AdvisoryID    string
	Ecosystem     string
	Distro        string
	Release       string
	Package       string
	SourcePackage string
	Introduced    string
	Fixed         string
	FixState      FixState
	SnapshotID    *int64
	// Issued is the calendar date (YYYY-MM-DD) the vendor published the erratum
	// behind the range; empty when the feed does not say.
	Issued string
	// Feed names the feed that loaded the range ("ubuntu-jammy"); empty for
	// ranges loaded before the column existed.
	Feed string
}

// Advisory is one vulnerability record with its ranges. Dates are calendar
// dates (the time-of-day is ignored).
type Advisory struct {
	ID         string
	CVE        string
	Summary    string
	Severity   string
	Source     string
	CVSSVector string
	CVSSScore  *float64
	CWE        []string
	KEV        bool
	KEVAdded   *time.Time
	EPSS       *float64
	EPSSDate   *time.Time
	SnapshotID *int64
	UpdatedAt  time.Time
	Ranges     []AdvisoryRange
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (f FeedRef) validate() error {
	switch {
	case strings.TrimSpace(f.Name) == "":
		return errors.New("feed name is required")
	case strings.TrimSpace(f.URL) == "":
		return fmt.Errorf("feed %q: url is required", f.Name)
	case f.FetchedAt.IsZero():
		return fmt.Errorf("feed %q: fetched_at is required", f.Name)
	case !sha256Hex.MatchString(f.SHA256):
		return fmt.Errorf("feed %q: sha256 must be 64 lowercase hex characters", f.Name)
	case f.RecordCount < 0:
		return fmt.Errorf("feed %q: record_count must not be negative", f.Name)
	}
	return nil
}

// validate checks everything the database would reject, plus what it cannot
// express, so callers get a specific error before any row is written.
func (a Advisory) validate() error {
	if strings.TrimSpace(a.ID) == "" {
		return errors.New("advisory id is required")
	}
	if strings.TrimSpace(a.Severity) == "" {
		return fmt.Errorf("advisory %s: severity is required", a.ID)
	}
	if a.CVSSScore != nil && (*a.CVSSScore < 0 || *a.CVSSScore > 10) {
		return fmt.Errorf("advisory %s: cvss_score %v outside 0..10", a.ID, *a.CVSSScore)
	}
	if a.EPSS != nil && (*a.EPSS < 0 || *a.EPSS > 1) {
		return fmt.Errorf("advisory %s: epss %v outside 0..1", a.ID, *a.EPSS)
	}
	seen := make(map[string]int, len(a.Ranges))
	for i, r := range a.Ranges {
		if err := r.validate(); err != nil {
			return fmt.Errorf("advisory %s range %d: %w", a.ID, i, err)
		}
		k := r.identity()
		if j, dup := seen[k]; dup {
			return fmt.Errorf("advisory %s: range %d duplicates range %d", a.ID, i, j)
		}
		seen[k] = i
	}
	return nil
}

func (r AdvisoryRange) validate() error {
	switch {
	case strings.TrimSpace(r.Package) == "":
		return errors.New("package is required")
	case !r.FixState.valid():
		return fmt.Errorf("fix_state %q is not one of affected, fixed, will_not_fix, not_affected, under_investigation", r.FixState)
	case r.FixState == FixStateFixed && r.Fixed == "":
		return errors.New("fix_state fixed requires a fixed version")
	case r.Release != "" && r.Distro == "":
		return errors.New("release requires distro")
	case r.Ecosystem == legacyEcosystem:
		return fmt.Errorf("ecosystem %q is reserved", legacyEcosystem)
	}
	return nil
}

// identity mirrors the unique index advisory_ranges_identity_idx.
func (r AdvisoryRange) identity() string {
	return strings.Join([]string{r.Ecosystem, r.Distro, r.Release, r.Package, r.Introduced, r.Fixed}, "\x00")
}

// nullable maps "" to SQL NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

const (
	insertSnapshotSQL = `INSERT INTO feed_snapshots (feeds) VALUES ($1::jsonb) RETURNING id, created_at`

	// Takes over the whole advisory: the legacy floor columns are cleared, so
	// the migration trigger drops the mirrored legacy range, and the caller's
	// ranges replace everything else.
	upsertAdvisorySQL = `
		INSERT INTO advisories (
			id, cve, package, below, severity, summary, source,
			cvss_vector, cvss_score, cwe, kev, kev_added, epss, epss_date, snapshot_id, updated_at
		) VALUES ($1,$2,'','',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now())
		ON CONFLICT (id) DO UPDATE SET
			cve=EXCLUDED.cve, package='', below='', severity=EXCLUDED.severity,
			summary=EXCLUDED.summary, source=EXCLUDED.source,
			cvss_vector=EXCLUDED.cvss_vector, cvss_score=EXCLUDED.cvss_score, cwe=EXCLUDED.cwe,
			kev=EXCLUDED.kev, kev_added=EXCLUDED.kev_added,
			epss=EXCLUDED.epss, epss_date=EXCLUDED.epss_date,
			snapshot_id=EXCLUDED.snapshot_id, updated_at=now()`

	deleteRangesSQL = `DELETE FROM advisory_ranges WHERE advisory_id = $1`

	insertRangeSQL = `
		INSERT INTO advisory_ranges (
			advisory_id, ecosystem, distro, release, package, source_package,
			introduced, fixed, fix_state, snapshot_id, feed, issued
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, NULLIF($12::text, '')::date)`

	rangeColumns = `r.id, r.advisory_id, r.ecosystem, COALESCE(r.distro,''), COALESCE(r.release,''),
		r.package, COALESCE(r.source_package,''), COALESCE(r.introduced,''), COALESCE(r.fixed,''),
		r.fix_state, r.snapshot_id, r.feed, COALESCE(r.issued::text,'')`

	// A range matches when its binary or source package is the one asked for
	// and it applies to the distro/release: the same distro with the same (or
	// any) release, or, if $4, a range that is not distro-specific.
	listRangesSQL = `
		SELECT ` + rangeColumns + `
		FROM advisory_ranges r
		WHERE (r.package = $3 OR r.source_package = $3)
		  AND ((r.distro = $1 AND (r.release = $2 OR r.release IS NULL))
		       OR ($4 AND r.distro IS NULL))
		ORDER BY r.advisory_id, r.id`

	getAdvisorySQL = `
		SELECT id, cve, severity, summary, source, cvss_vector, cvss_score, cwe,
		       kev, kev_added, epss, epss_date, snapshot_id, updated_at
		FROM advisories WHERE id = $1`

	getRangesSQL = `SELECT ` + rangeColumns + ` FROM advisory_ranges r WHERE r.advisory_id = $1 ORDER BY r.id`
)

// RecordFeedSnapshot stores one snapshot describing the feeds a sync used and
// returns it with its assigned ID and creation time.
func (s *Store) RecordFeedSnapshot(ctx context.Context, feeds []FeedRef) (FeedSnapshot, error) {
	if len(feeds) == 0 {
		return FeedSnapshot{}, errors.New("a snapshot needs at least one feed")
	}
	for _, f := range feeds {
		if err := f.validate(); err != nil {
			return FeedSnapshot{}, err
		}
	}
	// Normalise to UTC so the stored digest record does not depend on the
	// zone of the host that fetched.
	norm := make([]FeedRef, len(feeds))
	for i, f := range feeds {
		f.FetchedAt = f.FetchedAt.UTC()
		norm[i] = f
	}
	raw, err := json.Marshal(norm)
	if err != nil {
		return FeedSnapshot{}, err
	}
	snap := FeedSnapshot{Feeds: norm}
	if err := s.pool.QueryRow(ctx, insertSnapshotSQL, string(raw)).Scan(&snap.ID, &snap.CreatedAt); err != nil {
		return FeedSnapshot{}, fmt.Errorf("record feed snapshot: %w", err)
	}
	return snap, nil
}

// GetFeedSnapshot loads a snapshot by ID. It returns pgx.ErrNoRows if absent.
func (s *Store) GetFeedSnapshot(ctx context.Context, id int64) (FeedSnapshot, error) {
	var snap FeedSnapshot
	var raw []byte
	if err := s.pool.QueryRow(ctx, `SELECT id, created_at, feeds FROM feed_snapshots WHERE id = $1`, id).
		Scan(&snap.ID, &snap.CreatedAt, &raw); err != nil {
		return FeedSnapshot{}, err
	}
	if err := json.Unmarshal(raw, &snap.Feeds); err != nil {
		return FeedSnapshot{}, fmt.Errorf("decode snapshot %d feeds: %w", id, err)
	}
	return snap, nil
}

// UpsertAdvisoryWithRanges writes the advisory and replaces its full range set
// in one transaction. Ranges are replaced, not merged: whatever the caller
// passes is the complete current truth for that advisory. Any legacy
// package/below floor on the row is cleared. a.UpdatedAt and the Range IDs
// and AdvisoryIDs are ignored; ranges inherit a.SnapshotID unless they set
// their own.
func (s *Store) UpsertAdvisoryWithRanges(ctx context.Context, a Advisory) error {
	if err := a.validate(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	cwe := a.CWE
	if cwe == nil {
		cwe = []string{}
	}
	if _, err := tx.Exec(ctx, upsertAdvisorySQL,
		a.ID, a.CVE, a.Severity, a.Summary, sourceOrLocal(a.Source),
		a.CVSSVector, a.CVSSScore, cwe, a.KEV, a.KEVAdded, a.EPSS, a.EPSSDate, a.SnapshotID); err != nil {
		return fmt.Errorf("upsert advisory %s: %w", a.ID, err)
	}
	if _, err := tx.Exec(ctx, deleteRangesSQL, a.ID); err != nil {
		return fmt.Errorf("clear ranges for %s: %w", a.ID, err)
	}
	batch := &pgx.Batch{}
	for _, r := range a.Ranges {
		snap := r.SnapshotID
		if snap == nil {
			snap = a.SnapshotID
		}
		batch.Queue(insertRangeSQL, a.ID, r.Ecosystem, nullable(r.Distro), nullable(r.Release),
			r.Package, nullable(r.SourcePackage), nullable(r.Introduced), nullable(r.Fixed),
			string(r.FixState), snap, sourceOrLocal(a.Source), r.Issued)
	}
	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := range a.Ranges {
			if _, err := br.Exec(); err != nil {
				br.Close() //nolint:errcheck
				return fmt.Errorf("insert range %d for %s: %w", i, a.ID, err)
			}
		}
		if err := br.Close(); err != nil {
			return fmt.Errorf("insert ranges for %s: %w", a.ID, err)
		}
	}
	return tx.Commit(ctx)
}

func sourceOrLocal(s string) string {
	if s == "" {
		return "local"
	}
	return s
}

// RangeQuery selects ranges for one installed package on one distro release.
// Package is matched against both the binary and the source package name.
type RangeQuery struct {
	Distro  string
	Release string
	Package string
	// IncludeDistroAgnostic also returns ranges with no distro (upstream and
	// legacy floors). Whether those are trustworthy for a distro package is a
	// matcher decision, so the store does not default it on.
	IncludeDistroAgnostic bool
}

// ListAdvisoryRanges returns the ranges that apply to q, ordered by advisory.
func (s *Store) ListAdvisoryRanges(ctx context.Context, q RangeQuery) ([]AdvisoryRange, error) {
	if q.Package == "" {
		return nil, errors.New("package is required")
	}
	if q.Distro == "" && !q.IncludeDistroAgnostic {
		return nil, errors.New("distro is required unless IncludeDistroAgnostic is set")
	}
	rows, err := s.pool.Query(ctx, listRangesSQL, q.Distro, q.Release, q.Package, q.IncludeDistroAgnostic)
	if err != nil {
		return nil, err
	}
	return scanRanges(rows)
}

func scanRanges(rows pgx.Rows) ([]AdvisoryRange, error) {
	defer rows.Close()
	var out []AdvisoryRange
	for rows.Next() {
		var r AdvisoryRange
		var state string
		if err := rows.Scan(&r.ID, &r.AdvisoryID, &r.Ecosystem, &r.Distro, &r.Release,
			&r.Package, &r.SourcePackage, &r.Introduced, &r.Fixed, &state, &r.SnapshotID, &r.Feed, &r.Issued); err != nil {
			return nil, err
		}
		r.FixState = FixState(state)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetAdvisory loads one advisory with all of its ranges. It returns
// pgx.ErrNoRows if the advisory does not exist.
func (s *Store) GetAdvisory(ctx context.Context, id string) (Advisory, error) {
	var a Advisory
	if err := s.pool.QueryRow(ctx, getAdvisorySQL, id).Scan(
		&a.ID, &a.CVE, &a.Severity, &a.Summary, &a.Source, &a.CVSSVector, &a.CVSSScore, &a.CWE,
		&a.KEV, &a.KEVAdded, &a.EPSS, &a.EPSSDate, &a.SnapshotID, &a.UpdatedAt); err != nil {
		return Advisory{}, err
	}
	rows, err := s.pool.Query(ctx, getRangesSQL, id)
	if err != nil {
		return Advisory{}, err
	}
	if a.Ranges, err = scanRanges(rows); err != nil {
		return Advisory{}, err
	}
	return a, nil
}
