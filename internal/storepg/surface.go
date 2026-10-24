package storepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/evidence"
	"defendsec/internal/surface"
)

// External surface scanner storage (slice 7a). See db/migrations/023_surface.sql.

var (
	// ErrNoSurfaceAsset is returned for an unknown or removed asset.
	ErrNoSurfaceAsset = errors.New("surface asset not found")
	// ErrSurfaceAssetExists is returned when an active asset has that value.
	ErrSurfaceAssetExists = errors.New("surface asset already declared")
	// ErrSurfaceAssetNotAuthorised is returned when recording a scan of an
	// asset that is not (or is no longer) confirmed as authorised.
	ErrSurfaceAssetNotAuthorised = errors.New("surface asset is not confirmed as authorised to test")
)

// SurfaceAsset is a declared asset.
type SurfaceAsset struct {
	ID            int64      `json:"id"`
	Kind          string     `json:"kind"`
	Value         string     `json:"value"`
	Label         string     `json:"label"`
	DKIMSelectors []string   `json:"dkimSelectors"`
	SharedHosting bool       `json:"sharedHosting"`
	MailHost      bool       `json:"mailHost"`
	Authorised    bool       `json:"authorised"`
	AuthorisedBy  string     `json:"authorisedBy"`
	AuthorisedAt  *time.Time `json:"authorisedAt"`
	CreatedBy     string     `json:"createdBy"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastScanAt    *time.Time `json:"lastScanAt"`
}

// ScanAsset converts the row into what the scanner takes.
func (a SurfaceAsset) ScanAsset() surface.Asset {
	return surface.Asset{
		ID: a.ID, Kind: surface.Kind(a.Kind), Value: a.Value, Label: a.Label,
		DKIMSelectors: a.DKIMSelectors, SharedHosting: a.SharedHosting, MailHost: a.MailHost,
		Authorised: a.Authorised,
	}
}

// SurfaceAssetInput is what declaring an asset takes. Kind and Value must
// already be normalised (surface.NormaliseAsset).
type SurfaceAssetInput struct {
	Kind          string
	Value         string
	Label         string
	DKIMSelectors []string
	SharedHosting bool
	MailHost      bool
	// Authorised confirms the operator is authorised to test it; AuthorisedBy
	// is who said so.
	Authorised   bool
	AuthorisedBy string
	CreatedBy    string
}

const surfaceAssetColumns = `id, kind, value, label, dkim_selectors, shared_hosting, mail_host, authorised,
	authorised_by, authorised_at, created_by, created_at, last_scan_at`

func scanSurfaceAsset(row pgx.Row) (SurfaceAsset, error) {
	var a SurfaceAsset
	err := row.Scan(&a.ID, &a.Kind, &a.Value, &a.Label, &a.DKIMSelectors, &a.SharedHosting, &a.MailHost,
		&a.Authorised, &a.AuthorisedBy, &a.AuthorisedAt, &a.CreatedBy, &a.CreatedAt, &a.LastScanAt)
	if a.DKIMSelectors == nil {
		a.DKIMSelectors = []string{}
	}
	return a, err
}

// CreateSurfaceAsset declares an asset. Declaring a value that was removed
// reactivates the row (its findings and history come back with it) and, like a
// new declaration, takes the authorisation from the input: nothing carries
// over from before the removal.
func (s *Store) CreateSurfaceAsset(ctx context.Context, in SurfaceAssetInput) (SurfaceAsset, error) {
	if in.DKIMSelectors == nil {
		in.DKIMSelectors = []string{}
	}
	var at *time.Time
	by := ""
	if in.Authorised {
		now := time.Now().UTC()
		at, by = &now, in.AuthorisedBy
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO surface_assets (kind, value, label, dkim_selectors, shared_hosting, mail_host,
			authorised, authorised_by, authorised_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (kind, value) DO UPDATE SET
			label = EXCLUDED.label, dkim_selectors = EXCLUDED.dkim_selectors,
			shared_hosting = EXCLUDED.shared_hosting, mail_host = EXCLUDED.mail_host,
			authorised = EXCLUDED.authorised, authorised_by = EXCLUDED.authorised_by,
			authorised_at = EXCLUDED.authorised_at, created_by = EXCLUDED.created_by,
			removed_at = NULL
		WHERE surface_assets.removed_at IS NOT NULL
		RETURNING `+surfaceAssetColumns,
		in.Kind, in.Value, in.Label, in.DKIMSelectors, in.SharedHosting, in.MailHost,
		in.Authorised, by, at, in.CreatedBy)
	a, err := scanSurfaceAsset(row)
	if errors.Is(err, pgx.ErrNoRows) { // the conflict row is active: the WHERE refused the update
		return SurfaceAsset{}, ErrSurfaceAssetExists
	}
	return a, err
}

// ListSurfaceAssets returns the declared, not-removed assets.
func (s *Store) ListSurfaceAssets(ctx context.Context) ([]SurfaceAsset, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+surfaceAssetColumns+` FROM surface_assets
		WHERE removed_at IS NULL ORDER BY kind, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SurfaceAsset{}
	for rows.Next() {
		a, err := scanSurfaceAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetSurfaceAsset returns one not-removed asset.
func (s *Store) GetSurfaceAsset(ctx context.Context, id int64) (SurfaceAsset, error) {
	a, err := scanSurfaceAsset(s.pool.QueryRow(ctx, `SELECT `+surfaceAssetColumns+`
		FROM surface_assets WHERE id = $1 AND removed_at IS NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return SurfaceAsset{}, ErrNoSurfaceAsset
	}
	return a, err
}

// SetSurfaceAssetAuthorised gives or withdraws the authorisation.
func (s *Store) SetSurfaceAssetAuthorised(ctx context.Context, id int64, authorised bool, actor string) error {
	var at *time.Time
	by := ""
	if authorised {
		now := time.Now().UTC()
		at, by = &now, actor
	}
	tag, err := s.pool.Exec(ctx, `UPDATE surface_assets SET authorised = $2, authorised_by = $3, authorised_at = $4
		WHERE id = $1 AND removed_at IS NULL`, id, authorised, by, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSurfaceAsset
	}
	return nil
}

// RemoveSurfaceAsset stops scanning an asset and hides it. Its findings and
// observations stay.
func (s *Store) RemoveSurfaceAsset(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `UPDATE surface_assets SET removed_at = now(), authorised = false,
		authorised_by = '', authorised_at = NULL WHERE id = $1 AND removed_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNoSurfaceAsset
	}
	return nil
}

// SurfaceAssetsDue returns the authorised assets not scanned within olderThan.
func (s *Store) SurfaceAssetsDue(ctx context.Context, olderThan time.Duration) ([]SurfaceAsset, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+surfaceAssetColumns+` FROM surface_assets
		WHERE removed_at IS NULL AND authorised
		  AND (last_scan_at IS NULL OR last_scan_at < now() - make_interval(secs => $1))
		ORDER BY last_scan_at NULLS FIRST, id`, olderThan.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SurfaceAsset{}
	for rows.Next() {
		a, err := scanSurfaceAsset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SurfaceScanSummary is what recording a scan changed.
type SurfaceScanSummary struct {
	ScanID int64 `json:"scanId"`
	// Digest is the SHA-256 of the scan as stored (evidence.ScanDigest). It is
	// chained in the audit log by the same transaction that stored the scan.
	Digest            string `json:"digest"`
	New               int    `json:"new"`
	Reopened          int    `json:"reopened"`
	StillOpen         int    `json:"stillOpen"`
	Resolved          int    `json:"resolved"`
	Open              int    `json:"open"`
	ChecksAssessed    int    `json:"checksAssessed"`
	ChecksNotAssessed int    `json:"checksNotAssessed"`
}

func findingKey(id, subject string) string { return id + "\x01" + subject }

// RecordSurfaceScan stores a scan: the raw observation of every check, the
// findings with first-seen bookkeeping, and the resolution of findings that a
// successfully assessed check no longer sees. A check that was not assessed
// resolves nothing and refreshes nothing: its open findings keep the last_seen
// of the last scan that really confirmed them.
//
// It refuses an asset that is not currently authorised, so a revocation that
// lands mid-scan cannot leave fresh results behind.
func (s *Store) RecordSurfaceScan(ctx context.Context, assetID int64, trigger string, rep *surface.Report) (SurfaceScanSummary, error) {
	var sum SurfaceScanSummary
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return sum, err
	}
	defer tx.Rollback(ctx)

	var authorised bool
	err = tx.QueryRow(ctx, `SELECT authorised FROM surface_assets WHERE id = $1 AND removed_at IS NULL FOR UPDATE`, assetID).Scan(&authorised)
	if errors.Is(err, pgx.ErrNoRows) {
		return sum, ErrNoSurfaceAsset
	}
	if err != nil {
		return sum, err
	}
	if !authorised {
		return sum, ErrSurfaceAssetNotAuthorised
	}

	// timestamptz keeps microseconds: cut to them first, so the times hashed
	// into the scan's digest are the times read back at export.
	at := rep.FinishedAt.UTC().Round(time.Microsecond)
	startedAt := rep.StartedAt.UTC().Round(time.Microsecond)
	if err := tx.QueryRow(ctx, `INSERT INTO surface_scans (asset_id, triggered_by, started_at, finished_at)
		VALUES ($1,$2,$3,$4) RETURNING id`, assetID, trigger, startedAt, at).Scan(&sum.ScanID); err != nil {
		return sum, err
	}
	var assetKind, assetValue string
	if err := tx.QueryRow(ctx, `SELECT kind, value FROM surface_assets WHERE id = $1`, assetID).Scan(&assetKind, &assetValue); err != nil {
		return sum, err
	}
	scan := evidence.SurfaceScan{
		ScanID: sum.ScanID, AssetID: assetID, AssetKind: assetKind, AssetValue: assetValue,
		TriggeredBy: trigger, StartedAt: startedAt, FinishedAt: at,
		Observations: []evidence.SurfaceObservation{}, Changes: []evidence.SurfaceChange{},
	}

	for _, res := range rep.Results {
		observed := res.Observed
		if observed == nil {
			observed = map[string]any{}
		}
		raw, err := json.Marshal(observed)
		if err != nil {
			return sum, fmt.Errorf("observation of %s: %w", res.Check, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO surface_observations (scan_id, asset_id, check_group, assessed, reason, observed, observed_at)
			VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7)`, sum.ScanID, assetID, res.Check, res.Assessed, res.Reason, string(raw), at); err != nil {
			return sum, err
		}
		scan.Observations = append(scan.Observations, evidence.SurfaceObservation{
			Check: res.Check, Assessed: res.Assessed, Reason: res.Reason, Observed: json.RawMessage(raw), ObservedAt: at,
		})
		if res.Assessed {
			sum.ChecksAssessed++
		} else {
			sum.ChecksNotAssessed++
		}

		keys := make([]string, 0, len(res.Findings))
		for _, f := range res.Findings {
			keys = append(keys, findingKey(f.ID, f.Subject))
			ev, err := json.Marshal(f.Evidence)
			if err != nil {
				return sum, fmt.Errorf("evidence of %s: %w", f.ID, err)
			}
			controls := f.Controls
			if controls == nil {
				controls = []string{}
			}
			var prevResolved, prevFirstSeen *time.Time
			var prevSeverity string
			var existed bool
			err = tx.QueryRow(ctx, `SELECT true, resolved_at, first_seen, severity FROM surface_findings
				WHERE asset_id = $1 AND finding_id = $2 AND subject = $3`, assetID, f.ID, f.Subject).Scan(&existed, &prevResolved, &prevFirstSeen, &prevSeverity)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return sum, err
			}
			switch {
			case !existed:
				sum.New++
			case prevResolved != nil:
				sum.Reopened++
				// The interval that ended is kept before first_seen restarts,
				// so the days it was closed never count as open.
				if _, err := tx.Exec(ctx, `INSERT INTO surface_finding_intervals (asset_id, finding_id, subject, severity, opened_at, closed_at)
					VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, assetID, f.ID, f.Subject, prevSeverity, prevFirstSeen, prevResolved); err != nil {
					return sum, err
				}
			default:
				sum.StillOpen++
			}
			if !existed || prevResolved != nil {
				scan.Changes = append(scan.Changes, evidence.SurfaceChange{
					FindingID: f.ID, Subject: f.Subject, Severity: string(f.Severity), Change: evidence.SurfaceOpened,
				})
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO surface_findings (asset_id, check_group, finding_id, subject, severity, title, detail, fix,
					evidence, controls, first_seen, last_seen, first_scan_id, last_scan_id)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$11,$12,$12)
				ON CONFLICT (asset_id, finding_id, subject) DO UPDATE SET
					first_seen = CASE WHEN surface_findings.resolved_at IS NOT NULL THEN EXCLUDED.first_seen ELSE surface_findings.first_seen END,
					first_scan_id = CASE WHEN surface_findings.resolved_at IS NOT NULL THEN EXCLUDED.first_scan_id ELSE surface_findings.first_scan_id END,
					check_group = EXCLUDED.check_group, severity = EXCLUDED.severity, title = EXCLUDED.title,
					detail = EXCLUDED.detail, fix = EXCLUDED.fix, evidence = EXCLUDED.evidence,
					controls = EXCLUDED.controls, last_seen = EXCLUDED.last_seen, last_scan_id = EXCLUDED.last_scan_id,
					resolved_at = NULL`,
				assetID, res.Check, f.ID, f.Subject, string(f.Severity), f.Title, f.Detail, f.Fix,
				string(ev), controls, at, sum.ScanID); err != nil {
				return sum, err
			}
		}
		if res.Assessed {
			rows, err := tx.Query(ctx, `UPDATE surface_findings SET resolved_at = $4, last_scan_id = $3
				WHERE asset_id = $1 AND check_group = $2 AND resolved_at IS NULL
				  AND (finding_id || chr(1) || subject) <> ALL($5::text[])
				RETURNING finding_id, subject, severity`, assetID, res.Check, sum.ScanID, at, keys)
			if err != nil {
				return sum, err
			}
			for rows.Next() {
				var c evidence.SurfaceChange
				if err := rows.Scan(&c.FindingID, &c.Subject, &c.Severity); err != nil {
					rows.Close()
					return sum, err
				}
				c.Change = evidence.SurfaceResolved
				scan.Changes = append(scan.Changes, c)
				sum.Resolved++
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return sum, err
			}
		}
	}

	if err := tx.QueryRow(ctx, `SELECT count(*) FROM surface_findings WHERE asset_id = $1 AND resolved_at IS NULL`, assetID).Scan(&sum.Open); err != nil {
		return sum, err
	}
	if _, err := tx.Exec(ctx, `UPDATE surface_scans SET checks_assessed = $2, checks_not_assessed = $3, findings_open = $4 WHERE id = $1`,
		sum.ScanID, sum.ChecksAssessed, sum.ChecksNotAssessed, sum.Open); err != nil {
		return sum, err
	}
	if _, err := tx.Exec(ctx, `UPDATE surface_assets SET last_scan_at = $2 WHERE id = $1`, assetID, at); err != nil {
		return sum, err
	}

	// Chain the scan: the digest of what was just stored goes into the audit
	// log in the same transaction, so there is never a stored scan without its
	// attestation or an attestation without its scan.
	changes, err := json.Marshal(scan.Changes)
	if err != nil {
		return sum, err
	}
	if _, err := tx.Exec(ctx, `UPDATE surface_scans SET changes = $2::jsonb WHERE id = $1`, sum.ScanID, string(changes)); err != nil {
		return sum, err
	}
	sum.Digest = evidence.ScanDigest(scan)
	if err := auditInTx(ctx, tx, "system:surface-scanner", evidence.SurfaceScanAction, "", evidence.SurfaceScanEntry{
		ScanID: sum.ScanID, AssetID: assetID, Digest: sum.Digest, FinishedAt: at.Format(time.RFC3339Nano),
		Opened: sum.New + sum.Reopened, Resolved: sum.Resolved,
	}); err != nil {
		return sum, fmt.Errorf("chain the scan: %w", err)
	}
	return sum, tx.Commit(ctx)
}

// SurfaceFinding is one stored finding with its asset.
type SurfaceFinding struct {
	ID         int64          `json:"id"`
	AssetID    int64          `json:"assetId"`
	AssetKind  string         `json:"assetKind"`
	AssetValue string         `json:"assetValue"`
	Check      string         `json:"check"`
	FindingID  string         `json:"findingId"`
	Subject    string         `json:"subject"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail"`
	Fix        string         `json:"fix"`
	Evidence   map[string]any `json:"evidence"`
	Controls   []string       `json:"controls"`
	FirstSeen  time.Time      `json:"firstSeen"`
	LastSeen   time.Time      `json:"lastSeen"`
	ResolvedAt *time.Time     `json:"resolvedAt"`
}

// SurfaceFindingFilter narrows ListSurfaceFindings.
type SurfaceFindingFilter struct {
	AssetID         int64
	IncludeResolved bool
	Limit           int
}

// MaxSurfaceFindingsPage caps one page of findings.
const MaxSurfaceFindingsPage = 2000

// ListSurfaceFindings returns findings of not-removed assets, most severe first.
func (s *Store) ListSurfaceFindings(ctx context.Context, f SurfaceFindingFilter) ([]SurfaceFinding, error) {
	var where []string
	args := []any{}
	where = append(where, "a.removed_at IS NULL")
	if f.AssetID != 0 {
		args = append(args, f.AssetID)
		where = append(where, fmt.Sprintf("sf.asset_id = $%d", len(args)))
	}
	if !f.IncludeResolved {
		where = append(where, "sf.resolved_at IS NULL")
	}
	limit := f.Limit
	if limit <= 0 || limit > MaxSurfaceFindingsPage {
		limit = MaxSurfaceFindingsPage
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, `
		SELECT sf.id, sf.asset_id, a.kind, a.value, sf.check_group, sf.finding_id, sf.subject, sf.severity,
		       sf.title, sf.detail, sf.fix, sf.evidence, sf.controls, sf.first_seen, sf.last_seen, sf.resolved_at
		FROM surface_findings sf JOIN surface_assets a ON a.id = sf.asset_id
		WHERE `+strings.Join(where, " AND ")+`
		ORDER BY (sf.resolved_at IS NOT NULL),
		         CASE sf.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
		         a.value, sf.check_group, sf.finding_id, sf.subject
		LIMIT $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SurfaceFinding{}
	for rows.Next() {
		var sf SurfaceFinding
		var ev []byte
		if err := rows.Scan(&sf.ID, &sf.AssetID, &sf.AssetKind, &sf.AssetValue, &sf.Check, &sf.FindingID, &sf.Subject,
			&sf.Severity, &sf.Title, &sf.Detail, &sf.Fix, &ev, &sf.Controls, &sf.FirstSeen, &sf.LastSeen, &sf.ResolvedAt); err != nil {
			return nil, err
		}
		sf.Evidence = map[string]any{}
		if len(ev) > 0 {
			_ = json.Unmarshal(ev, &sf.Evidence)
		}
		if sf.Controls == nil {
			sf.Controls = []string{}
		}
		out = append(out, sf)
	}
	return out, rows.Err()
}

// SurfaceCheckState is the latest observation of one check on one asset.
type SurfaceCheckState struct {
	AssetID    int64          `json:"assetId"`
	Check      string         `json:"check"`
	Assessed   bool           `json:"assessed"`
	Reason     string         `json:"reason"`
	Observed   map[string]any `json:"observed"`
	ObservedAt time.Time      `json:"observedAt"`
	ScanID     int64          `json:"scanId"`
}

// SurfaceChecks returns, per asset, the latest observation of each check group.
func (s *Store) SurfaceChecks(ctx context.Context, assetID int64) ([]SurfaceCheckState, error) {
	q := `SELECT DISTINCT ON (o.asset_id, o.check_group) o.asset_id, o.check_group, o.assessed, o.reason,
	             o.observed, o.observed_at, o.scan_id
	      FROM surface_observations o JOIN surface_assets a ON a.id = o.asset_id
	      WHERE a.removed_at IS NULL`
	args := []any{}
	if assetID != 0 {
		q += ` AND o.asset_id = $1`
		args = append(args, assetID)
	}
	q += ` ORDER BY o.asset_id, o.check_group, o.observed_at DESC, o.id DESC`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SurfaceCheckState{}
	for rows.Next() {
		var c SurfaceCheckState
		var raw []byte
		if err := rows.Scan(&c.AssetID, &c.Check, &c.Assessed, &c.Reason, &raw, &c.ObservedAt, &c.ScanID); err != nil {
			return nil, err
		}
		c.Observed = map[string]any{}
		_ = json.Unmarshal(raw, &c.Observed)
		out = append(out, c)
	}
	return out, rows.Err()
}
