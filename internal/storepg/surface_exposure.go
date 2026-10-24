package storepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/evidence"
	"defendsec/internal/exposure"
)

// Surface findings in the exposure view (slice 7b). The ranked list itself is
// in exposure.go (one SQL order for vulnerabilities and surface findings); this
// file holds the pieces that are only about the surface: the Monday summary, the
// provenance drawer, the trend series and the evidence export.
//
// Which surface findings count: open ones of assets that are not removed,
// excluding severity "info" (an observation, not work). A removed asset keeps
// its findings as evidence but is out of every count, like a revoked host.

// SurfaceExposureSummary is the external surface card on the Fleet page.
type SurfaceExposureSummary struct {
	// Assets are declared, authorised and not removed: the ones that get scanned.
	Assets int `json:"assets"`
	// Unauthorised assets are declared but not confirmed, so never scanned.
	Unauthorised int `json:"unauthorised"`
	// Scanned is how many of Assets have been scanned at least once.
	Scanned int `json:"scanned"`
	// Findings are the open, ranked ones: critical, high, medium and low.
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"bySeverity"`
	// Info are open observations that are never counted as findings.
	Info int `json:"info"`
	// AssetsAffected is how many assets have at least one open finding.
	AssetsAffected int `json:"assetsAffected"`
	// LastScanAt is the most recent scan of any authorised asset.
	LastScanAt *time.Time `json:"lastScanAt"`
	// ChecksNotAssessed counts the checks whose latest run could not reach a
	// conclusion. Their findings, if any, are shown from the last confirmation;
	// where there is none, they say nothing either way.
	ChecksNotAssessed int `json:"checksNotAssessed"`
}

// SurfaceExposureSummary computes the counts behind the surface card.
func (s *Store) SurfaceExposureSummary(ctx context.Context) (SurfaceExposureSummary, error) {
	out := SurfaceExposureSummary{BySeverity: map[string]int{}}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE authorised), count(*) FILTER (WHERE NOT authorised),
		       count(*) FILTER (WHERE authorised AND last_scan_at IS NOT NULL),
		       max(last_scan_at) FILTER (WHERE authorised)
		FROM surface_assets WHERE removed_at IS NULL`).Scan(&out.Assets, &out.Unauthorised, &out.Scanned, &out.LastScanAt); err != nil {
		return out, err
	}
	if out.LastScanAt != nil {
		t := out.LastScanAt.UTC()
		out.LastScanAt = &t
	}
	rows, err := s.pool.Query(ctx, `
		SELECT sf.severity, count(*), count(DISTINCT sf.asset_id)
		FROM surface_findings sf JOIN surface_assets a ON a.id = sf.asset_id AND a.removed_at IS NULL
		WHERE sf.resolved_at IS NULL GROUP BY sf.severity`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var sev string
		var n, assets int
		if err := rows.Scan(&sev, &n, &assets); err != nil {
			rows.Close()
			return out, err
		}
		if _, ranked := exposure.SurfaceScore(sev); !ranked {
			out.Info += n
			continue
		}
		out.BySeverity[sev] += n
		out.Findings += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(DISTINCT sf.asset_id)
		FROM surface_findings sf JOIN surface_assets a ON a.id = sf.asset_id AND a.removed_at IS NULL
		WHERE sf.resolved_at IS NULL AND sf.severity <> 'info'`).Scan(&out.AssetsAffected); err != nil {
		return out, err
	}
	err = s.pool.QueryRow(ctx, `
		SELECT count(*) FROM (
		  SELECT DISTINCT ON (o.asset_id, o.check_group) o.assessed
		  FROM surface_observations o JOIN surface_assets a ON a.id = o.asset_id AND a.removed_at IS NULL AND a.authorised
		  ORDER BY o.asset_id, o.check_group, o.observed_at DESC, o.id DESC) latest
		WHERE NOT assessed`).Scan(&out.ChecksNotAssessed)
	return out, err
}

// ---- the provenance drawer ----------------------------------------------------

// ErrBadSurfaceKey is returned for an id that is not a surface row's.
var ErrBadSurfaceKey = errors.New("bad surface finding id")

// SurfaceKey is the row id of surface finding n in the exposure list:
// "surface:" and the finding's id, zero-padded to 12 digits so that the text
// order of two keys is the numeric order.
func SurfaceKey(n int64) string {
	return exposure.SurfaceKeyPrefix + fmt.Sprintf("%012d", n)
}

// ParseSurfaceKey reverses SurfaceKey.
func ParseSurfaceKey(key string) (int64, error) {
	rest, ok := strings.CutPrefix(key, exposure.SurfaceKeyPrefix)
	if !ok || len(rest) != 12 {
		return 0, ErrBadSurfaceKey
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n <= 0 {
		return 0, ErrBadSurfaceKey
	}
	return n, nil
}

// SurfaceDetail is the drawer of a surface row: the finding, how long it has
// been open, and the raw observations behind it.
type SurfaceDetail struct {
	Key     string         `json:"key"`
	Finding SurfaceFinding `json:"finding"`
	// Intervals are every span the finding was open, oldest first.
	Intervals []evidence.SurfaceInterval `json:"intervals"`
	// Confirmed is the observation of the scan that last confirmed (or, for a
	// resolved finding, last settled) the finding, and Latest the most recent
	// observation of the check. They differ when the latest run could not
	// reach a conclusion: then Unconfirmed is true and the finding is shown
	// from its last confirmation.
	Confirmed   *SurfaceCheckState `json:"confirmed"`
	Latest      *SurfaceCheckState `json:"latest"`
	Unconfirmed bool               `json:"unconfirmed"`
}

// GetSurfaceDetail returns one surface finding by its list key.
func (s *Store) GetSurfaceDetail(ctx context.Context, key string) (SurfaceDetail, error) {
	id, err := ParseSurfaceKey(key)
	if err != nil {
		return SurfaceDetail{}, err
	}
	d := SurfaceDetail{Key: key, Intervals: []evidence.SurfaceInterval{}}
	var ev []byte
	var lastScan *int64
	err = s.pool.QueryRow(ctx, `
		SELECT sf.id, sf.asset_id, a.kind, a.value, sf.check_group, sf.finding_id, sf.subject, sf.severity,
		       sf.title, sf.detail, sf.fix, sf.evidence, sf.controls, sf.first_seen, sf.last_seen, sf.resolved_at, sf.last_scan_id
		FROM surface_findings sf JOIN surface_assets a ON a.id = sf.asset_id AND a.removed_at IS NULL
		WHERE sf.id = $1`, id).Scan(&d.Finding.ID, &d.Finding.AssetID, &d.Finding.AssetKind, &d.Finding.AssetValue,
		&d.Finding.Check, &d.Finding.FindingID, &d.Finding.Subject, &d.Finding.Severity, &d.Finding.Title,
		&d.Finding.Detail, &d.Finding.Fix, &ev, &d.Finding.Controls, &d.Finding.FirstSeen, &d.Finding.LastSeen,
		&d.Finding.ResolvedAt, &lastScan)
	if errors.Is(err, pgx.ErrNoRows) {
		return SurfaceDetail{}, ErrNoSurfaceFinding
	}
	if err != nil {
		return SurfaceDetail{}, err
	}
	d.Finding.Evidence = map[string]any{}
	_ = json.Unmarshal(ev, &d.Finding.Evidence)
	if d.Finding.Controls == nil {
		d.Finding.Controls = []string{}
	}
	d.Finding.FirstSeen, d.Finding.LastSeen = d.Finding.FirstSeen.UTC(), d.Finding.LastSeen.UTC()
	if d.Finding.ResolvedAt != nil {
		t := d.Finding.ResolvedAt.UTC()
		d.Finding.ResolvedAt = &t
	}

	rows, err := s.pool.Query(ctx, `
		SELECT opened_at, closed_at FROM surface_finding_intervals
		WHERE asset_id = $1 AND finding_id = $2 AND subject = $3 ORDER BY opened_at`,
		d.Finding.AssetID, d.Finding.FindingID, d.Finding.Subject)
	if err != nil {
		return SurfaceDetail{}, err
	}
	for rows.Next() {
		var o, c time.Time
		if err := rows.Scan(&o, &c); err != nil {
			rows.Close()
			return SurfaceDetail{}, err
		}
		c = c.UTC()
		d.Intervals = append(d.Intervals, evidence.SurfaceInterval{OpenedAt: o.UTC(), ClosedAt: &c})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return SurfaceDetail{}, err
	}
	d.Intervals = append(d.Intervals, evidence.SurfaceInterval{OpenedAt: d.Finding.FirstSeen, ClosedAt: d.Finding.ResolvedAt})

	obs := func(where string, args ...any) (*SurfaceCheckState, error) {
		var c SurfaceCheckState
		var raw []byte
		err := s.pool.QueryRow(ctx, `
			SELECT o.asset_id, o.check_group, o.assessed, o.reason, o.observed, o.observed_at, o.scan_id
			FROM surface_observations o WHERE o.asset_id = $1 AND o.check_group = $2 `+where+`
			ORDER BY o.observed_at DESC, o.id DESC LIMIT 1`, append([]any{d.Finding.AssetID, d.Finding.Check}, args...)...).
			Scan(&c.AssetID, &c.Check, &c.Assessed, &c.Reason, &raw, &c.ObservedAt, &c.ScanID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		c.Observed = map[string]any{}
		_ = json.Unmarshal(raw, &c.Observed)
		c.ObservedAt = c.ObservedAt.UTC()
		return &c, nil
	}
	if d.Latest, err = obs(""); err != nil {
		return SurfaceDetail{}, err
	}
	if lastScan != nil {
		if d.Confirmed, err = obs(`AND o.scan_id = $3`, *lastScan); err != nil {
			return SurfaceDetail{}, err
		}
	}
	d.Unconfirmed = d.Finding.ResolvedAt == nil && d.Latest != nil && !d.Latest.Assessed
	return d, nil
}

// ErrNoSurfaceFinding is returned for a surface finding that does not exist or
// belongs to a removed asset.
var ErrNoSurfaceFinding = errors.New("surface finding not found")

// ---- trend --------------------------------------------------------------------

// surfaceTrend fills the surface series of points that were laid out by
// ExposureTrend: findings open at the end of each day, from first_seen and
// resolved_at plus the intervals of findings that closed and came back.
// A day is known if it ends after the first surface scan; before that the
// zeros mean no data.
func (s *Store) surfaceTrend(ctx context.Context, start, end, now time.Time, points []TrendPoint) (*time.Time, error) {
	var since *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT min(started_at) FROM surface_scans`).Scan(&since); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		WITH days AS (
		  SELECT d::date AS day, LEAST((d + interval '1 day') AT TIME ZONE 'UTC', $3::timestamptz) AS asof
		  FROM generate_series($1::timestamp, $2::timestamp, interval '1 day') d
		), spans AS (
		  SELECT sf.severity, sf.first_seen AS opened, sf.resolved_at AS closed
		  FROM surface_findings sf JOIN surface_assets a ON a.id = sf.asset_id AND a.removed_at IS NULL
		  WHERE sf.severity <> 'info'
		  UNION ALL
		  SELECT i.severity, i.opened_at, i.closed_at
		  FROM surface_finding_intervals i JOIN surface_assets a ON a.id = i.asset_id AND a.removed_at IS NULL
		  WHERE i.severity <> 'info'
		)
		SELECT days.day, count(spans.severity), count(spans.severity) FILTER (WHERE spans.severity IN ('critical', 'high'))
		FROM days
		LEFT JOIN spans ON spans.opened <= days.asof AND (spans.closed IS NULL OR spans.closed > days.asof)
		GROUP BY days.day ORDER BY days.day`, start, end, now.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var day time.Time
		var n, high int
		if err := rows.Scan(&day, &n, &high); err != nil {
			return nil, err
		}
		if i >= len(points) || points[i].Day != day.Format("2006-01-02") {
			return nil, fmt.Errorf("surface trend day %s does not line up with the exposure trend", day.Format("2006-01-02"))
		}
		known := since != nil && day.Add(24*time.Hour).After(since.UTC())
		points[i].SurfaceKnown = known
		if known {
			points[i].Surface, points[i].SurfaceHigh = n, high
		}
		i++
	}
	return since, rows.Err()
}

// ---- evidence export ------------------------------------------------------------

// ExportSurfaceEvidence builds the surface section of an evidence bundle: every
// declared asset (removed ones too, since their findings are evidence), every
// scan with the raw observation of each check and the findings it opened or
// closed, and every finding with each span it was open. nil if the instance
// never declared an asset. See internal/evidence/surface.go for what the
// section proves and what it does not.
func (s *Store) ExportSurfaceEvidence(ctx context.Context) (*evidence.SurfaceScope, error) {
	sc := &evidence.SurfaceScope{
		Assets: []evidence.SurfaceAsset{}, Scans: []evidence.SurfaceScan{}, Findings: []evidence.SurfaceFinding{},
		Provenance: evidence.SurfaceProvenance,
	}
	kinds := map[int64][2]string{}
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, value, label, authorised, authorised_by, authorised_at, removed_at IS NOT NULL
		FROM surface_assets ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var a evidence.SurfaceAsset
		if err := rows.Scan(&a.ID, &a.Kind, &a.Value, &a.Label, &a.Authorised, &a.AuthorisedBy, &a.AuthorisedAt, &a.Removed); err != nil {
			rows.Close()
			return nil, err
		}
		if a.AuthorisedAt != nil {
			t := a.AuthorisedAt.UTC()
			a.AuthorisedAt = &t
		}
		kinds[a.ID] = [2]string{a.Kind, a.Value}
		sc.Assets = append(sc.Assets, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(sc.Assets) == 0 {
		return nil, nil
	}

	scanIdx := map[int64]int{}
	rows, err = s.pool.Query(ctx, `
		SELECT id, asset_id, triggered_by, started_at, finished_at, changes FROM surface_scans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sn evidence.SurfaceScan
		var changes []byte
		if err := rows.Scan(&sn.ScanID, &sn.AssetID, &sn.TriggeredBy, &sn.StartedAt, &sn.FinishedAt, &changes); err != nil {
			rows.Close()
			return nil, err
		}
		sn.StartedAt, sn.FinishedAt = sn.StartedAt.UTC(), sn.FinishedAt.UTC()
		sn.AssetKind, sn.AssetValue = kinds[sn.AssetID][0], kinds[sn.AssetID][1]
		sn.Observations = []evidence.SurfaceObservation{}
		sn.Changes = []evidence.SurfaceChange{}
		if len(changes) > 0 {
			if err := json.Unmarshal(changes, &sn.Changes); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan %d changes: %w", sn.ScanID, err)
			}
		}
		scanIdx[sn.ScanID] = len(sc.Scans)
		sc.Scans = append(sc.Scans, sn)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT scan_id, check_group, assessed, reason, observed, observed_at FROM surface_observations ORDER BY scan_id, check_group, id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var scanID int64
		var o evidence.SurfaceObservation
		var raw []byte
		if err := rows.Scan(&scanID, &o.Check, &o.Assessed, &o.Reason, &raw, &o.ObservedAt); err != nil {
			rows.Close()
			return nil, err
		}
		o.Observed, o.ObservedAt = json.RawMessage(raw), o.ObservedAt.UTC()
		if i, ok := scanIdx[scanID]; ok {
			sc.Scans[i].Observations = append(sc.Scans[i].Observations, o)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type fkey struct {
		asset   int64
		finding string
		subject string
	}
	past := map[fkey][]evidence.SurfaceInterval{}
	rows, err = s.pool.Query(ctx, `
		SELECT asset_id, finding_id, subject, opened_at, closed_at FROM surface_finding_intervals ORDER BY opened_at, id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k fkey
		var o, c time.Time
		if err := rows.Scan(&k.asset, &k.finding, &k.subject, &o, &c); err != nil {
			rows.Close()
			return nil, err
		}
		c = c.UTC()
		past[k] = append(past[k], evidence.SurfaceInterval{OpenedAt: o.UTC(), ClosedAt: &c})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT asset_id, check_group, finding_id, subject, severity, title, detail, fix, evidence, controls,
		       first_seen, resolved_at, COALESCE(first_scan_id, 0), COALESCE(last_scan_id, 0)
		FROM surface_findings ORDER BY asset_id, check_group, finding_id, subject`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f evidence.SurfaceFinding
		var ev []byte
		var first time.Time
		var resolved *time.Time
		if err := rows.Scan(&f.AssetID, &f.Check, &f.FindingID, &f.Subject, &f.Severity, &f.Title, &f.Detail, &f.Fix,
			&ev, &f.Controls, &first, &resolved, &f.FirstScan, &f.LastScan); err != nil {
			rows.Close()
			return nil, err
		}
		f.AssetKind, f.AssetValue = kinds[f.AssetID][0], kinds[f.AssetID][1]
		f.Evidence = map[string]any{}
		_ = json.Unmarshal(ev, &f.Evidence)
		f.Intervals = append([]evidence.SurfaceInterval{}, past[fkey{f.AssetID, f.FindingID, f.Subject}]...)
		cur := evidence.SurfaceInterval{OpenedAt: first.UTC()}
		if resolved != nil {
			t := resolved.UTC()
			cur.ClosedAt = &t
		}
		f.Intervals = append(f.Intervals, cur)
		sc.Findings = append(sc.Findings, f)
	}
	rows.Close()
	return sc, rows.Err()
}
