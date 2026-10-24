package storepg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/exposure"
)

// The exposure view reads vuln_findings the way an operator does: not one row
// per host and package, but one row per advisory, with the hosts it affects.
// Ranking and paging happen here, in the database, so a client never receives
// the fleet's findings to sort them. The ranking rule itself is documented and
// unit-tested in internal/exposure; the ORDER BY below is tested against it.

// Exposure buckets. Only fixable findings are work for this week; the watch
// bucket holds exposure with nothing to install yet. Informational findings
// (will_not_fix, ESM-only) are in neither: they are never counted.
const (
	BucketFix   = "fix"
	BucketWatch = "watch"
)

// Exposure statuses.
const (
	ExposureOpen     = "open"
	ExposureResolved = "resolved"
)

// MaxExposurePage bounds one page of the exposure list.
const MaxExposurePage = 200

// ErrBadExposureQuery is wrapped by validation errors an API can show.
var ErrBadExposureQuery = errors.New("bad exposure query")

func bucketKinds(bucket string) ([]string, error) {
	switch bucket {
	case "", BucketFix:
		return []string{"finding"}, nil
	case BucketWatch:
		return []string{"unfixed", "awaiting_vendor"}, nil
	}
	return nil, fmt.Errorf("%w: bucket must be fix or watch", ErrBadExposureQuery)
}

// ExposureQuery selects and pages the ranked list.
type ExposureQuery struct {
	// Bucket is BucketFix (default) or BucketWatch.
	Bucket string
	// Status is ExposureOpen (default) or ExposureResolved.
	Status string
	// KEVOnly keeps only advisories on the KEV list: the red callout.
	KEVOnly bool
	// Limit is the page size, 1..MaxExposurePage; 0 means 50.
	Limit int
	// Cursor is the opaque value a previous page returned as Next.
	Cursor string
}

func (q *ExposureQuery) normalize() ([]string, error) {
	kinds, err := bucketKinds(q.Bucket)
	if err != nil {
		return nil, err
	}
	switch q.Status {
	case "":
		q.Status = ExposureOpen
	case ExposureOpen, ExposureResolved:
	default:
		return nil, fmt.Errorf("%w: status must be open or resolved", ErrBadExposureQuery)
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > MaxExposurePage {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrBadExposureQuery, MaxExposurePage)
	}
	return kinds, nil
}

// HostRef names a host in a list.
type HostRef struct {
	DeviceID string `json:"deviceId"`
	Hostname string `json:"hostname"`
}

// ExposureSampleHosts is how many hosts a list row names; HostCount is the
// whole count.
const ExposureSampleHosts = 5

// ExposureGroup is one advisory with every host it affects.
type ExposureGroup struct {
	AdvisoryID string   `json:"advisoryId"`
	CVE        string   `json:"cve"`
	Summary    string   `json:"summary"`
	Severity   string   `json:"severity"`
	KEV        bool     `json:"kev"`
	KEVAdded   *string  `json:"kevAdded"`
	EPSS       *float64 `json:"epss"`
	CVSS       *float64 `json:"cvss"`
	// Kinds are the finding kinds present in the group: "finding" for the fix
	// bucket; "unfixed" and/or "awaiting_vendor" for the watch bucket.
	Kinds []string `json:"kinds"`
	// HostCount is the number of hosts affected; Hosts names the first few,
	// by hostname. The provenance drawer fetches them all.
	HostCount    int       `json:"hostCount"`
	Hosts        []HostRef `json:"hosts"`
	FindingCount int       `json:"findingCount"`
	// Packages and Fixed are the distinct installed package names and fixed
	// versions across the group (capped at three each).
	Packages []string `json:"packages"`
	Fixed    []string `json:"fixed"`
	// FirstSeen is when the oldest open finding in the group was first seen;
	// for resolved groups, ResolvedAt is when the latest one closed.
	FirstSeen  time.Time  `json:"firstSeen"`
	ResolvedAt *time.Time `json:"resolvedAt"`
	// AwaitingSince is, for awaiting_vendor findings in the group, the latest
	// date Red Hat shipped the fix ("fixed by Red Hat on <date>; awaiting
	// Rocky/Alma"); nil when none applies or the feed gave no date.
	AwaitingSince *string `json:"awaitingSince"`

	// Source is SourceVulnerability or SourceSurface. A surface row is one
	// external-surface finding (slice 7b): AdvisoryID is its list key
	// ("surface:<12 digits>"), Summary its title, Kinds is ["surface"], there
	// are no hosts, and Surface carries the rest.
	Source  string      `json:"source"`
	Surface *SurfaceRow `json:"surface,omitempty"`
}

// The two kinds of row in the ranked list.
const (
	SourceVulnerability = "vulnerability"
	SourceSurface       = "surface"
)

// SurfaceRow is what a surface row of the list says about its finding.
type SurfaceRow struct {
	FindingID  int64  `json:"findingId"`
	AssetID    int64  `json:"assetId"`
	AssetKind  string `json:"assetKind"`
	AssetValue string `json:"assetValue"`
	// Check is the check group ("dmarc", "ports"); ID the condition
	// ("dmarc.p_none"); Subject tells apart several of one condition.
	Check   string `json:"check"`
	ID      string `json:"id"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
	Fix     string `json:"fix"`
	// LastSeen is when a scan last confirmed the finding.
	LastSeen time.Time `json:"lastSeen"`
	// Unconfirmed is true when the latest run of the finding's check could not
	// reach a conclusion: the finding is shown from its last confirmation.
	Unconfirmed bool `json:"unconfirmed"`
}

// ExposurePage is one page of the ranked list.
type ExposurePage struct {
	Findings []ExposureGroup `json:"findings"`
	// Next is the cursor for the following page; empty on the last page.
	Next string `json:"next,omitempty"`
	// Total is the number of advisories matching the filter, across all pages.
	Total int `json:"total"`
}

// exposureCursor is a position in the ranking: the sort key of the last row
// returned. The numeric keys travel as text so they round-trip exactly.
type exposureCursor struct {
	K1 int    `json:"a"`
	K2 string `json:"b"`
	K3 string `json:"c"`
	K4 string `json:"d"`
	K5 int    `json:"e"`
	K6 string `json:"f"`
}

func encodeExposureCursor(c exposureCursor) string {
	raw, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeExposureCursor(s string) (exposureCursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return exposureCursor{}, ErrBadCursor
	}
	var c exposureCursor
	if err := json.Unmarshal(raw, &c); err != nil || c.K6 == "" {
		return exposureCursor{}, ErrBadCursor
	}
	// The keys are interpolated as numeric parameters; refuse anything else.
	for _, k := range []string{c.K2, c.K3, c.K4} {
		if !isNumericText(k) {
			return exposureCursor{}, ErrBadCursor
		}
	}
	return c, nil
}

func isNumericText(s string) bool {
	if s == "" {
		return false
	}
	dots := 0
	for i, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r == '-' && i == 0:
		case r == '.':
			dots++
			if dots > 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// exposureRankedSQL is the ranked list: the findings of one bucket grouped by
// advisory, and (in the fix bucket) the open or resolved external-surface
// findings, each with six sort keys, all ascending, so a keyset cursor is a row
// comparison. It is the SQL form of internal/exposure.Compare:
//
//	k1  band: 0 a KEV vulnerability, 1 a critical or high surface finding, 2 everything else
//	k2  minus the KEV date as days since 1970 (0 when none, or not a KEV vulnerability): newest first, undated last
//	k3  minus EPSS (1 when none, which every surface finding is): highest first, unscored last
//	k4  minus CVSS (1 when none), or for a surface finding minus its severity's CVSS-equivalent
//	k5  severity label rank
//	k6  the row id: the advisory id, or "surface:<12 digits>" (compared bytewise, as Go does)
//
// $1 kinds, $2 resolved?, $3 KEV only?
const exposureRankedSQL = `
	SELECT advisory_id, cve, summary, severity, kev, kev_added, epss, cvss, kinds, host_count, finding_count,
	       host_ids, host_names, packages, fixed, first_seen, resolved_at, awaiting_since,
	       source, s_id, s_asset_id, s_asset_kind, s_asset, s_check, s_finding, s_subject, s_detail, s_fix, s_last_seen, s_unconfirmed,
	       CASE WHEN source = 'surface' THEN (CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 2 END)
	            WHEN kev THEN 0 ELSE 2 END AS k1,
	       (CASE WHEN source = 'vulnerability' AND kev THEN -COALESCE(kev_added - DATE '1970-01-01', 0) ELSE 0 END)::text AS k2,
	       (-COALESCE(epss, -1))::text AS k3,
	       (CASE WHEN source = 'surface'
	             THEN -(CASE severity WHEN 'critical' THEN 9.5 WHEN 'high' THEN 8.0 WHEN 'medium' THEN 5.0 ELSE 2.0 END)
	             ELSE -COALESCE(cvss, -1) END)::text AS k4,
	       CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END AS k5,
	       advisory_id COLLATE "C" AS k6
	FROM (
	  SELECT f.advisory_id,
	         max(f.cve) AS cve, max(f.summary) AS summary,
	         (array_agg(f.severity ORDER BY array_position(ARRAY['critical','high','medium','low','unknown'], f.severity)))[1] AS severity,
	         bool_or(f.kev) AS kev,
	         max(a.kev_added) AS kev_added,
	         max(f.epss) AS epss, max(f.cvss_score) AS cvss,
	         array_agg(DISTINCT f.kind ORDER BY f.kind) AS kinds,
	         count(DISTINCT f.device_id) AS host_count,
	         count(*) AS finding_count,
	         (array_agg(f.device_id ORDER BY lower(d.hostname), f.device_id))[1:` + exposureSample + `] AS host_ids,
	         (array_agg(d.hostname ORDER BY lower(d.hostname), f.device_id))[1:` + exposureSample + `] AS host_names,
	         (array_agg(DISTINCT f.package))[1:3] AS packages,
	         (array_agg(DISTINCT f.fixed) FILTER (WHERE f.fixed <> ''))[1:3] AS fixed,
	         min(f.first_seen) AS first_seen,
	         max(f.resolved_at) AS resolved_at,
	         max(f.upstream_fixed_on) FILTER (WHERE f.kind = 'awaiting_vendor') AS awaiting_since,
	         'vulnerability'::text AS source,
	         NULL::bigint AS s_id, NULL::bigint AS s_asset_id, NULL::text AS s_asset_kind, NULL::text AS s_asset,
	         NULL::text AS s_check, NULL::text AS s_finding, NULL::text AS s_subject, NULL::text AS s_detail,
	         NULL::text AS s_fix, NULL::timestamptz AS s_last_seen, false AS s_unconfirmed
	  FROM vuln_findings f
	  JOIN devices d ON d.id = f.device_id AND NOT d.revoked
	  LEFT JOIN advisories a ON a.id = f.advisory_id
	  WHERE f.kind = ANY($1) AND (f.resolved_at IS NOT NULL) = $2
	  GROUP BY f.advisory_id
	  HAVING NOT $3 OR bool_or(f.kev)
	  UNION ALL
	  SELECT '` + exposure.SurfaceKeyPrefix + `' || lpad(sf.id::text, 12, '0'), '', sf.title, sf.severity,
	         false, NULL::date, NULL::numeric, NULL::numeric,
	         ARRAY['surface']::text[], 0::bigint, 1::bigint,
	         ARRAY[]::text[], ARRAY[]::text[], ARRAY[]::text[], ARRAY[]::text[],
	         sf.first_seen, sf.resolved_at, NULL::date,
	         'surface'::text, sf.id, sa.id, sa.kind, sa.value,
	         sf.check_group, sf.finding_id, sf.subject, sf.detail,
	         sf.fix, sf.last_seen,
	         sf.resolved_at IS NULL AND COALESCE((SELECT NOT o.assessed FROM surface_observations o
	           WHERE o.asset_id = sf.asset_id AND o.check_group = sf.check_group
	           ORDER BY o.observed_at DESC, o.id DESC LIMIT 1), false)
	  FROM surface_findings sf
	  JOIN surface_assets sa ON sa.id = sf.asset_id AND sa.removed_at IS NULL
	  WHERE 'finding' = ANY($1) AND NOT $3 AND sf.severity <> 'info' AND (sf.resolved_at IS NOT NULL) = $2
	) g`

const exposureSample = "5"

// ListExposure returns one page of the ranked list: KEV first (newest listing
// first), then EPSS, then CVSS (see internal/exposure).
func (s *Store) ListExposure(ctx context.Context, q ExposureQuery) (ExposurePage, error) {
	kinds, err := q.normalize()
	if err != nil {
		return ExposurePage{}, err
	}
	resolved := q.Status == ExposureResolved
	page := ExposurePage{Findings: []ExposureGroup{}}

	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM (`+exposureRankedSQL+`) r`, kinds, resolved, q.KEVOnly).Scan(&page.Total); err != nil {
		return ExposurePage{}, err
	}

	sql := `SELECT * FROM (` + exposureRankedSQL + `) r`
	args := []any{kinds, resolved, q.KEVOnly}
	if q.Cursor != "" {
		c, err := decodeExposureCursor(q.Cursor)
		if err != nil {
			return ExposurePage{}, err
		}
		sql += ` WHERE (k1, k2::numeric, k3::numeric, k4::numeric, k5, k6) > ($4, $5::numeric, $6::numeric, $7::numeric, $8, $9)`
		args = append(args, c.K1, c.K2, c.K3, c.K4, c.K5, c.K6)
	}
	sql += fmt.Sprintf(` ORDER BY k1, k2::numeric, k3::numeric, k4::numeric, k5, k6 LIMIT %d`, q.Limit+1)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return ExposurePage{}, err
	}
	defer rows.Close()
	var cursors []exposureCursor
	for rows.Next() {
		g, c, err := scanExposureGroup(rows)
		if err != nil {
			return ExposurePage{}, err
		}
		page.Findings = append(page.Findings, g)
		cursors = append(cursors, c)
	}
	if err := rows.Err(); err != nil {
		return ExposurePage{}, err
	}
	if len(page.Findings) > q.Limit {
		page.Findings = page.Findings[:q.Limit]
		page.Next = encodeExposureCursor(cursors[q.Limit-1])
	}
	return page, nil
}

func scanExposureGroup(row pgx.Row) (ExposureGroup, exposureCursor, error) {
	var g ExposureGroup
	var c exposureCursor
	var kevAdded, awaitingSince, sLastSeen *time.Time
	var ids, names []string
	var sID, sAssetID *int64
	var sKind, sAsset, sCheck, sFinding, sSubject, sDetail, sFix *string
	var sUnconfirmed bool
	if err := row.Scan(&g.AdvisoryID, &g.CVE, &g.Summary, &g.Severity, &g.KEV, &kevAdded, &g.EPSS, &g.CVSS,
		&g.Kinds, &g.HostCount, &g.FindingCount, &ids, &names, &g.Packages, &g.Fixed, &g.FirstSeen, &g.ResolvedAt, &awaitingSince,
		&g.Source, &sID, &sAssetID, &sKind, &sAsset, &sCheck, &sFinding, &sSubject, &sDetail, &sFix, &sLastSeen, &sUnconfirmed,
		&c.K1, &c.K2, &c.K3, &c.K4, &c.K5, &c.K6); err != nil {
		return g, c, err
	}
	if g.Source == SourceSurface && sID != nil {
		str := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		g.Surface = &SurfaceRow{
			FindingID: *sID, AssetKind: str(sKind), AssetValue: str(sAsset), Check: str(sCheck), ID: str(sFinding),
			Subject: str(sSubject), Detail: str(sDetail), Fix: str(sFix), Unconfirmed: sUnconfirmed,
		}
		if sAssetID != nil {
			g.Surface.AssetID = *sAssetID
		}
		if sLastSeen != nil {
			g.Surface.LastSeen = sLastSeen.UTC()
		}
	}
	g.FirstSeen = g.FirstSeen.UTC()
	if g.ResolvedAt != nil {
		t := g.ResolvedAt.UTC()
		g.ResolvedAt = &t
	}
	g.KEVAdded = dateText(kevAdded)
	g.AwaitingSince = dateText(awaitingSince)
	g.Hosts = make([]HostRef, 0, len(ids))
	named := make(map[string]bool, len(ids))
	for i, id := range ids {
		// A host with a finding for the same advisory in two packages (two KBs, a
		// kernel and its modules) is one host.
		if named[id] {
			continue
		}
		named[id] = true
		name := ""
		if i < len(names) {
			name = names[i]
		}
		g.Hosts = append(g.Hosts, HostRef{DeviceID: id, Hostname: name})
	}
	if g.Packages == nil {
		g.Packages = []string{}
	}
	if g.Fixed == nil {
		g.Fixed = []string{}
	}
	if !g.KEV {
		g.KEVAdded = nil
	}
	return g, c, nil
}

func dateText(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02")
	return &s
}

// ---- one advisory, every host ------------------------------------------------

// MaxExposureHosts bounds the host rows of one advisory's detail.
const MaxExposureHosts = 500

// ExposureDetail is the provenance drawer: the advisory, each affected host's
// finding, and the feed snapshots those findings were computed from.
type ExposureDetail struct {
	AdvisoryID string
	Advisory   *Advisory
	Findings   []VulnFinding
	// Truncated is true when more than MaxExposureHosts hosts are affected.
	Truncated bool
	Snapshots []FeedSnapshot
}

// GetExposureDetail returns every host's finding for one advisory in a bucket
// and status, hosts in name order, with the snapshots they reference.
func (s *Store) GetExposureDetail(ctx context.Context, advisoryID, bucket, status string) (ExposureDetail, error) {
	kinds, err := bucketKinds(bucket)
	if err != nil {
		return ExposureDetail{}, err
	}
	switch status {
	case "", ExposureOpen, ExposureResolved:
	default:
		return ExposureDetail{}, fmt.Errorf("%w: status must be open or resolved", ErrBadExposureQuery)
	}
	if advisoryID == "" {
		return ExposureDetail{}, fmt.Errorf("%w: advisory id is required", ErrBadExposureQuery)
	}
	if len(advisoryID) >= len(exposure.SurfaceKeyPrefix) && advisoryID[:len(exposure.SurfaceKeyPrefix)] == exposure.SurfaceKeyPrefix {
		return ExposureDetail{}, fmt.Errorf("%w: %s is an external surface finding; use GetSurfaceDetail", ErrBadExposureQuery, advisoryID)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+findingColumns+`
		FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND NOT d.revoked
		WHERE f.advisory_id = $1 AND f.kind = ANY($2) AND (f.resolved_at IS NOT NULL) = $3
		ORDER BY lower(d.hostname), f.device_id, f.family
		LIMIT $4`, advisoryID, kinds, status == ExposureResolved, MaxExposureHosts+1)
	if err != nil {
		return ExposureDetail{}, err
	}
	defer rows.Close()
	out := ExposureDetail{AdvisoryID: advisoryID, Findings: []VulnFinding{}}
	for rows.Next() {
		v, err := scanFinding(rows)
		if err != nil {
			return ExposureDetail{}, err
		}
		out.Findings = append(out.Findings, v)
	}
	if err := rows.Err(); err != nil {
		return ExposureDetail{}, err
	}
	rows.Close()
	if len(out.Findings) > MaxExposureHosts {
		out.Findings, out.Truncated = out.Findings[:MaxExposureHosts], true
	}
	if len(out.Findings) == 0 {
		return out, nil
	}
	if adv, err := s.GetAdvisory(ctx, advisoryID); err == nil {
		out.Advisory = &adv
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return ExposureDetail{}, err
	}
	seen := map[int64]bool{}
	for _, f := range out.Findings {
		if f.SnapshotID == nil || seen[*f.SnapshotID] {
			continue
		}
		seen[*f.SnapshotID] = true
		if snap, err := s.GetFeedSnapshot(ctx, *f.SnapshotID); err == nil {
			out.Snapshots = append(out.Snapshots, snap)
		}
	}
	return out, nil
}

// ---- summary ------------------------------------------------------------------

// SilentAfter is how long a host may go without reporting before the Monday
// view calls it silent.
const SilentAfter = 7 * 24 * time.Hour

// ExposureCount is a count of findings and of the advisories they belong to.
type ExposureCount struct {
	Findings   int `json:"findings"`
	Advisories int `json:"advisories"`
}

// ExposureSummary is the one-screen standing of the fleet.
type ExposureSummary struct {
	Hosts struct {
		Total int `json:"total"`
		// Assessed hosts were matched against a feed that covers them. The
		// rest are "not assessed": an empty list for them proves nothing.
		Assessed    int `json:"assessed"`
		NotAssessed int `json:"notAssessed"`
		// Silent hosts have not reported for SilentAfter; SilentList names the
		// ones quiet the longest.
		Silent     int          `json:"silent"`
		SilentList []SilentHost `json:"silentList"`
	} `json:"hosts"`
	Fixable struct {
		Findings   int           `json:"findings"`
		Advisories int           `json:"advisories"`
		Hosts      int           `json:"hosts"`
		KEV        ExposureCount `json:"kev"`
		// Surface is the open external-surface findings that rank (critical,
		// high, medium, low): work for this week beside the vulnerabilities.
		// Total is Advisories plus Surface: the length of the Fix this week list.
		Surface int `json:"surface"`
		Total   int `json:"total"`
	} `json:"fixable"`
	Watch struct {
		Unfixed        ExposureCount `json:"unfixed"`
		AwaitingVendor ExposureCount `json:"awaitingVendor"`
		// KEV is the part of Unfixed and AwaitingVendor that is exploited in
		// the wild and has nothing to install: it needs a mitigation.
		KEV ExposureCount `json:"kev"`
	} `json:"watch"`
	// Surface is the external surface card (slice 7b); see SurfaceExposureSummary.
	Surface SurfaceExposureSummary `json:"surface"`
	// SCA counts the open failed configuration checks by severity.
	SCA struct {
		Total    int            `json:"total"`
		Hosts    int            `json:"hosts"`
		Severity map[string]int `json:"bySeverity"`
	} `json:"sca"`
}

// SilentHost is a host that has stopped reporting.
type SilentHost struct {
	DeviceID string    `json:"deviceId"`
	Hostname string    `json:"hostname"`
	LastSeen time.Time `json:"lastSeen"`
}

// ExposureSummary computes the counts behind the Monday view. Findings are
// counted only for hosts that are not revoked, and informational findings not
// at all.
func (s *Store) ExposureSummary(ctx context.Context, now time.Time) (ExposureSummary, error) {
	var out ExposureSummary
	cutoff := now.Add(-SilentAfter)

	if err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE s.coverage = 'covered' OR (`+effectivePatchCoverage+`) = 'covered' OR EXISTS (
		         SELECT 1 FROM devices m JOIN host_patch_state p2 ON p2.device_id = m.id
		         WHERE m.merged_into = d.id AND NOT m.revoked AND p2.coverage = 'covered'
		           AND p2.evidence_at >= $1::timestamptz - make_interval(days => COALESCE((SELECT stale_after_days FROM rmm_settings WHERE id = 1), 7)))),
		       count(*) FILTER (WHERE d.last_seen < $2)
		FROM devices d LEFT JOIN host_vuln_state s ON s.device_id = d.id LEFT JOIN host_patch_state p ON p.device_id = d.id
		WHERE NOT d.revoked AND d.merged_into IS NULL`, now, cutoff).Scan(&out.Hosts.Total, &out.Hosts.Assessed, &out.Hosts.Silent); err != nil {
		return out, err
	}
	out.Hosts.NotAssessed = out.Hosts.Total - out.Hosts.Assessed

	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, last_seen FROM devices WHERE NOT revoked AND merged_into IS NULL AND last_seen < $1
		ORDER BY last_seen, id LIMIT 10`, cutoff)
	if err != nil {
		return out, err
	}
	out.Hosts.SilentList = []SilentHost{}
	for rows.Next() {
		var h SilentHost
		if err := rows.Scan(&h.DeviceID, &h.Hostname, &h.LastSeen); err != nil {
			rows.Close()
			return out, err
		}
		out.Hosts.SilentList = append(out.Hosts.SilentList, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	if err := s.pool.QueryRow(ctx, `
		SELECT
		  count(*) FILTER (WHERE f.kind = 'finding'),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'finding'),
		  count(DISTINCT f.device_id) FILTER (WHERE f.kind = 'finding'),
		  count(*) FILTER (WHERE f.kind = 'finding' AND f.kev),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'finding' AND f.kev),
		  count(*) FILTER (WHERE f.kind = 'unfixed'),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'unfixed'),
		  count(*) FILTER (WHERE f.kind = 'awaiting_vendor'),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'awaiting_vendor'),
		  count(*) FILTER (WHERE f.kind IN ('unfixed', 'awaiting_vendor') AND f.kev),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind IN ('unfixed', 'awaiting_vendor') AND f.kev)
		FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND NOT d.revoked
		WHERE f.resolved_at IS NULL`).Scan(
		&out.Fixable.Findings, &out.Fixable.Advisories, &out.Fixable.Hosts,
		&out.Fixable.KEV.Findings, &out.Fixable.KEV.Advisories,
		&out.Watch.Unfixed.Findings, &out.Watch.Unfixed.Advisories,
		&out.Watch.AwaitingVendor.Findings, &out.Watch.AwaitingVendor.Advisories,
		&out.Watch.KEV.Findings, &out.Watch.KEV.Advisories); err != nil {
		return out, err
	}

	if out.Surface, err = s.SurfaceExposureSummary(ctx); err != nil {
		return out, err
	}
	out.Fixable.Surface = out.Surface.Findings
	out.Fixable.Total = out.Fixable.Advisories + out.Fixable.Surface

	out.SCA.Severity = map[string]int{}
	srows, err := s.pool.Query(ctx, `
		SELECT a.severity, count(*), count(DISTINCT a.device_id)
		FROM alerts a JOIN devices d ON d.id = a.device_id AND NOT d.revoked
		WHERE a.kind = 'sca' AND a.status = 'open' GROUP BY a.severity`)
	if err != nil {
		return out, err
	}
	defer srows.Close()
	for srows.Next() {
		var sev string
		var n, hosts int
		if err := srows.Scan(&sev, &n, &hosts); err != nil {
			return out, err
		}
		out.SCA.Severity[sev] += n
		out.SCA.Total += n
	}
	if err := srows.Err(); err != nil {
		return out, err
	}
	srows.Close()
	return out, s.pool.QueryRow(ctx, `
		SELECT count(DISTINCT a.device_id)
		FROM alerts a JOIN devices d ON d.id = a.device_id AND NOT d.revoked
		WHERE a.kind = 'sca' AND a.status = 'open'`).Scan(&out.SCA.Hosts)
}

// ---- trend --------------------------------------------------------------------

// MaxTrendDays bounds a trend window: one point per day.
const MaxTrendDays = 366

// TrendPoint is the open findings at the end of one UTC day (at the moment of
// the query for today).
type TrendPoint struct {
	Day string `json:"day"`
	// Known is false for days before DefendSec could have matched anything
	// (before the first feed snapshot): their zeros mean "no data".
	Known bool `json:"known"`
	// Open is the fixable findings open that day; KEV the part on the KEV list.
	Open int `json:"open"`
	KEV  int `json:"kev"`
	// Watch is findings with nothing to install (unfixed, awaiting vendor).
	Watch int `json:"watch"`
	// Surface is the external surface findings open that day (critical, high,
	// medium and low; never info) and SurfaceHigh the critical and high part: a
	// series of its own, so a client sees an email-auth fix pay off. A day
	// before the first surface scan is SurfaceKnown false and its zeros mean
	// no data.
	Surface      int  `json:"surface"`
	SurfaceHigh  int  `json:"surfaceHigh"`
	SurfaceKnown bool `json:"surfaceKnown"`
}

// ExposureTrend is the daily series for a window.
type ExposureTrend struct {
	From   time.Time    `json:"from"`
	To     time.Time    `json:"to"`
	Points []TrendPoint `json:"points"`
	// HistorySince is when the oldest feed snapshot was taken: the earliest
	// moment findings could have been recorded. Nil if none exists.
	HistorySince *time.Time `json:"historySince"`
	// SurfaceSince is when the first surface scan started: the earliest moment
	// a surface finding could have been recorded. Nil if none ever ran.
	SurfaceSince *time.Time `json:"surfaceSince"`
}

// ErrBadTrendWindow is returned for a window the trend cannot answer.
var ErrBadTrendWindow = errors.New("bad trend window")

// ExposureTrend counts, for each UTC day in [from, to], the findings that were
// open at the end of that day: first seen by then and not yet resolved. It reads
// first_seen/resolved_at on vuln_findings plus the intervals of findings that
// closed and later came back. Findings whose kind changed over their life (an
// awaiting_vendor finding that became fixable) count under their current kind
// for their whole interval.
func (s *Store) ExposureTrend(ctx context.Context, from, to, now time.Time) (ExposureTrend, error) {
	from, to = from.UTC(), to.UTC()
	if !to.After(from) {
		return ExposureTrend{}, fmt.Errorf("%w: to must be after from", ErrBadTrendWindow)
	}
	if to.After(now) {
		to = now.UTC()
	}
	if to.Before(from) {
		return ExposureTrend{}, fmt.Errorf("%w: window is in the future", ErrBadTrendWindow)
	}
	start, end := from.Truncate(24*time.Hour), to.Truncate(24*time.Hour)
	if int(end.Sub(start)/(24*time.Hour))+1 > MaxTrendDays {
		return ExposureTrend{}, fmt.Errorf("%w: window is longer than %d days", ErrBadTrendWindow, MaxTrendDays)
	}
	out := ExposureTrend{From: from, To: to, Points: []TrendPoint{}}

	var since *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT min(created_at) FROM feed_snapshots`).Scan(&since); err != nil {
		return out, err
	}
	out.HistorySince = since

	rows, err := s.pool.Query(ctx, `
		WITH days AS (
		  SELECT d::date AS day, LEAST((d + interval '1 day') AT TIME ZONE 'UTC', $3::timestamptz) AS asof
		  FROM generate_series($1::timestamp, $2::timestamp, interval '1 day') d
		), spans AS (
		  SELECT f.kind, f.kev, f.first_seen AS opened, f.resolved_at AS closed
		  FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND NOT d.revoked
		  WHERE f.kind IN ('finding', 'unfixed', 'awaiting_vendor')
		  UNION ALL
		  SELECT i.kind, i.kev, i.opened_at, i.closed_at
		  FROM vuln_finding_intervals i JOIN devices d ON d.id = i.device_id AND NOT d.revoked
		  WHERE i.kind IN ('finding', 'unfixed', 'awaiting_vendor')
		)
		SELECT days.day,
		       count(spans.kind) FILTER (WHERE spans.kind = 'finding'),
		       count(spans.kind) FILTER (WHERE spans.kind = 'finding' AND spans.kev),
		       count(spans.kind) FILTER (WHERE spans.kind <> 'finding')
		FROM days
		LEFT JOIN spans ON spans.opened <= days.asof AND (spans.closed IS NULL OR spans.closed > days.asof)
		GROUP BY days.day ORDER BY days.day`, start, end, now.UTC())
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var day time.Time
		var p TrendPoint
		if err := rows.Scan(&day, &p.Open, &p.KEV, &p.Watch); err != nil {
			return out, err
		}
		p.Day = day.Format("2006-01-02")
		// A day is known if it ends after history begins.
		p.Known = since != nil && day.Add(24*time.Hour).After(since.UTC())
		if !p.Known {
			p.Open, p.KEV, p.Watch = 0, 0, 0
		}
		out.Points = append(out.Points, p)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	rows.Close()
	out.SurfaceSince, err = s.surfaceTrend(ctx, start, end, now, out.Points)
	return out, err
}
