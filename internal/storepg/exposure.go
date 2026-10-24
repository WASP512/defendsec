package storepg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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
		// Upgrading end-of-life software is work for this week as much as
		// installing a patch is: both have something to do.
		return []string{"finding", "eol"}, nil
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
	// EOL is set on an end-of-life group (advisory id "EOL:<product>:<cycle>").
	EOL *ExposureEOL `json:"eol"`
}

// ExposureEOL describes the release an end-of-life group is about.
type ExposureEOL struct {
	Product      string `json:"product"`
	ProductLabel string `json:"productLabel"`
	Cycle        string `json:"cycle"`
	// Stage is "eol" (security support ended) or "eoas" (active support
	// ended); Date is the day that stage began.
	Stage string `json:"stage"`
	Date  string `json:"date"`
	// UpgradeTo is the release to move to; empty when none is supported.
	UpgradeTo string `json:"upgradeTo"`
	// Origins are the repositories or vendors the packages came from.
	Origins []string `json:"origins"`
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

// exposureRankedSQL groups the findings of one bucket by advisory and computes
// the six sort keys, all ascending, so a keyset cursor is a row comparison:
//
//	k1  0 if on KEV, else 1
//	k2  minus the KEV date as days since 1970 (0 when none or not KEV): newest first, undated last
//	k3  minus EPSS (1 when none): highest first, unscored last
//	k4  minus CVSS (1 when none, which sorts after any real score)
//	k5  severity label rank
//	k6  advisory id
//
// $1 kinds, $2 resolved?, $3 KEV only?
const exposureRankedSQL = `
	SELECT advisory_id, cve, summary, severity, kev, kev_added, epss, cvss, kinds, host_count, finding_count,
	       host_ids, host_names, packages, fixed, first_seen, resolved_at, awaiting_since,
	       eol_product, eol_cycle, eol_stage, eol_date, eol_label, eol_upgrade, eol_origins,
	       CASE WHEN kev THEN 0 ELSE 1 END AS k1,
	       (CASE WHEN kev THEN -COALESCE(kev_added - DATE '1970-01-01', 0) ELSE 0 END)::text AS k2,
	       (-COALESCE(epss, -1))::text AS k3,
	       (-COALESCE(cvss, -1))::text AS k4,
	       CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END AS k5,
	       advisory_id AS k6
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
	         max(f.eol_product) AS eol_product, max(f.eol_cycle) AS eol_cycle, max(f.eol_stage) AS eol_stage,
	         max(f.eol_date) AS eol_date,
	         COALESCE(max(f.eol_detail->>'productLabel'), '') AS eol_label,
	         COALESCE(max(f.eol_detail->>'upgradeTo'), '') AS eol_upgrade,
	         COALESCE((array_agg(DISTINCT f.origin) FILTER (WHERE f.origin <> ''))[1:3], ARRAY[]::text[]) AS eol_origins
	  FROM vuln_findings f
	  JOIN devices d ON d.id = f.device_id AND NOT d.revoked
	  LEFT JOIN advisories a ON a.id = f.advisory_id
	  WHERE f.kind = ANY($1) AND (f.resolved_at IS NOT NULL) = $2
	  GROUP BY f.advisory_id
	  HAVING NOT $3 OR bool_or(f.kev)
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
	var kevAdded, awaitingSince, eolDate *time.Time
	var ids, names, eolOrigins []string
	var eolProduct, eolCycle, eolStage, eolLabel, eolUpgrade string
	if err := row.Scan(&g.AdvisoryID, &g.CVE, &g.Summary, &g.Severity, &g.KEV, &kevAdded, &g.EPSS, &g.CVSS,
		&g.Kinds, &g.HostCount, &g.FindingCount, &ids, &names, &g.Packages, &g.Fixed, &g.FirstSeen, &g.ResolvedAt, &awaitingSince,
		&eolProduct, &eolCycle, &eolStage, &eolDate, &eolLabel, &eolUpgrade, &eolOrigins,
		&c.K1, &c.K2, &c.K3, &c.K4, &c.K5, &c.K6); err != nil {
		return g, c, err
	}
	if eolProduct != "" {
		d := ""
		if t := dateText(eolDate); t != nil {
			d = *t
		}
		if eolOrigins == nil {
			eolOrigins = []string{}
		}
		g.EOL = &ExposureEOL{Product: eolProduct, ProductLabel: eolLabel, Cycle: eolCycle, Stage: eolStage,
			Date: d, UpgradeTo: eolUpgrade, Origins: eolOrigins}
	}
	g.FirstSeen = g.FirstSeen.UTC()
	if g.ResolvedAt != nil {
		t := g.ResolvedAt.UTC()
		g.ResolvedAt = &t
	}
	g.KEVAdded = dateText(kevAdded)
	g.AwaitingSince = dateText(awaitingSince)
	g.Hosts = make([]HostRef, 0, len(ids))
	for i, id := range ids {
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
		// Findings, Advisories and Hosts count both kinds of fixable work:
		// a patch to install and software past end of life to upgrade.
		Findings   int           `json:"findings"`
		Advisories int           `json:"advisories"`
		Hosts      int           `json:"hosts"`
		KEV        ExposureCount `json:"kev"`
		// EOL is the part of the above that is end-of-life software.
		EOL ExposureCount `json:"eol"`
	} `json:"fixable"`
	Watch struct {
		Unfixed        ExposureCount `json:"unfixed"`
		AwaitingVendor ExposureCount `json:"awaitingVendor"`
		// KEV is the part of Unfixed and AwaitingVendor that is exploited in
		// the wild and has nothing to install: it needs a mitigation.
		KEV ExposureCount `json:"kev"`
	} `json:"watch"`
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
		SELECT count(*), count(*) FILTER (WHERE s.coverage = 'covered'), count(*) FILTER (WHERE d.last_seen < $1)
		FROM devices d LEFT JOIN host_vuln_state s ON s.device_id = d.id
		WHERE NOT d.revoked`, cutoff).Scan(&out.Hosts.Total, &out.Hosts.Assessed, &out.Hosts.Silent); err != nil {
		return out, err
	}
	out.Hosts.NotAssessed = out.Hosts.Total - out.Hosts.Assessed

	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, last_seen FROM devices WHERE NOT revoked AND last_seen < $1
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
		  count(*) FILTER (WHERE f.kind IN ('finding', 'eol')),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind IN ('finding', 'eol')),
		  count(DISTINCT f.device_id) FILTER (WHERE f.kind IN ('finding', 'eol')),
		  count(*) FILTER (WHERE f.kind = 'finding' AND f.kev),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'finding' AND f.kev),
		  count(*) FILTER (WHERE f.kind = 'unfixed'),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'unfixed'),
		  count(*) FILTER (WHERE f.kind = 'awaiting_vendor'),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'awaiting_vendor'),
		  count(*) FILTER (WHERE f.kind IN ('unfixed', 'awaiting_vendor') AND f.kev),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind IN ('unfixed', 'awaiting_vendor') AND f.kev),
		  count(*) FILTER (WHERE f.kind = 'eol'),
		  count(DISTINCT f.advisory_id) FILTER (WHERE f.kind = 'eol')
		FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND NOT d.revoked
		WHERE f.resolved_at IS NULL`).Scan(
		&out.Fixable.Findings, &out.Fixable.Advisories, &out.Fixable.Hosts,
		&out.Fixable.KEV.Findings, &out.Fixable.KEV.Advisories,
		&out.Watch.Unfixed.Findings, &out.Watch.Unfixed.Advisories,
		&out.Watch.AwaitingVendor.Findings, &out.Watch.AwaitingVendor.Advisories,
		&out.Watch.KEV.Findings, &out.Watch.KEV.Advisories,
		&out.Fixable.EOL.Findings, &out.Fixable.EOL.Advisories); err != nil {
		return out, err
	}

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
}

// ExposureTrend is the daily series for a window.
type ExposureTrend struct {
	From   time.Time    `json:"from"`
	To     time.Time    `json:"to"`
	Points []TrendPoint `json:"points"`
	// HistorySince is when the oldest feed snapshot was taken: the earliest
	// moment findings could have been recorded. Nil if none exists.
	HistorySince *time.Time `json:"historySince"`
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
		  SELECT d::date AS day, LEAST(d + interval '1 day', $3::timestamptz) AS asof
		  FROM generate_series($1::timestamp, $2::timestamp, interval '1 day') d
		), spans AS (
		  SELECT f.kind, f.kev, f.first_seen AS opened, f.resolved_at AS closed
		  FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND NOT d.revoked
		  WHERE f.kind IN ('finding', 'eol', 'unfixed', 'awaiting_vendor')
		  UNION ALL
		  SELECT i.kind, i.kev, i.opened_at, i.closed_at
		  FROM vuln_finding_intervals i JOIN devices d ON d.id = i.device_id AND NOT d.revoked
		  WHERE i.kind IN ('finding', 'eol', 'unfixed', 'awaiting_vendor')
		)
		SELECT days.day,
		       count(spans.kind) FILTER (WHERE spans.kind IN ('finding', 'eol')),
		       count(spans.kind) FILTER (WHERE spans.kind = 'finding' AND spans.kev),
		       count(spans.kind) FILTER (WHERE spans.kind NOT IN ('finding', 'eol'))
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
	return out, rows.Err()
}
