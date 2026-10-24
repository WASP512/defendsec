package storepg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/vuln"
)

// Store implements vuln.RangeSource, so the matcher runs straight off the
// advisory tables.
var _ vuln.RangeSource = (*Store)(nil)

// upstreamEcosystems are the distro-less ranges that describe software
// installed outside a distro's package set. OSV language ecosystems (PyPI, npm,
// Go, ...) are deliberately absent: a Linux package named "requests" is not the
// PyPI package of that name, and the inventory has no way to say which it is.
// "legacy" is the operator-supplied single-floor catalogue.
var upstreamEcosystems = []string{legacyEcosystem}

const candidateColumns = `
	r.id, r.advisory_id, COALESCE(a.cve,''), COALESCE(a.severity,'unknown'), COALESCE(a.summary,''),
	COALESCE(a.kev,false), a.epss, a.cvss_score,
	r.ecosystem, COALESCE(r.distro,''), COALESCE(r.release,''), r.package, COALESCE(r.source_package,''),
	COALESCE(r.introduced,''), COALESCE(r.fixed,''), r.fix_state, r.snapshot_id, r.feed, COALESCE(r.issued::text,'')`

const (
	distroCandidatesSQL = `
		SELECT ` + candidateColumns + `
		FROM advisory_ranges r JOIN advisories a ON a.id = r.advisory_id
		WHERE r.distro = $1 AND (r.release = $2 OR r.release IS NULL)
		  AND (r.package = ANY($3) OR r.source_package = ANY($3))
		ORDER BY r.advisory_id, r.id`

	upstreamCandidatesSQL = `
		SELECT ` + candidateColumns + `
		FROM advisory_ranges r JOIN advisories a ON a.id = r.advisory_id
		WHERE r.distro IS NULL AND r.ecosystem = ANY($1)
		ORDER BY r.advisory_id, r.id`

	distroCoveredSQL = `
		SELECT EXISTS (SELECT 1 FROM advisory_ranges
		               WHERE distro = $1 AND (release = $2 OR release IS NULL))`
)

// DistroRanges implements vuln.RangeSource.
func (s *Store) DistroRanges(ctx context.Context, distro, release string, names []string) ([]vuln.Candidate, error) {
	if len(names) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, distroCandidatesSQL, distro, release, names)
	if err != nil {
		return nil, err
	}
	return s.scanCandidates(ctx, rows)
}

// UpstreamRanges implements vuln.RangeSource. names is not used to narrow the
// query: upstream package names are matched by canonical form in the matcher,
// and the catalogue of upstream floors is small.
func (s *Store) UpstreamRanges(ctx context.Context, _ []string) ([]vuln.Candidate, error) {
	rows, err := s.pool.Query(ctx, upstreamCandidatesSQL, upstreamEcosystems)
	if err != nil {
		return nil, err
	}
	return s.scanCandidates(ctx, rows)
}

// DistroCovered implements vuln.RangeSource.
func (s *Store) DistroCovered(ctx context.Context, distro, release string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, distroCoveredSQL, distro, release).Scan(&ok)
	return ok, err
}

func (s *Store) scanCandidates(ctx context.Context, rows pgx.Rows) ([]vuln.Candidate, error) {
	defer rows.Close()
	var out []vuln.Candidate
	for rows.Next() {
		var c vuln.Candidate
		if err := rows.Scan(&c.RangeID, &c.AdvisoryID, &c.CVE, &c.Severity, &c.Summary,
			&c.KEV, &c.EPSS, &c.CVSS,
			&c.Ecosystem, &c.Distro, &c.Release, &c.Package, &c.SourcePackage,
			&c.Introduced, &c.Fixed, &c.State, &c.SnapshotID, &c.Feed, &c.Issued); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	return out, s.stampFeedDates(ctx, out)
}

// stampFeedDates fills in each candidate's feed name (when the range predates
// the feed column) and the date its feed was fetched, from the snapshot that
// loaded the range.
func (s *Store) stampFeedDates(ctx context.Context, cands []vuln.Candidate) error {
	snaps := map[int64]FeedSnapshot{}
	for i := range cands {
		c := &cands[i]
		if c.Feed == "" {
			c.Feed = fallbackFeedLabel(c)
		}
		if c.SnapshotID == nil {
			continue
		}
		snap, ok := snaps[*c.SnapshotID]
		if !ok {
			var err error
			snap, err = s.GetFeedSnapshot(ctx, *c.SnapshotID)
			if err != nil {
				return fmt.Errorf("snapshot %d: %w", *c.SnapshotID, err)
			}
			snaps[*c.SnapshotID] = snap
		}
		at := snap.CreatedAt
		for _, f := range snap.Feeds {
			if f.Name == c.Feed {
				at = f.FetchedAt
				break
			}
		}
		at = at.UTC()
		c.FeedDate = &at
	}
	return nil
}

func fallbackFeedLabel(c *vuln.Candidate) string {
	switch {
	case c.Distro != "" && c.Release != "":
		return c.Distro + " " + c.Release
	case c.Distro != "":
		return c.Distro
	case c.Ecosystem != "":
		return c.Ecosystem
	}
	return "unknown"
}

// ---- persistence -------------------------------------------------------------

// HostVulnState is what the last match run for a host examined.
type HostVulnState struct {
	DeviceID     string    `json:"deviceId"`
	Distro       string    `json:"distro"`
	Release      string    `json:"release"`
	Coverage     string    `json:"coverage"`
	Packages     int       `json:"packages"`
	DistroMapped int       `json:"distroMapped"`
	Upstream     int       `json:"upstream"`
	Undecidable  int       `json:"undecidable"`
	NotAffected  int       `json:"notAffected"`
	SnapshotID   *int64    `json:"snapshotId"`
	MatchedAt    time.Time `json:"matchedAt"`
}

// VulnFinding is a stored finding. SnapshotID, RangeID, Feed and FeedDate say
// exactly what data the finding was computed from.
type VulnFinding struct {
	ID            int64      `json:"id"`
	DeviceID      string     `json:"deviceId"`
	Hostname      string     `json:"hostname,omitempty"`
	AdvisoryID    string     `json:"advisoryId"`
	CVE           string     `json:"cve"`
	Family        string     `json:"family"`
	Key           string     `json:"key"`
	RangeID       *int64     `json:"rangeId"`
	SnapshotID    *int64     `json:"snapshotId"`
	Feed          string     `json:"feed"`
	FeedDate      *time.Time `json:"feedDate"`
	Kind          string     `json:"kind"`
	Basis         string     `json:"basis"`
	Package       string     `json:"package"`
	SourcePackage string     `json:"sourcePackage"`
	Installed     string     `json:"installed"`
	Fixed         string     `json:"fixed"`
	FixState      string     `json:"fixState"`
	Severity      string     `json:"severity"`
	Summary       string     `json:"summary"`
	KEV           bool       `json:"kev"`
	EPSS          *float64   `json:"epss"`
	CVSS          *float64   `json:"cvss"`
	Reason        string     `json:"reason"`
	FirstSeen     time.Time  `json:"firstSeen"`
	LastSeen      time.Time  `json:"lastSeen"`
	ResolvedAt    *time.Time `json:"resolvedAt"`
	// Resolution says how a closed finding closed (see the Resolution
	// constants); ResolvedInstalled is the version the host had then.
	Resolution        string `json:"resolution"`
	ResolvedInstalled string `json:"resolvedInstalled"`
	// UpstreamFixedOn is, for an awaiting_vendor finding, the date Red Hat
	// shipped the fix (YYYY-MM-DD); empty otherwise.
	UpstreamFixedOn string `json:"upstreamFixedOn"`
}

// FindingKey is the key the console's triage store uses for a finding, so an
// acknowledgement survives the move from client-side matching.
func FindingKey(deviceID, advisoryID, family string) string {
	return deviceID + ":" + advisoryID + ":" + strings.ToLower(family)
}

const (
	upsertFindingSQL = `
		INSERT INTO vuln_findings (
			device_id, advisory_id, family, range_id, snapshot_id, feed, feed_date, kind, basis,
			package, source_package, installed, fixed, fix_state, cve, severity, summary,
			kev, epss, cvss_score, reason, upstream_fixed_on, first_seen, last_seen, resolved_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21, NULLIF($22,'')::date, now(), now(), NULL)
		ON CONFLICT (device_id, advisory_id, family) DO UPDATE SET
			range_id=EXCLUDED.range_id, snapshot_id=EXCLUDED.snapshot_id, feed=EXCLUDED.feed,
			feed_date=EXCLUDED.feed_date, kind=EXCLUDED.kind, basis=EXCLUDED.basis,
			package=EXCLUDED.package, source_package=EXCLUDED.source_package,
			installed=EXCLUDED.installed, fixed=EXCLUDED.fixed, fix_state=EXCLUDED.fix_state,
			cve=EXCLUDED.cve, severity=EXCLUDED.severity, summary=EXCLUDED.summary,
			kev=EXCLUDED.kev, epss=EXCLUDED.epss, cvss_score=EXCLUDED.cvss_score, reason=EXCLUDED.reason,
			upstream_fixed_on=EXCLUDED.upstream_fixed_on,
			last_seen=now(),
			first_seen=CASE WHEN vuln_findings.resolved_at IS NULL THEN vuln_findings.first_seen ELSE now() END,
			resolved_at=NULL, resolution='', resolved_installed=''`

	// A closed finding that comes back restarts first_seen; the interval that
	// ended is copied to vuln_finding_intervals first so the history survives.
	archiveReopenedSQL = `
		INSERT INTO vuln_finding_intervals (device_id, advisory_id, family, kind, kev, opened_at, closed_at, resolution)
		SELECT f.device_id, f.advisory_id, f.family, f.kind, f.kev, f.first_seen, f.resolved_at, f.resolution
		FROM vuln_findings f
		JOIN unnest($2::text[], $3::text[]) AS k(advisory_id, family)
		  ON k.advisory_id = f.advisory_id AND k.family = f.family
		WHERE f.device_id = $1 AND f.resolved_at IS NOT NULL
		ON CONFLICT DO NOTHING`

	// Anything the run did not confirm is closed, not deleted.
	staleFindingsSQL = `
		SELECT id, package, fixed FROM vuln_findings
		WHERE device_id = $1 AND resolved_at IS NULL AND last_seen < $2`

	closeFindingsSQL = `
		UPDATE vuln_findings f SET resolved_at = now(), resolution = c.resolution, resolved_installed = c.installed
		FROM unnest($1::bigint[], $2::text[], $3::text[]) AS c(id, resolution, installed)
		WHERE f.id = c.id`

	upsertHostStateSQL = `
		INSERT INTO host_vuln_state (device_id, distro, release, coverage, packages, distro_mapped,
		                             upstream, undecidable, not_affected, snapshot_id, matched_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10, now())
		ON CONFLICT (device_id) DO UPDATE SET
			distro=EXCLUDED.distro, release=EXCLUDED.release, coverage=EXCLUDED.coverage,
			packages=EXCLUDED.packages, distro_mapped=EXCLUDED.distro_mapped, upstream=EXCLUDED.upstream,
			undecidable=EXCLUDED.undecidable, not_affected=EXCLUDED.not_affected,
			snapshot_id=EXCLUDED.snapshot_id, matched_at=now()`

	findingColumns = `
		f.id, f.device_id, COALESCE(d.hostname,''), f.advisory_id, f.cve, f.family, f.range_id, f.snapshot_id,
		f.feed, f.feed_date, f.kind, f.basis, f.package, f.source_package, f.installed, f.fixed,
		f.fix_state, f.severity, f.summary, f.kev, f.epss, f.cvss_score, f.reason,
		f.first_seen, f.last_seen, f.resolved_at, f.resolution, f.resolved_installed,
		COALESCE(f.upstream_fixed_on::text, '')`
)

// Resolution says how a finding came to be closed (vuln_findings.resolution).
const (
	ResolutionUnknown         = ""
	ResolutionFixed           = "fixed"
	ResolutionPackageRemoved  = "package_removed"
	ResolutionNoLongerAffects = "no_longer_affected"
)

// Inventory is the host's installed packages at the time of a match, used to
// tell a finding closed because the host installed the fix from one closed
// because the package went away or the advisory data changed.
type Inventory struct {
	Scheme vuln.Scheme
	// Versions maps an installed package name to its version.
	Versions map[string]string
	// InstalledKBs, when non-nil, makes this the inventory of a Windows host
	// read through an RMM: findings are keyed by KB, and a KB that is installed
	// now closed its findings as fixed. Any other closed finding is the RMM no
	// longer listing the update (superseded, withdrawn, or no longer offered).
	InstalledKBs map[string]bool
}

// Classify says why a finding for pkg (fixed in fixed, "" if no fix) is no
// longer confirmed. A nil inventory cannot say.
func (inv *Inventory) Classify(pkg, fixed string) (resolution, installed string) {
	if inv == nil {
		return ResolutionUnknown, ""
	}
	if inv.InstalledKBs != nil {
		if inv.InstalledKBs[pkg] {
			return ResolutionFixed, "installed"
		}
		return ResolutionNoLongerAffects, ""
	}
	cur, ok := inv.Versions[pkg]
	if !ok {
		return ResolutionPackageRemoved, ""
	}
	if fixed != "" && vuln.Compare(cur, fixed, inv.Scheme) >= 0 {
		return ResolutionFixed, cur
	}
	return ResolutionNoLongerAffects, cur
}

// RecordFindings stores the outcome of matching one host without knowing the
// host's inventory; findings it closes carry no resolution. See
// RecordFindingsFor.
func (s *Store) RecordFindings(ctx context.Context, deviceID string, res vuln.Result, snapshotID *int64) error {
	return s.RecordFindingsFor(ctx, deviceID, res, snapshotID, nil)
}

// RecordFindingsFor stores the outcome of matching one host: it upserts every
// finding, closes the host's findings the run did not confirm (recording from
// inv why, when it is given), and records what was examined. All in one
// transaction, so a reader never sees a half-written host. snapshotID is the
// latest feed snapshot at match time.
func (s *Store) RecordFindingsFor(ctx context.Context, deviceID string, res vuln.Result, snapshotID *int64, inv *Inventory) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := recordFindingsTx(ctx, tx, deviceID, res, inv); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, upsertHostStateSQL, deviceID, res.Distro, res.Release, string(res.Coverage),
		res.Stats.Packages, res.Stats.DistroMapped, res.Stats.Upstream, res.Stats.Undecidable,
		res.Stats.NotAffected, snapshotID); err != nil {
		return fmt.Errorf("record host state: %w", err)
	}
	return tx.Commit(ctx)
}

// recordFindingsTx upserts a host's findings and closes the ones the run did
// not confirm, inside the caller's transaction. The caller records the host's
// state: host_vuln_state for an agent host, host_patch_state for an RMM host.
func recordFindingsTx(ctx context.Context, tx pgx.Tx, deviceID string, res vuln.Result, inv *Inventory) error {
	// The transaction's clock, not the caller's: the stale sweep compares with
	// last_seen values this same transaction wrote with now().
	var start time.Time
	if err := tx.QueryRow(ctx, `SELECT now()`).Scan(&start); err != nil {
		return err
	}
	advisories, families := make([]string, 0, len(res.Findings)), make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		family := f.SourcePackage
		if family == "" {
			family = f.Package
		}
		advisories, families = append(advisories, f.AdvisoryID), append(families, family)
	}
	if len(advisories) > 0 {
		if _, err := tx.Exec(ctx, archiveReopenedSQL, deviceID, advisories, families); err != nil {
			return fmt.Errorf("archive reopened findings: %w", err)
		}
	}
	for _, f := range res.Findings {
		var rangeID *int64
		if f.RangeID != 0 {
			id := f.RangeID
			rangeID = &id
		}
		family := f.SourcePackage
		if family == "" {
			family = f.Package
		}
		if _, err := tx.Exec(ctx, upsertFindingSQL,
			deviceID, f.AdvisoryID, family, rangeID, f.SnapshotID, f.Feed, f.FeedDate, string(f.Kind), string(f.Basis),
			f.Package, f.SourcePackage, f.Installed, f.Fixed, f.FixState, f.CVE, normSeverity(f.Severity), f.Summary,
			f.KEV, f.EPSS, f.CVSS, f.Reason, f.UpstreamFixedOn); err != nil {
			return fmt.Errorf("record finding %s: %w", f.AdvisoryID, err)
		}
	}
	if err := closeStaleFindings(ctx, tx, deviceID, start, inv); err != nil {
		return fmt.Errorf("close stale findings: %w", err)
	}
	return nil
}

// closeStaleFindings closes every open finding of the host that the run did not
// confirm, recording why when the inventory is known.
func closeStaleFindings(ctx context.Context, tx pgx.Tx, deviceID string, start time.Time, inv *Inventory) error {
	rows, err := tx.Query(ctx, staleFindingsSQL, deviceID, start)
	if err != nil {
		return err
	}
	var ids []int64
	var resolutions, installed []string
	for rows.Next() {
		var id int64
		var pkg, fixed string
		if err := rows.Scan(&id, &pkg, &fixed); err != nil {
			rows.Close()
			return err
		}
		r, v := inv.Classify(pkg, fixed)
		ids, resolutions, installed = append(ids, id), append(resolutions, r), append(installed, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = tx.Exec(ctx, closeFindingsSQL, ids, resolutions, installed)
	return err
}

func normSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low":
		return s
	}
	return "unknown"
}

// FindingFilter selects stored findings.
type FindingFilter struct {
	DeviceID string
	// Kind is "finding", "awaiting_vendor", "unfixed", "informational" or ""
	// for all four.
	Kind string
	// IncludeResolved adds findings that have since been closed.
	IncludeResolved bool
	Limit           int
}

// MaxFindingsPage bounds one list response.
const MaxFindingsPage = 5000

// ListFindings returns stored findings, most urgent first: KEV, severity, then
// EPSS.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]VulnFinding, error) {
	if f.Limit <= 0 || f.Limit > MaxFindingsPage {
		f.Limit = 500
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+findingColumns+`
		FROM vuln_findings f LEFT JOIN devices d ON d.id = f.device_id
		WHERE ($1 = '' OR f.device_id = $1)
		  AND ($2 = '' OR f.kind = $2)
		  AND ($3 OR f.resolved_at IS NULL)
		ORDER BY array_position(ARRAY['finding','awaiting_vendor','unfixed','informational'], f.kind), f.kev DESC,
		         array_position(ARRAY['critical','high','medium','low','unknown'], f.severity),
		         f.epss DESC NULLS LAST, f.cvss_score DESC NULLS LAST, f.device_id, f.advisory_id, f.family
		LIMIT $4`, f.DeviceID, f.Kind, f.IncludeResolved, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VulnFinding
	for rows.Next() {
		v, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetFinding returns one finding by id; pgx.ErrNoRows if there is none.
func (s *Store) GetFinding(ctx context.Context, id int64) (VulnFinding, error) {
	return scanFinding(s.pool.QueryRow(ctx, `
		SELECT `+findingColumns+`
		FROM vuln_findings f LEFT JOIN devices d ON d.id = f.device_id
		WHERE f.id = $1`, id))
}

// ErrNoFinding is returned when a finding does not exist.
var ErrNoFinding = errors.New("finding not found")

func scanFinding(row pgx.Row) (VulnFinding, error) {
	var v VulnFinding
	if err := row.Scan(&v.ID, &v.DeviceID, &v.Hostname, &v.AdvisoryID, &v.CVE, &v.Family, &v.RangeID, &v.SnapshotID,
		&v.Feed, &v.FeedDate, &v.Kind, &v.Basis, &v.Package, &v.SourcePackage, &v.Installed, &v.Fixed,
		&v.FixState, &v.Severity, &v.Summary, &v.KEV, &v.EPSS, &v.CVSS, &v.Reason,
		&v.FirstSeen, &v.LastSeen, &v.ResolvedAt, &v.Resolution, &v.ResolvedInstalled, &v.UpstreamFixedOn); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VulnFinding{}, ErrNoFinding
		}
		return VulnFinding{}, err
	}
	v.Key = FindingKey(v.DeviceID, v.AdvisoryID, v.Family)
	return v, nil
}

// GetHostVulnState returns what the last match run for a host examined; ok is
// false if the host has never been matched.
func (s *Store) GetHostVulnState(ctx context.Context, deviceID string) (HostVulnState, bool, error) {
	var st HostVulnState
	err := s.pool.QueryRow(ctx, `
		SELECT device_id, distro, release, coverage, packages, distro_mapped, upstream, undecidable,
		       not_affected, snapshot_id, matched_at
		FROM host_vuln_state WHERE device_id = $1`, deviceID).Scan(&st.DeviceID, &st.Distro, &st.Release,
		&st.Coverage, &st.Packages, &st.DistroMapped, &st.Upstream, &st.Undecidable, &st.NotAffected,
		&st.SnapshotID, &st.MatchedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return HostVulnState{}, false, nil
	}
	return st, err == nil, err
}

// FindingDetail is a finding plus the evidence behind it: the advisory, the
// range that matched (if it still exists) and the feeds in the snapshot.
type FindingDetail struct {
	Finding  VulnFinding
	Advisory *Advisory
	Range    *AdvisoryRange
	Snapshot *FeedSnapshot
}

// GetFindingDetail loads a finding with its advisory, matched range and
// snapshot. The range is looked up by id and then checked against the finding's
// advisory: ranges are replaced on every feed sync, so an old id can be reused
// by a different advisory, and showing that as evidence would be wrong.
func (s *Store) GetFindingDetail(ctx context.Context, id int64) (FindingDetail, error) {
	f, err := s.GetFinding(ctx, id)
	if err != nil {
		return FindingDetail{}, err
	}
	d := FindingDetail{Finding: f}
	if adv, err := s.GetAdvisory(ctx, f.AdvisoryID); err == nil {
		d.Advisory = &adv
		if f.RangeID != nil {
			for i := range adv.Ranges {
				if adv.Ranges[i].ID == *f.RangeID {
					r := adv.Ranges[i]
					d.Range = &r
				}
			}
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return FindingDetail{}, err
	}
	if f.SnapshotID != nil {
		if snap, err := s.GetFeedSnapshot(ctx, *f.SnapshotID); err == nil {
			d.Snapshot = &snap
		}
	}
	return d, nil
}

// DeviceFindingsSummary is one host's standing, compact enough to fetch for a
// whole fleet. SeriousKeys are the triage keys of its open findings that are
// critical, high or on the KEV list (a KEV entry awaiting the vendor's release
// included), so a caller can drop the acknowledged ones without fetching every
// finding; capped at SummaryKeyCap.
type DeviceFindingsSummary struct {
	DeviceID      string `json:"deviceId"`
	Distro        string `json:"distro"`
	Release       string `json:"release"`
	Coverage      string `json:"coverage"`
	Open          int    `json:"open"`
	KEV           int    `json:"kev"`
	Unfixed       int    `json:"unfixed"`
	Informational int    `json:"informational"`
	// AwaitingVendor: fixed by Red Hat, not yet released by the host's own
	// distribution (Rocky, AlmaLinux). Nothing to install, so it is not in Open;
	// KEVAwaitingVendor is the part of it that is exploited in the wild and
	// still needs the red callout.
	AwaitingVendor    int       `json:"awaitingVendor"`
	KEVAwaitingVendor int       `json:"kevAwaitingVendor"`
	SeriousKeys       []string  `json:"seriousKeys"`
	MatchedAt         time.Time `json:"matchedAt"`
}

// SummaryKeyCap bounds SeriousKeys per host.
const SummaryKeyCap = 200

const findingsSummarySQL = `
	SELECT s.device_id, s.distro, s.release, s.coverage, s.matched_at,
	       COALESCE(a.open, 0), COALESCE(a.kev, 0), COALESCE(a.unfixed, 0), COALESCE(a.info, 0),
	       COALESCE(a.awaiting, 0), COALESCE(a.kev_awaiting, 0),
	       COALESCE(a.keys, ARRAY[]::text[])
	FROM host_vuln_state s
	LEFT JOIN (
	  SELECT f.device_id,
	         count(*) FILTER (WHERE f.kind = 'finding') AS open,
	         count(*) FILTER (WHERE f.kind = 'finding' AND f.kev) AS kev,
	         count(*) FILTER (WHERE f.kind = 'unfixed') AS unfixed,
	         count(*) FILTER (WHERE f.kind = 'informational') AS info,
	         count(*) FILTER (WHERE f.kind = 'awaiting_vendor') AS awaiting,
	         count(*) FILTER (WHERE f.kind = 'awaiting_vendor' AND f.kev) AS kev_awaiting,
	         (array_agg(f.device_id || ':' || f.advisory_id || ':' || lower(f.family) ORDER BY f.advisory_id)
	            FILTER (WHERE (f.kind = 'finding' AND (f.kev OR f.severity IN ('critical', 'high')))
	                       OR (f.kind = 'awaiting_vendor' AND f.kev)))[1:` + "200" + `] AS keys
	  FROM vuln_findings f WHERE f.resolved_at IS NULL GROUP BY f.device_id
	) a ON a.device_id = s.device_id
	WHERE ($1 = '' OR s.device_id = $1)
	ORDER BY s.device_id`

// FindingsSummary returns one row per host that has been matched, or just the
// one named by deviceID.
func (s *Store) FindingsSummary(ctx context.Context, deviceID string) ([]DeviceFindingsSummary, error) {
	rows, err := s.pool.Query(ctx, findingsSummarySQL, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DeviceFindingsSummary{}
	for rows.Next() {
		var d DeviceFindingsSummary
		if err := rows.Scan(&d.DeviceID, &d.Distro, &d.Release, &d.Coverage, &d.MatchedAt,
			&d.Open, &d.KEV, &d.Unfixed, &d.Informational, &d.AwaitingVendor, &d.KEVAwaitingVendor, &d.SeriousKeys); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
