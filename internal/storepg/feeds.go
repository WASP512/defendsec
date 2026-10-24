package storepg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Feed loading and status (migration 020). defendsec-feeds is the only writer.
//
// Several feeds describe the same CVE (Ubuntu, Debian, Red Hat, SUSE, OSV, then
// KEV and EPSS on top), so none of these methods replaces an advisory the way
// UpsertAdvisoryWithRanges does. A feed owns a *scope* of ranges
// (a distro+release, or an upstream ecosystem): loading it replaces exactly that
// scope and merges its advisory metadata into the shared advisory rows.

// ErrInvalidRecord marks a record that FeedLoad.Add refused for its own
// content (bad severity, a range outside the declared scopes, ...), as opposed
// to a database failure. A feed sync skips and counts these; it aborts on
// anything else.
var ErrInvalidRecord = errors.New("invalid feed record")

// RangeScope names the set of advisory_ranges rows one feed owns. With Distro
// set it is every range for that distro and release (Release "" = the rolling
// release, stored as NULL); otherwise it is the distro-less ranges of Ecosystem.
type RangeScope struct {
	Distro    string
	Release   string
	Ecosystem string
}

func (sc RangeScope) validate() error {
	if sc.Distro == "" && sc.Ecosystem == "" {
		return errors.New("range scope needs a distro or an ecosystem")
	}
	if sc.Distro == "" && sc.Release != "" {
		return errors.New("range scope: release requires distro")
	}
	if sc.Ecosystem == legacyEcosystem {
		return fmt.Errorf("range scope: ecosystem %q is reserved", legacyEcosystem)
	}
	return nil
}

func (sc RangeScope) contains(r AdvisoryRange) bool {
	if sc.Distro != "" {
		return r.Distro == sc.Distro && r.Release == sc.Release
	}
	return r.Distro == "" && r.Ecosystem == sc.Ecosystem
}

// FeedLoadResult counts what a FeedLoad committed.
type FeedLoadResult struct {
	Advisories int // distinct advisories written or merged
	Ranges     int // distinct ranges inserted
}

// FeedLoad stages one feed's advisories and ranges in a transaction. Add
// streams records in (bounded memory); Commit replaces the feed's scope and
// merges advisory metadata atomically. Until Commit nothing is visible, and a
// failed or abandoned load leaves the previous data in place.
type FeedLoad struct {
	tx       pgx.Tx
	source   string
	snapshot *int64
	scopes   []RangeScope

	advRows [][]any
	rngRows [][]any
	seenAdv map[[16]byte]struct{}
	seenRng map[[16]byte]struct{}
	nAdv    int
	nRng    int
	done    bool
}

const feedFlushRows = 20000

const (
	createFeedTempSQL = `
		CREATE TEMP TABLE feed_adv_tmp (
			id TEXT, cve TEXT, severity TEXT, summary TEXT, cvss_vector TEXT,
			cvss_score NUMERIC, cwe TEXT[]
		) ON COMMIT DROP;
		CREATE TEMP TABLE feed_rng_tmp (
			advisory_id TEXT, ecosystem TEXT, distro TEXT, release TEXT, package TEXT,
			source_package TEXT, introduced TEXT, fixed TEXT, fix_state TEXT
		) ON COMMIT DROP;`

	// Merge rules when several feeds describe one CVE: the highest severity and
	// the highest CVSS score any feed asserts win (a conservative exposure
	// view), the vector travels with its score, and empty fields are filled.
	// A KEV stub (source 'cisa-kev') is replaced by the first real record.
	mergeAdvisoriesSQL = `
		INSERT INTO advisories (id, cve, package, below, severity, summary, source,
		                        cvss_vector, cvss_score, cwe, snapshot_id, updated_at)
		SELECT DISTINCT ON (id) id, cve, '', '', severity, summary, $1, cvss_vector, cvss_score, cwe, $2, now()
		FROM feed_adv_tmp
		ORDER BY id, (summary <> '') DESC
		ON CONFLICT (id) DO UPDATE SET
			cve = CASE WHEN advisories.cve = '' THEN EXCLUDED.cve ELSE advisories.cve END,
			severity = CASE WHEN COALESCE(array_position(ARRAY['unknown','low','medium','high','critical'], EXCLUDED.severity), 1)
			                   > COALESCE(array_position(ARRAY['unknown','low','medium','high','critical'], advisories.severity), 1)
			                THEN EXCLUDED.severity ELSE advisories.severity END,
			summary = CASE WHEN advisories.summary = '' OR advisories.source = 'cisa-kev'
			               THEN EXCLUDED.summary ELSE advisories.summary END,
			source = CASE WHEN advisories.source = 'cisa-kev' THEN EXCLUDED.source ELSE advisories.source END,
			cvss_vector = CASE WHEN EXCLUDED.cvss_score IS NOT NULL
			                    AND (advisories.cvss_score IS NULL OR EXCLUDED.cvss_score > advisories.cvss_score)
			                   THEN EXCLUDED.cvss_vector
			                   WHEN advisories.cvss_vector = '' THEN EXCLUDED.cvss_vector
			                   ELSE advisories.cvss_vector END,
			cvss_score = GREATEST(advisories.cvss_score, EXCLUDED.cvss_score),
			cwe = CASE WHEN cardinality(advisories.cwe) = 0 THEN EXCLUDED.cwe ELSE advisories.cwe END,
			snapshot_id = EXCLUDED.snapshot_id,
			updated_at = now()`

	deleteScopeDistroSQL = `
		DELETE FROM advisory_ranges
		WHERE distro = $1 AND release IS NOT DISTINCT FROM NULLIF($2, '')`
	deleteScopeEcosystemSQL = `
		DELETE FROM advisory_ranges
		WHERE distro IS NULL AND ecosystem = $1`

	insertRangesFromTmpSQL = `
		INSERT INTO advisory_ranges (advisory_id, ecosystem, distro, release, package, source_package,
		                             introduced, fixed, fix_state, snapshot_id)
		SELECT advisory_id, ecosystem, NULLIF(distro, ''), NULLIF(release, ''), package,
		       NULLIF(source_package, ''), NULLIF(introduced, ''), NULLIF(fixed, ''), fix_state, $1
		FROM feed_rng_tmp
		ON CONFLICT DO NOTHING`
)

// BeginFeedLoad starts a load. source labels new advisory rows (the feed name);
// scopes are the range sets this feed owns and replaces; snapshotID, if
// non-zero, is stamped on every row written.
func (s *Store) BeginFeedLoad(ctx context.Context, source string, scopes []RangeScope, snapshotID int64) (*FeedLoad, error) {
	if strings.TrimSpace(source) == "" {
		return nil, errors.New("feed load needs a source name")
	}
	if len(scopes) == 0 {
		return nil, errors.New("feed load needs at least one range scope")
	}
	for _, sc := range scopes {
		if err := sc.validate(); err != nil {
			return nil, err
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, createFeedTempSQL); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		return nil, fmt.Errorf("create staging tables: %w", err)
	}
	l := &FeedLoad{
		tx: tx, source: source, scopes: scopes,
		seenAdv: map[[16]byte]struct{}{}, seenRng: map[[16]byte]struct{}{},
	}
	if snapshotID != 0 {
		l.snapshot = &snapshotID
	}
	return l, nil
}

func digest(parts ...string) [16]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Add stages one advisory and its ranges. The same advisory ID may be added
// many times (one CVE appears in many USNs, or under many source packages);
// ranges are de-duplicated by identity and the first record's text wins. Every
// range must fall inside a scope declared at Begin, so a load can never leave
// rows behind that the next load would not replace.
func (l *FeedLoad) Add(ctx context.Context, a Advisory) error {
	if l.done {
		return errors.New("feed load already finished")
	}
	if a.Severity == "" {
		a.Severity = "unknown"
	}
	if err := a.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRecord, err)
	}
	for i, r := range a.Ranges {
		in := false
		for _, sc := range l.scopes {
			if sc.contains(r) {
				in = true
				break
			}
		}
		if !in {
			return fmt.Errorf("%w: advisory %s range %d (distro %q release %q ecosystem %q) is outside the declared scopes",
				ErrInvalidRecord, a.ID, i, r.Distro, r.Release, r.Ecosystem)
		}
	}
	if _, dup := l.seenAdv[digest(a.ID)]; !dup {
		l.seenAdv[digest(a.ID)] = struct{}{}
		cwe := a.CWE
		if cwe == nil {
			cwe = []string{}
		}
		l.advRows = append(l.advRows, []any{a.ID, a.CVE, a.Severity, a.Summary, a.CVSSVector, a.CVSSScore, cwe})
		l.nAdv++
	}
	for _, r := range a.Ranges {
		k := digest(a.ID, r.Ecosystem, r.Distro, r.Release, r.Package, r.Introduced, r.Fixed)
		if _, dup := l.seenRng[k]; dup {
			continue
		}
		l.seenRng[k] = struct{}{}
		l.rngRows = append(l.rngRows, []any{a.ID, r.Ecosystem, r.Distro, r.Release, r.Package,
			r.SourcePackage, r.Introduced, r.Fixed, string(r.FixState)})
		l.nRng++
	}
	if len(l.advRows) >= feedFlushRows || len(l.rngRows) >= feedFlushRows {
		return l.flush(ctx)
	}
	return nil
}

func (l *FeedLoad) flush(ctx context.Context) error {
	if len(l.advRows) > 0 {
		if _, err := l.tx.CopyFrom(ctx, pgx.Identifier{"feed_adv_tmp"},
			[]string{"id", "cve", "severity", "summary", "cvss_vector", "cvss_score", "cwe"},
			pgx.CopyFromRows(l.advRows)); err != nil {
			return fmt.Errorf("stage advisories: %w", err)
		}
		l.advRows = l.advRows[:0]
	}
	if len(l.rngRows) > 0 {
		if _, err := l.tx.CopyFrom(ctx, pgx.Identifier{"feed_rng_tmp"},
			[]string{"advisory_id", "ecosystem", "distro", "release", "package", "source_package", "introduced", "fixed", "fix_state"},
			pgx.CopyFromRows(l.rngRows)); err != nil {
			return fmt.Errorf("stage ranges: %w", err)
		}
		l.rngRows = l.rngRows[:0]
	}
	return nil
}

// Commit replaces the feed's range scopes and merges advisory metadata, in one
// transaction. The result counts distinct advisories and ranges staged.
func (l *FeedLoad) Commit(ctx context.Context) (FeedLoadResult, error) {
	if l.done {
		return FeedLoadResult{}, errors.New("feed load already finished")
	}
	l.done = true
	fail := func(err error) (FeedLoadResult, error) {
		l.tx.Rollback(ctx) //nolint:errcheck
		return FeedLoadResult{}, err
	}
	if err := l.flush(ctx); err != nil {
		return fail(err)
	}
	if _, err := l.tx.Exec(ctx, mergeAdvisoriesSQL, l.source, l.snapshot); err != nil {
		return fail(fmt.Errorf("merge advisories: %w", err))
	}
	for _, sc := range l.scopes {
		var err error
		if sc.Distro != "" {
			_, err = l.tx.Exec(ctx, deleteScopeDistroSQL, sc.Distro, sc.Release)
		} else {
			_, err = l.tx.Exec(ctx, deleteScopeEcosystemSQL, sc.Ecosystem)
		}
		if err != nil {
			return fail(fmt.Errorf("clear scope: %w", err))
		}
	}
	if _, err := l.tx.Exec(ctx, insertRangesFromTmpSQL, l.snapshot); err != nil {
		return fail(fmt.Errorf("insert ranges: %w", err))
	}
	if err := l.tx.Commit(ctx); err != nil {
		return FeedLoadResult{}, err
	}
	return FeedLoadResult{Advisories: l.nAdv, Ranges: l.nRng}, nil
}

// Rollback abandons the load. Safe to call after Commit.
func (l *FeedLoad) Rollback(ctx context.Context) {
	if l.done {
		return
	}
	l.done = true
	l.tx.Rollback(ctx) //nolint:errcheck
}

// ---- KEV and EPSS ----------------------------------------------------------

// KEVRow is one CISA Known Exploited Vulnerabilities entry.
type KEVRow struct {
	CVE   string
	Added time.Time
	Name  string
}

// KEVResult counts what ApplyKEV changed.
type KEVResult struct {
	Marked  int // advisories now flagged (including newly created stubs)
	Created int // stub advisories created for KEV CVEs no feed covers
	Cleared int // advisories whose flag was removed because CISA dropped the CVE
}

// ApplyKEV makes the kev flag mirror the catalog exactly: flagged CVEs get
// kev=true and their date added, CVEs no longer in the catalog are cleared. A
// KEV CVE that no other feed describes gets a stub advisory (severity
// "unknown", source 'cisa-kev', no ranges) so the fact it is exploited is not
// lost; the first distro or OSV record for it replaces the stub's text.
func (s *Store) ApplyKEV(ctx context.Context, rows []KEVRow, snapshotID int64) (KEVResult, error) {
	if len(rows) == 0 {
		return KEVResult{}, errors.New("refusing to apply an empty KEV catalog (it would clear every flag)")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return KEVResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE kev_tmp (cve TEXT PRIMARY KEY, added DATE, name TEXT) ON COMMIT DROP`); err != nil {
		return KEVResult{}, err
	}
	in := make([][]any, len(rows))
	for i, r := range rows {
		in[i] = []any{r.CVE, r.Added, r.Name}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"kev_tmp"}, []string{"cve", "added", "name"}, pgx.CopyFromRows(in)); err != nil {
		return KEVResult{}, fmt.Errorf("stage kev: %w", err)
	}
	var snap *int64
	if snapshotID != 0 {
		snap = &snapshotID
	}
	var res KEVResult
	tag, err := tx.Exec(ctx, `
		UPDATE advisories SET kev = false, kev_added = NULL, updated_at = now()
		WHERE kev AND NOT EXISTS (
			SELECT 1 FROM kev_tmp t WHERE t.cve = advisories.id OR (advisories.cve <> '' AND t.cve = advisories.cve))`)
	if err != nil {
		return KEVResult{}, fmt.Errorf("clear kev: %w", err)
	}
	res.Cleared = int(tag.RowsAffected())

	var created int
	if err := tx.QueryRow(ctx, `
		WITH ins AS (
			INSERT INTO advisories (id, cve, package, below, severity, summary, source, kev, kev_added, snapshot_id, updated_at)
			SELECT cve, cve, '', '', 'unknown', name, 'cisa-kev', true, added, $1, now() FROM kev_tmp
			WHERE NOT EXISTS (SELECT 1 FROM advisories a
			                  WHERE a.id = kev_tmp.cve OR (a.cve <> '' AND a.cve = kev_tmp.cve))
			ON CONFLICT (id) DO NOTHING
			RETURNING 1)
		SELECT count(*) FROM ins`, snap).Scan(&created); err != nil {
		return KEVResult{}, fmt.Errorf("create kev stubs: %w", err)
	}
	res.Created = created
	// Flag everything the catalog covers (by id, or by the cve column for rows
	// whose id is a vendor id such as an OSV advisory id).
	tag, err = tx.Exec(ctx, `
		UPDATE advisories a SET kev = true, kev_added = t.added, updated_at = now()
		FROM kev_tmp t
		WHERE (a.id = t.cve OR (a.cve <> '' AND a.cve = t.cve))
		  AND (NOT a.kev OR a.kev_added IS DISTINCT FROM t.added)`)
	if err != nil {
		return KEVResult{}, fmt.Errorf("flag kev: %w", err)
	}
	var marked int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM advisories a
		WHERE a.kev`).Scan(&marked); err != nil {
		return KEVResult{}, err
	}
	res.Marked = marked
	return res, tx.Commit(ctx)
}

// EPSSRow is one CVE's exploitation probability.
type EPSSRow struct {
	CVE   string
	Score float64
}

// ApplyEPSS stamps scores and the score date onto advisories whose cve column
// matches. CVEs with no advisory are ignored: EPSS covers ~300k CVEs and only
// the ones a feed actually describes matter. Returns rows changed.
func (s *Store) ApplyEPSS(ctx context.Context, date time.Time, rows []EPSSRow) (int, error) {
	if len(rows) == 0 {
		return 0, errors.New("refusing to apply an empty EPSS file")
	}
	if date.IsZero() {
		return 0, errors.New("EPSS score date is required")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE epss_tmp (cve TEXT, epss NUMERIC) ON COMMIT DROP`); err != nil {
		return 0, err
	}
	const chunk = 50000
	for start := 0; start < len(rows); start += chunk {
		end := min(start+chunk, len(rows))
		in := make([][]any, 0, end-start)
		for _, r := range rows[start:end] {
			in = append(in, []any{r.CVE, r.Score})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"epss_tmp"}, []string{"cve", "epss"}, pgx.CopyFromRows(in)); err != nil {
			return 0, fmt.Errorf("stage epss: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `CREATE INDEX ON epss_tmp (cve)`); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE advisories a SET epss = t.epss, epss_date = $1::date
		FROM epss_tmp t
		WHERE a.cve <> '' AND a.cve = t.cve
		  AND (a.epss IS DISTINCT FROM t.epss OR a.epss_date IS DISTINCT FROM $1::date)`, date)
	if err != nil {
		return 0, fmt.Errorf("apply epss: %w", err)
	}
	return int(tag.RowsAffected()), tx.Commit(ctx)
}

// ---- Feed status and snapshots --------------------------------------------

// FeedStatus is one row of feed_status.
type FeedStatus struct {
	Name         string
	Kind         string
	URL          string
	LastAttempt  *time.Time
	LastError    string
	LastSuccess  *time.Time
	RecordCount  int64
	SHA256       string
	ETag         string
	LastModified string
	SnapshotID   *int64
}

const feedStatusColumns = `name, kind, url, last_attempt_at, last_error, last_success_at, record_count,
	sha256, etag, last_modified, snapshot_id`

func scanFeedStatus(row pgx.Row) (FeedStatus, error) {
	var f FeedStatus
	err := row.Scan(&f.Name, &f.Kind, &f.URL, &f.LastAttempt, &f.LastError, &f.LastSuccess,
		&f.RecordCount, &f.SHA256, &f.ETag, &f.LastModified, &f.SnapshotID)
	return f, err
}

// GetFeedStatus returns a feed's status; ok is false if it has never run.
func (s *Store) GetFeedStatus(ctx context.Context, name string) (FeedStatus, bool, error) {
	f, err := scanFeedStatus(s.pool.QueryRow(ctx, `SELECT `+feedStatusColumns+` FROM feed_status WHERE name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedStatus{}, false, nil
	}
	return f, err == nil, err
}

// ListFeedStatus returns every feed's status ordered by name.
func (s *Store) ListFeedStatus(ctx context.Context) ([]FeedStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+feedStatusColumns+` FROM feed_status ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedStatus
	for rows.Next() {
		f, err := scanFeedStatus(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RecordFeedSuccess stores a successful load or a confirmed-current check. The
// error field is cleared.
func (s *Store) RecordFeedSuccess(ctx context.Context, f FeedStatus) error {
	if f.Name == "" || f.LastSuccess == nil {
		return errors.New("feed status needs a name and a success time")
	}
	attempt := f.LastAttempt
	if attempt == nil {
		attempt = f.LastSuccess
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_status (name, kind, url, last_attempt_at, last_error, last_success_at, record_count,
		                         sha256, etag, last_modified, snapshot_id)
		VALUES ($1,$2,$3,$4,'',$5,$6,$7,$8,$9,$10)
		ON CONFLICT (name) DO UPDATE SET
			kind=EXCLUDED.kind, url=EXCLUDED.url, last_attempt_at=EXCLUDED.last_attempt_at, last_error='',
			last_success_at=EXCLUDED.last_success_at, record_count=EXCLUDED.record_count,
			sha256=EXCLUDED.sha256, etag=EXCLUDED.etag, last_modified=EXCLUDED.last_modified,
			snapshot_id=EXCLUDED.snapshot_id`,
		f.Name, f.Kind, f.URL, attempt, f.LastSuccess, f.RecordCount, f.SHA256, f.ETag, f.LastModified, f.SnapshotID)
	return err
}

// RecordFeedFailure notes a failed attempt without touching the last-success
// fields, so a feed that has been failing for a week shows its true age.
func (s *Store) RecordFeedFailure(ctx context.Context, name, kind, url string, at time.Time, msg string) error {
	if name == "" {
		return errors.New("feed name is required")
	}
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_status (name, kind, url, last_attempt_at, last_error)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (name) DO UPDATE SET last_attempt_at=EXCLUDED.last_attempt_at, last_error=EXCLUDED.last_error,
			kind=EXCLUDED.kind, url=EXCLUDED.url`, name, kind, url, at, msg)
	return err
}

// FinalizeFeedSnapshot rewrites a snapshot's feed list once record counts are
// known. A snapshot is created before loading (rows reference its ID) and
// finalized after; the list only ever describes the run that created it.
func (s *Store) FinalizeFeedSnapshot(ctx context.Context, id int64, feeds []FeedRef) error {
	if len(feeds) == 0 {
		return errors.New("a snapshot needs at least one feed")
	}
	for _, f := range feeds {
		if err := f.validate(); err != nil {
			return err
		}
	}
	raw, err := marshalFeedRefs(feeds)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE feed_snapshots SET feeds = $2::jsonb WHERE id = $1`, id, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("snapshot %d not found", id)
	}
	return nil
}

// LatestFeedSnapshot returns the most recent snapshot; ok is false if none.
func (s *Store) LatestFeedSnapshot(ctx context.Context) (FeedSnapshot, bool, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `SELECT id FROM feed_snapshots ORDER BY id DESC LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedSnapshot{}, false, nil
	}
	if err != nil {
		return FeedSnapshot{}, false, err
	}
	snap, err := s.GetFeedSnapshot(ctx, id)
	return snap, err == nil, err
}

// marshalFeedRefs normalises fetch times to UTC, as RecordFeedSnapshot does, so
// the stored record does not depend on the zone of the host that fetched.
func marshalFeedRefs(feeds []FeedRef) (string, error) {
	norm := make([]FeedRef, len(feeds))
	for i, f := range feeds {
		f.FetchedAt = f.FetchedAt.UTC()
		norm[i] = f
	}
	raw, err := json.Marshal(norm)
	return string(raw), err
}

// TryFeedLock takes the cluster-wide feed sync lock on a dedicated connection,
// so two defendsec-feeds runs (a timer firing during a manual sync, say) cannot
// interleave their loads. ok is false if another run holds it. Call release when
// done; it is safe to call once.
func (s *Store) TryFeedLock(ctx context.Context) (release func(), ok bool, err error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext('defendsec:feeds'))`).Scan(&got); err != nil {
		conn.Release()
		return nil, false, err
	}
	if !got {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('defendsec:feeds'))`) //nolint:errcheck
		conn.Release()
	}, true, nil
}

// Pending reports the distinct advisories and ranges staged so far (what Commit
// would return), so a caller can sanity-check a load before committing it.
func (l *FeedLoad) Pending() FeedLoadResult {
	return FeedLoadResult{Advisories: l.nAdv, Ranges: l.nRng}
}
