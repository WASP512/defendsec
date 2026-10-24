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

	"defendsec/internal/exposure"
	"defendsec/internal/gws"
	"defendsec/internal/m365"
	"defendsec/internal/m365/graph"
)

// Identity posture storage (migration 028). One set of tables for every identity
// provider; slice 12 fills them from Microsoft 365. A finding keeps first-seen /
// resolved bookkeeping; a run records, per check group, whether it was assessed,
// and a check that was not assessed resolves nothing.

// ---- settings ---------------------------------------------------------------------

// M365Settings is the instance's one Microsoft 365 tenant and how it is judged.
type M365Settings struct {
	// Configured is true once a tenant and an application ID are set.
	Configured     bool       `json:"configured"`
	TenantID       string     `json:"tenantId"`
	ClientID       string     `json:"clientId"`
	Cloud          string     `json:"cloud"`
	GlobalAdminMax int        `json:"globalAdminMax"`
	TrustedDomains []string   `json:"trustedDomains"`
	FinanceTerms   []string   `json:"financeTerms"`
	ResolveFolders bool       `json:"resolveFolders"`
	UpdatedBy      string     `json:"updatedBy,omitempty"`
	UpdatedAt      *time.Time `json:"updatedAt,omitempty"`
}

// ErrBadIdentitySettings is wrapped by validation errors an API can show.
var ErrBadIdentitySettings = errors.New("bad identity settings")

// DefaultM365Settings are the settings of an instance that never saved any.
func DefaultM365Settings() M365Settings {
	return M365Settings{Cloud: string(graph.CloudGlobal), GlobalAdminMax: m365.DefaultGlobalAdminMax, TrustedDomains: []string{}, FinanceTerms: []string{}}
}

// GetM365Settings returns the saved settings, or the defaults with Configured=false.
func (s *Store) GetM365Settings(ctx context.Context) (M365Settings, error) {
	out := DefaultM365Settings()
	var at time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT tenant_id, client_id, cloud, global_admin_max, trusted_domains, finance_terms, resolve_folders, updated_by, updated_at
		FROM m365_settings WHERE id = 1`).
		Scan(&out.TenantID, &out.ClientID, &out.Cloud, &out.GlobalAdminMax, &out.TrustedDomains, &out.FinanceTerms, &out.ResolveFolders, &out.UpdatedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if out.TrustedDomains == nil {
		out.TrustedDomains = []string{}
	}
	if out.FinanceTerms == nil {
		out.FinanceTerms = []string{}
	}
	out.Configured = out.TenantID != "" && out.ClientID != ""
	out.UpdatedAt = &at
	return out, nil
}

func cleanList(in []string, what string, max int, valid func(string) bool) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] {
			continue
		}
		if !valid(v) {
			return nil, fmt.Errorf("%w: %s %q is not valid", ErrBadIdentitySettings, what, v)
		}
		seen[v] = true
		out = append(out, v)
	}
	if len(out) > max {
		return nil, fmt.Errorf("%w: at most %d %ss", ErrBadIdentitySettings, max, what)
	}
	return out, nil
}

func validDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// Normalize validates and cleans the settings in place.
func (m *M365Settings) Normalize() error {
	m.TenantID, m.ClientID = strings.TrimSpace(m.TenantID), strings.TrimSpace(m.ClientID)
	if m.TenantID != "" && !graph.ValidTenant(m.TenantID) {
		return fmt.Errorf("%w: the tenant must be a directory (tenant) ID or a domain name", ErrBadIdentitySettings)
	}
	if m.ClientID != "" && !graph.ValidClientID(m.ClientID) {
		return fmt.Errorf("%w: the application (client) ID must be a GUID", ErrBadIdentitySettings)
	}
	if (m.TenantID == "") != (m.ClientID == "") {
		return fmt.Errorf("%w: set the tenant and the application ID together", ErrBadIdentitySettings)
	}
	if m.Cloud == "" {
		m.Cloud = string(graph.CloudGlobal)
	}
	if _, err := graph.ParseCloud(m.Cloud); err != nil {
		return fmt.Errorf("%w: %v", ErrBadIdentitySettings, err)
	}
	if m.GlobalAdminMax < 1 || m.GlobalAdminMax > 50 {
		return fmt.Errorf("%w: the Global Administrator limit must be between 1 and 50", ErrBadIdentitySettings)
	}
	var err error
	if m.TrustedDomains, err = cleanList(m.TrustedDomains, "trusted domain", 50, validDomain); err != nil {
		return err
	}
	if m.FinanceTerms, err = cleanList(m.FinanceTerms, "finance term", 50, func(s string) bool { return len(s) >= 3 && len(s) <= 40 }); err != nil {
		return err
	}
	return nil
}

// SetM365Settings saves the settings and chains the change in the audit log in
// the same transaction.
func (s *Store) SetM365Settings(ctx context.Context, actor string, in M365Settings) error {
	if err := in.Normalize(); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO m365_settings (id, tenant_id, client_id, cloud, global_admin_max, trusted_domains, finance_terms, resolve_folders, updated_by, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, client_id = EXCLUDED.client_id, cloud = EXCLUDED.cloud,
			global_admin_max = EXCLUDED.global_admin_max, trusted_domains = EXCLUDED.trusted_domains,
			finance_terms = EXCLUDED.finance_terms, resolve_folders = EXCLUDED.resolve_folders,
			updated_by = EXCLUDED.updated_by, updated_at = now()`,
		in.TenantID, in.ClientID, in.Cloud, in.GlobalAdminMax, in.TrustedDomains, in.FinanceTerms, in.ResolveFolders, actor); err != nil {
		return err
	}
	if err := auditInTx(ctx, tx, actor, "identity_settings_changed", "", map[string]any{
		"provider": m365.Provider, "tenantId": in.TenantID, "clientId": in.ClientID, "cloud": in.Cloud,
		"globalAdminMax": in.GlobalAdminMax, "trustedDomains": in.TrustedDomains, "financeTerms": in.FinanceTerms,
		"resolveFolders": in.ResolveFolders,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- runs ---------------------------------------------------------------------------

// IdentityCheck is one check group's state in a run.
type IdentityCheck struct {
	Check    string         `json:"check"`
	Label    string         `json:"label"`
	Assessed bool           `json:"assessed"`
	Reason   string         `json:"reason"`
	Observed map[string]any `json:"observed"`
	// UnassessedPrefixes are subject prefixes (a user id) the check ran without covering.
	UnassessedPrefixes []string `json:"unassessedPrefixes,omitempty"`
}

// IdentityRun is one read of a tenant.
type IdentityRun struct {
	ID          int64              `json:"id"`
	Provider    string             `json:"provider"`
	Tenant      string             `json:"tenant"`
	TriggeredBy string             `json:"triggeredBy"`
	StartedAt   time.Time          `json:"startedAt"`
	FinishedAt  time.Time          `json:"finishedAt"`
	Status      string             `json:"status"` // ok, partial, not_assessed
	Reason      string             `json:"reason"`
	Requests    int                `json:"requests"`
	Counts      m365.Counts        `json:"counts"`
	Checks      []IdentityCheck    `json:"checks"`
	NotAssessed []m365.NotAssessed `json:"notAssessed"`
	Open        int                `json:"findingsOpen"`
	Opened      int                `json:"opened"`
	Resolved    int                `json:"resolved"`
}

// IdentityRunAttestation is what the audit chain holds for a run: which run, how
// it went, what it opened and closed. It does not hold the findings themselves.
type IdentityRunAttestation struct {
	RunID      int64  `json:"runId"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
	Opened     int    `json:"opened"`
	Resolved   int    `json:"resolved"`
	Open       int    `json:"findingsOpen"`
	FinishedAt string `json:"finishedAt"`
}

func ckey(id, subject string) string { return id + "\x01" + subject }

// RecordIdentityRun stores a read of a tenant: the run, its findings, and the
// resolution of the findings of every check group that was assessed. A group that
// was not assessed changes nothing, and neither does the part of a group the run
// did not cover (an unreadable mailbox). The run and its audit entry commit together.
func (s *Store) RecordIdentityRun(ctx context.Context, provider, tenant, trigger string, rep *m365.Report) (IdentityRun, error) {
	var run IdentityRun
	if provider == "" {
		return run, errors.New("identity: a provider is required")
	}
	if trigger == "" {
		trigger = "schedule"
	}
	status := rep.Status()
	startedAt := rep.StartedAt.UTC().Round(time.Microsecond)
	finishedAt := rep.FinishedAt.UTC().Round(time.Microsecond)

	checks := make([]IdentityCheck, 0, len(rep.Checks))
	for _, c := range rep.Checks {
		obs := c.Observed
		if obs == nil {
			obs = map[string]any{}
		}
		checks = append(checks, IdentityCheck{Check: c.Check, Label: rep.Label(c.Check), Assessed: c.Assessed, Reason: c.Reason, Observed: obs, UnassessedPrefixes: c.UnassessedPrefixes})
	}
	checksJSON, err := json.Marshal(checks)
	if err != nil {
		return run, err
	}
	naList := rep.NotAssessed
	if naList == nil {
		naList = []m365.NotAssessed{}
	}
	naJSON, _ := json.Marshal(naList)
	countsJSON, _ := json.Marshal(rep.Counts)
	reason := rep.Reason()
	if len(reason) > 2000 {
		reason = reason[:2000]
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return run, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// One writer per provider at a time: two runs interleaving would each see the
	// other's findings as new.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('identity-run:' || $1))`, provider); err != nil {
		return run, err
	}
	var runID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO identity_runs (provider, tenant, triggered_by, started_at, finished_at, status, reason, requests, counts, checks, not_assessed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11::jsonb) RETURNING id`,
		provider, tenant, trigger, startedAt, finishedAt, status, reason, rep.Requests, string(countsJSON), string(checksJSON), string(naJSON)).Scan(&runID); err != nil {
		return run, err
	}

	opened, resolved := 0, 0
	for _, c := range rep.Checks {
		if !c.Assessed {
			continue
		}
		keys := make([]string, 0, len(c.Findings))
		for _, f := range c.Findings {
			keys = append(keys, ckey(f.ID, f.Subject))
			ev, err := json.Marshal(f.Evidence)
			if err != nil {
				return run, fmt.Errorf("evidence of %s: %w", f.ID, err)
			}
			controls := f.Controls
			if controls == nil {
				controls = []string{}
			}
			var prevResolved, prevFirst *time.Time
			var prevSeverity string
			var existed bool
			err = tx.QueryRow(ctx, `SELECT true, resolved_at, first_seen, severity FROM identity_findings
				WHERE provider = $1 AND finding_id = $2 AND subject = $3`, provider, f.ID, f.Subject).Scan(&existed, &prevResolved, &prevFirst, &prevSeverity)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return run, err
			}
			switch {
			case !existed:
				opened++
			case prevResolved != nil:
				opened++
				// The interval that ended is kept before first_seen restarts.
				if _, err := tx.Exec(ctx, `INSERT INTO identity_finding_intervals (provider, finding_id, subject, severity, opened_at, closed_at)
					VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, provider, f.ID, f.Subject, prevSeverity, prevFirst, prevResolved); err != nil {
					return run, err
				}
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO identity_findings (provider, check_group, finding_id, subject, subject_label, severity, title, detail, fix,
					evidence, controls, first_seen, last_seen, first_run_id, last_run_id)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$12,$13,$13)
				ON CONFLICT (provider, finding_id, subject) DO UPDATE SET
					first_seen = CASE WHEN identity_findings.resolved_at IS NOT NULL THEN EXCLUDED.first_seen ELSE identity_findings.first_seen END,
					first_run_id = CASE WHEN identity_findings.resolved_at IS NOT NULL THEN EXCLUDED.first_run_id ELSE identity_findings.first_run_id END,
					check_group = EXCLUDED.check_group, subject_label = EXCLUDED.subject_label, severity = EXCLUDED.severity,
					title = EXCLUDED.title, detail = EXCLUDED.detail, fix = EXCLUDED.fix, evidence = EXCLUDED.evidence,
					controls = EXCLUDED.controls, last_seen = EXCLUDED.last_seen, last_run_id = EXCLUDED.last_run_id,
					resolved_at = NULL`,
				provider, c.Check, f.ID, f.Subject, f.SubjectLabel, string(f.Severity), f.Title, f.Detail, f.Fix, string(ev), controls, finishedAt, runID); err != nil {
				return run, err
			}
		}
		rows, err := tx.Query(ctx, `
			UPDATE identity_findings SET resolved_at = $4, last_run_id = $3
			WHERE provider = $1 AND check_group = $2 AND resolved_at IS NULL
			  AND (finding_id || chr(1) || subject) <> ALL($5::text[])
			  AND NOT EXISTS (SELECT 1 FROM unnest($6::text[]) p WHERE starts_with(subject, p))
			RETURNING id`, provider, c.Check, runID, finishedAt, keys, nonNil(c.UnassessedPrefixes))
		if err != nil {
			return run, err
		}
		for rows.Next() {
			resolved++
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return run, err
		}
	}

	var open int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM identity_findings WHERE provider = $1 AND resolved_at IS NULL`, provider).Scan(&open); err != nil {
		return run, err
	}
	if _, err := tx.Exec(ctx, `UPDATE identity_runs SET findings_open = $2, opened = $3, resolved = $4 WHERE id = $1`, runID, open, opened, resolved); err != nil {
		return run, err
	}
	if err := auditInTx(ctx, tx, "system:"+provider+"-collector", "identity_run_recorded", "", IdentityRunAttestation{
		RunID: runID, Provider: provider, Status: status, Opened: opened, Resolved: resolved, Open: open,
		FinishedAt: finishedAt.Format(time.RFC3339Nano),
	}); err != nil {
		return run, fmt.Errorf("chain the run: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return run, err
	}
	return IdentityRun{
		ID: runID, Provider: provider, Tenant: tenant, TriggeredBy: trigger, StartedAt: startedAt, FinishedAt: finishedAt,
		Status: status, Reason: reason, Requests: rep.Requests, Counts: rep.Counts, Checks: checks, NotAssessed: naList,
		Open: open, Opened: opened, Resolved: resolved,
	}, nil
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

const identityRunColumns = `id, provider, tenant, triggered_by, started_at, finished_at, status, reason, requests, counts, checks, not_assessed, findings_open, opened, resolved`

func scanIdentityRun(row pgx.Row) (IdentityRun, error) {
	var r IdentityRun
	var counts, checks, na []byte
	if err := row.Scan(&r.ID, &r.Provider, &r.Tenant, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Reason, &r.Requests,
		&counts, &checks, &na, &r.Open, &r.Opened, &r.Resolved); err != nil {
		return r, err
	}
	_ = json.Unmarshal(counts, &r.Counts)
	_ = json.Unmarshal(checks, &r.Checks)
	_ = json.Unmarshal(na, &r.NotAssessed)
	if r.Checks == nil {
		r.Checks = []IdentityCheck{}
	}
	if r.NotAssessed == nil {
		r.NotAssessed = []m365.NotAssessed{}
	}
	r.StartedAt, r.FinishedAt = r.StartedAt.UTC(), r.FinishedAt.UTC()
	return r, nil
}

// LatestIdentityRun returns the most recent run of a provider, or nil.
func (s *Store) LatestIdentityRun(ctx context.Context, provider string) (*IdentityRun, error) {
	r, err := scanIdentityRun(s.pool.QueryRow(ctx, `SELECT `+identityRunColumns+` FROM identity_runs WHERE provider = $1 ORDER BY finished_at DESC, id DESC LIMIT 1`, provider))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListIdentityRuns returns the most recent runs of a provider, newest first.
func (s *Store) ListIdentityRuns(ctx context.Context, provider string, limit int) ([]IdentityRun, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `SELECT `+identityRunColumns+` FROM identity_runs WHERE provider = $1 ORDER BY finished_at DESC, id DESC LIMIT $2`, provider, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityRun{}
	for rows.Next() {
		r, err := scanIdentityRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ---- findings ------------------------------------------------------------------------

// IdentityFinding is a stored finding.
type IdentityFinding struct {
	ID           int64          `json:"id"`
	Key          string         `json:"key"`
	Provider     string         `json:"provider"`
	Check        string         `json:"check"`
	FindingID    string         `json:"findingId"`
	Subject      string         `json:"subject"`
	SubjectLabel string         `json:"subjectLabel"`
	Severity     string         `json:"severity"`
	Title        string         `json:"title"`
	Detail       string         `json:"detail"`
	Fix          string         `json:"fix"`
	Evidence     map[string]any `json:"evidence"`
	Controls     []string       `json:"controls"`
	FirstSeen    time.Time      `json:"firstSeen"`
	LastSeen     time.Time      `json:"lastSeen"`
	ResolvedAt   *time.Time     `json:"resolvedAt"`
	// Unconfirmed: the latest run could not assess this finding's check (or the part
	// of it this finding belongs to): it is shown from its last confirmation.
	Unconfirmed bool `json:"unconfirmed"`
}

// IdentityKey is the row id of identity finding n in the exposure list:
// "identity:" and the id zero-padded to 12 digits, so text order is numeric order.
func IdentityKey(n int64) string { return exposure.IdentityKeyPrefix + fmt.Sprintf("%012d", n) }

// ErrBadIdentityKey is returned for an id that is not an identity row's.
var ErrBadIdentityKey = errors.New("bad identity finding id")

// ParseIdentityKey reverses IdentityKey.
func ParseIdentityKey(key string) (int64, error) {
	rest, ok := strings.CutPrefix(key, exposure.IdentityKeyPrefix)
	if !ok || len(rest) != 12 {
		return 0, ErrBadIdentityKey
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n <= 0 {
		return 0, ErrBadIdentityKey
	}
	return n, nil
}

// ErrNoIdentityFinding is returned for a finding that does not exist.
var ErrNoIdentityFinding = errors.New("identity finding not found")

// identityUnconfirmedSQL is the SQL for "the latest run of this finding's
// provider could not assess its check, or the part of it the finding is in". f is
// the identity_findings alias.
const identityUnconfirmedSQL = `(f.resolved_at IS NULL AND EXISTS (
	SELECT 1 FROM identity_runs r, jsonb_array_elements(r.checks) c
	WHERE r.id = (SELECT r2.id FROM identity_runs r2 WHERE r2.provider = f.provider ORDER BY r2.finished_at DESC, r2.id DESC LIMIT 1)
	  AND c->>'check' = f.check_group
	  AND (NOT (c->>'assessed')::boolean
	       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(COALESCE(c->'unassessedPrefixes', '[]'::jsonb)) p WHERE starts_with(f.subject, p)))))`

const identityFindingColumns = `f.id, f.provider, f.check_group, f.finding_id, f.subject, f.subject_label, f.severity, f.title, f.detail, f.fix,
	f.evidence, f.controls, f.first_seen, f.last_seen, f.resolved_at, ` + identityUnconfirmedSQL

func scanIdentityFinding(row pgx.Row) (IdentityFinding, error) {
	var f IdentityFinding
	var ev []byte
	if err := row.Scan(&f.ID, &f.Provider, &f.Check, &f.FindingID, &f.Subject, &f.SubjectLabel, &f.Severity, &f.Title, &f.Detail, &f.Fix,
		&ev, &f.Controls, &f.FirstSeen, &f.LastSeen, &f.ResolvedAt, &f.Unconfirmed); err != nil {
		return f, err
	}
	f.Key = IdentityKey(f.ID)
	f.Evidence = map[string]any{}
	_ = json.Unmarshal(ev, &f.Evidence)
	if f.Controls == nil {
		f.Controls = []string{}
	}
	f.FirstSeen, f.LastSeen = f.FirstSeen.UTC(), f.LastSeen.UTC()
	if f.ResolvedAt != nil {
		t := f.ResolvedAt.UTC()
		f.ResolvedAt = &t
	}
	return f, nil
}

// IdentityFindingFilter selects findings.
type IdentityFindingFilter struct {
	Provider string
	// Resolved lists closed findings instead of open ones.
	Resolved bool
	Check    string
	Limit    int
}

// ListIdentityFindings returns findings, most severe first, then newest.
func (s *Store) ListIdentityFindings(ctx context.Context, flt IdentityFindingFilter) ([]IdentityFinding, error) {
	if flt.Limit < 1 || flt.Limit > 1000 {
		flt.Limit = 500
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+identityFindingColumns+`
		FROM identity_findings f
		WHERE ($1 = '' OR f.provider = $1) AND ($2 = '' OR f.check_group = $2) AND (f.resolved_at IS NOT NULL) = $3
		ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.first_seen DESC, f.id DESC
		LIMIT $4`, flt.Provider, flt.Check, flt.Resolved, flt.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityFinding{}
	for rows.Next() {
		f, err := scanIdentityFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// IdentityInterval is one span a finding was open.
type IdentityInterval struct {
	OpenedAt time.Time  `json:"openedAt"`
	ClosedAt *time.Time `json:"closedAt"`
}

// IdentityDetail is the drawer of an identity row: the finding, every span it was
// open, and the state of its check in the latest run.
type IdentityDetail struct {
	Key       string             `json:"key"`
	Finding   IdentityFinding    `json:"finding"`
	Intervals []IdentityInterval `json:"intervals"`
	// Latest is the latest run of the finding's provider.
	Latest *IdentityRun `json:"latest"`
	// CheckState is that run's state of the finding's check group.
	CheckState *IdentityCheck `json:"checkState"`
}

// GetIdentityDetail returns one identity finding by its list key.
func (s *Store) GetIdentityDetail(ctx context.Context, key string) (IdentityDetail, error) {
	id, err := ParseIdentityKey(key)
	if err != nil {
		return IdentityDetail{}, err
	}
	f, err := scanIdentityFinding(s.pool.QueryRow(ctx, `SELECT `+identityFindingColumns+` FROM identity_findings f WHERE f.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentityDetail{}, ErrNoIdentityFinding
	}
	if err != nil {
		return IdentityDetail{}, err
	}
	d := IdentityDetail{Key: key, Finding: f, Intervals: []IdentityInterval{}}
	rows, err := s.pool.Query(ctx, `SELECT opened_at, closed_at FROM identity_finding_intervals
		WHERE provider = $1 AND finding_id = $2 AND subject = $3 ORDER BY opened_at`, f.Provider, f.FindingID, f.Subject)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var o, c time.Time
		if err := rows.Scan(&o, &c); err != nil {
			rows.Close()
			return d, err
		}
		c = c.UTC()
		d.Intervals = append(d.Intervals, IdentityInterval{OpenedAt: o.UTC(), ClosedAt: &c})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return d, err
	}
	d.Intervals = append(d.Intervals, IdentityInterval{OpenedAt: f.FirstSeen, ClosedAt: f.ResolvedAt})
	if d.Latest, err = s.LatestIdentityRun(ctx, f.Provider); err != nil {
		return d, err
	}
	if d.Latest != nil {
		for i := range d.Latest.Checks {
			if d.Latest.Checks[i].Check == f.Check {
				c := d.Latest.Checks[i]
				d.CheckState = &c
			}
		}
	}
	return d, nil
}

// ---- summary and trend ---------------------------------------------------------------

// IdentityExposureSummary is the identity card on the Fleet page and the head of
// the Identity page. It covers every identity provider (Microsoft 365, Google
// Workspace): the findings are all the open ones, and the last read is the most
// recent of the providers' latest reads, as bad as the worst of them.
type IdentityExposureSummary struct {
	// Configured: a tenant or domain is set up for reading.
	Configured bool `json:"configured"`
	// Provider is the configured provider, or the providers joined by a comma;
	// "m365" when none is configured.
	Provider string `json:"provider"`
	// Providers are the configured providers ("m365", "google").
	Providers []string `json:"providers"`
	// Findings are the open ones (critical, high, medium, low).
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"bySeverity"`
	// LastRunAt is when the latest run finished; LastStatus is ok, partial or
	// not_assessed (the worst across providers); "" when there has been none.
	LastRunAt  *time.Time `json:"lastRunAt"`
	LastStatus string     `json:"lastStatus"`
	LastReason string     `json:"lastReason"`
	// ChecksNotAssessed counts the check groups the latest runs could not assess;
	// ChecksTotal how many they list.
	ChecksNotAssessed int `json:"checksNotAssessed"`
	ChecksTotal       int `json:"checksTotal"`
}

var identityProviderNames = map[string]string{m365.Provider: "Microsoft 365", gws.Provider: "Google Workspace"}

func statusRank(s string) int {
	switch s {
	case "not_assessed":
		return 2
	case "partial":
		return 1
	}
	return 0
}

// IdentityExposureSummary computes the counts behind the identity card, over every
// provider.
func (s *Store) IdentityExposureSummary(ctx context.Context) (IdentityExposureSummary, error) {
	return s.identitySummary(ctx, []string{m365.Provider, gws.Provider})
}

// IdentityProviderSummary is the same for one provider: the head of that provider's
// page.
func (s *Store) IdentityProviderSummary(ctx context.Context, provider string) (IdentityExposureSummary, error) {
	return s.identitySummary(ctx, []string{provider})
}

func (s *Store) providerConfigured(ctx context.Context, provider string) (bool, error) {
	switch provider {
	case m365.Provider:
		set, err := s.GetM365Settings(ctx)
		return set.Configured, err
	case gws.Provider:
		set, err := s.GetGWSSettings(ctx)
		return set.Configured, err
	}
	return false, nil
}

func (s *Store) identitySummary(ctx context.Context, providers []string) (IdentityExposureSummary, error) {
	out := IdentityExposureSummary{BySeverity: map[string]int{}, Providers: []string{}}
	for _, p := range providers {
		on, err := s.providerConfigured(ctx, p)
		if err != nil {
			return out, err
		}
		if on {
			out.Providers = append(out.Providers, p)
		}
	}
	out.Configured = len(out.Providers) > 0
	out.Provider = strings.Join(out.Providers, ",")
	if out.Provider == "" {
		out.Provider = providers[0]
	}
	rows, err := s.pool.Query(ctx, `SELECT severity, count(*) FROM identity_findings WHERE resolved_at IS NULL AND provider = ANY($1) GROUP BY severity`, providers)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return out, err
		}
		out.BySeverity[sev] += n
		out.Findings += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	var reasons []string
	var runs int
	for _, p := range providers {
		run, err := s.LatestIdentityRun(ctx, p)
		if err != nil {
			return out, err
		}
		if run == nil {
			continue
		}
		runs++
		if out.LastRunAt == nil || run.FinishedAt.After(*out.LastRunAt) {
			t := run.FinishedAt
			out.LastRunAt = &t
		}
		if out.LastStatus == "" || statusRank(run.Status) > statusRank(out.LastStatus) {
			out.LastStatus = run.Status
		}
		if run.Reason != "" {
			reasons = append(reasons, identityProviderNames[p]+": "+run.Reason)
		}
		out.ChecksTotal += len(run.Checks)
		for _, c := range run.Checks {
			if !c.Assessed {
				out.ChecksNotAssessed++
			}
		}
	}
	if runs == 1 && len(reasons) == 1 {
		// One provider read: its reason as it said it, with no prefix.
		out.LastReason = reasons[0][strings.Index(reasons[0], ": ")+2:]
	} else {
		out.LastReason = strings.Join(reasons, "; ")
	}
	return out, nil
}

// identityTrend fills the identity series of points laid out by ExposureTrend:
// findings open at the end of each day, from first_seen and resolved_at plus the
// intervals of findings that closed and came back. A day is known if it ends after
// the first run; before that the zeros mean no data.
func (s *Store) identityTrend(ctx context.Context, start, end, now time.Time, points []TrendPoint) (*time.Time, error) {
	var since *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT min(started_at) FROM identity_runs`).Scan(&since); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		WITH days AS (
		  SELECT d::date AS day, LEAST((d + interval '1 day') AT TIME ZONE 'UTC', $3::timestamptz) AS asof
		  FROM generate_series($1::timestamp, $2::timestamp, interval '1 day') d
		), spans AS (
		  SELECT severity, first_seen AS opened, resolved_at AS closed FROM identity_findings
		  UNION ALL
		  SELECT severity, opened_at, closed_at FROM identity_finding_intervals
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
			return nil, fmt.Errorf("identity trend day %s does not line up with the exposure trend", day.Format("2006-01-02"))
		}
		known := since != nil && day.Add(24*time.Hour).After(since.UTC())
		points[i].IdentityKnown = known
		if known {
			points[i].Identity, points[i].IdentityHigh = n, high
		}
		i++
	}
	return since, rows.Err()
}
