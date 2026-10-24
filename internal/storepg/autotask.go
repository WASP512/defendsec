package storepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/autotask"
)

// Autotask storage (migration 029): the settings of the one company an instance
// maps to, the tickets DefendSec follows (the idempotency record), and the runs.
// Every ticket action is an audit-chain entry written in the transaction that
// changes the row it describes.

// ---- settings ---------------------------------------------------------------------

// AutotaskSettings are autotask.Settings with who saved them and when.
type AutotaskSettings struct {
	autotask.Settings
	UpdatedBy string     `json:"updatedBy,omitempty"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// GetAutotaskSettings returns the saved settings, or the defaults.
func (s *Store) GetAutotaskSettings(ctx context.Context) (AutotaskSettings, error) {
	out := AutotaskSettings{Settings: autotask.DefaultSettings()}
	var at time.Time
	st := &out.Settings
	err := s.pool.QueryRow(ctx, `
		SELECT mode, api_user, zone_url, company_id, queue_id, status, source, issue_type, sub_issue_type,
		       priority_critical, priority_high, priority_medium, note_type, note_publish, auto_complete, complete_status,
		       min_urgency, due_days_critical, due_days_high, due_days_medium, console_url, max_creates, updated_by, updated_at
		FROM autotask_settings WHERE id = 1`).
		Scan(&st.Mode, &st.APIUser, &st.ZoneURL, &st.CompanyID, &st.QueueID, &st.Status, &st.Source, &st.IssueType, &st.SubIssueType,
			&st.PriorityCritical, &st.PriorityHigh, &st.PriorityMedium, &st.NoteType, &st.NotePublish, &st.AutoComplete, &st.CompleteStatus,
			&st.MinUrgency, &st.DueDaysCritical, &st.DueDaysHigh, &st.DueDaysMedium, &st.ConsoleURL, &st.MaxCreates, &out.UpdatedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.UpdatedAt = &at
	return out, nil
}

// SetAutotaskSettings validates and saves the settings and chains the change in
// the audit log in the same transaction. Switching to live needs the fingerprint
// of a dry run that shows these settings.
func (s *Store) SetAutotaskSettings(ctx context.Context, actor string, in autotask.Settings) error {
	if err := in.Normalize(); err != nil {
		return err
	}
	if in.Mode == autotask.ModeLive {
		fp, err := s.LatestGoodDryRunFingerprint(ctx)
		if err != nil {
			return err
		}
		if fp != in.Fingerprint() {
			return fmt.Errorf("%w: run a dry run with these settings and look at the tickets it lists before going live", autotask.ErrBadSettings)
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO autotask_settings (id, mode, api_user, zone_url, company_id, queue_id, status, source, issue_type, sub_issue_type,
			priority_critical, priority_high, priority_medium, note_type, note_publish, auto_complete, complete_status,
			min_urgency, due_days_critical, due_days_high, due_days_medium, console_url, max_creates, updated_by, updated_at)
		VALUES (1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23, now())
		ON CONFLICT (id) DO UPDATE SET mode=EXCLUDED.mode, api_user=EXCLUDED.api_user, zone_url=EXCLUDED.zone_url, company_id=EXCLUDED.company_id,
			queue_id=EXCLUDED.queue_id, status=EXCLUDED.status, source=EXCLUDED.source, issue_type=EXCLUDED.issue_type,
			sub_issue_type=EXCLUDED.sub_issue_type, priority_critical=EXCLUDED.priority_critical, priority_high=EXCLUDED.priority_high,
			priority_medium=EXCLUDED.priority_medium, note_type=EXCLUDED.note_type, note_publish=EXCLUDED.note_publish,
			auto_complete=EXCLUDED.auto_complete, complete_status=EXCLUDED.complete_status, min_urgency=EXCLUDED.min_urgency,
			due_days_critical=EXCLUDED.due_days_critical, due_days_high=EXCLUDED.due_days_high, due_days_medium=EXCLUDED.due_days_medium,
			console_url=EXCLUDED.console_url, max_creates=EXCLUDED.max_creates, updated_by=EXCLUDED.updated_by, updated_at=now()`,
		in.Mode, in.APIUser, in.ZoneURL, in.CompanyID, in.QueueID, in.Status, in.Source, in.IssueType, in.SubIssueType,
		in.PriorityCritical, in.PriorityHigh, in.PriorityMedium, in.NoteType, in.NotePublish, in.AutoComplete, in.CompleteStatus,
		in.MinUrgency, in.DueDaysCritical, in.DueDaysHigh, in.DueDaysMedium, in.ConsoleURL, in.MaxCreates, actor); err != nil {
		return err
	}
	// The ledger names every choice that decides where tickets go and what they say.
	// No credential is here to leak: none is ever accepted or stored.
	if err := auditInTx(ctx, tx, actor, "autotask_settings_changed", "", map[string]any{
		"mode": in.Mode, "apiUser": in.APIUser, "zoneUrl": in.ZoneURL, "companyId": in.CompanyID, "queueId": in.QueueID, "status": in.Status,
		"source": in.Source, "issueType": in.IssueType, "subIssueType": in.SubIssueType,
		"priorityCritical": in.PriorityCritical, "priorityHigh": in.PriorityHigh, "priorityMedium": in.PriorityMedium,
		"noteType": in.NoteType, "notePublish": in.NotePublish, "autoComplete": in.AutoComplete, "completeStatus": in.CompleteStatus,
		"minUrgency": in.MinUrgency, "dueDays": []int{in.DueDaysCritical, in.DueDaysHigh, in.DueDaysMedium},
		"consoleUrl": in.ConsoleURL, "maxCreates": in.MaxCreates, "fingerprint": in.Fingerprint(),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ---- candidates: the open Fix-this-week findings ---------------------------------------

// AutotaskCandidates returns every open finding of the Fix-this-week list, as the
// planner sees it: fixable vulnerabilities and end-of-life software per host,
// surface findings above info on declared assets, and identity findings. It is the
// same population as ListExposure's fix bucket (revoked devices and removed assets
// excluded), and it is read-only.
func (s *Store) AutotaskCandidates(ctx context.Context) ([]autotask.Finding, error) {
	var out []autotask.Finding

	rows, err := s.pool.Query(ctx, `
		SELECT f.kind, f.device_id, d.hostname, f.first_seen, f.family, f.package, f.installed, f.fixed, f.advisory_id, f.cve,
		       f.severity, f.kev, f.epss::float8, f.cvss_score::float8, d.package_manager, d.distro,
		       f.eol_product, f.eol_cycle, f.eol_stage, COALESCE(f.eol_detail->>'productLabel', ''), COALESCE(f.eol_detail->>'upgradeTo', ''),
		       COALESCE(f.eol_date::text, '')
		FROM vuln_findings f
		JOIN devices d ON d.id = f.device_id AND NOT d.revoked
		WHERE f.kind IN ('finding', 'eol') AND f.resolved_at IS NULL
		ORDER BY f.family, f.device_id, f.advisory_id`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f autotask.Finding
		var kind string
		if err := rows.Scan(&kind, &f.MemberKey, &f.MemberLabel, &f.FirstSeen, &f.Family, &f.Package, &f.Installed, &f.Fixed, &f.AdvisoryID, &f.CVE,
			&f.Severity, &f.KEV, &f.EPSS, &f.CVSS, &f.PackageManager, &f.Distro,
			&f.EOLProduct, &f.EOLCycle, &f.EOLStage, &f.EOLLabel, &f.EOLUpgrade, &f.EOLDate); err != nil {
			rows.Close()
			return nil, err
		}
		f.Source = autotask.SourceVuln
		if kind == "eol" {
			f.Source = autotask.SourceEOL
		}
		if f.MemberLabel == "" {
			f.MemberLabel = f.MemberKey
		}
		out = append(out, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT sa.id, sa.value, sf.finding_id, sf.subject, sf.severity, sf.title, sf.detail, sf.fix, sf.first_seen
		FROM surface_findings sf
		JOIN surface_assets sa ON sa.id = sf.asset_id AND sa.removed_at IS NULL
		WHERE sf.resolved_at IS NULL AND sf.severity <> 'info'
		ORDER BY sf.finding_id, sa.value, sf.subject`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f autotask.Finding
		var assetID int64
		if err := rows.Scan(&assetID, &f.MemberLabel, &f.CheckID, &f.Subject, &f.Severity, &f.Title, &f.Detail, &f.Fix, &f.FirstSeen); err != nil {
			rows.Close()
			return nil, err
		}
		f.Source = autotask.SourceSurface
		f.MemberKey = surfaceMemberKey(assetID, f.CheckID, f.Subject)
		out = append(out, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.pool.Query(ctx, `
		SELECT provider, finding_id, subject, subject_label, severity, title, detail, fix, first_seen
		FROM identity_findings WHERE resolved_at IS NULL
		ORDER BY provider, finding_id, subject_label, subject`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f autotask.Finding
		if err := rows.Scan(&f.Provider, &f.CheckID, &f.Subject, &f.MemberLabel, &f.Severity, &f.Title, &f.Detail, &f.Fix, &f.FirstSeen); err != nil {
			rows.Close()
			return nil, err
		}
		f.Source = autotask.SourceIdentity
		f.MemberKey = f.Provider + "|" + f.CheckID + "|" + f.Subject
		if f.MemberLabel == "" {
			f.MemberLabel = f.Subject
		}
		out = append(out, f)
	}
	rows.Close()
	return out, rows.Err()
}

func surfaceMemberKey(assetID int64, checkID, subject string) string {
	return strconv.FormatInt(assetID, 10) + "|" + checkID + "|" + subject
}

// ---- the port the engine uses ---------------------------------------------------------------

// AutotaskPort returns the engine's view of this store, naming the actor in
// nothing: the actor is passed on each commit.
func (s *Store) AutotaskPort() autotask.Store { return autotaskPort{s} }

type autotaskPort struct{ s *Store }

func (p autotaskPort) Tracked(ctx context.Context) ([]autotask.Tracked, error) {
	return p.s.AutotaskTracked(ctx)
}

func (p autotaskPort) Commit(ctx context.Context, actor string, ch autotask.Change) error {
	return p.s.AutotaskCommit(ctx, actor, ch)
}

func (p autotaskPort) Evidence(ctx context.Context, refs []autotask.MemberRef) (map[autotask.MemberRef]autotask.Evidence, error) {
	return p.s.AutotaskEvidence(ctx, refs)
}

// AutotaskTracked returns every ticket DefendSec follows, newest generation of
// each action included alongside the older ones.
func (s *Store) AutotaskTracked(ctx context.Context) ([]autotask.Tracked, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT group_key, generation, tag, ticket_id, ticket_number, company_id, title, state, urgency, members, created_at, updated_at, resolved_at
		FROM autotask_tickets ORDER BY group_key, generation`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []autotask.Tracked
	for rows.Next() {
		var t autotask.Tracked
		var members []byte
		if err := rows.Scan(&t.GroupKey, &t.Generation, &t.Tag, &t.TicketID, &t.TicketNumber, &t.CompanyID, &t.Title, &t.State, &t.Urgency, &members,
			&t.CreatedAt, &t.UpdatedAt, &t.ResolvedAt); err != nil {
			return nil, err
		}
		t.Members = map[string]autotask.MemberState{}
		if err := json.Unmarshal(members, &t.Members); err != nil {
			return nil, fmt.Errorf("tracked ticket %s: members: %w", t.Tag, err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AutotaskCommit saves a tracked ticket's new state and its ledger entry in one
// transaction. The ledger entry is the audit chain's: tamper evidence for "this
// ticket was created for this action at this time".
func (s *Store) AutotaskCommit(ctx context.Context, actor string, ch autotask.Change) error {
	t := ch.Tracked
	members, err := json.Marshal(t.Members)
	if err != nil {
		return err
	}
	if t.Members == nil {
		members = []byte("{}")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO autotask_tickets (group_key, generation, tag, ticket_id, ticket_number, company_id, title, state, urgency, members, created_at, updated_at, resolved_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)
		ON CONFLICT (group_key, generation) DO UPDATE SET ticket_number = EXCLUDED.ticket_number, title = EXCLUDED.title, state = EXCLUDED.state,
			urgency = EXCLUDED.urgency, members = EXCLUDED.members, updated_at = EXCLUDED.updated_at, resolved_at = EXCLUDED.resolved_at`,
		t.GroupKey, t.Generation, t.Tag, t.TicketID, t.TicketNumber, t.CompanyID, t.Title, t.State, t.Urgency, string(members),
		orNow(t.CreatedAt), orNow(t.UpdatedAt), t.ResolvedAt); err != nil {
		return err
	}
	if err := auditInTx(ctx, tx, actor, ch.Action, "", ch.Detail); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t.UTC()
}

// AutotaskEvidence says how members that were open on a ticket are no longer.
// A vulnerability or end-of-life member (a host) is the resolved rows of that
// host and package family since the ticket opened; a surface or identity member
// is the finding's own row.
func (s *Store) AutotaskEvidence(ctx context.Context, refs []autotask.MemberRef) (map[autotask.MemberRef]autotask.Evidence, error) {
	out := map[autotask.MemberRef]autotask.Evidence{}
	for _, r := range refs {
		var ev autotask.Evidence
		var err error
		parts := strings.SplitN(r.GroupKey, "|", 3)
		switch parts[0] {
		case autotask.SourceVuln:
			ev, err = s.hostEvidence(ctx, r, parts[1], "")
		case autotask.SourceEOL:
			cycle := ""
			if len(parts) == 3 {
				cycle = parts[2]
			}
			ev, err = s.hostEvidence(ctx, r, parts[1], cycle)
		case autotask.SourceSurface:
			ev, err = s.surfaceEvidence(ctx, r)
		case autotask.SourceIdentity:
			ev, err = s.identityEvidence(ctx, r)
		}
		if err != nil {
			return nil, err
		}
		if ev.Found {
			out[r] = ev
		}
	}
	return out, nil
}

// hostEvidence reads the resolved rows of one host and package family (for
// end-of-life software, product and release) that closed since the ticket opened.
func (s *Store) hostEvidence(ctx context.Context, r autotask.MemberRef, family, eolCycle string) (autotask.Evidence, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT f.package, f.resolution, f.resolved_installed, f.fixed, f.advisory_id, f.resolved_at, f.kind
		FROM vuln_findings f
		WHERE f.device_id = $1 AND f.family = $2 AND f.resolved_at IS NOT NULL AND f.resolved_at >= $3
		  AND ($4 = '' OR f.eol_cycle = $4)
		ORDER BY f.package, f.advisory_id`, r.MemberKey, family, r.Since.Add(-time.Minute), eolCycle)
	if err != nil {
		return autotask.Evidence{}, err
	}
	defer rows.Close()
	type key struct{ pkg, resolution, installed, fixed string }
	seen := map[key]bool{}
	var parts []string
	advisories := map[string]bool{}
	var latest time.Time
	for rows.Next() {
		var k key
		var adv, kind string
		var at time.Time
		if err := rows.Scan(&k.pkg, &k.resolution, &k.installed, &k.fixed, &adv, &at, &kind); err != nil {
			return autotask.Evidence{}, err
		}
		advisories[adv] = true
		if at.After(latest) {
			latest = at
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		switch k.resolution {
		case "fixed":
			if k.fixed != "" {
				parts = append(parts, fmt.Sprintf("%s %s observed, at or above the fixed version %s", k.pkg, k.installed, k.fixed))
			} else {
				parts = append(parts, fmt.Sprintf("%s %s observed", k.pkg, k.installed))
			}
		case "package_removed":
			parts = append(parts, fmt.Sprintf("%s is no longer installed", k.pkg))
		case "no_longer_affected":
			parts = append(parts, fmt.Sprintf("%s no longer matches the advisory data (a feed reclassified or withdrew it; the version was not what closed it)", k.pkg))
		default:
			parts = append(parts, fmt.Sprintf("%s: no longer reported", k.pkg))
		}
	}
	if err := rows.Err(); err != nil {
		return autotask.Evidence{}, err
	}
	if len(parts) == 0 {
		return autotask.Evidence{}, nil
	}
	sort.Strings(parts)
	detail := strings.Join(parts, "; ")
	if len(parts) > 3 {
		detail = strings.Join(parts[:3], "; ") + fmt.Sprintf("; and %d more", len(parts)-3)
	}
	n := len(advisories)
	detail += fmt.Sprintf(" (%d %s closed)", n, map[bool]string{true: "finding", false: "findings"}[n == 1])
	return autotask.Evidence{Found: true, ResolvedAt: latest.UTC(), Detail: detail}, nil
}

func (s *Store) surfaceEvidence(ctx context.Context, r autotask.MemberRef) (autotask.Evidence, error) {
	parts := strings.SplitN(r.MemberKey, "|", 3)
	if len(parts) != 3 {
		return autotask.Evidence{}, nil
	}
	assetID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return autotask.Evidence{}, nil
	}
	var resolved *time.Time
	var removed *time.Time
	var title string
	err = s.pool.QueryRow(ctx, `
		SELECT sf.resolved_at, sa.removed_at, sf.title
		FROM surface_findings sf JOIN surface_assets sa ON sa.id = sf.asset_id
		WHERE sf.asset_id = $1 AND sf.finding_id = $2 AND sf.subject = $3`, assetID, parts[1], parts[2]).Scan(&resolved, &removed, &title)
	if errors.Is(err, pgx.ErrNoRows) {
		return autotask.Evidence{}, nil
	}
	if err != nil {
		return autotask.Evidence{}, err
	}
	switch {
	case resolved != nil:
		return autotask.Evidence{Found: true, ResolvedAt: resolved.UTC(), Detail: "the latest scan no longer reports it (" + title + ")"}, nil
	case removed != nil:
		return autotask.Evidence{Found: true, ResolvedAt: removed.UTC(), Detail: "the asset was removed from DefendSec's declared assets, so nothing was verified"}, nil
	}
	return autotask.Evidence{}, nil
}

func (s *Store) identityEvidence(ctx context.Context, r autotask.MemberRef) (autotask.Evidence, error) {
	parts := strings.SplitN(r.MemberKey, "|", 3)
	if len(parts) != 3 {
		return autotask.Evidence{}, nil
	}
	var resolved *time.Time
	var title string
	err := s.pool.QueryRow(ctx, `SELECT resolved_at, title FROM identity_findings WHERE provider = $1 AND finding_id = $2 AND subject = $3`,
		parts[0], parts[1], parts[2]).Scan(&resolved, &title)
	if errors.Is(err, pgx.ErrNoRows) {
		return autotask.Evidence{}, nil
	}
	if err != nil {
		return autotask.Evidence{}, err
	}
	if resolved == nil {
		return autotask.Evidence{}, nil
	}
	return autotask.Evidence{Found: true, ResolvedAt: resolved.UTC(), Detail: "the latest read of the tenant no longer reports it (" + title + ")"}, nil
}

// ---- runs ---------------------------------------------------------------------------------

// AutotaskRun is one run, dry or live, with the operations it showed or did.
type AutotaskRun struct {
	ID            int64         `json:"id"`
	Mode          string        `json:"mode"`
	TriggeredBy   string        `json:"triggeredBy"`
	StartedAt     time.Time     `json:"startedAt"`
	FinishedAt    time.Time     `json:"finishedAt"`
	Status        string        `json:"status"`
	Verified      bool          `json:"verified"`
	UnverifiedWhy string        `json:"unverifiedWhy"`
	Fingerprint   string        `json:"fingerprint"`
	CompanyName   string        `json:"companyName"`
	Requests      int           `json:"requests"`
	Groups        int           `json:"groups"`
	Below         int           `json:"belowThreshold"`
	Created       int           `json:"created"`
	Noted         int           `json:"noted"`
	Completed     int           `json:"completed"`
	Failed        int           `json:"failed"`
	Deferred      int           `json:"deferred"`
	Flagged       int           `json:"flagged"`
	Problems      []string      `json:"problems"`
	Ops           []autotask.Op `json:"ops"`
}

// AutotaskRunAttestation is what the audit chain holds of a run: which run, how it
// went, what it counted. The operations themselves each have an entry when they
// were carried out; the text of a dry run's tickets is only in the run.
type AutotaskRunAttestation struct {
	RunID       int64  `json:"runId"`
	Mode        string `json:"mode"`
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
	Verified    bool   `json:"verified"`
	Groups      int    `json:"groups"`
	Created     int    `json:"created"`
	Noted       int    `json:"noted"`
	Completed   int    `json:"completed"`
	Failed      int    `json:"failed"`
	FinishedAt  string `json:"finishedAt"`
}

// RecordAutotaskRun stores a run and chains it: a dry run is "autotask_dry_run",
// a live run "autotask_run".
func (s *Store) RecordAutotaskRun(ctx context.Context, trigger string, started time.Time, res autotask.Result) (AutotaskRun, error) {
	finished := time.Now().UTC().Round(time.Microsecond)
	started = started.UTC().Round(time.Microsecond)
	if trigger == "" {
		trigger = "schedule"
	}
	if res.Ops == nil {
		res.Ops = []autotask.Op{}
	}
	if res.Problems == nil {
		res.Problems = []string{}
	}
	why := res.UnverifiedWhy
	if len(why) > 2000 {
		why = why[:2000]
	}
	opsJSON, err := json.Marshal(res.Ops)
	if err != nil {
		return AutotaskRun{}, err
	}
	probJSON, _ := json.Marshal(res.Problems)
	run := AutotaskRun{Mode: res.Mode, TriggeredBy: trigger, StartedAt: started, FinishedAt: finished, Status: res.Status(), Verified: res.Verified,
		UnverifiedWhy: why, Fingerprint: res.Fingerprint, CompanyName: res.CompanyName, Requests: res.Requests, Groups: res.Groups, Below: res.BelowThreshold,
		Created: res.Created, Noted: res.Noted, Completed: res.Completed, Failed: res.Failed, Deferred: res.Deferred, Flagged: res.Flagged, Problems: res.Problems, Ops: res.Ops}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return run, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := tx.QueryRow(ctx, `
		INSERT INTO autotask_runs (mode, triggered_by, started_at, finished_at, status, verified, unverified_why, fingerprint, company_name, requests, groups,
			below_threshold, created, noted, completed, failed, deferred, flagged, problems, ops)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20::jsonb) RETURNING id`,
		run.Mode, trigger, started, finished, run.Status, run.Verified, why, run.Fingerprint, run.CompanyName, run.Requests, run.Groups, run.Below,
		run.Created, run.Noted, run.Completed, run.Failed, run.Deferred, run.Flagged, string(probJSON), string(opsJSON)).Scan(&run.ID); err != nil {
		return run, err
	}
	action := "autotask_run"
	if run.Mode == autotask.ModeDryRun {
		action = "autotask_dry_run"
	}
	if err := auditInTx(ctx, tx, "system:autotask", action, "", AutotaskRunAttestation{
		RunID: run.ID, Mode: run.Mode, Status: run.Status, Fingerprint: run.Fingerprint, Verified: run.Verified, Groups: run.Groups,
		Created: run.Created, Noted: run.Noted, Completed: run.Completed, Failed: run.Failed, FinishedAt: finished.Format(time.RFC3339Nano),
	}); err != nil {
		return run, fmt.Errorf("chain the run: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return run, err
	}
	return run, nil
}

const autotaskRunCols = `id, mode, triggered_by, started_at, finished_at, status, verified, unverified_why, fingerprint, company_name, requests, groups,
	below_threshold, created, noted, completed, failed, deferred, flagged, problems, ops`

func scanAutotaskRun(row pgx.Row) (AutotaskRun, error) {
	var r AutotaskRun
	var problems, ops []byte
	if err := row.Scan(&r.ID, &r.Mode, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Verified, &r.UnverifiedWhy, &r.Fingerprint, &r.CompanyName,
		&r.Requests, &r.Groups, &r.Below, &r.Created, &r.Noted, &r.Completed, &r.Failed, &r.Deferred, &r.Flagged, &problems, &ops); err != nil {
		return r, err
	}
	r.Problems, r.Ops = []string{}, []autotask.Op{}
	_ = json.Unmarshal(problems, &r.Problems)
	_ = json.Unmarshal(ops, &r.Ops)
	return r, nil
}

// LatestAutotaskRun returns the newest run, or nil.
func (s *Store) LatestAutotaskRun(ctx context.Context) (*AutotaskRun, error) {
	r, err := scanAutotaskRun(s.pool.QueryRow(ctx, `SELECT `+autotaskRunCols+` FROM autotask_runs ORDER BY finished_at DESC, id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ErrAutotaskRunNotFound says no run has that id.
var ErrAutotaskRunNotFound = errors.New("autotask run not found")

// GetAutotaskRun returns one run with its operations.
func (s *Store) GetAutotaskRun(ctx context.Context, id int64) (AutotaskRun, error) {
	r, err := scanAutotaskRun(s.pool.QueryRow(ctx, `SELECT `+autotaskRunCols+` FROM autotask_runs WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return AutotaskRun{}, ErrAutotaskRunNotFound
	}
	return r, err
}

// LatestAutotaskRunOf returns the newest run of a mode, or nil.
func (s *Store) LatestAutotaskRunOf(ctx context.Context, mode string) (*AutotaskRun, error) {
	r, err := scanAutotaskRun(s.pool.QueryRow(ctx, `SELECT `+autotaskRunCols+` FROM autotask_runs WHERE mode = $1 ORDER BY finished_at DESC, id DESC LIMIT 1`, mode))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// LatestAutotaskDryRun returns the newest dry run, or nil.
func (s *Store) LatestAutotaskDryRun(ctx context.Context) (*AutotaskRun, error) {
	r, err := scanAutotaskRun(s.pool.QueryRow(ctx, `SELECT `+autotaskRunCols+` FROM autotask_runs WHERE mode = 'dry_run' ORDER BY finished_at DESC, id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListAutotaskRuns returns the newest runs (without their operations).
func (s *Store) ListAutotaskRuns(ctx context.Context, limit int) ([]AutotaskRun, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `SELECT `+autotaskRunCols+` FROM autotask_runs ORDER BY finished_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AutotaskRun{}
	for rows.Next() {
		r, err := scanAutotaskRun(rows)
		if err != nil {
			return nil, err
		}
		r.Ops = []autotask.Op{} // the history is a list; GET /v1/autotask/runs/<id> would carry them
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestGoodDryRunFingerprint is the fingerprint of the newest dry run that read
// Autotask (so its company, picklists and tickets were checked) and ended with no
// problem. A live run, and switching to live, need the current settings' to equal it.
func (s *Store) LatestGoodDryRunFingerprint(ctx context.Context) (string, error) {
	var fp string
	err := s.pool.QueryRow(ctx, `
		SELECT fingerprint FROM autotask_runs
		WHERE mode = 'dry_run' AND verified AND jsonb_array_length(problems) = 0
		ORDER BY finished_at DESC, id DESC LIMIT 1`).Scan(&fp)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return fp, err
}

// AutotaskCounts is what the status shows of the tracked tickets.
type AutotaskCounts struct {
	Open        int `json:"open"`
	Resolved    int `json:"resolved"`
	ClosedInPSA int `json:"closedInPsa"`
}

// AutotaskTicketCounts counts the tracked tickets by state (latest generation of
// each action only).
func (s *Store) AutotaskTicketCounts(ctx context.Context) (AutotaskCounts, error) {
	var c AutotaskCounts
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE state = 'open'), count(*) FILTER (WHERE state = 'resolved'), count(*) FILTER (WHERE state = 'closed_in_psa')
		FROM autotask_tickets t
		WHERE generation = (SELECT max(generation) FROM autotask_tickets x WHERE x.group_key = t.group_key)`).Scan(&c.Open, &c.Resolved, &c.ClosedInPSA)
	return c, err
}

// AutotaskTicketList returns the tracked tickets, newest first, for the console.
func (s *Store) AutotaskTicketList(ctx context.Context, limit int) ([]autotask.Tracked, error) {
	all, err := s.AutotaskTracked(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool { return all[i].UpdatedAt.After(all[j].UpdatedAt) })
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}
