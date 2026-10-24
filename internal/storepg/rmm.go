package storepg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"defendsec/internal/presence"
	"defendsec/internal/vuln"
)

// Datto RMM collector storage (migration 027). Devices read from the RMM are rows
// of `devices` with source 'rmm', held in Postgres only (LoadDevices skips them,
// so no agent code path sees one); what RMM said about them is in rmm_devices
// and rmm_patches; their findings are ordinary vuln_findings rows whose feed is
// 'msrc'; what the last match examined is host_patch_state.

// SourceRMM marks a devices row read from an RMM.
const SourceRMM = "rmm"

// DefaultRMMStaleDays is the audit age past which a device's evidence is
// treated as missing.
const DefaultRMMStaleDays = 7

// RMMSettings is the instance's one RMM site.
type RMMSettings struct {
	Configured     bool       `json:"configured"`
	SiteUID        string     `json:"siteUid"`
	SiteName       string     `json:"siteName"`
	StaleAfterDays int        `json:"staleAfterDays"`
	SelectedBy     string     `json:"selectedBy,omitempty"`
	SelectedAt     *time.Time `json:"selectedAt,omitempty"`
}

// GetRMMSettings returns the selected site, or Configured=false with defaults.
func (s *Store) GetRMMSettings(ctx context.Context) (RMMSettings, error) {
	out := RMMSettings{StaleAfterDays: DefaultRMMStaleDays}
	var at time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT site_uid, site_name, stale_after_days, selected_by, selected_at FROM rmm_settings WHERE id = 1`).
		Scan(&out.SiteUID, &out.SiteName, &out.StaleAfterDays, &out.SelectedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Configured = out.SiteUID != ""
	out.SelectedAt = &at
	return out, nil
}

// SetRMMSettings records the site this instance reads and the stale-audit
// threshold, and chains the change in the audit log in the same transaction.
func (s *Store) SetRMMSettings(ctx context.Context, actor, siteUID, siteName string, staleDays int) error {
	if siteUID == "" {
		return errors.New("rmm: a site is required")
	}
	if staleDays < 1 || staleDays > 90 {
		return errors.New("rmm: stale-after days must be between 1 and 90")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO rmm_settings (id, site_uid, site_name, stale_after_days, selected_by, selected_at)
		VALUES (1, $1, $2, $3, $4, now())
		ON CONFLICT (id) DO UPDATE SET site_uid = EXCLUDED.site_uid, site_name = EXCLUDED.site_name,
			stale_after_days = EXCLUDED.stale_after_days, selected_by = EXCLUDED.selected_by, selected_at = now()`,
		siteUID, siteName, staleDays, actor); err != nil {
		return err
	}
	if err := auditInTx(ctx, tx, actor, "rmm_site_selected", "", map[string]any{
		"provider": "datto", "siteUid": siteUID, "siteName": siteName, "staleAfterDays": staleDays,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// RMMDevice is a device read from the RMM, ready to store.
type RMMDevice struct {
	DeviceID string // "rmm-<uid>"
	UID      string
	SiteUID  string
	Hostname string
	Serial   string

	OSCaption, OSVersion, OSBuild, OSDisplay, OSInstallType, DeviceType string
	Arch, Hardware                                                      string

	Online         bool
	LastSeen       *time.Time
	LastAudit      *time.Time
	LastReboot     *time.Time
	RebootRequired bool

	PatchStatus                                                  string
	PatchesApprovedPending, PatchesNotApproved, PatchesInstalled int
	AntivirusProduct, AntivirusStatus                            string

	// Software replaces the stored list when SoftwareSet; otherwise the stored
	// one is kept (a device whose software was not read this time).
	Software    []presence.Software
	SoftwareSet bool
	// Pending replaces the host's pending updates when PendingSet.
	Pending    []presence.Update
	PendingSet bool

	CollectError string
	CollectedAt  time.Time
}

// RMMDeviceID is the devices.id of an RMM device.
func RMMDeviceID(uid string) string { return "rmm-" + uid }

// UpsertRMMDevice stores a device and what RMM said about it. A device that had
// been retired (it left the site) comes back.
func (s *Store) UpsertRMMDevice(ctx context.Context, d RMMDevice) error {
	if d.DeviceID == "" || d.UID == "" || d.SiteUID == "" {
		return errors.New("rmm device needs an id, uid and site")
	}
	sw, _ := json.Marshal(d.Software)
	if d.Software == nil {
		sw = []byte("[]")
	}
	pend, _ := json.Marshal(d.Pending)
	if d.Pending == nil {
		pend = []byte("[]")
	}
	lastSeen := time.Now().UTC()
	if d.LastSeen != nil && !d.LastSeen.IsZero() {
		lastSeen = d.LastSeen.UTC()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `
		INSERT INTO devices (id, hostname, platform, os_name, os_version, arch, serial, hardware_model,
			software, pending_updates, last_seen, connected, transport, source, revoked, updated_at)
		VALUES ($1,$2,'windows',$3,$4,$5,$6,$7,
			CASE WHEN $8 THEN $9::jsonb ELSE '[]'::jsonb END, CASE WHEN $10 THEN $11::jsonb ELSE '[]'::jsonb END,
			$12::timestamptz,$13,'rmm','rmm',false,now())
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname, os_name = EXCLUDED.os_name, os_version = EXCLUDED.os_version,
			arch = COALESCE(NULLIF(EXCLUDED.arch,''), devices.arch),
			serial = COALESCE(NULLIF(EXCLUDED.serial,''), devices.serial),
			hardware_model = COALESCE(NULLIF(EXCLUDED.hardware_model,''), devices.hardware_model),
			software = CASE WHEN $8 THEN EXCLUDED.software ELSE devices.software END,
			pending_updates = CASE WHEN $10 THEN EXCLUDED.pending_updates ELSE devices.pending_updates END,
			last_seen = EXCLUDED.last_seen, connected = EXCLUDED.connected,
			transport = 'rmm', source = 'rmm', revoked = false, updated_at = now()
		WHERE devices.source = 'rmm'`,
		d.DeviceID, d.Hostname, d.OSCaption, d.OSVersion, d.Arch, d.Serial, d.Hardware,
		d.SoftwareSet, string(sw), d.PendingSet, string(pend), lastSeen, d.Online); err != nil {
		return fmt.Errorf("store rmm device: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rmm_devices (device_id, rmm_uid, site_uid, hostname, serial, os_caption, os_version, os_build,
			os_display, os_install_type, device_type, online, rmm_last_seen, last_audit_at, last_reboot_at, reboot_required,
			patch_status, patches_approved_pending, patches_not_approved, patches_installed,
			antivirus_product, antivirus_status, software_count, collect_error, collected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
			CASE WHEN $23 THEN $24 ELSE 0 END, $25, $26)
		ON CONFLICT (device_id) DO UPDATE SET
			site_uid = EXCLUDED.site_uid, hostname = EXCLUDED.hostname,
			serial = COALESCE(NULLIF(EXCLUDED.serial,''), rmm_devices.serial),
			os_caption = EXCLUDED.os_caption, os_version = EXCLUDED.os_version, os_build = EXCLUDED.os_build,
			os_display = EXCLUDED.os_display, os_install_type = EXCLUDED.os_install_type, device_type = EXCLUDED.device_type,
			online = EXCLUDED.online, rmm_last_seen = EXCLUDED.rmm_last_seen, last_audit_at = EXCLUDED.last_audit_at,
			last_reboot_at = EXCLUDED.last_reboot_at, reboot_required = EXCLUDED.reboot_required,
			patch_status = EXCLUDED.patch_status, patches_approved_pending = EXCLUDED.patches_approved_pending,
			patches_not_approved = EXCLUDED.patches_not_approved, patches_installed = EXCLUDED.patches_installed,
			antivirus_product = EXCLUDED.antivirus_product, antivirus_status = EXCLUDED.antivirus_status,
			software_count = CASE WHEN $23 THEN EXCLUDED.software_count ELSE rmm_devices.software_count END,
			collect_error = EXCLUDED.collect_error, collected_at = EXCLUDED.collected_at`,
		d.DeviceID, d.UID, d.SiteUID, d.Hostname, d.Serial, d.OSCaption, d.OSVersion, d.OSBuild,
		d.OSDisplay, d.OSInstallType, d.DeviceType, d.Online, d.LastSeen, d.LastAudit, d.LastReboot, d.RebootRequired,
		d.PatchStatus, d.PatchesApprovedPending, d.PatchesNotApproved, d.PatchesInstalled,
		d.AntivirusProduct, d.AntivirusStatus, d.SoftwareSet, len(d.Software), d.CollectError, d.CollectedAt); err != nil {
		return fmt.Errorf("store rmm device facts: %w", err)
	}
	return tx.Commit(ctx)
}

// RMMPatch is one update RMM lists for a device as not installed.
type RMMPatch struct {
	UID            string
	KB             string // "KB5000001" or ""
	Title          string
	Severity       string
	Type           string
	Status         string // APPROVED_PENDING or NOT_APPROVED
	ReleaseDate    *time.Time
	RebootRequired bool
}

// ReplaceRMMPatches replaces a device's list of missing patches.
func (s *Store) ReplaceRMMPatches(ctx context.Context, deviceID string, ps []RMMPatch) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `DELETE FROM rmm_patches WHERE device_id = $1`, deviceID); err != nil {
		return err
	}
	for _, p := range ps {
		if _, err := tx.Exec(ctx, `
			INSERT INTO rmm_patches (device_id, patch_uid, kb, title, severity, patch_type, install_status, release_date, reboot_required)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::date,$9)
			ON CONFLICT (device_id, patch_uid) DO UPDATE SET kb = EXCLUDED.kb, title = EXCLUDED.title,
				severity = EXCLUDED.severity, patch_type = EXCLUDED.patch_type, install_status = EXCLUDED.install_status,
				release_date = EXCLUDED.release_date, reboot_required = EXCLUDED.reboot_required`,
			deviceID, p.UID, p.KB, p.Title, p.Severity, p.Type, p.Status, p.ReleaseDate, p.RebootRequired); err != nil {
			return fmt.Errorf("store patch %s: %w", p.UID, err)
		}
	}
	return tx.Commit(ctx)
}

// RetireRMMDevices marks RMM device rows that are not in keep (the uids the site
// listing returned) as revoked: they left the site, or the site changed. The
// rows and their findings stay as evidence but leave every list and count, as a
// revoked agent does. It returns how many were retired.
func (s *Store) RetireRMMDevices(ctx context.Context, siteUID string, keep []string) (int, error) {
	ids := make([]string, 0, len(keep))
	for _, uid := range keep {
		ids = append(ids, RMMDeviceID(uid))
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET revoked = true, updated_at = now()
		WHERE source = 'rmm' AND NOT revoked
		  AND (id <> ALL($1::text[]) OR id IN (SELECT device_id FROM rmm_devices WHERE site_uid <> $2))`, ids, siteUID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// AgentIdentity is what an enrolled Windows agent device offers for matching an
// RMM device with the same machine.
type AgentIdentity struct {
	ID       string
	Hostname string
	Serial   string
}

// AgentIdentities lists the live Windows agent devices (an RMM device read here is
// always Windows, so only a Windows agent can be the same machine).
func (s *Store) AgentIdentities(ctx context.Context) ([]AgentIdentity, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, serial FROM devices WHERE source = 'agent' AND platform = 'windows' AND NOT revoked AND NOT sample ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentIdentity
	for rows.Next() {
		var a AgentIdentity
		if err := rows.Scan(&a.ID, &a.Hostname, &a.Serial); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetRMMMerge records that an RMM device is the same machine as an agent device
// (agentID "" clears it). A merged RMM row is left out of the host list and the
// host counts; the agent row stands for the machine.
func (s *Store) SetRMMMerge(ctx context.Context, deviceID, agentID, basis string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `UPDATE devices SET merged_into = NULLIF($2,'') WHERE id = $1 AND source = 'rmm'`, deviceID, agentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE rmm_devices SET agent_device_id = NULLIF($2,''), dedupe_basis = $3 WHERE device_id = $1`, deviceID, agentID, basis); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// OpenMSRCKBs lists the KBs behind a device's open Microsoft findings.
func (s *Store) OpenMSRCKBs(ctx context.Context, deviceID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT package FROM vuln_findings WHERE device_id = $1 AND resolved_at IS NULL ORDER BY 1`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var kb string
		if err := rows.Scan(&kb); err != nil {
			return nil, err
		}
		out = append(out, kb)
	}
	return out, rows.Err()
}

// HostPatchState is what the last patch match examined for a host.
type HostPatchState struct {
	DeviceID   string     `json:"deviceId"`
	Coverage   string     `json:"coverage"`
	Reason     string     `json:"reason"`
	EvidenceAt *time.Time `json:"evidenceAt"`
	KBsMissing int        `json:"kbsMissing"`
	KBsMapped  int        `json:"kbsMapped"`
	SnapshotID *int64     `json:"snapshotId"`
	MatchedAt  time.Time  `json:"matchedAt"`
}

// Host patch coverage values.
const (
	PatchCovered = "covered"
	PatchStale   = "stale"
	PatchNoData  = "no_data"
	PatchNoFeed  = "no_feed"
)

// effectivePatchCoverage is the coverage as of $1 (now): a 'covered' state whose
// evidence has aged past the site's stale threshold since the last read (the RMM
// was unreachable for days, say) reads as stale. Stored state is what the last
// read saw; this is what may still be said today.
const effectivePatchCoverage = `CASE WHEN p.coverage = 'covered' AND (p.evidence_at IS NULL OR p.evidence_at <
		$1::timestamptz - make_interval(days => COALESCE((SELECT stale_after_days FROM rmm_settings WHERE id = 1), 7)))
		THEN 'stale' ELSE p.coverage END`

const upsertPatchStateSQL = `
	INSERT INTO host_patch_state (device_id, source, coverage, reason, evidence_at, kbs_missing, kbs_mapped, snapshot_id, matched_at)
	VALUES ($1, 'datto-rmm', $2, $3, $4, $5, $6, $7, now())
	ON CONFLICT (device_id) DO UPDATE SET coverage = EXCLUDED.coverage, reason = EXCLUDED.reason,
		evidence_at = EXCLUDED.evidence_at, kbs_missing = EXCLUDED.kbs_missing, kbs_mapped = EXCLUDED.kbs_mapped,
		snapshot_id = EXCLUDED.snapshot_id, matched_at = now()`

// SetHostPatchState records a coverage without touching findings: a stale or
// unreadable device keeps the findings it had, and is not clean.
func (s *Store) SetHostPatchState(ctx context.Context, st HostPatchState) error {
	switch st.Coverage {
	case PatchCovered, PatchStale, PatchNoData, PatchNoFeed:
	default:
		return fmt.Errorf("bad patch coverage %q", st.Coverage)
	}
	_, err := s.pool.Exec(ctx, upsertPatchStateSQL, st.DeviceID, st.Coverage, st.Reason, st.EvidenceAt, st.KBsMissing, st.KBsMapped, st.SnapshotID)
	return err
}

// GetHostPatchState returns what the last match examined for a host.
func (s *Store) GetHostPatchState(ctx context.Context, deviceID string) (HostPatchState, bool, error) {
	var st HostPatchState
	err := s.pool.QueryRow(ctx, `
		SELECT device_id, coverage, reason, evidence_at, kbs_missing, kbs_mapped, snapshot_id, matched_at
		FROM host_patch_state WHERE device_id = $1`, deviceID).
		Scan(&st.DeviceID, &st.Coverage, &st.Reason, &st.EvidenceAt, &st.KBsMissing, &st.KBsMapped, &st.SnapshotID, &st.MatchedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, false, nil
	}
	return st, err == nil, err
}

// RecordPatchFindings stores the outcome of matching one RMM device's missing
// updates: it upserts every finding, closes the device's findings the run did
// not confirm (recording from inv why), and records the coverage. One
// transaction, so a reader never sees a half-written host.
func (s *Store) RecordPatchFindings(ctx context.Context, deviceID string, res vuln.Result, snapshotID *int64, inv *Inventory, st HostPatchState) error {
	switch st.Coverage {
	case PatchCovered, PatchStale, PatchNoData, PatchNoFeed:
	default:
		return fmt.Errorf("bad patch coverage %q", st.Coverage)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := recordFindingsTx(ctx, tx, deviceID, res, inv); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, upsertPatchStateSQL, deviceID, st.Coverage, st.Reason, st.EvidenceAt, st.KBsMissing, st.KBsMapped, snapshotID); err != nil {
		return fmt.Errorf("record patch state: %w", err)
	}
	return tx.Commit(ctx)
}

// CountOpenRMMFindings counts the open fixable Microsoft findings of live RMM devices.
func (s *Store) CountOpenRMMFindings(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND d.source = 'rmm' AND NOT d.revoked
		WHERE f.resolved_at IS NULL AND f.kind = 'finding'`).Scan(&n)
	return n, err
}

// RMMSync is one read of the RMM site.
type RMMSync struct {
	ID           int64     `json:"id"`
	SiteUID      string    `json:"siteUid"`
	TriggeredBy  string    `json:"triggeredBy"`
	StartedAt    time.Time `json:"startedAt"`
	FinishedAt   time.Time `json:"finishedAt"`
	Status       string    `json:"status"` // ok, partial, not_assessed
	Reason       string    `json:"reason"`
	Devices      int       `json:"devices"`
	Windows      int       `json:"windows"`
	Skipped      int       `json:"skipped"`
	Stale        int       `json:"stale"`
	Unreadable   int       `json:"unreadable"`
	Merged       int       `json:"merged"`
	KBsMissing   int       `json:"kbsMissing"`
	KBsUnmapped  int       `json:"kbsUnmapped"`
	FindingsOpen int       `json:"findingsOpen"`
	Requests     int       `json:"requests"`
	Errors       []string  `json:"errors"`
}

// RMMSyncAttestation is what the audit chain holds for a sync.
type RMMSyncAttestation struct {
	SyncID       int64  `json:"syncId"`
	SiteUID      string `json:"siteUid"`
	Status       string `json:"status"`
	Devices      int    `json:"devices"`
	Windows      int    `json:"windows"`
	Stale        int    `json:"stale"`
	Unreadable   int    `json:"unreadable"`
	KBsMissing   int    `json:"kbsMissing"`
	FindingsOpen int    `json:"findingsOpen"`
	FinishedAt   string `json:"finishedAt"`
}

// RecordRMMSync stores the record of a read and chains a summary of it in the
// audit log, in one transaction.
func (s *Store) RecordRMMSync(ctx context.Context, r RMMSync) (RMMSync, error) {
	if r.Errors == nil {
		r.Errors = []string{}
	}
	if len(r.Errors) > 50 {
		r.Errors = r.Errors[:50]
	}
	errs, _ := json.Marshal(r.Errors)
	switch r.Status {
	case "ok", "partial", "not_assessed":
	default:
		return r, fmt.Errorf("bad sync status %q", r.Status)
	}
	if r.TriggeredBy == "" {
		r.TriggeredBy = "schedule"
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := tx.QueryRow(ctx, `
		INSERT INTO rmm_syncs (site_uid, triggered_by, started_at, finished_at, status, reason, devices, windows, skipped, stale,
			unreadable, merged, kbs_missing, kbs_unmapped, findings_open, requests, errors)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::jsonb) RETURNING id`,
		r.SiteUID, r.TriggeredBy, r.StartedAt, r.FinishedAt, r.Status, r.Reason, r.Devices, r.Windows, r.Skipped, r.Stale,
		r.Unreadable, r.Merged, r.KBsMissing, r.KBsUnmapped, r.FindingsOpen, r.Requests, string(errs)).Scan(&r.ID); err != nil {
		return r, err
	}
	if err := auditInTx(ctx, tx, "system:rmm-collector", "rmm_sync_recorded", "", RMMSyncAttestation{
		SyncID: r.ID, SiteUID: r.SiteUID, Status: r.Status, Devices: r.Devices, Windows: r.Windows, Stale: r.Stale,
		Unreadable: r.Unreadable, KBsMissing: r.KBsMissing, FindingsOpen: r.FindingsOpen,
		FinishedAt: r.FinishedAt.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return r, fmt.Errorf("chain the sync: %w", err)
	}
	return r, tx.Commit(ctx)
}

const syncColumns = `id, site_uid, triggered_by, started_at, finished_at, status, reason, devices, windows, skipped, stale,
	unreadable, merged, kbs_missing, kbs_unmapped, findings_open, requests, errors`

func scanSync(row pgx.Row) (RMMSync, error) {
	var r RMMSync
	var errs []byte
	if err := row.Scan(&r.ID, &r.SiteUID, &r.TriggeredBy, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Reason, &r.Devices,
		&r.Windows, &r.Skipped, &r.Stale, &r.Unreadable, &r.Merged, &r.KBsMissing, &r.KBsUnmapped, &r.FindingsOpen,
		&r.Requests, &errs); err != nil {
		return r, err
	}
	_ = json.Unmarshal(errs, &r.Errors)
	if r.Errors == nil {
		r.Errors = []string{}
	}
	return r, nil
}

// LatestRMMSync returns the most recent read, or nil if there has been none.
func (s *Store) LatestRMMSync(ctx context.Context) (*RMMSync, error) {
	r, err := scanSync(s.pool.QueryRow(ctx, `SELECT `+syncColumns+` FROM rmm_syncs ORDER BY finished_at DESC, id DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRMMSyncs returns the most recent reads, newest first.
func (s *Store) ListRMMSyncs(ctx context.Context, limit int) ([]RMMSync, error) {
	if limit < 1 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `SELECT `+syncColumns+` FROM rmm_syncs ORDER BY finished_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RMMSync{}
	for rows.Next() {
		r, err := scanSync(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RMMSummary is the counts behind the RMM page and the Fleet card.
type RMMSummary struct {
	Settings RMMSettings `json:"settings"`
	// Devices counts live RMM device rows (not retired); Merged is how many of
	// them are also enrolled agents.
	Devices int `json:"devices"`
	Merged  int `json:"merged"`
	// Coverage: how many devices have fresh evidence matched against the feed
	// (covered), an audit older than the threshold (stale), no usable data
	// (noData), or no feed to map against (noFeed). Devices with no state yet
	// are in Unmatched.
	Covered   int `json:"covered"`
	Stale     int `json:"stale"`
	NoData    int `json:"noData"`
	NoFeed    int `json:"noFeed"`
	Unmatched int `json:"unmatched"`
	// Patches, as RMM counts them across devices, and the per-KB list.
	PatchesApprovedPending int `json:"patchesApprovedPending"`
	PatchesNotApproved     int `json:"patchesNotApproved"`
	DevicesMissingPatches  int `json:"devicesMissingPatches"`
	MissingKBs             int `json:"missingKbs"`
	MissingKBsMapped       int `json:"missingKbsMapped"`
	// Findings the missing KBs produce, open now.
	FindingsOpen     int `json:"findingsOpen"`
	FindingsKEV      int `json:"findingsKev"`
	AdvisoriesOpen   int `json:"advisoriesOpen"`
	DevicesWithFinds int `json:"devicesWithFindings"`
	// OldestAuditAt is the oldest last-audit time among live devices.
	OldestAuditAt *time.Time `json:"oldestAuditAt"`
	// FeedLoaded is whether the Microsoft feed (KB to CVE) has any data.
	FeedLoaded bool     `json:"feedLoaded"`
	LastSync   *RMMSync `json:"lastSync"`
}

// RMMSummary computes the RMM counts.
func (s *Store) RMMSummary(ctx context.Context, now time.Time) (RMMSummary, error) {
	var out RMMSummary
	var err error
	if out.Settings, err = s.GetRMMSettings(ctx); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE d.merged_into IS NOT NULL),
		       count(*) FILTER (WHERE `+effectivePatchCoverage+` = 'covered'), count(*) FILTER (WHERE `+effectivePatchCoverage+` = 'stale'),
		       count(*) FILTER (WHERE `+effectivePatchCoverage+` = 'no_data'), count(*) FILTER (WHERE `+effectivePatchCoverage+` = 'no_feed'),
		       count(*) FILTER (WHERE p.device_id IS NULL),
		       COALESCE(sum(r.patches_approved_pending), 0), COALESCE(sum(r.patches_not_approved), 0),
		       count(*) FILTER (WHERE r.patches_approved_pending + r.patches_not_approved > 0),
		       min(r.last_audit_at)
		FROM devices d JOIN rmm_devices r ON r.device_id = d.id
		LEFT JOIN host_patch_state p ON p.device_id = d.id
		WHERE d.source = 'rmm' AND NOT d.revoked`, now).
		Scan(&out.Devices, &out.Merged, &out.Covered, &out.Stale, &out.NoData, &out.NoFeed, &out.Unmatched,
			&out.PatchesApprovedPending, &out.PatchesNotApproved, &out.DevicesMissingPatches, &out.OldestAuditAt); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(DISTINCT p.kb), count(DISTINCT p.kb) FILTER (WHERE EXISTS (
		         SELECT 1 FROM advisory_ranges ar WHERE ar.distro = 'windows' AND ar.package = p.kb))
		FROM rmm_patches p JOIN devices d ON d.id = p.device_id AND d.source = 'rmm' AND NOT d.revoked
		WHERE p.kb <> ''`).Scan(&out.MissingKBs, &out.MissingKBsMapped); err != nil {
		return out, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE f.kev), count(DISTINCT f.advisory_id), count(DISTINCT f.device_id)
		FROM vuln_findings f JOIN devices d ON d.id = f.device_id AND d.source = 'rmm' AND NOT d.revoked
		WHERE f.resolved_at IS NULL AND f.kind = 'finding'`).
		Scan(&out.FindingsOpen, &out.FindingsKEV, &out.AdvisoriesOpen, &out.DevicesWithFinds); err != nil {
		return out, err
	}
	if out.FeedLoaded, err = s.DistroCovered(ctx, vuln.WindowsDistro, ""); err != nil {
		return out, err
	}
	out.LastSync, err = s.LatestRMMSync(ctx)
	return out, err
}

// RMMDeviceRow is one RMM device in a list.
type RMMDeviceRow struct {
	ID            string     `json:"id"`
	Hostname      string     `json:"hostname"`
	OSCaption     string     `json:"osCaption"`
	OSVersion     string     `json:"osVersion"`
	OSDisplay     string     `json:"osDisplay"`
	DeviceType    string     `json:"deviceType"`
	Online        bool       `json:"online"`
	LastSeen      *time.Time `json:"lastSeen"`
	LastAuditAt   *time.Time `json:"lastAuditAt"`
	PatchStatus   string     `json:"patchStatus"`
	PendingCount  int        `json:"patchesApprovedPending"`
	NotApproved   int        `json:"patchesNotApproved"`
	SoftwareCount int        `json:"softwareCount"`
	Coverage      string     `json:"coverage"` // covered, stale, no_data, no_feed, or "" before the first match
	Reason        string     `json:"reason"`
	MergedInto    string     `json:"mergedInto"`
	DedupeBasis   string     `json:"dedupeBasis"`
	FindingsOpen  int        `json:"findingsOpen"`
	KEVOpen       int        `json:"kevOpen"`
}

// ListRMMDevices lists the live RMM devices by hostname (at most limit, 1000).
func (s *Store) ListRMMDevices(ctx context.Context, now time.Time, limit int) ([]RMMDeviceRow, error) {
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, r.hostname, r.os_caption, r.os_version, r.os_display, r.device_type, r.online, r.rmm_last_seen,
		       r.last_audit_at, r.patch_status, r.patches_approved_pending, r.patches_not_approved, r.software_count,
		       COALESCE(`+effectivePatchCoverage+`, ''), COALESCE(p.reason, ''), COALESCE(d.merged_into, ''), r.dedupe_basis,
		       (SELECT count(*) FROM vuln_findings f WHERE f.device_id = d.id AND f.resolved_at IS NULL AND f.kind = 'finding'),
		       (SELECT count(*) FROM vuln_findings f WHERE f.device_id = d.id AND f.resolved_at IS NULL AND f.kind = 'finding' AND f.kev)
		FROM devices d JOIN rmm_devices r ON r.device_id = d.id
		LEFT JOIN host_patch_state p ON p.device_id = d.id
		WHERE d.source = 'rmm' AND NOT d.revoked
		ORDER BY lower(r.hostname), d.id LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RMMDeviceRow{}
	for rows.Next() {
		var x RMMDeviceRow
		if err := rows.Scan(&x.ID, &x.Hostname, &x.OSCaption, &x.OSVersion, &x.OSDisplay, &x.DeviceType, &x.Online, &x.LastSeen,
			&x.LastAuditAt, &x.PatchStatus, &x.PendingCount, &x.NotApproved, &x.SoftwareCount, &x.Coverage, &x.Reason,
			&x.MergedInto, &x.DedupeBasis, &x.FindingsOpen, &x.KEVOpen); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// RMMPatchRow is one missing patch with how many open CVEs it would close.
type RMMPatchRow struct {
	UID         string     `json:"uid"`
	KB          string     `json:"kb"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Type        string     `json:"type"`
	Status      string     `json:"status"`
	ReleaseDate *time.Time `json:"releaseDate"`
	Reboot      bool       `json:"rebootRequired"`
	// CVEs is how many open findings this KB accounts for on the device; Mapped
	// says whether the Microsoft feed knows the KB at all (a KB it does not know
	// is not a security update, or is older than the feed's window).
	CVEs   int  `json:"cves"`
	KEV    int  `json:"kev"`
	Mapped bool `json:"mapped"`
}

// RMMDeviceDetail is one RMM device in full.
type RMMDeviceDetail struct {
	RMMDeviceRow
	SiteUID        string              `json:"siteUid"`
	RMMUID         string              `json:"rmmUid"`
	Serial         string              `json:"serial"`
	OSBuild        string              `json:"osBuild"`
	OSInstallType  string              `json:"osInstallType"`
	RebootRequired bool                `json:"rebootRequired"`
	LastReboot     *time.Time          `json:"lastReboot"`
	PatchesInstall int                 `json:"patchesInstalled"`
	Antivirus      string              `json:"antivirus"`
	CollectError   string              `json:"collectError"`
	CollectedAt    time.Time           `json:"collectedAt"`
	AgentDeviceID  string              `json:"agentDeviceId"`
	EvidenceAt     *time.Time          `json:"evidenceAt"`
	KBsMissing     int                 `json:"kbsMissing"`
	KBsMapped      int                 `json:"kbsMapped"`
	Patches        []RMMPatchRow       `json:"patches"`
	Software       []presence.Software `json:"software"`
}

// ErrRMMNotFound is returned for a device that is not a live RMM device.
var ErrRMMNotFound = errors.New("rmm device not found")

// GetRMMDevice returns one RMM device with its missing patches and software.
func (s *Store) GetRMMDevice(ctx context.Context, now time.Time, id string) (RMMDeviceDetail, error) {
	var d RMMDeviceDetail
	var sw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT d.id, r.hostname, r.os_caption, r.os_version, r.os_display, r.device_type, r.online, r.rmm_last_seen,
		       r.last_audit_at, r.patch_status, r.patches_approved_pending, r.patches_not_approved, r.software_count,
		       COALESCE(`+effectivePatchCoverage+`, ''), COALESCE(p.reason, ''), COALESCE(d.merged_into, ''), r.dedupe_basis,
		       (SELECT count(*) FROM vuln_findings f WHERE f.device_id = d.id AND f.resolved_at IS NULL AND f.kind = 'finding'),
		       (SELECT count(*) FROM vuln_findings f WHERE f.device_id = d.id AND f.resolved_at IS NULL AND f.kind = 'finding' AND f.kev),
		       r.site_uid, r.rmm_uid, r.serial, r.os_build, r.os_install_type, r.reboot_required, r.last_reboot_at,
		       r.patches_installed, trim(r.antivirus_product || ' ' || r.antivirus_status), r.collect_error, r.collected_at,
		       COALESCE(r.agent_device_id, ''), p.evidence_at, COALESCE(p.kbs_missing, 0), COALESCE(p.kbs_mapped, 0), d.software
		FROM devices d JOIN rmm_devices r ON r.device_id = d.id
		LEFT JOIN host_patch_state p ON p.device_id = d.id
		WHERE d.id = $2 AND d.source = 'rmm' AND NOT d.revoked`, now, id).
		Scan(&d.ID, &d.Hostname, &d.OSCaption, &d.OSVersion, &d.OSDisplay, &d.DeviceType, &d.Online, &d.LastSeen,
			&d.LastAuditAt, &d.PatchStatus, &d.PendingCount, &d.NotApproved, &d.SoftwareCount, &d.Coverage, &d.Reason,
			&d.MergedInto, &d.DedupeBasis, &d.FindingsOpen, &d.KEVOpen,
			&d.SiteUID, &d.RMMUID, &d.Serial, &d.OSBuild, &d.OSInstallType, &d.RebootRequired, &d.LastReboot,
			&d.PatchesInstall, &d.Antivirus, &d.CollectError, &d.CollectedAt, &d.AgentDeviceID, &d.EvidenceAt,
			&d.KBsMissing, &d.KBsMapped, &sw)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrRMMNotFound
	}
	if err != nil {
		return d, err
	}
	d.Software = []presence.Software{}
	if len(sw) > 0 {
		_ = json.Unmarshal(sw, &d.Software)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.patch_uid, p.kb, p.title, p.severity, p.patch_type, p.install_status, p.release_date::timestamptz, p.reboot_required,
		       (SELECT count(*) FROM vuln_findings f WHERE f.device_id = p.device_id AND f.package = p.kb AND f.resolved_at IS NULL),
		       (SELECT count(*) FROM vuln_findings f WHERE f.device_id = p.device_id AND f.package = p.kb AND f.resolved_at IS NULL AND f.kev),
		       p.kb <> '' AND EXISTS (SELECT 1 FROM advisory_ranges ar WHERE ar.distro = 'windows' AND ar.package = p.kb)
		FROM rmm_patches p WHERE p.device_id = $1
		ORDER BY 10 DESC, 9 DESC, p.release_date DESC NULLS LAST, p.patch_uid`, id)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	d.Patches = []RMMPatchRow{}
	for rows.Next() {
		var p RMMPatchRow
		if err := rows.Scan(&p.UID, &p.KB, &p.Title, &p.Severity, &p.Type, &p.Status, &p.ReleaseDate, &p.Reboot, &p.CVEs, &p.KEV, &p.Mapped); err != nil {
			return d, err
		}
		d.Patches = append(d.Patches, p)
	}
	return d, rows.Err()
}

// RMMMissing is a missing update with a KB, as stored.
type RMMMissing struct {
	KB     string
	Title  string
	Status string // "approved_pending" or "not_approved"
}

// RMMRematch is a covered RMM device whose findings were computed against an
// older feed snapshot than the latest one.
type RMMRematch struct {
	DeviceID   string
	EvidenceAt *time.Time
	Reason     string
	Missing    []RMMMissing
}

// RMMRematchCandidates lists the covered, still fresh RMM devices whose last
// match used a feed snapshot other than latest. Re-matching them needs no RMM
// request: it uses the missing-update list stored at the last read, so a new
// KEV listing or a new KB to CVE mapping shows up without waiting for the next
// read. A device whose evidence has gone stale is left alone.
func (s *Store) RMMRematchCandidates(ctx context.Context, latestSnapshot int64, now time.Time) ([]RMMRematch, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, p.evidence_at, p.reason
		FROM devices d JOIN host_patch_state p ON p.device_id = d.id
		WHERE d.source = 'rmm' AND NOT d.revoked AND p.coverage = 'covered'
		  AND p.snapshot_id IS DISTINCT FROM $1
		  AND p.evidence_at >= $2::timestamptz - make_interval(days => COALESCE((SELECT stale_after_days FROM rmm_settings WHERE id = 1), 7))
		ORDER BY d.id`, latestSnapshot, now)
	if err != nil {
		return nil, err
	}
	var out []RMMRematch
	idx := map[string]int{}
	var ids []string
	for rows.Next() {
		var r RMMRematch
		if err := rows.Scan(&r.DeviceID, &r.EvidenceAt, &r.Reason); err != nil {
			rows.Close()
			return nil, err
		}
		idx[r.DeviceID] = len(out)
		ids = append(ids, r.DeviceID)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return out, err
	}
	prow, err := s.pool.Query(ctx, `
		SELECT device_id, kb, title, lower(install_status) FROM rmm_patches
		WHERE device_id = ANY($1) AND kb <> '' ORDER BY device_id, kb`, ids)
	if err != nil {
		return nil, err
	}
	defer prow.Close()
	for prow.Next() {
		var id string
		var m RMMMissing
		if err := prow.Scan(&id, &m.KB, &m.Title, &m.Status); err != nil {
			return nil, err
		}
		out[idx[id]].Missing = append(out[idx[id]].Missing, m)
	}
	return out, prow.Err()
}
