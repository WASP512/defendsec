package storepg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/internal/cmdlog"
	"defendsec/internal/presence"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) UpsertDevice(ctx context.Context, d presence.Device) error {
	ips, _ := json.Marshal(d.IPAddresses)
	sw, _ := json.Marshal(d.Software)
	pend, _ := json.Marshal(d.PendingUpdates)
	fim, _ := json.Marshal(d.Fim)
	base, _ := json.Marshal(d.FimBaseline)
	lastSeen := d.LastSeen
	if lastSeen == "" {
		lastSeen = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO devices (
			id, hostname, platform, os_name, os_version, arch, serial, hardware_model, cpu, memory_mb,
			disk_encryption, firewall, ip_addresses, username, uptime_seconds, software, pending_updates,
			patch_inventory, fim, fim_baseline, last_seen, connected, isolated, cert_fingerprint, transport, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17::jsonb,
			$18,$19::jsonb,$20::jsonb,$21::timestamptz,$22,$23,$24,$25,now()
		)
		ON CONFLICT (id) DO UPDATE SET
			hostname=EXCLUDED.hostname,
			platform=EXCLUDED.platform,
			os_name=EXCLUDED.os_name,
			os_version=EXCLUDED.os_version,
			arch=EXCLUDED.arch,
			serial=COALESCE(NULLIF(EXCLUDED.serial,''), devices.serial),
			hardware_model=COALESCE(NULLIF(EXCLUDED.hardware_model,''), devices.hardware_model),
			cpu=COALESCE(NULLIF(EXCLUDED.cpu,''), devices.cpu),
			memory_mb=CASE WHEN EXCLUDED.memory_mb>0 THEN EXCLUDED.memory_mb ELSE devices.memory_mb END,
			disk_encryption=COALESCE(EXCLUDED.disk_encryption, devices.disk_encryption),
			firewall=COALESCE(EXCLUDED.firewall, devices.firewall),
			ip_addresses=CASE WHEN EXCLUDED.ip_addresses <> '[]'::jsonb THEN EXCLUDED.ip_addresses ELSE devices.ip_addresses END,
			username=COALESCE(NULLIF(EXCLUDED.username,''), devices.username),
			uptime_seconds=EXCLUDED.uptime_seconds,
			software=CASE WHEN EXCLUDED.software <> '[]'::jsonb THEN EXCLUDED.software ELSE devices.software END,
			pending_updates=CASE WHEN EXCLUDED.pending_updates <> '[]'::jsonb THEN EXCLUDED.pending_updates ELSE devices.pending_updates END,
			patch_inventory=COALESCE(NULLIF(EXCLUDED.patch_inventory,''), devices.patch_inventory),
			fim=CASE WHEN EXCLUDED.fim <> '[]'::jsonb THEN EXCLUDED.fim ELSE devices.fim END,
			fim_baseline=CASE WHEN EXCLUDED.fim_baseline <> '[]'::jsonb THEN EXCLUDED.fim_baseline ELSE devices.fim_baseline END,
			last_seen=EXCLUDED.last_seen,
			connected=EXCLUDED.connected,
			isolated=EXCLUDED.isolated,
			cert_fingerprint=COALESCE(NULLIF(EXCLUDED.cert_fingerprint,''), devices.cert_fingerprint),
			transport=EXCLUDED.transport,
			updated_at=now()
	`, d.ID, d.Hostname, d.Platform, d.OSName, d.OSVersion, d.Arch, d.Serial, d.HardwareModel, d.CPU, d.MemoryMb,
		d.DiskEncryption, d.Firewall, string(ips), d.Username, d.UptimeSeconds, string(sw), string(pend),
		d.PatchInventory, string(fim), string(base), lastSeen, d.Connected, d.Isolated, d.CertFingerprint, d.Transport)
	return err
}

func (s *Store) AppendFimEvent(ctx context.Context, ev presence.FimEvent) error {
	action := ev.Action
	if action == "" {
		action = "modified"
	}
	severity := ev.Severity
	if severity == "" {
		severity = "medium"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO fim_events (id, device_id, hostname, path, previous, current, detected_at, action, severity)
		VALUES ($1,$2,$3,$4,$5,$6,$7::timestamptz,$8,$9)
		ON CONFLICT (id) DO NOTHING
	`, ev.ID, ev.DeviceID, ev.Hostname, ev.Path, ev.Previous, ev.Current, ev.DetectedAt, action, severity)
	return err
}

func (s *Store) SetConnected(ctx context.Context, id string, connected bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE devices SET connected=$2, updated_at=now() WHERE id=$1`, id, connected)
	return err
}

func (s *Store) SetIsolated(ctx context.Context, id string, isolated bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE devices SET isolated=$2, updated_at=now() WHERE id=$1`, id, isolated)
	return err
}

func (s *Store) AcceptBaseline(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE devices SET fim_baseline=fim, updated_at=now() WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *Store) IsRevoked(ctx context.Context, fingerprint string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(1) FROM revoked_certs WHERE fingerprint=$1`, fingerprint).Scan(&n)
	return n > 0, err
}

func (s *Store) Revoke(ctx context.Context, fingerprint, deviceID, reason string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO revoked_certs (fingerprint, device_id, reason) VALUES ($1,$2,$3)
		ON CONFLICT (fingerprint) DO UPDATE SET reason=EXCLUDED.reason, revoked_at=now()
	`, fingerprint, deviceID, reason)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE devices SET revoked=true, connected=false, updated_at=now() WHERE id=$1`, deviceID)
	return err
}

func (s *Store) Audit(ctx context.Context, actor, action, deviceID string, detail any) error {
	raw, _ := json.Marshal(detail)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor, action, device_id, detail) VALUES ($1,$2,$3,$4::jsonb)
	`, actor, action, deviceID, string(raw))
	return err
}

func (s *Store) AppendCommand(ctx context.Context, rec cmdlog.Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO commands (id, device_id, hostname, type, payload, status, accepted, message, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10::timestamptz)
		ON CONFLICT (id) DO NOTHING
	`, rec.ID, rec.DeviceID, rec.Hostname, rec.Type, rec.Payload, rec.Status, rec.Accepted, rec.Message, rec.CreatedAt, rec.UpdatedAt)
	return err
}

func (s *Store) UpdateCommand(ctx context.Context, id string, status string, accepted bool, message string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE commands SET status=$2, accepted=$3, message=$4, updated_at=now() WHERE id=$1
	`, id, status, accepted, message)
	return err
}

func (s *Store) ListCommands(ctx context.Context, deviceID string) ([]cmdlog.Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, device_id, hostname, type, payload, status, accepted, message, created_at, updated_at
		FROM commands
		WHERE ($1 = '' OR device_id = $1)
		ORDER BY created_at DESC
		LIMIT 200
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cmdlog.Record
	for rows.Next() {
		var rec cmdlog.Record
		var created, updated time.Time
		if err := rows.Scan(&rec.ID, &rec.DeviceID, &rec.Hostname, &rec.Type, &rec.Payload, &rec.Status, &rec.Accepted, &rec.Message, &created, &updated); err != nil {
			return nil, err
		}
		rec.CreatedAt = created.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updated.UTC().Format(time.RFC3339)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *Store) UpsertAdvisory(ctx context.Context, id, cve, pkg, below, severity, summary, source string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO advisories (id, cve, package, below, severity, summary, source, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now())
		ON CONFLICT (id) DO UPDATE SET
			cve=EXCLUDED.cve, package=EXCLUDED.package, below=EXCLUDED.below,
			severity=EXCLUDED.severity, summary=EXCLUDED.summary, source=EXCLUDED.source, updated_at=now()
	`, id, cve, pkg, below, severity, summary, source)
	return err
}

func (s *Store) ListAdvisories(ctx context.Context) ([]map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, cve, package, below, severity, summary, source FROM advisories ORDER BY severity, package`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var id, cve, pkg, below, severity, summary, source string
		if err := rows.Scan(&id, &cve, &pkg, &below, &severity, &summary, &source); err != nil {
			return nil, err
		}
		out = append(out, map[string]string{
			"id": id, "cve": cve, "package": pkg, "below": below, "severity": severity, "summary": summary, "source": source,
		})
	}
	return out, rows.Err()
}

func (s *Store) LatestAgentRelease(ctx context.Context, channel string) (version, url, sha256, notes string, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT version, url, sha256, notes FROM agent_releases
		WHERE channel=$1 ORDER BY published_at DESC LIMIT 1
	`, channel).Scan(&version, &url, &sha256, &notes)
	return
}

func (s *Store) PublishAgentRelease(ctx context.Context, version, channel, url, sha256, notes string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_releases (version, channel, url, sha256, notes)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (version) DO UPDATE SET channel=EXCLUDED.channel, url=EXCLUDED.url, sha256=EXCLUDED.sha256, notes=EXCLUDED.notes, published_at=now()
	`, version, channel, url, sha256, notes)
	return err
}

func (s *Store) SaveLiveQueryResult(ctx context.Context, id, deviceID, queryID, status, output string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO live_query_results (id, device_id, query_id, status, output)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, output=EXCLUDED.output
	`, id, deviceID, queryID, status, output)
	return err
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, at, actor, action, device_id, detail FROM audit_log ORDER BY at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int64
		var at time.Time
		var actor, action, deviceID string
		var detail []byte
		if err := rows.Scan(&id, &at, &actor, &action, &deviceID, &detail); err != nil {
			return nil, err
		}
		var parsed any
		_ = json.Unmarshal(detail, &parsed)
		out = append(out, map[string]any{
			"id": id, "at": at.UTC().Format(time.RFC3339), "actor": actor, "action": action, "deviceId": deviceID, "detail": parsed,
		})
	}
	return out, rows.Err()
}

func (s *Store) ExportAgentsJSON(ctx context.Context) ([]byte, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, platform, os_name, os_version, arch, uptime_seconds, last_seen, connected,
		       cert_fingerprint, transport, isolated, serial, hardware_model, cpu, memory_mb,
		       disk_encryption, firewall, ip_addresses, username, software, pending_updates,
		       patch_inventory, fim, fim_baseline
		FROM devices WHERE transport = 'mtls-grpc' OR cert_fingerprint <> ''
		ORDER BY hostname
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type snap struct {
		UpdatedAt string            `json:"updatedAt"`
		Devices   []presence.Device `json:"devices"`
		FimEvents []presence.FimEvent `json:"fimEvents"`
	}
	doc := snap{UpdatedAt: time.Now().UTC().Format(time.RFC3339), Devices: []presence.Device{}}
	for rows.Next() {
		var d presence.Device
		var ips, sw, pend, fim, base []byte
		var lastSeen time.Time
		if err := rows.Scan(
			&d.ID, &d.Hostname, &d.Platform, &d.OSName, &d.OSVersion, &d.Arch, &d.UptimeSeconds, &lastSeen, &d.Connected,
			&d.CertFingerprint, &d.Transport, &d.Isolated, &d.Serial, &d.HardwareModel, &d.CPU, &d.MemoryMb,
			&d.DiskEncryption, &d.Firewall, &ips, &d.Username, &sw, &pend, &d.PatchInventory, &fim, &base,
		); err != nil {
			return nil, err
		}
		d.LastSeen = lastSeen.UTC().Format(time.RFC3339)
		_ = json.Unmarshal(ips, &d.IPAddresses)
		_ = json.Unmarshal(sw, &d.Software)
		_ = json.Unmarshal(pend, &d.PendingUpdates)
		_ = json.Unmarshal(fim, &d.Fim)
		_ = json.Unmarshal(base, &d.FimBaseline)
		doc.Devices = append(doc.Devices, d)
	}
	evRows, err := s.pool.Query(ctx, `
		SELECT id, device_id, hostname, path, previous, current, detected_at
		FROM fim_events ORDER BY detected_at DESC LIMIT 200
	`)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()
	for evRows.Next() {
		var ev presence.FimEvent
		var at time.Time
		if err := evRows.Scan(&ev.ID, &ev.DeviceID, &ev.Hostname, &ev.Path, &ev.Previous, &ev.Current, &at); err != nil {
			return nil, err
		}
		ev.DetectedAt = at.UTC().Format(time.RFC3339)
		doc.FimEvents = append(doc.FimEvents, ev)
	}
	return json.MarshalIndent(doc, "", "  ")
}
