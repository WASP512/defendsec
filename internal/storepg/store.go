package storepg

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/internal/auditchain"
	"defendsec/internal/cmdlog"
	"defendsec/internal/evidence"
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
			patch_inventory, fim, fim_baseline, last_seen, connected, isolated, cert_fingerprint, transport, agent_public_key_pem, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			$11,$12,$13::jsonb,$14,$15,$16::jsonb,$17::jsonb,
			$18,$19::jsonb,$20::jsonb,$21::timestamptz,$22,$23,$24,$25,$26,now()
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
			agent_public_key_pem=COALESCE(NULLIF(EXCLUDED.agent_public_key_pem,''), devices.agent_public_key_pem),
			transport=EXCLUDED.transport,
			updated_at=now()
	`, d.ID, d.Hostname, d.Platform, d.OSName, d.OSVersion, d.Arch, d.Serial, d.HardwareModel, d.CPU, d.MemoryMb,
		d.DiskEncryption, d.Firewall, string(ips), d.Username, d.UptimeSeconds, string(sw), string(pend),
		d.PatchInventory, string(fim), string(base), lastSeen, d.Connected, d.Isolated, d.CertFingerprint, d.Transport,
		d.AgentPublicKeyPEM)
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

// auditChainLock serializes audit appends so the chain has one unambiguous
// order. Without it, two concurrent writers could read the same tip and both
// chain onto it.
const auditChainLock = "SELECT pg_advisory_xact_lock(hashtext('defendsec:audit-chain'))"

// Audit appends a hash-chained audit entry. Each entry commits to the one
// before it, so a later edit, deletion or reordering is detectable by
// VerifyAuditChain.
func (s *Store) Audit(ctx context.Context, actor, action, deviceID string, detail any) error {
	raw, _ := json.Marshal(detail)
	if len(raw) == 0 {
		raw = []byte("{}")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, auditChainLock); err != nil {
		return err
	}

	// Hash the canonical jsonb rendering rather than the bytes just
	// marshalled: Postgres normalizes jsonb on input, so this is what the row
	// will actually hold and what a verifier will read back.
	var detailText string
	if err := tx.QueryRow(ctx, `SELECT $1::jsonb::text`, string(raw)).Scan(&detailText); err != nil {
		return err
	}

	var prevSeq int64
	prevHash := auditchain.Genesis
	err = tx.QueryRow(ctx, `
		SELECT seq, entry_hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1
	`).Scan(&prevSeq, &prevHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	entry := auditchain.Link(prevHash, auditchain.Entry{
		Seq: prevSeq + 1,
		// timestamptz keeps microseconds, so truncate before hashing or the
		// value read back would not reproduce the hash.
		At:       time.Now().UTC().Truncate(time.Microsecond),
		Actor:    actor,
		Action:   action,
		DeviceID: deviceID,
		Detail:   detailText,
	})

	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_log (at, actor, action, device_id, detail, seq, prev_hash, entry_hash)
		VALUES ($1::timestamptz,$2,$3,$4,$5::jsonb,$6,$7,$8)
	`, entry.At, entry.Actor, entry.Action, entry.DeviceID, detailText,
		entry.Seq, entry.PrevHash, entry.EntryHash); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListAuditChain returns chained entries in sequence order, oldest first.
// Entries written before migration 006 have no sequence and are excluded:
// they were never chained and cannot be retroactively vouched for.
func (s *Store) ListAuditChain(ctx context.Context, fromSeq int64, limit int) ([]auditchain.Entry, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, `
		SELECT seq, at, actor, action, device_id, detail::text, prev_hash, entry_hash
		FROM audit_log
		WHERE seq IS NOT NULL AND seq >= $1
		ORDER BY seq
		LIMIT $2
	`, fromSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditchain.Entry
	for rows.Next() {
		var e auditchain.Entry
		var at time.Time
		if err := rows.Scan(&e.Seq, &at, &e.Actor, &e.Action, &e.DeviceID, &e.Detail, &e.PrevHash, &e.EntryHash); err != nil {
			return nil, err
		}
		e.At = at.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// auditChainPage is how many entries VerifyAuditChain pulls at a time. The
// chain is verified in full regardless; this only bounds memory.
const auditChainPage = 1000

// VerifyAuditChain walks the entire stored chain and reports the first entry
// whose contents no longer match its hash, as an *auditchain.TamperError.
//
// It pages rather than taking one bounded read. An earlier version asked
// ListAuditChain for a single default page, which silently stopped checking
// at sequence 1000 and reported everything beyond it as intact — a database
// actor only had to wait out the first thousand events to edit freely.
func (s *Store) VerifyAuditChain(ctx context.Context) error {
	prevHash := auditchain.Genesis
	var fromSeq int64 = 1
	var seen int64

	for {
		entries, err := s.ListAuditChain(ctx, fromSeq, auditChainPage)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			return nil
		}
		if seen == 0 && entries[0].Seq != 1 {
			return &auditchain.TamperError{
				Seq: entries[0].Seq, Actor: entries[0].Actor, Action: entries[0].Action, At: entries[0].At,
				Reason: "chain does not start at sequence 1",
			}
		}
		if err := auditchain.VerifyFrom(prevHash, entries); err != nil {
			return err
		}
		last := entries[len(entries)-1]
		prevHash = last.EntryHash
		fromSeq = last.Seq + 1
		seen += int64(len(entries))

		if len(entries) < auditChainPage {
			return nil
		}
	}
}

// AuditChainTip returns the sequence and hash of the newest chained entry.
func (s *Store) AuditChainTip(ctx context.Context) (int64, string, error) {
	var seq int64
	var hash string
	err := s.pool.QueryRow(ctx, `
		SELECT seq, entry_hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1
	`).Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, auditchain.Genesis, nil
	}
	return seq, hash, err
}

// AppendCheckpoint signs the current tip of the chain, so that range can later
// be validated from one signature and tail truncation becomes detectable.
// It returns false when there is nothing chained yet.
func (s *Store) AppendCheckpoint(ctx context.Context, priv ed25519.PrivateKey, keyID string) (auditchain.Checkpoint, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return auditchain.Checkpoint{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, auditChainLock); err != nil {
		return auditchain.Checkpoint{}, false, err
	}

	var seq int64
	var hash string
	err = tx.QueryRow(ctx, `
		SELECT seq, entry_hash FROM audit_log WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1
	`).Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditchain.Checkpoint{}, false, nil
	}
	if err != nil {
		return auditchain.Checkpoint{}, false, err
	}

	cp := auditchain.SignCheckpoint(priv, auditchain.Checkpoint{
		ThroughSeq:   seq,
		EntryHash:    hash,
		At:           time.Now().UTC().Truncate(time.Microsecond),
		SigningKeyID: keyID,
	})
	if _, err := tx.Exec(ctx, `
		INSERT INTO audit_checkpoints (at, through_seq, entry_hash, signing_key_id, signature)
		VALUES ($1::timestamptz,$2,$3,$4,$5)
	`, cp.At, cp.ThroughSeq, cp.EntryHash, cp.SigningKeyID, cp.Signature); err != nil {
		return auditchain.Checkpoint{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return auditchain.Checkpoint{}, false, err
	}
	return cp, true, nil
}

// LatestCheckpoint returns the most recent signed checkpoint.
func (s *Store) LatestCheckpoint(ctx context.Context) (auditchain.Checkpoint, bool, error) {
	var cp auditchain.Checkpoint
	var at time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT at, through_seq, entry_hash, signing_key_id, signature
		FROM audit_checkpoints ORDER BY through_seq DESC LIMIT 1
	`).Scan(&at, &cp.ThroughSeq, &cp.EntryHash, &cp.SigningKeyID, &cp.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return auditchain.Checkpoint{}, false, nil
	}
	if err != nil {
		return auditchain.Checkpoint{}, false, err
	}
	cp.At = at.UTC()
	return cp, true, nil
}

func (s *Store) AppendCommand(ctx context.Context, rec cmdlog.Record) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO commands (id, device_id, hostname, type, payload, status, accepted, message, created_at, updated_at,
		                      signature, signing_key_id, issued_unix, expires_unix, actor_identity)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::timestamptz,$10::timestamptz,$11,$12,$13,$14,$15)
		ON CONFLICT (id) DO NOTHING
	`, rec.ID, rec.DeviceID, rec.Hostname, rec.Type, rec.Payload, rec.Status, rec.Accepted, rec.Message, rec.CreatedAt, rec.UpdatedAt,
		rec.Signature, rec.SigningKeyID, rec.IssuedUnix, rec.ExpiresUnix, rec.ActorIdentity)
	return err
}

// RecordCommandProof stores the signature actually transmitted to the agent.
// The command path re-signs with fresh issue and expiry timestamps whenever a
// queued command is flushed after a reconnect, so the retained proof is the
// envelope most recently put on the wire.
func (s *Store) RecordCommandProof(ctx context.Context, id, signature, keyID string, issuedUnix, expiresUnix int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE commands SET signature=$2, signing_key_id=$3, issued_unix=$4, expires_unix=$5, updated_at=now()
		WHERE id=$1
	`, id, signature, keyID, issuedUnix, expiresUnix)
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
		SELECT id, device_id, hostname, type, payload, status, accepted, message, created_at, updated_at,
		       signature, signing_key_id, issued_unix, expires_unix, actor_identity,
		       ack_signature, ack_result_hash, ack_executed_unix, ack_verified
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
		if err := rows.Scan(&rec.ID, &rec.DeviceID, &rec.Hostname, &rec.Type, &rec.Payload, &rec.Status, &rec.Accepted, &rec.Message, &created, &updated,
			&rec.Signature, &rec.SigningKeyID, &rec.IssuedUnix, &rec.ExpiresUnix, &rec.ActorIdentity,
			&rec.AckSignature, &rec.AckResultHash, &rec.AckExecutedUnix, &rec.AckVerified); err != nil {
			return nil, err
		}
		rec.CreatedAt = created.UTC().Format(time.RFC3339)
		rec.UpdatedAt = updated.UTC().Format(time.RFC3339)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// listAllCommands pages through every command for a device, or the whole
// fleet when deviceID is empty. ListCommands is capped at 200 for console
// display; an evidence bundle that quietly dropped older commands would
// misrepresent what it covers, so the export path uses this instead.
func (s *Store) listAllCommands(ctx context.Context, deviceID string) ([]cmdlog.Record, error) {
	const page = 500
	var out []cmdlog.Record
	var afterCreated time.Time
	var afterID string
	first := true

	for {
		rows, err := s.pool.Query(ctx, `
			SELECT id, device_id, hostname, type, payload, status, accepted, message, created_at, updated_at,
			       signature, signing_key_id, issued_unix, expires_unix, actor_identity,
			       ack_signature, ack_result_hash, ack_executed_unix, ack_verified
			FROM commands
			WHERE ($1 = '' OR device_id = $1)
			  AND ($2::boolean OR (created_at, id) > ($3::timestamptz, $4))
			ORDER BY created_at, id
			LIMIT $5
		`, deviceID, first, afterCreated, afterID, page)
		if err != nil {
			return nil, err
		}
		n := 0
		for rows.Next() {
			var rec cmdlog.Record
			var created, updated time.Time
			if err := rows.Scan(&rec.ID, &rec.DeviceID, &rec.Hostname, &rec.Type, &rec.Payload, &rec.Status,
				&rec.Accepted, &rec.Message, &created, &updated,
				&rec.Signature, &rec.SigningKeyID, &rec.IssuedUnix, &rec.ExpiresUnix, &rec.ActorIdentity,
				&rec.AckSignature, &rec.AckResultHash, &rec.AckExecutedUnix, &rec.AckVerified); err != nil {
				rows.Close()
				return nil, err
			}
			rec.CreatedAt = created.UTC().Format(time.RFC3339)
			rec.UpdatedAt = updated.UTC().Format(time.RFC3339)
			out = append(out, rec)
			afterCreated, afterID = created, rec.ID
			n++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		first = false
		if n < page {
			return out, nil
		}
	}
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
		UpdatedAt string              `json:"updatedAt"`
		Devices   []presence.Device   `json:"devices"`
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

// ExportEvidence builds a portable proof bundle for an audit range, so the
// result can be verified by defendsec-verify without this server, this
// database, or any credential. Pass deviceID to scope the commands to one
// host, or "" for all of them.
func (s *Store) ExportEvidence(ctx context.Context, controlPubPEM, server, scope, deviceID string, fromSeq int64) (*evidence.Bundle, error) {
	// Page the whole range. A single default read stopped at 1000 entries and
	// produced a bundle that either failed its own coverage check or looked
	// complete while missing its tail — either way misrepresenting what it
	// attests.
	var entries []auditchain.Entry
	next := fromSeq
	for {
		page, err := s.ListAuditChain(ctx, next, auditChainPage)
		if err != nil {
			return nil, err
		}
		entries = append(entries, page...)
		if len(page) < auditChainPage {
			break
		}
		next = page[len(page)-1].Seq + 1
	}

	b := &evidence.Bundle{
		Manifest: evidence.Manifest{
			FormatVersion: evidence.FormatVersion,
			GeneratedAt:   time.Now().UTC().Truncate(time.Second),
			Server:        server,
			Scope:         scope,
		},
		ControlPublicKeyPEM: controlPubPEM,
		Audit:               entries,
	}

	if len(entries) > 0 {
		b.Manifest.FromSeq = entries[0].Seq
		b.Manifest.ThroughSeq = entries[len(entries)-1].Seq
		// A range that does not start at the beginning of the chain needs the
		// hash of the entry before it, or it cannot be anchored.
		if entries[0].Seq > 1 {
			var prev string
			err := s.pool.QueryRow(ctx,
				`SELECT entry_hash FROM audit_log WHERE seq = $1`, entries[0].Seq-1).Scan(&prev)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, err
			}
			b.Manifest.PrevHash = prev
		}
	}

	// Only carry checkpoints that fall inside the range shipped. A checkpoint
	// attesting past the last entry included would fail the verifier's
	// coverage check for a reason that is an artefact of export, not tampering.
	throughSeq := b.Manifest.ThroughSeq
	if len(entries) == 0 {
		throughSeq = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT at, through_seq, entry_hash, signing_key_id, signature
		FROM audit_checkpoints
		WHERE through_seq >= $1 AND through_seq <= $2
		ORDER BY through_seq
	`, fromSeq, throughSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cp auditchain.Checkpoint
		var at time.Time
		if err := rows.Scan(&at, &cp.ThroughSeq, &cp.EntryHash, &cp.SigningKeyID, &cp.Signature); err != nil {
			return nil, err
		}
		cp.At = at.UTC()
		b.Checkpoints = append(b.Checkpoints, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	cmds, err := s.listAllCommands(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	devices := map[string]bool{}
	for _, c := range cmds {
		b.Commands = append(b.Commands, evidence.CommandProof{
			ID: c.ID, DeviceID: c.DeviceID, Hostname: c.Hostname, Type: c.Type,
			Payload: c.Payload, Status: c.Status, Accepted: c.Accepted,
			ActorIdentity: c.ActorIdentity,
			Signature:     c.Signature, SigningKeyID: c.SigningKeyID,
			IssuedUnix: c.IssuedUnix, ExpiresUnix: c.ExpiresUnix,
			AckSignature: c.AckSignature, AckResultHash: c.AckResultHash,
			AckExecutedUnix: c.AckExecutedUnix,
		})
		devices[c.DeviceID] = true
	}

	// Carry the enrolled public key of every device the bundle mentions, so
	// acknowledgement signatures verify without reaching the agent or server.
	for id := range devices {
		pubPEM, err := s.AgentPublicKeyPEM(ctx, id)
		if err != nil {
			return nil, err
		}
		if pubPEM == "" {
			continue
		}
		if b.AgentPublicKeys == nil {
			b.AgentPublicKeys = map[string]string{}
		}
		b.AgentPublicKeys[id] = pubPEM
	}
	return b, nil
}

// AgentPublicKeyPEM returns the public half of a device's enrolled
// certificate key, used to verify acknowledgement signatures. It returns an
// empty string for devices enrolled before migration 007.
func (s *Store) AgentPublicKeyPEM(ctx context.Context, deviceID string) (string, error) {
	var pem string
	err := s.pool.QueryRow(ctx,
		`SELECT agent_public_key_pem FROM devices WHERE id = $1`, deviceID).Scan(&pem)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return pem, err
}

// RecordAckProof stores the endpoint's signed claim that it executed a
// command. verified records whether the signature checked out when it arrived.
func (s *Store) RecordAckProof(ctx context.Context, commandID, signature, resultHash string, executedUnix int64, verified bool) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE commands
		SET ack_signature=$2, ack_result_hash=$3, ack_executed_unix=$4, ack_verified=$5, updated_at=now()
		WHERE id=$1
	`, commandID, signature, resultHash, executedUnix, verified)
	return err
}
