package storepg

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"defendsec/internal/presence"
)

// OnlineWindow matches the console's ONLINE_WINDOW_MS: a device is online if
// it has been seen within it.
const OnlineWindow = 2 * time.Minute

// MaxPageSize bounds a device listing page.
const MaxPageSize = 500

// DeviceQuery filters and pages the fleet (roadmap 5.5).
type DeviceQuery struct {
	// Q matches hostname, serial, username, OS name, or an IP address,
	// case-insensitively, as a substring.
	Q string
	// Platform is linux, windows, or empty for any.
	Platform string
	// Status is online, offline, isolated, or empty for any.
	Status string
	// Limit is the page size, 1..MaxPageSize; 0 means 50.
	Limit int
	// Cursor is the opaque value a previous page returned as Next.
	Cursor string
	// Now is the reference time for online/offline; zero means time.Now().
	Now time.Time
}

// DeviceSummary is a listing row: the fields a fleet table shows, without
// the software, FIM and patch payloads that dominate a device's size.
type DeviceSummary struct {
	ID             string    `json:"id"`
	Hostname       string    `json:"hostname"`
	Platform       string    `json:"platform"`
	OSName         string    `json:"osName"`
	OSVersion      string    `json:"osVersion"`
	Arch           string    `json:"arch"`
	AgentVersion   string    `json:"agentVersion"`
	Serial         string    `json:"serial"`
	HardwareModel  string    `json:"hardwareModel"`
	Username       string    `json:"username"`
	IPAddresses    []string  `json:"ipAddresses"`
	DiskEncryption *bool     `json:"diskEncryption"`
	Firewall       *bool     `json:"firewall"`
	Isolated       bool      `json:"isolated"`
	LastSeen       time.Time `json:"lastSeen"`
	Online         bool      `json:"online"`
	SoftwareCount  int       `json:"softwareCount"`
	PendingUpdates int       `json:"pendingUpdates"`
}

// DevicePage is one page of a listing.
type DevicePage struct {
	Devices []DeviceSummary `json:"devices"`
	// Next is the cursor for the following page; empty on the last page.
	Next string `json:"next,omitempty"`
	// Total is the number of devices matching the filter, across all pages.
	Total int `json:"total"`
}

// ErrBadCursor is returned for a cursor this code did not produce.
var ErrBadCursor = errors.New("invalid cursor")

// Cursor is a listing position.
type Cursor struct {
	Host string `json:"h"`
	ID   string `json:"i"`
}

// EncodeCursor makes the opaque cursor for a (lower(hostname), id) position.
func EncodeCursor(host, id string) string {
	raw, _ := json.Marshal(Cursor{host, id})
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeCursor reverses EncodeCursor.
func DecodeCursor(s string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Cursor{}, ErrBadCursor
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil || c.ID == "" {
		return Cursor{}, ErrBadCursor
	}
	return c, nil
}

// Normalize validates a query, returning an error an API can show.
func (q *DeviceQuery) Normalize() error {
	q.Q = strings.TrimSpace(q.Q)
	if len(q.Q) > 200 {
		return fmt.Errorf("search is longer than 200 characters")
	}
	switch q.Platform {
	case "", "linux", "windows":
	default:
		return fmt.Errorf("platform must be linux or windows")
	}
	switch q.Status {
	case "", "online", "offline", "isolated":
	default:
		return fmt.Errorf("status must be online, offline or isolated")
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit < 1 || q.Limit > MaxPageSize {
		return fmt.Errorf("limit must be between 1 and %d", MaxPageSize)
	}
	if q.Now.IsZero() {
		q.Now = time.Now()
	}
	return nil
}

// ListDevices returns one page of the fleet, filtered in the database.
func (s *Store) ListDevices(ctx context.Context, q DeviceQuery) (DevicePage, error) {
	if err := q.Normalize(); err != nil {
		return DevicePage{}, err
	}
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	where = append(where, "NOT revoked")
	if q.Q != "" {
		like := arg("%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.ToLower(q.Q)) + "%")
		where = append(where, fmt.Sprintf(`(lower(hostname) LIKE %[1]s OR lower(serial) LIKE %[1]s OR lower(username) LIKE %[1]s
			OR lower(os_name) LIKE %[1]s OR lower(ip_addresses::text) LIKE %[1]s)`, like))
	}
	if q.Platform != "" {
		where = append(where, "platform = "+arg(q.Platform))
	}
	cutoff := q.Now.Add(-OnlineWindow)
	switch q.Status {
	case "online":
		where = append(where, "last_seen >= "+arg(cutoff))
	case "offline":
		where = append(where, "last_seen < "+arg(cutoff))
	case "isolated":
		where = append(where, "isolated")
	}
	filter := strings.Join(where, " AND ")

	var page DevicePage
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM devices WHERE "+filter, args...).Scan(&page.Total); err != nil {
		return DevicePage{}, err
	}

	pageWhere := filter
	if q.Cursor != "" {
		c, err := DecodeCursor(q.Cursor)
		if err != nil {
			return DevicePage{}, err
		}
		pageWhere += fmt.Sprintf(" AND (lower(hostname), id) > (%s, %s)", arg(c.Host), arg(c.ID))
	}
	cutoffArg := arg(cutoff)
	limitArg := arg(q.Limit + 1)
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, platform, os_name, os_version, arch, agent_version, serial, hardware_model,
		       username, ip_addresses, disk_encryption, firewall, isolated, last_seen,
		       last_seen >= `+cutoffArg+`, CASE WHEN jsonb_typeof(software) = 'array' THEN jsonb_array_length(software) ELSE 0 END,
		       CASE WHEN jsonb_typeof(pending_updates) = 'array' THEN jsonb_array_length(pending_updates) ELSE 0 END
		FROM devices WHERE `+pageWhere+`
		ORDER BY lower(hostname), id
		LIMIT `+limitArg, args...)
	if err != nil {
		return DevicePage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var d DeviceSummary
		var ips []byte
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Platform, &d.OSName, &d.OSVersion, &d.Arch, &d.AgentVersion,
			&d.Serial, &d.HardwareModel, &d.Username, &ips, &d.DiskEncryption, &d.Firewall, &d.Isolated,
			&d.LastSeen, &d.Online, &d.SoftwareCount, &d.PendingUpdates); err != nil {
			return DevicePage{}, err
		}
		_ = json.Unmarshal(ips, &d.IPAddresses)
		if d.IPAddresses == nil {
			d.IPAddresses = []string{}
		}
		page.Devices = append(page.Devices, d)
	}
	if err := rows.Err(); err != nil {
		return DevicePage{}, err
	}
	if len(page.Devices) > q.Limit {
		page.Devices = page.Devices[:q.Limit]
		last := page.Devices[len(page.Devices)-1]
		page.Next = EncodeCursor(strings.ToLower(last.Hostname), last.ID)
	}
	if page.Devices == nil {
		page.Devices = []DeviceSummary{}
	}
	return page, nil
}

// FleetCounts is the fleet at a glance, computed in the database.
type FleetCounts struct {
	Total      int            `json:"total"`
	Online     int            `json:"online"`
	Isolated   int            `json:"isolated"`
	ByPlatform map[string]int `json:"byPlatform"`
	// Unencrypted and FirewallOff count devices that reported false; a
	// device that did not report is in neither.
	Unencrypted int `json:"unencrypted"`
	FirewallOff int `json:"firewallOff"`
}

// CountDevices summarises the fleet without loading it.
func (s *Store) CountDevices(ctx context.Context, now time.Time) (FleetCounts, error) {
	c := FleetCounts{ByPlatform: map[string]int{}}
	cutoff := now.Add(-OnlineWindow)
	err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE last_seen >= $1),
		       count(*) FILTER (WHERE isolated),
		       count(*) FILTER (WHERE disk_encryption = false),
		       count(*) FILTER (WHERE firewall = false)
		FROM devices WHERE NOT revoked`, cutoff).Scan(&c.Total, &c.Online, &c.Isolated, &c.Unencrypted, &c.FirewallOff)
	if err != nil {
		return c, err
	}
	rows, err := s.pool.Query(ctx, `SELECT platform, count(*) FROM devices WHERE NOT revoked GROUP BY platform`)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			return c, err
		}
		c.ByPlatform[p] = n
	}
	return c, rows.Err()
}

// TouchDevice records a heartbeat: liveness and the small identity fields a
// heartbeat carries. The full upsert rewrote every JSONB column — software,
// FIM, patches — on every heartbeat, which at fleet scale is the database
// doing the same wasted work the JSON file used to.
func (s *Store) TouchDevice(ctx context.Context, d presence.Device) (bool, error) {
	lastSeen := d.LastSeen
	if lastSeen == "" {
		lastSeen = time.Now().UTC().Format(time.RFC3339)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE devices SET
			hostname = COALESCE(NULLIF($2,''), hostname),
			platform = COALESCE(NULLIF($3,''), platform),
			os_name = COALESCE(NULLIF($4,''), os_name),
			os_version = COALESCE(NULLIF($5,''), os_version),
			arch = COALESCE(NULLIF($6,''), arch),
			uptime_seconds = CASE WHEN $7 > 0 THEN $7 ELSE uptime_seconds END,
			last_seen = $8::timestamptz,
			connected = $9,
			isolated = $10,
			agent_version = COALESCE(NULLIF($11,''), agent_version),
			updated_at = now()
		WHERE id = $1`,
		d.ID, d.Hostname, d.Platform, d.OSName, d.OSVersion, d.Arch, d.UptimeSeconds, lastSeen,
		d.Connected, d.Isolated, d.AgentVersion)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// LoadDevices reads every non-revoked device in full, to seed apid's memory
// at start when Postgres is the primary store.
func (s *Store) LoadDevices(ctx context.Context) ([]presence.Device, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, platform, os_name, os_version, arch, serial, hardware_model, cpu, memory_mb,
		       disk_encryption, firewall, ip_addresses, username, uptime_seconds, software, pending_updates,
		       COALESCE(patch_inventory,''), fim, fim_baseline, last_seen, connected, isolated,
		       cert_fingerprint, transport, agent_version, agent_public_key_pem
		FROM devices WHERE NOT revoked AND NOT sample`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []presence.Device
	for rows.Next() {
		var d presence.Device
		var ips, sw, pend, fim, base []byte
		var lastSeen time.Time
		if err := rows.Scan(&d.ID, &d.Hostname, &d.Platform, &d.OSName, &d.OSVersion, &d.Arch, &d.Serial,
			&d.HardwareModel, &d.CPU, &d.MemoryMb, &d.DiskEncryption, &d.Firewall, &ips, &d.Username,
			&d.UptimeSeconds, &sw, &pend, &d.PatchInventory, &fim, &base, &lastSeen, &d.Connected,
			&d.Isolated, &d.CertFingerprint, &d.Transport, &d.AgentVersion, &d.AgentPublicKeyPEM); err != nil {
			return nil, err
		}
		for _, pair := range []struct {
			raw []byte
			dst any
		}{{ips, &d.IPAddresses}, {sw, &d.Software}, {pend, &d.PendingUpdates}, {fim, &d.Fim}, {base, &d.FimBaseline}} {
			if err := json.Unmarshal(pair.raw, pair.dst); err != nil {
				return nil, fmt.Errorf("device %s: %w", d.ID, err)
			}
		}
		d.LastSeen = lastSeen.UTC().Format(time.RFC3339)
		out = append(out, d)
	}
	return out, rows.Err()
}
