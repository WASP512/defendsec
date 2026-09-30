package presence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FimPathSeverity returns the default severity for a watched integrity path.
func FimPathSeverity(path string) string {
	base := strings.ToLower(filepath.Base(path))
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "sshd_config"), strings.Contains(lower, "sudoers"),
		base == "shadow", strings.Contains(lower, "/shadow"):
		return "high"
	case base == "passwd", base == "group", strings.Contains(lower, "/hosts"),
		strings.Contains(lower, "ssh_config"), strings.Contains(lower, "crypto-policies"):
		return "medium"
	default:
		return "medium"
	}
}

type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Update struct {
	Name      string `json:"name"`
	Current   string `json:"current"`
	Available string `json:"available"`
}

type FimFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mtime  string `json:"mtime"`
}

type FimEvent struct {
	ID         string `json:"id"`
	DeviceID   string `json:"deviceId"`
	Hostname   string `json:"hostname"`
	Path       string `json:"path"`
	Previous   string `json:"previous"`
	Current    string `json:"current"`
	DetectedAt string `json:"detectedAt"`
	Action     string `json:"action,omitempty"`
	Severity   string `json:"severity,omitempty"`
}

type ScaResult struct {
	PackID   string `json:"packId"`
	CheckID  string `json:"checkId"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Pass     bool   `json:"pass"`
	Detail   string `json:"detail"`
	// Controls are the framework controls the check names. Carried with the
	// result so the alert raised from it is tagged with them rather than
	// only with the generic SCA signal.
	Controls []string `json:"controls,omitempty"`
}

type Alert struct {
	ID               string         `json:"id"`
	CreatedAt        string         `json:"createdAt"`
	UpdatedAt        string         `json:"updatedAt"`
	DetectedAt       string         `json:"detectedAt,omitempty"`
	IngestedAt       string         `json:"ingestedAt,omitempty"`
	DeviceID         string         `json:"deviceId"`
	Hostname         string         `json:"hostname"`
	Kind             string         `json:"kind"`
	Severity         string         `json:"severity"`
	Title            string         `json:"title"`
	Summary          string         `json:"summary"`
	Status           string         `json:"status"`
	SourceType       string         `json:"sourceType"`
	SourceID         string         `json:"sourceId"`
	GeneratorID      string         `json:"generatorId,omitempty"`
	GeneratorVersion string         `json:"generatorVersion,omitempty"`
	Detail           map[string]any `json:"detail,omitempty"`
	// Signal names what was observed, and ControlIDs are the framework
	// controls it resolved to when the alert was raised (roadmap 1.7).
	Signal     string   `json:"signal,omitempty"`
	ControlIDs []string `json:"controlIds,omitempty"`
}

type Device struct {
	ID              string `json:"id"`
	Hostname        string `json:"hostname"`
	AgentVersion    string `json:"agentVersion,omitempty"`
	Platform        string `json:"platform"`
	OSName          string `json:"osName"`
	OSVersion       string `json:"osVersion"`
	Arch            string `json:"arch"`
	UptimeSeconds   int64  `json:"uptimeSeconds"`
	LastSeen        string `json:"lastSeen"`
	Connected       bool   `json:"connected"`
	CertFingerprint string `json:"certFingerprint"`
	// AgentPublicKeyPEM is the public half of the enrolled certificate key,
	// kept so acknowledgement signatures can be verified later without the
	// agent being connected (roadmap 1.3).
	AgentPublicKeyPEM string      `json:"agentPublicKeyPem,omitempty"`
	Transport         string      `json:"transport"`
	Isolated          bool        `json:"isolated"`
	Serial            string      `json:"serial,omitempty"`
	HardwareModel     string      `json:"hardwareModel,omitempty"`
	CPU               string      `json:"cpu,omitempty"`
	MemoryMb          int64       `json:"memoryMb,omitempty"`
	DiskEncryption    *bool       `json:"diskEncryption"`
	Firewall          *bool       `json:"firewall"`
	IPAddresses       []string    `json:"ipAddresses,omitempty"`
	Username          string      `json:"username,omitempty"`
	Software          []Software  `json:"software,omitempty"`
	PendingUpdates    []Update    `json:"pendingUpdates,omitempty"`
	PatchInventory    string      `json:"patchInventory,omitempty"`
	Fim               []FimFile   `json:"fim,omitempty"`
	FimBaseline       []FimFile   `json:"fimBaseline,omitempty"`
	ScaResults        []ScaResult `json:"scaResults,omitempty"`
}

// File is the device, FIM-event and alert state apid holds for mTLS agents.
//
// # Memory first, disk as export (roadmap 5.5)
//
// The state is read from disk once and then held in memory. Before this,
// every heartbeat read, parsed and rewrote the whole file: at 10,000 hosts
// heartbeating every 20 seconds that is 500 full rewrites of a file tens of
// megabytes long per second, and the fleet size was bounded by how fast one
// JSON document could be serialised.
//
// Without Postgres, writes are still synchronous — the file is the only
// durable copy, and a crash must not lose an acknowledged change. With
// Postgres, the database is the durable copy (every change is written there
// by the control server), the file is seeded from it at start, and the JSON
// becomes an export written at most every ExportEvery.
// maxFileAlerts bounds the alerts held in the file. With Postgres
// configured, alerts are also written there without this cap.
const maxFileAlerts = 5000

type File struct {
	path string
	mu   sync.Mutex

	cache       *snapshot
	exportEvery time.Duration
	dirty       bool
	flushMu     sync.Mutex // one export at a time
	// index maps a device id to its position in the cached slice. It is a
	// hint, verified on use and rebuilt when stale, so no mutation can make
	// it return the wrong device.
	index map[string]int
}

// deviceIndex finds a device's position, or -1. Caller holds f.mu.
func (f *File) deviceIndex(devs []Device, id string) int {
	if i, ok := f.index[id]; ok && i < len(devs) && devs[i].ID == id {
		return i
	}
	f.index = make(map[string]int, len(devs))
	for i, d := range devs {
		f.index[d.ID] = i
	}
	if i, ok := f.index[id]; ok {
		return i
	}
	return -1
}

type snapshot struct {
	UpdatedAt string     `json:"updatedAt"`
	Devices   []Device   `json:"devices"`
	FimEvents []FimEvent `json:"fimEvents"`
	Alerts    []Alert    `json:"alerts"`
}

func New(path string) *File {
	return &File{path: path}
}

func (f *File) Upsert(dev Device) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	if i := f.deviceIndex(doc.Devices, dev.ID); i >= 0 {
		doc.Devices[i] = mergeHeartbeat(doc.Devices[i], dev)
	} else {
		doc.Devices = append(doc.Devices, dev)
		if f.index != nil {
			f.index[dev.ID] = len(doc.Devices) - 1
		}
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return f.write(doc)
}

func mergeHeartbeat(old, neu Device) Device {
	out := old
	if neu.Hostname != "" {
		out.Hostname = neu.Hostname
	}
	if neu.AgentVersion != "" {
		out.AgentVersion = neu.AgentVersion
	}
	if neu.Platform != "" {
		out.Platform = neu.Platform
	}
	if neu.OSName != "" {
		out.OSName = neu.OSName
	}
	if neu.OSVersion != "" {
		out.OSVersion = neu.OSVersion
	}
	if neu.Arch != "" {
		out.Arch = neu.Arch
	}
	out.UptimeSeconds = neu.UptimeSeconds
	if neu.UptimeSeconds == 0 && old.UptimeSeconds != 0 {
		out.UptimeSeconds = old.UptimeSeconds
	}
	out.LastSeen = neu.LastSeen
	out.Connected = neu.Connected
	out.Isolated = neu.Isolated
	if neu.AgentPublicKeyPEM != "" {
		out.AgentPublicKeyPEM = neu.AgentPublicKeyPEM
	}
	if neu.CertFingerprint != "" {
		out.CertFingerprint = neu.CertFingerprint
	}
	if neu.Transport != "" {
		out.Transport = neu.Transport
	}
	return out
}

func (f *File) ApplyInventory(dev Device) ([]FimEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return nil, err
	}
	idx := f.deviceIndex(doc.Devices, dev.ID)
	var old Device
	if idx >= 0 {
		old = doc.Devices[idx]
	}
	merged := mergeHeartbeat(old, dev)
	merged.ID = dev.ID
	merged.Serial = dev.Serial
	merged.HardwareModel = dev.HardwareModel
	merged.CPU = dev.CPU
	merged.MemoryMb = dev.MemoryMb
	merged.DiskEncryption = dev.DiskEncryption
	merged.Firewall = dev.Firewall
	merged.IPAddresses = dev.IPAddresses
	merged.Username = dev.Username
	merged.Software = dev.Software
	merged.PendingUpdates = dev.PendingUpdates
	merged.PatchInventory = dev.PatchInventory
	if len(dev.ScaResults) > 0 {
		merged.ScaResults = dev.ScaResults
	} else {
		merged.ScaResults = old.ScaResults
	}
	if len(old.FimBaseline) == 0 && len(dev.Fim) > 0 {
		merged.FimBaseline = copyFim(dev.Fim)
	} else {
		merged.FimBaseline = old.FimBaseline
	}
	prev := map[string]string{}
	for _, file := range old.Fim {
		prev[file.Path] = file.SHA256
	}
	curr := map[string]string{}
	for _, file := range dev.Fim {
		curr[file.Path] = file.SHA256
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var created []FimEvent
	appendEvent := func(path, previous, current, action string) {
		ev := FimEvent{
			ID:         newID(),
			DeviceID:   dev.ID,
			Hostname:   merged.Hostname,
			Path:       path,
			Previous:   previous,
			Current:    current,
			DetectedAt: now,
			Action:     action,
			Severity:   FimPathSeverity(path),
		}
		created = append(created, ev)
		doc.FimEvents = append([]FimEvent{ev}, doc.FimEvents...)
	}
	for path, hash := range curr {
		if last, ok := prev[path]; ok {
			if last != hash {
				appendEvent(path, last, hash, "modified")
			}
		} else if len(prev) > 0 {
			appendEvent(path, "", hash, "created")
		}
	}
	for path, last := range prev {
		if _, ok := curr[path]; !ok {
			appendEvent(path, last, "", "deleted")
		}
	}
	if len(doc.FimEvents) > 200 {
		doc.FimEvents = doc.FimEvents[:200]
	}
	merged.Fim = dev.Fim
	if idx >= 0 {
		doc.Devices[idx] = merged
	} else {
		doc.Devices = append(doc.Devices, merged)
	}
	doc.UpdatedAt = now
	if err := f.write(doc); err != nil {
		return nil, err
	}
	return created, nil
}

func (f *File) AcceptBaseline(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return false
	}
	for i, existing := range doc.Devices {
		if existing.ID == id {
			doc.Devices[i].FimBaseline = copyFim(existing.Fim)
			doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			_ = f.write(doc)
			return true
		}
	}
	return false
}

func (f *File) Get(id string) (Device, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return Device{}, false
	}
	if i := f.deviceIndex(doc.Devices, id); i >= 0 {
		return doc.Devices[i], true
	}
	return Device{}, false
}

// List returns every known device.
//
// Added for the MCP read surface (roadmap 4.1): an agent asking "what is in
// this fleet" needs the list, and having it go through the same store the
// console uses means there is one answer to that question rather than two.
func (f *File) List() []Device {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return nil
	}
	out := make([]Device, len(doc.Devices))
	copy(out, doc.Devices)
	return out
}

func (f *File) SetConnected(id string, connected bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	for i, existing := range doc.Devices {
		if existing.ID == id {
			doc.Devices[i].Connected = connected
			break
		}
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return f.write(doc)
}

func (f *File) SetAgentVersion(id, hostname, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	for i, existing := range doc.Devices {
		if existing.ID == id {
			doc.Devices[i].AgentVersion = version
			if hostname != "" {
				doc.Devices[i].Hostname = hostname
			}
			doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			return f.write(doc)
		}
	}
	doc.Devices = append(doc.Devices, Device{
		ID:           id,
		Hostname:     hostname,
		AgentVersion: version,
		LastSeen:     time.Now().UTC().Format(time.RFC3339),
		Connected:    true,
		Transport:    "mtls-grpc",
	})
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return f.write(doc)
}

func (f *File) InsertAlert(alert Alert) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	for _, existing := range doc.Alerts {
		if existing.ID == alert.ID {
			return nil
		}
	}
	if alert.CreatedAt == "" {
		alert.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if alert.UpdatedAt == "" {
		alert.UpdatedAt = alert.CreatedAt
	}
	if alert.Status == "" {
		alert.Status = "open"
	}
	// Appended, oldest first. Prepending copied every alert on every insert,
	// and at fleet scale that copying was most of apid's CPU (measured by
	// the 5.5 load test).
	doc.Alerts = append(doc.Alerts, alert)
	// Trimmed in batches, so reaching the cap does not reintroduce a full
	// copy on every insert.
	if n := len(doc.Alerts); n > maxFileAlerts+maxFileAlerts/10 {
		doc.Alerts = append([]Alert(nil), doc.Alerts[n-maxFileAlerts:]...)
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return f.write(doc)
}

func (f *File) ListAlerts(status, kind, deviceID string, limit int) []Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return nil
	}
	if limit <= 0 {
		limit = 200
	}
	var out []Alert
	for i := len(doc.Alerts) - 1; i >= 0; i-- { // newest first
		a := doc.Alerts[i]
		if status != "" && a.Status != status {
			continue
		}
		if kind != "" && a.Kind != kind {
			continue
		}
		if deviceID != "" && a.DeviceID != deviceID {
			continue
		}
		out = append(out, a)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (f *File) UpdateAlertStatus(id, status string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return false
	}
	for i, a := range doc.Alerts {
		if a.ID == id {
			doc.Alerts[i].Status = status
			doc.Alerts[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			doc.UpdatedAt = doc.Alerts[i].UpdatedAt
			_ = f.write(doc)
			return true
		}
	}
	return false
}

func (f *File) HasOpenAlert(deviceID, kind, sourceID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return false
	}
	for _, a := range doc.Alerts {
		if a.DeviceID == deviceID && a.Kind == kind && a.SourceID == sourceID &&
			(a.Status == "open" || a.Status == "acknowledged") {
			return true
		}
	}
	return false
}

func (f *File) ResolveOpenAlerts(deviceID, kind, sourceID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return false
	}
	changed := false
	now := time.Now().UTC().Format(time.RFC3339)
	for i, a := range doc.Alerts {
		if a.DeviceID == deviceID && a.Kind == kind && a.SourceID == sourceID &&
			(a.Status == "open" || a.Status == "acknowledged") {
			doc.Alerts[i].Status = "resolved"
			doc.Alerts[i].UpdatedAt = now
			changed = true
		}
	}
	if changed {
		doc.UpdatedAt = now
		_ = f.write(doc)
	}
	return changed
}

func (f *File) SetIsolated(id string, isolated bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	for i, existing := range doc.Devices {
		if existing.ID == id {
			doc.Devices[i].Isolated = isolated
			break
		}
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return f.write(doc)
}

func copyFim(in []FimFile) []FimFile {
	out := make([]FimFile, len(in))
	copy(out, in)
	return out
}

func newID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (f *File) read() (snapshot, error) {
	if f.cache != nil {
		return *f.cache, nil
	}
	doc, err := f.readDisk()
	if err != nil {
		return doc, err
	}
	f.cache = &doc
	return doc, nil
}

func (f *File) readDisk() (snapshot, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot{Devices: []Device{}, FimEvents: []FimEvent{}, Alerts: []Alert{}}, nil
		}
		return snapshot{}, err
	}
	var doc snapshot
	if err := json.Unmarshal(raw, &doc); err != nil {
		return snapshot{}, err
	}
	if doc.Devices == nil {
		doc.Devices = []Device{}
	}
	if doc.FimEvents == nil {
		doc.FimEvents = []FimEvent{}
	}
	if doc.Alerts == nil {
		doc.Alerts = []Alert{}
	}
	// Files written before alerts were stored oldest-first hold them newest
	// first. Stable, so equal timestamps keep their relative order.
	sort.SliceStable(doc.Alerts, func(i, j int) bool { return doc.Alerts[i].CreatedAt < doc.Alerts[j].CreatedAt })
	return doc, nil
}

func (f *File) write(doc snapshot) error {
	f.cache = &doc
	if f.exportEvery > 0 {
		f.dirty = true
		return nil
	}
	return f.writeDisk(doc)
}

// ExportEvery switches the file to export mode: changes are held in memory
// and written at most once per interval, and once more when ctx ends. Only
// for use when another store (Postgres) is the durable copy.
func (f *File) ExportEvery(ctx context.Context, every time.Duration, onErr func(error)) {
	f.mu.Lock()
	f.exportEvery = every
	f.mu.Unlock()
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				if err := f.Flush(); err != nil && onErr != nil {
					onErr(err)
				}
				return
			case <-t.C:
				if err := f.Flush(); err != nil && onErr != nil {
					onErr(err)
				}
			}
		}
	}()
}

// Flush writes pending changes to disk.
//
// The snapshot is copied under the lock and serialised outside it: at 10,000
// devices the JSON is tens of megabytes, and marshalling it while holding
// the lock stalled every heartbeat for the duration. The copy is of the
// top-level slices; their elements are replaced, never mutated through a
// shared inner slice, so the copy is a consistent view.
func (f *File) Flush() error {
	f.flushMu.Lock()
	defer f.flushMu.Unlock()
	f.mu.Lock()
	if !f.dirty || f.cache == nil {
		f.mu.Unlock()
		return nil
	}
	doc := *f.cache
	doc.Devices = append([]Device(nil), doc.Devices...)
	doc.FimEvents = append([]FimEvent(nil), doc.FimEvents...)
	doc.Alerts = append([]Alert(nil), doc.Alerts...)
	f.dirty = false
	f.mu.Unlock()
	if err := f.writeDisk(doc); err != nil {
		f.mu.Lock()
		f.dirty = true
		f.mu.Unlock()
		return err
	}
	return nil
}

// Seed replaces the device list with devices from the durable store, keeping
// FIM events and alerts from the file. Devices the file has and the store
// does not are kept, so a Postgres that lost rows does not also erase the
// export's copy of them.
func (f *File) Seed(devices []Device) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(devices))
	merged := make([]Device, 0, len(devices)+len(doc.Devices))
	for _, d := range devices {
		seen[d.ID] = true
		merged = append(merged, d)
	}
	for _, d := range doc.Devices {
		if !seen[d.ID] {
			merged = append(merged, d)
		}
	}
	doc.Devices = merged
	return f.write(doc)
}

func (f *File) writeDisk(doc snapshot) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// PackageChange is one observed version transition (roadmap 4.3).
type PackageChange struct {
	Package         string `json:"package"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	NewVersion      string `json:"newVersion,omitempty"`
}

// Upgrade reports whether this was a version change rather than an install or
// a removal. Triage cares about the distinction: only an upgrade explains a
// configuration file being rewritten in place.
func (c PackageChange) Upgrade() bool {
	return c.PreviousVersion != "" && c.NewVersion != "" && c.PreviousVersion != c.NewVersion
}

// DiffSoftware reports what changed between two software inventories.
//
// Pure, so the correlation built on it can be tested without a database or a
// host. An empty previous inventory returns nothing rather than reporting
// every installed package as newly appeared: the first heartbeat from a host
// is not a thousand installs, and treating it as one would bury the real
// changes that follow under noise on day one.
func DiffSoftware(previous, current []Software) []PackageChange {
	if len(previous) == 0 {
		return nil
	}
	was := make(map[string]string, len(previous))
	for _, s := range previous {
		was[s.Name] = s.Version
	}
	now := make(map[string]string, len(current))
	for _, s := range current {
		now[s.Name] = s.Version
	}

	var out []PackageChange
	for name, version := range now {
		old, existed := was[name]
		switch {
		case !existed:
			out = append(out, PackageChange{Package: name, NewVersion: version})
		case old != version:
			out = append(out, PackageChange{
				Package: name, PreviousVersion: old, NewVersion: version,
			})
		}
	}
	for name, version := range was {
		if _, still := now[name]; !still {
			out = append(out, PackageChange{Package: name, PreviousVersion: version})
		}
	}
	// Sorted so a caller writing these to a store, or a test asserting on
	// them, sees a stable order rather than Go's map iteration.
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out
}
