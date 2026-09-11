package presence

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
}

type Device struct {
	ID              string      `json:"id"`
	Hostname        string      `json:"hostname"`
	AgentVersion    string      `json:"agentVersion,omitempty"`
	Platform        string      `json:"platform"`
	OSName          string      `json:"osName"`
	OSVersion       string      `json:"osVersion"`
	Arch            string      `json:"arch"`
	UptimeSeconds   int64       `json:"uptimeSeconds"`
	LastSeen        string      `json:"lastSeen"`
	Connected       bool        `json:"connected"`
	CertFingerprint string      `json:"certFingerprint"`
	Transport       string      `json:"transport"`
	Isolated        bool        `json:"isolated"`
	Serial          string      `json:"serial,omitempty"`
	HardwareModel   string      `json:"hardwareModel,omitempty"`
	CPU             string      `json:"cpu,omitempty"`
	MemoryMb        int64       `json:"memoryMb,omitempty"`
	DiskEncryption  *bool       `json:"diskEncryption"`
	Firewall        *bool       `json:"firewall"`
	IPAddresses     []string    `json:"ipAddresses,omitempty"`
	Username        string      `json:"username,omitempty"`
	Software        []Software  `json:"software,omitempty"`
	PendingUpdates  []Update    `json:"pendingUpdates,omitempty"`
	PatchInventory  string      `json:"patchInventory,omitempty"`
	Fim             []FimFile   `json:"fim,omitempty"`
	FimBaseline     []FimFile   `json:"fimBaseline,omitempty"`
	ScaResults      []ScaResult `json:"scaResults,omitempty"`
}

type File struct {
	path string
	mu   sync.Mutex
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
	found := false
	for i, existing := range doc.Devices {
		if existing.ID == dev.ID {
			doc.Devices[i] = mergeHeartbeat(existing, dev)
			found = true
			break
		}
	}
	if !found {
		doc.Devices = append(doc.Devices, dev)
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
	idx := -1
	var old Device
	for i, existing := range doc.Devices {
		if existing.ID == dev.ID {
			idx = i
			old = existing
			break
		}
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
	for _, existing := range doc.Devices {
		if existing.ID == id {
			return existing, true
		}
	}
	return Device{}, false
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
	doc.Alerts = append([]Alert{alert}, doc.Alerts...)
	if len(doc.Alerts) > 5000 {
		doc.Alerts = doc.Alerts[:5000]
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
	for _, a := range doc.Alerts {
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
	return doc, nil
}

func (f *File) write(doc snapshot) error {
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
