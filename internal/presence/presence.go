package presence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Device struct {
	ID               string `json:"id"`
	Hostname         string `json:"hostname"`
	Platform         string `json:"platform"`
	OSName           string `json:"osName"`
	OSVersion        string `json:"osVersion"`
	Arch             string `json:"arch"`
	UptimeSeconds    int64  `json:"uptimeSeconds"`
	LastSeen         string `json:"lastSeen"`
	Connected        bool   `json:"connected"`
	CertFingerprint  string `json:"certFingerprint"`
	Transport        string `json:"transport"`
}

type File struct {
	path string
	mu   sync.Mutex
}

type snapshot struct {
	UpdatedAt string   `json:"updatedAt"`
	Devices   []Device `json:"devices"`
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
			doc.Devices[i] = dev
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
			if !connected {
				break
			}
		}
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return f.write(doc)
}

func (f *File) read() (snapshot, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot{Devices: []Device{}}, nil
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
