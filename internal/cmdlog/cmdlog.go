package cmdlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Record struct {
	ID        string `json:"id"`
	DeviceID  string `json:"deviceId"`
	Hostname  string `json:"hostname"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Status    string `json:"status"`
	Accepted  bool   `json:"accepted"`
	Message   string `json:"message"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`

	// Proof of authority. The signature is retained rather than discarded
	// after transmission, so the record can be verified later without
	// trusting the server that wrote it (roadmap 1.1). The canonical bytes
	// are rebuilt from DeviceID, ID, Type, IssuedUnix, ExpiresUnix and
	// Payload, so they are not stored separately.
	Signature    string `json:"signature,omitempty"`
	SigningKeyID string `json:"signingKeyId,omitempty"`
	IssuedUnix   int64  `json:"issuedUnix,omitempty"`
	ExpiresUnix  int64  `json:"expiresUnix,omitempty"`

	// ActorIdentity is who authorised the command. Until per-user identity
	// lands (roadmap 1.0) this is the shared-token actor and cannot be
	// attributed to an individual.
	ActorIdentity string `json:"actorIdentity,omitempty"`

	// Proof of execution, signed by the endpoint with its enrolled
	// certificate key. AckVerified records whether the server could check it
	// when the acknowledgement arrived; agents predating this send none, and
	// those are unattested rather than rejected.
	AckSignature    string `json:"ackSignature,omitempty"`
	AckResultHash   string `json:"ackResultHash,omitempty"`
	AckExecutedUnix int64  `json:"ackExecutedUnix,omitempty"`
	AckVerified     bool   `json:"ackVerified,omitempty"`
}

type File struct {
	path string
	mu   sync.Mutex
}

type snapshot struct {
	UpdatedAt string   `json:"updatedAt"`
	Commands  []Record `json:"commands"`
}

func New(path string) *File {
	return &File{path: path}
}

func (f *File) Append(rec Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	doc.Commands = append(doc.Commands, rec)
	if len(doc.Commands) > 500 {
		doc.Commands = doc.Commands[len(doc.Commands)-500:]
	}
	return f.write(doc)
}

func (f *File) Update(id string, mut func(*Record)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range doc.Commands {
		if doc.Commands[i].ID == id {
			mut(&doc.Commands[i])
			doc.Commands[i].UpdatedAt = now
			return f.write(doc)
		}
	}
	return nil
}

func (f *File) Pending(deviceID string) []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return nil
	}
	var out []Record
	for _, rec := range doc.Commands {
		if rec.DeviceID == deviceID && rec.Status == "queued" {
			out = append(out, rec)
		}
	}
	return out
}

func (f *File) List(deviceID string) []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return nil
	}
	var out []Record
	for _, rec := range doc.Commands {
		if deviceID == "" || rec.DeviceID == deviceID {
			out = append(out, rec)
		}
	}
	return out
}

func (f *File) read() (snapshot, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot{Commands: []Record{}}, nil
		}
		return snapshot{}, err
	}
	var doc snapshot
	if err := json.Unmarshal(raw, &doc); err != nil {
		return snapshot{}, err
	}
	if doc.Commands == nil {
		doc.Commands = []Record{}
	}
	return doc, nil
}

func (f *File) write(doc snapshot) error {
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
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
