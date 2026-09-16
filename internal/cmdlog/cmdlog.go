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

// Retention for the file-backed command log (roadmap 5.5).
//
// This was a 500-record ring buffer: the 501st command silently discarded the
// oldest, regardless of age. That is the wrong shape entirely for a record of
// privileged actions. CJIS Policy Area 4 requires that history be kept for a
// year, and DefendSec's own compliance view claims to evidence exactly that —
// so a busy fleet could push a month of signed actions out of the file in an
// afternoon while the console reported the control as satisfied.
//
// Retention is now by age. The count cap that remains is a safety valve on
// file size, not a retention policy: it is high enough that reaching it means
// something is very wrong, and crossing it is reported rather than silent.
const (
	// DefaultRetentionDays is one year, the CJIS minimum. Chosen over a
	// shorter convenience default because the deployments that most need the
	// history are the least likely to have configured it.
	DefaultRetentionDays = 365

	// maxRecords bounds the file so a runaway cannot exhaust the disk. At
	// roughly 500 bytes a record this is a few tens of megabytes.
	maxRecords = 50000
)

type File struct {
	path string
	mu   sync.Mutex

	// retentionDays is how long records are kept. Zero means the default;
	// negative means keep everything, which some deployments are required to
	// do and which must be expressible.
	retentionDays int

	// onOverflow is called when the count cap discards records, so the drop
	// is reported rather than silent. Set by the server at construction.
	onOverflow func(dropped int)
}

type snapshot struct {
	UpdatedAt string   `json:"updatedAt"`
	Commands  []Record `json:"commands"`
}

func New(path string) *File {
	return &File{path: path, retentionDays: DefaultRetentionDays}
}

// SetRetentionDays configures how long records are kept.
//
// A negative value keeps everything. Zero restores the default rather than
// meaning "keep nothing", because a configuration mistake that silently
// deletes the audit trail is the worst possible reading of an empty value.
func (f *File) SetRetentionDays(days int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if days == 0 {
		days = DefaultRetentionDays
	}
	f.retentionDays = days
}

// RetentionDays reports the configured window, for the posture report.
func (f *File) RetentionDays() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retentionDays
}

// SetOverflowHandler installs a callback for when the count cap discards
// records. Discarding privileged-action history must never be silent.
func (f *File) SetOverflowHandler(fn func(dropped int)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onOverflow = fn
}

func (f *File) Append(rec Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return err
	}
	doc.Commands = append(doc.Commands, rec)
	doc.Commands = f.applyRetention(doc.Commands)
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

// applyRetention drops records older than the window, then enforces the count
// cap. Caller holds the lock.
func (f *File) applyRetention(records []Record) []Record {
	if f.retentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -f.retentionDays)
		kept := records[:0]
		for _, r := range records {
			// A record whose timestamp cannot be parsed is kept. Discarding
			// history because a field is malformed would delete exactly the
			// records most worth looking at.
			at, err := time.Parse(time.RFC3339, r.CreatedAt)
			if err != nil || !at.Before(cutoff) {
				kept = append(kept, r)
			}
		}
		records = kept
	}

	// The count cap is a safety valve on file size, not a retention policy.
	// Reaching it means the age window is not doing its job, so it is
	// reported rather than applied quietly.
	if len(records) > maxRecords {
		dropped := len(records) - maxRecords
		records = records[dropped:]
		if f.onOverflow != nil {
			f.onOverflow(dropped)
		}
	}
	return records
}
