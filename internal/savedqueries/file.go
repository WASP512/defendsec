package savedqueries

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Record struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Query     string `json:"query"`
	CreatedAt string `json:"createdAt"`
}

type File struct {
	path string
	mu   sync.Mutex
}

type snapshot struct {
	UpdatedAt string   `json:"updatedAt"`
	Queries   []Record `json:"queries"`
}

func NewFile(path string) *File {
	return &File{path: path}
}

func (f *File) List() ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return nil, err
	}
	out := make([]Record, len(doc.Queries))
	copy(out, doc.Queries)
	return out, nil
}

func (f *File) Append(name, query string) (Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.read()
	if err != nil {
		return Record{}, err
	}
	rec := Record{
		ID:        newID(),
		Name:      name,
		Query:     query,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	doc.Queries = append(doc.Queries, rec)
	if len(doc.Queries) > 200 {
		doc.Queries = doc.Queries[len(doc.Queries)-200:]
	}
	return rec, f.write(doc)
}

func (f *File) read() (snapshot, error) {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot{Queries: []Record{}}, nil
		}
		return snapshot{}, err
	}
	var doc snapshot
	if err := json.Unmarshal(raw, &doc); err != nil {
		return snapshot{}, err
	}
	if doc.Queries == nil {
		doc.Queries = []Record{}
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

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
