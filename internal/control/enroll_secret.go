package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

func (s *Server) HandleEnrollSecret(w http.ResponseWriter, r *http.Request) {
	if !s.adminWriteOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := os.ReadFile(filepath.Join(s.dataDir, "defendsec.json"))
	if err != nil {
		http.Error(w, "read store", http.StatusInternalServerError)
		return
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		http.Error(w, "parse store", http.StatusInternalServerError)
		return
	}

	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, "generate secret", http.StatusInternalServerError)
		return
	}
	next := hex.EncodeToString(buf)
	doc["enrollSecret"] = next
	updated, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		http.Error(w, "encode store", http.StatusInternalServerError)
		return
	}
	updated = append(updated, '\n')

	path := filepath.Join(s.dataDir, "defendsec.json")
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, updated, 0o640); err != nil {
		http.Error(w, "write store", http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		http.Error(w, "replace store", http.StatusInternalServerError)
		return
	}
	_ = os.WriteFile(path+".bak", updated, 0o640)

	s.secretMu.Lock()
	s.secret = next
	s.secretMu.Unlock()
	s.audit("admin", "enroll_secret_rotate", "", nil)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"enrollSecret": next})
}
