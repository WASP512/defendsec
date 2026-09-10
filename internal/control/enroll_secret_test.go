package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRotateEnrollSecretUpdatesRuntimeAndStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "defendsec.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":2,"enrollSecret":"old","devices":[]}`), 0o640); err != nil {
		t.Fatal(err)
	}
	s := &Server{secret: "old", adminToken: "admin", dataDir: dir}
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll-secret", nil)
	req.Header.Set("Authorization", "Bearer admin")
	rec := httptest.NewRecorder()

	s.HandleEnrollSecret(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		EnrollSecret string `json:"enrollSecret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.EnrollSecret == "" || response.EnrollSecret == "old" {
		t.Fatalf("secret was not rotated: %q", response.EnrollSecret)
	}
	if !secretMatch(response.EnrollSecret, s.secret) {
		t.Fatal("runtime secret was not updated")
	}

	var doc struct {
		EnrollSecret string `json:"enrollSecret"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.EnrollSecret != response.EnrollSecret {
		t.Fatalf("store secret=%q response secret=%q", doc.EnrollSecret, response.EnrollSecret)
	}
}

func TestRotateEnrollSecretRejectsViewer(t *testing.T) {
	s := &Server{secret: "old", adminToken: "admin", viewerToken: "viewer", dataDir: t.TempDir()}
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll-secret", nil)
	req.Header.Set("Authorization", "Bearer viewer")
	rec := httptest.NewRecorder()

	s.HandleEnrollSecret(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
