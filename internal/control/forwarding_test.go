package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/forward"
	"defendsec/internal/presence"
)

type recordingDest struct {
	mu  sync.Mutex
	got []forward.Record
}

func (r *recordingDest) Name() string { return "recording" }
func (r *recordingDest) Send(_ context.Context, records []forward.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, records...)
	return nil
}
func (r *recordingDest) Close() error { return nil }
func (r *recordingDest) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.got {
		out = append(out, rec.Kind)
	}
	return out
}

// An alert has to reach the operator's platform too: for many operators the
// collector is the system of record. What is forwarded is alerts, and only
// alerts: there is no event stream any more.
func TestAlertsAreForwarded(t *testing.T) {
	s := testServer()
	s.store = presence.New(filepath.Join(t.TempDir(), "defendsec.json"))
	dest := &recordingDest{}
	f := forward.New(0, dest)
	defer f.Close()
	s.SetForwarder(f)

	s.recordAlert(presence.Alert{
		ID: "a1", DeviceID: "dev-1", Hostname: "host-1", Kind: "fim", Severity: "high",
		Title: "Baseline drift (modified): /etc/ssh/sshd_config", Summary: "abc → def",
		SourceType: "fim_drift", SourceID: "drift:/etc/ssh/sshd_config",
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if kinds := dest.kinds(); len(kinds) > 0 {
			for _, k := range kinds {
				if k != "alert" {
					t.Fatalf("forwarded a %q record, want only alerts: %v", k, kinds)
				}
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no alert was forwarded: %v", dest.kinds())
}

func TestForwardingEndpointStatesPositioning(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/forwarding", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleForwarding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not a log store") {
		t.Errorf("body = %s", rec.Body.String())
	}

	// Destination addresses are part of the operator's infrastructure map.
	viewer := httptest.NewRequest(http.MethodGet, "/v1/forwarding", nil)
	viewer.Header.Set("Authorization", "Bearer viewer-token")
	rec = httptest.NewRecorder()
	s.HandleForwarding(rec, viewer)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a viewer read the forwarding destinations: %d", rec.Code)
	}
}
