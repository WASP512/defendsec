package control

import (
	"net/http"
	"time"

	"defendsec/internal/forward"
	"defendsec/internal/presence"
)

// Forwarding to the operator's own log platform (syslog, CEF, webhook, OTLP,
// chat). What is forwarded is the alert table: file-integrity drift,
// configuration-check failures and vulnerability findings. DefendSec is not a
// log store and ships no event stream (the process telemetry that used to be
// forwarded was removed in slice 6).

// SetForwarder installs the log forwarder.
func (s *Server) SetForwarder(f *forward.Forwarder) { s.forwarder = f }

// Forwarder returns the configured forwarder, which may be nil.
func (s *Server) Forwarder() *forward.Forwarder { return s.forwarder }

// forwardAlert ships an alert: an operator whose collector is their system of
// record needs the finding there, not only in DefendSec.
//
// Never on the critical path: the forwarder queues and drops rather than
// blocking, so a stalled collector cannot slow inventory processing.
func (s *Server) forwardAlert(alert presence.Alert) {
	if s.forwarder == nil || !s.forwarder.Enabled() {
		return
	}
	body := map[string]any{
		"alertId": alert.ID, "title": alert.Title, "kind": alert.Kind,
		"sourceType": alert.SourceType, "sourceId": alert.SourceID,
	}
	for name, value := range alert.Detail {
		body[name] = value
	}
	s.forwarder.Send(forward.Record{
		Kind: "alert", At: time.Now().UTC(), Severity: alert.Severity,
		DeviceID: alert.DeviceID, Hostname: alert.Hostname,
		Summary: alert.Title + ": " + alert.Summary, Body: body,
	})
}

// HandleForwarding reports where alerts are being sent.
//
// Admin-only: destination addresses are part of the operator's infrastructure
// map, and a read-only console role does not need them.
func (s *Server) HandleForwarding(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminActor(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, s.forwarder.Status())
}
