package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/presence"
	"defendsec/internal/sca"
	"defendsec/internal/storepg"
)

func (s *Server) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listAlerts(w, r)
	case http.MethodPost:
		if strings.HasSuffix(r.URL.Path, "/status") || r.URL.Query().Get("action") == "status" {
			if !s.adminWriteOK(r) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			s.updateAlertStatus(w, r)
			return
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	kind := r.URL.Query().Get("kind")
	deviceID := r.URL.Query().Get("deviceId")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	var rows []map[string]any
	if s.pg != nil {
		alerts, err := s.pg.ListAlerts(r.Context(), storepg.AlertFilters{
			Status: status, Kind: kind, DeviceID: deviceID, Limit: limit,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, a := range alerts {
			rows = append(rows, alertToMap(a))
		}
	} else {
		for _, a := range s.store.ListAlerts(status, kind, deviceID, limit) {
			rows = append(rows, alertToMap(storepg.Alert{
				ID: a.ID, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
				DeviceID: a.DeviceID, Hostname: a.Hostname, Kind: a.Kind,
				Severity: a.Severity, Title: a.Title, Summary: a.Summary,
				Status: a.Status, SourceType: a.SourceType, SourceID: a.SourceID,
				Detail: mustJSON(a.Detail),
			}))
		}
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"alerts": rows})
}

func (s *Server) updateAlertStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Status = strings.TrimSpace(req.Status)
	switch req.Status {
	case "open", "acknowledged", "resolved", "suppressed":
	default:
		http.Error(w, "invalid status", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	var ok bool
	if s.pg != nil {
		ok, err = s.pg.UpdateAlertStatus(r.Context(), req.ID, req.Status)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		ok = s.store.UpdateAlertStatus(req.ID, req.Status)
	}
	if !ok {
		http.Error(w, "alert not found", http.StatusNotFound)
		return
	}
	s.audit("admin", "alert_status", "", map[string]any{"id": req.ID, "status": req.Status})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (s *Server) recordAlert(alert presence.Alert) {
	if alert.Status == "" {
		alert.Status = "open"
	}
	if alert.CreatedAt == "" {
		alert.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if alert.UpdatedAt == "" {
		alert.UpdatedAt = alert.CreatedAt
	}
	if err := s.store.InsertAlert(alert); err != nil {
		s.log.Warn("alert file", "err", err)
	}
	if s.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.pg.InsertAlert(ctx, storeAlert(alert)); err != nil {
			s.log.Warn("alert postgres", "err", err)
		}
	}
}

func (s *Server) ensureAlert(deviceID, kind, sourceID string, build func() presence.Alert) {
	if s.store.HasOpenAlert(deviceID, kind, sourceID) {
		return
	}
	if s.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		open, err := s.pg.HasOpenAlert(ctx, deviceID, kind, sourceID)
		cancel()
		if err == nil && open {
			return
		}
	}
	s.recordAlert(build())
}

func (s *Server) alertFromFimEvent(ev presence.FimEvent) presence.Alert {
	severity := ev.Severity
	if severity == "" {
		severity = fimPathSeverity(ev.Path)
	}
	return presence.Alert{
		ID:         ev.ID,
		DeviceID:   ev.DeviceID,
		Hostname:   ev.Hostname,
		Kind:       "fim",
		Severity:   severity,
		Title:      "File integrity change: " + ev.Path,
		Summary:    shortHash(ev.Previous) + " → " + shortHash(ev.Current),
		SourceType: "fim_event",
		SourceID:   ev.ID,
		Detail: map[string]any{
			"path": ev.Path, "previous": ev.Previous, "current": ev.Current, "action": ev.Action,
		},
	}
}

func (s *Server) alertFromDrift(dev presence.Device, path string) presence.Alert {
	id, _ := newDeviceID()
	return presence.Alert{
		ID:         id,
		DeviceID:   dev.ID,
		Hostname:   dev.Hostname,
		Kind:       "fim",
		Severity:   fimPathSeverity(path),
		Title:      "Baseline drift: " + path,
		Summary:    "Current hash differs from accepted baseline",
		SourceType: "fim_drift",
		SourceID:   "drift:" + path,
		Detail:     map[string]any{"path": path},
	}
}

func (s *Server) alertFromSca(dev presence.Device, r sca.Result) presence.Alert {
	id, _ := newDeviceID()
	return presence.Alert{
		ID:         id,
		DeviceID:   dev.ID,
		Hostname:   dev.Hostname,
		Kind:       "sca",
		Severity:   r.Severity,
		Title:      r.Title,
		Summary:    r.Detail,
		SourceType: "sca_check",
		SourceID:   r.PackID + "/" + r.CheckID,
		Detail: map[string]any{
			"packId": r.PackID, "checkId": r.CheckID, "detail": r.Detail,
		},
	}
}

func (s *Server) processFimAlerts(events []presence.FimEvent) {
	for _, ev := range events {
		ev := ev
		s.recordAlert(s.alertFromFimEvent(ev))
	}
}

func (s *Server) processDriftAlerts(dev presence.Device) {
	for _, path := range driftPaths(dev) {
		path := path
		s.ensureAlert(dev.ID, "fim", "drift:"+path, func() presence.Alert {
			return s.alertFromDrift(dev, path)
		})
	}
}

func (s *Server) processScaAlerts(dev presence.Device, results []sca.Result) {
	for _, r := range results {
		if r.Pass {
			continue
		}
		r := r
		s.ensureAlert(dev.ID, "sca", r.PackID+"/"+r.CheckID, func() presence.Alert {
			return s.alertFromSca(dev, r)
		})
	}
}

func (s *Server) evaluateSca(dev presence.Device, agentResults []presence.ScaResult) []presence.ScaResult {
	pack, err := sca.LoadDefaultLinuxSSH()
	if err != nil {
		s.log.Warn("sca pack", "err", err)
		return agentResults
	}
	if dev.Platform != "" && pack.Platform != "" && dev.Platform != pack.Platform {
		return agentResults
	}
	agentByID := map[string]presence.ScaResult{}
	for _, r := range agentResults {
		agentByID[r.CheckID] = r
	}
	var merged []presence.ScaResult
	for _, r := range sca.EvalInventoryFieldChecks(pack, dev) {
		merged = append(merged, presence.ScaResult{
			PackID: r.PackID, CheckID: r.CheckID, Title: r.Title,
			Severity: r.Severity, Pass: r.Pass, Detail: r.Detail,
		})
	}
	for _, check := range pack.Checks {
		if check.Type != "file_regex" {
			continue
		}
		if r, ok := agentByID[check.ID]; ok {
			merged = append(merged, r)
		}
	}
	return merged
}

func driftPaths(dev presence.Device) []string {
	baseline := map[string]string{}
	for _, f := range dev.FimBaseline {
		baseline[f.Path] = f.SHA256
	}
	current := map[string]string{}
	for _, f := range dev.Fim {
		current[f.Path] = f.SHA256
	}
	var out []string
	seen := map[string]bool{}
	for path, hash := range current {
		if exp, ok := baseline[path]; ok && exp != hash {
			if !seen[path] {
				out = append(out, path)
				seen[path] = true
			}
		}
	}
	for path := range baseline {
		if _, ok := current[path]; !ok {
			if !seen[path] {
				out = append(out, path)
				seen[path] = true
			}
		}
	}
	return out
}

func fimPathSeverity(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "sshd_config"), strings.Contains(lower, "sudoers"):
		return "high"
	case strings.Contains(lower, "passwd"), strings.Contains(lower, "shadow"), strings.Contains(lower, "hosts"):
		return "medium"
	default:
		return "medium"
	}
}

func storeAlert(a presence.Alert) storepg.Alert {
	return storepg.Alert{
		ID: a.ID, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		DeviceID: a.DeviceID, Hostname: a.Hostname, Kind: a.Kind,
		Severity: a.Severity, Title: a.Title, Summary: a.Summary,
		Status: a.Status, SourceType: a.SourceType, SourceID: a.SourceID,
		Detail: mustJSON(a.Detail),
	}
}

func alertToMap(a storepg.Alert) map[string]any {
	var detail any
	_ = json.Unmarshal(a.Detail, &detail)
	if detail == nil {
		detail = map[string]any{}
	}
	return map[string]any{
		"id": a.ID, "createdAt": a.CreatedAt, "updatedAt": a.UpdatedAt,
		"deviceId": a.DeviceID, "hostname": a.Hostname, "kind": a.Kind,
		"severity": a.Severity, "title": a.Title, "summary": a.Summary,
		"status": a.Status, "sourceType": a.SourceType, "sourceId": a.SourceID,
		"detail": detail,
	}
}

func shortHash(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return []byte("{}")
	}
	return raw
}
