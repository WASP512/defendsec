package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/alertmeta"
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
			rows = append(rows, alertToMap(storeAlert(a)))
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
	detected, ingested := alertmeta.Stamp(alert.DetectedAt)
	alert.DetectedAt = detected
	alert.IngestedAt = ingested
	if alert.CreatedAt == "" {
		alert.CreatedAt = ingested
	}
	if alert.UpdatedAt == "" {
		alert.UpdatedAt = alert.CreatedAt
	}
	if alert.GeneratorVersion == "" {
		alert.GeneratorVersion = alertmeta.GeneratorVersion
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

func (s *Server) resolveAlert(deviceID, kind, sourceID string) {
	_ = s.store.ResolveOpenAlerts(deviceID, kind, sourceID)
	if s.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := s.pg.ResolveOpenAlerts(ctx, deviceID, kind, sourceID); err != nil {
			s.log.Warn("resolve alert", "err", err, "kind", kind, "source", sourceID)
		}
	}
}

func (s *Server) alertFromFimEvent(ev presence.FimEvent) presence.Alert {
	severity := ev.Severity
	if severity == "" {
		severity = fimPathSeverity(ev.Path)
	}
	action := ev.Action
	if action == "" {
		action = "modified"
	}
	detail := alertmeta.BaseDetail(ev.Hostname)
	detail[alertmeta.KeyFilePath] = ev.Path
	detail[alertmeta.KeyFileHashPrev] = ev.Previous
	detail[alertmeta.KeyFileHashCurr] = ev.Current
	detail[alertmeta.KeyEventAction] = action
	detail = alertmeta.WithRaw(detail, map[string]any{
		"path": ev.Path, "previous": ev.Previous, "current": ev.Current, "action": action,
	})
	return presence.Alert{
		ID:               ev.ID,
		DetectedAt:       ev.DetectedAt,
		DeviceID:         ev.DeviceID,
		Hostname:         ev.Hostname,
		Kind:             "fim",
		Severity:         severity,
		Title:            "File integrity " + action + ": " + ev.Path,
		Summary:          shortHash(ev.Previous) + " → " + shortHash(ev.Current),
		SourceType:       "fim_event",
		SourceID:         ev.ID,
		GeneratorID:      alertmeta.GeneratorFIM,
		GeneratorVersion: alertmeta.GeneratorVersion,
		Detail:           detail,
	}
}

func (s *Server) alertFromDrift(dev presence.Device, path, prev, curr string) presence.Alert {
	id, _ := newDeviceID()
	action := "modified"
	if prev != "" && curr == "" {
		action = "deleted"
	} else if prev == "" && curr != "" {
		action = "created"
	}
	detail := alertmeta.BaseDetail(dev.Hostname)
	detail[alertmeta.KeyFilePath] = path
	detail[alertmeta.KeyFileHashPrev] = prev
	detail[alertmeta.KeyFileHashCurr] = curr
	detail[alertmeta.KeyEventAction] = action
	detail = alertmeta.WithRaw(detail, map[string]any{
		"path": path, "previous": prev, "current": curr, "action": action,
	})
	summary := "Current hash differs from accepted baseline"
	if action == "deleted" {
		summary = "Path missing from current inventory (present in baseline)"
	} else if action == "created" {
		summary = "Path appeared in inventory (not in baseline)"
	} else if prev != "" || curr != "" {
		summary = shortHash(prev) + " → " + shortHash(curr)
	}
	return presence.Alert{
		ID:               id,
		DeviceID:         dev.ID,
		Hostname:         dev.Hostname,
		Kind:             "fim",
		Severity:         fimPathSeverity(path),
		Title:            "Baseline drift (" + action + "): " + path,
		Summary:          summary,
		SourceType:       "fim_drift",
		SourceID:         "drift:" + path,
		GeneratorID:      alertmeta.GeneratorFIM,
		GeneratorVersion: alertmeta.GeneratorVersion,
		Detail:           detail,
	}
}

func (s *Server) alertFromSca(dev presence.Device, r sca.Result) presence.Alert {
	id, _ := newDeviceID()
	detail := alertmeta.BaseDetail(dev.Hostname)
	detail[alertmeta.KeySCAPackID] = r.PackID
	detail[alertmeta.KeySCACheckID] = r.CheckID
	detail[alertmeta.KeySCADetail] = r.Detail
	detail = alertmeta.WithRaw(detail, map[string]any{
		"packId": r.PackID, "checkId": r.CheckID, "detail": r.Detail, "pass": r.Pass,
	})
	return presence.Alert{
		ID:               id,
		DeviceID:         dev.ID,
		Hostname:         dev.Hostname,
		Kind:             "sca",
		Severity:         r.Severity,
		Title:            r.Title,
		Summary:          r.Detail,
		SourceType:       "sca_check",
		SourceID:         r.PackID + "/" + r.CheckID,
		GeneratorID:      alertmeta.GeneratorSCA,
		GeneratorVersion: alertmeta.GeneratorVersion,
		Detail:           detail,
	}
}

func (s *Server) processFimAlerts(events []presence.FimEvent) {
	for _, ev := range events {
		ev := ev
		s.recordAlert(s.alertFromFimEvent(ev))
	}
}

func (s *Server) processDriftAlerts(dev presence.Device) {
	drifts := driftStates(dev)
	open := map[string]bool{}
	for path, st := range drifts {
		path, st := path, st
		open[path] = true
		s.ensureAlert(dev.ID, "fim", "drift:"+path, func() presence.Alert {
			return s.alertFromDrift(dev, path, st.prev, st.curr)
		})
	}
	// Resolve drift alerts for paths that returned to baseline.
	baseline := map[string]string{}
	for _, f := range dev.FimBaseline {
		baseline[f.Path] = f.SHA256
	}
	current := map[string]string{}
	for _, f := range dev.Fim {
		current[f.Path] = f.SHA256
	}
	for path, exp := range baseline {
		if open[path] {
			continue
		}
		if cur, ok := current[path]; ok && cur == exp {
			s.resolveAlert(dev.ID, "fim", "drift:"+path)
		}
	}
}

func (s *Server) processScaAlerts(dev presence.Device, results []sca.Result) {
	for _, r := range results {
		r := r
		sourceID := r.PackID + "/" + r.CheckID
		if r.Pass {
			s.resolveAlert(dev.ID, "sca", sourceID)
			continue
		}
		s.ensureAlert(dev.ID, "sca", sourceID, func() presence.Alert {
			return s.alertFromSca(dev, r)
		})
	}
}

func (s *Server) evaluateSca(dev presence.Device, agentResults []presence.ScaResult) []presence.ScaResult {
	var packs []*sca.Pack
	if pack, err := sca.LoadDefaultLinuxSSH(); err == nil {
		packs = append(packs, pack)
	} else {
		s.log.Warn("sca pack", "err", err)
	}
	if pack, err := sca.LoadDefaultLinuxHost(); err == nil {
		packs = append(packs, pack)
	}
	agentByKey := map[string]presence.ScaResult{}
	for _, r := range agentResults {
		agentByKey[r.PackID+"/"+r.CheckID] = r
		agentByKey[r.CheckID] = r
	}
	var merged []presence.ScaResult
	seen := map[string]bool{}
	for _, pack := range packs {
		if pack == nil {
			continue
		}
		if dev.Platform != "" && pack.Platform != "" && pack.Platform != "linux" && pack.Platform != dev.Platform {
			continue
		}
		for _, r := range sca.EvalInventoryFieldChecks(pack, dev) {
			key := r.PackID + "/" + r.CheckID
			if seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, presence.ScaResult{
				PackID: r.PackID, CheckID: r.CheckID, Title: r.Title,
				Severity: r.Severity, Pass: r.Pass, Detail: r.Detail,
			})
		}
		for _, check := range pack.Checks {
			if check.Type != "file_regex" {
				continue
			}
			key := pack.ID + "/" + check.ID
			if seen[key] {
				continue
			}
			if r, ok := agentByKey[key]; ok {
				seen[key] = true
				merged = append(merged, r)
				continue
			}
			if r, ok := agentByKey[check.ID]; ok {
				seen[key] = true
				r.PackID = pack.ID
				merged = append(merged, r)
			}
		}
	}
	if len(merged) == 0 {
		return agentResults
	}
	return merged
}

type driftState struct {
	prev string
	curr string
}

func driftStates(dev presence.Device) map[string]driftState {
	baseline := map[string]string{}
	for _, f := range dev.FimBaseline {
		baseline[f.Path] = f.SHA256
	}
	current := map[string]string{}
	for _, f := range dev.Fim {
		current[f.Path] = f.SHA256
	}
	out := map[string]driftState{}
	for path, hash := range current {
		if exp, ok := baseline[path]; ok && exp != hash {
			out[path] = driftState{prev: exp, curr: hash}
		} else if !ok {
			// Present now but not in baseline: only alert after baseline exists.
			if len(baseline) > 0 {
				out[path] = driftState{prev: "", curr: hash}
			}
		}
	}
	for path, exp := range baseline {
		if _, ok := current[path]; !ok {
			out[path] = driftState{prev: exp, curr: ""}
		}
	}
	return out
}

func fimPathSeverity(path string) string {
	return presence.FimPathSeverity(path)
}

func storeAlert(a presence.Alert) storepg.Alert {
	return storepg.Alert{
		ID: a.ID, CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt,
		DetectedAt: a.DetectedAt, IngestedAt: a.IngestedAt,
		DeviceID: a.DeviceID, Hostname: a.Hostname, Kind: a.Kind,
		Severity: a.Severity, Title: a.Title, Summary: a.Summary,
		Status: a.Status, SourceType: a.SourceType, SourceID: a.SourceID,
		GeneratorID: a.GeneratorID, GeneratorVersion: a.GeneratorVersion,
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
		"detectedAt": a.DetectedAt, "ingestedAt": a.IngestedAt,
		"deviceId": a.DeviceID, "hostname": a.Hostname, "kind": a.Kind,
		"severity": a.Severity, "title": a.Title, "summary": a.Summary,
		"status": a.Status, "sourceType": a.SourceType, "sourceId": a.SourceID,
		"generatorId": a.GeneratorID, "generatorVersion": a.GeneratorVersion,
		"detail": detail,
	}
}

func shortHash(s string) string {
	if s == "" {
		return "(none)"
	}
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
