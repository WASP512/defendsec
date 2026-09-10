package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/agentcmd"
	"defendsec/internal/cmdlog"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/sign"
)

type issueRequest struct {
	DeviceID string          `json:"deviceId"`
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
}

func (s *Server) HandleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.adminWriteOK(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req struct {
		DeviceID string `json:"deviceId"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.DeviceID) == "" {
		http.Error(w, "deviceId required", http.StatusBadRequest)
		return
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	if !s.store.AcceptBaseline(deviceID) {
		http.Error(w, "unknown mTLS device", http.StatusNotFound)
		return
	}
	if s.pg != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		_, _ = s.pg.AcceptBaseline(ctx, deviceID)
		cancel()
		if got, ok := s.store.Get(deviceID); ok {
			s.syncDevice(got)
		}
	}
	s.audit("admin", "baseline_accept", deviceID, nil)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *Server) HandleControlPub(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.signer.PublicPEM())
}

func (s *Server) HandleAdminCommands(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.adminOK(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		deviceID := r.URL.Query().Get("deviceId")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"commands": s.commands.List(deviceID)})
	case http.MethodPost:
		if !s.adminWriteOK(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		s.issueCommand(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) bearerToken(r *http.Request) string {
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if got == "" {
		got = strings.TrimSpace(r.Header.Get("X-DefendSec-Admin"))
	}
	return got
}

func (s *Server) tokenRole(got string) string {
	if got == "" || s.adminToken == "" {
		return ""
	}
	a := sha256.Sum256([]byte(got))
	admin := sha256.Sum256([]byte(s.adminToken))
	if subtle.ConstantTimeCompare(a[:], admin[:]) == 1 {
		return "admin"
	}
	if s.viewerToken != "" {
		v := sha256.Sum256([]byte(s.viewerToken))
		if subtle.ConstantTimeCompare(a[:], v[:]) == 1 {
			return "viewer"
		}
	}
	return ""
}

func (s *Server) adminOK(r *http.Request) bool {
	role := s.tokenRole(s.bearerToken(r))
	return role == "admin" || role == "viewer"
}

func (s *Server) adminWriteOK(r *http.Request) bool {
	return s.tokenRole(s.bearerToken(r)) == "admin"
}

func validateCommandPayload(cmdType string, payload []byte) error {
	switch cmdType {
	case "run_script":
		if _, err := agentcmd.ParseRunScriptPayload(payload); err != nil {
			return err
		}
	case "quarantine_path":
		if _, err := agentcmd.ParseQuarantinePayload(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) issueCommand(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var req issueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.Type = strings.TrimSpace(req.Type)
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	switch req.Type {
	case "isolate", "release", "kill_process", "live_query", "agent_update", "run_script", "quarantine_path":
	default:
		http.Error(w, "unknown command type", http.StatusBadRequest)
		return
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if err := validateCommandPayload(req.Type, payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dev, ok := s.store.Get(req.DeviceID)
	if !ok {
		http.Error(w, "unknown mTLS device", http.StatusNotFound)
		return
	}
	id, err := newDeviceID()
	if err != nil {
		http.Error(w, "id", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	env := sign.Envelope{
		DeviceID:    req.DeviceID,
		CommandID:   id,
		Type:        req.Type,
		IssuedUnix:  now.Unix(),
		ExpiresUnix: now.Add(2 * time.Minute).Unix(),
		Payload:     payload,
	}
	rec := cmdlog.Record{
		ID:        env.CommandID,
		DeviceID:  env.DeviceID,
		Hostname:  dev.Hostname,
		Type:      env.Type,
		Payload:   string(env.Payload),
		Status:    "queued",
		Message:   "waiting for connected agent",
		CreatedAt: now.UTC().Format(time.RFC3339),
		UpdatedAt: now.UTC().Format(time.RFC3339),
	}
	if err := s.commands.Append(rec); err != nil {
		s.log.Error("command log", "err", err)
		http.Error(w, "log", http.StatusInternalServerError)
		return
	}
	s.syncCommand(rec)
	s.audit("admin", "command_issue", req.DeviceID, map[string]any{"type": req.Type, "commandId": id})
	if s.pushSigned(env) {
		_ = s.commands.Update(id, func(r *cmdlog.Record) {
			r.Status = "sent"
			r.Message = "signed command pushed on mTLS stream"
		})
		rec.Status = "sent"
		rec.Message = "signed command pushed on mTLS stream"
		if s.pg != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.pg.UpdateCommand(ctx, id, "sent", false, rec.Message)
			cancel()
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

func (s *Server) pushSigned(env sign.Envelope) bool {
	cmd := &defendsecv1.ControlCommand{
		CommandId:   env.CommandID,
		Type:        env.Type,
		Payload:     env.Payload,
		Signature:   s.signer.Sign(env),
		IssuedUnix:  env.IssuedUnix,
		ExpiresUnix: env.ExpiresUnix,
		DeviceId:    env.DeviceID,
	}
	return s.hub.Send(env.DeviceID, &defendsecv1.ServerToAgent{
		RequestId: env.CommandID,
		Body:      &defendsecv1.ServerToAgent_Command{Command: cmd},
	})
}

func (s *Server) flushQueued(deviceID string) {
	for _, rec := range s.commands.Pending(deviceID) {
		env := sign.Envelope{
			DeviceID:    rec.DeviceID,
			CommandID:   rec.ID,
			Type:        rec.Type,
			IssuedUnix:  time.Now().Unix(),
			ExpiresUnix: time.Now().Add(2 * time.Minute).Unix(),
			Payload:     []byte(rec.Payload),
		}
		if len(env.Payload) == 0 {
			env.Payload = []byte("{}")
		}
		if s.pushSigned(env) {
			_ = s.commands.Update(rec.ID, func(r *cmdlog.Record) {
				r.Status = "sent"
				r.Message = "flushed to agent after reconnect"
			})
		}
	}
}

func (s *Server) noteAck(deviceID string, accepted bool, commandID, message string) {
	var cmdType, cmdPayload string
	_ = s.commands.Update(commandID, func(r *cmdlog.Record) {
		cmdType = r.Type
		cmdPayload = r.Payload
		r.Status = "acked"
		r.Accepted = accepted
		r.Message = message
	})
	if s.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.pg.UpdateCommand(ctx, commandID, "acked", accepted, message)
		if cmdType == "live_query" {
			queryID := liveQueryID(cmdPayload)
			status := "error"
			if accepted {
				status = "ok"
			}
			_ = s.pg.SaveLiveQueryResult(ctx, commandID, deviceID, queryID, status, message)
		}
		cancel()
	}
	lower := strings.ToLower(message)
	if accepted && strings.Contains(lower, "isolated") && !strings.Contains(lower, "cleared") {
		_ = s.store.SetIsolated(deviceID, true)
		if s.pg != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.pg.SetIsolated(ctx, deviceID, true)
			cancel()
		}
	}
	if accepted && strings.Contains(lower, "isolation cleared") {
		_ = s.store.SetIsolated(deviceID, false)
		if s.pg != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.pg.SetIsolated(ctx, deviceID, false)
			cancel()
		}
	}
	s.audit("agent", "command_ack", deviceID, map[string]any{"commandId": commandID, "accepted": accepted, "message": message})
}

func liveQueryID(payload string) string {
	var p struct {
		Query string `json:"query"`
	}
	if json.Unmarshal([]byte(payload), &p) == nil && strings.TrimSpace(p.Query) != "" {
		return strings.TrimSpace(strings.ToLower(p.Query))
	}
	return "unknown"
}
