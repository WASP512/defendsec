package control

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"keel/internal/cmdlog"
	keelv1 "keel/internal/gen/keel/v1"
	"keel/internal/sign"
)

type issueRequest struct {
	DeviceID string          `json:"deviceId"`
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
}

func (s *Server) HandleControlPub(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.signer.PublicPEM())
}

func (s *Server) HandleAdminCommands(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		deviceID := r.URL.Query().Get("deviceId")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"commands": s.commands.List(deviceID)})
	case http.MethodPost:
		s.issueCommand(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) adminOK(r *http.Request) bool {
	got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if got == "" {
		got = strings.TrimSpace(r.Header.Get("X-Keel-Admin"))
	}
	a := sha256.Sum256([]byte(got))
	b := sha256.Sum256([]byte(s.adminToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1 && s.adminToken != ""
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
	case "isolate", "release", "kill_process":
	default:
		http.Error(w, "unknown command type", http.StatusBadRequest)
		return
	}
	dev, ok := s.store.Get(req.DeviceID)
	if !ok {
		http.Error(w, "unknown mTLS device", http.StatusNotFound)
		return
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
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
	if s.pushSigned(env) {
		_ = s.commands.Update(id, func(r *cmdlog.Record) {
			r.Status = "sent"
			r.Message = "signed command pushed on mTLS stream"
		})
		rec.Status = "sent"
		rec.Message = "signed command pushed on mTLS stream"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rec)
}

func (s *Server) pushSigned(env sign.Envelope) bool {
	cmd := &keelv1.ControlCommand{
		CommandId:   env.CommandID,
		Type:        env.Type,
		Payload:     env.Payload,
		Signature:   s.signer.Sign(env),
		IssuedUnix:  env.IssuedUnix,
		ExpiresUnix: env.ExpiresUnix,
		DeviceId:    env.DeviceID,
	}
	return s.hub.Send(env.DeviceID, &keelv1.ServerToAgent{
		RequestId: env.CommandID,
		Body:      &keelv1.ServerToAgent_Command{Command: cmd},
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
	_ = s.commands.Update(commandID, func(r *cmdlog.Record) {
		r.Status = "acked"
		r.Accepted = accepted
		r.Message = message
	})
	lower := strings.ToLower(message)
	if accepted && strings.Contains(lower, "isolated") && !strings.Contains(lower, "cleared") {
		_ = s.store.SetIsolated(deviceID, true)
	}
	if accepted && strings.Contains(lower, "isolation cleared") {
		_ = s.store.SetIsolated(deviceID, false)
	}
}
