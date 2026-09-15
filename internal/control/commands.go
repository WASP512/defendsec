package control

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/agentcmd"
	"defendsec/internal/cmdlog"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/identity"
	"defendsec/internal/policy"
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
	s.audit(s.actorIdentity(r), "baseline_accept", deviceID, nil)
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

// adminOK and adminWriteOK go through resolveActor, so a per-user session
// token authorises exactly as the shared tokens did and every existing admin
// handler gains named identity without being changed.
func (s *Server) adminOK(r *http.Request) bool {
	role := s.resolveActor(r).Role
	return role == identity.RoleAdmin || role == identity.RoleViewer
}

func (s *Server) adminWriteOK(r *http.Request) bool {
	return s.resolveActor(r).Role == identity.RoleAdmin
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
	// Policy decides before anything is signed (roadmap 2.1). This is the
	// chokepoint: a command policy refuses never becomes a signed envelope,
	// so it is inert regardless of what happens above this line.
	polReq := s.policyRequest(r.Context(), r, req.Type, req.DeviceID, dev.Hostname)
	decision, err := s.authorise(r.Context(), polReq)
	if err != nil {
		s.log.Error("authorise command", "err", err)
		http.Error(w, "could not evaluate policy", http.StatusInternalServerError)
		return
	}

	switch decision.Effect {
	case policy.EffectDeny:
		s.recordDecision(r.Context(), polReq, decision, "")
		denyResponse(w, decision)
		return

	case policy.EffectRequireApproval:
		pending, err := s.createPendingCommand(r.Context(), polReq, decision, payload)
		if err != nil {
			s.log.Error("create pending command", "err", err)
			http.Error(w, "could not record the approval request", http.StatusInternalServerError)
			return
		}
		s.recordDecision(r.Context(), polReq, decision, "")
		approvalResponse(w, pending, decision)
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
	actor := s.resolveActor(r)
	signature := s.signer.Sign(env)
	s.recordDecision(r.Context(), polReq, decision, id)
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

		// Retain the proof of authority alongside the fact of the command.
		Signature:    base64.StdEncoding.EncodeToString(signature),
		SigningKeyID: s.signer.KeyID(),
		IssuedUnix:   env.IssuedUnix,
		ExpiresUnix:  env.ExpiresUnix,
		// Resolved from the caller's own session, so this names the person who
		// authorised the command. A shared bootstrap token records an explicit
		// unattributed marker instead of implying an attribution that does not
		// exist.
		ActorIdentity: actor.Identity(),
	}
	if err := s.commands.Append(rec); err != nil {
		s.log.Error("command log", "err", err)
		http.Error(w, "log", http.StatusInternalServerError)
		return
	}
	s.syncCommand(rec)
	s.audit(s.actorIdentity(r), "command_issue", req.DeviceID, map[string]any{"type": req.Type, "commandId": id})
	if s.pushSigned(env, signature) {
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

// pushSigned transmits an already-signed envelope. The signature is passed in
// rather than recomputed so that the bytes stored as proof are exactly the
// bytes put on the wire.
func (s *Server) pushSigned(env sign.Envelope, signature []byte) bool {
	cmd := &defendsecv1.ControlCommand{
		CommandId:   env.CommandID,
		Type:        env.Type,
		Payload:     env.Payload,
		Signature:   signature,
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
		signature := s.signer.Sign(env)
		if s.pushSigned(env, signature) {
			sigB64 := base64.StdEncoding.EncodeToString(signature)
			keyID := s.signer.KeyID()
			_ = s.commands.Update(rec.ID, func(r *cmdlog.Record) {
				r.Status = "sent"
				r.Message = "flushed to agent after reconnect"
				// The envelope was re-signed with new issue and expiry
				// timestamps, so the stored proof must track the envelope
				// that actually went out.
				r.Signature = sigB64
				r.SigningKeyID = keyID
				r.IssuedUnix = env.IssuedUnix
				r.ExpiresUnix = env.ExpiresUnix
			})
			if s.pg != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				if err := s.pg.RecordCommandProof(ctx, rec.ID, sigB64, keyID, env.IssuedUnix, env.ExpiresUnix); err != nil {
					s.log.Warn("record command proof", "err", err)
				}
				cancel()
			}
		}
	}
}

func (s *Server) noteAck(deviceID string, accepted bool, commandID, message string, ack *defendsecv1.CommandAck) {
	// Check the endpoint's proof that it ran the command. A missing or bad
	// signature never discards the result — the acknowledgement is still
	// recorded, marked unattested, so upgrading the server does not silently
	// drop older agents and a forged one is visible rather than trusted.
	sigB64, resultHash, executedUnix, verified := s.verifyAck(deviceID, commandID, accepted, ack)

	var cmdType, cmdPayload string
	_ = s.commands.Update(commandID, func(r *cmdlog.Record) {
		cmdType = r.Type
		cmdPayload = r.Payload
		r.Status = "acked"
		r.Accepted = accepted
		r.Message = message
		r.AckSignature = sigB64
		r.AckResultHash = resultHash
		r.AckExecutedUnix = executedUnix
		r.AckVerified = verified
	})
	if s.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.pg.UpdateCommand(ctx, commandID, "acked", accepted, message)
		if sigB64 != "" || executedUnix != 0 {
			if err := s.pg.RecordAckProof(ctx, commandID, sigB64, resultHash, executedUnix, verified); err != nil {
				s.log.Warn("record ack proof", "err", err, "command", commandID)
			}
		}
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

// verifyAck checks an acknowledgement signature against the public half of the
// device's enrolled certificate key, recorded at enrollment. It returns the
// base64 signature, result hash, execution time, and whether the signature
// verified.
func (s *Server) verifyAck(deviceID, commandID string, accepted bool, ack *defendsecv1.CommandAck) (string, string, int64, bool) {
	if ack == nil || len(ack.GetSignature()) == 0 {
		return "", ack.GetResultHash(), ack.GetExecutedUnix(), false
	}
	sigB64 := base64.StdEncoding.EncodeToString(ack.GetSignature())
	resultHash := ack.GetResultHash()
	executedUnix := ack.GetExecutedUnix()

	// The signature covers the result hash, not the result text, so the two
	// have to be checked against each other on arrival. Without this an agent
	// could sign the hash of one result and report another, and the stored
	// record would verify while saying something the endpoint never attested.
	if want := sign.HashResult(ack.GetMessage()); resultHash != want {
		s.log.Warn("acknowledgement result hash does not match the reported result",
			"device", deviceID, "command", commandID)
		s.audit("agent", "ack_result_hash_mismatch", deviceID, map[string]any{
			"commandId": commandID,
		})
		return sigB64, resultHash, executedUnix, false
	}

	pubPEM := ""
	if dev, ok := s.store.Get(deviceID); ok {
		pubPEM = dev.AgentPublicKeyPEM
	}
	if pubPEM == "" && s.pg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if stored, err := s.pg.AgentPublicKeyPEM(ctx, deviceID); err == nil {
			pubPEM = stored
		}
		cancel()
	}
	if pubPEM == "" {
		// Enrolled before migration 007, so there is no key to check against.
		s.log.Warn("acknowledgement cannot be attested: no enrolled agent key",
			"device", deviceID, "command", commandID)
		return sigB64, resultHash, executedUnix, false
	}

	if err := sign.VerifyAckStored(pubPEM, commandID, deviceID, accepted, resultHash, executedUnix, sigB64); err != nil {
		s.log.Warn("acknowledgement signature did not verify", "err", err,
			"device", deviceID, "command", commandID)
		s.audit("agent", "ack_signature_invalid", deviceID, map[string]any{
			"commandId": commandID, "error": err.Error(),
		})
		return sigB64, resultHash, executedUnix, false
	}
	return sigB64, resultHash, executedUnix, true
}
