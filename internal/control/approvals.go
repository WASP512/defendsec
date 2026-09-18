package control

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/cmdlog"
	"defendsec/internal/identity"
	"defendsec/internal/policy"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// Two-person integrity (roadmap 2.3).
//
// A command needing a second approver is stored unsigned. That is the whole
// mechanism: it is not a signed command with a pending flag, so an attacker
// who flips a status column in the database still has nothing an agent will
// execute. The signature is produced once, at the moment the approvals are
// in, and not before.

// pendingTTL bounds how long a request waits. An approval request that never
// expires becomes a way to get a command signed weeks later, under conditions
// nobody re-examined.
const pendingTTL = 30 * time.Minute

// createPendingCommand records a command awaiting approval.
func (s *Server) createPendingCommand(ctx context.Context, req policy.Request, d policy.Decision, payload []byte) (storepg.PendingCommand, error) {
	if s.pg == nil {
		return storepg.PendingCommand{}, fmt.Errorf(
			"this command requires %d approvals, which needs a configured database to track", d.RequiredApprovals)
	}
	id, err := newDeviceID()
	if err != nil {
		return storepg.PendingCommand{}, err
	}
	now := req.At
	return s.pg.CreatePendingCommand(ctx, storepg.PendingCommand{
		ID: id, CreatedAt: now, ExpiresAt: now.Add(pendingTTL),
		DeviceID: req.DeviceID, Hostname: req.Hostname,
		CommandType: req.CommandType, Payload: string(payload),
		RequestedBy: req.Actor, RequiredApprovals: d.RequiredApprovals,
		RuleID: d.RuleID, PolicyHash: d.PolicyHash,
	})
}

// HandleApprovals lists requests awaiting approval and approves them.
func (s *Server) HandleApprovals(w http.ResponseWriter, r *http.Request) {
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.adminOK(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		pending, err := pg.ListPendingCommands(r.Context(), time.Now().UTC())
		if err != nil {
			s.log.Warn("list pending commands", "err", err)
			http.Error(w, "could not list approval requests", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pending": pending})

	case http.MethodPost:
		s.approvePending(w, r, pg)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) approvePending(w http.ResponseWriter, r *http.Request, pg *storepg.Store) {
	actor := s.resolveActor(r)
	if !s.requireAdminActor(w, r) {
		return
	}
	var req struct {
		PendingID string `json:"pendingId"`
		// Reject, with an id, refuses the request instead of approving it.
		Reject bool `json:"reject"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	id := strings.TrimSpace(req.PendingID)
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "pendingId is required"})
		return
	}
	now := time.Now().UTC()

	if req.Reject {
		if err := pg.ResolvePendingCommand(r.Context(), id, "rejected", ""); err != nil {
			s.notFoundOrError(w, err, "could not reject the request")
			return
		}
		s.audit(actor.Identity(), "command_approval_rejected", "", map[string]any{"pendingId": id})
		writeJSON(w, http.StatusOK, map[string]any{"status": "rejected", "pendingId": id})
		return
	}

	pending, err := pg.ApprovePendingCommand(r.Context(), id, actor.Identity(), now)
	if err != nil {
		s.notFoundOrError(w, err, err.Error())
		return
	}
	s.audit(actor.Identity(), "command_approval_granted", pending.DeviceID, map[string]any{
		"pendingId": id, "commandType": pending.CommandType,
		"approvals": len(pending.Approvals), "required": pending.RequiredApprovals,
	})

	if !pending.Approved() {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "awaiting-approval",
			"pendingId":         id,
			"approvals":         pending.Approvals,
			"requiredApprovals": pending.RequiredApprovals,
			"detail": fmt.Sprintf("%d of %d approvals. Still unsigned.",
				len(pending.Approvals), pending.RequiredApprovals),
		})
		return
	}

	// Enough approvals: re-evaluate against policy before signing.
	//
	// Re-evaluating rather than trusting the earlier decision matters. Minutes
	// have passed: a blast-radius limit may now be exhausted, a time window
	// may have closed, the policy file may have been reloaded, and the host
	// may have been reclassified. The first decision authorised asking for
	// approval; it does not authorise acting later under conditions nobody
	// re-checked.
	rec, decision, err := s.issueApproved(r.Context(), pending, actor.Identity(), now)
	if err != nil {
		s.log.Error("issue approved command", "err", err)
		http.Error(w, "could not issue the approved command", http.StatusInternalServerError)
		return
	}
	if !decision.Allowed() {
		_ = pg.ResolvePendingCommand(r.Context(), id, "denied", "")
		denyResponse(w, decision)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "issued",
		"pendingId": id,
		"command":   rec,
		"approvals": pending.Approvals,
	})
}

// issueApproved re-evaluates and, if still permitted, signs and sends.
func (s *Server) issueApproved(ctx context.Context, pending storepg.PendingCommand, approver string, now time.Time) (*cmdlog.Record, policy.Decision, error) {
	// The role an approved request is re-evaluated under.
	//
	// A human request is evaluated as admin: an approver with admin authority
	// is standing behind it, which is what the approval means.
	//
	// An agent proposal is re-evaluated as "agent" even though a human is
	// approving it, and that is the whole point. Policy rules can match on
	// role, so an operator can write a rule constraining what agents may
	// propose. If approval promoted the request to admin, a human clicking
	// approve would launder a proposal past the very rule written to bound
	// it, and the bound would hold only until somebody was busy. The rule
	// binds at signing time or it does not bind at all.
	role := identity.RoleAdmin
	if pending.FromAgent() {
		role = RoleAgent
	}
	polReq := policy.Request{
		Actor: pending.RequestedBy, Role: role,
		CommandType: pending.CommandType, DeviceID: pending.DeviceID,
		Hostname: pending.Hostname, At: now,
		Approvals: pending.Approvals,
	}
	if classes, err := s.pg.DeviceClasses(ctx, pending.DeviceID); err == nil {
		polReq.HostClasses = classes
	}
	if bg, err := s.pg.ActiveBreakGlass(ctx, now); err == nil {
		polReq.BreakGlass = bg
	}

	decision, err := s.authorise(ctx, polReq)
	if err != nil {
		return nil, policy.Decision{}, err
	}
	if !decision.Allowed() {
		s.recordDecision(ctx, polReq, decision, "")
		return nil, decision, nil
	}

	// Claim the request before signing. Two approvers racing to the final
	// approval must not both produce a command; the status moves only from
	// pending, so exactly one of them wins.
	id, err := newDeviceID()
	if err != nil {
		return nil, policy.Decision{}, err
	}
	if err := s.pg.ResolvePendingCommand(ctx, pending.ID, "issued", id); err != nil {
		if errors.Is(err, storepg.ErrNotFound) {
			// Somebody else got there first. Not an error, and not a second
			// command.
			return nil, decision, fmt.Errorf("this request was already resolved by another approver")
		}
		return nil, policy.Decision{}, err
	}

	dev, _ := s.store.Get(pending.DeviceID)
	env := sign.Envelope{
		DeviceID:    pending.DeviceID,
		CommandID:   id,
		Type:        pending.CommandType,
		IssuedUnix:  now.Unix(),
		ExpiresUnix: now.Add(2 * time.Minute).Unix(),
		Payload:     []byte(pending.Payload),
	}
	signature := s.signer.Sign(env)
	s.recordDecision(ctx, polReq, decision, id)

	rec := cmdlog.Record{
		ID: id, DeviceID: pending.DeviceID, Hostname: dev.Hostname,
		Type: pending.CommandType, Payload: pending.Payload,
		Status: "queued", Message: "waiting for connected agent",
		CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339),
		Signature:    base64.StdEncoding.EncodeToString(signature),
		SigningKeyID: s.signer.KeyID(),
		IssuedUnix:   env.IssuedUnix,
		ExpiresUnix:  env.ExpiresUnix,
		// The requester is the actor; the approvers are recorded in the
		// ledger entry alongside, so both halves of a two-person action are
		// attributable.
		ActorIdentity: pending.RequestedBy,
	}
	if err := s.commands.Append(rec); err != nil {
		return nil, policy.Decision{}, err
	}
	s.syncCommand(rec)
	s.audit(pending.RequestedBy, "command_issue", pending.DeviceID, map[string]any{
		"type": pending.CommandType, "commandId": id,
		"pendingId": pending.ID, "approvedBy": pending.Approvals,
		"finalApprover": approver,
	})
	if s.pushSigned(env, signature) {
		_ = s.commands.Update(id, func(r *cmdlog.Record) {
			r.Status = "sent"
			r.Message = "signed command pushed on mTLS stream"
		})
		rec.Status = "sent"
		rec.Message = "signed command pushed on mTLS stream"
		if s.pg != nil {
			updCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = s.pg.UpdateCommand(updCtx, id, "sent", false, rec.Message)
			cancel()
		}
	}
	return &rec, decision, nil
}

func (s *Server) notFoundOrError(w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, storepg.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such open approval request"})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
}
