package control

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"defendsec/internal/cmdlog"
	"defendsec/internal/policy"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// Bounded autonomy (roadmap 4.4).
//
// # Two switches, both off by default
//
// An agent acts without a human only when both of these hold:
//
//   - the policy rule that permitted the command is marked `autonomous:
//     true`, validated at load time to be a permit rule, to not also demand
//     approvals, and to have a blast-radius limit covering every command it
//     names; and
//   - the agent principal has autonomy enabled on it.
//
// Two rather than one, because they revoke differently. Turning off the rule
// stops every agent and needs a policy reload. Turning off the principal stops
// one agent with a single call and touches nothing that governs the others.
// "Trivially revocable" is part of the claim and it has to mean the second
// thing.
//
// Everything else is unchanged: the same policy engine, the same blast-radius
// limits counted the same way, the same signing key, the same hash-chained
// ledger. Autonomy removes the human from the loop and removes nothing else.
// The operator sets the ceiling; the cryptography enforces it.

// autonomyDecision records why an autonomous attempt was or was not allowed.
type autonomyDecision struct {
	// Permitted is whether it may run unattended.
	Permitted bool
	// Reason is written for the ledger and for the agent, so a refusal is
	// actionable rather than mysterious.
	Reason string
}

// mayActAutonomously decides whether a permitted proposal can execute now.
//
// Deliberately explicit about which switch was missing. An operator who
// enabled the rule but not the principal, or the reverse, should learn that
// from the refusal rather than by reading two configuration sources.
func mayActAutonomously(agent storepg.AgentPrincipal, d policy.Decision) autonomyDecision {
	switch {
	case !d.Autonomous && !agent.AutonomyEnabled:
		return autonomyDecision{Reason: "Neither the permitting policy rule nor this agent principal allows autonomous execution, so this was recorded for a human to approve."}
	case !d.Autonomous:
		return autonomyDecision{Reason: fmt.Sprintf(
			"This agent has autonomy enabled, but rule %q does not permit autonomous execution. Recorded for a human to approve.", d.RuleID)}
	case !agent.AutonomyEnabled:
		return autonomyDecision{Reason: fmt.Sprintf(
			"Rule %q permits autonomous execution, but autonomy is not enabled for this agent principal. Recorded for a human to approve.", d.RuleID)}
	case d.RequiredApprovals > 1:
		// Refused at policy load as well. Checked again here because a
		// decision reaching this point with both set and approvals demanded
		// would mean the two safeguards disagree, and the safe reading is the
		// one that asks for a human.
		return autonomyDecision{Reason: fmt.Sprintf(
			"Rule %q permits autonomous execution but also requires %d approvals. Treated as needing a human.",
			d.RuleID, d.RequiredApprovals)}
	}
	return autonomyDecision{Permitted: true, Reason: fmt.Sprintf(
		"Rule %q permits autonomous execution and autonomy is enabled for this agent.", d.RuleID)}
}

// issueAutonomous signs and dispatches a command an agent is acting on alone.
//
// This is the only path in DefendSec that signs without a human in the loop,
// and it mirrors the approved-command path exactly except for attribution: the
// actor is the agent, and the ledger entry names the model and the rule that
// let it act. An auditor reading the ledger can therefore tell a command a
// person authorised from one an AI took by itself, which is the distinction
// that makes autonomy defensible at all.
func (s *Server) issueAutonomous(ctx context.Context, agent storepg.AgentPrincipal, p Proposal, payload []byte, polReq policy.Request, d policy.Decision, why string) (*cmdlog.Record, error) {
	if s.signer == nil {
		// No signing key: the deployment cannot produce a command at all.
		// Returned as an error rather than dereferenced, because a panic here
		// runs on the request path and would take the control plane down —
		// and the one thing worse than an agent that cannot act is a server
		// that stops defending because an agent tried to.
		return nil, fmt.Errorf("no signing key is configured, so no command can be issued")
	}
	id, err := newDeviceID()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	dev, _ := s.store.Get(p.DeviceID)

	env := sign.Envelope{
		DeviceID:    p.DeviceID,
		CommandID:   id,
		Type:        p.CommandType,
		IssuedUnix:  now.Unix(),
		ExpiresUnix: now.Add(2 * time.Minute).Unix(),
		Payload:     payload,
	}
	signature := s.signer.Sign(env)
	s.recordDecision(ctx, polReq, d, id)

	rec := cmdlog.Record{
		ID: id, DeviceID: p.DeviceID, Hostname: dev.Hostname,
		Type: p.CommandType, Payload: string(payload),
		Status: "queued", Message: "waiting for connected agent",
		CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339),
		Signature:    base64.StdEncoding.EncodeToString(signature),
		SigningKeyID: s.signer.KeyID(),
		IssuedUnix:   env.IssuedUnix,
		ExpiresUnix:  env.ExpiresUnix,
		// The agent, not a person. A command taken autonomously must never
		// be attributable to a human who did not authorise it.
		ActorIdentity: agent.Identity(),
	}
	if err := s.commands.Append(rec); err != nil {
		return nil, err
	}
	s.syncCommand(rec)

	// A distinct audit action, not "command_issue". An auditor asking "what
	// did the AI do by itself" must be able to answer it by filtering the
	// ledger rather than by inferring from the actor string.
	s.audit(agent.Identity(), "agent_autonomous_action", p.DeviceID, map[string]any{
		"commandId":         id,
		"type":              p.CommandType,
		"model":             agent.Model,
		"modelAttestation":  "self-reported by the operator who registered this principal; not verified",
		"ruleId":            d.RuleID,
		"policyHash":        d.PolicyHash,
		"reasoning":         p.Reasoning,
		"evidence":          p.Evidence,
		"prompt":            p.Prompt,
		"autonomyGrantedBy": agent.AutonomyGrantedBy,
		"authority":         why,
		"detail":            "Executed without a human approval under a policy rule marked autonomous. Blast-radius limits were evaluated and counted as for any other command.",
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
	return &rec, nil
}

// HandleAgentAutonomy grants or withdraws a principal's autonomy.
func (s *Server) HandleAgentAutonomy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pg, ok := s.auditStore(w)
	if !ok {
		return
	}
	if !s.requireAdminActor(w, r) {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := s.resolveActor(r)
	agent, err := pg.SetAgentAutonomy(r.Context(), req.Name, req.Enabled, actor.Identity())
	if err != nil {
		s.notFoundOrError(w, err, "could not change this agent's autonomy")
		return
	}
	// Granting autonomy is the most consequential thing an operator can
	// configure here, so it is its own audit action rather than a generic
	// update.
	action := "agent_autonomy_withdrawn"
	if req.Enabled {
		action = "agent_autonomy_granted"
	}
	s.audit(actor.Identity(), action, "", map[string]any{
		"agent": agent.Name, "model": agent.Model,
	})

	detail := "Autonomy withdrawn. This agent's proposals now wait for a human again."
	if agent.AutonomyEnabled {
		detail = "Autonomy enabled for this principal. It still acts only where a policy rule is marked autonomous, and still only within the blast-radius limits."
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent": agent, "detail": detail})
}
