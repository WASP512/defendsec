package control

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"defendsec/internal/policy"
	"defendsec/internal/storepg"
)

// Policy enforcement (roadmap 2.1).
//
// The one rule this file exists to hold: nothing reaches s.signer.Sign without
// passing through authorise() first. A denied command is never signed, so it
// is inert even if every layer above this is bypassed — an agent checks the
// signature, and there is no signature to check.
//
// That is why enforcement lives here rather than in the HTTP handler's
// validation block. Validation rejects malformed requests; this decides
// whether a well-formed one is allowed to become a cryptographic instruction.

// SetPolicy installs the policy engine.
func (s *Server) SetPolicy(e *policy.Engine) { s.policy = e }

// PolicyEngine returns the engine in force, which may be nil.
func (s *Server) PolicyEngine() *policy.Engine { return s.policy }

// authorise evaluates a command against policy and records the decision.
//
// Every decision is written to the ledger, permit and deny alike. Denials are
// evidence: a tool that records only what it did cannot answer "did anyone
// try", which is the question asked after an incident.
func (s *Server) authorise(ctx context.Context, req policy.Request) (policy.Decision, error) {
	if s.policy == nil {
		// An engine that was never installed is not permission to act. A
		// response tool with no policy is unconfigured, and unconfigured
		// should refuse rather than guess.
		return policy.Decision{
			Effect: policy.EffectDeny,
			Reason: "No policy is loaded, and DefendSec denies by default. Set DEFENDSEC_POLICY_FILE.",
		}, nil
	}

	var usage policy.UsageFunc
	if s.pg != nil {
		usage = func(types []string, since time.Time, deviceID string) (policy.Usage, error) {
			return s.pg.CommandUsage(ctx, types, since, deviceID)
		}
	}

	decision, err := s.policy.Evaluate(req, usage)
	if err != nil {
		// An evaluation that could not complete is a denial, not a pass. The
		// usual cause is an unreadable usage count, and treating that as
		// "under the limit" would disable blast-radius limits exactly when
		// the database is struggling.
		s.log.Warn("policy evaluation failed", "err", err, "command", req.CommandType)
		return policy.Decision{
			Effect: policy.EffectDeny,
			Reason: "Policy could not be evaluated, so the command was refused: " + err.Error(),
		}, nil
	}
	return decision, nil
}

// recordDecision writes an evaluation to the ledger and the decision table.
func (s *Server) recordDecision(ctx context.Context, req policy.Request, d policy.Decision, commandID string) {
	breakGlassID := ""
	if d.BreakGlassUsed && req.BreakGlass != nil {
		breakGlassID = req.BreakGlass.ID
	}

	// The audit entry comes first and is not conditional on Postgres storing
	// the row: the ledger is the tamper-evident record, and a decision that
	// reached only the decisions table would be editable without trace.
	s.audit(req.Actor, "policy_decision", req.DeviceID, map[string]any{
		"effect": string(d.Effect), "commandType": req.CommandType,
		"ruleId": d.RuleID, "reason": d.Reason,
		"policyName": d.PolicyName, "policyHash": d.PolicyHash,
		"limitExceeded": d.LimitExceeded, "breakGlassId": breakGlassID,
		"commandId": commandID,
	})

	if s.pg == nil {
		return
	}
	id, err := newDeviceID()
	if err != nil {
		s.log.Warn("allocate policy decision id", "err", err)
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.pg.RecordPolicyDecision(writeCtx, storepg.PolicyDecision{
		ID: id, At: req.At, Actor: req.Actor, Role: req.Role,
		CommandType: req.CommandType, DeviceID: req.DeviceID, Hostname: req.Hostname,
		HostClasses: req.HostClasses, Effect: d.Effect, RuleID: d.RuleID,
		Reason: d.Reason, PolicyName: d.PolicyName, PolicyHash: d.PolicyHash,
		LimitExceeded: d.LimitExceeded, BreakGlassID: breakGlassID, CommandID: commandID,
	}); err != nil {
		s.log.Warn("record policy decision", "err", err)
	}
}

// policyRequest assembles what the engine needs about a command.
func (s *Server) policyRequest(ctx context.Context, r *http.Request, commandType, deviceID, hostname string) policy.Request {
	actor := s.resolveActor(r)
	req := policy.Request{
		Actor:       actor.Identity(),
		Role:        actor.Role,
		CommandType: commandType,
		DeviceID:    deviceID,
		Hostname:    hostname,
		At:          time.Now().UTC(),
		// The issuer's own approval. A second one has to come from somebody
		// else, through the pending-approval path.
		Approvals: []string{actor.Identity()},
	}
	if s.pg != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if classes, err := s.pg.DeviceClasses(lookupCtx, deviceID); err != nil {
			// A host whose classes cannot be read is evaluated as
			// unclassified, which is the stricter reading: rules naming a
			// class will not match, and only rules that apply to any host can
			// permit it.
			s.log.Warn("read device classes", "err", err, "device", deviceID)
		} else {
			req.HostClasses = classes
		}
		if bg, err := s.pg.ActiveBreakGlass(lookupCtx, req.At); err != nil {
			s.log.Warn("read break-glass", "err", err)
		} else {
			req.BreakGlass = bg
		}
	}
	return req
}

// denyResponse writes a refusal the operator can act on.
//
// The rule id and the reason are returned to the caller on purpose. A refusal
// that says only "forbidden" produces a support ticket, and then a request for
// a bypass; one that names the rule produces a conversation about the rule.
func denyResponse(w http.ResponseWriter, d policy.Decision) {
	body := map[string]any{
		"error":  "policy denied this command",
		"effect": string(d.Effect),
		"reason": d.Reason,
	}
	if d.RuleID != "" {
		body["ruleId"] = d.RuleID
	}
	if d.PolicyName != "" {
		body["policy"] = d.PolicyName
	}
	if d.LimitExceeded != "" {
		body["limitExceeded"] = d.LimitExceeded
	}
	writeJSON(w, http.StatusForbidden, body)
}

// approvalResponse tells the caller the command is waiting on someone else.
//
// 202 rather than 403: this is not a refusal. The request was well formed and
// policy permits it in principle — it is pending, and an operator can resolve
// it by finding a colleague.
func approvalResponse(w http.ResponseWriter, p storepg.PendingCommand, d policy.Decision) {
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":            "awaiting-approval",
		"pendingId":         p.ID,
		"requiredApprovals": d.RequiredApprovals,
		"haveApprovals":     len(p.Approvals),
		"approvals":         p.Approvals,
		"expiresAt":         p.ExpiresAt.Format(time.RFC3339),
		"ruleId":            d.RuleID,
		"reason":            d.Reason,
		"detail": fmt.Sprintf(
			"This command needs %d distinct approvals and has %d. It is not signed and will not run until another administrator approves it.",
			d.RequiredApprovals, len(p.Approvals)),
	})
}
