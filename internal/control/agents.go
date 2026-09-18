package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"defendsec/internal/policy"
	"defendsec/internal/storepg"
)

// AI agent principals and the propose-and-sign path (roadmap 4.1, 4.2).
//
// # The claim, and where it is enforced
//
// An agent connected to DefendSec cannot exceed the bounded command set,
// cannot bypass the policy engine, cannot sign its own authority, and cannot
// act without leaving a cryptographic record. Each of those rests on
// something structural rather than on a check somebody has to remember:
//
//   - The bounded command set: a proposal names a command type from the same
//     list the human endpoint accepts, and an unknown type is refused before
//     policy is consulted.
//   - The policy engine: a proposal goes through Server.authorise, the same
//     function and the same document as a human request.
//   - Signing: a proposal is written to pending_commands, which carries no
//     signature field at all. There is no code path from a proposal to
//     Signer.Sign that does not pass through a human approval.
//   - The record: the proposal, its reasoning, the evidence it cited and the
//     approving human all land in the hash-chained ledger.
//
// # Why the agent's own approval does not count
//
// A human requester's own approval counts as one, because they asked for it.
// An agent's does not. If it did, a one-approval rule would let an AI issue
// commands unsupervised and the guarantee above would be false. That
// asymmetry is enforced in storepg.CreatePendingCommand, on the write path,
// rather than by whoever is assembling the request here.

// RoleAgent is the role an agent-originated request is evaluated under.
//
// Deliberately not a member of identity.ValidRole: it is not a role a user
// account can hold, and an account with it would be an agent that could log
// into the console. It exists so policy rules can name agents — `roles:
// [agent]` — and so the role recorded on a decision says what kind of actor
// it was.
const RoleAgent = "agent"

// proposalTTL bounds how long a proposal waits for a human.
//
// Shorter than a human request's window would be wrong, and longer would be
// worse: an agent's reasoning was formed from the fleet as it was, and
// approving it a day later acts on an assessment nobody re-made. The pending
// TTL already applied to human requests is the right bound for the same
// reason, so this reuses it rather than inventing a second number.
const proposalTTL = pendingTTL

// agentPrincipal resolves an MCP bearer token.
//
// Note what this does not consult: users, sessions, or the shared bootstrap
// tokens. An agent token is not a weaker session — it is looked up in a
// different table entirely, which is why presenting one to the admin API
// yields an unauthenticated caller rather than an under-privileged one.
func (s *Server) agentPrincipal(r *http.Request) (storepg.AgentPrincipal, bool) {
	if s.pg == nil {
		return storepg.AgentPrincipal{}, false
	}
	token := s.bearerToken(r)
	if token == "" {
		return storepg.AgentPrincipal{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), actorTimeout)
	defer cancel()

	agent, err := s.pg.LookupAgentToken(ctx, token)
	if err != nil {
		if errors.Is(err, storepg.ErrAgentInactive) {
			// Worth an operator's attention: a withdrawn credential still
			// being presented means something is running that should not be.
			s.log.Warn("revoked or disabled agent principal presented a token",
				"agent", agent.Name)
		}
		return storepg.AgentPrincipal{}, false
	}
	s.pg.TouchAgent(ctx, agent.ID)
	return agent, true
}

// Proposal is an agent's recommendation.
type Proposal struct {
	CommandType string
	DeviceID    string
	Payload     []byte
	// Reasoning is the model's stated case, recorded verbatim. Never parsed
	// and never used in any decision: it is evidence about what the model
	// said, not an input to what DefendSec does.
	Reasoning string
	// Evidence are the DefendSec record ids the model says it relied on.
	Evidence []string
	// Prompt is what the agent says it was asked to do. Untrusted, recorded
	// so "who set this agent on this task" has an answer in the ledger.
	Prompt string
}

// ProposalOutcome is what happened to a proposal.
type ProposalOutcome struct {
	Status    string `json:"status"`
	PendingID string `json:"pendingId,omitempty"`
	// CommandID is set only when the proposal executed autonomously.
	CommandID string           `json:"commandId,omitempty"`
	Detail    string           `json:"detail"`
	Decision  *policy.Decision `json:"decision,omitempty"`
	// RequiredApprovals and Approvals report how far from signable it is.
	RequiredApprovals int      `json:"requiredApprovals,omitempty"`
	Approvals         []string `json:"approvals,omitempty"`
}

// Propose runs an agent's recommendation through policy and, if permitted,
// records it unsigned for a human to approve.
//
// There is no branch in which this signs anything. A permitted proposal and
// a proposal needing approval take the same path — into pending_commands —
// because a proposal that policy would have let a human execute immediately
// still needs a human, and collapsing those two cases is how a product ends
// up with an AI that acts on its own.
func (s *Server) Propose(ctx context.Context, agent storepg.AgentPrincipal, p Proposal) (ProposalOutcome, error) {
	if s.pg == nil {
		return ProposalOutcome{
			Status: "unavailable",
			Detail: "Proposals need a configured database to record them for approval.",
		}, nil
	}
	// Re-read the principal rather than trusting the struct handed in.
	//
	// The caller's copy was fetched at some earlier point — for an agent
	// holding a long conversation, possibly many minutes earlier — and a
	// revocation that landed in between must bite here. Checking
	// agent.Active() on the passed value would have made this guarantee
	// depend on every caller having refreshed first, which is the kind of
	// obligation that holds until somebody writes a new caller.
	fresh, err := s.pg.GetAgentPrincipal(ctx, agent.Name)
	if err != nil {
		return ProposalOutcome{
			Status: "denied",
			Detail: "This agent principal is no longer registered.",
		}, nil
	}
	if !fresh.Active() {
		return ProposalOutcome{
			Status: "denied",
			Detail: "This agent principal has been revoked or disabled. Nothing was recorded.",
		}, nil
	}
	// Everything below attributes to the stored principal, so a proposal
	// cannot be recorded against a model string the caller supplied.
	agent = fresh

	p.CommandType = strings.TrimSpace(p.CommandType)
	p.DeviceID = strings.TrimSpace(p.DeviceID)
	if !proposableCommand(p.CommandType) {
		return ProposalOutcome{
			Status: "invalid",
			Detail: fmt.Sprintf(
				"%q is not a command an agent may propose. Proposable types: %s.",
				p.CommandType, strings.Join(proposableCommands, ", ")),
		}, nil
	}
	payload := p.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if err := validateCommandPayload(p.CommandType, payload); err != nil {
		return ProposalOutcome{Status: "invalid", Detail: err.Error()}, nil
	}
	if strings.TrimSpace(p.Reasoning) == "" {
		// Required. An auditor reconstructing the decision needs what
		// recommended it, and a proposal with no stated case is one nobody
		// can review on its merits.
		return ProposalOutcome{
			Status: "invalid",
			Detail: "A proposal must state its reasoning: a human will be asked to approve it, and an unexplained recommendation cannot be reviewed.",
		}, nil
	}
	dev, ok := s.store.Get(p.DeviceID)
	if !ok {
		return ProposalOutcome{
			Status: "invalid",
			Detail: fmt.Sprintf("No enrolled host has device id %q.", p.DeviceID),
		}, nil
	}

	now := time.Now().UTC()
	polReq := policy.Request{
		Actor:       agent.Identity(),
		Role:        RoleAgent,
		CommandType: p.CommandType,
		DeviceID:    p.DeviceID,
		Hostname:    dev.Hostname,
		At:          now,
		// No approvals. Emphatically not the proposing agent's own: an agent
		// approving its own proposal is the failure this phase exists to
		// prevent, and starting the list empty is how that is true here as
		// well as on the write path.
		Approvals: nil,
	}
	if classes, err := s.pg.DeviceClasses(ctx, p.DeviceID); err != nil {
		// Unclassified is the stricter reading: rules naming a class will not
		// match, so only a rule applying to any host can permit this.
		s.log.Warn("read device classes for proposal", "err", err, "device", p.DeviceID)
	} else {
		polReq.HostClasses = classes
	}
	// Break-glass is deliberately not read here. An emergency bypass is a
	// human declaring an emergency; letting it widen what an AI may propose
	// would turn the worst moment to be careful into the moment the bounds
	// came off.

	decision, err := s.authorise(ctx, polReq)
	if err != nil {
		return ProposalOutcome{}, err
	}
	if decision.Effect == policy.EffectDeny {
		s.recordDecision(ctx, polReq, decision, "")
		s.audit(agent.Identity(), "agent_proposal_denied", p.DeviceID, map[string]any{
			"commandType": p.CommandType,
			"model":       agent.Model,
			"ruleId":      decision.RuleID,
			"reason":      decision.Reason,
			"reasoning":   p.Reasoning,
		})
		d := decision
		return ProposalOutcome{
			Status:   "denied",
			Detail:   decision.Reason,
			Decision: &d,
		}, nil
	}

	// Bounded autonomy (roadmap 4.4). Both switches must be on: the rule
	// marked autonomous, and this principal permitted to use it. Otherwise
	// the proposal takes the ordinary path below and waits for a human,
	// which is what every agent does by default.
	autonomy := mayActAutonomously(agent, decision)
	if autonomy.Permitted {
		rec, err := s.issueAutonomous(ctx, agent, p, payload, polReq, decision, autonomy.Reason)
		if err != nil {
			return ProposalOutcome{}, err
		}
		d := decision
		return ProposalOutcome{
			Status:    "executed",
			Detail:    fmt.Sprintf("Executed without a human approval as command %s. %s Blast-radius limits were evaluated and counted as for any other command, and the action is attributed to this agent in the signed ledger.", rec.ID, autonomy.Reason),
			Decision:  &d,
			CommandID: rec.ID,
		}, nil
	}

	// Permitted, or permitted-with-approvals. Either way it is recorded
	// unsigned and needs a human.
	required := decision.RequiredApprovals
	if required < 1 {
		// A policy that would have let a human act immediately still does not
		// let an agent act. One human approval is the floor, and it is a
		// floor rather than a default so a rule asking for two still gets two.
		required = 1
	}

	id, err := newDeviceID()
	if err != nil {
		return ProposalOutcome{}, err
	}
	pending, err := s.pg.CreatePendingCommand(ctx, storepg.PendingCommand{
		ID: id, CreatedAt: now, ExpiresAt: now.Add(proposalTTL),
		DeviceID: p.DeviceID, Hostname: dev.Hostname,
		CommandType: p.CommandType, Payload: string(payload),
		RequestedBy: agent.Identity(), RequiredApprovals: required,
		RuleID: decision.RuleID, PolicyHash: decision.PolicyHash,

		ProposedByAgent:   agent.Name,
		ProposalModel:     agent.Model,
		ProposalReasoning: p.Reasoning,
		ProposalEvidence:  p.Evidence,
		ProposalPrompt:    p.Prompt,
	})
	if err != nil {
		return ProposalOutcome{}, err
	}
	s.recordDecision(ctx, polReq, decision, "")
	s.audit(agent.Identity(), "agent_proposal_recorded", p.DeviceID, map[string]any{
		// Why this waited rather than ran. Recorded even in the ordinary case
		// so an operator who expected autonomy and did not get it can find
		// out which of the two switches was off.
		"autonomy":    autonomy.Reason,
		"pendingId":   pending.ID,
		"commandType": p.CommandType,
		// The model is recorded as the agent's operator declared it.
		// Self-reported, and the audit detail says so rather than implying an
		// attestation DefendSec cannot make.
		"model":             agent.Model,
		"modelAttestation":  "self-reported by the operator who registered this principal; not verified",
		"requiredApprovals": required,
		"reasoning":         p.Reasoning,
		"evidence":          p.Evidence,
		"prompt":            p.Prompt,
		"ruleId":            decision.RuleID,
		"detail":            "Recorded unsigned. No signature exists until a human approves it.",
	})

	d := decision
	return ProposalOutcome{
		Status:    "awaiting-approval",
		PendingID: pending.ID,
		Detail: fmt.Sprintf(
			"Recorded unsigned as %s. It needs %d human approval(s) and carries no signature until then. An operator reviews it on the console's Response page.",
			pending.ID, required),
		Decision:          &d,
		RequiredApprovals: required,
		Approvals:         pending.Approvals,
	}, nil
}

// proposableCommands is what an agent may put forward.
//
// A subset of what a human may issue, and the omissions are deliberate.
// run_script and agent_update are absent: the first is arbitrary code, and
// the second changes the agent that enforces everything else. Neither belongs
// in a set an AI can name, whatever policy would say afterwards — a bounded
// command set that includes "run this script" is not bounded.
var proposableCommands = []string{"isolate", "release", "kill_process", "live_query", "quarantine_path"}

func proposableCommand(t string) bool {
	for _, allowed := range proposableCommands {
		if allowed == t {
			return true
		}
	}
	return false
}

// HandleAgents manages agent principals. Admin-only, and admin-write for
// anything that creates or withdraws one.
func (s *Server) HandleAgents(w http.ResponseWriter, r *http.Request) {
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
		agents, err := pg.ListAgentPrincipals(r.Context())
		if err != nil {
			s.log.Warn("list agent principals", "err", err)
			http.Error(w, "could not list agent principals", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"agents": agents,
			"detail": "An agent principal may read fleet state and propose bounded responses. It can never sign a command: every proposal is recorded unsigned and needs a human approval.",
		})

	case http.MethodPost:
		s.createAgent(w, r, pg)

	case http.MethodDelete:
		s.revokeAgent(w, r, pg)

	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) createAgent(w http.ResponseWriter, r *http.Request, pg *storepg.Store) {
	if !s.requireAdminActor(w, r) {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Model       string `json:"model"`
		Description string `json:"description"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	actor := s.resolveActor(r)
	agent, token, err := pg.CreateAgentPrincipal(r.Context(),
		req.Name, req.Model, req.Description, actor.Identity())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	s.audit(actor.Identity(), "agent_principal_created", "", map[string]any{
		"agent": agent.Name, "model": agent.Model,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"agent": agent,
		// Shown once. Only the hash is stored, so a database copy yields no
		// working credential — which matters more for an agent than a person,
		// because an agent token is used unattended and nobody notices it
		// being replayed.
		"token":  token,
		"detail": "This token is shown once and is not recoverable. It can read fleet state and propose responses; it can never sign one.",
	})
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request, pg *storepg.Store) {
	if !s.requireAdminActor(w, r) {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name is required"})
		return
	}
	actor := s.resolveActor(r)
	agent, err := pg.RevokeAgentPrincipal(r.Context(), name, actor.Identity())
	if err != nil {
		s.notFoundOrError(w, err, "could not revoke the agent principal")
		return
	}
	s.audit(actor.Identity(), "agent_principal_revoked", "", map[string]any{
		"agent": agent.Name,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":  agent,
		"detail": "Revoked. The record is kept rather than deleted, so the ledger still shows the principal existed and when it was withdrawn.",
	})
}
