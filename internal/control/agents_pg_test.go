package control

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/cmdlog"
	"defendsec/internal/policy"
	"defendsec/internal/presence"
	"defendsec/internal/sign"
	"defendsec/internal/storepg"
)

// Phase 4 acceptance, asserted rather than asserted-about.
//
// The claim is that an AI agent can triage and propose, that the proposal is
// unsignable without a human approver, and that the ledger records the model,
// its reasoning and the approving human. Each of those is a test here, and
// the ones that matter are the negative ones: what an agent cannot do.
//
// These need a real database, because the guarantee lives partly in
// storepg.CreatePendingCommand and partly in the schema.

// agentServer builds a server with a policy that permits agent proposals.
func agentServer(t *testing.T, policySrc string) (*Server, *storepg.Store) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	// Everything these tests read or write. A table left out leaks an
	// earlier test's rows into a later one's correlation, which shows up as a
	// confident explanation built on another test's history — the failure is
	// obvious once seen and invisible until then.
	if _, err := pool.Exec(ctx,
		`TRUNCATE agent_principals, pending_commands, pending_command_approvals,
		 policy_decisions, audit_log, alerts, package_changes, commands,
		 devices, break_glass CASCADE`); err != nil {
		t.Fatal(err)
	}

	store := storepg.New(pool)
	// A real signing key and command log: the autonomy tests assert that a
	// command is actually signed, which a stubbed signer would not establish.
	signer, err := sign.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		adminToken:  "admin-token",
		viewerToken: "viewer-token",
		log:         slog.New(slog.DiscardHandler),
		signer:      signer,
		commands:    cmdlog.New(filepath.Join(t.TempDir(), "commands.json")),
	}
	s.SetPostgres(store)
	s.store = presence.New(filepath.Join(t.TempDir(), "defendsec.json"))
	doc, perr := policy.Parse([]byte(policySrc))
	if perr != nil {
		t.Fatal(perr)
	}
	s.SetPolicy(policy.NewEngine(doc))
	return s, store
}

// enrolHost registers a device the proposal can target.
//
// Written to both stores. The file store is what the server reads for host
// lookups, and Postgres is what alerts reference by foreign key — a host in
// only one of them fails in whichever place the test does not look.
func enrolHost(t *testing.T, s *Server, id, hostname string) {
	t.Helper()
	dev := presence.Device{
		ID: id, Hostname: hostname, Platform: "linux",
		LastSeen: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.store.Upsert(dev); err != nil {
		t.Fatal(err)
	}
	if s.pg != nil {
		if err := s.pg.UpsertDevice(context.Background(), dev); err != nil {
			t.Fatal(err)
		}
	}
}

// newAgent registers a principal and returns it with its token.
func newAgent(t *testing.T, store *storepg.Store, name string) (storepg.AgentPrincipal, string) {
	t.Helper()
	agent, token, err := store.CreateAgentPrincipal(context.Background(),
		name, "some-model-v1", "triage agent", "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	return agent, token
}

const agentPolicy = `
version: 1
name: agents-may-propose
rules:
  - id: agents-propose-readonly
    effect: permit
    roles: [agent]
    commands: [live_query, isolate]
  - id: humans-do-anything
    effect: permit
    roles: [admin]
    commands: [live_query, isolate, kill_process, run_script]
`

// The central guarantee: a proposal is recorded unsigned and carries no
// approval of its own, so it cannot be signed without a human.
func TestAgentProposalIsRecordedUnsignedAndUnapproved(t *testing.T) {
	s, store := agentServer(t, agentPolicy)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate",
		DeviceID:    "dev-1",
		Reasoning:   "Alert a-1 shows a reverse shell; isolating stops lateral movement.",
		Evidence:    []string{"alert:a-1"},
		Prompt:      "Triage open detection alerts.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "awaiting-approval" {
		t.Fatalf("status = %q, detail = %q", outcome.Status, outcome.Detail)
	}

	pending, err := store.GetPendingCommand(context.Background(), outcome.PendingID)
	if err != nil {
		t.Fatal(err)
	}

	// The proposal has nobody's approval. A human request self-approves; an
	// agent's must not, or a one-approval rule would let an AI act alone.
	if len(pending.Approvals) != 0 {
		t.Errorf("an agent proposal arrived with approvals %v — it has approved itself",
			pending.Approvals)
	}
	if pending.RequiredApprovals < 1 {
		t.Errorf("requiredApprovals = %d, want at least one human",
			pending.RequiredApprovals)
	}
	if pending.Approved() {
		t.Error("the proposal is already considered approved and would be signed")
	}
	if !pending.FromAgent() {
		t.Error("the pending command does not record that an agent proposed it")
	}

	// No command was written to the command log, because nothing was signed.
	cmds, err := store.ListCommands(context.Background(), "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Errorf("a proposal produced %d signed command(s)", len(cmds))
	}
}

// Even where policy would have let a human act with no approval at all, an
// agent still needs one. Collapsing those two cases is how a product ends up
// with an AI that acts on its own.
func TestAPolicyThatPermitsOutrightStillNeedsAHumanForAnAgent(t *testing.T) {
	s, store := agentServer(t, `
version: 1
name: wide-open
rules:
  - id: permit-everything
    effect: permit
    commands: [isolate, live_query]
`)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1",
		Reasoning: "Because the policy allows it.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "awaiting-approval" {
		t.Fatalf("status = %q: a permit-outright policy must still not let an agent act", outcome.Status)
	}
	if outcome.RequiredApprovals < 1 {
		t.Errorf("requiredApprovals = %d, want at least one", outcome.RequiredApprovals)
	}
}

// Deny-by-default extends to the AI. A policy that permits humans and says
// nothing about agents permits nothing to an agent.
func TestPolicySilentAboutAgentsDeniesThem(t *testing.T) {
	s, store := agentServer(t, `
version: 1
name: humans-only
rules:
  - id: admins-may-isolate
    effect: permit
    roles: [admin]
    commands: [isolate]
`)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1",
		Reasoning: "It looks compromised.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "denied" {
		t.Fatalf("status = %q, want denied: a policy naming only admins must not permit an agent", outcome.Status)
	}
	// The refusal names the reason, so the model does not retry with
	// different wording against a boundary that is not about wording.
	if outcome.Detail == "" {
		t.Error("the denial gives no reason")
	}
}

// A human approval must not promote an agent proposal to admin authority. If
// it did, an operator clicking approve would launder the proposal past the
// very rule written to bound agents.
func TestHumanApprovalDoesNotLaunderAnAgentProposalPastAnAgentRule(t *testing.T) {
	// Agents may propose live_query only. Admins may isolate. An agent
	// proposal to isolate is denied at proposal time, so to reach the
	// approval path we insert one directly — simulating a policy that was
	// narrowed after the proposal was recorded, which is exactly the case
	// re-evaluation exists for.
	s, store := agentServer(t, `
version: 1
name: agents-read-only
rules:
  - id: agents-query-only
    effect: permit
    roles: [agent]
    commands: [live_query]
  - id: admins-may-isolate
    effect: permit
    roles: [admin]
    commands: [isolate]
`)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	now := time.Now().UTC()
	pending, err := store.CreatePendingCommand(context.Background(), storepg.PendingCommand{
		ID: "pending-laundering-test", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		DeviceID: "dev-1", Hostname: "web-01",
		CommandType: "isolate", Payload: "{}",
		RequestedBy: agent.Identity(), RequiredApprovals: 1,
		ProposedByAgent: agent.Name, ProposalModel: agent.Model,
		ProposalReasoning: "Recorded while a wider policy was in force.",
	})
	if err != nil {
		t.Fatal(err)
	}

	// A human with admin authority approves. The re-evaluation must still see
	// an agent-originated request and refuse it.
	_, decision, err := s.issueApproved(context.Background(), pending, "user:alice", time.Now().UTC())
	if err != nil {
		t.Fatalf("issueApproved: %v", err)
	}
	if decision.Allowed() {
		t.Fatal("an admin approval promoted an agent proposal past a rule that bounds agents")
	}

	// And nothing was signed.
	cmds, err := store.ListCommands(context.Background(), "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 0 {
		t.Errorf("a laundered proposal produced %d signed command(s)", len(cmds))
	}
}

// A human's own request still self-approves. The agent asymmetry must not
// have made the human path worse.
func TestAHumanRequestStillCountsItsOwnApproval(t *testing.T) {
	_, store := agentServer(t, agentPolicy)
	now := time.Now().UTC()
	pending, err := store.CreatePendingCommand(context.Background(), storepg.PendingCommand{
		ID: "pending-human", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		DeviceID: "dev-1", CommandType: "isolate", Payload: "{}",
		RequestedBy: "user:alice", RequiredApprovals: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pending.Approvals) != 1 || pending.Approvals[0] != "user:alice" {
		t.Errorf("approvals = %v, want the human requester's own", pending.Approvals)
	}
}

// The ledger has to answer "what recommended this", not only "who approved
// it". That is the whole audit value of the phase.
func TestTheLedgerRecordsTheModelReasoningAndEvidence(t *testing.T) {
	s, store := agentServer(t, agentPolicy)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	const reasoning = "Alert a-1 matched a reverse-shell rule and the parent was a web server."
	if _, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1",
		Reasoning: reasoning,
		Evidence:  []string{"alert:a-1", "host:dev-1"},
		Prompt:    "Triage open detection alerts and recommend containment.",
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := store.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, e := range entries {
		if e["action"] == "agent_proposal_recorded" {
			found = e
			break
		}
	}
	if found == nil {
		t.Fatal("no proposal was written to the ledger")
	}
	if actor, _ := found["actor"].(string); actor != "agent:triage" {
		t.Errorf("actor = %q, want agent:triage — an agent must not be recorded as a person", actor)
	}
	blob, _ := json.Marshal(found)
	for _, want := range []string{
		reasoning,       // what it argued
		"some-model-v1", // which model
		"alert:a-1",     // what it cited
		"Triage open",   // what it was asked
		"self-reported", // and that the model claim is not attested
	} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("the ledger entry does not carry %q: %s", want, blob)
		}
	}
}

// An agent token is not a weak session. It must be invisible to the admin
// API, not merely under-privileged there.
func TestAnAgentTokenIsNotACallerTheAdminAPICanSee(t *testing.T) {
	s, store := agentServer(t, agentPolicy)
	_, token := newAgent(t, store, "triage")

	// resolveActor is what every admin endpoint funnels through.
	req := httptest.NewRequest(http.MethodGet, "/v1/alerts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	actor := s.resolveActor(req)
	if actor.Role != "" {
		t.Errorf("an agent token resolved to role %q; it must not be an admin-API caller at all", actor.Role)
	}

	// And the endpoints refuse it.
	for _, tc := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/v1/alerts", s.HandleAlerts},
		{"/v1/agents", s.HandleAgents},
		{"/v1/policy/approvals", s.HandleApprovals},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		tc.handler(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d to an agent token, want 401", tc.path, rec.Code)
		}
	}
}

// A revoked principal must stop working immediately, and the record must
// survive so an auditor can see it existed.
func TestRevokingAnAgentStopsItButKeepsTheRecord(t *testing.T) {
	s, store := agentServer(t, agentPolicy)
	agent, token := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	if _, err := store.LookupAgentToken(context.Background(), token); err != nil {
		t.Fatalf("the fresh token does not work: %v", err)
	}
	if _, err := store.RevokeAgentPrincipal(context.Background(), "triage", "user:alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupAgentToken(context.Background(), token); err == nil {
		t.Error("a revoked token still authenticates")
	}

	// Still listed, with the revocation recorded.
	agents, err := store.ListAgentPrincipals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 {
		t.Fatalf("got %d principals, want the revoked one kept", len(agents))
	}
	if agents[0].RevokedAt.IsZero() || agents[0].RevokedBy != "user:alice" {
		t.Errorf("the revocation is not recorded: %+v", agents[0])
	}

	// And it cannot propose.
	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1", Reasoning: "still trying",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "denied" {
		t.Errorf("a revoked agent's proposal was %q, want denied", outcome.Status)
	}
}

// The bounded command set is bounded. run_script is arbitrary code and
// agent_update replaces the agent enforcing everything else; neither belongs
// in a set an AI can name, whatever policy would say afterwards.
func TestRunScriptAndAgentUpdateAreNotProposable(t *testing.T) {
	s, store := agentServer(t, `
version: 1
name: permits-everything
rules:
  - id: permit-all
    effect: permit
    commands: [isolate, run_script, agent_update, live_query]
`)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	for _, cmd := range []string{"run_script", "agent_update"} {
		outcome, err := s.Propose(context.Background(), agent, Proposal{
			CommandType: cmd, DeviceID: "dev-1",
			Payload:   json.RawMessage(`{"script":"echo hi"}`),
			Reasoning: "policy allows it",
		})
		if err != nil {
			t.Fatal(err)
		}
		if outcome.Status != "invalid" {
			t.Errorf("%s was %q, want invalid: a bounded set that includes arbitrary code is not bounded",
				cmd, outcome.Status)
		}
	}
}

// A proposal with no stated case cannot be reviewed on its merits, so it is
// refused rather than put in front of an operator.
func TestAProposalWithNoReasoningIsRefused(t *testing.T) {
	s, store := agentServer(t, agentPolicy)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "invalid" {
		t.Errorf("status = %q, want invalid", outcome.Status)
	}
}

// A principal with no declared model makes "what recommended this"
// unanswerable from the start.
func TestAnAgentMustDeclareItsModel(t *testing.T) {
	_, store := agentServer(t, agentPolicy)
	if _, _, err := store.CreateAgentPrincipal(context.Background(),
		"nameless", "", "", "user:alice"); err == nil {
		t.Error("a principal with no declared model was accepted")
	}
}

// Break-glass is a human declaring an emergency. Letting it widen what an AI
// may propose would turn the worst moment to be careful into the moment the
// bounds came off.
func TestBreakGlassDoesNotWidenWhatAnAgentMayPropose(t *testing.T) {
	s, store := agentServer(t, `
version: 1
name: break-glass-widens-for-humans
rules:
  - id: agents-query-only
    effect: permit
    roles: [agent]
    commands: [live_query]
  - id: admins-may-isolate
    effect: permit
    roles: [admin]
    commands: [isolate]
`)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	now := time.Now().UTC()
	if _, err := store.OpenBreakGlass(context.Background(), policy.BreakGlass{
		ID:            "bg-1",
		Justification: "incident 42, containment authorised by the on-call lead",
		OpenedBy:      "user:alice",
		OpenedAt:      now,
		ExpiresAt:     now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("open break-glass: %v", err)
	}

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1",
		Reasoning: "there is an active incident",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "denied" {
		t.Errorf("status = %q: an emergency must not widen an agent's bounds", outcome.Status)
	}
}
