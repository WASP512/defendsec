package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"defendsec/internal/storepg"
)

// Bounded autonomy, end to end (roadmap 4.4).
//
// Autonomy is the most consequential thing an operator can configure here, so
// the tests that matter are the ones establishing it stays off: both switches
// are required, the default is off, the blast-radius ceiling still bites, and
// revoking either half stops it immediately.

const autonomyPolicy = `
version: 1
name: bounded-autonomy
rules:
  - id: agents-query-autonomously
    effect: permit
    roles: [agent]
    commands: [live_query]
    autonomous: true
  - id: agents-isolate-with-a-human
    effect: permit
    roles: [agent]
    commands: [isolate]
limits:
  - id: query-hourly
    commands: [live_query]
    scope: fleet
    max: 3
    per: 1h
`

// grantAutonomy enables the per-principal half.
func grantAutonomy(t *testing.T, store *storepg.Store, name string) storepg.AgentPrincipal {
	t.Helper()
	agent, err := store.SetAgentAutonomy(context.Background(), name, true, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	if !agent.AutonomyEnabled {
		t.Fatal("autonomy was not enabled")
	}
	return agent
}

// A freshly registered agent must not act, even where the rule allows it.
func TestAutonomyIsOffForANewPrincipal(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	if agent.AutonomyEnabled {
		t.Fatal("a new principal was created with autonomy already enabled")
	}
	if agent.MayActAutonomously() {
		t.Fatal("a new principal may act autonomously")
	}

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "live_query", DeviceID: "dev-1",
		Payload:   json.RawMessage(`{"queryId":"q1"}`),
		Reasoning: "checking listening ports",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "awaiting-approval" {
		t.Fatalf("status = %q, want awaiting-approval: an autonomous rule alone must not let an agent act", outcome.Status)
	}
}

// Both switches on: it runs, and the command is signed and attributed.
func TestBothSwitchesOnExecutesAndAttributesToTheAgent(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "live_query", DeviceID: "dev-1",
		Payload:   json.RawMessage(`{"queryId":"q1"}`),
		Reasoning: "checking listening ports after a detection",
		Evidence:  []string{"alert:a-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "executed" {
		t.Fatalf("status = %q, detail = %q", outcome.Status, outcome.Detail)
	}
	if outcome.CommandID == "" {
		t.Fatal("no command id was returned")
	}

	// A real signed command exists, attributed to the agent rather than to a
	// person who did not authorise it.
	cmds, err := store.ListCommands(context.Background(), "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) != 1 {
		t.Fatalf("got %d commands, want 1", len(cmds))
	}
	cmd := cmds[0]
	if cmd.Signature == "" {
		t.Error("the autonomous command carries no signature")
	}
	if cmd.ActorIdentity != "agent:triage" {
		t.Errorf("actor = %q, want agent:triage", cmd.ActorIdentity)
	}

	// And the ledger distinguishes it from a human-authorised command, so
	// "what did the AI do by itself" is answerable by filtering.
	entries, err := store.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, e := range entries {
		if e["action"] == "agent_autonomous_action" {
			found = e
			break
		}
	}
	if found == nil {
		t.Fatal("the autonomous action was not recorded under its own audit action")
	}
	blob, _ := json.Marshal(found)
	for _, want := range []string{
		"some-model-v1",
		"agents-query-autonomously",
		"checking listening ports",
		"self-reported",
	} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("the ledger entry does not carry %q: %s", want, blob)
		}
	}
}

// Autonomy applies per rule. A principal with autonomy enabled still waits
// for a human on a command whose rule is not marked autonomous.
func TestAutonomyDoesNotLeakToOtherRules(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "isolate", DeviceID: "dev-1",
		Reasoning: "it looks compromised",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "awaiting-approval" {
		t.Fatalf("status = %q: isolate is not an autonomous rule and must still need a human", outcome.Status)
	}
	// And nothing was signed.
	cmds, _ := store.ListCommands(context.Background(), "dev-1")
	if len(cmds) != 0 {
		t.Errorf("a non-autonomous rule produced %d signed command(s)", len(cmds))
	}
}

// The ceiling is the whole claim. An autonomous agent must stop at it.
func TestTheBlastRadiusCeilingStopsAnAutonomousAgent(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")
	for i, id := range []string{"dev-1", "dev-2", "dev-3", "dev-4", "dev-5"} {
		enrolHost(t, s, id, "web-0"+string(rune('1'+i)))
	}

	var executed, stopped int
	for _, id := range []string{"dev-1", "dev-2", "dev-3", "dev-4", "dev-5"} {
		outcome, err := s.Propose(context.Background(), agent, Proposal{
			CommandType: "live_query", DeviceID: id,
			Payload:   json.RawMessage(`{"queryId":"q1"}`),
			Reasoning: "sweeping the fleet",
		})
		if err != nil {
			t.Fatal(err)
		}
		switch outcome.Status {
		case "executed":
			executed++
		case "denied":
			stopped++
		default:
			t.Fatalf("unexpected status %q: %s", outcome.Status, outcome.Detail)
		}
	}
	// The limit is 3 per hour across the fleet.
	if executed != 3 {
		t.Errorf("an autonomous agent executed %d times, want exactly the limit of 3", executed)
	}
	if stopped != 2 {
		t.Errorf("stopped %d, want 2", stopped)
	}
}

// Withdrawing autonomy from one principal must take effect at once and must
// not require touching the policy document that governs the others.
func TestWithdrawingAutonomyStopsItImmediately(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	first, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "live_query", DeviceID: "dev-1",
		Payload: json.RawMessage(`{"queryId":"q1"}`), Reasoning: "one",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "executed" {
		t.Fatalf("first proposal = %q", first.Status)
	}

	if _, err := store.SetAgentAutonomy(context.Background(), "triage", false, "user:alice"); err != nil {
		t.Fatal(err)
	}

	// The caller still holds the stale principal with autonomy enabled. It
	// must not matter: Propose re-reads the principal, so the withdrawal
	// binds on the next call rather than on the next restart.
	second, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "live_query", DeviceID: "dev-1",
		Payload: json.RawMessage(`{"queryId":"q1"}`), Reasoning: "two",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != "awaiting-approval" {
		t.Fatalf("second proposal = %q, want awaiting-approval after withdrawal", second.Status)
	}
}

// Revoking the principal entirely stops autonomy too.
func TestRevokingThePrincipalStopsAutonomy(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	if _, err := store.RevokeAgentPrincipal(context.Background(), "triage", "user:alice"); err != nil {
		t.Fatal(err)
	}
	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "live_query", DeviceID: "dev-1",
		Payload: json.RawMessage(`{"queryId":"q1"}`), Reasoning: "still trying",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "denied" {
		t.Errorf("status = %q, want denied", outcome.Status)
	}
}

// A revoked principal must not be grantable autonomy: the row would be inert
// but self-contradictory, and somebody later has to reason about it.
func TestARevokedPrincipalCannotBeGrantedAutonomy(t *testing.T) {
	_, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	if _, err := store.RevokeAgentPrincipal(context.Background(), "triage", "user:alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetAgentAutonomy(context.Background(), "triage", true, "user:alice"); err == nil {
		t.Error("a revoked principal was granted autonomy")
	}
}

// Withdrawal must work on an already-disabled principal: an operator pulling
// autonomy from something dormant should succeed, not be told the state they
// want is unreachable.
func TestAutonomyCanBeWithdrawnFromARevokedPrincipal(t *testing.T) {
	_, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	grantAutonomy(t, store, "triage")
	if _, err := store.RevokeAgentPrincipal(context.Background(), "triage", "user:alice"); err != nil {
		t.Fatal(err)
	}
	agent, err := store.SetAgentAutonomy(context.Background(), "triage", false, "user:alice")
	if err != nil {
		t.Fatalf("withdrawing autonomy from a revoked principal failed: %v", err)
	}
	if agent.AutonomyEnabled {
		t.Error("autonomy is still enabled")
	}
}

// The grant is itself evidence, not a bare boolean.
func TestTheAutonomyGrantIsRecorded(t *testing.T) {
	_, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")

	if agent.AutonomyGrantedBy != "user:alice" {
		t.Errorf("grantedBy = %q", agent.AutonomyGrantedBy)
	}
	if agent.AutonomyGrantedAt.IsZero() {
		t.Error("the grant has no timestamp")
	}
	if time.Since(agent.AutonomyGrantedAt) > time.Minute {
		t.Errorf("grantedAt = %v, which is not recent", agent.AutonomyGrantedAt)
	}
}

// A policy silent about a command denies an autonomous agent as readily as
// any other caller. Deny-by-default is not suspended by autonomy.
func TestAutonomyDoesNotSuspendDenyByDefault(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	newAgent(t, store, "triage")
	agent := grantAutonomy(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	outcome, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "kill_process", DeviceID: "dev-1",
		Payload: json.RawMessage(`{"pid":1234}`), Reasoning: "it looks bad",
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Status != "denied" {
		t.Errorf("status = %q, want denied: no rule permits kill_process", outcome.Status)
	}
}

// When a proposal waits rather than running, the ledger says which switch was
// off — an operator who expected autonomy should not have to read two
// configuration sources to find out why it did not happen.
func TestTheLedgerSaysWhyAutonomyDidNotApply(t *testing.T) {
	s, store := agentServer(t, autonomyPolicy)
	agent, _ := newAgent(t, store, "triage")
	enrolHost(t, s, "dev-1", "web-01")

	if _, err := s.Propose(context.Background(), agent, Proposal{
		CommandType: "live_query", DeviceID: "dev-1",
		Payload: json.RawMessage(`{"queryId":"q1"}`), Reasoning: "why did this wait",
	}); err != nil {
		t.Fatal(err)
	}

	entries, err := store.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e["action"] != "agent_proposal_recorded" {
			continue
		}
		blob, _ := json.Marshal(e)
		if !strings.Contains(string(blob), "not enabled for this agent principal") {
			t.Errorf("the ledger does not name the missing switch: %s", blob)
		}
		return
	}
	t.Fatal("no proposal was recorded")
}
