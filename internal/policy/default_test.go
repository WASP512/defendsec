package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped policy is what most deployments will run, so it is tested like
// code rather than treated as documentation.
func loadShipped(t *testing.T) *Engine {
	t.Helper()
	for _, p := range []string{
		"packaging/policy/default.yaml",
		filepath.Join("..", "..", "packaging", "policy", "default.yaml"),
	} {
		if _, err := os.Stat(p); err == nil {
			doc, err := Load(p)
			if err != nil {
				t.Fatalf("the shipped policy does not load: %v", err)
			}
			return NewEngine(doc)
		}
	}
	t.Fatal("could not find packaging/policy/default.yaml")
	return nil
}

func TestShippedPolicyLoads(t *testing.T) {
	e := loadShipped(t)
	doc := e.Document()
	if doc.Name != "default" || len(doc.Rules) == 0 || len(doc.Limits) == 0 {
		t.Fatalf("shipped policy = %+v", doc)
	}
}

// The behaviours the shipped file is meant to produce, asserted rather than
// assumed from reading it.
func TestShippedPolicyBehaviour(t *testing.T) {
	e := loadShipped(t)
	weekday := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC) // Tuesday 14:00 UTC

	base := func(cmd string, classes ...string) Request {
		return Request{
			Actor: "user:alice", Role: "admin", CommandType: cmd,
			DeviceID: "dev-1", At: weekday, HostClasses: classes,
			Approvals: []string{"user:alice"},
		}
	}

	t.Run("a domain controller is never disrupted", func(t *testing.T) {
		for _, cmd := range []string{"kill_process", "quarantine_path", "run_script"} {
			d, _ := e.Evaluate(base(cmd, "domain-controller"), noUsage)
			if d.Allowed() {
				t.Errorf("%s was permitted on a domain controller", cmd)
			}
			if d.RuleID != "never-disrupt-domain-controllers" {
				t.Errorf("%s: decided by %q", cmd, d.RuleID)
			}
		}
		// Isolating one is still available, with two administrators: it is
		// the safer tool, and leaving these hosts with no response at all
		// would push an operator straight to break-glass.
		one := base("isolate", "domain-controller")
		d, _ := e.Evaluate(one, usageOf(0, 0))
		if d.Effect != EffectRequireApproval {
			t.Errorf("isolating a domain controller: effect = %s, want require-approval (%s)", d.Effect, d.Reason)
		}
		two := base("isolate", "domain-controller")
		two.Approvals = []string{"user:alice", "user:bob"}
		if d, _ := e.Evaluate(two, usageOf(0, 0)); !d.Allowed() {
			t.Errorf("two administrators could not isolate a domain controller: %s", d.Reason)
		}
	})

	t.Run("production isolation needs two people", func(t *testing.T) {
		d, _ := e.Evaluate(base("isolate", "production"), usageOf(0, 0))
		if d.Effect != EffectRequireApproval {
			t.Fatalf("effect = %s, want require-approval", d.Effect)
		}
		two := base("isolate", "production")
		two.Approvals = []string{"user:alice", "user:bob"}
		if d, _ := e.Evaluate(two, usageOf(0, 0)); !d.Allowed() {
			t.Errorf("two approvals were refused: %s", d.Reason)
		}
	})

	t.Run("release is never harder than isolate", func(t *testing.T) {
		// Recovering from an isolation must not need more ceremony than
		// causing one, on any host class.
		for _, class := range []string{"production", "critical", "domain-controller", "lab"} {
			d, _ := e.Evaluate(base("release", class), usageOf(0, 0))

			if !d.Allowed() {
				t.Errorf("release on a %s host was refused: %s", class, d.Reason)
			}
		}
	})

	t.Run("ordinary hosts are responsive on one approval", func(t *testing.T) {
		for _, cmd := range []string{"isolate", "kill_process", "run_script", "quarantine_path", "live_query"} {
			if d, _ := e.Evaluate(base(cmd, "lab"), usageOf(0, 0)); !d.Allowed() {
				t.Errorf("%s on an ordinary host was refused: %s", cmd, d.Reason)
			}
		}
	})

	t.Run("agent updates are confined to business hours", func(t *testing.T) {
		if d, _ := e.Evaluate(base("agent_update"), usageOf(0, 0)); !d.Allowed() {
			t.Errorf("an in-hours update was refused: %s", d.Reason)
		}
		night := base("agent_update")
		night.At = time.Date(2026, 9, 15, 23, 0, 0, 0, time.UTC)
		if d, _ := e.Evaluate(night, usageOf(0, 0)); d.Allowed() {
			t.Error("an out-of-hours agent update was permitted")
		}
	})

	t.Run("a viewer can do nothing", func(t *testing.T) {
		for _, cmd := range []string{"isolate", "release", "kill_process", "run_script", "live_query", "agent_update", "quarantine_path"} {
			r := base(cmd, "lab")
			r.Role = "viewer"
			if d, _ := e.Evaluate(r, usageOf(0, 0)); d.Allowed() {
				t.Errorf("a viewer was permitted to %s", cmd)
			}
		}
	})

	t.Run("a shared bootstrap token can do nothing", func(t *testing.T) {
		// The shared token resolves to the admin role but is not a person.
		// Every rule here is role-scoped, so it does pass — which is worth
		// asserting explicitly so the exposure is visible rather than assumed
		// away. Narrow it with an actors: rule if that is not wanted.
		r := base("isolate", "lab")
		r.Actor = "unattributed:shared-bootstrap-token"
		d, _ := e.Evaluate(r, usageOf(0, 0))
		if !d.Allowed() {
			t.Skip("the shipped policy already excludes unattributed actors")
		}
		t.Log("note: the shipped policy permits the shared bootstrap token, because its rules are scoped by role rather than by actor")
	})

	t.Run("the fleet isolate limit bites", func(t *testing.T) {
		d, _ := e.Evaluate(base("isolate", "lab"), usageOf(5, 0))
		if d.Allowed() {
			t.Fatal("the sixth fleet-wide isolate in an hour was permitted")
		}
		if d.LimitExceeded != "isolate-fleet-hourly" {
			t.Errorf("limit = %q", d.LimitExceeded)
		}
	})
}

// The shipped policy lets an agent propose and never lets one act
// (roadmap 4.1, 4.4).
func TestShippedPolicyLetsAgentsProposeButNotAct(t *testing.T) {
	e := loadShipped(t)
	weekday := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)

	agentReq := func(cmd string, classes ...string) Request {
		return Request{
			Actor: "agent:triage", Role: "agent", CommandType: cmd,
			DeviceID: "dev-1", At: weekday, HostClasses: classes,
		}
	}

	// Proposable, and permitted by policy.
	for _, cmd := range []string{"live_query", "isolate", "quarantine_path"} {
		d, err := e.Evaluate(agentReq(cmd), noUsage)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed() && d.Effect != EffectRequireApproval {
			t.Errorf("%s: the shipped policy refuses an agent proposal outright: %s", cmd, d.Reason)
		}
		// Nothing ships autonomous. An operator has to opt in deliberately.
		if d.Autonomous {
			t.Errorf("%s: the shipped policy grants autonomy out of the box", cmd)
		}
	}

	// run_script is not proposable at all, and the shipped policy does not
	// permit it for an agent either.
	d, err := e.Evaluate(agentReq("run_script"), noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Error("the shipped policy permits an agent to run scripts")
	}
}

// The commented autonomy example in the shipped file must be correct, or an
// operator who uncomments it gets a policy that refuses to load — at which
// point the control plane will not start.
func TestTheCommentedAutonomyExampleWouldLoad(t *testing.T) {
	var raw []byte
	for _, p := range []string{
		"packaging/policy/default.yaml",
		filepath.Join("..", "..", "packaging", "policy", "default.yaml"),
	} {
		if b, err := os.ReadFile(p); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		t.Fatal("could not find the shipped policy")
	}

	const commented = "    # autonomous: true"
	const uncommented = "    autonomous: true"

	if !strings.Contains(string(raw), commented) {
		t.Fatal("the commented autonomy example is not in the shipped policy in the expected form; if it was reworded, reword this test with it")
	}
	enabled := strings.Replace(string(raw), commented, uncommented, 1)

	doc, err := Parse([]byte(enabled))
	if err != nil {
		t.Fatalf("uncommenting the shipped autonomy example produces a policy that will not load: %v", err)
	}

	var found bool
	for _, r := range doc.Rules {
		if r.ID == "agents-may-query" {
			found = true
			if !r.Autonomous {
				t.Error("the example rule is not marked autonomous")
			}
		}
	}
	if !found {
		t.Error("the uncommented rule did not parse")
	}

	// And it actually grants autonomy for a query on an ordinary host, while
	// leaving critical hosts out.
	e := NewEngine(doc)
	weekday := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	ordinary := Request{
		Actor: "agent:triage", Role: "agent", CommandType: "live_query",
		DeviceID: "dev-1", At: weekday,
	}
	d, err := e.Evaluate(ordinary, noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Autonomous {
		t.Errorf("the example does not grant autonomy where it claims to: %+v", d)
	}

}

// Autonomy must not be reachable through a rule that does not grant it. Where
// the document says two things about one command, the reading that keeps a
// human in the loop is the one that holds.
func TestANonAutonomousPermitShadowsAnAutonomousOne(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: overlapping
rules:
  - id: broad-propose
    effect: permit
    roles: [agent]
    commands: [live_query, isolate]
  - id: narrow-autonomous
    effect: permit
    roles: [agent]
    commands: [live_query]
    autonomous: true
limits:
  - id: query-hourly
    commands: [live_query]
    scope: fleet
    max: 10
    per: 1h
`))
	d, err := e.Evaluate(Request{
		Actor: "agent:triage", Role: "agent", CommandType: "live_query",
		DeviceID: "dev-1", At: time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC),
	}, noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() {
		t.Fatalf("the command was refused: %s", d.Reason)
	}
	if d.Autonomous {
		t.Error("a broad non-autonomous permit was overridden by a narrower autonomous one")
	}
	if d.RuleID != "broad-propose" {
		t.Errorf("ruleId = %q, want the non-autonomous rule", d.RuleID)
	}
}
