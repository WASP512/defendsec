package policy

import (
	"strings"
	"testing"
	"time"
)

// Phase 2 acceptance: "blast-radius limits demonstrably stop a runaway
// playbook".
//
// A runaway is the case the limits exist for: a playbook that triggers on a
// finding it causes, firing repeatedly across the estate. Each step is
// individually policy-checked, so the limit has to bite partway through and
// keep biting — not merely be present in the document.
func TestBlastRadiusStopsARunawayPlaybook(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: runaway
rules:
  - id: allow-response
    effect: permit
    commands: [isolate, quarantine_path]
limits:
  - id: isolate-fleet-hourly
    commands: [isolate]
    scope: fleet
    max: 3
    per: 1h
`))

	// Simulate the loop: a playbook isolating a different host each time, as
	// findings cascade across the fleet. The engine sees the count climb.
	var issued, stopped int
	fleetCount := 0
	for host := 0; host < 25; host++ {
		r := req("isolate")
		r.DeviceID = "dev-" + string(rune('a'+host%26))
		count := fleetCount
		d, err := e.Evaluate(r, func(_ []string, _ time.Time, _ string) (Usage, error) {
			return Usage{FleetCount: count}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			issued++
			fleetCount++
			continue
		}
		stopped++
		if d.LimitExceeded != "isolate-fleet-hourly" {
			t.Fatalf("host %d stopped for the wrong reason: %+v", host, d)
		}
	}

	if issued != 3 {
		t.Fatalf("the runaway issued %d isolates, want exactly the limit of 3", issued)
	}
	if stopped != 22 {
		t.Fatalf("the limit stopped %d attempts, want the remaining 22", stopped)
	}

	// And it must keep refusing rather than resetting once it has fired.
	d, _ := e.Evaluate(req("isolate"), func(_ []string, _ time.Time, _ string) (Usage, error) {
		return Usage{FleetCount: fleetCount}, nil
	})
	if d.Allowed() {
		t.Fatal("the limit released after being hit")
	}
}

// Phase 2 acceptance: "a two-person command cannot be signed with one
// approval". Asserted against every way one person might try to reach two.
func TestTwoPersonCannotBeSatisfiedAlone(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: acceptance
rules:
  - id: needs-two
    effect: permit
    commands: [isolate]
    require_approvals: 2
`))

	attempts := map[string][]string{
		"one approval":        {"user:alice"},
		"repeated":            {"user:alice", "user:alice"},
		"repeated with space": {"user:alice", " user:alice"},
		"padded with blanks":  {"user:alice", "", "  "},
		"no approvals":        nil,
	}
	for name, approvals := range attempts {
		r := req("isolate")
		r.Approvals = approvals
		d, err := e.Evaluate(r, noUsage)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			t.Errorf("%s: signed a two-person command alone", name)
		}
		if d.Effect != EffectRequireApproval {
			t.Errorf("%s: effect = %s", name, d.Effect)
		}
	}

	// A genuinely distinct second approver is the only thing that works.
	r := req("isolate")
	r.Approvals = []string{"user:alice", "user:bob"}
	if d, _ := e.Evaluate(r, noUsage); !d.Allowed() {
		t.Error("two distinct administrators were refused")
	}
}

// Phase 2 acceptance: "a policy denial is impossible to bypass through the
// API". The engine-level half of that: nothing in a Request can turn a denial
// into a permit.
func TestNothingInARequestOverridesAnExplicitDeny(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: acceptance
rules:
  - id: allow-everything-else
    effect: permit
    commands: ["*"]
  - id: never-on-critical
    effect: deny
    commands: [kill_process]
    host_classes: [critical]
    reason: this host runs the estate
`))

	base := func() Request {
		r := req("kill_process")
		r.HostClasses = []string{"critical"}
		return r
	}

	attempts := map[string]func(*Request){
		"break-glass": func(r *Request) {
			r.BreakGlass = &BreakGlass{
				ID: "bg", Justification: "urgent", OpenedBy: "user:alice",
				OpenedAt: r.At.Add(-time.Minute), ExpiresAt: r.At.Add(time.Hour),
			}
		},
		"many approvals": func(r *Request) {
			r.Approvals = []string{"user:alice", "user:bob", "user:carol", "user:dave"}
		},
		"another role":  func(r *Request) { r.Role = "superuser" },
		"another actor": func(r *Request) { r.Actor = "user:root" },
		"class listed alongside others": func(r *Request) {
			r.HostClasses = []string{"lab", "critical", "production"}
		},
		"class cased differently": func(r *Request) { r.HostClasses = []string{"CRITICAL"} },
		"everything at once": func(r *Request) {
			r.Role, r.Actor = "superuser", "user:root"
			r.Approvals = []string{"user:alice", "user:bob"}
			r.BreakGlass = &BreakGlass{
				ID: "bg", Justification: "urgent", OpenedBy: "user:alice",
				OpenedAt: r.At.Add(-time.Minute), ExpiresAt: r.At.Add(time.Hour),
			}
		},
	}
	for name, mutate := range attempts {
		r := base()
		mutate(&r)
		d, err := e.Evaluate(r, noUsage)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			t.Errorf("%s: bypassed an explicit deny", name)
		}
		if d.RuleID != "never-on-critical" {
			t.Errorf("%s: decided by %q", name, d.RuleID)
		}
	}
}

// Every decision must carry enough to reconstruct why, since it is what lands
// in the ledger.
func TestEveryDecisionIsSelfExplaining(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: explaining
rules:
  - id: allow
    effect: permit
    commands: [isolate]
  - id: two
    effect: permit
    commands: [run_script]
    require_approvals: 2
  - id: never
    effect: deny
    commands: [kill_process]
    reason: not on this estate
limits:
  - id: capped
    commands: [isolate]
    scope: fleet
    max: 1
    per: 1h
`))

	cases := map[string]struct {
		cmd   string
		usage UsageFunc
	}{
		"permit":          {"isolate", usageOf(0, 0)},
		"deny by rule":    {"kill_process", noUsage},
		"deny by default": {"live_query", noUsage},
		"deny by limit":   {"isolate", usageOf(9, 0)},
		"needs approval":  {"run_script", noUsage},
	}
	for name, tc := range cases {
		d, err := e.Evaluate(req(tc.cmd), tc.usage)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("%s: no reason", name)
		}
		if d.PolicyHash == "" || d.PolicyName == "" {
			t.Errorf("%s: does not identify the policy that decided", name)
		}
		if d.Effect == "" {
			t.Errorf("%s: no effect", name)
		}
	}
}
