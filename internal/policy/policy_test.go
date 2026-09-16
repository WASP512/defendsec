package policy

import (
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, doc string) *Document {
	t.Helper()
	d, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func noUsage(_ []string, _ time.Time, _ string) (Usage, error) { return Usage{}, nil }

var at = time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC) // a Tuesday afternoon

func req(cmdType string) Request {
	return Request{
		Actor: "user:alice", Role: "admin", CommandType: cmdType,
		DeviceID: "dev-1", Hostname: "host-1", At: at,
		Approvals: []string{"user:alice"},
	}
}

// The property the whole phase rests on: nothing is permitted unless a rule
// permits it.
func TestDenyByDefault(t *testing.T) {
	doc := mustParse(t, `
version: 1
name: minimal
rules:
  - id: allow-live-query
    effect: permit
    commands: [live_query]
`)
	e := NewEngine(doc)

	d, err := e.Evaluate(req("live_query"), noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() {
		t.Fatalf("the permitted command was denied: %s", d.Reason)
	}

	// Every other command type must be denied without anyone having written
	// a rule about it. That is the point: a capability added tomorrow is not
	// live the moment it exists.
	for _, cmd := range []string{"isolate", "kill_process", "run_script", "quarantine_path", "agent_update", "release", "something_new"} {
		d, err := e.Evaluate(req(cmd), noUsage)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			t.Errorf("%s was permitted with no rule allowing it", cmd)
		}
		if d.RuleID != "" {
			t.Errorf("%s: a denial by default named rule %q", cmd, d.RuleID)
		}
		if !strings.Contains(d.Reason, "denies by default") {
			t.Errorf("%s: reason does not explain the default: %q", cmd, d.Reason)
		}
	}
}

// An unconfigured deployment must refuse, not allow everything.
func TestNoPolicyDeniesEverything(t *testing.T) {
	for _, e := range []*Engine{nil, NewEngine(nil), {}} {
		d, err := e.Evaluate(req("isolate"), noUsage)
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			t.Fatal("an engine with no policy permitted a command")
		}
		if !strings.Contains(d.Reason, "No policy is loaded") {
			t.Errorf("reason = %q", d.Reason)
		}
	}
}

// An explicit deny must beat an allow regardless of order, or a rule appended
// to the bottom of a file quietly re-enables what a security rule forbade.
func TestExplicitDenyBeatsPermitInEitherOrder(t *testing.T) {
	denyFirst := `
version: 1
name: order
rules:
  - id: no-kill-on-critical
    effect: deny
    commands: [kill_process]
    host_classes: [critical]
    reason: killing processes on a domain controller takes the estate down
  - id: admins-may-kill
    effect: permit
    commands: [kill_process]
    roles: [admin]
`
	permitFirst := `
version: 1
name: order
rules:
  - id: admins-may-kill
    effect: permit
    commands: [kill_process]
    roles: [admin]
  - id: no-kill-on-critical
    effect: deny
    commands: [kill_process]
    host_classes: [critical]
    reason: killing processes on a domain controller takes the estate down
`
	for name, src := range map[string]string{"deny first": denyFirst, "permit first": permitFirst} {
		t.Run(name, func(t *testing.T) {
			e := NewEngine(mustParse(t, src))

			r := req("kill_process")
			r.HostClasses = []string{"critical"}
			d, err := e.Evaluate(r, noUsage)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed() {
				t.Fatal("a critical host was killable despite an explicit deny")
			}
			if d.RuleID != "no-kill-on-critical" {
				t.Errorf("decided by %q", d.RuleID)
			}
			// The operator must be able to understand the refusal, or it
			// becomes a ticket and then a bypass.
			if !strings.Contains(d.Reason, "takes the estate down") {
				t.Errorf("reason does not carry the rule's explanation: %q", d.Reason)
			}

			// An unclassified host is still permitted by the allow rule.
			plain := req("kill_process")
			d, err = e.Evaluate(plain, noUsage)
			if err != nil {
				t.Fatal(err)
			}
			if !d.Allowed() {
				t.Errorf("an ordinary host was denied: %s", d.Reason)
			}
		})
	}
}

func TestRoleAndActorScoping(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: scoping
rules:
  - id: admins-isolate
    effect: permit
    commands: [isolate]
    roles: [admin]
  - id: named-responder-may-script
    effect: permit
    commands: [run_script]
    actors: ["user:alice"]
`))

	viewer := req("isolate")
	viewer.Role = "viewer"
	if d, _ := e.Evaluate(viewer, noUsage); d.Allowed() {
		t.Error("a viewer issued an isolate")
	}

	if d, _ := e.Evaluate(req("isolate"), noUsage); !d.Allowed() {
		t.Error("an admin could not isolate")
	}

	if d, _ := e.Evaluate(req("run_script"), noUsage); !d.Allowed() {
		t.Error("the named actor could not run a script")
	}
	other := req("run_script")
	other.Actor = "user:bob"
	if d, _ := e.Evaluate(other, noUsage); d.Allowed() {
		t.Error("an actor the rule does not name ran a script")
	}

	// A shared token is not a person, and must not inherit a person's rule.
	shared := req("run_script")
	shared.Actor = "unattributed:shared-bootstrap-token"
	if d, _ := e.Evaluate(shared, noUsage); d.Allowed() {
		t.Error("an unattributed actor matched an actor-scoped rule")
	}
}

func TestHostClassMatching(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: classes
rules:
  - id: isolate-non-production
    effect: permit
    commands: [isolate]
    exclude_host_classes: [production]
  - id: isolate-production-explicitly
    effect: permit
    commands: [isolate]
    host_classes: [production]
    require_approvals: 2
`))

	// A lab host: covered by the broad rule, one approval.
	lab := req("isolate")
	lab.HostClasses = []string{"lab"}
	d, _ := e.Evaluate(lab, noUsage)
	if !d.Allowed() || d.RuleID != "isolate-non-production" {
		t.Errorf("lab host: %+v", d)
	}

	// A production host: the excluding rule must not apply, so the stricter
	// rule is the only one left.
	prod := req("isolate")
	prod.HostClasses = []string{"production"}
	d, _ = e.Evaluate(prod, noUsage)
	if d.Effect != EffectRequireApproval {
		t.Fatalf("production host: effect = %s, want require-approval", d.Effect)
	}
	if d.RuleID != "isolate-production-explicitly" {
		t.Errorf("decided by %q", d.RuleID)
	}
}

// Where two rules both permit, the stricter one must win — otherwise adding a
// permissive rule silently removes an approval requirement.
func TestStrictestPermitWins(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: strictest
rules:
  - id: broad
    effect: permit
    commands: [isolate]
  - id: careful
    effect: permit
    commands: [isolate]
    require_approvals: 2
`))
	d, _ := e.Evaluate(req("isolate"), noUsage)
	if d.Effect != EffectRequireApproval || d.RuleID != "careful" {
		t.Fatalf("the permissive rule overrode the careful one: %+v", d)
	}
}

func TestTwoPersonIntegrity(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: two-person
rules:
  - id: isolate-needs-two
    effect: permit
    commands: [isolate]
    require_approvals: 2
`))

	one := req("isolate")
	d, _ := e.Evaluate(one, noUsage)
	if d.Effect != EffectRequireApproval {
		t.Fatalf("one approval signed a two-person command: %+v", d)
	}
	if d.RequiredApprovals != 2 || d.HaveApprovals != 1 {
		t.Errorf("counts = %d/%d", d.HaveApprovals, d.RequiredApprovals)
	}

	// The same person twice is one person.
	twice := req("isolate")
	twice.Approvals = []string{"user:alice", "user:alice", " user:alice "}
	d, _ = e.Evaluate(twice, noUsage)
	if d.Effect != EffectRequireApproval {
		t.Fatalf("one person approving repeatedly satisfied two-person integrity: %+v", d)
	}

	two := req("isolate")
	two.Approvals = []string{"user:alice", "user:bob"}
	d, _ = e.Evaluate(two, noUsage)
	if !d.Allowed() {
		t.Fatalf("two distinct approvals were refused: %s", d.Reason)
	}
	if d.HaveApprovals != 2 {
		t.Errorf("have = %d", d.HaveApprovals)
	}

	// Blank entries must not pad the count.
	padded := req("isolate")
	padded.Approvals = []string{"user:alice", "", "   "}
	if d, _ := e.Evaluate(padded, noUsage); d.Effect != EffectRequireApproval {
		t.Error("blank approvals were counted")
	}
}

func TestTimeWindows(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: windows
timezone: UTC
rules:
  - id: business-hours-only
    effect: permit
    commands: [agent_update]
    window:
      hours: "09:00-17:00"
      days: [mon, tue, wed, thu, fri]
`))

	inside := req("agent_update") // Tuesday 14:00
	if d, _ := e.Evaluate(inside, noUsage); !d.Allowed() {
		t.Error("a request inside the window was denied")
	}

	evening := req("agent_update")
	evening.At = time.Date(2026, 9, 15, 19, 0, 0, 0, time.UTC)
	if d, _ := e.Evaluate(evening, noUsage); d.Allowed() {
		t.Error("a request outside the hours was permitted")
	}

	saturday := req("agent_update")
	saturday.At = time.Date(2026, 9, 19, 14, 0, 0, 0, time.UTC)
	if d, _ := e.Evaluate(saturday, noUsage); d.Allowed() {
		t.Error("a request on an excluded day was permitted")
	}

	// Boundaries: inclusive start, exclusive end.
	for spec, want := range map[string]bool{
		"2026-09-15T09:00:00Z": true,
		"2026-09-15T16:59:00Z": true,
		"2026-09-15T17:00:00Z": false,
		"2026-09-15T08:59:00Z": false,
	} {
		r := req("agent_update")
		r.At, _ = time.Parse(time.RFC3339, spec)
		if d, _ := e.Evaluate(r, noUsage); d.Allowed() != want {
			t.Errorf("%s: allowed=%v, want %v", spec, !want, want)
		}
	}
}

// A change freeze usually wraps past midnight, so a window that does must work
// rather than silently covering nothing.
func TestTimeWindowWrappingMidnight(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: nights
rules:
  - id: nights-only
    effect: permit
    commands: [agent_update]
    window:
      hours: "22:00-06:00"
`))
	for spec, want := range map[string]bool{
		"2026-09-15T23:00:00Z": true,
		"2026-09-15T02:00:00Z": true,
		"2026-09-15T22:00:00Z": true,
		"2026-09-15T05:59:00Z": true,
		"2026-09-15T06:00:00Z": false,
		"2026-09-15T12:00:00Z": false,
	} {
		r := req("agent_update")
		r.At, _ = time.Parse(time.RFC3339, spec)
		if d, _ := e.Evaluate(r, noUsage); d.Allowed() != want {
			t.Errorf("%s: allowed=%v, want %v", spec, !want, want)
		}
	}
}

func TestTimezoneIsHonoured(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: tz
timezone: America/Denver
rules:
  - id: mst-business-hours
    effect: permit
    commands: [agent_update]
    window:
      hours: "09:00-17:00"
`))
	r := req("agent_update")
	// 16:00 UTC is 10:00 in Denver during daylight time: inside.
	r.At = time.Date(2026, 9, 15, 16, 0, 0, 0, time.UTC)
	if d, _ := e.Evaluate(r, noUsage); !d.Allowed() {
		t.Error("a request inside the local window was denied")
	}
	// 02:00 UTC is 20:00 the previous evening in Denver: outside.
	r.At = time.Date(2026, 9, 15, 2, 0, 0, 0, time.UTC)
	if d, _ := e.Evaluate(r, noUsage); d.Allowed() {
		t.Error("a request outside the local window was permitted")
	}
}
