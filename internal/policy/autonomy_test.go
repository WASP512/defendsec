package policy

import (
	"strings"
	"testing"
	"time"
)

// Bounded autonomy's load-time safeguards (roadmap 4.4).
//
// These are refused when the policy is parsed rather than when a command is
// attempted, because a policy that cannot be safe should not start. An
// operator finds out at reload; the alternative is finding out when an agent
// acts.

func TestAutonomousRuleNeedsABlastRadiusLimit(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: no-ceiling
rules:
  - id: agents-isolate-freely
    effect: permit
    roles: [agent]
    commands: [isolate]
    autonomous: true
`))
	if err == nil {
		t.Fatal("an autonomous rule with no limit was accepted; that is a runaway with paperwork")
	}
	if !strings.Contains(err.Error(), "no limit covers") {
		t.Errorf("err = %v", err)
	}
}

func TestAutonomousRuleWithALimitIsAccepted(t *testing.T) {
	doc, err := Parse([]byte(`
version: 1
name: bounded
rules:
  - id: agents-isolate-bounded
    effect: permit
    roles: [agent]
    commands: [isolate]
    autonomous: true
limits:
  - id: isolate-hourly
    commands: [isolate]
    scope: fleet
    max: 2
    per: 1h
`))
	if err != nil {
		t.Fatalf("a bounded autonomous rule was refused: %v", err)
	}
	if !doc.Rules[0].Autonomous {
		t.Error("the autonomous flag was not read")
	}
}

// A wildcard rule needs a wildcard limit. A rule permitting everything
// autonomously with a limit on isolate alone leaves every other command
// unbounded, which is the exact gap the check exists to close.
func TestAWildcardAutonomousRuleNeedsAWildcardLimit(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: wildcard-gap
rules:
  - id: agents-do-anything
    effect: permit
    roles: [agent]
    commands: ["*"]
    autonomous: true
limits:
  - id: isolate-only
    commands: [isolate]
    scope: fleet
    max: 2
    per: 1h
`))
	if err == nil {
		t.Fatal("a wildcard autonomous rule was accepted with a limit covering one command")
	}
}

// A limit of zero forbids rather than bounds, so it is not a ceiling.
func TestAZeroLimitDoesNotCountAsACeiling(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: zero-limit
rules:
  - id: agents-isolate
    effect: permit
    roles: [agent]
    commands: [isolate]
    autonomous: true
limits:
  - id: isolate-forbidden
    commands: [isolate]
    scope: fleet
    max: 0
    per: 1h
`))
	if err == nil {
		t.Fatal("a zero limit was accepted as a blast-radius ceiling")
	}
}

func TestAutonomyOnADenyRuleIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: contradiction
rules:
  - id: no-isolating
    effect: deny
    commands: [isolate]
    reason: never
    autonomous: true
`))
	if err == nil {
		t.Fatal("autonomy on a deny rule was accepted")
	}
	if !strings.Contains(err.Error(), "does not permit") {
		t.Errorf("err = %v", err)
	}
}

// Asking for a human and for no human at once cannot be meant.
func TestAutonomyWithMultipleApprovalsIsRefused(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: both
rules:
  - id: agents-isolate
    effect: permit
    roles: [agent]
    commands: [isolate]
    require_approvals: 2
    autonomous: true
limits:
  - id: isolate-hourly
    commands: [isolate]
    scope: fleet
    max: 2
    per: 1h
`))
	if err == nil {
		t.Fatal("a rule demanding two approvals and autonomy was accepted")
	}
}

// Autonomy is carried from the matching rule and never inferred.
func TestADecisionCarriesAutonomyOnlyFromTheMatchingRule(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: mixed
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
    max: 100
    per: 1h
`))

	q := req("live_query")
	q.Role = "agent"
	d, err := e.Evaluate(q, noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Autonomous {
		t.Error("the autonomous rule did not produce an autonomous decision")
	}

	i := req("isolate")
	i.Role = "agent"
	d, err = e.Evaluate(i, noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if d.Autonomous {
		t.Error("a rule not marked autonomous produced an autonomous decision")
	}
}

// A denial is never autonomous, whatever else is in the document.
func TestADeniedDecisionIsNotAutonomous(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: narrow
rules:
  - id: agents-query-autonomously
    effect: permit
    roles: [agent]
    commands: [live_query]
    autonomous: true
limits:
  - id: query-hourly
    commands: [live_query]
    scope: fleet
    max: 100
    per: 1h
`))
	r := req("isolate")
	r.Role = "agent"
	d, err := e.Evaluate(r, noUsage)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Fatal("isolate was permitted")
	}
	if d.Autonomous {
		t.Error("a denial came back marked autonomous")
	}
}

// The blast-radius limit must still bite on an autonomous rule — that is the
// ceiling the whole design rests on.
func TestBlastRadiusStillStopsAnAutonomousAgent(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: bounded
rules:
  - id: agents-isolate-bounded
    effect: permit
    roles: [agent]
    commands: [isolate]
    autonomous: true
limits:
  - id: isolate-fleet-hourly
    commands: [isolate]
    scope: fleet
    max: 3
    per: 1h
`))

	var issued, stopped int
	count := 0
	for i := 0; i < 20; i++ {
		r := req("isolate")
		r.Role = "agent"
		r.DeviceID = "dev-" + string(rune('a'+i))
		usageCount := count
		d, err := e.Evaluate(r, func(_ []string, _ time.Time, _ string) (Usage, error) {
			return Usage{FleetCount: usageCount}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			issued++
			count++
			continue
		}
		stopped++
		if d.LimitExceeded != "isolate-fleet-hourly" {
			t.Fatalf("stopped for the wrong reason: %+v", d)
		}
	}
	if issued != 3 {
		t.Errorf("an autonomous agent issued %d isolates, want exactly the limit of 3", issued)
	}
	if stopped != 17 {
		t.Errorf("stopped %d, want 17", stopped)
	}
}
