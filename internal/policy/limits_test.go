package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Blast-radius limits are what separate a response tool from an outage
// generator, so the failure modes are tested as hard as the happy path.

func limitDoc(t *testing.T) *Engine {
	t.Helper()
	return NewEngine(mustParse(t, `
version: 1
name: blast-radius
rules:
  - id: admins-isolate
    effect: permit
    commands: [isolate, release]
limits:
  - id: isolate-fleet-hourly
    commands: [isolate]
    scope: fleet
    max: 3
    per: 1h
`))
}

func usageOf(fleet, host int) UsageFunc {
	return func(_ []string, _ time.Time, _ string) (Usage, error) {
		return Usage{FleetCount: fleet, HostCount: host}, nil
	}
}

func TestFleetWideLimitStopsARunaway(t *testing.T) {
	e := limitDoc(t)

	// Under the limit: the third isolate is still allowed, because two have
	// been issued and this one is number three.
	for _, already := range []int{0, 1, 2} {
		d, err := e.Evaluate(req("isolate"), usageOf(already, 0))
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed() {
			t.Errorf("%d already issued: denied with %q", already, d.Reason)
		}
	}

	// The fourth must be stopped.
	d, err := e.Evaluate(req("isolate"), usageOf(3, 0))
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Fatal("the limit did not stop the fourth isolate")
	}
	if d.LimitExceeded != "isolate-fleet-hourly" {
		t.Errorf("limitExceeded = %q", d.LimitExceeded)
	}
	// The message has to carry the numbers, or an operator cannot tell
	// whether to wait or to escalate.
	for _, want := range []string{"at most 3", "3 have already been issued", "number 4"} {
		if !strings.Contains(d.Reason, want) {
			t.Errorf("reason missing %q: %q", want, d.Reason)
		}
	}

	// A command the limit does not cover is unaffected.
	if d, _ := e.Evaluate(req("release"), usageOf(99, 99)); !d.Allowed() {
		t.Error("a limit on isolate also stopped release")
	}
}

// A per-host limit would happily isolate the whole estate one host at a time,
// which is why fleet scope exists. Both must count the right thing.
func TestScopeCountsTheRightThing(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: scopes
rules:
  - id: allow
    effect: permit
    commands: [kill_process]
limits:
  - id: per-host
    commands: [kill_process]
    scope: host
    max: 1
    per: 15m
`))

	// Nine on other hosts, none on this one: allowed.
	if d, _ := e.Evaluate(req("kill_process"), usageOf(9, 0)); !d.Allowed() {
		t.Error("a host-scoped limit counted other hosts")
	}
	// One on this host: stopped.
	d, _ := e.Evaluate(req("kill_process"), usageOf(0, 1))
	if d.Allowed() {
		t.Fatal("a host-scoped limit did not count this host")
	}
	if !strings.Contains(d.Reason, "on this host") {
		t.Errorf("reason does not name the scope: %q", d.Reason)
	}
}

// Reporting "under the limit" because the count could not be read would
// disable the limit exactly when the system is least healthy.
func TestUnreadableUsageFailsClosed(t *testing.T) {
	e := limitDoc(t)

	broken := func(_ []string, _ time.Time, _ string) (Usage, error) {
		return Usage{}, fmt.Errorf("database unavailable")
	}
	if _, err := e.Evaluate(req("isolate"), broken); err == nil {
		t.Fatal("an unreadable usage count was treated as zero")
	}

	// A nil usage function with limits configured is the same hazard.
	if _, err := e.Evaluate(req("isolate"), nil); err == nil {
		t.Fatal("a missing usage function was treated as zero")
	}

	// But a command no limit covers needs no count, so nil is fine there.
	if _, err := e.Evaluate(req("release"), nil); err != nil {
		t.Errorf("an uncapped command required a usage count: %v", err)
	}
}

// A limit of zero is a valid way to say "never", and must not be read as
// "unlimited".
func TestZeroLimitMeansNever(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: never
rules:
  - id: allow
    effect: permit
    commands: [isolate]
limits:
  - id: frozen
    commands: [isolate]
    scope: fleet
    max: 0
    per: 24h
`))
	if d, _ := e.Evaluate(req("isolate"), usageOf(0, 0)); d.Allowed() {
		t.Fatal("a max of 0 permitted a command")
	}
}

func TestBreakGlassOverridesLimitsButNotDenies(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: emergency
rules:
  - id: allow-isolate
    effect: permit
    commands: [isolate]
  - id: never-kill-critical
    effect: deny
    commands: [kill_process]
    host_classes: [critical]
    reason: this host runs the estate
limits:
  - id: isolate-hourly
    commands: [isolate]
    scope: fleet
    max: 1
    per: 1h
`))

	glass := &BreakGlass{
		ID: "bg-1", Justification: "active ransomware on the finance segment",
		OpenedBy: "user:alice", OpenedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Hour),
	}

	// Over the limit, no bypass: stopped.
	over := req("isolate")
	if d, _ := e.Evaluate(over, usageOf(5, 0)); d.Allowed() {
		t.Fatal("the limit did not apply")
	}

	// Over the limit with the bypass in force: permitted, and recorded as
	// such, because break-glass is what an auditor searches for.
	over.BreakGlass = glass
	d, _ := e.Evaluate(over, usageOf(5, 0))
	if !d.Allowed() {
		t.Fatalf("break-glass did not override the limit: %s", d.Reason)
	}
	if !d.BreakGlassUsed {
		t.Error("the decision does not record that break-glass carried it")
	}
	if d.LimitExceeded != "isolate-hourly" {
		t.Error("the overridden limit was not named")
	}
	if !strings.Contains(d.Reason, "ransomware") {
		t.Errorf("the justification is not in the reason: %q", d.Reason)
	}

	// An explicit deny must survive break-glass. A bypass is for reaching
	// something policy never anticipated, not for doing the one thing policy
	// went out of its way to forbid.
	kill := req("kill_process")
	kill.HostClasses = []string{"critical"}
	kill.BreakGlass = glass
	if d, _ := e.Evaluate(kill, noUsage); d.Allowed() {
		t.Fatal("break-glass overrode an explicit deny")
	}

	// An unmatched command is reachable under break-glass — that is its
	// purpose — but is still marked.
	unmatched := req("quarantine_path")
	unmatched.BreakGlass = glass
	d, _ = e.Evaluate(unmatched, noUsage)
	if !d.Allowed() || !d.BreakGlassUsed {
		t.Fatalf("break-glass did not reach an unruled command: %+v", d)
	}
}

// Break-glass must not satisfy a two-person requirement: the entire point of
// that control is that one person cannot act alone, and a bypass one person
// can open would remove it.
func TestBreakGlassDoesNotSatisfyTwoPersonIntegrity(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: two-person
rules:
  - id: isolate-needs-two
    effect: permit
    commands: [isolate]
    require_approvals: 2
`))
	r := req("isolate")
	r.BreakGlass = &BreakGlass{
		ID: "bg-1", Justification: "urgent", OpenedBy: "user:alice",
		OpenedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Hour),
	}
	d, _ := e.Evaluate(r, noUsage)
	if d.Allowed() {
		t.Fatal("one person used break-glass to sign a two-person command")
	}
	if d.Effect != EffectRequireApproval {
		t.Errorf("effect = %s", d.Effect)
	}
}

// Time-boxed means time-boxed.
func TestBreakGlassExpiry(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: empty
rules:
  - id: nothing
    effect: permit
    commands: [release]
`))
	base := &BreakGlass{
		ID: "bg-1", Justification: "j", OpenedBy: "user:alice",
		OpenedAt: at, ExpiresAt: at.Add(time.Hour),
	}
	closed := at.Add(10 * time.Minute)

	cases := map[string]struct {
		glass *BreakGlass
		when  time.Time
		want  bool
	}{
		"before opening": {base, at.Add(-time.Minute), false},
		"at opening":     {base, at, true},
		"inside":         {base, at.Add(30 * time.Minute), true},
		"at expiry":      {base, at.Add(time.Hour), false},
		"after expiry":   {base, at.Add(2 * time.Hour), false},
		"nil":            {nil, at, false},
		"closed early":   {&BreakGlass{ID: "bg-2", Justification: "j", OpenedAt: at, ExpiresAt: at.Add(time.Hour), ClosedAt: &closed}, at.Add(30 * time.Minute), false},
		"before close":   {&BreakGlass{ID: "bg-3", Justification: "j", OpenedAt: at, ExpiresAt: at.Add(time.Hour), ClosedAt: &closed}, at.Add(5 * time.Minute), true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.glass.ActiveAt(tc.when); got != tc.want {
				t.Errorf("ActiveAt = %v, want %v", got, tc.want)
			}
			r := req("isolate")
			r.At, r.BreakGlass = tc.when, tc.glass
			d, _ := e.Evaluate(r, noUsage)
			if d.Allowed() != tc.want {
				t.Errorf("decision allowed = %v, want %v", d.Allowed(), tc.want)
			}
		})
	}
}

// The policy that decided must be identifiable afterwards from the ledger,
// not from whatever the file says today.
func TestDecisionsCarryThePolicyIdentity(t *testing.T) {
	doc := mustParse(t, `
version: 1
name: identified
rules:
  - id: allow
    effect: permit
    commands: [isolate]
`)
	e := NewEngine(doc)
	if doc.Hash == "" {
		t.Fatal("the document has no hash")
	}

	permit, _ := e.Evaluate(req("isolate"), noUsage)
	denied, _ := e.Evaluate(req("kill_process"), noUsage)
	for name, d := range map[string]Decision{"permit": permit, "deny": denied} {
		if d.PolicyHash != doc.Hash || d.PolicyName != "identified" {
			t.Errorf("%s decision does not identify its policy: %+v", name, d)
		}
	}

	// A changed document must produce a different hash, or the ledger cannot
	// tell two policies apart.
	other := mustParse(t, `
version: 1
name: identified
rules:
  - id: allow
    effect: permit
    commands: [isolate, release]
`)
	if other.Hash == doc.Hash {
		t.Fatal("two different policies share a hash")
	}
}
