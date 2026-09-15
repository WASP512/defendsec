package policy

import (
	"strings"
	"testing"
)

// A policy that half-loads is worse than none: the operator believes the rules
// are in force, and the ones that failed to parse are exactly the ones nobody
// notices are missing. So every malformed document must be refused outright.
func TestParseRefusesMalformedDocuments(t *testing.T) {
	cases := map[string]string{
		"no version": `
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
`,
		"wrong version": `
version: 2
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
`,
		"no name": `
version: 1
rules:
  - id: a
    effect: permit
    commands: [isolate]
`,
		"rule without id": `
version: 1
name: x
rules:
  - effect: permit
    commands: [isolate]
`,
		"duplicate rule id": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
  - id: a
    effect: permit
    commands: [release]
`,
		"rule without effect": `
version: 1
name: x
rules:
  - id: a
    commands: [isolate]
`,
		"unknown effect": `
version: 1
name: x
rules:
  - id: a
    effect: maybe
    commands: [isolate]
`,
		"rule without commands": `
version: 1
name: x
rules:
  - id: a
    effect: permit
`,
		"deny without reason": `
version: 1
name: x
rules:
  - id: a
    effect: deny
    commands: [isolate]
`,
		"deny that also requires approvals": `
version: 1
name: x
rules:
  - id: a
    effect: deny
    commands: [isolate]
    reason: no
    require_approvals: 2
`,
		"negative approvals": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
    require_approvals: -1
`,
		"misspelled key": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    comands: [isolate]
`,
		"unknown timezone": `
version: 1
name: x
timezone: Mars/Olympus
rules:
  - id: a
    effect: permit
    commands: [isolate]
`,
		"bad hours": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
    window:
      hours: "all day"
`,
		"empty window": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
    window:
      hours: "09:00-09:00"
`,
		"unknown day": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
    window:
      days: [funday]
`,
		"limit without id": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - commands: [isolate]
    max: 1
    per: 1h
`,
		"limit without commands": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - id: l
    max: 1
    per: 1h
`,
		"limit with bad duration": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - id: l
    commands: [isolate]
    max: 1
    per: soon
`,
		"limit with zero duration": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - id: l
    commands: [isolate]
    max: 1
    per: 0s
`,
		"limit with unknown scope": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - id: l
    commands: [isolate]
    scope: galaxy
    max: 1
    per: 1h
`,
		"negative max": `
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - id: l
    commands: [isolate]
    max: -1
    per: 1h
`,
		"not yaml": `::: not a document :::`,
	}

	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// A misspelled key must fail rather than be ignored: silently dropping
// "host_clases" turns a narrow rule into a fleet-wide one.
func TestMisspelledKeyIsNotIgnored(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
    host_clases: [production]
`))
	if err == nil {
		t.Fatal("a misspelled key was ignored, widening the rule")
	}
	if !strings.Contains(err.Error(), "host_clases") {
		t.Errorf("the error does not name the bad key: %v", err)
	}
}

func TestParseAcceptsAWellFormedDocument(t *testing.T) {
	doc, err := Parse([]byte(`
version: 1
name: production-default
timezone: America/Denver
rules:
  - id: responders-investigate
    effect: permit
    commands: [live_query]
    roles: [admin]
  - id: isolate-with-two-approvals
    effect: permit
    commands: [isolate]
    roles: [admin]
    host_classes: [production]
    require_approvals: 2
  - id: never-kill-domain-controllers
    effect: deny
    commands: [kill_process]
    host_classes: [domain-controller]
    reason: a domain controller losing a process takes authentication down estate-wide
limits:
  - id: isolate-fleet-hourly
    commands: [isolate]
    scope: fleet
    max: 3
    per: 1h
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Name != "production-default" || len(doc.Rules) != 3 || len(doc.Limits) != 1 {
		t.Fatalf("parsed document = %+v", doc)
	}
	if doc.Hash == "" {
		t.Error("no hash")
	}
	// Scope defaults to fleet, which is the safe default: a per-host default
	// would let a runaway walk the estate one host at a time.
	if doc.Limits[0].Scope != ScopeFleet {
		t.Errorf("scope = %q", doc.Limits[0].Scope)
	}
	want := []string{"isolate-with-two-approvals", "never-kill-domain-controllers", "responders-investigate"}
	got := doc.RuleIDs()
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule ids = %v, want %v", got, want)
			break
		}
	}
}

func TestScopeDefaultsToFleet(t *testing.T) {
	doc, err := Parse([]byte(`
version: 1
name: x
rules:
  - id: a
    effect: permit
    commands: [isolate]
limits:
  - id: l
    commands: [isolate]
    max: 1
    per: 1h
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Limits[0].Scope != ScopeFleet {
		t.Fatalf("an unspecified scope defaulted to %q, not fleet", doc.Limits[0].Scope)
	}
}

func TestLoadReportsTheFile(t *testing.T) {
	if _, err := Load("/nonexistent/policy.yaml"); err == nil {
		t.Fatal("a missing policy file loaded")
	}
}

func TestWildcards(t *testing.T) {
	e := NewEngine(mustParse(t, `
version: 1
name: wildcards
rules:
  - id: break-glass-role
    effect: permit
    commands: ["*"]
    roles: [admin]
    host_classes: ["*"]
`))
	// "*" means any host, the plain reading of a wildcard and the same meaning
	// it carries in commands and roles. A rule that should only touch
	// deliberately-tagged hosts names the tags instead.
	classed := req("isolate")
	classed.HostClasses = []string{"lab"}
	if d, _ := e.Evaluate(classed, noUsage); !d.Allowed() {
		t.Error("a classed host did not match the wildcard")
	}
	unclassed := req("isolate")
	if d, _ := e.Evaluate(unclassed, noUsage); !d.Allowed() {
		t.Error("an unclassified host did not match a host_classes wildcard")
	}

	// And "*" in exclude_host_classes therefore excludes every host, so the
	// rule can never match. Odd to write, but it must not mean its opposite.
	e2 := NewEngine(mustParse(t, `
version: 1
name: exclude-all
rules:
  - id: never-applies
    effect: permit
    commands: [isolate]
    exclude_host_classes: ["*"]
`))
	if d, _ := e2.Evaluate(req("isolate"), noUsage); d.Allowed() {
		t.Error("a rule excluding every host still matched one")
	}
}
