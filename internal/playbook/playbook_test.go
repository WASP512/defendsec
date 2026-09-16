package playbook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Playbook {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestParseRejectsMalformedPlaybooks(t *testing.T) {
	cases := map[string]string{
		"no version": `
id: p
name: n
steps:
  - id: s
    command: isolate
`,
		"no id": `
version: 1
name: n
steps:
  - id: s
    command: isolate
`,
		"no steps": `
version: 1
id: p
name: n
steps: []
`,
		"step without id": `
version: 1
id: p
name: n
steps:
  - command: isolate
`,
		"duplicate step id": `
version: 1
id: p
name: n
steps:
  - id: s
    command: isolate
  - id: s
    command: release
`,
		"unknown command": `
version: 1
id: p
name: n
steps:
  - id: s
    command: rm_rf
`,
		"misspelled key": `
version: 1
id: p
name: n
steps:
  - id: s
    comand: isolate
`,
		"automatic without trigger": `
version: 1
id: p
name: n
automatic: true
steps:
  - id: s
    command: isolate
`,
		"trigger with no kinds": `
version: 1
id: p
name: n
trigger:
  path_prefix: /etc
steps:
  - id: s
    command: isolate
`,
		"unknown alert kind": `
version: 1
id: p
name: n
trigger:
  alert_kinds: [telepathy]
steps:
  - id: s
    command: isolate
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

// A typo in a command name must fail at load, not produce a step that is
// denied at run time, mid-incident, for a reason that reads like a policy
// problem.
func TestUnknownCommandFailsAtLoad(t *testing.T) {
	_, err := Parse([]byte(`
version: 1
id: p
name: n
steps:
  - id: s
    command: isolat
`))
	if err == nil {
		t.Fatal("a misspelled command loaded")
	}
	if !strings.Contains(err.Error(), "isolat") {
		t.Errorf("the error does not name the bad command: %v", err)
	}
}

// The injection case this design exists to prevent. These paths come from
// files on a compromised host, so an attacker chooses them.
func TestBindDoesNotAllowPayloadInjection(t *testing.T) {
	hostile := `/etc/ssh/evil","extra":"injected`
	alert := Alert{ID: "a1", Kind: "fim", DeviceID: "dev-1", Path: hostile}

	bound, err := Bind(map[string]any{"path": "{{alert.path}}"}, alert)
	if err != nil {
		t.Fatal(err)
	}
	// The value must survive intact as a value...
	if bound["path"] != hostile {
		t.Fatalf("path = %q, want the original", bound["path"])
	}
	// ...and must not have introduced a second field when serialised.
	raw, err := json.Marshal(bound)
	if err != nil {
		t.Fatal(err)
	}
	var round map[string]any
	if err := json.Unmarshal(raw, &round); err != nil {
		t.Fatalf("the bound payload is not valid JSON: %v (%s)", err, raw)
	}
	if len(round) != 1 {
		t.Fatalf("binding produced extra fields: %s", raw)
	}
	if _, injected := round["extra"]; injected {
		t.Fatalf("a hostile path injected a field: %s", raw)
	}
}

// Interpolation is where a value stops being a value and becomes part of the
// surrounding syntax, so it is refused outright.
func TestBindRejectsEmbeddedPlaceholders(t *testing.T) {
	alert := Alert{ID: "a1", Path: "/etc/ssh/sshd_config"}
	for _, payload := range []map[string]any{
		{"path": "prefix-{{alert.path}}"},
		{"path": "{{alert.path}}-suffix"},
		{"cmd": "rm {{alert.path}}"},
		{"nested": map[string]any{"path": "x{{alert.path}}"}},
		{"list": []any{"{{alert.path}}-1"}},
	} {
		if _, err := Bind(payload, alert); err == nil {
			t.Errorf("%v: an embedded placeholder was interpolated", payload)
		}
	}
}

// A placeholder with no value would sign a command against nothing:
// quarantining "" or killing a process named "".
func TestBindRejectsMissingValues(t *testing.T) {
	noPath := Alert{ID: "a1", Kind: "vuln", DeviceID: "dev-1"}
	_, err := Bind(map[string]any{"path": "{{alert.path}}"}, noPath)
	if err == nil {
		t.Fatal("a placeholder with no value bound to an empty string")
	}
	if !strings.Contains(err.Error(), "run against nothing") {
		t.Errorf("error = %v", err)
	}
}

func TestBindSubstitutesNestedValues(t *testing.T) {
	alert := Alert{
		ID: "a1", Kind: "fim", Severity: "high", DeviceID: "dev-1",
		Hostname: "host-1", Title: "drift", Path: "/etc/ssh/sshd_config",
	}
	bound, err := Bind(map[string]any{
		"path":    "{{alert.path}}",
		"literal": "unchanged",
		"count":   3,
		"nested":  map[string]any{"device": "{{alert.deviceId}}"},
		"list":    []any{"{{alert.id}}", "plain"},
	}, alert)
	if err != nil {
		t.Fatal(err)
	}
	if bound["path"] != "/etc/ssh/sshd_config" || bound["literal"] != "unchanged" || bound["count"] != 3 {
		t.Fatalf("bound = %+v", bound)
	}
	if bound["nested"].(map[string]any)["device"] != "dev-1" {
		t.Errorf("nested = %+v", bound["nested"])
	}
	if bound["list"].([]any)[0] != "a1" || bound["list"].([]any)[1] != "plain" {
		t.Errorf("list = %+v", bound["list"])
	}
}

func TestTriggerMatching(t *testing.T) {
	p := mustParse(t, `
version: 1
id: ssh-drift
name: SSH drift response
trigger:
  alert_kinds: [fim]
  severities: [high, critical]
  path_prefix: /etc/ssh
  host_classes: [production]
steps:
  - id: s
    command: live_query
`)
	match := Alert{Kind: "fim", Severity: "high", Path: "/etc/ssh/sshd_config"}
	if !p.Matches(match, []string{"production"}) {
		t.Fatal("a matching finding did not trigger")
	}

	cases := map[string]struct {
		alert   Alert
		classes []string
	}{
		"wrong kind":     {Alert{Kind: "vuln", Severity: "high", Path: "/etc/ssh/x"}, []string{"production"}},
		"wrong severity": {Alert{Kind: "fim", Severity: "low", Path: "/etc/ssh/x"}, []string{"production"}},
		"wrong path":     {Alert{Kind: "fim", Severity: "high", Path: "/var/log/x"}, []string{"production"}},
		"no path":        {Alert{Kind: "fim", Severity: "high"}, []string{"production"}},
		"wrong class":    {Alert{Kind: "fim", Severity: "high", Path: "/etc/ssh/x"}, []string{"lab"}},
		"no class":       {Alert{Kind: "fim", Severity: "high", Path: "/etc/ssh/x"}, nil},
	}
	for name, tc := range cases {
		if p.Matches(tc.alert, tc.classes) {
			t.Errorf("%s: triggered anyway", name)
		}
	}

	// A playbook with no trigger is never matched, only run by hand.
	manual := mustParse(t, `
version: 1
id: manual
name: Manual only
steps:
  - id: s
    command: isolate
`)
	if manual.Matches(match, []string{"production"}) {
		t.Error("a playbook with no trigger was matched")
	}
	if manual.Automatic {
		t.Error("a playbook is automatic by default")
	}
}

func TestLoadDirFailsOnOneBadFile(t *testing.T) {
	dir := t.TempDir()
	good := `
version: 1
id: good
name: Good
steps:
  - id: s
    command: isolate
`
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 {
		t.Fatalf("loaded %d", set.Len())
	}

	// A partially-loaded set means the operator believes a playbook exists
	// when it does not, and they find out during the incident it was written
	// for.
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("version: 1\nid: bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("one bad file did not fail the load")
	}
}

func TestLoadDirRejectsDuplicateIDs(t *testing.T) {
	dir := t.TempDir()
	src := `
version: 1
id: same
name: n
steps:
  - id: s
    command: isolate
`
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("two playbooks shared an id")
	}
}

func TestHashIdentifiesTheVersion(t *testing.T) {
	a := mustParse(t, `
version: 1
id: p
name: n
steps:
  - id: s
    command: isolate
`)
	b := mustParse(t, `
version: 1
id: p
name: n
steps:
  - id: s
    command: isolate
  - id: s2
    command: release
`)
	if a.Hash == "" || a.Hash == b.Hash {
		t.Fatal("playbook versions are not distinguishable by hash")
	}
}

func TestEmptySetIsSafe(t *testing.T) {
	var s *Set
	if s.Len() != 0 || s.All() != nil {
		t.Error("a nil set is not empty")
	}
	if _, ok := s.Get("anything"); ok {
		t.Error("a nil set returned a playbook")
	}
}
