package sca

import (
	"os"
	"path/filepath"
	"testing"

	"defendsec/internal/controls"
	"defendsec/internal/presence"
)

func TestEvalFileRegex_pass(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	content := "# sshd config\nPasswordAuthentication no\nPermitRootLogin no\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	check := Check{
		ID:        "sshd-password-auth",
		Title:     "PasswordAuthentication should be no",
		Severity:  "high",
		Type:      "file_regex",
		Path:      path,
		MustMatch: `(?i)^PasswordAuthentication\s+no`,
	}
	got := EvalFileRegex(check)
	if !got.Pass {
		t.Fatalf("expected pass, got fail: %s", got.Detail)
	}
}

func TestEvalFileRegex_fail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("PasswordAuthentication yes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check := Check{
		ID:        "sshd-password-auth",
		Title:     "PasswordAuthentication should be no",
		Severity:  "high",
		Type:      "file_regex",
		Path:      path,
		MustMatch: `(?i)^PasswordAuthentication\s+no`,
	}
	got := EvalFileRegex(check)
	if got.Pass {
		t.Fatal("expected fail")
	}
}

func TestEvalInventoryField_firewall(t *testing.T) {
	on := true
	dev := presence.Device{Firewall: &on}
	check := Check{
		ID:       "firewall-enabled",
		Title:    "Host firewall reported enabled",
		Severity: "medium",
		Type:     "inventory_field",
		Field:    "firewall",
		Expect:   "true",
	}
	got := EvalInventoryField(check, dev)
	if !got.Pass {
		t.Fatalf("expected pass: %s", got.Detail)
	}
}

func TestEvalFileRegex_dropIns(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(main, []byte("Include sshd_config.d/*.conf\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drop := filepath.Join(dir, "sshd_config.d")
	if err := os.Mkdir(drop, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(drop, "50-harden.conf"), []byte("PasswordAuthentication no\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check := Check{
		ID:        "sshd-password-auth",
		Title:     "PasswordAuthentication should be no",
		Severity:  "high",
		Type:      "file_regex",
		Path:      main,
		MustMatch: `(?i)^PasswordAuthentication\s+no`,
	}
	got := EvalFileRegex(check)
	if !got.Pass {
		t.Fatalf("expected drop-in match, got: %s", got.Detail)
	}
}

func TestLoadDefaultLinuxHost(t *testing.T) {
	pack, err := LoadDefaultLinuxHost()
	if err != nil {
		t.Fatal(err)
	}
	if pack.ID != "sca-linux-host-v1" {
		t.Fatalf("id = %s", pack.ID)
	}
	if len(pack.Checks) < 3 {
		t.Fatalf("expected host checks, got %d", len(pack.Checks))
	}
}

// Roadmap 1.7: every shipped check must name the controls it tests, and a bad
// identifier must fail the load rather than producing a pack that looks tagged
// and evidences nothing.
func TestShippedPacksAreControlTagged(t *testing.T) {
	for _, path := range []string{DefaultLinuxSSHPath(), DefaultLinuxHostPath()} {
		pack, err := LoadPack(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		if len(pack.Checks) == 0 {
			t.Fatalf("%s has no checks", path)
		}
		for _, c := range pack.Checks {
			if len(c.Controls) == 0 {
				t.Errorf("%s: check %q names no controls", pack.ID, c.ID)
			}
			for _, raw := range c.Controls {
				if _, err := controls.ParseID(raw); err != nil {
					t.Errorf("%s/%s: %v", pack.ID, c.ID, err)
				}
			}
		}
	}
}

func TestPackControlsRejectBadIdentifiers(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	bad := write("bad.yaml", `
id: bad-pack
checks:
  - id: c1
    controls: ["not-a-framework:1"]
    title: t
`)
	if _, err := LoadPack(bad); err == nil {
		t.Error("a pack naming an unknown framework must not load")
	}

	badPackLevel := write("bad-pack-level.yaml", `
id: bad-pack-2
controls: ["AU-9"]
checks:
  - id: c1
    title: t
`)
	if _, err := LoadPack(badPackLevel); err == nil {
		t.Error("a pack-level control without a framework prefix must not load")
	}
}

// A pack-level default must reach the checks that are silent, and must not
// overwrite a check that names its own.
func TestPackControlsInheritAndOverride(t *testing.T) {
	p := filepath.Join(t.TempDir(), "pack.yaml")
	body := `
id: inherit-pack
controls: ["nist-800-53:CM-6"]
checks:
  - id: silent
    title: inherits the default
  - id: specific
    title: names its own
    controls: ["cis-v8:5.4"]
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pack, err := LoadPack(p)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Check{}
	for _, c := range pack.Checks {
		byID[c.ID] = c
	}
	if got := byID["silent"].Controls; len(got) != 1 || got[0] != "nist-800-53:CM-6" {
		t.Errorf("silent check controls = %v, want the pack default", got)
	}
	if got := byID["specific"].Controls; len(got) != 1 || got[0] != "cis-v8:5.4" {
		t.Errorf("specific check controls = %v, want only its own", got)
	}

	// And the tags must survive onto the result, so an alert raised from it
	// does not have to reload the pack.
	res := EvalFileRegex(byID["specific"])
	if len(res.Controls) != 1 || res.Controls[0] != "cis-v8:5.4" {
		t.Errorf("result controls = %v", res.Controls)
	}
}
