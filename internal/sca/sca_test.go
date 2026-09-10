package sca

import (
	"os"
	"path/filepath"
	"testing"

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
