package playbook

import (
	"os"
	"path/filepath"
	"testing"
)

func shippedDir(t *testing.T) string {
	t.Helper()
	for _, dir := range []string{
		"packaging/playbooks",
		filepath.Join("..", "..", "packaging", "playbooks"),
	} {
		if _, err := os.Stat(dir); err == nil {
			return dir
		}
	}
	t.Fatal("could not find packaging/playbooks")
	return ""
}

func TestShippedPlaybooksLoad(t *testing.T) {
	set, err := LoadDir(shippedDir(t))
	if err != nil {
		t.Fatalf("the shipped playbooks do not load: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("no shipped playbooks")
	}
	for _, pb := range set.All() {
		if pb.Description == "" {
			t.Errorf("%s has no description; a playbook nobody can explain is one nobody should approve", pb.ID)
		}
		for _, step := range pb.Steps {
			if step.Description == "" {
				t.Errorf("%s/%s has no description", pb.ID, step.ID)
			}
		}
	}
}

// Anything shipped with automatic: true must only read. A state-changing step
// running unattended by default is a decision the operator never made.
func TestShippedAutomaticPlaybooksOnlyRead(t *testing.T) {
	set, err := LoadDir(shippedDir(t))
	if err != nil {
		t.Fatal(err)
	}
	readOnly := map[string]bool{"live_query": true}

	for _, pb := range set.All() {
		if !pb.Automatic {
			continue
		}
		for _, step := range pb.Steps {
			if !readOnly[step.Command] {
				t.Errorf("%s runs automatically and includes %q, which changes state",
					pb.ID, step.Command)
			}
		}
	}
}

// The drift playbook is the roadmap's worked example, so its shape is
// asserted rather than assumed.
func TestSSHDriftPlaybookShape(t *testing.T) {
	set, err := LoadDir(shippedDir(t))
	if err != nil {
		t.Fatal(err)
	}
	pb, ok := set.Get("ssh-drift-response")
	if !ok {
		t.Fatal("ssh-drift-response is missing")
	}
	if pb.Automatic {
		t.Error("a playbook that isolates hosts ships as automatic")
	}
	if len(pb.Steps) != 3 {
		t.Fatalf("steps = %d, want collect, quarantine, isolate", len(pb.Steps))
	}
	want := []string{"live_query", "quarantine_path", "isolate"}
	for i, cmd := range want {
		if pb.Steps[i].Command != cmd {
			t.Errorf("step %d = %q, want %q", i, pb.Steps[i].Command, cmd)
		}
	}

	// It must bind the changed path rather than hard-coding one.
	alert := Alert{
		ID: "a1", Kind: "fim", Severity: "high",
		DeviceID: "dev-1", Hostname: "host-1", Title: "drift",
		Path: "/etc/ssh/sshd_config",
	}
	if !pb.Matches(alert, nil) {
		t.Error("the drift playbook does not match its own example finding")
	}
	bound, err := Bind(pb.Steps[1].Payload, alert)
	if err != nil {
		t.Fatal(err)
	}
	if bound["path"] != "/etc/ssh/sshd_config" {
		t.Errorf("quarantine path = %v", bound["path"])
	}

	// A finding elsewhere must not trigger it.
	other := alert
	other.Path = "/var/tmp/x"
	if pb.Matches(other, nil) {
		t.Error("the drift playbook triggered on a path outside /etc/ssh")
	}
}
