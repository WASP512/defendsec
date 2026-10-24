package hostinv

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The agent must not write to the host. Three of its package-manager calls have an
// option whose only job is to stop a write; a fake binary that records its arguments
// pins that each call still passes it (removing the option changes nothing else a
// test can see).
func fakeManager(t *testing.T, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, name+".args")
	script := "#!/bin/sh\necho \"$@\" > '" + log + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return log
}

func argsOf(t *testing.T, log string) string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the manager was never run: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func TestPendingAptRunsWithoutWritingAptsCache(t *testing.T) {
	log := fakeManager(t, "apt")
	pendingApt()
	got := argsOf(t, log)
	for _, want := range []string{"-o Dir::Cache::pkgcache=", "-o Dir::Cache::srcpkgcache=", "list --upgradable"} {
		if !strings.Contains(got, want) {
			t.Errorf("apt argv %q lacks %q", got, want)
		}
	}
}

func TestPendingDNFRunsFromTheCacheOnly(t *testing.T) {
	log := fakeManager(t, "dnf")
	pendingDNF("dnf")
	if got := argsOf(t, log); !strings.HasPrefix(got, "-C ") || !strings.Contains(got, "check-update") {
		t.Errorf("dnf argv %q must start with -C (cache only)", got)
	}
}

func TestPendingZypperDoesNotRefresh(t *testing.T) {
	log := fakeManager(t, "zypper")
	pendingZypper()
	if got := argsOf(t, log); !strings.Contains(got, "--no-refresh") || !strings.Contains(got, "list-updates") {
		t.Errorf("zypper argv %q must carry --no-refresh", got)
	}
}
