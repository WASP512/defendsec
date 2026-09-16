package sca

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner records what it was asked to run, so the argument shape a check
// produces can be asserted rather than assumed.
type fakeRunner struct {
	calls  [][]string
	stdout string
	code   int
	err    error
}

func (f *fakeRunner) Run(_ context.Context, argv []string) (string, int, error) {
	f.calls = append(f.calls, argv)
	return f.stdout, f.code, f.err
}

// The allowlist is the security boundary. A pack naming anything else must be
// refused, and naming a path must not get around it — /tmp/systemctl is not
// systemctl.
func TestRunnerAllowlist(t *testing.T) {
	r := NewRunner(nil)

	refused := []string{
		"sh", "bash", "zsh", "python3", "perl", "curl", "wget", "nc",
		"rm", "dd", "chmod", "chown", "useradd", "docker",
	}
	for _, name := range refused {
		_, _, err := r.Run(context.Background(), []string{name, "-c", "echo hi"})
		if !errors.Is(err, ErrCommandNotAllowed) {
			t.Errorf("%q: err = %v, want ErrCommandNotAllowed", name, err)
		}
	}

	// A path must be refused even when its base name is allowlisted.
	for _, name := range []string{
		"/tmp/systemctl", "./systemctl", "../bin/systemctl",
		"/usr/bin/systemctl", `..\systemctl`,
	} {
		_, _, err := r.Run(context.Background(), []string{name})
		if !errors.Is(err, ErrCommandNotAllowed) {
			t.Errorf("%q: err = %v, want ErrCommandNotAllowed", name, err)
		}
	}

	if _, _, err := r.Run(context.Background(), nil); err == nil {
		t.Error("an empty command was accepted")
	}
}

// There is no shell, so nothing in an argument can become syntax. Asserted
// against arguments that would be catastrophic if one existed.
func TestArgumentsAreNeverShellInterpreted(t *testing.T) {
	r := NewRunner([]string{"echo"}).(*execRunner)
	r.dirs = []string{"/usr/bin", "/bin"}

	hostile := []string{
		"; rm -rf /",
		"$(touch /tmp/defendsec-pwned)",
		"`id`",
		"| tee /tmp/x",
		"&& curl evil.example",
		"*",
	}
	for _, arg := range hostile {
		out, code, err := r.Run(context.Background(), []string{"echo", arg})
		if err != nil {
			t.Skipf("echo unavailable in this environment: %v", err)
		}
		if code != 0 {
			t.Errorf("%q: exit %d", arg, code)
			continue
		}
		// The argument comes back verbatim, which is only possible if it was
		// passed as one argv element rather than parsed.
		if strings.TrimSpace(out) != arg {
			t.Errorf("argument was interpreted: gave %q, got %q", arg, strings.TrimSpace(out))
		}
	}
}

// A non-zero exit is data, not a failure: systemctl is-enabled uses it to mean
// "disabled", and treating it as an error would make the answer unreachable.
func TestNonZeroExitIsData(t *testing.T) {
	h := &Host{Runner: &fakeRunner{stdout: "disabled\n", code: 1}}
	zero := 0
	res := h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"systemctl", "is-enabled", "x"},
		ExitCode: &zero,
	})
	if res.Pass {
		t.Fatal("exit 1 satisfied an exit_code of 0")
	}
	if !strings.Contains(res.Detail, "exit code 1") {
		t.Errorf("detail = %q", res.Detail)
	}

	one := 1
	res = h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"systemctl", "is-enabled", "x"},
		ExitCode: &one,
	})
	if !res.Pass {
		t.Errorf("exit 1 did not satisfy an exit_code of 1: %s", res.Detail)
	}
}

func TestCommandOutputMatching(t *testing.T) {
	h := &Host{Runner: &fakeRunner{stdout: "Current mode: enforcing\n"}}

	if res := h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"sestatus"},
		OutputMatches: `(?i)enforcing`,
	}); !res.Pass {
		t.Errorf("a matching output failed: %s", res.Detail)
	}

	if res := h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"sestatus"},
		OutputMatches: `(?i)permissive`,
	}); res.Pass {
		t.Error("a non-matching output passed")
	}

	if res := h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"sestatus"},
		OutputNotMatches: `(?i)disabled`,
	}); !res.Pass {
		t.Errorf("output_not_matches failed on absent text: %s", res.Detail)
	}

	if res := h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"sestatus"},
		OutputNotMatches: `(?i)enforcing`,
	}); res.Pass {
		t.Error("output_not_matches passed on present text")
	}
}

// A check with no expectation would pass whatever the command printed, which
// is worse than not running it — it reads as a satisfied control.
func TestCommandWithNoExpectationFails(t *testing.T) {
	h := &Host{Runner: &fakeRunner{stdout: "anything"}}
	res := h.EvalCommand(context.Background(), Check{
		ID: "c", Type: "command", Command: []string{"sestatus"},
	})
	if res.Pass {
		t.Fatal("a check with no expectation passed")
	}
	if !strings.Contains(res.Detail, "no expectation") {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestLimitedWriterCapsOutput(t *testing.T) {
	var sink strings.Builder
	w := &limitedWriter{W: &sink, N: 10}
	// Reports the full length so the caller does not see a short write and
	// retry forever, but stores only the cap.
	n, err := w.Write([]byte(strings.Repeat("x", 100)))
	if err != nil || n != 100 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if sink.Len() != 10 {
		t.Errorf("stored %d bytes, want the cap of 10", sink.Len())
	}
	if _, err := w.Write([]byte("more")); err != nil {
		t.Fatalf("write after the cap: %v", err)
	}
	if sink.Len() != 10 {
		t.Errorf("stored %d bytes after the cap", sink.Len())
	}
}

func TestPackageArgumentShapeIsFixed(t *testing.T) {
	fake := &fakeRunner{stdout: "install ok installed 1.2.3", code: 0}
	h := &Host{Root: t.TempDir(), Runner: fake}
	// Make it look like a dpkg host.
	writeDir(t, h, "/var/lib/dpkg/status")

	res := h.EvalPackage(context.Background(), Check{
		ID: "c", Type: "package", Package: "openssh-server",
	})
	if !res.Pass {
		t.Fatalf("an installed package failed: %s", res.Detail)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("calls = %v", fake.calls)
	}
	// The pack supplies a name, never a command: the shape is decided here.
	got := fake.calls[0]
	if got[0] != "dpkg-query" || got[len(got)-1] != "openssh-server" {
		t.Errorf("argv = %v", got)
	}
}

// Removed-but-not-purged has a version and would otherwise read as installed.
func TestRemovedPackageIsNotInstalled(t *testing.T) {
	h := &Host{Root: t.TempDir(), Runner: &fakeRunner{stdout: "deinstall ok config-files 1.2.3", code: 0}}
	writeDir(t, h, "/var/lib/dpkg/status")

	res := h.EvalPackage(context.Background(), Check{
		ID: "c", Type: "package", Package: "telnet",
	})
	if res.Pass {
		t.Fatal("a removed-but-not-purged package was reported as installed")
	}
}

func TestPackageAbsenceIsExpressible(t *testing.T) {
	h := &Host{Root: t.TempDir(), Runner: &fakeRunner{code: 1}}
	writeDir(t, h, "/var/lib/dpkg/status")

	no := false
	res := h.EvalPackage(context.Background(), Check{
		ID: "c", Type: "package", Package: "telnet", Present: &no,
	})
	if !res.Pass {
		t.Fatalf("an absent package failed an absence check: %s", res.Detail)
	}

	yes := true
	res = h.EvalPackage(context.Background(), Check{
		ID: "c", Type: "package", Package: "telnet", Present: &yes,
	})
	if res.Pass {
		t.Fatal("an absent package passed a presence check")
	}
}

func TestSystemdUnitStates(t *testing.T) {
	yes, no := true, false

	// "static" means the unit comes up, so treating only "enabled" as enabled
	// would report a false finding on a correct host.
	for _, state := range []string{"enabled", "enabled-runtime", "static", "indirect", "alias"} {
		h := &Host{Runner: &fakeRunner{stdout: state + "\n"}}
		res := h.EvalSystemdUnit(context.Background(), Check{
			ID: "c", Type: "systemd_unit", Unit: "sshd.service", Enabled: &yes,
		})
		if !res.Pass {
			t.Errorf("%q was not treated as enabled: %s", state, res.Detail)
		}
	}
	for _, state := range []string{"disabled", "masked", "not-found"} {
		h := &Host{Runner: &fakeRunner{stdout: state + "\n"}}
		res := h.EvalSystemdUnit(context.Background(), Check{
			ID: "c", Type: "systemd_unit", Unit: "telnet.socket", Enabled: &no,
		})
		if !res.Pass {
			t.Errorf("%q was not treated as disabled: %s", state, res.Detail)
		}
	}

	h := &Host{Runner: &fakeRunner{stdout: "active\n"}}
	if res := h.EvalSystemdUnit(context.Background(), Check{
		ID: "c", Type: "systemd_unit", Unit: "sshd.service", Active: &yes,
	}); !res.Pass {
		t.Errorf("an active unit failed: %s", res.Detail)
	}
}

// A unit name is interpolated into an argv, so it is constrained to what a
// unit name can contain.
func TestUnitAndPackageNamesAreConstrained(t *testing.T) {
	h := &Host{Root: t.TempDir(), Runner: &fakeRunner{}}
	yes := true
	for _, unit := range []string{"a b.service", "a;b", "$(id)", "../x", "a|b"} {
		res := h.EvalSystemdUnit(context.Background(), Check{
			ID: "c", Type: "systemd_unit", Unit: unit, Enabled: &yes,
		})
		if res.Pass || !strings.Contains(res.Detail, "unusable characters") {
			t.Errorf("unit %q: %q", unit, res.Detail)
		}
	}
	for _, pkg := range []string{"a b", "a;b", "$(id)", "a|b"} {
		res := h.EvalPackage(context.Background(), Check{ID: "c", Type: "package", Package: pkg})
		if res.Pass || !strings.Contains(res.Detail, "unusable characters") {
			t.Errorf("package %q: %q", pkg, res.Detail)
		}
	}
}

func writeDir(t *testing.T, h *Host, path string) {
	t.Helper()
	write(t, h, path, "", 0o644)
}
