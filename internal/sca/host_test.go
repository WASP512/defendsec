package sca

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fake root, so the checks most likely to be wrong — the ones that read
// /proc — are actually exercised rather than skipped on a build machine.
func fakeHost(t *testing.T) *Host {
	t.Helper()
	root := t.TempDir()
	return &Host{
		Root: root,
		// The accounts a benchmark names do not exist here.
		LookupUser: func(name string) (uint32, error) {
			switch name {
			case "root":
				return 0, nil
			case "syslog":
				return 104, nil
			}
			return 0, os.ErrNotExist
		},
		LookupGroup: func(name string) (uint32, error) {
			switch name {
			case "root":
				return 0, nil
			case "adm":
				return 4, nil
			}
			return 0, os.ErrNotExist
		},
	}
}

func write(t *testing.T, h *Host, path, body string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(h.Root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile respects umask, so set the mode explicitly or a test for
	// 0600 would pass against a file the umask already narrowed.
	if err := os.Chmod(full, mode); err != nil {
		t.Fatal(err)
	}
}

// Benchmarks say "no more permissive than", so a stricter host must pass.
// An exact comparison would fail a correctly-hardened machine and teach
// operators to ignore the result.
func TestFileModeIsAMaximumNotAnEquality(t *testing.T) {
	h := fakeHost(t)
	write(t, h, "/etc/shadow", "x", 0o640)

	cases := map[string]struct {
		maxMode string
		want    bool
	}{
		"exactly the maximum": {"0640", true},
		"stricter than asked": {"0600", false}, // 0640 has group read, 0600 does not allow it
		"looser maximum":      {"0644", true},
		"world writable bar":  {"0666", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := h.EvalFileMode(Check{ID: "c", Type: "file_mode", Path: "/etc/shadow", MaxMode: tc.maxMode})
			if res.Pass != tc.want {
				t.Errorf("pass = %v, want %v (%s)", res.Pass, tc.want, res.Detail)
			}
		})
	}

	// A world-readable file must fail a 0640 maximum, and the detail must
	// name the offending bits.
	write(t, h, "/etc/loose", "x", 0o644)
	res := h.EvalFileMode(Check{ID: "c", Type: "file_mode", Path: "/etc/loose", MaxMode: "0640"})
	if res.Pass {
		t.Fatal("a world-readable file passed a 0640 maximum")
	}
	if !strings.Contains(res.Detail, "0644") || !strings.Contains(res.Detail, "extra") {
		t.Errorf("detail does not identify the problem: %q", res.Detail)
	}
}

func TestFileModeOwnership(t *testing.T) {
	h := fakeHost(t)
	write(t, h, "/etc/passwd", "x", 0o644)

	// The test process owns the file, so root ownership must fail unless the
	// tests are running as root.
	res := h.EvalFileMode(Check{ID: "c", Type: "file_mode", Path: "/etc/passwd", Owner: "root"})
	if os.Getuid() == 0 {
		if !res.Pass {
			t.Errorf("running as root, but root ownership failed: %s", res.Detail)
		}
	} else if res.Pass {
		t.Errorf("a file owned by uid %d passed a root-ownership check", os.Getuid())
	}

	// An account that does not exist is reported as such rather than as a
	// failed check: the difference matters when reading a report.
	res = h.EvalFileMode(Check{ID: "c", Type: "file_mode", Path: "/etc/passwd", Owner: "nosuchuser"})
	if res.Pass || !strings.Contains(res.Detail, "unknown owner") {
		t.Errorf("detail = %q", res.Detail)
	}
}

// Whether a missing file is good depends entirely on the file, so it is
// reported rather than guessed at.
func TestFileModeOnAMissingFile(t *testing.T) {
	h := fakeHost(t)
	res := h.EvalFileMode(Check{ID: "c", Type: "file_mode", Path: "/etc/nope", MaxMode: "0644"})
	if res.Pass {
		t.Fatal("a missing file passed a permission check")
	}
	if !strings.Contains(res.Detail, "does not exist") {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestSysctl(t *testing.T) {
	h := fakeHost(t)
	write(t, h, "/proc/sys/net/ipv4/ip_forward", "0\n", 0o644)
	write(t, h, "/proc/sys/kernel/randomize_va_space", "2\n", 0o644)
	// Some parameters are tab-separated lists.
	write(t, h, "/proc/sys/net/ipv4/tcp_rmem", "4096\t131072\t6291456\n", 0o644)

	cases := map[string]struct {
		key, expect string
		want        bool
	}{
		"matching":            {"net.ipv4.ip_forward", "0", true},
		"not matching":        {"net.ipv4.ip_forward", "1", false},
		"another matching":    {"kernel.randomize_va_space", "2", true},
		"whitespace tolerant": {"net.ipv4.tcp_rmem", "4096 131072 6291456", true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := h.EvalSysctl(Check{ID: "c", Type: "sysctl", Key: tc.key, Expect: tc.expect})
			if res.Pass != tc.want {
				t.Errorf("pass = %v, want %v (%s)", res.Pass, tc.want, res.Detail)
			}
		})
	}

	// An absent parameter usually means the module is not loaded, which is a
	// different fact from a wrong value.
	res := h.EvalSysctl(Check{ID: "c", Type: "sysctl", Key: "net.ipv4.nonexistent", Expect: "1"})
	if res.Pass {
		t.Error("an absent parameter passed")
	}
	if !strings.Contains(res.Detail, "not present on this kernel") {
		t.Errorf("detail = %q", res.Detail)
	}

	// A key with a slash would escape the dotted-to-path mapping.
	res = h.EvalSysctl(Check{ID: "c", Type: "sysctl", Key: "../../etc/passwd", Expect: "x"})
	if res.Pass {
		t.Fatal("a key containing a path separator was evaluated")
	}
	if !strings.Contains(res.Detail, "must use dots") {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestMountOptions(t *testing.T) {
	h := fakeHost(t)
	write(t, h, "/proc/mounts", strings.Join([]string{
		"proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0",
		"/dev/sda1 / ext4 rw,relatime 0 0",
		"tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime 0 0",
		"/dev/sdb1 /mnt/my\\040disk ext4 rw,relatime 0 0",
		"tmpfs /var/tmp tmpfs rw,relatime 0 0",
	}, "\n")+"\n", 0o644)

	pass := h.EvalMountOption(Check{
		ID: "c", Type: "mount_option", MountPoint: "/tmp",
		RequireOptions: []string{"nosuid", "nodev", "noexec"},
	})
	if !pass.Pass {
		t.Errorf("/tmp should satisfy the options: %s", pass.Detail)
	}

	fail := h.EvalMountOption(Check{
		ID: "c", Type: "mount_option", MountPoint: "/var/tmp",
		RequireOptions: []string{"nosuid", "noexec"},
	})
	if fail.Pass {
		t.Error("/var/tmp passed without the required options")
	}
	if !strings.Contains(fail.Detail, "missing nosuid") {
		t.Errorf("detail does not name what is missing: %q", fail.Detail)
	}

	forbid := h.EvalMountOption(Check{
		ID: "c", Type: "mount_option", MountPoint: "/", ForbidOptions: []string{"rw"},
	})
	if forbid.Pass {
		t.Error("a forbidden option was not detected")
	}

	// Not a separate mount point is the finding, not a pass: a benchmark
	// asking for nodev on /home assumes /home is its own filesystem.
	missing := h.EvalMountOption(Check{
		ID: "c", Type: "mount_option", MountPoint: "/home", RequireOptions: []string{"nodev"},
	})
	if missing.Pass {
		t.Error("a non-existent mount point passed")
	}
	if !strings.Contains(missing.Detail, "not a separate mount point") {
		t.Errorf("detail = %q", missing.Detail)
	}

	// Mount points with spaces are octal-escaped by the kernel.
	spaced := h.EvalMountOption(Check{
		ID: "c", Type: "mount_option", MountPoint: "/mnt/my disk", ForbidOptions: []string{"noexec"},
	})
	if !spaced.Pass {
		t.Errorf("an escaped mount point was not decoded: %s", spaced.Detail)
	}
}

// A filesystem mounted twice over the same point is governed by the most
// recent mount; checking the first would report options no longer in effect.
func TestMountOptionsUsesTheLastMatchingEntry(t *testing.T) {
	h := fakeHost(t)
	write(t, h, "/proc/mounts", strings.Join([]string{
		"tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0",
		"tmpfs /tmp tmpfs rw 0 0",
	}, "\n")+"\n", 0o644)

	res := h.EvalMountOption(Check{
		ID: "c", Type: "mount_option", MountPoint: "/tmp", RequireOptions: []string{"noexec"},
	})
	if res.Pass {
		t.Fatal("the earlier, overridden mount was used")
	}
}

func TestUnescapeMount(t *testing.T) {
	cases := map[string]string{
		`/mnt/my\040disk`: "/mnt/my disk",
		`/plain`:          "/plain",
		`/tab\011here`:    "/tab\there",
		`/back\134slash`:  `/back\slash`,
		`/bad\09`:         `/bad\09`, // too short to be an escape, left alone
	}
	for in, want := range cases {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}
