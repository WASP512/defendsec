package sca

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Host is the machine a check runs against.
//
// The root exists so every check that reads the filesystem can be tested
// against a directory tree instead of against the machine running the tests.
// Checks that consult /proc are the ones most likely to be wrong, and they are
// exactly the ones that cannot be exercised on a developer's laptop without
// it — a check nobody can test is a check nobody should trust.
type Host struct {
	// Root is prefixed to absolute paths. Empty means the real filesystem.
	Root string
	// LookupUser and LookupGroup resolve names to ids. Replaced in tests,
	// because the accounts a benchmark names do not exist on a build machine.
	LookupUser  func(name string) (uid uint32, err error)
	LookupGroup func(name string) (gid uint32, err error)
	// Runner executes commands. Nil means the default, allowlisted runner.
	Runner Runner
}

// LocalHost is the real machine.
func LocalHost() *Host { return &Host{} }

// resolve maps a check's path into the host's root.
func (h *Host) resolve(path string) string {
	if h == nil || h.Root == "" {
		return path
	}
	return filepath.Join(h.Root, path)
}

func (h *Host) lookupUser(name string) (uint32, error) {
	if h != nil && h.LookupUser != nil {
		return h.LookupUser(name)
	}
	// A numeric value is taken as an id directly. Benchmarks write both, and
	// a host with a broken name service should still be checkable.
	if id, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(id), nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	return uint32(id), err
}

func (h *Host) lookupGroup(name string) (uint32, error) {
	if h != nil && h.LookupGroup != nil {
		return h.LookupGroup(name)
	}
	if id, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(id), nil
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(g.Gid, 10, 32)
	return uint32(id), err
}

// EvalFileMode checks permission bits and ownership (roadmap 3.7).
//
// The mode is compared as a maximum rather than an exact value: benchmarks say
// "no more permissive than 0644", and an exact comparison would fail a host
// that is correctly stricter than the baseline, teaching operators to ignore
// the result.
func (h *Host) EvalFileMode(check Check) Result {
	res := newResult(check)
	if check.Path == "" {
		res.Detail = "check is missing path"
		return res
	}
	if check.MaxMode == "" && check.Owner == "" && check.Group == "" {
		res.Detail = "check specifies neither max_mode, owner nor group"
		return res
	}

	info, err := os.Stat(h.resolve(check.Path))
	if err != nil {
		if os.IsNotExist(err) {
			// A missing file is reported as its own outcome rather than as a
			// pass or a failure. Whether absence is good depends entirely on
			// the file, and guessing would be wrong half the time.
			res.Detail = fmt.Sprintf("%s does not exist", check.Path)
			return res
		}
		res.Detail = fmt.Sprintf("cannot read %s: %v", check.Path, err)
		return res
	}

	var problems []string
	perm := info.Mode().Perm()

	if check.MaxMode != "" {
		maxMode, err := strconv.ParseUint(strings.TrimPrefix(check.MaxMode, "0o"), 8, 32)
		if err != nil {
			res.Detail = fmt.Sprintf("max_mode %q is not octal", check.MaxMode)
			return res
		}
		// Any bit set on the file that is not allowed by the maximum is a
		// finding. This is the "no more permissive than" test; a numeric
		// comparison would accept 0604 against a maximum of 0640.
		if extra := perm &^ os.FileMode(maxMode); extra != 0 {
			problems = append(problems, fmt.Sprintf(
				"mode is %04o, more permissive than %04o (extra: %04o)", perm, maxMode, extra))
		}
	}

	if check.Owner != "" || check.Group != "" {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			res.Detail = "ownership is not available on this platform"
			return res
		}
		if check.Owner != "" {
			want, err := h.lookupUser(check.Owner)
			if err != nil {
				res.Detail = fmt.Sprintf("unknown owner %q: %v", check.Owner, err)
				return res
			}
			if stat.Uid != want {
				problems = append(problems, fmt.Sprintf("owner is uid %d, want %d (%s)", stat.Uid, want, check.Owner))
			}
		}
		if check.Group != "" {
			want, err := h.lookupGroup(check.Group)
			if err != nil {
				res.Detail = fmt.Sprintf("unknown group %q: %v", check.Group, err)
				return res
			}
			if stat.Gid != want {
				problems = append(problems, fmt.Sprintf("group is gid %d, want %d (%s)", stat.Gid, want, check.Group))
			}
		}
	}

	if len(problems) > 0 {
		res.Detail = strings.Join(problems, "; ")
		return res
	}
	res.Pass = true
	res.Detail = fmt.Sprintf("%s: mode %04o", check.Path, perm)
	return res
}

// EvalSysctl checks a kernel parameter.
//
// Read from /proc/sys rather than by running sysctl(8): there is no process to
// spawn, nothing to parse out of human-readable output, and no dependency on a
// binary that a minimal container may not have.
func (h *Host) EvalSysctl(check Check) Result {
	res := newResult(check)
	if check.Key == "" {
		res.Detail = "check is missing key"
		return res
	}
	if check.Expect == "" {
		res.Detail = "check is missing expect"
		return res
	}
	// Dots are path separators under /proc/sys. A key containing a slash
	// would escape that mapping, so it is refused rather than normalised.
	if strings.ContainsAny(check.Key, "/\\") {
		res.Detail = fmt.Sprintf("sysctl key %q must use dots, not slashes", check.Key)
		return res
	}

	path := filepath.Join("/proc/sys", filepath.Join(strings.Split(check.Key, ".")...))
	raw, err := os.ReadFile(h.resolve(path))
	if err != nil {
		if os.IsNotExist(err) {
			// An absent parameter usually means the module is not loaded,
			// which is a different fact from a wrong value and is worth
			// saying so an operator does not go looking for a typo.
			res.Detail = fmt.Sprintf("%s is not present on this kernel", check.Key)
			return res
		}
		res.Detail = fmt.Sprintf("cannot read %s: %v", check.Key, err)
		return res
	}

	// Kernel values can be tab-separated lists; compare field by field so
	// whitespace differences do not register as a finding.
	got := strings.Join(strings.Fields(string(raw)), " ")
	want := strings.Join(strings.Fields(check.Expect), " ")
	if got == want {
		res.Pass = true
	}
	res.Detail = fmt.Sprintf("%s = %s (want %s)", check.Key, got, want)
	return res
}

// mountEntry is one line of /proc/mounts.
type mountEntry struct {
	Device  string
	Point   string
	FSType  string
	Options []string
}

// readMounts parses the host's mount table.
func (h *Host) readMounts() ([]mountEntry, error) {
	f, err := os.Open(h.resolve("/proc/mounts"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []mountEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		out = append(out, mountEntry{
			Device: unescapeMount(fields[0]),
			// Mount points with spaces are written with octal escapes, so
			// they have to be decoded or "/mnt/my disk" never matches.
			Point:   unescapeMount(fields[1]),
			FSType:  fields[2],
			Options: strings.Split(fields[3], ","),
		})
	}
	return out, sc.Err()
}

// unescapeMount decodes the octal escapes the kernel writes for spaces, tabs,
// newlines and backslashes in mount fields.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// EvalMountOption checks the options a filesystem is mounted with.
func (h *Host) EvalMountOption(check Check) Result {
	res := newResult(check)
	if check.MountPoint == "" {
		res.Detail = "check is missing mount_point"
		return res
	}
	if len(check.RequireOptions) == 0 && len(check.ForbidOptions) == 0 {
		res.Detail = "check specifies neither require_options nor forbid_options"
		return res
	}

	mounts, err := h.readMounts()
	if err != nil {
		res.Detail = fmt.Sprintf("cannot read mount table: %v", err)
		return res
	}

	// The last matching entry wins: a filesystem mounted twice over the same
	// point is governed by the most recent mount, and checking the first
	// would report options that are no longer in effect.
	var found *mountEntry
	for i := range mounts {
		if mounts[i].Point == check.MountPoint {
			found = &mounts[i]
		}
	}
	if found == nil {
		// Not a pass: a benchmark asking for nodev on /tmp assumes /tmp is a
		// separate filesystem, and it not being one is the finding.
		res.Detail = fmt.Sprintf("%s is not a separate mount point", check.MountPoint)
		return res
	}

	has := make(map[string]bool, len(found.Options))
	for _, opt := range found.Options {
		has[strings.TrimSpace(opt)] = true
	}

	var problems []string
	for _, want := range check.RequireOptions {
		if !has[strings.TrimSpace(want)] {
			problems = append(problems, "missing "+want)
		}
	}
	for _, forbidden := range check.ForbidOptions {
		if has[strings.TrimSpace(forbidden)] {
			problems = append(problems, "has "+forbidden)
		}
	}

	if len(problems) > 0 {
		res.Detail = fmt.Sprintf("%s (%s): %s", check.MountPoint,
			strings.Join(found.Options, ","), strings.Join(problems, ", "))
		return res
	}
	res.Pass = true
	res.Detail = fmt.Sprintf("%s mounted %s", check.MountPoint, strings.Join(found.Options, ","))
	return res
}

// newResult seeds a result from its check, so every evaluator carries the
// same identity and tags without repeating itself.
func newResult(check Check) Result {
	return Result{
		CheckID:  check.ID,
		Title:    check.Title,
		Severity: check.Severity,
		Pass:     false,
		Controls: check.Controls,
	}
}
