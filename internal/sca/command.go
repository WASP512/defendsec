package sca

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Command-output checks (roadmap 3.7).
//
// # Why this is narrow on purpose
//
// A benchmark pack is a data file, and a `command` check makes that data file
// executable. The roadmap also wants packs distributed as signed, versioned
// artifacts — at which point "run whatever this YAML says" becomes remote code
// execution on every host with a signature-checking step in front of it, and
// signatures are a supply-chain control, not a sandbox.
//
// So the other five new check types were implemented natively instead. File
// mode uses stat, sysctl reads /proc/sys, mount options parse /proc/mounts,
// package presence and unit state call one fixed binary with a fixed argument
// shape. None of them can run anything a pack chooses. `command` is the only
// general one, and it is constrained accordingly:
//
//   - argv, never a shell string. There is no `sh -c`, so there is no
//     globbing, no pipeline, no substitution, no `;`, and no quoting bug that
//     turns a filename into a second command.
//   - an allowlist of executables, defaulting to read-only introspection
//     tools. A pack naming anything else fails to load rather than running.
//   - absolute paths resolved from a fixed set of directories, so a writable
//     directory earlier in PATH cannot substitute the binary.
//   - a timeout and an output cap, because a check that hangs stops the whole
//     inventory report and a check that prints forever exhausts memory.
//
// This is deliberately not a sandbox. It is a reduction in blast radius, and
// an operator who adds a shell to the allowlist has removed most of it. The
// documentation says so plainly rather than implying a guarantee.

// Runner executes an allowlisted command.
type Runner interface {
	Run(ctx context.Context, argv []string) (stdout string, exitCode int, err error)
}

const (
	// commandTimeout bounds one check. Inventory reports are on a schedule;
	// a check that hangs would stall every later check behind it.
	commandTimeout = 10 * time.Second
	// maxCommandOutput caps what is read. Benchmarks compare against a line
	// or two, and an unbounded read is a free memory exhaustion.
	maxCommandOutput = 256 * 1024
)

// DefaultAllowedCommands is the set a pack may invoke.
//
// Every entry reads state and changes nothing. Notably absent: any shell, any
// interpreter, and anything that writes. Adding one of those is a decision an
// operator can make, and the docs say what it costs.
var DefaultAllowedCommands = []string{
	"systemctl", "dpkg-query", "rpm", "sysctl", "mount", "findmnt",
	"stat", "getent", "id", "sestatus", "getenforce", "auditctl",
	"grep", "awk", "modprobe", "lsmod", "ss", "sshd", "iptables-save", "nft",
}

// commandDirs are where an allowlisted binary may live. Resolving from a fixed
// list rather than PATH means a writable directory earlier in PATH cannot
// substitute the binary a check intends to run.
var commandDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// ErrCommandNotAllowed is returned when a pack names an executable outside the
// allowlist.
var ErrCommandNotAllowed = errors.New("command is not in the allowlist")

// execRunner is the default Runner.
type execRunner struct {
	allowed map[string]bool
	dirs    []string
}

// NewRunner builds a runner over an allowlist. An empty list means the
// default set.
func NewRunner(allowed []string) Runner {
	if len(allowed) == 0 {
		allowed = DefaultAllowedCommands
	}
	set := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		set[strings.TrimSpace(name)] = true
	}
	return &execRunner{allowed: set, dirs: commandDirs}
}

func (r *execRunner) Run(ctx context.Context, argv []string) (string, int, error) {
	if len(argv) == 0 {
		return "", -1, fmt.Errorf("empty command")
	}
	name := argv[0]
	// A pack names a bare executable, never a path. Accepting a path would
	// make the allowlist meaningless: /tmp/systemctl is not systemctl.
	if strings.ContainsAny(name, "/\\") {
		return "", -1, fmt.Errorf("%w: %q must be a bare executable name, not a path", ErrCommandNotAllowed, name)
	}
	if !r.allowed[name] {
		return "", -1, fmt.Errorf("%w: %q", ErrCommandNotAllowed, name)
	}

	path, err := r.resolve(name)
	if err != nil {
		return "", -1, err
	}

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	// exec.CommandContext with an argv slice: no shell is involved at any
	// point, so nothing in the arguments can become syntax.
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	// A deliberately empty environment. Inheriting the agent's would let
	// PATH, LD_PRELOAD or a locale change what a check observes.
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

	var buf bytes.Buffer
	cmd.Stdout = &limitedWriter{W: &buf, N: maxCommandOutput}
	cmd.Stderr = &limitedWriter{W: &buf, N: maxCommandOutput}

	runErr := cmd.Run()
	out := buf.String()

	if ctx.Err() != nil {
		return out, -1, fmt.Errorf("command timed out after %s", commandTimeout)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		// A non-zero exit is data, not a failure: `systemctl is-enabled` uses
		// it to mean "disabled", and treating it as an error would make the
		// answer unreachable.
		return out, exitErr.ExitCode(), nil
	}
	if runErr != nil {
		return out, -1, runErr
	}
	return out, 0, nil
}

func (r *execRunner) resolve(name string) (string, error) {
	for _, dir := range r.dirs {
		candidate := filepath.Join(dir, name)
		if info, err := exec.LookPath(candidate); err == nil {
			return info, nil
		}
	}
	return "", fmt.Errorf("%q is allowlisted but was not found in %s", name, strings.Join(r.dirs, ", "))
}

// limitedWriter stops after N bytes rather than erroring, so a chatty command
// still yields the beginning of its output — which is the part a check
// compares against.
type limitedWriter struct {
	W interface{ Write([]byte) (int, error) }
	N int
}

// Write always reports the full length. The io.Writer contract requires an
// error whenever n < len(p), and exec's output copier treats a short write as
// a failure — so truncating and reporting the truncated count would turn a
// chatty command into a failed check rather than a capped one.
func (l *limitedWriter) Write(p []byte) (int, error) {
	total := len(p)
	if l.N <= 0 {
		return total, nil
	}
	if len(p) > l.N {
		p = p[:l.N]
	}
	n, err := l.W.Write(p)
	l.N -= n
	if err != nil {
		return n, err
	}
	return total, nil
}

func (h *Host) runner() Runner {
	if h != nil && h.Runner != nil {
		return h.Runner
	}
	return NewRunner(nil)
}

// EvalCommand runs an allowlisted command and evaluates its output.
func (h *Host) EvalCommand(ctx context.Context, check Check) Result {
	res := newResult(check)
	if len(check.Command) == 0 {
		res.Detail = "check is missing command"
		return res
	}
	if check.OutputMatches == "" && check.OutputNotMatches == "" && check.ExitCode == nil {
		res.Detail = "check specifies no expectation: set output_matches, output_not_matches or exit_code"
		return res
	}

	out, code, err := h.runner().Run(ctx, check.Command)
	if err != nil {
		res.Detail = fmt.Sprintf("%s: %v", strings.Join(check.Command, " "), err)
		return res
	}

	var problems []string
	if check.ExitCode != nil && code != *check.ExitCode {
		problems = append(problems, fmt.Sprintf("exit code %d, want %d", code, *check.ExitCode))
	}
	if check.OutputMatches != "" {
		re, err := regexp.Compile(check.OutputMatches)
		if err != nil {
			res.Detail = fmt.Sprintf("output_matches is not a valid regular expression: %v", err)
			return res
		}
		if !re.MatchString(out) {
			problems = append(problems, "output does not match "+check.OutputMatches)
		}
	}
	if check.OutputNotMatches != "" {
		re, err := regexp.Compile(check.OutputNotMatches)
		if err != nil {
			res.Detail = fmt.Sprintf("output_not_matches is not a valid regular expression: %v", err)
			return res
		}
		if re.MatchString(out) {
			problems = append(problems, "output matches "+check.OutputNotMatches)
		}
	}

	summary := firstLine(out)
	if len(problems) > 0 {
		res.Detail = fmt.Sprintf("%s: %s (output: %s)",
			strings.Join(check.Command, " "), strings.Join(problems, "; "), summary)
		return res
	}
	res.Pass = true
	res.Detail = fmt.Sprintf("%s: %s", strings.Join(check.Command, " "), summary)
	return res
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(no output)"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " …"
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// checkAllowed reports whether a pack may name this executable, using the
// default allowlist. Used at load time so a pack that could never run fails
// where somebody is reading it rather than on every host at once.
func checkAllowed(name string) error {
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("%w: %q must be a bare executable name, not a path", ErrCommandNotAllowed, name)
	}
	for _, allowed := range DefaultAllowedCommands {
		if allowed == name {
			return nil
		}
	}
	return fmt.Errorf("%w: %q (allowed: %s)", ErrCommandNotAllowed, name,
		strings.Join(DefaultAllowedCommands, ", "))
}
