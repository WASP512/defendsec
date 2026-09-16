package sensor

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/events"
)

// ProcSensor observes process execution by polling /proc.
type ProcSensor struct {
	// Root is prefixed to /proc, so the sensor can be tested against a
	// directory tree rather than against the machine running the tests.
	Root string
	// DeviceID and Hostname stamp every event.
	DeviceID string
	Hostname string
	// Tree records lineage as processes are seen (roadmap 3.5).
	Tree *events.Tree
	// Interval overrides the poll interval.
	Interval time.Duration

	// known is the pid set from the previous sample, so a new pid is one that
	// was not there last time.
	known map[int32]procInfo
}

type procInfo struct {
	startTicks uint64
	image      string
}

// NewProcSensor creates a portable process sensor.
func NewProcSensor(deviceID, hostname string, tree *events.Tree) *ProcSensor {
	return &ProcSensor{
		DeviceID: deviceID, Hostname: hostname, Tree: tree,
		known: map[int32]procInfo{},
	}
}

// Name identifies the sensor.
func (p *ProcSensor) Name() string { return "proc-poll" }

// Describe states what polling can and cannot see.
func (p *ProcSensor) Describe() Capability {
	return Capability{
		Name:     p.Name(),
		Kinds:    []events.Kind{events.KindProcess},
		Complete: false,
		Limitations: []string{
			"Samples /proc every " + p.interval().String() + ", so a process that starts and exits between samples is never seen. Short-lived commands, including the `curl … | sh` pattern, are frequently missed.",
			"Reads the command line after the process has started, so a process that rewrites its own argv is recorded as it rewrote itself.",
			"Observes process execution only. Network connections, file writes, privilege transitions and module loads are not visible to this sensor.",
			"Use the eBPF sensor where it is available: it observes every execution exactly once, with the argument vector as passed.",
		},
	}
}

func (p *ProcSensor) interval() time.Duration {
	if p.Interval > 0 {
		return p.Interval
	}
	return pollInterval
}

// procPath resolves a path under /proc, honouring the test root.
//
// The empty root has to be handled explicitly: filepath.Join("", "proc")
// yields the *relative* path "proc", not "/proc", so a sensor with no root
// configured would silently read a directory that does not exist and report
// no processes at all. That is precisely what it did until a run against a
// real /proc caught it — the fake-root tests could not, because they always
// set a root.
func (p *ProcSensor) procPath(parts ...string) string {
	root := p.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root, "proc"}, parts...)...)
}

// Run polls until the context is cancelled.
func (p *ProcSensor) Run(ctx context.Context, sink func(*events.Event)) error {
	ticker := time.NewTicker(p.interval())
	defer ticker.Stop()

	// The first sample establishes the baseline. Emitting an event for every
	// process already running would produce a burst of alerts about a host's
	// normal state every time the agent restarts.
	p.scan(time.Now().UTC(), nil)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			p.scan(time.Now().UTC(), sink)
		}
	}
}

// Scan performs one sample. Exported for tests, which need to drive the
// sensor deterministically rather than waiting on a ticker.
func (p *ProcSensor) Scan(now time.Time, sink func(*events.Event)) {
	p.scan(now, sink)
}

func (p *ProcSensor) scan(now time.Time, sink func(*events.Event)) {
	entries, err := os.ReadDir(p.procPath())
	if err != nil {
		return
	}

	seen := make(map[int32]procInfo, len(entries))
	for _, entry := range entries {
		pid64, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid64 <= 0 {
			continue
		}
		pid := int32(pid64)

		info, ok := p.read(pid)
		if !ok {
			// The process exited while being read, which is normal and
			// frequent. Not an error worth reporting.
			continue
		}
		seen[pid] = info

		previous, existed := p.known[pid]
		// A pid whose start time changed is a different process that reused
		// the number, not the same one. Comparing only the pid would silently
		// merge two processes and attribute one's children to the other.
		if existed && previous.startTicks == info.startTicks {
			continue
		}

		ev := p.event(pid, now)
		if ev == nil {
			continue
		}
		if p.Tree != nil {
			p.Tree.Observe(ev.PID, ev.PPID,
				ev.String(events.FieldImage), ev.String(events.FieldCommandLine),
				ev.String(events.FieldUser), now)
		}
		if sink != nil {
			sink(ev)
		}
	}

	// Anything gone since the last sample has exited. Recorded in the tree so
	// a child that outlives its parent still has a lineage.
	if p.Tree != nil {
		for pid := range p.known {
			if _, still := seen[pid]; !still {
				p.Tree.MarkExited(pid, now)
			}
		}
	}
	p.known = seen
}

// read gathers the stable identity of a process: its start time and image.
func (p *ProcSensor) read(pid int32) (procInfo, bool) {
	raw, err := os.ReadFile(p.procPath(strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return procInfo{}, false
	}
	start, ok := startTicks(string(raw))
	if !ok {
		return procInfo{}, false
	}
	return procInfo{startTicks: start, image: p.exe(pid)}, true
}

// startTicks extracts field 22 of /proc/<pid>/stat.
//
// The comm field is parenthesised and can itself contain spaces and
// parentheses, so the fields cannot simply be split on whitespace. Everything
// after the last ')' is the part that can.
func startTicks(stat string) (uint64, bool) {
	close := strings.LastIndex(stat, ")")
	if close < 0 || close+2 > len(stat) {
		return 0, false
	}
	fields := strings.Fields(stat[close+1:])
	// After comm, field 3 of the original is index 0 here, so starttime
	// (field 22) is index 19.
	const startIndex = 19
	if len(fields) <= startIndex {
		return 0, false
	}
	value, err := strconv.ParseUint(fields[startIndex], 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func (p *ProcSensor) exe(pid int32) string {
	if target, err := os.Readlink(p.procPath(strconv.Itoa(int(pid)), "exe")); err == nil {
		// A deleted binary still running shows as "/path (deleted)", which is
		// itself worth keeping rather than trimming: a process running from a
		// binary that has been unlinked is a common anti-forensic move.
		return target
	}
	return ""
}

// event builds a process event from /proc.
func (p *ProcSensor) event(pid int32, now time.Time) *events.Event {
	dir := p.procPath(strconv.Itoa(int(pid)))

	cmdline, args := p.cmdline(dir)
	image := p.exe(pid)
	if image == "" {
		// Kernel threads have no exe link. Falling back to the comm field
		// keeps them visible rather than dropping them silently.
		image = p.comm(dir)
	}
	if image == "" && cmdline == "" {
		return nil
	}

	ppid, uid := p.statusFields(dir)

	ev := &events.Event{
		ID: newEventID(), DeviceID: p.DeviceID, Hostname: p.Hostname,
		Kind: events.KindProcess, At: now, PID: pid, PPID: ppid,
	}
	ev.Set(events.FieldImage, image)
	ev.Set(events.FieldCommandLine, cmdline)
	ev.Set(events.FieldProcessID, pid)
	ev.Set(events.FieldParentProcessID, ppid)
	if len(args) > 1 {
		// argv as a list, so a rule matching one argument does not
		// accidentally match a substring spanning two.
		ev.Set("CommandLineArgs", args)
	}
	if uid >= 0 {
		ev.Set(events.FieldUID, uid)
		ev.Set(events.FieldUser, lookupUser(uid))
	}
	if parent := p.exe(ppid); parent != "" {
		ev.Set(events.FieldParentImage, parent)
	}
	if parentCmd, _ := p.cmdline(p.procPath(strconv.Itoa(int(ppid)))); parentCmd != "" {
		ev.Set(events.FieldParentCommand, parentCmd)
	}
	if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
		ev.Set(events.FieldCurrentDirectory, cwd)
	}
	return ev
}

// cmdline reads the argument vector, which is NUL-separated.
func (p *ProcSensor) cmdline(dir string) (string, []string) {
	raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil || len(raw) == 0 {
		return "", nil
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, " "), out
}

func (p *ProcSensor) comm(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// statusFields reads PPid and the real Uid from /proc/<pid>/status.
func (p *ProcSensor) statusFields(dir string) (ppid int32, uid int) {
	uid = -1
	f, err := os.Open(filepath.Join(dir, "status"))
	if err != nil {
		return 0, uid
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "PPid:"):
			if v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32); err == nil {
				ppid = int32(v)
			}
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				if v, err := strconv.Atoi(fields[0]); err == nil {
					uid = v
				}
			}
		}
		if ppid != 0 && uid >= 0 {
			break
		}
	}
	return ppid, uid
}

// lookupUser resolves a uid to a name, falling back to the number. A host with
// a broken or slow name service should still produce usable events.
func lookupUser(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return strconv.Itoa(uid)
}

func newEventID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A collision is harmless here — the id exists so an alert can point
		// at a record — so a clock-derived fallback beats failing.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}
