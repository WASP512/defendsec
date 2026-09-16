package sensor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"defendsec/internal/events"
)

// A fake /proc, so the sensor is testable rather than only observable on the
// machine running the tests.
type fakeProc struct {
	root string
	t    *testing.T
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	return &fakeProc{root: t.TempDir(), t: t}
}

// add writes the /proc entries the sensor reads for one process.
func (f *fakeProc) add(pid, ppid int32, exe string, argv []string, uid int, startTicks uint64) {
	f.t.Helper()
	dir := filepath.Join(f.root, "proc", strconv.Itoa(int(pid)))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		f.t.Fatal(err)
	}

	// The comm field is parenthesised and can contain spaces and parentheses,
	// which is exactly what makes naive field splitting wrong.
	comm := filepath.Base(exe)
	stat := strconv.Itoa(int(pid)) + " (" + comm + ") S " + strings.Repeat("0 ", 18) +
		strconv.FormatUint(startTicks, 10) + " 0 0"
	f.write(dir, "stat", stat)
	f.write(dir, "comm", comm)
	f.write(dir, "cmdline", strings.Join(argv, "\x00"))
	f.write(dir, "status", "Name:\t"+comm+"\nPPid:\t"+strconv.Itoa(int(ppid))+"\nUid:\t"+
		strconv.Itoa(uid)+"\t"+strconv.Itoa(uid)+"\t"+strconv.Itoa(uid)+"\t"+strconv.Itoa(uid)+"\n")

	// exe and cwd are symlinks on a real /proc. A dangling link is fine:
	// Readlink returns the target without resolving it.
	_ = os.Remove(filepath.Join(dir, "exe"))
	if err := os.Symlink(exe, filepath.Join(dir, "exe")); err != nil {
		f.t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "cwd"))
	if err := os.Symlink("/home/deploy", filepath.Join(dir, "cwd")); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) remove(pid int32) {
	f.t.Helper()
	if err := os.RemoveAll(filepath.Join(f.root, "proc", strconv.Itoa(int(pid)))); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) write(dir, name, body string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeProc) sensor(tree *events.Tree) *ProcSensor {
	s := NewProcSensor("dev-1", "host-1", tree)
	s.Root = f.root
	return s
}

var now = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

// The first sample is a baseline. Emitting an event for everything already
// running would produce a burst of alerts about a host's normal state every
// time the agent restarts.
func TestFirstScanIsABaseline(t *testing.T) {
	f := newFakeProc(t)
	f.add(1, 1, "/sbin/init", []string{"/sbin/init"}, 0, 10)
	f.add(100, 1, "/usr/sbin/sshd", []string{"/usr/sbin/sshd", "-D"}, 0, 20)

	s := f.sensor(events.NewTree(0, 0))
	var got []*events.Event
	s.Scan(now, nil) // baseline
	s.Scan(now, func(e *events.Event) { got = append(got, e) })

	if len(got) != 0 {
		t.Fatalf("a rescan with no changes produced %d events", len(got))
	}

	// A genuinely new process is reported.
	f.add(200, 100, "/bin/bash", []string{"/bin/bash", "-i"}, 1000, 30)
	s.Scan(now.Add(time.Second), func(e *events.Event) { got = append(got, e) })
	if len(got) != 1 {
		t.Fatalf("a new process produced %d events", len(got))
	}
	if got[0].PID != 200 || got[0].PPID != 100 {
		t.Errorf("event = pid %d ppid %d", got[0].PID, got[0].PPID)
	}
}

func TestProcessEventCarriesSigmaFields(t *testing.T) {
	f := newFakeProc(t)
	f.add(100, 1, "/usr/sbin/sshd", []string{"/usr/sbin/sshd", "-D"}, 0, 10)
	s := f.sensor(events.NewTree(0, 0))
	s.Scan(now, nil)

	f.add(200, 100, "/usr/bin/curl", []string{"/usr/bin/curl", "-fsSL", "https://x/y.sh"}, 1000, 20)
	var got *events.Event
	s.Scan(now.Add(time.Second), func(e *events.Event) { got = e })
	if got == nil {
		t.Fatal("no event")
	}

	checks := map[string]string{
		events.FieldImage:            "/usr/bin/curl",
		events.FieldCommandLine:      "/usr/bin/curl -fsSL https://x/y.sh",
		events.FieldParentImage:      "/usr/sbin/sshd",
		events.FieldParentCommand:    "/usr/sbin/sshd -D",
		events.FieldCurrentDirectory: "/home/deploy",
	}
	for field, want := range checks {
		if got.String(field) != want {
			t.Errorf("%s = %q, want %q", field, got.String(field), want)
		}
	}
	if got.String(events.FieldUID) != "1000" {
		t.Errorf("Uid = %q", got.String(events.FieldUID))
	}
	// argv as a list, so a rule matching one argument does not match a
	// substring spanning two.
	args := events.Values(got.Field("CommandLineArgs"))
	if len(args) != 3 || args[1] != "-fsSL" {
		t.Errorf("CommandLineArgs = %v", args)
	}
}

// A pid whose start time changed is a different process. Comparing only the
// pid would merge two processes and attribute one's children to the other.
func TestPIDReuseIsDetected(t *testing.T) {
	f := newFakeProc(t)
	f.add(100, 1, "/bin/sleep", []string{"sleep", "1"}, 0, 10)
	s := f.sensor(events.NewTree(0, 0))
	s.Scan(now, nil)

	var got []*events.Event
	// Same pid, different start time: a reused number.
	f.add(100, 1, "/tmp/payload", []string{"/tmp/payload"}, 0, 99)
	s.Scan(now.Add(time.Second), func(e *events.Event) { got = append(got, e) })

	if len(got) != 1 {
		t.Fatalf("pid reuse produced %d events, want 1", len(got))
	}
	if got[0].String(events.FieldImage) != "/tmp/payload" {
		t.Errorf("image = %q", got[0].String(events.FieldImage))
	}
}

func TestExitedProcessesAreMarkedInTheTree(t *testing.T) {
	f := newFakeProc(t)
	tree := events.NewTree(time.Hour, 0)
	f.add(100, 1, "/tmp/dropper", []string{"./dropper"}, 0, 10)
	s := f.sensor(tree)
	s.Scan(now, nil)

	f.add(200, 100, "/bin/sh", []string{"sh", "-c", "curl x"}, 0, 20)
	s.Scan(now.Add(time.Second), nil)

	// The parent exits; its child's lineage must survive it.
	f.remove(100)
	s.Scan(now.Add(2*time.Second), nil)

	chain := tree.Ancestry(200)
	if len(chain) != 2 {
		t.Fatalf("lineage = %+v", chain)
	}
	if chain[1].Image != "/tmp/dropper" {
		t.Errorf("the exited parent was lost: %+v", chain)
	}
}

// comm can contain spaces and parentheses, which is what makes splitting
// /proc/<pid>/stat on whitespace wrong.
func TestStartTicksHandlesAwkwardCommFields(t *testing.T) {
	cases := map[string]uint64{
		"1 (init) S " + strings.Repeat("0 ", 18) + "12345 0 0":          12345,
		"7 (my (weird) proc) S " + strings.Repeat("0 ", 18) + "999 0 0": 999,
		"9 (has space) R " + strings.Repeat("0 ", 18) + "42 0 0":        42,
	}
	for stat, want := range cases {
		got, ok := startTicks(stat)
		if !ok || got != want {
			t.Errorf("startTicks(%q) = %d, %v; want %d", stat, got, ok, want)
		}
	}

	for _, bad := range []string{"", "no parens here", "1 (x) S 1 2 3"} {
		if _, ok := startTicks(bad); ok {
			t.Errorf("startTicks(%q) succeeded", bad)
		}
	}
}

// A detection surface that overstates itself is worse than a smaller one that
// does not, so the sensor has to say what it cannot see.
func TestCapabilityStatesItsLimits(t *testing.T) {
	c := NewProcSensor("d", "h", nil).Describe()
	if c.Complete {
		t.Error("a polling sensor reported itself complete")
	}
	if len(c.Limitations) == 0 {
		t.Fatal("no limitations stated")
	}
	joined := strings.Join(c.Limitations, " ")
	for _, want := range []string{"between samples", "curl", "eBPF"} {
		if !strings.Contains(joined, want) {
			t.Errorf("limitations do not mention %q: %v", want, c.Limitations)
		}
	}
	// It must not claim kinds it cannot observe.
	if len(c.Kinds) != 1 || c.Kinds[0] != events.KindProcess {
		t.Errorf("kinds = %v", c.Kinds)
	}
}

// An honest coverage map shows the blind spots, not just the coverage.
func TestMissingKinds(t *testing.T) {
	missing := MissingKinds([]Capability{NewProcSensor("d", "h", nil).Describe()})
	if len(missing) != 4 {
		t.Fatalf("missing = %v, want the four kinds no sensor covers", missing)
	}
	for _, kind := range missing {
		if kind == events.KindProcess {
			t.Error("a covered kind was reported missing")
		}
	}
}

// A process that exits mid-read is normal and frequent, not an error.
func TestProcessDisappearingMidScanIsIgnored(t *testing.T) {
	f := newFakeProc(t)
	dir := filepath.Join(f.root, "proc", "500")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A directory with no readable stat, as happens when a process exits
	// between the readdir and the read.
	s := f.sensor(events.NewTree(0, 0))
	var got []*events.Event
	s.Scan(now, nil)
	s.Scan(now.Add(time.Second), func(e *events.Event) { got = append(got, e) })
	if len(got) != 0 {
		t.Errorf("an unreadable process produced %d events", len(got))
	}
}

func TestMultiCombinesCapabilities(t *testing.T) {
	m := NewMulti(NewProcSensor("d", "h", nil))
	c := m.Describe()
	if c.Complete {
		t.Error("a set containing an incomplete sensor reported itself complete")
	}
	if len(c.Kinds) != 1 {
		t.Errorf("kinds = %v", c.Kinds)
	}
	// Limitations must stay attributed to the sensor they came from.
	for _, l := range c.Limitations {
		if !strings.HasPrefix(l, "proc-poll: ") {
			t.Errorf("limitation is not attributed: %q", l)
		}
	}
}

// An empty root must resolve to /proc, not the relative path "proc".
//
// This shipped broken: filepath.Join("", "proc") yields "proc", so a sensor
// with no root read a directory that does not exist and reported no processes
// at all. Every fake-root test passed, because they all set a root. Only a run
// against a real /proc caught it.
func TestEmptyRootResolvesToAbsoluteProc(t *testing.T) {
	s := NewProcSensor("d", "h", nil)
	if got := s.procPath(); got != "/proc" {
		t.Fatalf("procPath() = %q, want /proc", got)
	}
	if got := s.procPath("123", "stat"); got != "/proc/123/stat" {
		t.Errorf("procPath(123, stat) = %q", got)
	}

	rooted := NewProcSensor("d", "h", nil)
	rooted.Root = "/tmp/fake"
	if got := rooted.procPath("1"); got != "/tmp/fake/proc/1" {
		t.Errorf("rooted procPath = %q", got)
	}
}

// The same sensor must actually observe this process on the machine running
// the tests, which is the check the fake root cannot make.
func TestSensorSeesTheRealProcFilesystem(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc on this platform")
	}
	s := NewProcSensor("d", "h", events.NewTree(0, 0))

	// The baseline scan populates from the real /proc; if it finds nothing,
	// the sensor is not reading the filesystem at all.
	s.Scan(time.Now().UTC(), nil)
	if len(s.known) == 0 {
		t.Fatal("the sensor observed no processes on a live /proc")
	}
}
