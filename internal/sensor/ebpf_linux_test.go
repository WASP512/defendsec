//go:build linux

package sensor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/events"
)

// loadSensor loads the real program against the running kernel, skipping when
// the environment cannot run it.
//
// Skipping rather than failing is deliberate: CI containers frequently lack
// CAP_BPF or a mounted tracefs, and a red build there would train everyone to
// ignore it. What must never happen is the test silently passing without
// having loaded anything, so the skip messages say exactly what was missing.
func loadSensor(t *testing.T) *BPFSensor {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("loading a BPF program needs root or CAP_BPF")
	}
	s, err := NewBPFSensor("dev-1", "host-1",
		events.NewTree(time.Minute, 128))
	if err != nil {
		if errors.Is(err, ErrBPFUnsupported) {
			t.Skipf("this kernel cannot run the sensor: %v", err)
		}
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The claim that distinguishes this sensor from the poller is that it sees
// every exec, including one that exits immediately. This runs a real process
// and requires the sensor to have reported it.
func TestSensorCatchesARealExec(t *testing.T) {
	s := loadSensor(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var seen []*events.Event
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(ev *events.Event) {
			mu.Lock()
			seen = append(seen, ev)
			mu.Unlock()
		})
	}()

	// A marker argument makes the event findable among everything else the
	// machine is doing while the test runs.
	const marker = "defendsec-ebpf-sensor-test-marker"
	// Exits immediately, which is the case /proc polling misses.
	if err := exec.Command("/bin/true", marker).Run(); err != nil {
		t.Fatalf("run probe process: %v", err)
	}

	var match *events.Event
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, ev := range seen {
			if strings.Contains(ev.String(events.FieldCommandLine), marker) {
				match = ev
				break
			}
		}
		mu.Unlock()
		if match != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	if match == nil {
		t.Fatalf("the sensor did not report the exec; %d events seen", len(seen))
	}
	if got := match.String(events.FieldImage); got != "/bin/true" {
		t.Errorf("Image = %q, want /bin/true", got)
	}
	if got := match.String(events.FieldCommandLine); got != "/bin/true "+marker {
		t.Errorf("CommandLine = %q", got)
	}
	if match.PID <= 0 {
		t.Error("the event has no pid")
	}
	// The parent is this test process. Without it the process tree cannot be
	// built, which is the whole of roadmap 3.5.
	if int(match.PPID) != os.Getpid() {
		t.Errorf("PPID = %d, want %d (the CO-RE parent-pid relocation is the "+
			"most likely thing to have broken)", match.PPID, os.Getpid())
	}
	if got := match.String(events.FieldUser); got == "" {
		t.Error("the event has no user")
	}
	// Timestamps are converted from the kernel's monotonic clock; a bad
	// offset puts every event near the epoch or far in the future.
	if delta := time.Since(match.At); delta < 0 || delta > time.Minute {
		t.Errorf("At = %v, which is %v from now: the boot-time offset is wrong",
			match.At, delta)
	}
}

// argv must be what the caller passed, kept as a list. A rule matching one
// argument must not be able to match a string spanning two.
func TestArgumentVectorIsPreservedAsAList(t *testing.T) {
	s := loadSensor(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	found := make(chan *events.Event, 1)
	const marker = "defendsec-argv-list-marker"
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(ev *events.Event) {
			if strings.Contains(ev.String(events.FieldCommandLine), marker) {
				select {
				case found <- ev:
				default:
				}
			}
		})
	}()

	if err := exec.Command("/bin/true", marker, "second arg with spaces").Run(); err != nil {
		t.Fatalf("run probe process: %v", err)
	}

	var ev *events.Event
	select {
	case ev = <-found:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("the sensor did not report the exec")
	}
	cancel()
	<-done

	raw, ok := ev.Fields["CommandLineArgs"]
	if !ok {
		t.Fatal("the event carries no argument list")
	}
	args, ok := raw.([]string)
	if !ok {
		t.Fatalf("CommandLineArgs is %T, not a list", raw)
	}
	want := []string{"/bin/true", marker, "second arg with spaces"}
	if len(args) != len(want) {
		t.Fatalf("args = %q, want %q", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

// An exec that fails must not produce an event. A process that never ran,
// shown in the console as though it had, is something a rule would match on —
// worse than missing it, because it looks like evidence.
func TestAFailedExecIsNotReported(t *testing.T) {
	s := loadSensor(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var seen []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Run(ctx, func(ev *events.Event) {
			mu.Lock()
			seen = append(seen, ev.String(events.FieldCommandLine))
			mu.Unlock()
		})
	}()

	const marker = "defendsec-should-never-appear-marker"
	// No such binary, so execve returns ENOENT.
	_ = exec.Command("/nonexistent/defendsec-test-binary", marker).Run()
	// A real exec afterwards, used as a fence: once it has arrived, anything
	// the failed exec was going to produce has had its chance.
	const fence = "defendsec-fence-marker"
	if err := exec.Command("/bin/true", fence).Run(); err != nil {
		t.Fatalf("run fence process: %v", err)
	}

	fenced := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !fenced {
		mu.Lock()
		for _, cmd := range seen {
			if strings.Contains(cmd, fence) {
				fenced = true
			}
		}
		mu.Unlock()
		if !fenced {
			time.Sleep(20 * time.Millisecond)
		}
	}
	cancel()
	<-done

	if !fenced {
		t.Skip("the fence exec never arrived, so the absence below proves nothing")
	}
	mu.Lock()
	defer mu.Unlock()
	for _, cmd := range seen {
		if strings.Contains(cmd, marker) {
			t.Fatalf("a failed exec was reported as a process: %q", cmd)
		}
	}
}

// The capability statement is what the coverage view shows, so it has to name
// what the sensor cannot see even though it is complete for execution.
func TestCapabilityStatesWhatItCannotSee(t *testing.T) {
	s := &BPFSensor{}
	cap := s.Describe()
	if !cap.Complete {
		t.Error("the eBPF sensor is complete for execve and should say so")
	}
	joined := strings.ToLower(strings.Join(cap.Limitations, " "))
	for _, want := range []string{"execve only", "network connections", "truncated"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the capability does not mention %q: %v", want, cap.Limitations)
		}
	}
}

// The decoder is the one part testable without a kernel, and the failure it
// must get right is a short record: guessing at it would turn a truncated
// read into something that looks like evidence.
func TestDecodeRejectsAShortRecordRatherThanGuessing(t *testing.T) {
	s := &BPFSensor{}
	if ev := s.decode(make([]byte, 8)); ev != nil {
		t.Error("a short record produced an event")
	}
	if s.Lost() != 1 {
		t.Errorf("the short record was not counted as loss: %d", s.Lost())
	}
}

func TestDecodeArgsStopsAtTheRecordedCount(t *testing.T) {
	block := make([]byte, bpfArgCount*bpfArgLen)
	copy(block[0:], "first\x00")
	copy(block[bpfArgLen:], "second\x00")
	copy(block[2*bpfArgLen:], "stale\x00")

	// argc is 2, so the third slot is leftover from a previous event in the
	// same map slot and must not be read.
	got := decodeArgs(block, 2)
	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("args = %q", got)
	}
	// A count beyond the block is clamped rather than read out of bounds.
	if got := decodeArgs(block, bpfArgCount+50); len(got) != bpfArgCount {
		t.Errorf("an over-large argc produced %d args", len(got))
	}
}
