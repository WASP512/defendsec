//go:build linux

package sensor

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"defendsec/internal/events"
)

// The eBPF process sensor (roadmap 3.1).
//
// # Why this exists alongside the poller
//
// The /proc poller samples, so it misses any process that starts and exits
// between samples — and `curl … | sh` is short-lived. That is not a tuning
// problem; it is what sampling means. This sensor sees every successful exec,
// with the argument vector as the caller passed it rather than as the process
// later rewrote it.
//
// # Why cilium/ebpf rather than libbpf
//
// The roadmap said CO-RE plus libbpf, and gave the cost as cgo, a
// kernel-version matrix and a build that needs kernel headers. cilium/ebpf
// removes most of that: it is a pure-Go loader that performs CO-RE
// relocations itself, so defendsec-agentd still cross-compiles to a static
// binary with CGO_ENABLED=0. The compiled BPF object is committed and
// embedded, so building the agent needs no clang, no kernel headers and no
// libbpf — only rebuilding the object does, and `make bpf` is the only thing
// that asks for them.
//
// # What it requires, and what happens when the host cannot meet it
//
// A BPF ring buffer (Linux 5.8) and kernel BTF for the one relocated field.
// Where either is missing the sensor refuses to start with a reason naming
// which, and the agent falls back to the poller. Falling back loudly matters:
// a sensor that silently degraded to sampling would leave the coverage view
// claiming complete execution coverage it does not have.

//go:embed bpf/exec_bpfel.o
var bpfObjects embed.FS

// Bounds mirrored from the BPF program. They are duplicated rather than
// shared because the C side must be compile-time constant; the decoder checks
// the record size against them, so a change on one side that is not mirrored
// fails at load rather than silently misparsing every event.
const (
	bpfArgCount    = 16
	bpfArgLen      = 128
	bpfFilenameLen = 256
	bpfCommLen     = 16
)

// execRecord is the wire form of one exec, laid out to match struct
// exec_event in bpf/exec.bpf.c exactly.
type execRecord struct {
	AtNS          uint64
	PID           uint32
	PPID          uint32
	UID           uint32
	Argc          uint32
	ArgsTruncated uint32
	Pad           uint32
	Comm          [bpfCommLen]byte
	Filename      [bpfFilenameLen]byte
	Args          [bpfArgCount * bpfArgLen]byte
}

// BPFSensor observes process execution with an eBPF program on the execve
// tracepoints.
type BPFSensor struct {
	DeviceID string
	Hostname string
	// Tree records lineage as processes are seen (roadmap 3.5).
	Tree *events.Tree

	coll  *ebpf.Collection
	links []link.Link
	rb    *ringbuf.Reader

	// lost counts events the ring buffer had no room for, summed from the
	// kernel-side counter and the reader's own view.
	lost atomic.Uint64
	// bootOffset converts the kernel's monotonic timestamps to wall clock.
	bootOffset time.Duration
}

// ErrBPFUnsupported reports that this kernel cannot run the sensor. The agent
// treats it as a reason to fall back to the poller rather than as a failure.
var ErrBPFUnsupported = errors.New("ebpf sensor unsupported on this kernel")

// NewBPFSensor loads and attaches the program. It returns an error wrapping
// ErrBPFUnsupported when the kernel is the reason, so a caller can tell
// "this host cannot" from "this is broken".
func NewBPFSensor(deviceID, hostname string, tree *events.Tree) (*BPFSensor, error) {
	if err := supportedKernel(); err != nil {
		return nil, err
	}

	// The BPF map and program memory is charged to a rlimit on kernels
	// before 5.11. Raising it is a no-op on newer ones.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock rlimit: %w", err)
	}

	blob, err := bpfObjects.ReadFile("bpf/exec_bpfel.o")
	if err != nil {
		return nil, fmt.Errorf("read embedded bpf object: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("parse bpf object: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		// A verifier rejection on an unexpected kernel is a kernel problem,
		// not a bug to crash the agent over.
		return nil, fmt.Errorf("%w: load: %v", ErrBPFUnsupported, err)
	}

	s := &BPFSensor{
		DeviceID: deviceID, Hostname: hostname, Tree: tree,
		coll: coll, bootOffset: bootOffset(),
	}

	// Order matters: the success tracepoint only emits for execs whose entry
	// was stashed, so attaching entry first means no exec is seen half-way.
	for _, tp := range []struct{ group, name, prog string }{
		{"syscalls", "sys_enter_execve", "on_execve_enter"},
		{"sched", "sched_process_exec", "on_process_exec"},
	} {
		prog := coll.Programs[tp.prog]
		if prog == nil {
			s.Close()
			return nil, fmt.Errorf("bpf object has no program %q", tp.prog)
		}
		l, err := link.Tracepoint(tp.group, tp.name, prog, nil)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("%w: attach %s/%s: %v",
				ErrBPFUnsupported, tp.group, tp.name, err)
		}
		s.links = append(s.links, l)
	}

	rb, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}
	s.rb = rb
	return s, nil
}

// supportedKernel checks the two requirements before loading, so the failure
// names the missing thing rather than surfacing as a verifier message.
func supportedKernel() error {
	// Kernel BTF, for the one CO-RE-relocated field (task->real_parent->tgid).
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf(
			"%w: no kernel BTF at /sys/kernel/btf/vmlinux, so the parent-pid "+
				"field cannot be relocated; the kernel needs CONFIG_DEBUG_INFO_BTF",
			ErrBPFUnsupported)
	}
	// The ring buffer, which is Linux 5.8 and later. Probed rather than
	// version-compared: a vendor kernel's release string says little about
	// what has been backported into it.
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: 4096})
	if err != nil {
		return fmt.Errorf(
			"%w: BPF ring buffers are unavailable, which needs Linux 5.8 or later: %v",
			ErrBPFUnsupported, err)
	}
	m.Close()
	return nil
}

// bootOffset is what converts the kernel's monotonic event timestamps to wall
// clock. Read once: reading it per event would make two events from the same
// batch disagree by the cost of the syscall.
func bootOffset() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Duration(time.Now().UnixNano()) - time.Duration(ts.Nano())
}

// Name identifies the sensor.
func (s *BPFSensor) Name() string { return "ebpf-exec" }

// Describe states what this sensor can and cannot see.
//
// It is complete for process execution, which is the whole point of it, and
// it says so — but it still lists what it misses, because "complete" with no
// qualification would be read as covering more than execve.
func (s *BPFSensor) Describe() Capability {
	return Capability{
		Name:     s.Name(),
		Kinds:    []events.Kind{events.KindProcess},
		Complete: true,
		Limitations: []string{
			"Observes execve only. A process created by fork alone, without a following exec, is not reported — nor are execveat callers, which are rare but real.",
			fmt.Sprintf("Records the first %d arguments, each to %d bytes. Longer vectors are flagged truncated in the event rather than dropped.", bpfArgCount, bpfArgLen),
			"Network connections, file writes, privilege transitions and module loads have no sensor. Rules depending on those kinds cannot fire.",
			"An exec whose entry was evicted from the stash under extreme load is not reported, because an exec event with no argument vector would read as a process that ran with no arguments.",
		},
	}
}

// Lost reports events the ring buffer had no room for. A pipeline that drops
// silently produces a clean console during exactly the burst that overwhelmed
// it, so this is summed with the kernel-side counter and reported.
func (s *BPFSensor) Lost() uint64 {
	total := s.lost.Load()
	if s.coll == nil {
		return total
	}
	if m := s.coll.Maps["lost"]; m != nil {
		var n uint64
		if err := m.Lookup(uint32(0), &n); err == nil {
			total += n
		}
	}
	return total
}

// Run reads events until the context is cancelled.
func (s *BPFSensor) Run(ctx context.Context, sink func(*events.Event)) error {
	if s.rb == nil {
		return errors.New("sensor is not loaded")
	}
	// Unblocks the blocking Read below. Without this, cancellation would
	// hang until the next exec on the host, which on an idle machine is
	// unbounded.
	go func() {
		<-ctx.Done()
		s.rb.Close()
	}()

	for {
		record, err := s.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return ctx.Err()
			}
			// A malformed read is not a reason to stop sensing.
			continue
		}
		ev := s.decode(record.RawSample)
		if ev == nil {
			continue
		}
		if s.Tree != nil {
			s.Tree.Observe(ev.PID, ev.PPID,
				ev.String(events.FieldImage), ev.String(events.FieldCommandLine),
				ev.String(events.FieldUser), ev.At)
		}
		if sink != nil {
			sink(ev)
		}
	}
}

// decode turns one ring-buffer record into an event.
func (s *BPFSensor) decode(raw []byte) *events.Event {
	var rec execRecord
	if len(raw) < binary.Size(rec) {
		// The C struct and the Go struct have diverged. Counted as loss
		// rather than guessed at: a misparsed event is worse than a missing
		// one, because it looks like evidence.
		s.lost.Add(1)
		return nil
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &rec); err != nil {
		s.lost.Add(1)
		return nil
	}

	filename := cstring(rec.Filename[:])
	args := decodeArgs(rec.Args[:], int(rec.Argc))
	if filename == "" && len(args) == 0 {
		return nil
	}

	// The command line is joined from argv rather than read back from
	// /proc/<pid>/cmdline, which is the difference that matters: a process
	// that rewrites its own argv is recorded as it was invoked.
	cmdline := strings.Join(args, " ")
	if rec.ArgsTruncated != 0 && cmdline != "" {
		cmdline += " …"
	}

	ev := &events.Event{
		ID: newEventID(), DeviceID: s.DeviceID, Hostname: s.Hostname,
		Kind: events.KindProcess,
		At:   time.Unix(0, int64(rec.AtNS)+int64(s.bootOffset)).UTC(),
		PID:  int32(rec.PID), PPID: int32(rec.PPID),
	}
	ev.Set(events.FieldImage, filename)
	ev.Set(events.FieldCommandLine, cmdline)
	ev.Set(events.FieldProcessID, int32(rec.PID))
	ev.Set(events.FieldParentProcessID, int32(rec.PPID))
	ev.Set(events.FieldUID, int(rec.UID))
	ev.Set(events.FieldUser, lookupUser(int(rec.UID)))
	if len(args) > 1 {
		// argv as a list, so a rule matching one argument does not
		// accidentally match a substring spanning two.
		ev.Set("CommandLineArgs", args)
	}
	if comm := cstring(rec.Comm[:]); comm != "" {
		ev.Set("Comm", comm)
	}
	if rec.ArgsTruncated != 0 {
		// Stated in the event, so nothing downstream presents a clipped
		// command line as the whole thing.
		ev.Set("ArgsTruncated", true)
	}
	// The parent's image and command line come from the process tree, which
	// has them from the parent's own exec. Reading /proc here would reopen
	// the race the poller has: by the time an alert is triaged the parent has
	// often exited.
	if s.Tree != nil && rec.PPID > 0 {
		// Ancestry of the parent starts at the parent itself. It is empty
		// when the parent exec'd before this sensor started, which is
		// left empty rather than filled from /proc: a lineage that stops is
		// honest, and one stitched from a later read can be wrong.
		if lineage := s.Tree.Ancestry(int32(rec.PPID)); len(lineage) > 0 {
			if lineage[0].Image != "" {
				ev.Set(events.FieldParentImage, lineage[0].Image)
			}
			if lineage[0].CommandLine != "" {
				ev.Set(events.FieldParentCommand, lineage[0].CommandLine)
			}
		}
	}
	return ev
}

// decodeArgs splits the fixed-stride argument block.
func decodeArgs(block []byte, argc int) []string {
	if argc < 0 {
		return nil
	}
	if argc > bpfArgCount {
		argc = bpfArgCount
	}
	out := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		start := i * bpfArgLen
		if start+bpfArgLen > len(block) {
			break
		}
		out = append(out, cstring(block[start:start+bpfArgLen]))
	}
	return out
}

// cstring takes the bytes up to the first NUL.
func cstring(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// Close detaches and releases everything. Safe on a partially built sensor,
// because the constructor uses it to clean up its own failures.
func (s *BPFSensor) Close() error {
	if s == nil {
		return nil
	}
	if s.rb != nil {
		s.rb.Close()
		s.rb = nil
	}
	for _, l := range s.links {
		l.Close()
	}
	s.links = nil
	if s.coll != nil {
		s.coll.Close()
		s.coll = nil
	}
	return nil
}
