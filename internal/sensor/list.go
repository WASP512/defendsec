package sensor

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"defendsec/internal/events"
	"defendsec/internal/proclist"
)

// ListSensor observes process execution on Windows and macOS by sampling the
// platform's process table (roadmap 5.1, 5.2). It is the counterpart of
// ProcSensor for hosts with no /proc, and carries the same blind spot.
type ListSensor struct {
	DeviceID string
	Hostname string
	Tree     *events.Tree
	Interval time.Duration
	// List is the process source; nil means the platform's.
	List func() ([]proclist.Proc, error)

	// CommandLine reads a process's arguments; nil means the platform's.
	CommandLine func(pid int32) string

	known map[int32]uint64
}

func (s *ListSensor) commandLine(pid int32) string {
	if s.CommandLine != nil {
		return s.CommandLine(pid)
	}
	return proclist.CommandLine(pid)
}

// NewListSensor creates a process-table sensor.
func NewListSensor(deviceID, hostname string, tree *events.Tree) *ListSensor {
	return &ListSensor{DeviceID: deviceID, Hostname: hostname, Tree: tree}
}

// Name identifies the sensor.
func (s *ListSensor) Name() string { return "process-table-poll" }

// Describe states what the sensor can and cannot see.
func (s *ListSensor) Describe() Capability {
	lim := []string{
		"Samples the process table every " + s.interval().String() + ", so a process that starts and exits between samples is never seen.",
		"Reads the command line after the process has started, so a process that exits first, or rewrites its own arguments, is recorded without them or as rewritten.",
		"Observes process execution only. Network connections, file writes and module loads are not visible.",
	}
	switch runtime.GOOS {
	case "darwin":
		lim = append(lim,
			"On macOS the kernel reports only the first 16 characters of the executable name, not its path. Full paths and every execution need the EndpointSecurity sensor, which requires an Apple-granted entitlement.")
	case "windows":
		lim = append(lim,
			"Protected processes refuse the query for their full path and are recorded by executable name only. Every execution, with command lines, needs the ETW sensor.")
	}
	return Capability{Name: s.Name(), Kinds: []events.Kind{events.KindProcess}, Limitations: lim}
}

func (s *ListSensor) interval() time.Duration {
	if s.Interval > 0 {
		return s.Interval
	}
	return pollInterval
}

func (s *ListSensor) list() ([]proclist.Proc, error) {
	if s.List != nil {
		return s.List()
	}
	return proclist.List()
}

// Run polls until the context is cancelled. The first sample is a baseline,
// for the same reason as ProcSensor's.
func (s *ListSensor) Run(ctx context.Context, sink func(*events.Event)) error {
	if _, err := s.list(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.interval())
	defer ticker.Stop()
	s.Scan(time.Now().UTC(), nil)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.Scan(time.Now().UTC(), sink)
		}
	}
}

// Scan performs one sample.
func (s *ListSensor) Scan(now time.Time, sink func(*events.Event)) {
	procs, err := s.list()
	if err != nil {
		return
	}
	byPID := make(map[int32]proclist.Proc, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	seen := make(map[int32]uint64, len(procs))
	for _, p := range procs {
		seen[p.PID] = p.Start
		if start, ok := s.known[p.PID]; ok && start == p.Start {
			continue
		}
		ev := &events.Event{
			ID: newEventID(), DeviceID: s.DeviceID, Hostname: s.Hostname,
			Kind: events.KindProcess, At: now, PID: p.PID, PPID: p.PPID,
		}
		ev.Set(events.FieldImage, p.Image)
		ev.Set(events.FieldCommandLine, s.commandLine(p.PID))
		ev.Set(events.FieldProcessID, p.PID)
		ev.Set(events.FieldParentProcessID, p.PPID)
		ev.Set("OriginalFileName", baseName(p.Image))
		if parent, ok := byPID[p.PPID]; ok {
			ev.Set(events.FieldParentImage, parent.Image)
		}
		if p.UID >= 0 {
			ev.Set(events.FieldUID, p.UID)
			ev.Set(events.FieldUser, lookupUser(p.UID))
		}
		if s.Tree != nil {
			s.Tree.Observe(ev.PID, ev.PPID, p.Image, ev.String(events.FieldCommandLine), ev.String(events.FieldUser), now)
		}
		if sink != nil {
			sink(ev)
		}
	}
	if s.Tree != nil {
		for pid := range s.known {
			if _, still := seen[pid]; !still {
				s.Tree.MarkExited(pid, now)
			}
		}
	}
	s.known = seen
}

// baseName handles both separators, since a Windows path is parsed here on
// whatever platform the tests run.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return filepath.Base(p)
}
