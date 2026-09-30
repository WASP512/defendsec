package sensor

import (
	"context"
	"sync"
	"time"

	"defendsec/internal/etw"
	"defendsec/internal/events"
	"defendsec/internal/proclist"
)

// ETWSensor observes every process start through Event Tracing for Windows
// (roadmap 5.1). See package etw for what has and has not been verified.
type ETWSensor struct {
	DeviceID string
	Hostname string
	Tree     *events.Tree

	mu      sync.Mutex
	images  map[uint32]string
	devices map[string]string
}

// NewETWSensor creates the sensor. Nothing is started until Run.
func NewETWSensor(deviceID, hostname string, tree *events.Tree) *ETWSensor {
	return &ETWSensor{DeviceID: deviceID, Hostname: hostname, Tree: tree, images: map[uint32]string{}}
}

// Name identifies the sensor.
func (s *ETWSensor) Name() string { return "etw-process" }

// Describe states what ETW process events do and do not carry.
func (s *ETWSensor) Describe() Capability {
	return Capability{
		Name: s.Name(), Kinds: []events.Kind{events.KindProcess}, Complete: true,
		Limitations: []string{
			"Observes process start only, from Microsoft-Windows-Kernel-Process. Network, file, registry and module-load events are not collected.",
			"The start event carries the image but not the command line; it is read from the process immediately afterwards, so a process that exits first is recorded without it.",
			"ETW delivery is best effort: under extreme load the session drops buffers, and the count of lost events is not yet reported.",
		},
	}
}

// Run starts the ETW session and emits events until ctx is cancelled.
func (s *ETWSensor) Run(ctx context.Context, sink func(*events.Event)) error {
	s.devices = etw.DeviceMap()
	// Seed parent images from the current table so the first children seen
	// have a ParentImage.
	if procs, err := proclist.List(); err == nil {
		s.mu.Lock()
		for _, p := range procs {
			s.images[uint32(p.PID)] = p.Image
		}
		s.mu.Unlock()
	}
	sess, err := etw.Start(func(ps etw.ProcessStart) { s.emit(ps, sink) })
	if err != nil {
		return err
	}
	defer sess.Close()
	<-ctx.Done()
	return ctx.Err()
}

func (s *ETWSensor) emit(ps etw.ProcessStart, sink func(*events.Event)) {
	now := time.Now().UTC()
	image := etw.DOSPath(ps.ImageName, s.devices)
	s.mu.Lock()
	s.images[ps.PID] = image
	parent := s.images[ps.PPID]
	if len(s.images) > 50000 {
		// Bounded: pids are reused and exits are not tracked here.
		s.images = map[uint32]string{ps.PID: image}
	}
	s.mu.Unlock()

	ev := &events.Event{
		ID: newEventID(), DeviceID: s.DeviceID, Hostname: s.Hostname,
		Kind: events.KindProcess, At: now, PID: int32(ps.PID), PPID: int32(ps.PPID),
	}
	ev.Set(events.FieldImage, image)
	ev.Set(events.FieldCommandLine, proclist.CommandLine(int32(ps.PID)))
	ev.Set(events.FieldProcessID, int32(ps.PID))
	ev.Set(events.FieldParentProcessID, int32(ps.PPID))
	ev.Set(events.FieldParentImage, parent)
	ev.Set("OriginalFileName", baseName(image))
	if s.Tree != nil {
		s.Tree.Observe(ev.PID, ev.PPID, image, ev.String(events.FieldCommandLine), "", now)
	}
	if sink != nil {
		sink(ev)
	}
}
