// Package sensor collects behavioural telemetry from the host
// (roadmap 3.1).
//
// # Two sensors, and why this one exists
//
// The roadmap specifies an eBPF sensor: CO-RE and libbpf, hooking execve,
// connect, accept, writes on watched paths, privilege transitions and module
// loads. That is the right production sensor, and it is the only way to see
// every event exactly once with the full argument vector.
//
// It is also cgo, a kernel-version matrix, and a build that cannot run on a
// machine without kernel headers. Shipping only that would mean DefendSec has
// no behavioural detection at all on any host where the build did not work,
// and no way to test the pipeline above it.
//
// So the sensor is an interface, and this is the portable implementation: a
// /proc poller that runs on any Linux kernel with no privileges beyond reading
// /proc, and on which the whole event pipeline — buffer, batching, rules,
// process tree — can be exercised and tested.
//
// # What polling cannot see, stated plainly
//
// A poller samples. Between two samples a process can start, do its work and
// exit, and the poller will never see it. That is not a tuning problem; it is
// what sampling means. Concretely:
//
//   - short-lived processes are missed, and `curl … | sh` is short-lived
//   - the exact argv is read from /proc/<pid>/cmdline after the fact, so a
//     process that rewrites its own argv shows the rewritten version
//   - network connections and file writes are not observed at all here
//
// The ProcSensor reports these through Describe(), and the coverage view shows
// them, because a detection surface that overstates itself is worse than a
// smaller one that does not. An operator told "process execution: sampled,
// short-lived processes may be missed" can decide what to do. One told
// "process execution: covered" cannot.
package sensor

import (
	"context"
	"time"

	"defendsec/internal/events"
)

// Sensor produces behavioural events.
type Sensor interface {
	// Name identifies the implementation in a batch and in the coverage view.
	Name() string
	// Run emits events until the context is cancelled. It must not block on
	// the sink: the sink is a lossy buffer for exactly that reason.
	Run(ctx context.Context, sink func(*events.Event)) error
	// Describe states what this sensor can and cannot observe.
	Describe() Capability
}

// Capability is an honest statement of a sensor's reach.
type Capability struct {
	Name string `json:"name"`
	// Kinds are the event kinds this sensor can produce at all.
	Kinds []events.Kind `json:"kinds"`
	// Complete is true only when the sensor observes every event of those
	// kinds. A poller is never complete.
	Complete bool `json:"complete"`
	// Limitations are the specific things it will miss, written for an
	// operator deciding whether the coverage is enough.
	Limitations []string `json:"limitations,omitempty"`
}

// MissingKinds returns the event kinds no sensor in the set can observe, which
// is what an honest coverage map has to show alongside what is covered.
func MissingKinds(capabilities []Capability) []events.Kind {
	covered := map[events.Kind]bool{}
	for _, c := range capabilities {
		for _, k := range c.Kinds {
			covered[k] = true
		}
	}
	var out []events.Kind
	for _, k := range events.Kinds() {
		if !covered[k] {
			out = append(out, k)
		}
	}
	return out
}

// Multi runs several sensors together.
type Multi struct {
	sensors []Sensor
}

// NewMulti combines sensors.
func NewMulti(sensors ...Sensor) *Multi {
	return &Multi{sensors: sensors}
}

// Name identifies the set.
func (m *Multi) Name() string { return "multi" }

// Capabilities describes each member.
func (m *Multi) Capabilities() []Capability {
	out := make([]Capability, 0, len(m.sensors))
	for _, s := range m.sensors {
		out = append(out, s.Describe())
	}
	return out
}

// Run starts every sensor. One failing does not stop the others: partial
// telemetry is worth more than none, and a sensor that cannot start on this
// kernel should not take the working ones down with it.
func (m *Multi) Run(ctx context.Context, sink func(*events.Event)) error {
	errs := make(chan error, len(m.sensors))
	for _, s := range m.sensors {
		go func(s Sensor) { errs <- s.Run(ctx, sink) }(s)
	}
	<-ctx.Done()
	return ctx.Err()
}

// Describe summarises the set.
func (m *Multi) Describe() Capability {
	c := Capability{Name: "multi"}
	seen := map[events.Kind]bool{}
	complete := len(m.sensors) > 0
	for _, s := range m.sensors {
		d := s.Describe()
		if !d.Complete {
			complete = false
		}
		for _, k := range d.Kinds {
			if !seen[k] {
				seen[k] = true
				c.Kinds = append(c.Kinds, k)
			}
		}
		for _, l := range d.Limitations {
			c.Limitations = append(c.Limitations, d.Name+": "+l)
		}
	}
	c.Complete = complete
	return c
}

// pollInterval is how often the portable sensor samples /proc.
//
// A trade with no good answer: shorter misses fewer processes and costs more
// CPU on a host that is meant to be doing something else. 250ms catches most
// interactive activity and is cheap enough to be unnoticeable, while being
// honest that it catches nothing that starts and exits between samples.
const pollInterval = 250 * time.Millisecond
