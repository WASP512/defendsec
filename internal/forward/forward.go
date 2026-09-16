// Package forward sends events and alerts to the operator's own log platform
// (roadmap 3.6).
//
// # DefendSec is not a SIEM, on purpose
//
// A behavioural sensor produces thousands of events a second. Storing them all
// would make DefendSec a log lake, which is a different product with different
// economics, a different competitive field, and a storage bill the operator is
// already paying somewhere else. §2 declines that, and this package is how the
// decline is made practical rather than merely stated: everything goes to the
// platform the operator already runs, and DefendSec keeps only a short window
// for the thing it actually needs it for — context on an alert.
//
// # Forwarding must never affect detection
//
// The same rule as the agent buffer, for the same reason. A syslog collector
// that stops accepting connections must not stop DefendSec matching rules or
// raising alerts. So the sink is asynchronous and lossy, drops are counted and
// reported, and a destination that is down is a reported fault rather than an
// outage.
//
// Security function first, telemetry second. A tool that stops defending
// because its log shipper is unhappy has its priorities backwards.
package forward

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Record is anything forwardable.
type Record struct {
	// Kind is "event" or "alert", so a downstream rule can route them apart.
	Kind string `json:"kind"`
	// At is when it happened.
	At time.Time `json:"at"`
	// Severity maps onto syslog levels.
	Severity string `json:"severity,omitempty"`
	// DeviceID and Hostname identify the source host.
	DeviceID string `json:"deviceId,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// Summary is the one-line form, which is what a syslog line carries.
	Summary string `json:"summary"`
	// Body is the structured payload for JSON destinations.
	Body map[string]any `json:"body,omitempty"`
}

// Destination accepts records.
type Destination interface {
	// Name identifies it in the status report.
	Name() string
	// Send delivers a batch. It may block; the Forwarder calls it from its own
	// goroutine and never from the detection path.
	Send(ctx context.Context, records []Record) error
	// Close releases resources.
	Close() error
}

// Forwarder ships records without ever blocking the caller.
type Forwarder struct {
	destinations []Destination

	mu     sync.Mutex
	queue  []Record
	closed bool

	capacity int
	notify   chan struct{}

	accepted atomic.Uint64
	dropped  atomic.Uint64
	sent     atomic.Uint64
	failed   atomic.Uint64

	statusMu sync.Mutex
	status   map[string]*DestinationStatus

	wg   sync.WaitGroup
	stop context.CancelFunc
}

// DestinationStatus is what a destination has done lately.
type DestinationStatus struct {
	Name        string    `json:"name"`
	Sent        uint64    `json:"sent"`
	Failed      uint64    `json:"failed"`
	LastError   string    `json:"lastError,omitempty"`
	LastErrorAt time.Time `json:"lastErrorAt,omitempty"`
	LastSentAt  time.Time `json:"lastSentAt,omitempty"`
	// Healthy is false once a send has failed and not yet succeeded, so a
	// silently broken destination is visible rather than merely quiet.
	Healthy bool `json:"healthy"`
}

// DefaultCapacity bounds the outbound queue.
//
// Smaller than the agent's event buffer because this queue exists only to
// absorb a stalled destination, not a burst of host activity: by the time
// records reach here they have already been matched, and losing telemetry to a
// dead collector costs less than losing events to a dead sensor.
const DefaultCapacity = 4096

// batchSize bounds one delivery.
const batchSize = 256

// flushInterval is how often a partial batch goes out anyway, so a quiet
// system still forwards promptly rather than waiting for a full batch.
const flushInterval = 2 * time.Second

// New starts a forwarder. Closing it stops the worker.
func New(capacity int, destinations ...Destination) *Forwarder {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		destinations: destinations,
		capacity:     capacity,
		notify:       make(chan struct{}, 1),
		status:       map[string]*DestinationStatus{},
		stop:         cancel,
	}
	for _, d := range destinations {
		f.status[d.Name()] = &DestinationStatus{Name: d.Name(), Healthy: true}
	}
	if len(destinations) > 0 {
		f.wg.Add(1)
		go f.run(ctx)
	}
	return f
}

// Enabled reports whether anything is configured.
func (f *Forwarder) Enabled() bool { return f != nil && len(f.destinations) > 0 }

// Send queues a record. It never blocks and never returns an error: a caller
// on the detection path must not have to decide what to do about a full queue.
func (f *Forwarder) Send(r Record) {
	if !f.Enabled() {
		return
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	if len(f.queue) >= f.capacity {
		// Oldest first, matching the agent buffer: the recent records are the
		// ones a downstream investigation is most likely to want.
		copy(f.queue, f.queue[1:])
		f.queue = f.queue[:len(f.queue)-1]
		f.dropped.Add(1)
	}
	f.queue = append(f.queue, r)
	f.accepted.Add(1)
	f.mu.Unlock()

	select {
	case f.notify <- struct{}{}:
	default:
	}
}

func (f *Forwarder) run(ctx context.Context) {
	defer f.wg.Done()
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// One last flush, so a clean shutdown does not discard what is
			// already queued.
			f.flush(context.Background())
			return
		case <-ticker.C:
		case <-f.notify:
		}
		f.flush(ctx)
	}
}

func (f *Forwarder) flush(ctx context.Context) {
	for {
		f.mu.Lock()
		n := len(f.queue)
		if n == 0 {
			f.mu.Unlock()
			return
		}
		if n > batchSize {
			n = batchSize
		}
		batch := make([]Record, n)
		copy(batch, f.queue[:n])
		f.queue = append(f.queue[:0], f.queue[n:]...)
		f.mu.Unlock()

		for _, d := range f.destinations {
			sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := d.Send(sendCtx, batch)
			cancel()
			f.record(d.Name(), len(batch), err)
		}
	}
}

func (f *Forwarder) record(name string, n int, err error) {
	f.statusMu.Lock()
	defer f.statusMu.Unlock()
	st, ok := f.status[name]
	if !ok {
		st = &DestinationStatus{Name: name}
		f.status[name] = st
	}
	if err != nil {
		st.Failed += uint64(n)
		st.LastError = err.Error()
		st.LastErrorAt = time.Now().UTC()
		st.Healthy = false
		f.failed.Add(uint64(n))
		return
	}
	st.Sent += uint64(n)
	st.LastSentAt = time.Now().UTC()
	st.Healthy = true
	f.sent.Add(uint64(n))
}

// Status reports what forwarding has done, so a broken destination is visible
// rather than silently swallowing everything.
type Status struct {
	Enabled      bool                `json:"enabled"`
	Accepted     uint64              `json:"accepted"`
	Dropped      uint64              `json:"dropped"`
	Sent         uint64              `json:"sent"`
	Failed       uint64              `json:"failed"`
	Queued       int                 `json:"queued"`
	Capacity     int                 `json:"capacity"`
	Destinations []DestinationStatus `json:"destinations,omitempty"`
	Detail       string              `json:"detail"`
}

// Status returns the current picture.
func (f *Forwarder) Status() Status {
	if f == nil {
		return Status{Detail: "Forwarding is not configured. DefendSec keeps a short event window for alert context and is not a log store; send events to your own platform with DEFENDSEC_FORWARD."}
	}
	f.mu.Lock()
	queued := len(f.queue)
	f.mu.Unlock()

	st := Status{
		Enabled: f.Enabled(), Accepted: f.accepted.Load(),
		Dropped: f.dropped.Load(), Sent: f.sent.Load(), Failed: f.failed.Load(),
		Queued: queued, Capacity: f.capacity,
	}
	f.statusMu.Lock()
	for _, d := range f.destinations {
		if s, ok := f.status[d.Name()]; ok {
			st.Destinations = append(st.Destinations, *s)
		}
	}
	f.statusMu.Unlock()

	switch {
	case !st.Enabled:
		st.Detail = "Forwarding is not configured. DefendSec keeps a short event window for alert context and is not a log store; send events to your own platform with DEFENDSEC_FORWARD."
	case st.Dropped > 0:
		st.Detail = fmt.Sprintf(
			"%d records were dropped because a destination could not keep up. Detection is unaffected — forwarding is deliberately lossy so a stalled collector cannot stop DefendSec defending — but your log platform has gaps.",
			st.Dropped)
	case st.Failed > 0:
		st.Detail = fmt.Sprintf(
			"%d records failed to deliver. Check the destination below; records queued while it is down will be dropped once the queue fills.",
			st.Failed)
	default:
		st.Detail = "Forwarding is healthy. DefendSec keeps only a short window itself; your own platform holds the history."
	}
	return st
}

// Close stops the worker after one final flush.
func (f *Forwarder) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.mu.Unlock()

	f.stop()
	f.wg.Wait()
	var errs []string
	for _, d := range f.destinations {
		if err := d.Close(); err != nil {
			errs = append(errs, d.Name()+": "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close destinations: %s", strings.Join(errs, "; "))
	}
	return nil
}

// JSON renders a record for a structured destination.
func (r Record) JSON() ([]byte, error) { return json.Marshal(r) }
