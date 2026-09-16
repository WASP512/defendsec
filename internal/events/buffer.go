package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// The agent-side event buffer (roadmap 3.2).
//
// # The one rule
//
// This must never block. The sensor produces events from a hot path; the
// uplink is a network connection that can stall for seconds. If the buffer
// applies backpressure to the sensor, a slow server becomes a slow host, and
// a sensor that destabilises the host under load gets uninstalled — at which
// point detection coverage is zero rather than degraded.
//
// So it drops, and it counts what it dropped. The count travels with the next
// batch, so a gap is visible rather than inferred. A pipeline that drops
// events silently produces a clean console during exactly the incident that
// overwhelmed it, which is the worst possible moment to be quietly blind.
//
// # Why the oldest goes first
//
// When the buffer is full the oldest event is discarded, not the newest. An
// intrusion is a sequence, and the most recent events are the ones closest to
// whatever is happening now; keeping stale events and discarding live ones
// would preserve the least useful half.

// Buffer is a bounded, lossy, concurrent event queue.
type Buffer struct {
	mu       sync.Mutex
	items    []*Event
	capacity int

	// droppedSinceRead and droppedTotal are separate so a single batch can
	// report the gap it follows, while the lifetime figure stays visible to
	// anyone reading one batch much later.
	droppedSinceRead uint64
	droppedTotal     atomic.Uint64

	// accepted counts what made it in, which is the denominator for any
	// honest statement about loss.
	accepted atomic.Uint64
}

// DefaultCapacity is how many events are held before dropping.
//
// Sized for a burst rather than a backlog: at a few thousand events per second
// this is a couple of seconds of hard load, which covers a stalled uplink
// without letting the agent hold meaningful memory on a host that is meant to
// be running something else.
const DefaultCapacity = 8192

// NewBuffer creates a buffer. A non-positive capacity uses the default.
func NewBuffer(capacity int) *Buffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Buffer{capacity: capacity, items: make([]*Event, 0, capacity)}
}

// Add enqueues an event, dropping the oldest when full. It never blocks.
func (b *Buffer) Add(e *Event) {
	if e == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.items) >= b.capacity {
		// Drop the oldest. Shifting is O(n) on a full buffer, but it only
		// happens while already over capacity, and a ring would complicate
		// Drain for no benefit at this size.
		copy(b.items, b.items[1:])
		b.items = b.items[:len(b.items)-1]
		b.droppedSinceRead++
		b.droppedTotal.Add(1)
	}
	b.items = append(b.items, e)
	b.accepted.Add(1)
}

// Batch is a drained set of events with the gap that preceded it.
type Batch struct {
	Events []*Event
	// DroppedSinceLast is how many events were discarded since the previous
	// drain. Zero is the common case and means the batch is complete.
	DroppedSinceLast uint64
	// DroppedTotal is the lifetime count.
	DroppedTotal uint64
}

// Complete reports whether nothing was lost before this batch.
func (b Batch) Complete() bool { return b.DroppedSinceLast == 0 }

// Drain removes up to max events, resetting the since-last drop counter.
//
// The counter is reset here rather than on send, which means a batch that
// fails to transmit takes its gap count with it. That is the conservative
// direction: under-reporting a gap would be worse than reporting it twice,
// but reporting it twice is also wrong, and losing the batch already means
// the events are gone. The lifetime total is never reset, so the loss remains
// visible either way.
func (b *Buffer) Drain(max int) Batch {
	if max <= 0 {
		max = b.capacity
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	n := len(b.items)
	if n > max {
		n = max
	}
	out := make([]*Event, n)
	copy(out, b.items[:n])
	b.items = append(b.items[:0], b.items[n:]...)

	batch := Batch{
		Events:           out,
		DroppedSinceLast: b.droppedSinceRead,
		DroppedTotal:     b.droppedTotal.Load(),
	}
	b.droppedSinceRead = 0
	return batch
}

// Len is how many events are waiting.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// Capacity is the configured bound.
func (b *Buffer) Capacity() int { return b.capacity }

// Stats reports lifetime counters, for the coverage view.
type Stats struct {
	Accepted     uint64 `json:"accepted"`
	DroppedTotal uint64 `json:"droppedTotal"`
	Buffered     int    `json:"buffered"`
	Capacity     int    `json:"capacity"`
}

// Stats returns the counters.
func (b *Buffer) Stats() Stats {
	return Stats{
		Accepted:     b.accepted.Load(),
		DroppedTotal: b.droppedTotal.Load(),
		Buffered:     b.Len(),
		Capacity:     b.capacity,
	}
}

// Recent is a per-device ring of the most recent events, kept for pre-alert
// context (roadmap 3.6).
//
// Why a short ring rather than a store: the question an analyst asks first is
// "what else was this process doing just before". That needs seconds of
// history, not months. Keeping months would make DefendSec a log lake, which
// §2 declines — the operator's own platform holds the history, and this holds
// just enough to explain an alert without a round trip to it.
type Recent struct {
	mu    sync.Mutex
	items []*Event
	size  int
}

// DefaultRecentSize is how many events per device are kept for context.
const DefaultRecentSize = 256

// NewRecent creates a ring.
func NewRecent(size int) *Recent {
	if size <= 0 {
		size = DefaultRecentSize
	}
	return &Recent{size: size, items: make([]*Event, 0, size)}
}

// Add remembers an event, discarding the oldest when full.
func (r *Recent) Add(e *Event) {
	if e == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.items) >= r.size {
		copy(r.items, r.items[1:])
		r.items = r.items[:len(r.items)-1]
	}
	r.items = append(r.items, e)
}

// Before returns up to n events that happened before a moment, oldest first.
//
// Bounded by count rather than by time: an analyst wants "the last few things
// this host did", and on a quiet host a time window returns nothing while on a
// busy one it returns thousands.
func (r *Recent) Before(at time.Time, n int) []*Event {
	if n <= 0 {
		n = 20
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var out []*Event
	for i := len(r.items) - 1; i >= 0 && len(out) < n; i-- {
		if r.items[i].At.After(at) {
			continue
		}
		out = append(out, r.items[i])
	}
	// Reverse into chronological order, which is how a sequence reads.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Len is how many events are held.
func (r *Recent) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.items)
}
