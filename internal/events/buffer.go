package events

import (
	"sync"
	"sync/atomic"
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
