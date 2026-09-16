package forward

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturingDest struct {
	name string
	mu   sync.Mutex
	got  []Record
	err  error
	// block delays each send, to prove the caller is not affected.
	block time.Duration
}

func (c *capturingDest) Name() string { return c.name }
func (c *capturingDest) Send(_ context.Context, records []Record) error {
	if c.block > 0 {
		time.Sleep(c.block)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.got = append(c.got, records...)
	return nil
}
func (c *capturingDest) Close() error { return nil }
func (c *capturingDest) records() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Record(nil), c.got...)
}

func rec(summary string) Record {
	return Record{Kind: "event", At: time.Now().UTC(), Summary: summary, Severity: "high"}
}

func TestRecordsReachDestinations(t *testing.T) {
	d := &capturingDest{name: "test"}
	f := New(0, d)
	defer f.Close()

	for i := 0; i < 5; i++ {
		f.Send(rec(fmt.Sprintf("event %d", i)))
	}
	waitFor(t, func() bool { return len(d.records()) == 5 })

	st := f.Status()
	if st.Sent != 5 || st.Failed != 0 || st.Dropped != 0 {
		t.Errorf("status = %+v", st)
	}
	if !st.Destinations[0].Healthy {
		t.Error("a working destination reported unhealthy")
	}
}

// The rule the design turns on: a stalled collector must not slow the
// detection path. A tool that stops defending because its log shipper is
// unhappy has its priorities backwards.
func TestSendNeverBlocks(t *testing.T) {
	f := New(16, &capturingDest{name: "slow", block: 2 * time.Second})
	defer f.Close()

	start := time.Now()
	for i := 0; i < 5000; i++ {
		f.Send(rec("event"))
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Send took %s against a stalled destination", elapsed)
	}
	if f.Status().Dropped == 0 {
		t.Error("a small queue against a slow destination dropped nothing")
	}
}

// A destination that is down must be visible rather than silently swallowing
// everything.
func TestFailingDestinationIsReported(t *testing.T) {
	d := &capturingDest{name: "broken", err: fmt.Errorf("connection refused")}
	f := New(0, d)
	defer f.Close()

	f.Send(rec("event"))
	waitFor(t, func() bool { return f.Status().Failed > 0 })

	st := f.Status()
	if st.Destinations[0].Healthy {
		t.Error("a failing destination reported healthy")
	}
	if !strings.Contains(st.Destinations[0].LastError, "connection refused") {
		t.Errorf("lastError = %q", st.Destinations[0].LastError)
	}
	if !strings.Contains(st.Detail, "failed to deliver") {
		t.Errorf("detail = %q", st.Detail)
	}
}

// An unconfigured forwarder must say what that means, not look like a healthy
// one with nothing to do.
func TestUnconfiguredSaysSo(t *testing.T) {
	f := New(0)
	defer f.Close()
	if f.Enabled() {
		t.Error("a forwarder with no destinations reported enabled")
	}
	f.Send(rec("event")) // must not panic
	st := f.Status()
	if st.Enabled {
		t.Error("status reported enabled")
	}
	if !strings.Contains(st.Detail, "not a log store") {
		t.Errorf("detail does not state the positioning: %q", st.Detail)
	}

	var nilForwarder *Forwarder
	nilForwarder.Send(rec("event"))
	if nilForwarder.Status().Enabled {
		t.Error("a nil forwarder reported enabled")
	}
	if err := nilForwarder.Close(); err != nil {
		t.Errorf("closing a nil forwarder: %v", err)
	}
}

// A clean shutdown must not discard what is already queued.
func TestCloseFlushes(t *testing.T) {
	d := &capturingDest{name: "test"}
	f := New(0, d)
	for i := 0; i < 20; i++ {
		f.Send(rec("event"))
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if len(d.records()) != 20 {
		t.Errorf("delivered %d of 20 after Close", len(d.records()))
	}
	// Sending after close is a no-op rather than a panic.
	f.Send(rec("late"))
}

func TestSyslogFormatIsRFC5424(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	lines := make(chan string, 4)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			// Octet counting: a length, a space, then that many bytes.
			lengthField, err := reader.ReadString(' ')
			if err != nil {
				return
			}
			var n int
			if _, err := fmt.Sscanf(strings.TrimSpace(lengthField), "%d", &n); err != nil {
				return
			}
			buf := make([]byte, n)
			if _, err := readFull(reader, buf); err != nil {
				return
			}
			lines <- string(buf)
		}
	}()

	d, err := NewSyslog("tcp://"+ln.Addr().String(), "defendsec")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	err = d.Send(context.Background(), []Record{{
		Kind: "alert", At: at, Severity: "critical",
		Hostname: "web-01", Summary: "Reverse shell",
		Body: map[string]any{"rule": "Reverse shell", "pid": 4242},
	}})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case line := <-lines:
		// local0.crit is 16*8+2 = 130.
		if !strings.HasPrefix(line, "<130>1 ") {
			t.Errorf("priority/version = %q", line[:min(12, len(line))])
		}
		if !strings.Contains(line, "2026-09-16T12:00:00Z") {
			t.Errorf("timestamp missing: %q", line)
		}
		if !strings.Contains(line, "web-01") || !strings.Contains(line, "defendsec") {
			t.Errorf("host or tag missing: %q", line)
		}
		// The payload is JSON so collectors can parse it reliably.
		idx := strings.Index(line, "{")
		if idx < 0 {
			t.Fatalf("no JSON payload: %q", line)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line[idx:]), &payload); err != nil {
			t.Fatalf("payload is not JSON: %v (%q)", err, line[idx:])
		}
		if payload["rule"] != "Reverse shell" {
			t.Errorf("payload = %v", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no syslog message received")
	}
}

// Newline framing breaks on any message containing a newline, and JSON
// payloads routinely do.
func TestSyslogUsesOctetCounting(t *testing.T) {
	d, err := NewSyslog("tcp://127.0.0.1:514", "tag")
	if err != nil {
		t.Fatal(err)
	}
	line := d.format(Record{Summary: "x", At: time.Now(), Hostname: "h"})
	var declared int
	if _, err := fmt.Sscanf(line, "%d ", &declared); err != nil {
		t.Fatalf("no octet count: %q", line)
	}
	prefix := fmt.Sprintf("%d ", declared)
	if got := len(line) - len(prefix); got != declared {
		t.Errorf("declared %d bytes, message is %d", declared, got)
	}

	// UDP is one datagram per message, with no framing at all.
	udp, err := NewSyslog("udp://127.0.0.1:514", "tag")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(udp.format(Record{Summary: "x", At: time.Now()}), "1") {
		// A UDP message starts with the priority, not a length.
		t.Error("UDP message appears to carry octet counting")
	}
}

func TestSyslogSeverityMapping(t *testing.T) {
	for severity, want := range map[string]int{
		"critical": 2, "high": 3, "medium": 4, "low": 5, "": 6, "unknown": 6,
	} {
		if got := severityToSyslog(severity); got != want {
			t.Errorf("%q = %d, want %d", severity, got, want)
		}
	}
}

// RFC 5424 forbids spaces in header fields; a hostname containing one would
// otherwise shift every following field.
func TestSyslogHeaderFieldsAreSanitised(t *testing.T) {
	d, _ := NewSyslog("tcp://127.0.0.1:514", "my tag")
	line := d.format(Record{Summary: "x", At: time.Now(), Hostname: "host with spaces"})
	header := strings.SplitN(line, "{", 2)[0]
	fields := strings.Fields(header)
	// count, version-prefixed priority, timestamp, host, tag, then three "-".
	if len(fields) != 8 {
		t.Errorf("header has %d fields, want 8: %q", len(fields), header)
	}
}

func TestWebhookPostsBatches(t *testing.T) {
	var gotAuth string
	var payload struct {
		Source  string   `json:"source"`
		Count   int      `json:"count"`
		Records []Record `json:"records"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	d, err := NewWebhook(srv.URL+"/ingest", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Send(context.Background(), []Record{rec("one"), rec("two")}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer s3cret" {
		t.Errorf("auth = %q", gotAuth)
	}
	if payload.Count != 2 || len(payload.Records) != 2 || payload.Source != "defendsec" {
		t.Errorf("payload = %+v", payload)
	}

	// A non-2xx is a failure, or a rejecting collector would look healthy.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	badDest, _ := NewWebhook(bad.URL, "")
	if err := badDest.Send(context.Background(), []Record{rec("x")}); err == nil {
		t.Error("a 500 was treated as success")
	}
}

// A token in a query string must not end up in a status report.
func TestWebhookNameOmitsCredentials(t *testing.T) {
	d, err := NewWebhook("https://siem.example/ingest?token=secret123", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(d.Name(), "secret123") {
		t.Fatalf("the name leaks a credential: %q", d.Name())
	}
}

func TestFileDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	d, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Send(context.Background(), []Record{rec("one"), rec("two")}); err != nil {
		t.Fatal(err)
	}
	// Appends rather than truncating, so a second batch does not lose the first.
	if err := d.Send(context.Background(), []Record{rec("three")}); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("file holds %d lines, want 3", len(lines))
	}
	for _, line := range lines {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Errorf("line is not JSON: %v", err)
		}
	}
}

func TestParseDestinations(t *testing.T) {
	got, err := ParseDestinations(
		"syslog=tcp://collector:514, webhook=https://siem.example/ingest#tok ,file=/tmp/x.jsonl", "defendsec")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("parsed %d destinations", len(got))
	}

	// Malformed entries fail rather than being skipped: an operator who
	// believes events are being forwarded and is wrong stops looking.
	for _, bad := range []string{
		"nonsense",
		"unknown=x",
		"syslog=not a url",
		"syslog=ftp://host:514",
		"syslog=tcp://hostwithoutport",
		"webhook=ftp://x",
		"file=",
	} {
		if _, err := ParseDestinations(bad, "t"); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}

	// OTLP is named rather than ignored, so a misconfiguration is visible.
	_, err = ParseDestinations("otlp=http://collector:4318", "t")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("otlp error = %v", err)
	}

	if got, err := ParseDestinations("  ", "t"); err != nil || len(got) != 0 {
		t.Errorf("empty config = %v, %v", got, err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
