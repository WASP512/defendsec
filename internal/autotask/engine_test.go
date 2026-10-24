package autotask

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"defendsec/internal/autotask/atest"
	"defendsec/internal/autotask/client"
)

func fullSettings() Settings {
	s := DefaultSettings()
	s.APIUser = atest.User
	s.CompanyID = 3001
	s.QueueID = "101"
	s.Status = "1"
	s.Source = "7"
	s.IssueType = "20"
	s.SubIssueType = "200"
	s.PriorityCritical, s.PriorityHigh, s.PriorityMedium = "1", "2", "3"
	s.NoteType, s.NotePublish = "1", "2"
	s.CompleteStatus = "5"
	s.ConsoleURL = "https://defendsec.example.net"
	return s
}

// memStore is an in-memory Store that keeps a ledger.
type memStore struct {
	mu       sync.Mutex
	rows     map[string]Tracked // group|gen
	ledger   []Change
	evidence map[string]Evidence // by member key
	failNext string              // fail the Commit whose action matches
}

func newMemStore() *memStore {
	return &memStore{rows: map[string]Tracked{}, evidence: map[string]Evidence{}}
}

func (m *memStore) Tracked(ctx context.Context) ([]Tracked, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Tracked
	for _, t := range m.rows {
		out = append(out, t)
	}
	return out, nil
}

func (m *memStore) Commit(ctx context.Context, actor string, ch Change) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext != "" && ch.Action == m.failNext {
		m.failNext = ""
		return fmt.Errorf("disk full")
	}
	m.rows[fmt.Sprintf("%s|%d", ch.Tracked.GroupKey, ch.Tracked.Generation)] = ch.Tracked
	m.ledger = append(m.ledger, ch)
	return nil
}

func (m *memStore) Evidence(ctx context.Context, refs []MemberRef) (map[MemberRef]Evidence, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[MemberRef]Evidence{}
	for _, r := range refs {
		if ev, ok := m.evidence[r.MemberKey]; ok {
			out[r] = ev
		}
	}
	return out, nil
}

func (m *memStore) actions() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, c := range m.ledger {
		out[c.Action]++
	}
	return out
}

func (m *memStore) row(group string, gen int) Tracked {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rows[fmt.Sprintf("%s|%d", group, gen)]
}

var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type rig struct {
	t     *testing.T
	srv   *atest.Server
	store *memStore
	set   Settings
	// findings is what is open now; a test edits it between runs.
	findings []Finding
	now      time.Time
	cfg      func(*client.Config)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	srv := atest.New()
	t.Cleanup(srv.Close)
	return &rig{t: t, srv: srv, store: newMemStore(), set: fullSettings(), now: t0}
}

func (r *rig) desk() *client.Client {
	cfg := client.Config{BaseURL: r.srv.BaseURL(), UserName: atest.User, Secret: atest.Secret, IntegrationCode: atest.IntegrationCode,
		Sleep: func(context.Context, time.Duration) error { return nil }, AllowAnyHost: true}
	if r.cfg != nil {
		r.cfg(&cfg)
	}
	c, err := client.New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

// run does one reconciliation with a fresh client (a client is made per run).
func (r *rig) run(mode string) Result {
	r.t.Helper()
	e := &Engine{Desk: r.desk(), Store: r.store, Now: func() time.Time { return r.now }, Actor: "test", DryRunFingerprint: r.set.Fingerprint()}
	set := r.set
	set.Mode = mode
	res, err := e.Run(context.Background(), set, r.findings, mode)
	if err != nil {
		r.t.Fatal(err)
	}
	r.now = r.now.Add(time.Hour)
	return res
}

func (r *rig) live() Result { r.set.Mode = ModeLive; return r.run(ModeLive) }

func hostsFinding(host, family, adv string, kev bool) Finding {
	return vf(host, family, adv, "2.0", func(f *Finding) { f.KEV = kev; f.MemberKey = "dev-" + host })
}

func ops(res Result, kind string) []Op {
	var out []Op
	for _, o := range res.Ops {
		if o.Kind == kind {
			out = append(out, o)
		}
	}
	return out
}

func TestDryRunShowsTheExactTicketAndChangesNothing(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("web-02", "openssl", "CVE-1", true), hostsFinding("db-01", "openssl", "CVE-2", false)}
	res := r.run(ModeDryRun)
	if !res.Verified || res.CompanyName != "Example Client LLC" || len(res.Problems) != 0 {
		t.Fatalf("result = %+v", res)
	}
	cs := ops(res, OpCreate)
	if len(cs) != 1 || cs[0].Status != OpPlanned || cs[0].Create == nil {
		t.Fatalf("ops = %+v", res.Ops)
	}
	c := cs[0].Create
	if c.CompanyID != 3001 || c.Priority != 1 || c.Status != 1 || *c.QueueID != 101 || *c.Source != 7 || *c.IssueType != 20 || *c.SubIssueType != 200 {
		t.Errorf("payload = %+v", c)
	}
	if !strings.HasPrefix(c.Title, "Update openssl on 3 hosts [DS-") || c.DueDateTime != "2026-10-26T12:00:00.00" {
		t.Errorf("title %q, due %q (critical is due in 2 days)", c.Title, c.DueDateTime)
	}

	// Nothing was written anywhere.
	for _, q := range r.srv.Requests() {
		if q.Method == "PATCH" || (q.Method == "POST" && q.Path != "/Tickets/query") {
			t.Errorf("a dry run sent %s %s", q.Method, q.Path)
		}
	}
	if len(r.srv.Tickets()) != 0 || len(r.store.rows) != 0 || len(r.store.ledger) != 0 {
		t.Error("a dry run left a ticket, a tracked row or a ledger entry")
	}

	// An offline dry run shows the same ticket, marked unverified.
	e := &Engine{Store: r.store, Now: func() time.Time { return t0 }}
	off, err := e.Run(context.Background(), r.set, r.findings, ModeDryRun)
	if err != nil || off.Verified || off.UnverifiedWhy == "" {
		t.Fatalf("offline: %+v, %v", off, err)
	}
	if got := ops(off, OpCreate); len(got) != 1 || !samePayload(*got[0].Create, *c) {
		t.Errorf("offline payload differs:\n%+v\n%+v", got[0].Create, c)
	}

	// What a live run then sends is exactly what the dry run showed.
	r.now = t0
	live := r.live()
	if len(ops(live, OpCreate)) != 1 || live.Created != 1 {
		t.Fatalf("live = %+v", live)
	}
	tk := r.srv.Tickets()[0]
	if tk.Title != c.Title || tk.Description != c.Description || tk.DueDateTime != c.DueDateTime || tk.Priority != c.Priority {
		t.Errorf("the ticket differs from the dry run:\n%+v\nvs %+v", tk, c)
	}
}

func TestLiveNeedsALiveSettingAndADryRunBehindIt(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	e := &Engine{Desk: r.desk(), Store: r.store, Now: func() time.Time { return t0 }}

	res, _ := e.Run(context.Background(), r.set, r.findings, ModeLive)
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "still in dry-run mode") {
		t.Fatalf("live with the dry-run setting: %+v", res)
	}
	live := r.set
	live.Mode = ModeLive
	res, _ = e.Run(context.Background(), live, r.findings, ModeLive)
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "No dry run has been shown for these exact settings") {
		t.Fatalf("live without a dry run: %+v", res)
	}
	e.DryRunFingerprint = "deadbeef00000000"
	res, _ = e.Run(context.Background(), live, r.findings, ModeLive)
	if len(res.Problems) != 1 || len(r.srv.Requests()) != 0 {
		t.Fatalf("a dry run of other settings counted: %+v (%d requests)", res, len(r.srv.Requests()))
	}
	if len(r.srv.Tickets()) != 0 {
		t.Fatal("a refused live run created a ticket")
	}
}

func TestIncompleteSettingsStopBeforeAnything(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.set.QueueID, r.set.PriorityHigh = "", ""
	res := r.run(ModeDryRun)
	if len(res.Ops) != 0 || len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "the queue") || !strings.Contains(res.Problems[0], "a priority for each") {
		t.Fatalf("result = %+v", res)
	}
	if res.Status() != "not_run" || len(r.srv.Requests()) != 0 {
		t.Errorf("status %s, %d requests", res.Status(), len(r.srv.Requests()))
	}
}

func TestLiveCreatesOnceAndARerunChangesNothing(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("web-02", "openssl", "CVE-1", true),
		hostsFinding("web-01", "nginx", "CVE-9", true)}
	first := r.live()
	if first.Created != 2 || first.Failed != 0 || first.Status() != "ok" {
		t.Fatalf("first run = %+v", first)
	}
	tickets := r.srv.Tickets()
	if len(tickets) != 2 {
		t.Fatalf("%d tickets", len(tickets))
	}
	for _, tk := range tickets {
		if tk.CompanyID != 3001 || !strings.Contains(tk.Title, "[DS-") || !strings.Contains(tk.Description, "DefendSec key: DS-") {
			t.Errorf("ticket = %+v", tk)
		}
	}
	if a := r.store.actions(); a["autotask_ticket_created"] != 2 || len(a) != 1 {
		t.Fatalf("ledger = %v: every created ticket is one chained entry", a)
	}
	row := r.store.row("vuln|openssl", 1)
	if row.TicketID == 0 || row.TicketNumber == "" || row.State != StateOpen || len(row.Members) != 2 || row.Tag != Tag("vuln|openssl", 1) {
		t.Fatalf("tracked row = %+v", row)
	}

	r.srv.ResetRequests()
	again := r.live()
	if len(again.Ops) != 0 || again.Created != 0 || len(r.srv.Tickets()) != 2 {
		t.Fatalf("a re-run with nothing changed did something: %+v", again.Ops)
	}
	for _, q := range r.srv.Requests() {
		if q.Method == "PATCH" || (q.Method == "POST" && q.Path != "/Tickets/query") {
			t.Errorf("an idempotent re-run sent %s %s", q.Method, q.Path)
		}
	}
	if a := r.store.actions(); a["autotask_ticket_created"] != 2 || len(a) != 1 {
		t.Errorf("a re-run wrote to the ledger: %v", a)
	}
}

func TestALostRecordIsFoundByTheTagNotDuplicated(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	if len(r.srv.Tickets()) != 1 {
		t.Fatal("setup")
	}
	r.store = newMemStore() // DefendSec's table is gone
	res := r.live()
	if len(r.srv.Tickets()) != 1 {
		t.Fatalf("%d tickets: a lost record made a duplicate", len(r.srv.Tickets()))
	}
	ad := ops(res, OpAdopt)
	if len(ad) != 1 || ad[0].Status != OpDone || !strings.Contains(ad[0].Reason, "adopted, not duplicated") {
		t.Fatalf("ops = %+v", res.Ops)
	}
	if r.store.actions()["autotask_ticket_adopted"] != 1 || r.store.row("vuln|openssl", 1).TicketID != r.srv.Tickets()[0].ID {
		t.Error("the adopted ticket is not recorded")
	}
}

func TestAnAnswerLostOnCreateIsNotRepeated(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.srv.AddFault(atest.Fault{Match: "POST /Tickets$", Status: 502, AfterServing: true, Times: 1})
	first := r.live()
	if first.Failed != 1 || first.Created != 0 || first.Status() != "partial" {
		t.Fatalf("first = %+v", first)
	}
	if !strings.Contains(first.Ops[0].Reason, "may have been carried out") || len(r.srv.Tickets()) != 1 || len(r.store.rows) != 0 {
		t.Fatalf("op = %+v, tickets %d, rows %d", first.Ops[0], len(r.srv.Tickets()), len(r.store.rows))
	}
	second := r.live()
	if len(r.srv.Tickets()) != 1 || len(ops(second, OpAdopt)) != 1 {
		t.Fatalf("the next run opened a second ticket: %d tickets, %+v", len(r.srv.Tickets()), second.Ops)
	}
}

func TestStoreFailureAfterCreateStopsTheRunAndTheNextRunAdopts(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("web-01", "nginx", "CVE-2", true)}
	r.store.failNext = "autotask_ticket_created"
	res := r.live()
	if res.Failed != 1 || len(ops(res, OpCreate)) != 2 || ops(res, OpCreate)[1].Status != OpSkipped {
		t.Fatalf("ops = %+v: a run that cannot record must stop", res.Ops)
	}
	if len(r.srv.Tickets()) != 1 {
		t.Fatalf("%d tickets", len(r.srv.Tickets()))
	}
	next := r.live()
	if len(r.srv.Tickets()) != 2 || next.Created != 1 || len(ops(next, OpAdopt)) != 1 {
		t.Fatalf("tickets %d, ops %+v", len(r.srv.Tickets()), next.Ops)
	}
}

func TestNewHostJoinsAddsANoteNotATicket(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	id := r.srv.Tickets()[0].ID

	r.findings = append(r.findings, hostsFinding("web-02", "openssl", "CVE-1", true))
	res := r.live()
	if len(r.srv.Tickets()) != 1 || res.Noted != 1 || res.Created != 0 {
		t.Fatalf("tickets %d, result %+v", len(r.srv.Tickets()), res)
	}
	notes := r.srv.Notes(id)
	if len(notes) != 1 || !strings.Contains(notes[0].Description, "New since this ticket was opened (1):") || !strings.Contains(notes[0].Description, "web-02") ||
		!strings.Contains(notes[0].Description, "Still open in DefendSec: 2.") {
		t.Fatalf("notes = %+v", notes)
	}
	if notes[0].NoteType != 1 || notes[0].Publish != 2 || !strings.HasPrefix(notes[0].Title, "DefendSec update 2026-") {
		t.Errorf("note fields = %+v", notes[0])
	}
	// Told once.
	again := r.live()
	if len(again.Ops) != 0 || len(r.srv.Notes(id)) != 1 {
		t.Fatalf("the same news was told twice: %+v", again.Ops)
	}
	// More advisories on a host already in the group are news too.
	r.findings = append(r.findings, hostsFinding("web-01", "openssl", "CVE-77", false))
	res = r.live()
	n := r.srv.Notes(id)
	if res.Noted != 1 || len(n) != 2 || !strings.Contains(n[1].Description, "What is open changed on (1):") || !strings.Contains(n[1].Description, "web-01") {
		t.Fatalf("notes = %+v", n)
	}
}

func TestResolvedFindingGetsEvidenceAndTheTicketStaysOpenByDefault(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("web-02", "openssl", "CVE-1", true)}
	r.live()
	id := r.srv.Tickets()[0].ID
	r.store.evidence["dev-web-01"] = Evidence{Found: true, ResolvedAt: time.Date(2026, 10, 25, 9, 30, 0, 0, time.UTC), Detail: "openssl 2.0 observed, at or above the fixed version 2.0 (1 advisory closed)"}
	r.store.evidence["dev-web-02"] = Evidence{Found: true, ResolvedAt: time.Date(2026, 10, 25, 9, 45, 0, 0, time.UTC), Detail: "openssl 2.0 observed, at or above the fixed version 2.0 (1 advisory closed)"}

	r.findings = r.findings[1:] // web-01 is fixed
	res := r.live()
	n := r.srv.Notes(id)
	if res.Noted != 1 || len(n) != 1 {
		t.Fatalf("result %+v notes %+v", res, n)
	}
	if !strings.Contains(n[0].Description, "web-01: openssl 2.0 observed, at or above the fixed version 2.0 (1 advisory closed) at 2026-10-25 09:30 UTC") ||
		!strings.Contains(n[0].Description, "Still open in DefendSec: 1.") {
		t.Errorf("note:\n%s", n[0].Description)
	}

	r.findings = nil // web-02 is fixed too
	res = r.live()
	n = r.srv.Notes(id)
	if len(n) != 2 || !strings.Contains(n[1].Description, "web-02: openssl 2.0 observed") ||
		!strings.Contains(n[1].Description, "The ticket is left open: close it when you have checked.") {
		t.Fatalf("notes = %+v", n)
	}
	if len(ops(res, OpComplete)) != 0 || r.srv.Tickets()[0].Status != 1 || r.srv.Tickets()[0].CompletedDate != nil {
		t.Fatal("auto-complete is off by default, and the ticket was completed")
	}
	if r.store.row("vuln|openssl", 1).State != StateResolved {
		t.Errorf("state = %s", r.store.row("vuln|openssl", 1).State)
	}
	if again := r.live(); len(again.Ops) != 0 || len(r.srv.Notes(id)) != 2 {
		t.Fatalf("a resolved action was told twice: %+v", again.Ops)
	}
}

func TestAutoCompleteCompletesAndFailsSafely(t *testing.T) {
	r := newRig(t)
	r.set.AutoComplete = true
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	id := r.srv.Tickets()[0].ID
	r.store.evidence["dev-web-01"] = Evidence{Found: true, ResolvedAt: t0, Detail: "openssl 2.0 observed"}
	r.findings = nil

	// The completion fails: the note is not repeated on the retry.
	r.srv.AddFault(atest.Fault{Match: "PATCH /Tickets$", Status: 500, Body: `{"errors":["boom"]}`, Times: 1})
	res := r.live()
	if len(r.srv.Notes(id)) != 1 || res.Failed != 1 || r.srv.Tickets()[0].CompletedDate != nil {
		t.Fatalf("notes %d, result %+v", len(r.srv.Notes(id)), res)
	}
	if !strings.Contains(r.srv.Notes(id)[0].Description, "Auto-complete is on, so DefendSec is completing this ticket.") {
		t.Errorf("note = %s", r.srv.Notes(id)[0].Description)
	}
	res = r.live()
	if len(r.srv.Notes(id)) != 1 {
		t.Fatalf("the retry added a second note")
	}
	if res.Completed != 1 || r.srv.Tickets()[0].CompletedDate == nil || r.srv.Tickets()[0].Status != 5 {
		t.Fatalf("not completed: %+v / %+v", res, r.srv.Tickets()[0])
	}
	if r.store.row("vuln|openssl", 1).State != StateResolved || r.store.actions()["autotask_ticket_completed"] != 1 {
		t.Errorf("row %+v ledger %v", r.store.row("vuln|openssl", 1), r.store.actions())
	}
	if again := r.live(); len(again.Ops) != 0 {
		t.Fatalf("again: %+v", again.Ops)
	}
}

func TestATechnicianClosingTheTicketIsRespected(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	tk := r.srv.Tickets()[0]
	r.srv.Complete(tk.ID)

	res := r.live()
	fl := ops(res, OpFlag)
	if len(fl) != 1 || fl[0].Status != OpDone || !strings.Contains(fl[0].Reason, "was completed in Autotask while 1 member is still open") {
		t.Fatalf("ops = %+v", res.Ops)
	}
	if res.Flagged != 1 {
		t.Errorf("flagged = %d", res.Flagged)
	}
	if len(r.srv.Tickets()) != 1 || len(r.srv.Notes(tk.ID)) != 0 || r.store.row("vuln|openssl", 1).State != StateClosedInPSA {
		t.Fatal("DefendSec reopened, noted on or duplicated a ticket a person had closed")
	}
	if quiet := r.live(); len(quiet.Ops) != 0 || len(r.srv.Tickets()) != 1 {
		t.Fatalf("it keeps nagging: %+v", quiet.Ops)
	}

	// A new host is something the closed ticket never covered: a new ticket (generation 2).
	r.findings = append(r.findings, hostsFinding("web-02", "openssl", "CVE-1", true))
	res = r.live()
	if res.Created != 1 || len(r.srv.Tickets()) != 2 {
		t.Fatalf("result %+v", res)
	}
	second := r.store.row("vuln|openssl", 2)
	if second.TicketID == tk.ID || second.Tag == r.store.row("vuln|openssl", 1).Tag || len(second.Members) != 2 {
		t.Errorf("second = %+v", second)
	}
	if !strings.Contains(ops(res, OpCreate)[0].Reason, "the earlier one was completed in Autotask") {
		t.Errorf("reason = %q", ops(res, OpCreate)[0].Reason)
	}
}

func TestADeletedTicketIsNotRecreated(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	r.srv.Remove(r.srv.Tickets()[0].ID)
	res := r.live()
	if len(r.srv.Tickets()) != 0 || len(ops(res, OpFlag)) != 1 || !strings.Contains(ops(res, OpFlag)[0].Reason, "was not found in Autotask") {
		t.Fatalf("result %+v", res)
	}
}

func TestReturnedFindingsGoToTheOpenTicketOrANewOne(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	id := r.srv.Tickets()[0].ID
	r.findings = nil
	r.live() // resolved, ticket left open
	if r.store.row("vuln|openssl", 1).State != StateResolved {
		t.Fatal("setup")
	}
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-5", true)}
	res := r.live()
	n := r.srv.Notes(id)
	if len(r.srv.Tickets()) != 1 || res.Noted != 1 || !strings.Contains(n[len(n)-1].Description, "DefendSec sees this again") ||
		r.store.row("vuln|openssl", 1).State != StateOpen {
		t.Fatalf("returned to an open ticket: tickets %d, notes %+v", len(r.srv.Tickets()), n)
	}

	// Once the old ticket is completed, a return is a new ticket.
	r.findings = nil
	r.live()
	r.srv.Complete(id)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-6", true)}
	res = r.live()
	if len(r.srv.Tickets()) != 2 || res.Created != 1 || r.store.row("vuln|openssl", 2).TicketID == id {
		t.Fatalf("tickets %d result %+v", len(r.srv.Tickets()), res)
	}
}

func TestUrgencyRaisedIsToldNotChanged(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", false)} // high
	r.live()
	id := r.srv.Tickets()[0].ID
	if r.srv.Tickets()[0].Priority != 2 {
		t.Fatal("setup")
	}
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)} // now on KEV
	res := r.live()
	n := r.srv.Notes(id)
	if res.Noted != 1 || len(n) != 1 || !strings.Contains(n[0].Description, "Urgency went from high to critical. This ticket's priority was not changed") {
		t.Fatalf("notes = %+v", n)
	}
	if r.srv.Tickets()[0].Priority != 2 {
		t.Error("DefendSec changed a ticket's priority")
	}
	if again := r.live(); len(again.Ops) != 0 {
		t.Fatalf("told twice: %+v", again.Ops)
	}
}

func TestBelowTheThresholdIsCountedNotTicketed(t *testing.T) {
	r := newRig(t)
	med := vf("h", "libfoo", "CVE-3", "2", func(f *Finding) { f.Severity = "medium" })
	r.findings = []Finding{med, hostsFinding("web-01", "openssl", "CVE-1", true)}
	res := r.live()
	if res.Created != 1 || res.BelowThreshold != 1 || len(r.srv.Tickets()) != 1 {
		t.Fatalf("result %+v", res)
	}
	r.set.MinUrgency = UrgencyMedium
	res = r.run(ModeDryRun)
	if len(ops(res, OpCreate)) != 1 || res.BelowThreshold != 0 {
		t.Fatalf("with medium as the floor: %+v", res)
	}
	// An action that dips below the floor after it has a ticket is still followed.
	r.set.MinUrgency = UrgencyHigh
	r.findings = []Finding{vf("web-01", "openssl", "CVE-1", "2.0", func(f *Finding) { f.Severity = "low" })}
	res = r.run(ModeDryRun)
	if len(res.Ops) != 0 {
		t.Fatalf("ops = %+v", res.Ops)
	}
}

func TestPerRunLimitDefersTheRest(t *testing.T) {
	r := newRig(t)
	r.set.MaxCreates = 3
	for i := 0; i < 5; i++ {
		r.findings = append(r.findings, hostsFinding("web-01", fmt.Sprintf("pkg%d", i), fmt.Sprintf("CVE-%d", i), true))
	}
	res := r.live()
	if res.Created != 3 || res.Deferred != 2 || res.Status() != "partial" || len(r.srv.Tickets()) != 3 {
		t.Fatalf("result %+v", res)
	}
	res = r.live()
	if res.Created != 2 || res.Deferred != 0 || len(r.srv.Tickets()) != 5 {
		t.Fatalf("second run %+v", res)
	}
}

func TestThresholdStopsTheRun(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.srv.Used = 5000 // half of 10,000
	res := r.live()
	if len(r.srv.Tickets()) != 0 || len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "5000 of 10000 requests") || res.Status() != "not_run" {
		t.Fatalf("result %+v", res)
	}
	if n := len(r.srv.Requests()); n != 1 {
		t.Errorf("%d requests after the threshold said stop", n)
	}
	r.srv.Used = 4999
	if res = r.live(); res.Created != 1 {
		t.Fatalf("below half it must run: %+v", res)
	}
}

func TestLivePicklistDriftFailsClosed(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.set.PriorityCritical = "4" // an inactive priority in the fixture
	live := r.live()
	if len(r.srv.Tickets()) != 0 || len(live.Problems) == 0 || !strings.Contains(strings.Join(live.Problems, " "), "the critical priority (4) is not an active value") {
		t.Fatalf("live: %+v", live)
	}
	// A dry run still shows the tickets, and says the settings are off.
	r.set.PriorityCritical = "1"
	r.set.QueueID = "999"
	dry := r.run(ModeDryRun)
	if dry.Verified || len(ops(dry, OpCreate)) != 1 || !strings.Contains(dry.UnverifiedWhy, "no longer match Autotask") {
		t.Fatalf("dry: %+v", dry)
	}
}

func TestSubIssueMustBelongToTheIssueType(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.set.SubIssueType = "210" // Printer, under Hardware
	res := r.live()
	if len(r.srv.Tickets()) != 0 || !strings.Contains(strings.Join(res.Problems, " "), "belongs to another issue type") {
		t.Fatalf("result %+v", res)
	}
}

func TestRefusedCredentialsStopTheRunAndNothingIsAssumed(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.cfg = func(c *client.Config) { c.Secret = "wrong" }
	res := r.live()
	if len(res.Problems) != 1 || !strings.Contains(res.Problems[0], "auth") || len(r.srv.Tickets()) != 0 || strings.Contains(fmt.Sprint(res), "wrong") {
		t.Fatalf("result %+v", res)
	}
	dry := r.run(ModeDryRun)
	if dry.Verified || dry.UnverifiedWhy == "" || len(ops(dry, OpCreate)) != 1 {
		t.Fatalf("dry: %+v", dry)
	}
}

func TestFatalErrorMidRunSkipsTheRest(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 4; i++ {
		r.findings = append(r.findings, hostsFinding("web-01", fmt.Sprintf("pkg%d", i), fmt.Sprintf("CVE-%d", i), true))
	}
	// The service keeps throttling creates.
	r.srv.AddFault(atest.Fault{Match: "POST /Tickets$", Status: 429, Header: map[string]string{"Retry-After": "1"}})
	res := r.live()
	if res.Failed != 1 || res.Created != 0 || len(res.Ops) != 4 {
		t.Fatalf("result %+v", res)
	}
	for i, o := range res.Ops {
		want := OpSkipped
		if i == 0 {
			want = OpFailed
		}
		if o.Status != want {
			t.Errorf("op %d is %s, want %s", i, o.Status, want)
		}
	}
	if len(r.srv.Tickets()) != 0 || len(r.store.rows) != 0 {
		t.Error("a throttled create left a ticket or a row")
	}
}

func TestBudgetStopsARun(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 5; i++ {
		r.findings = append(r.findings, hostsFinding("web-01", fmt.Sprintf("pkg%d", i), fmt.Sprintf("CVE-%d", i), true))
	}
	r.cfg = func(c *client.Config) { c.MaxRequests = 10 } // preflight uses 4, each create 3
	res := r.live()
	if res.Created != 2 || res.Failed != 1 || res.Requests != 10 {
		t.Fatalf("result %+v", res)
	}
	if skipped := len(ops(res, OpCreate)) - 3; skipped != 2 {
		t.Errorf("ops %+v", res.Ops)
	}
	if !strings.Contains(res.Ops[2].Error, "budget") {
		t.Errorf("error = %q", res.Ops[2].Error)
	}
}

func TestEveryLiveActionIsOneLedgerEntry(t *testing.T) {
	r := newRig(t)
	r.set.AutoComplete = true
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("web-01", "nginx", "CVE-2", true)}
	r.live() // two creates
	r.findings = append(r.findings, hostsFinding("web-02", "openssl", "CVE-1", true))
	r.live() // a note
	r.store.evidence["dev-web-01"] = Evidence{Found: true, ResolvedAt: t0, Detail: "x"}
	r.findings = []Finding{hostsFinding("web-02", "openssl", "CVE-1", true)}
	r.live() // nginx: note + complete; openssl: web-01 left (a note)
	a := r.store.actions()
	if a["autotask_ticket_created"] != 2 || a["autotask_ticket_note_added"] != 3 || a["autotask_ticket_completed"] != 1 {
		t.Fatalf("ledger = %v", a)
	}
	for _, c := range r.store.ledger {
		for _, k := range []string{"groupKey", "tag", "ticketId", "companyId"} {
			if _, ok := c.Detail[k]; !ok {
				t.Errorf("%s entry lacks %s", c.Action, k)
			}
		}
		if s := fmt.Sprint(c.Detail); strings.Contains(s, atest.Secret) || strings.Contains(s, atest.IntegrationCode) {
			t.Errorf("a ledger entry holds a credential: %v", c.Detail)
		}
	}
}

func TestLongListsStayInsideAutotasksFieldLimits(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 400; i++ {
		r.findings = append(r.findings, hostsFinding(fmt.Sprintf("host-%03d-with-a-rather-long-name.example.net", i), "openssl", "CVE-1", true))
	}
	res := r.live()
	if res.Created != 1 || res.Failed != 0 {
		t.Fatalf("result %+v", res)
	}
	tk := r.srv.Tickets()[0]
	if utf8.RuneCountInString(tk.Description) > 8000 || utf8.RuneCountInString(tk.Title) > 255 || !strings.Contains(tk.Description, "DefendSec key: DS-") {
		t.Errorf("description %d runes, title %d", utf8.RuneCountInString(tk.Description), utf8.RuneCountInString(tk.Title))
	}
	// A note about 400 new members also fits.
	r.srv.ClearFaults()
	for i := 400; i < 800; i++ {
		r.findings = append(r.findings, hostsFinding(fmt.Sprintf("host-%03d-with-a-rather-long-name.example.net", i), "openssl", "CVE-1", true))
	}
	if res = r.live(); res.Noted != 1 || res.Failed != 0 {
		t.Fatalf("note: %+v", res)
	}
}

func TestOtherCompanysTicketWithTheSameTagIsNotAdopted(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.srv.Seed(atest.Ticket{CompanyID: 3002, Title: "Update openssl on web-01 [" + Tag("vuln|openssl", 1) + "]", Status: 1, Priority: 1})
	res := r.live()
	if res.Created != 1 || len(ops(res, OpAdopt)) != 0 || len(r.srv.Tickets()) != 2 {
		t.Fatalf("result %+v", res)
	}
	if r.store.row("vuln|openssl", 1).CompanyID != 3001 {
		t.Error("tracked under the wrong company")
	}
}

func TestDryRunSaysWhenATicketAlreadyExists(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	r.store = newMemStore()
	res := r.run(ModeDryRun)
	ad := ops(res, OpAdopt)
	if len(ad) != 1 || ad[0].Status != OpPlanned || !strings.Contains(ad[0].Reason, "would be adopted, not duplicated") {
		t.Fatalf("ops = %+v", res.Ops)
	}
	if len(r.store.rows) != 0 || len(r.srv.Tickets()) != 1 {
		t.Error("a dry run changed something")
	}
}

func samePayload(a, b client.TicketCreate) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestOpsNameThePicklistValuesWhenAutotaskWasRead(t *testing.T) {
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	res := r.run(ModeDryRun)
	l := ops(res, OpCreate)[0].Labels
	if l["queue"] != "Security Test Queue" || l["priority"] != "P1 Urgent" || l["status"] != "New" || l["source"] != "DefendSec" ||
		l["issueType"] != "Cybersecurity & Cloud" || l["subIssueType"] != "Vulnerability remediation" {
		t.Errorf("labels = %v", l)
	}
	e := &Engine{Store: r.store, Now: func() time.Time { return t0 }}
	off, _ := e.Run(context.Background(), r.set, r.findings, ModeDryRun)
	if got := ops(off, OpCreate)[0].Labels; len(got) != 0 {
		t.Errorf("an offline run names values it did not read: %v", got)
	}
}
