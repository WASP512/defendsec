package autotask

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"defendsec/internal/autotask/atest"
)

// dryRunSnapshot is everything a dry run must leave exactly as it found it.
type dryRunSnapshot struct {
	tickets string
	notes   string
	rows    string
	ledger  int
}

func takeSnapshot(r *rig) dryRunSnapshot {
	tickets := r.srv.Tickets()
	notes := map[int64]int{}
	for _, tk := range tickets {
		notes[tk.ID] = len(r.srv.Notes(tk.ID))
	}
	tj, _ := json.Marshal(tickets)
	nj, _ := json.Marshal(notes)
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	rj, _ := json.Marshal(r.store.rows)
	return dryRunSnapshot{tickets: string(tj), notes: string(nj), rows: string(rj), ledger: len(r.store.ledger)}
}

// dryRunWith runs ModeDryRun after the test has set up an open tracked ticket and
// changed what is open, and fails if anything but a read reached Autotask or any
// state changed in Autotask or in DefendSec.
func dryRunWith(t *testing.T, r *rig) Result {
	t.Helper()
	before := takeSnapshot(r)
	r.srv.ResetRequests()
	res := r.run(ModeDryRun)
	for _, q := range r.srv.Requests() {
		if q.Method == "PATCH" || q.Method == "PUT" || q.Method == "DELETE" || (q.Method == "POST" && q.Path != "/Tickets/query") {
			t.Errorf("a dry run sent %s %s", q.Method, q.Path)
		}
	}
	if after := takeSnapshot(r); after != before {
		t.Errorf("a dry run changed state:\nbefore %+v\nafter  %+v", before, after)
	}
	for _, o := range res.Ops {
		if o.Status == OpDone {
			t.Errorf("a dry run reports %s as done: %+v", o.Kind, o)
		}
	}
	return res
}

func TestDryRunWithATrackedTicketSendsNoNoteAndNoCompletion(t *testing.T) {
	// New host and a fixed host on one open ticket: two notes would be written live.
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("web-02", "openssl", "CVE-1", true)}
	r.live()
	r.store.evidence["dev-web-01"] = Evidence{Found: true, ResolvedAt: t0, Detail: "openssl 2.0 observed"}
	r.findings = []Finding{hostsFinding("web-02", "openssl", "CVE-1", true), hostsFinding("web-03", "openssl", "CVE-1", true)}
	res := dryRunWith(t, r)
	notes := ops(res, OpNote)
	if len(notes) != 1 || notes[0].Status != OpPlanned || !strings.Contains(notes[0].Note, "web-03") || !strings.Contains(notes[0].Note, "web-01: openssl 2.0 observed") {
		t.Fatalf("the dry run should show the note it would add: %+v", res.Ops)
	}

	// Auto-complete on, and nothing of the action open any more: a note and a completion.
	r2 := newRig(t)
	r2.set.AutoComplete = true
	r2.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r2.live()
	r2.store.evidence["dev-web-01"] = Evidence{Found: true, ResolvedAt: t0, Detail: "openssl 2.0 observed"}
	r2.findings = nil
	res = dryRunWith(t, r2)
	if len(ops(res, OpNote)) != 1 || len(ops(res, OpComplete)) != 1 || ops(res, OpComplete)[0].Status != OpPlanned {
		t.Fatalf("the dry run should show the note and the completion: %+v", res.Ops)
	}
	if r2.srv.Tickets()[0].CompletedDate != nil {
		t.Fatal("a dry run completed a ticket")
	}

	// A technician closed the ticket, and another was deleted: the flags are shown, not recorded.
	r3 := newRig(t)
	r3.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true), hostsFinding("db-01", "postgresql", "CVE-2", true)}
	r3.live()
	for _, tk := range r3.srv.Tickets() {
		if strings.Contains(tk.Title, "openssl") {
			r3.srv.Complete(tk.ID)
		} else {
			r3.srv.Remove(tk.ID)
		}
	}
	res = dryRunWith(t, r3)
	if len(ops(res, OpFlag)) != 2 {
		t.Fatalf("the dry run should show both flags: %+v", res.Ops)
	}

	// A fixed host's note is what live would send, and the same data live sends it.
	r4 := newRig(t)
	r4.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r4.live()
	r4.findings = append(r4.findings, hostsFinding("web-02", "openssl", "CVE-1", true))
	dry := dryRunWith(t, r4)
	live := r4.live()
	if len(ops(dry, OpNote)) != 1 || len(ops(live, OpNote)) != 1 || ops(dry, OpNote)[0].Note != ops(live, OpNote)[0].Note {
		t.Fatalf("dry and live notes differ:\n%+v\n%+v", dry.Ops, live.Ops)
	}
	if got := r4.srv.Notes(r4.srv.Tickets()[0].ID); len(got) != 1 {
		t.Fatalf("live notes = %d", len(got))
	}
}

func TestANoteThatFailsOnAServerErrorIsNotRetried(t *testing.T) {
	// A note is not idempotent: if the answer was lost the note may exist, and a retry
	// would write it twice. The engine reports the failure and sends one request.
	r := newRig(t)
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	id := r.srv.Tickets()[0].ID
	r.findings = append(r.findings, hostsFinding("web-02", "openssl", "CVE-1", true))
	r.srv.ResetRequests()
	r.srv.AddFault(atest.Fault{Match: fmt.Sprintf("POST /Tickets/%d/Notes", id), Status: 502, AfterServing: true, Times: 1})
	res := r.live()
	posts := 0
	for _, q := range r.srv.Requests() {
		if q.Method == "POST" && strings.HasSuffix(q.Path, "/Notes") {
			posts++
		}
	}
	if posts != 1 || res.Failed != 1 || res.Noted != 0 {
		t.Fatalf("note POSTs = %d, result %+v: a 5xx on a note must not be retried", posts, res)
	}
	if n := len(r.srv.Notes(id)); n != 1 {
		t.Fatalf("the fake holds %d notes (the lost answer carried the first one out)", n)
	}
}

func TestDryRunAfterAFailedCompletionDoesNotRetryIt(t *testing.T) {
	// A live run added the note but the completion failed: the row is open with no
	// members. The next live run only completes; a dry run must only say so.
	r := newRig(t)
	r.set.AutoComplete = true
	r.findings = []Finding{hostsFinding("web-01", "openssl", "CVE-1", true)}
	r.live()
	r.store.evidence["dev-web-01"] = Evidence{Found: true, ResolvedAt: t0, Detail: "openssl 2.0 observed"}
	r.findings = nil
	r.srv.AddFault(atest.Fault{Match: "PATCH /Tickets$", Status: 500, Body: `{"errors":["boom"]}`, Times: 1})
	if res := r.live(); res.Failed != 1 {
		t.Fatalf("setup: %+v", res)
	}
	res := dryRunWith(t, r)
	if c := ops(res, OpComplete); len(c) != 1 || c[0].Status != OpPlanned {
		t.Fatalf("the dry run should show the completion it would retry: %+v", res.Ops)
	}
	if r.srv.Tickets()[0].CompletedDate != nil {
		t.Fatal("a dry run completed a ticket")
	}
	if res := r.live(); res.Completed != 1 {
		t.Fatalf("the live run after it should complete: %+v", res)
	}
}
