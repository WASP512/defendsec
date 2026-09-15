package auditlayer

import (
	"strings"
	"testing"
	"time"

	"defendsec/internal/controls"
)

var (
	start = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end   = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	after = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
)

func period() Period {
	return Period{
		ID: "p1", Name: "Q1 2026", Framework: string(controls.CISv8),
		StartsAt: start, EndsAt: end, CreatedAt: start,
	}
}

func statusOf(a Assessment, id string) (ControlStatus, bool) {
	for _, c := range a.Controls {
		if string(c.Control.ID) == id {
			return c, true
		}
	}
	return ControlStatus{}, false
}

// The distinction the whole layer turns on: "cannot evidence" and "can
// evidence and saw nothing" must never collapse into each other, and neither
// may ever read as satisfied.
func TestNoEvidenceIsNotTheSameAsNotEvidenced(t *testing.T) {
	a := Assess(Input{Framework: controls.CISv8, Period: period(), Now: after})

	// 10.1 is anti-malware — DefendSec cannot evidence it.
	cannot, ok := statusOf(a, "cis-v8:10.1")
	if !ok {
		t.Fatal("cis-v8:10.1 missing from the assessment")
	}
	if cannot.Status != StatusNotEvidenced {
		t.Errorf("cis-v8:10.1 = %s, want not-evidenced", cannot.Status)
	}

	// 2.1 is software inventory — DefendSec can evidence it, and here did not.
	silent, ok := statusOf(a, "cis-v8:2.1")
	if !ok {
		t.Fatal("cis-v8:2.1 missing from the assessment")
	}
	if silent.Status != StatusNoEvidence {
		t.Errorf("cis-v8:2.1 = %s, want no-evidence", silent.Status)
	}

	if cannot.Status == silent.Status {
		t.Fatal("the two statuses collapsed into one")
	}
	for _, cs := range []ControlStatus{cannot, silent} {
		if cs.Status == StatusSatisfied {
			t.Errorf("%s was rendered satisfied", cs.Control.ID)
		}
	}

	// And the empty window must say what it probably means, rather than
	// leaving a reader to assume all was well.
	if !strings.Contains(silent.Statement, "did not run") {
		t.Errorf("empty-window statement does not explain itself: %q", silent.Statement)
	}
	if !strings.Contains(silent.Statement, "not a pass") {
		t.Errorf("empty-window statement could be misread as a pass: %q", silent.Statement)
	}
}

// A control DefendSec cannot see must stay not-evidenced even when records
// happen to carry its tag. This is the most damaging thing a compliance view
// can get wrong, so it is asserted against a hostile input.
func TestNotEvidencedSurvivesTaggedRecords(t *testing.T) {
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence: map[string]Evidence{
			"cis-v8:10.1": {Alerts: 40, Commands: 12, AuditEntries: 99},
		},
	})
	cs, _ := statusOf(a, "cis-v8:10.1")
	if cs.Status != StatusNotEvidenced {
		t.Fatalf("records promoted an unevidenceable control to %s", cs.Status)
	}
}

func TestOpenFindingsAreDeficient(t *testing.T) {
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence: map[string]Evidence{
			"cis-v8:5.4": {Alerts: 5, OpenAlerts: 2, OpenAtEnd: 2, AuditEntries: 3},
		},
	})
	cs, _ := statusOf(a, "cis-v8:5.4")
	if cs.Status != StatusDeficient {
		t.Fatalf("status = %s, want deficient", cs.Status)
	}
	if !strings.Contains(cs.Statement, "2 findings are still open") {
		t.Errorf("statement does not carry the numbers: %q", cs.Statement)
	}
	if !strings.Contains(cs.Statement, "No documented exception") {
		t.Errorf("statement does not say the deficiency is uncovered: %q", cs.Statement)
	}
}

func TestResolvedFindingsStillSatisfy(t *testing.T) {
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence: map[string]Evidence{
			"cis-v8:5.4": {Alerts: 7, OpenAlerts: 0, Commands: 4, AuditEntries: 9},
		},
	})
	cs, _ := statusOf(a, "cis-v8:5.4")
	if cs.Status != StatusSatisfied {
		t.Fatalf("status = %s, want satisfied", cs.Status)
	}
	if !strings.Contains(cs.Statement, "Held continuously") {
		t.Errorf("statement = %q", cs.Statement)
	}
	// Findings raised and closed inside the window are evidence the control
	// was operating, not evidence against it.
	if !strings.Contains(cs.Statement, "none outstanding") {
		t.Errorf("statement = %q", cs.Statement)
	}
}

// An exception is an accepted deficiency, and must never be dressed up as a
// satisfied control.
func TestExceptionCoversButDoesNotSatisfy(t *testing.T) {
	ex := Exception{
		ID: "e1", ControlID: "cis-v8:5.4", Reason: "legacy appliance, replacement ordered",
		OpenedAt: start, ExpiresAt: end.Add(30 * 24 * time.Hour),
	}
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence:   map[string]Evidence{"cis-v8:5.4": {Alerts: 3, OpenAlerts: 3, OpenAtEnd: 3}},
		Exceptions: []Exception{ex},
	})
	cs, _ := statusOf(a, "cis-v8:5.4")
	if cs.Status != StatusExcepted {
		t.Fatalf("status = %s, want excepted", cs.Status)
	}
	if cs.Status == StatusSatisfied {
		t.Fatal("an exception produced a pass")
	}
	if !strings.Contains(cs.Statement, "not a satisfied control") {
		t.Errorf("statement could be misread as a pass: %q", cs.Statement)
	}
	if !strings.Contains(cs.Statement, ex.Reason) {
		t.Errorf("statement omits the documented reason: %q", cs.Statement)
	}
}

// Time-limited means time-limited: an expired exception stops covering.
func TestExpiredExceptionStopsCovering(t *testing.T) {
	expired := Exception{
		ID: "e1", ControlID: "cis-v8:5.4", Reason: "was accepted",
		OpenedAt: start, ExpiresAt: start.Add(24 * time.Hour),
	}
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence:   map[string]Evidence{"cis-v8:5.4": {Alerts: 1, OpenAlerts: 1, OpenAtEnd: 1}},
		Exceptions: []Exception{expired},
	})
	cs, _ := statusOf(a, "cis-v8:5.4")
	if cs.Status != StatusDeficient {
		t.Fatalf("status = %s, want deficient once the exception expired", cs.Status)
	}
	// It is still shown — the reader should see that an exception existed and
	// lapsed, not that there never was one.
	if len(cs.Exceptions) != 1 {
		t.Error("the lapsed exception was hidden")
	}
}

func TestClosedExceptionStopsCovering(t *testing.T) {
	closedAt := start.Add(48 * time.Hour)
	closed := Exception{
		ID: "e1", ControlID: "cis-v8:5.4", Reason: "resolved early",
		OpenedAt: start, ExpiresAt: after, ClosedAt: &closedAt,
	}
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence:   map[string]Evidence{"cis-v8:5.4": {Alerts: 1, OpenAlerts: 1, OpenAtEnd: 1}},
		Exceptions: []Exception{closed},
	})
	if cs, _ := statusOf(a, "cis-v8:5.4"); cs.Status != StatusDeficient {
		t.Fatalf("status = %s, want deficient after the exception was closed", cs.Status)
	}
}

func TestExceptionActiveAt(t *testing.T) {
	closedAt := start.Add(10 * 24 * time.Hour)
	e := Exception{OpenedAt: start, ExpiresAt: start.Add(30 * 24 * time.Hour), ClosedAt: &closedAt}
	cases := map[time.Time]bool{
		start.Add(-time.Hour):          false, // before it opened
		start:                          true,  // inclusive at open
		start.Add(5 * 24 * time.Hour):  true,
		closedAt:                       false, // exclusive at close
		start.Add(40 * 24 * time.Hour): false,
	}
	for at, want := range cases {
		if got := e.ActiveAt(at); got != want {
			t.Errorf("ActiveAt(%s) = %v, want %v", at.Format(time.RFC3339), got, want)
		}
	}

	// An expiry that falls inside the open window still binds.
	open := Exception{OpenedAt: start, ExpiresAt: start.Add(time.Hour)}
	if open.ActiveAt(start.Add(2 * time.Hour)) {
		t.Error("an expired exception is still active")
	}
}

// A period that has not finished yet must be judged as of now, not as of a
// date in the future where nothing has had a chance to happen.
func TestRunningPeriodIsJudgedAsOfNow(t *testing.T) {
	now := start.Add(24 * time.Hour)
	ex := Exception{
		ID: "e1", ControlID: "cis-v8:5.4", Reason: "temporary",
		OpenedAt: start, ExpiresAt: start.Add(48 * time.Hour), // lapses before the period ends
	}
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: now,
		Evidence:   map[string]Evidence{"cis-v8:5.4": {Alerts: 1, OpenAlerts: 1, OpenAtEnd: 1}},
		Exceptions: []Exception{ex},
	})
	if cs, _ := statusOf(a, "cis-v8:5.4"); cs.Status != StatusExcepted {
		t.Fatalf("status = %s; an exception in force today must apply to a period still running", cs.Status)
	}
}

func TestQualifiedSatisfiedSaysSo(t *testing.T) {
	// 4.1 is partially covered: DefendSec does the checking, not the process.
	a := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence: map[string]Evidence{"cis-v8:4.1": {Alerts: 2, AuditEntries: 5}},
	})
	cs, _ := statusOf(a, "cis-v8:4.1")
	if cs.Status != StatusSatisfied || !cs.Qualified {
		t.Fatalf("status=%s qualified=%v, want a qualified satisfied", cs.Status, cs.Qualified)
	}
	if !strings.Contains(cs.Statement, "only in part") {
		t.Errorf("a qualified pass reads as a full one: %q", cs.Statement)
	}
}

func TestCountsAndCaveats(t *testing.T) {
	a := Assess(Input{Framework: controls.CJISv6, Period: period(), Now: after})

	var total int
	for _, n := range a.Counts {
		total += n
	}
	if total != len(a.Controls) {
		t.Errorf("counts total %d, assessment has %d controls", total, len(a.Controls))
	}
	if len(a.Controls) == 0 {
		t.Fatal("no controls assessed")
	}

	joined := strings.Join(a.Caveats, " ")
	if !strings.Contains(joined, "percentage") {
		t.Error("the caveats do not explain the absent percentage")
	}
	if !strings.Contains(joined, "cannot be evidenced") {
		t.Error("the caveats do not surface the unevidenceable controls")
	}
	if a.Title != controls.FrameworkTitle(controls.CJISv6) {
		t.Errorf("title = %q", a.Title)
	}
}

// Every control in the framework must appear. A compliance view that omits a
// control is worse than one that marks it badly: the reader cannot notice.
func TestAssessmentCoversEveryControl(t *testing.T) {
	for _, f := range controls.Frameworks() {
		a := Assess(Input{Framework: f, Period: period(), Now: after})
		if len(a.Controls) != len(controls.ForFramework(f)) {
			t.Errorf("%s: assessed %d of %d controls", f, len(a.Controls), len(controls.ForFramework(f)))
		}
		for _, cs := range a.Controls {
			if cs.Status == "" {
				t.Errorf("%s: %s has no status", f, cs.Control.ID)
			}
			if strings.TrimSpace(cs.Statement) == "" {
				t.Errorf("%s: %s has no statement", f, cs.Control.ID)
			}
		}
	}
}

// A finding resolved inside the window must not make the control deficient,
// and one still open at the close must — regardless of what its status is
// today. This is the difference between judging a period and judging now.
func TestDeficiencyUsesOpenAtEndNotOpenNow(t *testing.T) {
	// Resolved before the window closed, still shown as open today because it
	// was reopened afterwards: the period itself was clean.
	clean := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence: map[string]Evidence{
			"cis-v8:5.4": {Alerts: 4, OpenAlerts: 2, OpenAtEnd: 0, AuditEntries: 1},
		},
	})
	if cs, _ := statusOf(clean, "cis-v8:5.4"); cs.Status != StatusSatisfied {
		t.Errorf("status = %s; findings opened after the window must not make it deficient", cs.Status)
	}

	// Open at the close, resolved since: the period was deficient and saying
	// otherwise would rewrite a window that has already been assessed.
	dirty := Assess(Input{
		Framework: controls.CISv8, Period: period(), Now: after,
		Evidence: map[string]Evidence{
			"cis-v8:5.4": {Alerts: 4, OpenAlerts: 0, OpenAtEnd: 3, AuditEntries: 1},
		},
	})
	cs, _ := statusOf(dirty, "cis-v8:5.4")
	if cs.Status != StatusDeficient {
		t.Fatalf("status = %s, want deficient", cs.Status)
	}
	if !strings.Contains(cs.Statement, "3 findings are still open") {
		t.Errorf("statement uses the wrong number: %q", cs.Statement)
	}

	// And the reconstruction must be disclosed rather than presented as exact.
	if !strings.Contains(strings.Join(dirty.Caveats, " "), "reconstructed") {
		t.Error("the caveats do not disclose that open-at-close is reconstructed")
	}
}
