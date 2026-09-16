package cmdlog

import (
	"path/filepath"
	"testing"
	"time"
)

func tmpLog(t *testing.T) *File {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "commands.json"))
}

func rec(id string, at time.Time) Record {
	stamp := at.UTC().Format(time.RFC3339)
	return Record{
		ID: id, DeviceID: "dev-1", Type: "isolate", Status: "sent",
		CreatedAt: stamp, UpdatedAt: stamp,
	}
}

// The bug this replaced: a 500-record cap silently discarded the oldest
// privileged action regardless of age, while the compliance view claimed to
// evidence a control requiring a year of history.
func TestRetentionIsByAgeNotCount(t *testing.T) {
	f := tmpLog(t)
	now := time.Now().UTC()

	// Far more than the old cap, all recent.
	for i := 0; i < 700; i++ {
		if err := f.Append(rec("cmd-"+string(rune('a'+i%26))+time.Duration(i).String(), now.Add(-time.Duration(i)*time.Minute))); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.List("")); got != 700 {
		t.Fatalf("kept %d records, want all 700 — a count cap is still discarding history", got)
	}
}

func TestRecordsOlderThanTheWindowAreDropped(t *testing.T) {
	f := tmpLog(t)
	f.SetRetentionDays(30)
	now := time.Now().UTC()

	if err := f.Append(rec("old", now.AddDate(0, 0, -40))); err != nil {
		t.Fatal(err)
	}
	if err := f.Append(rec("edge", now.AddDate(0, 0, -29))); err != nil {
		t.Fatal(err)
	}
	if err := f.Append(rec("fresh", now)); err != nil {
		t.Fatal(err)
	}

	ids := map[string]bool{}
	for _, r := range f.List("") {
		ids[r.ID] = true
	}
	if ids["old"] {
		t.Error("a record outside the window survived")
	}
	if !ids["edge"] || !ids["fresh"] {
		t.Errorf("records inside the window were dropped: %v", ids)
	}
}

// The default has to meet the obligation of the deployments least likely to
// have configured it.
func TestDefaultRetentionMeetsTheCJISMinimum(t *testing.T) {
	if DefaultRetentionDays < 365 {
		t.Fatalf("default retention is %d days, below the CJIS minimum of 365", DefaultRetentionDays)
	}
	if got := tmpLog(t).RetentionDays(); got != DefaultRetentionDays {
		t.Errorf("a fresh log retains for %d days, want the default %d", got, DefaultRetentionDays)
	}
}

// Zero must restore the default, not mean "keep nothing". A configuration
// mistake that silently deletes the audit trail is the worst reading of an
// empty value.
func TestZeroRetentionRestoresTheDefault(t *testing.T) {
	f := tmpLog(t)
	f.SetRetentionDays(7)
	f.SetRetentionDays(0)
	if got := f.RetentionDays(); got != DefaultRetentionDays {
		t.Fatalf("retention after zero = %d, want the default %d", got, DefaultRetentionDays)
	}

	now := time.Now().UTC()
	if err := f.Append(rec("year-old", now.AddDate(0, 0, -200))); err != nil {
		t.Fatal(err)
	}
	if len(f.List("")) != 1 {
		t.Error("zero retention deleted a record inside the default window")
	}
}

// Some deployments are required to keep everything, and that has to be
// expressible.
func TestNegativeRetentionKeepsEverything(t *testing.T) {
	f := tmpLog(t)
	f.SetRetentionDays(-1)
	now := time.Now().UTC()

	for i, age := range []int{0, 400, 4000} {
		if err := f.Append(rec("r"+string(rune('a'+i)), now.AddDate(0, 0, -age))); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(f.List("")); got != 3 {
		t.Fatalf("kept %d of 3 records with retention disabled", got)
	}
}

// Discarding history because a timestamp is malformed would delete exactly the
// records most worth looking at.
func TestUnparseableTimestampsAreKept(t *testing.T) {
	f := tmpLog(t)
	f.SetRetentionDays(1)

	if err := f.Append(Record{ID: "broken", DeviceID: "dev-1", Type: "isolate", CreatedAt: "not a time"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Append(Record{ID: "empty", DeviceID: "dev-1", Type: "isolate"}); err != nil {
		t.Fatal(err)
	}
	if got := len(f.List("")); got != 2 {
		t.Fatalf("kept %d of 2 records with unusable timestamps", got)
	}
}

// The count cap is a safety valve, and crossing it must be reported rather
// than silently dropping privileged-action history.
func TestOverflowIsReported(t *testing.T) {
	f := tmpLog(t)
	f.SetRetentionDays(-1) // isolate the count cap from the age window

	var reported int
	f.SetOverflowHandler(func(dropped int) { reported += dropped })

	now := time.Now().UTC()
	records := make([]Record, 0, maxRecords+5)
	for i := 0; i < maxRecords+5; i++ {
		records = append(records, rec("r"+time.Duration(i).String(), now))
	}
	// Append them through the real path in one batch by writing directly, then
	// appending one more to trigger the cap.
	f.mu.Lock()
	doc := snapshot{Commands: records}
	if err := f.write(doc); err != nil {
		f.mu.Unlock()
		t.Fatal(err)
	}
	f.mu.Unlock()

	if err := f.Append(rec("one-more", now)); err != nil {
		t.Fatal(err)
	}
	if reported == 0 {
		t.Fatal("the count cap discarded records without reporting it")
	}
	if got := len(f.List("")); got != maxRecords {
		t.Errorf("kept %d records, want the cap of %d", got, maxRecords)
	}
}

func TestRetentionDoesNotDisturbPendingLookup(t *testing.T) {
	f := tmpLog(t)
	now := time.Now().UTC()
	r := rec("pending-1", now)
	r.Status = "queued"
	if err := f.Append(r); err != nil {
		t.Fatal(err)
	}
	if got := len(f.Pending("dev-1")); got != 1 {
		t.Fatalf("pending = %d, want 1", got)
	}
}
