package storepg

import (
	"context"
	"testing"
	"time"

	"defendsec/internal/controls"
)

// clearWindow removes alerts whose effective time falls in [from, to), so a
// counting test starts from a known empty window in a database that persists
// between runs.
func clearWindow(t *testing.T, s *Store, from, to time.Time) {
	t.Helper()
	if _, err := s.pool.Exec(context.Background(), `
		DELETE FROM alerts
		WHERE COALESCE(detected_at, created_at) >= $1 AND COALESCE(detected_at, created_at) < $2
	`, from, to); err != nil {
		t.Fatalf("clear window: %v", err)
	}
}

func TestSyncControlCatalogIsIdempotent(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	n, err := s.SyncControlCatalog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(controls.Catalog()) {
		t.Fatalf("synced %d controls, catalog has %d", n, len(controls.Catalog()))
	}

	// Running it twice must not duplicate or fail — it happens on every start.
	if _, err := s.SyncControlCatalog(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM control_catalog`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Fatalf("after two syncs the table holds %d rows, want %d", count, n)
	}

	// A row edited by hand must not survive the next sync: the Go registry is
	// the source of truth, and a stale hand-edit outliving the code is how a
	// compliance view starts lying.
	if _, err := s.pool.Exec(ctx,
		`UPDATE control_catalog SET coverage='evidenced', note='' WHERE coverage='not-evidenced'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncControlCatalog(ctx); err != nil {
		t.Fatal(err)
	}
	var none int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM control_catalog WHERE coverage='not-evidenced'`).Scan(&none); err != nil {
		t.Fatal(err)
	}
	if none == 0 {
		t.Fatal("a hand-edited catalog row survived the sync")
	}
}

func TestCountControlRecordsUsesHalfOpenBounds(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	dev := randID(t)
	seedDevice(t, s, dev)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	id := "cis-v8:4.1"
	prefix := randID(t)

	// The test database persists between runs, so rows left by a previous run
	// sit in this window and would be counted too. Clear the window rather
	// than the table: other tests own rows elsewhere in it.
	clearWindow(t, s, base.Add(-2*time.Hour), base.Add(26*time.Hour))

	insert := func(alertID string, at time.Time) {
		if err := s.InsertAlert(ctx, Alert{
			ID: prefix + alertID, DeviceID: dev, Kind: "sca", Severity: "high",
			Title: "t", Status: "open", CreatedAt: at.Format(time.RFC3339),
			DetectedAt: at.Format(time.RFC3339),
			Signal:     string(controls.SignalSCA), ControlIDs: []string{id},
		}); err != nil {
			t.Fatal(err)
		}
	}
	insert("before", base.Add(-time.Hour))
	insert("start", base)
	insert("inside", base.Add(12*time.Hour))
	insert("end", base.Add(24*time.Hour)) // exactly the exclusive upper bound

	counts, err := s.CountControlRecords(ctx,
		base.Format(time.RFC3339), base.Add(24*time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	got := counts[id]
	// Inclusive start, exclusive end: the record before and the record exactly
	// at the end must both be out, or two adjacent periods double-count.
	if got.Alerts != 2 {
		t.Fatalf("counted %d alerts, want 2 (the start and inside ones)", got.Alerts)
	}
	if got.OpenAlerts != 2 {
		t.Errorf("open = %d, want 2", got.OpenAlerts)
	}
}

// An untagged record must not appear under any control. Tagging is what makes
// the count mean something.
func TestCountControlRecordsIgnoresUntagged(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	dev := randID(t)
	seedDevice(t, s, dev)
	at := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	clearWindow(t, s, at.Add(-2*time.Hour), at.Add(2*time.Hour))
	if err := s.InsertAlert(ctx, Alert{
		ID: randID(t), DeviceID: dev, Kind: "other", Severity: "low",
		Title: "t", Status: "open",
		CreatedAt: at.Format(time.RFC3339), DetectedAt: at.Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	counts, err := s.CountControlRecords(ctx,
		at.Add(-time.Hour).Format(time.RFC3339), at.Add(time.Hour).Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 0 {
		t.Fatalf("an untagged alert produced counts: %+v", counts)
	}
}

// Audit entries are tagged from their action, and the tag must be the same one
// a verifier recomputes.
func TestAuditEntriesAreControlTagged(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	if err := s.Audit(ctx, "user:alice", "command_issue", "", map[string]any{"k": "v"}); err != nil {
		t.Fatal(err)
	}
	var signal string
	var ids []string
	if err := s.pool.QueryRow(ctx,
		`SELECT signal, control_ids FROM audit_log WHERE action='command_issue' ORDER BY seq DESC LIMIT 1`,
	).Scan(&signal, &ids); err != nil {
		t.Fatal(err)
	}
	if signal != controls.AuditActionSignalName("command_issue") {
		t.Errorf("signal = %q", signal)
	}
	want := controls.TagAuditAction("command_issue")
	if len(ids) != len(want) {
		t.Fatalf("stored %v, recomputed %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("stored %v, recomputed %v", ids, want)
		}
	}
	if len(ids) == 0 {
		t.Fatal("command_issue produced no control tags")
	}
}
