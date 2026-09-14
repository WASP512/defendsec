package storepg

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/presence"
)

// Integration tests against a real Postgres, matching the TEST_DATABASE_URL
// convention already used by db/migrations/migrations_test.go. Skipped
// unless that's set — see docker-compose.yml for a local instance, and the
// "postgres-integration" CI job for how it's wired up there.

func testStore(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return New(pool)
}

func randID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// alerts.device_id has a NOT NULL FOREIGN KEY REFERENCES devices(id), so
// every alert test needs a real device row first.
func seedDevice(t *testing.T, s *Store, id string) {
	t.Helper()
	if err := s.UpsertDevice(context.Background(), presence.Device{
		ID: id, Hostname: "host-" + id, Platform: "linux",
	}); err != nil {
		t.Fatalf("seed device %s: %v", id, err)
	}
}

func TestInsertAlertAndHasOpenAlert(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	deviceID, sourceID := randID(t), randID(t)
	seedDevice(t, s, deviceID)

	open, err := s.HasOpenAlert(ctx, deviceID, "fim", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("expected no open alert before insert")
	}

	if err := s.InsertAlert(ctx, Alert{
		ID: randID(t), DeviceID: deviceID, Hostname: "host-1", Kind: "fim",
		Severity: "high", Title: "t", Summary: "s", Status: "open",
		SourceType: "fim_drift", SourceID: sourceID,
	}); err != nil {
		t.Fatal(err)
	}

	open, err = s.HasOpenAlert(ctx, deviceID, "fim", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !open {
		t.Fatal("expected an open alert after insert")
	}

	// A different kind/device/source must not match.
	open, err = s.HasOpenAlert(ctx, deviceID, "sca", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("HasOpenAlert matched across kinds")
	}
}

func TestInsertAlertIsIdempotentByID(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, deviceID, sourceID := randID(t), randID(t), randID(t)
	seedDevice(t, s, deviceID)

	alert := Alert{
		ID: id, DeviceID: deviceID, Hostname: "host-1", Kind: "sca",
		Severity: "medium", Title: "t", Summary: "s", Status: "open",
		SourceType: "sca_check", SourceID: sourceID,
	}
	if err := s.InsertAlert(ctx, alert); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAlert(ctx, alert); err != nil {
		t.Fatal(err)
	}

	alerts, err := s.ListAlerts(ctx, AlertFilters{DeviceID: deviceID, Kind: "sca"})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts for device, want 1 (insert should be idempotent by id)", len(alerts))
	}
}

func TestResolveOpenAlerts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	deviceID, sourceID := randID(t), randID(t)
	seedDevice(t, s, deviceID)

	if err := s.InsertAlert(ctx, Alert{
		ID: randID(t), DeviceID: deviceID, Hostname: "host-1", Kind: "fim",
		Severity: "high", Title: "t", Summary: "s", Status: "open",
		SourceType: "fim_drift", SourceID: sourceID,
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.ResolveOpenAlerts(ctx, deviceID, "fim", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("resolved %d alerts, want 1", n)
	}

	open, err := s.HasOpenAlert(ctx, deviceID, "fim", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("alert still open after resolve")
	}

	// Resolving again must be a harmless no-op, not an error — this is the
	// property the fim/sca alert loops rely on to self-heal a resolve that
	// failed to reach Postgres on an earlier cycle.
	n, err = s.ResolveOpenAlerts(ctx, deviceID, "fim", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("resolved %d already-resolved alerts, want 0", n)
	}
}

func TestUpdateAlertStatusAndListFilters(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	deviceID := randID(t)
	seedDevice(t, s, deviceID)
	openID, ackID := randID(t), randID(t)

	if err := s.InsertAlert(ctx, Alert{
		ID: openID, DeviceID: deviceID, Hostname: "host-1", Kind: "vuln",
		Severity: "critical", Title: "t1", Summary: "s1", Status: "open",
		SourceType: "advisory", SourceID: randID(t),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertAlert(ctx, Alert{
		ID: ackID, DeviceID: deviceID, Hostname: "host-1", Kind: "vuln",
		Severity: "low", Title: "t2", Summary: "s2", Status: "open",
		SourceType: "advisory", SourceID: randID(t),
	}); err != nil {
		t.Fatal(err)
	}

	ok, err := s.UpdateAlertStatus(ctx, ackID, "acknowledged")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("UpdateAlertStatus reported no match for an alert that exists")
	}

	ok, err = s.UpdateAlertStatus(ctx, randID(t), "acknowledged")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("UpdateAlertStatus reported a match for an id that doesn't exist")
	}

	openAlerts, err := s.ListAlerts(ctx, AlertFilters{DeviceID: deviceID, Status: "open"})
	if err != nil {
		t.Fatal(err)
	}
	if len(openAlerts) != 1 || openAlerts[0].ID != openID {
		t.Fatalf("open-status filter = %+v, want exactly [%s]", openAlerts, openID)
	}

	ackAlerts, err := s.ListAlerts(ctx, AlertFilters{DeviceID: deviceID, Status: "acknowledged"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ackAlerts) != 1 || ackAlerts[0].ID != ackID {
		t.Fatalf("acknowledged-status filter = %+v, want exactly [%s]", ackAlerts, ackID)
	}
}
