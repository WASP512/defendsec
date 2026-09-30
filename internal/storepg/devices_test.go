package storepg

import (
	"context"
	"fmt"
	"testing"
	"time"

	"defendsec/internal/presence"
)

// seedFleet inserts n devices under a unique hostname prefix, so assertions
// can be scoped to them in a shared test database.
func seedFleet(t *testing.T, s *Store, prefix string, n int) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	platforms := []string{"linux", "windows", "darwin"}
	for i := 0; i < n; i++ {
		seen := now
		if i%4 == 0 {
			seen = now.Add(-time.Hour) // offline
		}
		f := i%5 != 0
		d := presence.Device{
			ID: fmt.Sprintf("%s-%04d", prefix, i), Hostname: fmt.Sprintf("%s-Host-%04d", prefix, i),
			Platform: platforms[i%3], OSName: "Test OS", LastSeen: seen.Format(time.RFC3339),
			Isolated: i%10 == 0, Firewall: &f, IPAddresses: []string{fmt.Sprintf("10.9.%d.%d", i/250, i%250)},
			Software: []presence.Software{{Name: "a", Version: "1"}, {Name: "b", Version: "2"}},
		}
		if err := s.UpsertDevice(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
}

func TestListDevicesPagesEveryDeviceExactlyOnce(t *testing.T) {
	s := testStore(t)
	prefix := "pg" + randID(t)[:8]
	seedFleet(t, s, prefix, 237)

	seen := map[string]bool{}
	cursor := ""
	pages := 0
	for {
		page, err := s.ListDevices(context.Background(), DeviceQuery{Q: prefix, Limit: 50, Cursor: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 237 {
			t.Fatalf("total = %d, want 237", page.Total)
		}
		for _, d := range page.Devices {
			if seen[d.ID] {
				t.Fatalf("%s returned twice", d.ID)
			}
			seen[d.ID] = true
			if d.SoftwareCount != 2 {
				t.Fatalf("software count = %d", d.SoftwareCount)
			}
		}
		pages++
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	if len(seen) != 237 || pages != 5 {
		t.Fatalf("saw %d devices over %d pages", len(seen), pages)
	}
}

func TestListDevicesFiltersInTheDatabase(t *testing.T) {
	s := testStore(t)
	prefix := "pf" + randID(t)[:8]
	seedFleet(t, s, prefix, 60)
	ctx := context.Background()
	count := func(q DeviceQuery) int {
		t.Helper()
		q.Limit = MaxPageSize
		p, err := s.ListDevices(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return p.Total
	}
	if n := count(DeviceQuery{Q: prefix, Platform: "windows"}); n != 20 {
		t.Errorf("windows = %d, want 20", n)
	}
	if n := count(DeviceQuery{Q: prefix, Status: "offline"}); n != 15 {
		t.Errorf("offline = %d, want 15", n)
	}
	if n := count(DeviceQuery{Q: prefix, Status: "online"}); n != 45 {
		t.Errorf("online = %d, want 45", n)
	}
	if n := count(DeviceQuery{Q: prefix, Status: "isolated"}); n != 6 {
		t.Errorf("isolated = %d, want 6", n)
	}
	// Case-insensitive hostname match, and a search by IP address.
	if n := count(DeviceQuery{Q: prefix + "-HOST-0007"}); n != 1 {
		t.Errorf("hostname search = %d, want 1", n)
	}
	// LIKE metacharacters are literal: "%" must not match everything.
	if n := count(DeviceQuery{Q: prefix + "%"}); n != 0 {
		t.Errorf("%%-search = %d, want 0", n)
	}
}

func TestListDevicesRejectsBadInput(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	for _, q := range []DeviceQuery{
		{Cursor: "not-a-cursor"},
		{Platform: "plan9"},
		{Status: "sideways"},
		{Limit: MaxPageSize + 1},
	} {
		if _, err := s.ListDevices(ctx, q); err == nil {
			t.Errorf("%+v: want an error", q)
		}
	}
}

func TestTouchDeviceLeavesInventoryAlone(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	prefix := "pt" + randID(t)[:8]
	seedFleet(t, s, prefix, 1)
	ok, err := s.TouchDevice(ctx, presence.Device{ID: prefix + "-0000", Connected: true, UptimeSeconds: 99})
	if err != nil || !ok {
		t.Fatalf("touch: %v %v", ok, err)
	}
	if ok, _ := s.TouchDevice(ctx, presence.Device{ID: "missing-" + prefix}); ok {
		t.Fatal("touching an unknown device must report it")
	}
	devs, err := s.LoadDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.ID == prefix+"-0000" {
			if len(d.Software) != 2 || d.UptimeSeconds != 99 || !d.Connected || d.Hostname == "" {
				t.Fatalf("after touch: %+v", d)
			}
			return
		}
	}
	t.Fatal("device not loaded")
}

func TestOpenAlertKeys(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id := "oak-" + randID(t)[:8]
	seedDevice(t, s, id)
	for i, status := range []string{"open", "acknowledged", "resolved"} {
		a := Alert{ID: fmt.Sprintf("%s-a%d", id, i), DeviceID: id, Hostname: "h", Kind: "sca",
			SourceID: fmt.Sprintf("p/c%d", i), Severity: "low", Title: "t", Status: status, Detail: []byte("{}")}
		if err := s.InsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := s.OpenAlertKeys(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !keys["sca\x00p/c0"] || !keys["sca\x00p/c1"] || keys["sca\x00p/c2"] || len(keys) != 2 {
		t.Fatalf("keys = %v", keys)
	}
}
