package control

import (
	"fmt"
	"testing"
	"time"

	"defendsec/internal/presence"
	"defendsec/internal/storepg"
)

func memFleet(n int, now time.Time) []presence.Device {
	platforms := []string{"linux", "windows", "darwin"}
	var out []presence.Device
	for i := 0; i < n; i++ {
		seen := now
		if i%4 == 0 {
			seen = now.Add(-time.Hour)
		}
		out = append(out, presence.Device{
			ID: fmt.Sprintf("d%04d", i), Hostname: fmt.Sprintf("Host-%04d", n-i), Platform: platforms[i%3],
			LastSeen: seen.Format(time.RFC3339), Isolated: i%10 == 0,
		})
	}
	return out
}

// The in-memory path must page exactly like the Postgres one: every device
// once, in hostname order, with the same totals.
func TestFilterDevicesPagesLikePostgres(t *testing.T) {
	now := time.Now()
	fleet := memFleet(237, now)
	seen := map[string]bool{}
	cursor, prev := "", ""
	for {
		page, err := FilterDevices(fleet, storepg.DeviceQuery{Limit: 50, Cursor: cursor, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		if page.Total != 237 {
			t.Fatalf("total %d", page.Total)
		}
		for _, d := range page.Devices {
			if seen[d.ID] || d.Hostname < prev {
				t.Fatalf("%s out of order or repeated", d.Hostname)
			}
			seen[d.ID], prev = true, d.Hostname
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	if len(seen) != 237 {
		t.Fatalf("saw %d", len(seen))
	}
	for q, want := range map[storepg.DeviceQuery]int{
		{Platform: "windows"}: 79,
		{Status: "offline"}:   60,
		{Status: "isolated"}:  24,
		{Q: "host-0001"}:      1,
	} {
		q.Now, q.Limit = now, 500
		p, err := FilterDevices(fleet, q)
		if err != nil || p.Total != want {
			t.Errorf("%+v: %d, want %d (%v)", q, p.Total, want, err)
		}
	}
	if _, err := FilterDevices(fleet, storepg.DeviceQuery{Cursor: "junk"}); err == nil {
		t.Error("bad cursor accepted")
	}
}

func TestCountDevices(t *testing.T) {
	now := time.Now()
	c := CountDevices(memFleet(40, now), now)
	if c.Total != 40 || c.Online != 30 || c.Isolated != 4 || c.ByPlatform["linux"] != 14 {
		t.Errorf("%+v", c)
	}
}
