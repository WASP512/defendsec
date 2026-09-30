package sensor

import (
	"testing"
	"time"

	"defendsec/internal/events"
	"defendsec/internal/proclist"
)

func TestListSensorReportsNewAndReusedPIDs(t *testing.T) {
	table := []proclist.Proc{
		{PID: 4, PPID: 0, Start: 1, Image: "System", UID: -1},
		{PID: 100, PPID: 4, Start: 5, Image: `C:\Windows\explorer.exe`, UID: -1},
	}
	s := &ListSensor{DeviceID: "d", List: func() ([]proclist.Proc, error) { return table, nil }, CommandLine: func(int32) string { return "cmd.exe /c whoami" }}
	var got []*events.Event
	sink := func(e *events.Event) { got = append(got, e) }

	s.Scan(time.Now(), nil) // baseline
	table = append(table, proclist.Proc{PID: 200, PPID: 100, Start: 9, Image: `C:\Windows\System32\cmd.exe`, UID: -1})
	s.Scan(time.Now(), sink)
	if len(got) != 1 || got[0].PID != 200 {
		t.Fatalf("want one event for pid 200, got %d", len(got))
	}
	if got[0].String(events.FieldCommandLine) != "cmd.exe /c whoami" {
		t.Error("command line missing")
	}
	if got[0].String(events.FieldParentImage) != `C:\Windows\explorer.exe` || got[0].String("OriginalFileName") != "cmd.exe" {
		t.Errorf("fields: %v", got[0].Fields)
	}

	// Same pid, new start time: a different process.
	got = nil
	table[2].Start = 10
	s.Scan(time.Now(), sink)
	if len(got) != 1 {
		t.Fatalf("pid reuse must be reported, got %d", len(got))
	}
	got = nil
	s.Scan(time.Now(), sink)
	if len(got) != 0 {
		t.Fatalf("unchanged table must be quiet, got %d", len(got))
	}
}
