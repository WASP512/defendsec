package storepg

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"defendsec/internal/presence"
)

// The Windows edition survives the database: stored on first sight, kept when a
// later report does not carry one (an older agent, a heartbeat), replaced when
// a newer one does, and exported to the console.
func TestDeviceEditionIsStoredKeptAndExported(t *testing.T) {
	s, _ := scratchStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	d := presence.Device{ID: "win-1", Hostname: "win-1", Platform: "windows", OSName: "Microsoft Windows Server 2016 Standard",
		OSVersion: "10.0.14393", OSEdition: "ServerStandard", LastSeen: now}
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	load := func() presence.Device {
		t.Helper()
		all, err := s.LoadDevices(ctx)
		if err != nil || len(all) != 1 {
			t.Fatalf("LoadDevices = %v, %v", all, err)
		}
		return all[0]
	}
	if got := load().OSEdition; got != "ServerStandard" {
		t.Fatalf("edition = %q", got)
	}
	d.OSEdition = "" // a report from an agent that does not send it
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got := load().OSEdition; got != "ServerStandard" {
		t.Errorf("an empty edition erased the stored one: %q", got)
	}
	d.OSEdition = "ServerDatacenter"
	if err := s.UpsertDevice(ctx, d); err != nil {
		t.Fatal(err)
	}
	if got := load().OSEdition; got != "ServerDatacenter" {
		t.Errorf("a new edition was not stored: %q", got)
	}
	// agents are exported to the console only when they have a certificate
	if err := s.UpsertDevice(ctx, presence.Device{ID: "win-1", Hostname: "win-1", Platform: "windows", OSEdition: "ServerDatacenter",
		CertFingerprint: "ab", Transport: "mtls-grpc", LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	raw, err := s.ExportAgentsJSON(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Devices []struct {
			OSEdition string `json:"osEdition"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Devices) != 1 || doc.Devices[0].OSEdition != "ServerDatacenter" {
		t.Errorf("export does not carry the edition: %s", raw)
	}
}
