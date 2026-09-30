package presence

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestFimPathSeverity(t *testing.T) {
	if FimPathSeverity("/etc/ssh/sshd_config") != "high" {
		t.Fatal("sshd_config should be high")
	}
	if FimPathSeverity("/etc/ssh/sshd_config.d/50-redhat.conf") != "high" {
		t.Fatal("sshd drop-in should be high")
	}
	if FimPathSeverity("/etc/hosts") != "medium" {
		t.Fatal("hosts should be medium")
	}
	if FimPathSeverity("/etc/crypto-policies/config") != "medium" {
		t.Fatal("crypto-policies should be medium")
	}
}

func TestApplyInventory_createModifyDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "presence.json")
	store := New(path)
	dev := Device{
		ID: "d1", Hostname: "h1", Platform: "linux",
		Fim: []FimFile{{Path: "/etc/hosts", SHA256: "aaa"}},
	}
	if err := store.Upsert(dev); err != nil {
		t.Fatal(err)
	}
	// First inventory establishes baseline + current; no prior FIM → no events.
	ev, err := store.ApplyInventory(dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 0 {
		t.Fatalf("expected 0 events on first inventory, got %d", len(ev))
	}

	dev.Fim = []FimFile{{Path: "/etc/hosts", SHA256: "bbb"}}
	ev, err = store.ApplyInventory(dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Action != "modified" {
		t.Fatalf("expected modified, got %#v", ev)
	}

	dev.Fim = append(dev.Fim, FimFile{Path: "/etc/passwd", SHA256: "ccc"})
	ev, err = store.ApplyInventory(dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Action != "created" || ev[0].Path != "/etc/passwd" {
		t.Fatalf("expected created passwd, got %#v", ev)
	}

	dev.Fim = []FimFile{{Path: "/etc/hosts", SHA256: "bbb"}}
	ev, err = store.ApplyInventory(dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Action != "deleted" || ev[0].Path != "/etc/passwd" {
		t.Fatalf("expected deleted passwd, got %#v", ev)
	}
}

func TestSetAgentVersionPersistsHelloMetadata(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "presence.json"))
	if err := store.SetAgentVersion("device-1", "host-1", "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	device, ok := store.Get("device-1")
	if !ok {
		t.Fatal("device was not created")
	}
	if device.AgentVersion != "v1.2.3" || device.Hostname != "host-1" || !device.Connected {
		t.Fatalf("unexpected device after hello: %#v", device)
	}

	if err := store.SetAgentVersion("device-1", "renamed-host", "v1.2.4"); err != nil {
		t.Fatal(err)
	}
	device, ok = store.Get("device-1")
	if !ok || device.AgentVersion != "v1.2.4" || device.Hostname != "renamed-host" {
		t.Fatalf("agent version was not updated: %#v", device)
	}
}

// The id index is a hint: devices added by every path, and a file reloaded
// from disk, must still be found.
func TestDeviceIndexStaysCorrect(t *testing.T) {
	f := New(filepath.Join(t.TempDir(), "p.json"))
	for i := 0; i < 50; i++ {
		if err := f.Upsert(Device{ID: fmt.Sprintf("d%d", i), Hostname: "h"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.ApplyInventory(Device{ID: "inv-only", Hostname: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := f.SetAgentVersion("ver-only", "y", "1.0"); err != nil {
		t.Fatal(err)
	}
	if err := f.Seed([]Device{{ID: "seeded", Hostname: "s"}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"d0", "d49", "inv-only", "ver-only", "seeded"} {
		if _, ok := f.Get(id); !ok {
			t.Errorf("%s not found", id)
		}
	}
	if err := f.Upsert(Device{ID: "d7", Hostname: "renamed"}); err != nil {
		t.Fatal(err)
	}
	if d, _ := f.Get("d7"); d.Hostname != "renamed" {
		t.Errorf("update went to the wrong device: %+v", d)
	}
	if n := len(f.List()); n != 53 {
		t.Errorf("%d devices, want 53", n)
	}
}
