package presence

import (
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
