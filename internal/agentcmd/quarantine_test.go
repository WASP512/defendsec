package agentcmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowedQuarantinePath(t *testing.T) {
	if !AllowedQuarantinePath("/etc/passwd") {
		t.Fatal("expected /etc/passwd allowed")
	}
	if !AllowedQuarantinePath("/tmp/defendsec-quarantine/evil.bin") {
		t.Fatal("expected staging path allowed")
	}
	if AllowedQuarantinePath("/etc/shadow") {
		t.Fatal("expected /etc/shadow rejected (not in default FIM list)")
	}
	if AllowedQuarantinePath("/var/tmp/random") {
		t.Fatal("expected /var/tmp/random rejected")
	}
}

func TestQuarantinePathMovesFile(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("linux-only")
	}
	stateDir := t.TempDir()
	staging := filepath.Join("/tmp/defendsec-quarantine", "test-"+filepath.Base(t.TempDir()))
	if err := os.MkdirAll(filepath.Dir(staging), 0o755); err != nil {
		t.Fatal(err)
	}
	src := staging + ".src"
	if err := os.WriteFile(src, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(src); _ = os.RemoveAll(filepath.Join(stateDir, "quarantine")) })

	dest, err := QuarantinePath(stateDir, src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("source should be moved")
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0 {
		t.Fatalf("expected mode 000, got %o", info.Mode().Perm())
	}
}
