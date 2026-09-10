package hostinv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectHasHostnameAndFIM(t *testing.T) {
	snap := Collect()
	if snap.Hostname == "" {
		t.Fatal("hostname")
	}
	if snap.PatchInventory == "" {
		t.Fatal("patch inventory status")
	}
	foundHosts := false
	for _, f := range snap.Fim {
		if f.Path == "/etc/hosts" && len(f.SHA256) == 64 {
			foundHosts = true
		}
	}
	if !foundHosts {
		t.Fatal("expected hashed /etc/hosts")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("keel"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := HashPathForTest(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.Size != 4 || len(f.SHA256) != 64 {
		t.Fatalf("%+v", f)
	}
}
