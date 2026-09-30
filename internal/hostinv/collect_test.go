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
	if err := os.WriteFile(p, []byte("test"), 0o644); err != nil {
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

func TestParseZypperUpdates(t *testing.T) {
	out := `Loading repository data...
Reading installed packages...
S | Repository         | Name            | Current Version | Available Version | Arch
--+--------------------+-----------------+-----------------+-------------------+-------
v | repo-sle-update    | curl            | 8.6.0-1.1       | 8.6.0-2.1         | x86_64
v | repo-sle-update    | openssh-server  | 9.6p1-2.3       | 9.6p1-2.7         | x86_64
`
	ups := ParseZypperUpdates(out)
	if len(ups) != 2 || ups[0].Name != "curl" || ups[0].Current != "8.6.0-1.1" || ups[1].Available != "9.6p1-2.7" {
		t.Fatalf("%+v", ups)
	}
	if got := ParseZypperUpdates("No updates found.\n"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}
