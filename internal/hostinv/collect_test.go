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

func TestNftFirewallActive(t *testing.T) {
	cases := []struct {
		name, json string
		active, ok bool
	}{
		{"empty ruleset", `{"nftables": [{"metainfo": {"version": "1.0.9"}}]}`, false, true},
		{"input policy drop", `{"nftables": [{"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "prio": 0, "policy": "drop"}}]}`, true, true},
		{"accept policy with a drop rule", `{"nftables": [
			{"chain": {"family": "inet", "table": "filter", "name": "input", "hook": "input", "policy": "accept"}},
			{"rule": {"family": "inet", "table": "filter", "chain": "input", "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 23}}, {"drop": null}]}}]}`, true, true},
		{"docker: forward only, input accepts", `{"nftables": [
			{"chain": {"family": "ip", "table": "filter", "name": "INPUT", "hook": "input", "policy": "accept"}},
			{"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "hook": "forward", "policy": "drop"}},
			{"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "expr": [{"drop": null}]}}]}`, false, true},
		{"unreadable", `Error: permission denied`, false, false},
	}
	for _, c := range cases {
		active, ok := NftFirewallActive([]byte(c.json))
		if active != c.active || ok != c.ok {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", c.name, active, ok, c.active, c.ok)
		}
	}
}

// Real `nft -j list ruleset` output (nftables 1.0.9), captured from loaded
// rulesets rather than written by hand.
func TestNftFirewallActiveOnRealOutput(t *testing.T) {
	for file, want := range map[string]bool{
		"testdata/nft-accept-with-reject.json":  true,
		"testdata/nft-input-drop.json":          true,
		"testdata/nft-docker-forward-only.json": false,
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := NftFirewallActive(raw); !ok || got != want {
			t.Errorf("%s: got %v (ok=%v), want %v", file, got, ok, want)
		}
	}
}
