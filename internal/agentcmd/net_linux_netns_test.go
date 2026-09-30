//go:build linux

package agentcmd

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestIsolationWithRealTraffic applies isolation to a real network
// namespace and checks what actually gets through. It runs only inside the
// namespace scripts/test-isolation-netns.sh builds, which provides a peer at
// DEFENDSEC_NETNS_PEER4 / _PEER6 serving the "control plane" on 47263, an
// unrelated service on 8080, and connecting back to this host's port 9000.
func TestIsolationWithRealTraffic(t *testing.T) {
	peer4, peer6 := os.Getenv("DEFENDSEC_NETNS_PEER4"), os.Getenv("DEFENDSEC_NETNS_PEER6")
	if peer4 == "" {
		t.Skip("run by scripts/test-isolation-netns.sh")
	}
	if peer6 == "" {
		t.Log("no IPv6 in this kernel: IPv6 rules are loaded but only IPv4 traffic is tested")
	}
	for _, backend := range []string{"nft", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			forceIptables = backend == "iptables"
			defer func() { forceIptables = false }()
			isolationScenario(t, peer4, peer6, backend)
		})
	}
}

func dial(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 700*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(700 * time.Millisecond))
	if _, err := c.Write([]byte("ping\n")); err != nil {
		return err
	}
	_, err = bufio.NewReader(c).ReadString('\n')
	return err
}

func isolationScenario(t *testing.T, peer4, peer6, backend string) {
	cp := []string{net.JoinHostPort(peer4, "47263")}
	other := []string{net.JoinHostPort(peer4, "8080")}
	if peer6 != "" {
		cp = append(cp, net.JoinHostPort(peer6, "47263"))
		other = append(other, net.JoinHostPort(peer6, "8080"))
	}
	other4 := other[0]

	// Inbound: count connections the peer makes to us.
	var accepted atomic.Int64
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()

	for _, a := range append(append([]string{}, cp...), other...) {
		if err := dial(a); err != nil {
			t.Fatalf("before isolation %s: %v", a, err)
		}
	}
	// A session that exists before isolation: the attacker's shell.
	shell, err := net.Dial("tcp", other4)
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()
	time.Sleep(600 * time.Millisecond)
	if accepted.Load() == 0 {
		t.Fatal("peer is not connecting in; the harness is not running")
	}

	dir := t.TempDir()
	// Always an IPv6 control plane too, so the IPv6 rules are generated and
	// loaded even where the kernel cannot carry IPv6 traffic.
	SetControlPlane(cp[0], "[fd77::2]:47263")
	defer SetControlPlane()
	if err := applyNetIsolate(dir); err != nil {
		t.Fatalf("isolate: %v", err)
	}
	if activeBackend != backend {
		t.Fatalf("backend = %q, want %q", activeBackend, backend)
	}

	for _, a := range cp {
		if err := dial(a); err != nil {
			t.Errorf("isolated: control plane %s must stay reachable (new connection): %v", a, err)
		}
	}
	for _, a := range other {
		if err := dial(a); err == nil {
			t.Errorf("isolated: %s must be unreachable", a)
		}
	}
	_ = shell.SetDeadline(time.Now().Add(time.Second))
	if _, err := shell.Write([]byte("id\n")); err == nil {
		if _, err := bufio.NewReader(shell).ReadString('\n'); err == nil {
			t.Error("isolated: a connection open before isolation still works")
		}
	}
	time.Sleep(500 * time.Millisecond)
	before := accepted.Load()
	time.Sleep(1500 * time.Millisecond)
	if n := accepted.Load() - before; n != 0 {
		t.Errorf("isolated: %d inbound connections accepted", n)
	}

	// Re-applying (agent restart, or reboot re-apply) must not stack rules.
	if err := applyNetIsolate(dir); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if backend == "iptables" {
		out, _ := runCmd([]string{"iptables", "-S", "OUTPUT"})
		if strings.Count(out, iptOutChain) != 1 {
			t.Errorf("re-apply stacked jumps:\n%s", out)
		}
	}

	// A reboot drops Linux firewall rules. The agent must restore isolation
	// when it starts, rather than leave the host open while the console
	// still reports it isolated.
	if err := SaveState(dir, State{Isolated: true, Mode: "net"}); err != nil {
		t.Fatal(err)
	}
	_, _ = runCmd([]string{"nft", "delete", "table", "inet", nftTable})
	_ = iptablesRelease()
	if err := dial(other[0]); err != nil {
		t.Fatalf("simulated reboot did not clear the rules: %v", err)
	}
	if st, reapplied, err := ReapplyIsolation(dir); err != nil || !reapplied || st.Mode != "net" {
		t.Fatalf("re-apply at start: %+v %v %v", st, reapplied, err)
	}
	if err := dial(other[0]); err == nil {
		t.Error("after re-apply at start, the host is not isolated")
	}
	if err := dial(cp[0]); err != nil {
		t.Errorf("after re-apply at start, the control plane is unreachable: %v", err)
	}

	if err := clearNetIsolate(dir); err != nil {
		t.Fatalf("release: %v", err)
	}
	for _, a := range other {
		if err := dial(a); err != nil {
			t.Errorf("released: %s: %v", a, err)
		}
	}
	time.Sleep(800 * time.Millisecond)
	before = accepted.Load()
	time.Sleep(800 * time.Millisecond)
	if accepted.Load() == before {
		t.Error("released: inbound connections did not resume")
	}
	// Nothing of ours is left behind.
	if out, _ := runCmd([]string{"nft", "list", "tables"}); strings.Contains(out, nftTable) {
		t.Error("nft table left after release")
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		out, _ := runCmd([]string{bin, "-S"})
		if strings.Contains(out, "DEFENDSEC") {
			t.Errorf("%s rules left after release:\n%s", bin, out)
		}
	}
}
