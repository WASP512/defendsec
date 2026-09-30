package agentcmd

import (
	"errors"
	"strings"
	"testing"
)

func TestResolveControlPlane(t *testing.T) {
	SetControlPlane("https://ds.example:47262", "ds.example:47263", "10.0.0.9:47263")
	defer SetControlPlane()
	ep, err := resolveControlPlane(func(h string) ([]string, error) {
		if h != "ds.example" {
			t.Fatalf("looked up %q", h)
		}
		return []string{"10.0.0.5", "fd00::5"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ep.IPs, " ") != "10.0.0.5 10.0.0.9 fd00::5" || joinPorts(ep.Ports) != "47262,47263" {
		t.Errorf("%+v", ep)
	}
	if _, err := resolveControlPlane(func(string) ([]string, error) { return nil, errors.New("nxdomain") }); err == nil {
		t.Error("an unresolvable server must refuse isolation, not isolate the host from it")
	}
	SetControlPlane()
	if _, err := resolveControlPlane(nil); err == nil {
		t.Error("unknown control plane must refuse")
	}
}

func TestWindowsIsolateAndRestore(t *testing.T) {
	cmds := windowsIsolateCommands(endpoint{IPs: []string{"10.0.0.5"}, Ports: []int{47262, 47263}})
	joined := make([]string, len(cmds))
	for i, c := range cmds {
		joined[i] = strings.Join(c, " ")
	}
	all := strings.Join(joined, "\n")
	for _, want := range []string{
		"remoteip=10.0.0.5 remoteport=47262,47263",
		"dir=in action=block",
		"firewallpolicy blockinbound,blockoutbound",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	// The allow rule must exist before outbound is blocked, or the agent
	// cuts itself off between the two commands.
	if !strings.Contains(joined[1], "action=allow") || !strings.Contains(joined[3], "blockoutbound") {
		t.Error("allow rule must precede the outbound block")
	}

	shown := `
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,BlockOutbound
Ok.
`
	saved := parseWindowsProfiles(shown)
	if len(saved) != 3 || saved[1].State != "off" || saved[2].Policy != "blockinbound,blockoutbound" {
		t.Fatalf("%+v", saved)
	}
	rel := windowsReleaseCommands(saved)
	var rs []string
	for _, c := range rel {
		rs = append(rs, strings.Join(c, " "))
	}
	r := strings.Join(rs, "\n")
	for _, want := range []string{
		"delete rule name=" + winRuleAllow,
		"set privateprofile state off", // a firewall that was off is put back off
		"set publicprofile firewallpolicy blockinbound,blockoutbound",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q in\n%s", want, r)
		}
	}
}

func TestNftRulesetAllowsOnlyTheControlPlane(t *testing.T) {
	r := nftRuleset(endpoint{IPs: []string{"10.0.0.5", "fd00::5"}, Ports: []int{47262, 47263}})
	for _, want := range []string{
		"table inet defendsec_isolate {}\ndelete table inet defendsec_isolate\n", // atomic replace
		"policy drop;",
		"ip daddr { 10.0.0.5 } tcp dport { 47262, 47263 } accept",
		"ip saddr { 10.0.0.5 } tcp sport { 47262, 47263 } accept",
		"ip6 daddr { fd00::5 } tcp dport { 47262, 47263 } accept",
		"chain input",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q in\n%s", want, r)
		}
	}
	// Established sessions in general must not survive: that is the
	// attacker's shell.
	if strings.Contains(r, "ct state") {
		t.Errorf("ruleset accepts tracked connections:\n%s", r)
	}
	if strings.Contains(nftRuleset(endpoint{IPs: []string{"10.0.0.5"}, Ports: []int{47263}}), "ip6 daddr") {
		t.Error("no IPv6 control plane, no IPv6 accept rule")
	}
}

func TestIptablesRulesPerFamily(t *testing.T) {
	ep := endpoint{IPs: []string{"10.0.0.5", "fd00::5"}, Ports: []int{47262, 47263}}
	join := func(rs [][]string) string {
		var out []string
		for _, r := range rs {
			out = append(out, strings.Join(r, " "))
		}
		return strings.Join(out, "\n")
	}
	v4, v6 := join(iptablesChainRules(ep, false)), join(iptablesChainRules(ep, true))
	if !strings.Contains(v4, "-d 10.0.0.5 -m multiport --dports 47262,47263 -j ACCEPT") || strings.Contains(v4, "fd00::5") {
		t.Errorf("v4:\n%s", v4)
	}
	if !strings.Contains(v6, "-d fd00::5") || strings.Contains(v6, "10.0.0.5") || !strings.Contains(v6, "icmp6-adm-prohibited") {
		t.Errorf("v6:\n%s", v6)
	}
	if strings.Contains(v4+v6, "conntrack") {
		t.Error("iptables rules accept tracked connections")
	}
	if !strings.HasSuffix(v4, iptInChain+" -j DROP") {
		t.Error("inbound must end in DROP")
	}
}
