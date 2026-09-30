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

func TestPfRules(t *testing.T) {
	r := pfRules(endpoint{IPs: []string{"10.0.0.5", "fd00::5"}, Ports: []int{47262, 47263}})
	want := "pass quick on lo0 all\npass out quick proto tcp to { 10.0.0.5 fd00::5 } port { 47262 47263 } keep state\nblock drop quick all\n"
	if !strings.HasSuffix(r, want) {
		t.Errorf("rules:\n%s", r)
	}
	if tok := parsePfToken("No ALTQ support in kernel\npf enabled\nToken : 12345678901234\n"); tok != "12345678901234" {
		t.Errorf("token %q", tok)
	}
}
