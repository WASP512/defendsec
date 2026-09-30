package agentcmd

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Isolation on Windows (roadmap 5.1). The commands and rules
// are built by pure functions so they are tested on every platform; only
// running them is platform-specific.

// controlPlane is where the agent talks to: host:port pairs for the HTTPS
// and gRPC endpoints, set at start. Isolation allows these and nothing else.
var controlPlane []string

// SetControlPlane records the endpoints isolation must keep reachable.
func SetControlPlane(endpoints ...string) {
	controlPlane = nil
	for _, e := range endpoints {
		if e = strings.TrimSpace(e); e != "" {
			controlPlane = append(controlPlane, e)
		}
	}
}

// endpoint is a resolved control-plane address.
type endpoint struct {
	IPs   []string
	Ports []int
}

// resolveControlPlane turns host:port pairs into addresses. Resolved at
// isolation time: once isolated, DNS is blocked, so rules must hold IPs.
func resolveControlPlane(lookup func(string) ([]string, error)) (endpoint, error) {
	if len(controlPlane) == 0 {
		return endpoint{}, fmt.Errorf("control-plane address unknown; refusing to isolate the host from its own server")
	}
	ips := map[string]bool{}
	ports := map[int]bool{}
	for _, hp := range controlPlane {
		host, portStr, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(hp, "https://"), "http://"))
		if err != nil {
			return endpoint{}, fmt.Errorf("control-plane address %q: %w", hp, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return endpoint{}, fmt.Errorf("control-plane port %q is invalid", portStr)
		}
		ports[port] = true
		if ip := net.ParseIP(host); ip != nil {
			ips[ip.String()] = true
			continue
		}
		addrs, err := lookup(host)
		if err != nil || len(addrs) == 0 {
			return endpoint{}, fmt.Errorf("resolve control plane %q: %v", host, err)
		}
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				ips[ip.String()] = true
			}
		}
	}
	var ep endpoint
	for ip := range ips {
		ep.IPs = append(ep.IPs, ip)
	}
	for p := range ports {
		ep.Ports = append(ep.Ports, p)
	}
	sort.Strings(ep.IPs)
	sort.Ints(ep.Ports)
	return ep, nil
}

func joinPorts(ports []int) string {
	s := make([]string, len(ports))
	for i, p := range ports {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

// Windows Firewall rule names, so release removes exactly what isolate added.
const (
	winRuleAllow = "DefendSec isolation - control plane"
	winRuleIn    = "DefendSec isolation - block inbound"
)

// windowsIsolateCommands are the netsh invocations that isolate a host. The
// firewall is stateful: an existing connection to the control plane
// survives, and replies to it are not inbound connections.
func windowsIsolateCommands(ep endpoint) [][]string {
	return [][]string{
		{"netsh", "advfirewall", "set", "allprofiles", "state", "on"},
		{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + winRuleAllow, "dir=out", "action=allow",
			"protocol=TCP", "remoteip=" + strings.Join(ep.IPs, ","), "remoteport=" + joinPorts(ep.Ports)},
		// Block rules win over allow rules, so this also overrides any
		// existing inbound exceptions such as RDP.
		{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + winRuleIn, "dir=in", "action=block", "protocol=any"},
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
	}
}

// windowsProfile is one firewall profile's settings before isolation.
type windowsProfile struct {
	Name   string `json:"name"`   // domainprofile, privateprofile, publicprofile
	State  string `json:"state"`  // on / off
	Policy string `json:"policy"` // e.g. blockinbound,allowoutbound
}

// parseWindowsProfiles reads `netsh advfirewall show allprofiles`.
func parseWindowsProfiles(out string) []windowsProfile {
	var profiles []windowsProfile
	var cur *windowsProfile
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "domain profile settings"):
			profiles = append(profiles, windowsProfile{Name: "domainprofile"})
		case strings.HasPrefix(lower, "private profile settings"):
			profiles = append(profiles, windowsProfile{Name: "privateprofile"})
		case strings.HasPrefix(lower, "public profile settings"):
			profiles = append(profiles, windowsProfile{Name: "publicprofile"})
		default:
			if len(profiles) == 0 {
				continue
			}
			cur = &profiles[len(profiles)-1]
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch strings.ToLower(f[0]) {
			case "state":
				cur.State = strings.ToLower(f[len(f)-1])
			case "firewall":
				if len(f) >= 3 && strings.ToLower(f[1]) == "policy" {
					cur.Policy = strings.ToLower(f[2])
				}
			}
		}
	}
	return profiles
}

// windowsReleaseCommands undo isolation, restoring each profile as it was.
func windowsReleaseCommands(saved []windowsProfile) [][]string {
	cmds := [][]string{
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + winRuleAllow},
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + winRuleIn},
	}
	if len(saved) == 0 {
		// Nothing recorded: the Windows default.
		return append(cmds, []string{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"})
	}
	for _, p := range saved {
		if p.Policy != "" {
			cmds = append(cmds, []string{"netsh", "advfirewall", "set", p.Name, "firewallpolicy", p.Policy})
		}
		if p.State == "on" || p.State == "off" {
			cmds = append(cmds, []string{"netsh", "advfirewall", "set", p.Name, "state", p.State})
		}
	}
	return cmds
}
