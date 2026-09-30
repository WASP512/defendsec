package agentcmd

import (
	"fmt"
	"net"
	"strings"
)

// Linux isolation rules. Pure, so both backends are tested on any platform.
//
// # What isolation allows
//
// Loopback, the control plane (both directions, by address and port), DHCP
// so the host keeps its address, and IPv6 neighbour discovery so it can
// still reach an IPv6 control plane. Nothing else, in either direction.
//
// # What it deliberately does not allow
//
// Established connections in general. Accepting "ESTABLISHED,RELATED", as
// the first version did, kept every connection that existed at the moment
// of isolation — including the reverse shell that is the reason for
// isolating the host. Replies from the control plane are matched by its
// address and port instead, so only that conversation survives.

// nftTable is the table isolation owns. Nothing outside it is touched.
const nftTable = "defendsec_isolate"

func splitFamilies(ips []string) (v4, v6 []string) {
	for _, ip := range ips {
		if p := net.ParseIP(ip); p != nil && p.To4() == nil {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	return v4, v6
}

// nftRuleset replaces the isolation table in one transaction: the empty
// declaration makes the delete valid when the table does not exist yet.
func nftRuleset(ep endpoint) string {
	v4, v6 := splitFamilies(ep.IPs)
	ports := strings.Join(strings.Split(joinPorts(ep.Ports), ","), ", ")
	var out, in strings.Builder
	if len(v4) > 0 {
		fmt.Fprintf(&out, "\t\tip daddr { %s } tcp dport { %s } accept\n", strings.Join(v4, ", "), ports)
		fmt.Fprintf(&in, "\t\tip saddr { %s } tcp sport { %s } accept\n", strings.Join(v4, ", "), ports)
	}
	if len(v6) > 0 {
		fmt.Fprintf(&out, "\t\tip6 daddr { %s } tcp dport { %s } accept\n", strings.Join(v6, ", "), ports)
		fmt.Fprintf(&in, "\t\tip6 saddr { %s } tcp sport { %s } accept\n", strings.Join(v6, ", "), ports)
	}
	const ndp = "\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept\n"
	return fmt.Sprintf(`table inet %[1]s {}
delete table inet %[1]s
table inet %[1]s {
	chain output {
		type filter hook output priority -10; policy drop;
		oif "lo" accept
%[2]s		udp sport 68 udp dport 67 accept
		udp sport 546 udp dport 547 accept
%[4]s		reject with icmpx type admin-prohibited
	}
	chain input {
		type filter hook input priority -10; policy drop;
		iif "lo" accept
%[3]s		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
%[4]s	}
}
`, nftTable, out.String(), in.String(), ndp)
}

// iptables chain names; release removes exactly these.
const (
	iptOutChain = "DEFENDSEC_ISOLATE_OUT"
	iptInChain  = "DEFENDSEC_ISOLATE_IN"
)

// iptablesChainRules are the rules for one family's isolation chains, as
// argument lists for iptables (v6=false) or ip6tables (v6=true). The chains
// are created, flushed and hooked by the caller.
func iptablesChainRules(ep endpoint, v6 bool) [][]string {
	v4ips, v6ips := splitFamilies(ep.IPs)
	ips := v4ips
	reject := []string{"-j", "REJECT", "--reject-with", "icmp-admin-prohibited"}
	dhcpOut := []string{"--sport", "68", "--dport", "67"}
	dhcpIn := []string{"--sport", "67", "--dport", "68"}
	if v6 {
		ips = v6ips
		reject = []string{"-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"}
		dhcpOut = []string{"--sport", "546", "--dport", "547"}
		dhcpIn = []string{"--sport", "547", "--dport", "546"}
	}
	ports := joinPorts(ep.Ports)
	rules := [][]string{
		{"-A", iptOutChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", iptInChain, "-i", "lo", "-j", "ACCEPT"},
	}
	for _, ip := range ips {
		rules = append(rules,
			[]string{"-A", iptOutChain, "-p", "tcp", "-d", ip, "-m", "multiport", "--dports", ports, "-j", "ACCEPT"},
			[]string{"-A", iptInChain, "-p", "tcp", "-s", ip, "-m", "multiport", "--sports", ports, "-j", "ACCEPT"})
	}
	rules = append(rules,
		append([]string{"-A", iptOutChain, "-p", "udp"}, append(dhcpOut, "-j", "ACCEPT")...),
		append([]string{"-A", iptInChain, "-p", "udp"}, append(dhcpIn, "-j", "ACCEPT")...))
	if v6 {
		for _, t := range []string{"neighbour-solicitation", "neighbour-advertisement", "router-solicitation", "router-advertisement"} {
			rules = append(rules,
				[]string{"-A", iptOutChain, "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "ACCEPT"},
				[]string{"-A", iptInChain, "-p", "ipv6-icmp", "--icmpv6-type", t, "-j", "ACCEPT"})
		}
	}
	rules = append(rules,
		append([]string{"-A", iptOutChain}, reject...),
		[]string{"-A", iptInChain, "-j", "DROP"})
	return rules
}
