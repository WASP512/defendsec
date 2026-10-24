package surface

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// PortSpec is one entry of the fixed port list.
type PortSpec struct {
	Port     int
	Service  string
	Severity Severity
	// Mail marks the mail ports: informational on a declared mail host,
	// low anywhere else.
	Mail bool
}

// DefaultPorts is the fixed list of risky TCP ports. Nothing outside it is
// ever connected to, and nothing is sent on a connection that succeeds: the
// connect itself is the whole measurement.
//
// 80 and 443 are deliberately absent, since a web server is expected to answer.
var DefaultPorts = []PortSpec{
	{21, "FTP", SevMedium, false},
	{22, "SSH", SevInfo, false},
	{23, "Telnet", SevHigh, false},
	{25, "SMTP", SevInfo, true},
	{110, "POP3", SevInfo, true},
	{143, "IMAP", SevInfo, true},
	{445, "SMB", SevCritical, false},
	{1433, "Microsoft SQL Server", SevHigh, false},
	{3306, "MySQL/MariaDB", SevHigh, false},
	{3389, "RDP", SevHigh, false},
	{5432, "PostgreSQL", SevHigh, false},
	{5900, "VNC", SevHigh, false},
	{6379, "Redis", SevHigh, false},
	{8080, "HTTP alternate", SevLow, false},
	{9200, "Elasticsearch", SevHigh, false},
	{27017, "MongoDB", SevHigh, false},
}

// edgeRanges are published address ranges of CDN edges, where a port answering
// says something about the provider and not about the client. Taken from
// https://www.cloudflare.com/ips-v4 and /ips-v6 (checked 2026-10-24). The list
// goes stale, so an operator can also mark any IP as shared hosting on the
// asset; this only saves them knowing Cloudflare's ranges.
var edgeRanges = map[string][]string{
	"Cloudflare": {
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	},
}

// edgeProvider names the CDN that owns ip, or "".
func edgeProvider(ip netip.Addr) string {
	for name, cidrs := range edgeRanges {
		for _, c := range cidrs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Contains(ip) {
				return name
			}
		}
	}
	return ""
}

type portResult struct {
	Port  int    `json:"port"`
	State string `json:"state"` // open, closed, filtered, error
	Error string `json:"error,omitempty"`
}

func (r *run) portsCheck() CheckResult {
	addr, err := netip.ParseAddr(r.a.Value)
	if err != nil {
		return notAssessed(CheckPorts, "not an IP address: "+r.a.Value, nil)
	}
	specs := r.s.Ports
	if specs == nil {
		specs = DefaultPorts
	}
	shared := r.a.SharedHosting
	edge := edgeProvider(addr)
	if edge != "" {
		shared = true
	}

	results := make([]portResult, len(specs))
	var wg sync.WaitGroup
	ip := net.IP(addr.AsSlice())
	for i, sp := range specs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = portResult{Port: sp.Port}
			c, err := r.dialIP(ip, strconv.Itoa(sp.Port))
			if err == nil {
				_ = c.Close()
				results[i].State = "open"
				return
			}
			switch classifyDial(err) {
			case netRefused:
				results[i].State = "closed"
			case netTimeout:
				results[i].State = "filtered"
			default:
				results[i].State, results[i].Error = "error", err.Error()
			}
		}()
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	counts := map[string]int{}
	var firstErr string
	for _, p := range results {
		counts[p.State]++
		if p.State == "error" && firstErr == "" {
			firstErr = p.Error
		}
	}
	obs := map[string]any{
		"ip": r.a.Value, "ports": results, "open": counts["open"], "closed": counts["closed"],
		"filtered": counts["filtered"], "errors": counts["error"],
		"sharedHosting": shared, "vantage": "the scanner's own network connection",
	}
	if edge != "" {
		obs["edgeProvider"] = edge
	}
	if counts["error"] == len(results) {
		return notAssessed(CheckPorts, "no connection could be attempted: "+firstErr, obs)
	}
	if counts["filtered"] == len(results) {
		return notAssessed(CheckPorts, "no port answered at all within the timeout: the address may be fully firewalled or the host may be down, and nothing here tells which", obs)
	}

	var fs []Finding
	for _, sp := range specs {
		var state string
		for _, p := range results {
			if p.Port == sp.Port {
				state = p.State
			}
		}
		if state != "open" {
			continue
		}
		sev := sp.Severity
		if sp.Mail {
			sev = SevLow
			if r.a.MailHost {
				sev = SevInfo
			}
		}
		subject := fmt.Sprintf("%d/tcp", sp.Port)
		detail := fmt.Sprintf("%s (%d/tcp) on %s accepted a TCP connection. That shows the service is reachable from the scanner's network connection; it does not show the service is vulnerable or misconfigured.", sp.Service, sp.Port, r.a.Value)
		fix := portFix(sp)
		if shared {
			provider := "a shared-hosting or CDN provider"
			if edge != "" {
				provider = edge
			}
			sev = SevInfo
			detail += " This address belongs to " + provider + " (shared hosting), so the open port describes the provider's edge servers rather than the client's own systems."
			fix = "Nothing to do for the client: this is the provider's service. If the client runs a service of its own behind this address, declare that service's own address instead."
		} else if sev.Rank() >= SevHigh.Rank() {
			detail += " Services like this are a common target for credential guessing and for exploits of unpatched versions."
		}
		fs = append(fs, newFinding(CheckPorts, "ports.open", subject, sev,
			fmt.Sprintf("%s (%d/tcp) is reachable", sp.Service, sp.Port), detail, fix,
			map[string]any{"ip": r.a.Value, "port": sp.Port, "service": sp.Service, "sharedHosting": shared}))
	}
	return assessed(CheckPorts, obs, fs...)
}

func portFix(sp PortSpec) string {
	switch sp.Port {
	case 445:
		return "Block 445/tcp from the internet at the firewall; SMB should never face the internet. If remote file access is needed, use a VPN."
	case 3389:
		return "Do not expose RDP directly. Put it behind a VPN or a remote-access gateway with multi-factor authentication, and block 3389/tcp at the firewall."
	case 23:
		return "Disable Telnet and use SSH. Block 23/tcp at the firewall."
	case 5900:
		return "Do not expose VNC to the internet. Tunnel it over SSH or a VPN and block 5900/tcp at the firewall."
	case 21:
		return "Replace FTP with SFTP or FTPS, or close the port if it is not used."
	case 22:
		return "Normal on a server. Make sure password logins are off in favour of keys, and restrict the source addresses if you can."
	case 25, 110, 143:
		return "Expected on a mail server. If this address is not meant to run mail, close the port."
	case 8080:
		return "Check what listens here. If it is an admin or development interface, restrict it to your own addresses."
	}
	if strings.Contains(sp.Service, "SQL") || sp.Port == 6379 || sp.Port == 9200 || sp.Port == 27017 || sp.Port == 3306 || sp.Port == 5432 {
		return "Databases and caches should not face the internet. Bind the service to a private address or restrict " + strconv.Itoa(sp.Port) + "/tcp to your application servers at the firewall."
	}
	return "Close the port at the firewall unless this exposure is intended."
}
