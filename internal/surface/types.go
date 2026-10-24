// Package surface is the external surface scanner: what the internet sees of a
// client, learned without installing anything.
//
// It reads DNS, performs TLS handshakes, fetches MTA-STS policies over HTTPS
// and makes TCP connections, nothing else. It never logs in, never sends an
// exploit and never scans anything the operator did not declare and confirm as
// authorised (see Scanner.ScanAsset).
//
// The principle that runs through every check: a check that could not run
// (timeout, SERVFAIL, nothing to look at) is missing evidence. It is reported
// as "not assessed" with the reason, never as a pass and never as a failure.
package surface

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/idna"

	"defendsec/internal/controls"
)

// Kind is what an asset is.
type Kind string

const (
	KindDomain   Kind = "domain"   // a registrable or delegated domain: email auth, DNS, TLS on the apex
	KindHostname Kind = "hostname" // a public hostname: DNS hygiene and TLS
	KindIP       Kind = "ip"       // a public IP address: TCP ports
)

// Severity of a finding, from most to least urgent.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rank orders severities, higher is more urgent. Unknown values rank lowest.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

// Valid reports whether s is one of the five severities.
func (s Severity) Valid() bool {
	switch s {
	case SevCritical, SevHigh, SevMedium, SevLow, SevInfo:
		return true
	}
	return false
}

// Asset is something the operator declared. The scanner only ever checks assets
// with Authorised set.
type Asset struct {
	ID    int64  `json:"id"`
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	Label string `json:"label"`
	// DKIMSelectors are selectors the operator knows exist. They cannot be
	// enumerated from DNS, so they are checked in addition to the common ones.
	DKIMSelectors []string `json:"dkimSelectors"`
	// SharedHosting marks an IP that belongs to a shared-hosting or CDN edge:
	// port results then describe the provider, not the client.
	SharedHosting bool `json:"sharedHosting"`
	// MailHost marks an IP that is meant to run a mail server, so 25/110/143
	// are expected there.
	MailHost   bool `json:"mailHost"`
	Authorised bool `json:"authorised"`
}

// Check groups. A finding belongs to exactly one group; when a group ran
// successfully, open findings of that group that were not seen again are
// resolved. A group that could not run resolves nothing.
const (
	CheckMX        = "mx"
	CheckSPF       = "spf"
	CheckDMARC     = "dmarc"
	CheckDKIM      = "dkim"
	CheckMTASTS    = "mta-sts"
	CheckTLSRPT    = "tls-rpt"
	CheckDNSSEC    = "dnssec"
	CheckCAA       = "caa"
	CheckCNAME     = "cname"
	CheckTLSCert   = "tls-cert"
	CheckTLSLegacy = "tls-legacy"
	CheckPorts     = "ports"
)

// signalFor says which signal a check group evidences.
func signalFor(check string) controls.Signal {
	switch check {
	case CheckMX, CheckSPF, CheckDMARC, CheckDKIM, CheckMTASTS, CheckTLSRPT:
		return controls.SignalSurfaceEmail
	case CheckDNSSEC, CheckCAA, CheckCNAME:
		return controls.SignalSurfaceDNS
	case CheckTLSCert, CheckTLSLegacy:
		return controls.SignalSurfaceTLS
	case CheckPorts:
		return controls.SignalSurfacePorts
	}
	return ""
}

// Finding is one thing wrong (or noteworthy) about an asset, with the evidence
// that makes it reproducible and the words to fix it.
type Finding struct {
	// Check is the group; ID names the specific condition ("dmarc.p_none");
	// Subject distinguishes several findings of one ID on one asset (a DKIM
	// selector, a port, an MX host). (ID, Subject) is the finding's identity
	// on an asset.
	Check    string         `json:"check"`
	ID       string         `json:"id"`
	Subject  string         `json:"subject"`
	Severity Severity       `json:"severity"`
	Title    string         `json:"title"`
	Detail   string         `json:"detail"`
	Fix      string         `json:"fix"`
	Evidence map[string]any `json:"evidence"`
	Controls []string       `json:"controls"`
}

// Key identifies a finding on its asset.
func (f Finding) Key() string { return f.ID + "\x00" + f.Subject }

func newFinding(check, id, subject string, sev Severity, title, detail, fix string, evidence map[string]any) Finding {
	if evidence == nil {
		evidence = map[string]any{}
	}
	return Finding{
		Check: check, ID: id, Subject: subject, Severity: sev,
		Title: title, Detail: detail, Fix: fix, Evidence: evidence,
		Controls: controls.Tag(signalFor(check)),
	}
}

// CheckResult is what one check group saw.
type CheckResult struct {
	Check string `json:"check"`
	// Assessed is false when the check could not run or could not reach a
	// conclusion; Reason says why. Findings may still be present (a partial
	// result), but nothing is resolved on the strength of an unassessed check.
	Assessed bool   `json:"assessed"`
	Reason   string `json:"reason"`
	// Observed is the raw material: the record text, the certificate fields.
	// It is stored with every scan so a finding can be reproduced later.
	Observed map[string]any `json:"observed"`
	Findings []Finding      `json:"findings"`
}

func assessed(check string, observed map[string]any, findings ...Finding) CheckResult {
	if observed == nil {
		observed = map[string]any{}
	}
	return CheckResult{Check: check, Assessed: true, Observed: observed, Findings: findings}
}

func notAssessed(check, reason string, observed map[string]any) CheckResult {
	if observed == nil {
		observed = map[string]any{}
	}
	return CheckResult{Check: check, Assessed: false, Reason: reason, Observed: observed}
}

// NormaliseAsset validates a declared value and returns its canonical form:
// lower-case, no trailing dot, punycode for internationalised names, IPs in
// their shortest text form.
//
// Declared IPs must be unicast and routable from here. Loopback, link-local
// (which includes cloud metadata addresses), unspecified and multicast are
// refused outright: the scanner would only be probing itself or its own
// neighbourhood. Private (RFC 1918) addresses are allowed, because a lab or an
// internal-facing address is a legitimate thing to declare, but results for
// them describe the view from the scanner's own network, not the internet.
func NormaliseAsset(kind Kind, value string) (string, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("value is required")
	}
	switch kind {
	case KindIP:
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return "", fmt.Errorf("%q is not an IP address", value)
		}
		addr = addr.Unmap()
		if addr.Zone() != "" {
			return "", fmt.Errorf("an IP with a zone is not a public address")
		}
		if reason := nonScannable(addr); reason != "" {
			return "", fmt.Errorf("%s is %s and cannot be a scan target", addr, reason)
		}
		return addr.String(), nil
	case KindDomain, KindHostname:
		if strings.ContainsAny(v, " \t/:@?#*") {
			return "", fmt.Errorf("%q must be a bare DNS name (no scheme, port, path or wildcard)", value)
		}
		if _, err := netip.ParseAddr(v); err == nil {
			return "", fmt.Errorf("%q is an IP address; declare it as an ip asset", value)
		}
		v = strings.TrimSuffix(strings.ToLower(v), ".")
		ascii, err := idna.Lookup.ToASCII(v)
		if err != nil {
			return "", fmt.Errorf("%q is not a valid DNS name: %v", value, err)
		}
		v = ascii
		if len(v) > 253 || !strings.Contains(v, ".") {
			return "", fmt.Errorf("%q must be a fully qualified DNS name of at most 253 characters", value)
		}
		for _, label := range strings.Split(v, ".") {
			if label == "" || len(label) > 63 {
				return "", fmt.Errorf("%q has an empty or over-long label", value)
			}
			if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", fmt.Errorf("%q has a label starting or ending with a hyphen", value)
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
					return "", fmt.Errorf("%q contains %q, which is not valid in a DNS name", value, r)
				}
			}
		}
		return v, nil
	}
	return "", fmt.Errorf("kind must be domain, hostname or ip")
}

// NormaliseSelectors lower-cases, validates and de-duplicates DKIM selectors.
func NormaliseSelectors(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if len(s) > 63 {
			return nil, fmt.Errorf("DKIM selector %q is longer than 63 characters", raw)
		}
		for _, r := range s {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				return nil, fmt.Errorf("DKIM selector %q contains %q", raw, r)
			}
		}
		if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") {
			return nil, fmt.Errorf("DKIM selector %q has an empty label", raw)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// nonScannable names why an address may never be a target, or "".
func nonScannable(a netip.Addr) string {
	switch {
	case a.IsUnspecified():
		return "the unspecified address"
	case a.IsLoopback():
		return "a loopback address"
	case a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast():
		return "a link-local address"
	case a.IsMulticast():
		return "a multicast address"
	}
	return ""
}

// scannableIP reports whether a resolved address may be connected to.
func scannableIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return nonScannable(a.Unmap()) == ""
}
