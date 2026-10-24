package surface

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// --- shared helpers --------------------------------------------------------

// parseTags reads "k=v; k=v" records (DMARC, DKIM, TLSRPT, STS). Keys are
// lower-cased, the first occurrence wins, and unknown keys are kept: the
// DMARCbis revision adds and changes tags, and a scanner that errors on a tag
// it does not know would be wrong the day a domain adopts it.
func parseTags(rec string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if _, dup := out[k]; !dup {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// recordsWithVersion returns the TXT strings that start with a version tag
// (case-insensitive), e.g. "v=DMARC1".
func recordsWithVersion(txts []string, version string) []string {
	var out []string
	want := strings.ToLower(version)
	for _, t := range txts {
		l := strings.ToLower(strings.TrimSpace(t))
		if !strings.HasPrefix(l, want) {
			continue
		}
		rest := l[len(want):]
		if rest == "" || rest[0] == ';' || rest[0] == ' ' || rest[0] == '\t' {
			out = append(out, strings.TrimSpace(t))
		}
	}
	return out
}

func orgDomain(name string) string {
	if o, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil {
		return o
	}
	return name
}

func quote(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = strconv.Quote(s)
	}
	return strings.Join(q, ", ")
}

// providerFromMX is a hint only: it picks the words in fix-it text and which
// DKIM selectors are worth trying. It is never a finding.
func providerFromMX(hosts []string) string {
	for _, h := range hosts {
		switch {
		case strings.HasSuffix(h, ".google.com") || strings.HasSuffix(h, ".googlemail.com") || h == "aspmx.l.google.com":
			return "google"
		case strings.HasSuffix(h, ".mail.protection.outlook.com"):
			return "microsoft365"
		case strings.HasSuffix(h, ".cf-emailsecurity.net") || strings.HasSuffix(h, ".mx.cloudflare.net"):
			return "cloudflare"
		}
	}
	return "other"
}

func providerNote(provider string) string {
	switch provider {
	case "google":
		return " The MX records point at Google Workspace: generate the key in the Admin console (Apps, Google Workspace, Gmail, Authenticate email), publish the TXT record it shows, then start authentication."
	case "microsoft365":
		return " The MX records point at Microsoft 365: enable DKIM for the domain in the Microsoft Defender portal (email authentication settings) and publish the two CNAME records it shows."
	case "cloudflare":
		return " The MX records point at Cloudflare's inbound mail filtering, which does not sign your outgoing mail. Mail you send needs its own DKIM key and SPF include from whichever service sends it (Google Workspace, Microsoft 365, a newsletter tool)."
	}
	return ""
}

func (r *run) noMail() bool { return r.mxKnown && !r.hasMail }

// --- MX ---------------------------------------------------------------------

func (r *run) mxCheck() CheckResult {
	d := r.a.Value
	a := r.lookup(Query{Name: d, Type: dns.TypeMX})
	if a.Status == StatusFail {
		return notAssessed(CheckMX, "MX lookup failed: "+a.Reason(), nil)
	}
	r.mxKnown = true
	type mxRec struct {
		pref uint16
		host string
	}
	var recs []mxRec
	for _, rr := range a.RRs {
		if m, ok := rr.(*dns.MX); ok {
			recs = append(recs, mxRec{m.Preference, trimDot(m.Mx)})
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].pref < recs[j].pref })
	var lines []string
	nullMX := false
	for _, m := range recs {
		lines = append(lines, fmt.Sprintf("%d %s", m.pref, m.host))
		if m.host == "" {
			nullMX = true
		} else {
			r.mx = append(r.mx, m.host)
		}
	}
	r.hasMail = len(r.mx) > 0 && !nullMX
	r.provider = providerFromMX(r.mx)
	obs := map[string]any{"mx": lines, "providerHint": r.provider, "nullMX": nullMX}

	var fs []Finding
	switch {
	case nullMX:
		fs = append(fs, newFinding(CheckMX, "mx.null", d, SevInfo,
			"Domain declares that it receives no mail (null MX)",
			d+" publishes a null MX (RFC 7505), so it is not meant to receive email.",
			"Nothing to fix if this domain should not receive mail. Make sure it also publishes SPF \"v=spf1 -all\" and a DMARC record with p=reject so it cannot be spoofed.", obs))
	case len(recs) == 0:
		fs = append(fs, newFinding(CheckMX, "mx.none", d, SevInfo,
			"No MX records",
			d+" has no MX records. Senders would fall back to its address record. If the domain does not receive mail this is fine.",
			"If the domain should not receive mail, publish a null MX (\"0 .\") so senders do not try. If it should, add MX records.", obs))
	}
	checked := 0
	for _, host := range r.mx {
		if checked >= 10 {
			break
		}
		checked++
		cn := r.lookup(Query{Name: host, Type: dns.TypeCNAME})
		if cn.Status == StatusOK {
			fs = append(fs, newFinding(CheckMX, "mx.cname", host, SevLow,
				"MX host is a CNAME",
				"The MX host "+host+" is an alias. RFC 2181 forbids an MX target that is a CNAME, and some senders refuse to deliver.",
				"Point the MX record at the host's real name, or replace the CNAME with address records.",
				map[string]any{"mxHost": host, "cname": trimDot(cn.CNAMEs[0].Target)}))
		}
		ips, st := r.addrs(host)
		if len(ips) == 0 && st.Absent() {
			fs = append(fs, newFinding(CheckMX, "mx.no_address", host, SevMedium,
				"MX host has no address records",
				"The MX host "+host+" does not resolve to any IP address, so mail sent through it cannot be delivered.",
				"Fix the MX record to name a host that exists, or publish A/AAAA records for "+host+".",
				map[string]any{"mxHost": host, "lookup": st.String()}))
		}
	}
	return assessed(CheckMX, obs, fs...)
}

// --- DMARC -----------------------------------------------------------------

type dmarcInfo struct {
	known    bool // the DMARC check completed
	enforced bool // effective policy is quarantine or reject
}

var dmarcRank = map[string]int{"none": 0, "quarantine": 1, "reject": 2}

func (r *run) dmarcCheck() CheckResult {
	d := r.a.Value
	source := d
	txts, a := r.txt("_dmarc." + d)
	if a.Status == StatusFail {
		return notAssessed(CheckDMARC, "DMARC lookup failed: "+a.Reason(), nil)
	}
	recs := recordsWithVersion(txts, "v=DMARC1")
	fallback := false
	if len(recs) == 0 {
		if org := orgDomain(d); org != d {
			// RFC 7489 6.6.3: no record at the name, so the organisational
			// domain's record applies.
			t2, a2 := r.txt("_dmarc." + org)
			if a2.Status == StatusFail {
				return notAssessed(CheckDMARC, "DMARC lookup at the organisational domain failed: "+a2.Reason(), nil)
			}
			if rs := recordsWithVersion(t2, "v=DMARC1"); len(rs) > 0 {
				recs, source, fallback = rs, org, true
			}
		}
	}
	obs := map[string]any{"name": "_dmarc." + source, "records": txts, "source": source, "organisationalFallback": fallback}
	if len(recs) == 0 {
		r.dmarc = dmarcInfo{known: true}
		return assessed(CheckDMARC, obs, newFinding(CheckDMARC, "dmarc.missing", d, SevHigh,
			"No DMARC record",
			"No DMARC record was found at _dmarc."+d+(map[bool]string{true: " or at its organisational domain", false: ""}[d != orgDomain(d)])+". Without one, receivers have no instruction to reject mail that spoofs this domain, and the domain's owner gets no reports of it happening.",
			"Publish a TXT record at _dmarc."+d+" such as \"v=DMARC1; p=none; rua=mailto:dmarc-reports@"+d+"\". Read the aggregate reports for a few weeks, fix any legitimate sender that fails, then move to p=quarantine and finally p=reject."+providerNote(r.provider),
			obs))
	}
	if len(recs) > 1 {
		r.dmarc = dmarcInfo{known: true}
		obs["records"] = recs
		return assessed(CheckDMARC, obs, newFinding(CheckDMARC, "dmarc.multiple", d, SevHigh,
			"More than one DMARC record",
			fmt.Sprintf("%d DMARC records were found at _dmarc.%s. RFC 7489 says receivers then ignore DMARC altogether, so the domain is effectively unprotected.", len(recs), source),
			"Delete all but one DMARC TXT record at _dmarc."+source+".", obs))
	}
	rec := recs[0]
	tags := parseTags(rec)
	obs["record"] = rec
	obs["tags"] = tags
	var fs []Finding

	p := strings.ToLower(tags["p"])
	_, rua := tags["rua"]
	if _, ok := dmarcRank[p]; !ok {
		if p == "" && rua {
			// RFC 7489 6.6.3: a record with no valid p= but with rua= is
			// treated as p=none.
			p = "none"
		} else {
			r.dmarc = dmarcInfo{known: true}
			fs = append(fs, newFinding(CheckDMARC, "dmarc.invalid", d, SevHigh,
				"DMARC record is invalid",
				"The record at _dmarc."+source+" has no valid p= tag ("+strconv.Quote(tags["p"])+"), so receivers discard it and the domain is unprotected.",
				"Rewrite the record as \"v=DMARC1; p=none; rua=mailto:...\" and tighten the policy from there.", obs))
			return assessed(CheckDMARC, obs, fs...)
		}
	}
	effective := p
	if fallback { // a subdomain with no record of its own is governed by sp, else p
		if sp, ok := tags["sp"]; ok {
			if _, valid := dmarcRank[strings.ToLower(sp)]; valid {
				effective = strings.ToLower(sp)
			}
		}
	}
	obs["effectivePolicy"] = effective
	r.dmarc = dmarcInfo{known: true, enforced: dmarcRank[effective] >= 1}

	if effective == "none" {
		fs = append(fs, newFinding(CheckDMARC, "dmarc.p_none", d, SevMedium,
			"DMARC is monitoring only (p=none)",
			"The DMARC policy"+map[bool]string{true: " that applies to " + d, false: ""}[fallback]+" is p=none: receivers report failures but still deliver mail that spoofs the domain.",
			"Once the aggregate reports show your legitimate senders pass, change the policy to p=quarantine and then p=reject.", obs))
	}
	if !fallback {
		if sp := strings.ToLower(tags["sp"]); sp != "" {
			if rk, ok := dmarcRank[sp]; ok && rk < dmarcRank[p] {
				fs = append(fs, newFinding(CheckDMARC, "dmarc.sp_weaker", d, SevLow,
					"DMARC subdomain policy is weaker than the domain policy",
					"p="+p+" but sp="+sp+": mail that spoofs a subdomain of "+d+" is treated more leniently than mail spoofing "+d+" itself.",
					"Remove the sp= tag so subdomains inherit p=, or set it to the same value.", obs))
			}
		}
	}
	if pct, ok := tags["pct"]; ok && dmarcRank[effective] >= 1 {
		if n, err := strconv.Atoi(pct); err == nil && n >= 0 && n < 100 {
			fs = append(fs, newFinding(CheckDMARC, "dmarc.pct", d, SevLow,
				"DMARC policy applies to only part of the mail",
				fmt.Sprintf("pct=%d, so the %s policy is applied to %d%% of failing messages and the rest are treated as p=none.", n, effective, n),
				"Raise pct to 100 (or remove it) once you are confident legitimate mail passes.", obs))
		}
	}
	if !rua {
		fs = append(fs, newFinding(CheckDMARC, "dmarc.no_rua", d, SevLow,
			"DMARC record has no aggregate report address (rua)",
			"Without rua= nobody receives the reports that show who is sending mail as this domain, so the policy cannot be tightened with confidence.",
			"Add rua=mailto:<mailbox or reporting service> to the record.", obs))
	}
	return assessed(CheckDMARC, obs, fs...)
}

// --- SPF -------------------------------------------------------------------

type spfTerm struct {
	qual byte   // '+', '-', '~', '?' (0 for modifiers)
	mech string // lower-case mechanism or modifier name
	arg  string // domain-spec, address or modifier value
	raw  string
}

var spfMechs = map[string]bool{"all": true, "include": true, "a": true, "mx": true, "ptr": true, "ip4": true, "ip6": true, "exists": true}

// parseSPF splits one v=spf1 record into terms and reports syntax errors.
func parseSPF(rec string) (terms []spfTerm, problems []string) {
	fields := strings.Fields(rec)
	seenMod := map[string]bool{}
	for _, f := range fields[1:] {
		// A modifier is name=value where name is alphanumeric; a mechanism
		// such as ip4:1.2.3.4 or a/24 never has '=' before ':' or '/'.
		if eq := strings.IndexByte(f, '='); eq > 0 && !strings.ContainsAny(f[:eq], ":/") && !strings.ContainsAny(f[:1], "+-~?") {
			name := strings.ToLower(f[:eq])
			val := f[eq+1:]
			if (name == "redirect" || name == "exp") && (val == "" || seenMod[name]) {
				problems = append(problems, f+": "+name+" needs exactly one value")
			}
			seenMod[name] = true
			terms = append(terms, spfTerm{mech: name, arg: val, raw: f})
			continue
		}
		t := spfTerm{qual: '+', raw: f}
		body := f
		if strings.ContainsAny(body[:1], "+-~?") {
			t.qual = body[0]
			body = body[1:]
		}
		name, arg := body, ""
		if i := strings.IndexAny(body, ":/"); i >= 0 {
			name = body[:i]
			arg = body[i:]
			if arg[0] == ':' {
				arg = arg[1:]
			}
		}
		t.mech = strings.ToLower(name)
		t.arg = arg
		if !spfMechs[t.mech] {
			problems = append(problems, f+": unknown mechanism "+strconv.Quote(name))
			continue
		}
		switch t.mech {
		case "all":
			if arg != "" {
				problems = append(problems, f+": all takes no argument")
			}
		case "include", "exists":
			if arg == "" {
				problems = append(problems, f+": "+t.mech+" needs a domain")
			}
		case "ip4":
			if p, err := parseCIDROrAddr(arg); err != nil || !p.Addr().Is4() {
				problems = append(problems, f+": not a valid IPv4 address or network")
			}
		case "ip6":
			if p, err := parseCIDROrAddr(arg); err != nil || !p.Addr().Is6() {
				problems = append(problems, f+": not a valid IPv6 address or network")
			}
		}
		terms = append(terms, t)
	}
	return terms, problems
}

func parseCIDROrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// domainSpec reads the target of a, mx, include, exists or redirect: the part
// of arg before any "/" prefix length, or the default domain if there is none.
func domainSpec(arg, def string) string {
	if i := strings.IndexByte(arg, '/'); i >= 0 {
		arg = arg[:i]
	}
	if arg == "" {
		return def
	}
	return strings.ToLower(strings.TrimSuffix(arg, "."))
}

type spfState struct {
	lookups    int
	voids      int
	voidNames  []string
	seen       map[string]bool
	chain      []string // domains whose records were read, in order
	problems   []string // syntax problems, "domain: term: reason"
	multiple   []string
	missing    []string // include/redirect targets with no SPF record
	loops      []string
	partial    []string // lookups that failed: the count may be low
	macros     int
	capped     bool
	ptr        bool
	topRecord  string
	topRecords []string
}

const spfLookupCap = 40

type spfEnd int

const (
	spfOK spfEnd = iota
	spfNone
	spfBroken // multiple records, loop, depth
	spfFailed // lookup failed
)

// spfWalk evaluates one domain's SPF record the way RFC 7208 counts the work:
// every include, a, mx, ptr, exists and (when evaluated) redirect is one
// DNS-querying term, recursively. It returns the qualifier of the record's
// final "all" (following redirect), or 0.
func (r *run) spfWalk(domain string, depth int, st *spfState) (byte, spfEnd) {
	if depth > 10 {
		st.problems = append(st.problems, domain+": include nesting deeper than 10")
		return 0, spfBroken
	}
	if st.seen[domain] {
		st.loops = append(st.loops, domain)
		return 0, spfBroken
	}
	st.seen[domain] = true
	txts, a := r.txt(domain)
	if a.Status == StatusFail {
		st.partial = append(st.partial, domain+": "+a.Reason())
		return 0, spfFailed
	}
	recs := recordsWithVersion(txts, "v=spf1")
	if depth == 0 {
		st.topRecords = recs
	}
	switch {
	case len(recs) == 0:
		return 0, spfNone
	case len(recs) > 1:
		st.multiple = append(st.multiple, domain)
		return 0, spfBroken
	}
	if depth == 0 {
		st.topRecord = recs[0]
	}
	st.chain = append(st.chain, domain)
	terms, problems := parseSPF(recs[0])
	for _, p := range problems {
		st.problems = append(st.problems, domain+": "+p)
	}
	var allQual byte
	hasAll := false
	var redirect string
	count := func() bool {
		st.lookups++
		if st.lookups > spfLookupCap {
			st.capped = true
			return false
		}
		return true
	}
	void := func(name string) {
		st.voids++
		st.voidNames = append(st.voidNames, name)
	}
	for _, t := range terms {
		switch t.mech {
		case "all":
			if !hasAll {
				allQual, hasAll = t.qual, true
			}
		case "redirect":
			redirect = t.arg
		case "include":
			if !count() {
				continue
			}
			target := domainSpec(t.arg, domain)
			if strings.Contains(target, "%") {
				st.macros++
				continue
			}
			if _, end := r.spfWalk(target, depth+1, st); end == spfNone {
				st.missing = append(st.missing, target)
			}
		case "a":
			if !count() {
				continue
			}
			target := domainSpec(t.arg, domain)
			if strings.Contains(target, "%") {
				st.macros++
				continue
			}
			if ips, status := r.addrs(target); len(ips) == 0 {
				if status.Absent() {
					void(target)
				} else {
					st.partial = append(st.partial, target+": address lookup failed")
				}
			}
		case "mx":
			if !count() {
				continue
			}
			target := domainSpec(t.arg, domain)
			if strings.Contains(target, "%") {
				st.macros++
				continue
			}
			if m := r.lookup(Query{Name: target, Type: dns.TypeMX}); m.Status.Absent() {
				void(target)
			} else if m.Status == StatusFail {
				st.partial = append(st.partial, target+": MX lookup failed")
			}
		case "exists":
			if !count() {
				continue
			}
			target := domainSpec(t.arg, domain)
			if strings.Contains(target, "%") {
				st.macros++ // exists is almost always a macro; it cannot be evaluated without a sender
				continue
			}
			if e := r.lookup(Query{Name: target, Type: dns.TypeA}); e.Status.Absent() {
				void(target)
			}
		case "ptr":
			count()
			st.ptr = true
		}
	}
	if !hasAll && redirect != "" {
		if count() {
			target := domainSpec(redirect, domain)
			if strings.Contains(target, "%") {
				st.macros++
			} else {
				aq, end := r.spfWalk(target, depth+1, st)
				if end == spfNone {
					st.missing = append(st.missing, target)
				}
				return aq, spfOK
			}
		}
	}
	return allQual, spfOK
}

func (r *run) spfCheck() CheckResult {
	d := r.a.Value
	st := &spfState{seen: map[string]bool{}}
	allQual, end := r.spfWalk(d, 0, st)
	obs := map[string]any{
		"records": st.topRecords, "lookups": st.lookups, "voidLookups": st.voids,
		"chain": st.chain, "dmarcEnforced": r.dmarc.enforced && r.dmarc.known,
	}
	if st.macros > 0 {
		obs["macroTermsNotEvaluated"] = st.macros
	}
	if st.capped {
		obs["lookupCountCapped"] = true
	}
	if len(st.partial) > 0 {
		obs["partial"] = st.partial
	}
	if end == spfFailed {
		return notAssessed(CheckSPF, "SPF lookup failed: "+strings.Join(st.partial, "; "), obs)
	}
	var fs []Finding
	if end == spfNone {
		sev, why := SevHigh, "The domain publishes MX records, so it receives mail and is expected to send it."
		fix := "Publish a TXT record at " + d + " listing the services that send mail for you, ending in -all (for example \"v=spf1 include:_spf.example.net -all\")."
		switch {
		case !r.mxKnown:
			sev, why = SevMedium, "Whether the domain receives mail could not be determined, so this is rated medium."
		case r.noMail():
			sev, why = SevLow, "The domain publishes no MX, so it probably sends no mail."
			fix = "If the domain sends no mail, publish \"v=spf1 -all\" so nobody can spoof it. If it does send mail, list its senders and end with -all."
		}
		fs = append(fs, newFinding(CheckSPF, "spf.missing", d, sev, "No SPF record",
			"No SPF record (a TXT record starting v=spf1) was found at "+d+". "+why+" Receivers cannot tell which servers may send for it.", fix+providerNote(r.provider), obs))
		return assessed(CheckSPF, obs, fs...)
	}
	for _, dom := range st.multiple {
		fs = append(fs, newFinding(CheckSPF, "spf.multiple", dom, SevHigh,
			"More than one SPF record",
			"More than one v=spf1 record exists at "+dom+". RFC 7208 makes that a permanent error, so SPF fails for every message.",
			"Merge the records into one v=spf1 record and delete the others.", obs))
	}
	for _, p := range st.problems {
		dom, rest, _ := strings.Cut(p, ": ")
		fs = append(fs, newFinding(CheckSPF, "spf.syntax", p, SevHigh,
			"SPF record has a syntax error",
			"The SPF record at "+dom+" has a term receivers cannot parse ("+rest+"). A permanent error means SPF fails for every message.",
			"Correct or remove the term and republish the record.", obs))
	}
	for _, dom := range st.loops {
		fs = append(fs, newFinding(CheckSPF, "spf.loop", dom, SevHigh,
			"SPF includes loop back on themselves",
			"The SPF chain reaches "+dom+" twice. RFC 7208 treats the loop as a permanent error.",
			"Remove the circular include or redirect.", obs))
	}
	for _, dom := range st.missing {
		fs = append(fs, newFinding(CheckSPF, "spf.include_missing", dom, SevHigh,
			"SPF include points at a domain with no SPF record",
			"The SPF record includes or redirects to "+dom+", which has no SPF record. That is a permanent error and SPF fails for every message.",
			"Remove the include, or correct the name to the provider's published SPF domain.", obs))
	}
	if st.lookups > 10 {
		counted := fmt.Sprintf("%d", st.lookups)
		if st.capped {
			counted = fmt.Sprintf("more than %d", spfLookupCap)
		}
		fs = append(fs, newFinding(CheckSPF, "spf.too_many_lookups", d, SevHigh,
			"SPF needs more than 10 DNS lookups",
			counted+" DNS-querying terms (include, a, mx, ptr, exists, redirect, counted through every include) were needed. RFC 7208 allows 10: above that receivers return a permanent error and SPF fails.",
			"Remove includes for services you no longer use, replace includes with ip4/ip6 ranges, or use a provider that flattens SPF.", obs))
	}
	if st.voids > 2 {
		fs = append(fs, newFinding(CheckSPF, "spf.void_lookups", d, SevHigh,
			"SPF has more than 2 void lookups",
			fmt.Sprintf("%d lookups returned no records (%s). RFC 7208 allows 2, and above that receivers return a permanent error.", st.voids, strings.Join(st.voidNames, ", ")),
			"Remove the terms that point at names which do not exist.", obs))
	}
	if st.ptr {
		fs = append(fs, newFinding(CheckSPF, "spf.ptr", d, SevLow,
			"SPF uses the deprecated ptr mechanism",
			"RFC 7208 says ptr should not be used: it is slow, unreliable and loads other people's DNS.",
			"Replace ptr with ip4/ip6 ranges or include.", obs))
	}
	switch allQual {
	case '+':
		fs = append(fs, newFinding(CheckSPF, "spf.plus_all", d, SevCritical,
			"SPF allows every server in the world to send as this domain (+all)",
			"The record ends in +all (or bare all), which passes any sender. It is worse than having no SPF record, because it looks like protection.",
			"Replace the ending with -all (or ~all while testing) after listing your real senders.", obs))
	case '?':
		fs = append(fs, newFinding(CheckSPF, "spf.neutral_all", d, SevHigh,
			"SPF ends in ?all (neutral)",
			"?all tells receivers to make no judgement about servers not listed, so it protects nothing.",
			"Change the ending to -all once your real senders are listed.", obs))
	case '~':
		if !(r.dmarc.known && r.dmarc.enforced) {
			why := "DMARC is not at enforcement, so"
			if !r.dmarc.known {
				why = "DMARC could not be read, and unless it is at enforcement"
			}
			fs = append(fs, newFinding(CheckSPF, "spf.softfail", d, SevLow,
				"SPF ends in ~all (softfail) without DMARC enforcement",
				"~all marks unlisted senders as suspicious but receivers still deliver. "+why+" nothing turns that into a rejection.",
				"Move DMARC to p=quarantine or p=reject, or change the SPF ending to -all.", obs))
		}
	case '-':
	default:
		fs = append(fs, newFinding(CheckSPF, "spf.no_all", d, SevMedium,
			"SPF record has no \"all\" ending",
			"The record lists senders but does not say what to do with anyone else, so unlisted servers get the default result (neutral).",
			"End the record with -all (or ~all while testing).", obs))
	}
	return assessed(CheckSPF, obs, fs...)
}

// rsaKeyBits reads the modulus size of a DKIM p= key. It parses the ASN.1 itself
// instead of using crypto/x509, because the standard library refuses to
// handle RSA keys under 1024 bits in some configurations and a 512-bit key in
// DNS is exactly what this has to be able to report.
func rsaKeyBits(der []byte) (int, error) {
	type rsaPub struct {
		N *big.Int
		E int
	}
	var info struct {
		Algo pkix.AlgorithmIdentifier
		Key  asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &info); err == nil && len(rest) == 0 {
		if !info.Algo.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
			return 0, fmt.Errorf("public key algorithm %s is not RSA", info.Algo.Algorithm)
		}
		var k rsaPub
		if _, err := asn1.Unmarshal(info.Key.RightAlign(), &k); err != nil || k.N == nil || k.N.Sign() <= 0 {
			return 0, fmt.Errorf("RSA public key is malformed")
		}
		return k.N.BitLen(), nil
	}
	// Some providers publish the bare PKCS#1 key without the SubjectPublicKeyInfo wrapper.
	var k rsaPub
	if rest, err := asn1.Unmarshal(der, &k); err == nil && len(rest) == 0 && k.N != nil && k.N.Sign() > 0 {
		return k.N.BitLen(), nil
	}
	return 0, fmt.Errorf("not an RSA public key")
}

// --- DKIM ------------------------------------------------------------------

var commonDKIMSelectors = []string{"google", "selector1", "selector2", "s1", "s2", "k1", "default", "dkim", "mail"}

func (r *run) dkimCheck() CheckResult {
	d := r.a.Value
	common := r.s.DKIMCommon
	if common == nil {
		common = commonDKIMSelectors
	}
	declared := map[string]bool{}
	var order []string
	for _, s := range r.a.DKIMSelectors {
		if !declared[s] {
			declared[s] = true
			order = append(order, s)
		}
	}
	for _, s := range common {
		if !declared[s] {
			order = append(order, s)
		}
	}
	type found struct {
		Selector string `json:"selector"`
		Record   string `json:"record"`
		KeyType  string `json:"keyType"`
		Bits     int    `json:"bits"`
		Revoked  bool   `json:"revoked"`
		Declared bool   `json:"declared"`
	}
	var hits []found
	var fs []Finding
	var failures []string
	absent := 0
	for _, sel := range order {
		name := sel + "._domainkey." + d
		txts, a := r.txt(name)
		if a.Status == StatusFail {
			failures = append(failures, sel+": "+a.Reason())
			continue
		}
		recs := recordsWithVersion(txts, "v=dkim1")
		if len(recs) == 0 {
			// A key record may omit v=. Take any TXT with a p= tag.
			for _, t := range txts {
				if _, ok := parseTags(t)["p"]; ok {
					recs = append(recs, t)
				}
			}
		}
		if len(recs) == 0 {
			absent++
			if declared[sel] && a.Status.Absent() {
				fs = append(fs, newFinding(CheckDKIM, "dkim.declared_missing", sel, SevMedium,
					"A declared DKIM selector has no key published",
					"The selector "+sel+" was declared for "+d+" but no DKIM record exists at "+name+", so mail signed with it fails DKIM.",
					"Publish the key record for selector "+sel+" at "+name+", or remove the selector from the asset if it is no longer used."+providerNote(r.provider),
					map[string]any{"selector": sel, "name": name, "lookup": a.Status.String()}))
			}
			continue
		}
		tags := parseTags(recs[0])
		h := found{Selector: sel, Record: recs[0], Declared: declared[sel], KeyType: strings.ToLower(tags["k"])}
		if h.KeyType == "" {
			h.KeyType = "rsa"
		}
		p := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, tags["p"])
		ev := map[string]any{"selector": sel, "name": name, "record": recs[0]}
		switch {
		case p == "":
			h.Revoked = true
			fs = append(fs, newFinding(CheckDKIM, "dkim.revoked", sel, SevInfo,
				"DKIM selector has been revoked",
				"The record at "+name+" has an empty p= tag, which publishes the key as revoked. Mail still signed with it fails DKIM.",
				"Nothing to do if the selector is retired. If it is still in use, publish its public key again.", ev))
		default:
			der, err := base64.StdEncoding.DecodeString(p)
			if err != nil {
				fs = append(fs, newFinding(CheckDKIM, "dkim.key_invalid", sel, SevMedium,
					"DKIM public key cannot be decoded",
					"The p= value at "+name+" is not valid base64, so receivers cannot verify signatures made with it.",
					"Republish the key exactly as your mail provider shows it (long keys must be split into 255-character strings, not truncated).", ev))
				break
			}
			if h.KeyType == "ed25519" {
				if len(der) == ed25519.PublicKeySize {
					h.Bits = 256
				}
				break
			}
			bits, err := rsaKeyBits(der)
			if err != nil {
				fs = append(fs, newFinding(CheckDKIM, "dkim.key_invalid", sel, SevMedium,
					"DKIM public key cannot be parsed as an RSA key",
					"The p= value at "+name+" does not parse as an RSA public key, so receivers cannot verify signatures made with it.",
					"Republish the key exactly as your mail provider shows it.", ev))
				break
			}
			h.Bits = bits
			ev["bits"] = h.Bits
			switch {
			case h.Bits < 1024:
				fs = append(fs, newFinding(CheckDKIM, "dkim.key_short", sel, SevHigh,
					fmt.Sprintf("DKIM key is only %d bits", h.Bits),
					fmt.Sprintf("The RSA key at %s is %d bits. Keys under 1024 bits can be factored with modest resources and used to forge signed mail.", name, h.Bits),
					"Generate a 2048-bit key, publish it under a new selector, switch signing to it, and retire this one."+providerNote(r.provider), ev))
			case h.Bits == 1024:
				fs = append(fs, newFinding(CheckDKIM, "dkim.key_1024", sel, SevLow,
					"DKIM key is 1024 bits",
					"The RSA key at "+name+" is 1024 bits. It is accepted today, but 2048 bits is the recommended size.",
					"Generate a 2048-bit key, publish it under a new selector, switch signing to it, and retire this one."+providerNote(r.provider), ev))
			}
		}
		hits = append(hits, h)
	}
	obs := map[string]any{"selectorsChecked": order, "found": hits, "declared": r.a.DKIMSelectors}
	if len(failures) > 0 {
		obs["lookupFailures"] = failures
	}
	if len(hits) == 0 {
		reason := fmt.Sprintf("no DKIM selector found among %d checked (%s); selectors cannot be listed from DNS, so declare yours on the asset", len(order), strings.Join(order, ", "))
		if len(failures) > 0 {
			reason += fmt.Sprintf("; %d lookups also failed", len(failures))
		}
		res := notAssessed(CheckDKIM, reason, obs)
		res.Findings = fs
		return res
	}
	res := assessed(CheckDKIM, obs, fs...)
	if len(failures) > 0 {
		res.Assessed = false
		res.Reason = fmt.Sprintf("%d selector lookups failed, so the result is partial", len(failures))
	}
	return res
}

// --- network helpers for MTA-STS and TLS ----------------------------------------

type netErrKind int

const (
	netOther netErrKind = iota
	netTimeout
	netRefused
	netUnreachable
	netNoHost // the name does not exist, or only resolves to addresses we never connect to
)

type hostError struct {
	kind netErrKind
	err  error
}

func (e *hostError) Error() string { return e.err.Error() }
func (e *hostError) Unwrap() error { return e.err }

func classifyDial(err error) netErrKind {
	var he *hostError
	if errors.As(err, &he) {
		return he.kind
	}
	msg := strings.ToLower(err.Error())
	var ne net.Error
	switch {
	case strings.Contains(msg, "connection refused"):
		return netRefused
	case strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "no route to host"):
		return netUnreachable
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout(), strings.Contains(msg, "i/o timeout"):
		return netTimeout
	}
	return netOther
}

func (s *Scanner) dialer() DialFunc {
	if s.Dial != nil {
		return s.Dial
	}
	d := &net.Dialer{Timeout: TCPTimeout}
	return d.DialContext
}

// dialHost resolves a declared hostname through the scanner's resolver and
// connects to one of its addresses. Addresses that are loopback, link-local or
// unspecified are never dialled, so a name that rebinds to an internal address
// cannot turn the scanner against its own network.
func (r *run) dialHost(host, port string) (net.Conn, net.IP, error) {
	ips, st := r.addrs(host)
	if len(ips) == 0 {
		switch st {
		case StatusFail:
			return nil, nil, &hostError{netOther, fmt.Errorf("could not resolve %s", host)}
		default:
			return nil, nil, &hostError{netNoHost, fmt.Errorf("%s has no address records", host)}
		}
	}
	var ok []net.IP
	for _, ip := range ips {
		if scannableIP(ip) {
			ok = append(ok, ip)
		}
	}
	if len(ok) == 0 {
		return nil, nil, &hostError{netNoHost, fmt.Errorf("%s resolves only to addresses that are never scanned (loopback, link-local or unspecified)", host)}
	}
	sort.SliceStable(ok, func(i, j int) bool { return ok[i].To4() != nil && ok[j].To4() == nil })
	var last error
	for i, ip := range ok {
		if i >= 3 {
			break
		}
		c, err := r.dialIP(ip, port)
		if err == nil {
			return c, ip, nil
		}
		last = err
	}
	return nil, nil, &hostError{classifyDial(last), last}
}

// dialIP makes one paced, bounded TCP connection.
func (r *run) dialIP(ip net.IP, port string) (net.Conn, error) {
	release, err := r.s.acquire(r.ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := r.s.wait(r.ctx); err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(r.ctx, TCPTimeout)
	defer cancel()
	return r.s.dialer()(dctx, "tcp", net.JoinHostPort(ip.String(), port))
}

// --- MTA-STS ---------------------------------------------------------------

type stsPolicy struct {
	Version string
	Mode    string
	MX      []string
	MaxAge  int
}

func parseSTSPolicy(body string) (stsPolicy, []string) {
	var p stsPolicy
	var problems []string
	hasAge := false
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			problems = append(problems, "line without a colon: "+strconv.Quote(line))
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "version":
			p.Version = v
		case "mode":
			p.Mode = strings.ToLower(v)
		case "mx":
			p.MX = append(p.MX, strings.ToLower(strings.TrimSuffix(v, ".")))
		case "max_age":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 31557600 {
				problems = append(problems, "max_age must be a number of seconds up to 31557600, got "+strconv.Quote(v))
			} else {
				p.MaxAge, hasAge = n, true
			}
		}
	}
	if p.Version != "STSv1" {
		problems = append(problems, "version must be STSv1")
	}
	switch p.Mode {
	case "enforce", "testing", "none":
	default:
		problems = append(problems, "mode must be enforce, testing or none, got "+strconv.Quote(p.Mode))
	}
	if p.Mode != "none" && len(p.MX) == 0 {
		problems = append(problems, "no mx: lines")
	}
	if !hasAge {
		problems = append(problems, "max_age is missing or invalid")
	}
	return p, problems
}

// stsMatches implements RFC 8461 4.1: an exact match, or "*.suffix" matching
// exactly one label in front of the suffix.
func stsMatches(pattern, host string) bool {
	pattern, host = strings.ToLower(pattern), strings.ToLower(host)
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		label, found := strings.CutSuffix(host, "."+rest)
		return found && label != "" && !strings.Contains(label, ".")
	}
	return pattern == host
}

// fetchSTS GETs the policy over HTTPS with certificate verification, no
// redirects (RFC 8461 3.3) and a 64 KB cap.
func (r *run) fetchSTS(domain string) (status int, body string, err error) {
	host := "mta-sts." + domain
	tr := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			c, _, err := r.dialHost(host, port)
			return c, err
		},
		TLSClientConfig:     &tls.Config{RootCAs: r.s.RootCAs, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: TLSTimeout,
	}
	client := &http.Client{
		Transport:     tr,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := url.URL{Scheme: "https", Host: host, Path: "/.well-known/mta-sts.txt"}
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "defendsec-surface/1 (declared-asset check)")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b), err
}

func (r *run) mtastsCheck() CheckResult {
	d := r.a.Value
	txts, a := r.txt("_mta-sts." + d)
	if a.Status == StatusFail {
		return notAssessed(CheckMTASTS, "MTA-STS lookup failed: "+a.Reason(), nil)
	}
	recs := recordsWithVersion(txts, "v=STSv1")
	obs := map[string]any{"name": "_mta-sts." + d, "records": txts}
	if len(recs) == 0 {
		if r.noMail() {
			obs["note"] = "domain publishes no MX; MTA-STS not applicable"
			return assessed(CheckMTASTS, obs)
		}
		return assessed(CheckMTASTS, obs, newFinding(CheckMTASTS, "mtasts.missing", d, SevLow,
			"No MTA-STS policy",
			"No MTA-STS record exists at _mta-sts."+d+". Without it, a network attacker between two mail servers can strip STARTTLS and read or alter mail in transit.",
			"Publish a TXT record \"v=STSv1; id=<date>\" at _mta-sts."+d+" and serve a policy at https://mta-sts."+d+"/.well-known/mta-sts.txt, starting in mode: testing. Add a TLS-RPT record to receive reports.", obs))
	}
	if len(recs) > 1 {
		return assessed(CheckMTASTS, obs, newFinding(CheckMTASTS, "mtasts.invalid", d, SevMedium,
			"More than one MTA-STS record",
			"Several v=STSv1 records exist at _mta-sts."+d+"; RFC 8461 says senders then ignore MTA-STS.",
			"Keep one record.", obs))
	}
	if id := parseTags(recs[0])["id"]; id == "" {
		return assessed(CheckMTASTS, obs, newFinding(CheckMTASTS, "mtasts.invalid", d, SevMedium,
			"MTA-STS record has no id",
			"The record at _mta-sts."+d+" has no id= tag, so senders ignore it.",
			"Add id=<a new value each time the policy changes>.", obs))
	}
	obs["record"] = recs[0]

	status, body, err := r.fetchSTS(d)
	obs["policyURL"] = "https://mta-sts." + d + "/.well-known/mta-sts.txt"
	unreachable := func(id, title, why string) CheckResult {
		return assessed(CheckMTASTS, obs, newFinding(CheckMTASTS, id, d, SevMedium, title,
			"The MTA-STS record exists but the policy cannot be used: "+why+". Senders that cached nothing treat the domain as having no MTA-STS, and ones that did cache a policy may refuse to deliver.",
			"Serve the policy at https://mta-sts."+d+"/.well-known/mta-sts.txt over HTTPS with a certificate valid for mta-sts."+d+", answering 200 without redirects.", obs))
	}
	if err != nil {
		obs["fetchError"] = err.Error()
		switch k := classifyDial(err); {
		case k == netTimeout || k == netUnreachable:
			return notAssessed(CheckMTASTS, "could not reach the MTA-STS policy host from here: "+err.Error(), obs)
		case k == netNoHost:
			return unreachable("mtasts.policy_unreachable", "MTA-STS policy host does not exist", "mta-sts."+d+" does not resolve")
		default:
			var cve *tls.CertificateVerificationError
			if errors.As(err, &cve) {
				return unreachable("mtasts.policy_unreachable", "MTA-STS policy host certificate does not verify", "its certificate failed verification ("+cve.Err.Error()+")")
			}
			return unreachable("mtasts.policy_unreachable", "MTA-STS policy cannot be fetched", err.Error())
		}
	}
	obs["httpStatus"] = status
	if status != http.StatusOK {
		return unreachable("mtasts.policy_unreachable", "MTA-STS policy cannot be fetched", fmt.Sprintf("the server answered HTTP %d (redirects are not followed)", status))
	}
	obs["policy"] = body
	pol, problems := parseSTSPolicy(body)
	if len(problems) > 0 {
		obs["problems"] = problems
		return unreachable("mtasts.policy_invalid", "MTA-STS policy is invalid", strings.Join(problems, "; "))
	}
	obs["mode"], obs["policyMX"], obs["maxAge"] = pol.Mode, pol.MX, pol.MaxAge
	var fs []Finding
	switch pol.Mode {
	case "testing":
		fs = append(fs, newFinding(CheckMTASTS, "mtasts.mode_testing", d, SevLow,
			"MTA-STS is in testing mode",
			"mode: testing means senders report problems but still deliver over an unencrypted or unverified connection.",
			"After TLS-RPT reports look clean, change the policy to mode: enforce and update the id in the TXT record.", obs))
	case "none":
		fs = append(fs, newFinding(CheckMTASTS, "mtasts.mode_none", d, SevLow,
			"MTA-STS policy is switched off (mode: none)",
			"mode: none withdraws MTA-STS, so senders do not require TLS to this domain's mail servers.",
			"Set mode: enforce when you want MTA-STS protection.", obs))
	}
	if pol.Mode != "none" {
		for _, host := range r.mx {
			covered := false
			for _, pat := range pol.MX {
				if stsMatches(pat, host) {
					covered = true
					break
				}
			}
			if !covered {
				fs = append(fs, newFinding(CheckMTASTS, "mtasts.mx_not_covered", host, SevMedium,
					"A mail server is not covered by the MTA-STS policy",
					"The MX host "+host+" matches none of the policy's mx: patterns ("+strings.Join(pol.MX, ", ")+"). In enforce mode senders would refuse to deliver to it.",
					"Add an mx: line covering "+host+" to the policy and bump the id in the TXT record.",
					map[string]any{"mxHost": host, "policyMX": pol.MX, "mode": pol.Mode}))
			}
		}
	}
	return assessed(CheckMTASTS, obs, fs...)
}

// --- TLS-RPT ---------------------------------------------------------------

func (r *run) tlsrptCheck() CheckResult {
	d := r.a.Value
	txts, a := r.txt("_smtp._tls." + d)
	if a.Status == StatusFail {
		return notAssessed(CheckTLSRPT, "TLS-RPT lookup failed: "+a.Reason(), nil)
	}
	obs := map[string]any{"name": "_smtp._tls." + d, "records": txts}
	recs := recordsWithVersion(txts, "v=TLSRPTv1")
	if len(recs) == 0 {
		if r.noMail() {
			return assessed(CheckTLSRPT, obs)
		}
		return assessed(CheckTLSRPT, obs, newFinding(CheckTLSRPT, "tlsrpt.missing", d, SevInfo,
			"No TLS-RPT record",
			"No TLS reporting record exists at _smtp._tls."+d+", so you receive no reports about mail servers that failed to negotiate TLS with yours.",
			"Publish a TXT record \"v=TLSRPTv1; rua=mailto:tls-reports@"+d+"\" at _smtp._tls."+d+".", obs))
	}
	rua := parseTags(recs[0])["rua"]
	obs["record"] = recs[0]
	ok := false
	for _, u := range strings.Split(rua, ",") {
		u = strings.ToLower(strings.TrimSpace(u))
		if strings.HasPrefix(u, "mailto:") || strings.HasPrefix(u, "https:") {
			ok = true
		}
	}
	if !ok {
		return assessed(CheckTLSRPT, obs, newFinding(CheckTLSRPT, "tlsrpt.invalid", d, SevLow,
			"TLS-RPT record has no valid report address",
			"The record at _smtp._tls."+d+" has no rua= with a mailto: or https: address, so no reports are sent.",
			"Set rua=mailto:<mailbox> or an https: endpoint.", obs))
	}
	return assessed(CheckTLSRPT, obs)
}
