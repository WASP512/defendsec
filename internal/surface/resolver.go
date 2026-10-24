package surface

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Query is one DNS question. DO asks for DNSSEC records and the AD flag; CD
// turns off the resolver's own validation, which is how a bogus signature is
// told apart from an outage (see dnssecCheck). Validating routes the question
// to the validating resolvers instead of the ordinary ones.
type Query struct {
	Name       string
	Type       uint16
	DO         bool
	CD         bool
	Validating bool
}

// Response is a DNS answer as the checks need it. Resolver names who answered,
// which the DNSSEC observation records.
type Response struct {
	Rcode    int
	Answer   []dns.RR
	AD       bool
	Resolver string
}

// Resolver is DNS behind an interface so the checks run on fixtures.
// An error means no answer was obtained (timeout, refused connection); an
// answer with a failure rcode is a Response, not an error.
type Resolver interface {
	Exchange(ctx context.Context, q Query) (*Response, error)
}

// Status classifies a lookup the way the checks need: there was an answer,
// the name has no records of that type, the name does not exist, or we could
// not find out. The last is missing evidence, never "absent".
type Status int

const (
	StatusOK Status = iota
	StatusNoData
	StatusNXDomain
	StatusFail
)

func (s Status) String() string {
	return [...]string{"ok", "nodata", "nxdomain", "fail"}[s]
}

// Absent is true when DNS positively said the record does not exist.
func (s Status) Absent() bool { return s == StatusNoData || s == StatusNXDomain }

// Answer is a lookup result filtered to the type that was asked for.
type Answer struct {
	Status   Status
	RRs      []dns.RR // records of the requested type, any owner (CNAME chains followed by the resolver)
	CNAMEs   []*dns.CNAME
	AD       bool
	Rcode    int
	Resolver string
	Err      error
}

// Reason is a one-line explanation of a failed lookup.
func (a Answer) Reason() string {
	if a.Err != nil {
		return a.Err.Error()
	}
	return "DNS rcode " + dns.RcodeToString[a.Rcode]
}

func fqdn(name string) string { return dns.Fqdn(strings.ToLower(name)) }

func trimDot(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

// lookup asks one question through the scanner's resolver and classifies it.
// Each asset gets a fixed query budget; a name that fans out cannot exceed it.
func (r *run) lookup(q Query) Answer {
	if r.queries.Add(1) > maxQueriesPerAsset {
		return Answer{Status: StatusFail, Err: errors.New("per-asset DNS query budget exhausted")}
	}
	if err := r.s.wait(r.ctx); err != nil {
		return Answer{Status: StatusFail, Err: err}
	}
	var res Resolver = r.s.Resolver
	if q.Validating && r.s.Validating != nil {
		res = r.s.Validating
	}
	if res == nil {
		return Answer{Status: StatusFail, Err: errors.New("no resolver configured")}
	}
	q.Name = fqdn(q.Name)
	resp, err := res.Exchange(r.ctx, q)
	if err != nil {
		return Answer{Status: StatusFail, Err: err}
	}
	a := Answer{Rcode: resp.Rcode, AD: resp.AD, Resolver: resp.Resolver}
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			a.CNAMEs = append(a.CNAMEs, c)
		}
		if rr.Header().Rrtype == q.Type {
			a.RRs = append(a.RRs, rr)
		}
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		if len(a.RRs) > 0 {
			a.Status = StatusOK
		} else {
			a.Status = StatusNoData
		}
	case dns.RcodeNameError:
		a.Status = StatusNXDomain
	default:
		a.Status = StatusFail
	}
	return a
}

func (r *run) txt(name string) ([]string, Answer) {
	a := r.lookup(Query{Name: name, Type: dns.TypeTXT})
	out := make([]string, 0, len(a.RRs))
	for _, rr := range a.RRs {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, a
}

// addrs resolves a name to its A and AAAA addresses. It reports failure only if
// neither family answered and at least one query failed.
func (r *run) addrs(name string) ([]net.IP, Status) {
	var ips []net.IP
	var failed, nx bool
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		a := r.lookup(Query{Name: name, Type: t})
		switch a.Status {
		case StatusFail:
			failed = true
		case StatusNXDomain:
			nx = true
		}
		for _, rr := range a.RRs {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, v.A)
			case *dns.AAAA:
				ips = append(ips, v.AAAA)
			}
		}
	}
	switch {
	case len(ips) > 0:
		return ips, StatusOK
	case failed:
		return nil, StatusFail
	case nx:
		return nil, StatusNXDomain
	}
	return nil, StatusNoData
}

// --- the real resolver --------------------------------------------------

// ExchangeFunc is the wire exchange, replaceable in tests of the resolver.
type ExchangeFunc func(ctx context.Context, c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error)

// NetResolver sends queries to recursive resolvers with miekg/dns: UDP first,
// TCP on truncation, the next server on a network error. Timeouts are the
// client's (3 s by default) and queries are paced by the Scanner, not here.
type NetResolver struct {
	Servers []string // host:port
	Timeout time.Duration
	Wire    ExchangeFunc // nil: the real network
}

// SystemServers reads the host's resolvers from /etc/resolv.conf, falling back
// to the given defaults when there are none.
func SystemServers(fallback ...string) []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(cfg.Servers) > 0 {
		out := make([]string, 0, len(cfg.Servers))
		for _, s := range cfg.Servers {
			out = append(out, net.JoinHostPort(s, cfg.Port))
		}
		return out
	}
	return fallback
}

// Exchange implements Resolver.
func (r *NetResolver) Exchange(ctx context.Context, q Query) (*Response, error) {
	if len(r.Servers) == 0 {
		return nil, errors.New("no DNS servers configured")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(q.Name), q.Type)
	m.RecursionDesired = true
	m.CheckingDisabled = q.CD
	m.SetEdns0(1232, q.DO)

	exchange := r.Wire
	if exchange == nil {
		exchange = func(ctx context.Context, c *dns.Client, m *dns.Msg, addr string) (*dns.Msg, error) {
			resp, _, err := c.ExchangeContext(ctx, m, addr)
			return resp, err
		}
	}
	var lastErr error
	for _, server := range r.Servers {
		udp := &dns.Client{Net: "udp", Timeout: timeout}
		resp, err := exchange(ctx, udp, m, server)
		if err == nil && resp != nil && resp.Truncated {
			tcp := &dns.Client{Net: "tcp", Timeout: timeout}
			resp, err = exchange(ctx, tcp, m, server)
		}
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", server, err)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("%s: empty response", server)
			continue
		}
		return &Response{Rcode: resp.Rcode, Answer: resp.Answer, AD: resp.AuthenticatedData, Resolver: server}, nil
	}
	return nil, lastErr
}

// --- fixtures ------------------------------------------------------------

// FakeResolver is a zone held in memory. Tests (here and in the control
// package) use it so every check runs on fixtures, with no network.
//
// Names with no record of any type are NXDOMAIN, names with records of other
// types are NODATA, and CNAMEs are followed the way a recursive resolver does.
type FakeResolver struct {
	mu      sync.Mutex
	zone    map[string][]dns.RR // "name/TYPE"
	names   map[string]bool
	rcode   map[string]int  // name/TYPE -> forced rcode
	failing map[string]bool // name/TYPE -> network error
	ad      map[string]bool // name/TYPE -> AD flag on a validating answer
	bogus   map[string]bool // name -> validating resolvers SERVFAIL unless CD is set
	// Log records every question asked, "name/TYPE", in order.
	Log []string
}

// NewFakeResolver returns an empty zone.
func NewFakeResolver() *FakeResolver {
	return &FakeResolver{
		zone: map[string][]dns.RR{}, names: map[string]bool{}, rcode: map[string]int{},
		failing: map[string]bool{}, ad: map[string]bool{}, bogus: map[string]bool{},
	}
}

func fkey(name string, t uint16) string { return trimDot(name) + "/" + dns.TypeToString[t] }

// Add parses zone-file lines ("example.com. 300 IN TXT \"v=spf1 -all\"") into
// the zone. It panics on a bad line: a fixture typo should not pass quietly.
func (f *FakeResolver) Add(lines ...string) *FakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil || rr == nil {
			panic(fmt.Sprintf("surface: bad fixture record %q: %v", l, err))
		}
		k := fkey(rr.Header().Name, rr.Header().Rrtype)
		f.zone[k] = append(f.zone[k], rr)
		f.names[trimDot(rr.Header().Name)] = true
	}
	return f
}

// Fail makes a question return a network error (a timeout), not an answer.
func (f *FakeResolver) Fail(name string, t uint16) *FakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing[fkey(name, t)] = true
	return f
}

// Rcode forces a response code for a question (SERVFAIL, REFUSED).
func (f *FakeResolver) Rcode(name string, t uint16, rcode int) *FakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rcode[fkey(name, t)] = rcode
	return f
}

// Validated marks a question as DNSSEC-validated: validating answers carry AD.
func (f *FakeResolver) Validated(name string, t uint16) *FakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ad[fkey(name, t)] = true
	return f
}

// Bogus marks a name whose DNSSEC data does not validate: validating resolvers
// answer SERVFAIL for it unless the checking-disabled bit is set.
func (f *FakeResolver) Bogus(name string) *FakeResolver {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bogus[trimDot(name)] = true
	return f
}

// Exchange implements Resolver.
func (f *FakeResolver) Exchange(_ context.Context, q Query) (*Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := trimDot(q.Name)
	k := fkey(name, q.Type)
	f.Log = append(f.Log, k)
	if f.failing[k] {
		return nil, fmt.Errorf("fake resolver: timeout asking %s", k)
	}
	resolver := "fake"
	if q.Validating {
		resolver = "fake-validating"
		if f.bogus[name] && !q.CD && q.Type != dns.TypeDS { // a DS answer comes from the parent, which is fine
			return &Response{Rcode: dns.RcodeServerFailure, Resolver: resolver}, nil
		}
	}
	if rc, ok := f.rcode[k]; ok {
		return &Response{Rcode: rc, Resolver: resolver}, nil
	}
	var chain []dns.RR
	cur := name
	for i := 0; i < 8; i++ {
		if recs := f.zone[fkey(cur, q.Type)]; len(recs) > 0 {
			resp := &Response{Rcode: dns.RcodeSuccess, Answer: append(chain, recs...), Resolver: resolver}
			resp.AD = q.Validating && q.DO && f.ad[k]
			return resp, nil
		}
		if q.Type != dns.TypeCNAME {
			if cn := f.zone[fkey(cur, dns.TypeCNAME)]; len(cn) > 0 {
				chain = append(chain, cn[0])
				cur = trimDot(cn[0].(*dns.CNAME).Target)
				continue
			}
		}
		break
	}
	exists := f.names[cur]
	for k2 := range f.rcode { // a forced rcode on another type still means the name exists
		if strings.HasPrefix(k2, cur+"/") {
			exists = true
		}
	}
	rc := dns.RcodeSuccess
	if !exists {
		rc = dns.RcodeNameError
	}
	resp := &Response{Rcode: rc, Answer: chain, Resolver: resolver}
	resp.AD = q.Validating && q.DO && f.ad[k]
	return resp, nil
}

// Asked reports whether a question was asked.
func (f *FakeResolver) Asked(name string, t uint16) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := fkey(name, t)
	for _, l := range f.Log {
		if l == k {
			return true
		}
	}
	return false
}
