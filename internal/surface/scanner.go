package surface

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Politeness limits (see the defendsec-surface skill): DNS 3 s, TCP 3 s, TLS 5 s,
// at most 8 concurrent connections per scan.
const (
	DNSTimeout     = 3 * time.Second
	TCPTimeout     = 3 * time.Second
	TLSTimeout     = 5 * time.Second
	MaxConnections = 8
	// maxQueriesPerAsset bounds the DNS work one asset can cause. SPF
	// includes are attacker-controlled data, and a record that fans out
	// should not turn a daily scan into a flood.
	maxQueriesPerAsset = 400
)

// ErrNotAuthorised is returned for an asset the operator has not confirmed.
var ErrNotAuthorised = errors.New("asset is not confirmed as authorised to test")

// DialFunc opens a TCP connection. Tests replace it to reach local servers.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Scanner runs the checks. Build it with NewScanner; tests fill the struct
// directly with a FakeResolver, a Dial that reaches a local server and a Now.
type Scanner struct {
	// Resolver answers ordinary questions; Validating answers the DNSSEC ones.
	Resolver   Resolver
	Validating Resolver
	// Dial opens TCP connections (ports, TLS, MTA-STS). Nil uses net.Dialer.
	Dial DialFunc
	// RootCAs verifies certificates. Nil uses the system roots.
	RootCAs *x509.CertPool
	Now     func() time.Time
	// Ports is the fixed risky-port list; nil means DefaultPorts.
	Ports []PortSpec
	// DKIMCommon replaces the common selector list when set.
	DKIMCommon []string
	// FIPS reports whether the Go FIPS 140 module is in force. In that mode
	// the legacy-protocol probe cannot run, so it is reported as not assessed.
	FIPS func() bool

	// pace spaces out DNS queries and TCP connects. Nil means no pacing.
	pace *time.Ticker
	// conns bounds concurrent connections. Nil is treated as unbounded
	// (tests); NewScanner sets it.
	conns chan struct{}

	mu       sync.Mutex
	scanning map[string]bool // one scan per asset at a time
}

// Config is what NewScanner needs from the environment.
type Config struct {
	// Servers are the resolvers for ordinary lookups, host:port. Empty means
	// the host's /etc/resolv.conf.
	Servers []string
	// ValidatingServers are validating resolvers for the DNSSEC check. Empty
	// means 1.1.1.1 and 9.9.9.9; the observation records which one answered.
	ValidatingServers []string
	// QueriesPerSecond paces DNS and connects together. Zero means 25.
	QueriesPerSecond int
}

// DefaultValidatingServers are public validating resolvers.
var DefaultValidatingServers = []string{"1.1.1.1:53", "9.9.9.9:53"}

// NewScanner builds the real scanner.
func NewScanner(cfg Config) *Scanner {
	servers := cfg.Servers
	if len(servers) == 0 {
		servers = SystemServers("1.1.1.1:53", "9.9.9.9:53")
	}
	val := cfg.ValidatingServers
	if len(val) == 0 {
		val = DefaultValidatingServers
	}
	qps := cfg.QueriesPerSecond
	if qps <= 0 {
		qps = 25
	}
	return &Scanner{
		Resolver:   &NetResolver{Servers: servers, Timeout: DNSTimeout},
		Validating: &NetResolver{Servers: val, Timeout: DNSTimeout},
		Now:        time.Now,
		pace:       time.NewTicker(time.Second / time.Duration(qps)),
		conns:      make(chan struct{}, MaxConnections),
	}
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// wait paces one outgoing operation.
func (s *Scanner) wait(ctx context.Context) error {
	if s.pace == nil {
		return ctx.Err()
	}
	select {
	case <-s.pace.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acquire takes a connection slot; the returned func releases it.
func (s *Scanner) acquire(ctx context.Context) (func(), error) {
	if s.conns == nil {
		return func() {}, ctx.Err()
	}
	select {
	case s.conns <- struct{}{}:
		return func() { <-s.conns }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// run carries one asset's scan: its asset, a query budget and what earlier
// checks learned (the later ones use it).
type run struct {
	s       *Scanner
	a       Asset
	ctx     context.Context
	queries atomic.Int64

	mx       []string // MX hosts, lower-case without the dot
	mxKnown  bool
	hasMail  bool // the domain publishes at least one real (non-null) MX
	dmarc    dmarcInfo
	provider string
}

// Report is one asset's full scan.
type Report struct {
	Asset      Asset         `json:"asset"`
	StartedAt  time.Time     `json:"startedAt"`
	FinishedAt time.Time     `json:"finishedAt"`
	Results    []CheckResult `json:"results"`
}

// Findings flattens every finding in the report.
func (r *Report) Findings() []Finding {
	var out []Finding
	for _, c := range r.Results {
		out = append(out, c.Findings...)
	}
	return out
}

// ScanAsset runs every check that applies to the asset's kind.
//
// It refuses an asset that is not confirmed as authorised, whatever the
// caller's checks, and one that is already being scanned: one scan per asset
// at a time.
func (s *Scanner) ScanAsset(ctx context.Context, a Asset) (*Report, error) {
	if !a.Authorised {
		return nil, fmt.Errorf("%w: %s %s", ErrNotAuthorised, a.Kind, a.Value)
	}
	norm, err := NormaliseAsset(a.Kind, a.Value)
	if err != nil {
		return nil, err
	}
	a.Value = norm

	key := string(a.Kind) + ":" + a.Value
	s.mu.Lock()
	if s.scanning == nil {
		s.scanning = map[string]bool{}
	}
	if s.scanning[key] {
		s.mu.Unlock()
		return nil, ErrScanInProgress
	}
	s.scanning[key] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.scanning, key)
		s.mu.Unlock()
	}()

	r := &run{s: s, a: a}
	rep := &Report{Asset: a, StartedAt: s.now()}
	r.ctx = ctx
	add := func(c CheckResult) { rep.Results = append(rep.Results, c) }
	switch a.Kind {
	case KindDomain:
		add(r.mxCheck())
		add(r.dmarcCheck())
		add(r.spfCheck())
		add(r.dkimCheck())
		add(r.mtastsCheck())
		add(r.tlsrptCheck())
		add(r.dnssecCheck())
		add(r.caaCheck())
		add(r.cnameCheck())
		cert, legacy := r.tlsChecks()
		add(cert)
		add(legacy)
	case KindHostname:
		add(r.cnameCheck())
		cert, legacy := r.tlsChecks()
		add(cert)
		add(legacy)
	case KindIP:
		add(r.portsCheck())
	}
	rep.FinishedAt = s.now()
	return rep, nil
}

// ErrScanInProgress is returned when the asset is already being scanned.
var ErrScanInProgress = errors.New("a scan of this asset is already running")
