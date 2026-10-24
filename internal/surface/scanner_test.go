package surface

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// wellConfiguredZone is a domain with nothing wrong in DNS except that it is
// not DNSSEC-signed, which is information, not a fault.
func wellConfiguredZone(t *testing.T) *FakeResolver {
	return NewFakeResolver().Add(
		"example.com. 300 IN A 192.0.2.10",
		"example.com. 300 IN MX 10 aspmx.l.google.com.",
		"aspmx.l.google.com. 300 IN A 192.0.2.20",
		"example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
		txt("example.com", "v=spf1 include:_spf.google.com -all"),
		txt("_spf.google.com", "v=spf1 ip4:192.0.2.0/24 ~all"),
		txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"),
		dkimTXT("google", "example.com", dkimKey(t, 2048)),
		txt("_mta-sts.example.com", "v=STSv1; id=1"),
		"mta-sts.example.com. 300 IN A 192.0.2.10",
		txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:tls@example.com"),
		`example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
	)
}

func wellConfiguredScanner(t *testing.T, f *FakeResolver) *Scanner {
	ca := newCA(t, "E2E CA")
	srv := httptest.NewUnstartedServer(policy("version: STSv1", "mode: enforce", "mx: aspmx.l.google.com", "max_age: 604800"))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.issue(t, []string{"example.com", "mta-sts.example.com"}, -time.Hour, 80*24*time.Hour)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s := testScanner(f)
	s.Dial, s.RootCAs = toLocal(srv.Listener.Addr().String()), ca.pool
	return s
}

func TestScanWellConfiguredDomainHasOnlyAnInfo(t *testing.T) {
	s := wellConfiguredScanner(t, wellConfiguredZone(t))
	rep, err := s.ScanAsset(context.Background(), domainAsset("Example.com."))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Asset.Value != "example.com" {
		t.Fatalf("asset not normalised: %q", rep.Asset.Value)
	}
	groups := map[string]bool{}
	for _, res := range rep.Results {
		groups[res.Check] = true
		if !res.Assessed {
			t.Errorf("%s was not assessed: %s", res.Check, res.Reason)
		}
		if len(res.Observed) == 0 {
			t.Errorf("%s stored no observation", res.Check)
		}
	}
	for _, g := range []string{CheckMX, CheckSPF, CheckDMARC, CheckDKIM, CheckMTASTS, CheckTLSRPT, CheckDNSSEC, CheckCAA, CheckCNAME, CheckTLSCert, CheckTLSLegacy} {
		if !groups[g] {
			t.Errorf("check group %s did not run on a domain", g)
		}
	}
	fs := rep.Findings()
	if got := ids(fs); len(got) != 1 || got[0] != "dnssec.unsigned|example.com" {
		t.Fatalf("a well-configured domain should show only the unsigned-zone note, got %v", got)
	}
}

func TestScanBrokenDomainFindsEverythingAndEveryFindingIsComplete(t *testing.T) {
	f := NewFakeResolver().Add(
		"example.com. 300 IN MX 10 gone.example.com.",
		"gone.example.com. 300 IN TXT \"x\"",
		txt("example.com", "v=spf1 ip4:192.0.2.0/24 +all"),
		txt("_dmarc.example.com", "v=DMARC1; p=none"),
		dkimTXT("s1", "example.com", dkimKey(t, 512)),
		txt("_mta-sts.example.com", "v=STSv1; id=1"),
		"example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 300",
	)
	s := testScanner(f)
	rep, err := s.ScanAsset(context.Background(), domainAsset("example.com"))
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, fnd := range rep.Findings() {
		have[fnd.ID] = true
		if !fnd.Severity.Valid() || fnd.Title == "" || fnd.Detail == "" || fnd.Fix == "" || len(fnd.Evidence) == 0 || len(fnd.Controls) == 0 {
			t.Errorf("%s is missing something a finding must carry: %+v", fnd.ID, fnd)
		}
		if fnd.Check == "" || fnd.ID == "" {
			t.Errorf("finding without check or id: %+v", fnd)
		}
	}
	for _, id := range []string{"mx.no_address", "spf.plus_all", "dmarc.p_none", "dkim.key_short", "mtasts.policy_unreachable", "caa.missing", "dnssec.unsigned"} {
		if !have[id] {
			t.Errorf("expected finding %s; have %v", id, have)
		}
	}
	// Nothing was reachable on 443 (the test dialler refuses to dial), so the
	// TLS groups must say so rather than pass.
	for _, res := range rep.Results {
		if (res.Check == CheckTLSCert || res.Check == CheckTLSLegacy) && res.Assessed {
			t.Errorf("%s passed with no way to connect", res.Check)
		}
	}
}

func TestControlTagsComeFromTheCatalogue(t *testing.T) {
	fnd := newFinding(CheckDMARC, "x", "s", SevLow, "t", "d", "f", nil)
	if len(fnd.Controls) == 0 || !contains(fnd.Controls, "cis-v8:9.5") {
		t.Fatalf("email findings should reach CIS 9.5: %v", fnd.Controls)
	}
	if got := newFinding(CheckPorts, "x", "s", SevLow, "t", "d", "f", nil).Controls; !contains(got, "nist-800-53:SC-7") {
		t.Fatalf("%v", got)
	}
	if got := newFinding(CheckTLSLegacy, "x", "s", SevLow, "t", "d", "f", nil).Controls; !contains(got, "nist-800-53:SC-8") || !contains(got, "nist-800-53:SC-17") {
		t.Fatalf("%v", got)
	}
	if got := newFinding(CheckDNSSEC, "x", "s", SevLow, "t", "d", "f", nil).Controls; !contains(got, "nist-800-53:SC-20") {
		t.Fatalf("%v", got)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func TestScanRefusesAnAssetThatIsNotAuthorised(t *testing.T) {
	f := NewFakeResolver()
	s := testScanner(f)
	dialled := false
	s.Dial = func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, errors.New("no") }
	for _, a := range []Asset{
		{Kind: KindDomain, Value: "example.com"},
		{Kind: KindHostname, Value: "www.example.com"},
		{Kind: KindIP, Value: "192.0.2.1"},
	} {
		if _, err := s.ScanAsset(context.Background(), a); !errors.Is(err, ErrNotAuthorised) {
			t.Errorf("%s %s: err = %v, want ErrNotAuthorised", a.Kind, a.Value, err)
		}
	}
	if len(f.Log) != 0 || dialled {
		t.Fatalf("an unauthorised asset caused network activity: queries=%v dialled=%v", f.Log, dialled)
	}
}

func TestScanRefusesUnscannableTargets(t *testing.T) {
	s := testScanner(NewFakeResolver())
	for _, a := range []Asset{
		{Kind: KindIP, Value: "127.0.0.1", Authorised: true},
		{Kind: KindIP, Value: "169.254.169.254", Authorised: true},
		{Kind: KindDomain, Value: "https://example.com/", Authorised: true},
	} {
		if _, err := s.ScanAsset(context.Background(), a); err == nil {
			t.Errorf("%s %s was scanned", a.Kind, a.Value)
		}
	}
}

// blockingResolver holds the first question until released.
type blockingResolver struct {
	inner   Resolver
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingResolver) Exchange(ctx context.Context, q Query) (*Response, error) {
	if strings.HasSuffix(trimDot(q.Name), "example.com") {
		b.once.Do(func() { close(b.started); <-b.release })
	}
	return b.inner.Exchange(ctx, q)
}

func TestOneScanPerAssetAtATime(t *testing.T) {
	br := &blockingResolver{inner: NewFakeResolver(), started: make(chan struct{}), release: make(chan struct{})}
	s := testScanner(NewFakeResolver())
	s.Resolver, s.Validating = br, br
	done := make(chan error, 1)
	go func() { _, err := s.ScanAsset(context.Background(), domainAsset("example.com")); done <- err }()
	<-br.started
	if _, err := s.ScanAsset(context.Background(), domainAsset("example.com")); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("second scan of the same asset: %v", err)
	}
	// A different asset is not blocked by it.
	if _, err := s.ScanAsset(context.Background(), domainAsset("example.net")); err != nil && errors.Is(err, ErrScanInProgress) {
		t.Fatal("another asset must be scannable")
	}
	close(br.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScanAsset(context.Background(), domainAsset("example.com")); err != nil {
		t.Fatalf("the slot must be released after a scan: %v", err)
	}
}

func TestSPFFanOutCannotExceedTheQueryBudget(t *testing.T) {
	f := NewFakeResolver()
	var terms []string
	for i := 0; i < 300; i++ {
		n := fmt.Sprintf("inc%d.example.net", i)
		terms = append(terms, "include:"+n)
		f.Add(txt(n, "v=spf1 -all"))
	}
	f.Add(txt("example.com", "v=spf1 "+strings.Join(terms, " ")+" -all"))
	r := newRun(testScanner(f), domainAsset("example.com"))
	r.mxKnown, r.hasMail = true, true
	res := r.spfCheck()
	if n := r.queries.Load(); n > maxQueriesPerAsset+int64(spfLookupCap) {
		t.Fatalf("one asset made %d queries", n)
	}
	if len(f.Log) > spfLookupCap+5 {
		t.Fatalf("a hostile SPF record caused %d DNS queries", len(f.Log))
	}
	find(t, res, "spf.too_many_lookups")
	if res.Observed["lookupCountCapped"] != true {
		t.Fatalf("%v", res.Observed)
	}
}

func TestQueryBudgetIsEnforced(t *testing.T) {
	r := newRun(testScanner(NewFakeResolver()), domainAsset("example.com"))
	for i := 0; i < maxQueriesPerAsset; i++ {
		r.lookup(Query{Name: "example.com", Type: dns.TypeA})
	}
	if a := r.lookup(Query{Name: "example.com", Type: dns.TypeA}); a.Status != StatusFail || !strings.Contains(a.Reason(), "budget") {
		t.Fatalf("%+v", a)
	}
}

// --- the real resolver against a local DNS server ---------------------------------

func localDNS(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestNetResolverTalksDNS(t *testing.T) {
	var sawDO, sawCD atomic.Bool
	addr := localDNS(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if o := req.IsEdns0(); o != nil {
			sawDO.Store(o.Do())
		}
		sawCD.Store(req.CheckingDisabled)
		m.AuthenticatedData = sawDO.Load()
		rr, _ := dns.NewRR(`example.com. 60 IN TXT "v=spf1 -all"`)
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	r := &NetResolver{Servers: []string{addr}, Timeout: time.Second}
	resp, err := r.Exchange(context.Background(), Query{Name: "example.com.", Type: dns.TypeTXT, DO: true, CD: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || !resp.AD || resp.Resolver != addr || !sawDO.Load() || !sawCD.Load() {
		t.Fatalf("resp=%+v DO=%v CD=%v", resp, sawDO.Load(), sawCD.Load())
	}

	// And through the scanner's own lookup helper.
	s := &Scanner{Resolver: r}
	txts, a := (&run{s: s, ctx: context.Background()}).txt("example.com")
	if a.Status != StatusOK || len(txts) != 1 || txts[0] != "v=spf1 -all" {
		t.Fatalf("%v %+v", txts, a)
	}
}

func TestNetResolverFallsBackToTCPAndNextServer(t *testing.T) {
	// A server that truncates over UDP and answers fully over TCP.
	big := func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
			m.Truncated = true
		} else {
			rr, _ := dns.NewRR(`example.com. 60 IN TXT "over tcp"`)
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	}
	// dns.Server on the same port for UDP and TCP.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Skip("could not bind the same port for TCP:", err)
	}
	udp, tcp := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(big)}, &dns.Server{Listener: ln, Handler: dns.HandlerFunc(big)}
	var wg sync.WaitGroup
	wg.Add(2)
	udp.NotifyStartedFunc, tcp.NotifyStartedFunc = wg.Done, wg.Done
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	wg.Wait()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })

	dead, _ := net.ListenPacket("udp", "127.0.0.1:0") // nobody answers
	deadAddr := dead.LocalAddr().String()
	dead.Close()

	r := &NetResolver{Servers: []string{deadAddr, pc.LocalAddr().String()}, Timeout: 300 * time.Millisecond}
	resp, err := r.Exchange(context.Background(), Query{Name: "example.com", Type: dns.TypeTXT})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Resolver != pc.LocalAddr().String() {
		t.Fatalf("%+v", resp)
	}

	// Every server dead: an error, never an empty answer.
	r = &NetResolver{Servers: []string{deadAddr}, Timeout: 200 * time.Millisecond}
	if _, err := r.Exchange(context.Background(), Query{Name: "example.com", Type: dns.TypeTXT}); err == nil {
		t.Fatal("no answer must be an error")
	}
}

func TestNetResolverServfailIsAnAnswerNotAnError(t *testing.T) {
	addr := localDNS(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	s := &Scanner{Resolver: &NetResolver{Servers: []string{addr}, Timeout: time.Second}}
	a := (&run{s: s, ctx: context.Background()}).lookup(Query{Name: "example.com", Type: dns.TypeTXT})
	if a.Status != StatusFail || !strings.Contains(a.Reason(), "SERVFAIL") {
		t.Fatalf("%+v", a)
	}
}

func TestParseTagsKeepsUnknownAndFirstWins(t *testing.T) {
	got := parseTags("v=DMARC1; p=reject; P=none; zz=1; ; =x; noequals")
	if got["p"] != "reject" || got["zz"] != "1" || got["v"] != "DMARC1" {
		t.Fatalf("%v", got)
	}
}
