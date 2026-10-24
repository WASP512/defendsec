package surface

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// portDialer sends a connection for ip:port to a local listener when open has
// that port, and answers "connection refused" for every other port.
func portDialer(t *testing.T, open ...int) (DialFunc, *atomic.Int64) {
	t.Helper()
	local := map[string]string{}
	for _, p := range open {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close() // the connect is the whole measurement; nothing is read or sent
			}
		}()
		local[strconv.Itoa(p)] = ln.Addr().String()
	}
	var calls atomic.Int64
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		_, port, _ := net.SplitHostPort(addr)
		if l, ok := local[port]; ok {
			var d net.Dialer
			return d.DialContext(ctx, network, l)
		}
		return nil, errors.New("dial tcp " + addr + ": connect: connection refused")
	}, &calls
}

func ipAsset(ip string) Asset { return Asset{Kind: KindIP, Value: ip, Authorised: true} }

func TestPortSeverities(t *testing.T) {
	dial, calls := portDialer(t, 445, 3389, 22, 25, 21, 8080, 5432)
	s := testScanner(NewFakeResolver())
	s.Dial = dial
	res := newRun(s, ipAsset("192.0.2.50")).portsCheck()
	if !res.Assessed {
		t.Fatalf("%+v", res)
	}
	want := map[string]Severity{
		"445/tcp": SevCritical, "3389/tcp": SevHigh, "5432/tcp": SevHigh, "21/tcp": SevMedium,
		"8080/tcp": SevLow, "22/tcp": SevInfo, "25/tcp": SevLow, // 25 is low on a host not declared as mail
	}
	got := map[string]Severity{}
	for _, f := range res.Findings {
		got[f.Subject] = f.Severity
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if n := calls.Load(); n != int64(len(DefaultPorts)) {
		t.Fatalf("connected %d times, want exactly the %d ports on the fixed list", n, len(DefaultPorts))
	}
	for _, f := range res.Findings {
		if f.Severity.Rank() >= SevHigh.Rank() && !strings.Contains(f.Detail, "not show the service is vulnerable") {
			t.Errorf("%s: an open port must be worded as reachable, not as compromised: %s", f.Subject, f.Detail)
		}
	}
}

func TestMailPortsAreInfoOnADeclaredMailHost(t *testing.T) {
	dial, _ := portDialer(t, 25, 143, 110)
	s := testScanner(NewFakeResolver())
	s.Dial = dial
	a := ipAsset("192.0.2.51")
	a.MailHost = true
	res := newRun(s, a).portsCheck()
	for _, f := range res.Findings {
		wantSeverity(t, f, SevInfo)
	}
	if len(res.Findings) != 3 {
		t.Fatal(ids(res.Findings))
	}
}

func TestSharedHostingCapsSeverityAndSaysWhose(t *testing.T) {
	dial, _ := portDialer(t, 445, 8080)
	s := testScanner(NewFakeResolver())
	s.Dial = dial

	// Operator-declared shared hosting.
	a := ipAsset("198.51.100.20")
	a.SharedHosting = true
	res := newRun(s, a).portsCheck()
	for _, f := range res.Findings {
		wantSeverity(t, f, SevInfo)
		if !strings.Contains(f.Detail, "shared hosting") {
			t.Fatalf("%s", f.Detail)
		}
	}
	if len(res.Findings) != 2 {
		t.Fatal(ids(res.Findings))
	}

	// A Cloudflare edge address is recognised without being told.
	res = newRun(s, ipAsset("104.16.1.1")).portsCheck()
	if res.Observed["edgeProvider"] != "Cloudflare" {
		t.Fatalf("%v", res.Observed)
	}
	for _, f := range res.Findings {
		wantSeverity(t, f, SevInfo)
		if !strings.Contains(f.Detail, "Cloudflare") {
			t.Fatal(f.Detail)
		}
	}
	// A non-edge address with the same open ports is not capped.
	res = newRun(s, ipAsset("203.0.113.9")).portsCheck()
	wantSeverity(t, find(t, res, "ports.open"), SevCritical)
}

func TestPortsAllFilteredOrUnreachableIsNotAssessed(t *testing.T) {
	s := testScanner(NewFakeResolver())
	s.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, timeoutErr{} }
	res := newRun(s, ipAsset("192.0.2.60")).portsCheck()
	if res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("a silent address proves nothing: %+v", res)
	}

	s.Dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp: connect: network is unreachable")
	}
	res = newRun(s, ipAsset("192.0.2.60")).portsCheck()
	if res.Assessed || !strings.Contains(res.Reason, "no connection could be attempted") {
		t.Fatalf("%+v", res)
	}

	// One refusal means somebody answered: closed ports, assessed, no findings.
	s.Dial = func(_ context.Context, _, addr string) (net.Conn, error) {
		if strings.HasSuffix(addr, ":22") {
			return nil, errors.New("connection refused")
		}
		return nil, timeoutErr{}
	}
	res = newRun(s, ipAsset("192.0.2.60")).portsCheck()
	if !res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestPortConcurrencyIsBounded(t *testing.T) {
	var cur, peak atomic.Int64
	s := testScanner(NewFakeResolver())
	s.conns = make(chan struct{}, MaxConnections)
	s.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		cur.Add(-1)
		return nil, errors.New("connection refused")
	}
	s.Ports = make([]PortSpec, 40)
	for i := range s.Ports {
		s.Ports[i] = PortSpec{Port: 1000 + i, Service: "x", Severity: SevLow}
	}
	newRun(s, ipAsset("192.0.2.70")).portsCheck()
	if p := peak.Load(); p > MaxConnections || p < 2 {
		t.Fatalf("peak concurrent connections = %d, want 2..%d", p, MaxConnections)
	}
}

func TestEdgeProviderRanges(t *testing.T) {
	for ip, want := range map[string]string{"104.16.0.1": "Cloudflare", "2606:4700::1": "Cloudflare", "192.0.2.1": "", "8.8.8.8": ""} {
		a, _ := parseAddr(ip)
		if got := edgeProvider(a); got != want {
			t.Errorf("edgeProvider(%s) = %q, want %q", ip, got, want)
		}
	}
}
