package surface

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func tlsScan(t *testing.T, host string, cfg *tls.Config, ca *testCA) (CheckResult, CheckResult) {
	t.Helper()
	addr := tlsServer(t, cfg)
	s := testScanner(hostZone(host))
	s.Dial = toLocal(addr)
	if ca != nil {
		s.RootCAs = ca.pool
	}
	a := Asset{Kind: KindHostname, Value: host, Authorised: true}
	return newRun(s, a).tlsChecks()
}

func TestTLSHealthyCertificate(t *testing.T) {
	ca := newCA(t, "Good CA")
	cert := ca.issue(t, []string{"www.example.com"}, -time.Hour, 80*24*time.Hour)
	res, legacy := tlsScan(t, "www.example.com", &tls.Config{Certificates: []tls.Certificate{cert}}, ca)
	if !res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("healthy certificate produced %v (%s)", ids(res.Findings), res.Reason)
	}
	for _, k := range []string{"version", "cipherSuite", "chainSent", "daysRemaining", "ip"} {
		if _, ok := res.Observed[k]; !ok {
			t.Errorf("observation lacks %q: %v", k, res.Observed)
		}
	}
	chain := res.Observed["chainSent"].([]map[string]any)
	if len(chain) != 1 || chain[0]["sha256"] == "" || chain[0]["notAfter"] == "" {
		t.Fatalf("certificate fingerprint and dates are the evidence: %v", chain)
	}
	if !legacy.Assessed || len(legacy.Findings) != 0 {
		t.Fatalf("a TLS 1.2+ server does not accept 1.0/1.1: %+v", legacy)
	}
}

func TestTLSExpiryThresholds(t *testing.T) {
	ca := newCA(t, "Expiry CA")
	cases := []struct {
		name      string
		notBefore time.Duration
		notAfter  time.Duration
		id        string
		sev       Severity
	}{
		{"expired", -90 * 24 * time.Hour, -2 * 24 * time.Hour, "tls.expired", SevCritical},
		{"5 days", -85 * 24 * time.Hour, 5 * 24 * time.Hour, "tls.expires_soon", SevHigh},
		{"20 days", -70 * 24 * time.Hour, 20 * 24 * time.Hour, "tls.expiring", SevLow},
		{"45 days", -45 * 24 * time.Hour, 45 * 24 * time.Hour, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cert := ca.issue(t, []string{"www.example.com"}, c.notBefore, c.notAfter)
			res, _ := tlsScan(t, "www.example.com", &tls.Config{Certificates: []tls.Certificate{cert}}, ca)
			if c.id == "" {
				if len(res.Findings) != 0 {
					t.Fatal(ids(res.Findings))
				}
				return
			}
			wantSeverity(t, find(t, res, c.id), c.sev)
			if len(res.Findings) != 1 {
				t.Fatalf("an expired certificate should not also be reported as a chain failure: %v", ids(res.Findings))
			}
		})
	}
}

func TestTLSHostnameMismatch(t *testing.T) {
	ca := newCA(t, "Name CA")
	cert := ca.issue(t, []string{"other.example.net"}, -time.Hour, 80*24*time.Hour)
	res, _ := tlsScan(t, "www.example.com", &tls.Config{Certificates: []tls.Certificate{cert}}, ca)
	f := find(t, res, "tls.hostname_mismatch")
	wantSeverity(t, f, SevHigh)
	if names, _ := f.Evidence["dnsNames"].([]string); len(names) != 1 || names[0] != "other.example.net" {
		t.Fatalf("evidence should list the names the certificate has: %v", f.Evidence)
	}
}

func TestTLSChainFailures(t *testing.T) {
	ca := newCA(t, "Chain CA")
	t.Run("missing intermediate", func(t *testing.T) {
		cert := ca.chain(t, []string{"www.example.com"}, false)
		res, _ := tlsScan(t, "www.example.com", &tls.Config{Certificates: []tls.Certificate{cert}}, ca)
		f := find(t, res, "tls.chain_invalid")
		wantSeverity(t, f, SevMedium)
		if f.Evidence["certificatesSent"] != 1 || f.Evidence["error"] == "" {
			t.Fatalf("the exact reason is the evidence: %v", f.Evidence)
		}
	})
	t.Run("complete chain verifies", func(t *testing.T) {
		cert := ca.chain(t, []string{"www.example.com"}, true)
		res, _ := tlsScan(t, "www.example.com", &tls.Config{Certificates: []tls.Certificate{cert}}, ca)
		if len(res.Findings) != 0 {
			t.Fatal(ids(res.Findings))
		}
	})
	t.Run("self-signed", func(t *testing.T) {
		res, _ := tlsScan(t, "www.example.com", &tls.Config{Certificates: []tls.Certificate{selfSigned(t, "www.example.com")}}, ca)
		f := find(t, res, "tls.chain_invalid")
		if !strings.Contains(f.Evidence["error"].(string), "unknown authority") {
			t.Fatalf("%v", f.Evidence)
		}
	})
}

func TestTLSLegacyProtocols(t *testing.T) {
	ca := newCA(t, "Legacy CA")
	cert := ca.issue(t, []string{"old.example.com"}, -time.Hour, 80*24*time.Hour)
	// A server that still accepts everything from TLS 1.0 up.
	res, legacy := tlsScan(t, "old.example.com", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10}, ca)
	if len(res.Findings) != 0 {
		t.Fatal(ids(res.Findings))
	}
	if !legacy.Assessed {
		t.Fatalf("%+v", legacy)
	}
	got := ids(legacy.Findings)
	if len(got) != 2 || got[0] != "tls.legacy_protocol|TLS 1.0" || got[1] != "tls.legacy_protocol|TLS 1.1" {
		t.Fatalf("want both legacy versions reported, got %v (observed %v)", got, legacy.Observed)
	}
	wantSeverity(t, legacy.Findings[0], SevMedium)

	// Accepting 1.1 but not 1.0 must report only 1.1.
	cert2 := ca.issue(t, []string{"old.example.com"}, -time.Hour, 80*24*time.Hour)
	_, legacy = tlsScan(t, "old.example.com", &tls.Config{Certificates: []tls.Certificate{cert2}, MinVersion: tls.VersionTLS11}, ca)
	if got := ids(legacy.Findings); len(got) != 1 || got[0] != "tls.legacy_protocol|TLS 1.1" {
		t.Fatalf("%v (observed %v)", got, legacy.Observed)
	}
}

func TestTLSLegacyInFIPSModeIsNotAssessed(t *testing.T) {
	ca := newCA(t, "FIPS CA")
	cert := ca.issue(t, []string{"www.example.com"}, -time.Hour, 80*24*time.Hour)
	addr := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10})
	s := testScanner(hostZone("www.example.com"))
	s.Dial, s.RootCAs, s.FIPS = toLocal(addr), ca.pool, func() bool { return true }
	_, legacy := newRun(s, Asset{Kind: KindHostname, Value: "www.example.com", Authorised: true}).tlsChecks()
	if legacy.Assessed || len(legacy.Findings) != 0 || !strings.Contains(legacy.Reason, "FIPS") {
		t.Fatalf("%+v", legacy)
	}
}

func TestTLSConnectionProblemsAreMissingEvidence(t *testing.T) {
	check := func(name string, dial DialFunc, zone *FakeResolver, wantReason string) {
		t.Run(name, func(t *testing.T) {
			s := testScanner(zone)
			s.Dial = dial
			cert, legacy := newRun(s, Asset{Kind: KindHostname, Value: "www.example.com", Authorised: true}).tlsChecks()
			for _, res := range []CheckResult{cert, legacy} {
				if res.Assessed || len(res.Findings) != 0 || !strings.Contains(res.Reason, wantReason) {
					t.Fatalf("%+v, want reason containing %q", res, wantReason)
				}
			}
		})
	}
	check("refused", func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("dial tcp 192.0.2.10:443: connect: connection refused")
	}, hostZone("www.example.com"), "no HTTPS listener")
	check("timeout", func(context.Context, string, string) (net.Conn, error) { return nil, timeoutErr{} },
		hostZone("www.example.com"), "timed out")
	check("no address", nil, NewFakeResolver().Add("example.com. 300 IN A 192.0.2.1"), "no address records")
}

func TestHostnameResolvingToLoopbackIsNeverDialled(t *testing.T) {
	zone := NewFakeResolver().Add("evil.example.com. 300 IN A 127.0.0.1", "evil.example.com. 300 IN AAAA ::1")
	s := testScanner(zone)
	dialled := false
	s.Dial = func(context.Context, string, string) (net.Conn, error) {
		dialled = true
		return nil, errors.New("must not be called")
	}
	cert, _ := newRun(s, Asset{Kind: KindHostname, Value: "evil.example.com", Authorised: true}).tlsChecks()
	if dialled {
		t.Fatal("the scanner connected to a loopback address that a declared name resolved to")
	}
	if cert.Assessed || !strings.Contains(cert.Reason, "never scanned") {
		t.Fatalf("%+v", cert)
	}
}

func TestLegacyRejectionRecognition(t *testing.T) {
	for _, msg := range []string{
		"remote error: tls: protocol version not supported",
		"remote error: tls: handshake failure",
		"tls: server selected unsupported protocol version 303",
		"EOF", "read tcp: connection reset by peer",
	} {
		if !legacyRejected(errors.New(msg)) {
			t.Errorf("%q should count as a refusal", msg)
		}
	}
	for _, msg := range []string{"i/o timeout", "context deadline exceeded", "no route to host"} {
		if legacyRejected(errors.New(msg)) {
			t.Errorf("%q must not count as a refusal", msg)
		}
	}
}
