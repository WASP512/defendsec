package surface

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- MTA-STS -----------------------------------------------------------------

// stsServer serves path /.well-known/mta-sts.txt over HTTPS with a certificate
// for mta-sts.<domain> issued by a private CA, and returns a scanner whose
// dials reach it and whose roots trust that CA.
func stsScanner(t *testing.T, f *FakeResolver, handler http.HandlerFunc) *Scanner {
	t.Helper()
	ca := newCA(t, "STS Test CA")
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.issue(t, []string{"mta-sts.example.com"}, -time.Hour, 60*24*time.Hour)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s := testScanner(f)
	s.Dial = toLocal(srv.Listener.Addr().String())
	s.RootCAs = ca.pool
	return s
}

func policy(lines ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Join(lines, "\r\n") + "\r\n"))
	}
}

func stsZone() *FakeResolver {
	return NewFakeResolver().Add(
		txt("_mta-sts.example.com", "v=STSv1; id=20261024"),
		"mta-sts.example.com. 300 IN A 192.0.2.30",
		"example.com. 300 IN MX 10 mx1.example.com.",
		"example.com. 300 IN MX 20 mx2.mail.example.net.",
		"mx1.example.com. 300 IN A 192.0.2.31",
		"mx2.mail.example.net. 300 IN A 192.0.2.32",
	)
}

func runSTS(t *testing.T, s *Scanner) CheckResult {
	t.Helper()
	r := newRun(s, domainAsset("example.com"))
	if res := r.mxCheck(); !res.Assessed {
		t.Fatalf("mx: %+v", res)
	}
	return r.mtastsCheck()
}

func TestMTASTSEnforcingPolicyCoveringEveryMX(t *testing.T) {
	s := stsScanner(t, stsZone(), policy("version: STSv1", "mode: enforce", "mx: mx1.example.com", "mx: *.mail.example.net", "max_age: 604800"))
	res := runSTS(t, s)
	if !res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("%+v", res)
	}
	if res.Observed["mode"] != "enforce" || res.Observed["httpStatus"] != 200 {
		t.Fatalf("observation does not keep what was fetched: %v", res.Observed)
	}
	if !strings.Contains(res.Observed["policy"].(string), "mx1.example.com") {
		t.Fatal("the raw policy text must be stored")
	}
}

func TestMTASTSTestingModeAndUncoveredMX(t *testing.T) {
	s := stsScanner(t, stsZone(), policy("version: STSv1", "mode: testing", "mx: mx1.example.com", "max_age: 86400"))
	res := runSTS(t, s)
	wantSeverity(t, find(t, res, "mtasts.mode_testing"), SevLow)
	miss := find(t, res, "mtasts.mx_not_covered")
	wantSeverity(t, miss, SevMedium)
	if miss.Subject != "mx2.mail.example.net" {
		t.Fatal(miss.Subject)
	}
}

func TestMTASTSWildcardMatchesOneLabelOnly(t *testing.T) {
	for _, c := range []struct {
		pat, host string
		want      bool
	}{
		{"*.example.com", "mx.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "a.b.example.com", false},
		{"mx.example.com", "MX.example.com", true},
		{"mx.example.com", "mx2.example.com", false},
	} {
		if got := stsMatches(c.pat, c.host); got != c.want {
			t.Errorf("stsMatches(%q, %q) = %v", c.pat, c.host, got)
		}
	}
}

func TestMTASTSPolicyProblems(t *testing.T) {
	cases := map[string]struct {
		h  http.HandlerFunc
		id string
	}{
		"404": {func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, "mtasts.policy_unreachable"},
		"redirect is not followed": {func(w http.ResponseWriter, r *http.Request) {
			// The target is a perfectly good policy: following the redirect would pass, refusing it must not.
			if r.URL.Path == "/real" {
				_, _ = w.Write([]byte("version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: *.mail.example.net\nmax_age: 604800\n"))
				return
			}
			http.Redirect(w, r, "https://mta-sts.example.com/real", http.StatusFound)
		}, "mtasts.policy_unreachable"},
		"bad mode":      {policy("version: STSv1", "mode: maybe", "mx: mx1.example.com", "max_age: 1"), "mtasts.policy_invalid"},
		"no max_age":    {policy("version: STSv1", "mode: enforce", "mx: mx1.example.com"), "mtasts.policy_invalid"},
		"huge max_age":  {policy("version: STSv1", "mode: enforce", "mx: mx1.example.com", "max_age: 99999999999"), "mtasts.policy_invalid"},
		"no mx lines":   {policy("version: STSv1", "mode: enforce", "max_age: 1"), "mtasts.policy_invalid"},
		"wrong version": {policy("version: STSv2", "mode: enforce", "mx: a.example.com", "max_age: 1"), "mtasts.policy_invalid"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			res := runSTS(t, stsScanner(t, stsZone(), c.h))
			wantSeverity(t, find(t, res, c.id), SevMedium)
		})
	}
}

func TestMTASTSCertificateThatDoesNotVerify(t *testing.T) {
	s := stsScanner(t, stsZone(), policy("version: STSv1", "mode: enforce", "mx: mx1.example.com", "max_age: 1"))
	s.RootCAs = x509.NewCertPool() // trust nobody
	res := runSTS(t, s)
	f := find(t, res, "mtasts.policy_unreachable")
	if !strings.Contains(f.Detail, "certificate") {
		t.Fatalf("detail should name the certificate failure: %s", f.Detail)
	}
}

func TestMTASTSHostMissingAndUnreachable(t *testing.T) {
	// The TXT record exists but mta-sts.example.com has no address: a definite problem.
	f := NewFakeResolver().Add(txt("_mta-sts.example.com", "v=STSv1; id=1"), "example.com. 300 IN MX 10 mx1.example.com.", "mx1.example.com. 300 IN A 192.0.2.31")
	res := runSTS(t, testScanner(f))
	wantSeverity(t, find(t, res, "mtasts.policy_unreachable"), SevMedium)

	// A timeout reaching the host is not proof of anything.
	s := stsScanner(t, stsZone(), policy())
	s.Dial = func(_ context.Context, _, _ string) (net.Conn, error) { return nil, timeoutErr{} }
	res = runSTS(t, s)
	if res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("a connect timeout must be missing evidence: %+v", res)
	}
}

func TestMTASTSMissingAndMalformedRecords(t *testing.T) {
	mail := func(f *FakeResolver) *run {
		r := newRun(testScanner(f), domainAsset("example.com"))
		r.mxKnown, r.hasMail = true, true
		return r
	}
	wantSeverity(t, find(t, mail(NewFakeResolver()).mtastsCheck(), "mtasts.missing"), SevLow)

	r := newRun(testScanner(NewFakeResolver()), domainAsset("example.com"))
	r.mxKnown = true // no mail: MTA-STS does not apply
	if res := r.mtastsCheck(); len(res.Findings) != 0 || !res.Assessed {
		t.Fatalf("%+v", res)
	}
	wantSeverity(t, find(t, mail(NewFakeResolver().Add(txt("_mta-sts.example.com", "v=STSv1"))).mtastsCheck(), "mtasts.invalid"), SevMedium)
	two := NewFakeResolver().Add(txt("_mta-sts.example.com", "v=STSv1; id=1"), txt("_mta-sts.example.com", "v=STSv1; id=2"))
	wantSeverity(t, find(t, mail(two).mtastsCheck(), "mtasts.invalid"), SevMedium)
	res := mail(NewFakeResolver().Fail("_mta-sts.example.com", dns.TypeTXT)).mtastsCheck()
	if res.Assessed {
		t.Fatal("a failed lookup is not 'no MTA-STS'")
	}
}

// --- DNSSEC ------------------------------------------------------------------

func TestDNSSEC(t *testing.T) {
	ds := "example.com. 300 IN DS 12345 13 2 49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD46E6C4B45C55D4AC49FD"
	soa := "example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"
	t.Run("unsigned is info", func(t *testing.T) {
		f := NewFakeResolver().Add(soa)
		res := newRun(testScanner(f), domainAsset("example.com")).dnssecCheck()
		wantSeverity(t, find(t, res, "dnssec.unsigned"), SevInfo)
		if !res.Assessed {
			t.Fatal("unsigned is an assessed result")
		}
	})
	t.Run("signed and validated", func(t *testing.T) {
		f := NewFakeResolver().Add(soa, ds).Validated("example.com", dns.TypeSOA)
		res := newRun(testScanner(f), domainAsset("example.com")).dnssecCheck()
		if !res.Assessed || len(res.Findings) != 0 || res.Observed["validated"] != true || res.Observed["resolver"] != "fake-validating" {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("bogus chain is high", func(t *testing.T) {
		f := NewFakeResolver().Add(soa, ds).Bogus("example.com")
		res := newRun(testScanner(f), domainAsset("example.com")).dnssecCheck()
		wantSeverity(t, find(t, res, "dnssec.broken"), SevHigh)
		if res.Observed["withChecksDisabled"] != "ok" {
			t.Fatalf("the CD retry is the evidence: %v", res.Observed)
		}
	})
	t.Run("SERVFAIL even with checking disabled is an outage, not a chain failure", func(t *testing.T) {
		f := NewFakeResolver().Add(soa, ds).Rcode("example.com", dns.TypeSOA, dns.RcodeServerFailure)
		res := newRun(testScanner(f), domainAsset("example.com")).dnssecCheck()
		if res.Assessed || len(res.Findings) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("resolver that does not set AD proves nothing", func(t *testing.T) {
		f := NewFakeResolver().Add(soa, ds) // no Validated()
		res := newRun(testScanner(f), domainAsset("example.com")).dnssecCheck()
		if res.Assessed || len(res.Findings) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("DS lookup failure", func(t *testing.T) {
		f := NewFakeResolver().Fail("example.com", dns.TypeDS)
		if res := newRun(testScanner(f), domainAsset("example.com")).dnssecCheck(); res.Assessed {
			t.Fatal("assessed despite a failed lookup")
		}
	})
}

// --- CAA and dangling CNAME --------------------------------------------------

func TestCAA(t *testing.T) {
	f := NewFakeResolver().Add("example.com. 300 IN A 192.0.2.1")
	res := newRun(testScanner(f), domainAsset("www.example.com")).caaCheck()
	wantSeverity(t, find(t, res, "caa.missing"), SevLow)
	if tried := res.Observed["tried"].([]string); len(tried) != 2 || tried[1] != "example.com" {
		t.Fatalf("CAA climbs to the organisational domain and stops: %v", tried)
	}

	f = NewFakeResolver().Add(`example.com. 300 IN CAA 0 issue "letsencrypt.org"`)
	res = newRun(testScanner(f), domainAsset("www.example.com")).caaCheck()
	if len(res.Findings) != 0 || res.Observed["foundAt"] != "example.com" {
		t.Fatalf("a CAA set on the parent applies to the child: %+v", res)
	}

	f = NewFakeResolver().Fail("example.com", dns.TypeCAA)
	if res := newRun(testScanner(f), domainAsset("example.com")).caaCheck(); res.Assessed {
		t.Fatal("a failed CAA lookup is not 'no CAA'")
	}
}

func TestDanglingCNAME(t *testing.T) {
	f := NewFakeResolver().Add("shop.example.com. 300 IN CNAME acme-shop.azurewebsites.net.")
	res := newRun(testScanner(f), Asset{Kind: KindHostname, Value: "shop.example.com", Authorised: true}).cnameCheck()
	fnd := find(t, res, "cname.dangling")
	wantSeverity(t, fnd, SevMedium)
	if !strings.Contains(fnd.Detail, "does not exist") || !strings.Contains(fnd.Detail, "Azure App Service") {
		t.Fatalf("%s", fnd.Detail)
	}
	if strings.Contains(strings.ToLower(fnd.Detail+fnd.Title+fnd.Fix), "takeover is possible") || strings.Contains(strings.ToLower(fnd.Detail), "can be taken over") {
		t.Fatalf("the finding claims a takeover it has no evidence for: %s", fnd.Detail)
	}

	// CNAME to a target that exists: no finding.
	f = NewFakeResolver().Add("www.example.com. 300 IN CNAME example.com.", "example.com. 300 IN A 192.0.2.1")
	res = newRun(testScanner(f), Asset{Kind: KindHostname, Value: "www.example.com", Authorised: true}).cnameCheck()
	if len(res.Findings) != 0 || !res.Assessed {
		t.Fatalf("%+v", res)
	}
	// A name with no CNAME at all.
	f = NewFakeResolver().Add("www.example.com. 300 IN A 192.0.2.1")
	if res := newRun(testScanner(f), Asset{Kind: KindHostname, Value: "www.example.com", Authorised: true}).cnameCheck(); len(res.Findings) != 0 {
		t.Fatal(ids(res.Findings))
	}
	// Lookup failure.
	f = NewFakeResolver().Fail("www.example.com", dns.TypeA)
	if res := newRun(testScanner(f), Asset{Kind: KindHostname, Value: "www.example.com", Authorised: true}).cnameCheck(); res.Assessed {
		t.Fatal("assessed despite failed lookup")
	}
}
