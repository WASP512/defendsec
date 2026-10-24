package surface

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestNormaliseAsset(t *testing.T) {
	good := []struct {
		kind       Kind
		in, wanted string
	}{
		{KindDomain, "Example.COM.", "example.com"},
		{KindHostname, "WWW.Example.com", "www.example.com"},
		{KindDomain, "bücher.example", "xn--bcher-kva.example"},
		{KindIP, "192.0.2.10", "192.0.2.10"},
		{KindIP, "::ffff:198.51.100.7", "198.51.100.7"},
		{KindIP, "2001:db8::1", "2001:db8::1"},
		{KindIP, "10.1.2.3", "10.1.2.3"}, // private: allowed, labelled in docs
	}
	for _, c := range good {
		got, err := NormaliseAsset(c.kind, c.in)
		if err != nil || got != c.wanted {
			t.Errorf("NormaliseAsset(%s, %q) = %q, %v; want %q", c.kind, c.in, got, err, c.wanted)
		}
	}
	bad := []struct {
		kind Kind
		in   string
	}{
		{KindDomain, ""}, {KindDomain, "https://example.com"}, {KindDomain, "example.com:443"},
		{KindDomain, "*.example.com"}, {KindDomain, "localhost"}, {KindDomain, "a b.example.com"},
		{KindDomain, "-bad.example.com"}, {KindDomain, "192.0.2.1"}, {KindDomain, "exa$mple.com"},
		{KindIP, "example.com"}, {KindIP, "127.0.0.1"}, {KindIP, "0.0.0.0"}, {KindIP, "169.254.169.254"},
		{KindIP, "::1"}, {KindIP, "224.0.0.1"}, {KindIP, "fe80::1"}, {KindIP, "192.0.2.1%eth0"},
		{Kind("url"), "example.com"},
	}
	for _, c := range bad {
		if got, err := NormaliseAsset(c.kind, c.in); err == nil {
			t.Errorf("NormaliseAsset(%s, %q) = %q, want an error", c.kind, c.in, got)
		}
	}
}

func TestNormaliseSelectors(t *testing.T) {
	got, err := NormaliseSelectors([]string{" Google ", "s1", "google", "", "k1.sub"})
	if err != nil || strings.Join(got, ",") != "google,k1.sub,s1" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"a b", "sel/ector", ".x", "a..b", strings.Repeat("a", 64)} {
		if _, err := NormaliseSelectors([]string{bad}); err == nil {
			t.Errorf("selector %q accepted", bad)
		}
	}
}

// --- MX ----------------------------------------------------------------------

func TestMXCheck(t *testing.T) {
	t.Run("provider hint and clean", func(t *testing.T) {
		f := NewFakeResolver().Add(
			"example.com. 300 IN MX 10 aspmx.l.google.com.",
			"example.com. 300 IN MX 20 alt1.aspmx.l.google.com.",
			"aspmx.l.google.com. 300 IN A 192.0.2.20",
			"alt1.aspmx.l.google.com. 300 IN A 192.0.2.21",
		)
		r := newRun(testScanner(f), domainAsset("example.com"))
		res := r.mxCheck()
		if !res.Assessed || len(res.Findings) != 0 || r.provider != "google" || !r.hasMail {
			t.Fatalf("%+v provider=%s hasMail=%v", res, r.provider, r.hasMail)
		}
	})
	t.Run("no MX is info", func(t *testing.T) {
		f := NewFakeResolver().Add("example.com. 300 IN A 192.0.2.1")
		r := newRun(testScanner(f), domainAsset("example.com"))
		res := r.mxCheck()
		wantSeverity(t, find(t, res, "mx.none"), SevInfo)
		if !r.mxKnown || r.hasMail {
			t.Fatal("a domain with no MX must be known to receive no mail")
		}
	})
	t.Run("null MX", func(t *testing.T) {
		f := NewFakeResolver().Add("example.com. 300 IN MX 0 .")
		r := newRun(testScanner(f), domainAsset("example.com"))
		res := r.mxCheck()
		find(t, res, "mx.null")
		if r.hasMail {
			t.Fatal("null MX means no mail")
		}
	})
	t.Run("host with no address, and a CNAME host", func(t *testing.T) {
		f := NewFakeResolver().Add(
			"example.com. 300 IN MX 10 gone.example.com.",
			"example.com. 300 IN MX 20 alias.example.com.",
			"alias.example.com. 300 IN CNAME real.example.net.",
			"real.example.net. 300 IN A 192.0.2.5",
			"gone.example.com. 300 IN TXT \"x\"", // exists, but no A/AAAA
		)
		res := newRun(testScanner(f), domainAsset("example.com")).mxCheck()
		wantSeverity(t, find(t, res, "mx.no_address"), SevMedium)
		wantSeverity(t, find(t, res, "mx.cname"), SevLow)
	})
	t.Run("lookup failure is missing evidence", func(t *testing.T) {
		f := NewFakeResolver().Fail("example.com", dns.TypeMX)
		r := newRun(testScanner(f), domainAsset("example.com"))
		res := r.mxCheck()
		if res.Assessed || res.Reason == "" || r.mxKnown {
			t.Fatalf("%+v", res)
		}
	})
}

// --- DMARC -------------------------------------------------------------------

func dmarcRun(t *testing.T, f *FakeResolver, domain string) (CheckResult, *run) {
	t.Helper()
	r := newRun(testScanner(f), domainAsset(domain))
	return r.dmarcCheck(), r
}

func TestDMARC(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		res, r := dmarcRun(t, NewFakeResolver().Add("example.com. 300 IN A 192.0.2.1"), "example.com")
		wantSeverity(t, find(t, res, "dmarc.missing"), SevHigh)
		if !res.Assessed || !r.dmarc.known || r.dmarc.enforced {
			t.Fatal("missing DMARC is an assessed result and not enforced")
		}
	})
	t.Run("p=none with rua is medium only", func(t *testing.T) {
		res, _ := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:r@example.com")), "example.com")
		wantSeverity(t, find(t, res, "dmarc.p_none"), SevMedium)
		noFinding(t, res, "dmarc.no_rua")
	})
	t.Run("reject is clean, unknown tags accepted", func(t *testing.T) {
		res, r := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:r@example.com; np=reject; psd=n; t=n; futuretag=1")), "example.com")
		if len(res.Findings) != 0 || !r.dmarc.enforced {
			t.Fatalf("findings %v enforced=%v", ids(res.Findings), r.dmarc.enforced)
		}
	})
	t.Run("pct under 100, no rua, weaker sp", func(t *testing.T) {
		res, _ := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=reject; sp=none; pct=25")), "example.com")
		wantSeverity(t, find(t, res, "dmarc.pct"), SevLow)
		wantSeverity(t, find(t, res, "dmarc.no_rua"), SevLow)
		wantSeverity(t, find(t, res, "dmarc.sp_weaker"), SevLow)
	})
	t.Run("pct is irrelevant under p=none", func(t *testing.T) {
		res, _ := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=none; pct=10; rua=mailto:r@example.com")), "example.com")
		noFinding(t, res, "dmarc.pct")
	})
	t.Run("organisational domain fallback names the record used", func(t *testing.T) {
		f := NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=quarantine; sp=none; rua=mailto:r@example.com"))
		res, r := dmarcRun(t, f, "mail.example.com")
		// The subdomain is governed by sp=none, so it is effectively unprotected.
		f1 := find(t, res, "dmarc.p_none")
		if f1.Evidence["source"] != "example.com" || f1.Evidence["organisationalFallback"] != true {
			t.Fatalf("evidence does not say which record applied: %v", f1.Evidence)
		}
		if r.dmarc.enforced {
			t.Fatal("sp=none leaves the subdomain unenforced")
		}
		if !f.Asked("_dmarc.mail.example.com", dns.TypeTXT) || !f.Asked("_dmarc.example.com", dns.TypeTXT) {
			t.Fatal("fallback should query the subdomain and then the organisational domain")
		}
	})
	t.Run("multiple records", func(t *testing.T) {
		res, _ := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=reject"), txt("_dmarc.example.com", "v=DMARC1; p=none")), "example.com")
		wantSeverity(t, find(t, res, "dmarc.multiple"), SevHigh)
	})
	t.Run("invalid p", func(t *testing.T) {
		res, _ := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; p=banana")), "example.com")
		wantSeverity(t, find(t, res, "dmarc.invalid"), SevHigh)
	})
	t.Run("no p but rua is treated as none", func(t *testing.T) {
		res, _ := dmarcRun(t, NewFakeResolver().Add(txt("_dmarc.example.com", "v=DMARC1; rua=mailto:r@example.com")), "example.com")
		find(t, res, "dmarc.p_none")
	})
	t.Run("lookup failure is missing evidence", func(t *testing.T) {
		res, r := dmarcRun(t, NewFakeResolver().Rcode("_dmarc.example.com", dns.TypeTXT, dns.RcodeServerFailure), "example.com")
		if res.Assessed || len(res.Findings) != 0 || r.dmarc.known {
			t.Fatalf("a SERVFAIL must not read as missing DMARC: %+v", res)
		}
	})
}

// --- SPF ---------------------------------------------------------------------

func spfRun(t *testing.T, f *FakeResolver, mutate func(*run)) CheckResult {
	t.Helper()
	r := newRun(testScanner(f), domainAsset("example.com"))
	r.mxKnown, r.hasMail = true, true
	if mutate != nil {
		mutate(r)
	}
	return r.spfCheck()
}

func TestSPFAllQualifiers(t *testing.T) {
	cases := []struct {
		rec  string
		id   string
		sev  Severity
		none bool
	}{
		{"v=spf1 ip4:192.0.2.0/24 -all", "", "", true},
		{"v=spf1 ip4:192.0.2.0/24 +all", "spf.plus_all", SevCritical, false},
		{"v=spf1 ip4:192.0.2.0/24 all", "spf.plus_all", SevCritical, false},
		{"v=spf1 ip4:192.0.2.0/24 ?all", "spf.neutral_all", SevHigh, false},
		{"v=spf1 ip4:192.0.2.0/24 ~all", "spf.softfail", SevLow, false},
		{"v=spf1 ip4:192.0.2.0/24", "spf.no_all", SevMedium, false},
	}
	for _, c := range cases {
		res := spfRun(t, NewFakeResolver().Add(txt("example.com", c.rec)), nil)
		if c.none {
			if len(res.Findings) != 0 {
				t.Errorf("%s: %v", c.rec, ids(res.Findings))
			}
			continue
		}
		wantSeverity(t, find(t, res, c.id), c.sev)
	}
}

func TestSPFSoftfailIsFineUnderEnforcedDMARC(t *testing.T) {
	f := NewFakeResolver().Add(txt("example.com", "v=spf1 ip4:192.0.2.0/24 ~all"))
	res := spfRun(t, f, func(r *run) { r.dmarc = dmarcInfo{known: true, enforced: true} })
	if len(res.Findings) != 0 {
		t.Fatalf("~all with DMARC reject is a normal setup: %v", ids(res.Findings))
	}
	res = spfRun(t, f, func(r *run) { r.dmarc = dmarcInfo{known: false} })
	if find(t, res, "spf.softfail").Detail == "" {
		t.Fatal("expected softfail when DMARC could not be read")
	}
}

func TestSPFMissing(t *testing.T) {
	f := NewFakeResolver().Add("example.com. 300 IN A 192.0.2.1")
	wantSeverity(t, find(t, spfRun(t, f, nil), "spf.missing"), SevHigh)
	wantSeverity(t, find(t, spfRun(t, f, func(r *run) { r.hasMail = false }), "spf.missing"), SevLow)
	wantSeverity(t, find(t, spfRun(t, f, func(r *run) { r.mxKnown, r.hasMail = false, false }), "spf.missing"), SevMedium)
}

func TestSPFMultipleSyntaxAndPtr(t *testing.T) {
	res := spfRun(t, NewFakeResolver().Add(txt("example.com", "v=spf1 -all"), txt("example.com", "v=spf1 +all")), nil)
	wantSeverity(t, find(t, res, "spf.multiple"), SevHigh)

	res = spfRun(t, NewFakeResolver().Add(txt("example.com", "v=spf1 ip4:300.1.1.1 frobnicate:x ip6:192.0.2.1 include -all")), nil)
	syntax := 0
	for _, f := range res.Findings {
		if f.ID == "spf.syntax" {
			syntax++
			wantSeverity(t, f, SevHigh)
		}
	}
	if syntax != 4 {
		t.Fatalf("want 4 syntax findings, got %d: %v", syntax, ids(res.Findings))
	}

	res = spfRun(t, NewFakeResolver().Add(txt("example.com", "v=spf1 ptr -all")), nil)
	wantSeverity(t, find(t, res, "spf.ptr"), SevLow)
}

func TestSPFLookupCountIsRecursive(t *testing.T) {
	// 4 includes at the top, each of which includes 2 more and has an "a": the
	// total is 4 + 8 + 4 = 16 DNS-querying terms. The top record alone has 4.
	f := NewFakeResolver().Add(txt("example.com", "v=spf1 include:s1.example.net include:s2.example.net include:s3.example.net include:s4.example.net -all"))
	for _, s := range []string{"s1", "s2", "s3", "s4"} {
		f.Add(
			txt(s+".example.net", "v=spf1 include:"+s+"a.example.org include:"+s+"b.example.org a -all"),
			txt(s+"a.example.org", "v=spf1 ip4:192.0.2.1 -all"),
			txt(s+"b.example.org", "v=spf1 ip4:192.0.2.2 -all"),
			s+".example.net. 300 IN A 192.0.2.9",
		)
	}
	res := spfRun(t, f, nil)
	fnd := find(t, res, "spf.too_many_lookups")
	wantSeverity(t, fnd, SevHigh)
	if got := res.Observed["lookups"]; got != 16 {
		t.Fatalf("lookups = %v, want 16", got)
	}
	if !strings.Contains(fnd.Detail, "16") {
		t.Fatalf("detail should state the count: %s", fnd.Detail)
	}
}

func TestSPFExactlyTenIsFine(t *testing.T) {
	var terms []string
	f := NewFakeResolver()
	for i := 0; i < 10; i++ {
		n := "inc" + string(rune('a'+i)) + ".example.net"
		terms = append(terms, "include:"+n)
		f.Add(txt(n, "v=spf1 ip4:192.0.2.1 -all"))
	}
	f.Add(txt("example.com", "v=spf1 "+strings.Join(terms, " ")+" -all"))
	res := spfRun(t, f, nil)
	noFinding(t, res, "spf.too_many_lookups")
	if res.Observed["lookups"] != 10 {
		t.Fatalf("lookups = %v", res.Observed["lookups"])
	}
}

func TestSPFVoidLookupsLoopsAndMissingIncludes(t *testing.T) {
	// Three void lookups: a nonexistent include is "missing" (a different
	// finding); here a, mx and exists names that do not resolve.
	f := NewFakeResolver().Add(txt("example.com", "v=spf1 a:gone1.example.net mx:gone2.example.net exists:gone3.example.net -all"))
	res := spfRun(t, f, nil)
	wantSeverity(t, find(t, res, "spf.void_lookups"), SevHigh)

	two := NewFakeResolver().Add(txt("example.com", "v=spf1 a:gone1.example.net mx:gone2.example.net -all"))
	noFinding(t, spfRun(t, two, nil), "spf.void_lookups")

	loop := NewFakeResolver().Add(
		txt("example.com", "v=spf1 include:a.example.net -all"),
		txt("a.example.net", "v=spf1 include:b.example.net -all"),
		txt("b.example.net", "v=spf1 include:a.example.net -all"),
	)
	wantSeverity(t, find(t, spfRun(t, loop, nil), "spf.loop"), SevHigh)

	miss := NewFakeResolver().Add(txt("example.com", "v=spf1 include:nospf.example.net -all"), txt("nospf.example.net", "hello"))
	wantSeverity(t, find(t, spfRun(t, miss, nil), "spf.include_missing"), SevHigh)
}

func TestSPFRedirect(t *testing.T) {
	f := NewFakeResolver().Add(
		txt("example.com", "v=spf1 redirect=_spf.example.net"),
		txt("_spf.example.net", "v=spf1 ip4:192.0.2.0/24 +all"),
	)
	res := spfRun(t, f, nil)
	wantSeverity(t, find(t, res, "spf.plus_all"), SevCritical) // the qualifier comes from the redirect target
	if res.Observed["lookups"] != 1 {
		t.Fatalf("redirect counts as one lookup, got %v", res.Observed["lookups"])
	}
	// redirect is ignored when the record has its own all
	f2 := NewFakeResolver().Add(txt("example.com", "v=spf1 -all redirect=_spf.example.net"))
	res = spfRun(t, f2, nil)
	if len(res.Findings) != 0 || res.Observed["lookups"] != 0 {
		t.Fatalf("%v lookups=%v", ids(res.Findings), res.Observed["lookups"])
	}
}

func TestSPFLookupFailureIsNotAssessed(t *testing.T) {
	f := NewFakeResolver().Fail("example.com", dns.TypeTXT)
	res := spfRun(t, f, nil)
	if res.Assessed || len(res.Findings) != 0 {
		t.Fatalf("a failed TXT lookup is missing evidence, not 'no SPF': %+v", res)
	}
}

// --- DKIM --------------------------------------------------------------------

func dkimTXT(sel, domain, key string) string {
	return txt(sel+"._domainkey."+domain, "v=DKIM1; k=rsa; p="+key)
}

func TestDKIM(t *testing.T) {
	t.Run("nothing found is missing evidence, not a failure", func(t *testing.T) {
		res := newRun(testScanner(NewFakeResolver().Add("example.com. 300 IN A 192.0.2.1")), domainAsset("example.com")).dkimCheck()
		if res.Assessed || len(res.Findings) != 0 {
			t.Fatalf("%+v", res)
		}
		if !strings.Contains(res.Reason, "no DKIM selector found among 9 checked") || !strings.Contains(res.Reason, "declare") {
			t.Fatalf("reason does not tell the operator what to do: %q", res.Reason)
		}
	})
	t.Run("2048 is clean, 1024 is low, 512 is high", func(t *testing.T) {
		f := NewFakeResolver().Add(
			dkimTXT("google", "example.com", dkimKey(t, 2048)),
			dkimTXT("s1", "example.com", dkimKey(t, 1024)),
			dkimTXT("s2", "example.com", dkimKey(t, 512)),
		)
		res := newRun(testScanner(f), domainAsset("example.com")).dkimCheck()
		if !res.Assessed {
			t.Fatalf("%+v", res)
		}
		wantSeverity(t, find(t, res, "dkim.key_1024"), SevLow)
		short := find(t, res, "dkim.key_short")
		wantSeverity(t, short, SevHigh)
		if short.Subject != "s2" || short.Evidence["bits"] != 512 {
			t.Fatalf("%+v", short)
		}
		if len(res.Findings) != 2 {
			t.Fatalf("2048-bit key should not be flagged: %v", ids(res.Findings))
		}
	})
	t.Run("selector reached through a CNAME", func(t *testing.T) {
		f := NewFakeResolver().Add(
			"selector1._domainkey.example.com. 300 IN CNAME selector1-example-com._domainkey.tenant.example.net.",
			txt("selector1-example-com._domainkey.tenant.example.net", "v=DKIM1; k=rsa; p="+dkimKey(t, 2048)),
		)
		res := newRun(testScanner(f), domainAsset("example.com")).dkimCheck()
		if !res.Assessed || len(res.Findings) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("declared selector that does not exist", func(t *testing.T) {
		f := NewFakeResolver().Add(dkimTXT("google", "example.com", dkimKey(t, 2048)))
		a := domainAsset("example.com")
		a.DKIMSelectors = []string{"mailgun"}
		res := newRun(testScanner(f), a).dkimCheck()
		fnd := find(t, res, "dkim.declared_missing")
		wantSeverity(t, fnd, SevMedium)
		if fnd.Subject != "mailgun" {
			t.Fatal(fnd.Subject)
		}
	})
	t.Run("declared selector that is found", func(t *testing.T) {
		f := NewFakeResolver().Add(dkimTXT("mailgun", "example.com", dkimKey(t, 2048)))
		a := domainAsset("example.com")
		a.DKIMSelectors = []string{"mailgun"}
		res := newRun(testScanner(f), a).dkimCheck()
		if !res.Assessed || len(res.Findings) != 0 {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("revoked key", func(t *testing.T) {
		f := NewFakeResolver().Add(txt("google._domainkey.example.com", "v=DKIM1; k=rsa; p="))
		res := newRun(testScanner(f), domainAsset("example.com")).dkimCheck()
		wantSeverity(t, find(t, res, "dkim.revoked"), SevInfo)
	})
	t.Run("garbage key", func(t *testing.T) {
		f := NewFakeResolver().Add(txt("google._domainkey.example.com", "v=DKIM1; p=!!!notbase64"), txt("s1._domainkey.example.com", "v=DKIM1; p=AAAA"))
		res := newRun(testScanner(f), domainAsset("example.com")).dkimCheck()
		n := 0
		for _, f := range res.Findings {
			if f.ID == "dkim.key_invalid" {
				n++
			}
		}
		if n != 2 {
			t.Fatalf("%v", ids(res.Findings))
		}
	})
	t.Run("failed lookups make the result partial", func(t *testing.T) {
		f := NewFakeResolver().Add(dkimTXT("google", "example.com", dkimKey(t, 2048))).Fail("s1._domainkey.example.com", dns.TypeTXT)
		res := newRun(testScanner(f), domainAsset("example.com")).dkimCheck()
		if res.Assessed {
			t.Fatal("a result with failed lookups must not claim to be complete")
		}
	})
}

// --- TLS-RPT -----------------------------------------------------------------

func TestTLSRPT(t *testing.T) {
	mail := func(r *run) { r.mxKnown, r.hasMail = true, true }
	r := newRun(testScanner(NewFakeResolver()), domainAsset("example.com"))
	mail(r)
	wantSeverity(t, find(t, r.tlsrptCheck(), "tlsrpt.missing"), SevInfo)

	r = newRun(testScanner(NewFakeResolver().Add(txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=mailto:t@example.com"))), domainAsset("example.com"))
	mail(r)
	if res := r.tlsrptCheck(); len(res.Findings) != 0 {
		t.Fatal(ids(res.Findings))
	}
	r = newRun(testScanner(NewFakeResolver().Add(txt("_smtp._tls.example.com", "v=TLSRPTv1; rua=ftp://nope"))), domainAsset("example.com"))
	mail(r)
	wantSeverity(t, find(t, r.tlsrptCheck(), "tlsrpt.invalid"), SevLow)

	// no mail: nothing to report on
	r = newRun(testScanner(NewFakeResolver()), domainAsset("example.com"))
	r.mxKnown = true
	if res := r.tlsrptCheck(); len(res.Findings) != 0 || !res.Assessed {
		t.Fatalf("%+v", res)
	}
}

func TestSPFLimitIsExactlyTen(t *testing.T) {
	build := func(n int) *FakeResolver {
		f := NewFakeResolver()
		var terms []string
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("inc%d.example.net", i)
			terms = append(terms, "include:"+name)
			f.Add(txt(name, "v=spf1 ip4:192.0.2.1 -all"))
		}
		return f.Add(txt("example.com", "v=spf1 "+strings.Join(terms, " ")+" -all"))
	}
	noFinding(t, spfRun(t, build(10), nil), "spf.too_many_lookups")
	find(t, spfRun(t, build(11), nil), "spf.too_many_lookups")
}

// Two branches that include the same domain are not a loop: RFC 7208 counts the
// repeated lookups, and only a domain that includes itself through its own
// chain is a permanent error.
func TestSPFRepeatedIncludeIsNotALoop(t *testing.T) {
	f := NewFakeResolver().Add(
		txt("example.com", "v=spf1 include:a.example.net include:b.example.net -all"),
		txt("a.example.net", "v=spf1 include:shared.example.org -all"),
		txt("b.example.net", "v=spf1 include:shared.example.org -all"),
		txt("shared.example.org", "v=spf1 ip4:192.0.2.0/24 -all"),
	)
	res := spfRun(t, f, nil)
	noFinding(t, res, "spf.loop")
	if len(res.Findings) != 0 {
		t.Fatalf("%v", ids(res.Findings))
	}
	if res.Observed["lookups"] != 4 {
		t.Fatalf("a, b, and shared twice = 4 lookups, got %v", res.Observed["lookups"])
	}
}
