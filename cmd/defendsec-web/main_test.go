package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"defendsec/internal/webtls"
)

// The console decides cookie flags and builds absolute URLs from these
// headers, so a proxy that does not set them turns Secure cookies off exactly
// when TLS is on.
func TestProxyForwardsSchemeAndHost(t *testing.T) {
	var gotProto, gotHost, gotFor string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotProto = r.Header.Get("X-Forwarded-Proto")
		gotHost = r.Header.Get("X-Forwarded-Host")
		gotFor = r.Header.Get("X-Forwarded-For")
		_, _ = io.WriteString(w, "console")
	}))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	front := httptest.NewServer(newProxy(target, true))
	defer front.Close()

	res, err := http.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "console" {
		t.Fatalf("body = %q", body)
	}
	if gotProto != "https" {
		t.Errorf("X-Forwarded-Proto = %q, want https — the console would drop the Secure cookie flag", gotProto)
	}
	if gotHost == "" {
		t.Error("X-Forwarded-Host is empty; the console would build URLs pointing at loopback")
	}
	if gotFor == "" {
		t.Error("X-Forwarded-For is empty; the real client address is lost")
	}
	// HSTS only over HTTPS.
	if res.Header.Get("Strict-Transport-Security") == "" {
		t.Error("no HSTS header on a secure front-end")
	}
}

// Sending HSTS from a lab deployment would pin browsers to a scheme that
// deployment does not serve.
func TestPlainModeDoesNotSendHSTS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Forwarded-Proto"); got != "http" {
			t.Errorf("X-Forwarded-Proto = %q, want http", got)
		}
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)

	front := httptest.NewServer(newProxy(target, false))
	defer front.Close()

	res, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Strict-Transport-Security") != "" {
		t.Error("a plain-HTTP front-end sent HSTS")
	}
}

// A console that is down must say so, rather than surfacing as an opaque
// failure that looks like the console's own error.
func TestUpstreamDownGivesAnActionableError(t *testing.T) {
	target, _ := url.Parse("http://127.0.0.1:1")
	front := httptest.NewServer(newProxy(target, true))
	defer front.Close()

	res, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "systemctl status defendsec-console") {
		t.Errorf("the error does not say what to check: %q", body)
	}
}

// End to end: a real TLS handshake against a generated certificate, proxied
// through to the console.
func TestServesRealHTTPS(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "console over tls")
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)

	provider, err := webtls.New(webtls.Config{
		Mode: webtls.ModeSelfSigned, Dir: t.TempDir(), Hosts: []string{"localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := provider.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	// httptest.StartTLS installs its own certificate when Certificates is
	// empty, which would test its cert rather than ours. Materialise the
	// generated one so the server really serves it.
	cert, err := tlsCfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg = tlsCfg.Clone()
	tlsCfg.Certificates = []tls.Certificate{*cert}
	tlsCfg.GetCertificate = nil

	front := httptest.NewUnstartedServer(newProxy(target, true))
	front.TLS = tlsCfg
	front.StartTLS()
	defer front.Close()

	// Trust only the generated certificate: this also proves it is the one
	// actually served, not whatever the test client would otherwise accept.
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	res, err := client.Get(front.URL + "/")
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "console over tls" {
		t.Fatalf("body = %q", body)
	}
	if res.TLS == nil || res.TLS.Version < tls.VersionTLS12 {
		t.Error("the connection was not TLS 1.2 or better")
	}
}

// A permanent redirect is cached indefinitely, so an operator who later turns
// TLS off for a lab would find the console unreachable with no obvious cause.
func TestRedirectIsTemporary(t *testing.T) {
	rec := httptest.NewRecorder()
	redirectToHTTPS(rec, httptest.NewRequest(http.MethodGet, "http://console.example/login?x=1", nil), ":47261")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://console.example:47261") {
		t.Errorf("Location = %q, want the HTTPS port carried across", loc)
	}

	// The default HTTPS port is omitted, because a browser assumes it.
	rec = httptest.NewRecorder()
	redirectToHTTPS(rec, httptest.NewRequest(http.MethodGet, "http://console.example/", nil), ":443")
	if got := rec.Header().Get("Location"); got != "https://console.example/" {
		t.Errorf("Location = %q, want no explicit :443", got)
	}
	// The path and query must survive, or a bookmarked deep link lands on the
	// dashboard instead.
	if !strings.HasSuffix(loc, "/login?x=1") {
		t.Errorf("the redirect dropped the path or query: %q", loc)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("DEFENDSEC_TEST_ENV", "  value  ")
	if got := envOr("DEFENDSEC_TEST_ENV", "fallback"); got != "value" {
		t.Errorf("envOr = %q", got)
	}
	t.Setenv("DEFENDSEC_TEST_ENV", "   ")
	if got := envOr("DEFENDSEC_TEST_ENV", "fallback"); got != "fallback" {
		t.Errorf("a blank value did not fall back: %q", got)
	}

	if got := splitHosts(" a.example , b.example ,, "); len(got) != 2 || got[0] != "a.example" {
		t.Errorf("splitHosts = %v", got)
	}
	for _, yes := range []string{"1", "true", "YES", "on"} {
		if !truthy(yes) {
			t.Errorf("truthy(%q) = false", yes)
		}
	}
	for _, no := range []string{"", "0", "false", "maybe"} {
		if truthy(no) {
			t.Errorf("truthy(%q) = true", no)
		}
	}
}
