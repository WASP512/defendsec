package graph_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/m365/graph"
	"defendsec/internal/m365/m365test"
)

type sleeper struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleeper) sleep(_ context.Context, d time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.d = append(s.d, d)
	return nil
}

func newClient(t *testing.T, srv *m365test.Server, mod func(*graph.Config)) (*graph.Client, *sleeper) {
	t.Helper()
	sl := &sleeper{}
	cfg := srv.Config()
	cfg.Sleep = sl.sleep
	if mod != nil {
		mod(&cfg)
	}
	c, err := graph.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, sl
}

type shell struct {
	Value []struct {
		ID string `json:"id"`
	} `json:"value"`
}

func TestTokenIsCachedAndOnlyGETsReachGraph(t *testing.T) {
	srv := m365test.New(t)
	c, _ := newClient(t, srv, nil)
	for i := 0; i < 3; i++ {
		var out shell
		if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil || len(out.Value) != 3 {
			t.Fatalf("get %d: %v (%d roles)", i, err, len(out.Value))
		}
	}
	if n := srv.TokenRequests(); n != 1 {
		t.Errorf("token requests = %d, want 1 (cached)", n)
	}
	if c.Requests() != 3 {
		t.Errorf("Requests() = %d, want 3", c.Requests())
	}
	for _, r := range srv.Requests() {
		if r.Method != http.MethodGet {
			t.Errorf("a %s request reached Graph: %s", r.Method, r.Path)
		}
		if strings.Contains(r.Query, "fixture-client-secret") {
			t.Errorf("the secret is in a Graph query")
		}
	}
}

func TestPagingFollowsNextLinkAndRefusesForeignHosts(t *testing.T) {
	srv := m365test.New(t)
	c, _ := newClient(t, srv, nil)
	var ids []string
	if err := c.Each(context.Background(), "/users", nil, func(raw json.RawMessage) error {
		var u struct{ ID string }
		_ = json.Unmarshal(raw, &u)
		ids = append(ids, u.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 9 {
		t.Errorf("read %d users over two pages, want 9", len(ids))
	}

	// A nextLink to another host must not receive the bearer token.
	var foreignHits int
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignHits++ }))
	defer foreign.Close()
	srv.Override["/users"] = `{"value":[{"id":"x"}],"@odata.nextLink":"` + foreign.URL + `/v1.0/users?page=2"}`
	err := c.Each(context.Background(), "/users", nil, func(json.RawMessage) error { return nil })
	if graph.KindOf(err) != graph.KindBadResponse || foreignHits != 0 {
		t.Errorf("foreign nextLink: err=%v hits=%d, want a refusal and no request", err, foreignHits)
	}
}

func TestCredentialsRefusedIsClassifiedAndNeverEchoesTheSecret(t *testing.T) {
	srv := m365test.New(t)
	srv.RejectToken = true
	c, _ := newClient(t, srv, nil)
	var out shell
	err := c.Get(context.Background(), "/users", nil, &out)
	if graph.KindOf(err) != graph.KindCredentials || graph.CodeOf(err) != "AADSTS7000215" {
		t.Fatalf("err = %v, want credentials / AADSTS7000215", err)
	}
	if strings.Contains(err.Error(), m365test.ClientSecret) || strings.Contains(graph.Reason(err), m365test.ClientSecret) {
		t.Error("the secret is in the error text")
	}
	if strings.Contains(err.Error(), "Trace ID") {
		t.Errorf("the trace id line was kept: %v", err)
	}
	if srv.Count("/") != 0 {
		t.Error("a Graph request was made without a token")
	}
}

func TestUnauthorizedRefreshesTheTokenOnce(t *testing.T) {
	srv := m365test.New(t)
	c, _ := newClient(t, srv, nil)
	var out shell
	if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil {
		t.Fatal(err)
	}
	srv.RevokeTokens() // the cached token is now refused
	if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil {
		t.Fatalf("after revocation: %v", err)
	}
	if n := srv.TokenRequests(); n != 2 {
		t.Errorf("token requests = %d, want 2 (one refresh)", n)
	}

	// A token that is refused even when fresh is reported, not retried forever.
	srv.Fail("*", 401, -1, nil)
	err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out)
	if graph.KindOf(err) != graph.KindUnauthorized {
		t.Errorf("err = %v, want unauthorized", err)
	}
	if n := srv.TokenRequests(); n > 4 {
		t.Errorf("token requests = %d: the refresh is not bounded", n)
	}
}

func TestForbiddenIsNotRetried(t *testing.T) {
	srv := m365test.New(t)
	srv.FailBody("/reports/authenticationMethods/userRegistrationDetails", 403, -1, nil,
		`{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"Neither tenant is B2C or tenant doesn't have premium license\r\nRequest ID: 0000"}}`)
	c, sl := newClient(t, srv, nil)
	var out shell
	err := c.Get(context.Background(), "/reports/authenticationMethods/userRegistrationDetails", nil, &out)
	if graph.KindOf(err) != graph.KindForbidden || graph.CodeOf(err) != "Authentication_RequestFromNonPremiumTenantOrB2CTenant" {
		t.Fatalf("err = %v", err)
	}
	if n := srv.Count("/reports"); n != 1 || len(sl.d) != 0 {
		t.Errorf("requests = %d sleeps = %v, want one request and no waiting", n, sl.d)
	}
	if strings.Contains(err.Error(), "Request ID") {
		t.Errorf("only the first line of Graph's message is kept: %v", err)
	}
}

func TestThrottlingHonoursRetryAfter(t *testing.T) {
	srv := m365test.New(t)
	srv.Fail("/roleManagement/directory/roleDefinitions", 429, 2, map[string]string{"Retry-After": "7"})
	c, sl := newClient(t, srv, nil)
	var out shell
	if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil || len(out.Value) != 3 {
		t.Fatalf("after two 429s: %v", err)
	}
	if len(sl.d) != 2 || sl.d[0] != 7*time.Second || sl.d[1] != 7*time.Second {
		t.Errorf("waited %v, want 7s twice", sl.d)
	}
}

func TestThrottlingThatNeverClearsFailsClosed(t *testing.T) {
	srv := m365test.New(t)
	srv.Fail("/users", 429, -1, map[string]string{"Retry-After": "2"})
	c, sl := newClient(t, srv, nil)
	err := c.Each(context.Background(), "/users", nil, func(json.RawMessage) error { return nil })
	if graph.KindOf(err) != graph.KindThrottled {
		t.Fatalf("err = %v, want throttled", err)
	}
	if n := srv.Count("/users"); n != 4 || len(sl.d) != 3 {
		t.Errorf("requests = %d, sleeps = %d, want 4 and 3 (MaxAttempts)", n, len(sl.d))
	}

	// A Retry-After longer than we will wait is reported at once.
	srv2 := m365test.New(t)
	srv2.Fail("/users", 429, -1, map[string]string{"Retry-After": "3600"})
	c2, sl2 := newClient(t, srv2, nil)
	err = c2.Each(context.Background(), "/users", nil, func(json.RawMessage) error { return nil })
	if graph.KindOf(err) != graph.KindThrottled || len(sl2.d) != 0 || srv2.Count("/users") != 1 {
		t.Errorf("long Retry-After: err=%v sleeps=%v requests=%d, want an immediate throttled error", err, sl2.d, srv2.Count("/users"))
	}
}

func TestServerErrorsRetryThenFail(t *testing.T) {
	srv := m365test.New(t)
	srv.Fail("/roleManagement/directory/roleDefinitions", 503, 1, nil)
	c, _ := newClient(t, srv, nil)
	var out shell
	if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil {
		t.Fatalf("one 503 then ok: %v", err)
	}
	srv.Fail("/users", 500, -1, nil)
	err := c.Each(context.Background(), "/users", nil, func(json.RawMessage) error { return nil })
	if graph.KindOf(err) != graph.KindServer {
		t.Errorf("err = %v, want server", err)
	}
}

func TestRequestBudgetStopsARunawayRead(t *testing.T) {
	srv := m365test.New(t)
	c, _ := newClient(t, srv, func(c *graph.Config) { c.MaxRequests = 2 })
	var out shell
	for i := 0; i < 2; i++ {
		if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil {
			t.Fatal(err)
		}
	}
	err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out)
	if graph.KindOf(err) != graph.KindThrottled || srv.Count("/roleManagement") != 2 {
		t.Errorf("err = %v after %d requests, want the budget to stop the third", err, srv.Count("/roleManagement"))
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer other.Close()
	srv := m365test.New(t)
	srv.Fail("/users", 302, -1, map[string]string{"Location": other.URL + "/steal"})
	c, _ := newClient(t, srv, nil)
	err := c.Each(context.Background(), "/users", nil, func(json.RawMessage) error { return nil })
	if err == nil || hits != 0 {
		t.Errorf("err = %v, redirected hits = %d: a redirect must not carry the token anywhere", err, hits)
	}
}

func TestConfigValidation(t *testing.T) {
	srv := m365test.New(t)
	base := srv.Config()
	cases := map[string]func(*graph.Config){
		"tenant common":        func(c *graph.Config) { c.TenantID = "common" },
		"tenant organizations": func(c *graph.Config) { c.TenantID = "organizations" },
		"tenant with a slash":  func(c *graph.Config) { c.TenantID = "contoso.com/../x" },
		"tenant empty":         func(c *graph.Config) { c.TenantID = "" },
		"client id not a guid": func(c *graph.Config) { c.ClientID = "not-a-guid" },
		"no credential":        func(c *graph.Config) { c.Secret = "" },
		"login over http":      func(c *graph.Config) { c.LoginURL = "http://login.example.com" },
		"graph with userinfo":  func(c *graph.Config) { c.GraphURL = "https://u:p@graph.example.com" },
	}
	for name, mod := range cases {
		cfg := base
		mod(&cfg)
		if _, err := graph.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, ok := range []string{"contoso.onmicrosoft.com", "contoso.com", m365test.TenantID} {
		cfg := base
		cfg.TenantID = ok
		if _, err := graph.New(cfg); err != nil {
			t.Errorf("tenant %q refused: %v", ok, err)
		}
	}
	both := base
	both.Cert = &graph.Certificate{}
	if _, err := graph.New(both); err == nil {
		t.Error("a secret and a certificate together were accepted")
	}
	if _, err := graph.ParseCloud("mars"); err == nil {
		t.Error("an unknown cloud was accepted")
	}
	if c, err := graph.ParseCloud(""); err != nil || c != graph.CloudGlobal {
		t.Errorf("empty cloud = %v, %v, want global", c, err)
	}
}

// testCert makes an RSA key and a self-signed certificate, as a PEM bundle.
func testCert(t *testing.T) (bundle []byte, der []byte, pub *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "defendsec-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	k8, _ := x509.MarshalPKCS8PrivateKey(key)
	bundle = append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k8}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	return bundle, der, &key.PublicKey
}

func TestCertificateCredentialSignsAValidAssertion(t *testing.T) {
	bundle, der, pub := testCert(t)
	cert, err := graph.ParseCertificatePEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Thumbprint()) != 64 {
		t.Errorf("thumbprint %q is not 64 hex characters", cert.Thumbprint())
	}
	s256, s1 := sha256.Sum256(der), sha1.Sum(der)
	if cert.Thumbprint() != strings.ToUpper(hex.EncodeToString(s256[:])) || cert.ThumbprintSHA1() != strings.ToUpper(hex.EncodeToString(s1[:])) {
		t.Errorf("thumbprints %s / %s are not the SHA-256 / SHA-1 of the certificate", cert.Thumbprint(), cert.ThumbprintSHA1())
	}
	srv := m365test.New(t)
	srv.CertDER, srv.CertPub = der, pub
	c, _ := newClient(t, srv, func(c *graph.Config) { c.Secret, c.Cert = "", cert })
	var out shell
	// Two token fetches, so the jti must differ (the server rejects a replay).
	for i := 0; i < 2; i++ {
		if err := c.Get(context.Background(), "/roleManagement/directory/roleDefinitions", nil, &out); err != nil {
			t.Fatalf("certificate sign-in %d: %v", i, err)
		}
		srv.RevokeTokens()
	}
	if srv.TokenRequests() != 2 {
		t.Errorf("token requests = %d, want 2", srv.TokenRequests())
	}

	// The same server refuses a client secret: it is a certificate-only app here.
	c2, _ := newClient(t, srv, nil)
	if err := c2.Get(context.Background(), "/users", nil, &out); graph.KindOf(err) != graph.KindCredentials {
		t.Errorf("secret against a certificate app: %v, want a credentials error", err)
	}
}

func TestParseCertificatePEMRefusesBadBundles(t *testing.T) {
	bundle, _, _ := testCert(t)
	other, _, _ := testCert(t)
	blocks := func(b []byte) (keyPart, certPart []byte) {
		for rest := b; ; {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				return
			}
			if blk.Type == "CERTIFICATE" {
				certPart = pem.EncodeToMemory(blk)
			} else {
				keyPart = pem.EncodeToMemory(blk)
			}
		}
	}
	k1, c1 := blocks(bundle)
	_, c2 := blocks(other)
	for name, in := range map[string][]byte{
		"key only":            k1,
		"certificate only":    c1,
		"mismatched pair":     append(append([]byte{}, k1...), c2...),
		"not pem":             []byte("hello"),
		"encrypted key block": []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"),
	} {
		if _, err := graph.ParseCertificatePEM(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Either order is fine.
	if _, err := graph.ParseCertificatePEM(append(append([]byte{}, c1...), k1...)); err != nil {
		t.Errorf("certificate first: %v", err)
	}
}
