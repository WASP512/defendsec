package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"defendsec/internal/sso/ssotest"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fakeIdP struct {
	*ssotest.IdP
	claims       map[string]any
	lastVerifier string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	idp := ssotest.New(t)
	return &fakeIdP{IdP: idp, claims: idp.Claims}
}

func (f *fakeIdP) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(Config{
		Issuer: f.Server.URL, ClientID: "defendsec", ClientSecret: "s",
		RedirectURL:  "https://console.example/api/sso/callback",
		AdminGroups:  []string{"defendsec-admins"},
		ViewerGroups: []string{"defendsec-viewers"},
		HTTPClient:   f.Server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fakeFor[p] = f
	return p
}

// run does Start then Finish with the flow's own nonce, as the console does.
func run(t *testing.T, p *Provider) (Identity, error) {
	t.Helper()
	flow, err := p.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// A real IdP copies the nonce from the authorize request into the ID
	// token; the fake is told it directly.
	if _, set := fakeFor[p]; set {
		if _, overridden := fakeFor[p].claims["nonce"]; !overridden {
			fakeFor[p].claims["nonce"] = flow.Nonce
			defer delete(fakeFor[p].claims, "nonce")
		}
	}
	return p.Finish(context.Background(), "code", flow.Verifier, flow.Nonce)
}

var fakeFor = map[*Provider]*fakeIdP{}

func TestAVerifiedAdminSignsIn(t *testing.T) {
	f := newFakeIdP(t)
	id, err := run(t, f.provider(t))
	if err != nil {
		t.Fatal(err)
	}
	if id.Role != "admin" || id.Subject != "sub-123" || id.Username != "mason" {
		t.Errorf("identity = %+v", id)
	}
}

func TestTheAuthURLCarriesStateNonceAndPKCE(t *testing.T) {
	f := newFakeIdP(t)
	flow, err := f.provider(t).Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(flow.AuthURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != flow.State || q.Get("nonce") != flow.Nonce {
		t.Errorf("state or nonce missing from %s", flow.AuthURL)
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("PKCE missing from %s", flow.AuthURL)
	}
	if strings.Contains(flow.AuthURL, flow.Verifier) {
		t.Error("the PKCE verifier itself was put in the URL")
	}
}

func TestThePKCEVerifierIsSentOnExchange(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t)
	flow, _ := p.Start(context.Background())
	f.claims["nonce"] = flow.Nonce
	if _, err := p.Finish(context.Background(), "code", flow.Verifier, flow.Nonce); err != nil {
		t.Fatal(err)
	}
	if f.LastVerifier != flow.Verifier {
		t.Errorf("verifier sent = %q, want %q", f.LastVerifier, flow.Verifier)
	}
}

// Deny-by-default: a verified user in no mapped group gets no role.
func TestAUserInNoMappedGroupIsRefused(t *testing.T) {
	f := newFakeIdP(t)
	f.claims["groups"] = []string{"everyone"}
	_, err := run(t, f.provider(t))
	if !errors.Is(err, ErrNoMappedGroup) {
		t.Fatalf("err = %v, want ErrNoMappedGroup", err)
	}
}

func TestViewerGroupGivesViewerAndAdminWinsOverViewer(t *testing.T) {
	f := newFakeIdP(t)
	f.claims["groups"] = []string{"defendsec-viewers"}
	id, err := run(t, f.provider(t))
	if err != nil || id.Role != "viewer" {
		t.Fatalf("viewer: %+v %v", id, err)
	}
	f.claims["groups"] = []string{"defendsec-viewers", "defendsec-admins"}
	id, err = run(t, f.provider(t))
	if err != nil || id.Role != "admin" {
		t.Fatalf("both: %+v %v", id, err)
	}
}

// A token signed by a key the IdP does not publish must not verify.
func TestAForgedSignatureIsRejected(t *testing.T) {
	f := newFakeIdP(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	f.SignWith = other
	if _, err := run(t, f.provider(t)); err == nil {
		t.Fatal("a token signed with an unpublished key was accepted")
	}
}

func TestATokenForAnotherClientIsRejected(t *testing.T) {
	f := newFakeIdP(t)
	f.claims["aud"] = "some-other-app"
	if _, err := run(t, f.provider(t)); err == nil {
		t.Fatal("a token issued to another client was accepted")
	}
}

func TestAnExpiredTokenIsRejected(t *testing.T) {
	f := newFakeIdP(t)
	f.claims["exp"] = time.Now().Add(-time.Hour).Unix()
	if _, err := run(t, f.provider(t)); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestAWrongIssuerIsRejected(t *testing.T) {
	f := newFakeIdP(t)
	f.claims["iss"] = "https://evil.example"
	if _, err := run(t, f.provider(t)); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
}

// A replayed token carries another sign-in's nonce.
func TestANonceMismatchIsRejected(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t)
	flow, _ := p.Start(context.Background())
	f.claims["nonce"] = flow.Nonce
	if _, err := p.Finish(context.Background(), "code", flow.Verifier, "a-different-nonce"); err == nil {
		t.Fatal("a token with another sign-in's nonce was accepted")
	}
	f.claims["nonce"] = "attacker"
	if _, err := p.Finish(context.Background(), "code", flow.Verifier, ""); err == nil {
		t.Fatal("an empty expected nonce was accepted")
	}
}

func TestConfigIsValidated(t *testing.T) {
	good := Config{Issuer: "https://idp", ClientID: "c", RedirectURL: "https://x/cb", AdminGroups: []string{"a"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Config){
		"plain http issuer": func(c *Config) { c.Issuer = "http://idp" },
		"no groups mapped":  func(c *Config) { c.AdminGroups = nil },
		"no client id":      func(c *Config) { c.ClientID = "" },
		"no redirect":       func(c *Config) { c.RedirectURL = "" },
	} {
		c := good
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestGroupsClaimAsASingleString(t *testing.T) {
	f := newFakeIdP(t)
	f.claims["groups"] = "defendsec-admins"
	id, err := run(t, f.provider(t))
	if err != nil || id.Role != "admin" {
		t.Fatalf("%+v %v", id, err)
	}
}
