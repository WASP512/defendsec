// Package ssotest is a minimal OpenID provider for tests: discovery, JWKS,
// and a token endpoint returning a signed ID token the test controls. It
// exists so SSO verification is exercised against real signatures rather
// than trusted by assumption.
package ssotest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// IdP is a fake identity provider.
type IdP struct {
	Server *httptest.Server
	key    *rsa.PrivateKey

	mu sync.Mutex
	// Claims are merged into the next ID token.
	Claims map[string]any
	// SignWith, when set, signs with a key the IdP does not publish.
	SignWith *rsa.PrivateKey
	// LastVerifier is the PKCE verifier the client last sent.
	LastVerifier string
}

// New starts a fake IdP. Its client is Server.Client().
func New(t testing.TB) *IdP { return NewWith(t.Helper, t.Fatal, t.Cleanup) }

// NewWith is New without a testing.TB, for running the fake as a standalone
// process in end-to-end checks.
func NewWith(helper func(), fatal func(...any), cleanup func(func())) *IdP {
	t := struct {
		Helper  func()
		Fatal   func(...any)
		Cleanup func(func())
	}{helper, fatal, cleanup}
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &IdP{key: key, Claims: map[string]any{}}
	mux := http.NewServeMux()
	f.Server = httptest.NewTLSServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.Server.URL,
			"authorization_endpoint":                f.Server.URL + "/authorize",
			"token_endpoint":                        f.Server.URL + "/token",
			"jwks_uri":                              f.Server.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	// authorize behaves like a user who is already signed in at the IdP:
	// it remembers the nonce for the ID token and redirects straight back.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.Set("nonce", q.Get("nonce"))
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=fake-code&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.LastVerifier = r.Form.Get("code_verifier")
		signKey := f.key
		if f.SignWith != nil {
			signKey = f.SignWith
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signKey},
			(&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		c := map[string]any{
			"iss": f.Server.URL, "aud": "defendsec", "sub": "sub-123",
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
			"preferred_username": "mason", "name": "Mason",
			"groups": []string{"defendsec-admins"},
		}
		for k, v := range f.Claims {
			c[k] = v
		}
		raw, err := jwt.Signed(signer).Claims(c).Serialize()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "id_token": raw, "expires_in": 3600,
		})
	})
	t.Cleanup(f.Server.Close)
	return f
}

// Set sets a claim for subsequent tokens.
func (f *IdP) Set(k string, v any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Claims[k] = v
}
