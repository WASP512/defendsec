// Package sso signs operators in through an OpenID Connect identity provider
// (roadmap 5.4).
//
// # What it guarantees
//
//   - Authorization code flow with PKCE, a state value bound to the browser,
//     and a nonce bound to the ID token. Each defends a different replay:
//     PKCE a stolen code, state a forged callback, nonce a replayed token.
//   - The ID token's signature, issuer, audience and expiry are verified
//     against the provider's published keys before anything is trusted.
//   - Roles come only from group membership the operator mapped explicitly.
//     A user in no mapped group is refused, not given a default role:
//     deny-by-default applies to who may sign in as much as to what they may
//     do, and "everyone in the company directory is a viewer" is a decision
//     an operator should make on purpose rather than inherit.
//   - Accounts are linked by (issuer, subject), never by username or email.
//
// # What it does not do
//
// No SCIM or directory sync. Removing someone at the identity provider takes
// effect at their next sign-in, or when their session expires (12 hours);
// it does not end a session already open. Disabling the account in
// DefendSec does end it immediately. That gap is stated in the docs rather
// than implied away.
package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"defendsec/internal/identity"
)

// Config is the operator's SSO configuration.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is the console's callback, e.g.
	// https://defendsec.example.com:47261/api/sso/callback.
	RedirectURL string
	// GroupsClaim names the ID-token claim holding group membership.
	GroupsClaim string
	// AdminGroups and ViewerGroups map IdP groups to roles. Admin wins when
	// a user is in both.
	AdminGroups  []string
	ViewerGroups []string
	// DisplayName is the label on the login button, e.g. "Microsoft Entra".
	DisplayName string
	// HTTPClient, when set, is used for every call to the identity provider —
	// for an IdP behind a private CA, and for tests.
	HTTPClient *http.Client
}

// Validate refuses a configuration that cannot work or would be unsafe.
func (c Config) Validate() error {
	var missing []string
	if c.Issuer == "" {
		missing = append(missing, "issuer")
	}
	if c.ClientID == "" {
		missing = append(missing, "client id")
	}
	if c.RedirectURL == "" {
		missing = append(missing, "redirect URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("SSO is partly configured; missing %s", strings.Join(missing, ", "))
	}
	if !strings.HasPrefix(c.Issuer, "https://") {
		// The issuer URL is where signing keys come from. Fetching them over
		// plain HTTP would let anyone on the path substitute their own and
		// mint valid-looking tokens.
		return fmt.Errorf("the SSO issuer must be an https:// URL")
	}
	if len(c.AdminGroups) == 0 && len(c.ViewerGroups) == 0 {
		// Refused rather than defaulted. With no groups mapped, every sign-in
		// would be refused — or, if the default were permissive, everyone in
		// the directory would get in. Neither is what an operator meant.
		return fmt.Errorf("SSO needs at least one admin or viewer group mapped, or nobody can sign in")
	}
	return nil
}

// Provider runs the flow against one identity provider.
type Provider struct {
	cfg Config

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

// New builds a provider. Discovery happens on first use rather than here, so
// an identity provider that is briefly down when DefendSec starts does not
// stop the control plane from starting; local accounts and the admin token
// still work in the meantime.
func New(cfg Config) (*Provider, error) {
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "single sign-on"
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg}, nil
}

// DisplayName is the label for the login button.
func (p *Provider) DisplayName() string { return p.cfg.DisplayName }

func (p *Provider) ctx(ctx context.Context) context.Context {
	if p.cfg.HTTPClient != nil {
		return oidc.ClientContext(ctx, p.cfg.HTTPClient)
	}
	return ctx
}

func (p *Provider) discover(ctx context.Context) error {
	ctx = p.ctx(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return nil
	}
	prov, err := oidc.NewProvider(ctx, p.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("reach identity provider %s: %w", p.cfg.Issuer, err)
	}
	p.provider = prov
	p.verifier = prov.Verifier(&oidc.Config{ClientID: p.cfg.ClientID})
	p.oauth = &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		RedirectURL:  p.cfg.RedirectURL,
		Endpoint:     prov.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return nil
}

// Flow is the per-attempt secret material. The console keeps it in a short
// httpOnly cookie between the redirect and the callback.
type Flow struct {
	AuthURL  string `json:"authUrl"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

// Start begins a sign-in.
func (p *Provider) Start(ctx context.Context) (Flow, error) {
	if err := p.discover(ctx); err != nil {
		return Flow{}, err
	}
	state, err := randomString()
	if err != nil {
		return Flow{}, err
	}
	nonce, err := randomString()
	if err != nil {
		return Flow{}, err
	}
	verifier := oauth2.GenerateVerifier()
	url := p.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	return Flow{AuthURL: url, State: state, Nonce: nonce, Verifier: verifier}, nil
}

// Identity is a verified sign-in.
type Identity struct {
	Issuer      string
	Subject     string
	Username    string
	DisplayName string
	Groups      []string
	// Role is decided from Groups; empty means refused.
	Role string
}

// ErrNoMappedGroup reports a verified user who is in none of the mapped
// groups. Distinct from a verification failure so the audit log and the
// login page can say which.
var ErrNoMappedGroup = errors.New("not a member of any group mapped to a DefendSec role")

// Finish exchanges the code and verifies the ID token.
func (p *Provider) Finish(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	if err := p.discover(ctx); err != nil {
		return Identity{}, err
	}
	ctx = p.ctx(ctx)
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange code: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, errors.New("the identity provider returned no ID token")
	}
	idt, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verify ID token: %w", err)
	}
	if nonce == "" || idt.Nonce != nonce {
		return Identity{}, errors.New("the ID token's nonce does not match this sign-in")
	}

	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read claims: %w", err)
	}
	id := Identity{
		Issuer:  idt.Issuer,
		Subject: idt.Subject,
		Groups:  stringList(claims[p.cfg.GroupsClaim]),
	}
	id.Username = identity.NormalizeUsername(firstString(claims, "preferred_username", "email"))
	id.DisplayName = firstString(claims, "name")
	id.Role = p.RoleFor(id.Groups)
	if id.Role == "" {
		return id, ErrNoMappedGroup
	}
	return id, nil
}

// RoleFor maps group membership to a role. Admin wins over viewer; no mapped
// group means no role.
func (p *Provider) RoleFor(groups []string) string {
	has := func(want []string) bool {
		for _, g := range groups {
			for _, w := range want {
				if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(w)) {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has(p.cfg.AdminGroups):
		return identity.RoleAdmin
	case has(p.cfg.ViewerGroups):
		return identity.RoleViewer
	default:
		return ""
	}
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		// Some providers send a single group as a bare string.
		return []string{t}
	default:
		return nil
	}
}

func firstString(claims map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := claims[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func randomString() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
