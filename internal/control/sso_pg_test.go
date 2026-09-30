package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"defendsec/internal/sso"
	"defendsec/internal/sso/ssotest"
	"defendsec/internal/storepg"
)

func ssoServer(t *testing.T) (*Server, *ssotest.IdP) {
	t.Helper()
	s, _ := pgServer(t)
	idp := ssotest.New(t)
	prov, err := sso.New(sso.Config{
		Issuer: idp.Server.URL, ClientID: "defendsec", ClientSecret: "x",
		RedirectURL:  "https://console.example/api/sso/callback",
		AdminGroups:  []string{"defendsec-admins"},
		ViewerGroups: []string{"defendsec-viewers"},
		HTTPClient:   idp.Server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetSSO(prov)
	return s, idp
}

// signIn runs start then finish through the HTTP handlers, as the console
// does, and returns the status and decoded body.
func signIn(t *testing.T, s *Server, idp *ssotest.IdP) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.HandleSSO(rec, httptest.NewRequest(http.MethodPost, "/v1/sso/start", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	var flow sso.Flow
	_ = json.Unmarshal(rec.Body.Bytes(), &flow)
	idp.Set("nonce", flow.Nonce)

	body, _ := json.Marshal(map[string]string{
		"code": "c", "verifier": flow.Verifier, "nonce": flow.Nonce, "clientAddress": "10.0.0.9",
	})
	rec = httptest.NewRecorder()
	s.HandleSSO(rec, httptest.NewRequest(http.MethodPost, "/v1/sso/finish", strings.NewReader(string(body))))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSSOProvisionsAnAccountAndOpensAnAttributedSession(t *testing.T) {
	s, idp := ssoServer(t)
	code, out := signIn(t, s, idp)
	if code != http.StatusOK {
		t.Fatalf("status %d: %v", code, out)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+out["token"].(string))
	a := s.resolveActor(req)
	if a.Identity() != "user:mason" || a.Role != "admin" {
		t.Errorf("session = %s / %s", a.Identity(), a.Role)
	}
}

// Removing someone from the admin group must take effect at their next
// sign-in, not never.
func TestTheRoleFollowsTheIdPGroupsOnEverySignIn(t *testing.T) {
	s, idp := ssoServer(t)
	if code, _ := signIn(t, s, idp); code != http.StatusOK {
		t.Fatal("first sign-in failed")
	}
	idp.Set("groups", []string{"defendsec-viewers"})
	code, out := signIn(t, s, idp)
	if code != http.StatusOK {
		t.Fatalf("second sign-in: %d %v", code, out)
	}
	u, err := s.pg.GetUserByUsername(context.Background(), "mason")
	if err != nil {
		t.Fatal(err)
	}
	if u.Role != "viewer" {
		t.Errorf("role = %q after removal from the admin group, want viewer", u.Role)
	}

	// Out of every mapped group: refused, and recorded.
	idp.Set("groups", []string{"everyone"})
	if code, _ := signIn(t, s, idp); code != http.StatusForbidden {
		t.Errorf("status %d for a user in no mapped group, want 403", code)
	}
}

// Accounts are never linked by name. An IdP user called "mason" is not
// known to be the same person as a local account called "mason".
func TestAnSSOUserCannotTakeOverALocalAccountByName(t *testing.T) {
	s, idp := ssoServer(t)
	if _, err := s.pg.CreateUser(context.Background(), "local-1", "mason", "", "admin",
		"a sufficiently long password"); err != nil {
		t.Fatal(err)
	}
	code, out := signIn(t, s, idp)
	if code != http.StatusConflict {
		t.Fatalf("status %d: %v, want 409", code, out)
	}
	if !strings.Contains(out["error"].(string), "never linked by name") {
		t.Errorf("error = %v", out["error"])
	}
}

// An SSO account has no password, and the password form must not work
// against it with any input.
func TestAnSSOAccountCannotSignInWithAPassword(t *testing.T) {
	s, idp := ssoServer(t)
	if code, _ := signIn(t, s, idp); code != http.StatusOK {
		t.Fatal("sso sign-in failed")
	}
	for _, pw := range []string{"", "!sso", storepg.SSOPasswordMarker, "a sufficiently long password"} {
		if _, _, err := s.pg.Authenticate(context.Background(), "mason", pw, "", time.Now().UTC()); err == nil {
			t.Errorf("password %q signed into an SSO account", pw)
		}
	}
}

// Disabling in DefendSec must hold even though the IdP still vouches for the
// person: the control plane can always withdraw access.
func TestALocallyDisabledSSOAccountStaysDisabled(t *testing.T) {
	s, idp := ssoServer(t)
	if code, _ := signIn(t, s, idp); code != http.StatusOK {
		t.Fatal("sso sign-in failed")
	}
	u, _ := s.pg.GetUserByUsername(context.Background(), "mason")
	if err := s.pg.SetUserDisabled(context.Background(), u.ID, true); err != nil {
		t.Fatal(err)
	}
	if code, _ := signIn(t, s, idp); code == http.StatusOK {
		t.Fatal("a disabled account signed in through SSO")
	}
}

// Linking is by (issuer, subject): a second sign-in with a different
// username but the same subject is the same account, renamed at the IdP.
func TestTheAccountIsLinkedBySubjectNotUsername(t *testing.T) {
	s, idp := ssoServer(t)
	signIn(t, s, idp)
	idp.Set("preferred_username", "mason.hyatt")
	code, out := signIn(t, s, idp)
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, out)
	}
	n, _ := s.pg.CountUsers(context.Background())
	if n != 1 {
		t.Errorf("%d accounts after a rename at the IdP, want 1", n)
	}
}

func TestSSOStatusReportsWhetherItIsConfigured(t *testing.T) {
	s, _ := pgServer(t)
	rec := httptest.NewRecorder()
	s.HandleSSO(rec, httptest.NewRequest(http.MethodGet, "/v1/sso", nil))
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("unconfigured: %s", rec.Body)
	}
	s2, _ := ssoServer(t)
	rec = httptest.NewRecorder()
	s2.HandleSSO(rec, httptest.NewRequest(http.MethodGet, "/v1/sso", nil))
	if !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Errorf("configured: %s", rec.Body)
	}
}
