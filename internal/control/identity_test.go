package control

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"defendsec/internal/identity"
)

// These cover the parts that hold without a database: the shared tokens still
// authorise, they are recorded as unattributed, and an unauthenticated request
// is refused. The full login path is exercised against real Postgres in
// internal/storepg.

func testServer() *Server {
	return &Server{
		adminToken:  "admin-token",
		viewerToken: "viewer-token",
		log:         slog.New(slog.DiscardHandler),
	}
}

func TestResolveActorFromSharedTokens(t *testing.T) {
	s := testServer()
	cases := map[string]struct {
		token      string
		wantRole   string
		wantActor  string
		wantAttrib bool
	}{
		"admin": {
			"admin-token", identity.RoleAdmin, "unattributed:shared-bootstrap-token", false,
		},
		"viewer": {
			"viewer-token", identity.RoleViewer, "unattributed:shared-bootstrap-token", false,
		},
		"unknown": {"nope", "", "unattributed:shared-bootstrap-token", false},
		"empty":   {"", "", "unattributed:shared-bootstrap-token", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			actor := s.resolveActor(req)
			if actor.Role != tc.wantRole {
				t.Errorf("role = %q, want %q", actor.Role, tc.wantRole)
			}
			if actor.Attributed != tc.wantAttrib {
				t.Errorf("attributed = %v, want %v", actor.Attributed, tc.wantAttrib)
			}
			if got := actor.Identity(); got != tc.wantActor {
				t.Errorf("identity = %q, want %q", got, tc.wantActor)
			}
		})
	}
}

// A shared token must never look like a person in the ledger. This is the
// claim the whole phase rests on, so it is asserted directly.
func TestSharedTokenIsNeverAttributed(t *testing.T) {
	s := testServer()
	for _, token := range []string{"admin-token", "viewer-token"} {
		req := httptest.NewRequest(http.MethodPost, "/v1/commands", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		got := s.actorIdentity(req)
		if got == "" {
			t.Fatalf("token %q produced an empty actor identity", token)
		}
		if got[:len("unattributed:")] != "unattributed:" {
			t.Errorf("token %q produced %q, want an unattributed marker", token, got)
		}
	}
}

func TestAdminAndWriteChecksAcceptSharedTokens(t *testing.T) {
	s := testServer()
	cases := map[string]struct {
		token          string
		read, canWrite bool
	}{
		"admin":  {"admin-token", true, true},
		"viewer": {"viewer-token", true, false},
		"bogus":  {"bogus", false, false},
		"none":   {"", false, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/commands", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if got := s.adminOK(req); got != tc.read {
				t.Errorf("adminOK = %v, want %v", got, tc.read)
			}
			if got := s.adminWriteOK(req); got != tc.canWrite {
				t.Errorf("adminWriteOK = %v, want %v", got, tc.canWrite)
			}
		})
	}
}

func TestHandleSessionReportsRoleAndAttribution(t *testing.T) {
	s := testServer()

	req := httptest.NewRequest(http.MethodGet, "/v1/session", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleSession(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Role       string `json:"role"`
		Attributed bool   `json:"attributed"`
		Identity   string `json:"identity"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Role != identity.RoleAdmin || body.Attributed {
		t.Errorf("unexpected session body: %+v", body)
	}
	if body.Identity != "unattributed:shared-bootstrap-token" {
		t.Errorf("identity = %q", body.Identity)
	}
}

func TestHandleSessionRejectsUnauthenticated(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()
	s.HandleSession(rec, httptest.NewRequest(http.MethodGet, "/v1/session", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

// Without a database there are no accounts, so the endpoints that need one
// must say so rather than appearing to work.
func TestIdentityEndpointsRequireDatabase(t *testing.T) {
	s := testServer()
	for name, h := range map[string]http.HandlerFunc{
		"login":  s.HandleLogin,
		"users":  s.HandleUsers,
		"update": s.HandleUserUpdate,
		"totp":   s.HandleTOTP,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/"+name, http.NoBody)
			req.Header.Set("Authorization", "Bearer admin-token")
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status=%d, want 503 without a database", rec.Code)
			}
		})
	}
}

func TestIdentityEndpointsRejectWrongMethod(t *testing.T) {
	s := testServer()
	for name, h := range map[string]http.HandlerFunc{
		"login":  s.HandleLogin,
		"logout": s.HandleLogout,
		"update": s.HandleUserUpdate,
		"totp":   s.HandleTOTP,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/"+name, nil)
			req.Header.Set("Authorization", "Bearer admin-token")
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status=%d, want 405", rec.Code)
			}
		})
	}
}

// A shared token has no account, so it cannot enroll a second factor onto one.
func TestTOTPEnrollmentRequiresNamedAccount(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/totp", http.NoBody)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleTOTP(rec, req)
	// Reported as unavailable here because there is no database at all; the
	// named-account requirement is covered once one is configured.
	if rec.Code == http.StatusOK {
		t.Fatal("a shared token must not be able to enroll a second factor")
	}
}

func TestRequireAdminActor(t *testing.T) {
	s := testServer()
	for token, want := range map[string]bool{
		"admin-token":  true,
		"viewer-token": false,
		"bogus":        false,
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		if got := s.requireAdminActor(rec, req); got != want {
			t.Errorf("token %q: requireAdminActor = %v, want %v", token, got, want)
		}
		if !want && rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status=%d, want 401", token, rec.Code)
		}
	}
}

func TestCryptoPostureRequiresAdmin(t *testing.T) {
	s := testServer()
	for token, wantOK := range map[string]bool{
		"admin-token":  true,
		"viewer-token": false,
		"bogus":        false,
		"":             false,
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/crypto-posture", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		s.HandleCryptoPosture(rec, req)
		if wantOK && rec.Code != http.StatusOK {
			t.Errorf("token %q: status=%d, want 200", token, rec.Code)
		}
		if !wantOK && rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status=%d, want 401", token, rec.Code)
		}
	}
}

func TestCryptoPostureReportsKDFAndDeviations(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/crypto-posture", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleCryptoPosture(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var st identity.FIPSStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.PasswordKDF == "" {
		t.Error("passwordKdf is empty")
	}
	if len(st.Notes) == 0 {
		t.Error("no notes, so the deviations are left to be inferred from silence")
	}
}

func TestCryptoPostureRejectsWrongMethod(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodPost, "/v1/crypto-posture", http.NoBody)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleCryptoPosture(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want 405", rec.Code)
	}
}
