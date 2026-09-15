package control

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"defendsec/db/migrations"
	"defendsec/internal/identity"
	"defendsec/internal/storepg"
)

// The claim this whole phase rests on: a request made with a real account
// session is attributed to that person in the ledger, and one made with a
// shared token is not. Skipped unless TEST_DATABASE_URL is set.

func pgServer(t *testing.T) (*Server, *storepg.Store) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	store := storepg.New(pool)
	if _, err := pool.Exec(ctx, `TRUNCATE users, user_sessions CASCADE`); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		adminToken:  "admin-token",
		viewerToken: "viewer-token",
		log:         slog.New(slog.DiscardHandler),
	}
	s.SetPostgres(store)
	return s, store
}

func TestLoginThenActorIdentityNamesThePerson(t *testing.T) {
	s, _ := pgServer(t)

	// Bootstrap: with no accounts, the shared token creates the first one.
	create := httptest.NewRequest(http.MethodPost, "/v1/users",
		strings.NewReader(`{"username":"alice","displayName":"Alice","role":"admin","password":"a sufficiently long password"}`))
	create.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleUsers(rec, create)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Log in as that account.
	login := httptest.NewRequest(http.MethodPost, "/v1/login",
		strings.NewReader(`{"username":"alice","password":"a sufficiently long password"}`))
	rec = httptest.NewRecorder()
	s.HandleLogin(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token == "" {
		t.Fatal("login returned no session token")
	}

	// A request carrying that session is attributed to alice.
	req := httptest.NewRequest(http.MethodPost, "/v1/commands", nil)
	req.Header.Set("Authorization", "Bearer "+body.Token)
	actor := s.resolveActor(req)
	if actor.Role != identity.RoleAdmin {
		t.Errorf("role = %q, want admin", actor.Role)
	}
	if !actor.Attributed {
		t.Error("an account session must be attributed")
	}
	if got := actor.Identity(); got != "user:alice" {
		t.Fatalf("actor identity = %q, want user:alice", got)
	}
	if !s.adminWriteOK(req) {
		t.Error("an admin account session must authorise writes")
	}

	// The same request with the shared token is not attributed.
	shared := httptest.NewRequest(http.MethodPost, "/v1/commands", nil)
	shared.Header.Set("Authorization", "Bearer admin-token")
	if got := s.actorIdentity(shared); got != "unattributed:shared-bootstrap-token" {
		t.Errorf("shared token identity = %q, want the unattributed marker", got)
	}

	// Logging out stops the session working at once.
	logout := httptest.NewRequest(http.MethodPost, "/v1/logout", nil)
	logout.Header.Set("Authorization", "Bearer "+body.Token)
	rec = httptest.NewRecorder()
	s.HandleLogout(rec, logout)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: status=%d", rec.Code)
	}
	if s.resolveActor(req).Role != "" {
		t.Error("a logged-out session must no longer authorise anything")
	}
}

// Once an account exists, the bootstrap path closes: creating more accounts
// needs an authenticated admin, not the shared token alone.
func TestSecondAccountRequiresAdminSession(t *testing.T) {
	s, store := pgServer(t)
	ctx := context.Background()

	if _, err := store.CreateUser(ctx, "u1", "alice", "", identity.RoleAdmin, "a sufficiently long password"); err != nil {
		t.Fatal(err)
	}

	// A viewer session must not be able to create accounts.
	if _, err := store.CreateUser(ctx, "u2", "bob", "", identity.RoleViewer, "a sufficiently long password"); err != nil {
		t.Fatal(err)
	}
	_, viewerToken, err := store.Authenticate(ctx, "bob", "a sufficiently long password", "", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/users",
		strings.NewReader(`{"username":"carol","role":"admin","password":"a sufficiently long password"}`))
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	rec := httptest.NewRecorder()
	s.HandleUsers(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("viewer creating an account: status=%d, want 401", rec.Code)
	}

	// An admin session may.
	_, adminToken, err := store.Authenticate(ctx, "alice", "a sufficiently long password", "", timeNow())
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/users",
		strings.NewReader(`{"username":"carol","role":"admin","password":"a sufficiently long password"}`))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	s.HandleUsers(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("admin creating an account: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// Login must not reveal which accounts exist, and must not hand out a session
// on any failure.
func TestLoginFailuresAreUniform(t *testing.T) {
	s, store := pgServer(t)
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "u1", "alice", "", identity.RoleAdmin, "a sufficiently long password"); err != nil {
		t.Fatal(err)
	}

	for name, payload := range map[string]string{
		"unknown user":   `{"username":"nobody","password":"a sufficiently long password"}`,
		"wrong password": `{"username":"alice","password":"the wrong password here"}`,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/login", strings.NewReader(payload))
			rec := httptest.NewRecorder()
			s.HandleLogin(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "token") {
				t.Error("a failed login must not return a session token")
			}
			if !strings.Contains(rec.Body.String(), "invalid credentials") {
				t.Errorf("body = %s, want the uniform message", rec.Body.String())
			}
		})
	}
}

func timeNow() time.Time { return time.Now().UTC() }
