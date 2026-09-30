package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// First-run setup (creating the first administrator without the token).
//
// The tests that matter are the negative ones: setup must be impossible once
// an account exists, impossible after the window, impossible when disabled,
// and must create exactly one administrator when two people race for it.

// setupServer is a server with no accounts and a clean audit log.
func setupServer(t *testing.T) *Server {
	t.Helper()
	s, _ := pgServer(t) // truncates users and sessions
	return s
}

func postSetup(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/setup", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.HandleSetup(rec, req)
	return rec
}

func getSetup(t *testing.T, s *Server) SetupStatus {
	t.Helper()
	rec := httptest.NewRecorder()
	s.HandleSetup(rec, httptest.NewRequest(http.MethodGet, "/v1/setup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var st SetupStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

const goodSetup = `{"username":"mason","displayName":"Mason","password":"a sufficiently long password"}`

// The whole point: a fresh install gets an administrator, signed in, with no
// token involved.
func TestSetupCreatesTheFirstAdministratorAndSignsThemIn(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), DefaultSetupWindow)

	st := getSetup(t, s)
	if !st.SetupOpen || st.AccountsExist {
		t.Fatalf("status = %+v, want setup open on a fresh install", st)
	}
	if st.SecondsRemaining <= 0 {
		t.Errorf("secondsRemaining = %d", st.SecondsRemaining)
	}

	rec := postSetup(t, s, goodSetup)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Token string `json:"token"`
		User  struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.User.Role != "admin" {
		t.Errorf("role = %q, want admin", out.User.Role)
	}
	if out.Token == "" {
		t.Fatal("no session token was returned, so the operator is not signed in")
	}

	// The token is a real session, attributed to the new person.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+out.Token)
	actor := s.resolveActor(req)
	if actor.Identity() != "user:mason" {
		t.Errorf("session resolves to %q, want user:mason", actor.Identity())
	}
}

// Once an account exists setup is closed, whatever the clock says. This is
// the property that stops it being a way to add a second administrator.
func TestSetupClosesOnceAnAccountExists(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), DefaultSetupWindow)

	if rec := postSetup(t, s, goodSetup); rec.Code != http.StatusCreated {
		t.Fatalf("first setup: %d %s", rec.Code, rec.Body)
	}
	rec := postSetup(t, s, `{"username":"intruder","password":"another long enough password"}`)
	if rec.Code == http.StatusCreated {
		t.Fatal("setup created a second administrator after an account existed")
	}
	st := getSetup(t, s)
	if st.SetupOpen || !st.AccountsExist {
		t.Errorf("status = %+v, want closed with accounts", st)
	}
}

// After the window, an unauthenticated caller can create nothing.
func TestSetupIsRefusedAfterTheWindow(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC().Add(-time.Hour), DefaultSetupWindow)

	st := getSetup(t, s)
	if st.SetupOpen {
		t.Fatal("setup reports open after its window")
	}
	if !strings.Contains(st.Detail, "bootstrap-admin") {
		t.Errorf("the closed state does not say how to reopen it: %q", st.Detail)
	}
	if rec := postSetup(t, s, goodSetup); rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403 after the window", rec.Code)
	}
}

// An install that sets the window to zero wants no open setup at all.
func TestAZeroWindowMeansNoOpenSetup(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), 0)
	if getSetup(t, s).SetupOpen {
		t.Fatal("setup is open with a zero window")
	}
	if rec := postSetup(t, s, goodSetup); rec.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", rec.Code)
	}
}

// Two people submitting at once must not both become administrator.
func TestConcurrentSetupCreatesExactlyOneAdministrator(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), DefaultSetupWindow)

	const racers = 8
	var wg sync.WaitGroup
	codes := make(chan int, racers)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"username":"racer` + string(rune('a'+i)) +
				`","password":"a sufficiently long password"}`
			codes <- postSetup(t, s, body).Code
		}(i)
	}
	wg.Wait()
	close(codes)

	created := 0
	for c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d administrators were created by concurrent setup, want exactly 1", created)
	}
	n, err := s.pg.CountUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d accounts exist, want 1", n)
	}
}

// A weak password is refused with a reason the operator can act on, and does
// not consume the setup.
func TestAWeakPasswordIsRefusedAndSetupStaysOpen(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), DefaultSetupWindow)

	rec := postSetup(t, s, `{"username":"mason","password":"short"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "at least") {
		t.Errorf("the refusal does not say why: %s", rec.Body)
	}
	if !getSetup(t, s).SetupOpen {
		t.Error("a failed attempt closed setup")
	}
}

// The ledger has to answer how the first administrator came to exist.
func TestSetupIsRecordedInTheAuditLog(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), DefaultSetupWindow)
	if rec := postSetup(t, s, `{"username":"mason","password":"a sufficiently long password","clientAddress":"10.10.10.5"}`); rec.Code != http.StatusCreated {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	entries, err := s.pg.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e["action"] == "first_admin_created" {
			blob, _ := json.Marshal(e)
			if !strings.Contains(string(blob), "10.10.10.5") {
				t.Errorf("the entry does not record where setup came from: %s", blob)
			}
			return
		}
	}
	t.Fatal("first-run setup was not recorded in the audit log")
}

// The token path still works throughout, as the fallback.
func TestTheTokenStillCreatesTheFirstAccountWhenSetupIsClosed(t *testing.T) {
	s := setupServer(t)
	s.OpenSetupWindow(time.Now().UTC(), 0)

	req := httptest.NewRequest(http.MethodPost, "/v1/users",
		strings.NewReader(`{"username":"mason","role":"admin","password":"a sufficiently long password"}`))
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandleUsers(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("token bootstrap: %d %s", rec.Code, rec.Body)
	}
}

// bootstrap-admin: a one-time link issued on the server opens setup even
// after the window has closed, works once, and only the newest works.
func TestSetupInviteFromTheServer(t *testing.T) {
	s := setupServer(t)
	ctx := context.Background()
	s.OpenSetupWindow(time.Now().UTC(), 0) // closed

	if st := getSetup(t, s); st.SetupOpen {
		t.Fatal("setup must be closed without an invite")
	}
	first, _, err := IssueSetupInvite(ctx, s.pg, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := IssueSetupInvite(ctx, s.pg, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	status := func(invite string) SetupStatus {
		rec := httptest.NewRecorder()
		s.HandleSetup(rec, httptest.NewRequest(http.MethodGet, "/v1/setup?invite="+invite, nil))
		var st SetupStatus
		_ = json.Unmarshal(rec.Body.Bytes(), &st)
		return st
	}
	if st := status(first); st.SetupOpen || !st.InviteInvalid {
		t.Fatalf("a replaced invite must not open setup: %+v", st)
	}
	if st := status("forged"); st.SetupOpen || !st.InviteInvalid {
		t.Fatalf("a forged invite must not open setup: %+v", st)
	}
	if st := status(second); !st.SetupOpen || !st.ViaInvite {
		t.Fatalf("the current invite must open setup: %+v", st)
	}

	// A failed creation (bad password) must not spend the invite.
	bad := `{"username":"mason","password":"short","invite":"` + second + `"}`
	if rec := postSetup(t, s, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad password: %d %s", rec.Code, rec.Body)
	}
	good := `{"username":"mason","password":"a sufficiently long password","invite":"` + second + `"}`
	if rec := postSetup(t, s, good); rec.Code != http.StatusCreated {
		t.Fatalf("invite setup: %d %s", rec.Code, rec.Body)
	}
	// Used once; and accounts now exist, so no new invite can be issued.
	if st := status(second); st.SetupOpen {
		t.Fatal("setup reopened after the first administrator exists")
	}
	if _, _, err := IssueSetupInvite(ctx, s.pg, time.Now()); err == nil {
		t.Fatal("bootstrap-admin must refuse once an account exists")
	}
}
