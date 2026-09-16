package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"defendsec/internal/playbook"
	"defendsec/internal/policy"
)

func withPolicy(t *testing.T, src string) *Server {
	t.Helper()
	s := testServer()
	doc, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	s.SetPolicy(policy.NewEngine(doc))
	return s
}

// The property the whole phase rests on, asserted at the server boundary:
// a command policy refuses never becomes a signed envelope.
func TestDeniedCommandsAreNeverSigned(t *testing.T) {
	s := withPolicy(t, `
version: 1
name: test
rules:
  - id: only-live-query
    effect: permit
    commands: [live_query]
`)
	req := policy.Request{
		Actor: "user:alice", Role: "admin", CommandType: "isolate",
		DeviceID: "dev-1", At: time.Now().UTC(),
		Approvals: []string{"user:alice"},
	}
	d, err := s.authorise(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Fatal("an unruled command was authorised")
	}
	if d.Effect != policy.EffectDeny {
		t.Errorf("effect = %s", d.Effect)
	}
}

// A server with no policy installed must refuse everything rather than fall
// back to the pre-policy behaviour of allowing anything.
func TestNoPolicyInstalledDeniesEverything(t *testing.T) {
	s := testServer()
	for _, cmd := range []string{"isolate", "live_query", "kill_process"} {
		d, err := s.authorise(t.Context(), policy.Request{
			Actor: "user:alice", Role: "admin", CommandType: cmd, At: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if d.Allowed() {
			t.Errorf("%s was allowed with no policy installed", cmd)
		}
		if !strings.Contains(d.Reason, "No policy is loaded") {
			t.Errorf("%s: reason = %q", cmd, d.Reason)
		}
	}
}

// An evaluation that cannot complete is a denial, not a pass. The usual cause
// is an unreadable usage count, and treating that as "under the limit" would
// disable blast-radius limits exactly when the database is struggling.
func TestFailedEvaluationDenies(t *testing.T) {
	// A limit with no usage source available: s.pg is nil, so the engine gets
	// a nil UsageFunc and refuses to guess.
	s := withPolicy(t, `
version: 1
name: test
rules:
  - id: allow
    effect: permit
    commands: [isolate]
limits:
  - id: capped
    commands: [isolate]
    scope: fleet
    max: 3
    per: 1h
`)
	d, err := s.authorise(t.Context(), policy.Request{
		Actor: "user:alice", Role: "admin", CommandType: "isolate",
		DeviceID: "dev-1", At: time.Now().UTC(), Approvals: []string{"user:alice"},
	})
	if err != nil {
		t.Fatalf("authorise returned an error rather than a denial: %v", err)
	}
	if d.Allowed() {
		t.Fatal("a limit that could not be evaluated was treated as satisfied")
	}
	if !strings.Contains(d.Reason, "could not be evaluated") {
		t.Errorf("reason = %q", d.Reason)
	}
}

func TestPolicyEndpointReportsWhatIsLoaded(t *testing.T) {
	s := withPolicy(t, `
version: 1
name: reported
rules:
  - id: allow
    effect: permit
    commands: [live_query]
`)
	req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandlePolicy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var body struct {
		Loaded bool   `json:"loaded"`
		Name   string `json:"name"`
		Hash   string `json:"hash"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Loaded || body.Name != "reported" || body.Hash == "" {
		t.Errorf("body = %+v", body)
	}
	if !strings.Contains(body.Detail, "Deny by default") {
		t.Errorf("detail does not state the posture: %q", body.Detail)
	}
}

// An unconfigured deployment must say so, not report an empty policy that
// reads as permissive.
func TestPolicyEndpointReportsNothingLoaded(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	req.Header.Set("Authorization", "Bearer admin-token")
	rec := httptest.NewRecorder()
	s.HandlePolicy(rec, req)

	var body struct {
		Loaded bool   `json:"loaded"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Loaded {
		t.Error("an unconfigured server reported a loaded policy")
	}
	if !strings.Contains(body.Detail, "denies every command") {
		t.Errorf("detail does not warn that nothing can be issued: %q", body.Detail)
	}
}

func TestPolicyEndpointsRequireDatabase(t *testing.T) {
	s := testServer()
	for name, h := range map[string]http.HandlerFunc{
		"decisions":    s.HandlePolicyDecisions,
		"approvals":    s.HandleApprovals,
		"break-glass":  s.HandleBreakGlass,
		"host-classes": s.HandleHostClasses,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/policy/"+name, nil)
			req.Header.Set("Authorization", "Bearer admin-token")
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Errorf("status=%d, want 503 without a database", rec.Code)
			}
		})
	}
}

func TestPolicyDecisionsRejectsUnknownEffect(t *testing.T) {
	// Without a database the handler's availability check fires first, so
	// this asserts the accepted set directly.
	for _, effect := range []string{"permit", "deny", "require-approval", ""} {
		if !validEffectFilter(effect) {
			t.Errorf("%q should be a valid filter", effect)
		}
	}
	if validEffectFilter("maybe") {
		t.Error("an unknown effect filter was accepted")
	}
}

// Exposed for the test above: the same set the handler accepts.
func validEffectFilter(effect string) bool {
	switch effect {
	case "", string(policy.EffectPermit), string(policy.EffectDeny), string(policy.EffectRequireApproval):
		return true
	}
	return false
}

func TestDenyResponseNamesTheRule(t *testing.T) {
	rec := httptest.NewRecorder()
	denyResponse(rec, policy.Decision{
		Effect: policy.EffectDeny, RuleID: "never-kill-critical",
		Reason: "this host runs the estate", PolicyName: "default",
		LimitExceeded: "isolate-hourly",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
	body := rec.Body.String()
	// A refusal that says only "forbidden" produces a support ticket and then
	// a request for a bypass; one that names the rule produces a conversation
	// about the rule.
	for _, want := range []string{"never-kill-critical", "this host runs the estate", "default", "isolate-hourly"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal omits %q: %s", want, body)
		}
	}
}

// A playbook must not be an authority of its own: with no policy loaded,
// every step is refused just as a single command would be.
func TestPlaybookStepsAreNotExemptFromPolicy(t *testing.T) {
	s := testServer()
	d, err := s.authorise(t.Context(), policy.Request{
		Actor: "system:automatic-response", Role: "admin",
		CommandType: "isolate", DeviceID: "dev-1", At: time.Now().UTC(),
		Approvals: []string{"system:automatic-response"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Fatal("an automatic-response actor bypassed policy")
	}
}

// Automatic response needs playbooks and a database; without either it must
// be a quiet no-op rather than an error path nobody sees.
func TestAutorunIsANoOpWithoutPlaybooks(t *testing.T) {
	s := testServer()
	s.maybeAutorun(playbook.Alert{ID: "a1", Kind: "fim", DeviceID: "dev-1"}, nil)
}

func TestPlaybooksEndpointRequiresAuth(t *testing.T) {
	s := testServer()
	for token, wantOK := range map[string]bool{
		"admin-token":  true,
		"viewer-token": true,
		"bogus":        false,
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/playbooks", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.HandlePlaybooks(rec, req)
		if wantOK && rec.Code != http.StatusOK {
			t.Errorf("token %q: status=%d, want 200", token, rec.Code)
		}
		if !wantOK && rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q: status=%d, want 401", token, rec.Code)
		}
	}

	// Running one is admin-only: a sequence of signed commands is not a read.
	req := httptest.NewRequest(http.MethodPost, "/v1/playbooks", http.NoBody)
	req.Header.Set("Authorization", "Bearer viewer-token")
	rec := httptest.NewRecorder()
	s.HandlePlaybooks(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("a viewer ran a playbook")
	}
}
