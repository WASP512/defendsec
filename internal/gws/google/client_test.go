package google_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"defendsec/internal/gws/google"
	"defendsec/internal/gws/gwstest"
)

func newClient(t *testing.T, s *gwstest.Server, mod func(*google.Config)) *google.Client {
	t.Helper()
	cfg := s.Config()
	if mod != nil {
		mod(&cfg)
	}
	c, err := google.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func listUsers(t *testing.T, c *google.Client) (int, error) {
	t.Helper()
	n := 0
	err := c.EachUser(context.Background(), func(json.RawMessage) error { n++; return nil })
	return n, err
}

func TestParseServiceAccountJSON(t *testing.T) {
	s := gwstest.New(t)
	file, acct := s.NewKey()
	if acct.Email() != gwstest.ServiceEmail || acct.ClientID() != gwstest.ClientID || acct.ProjectID() != "fixture-project" || acct.KeyID() == "" {
		t.Errorf("account = %q %q %q %q", acct.Email(), acct.ClientID(), acct.ProjectID(), acct.KeyID())
	}
	_ = file

	// A PEM block whose body is not a key, assembled here so no key-shaped text sits in the repository.
	garbagePEM := "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n-----END " + "PRIVATE KEY-----\n"
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	mk := func(m map[string]string) []byte { b, _ := json.Marshal(m); return b }
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"not json":      {[]byte("hello"), "not JSON"},
		"wrong type":    {mk(map[string]string{"type": "authorized_user", "client_email": "a@b.c", "private_key": "x"}), "not a service account key"},
		"no email":      {mk(map[string]string{"type": "service_account", "private_key": "x"}), "no client_email"},
		"no pem":        {mk(map[string]string{"type": "service_account", "client_email": "a@b.c", "private_key": "nope"}), "no private_key in PEM"},
		"not rsa":       {mk(map[string]string{"type": "service_account", "client_email": "a@b.c", "private_key": ecPEM}), "not an RSA key"},
		"garbage block": {mk(map[string]string{"type": "service_account", "client_email": "a@b.c", "private_key": garbagePEM}), "not a valid PKCS #8"},
	} {
		_, err := google.ParseServiceAccountJSON(tc.data)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
		if err != nil && (strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), ecPEM[:40])) {
			t.Errorf("%s: the error quotes the key file: %v", name, err)
		}
	}
}

func TestNewValidation(t *testing.T) {
	s := gwstest.New(t)
	good := s.Config()
	for name, mod := range map[string]func(*google.Config){
		"no account":        func(c *google.Config) { c.Account = nil },
		"admin not email":   func(c *google.Config) { c.AdminEmail = "alex" },
		"admin two ats":     func(c *google.Config) { c.AdminEmail = "a@b@example.com" },
		"unknown scope":     func(c *google.Config) { c.GmailScope = "https://www.googleapis.com/auth/gmail.modify" },
		"http token url":    func(c *google.Config) { c.TokenURL = "http://oauth.example.com/token" },
		"http directory":    func(c *google.Config) { c.DirectoryURL = "http://admin.example.com" },
		"gmail with a user": func(c *google.Config) { c.GmailURL = "https://user:pw@gmail.example.com" },
	} {
		cfg := good
		mod(&cfg)
		if _, err := google.New(cfg); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
	for _, sc := range []string{"", google.ScopeGmailReadonly, google.ScopeGmailSettingsBasic} {
		cfg := good
		cfg.GmailScope = sc
		if _, err := google.New(cfg); err != nil {
			t.Errorf("scope %q: %v", sc, err)
		}
	}
	for s, want := range map[string]bool{"a@example.com": true, "a.b+c@sub.example.co": true, "a@example": false, "@example.com": false, "a@": false, "a b@example.com": false, "a@@example.com": false, "a@example..com": false, "a@.example.com": false} {
		if got := google.ValidEmail(s); got != want {
			t.Errorf("ValidEmail(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestEachUserPagesAndSignsTheAssertion(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, nil)
	n, err := listUsers(t, c)
	if err != nil || n != 11 {
		t.Fatalf("users = %d, err = %v (want 11 over two pages)", n, err)
	}
	reqs := s.Requests()
	if len(reqs) != 2 || reqs[0].Path != "/admin/directory/v1/users" {
		t.Fatalf("requests = %+v", reqs)
	}
	if !strings.Contains(reqs[1].Query, "pageToken=page-2-token") || strings.Contains(reqs[0].Query, "pageToken") {
		t.Errorf("page tokens: first %q, second %q", reqs[0].Query, reqs[1].Query)
	}
	for _, r := range reqs {
		if r.Method != "GET" {
			t.Errorf("method %s", r.Method)
		}
		if r.Sub != gwstest.AdminEmail || r.Scope != google.ScopeDirectoryUsers {
			t.Errorf("the Directory read acted as %q with scope %q", r.Sub, r.Scope)
		}
		for _, want := range []string{"customer=my_customer", "maxResults=500", "viewType=admin_view"} {
			if !strings.Contains(r.Query, want) {
				t.Errorf("query %q lacks %s", r.Query, want)
			}
		}
	}
	// The field mask is what keeps a user's phone numbers, addresses and the like out
	// of the read: assert it names none of them.
	for _, bad := range []string{"phones", "addresses", "emails", "recoveryPhone", "recoveryEmail", "notes", "externalIds", "customSchemas", "ims"} {
		if strings.Contains(reqs[0].Query, bad) {
			t.Errorf("the Directory read asks for %s", bad)
		}
	}
	if calls, subs := s.TokenCalls(); calls != 1 || len(subs) != 1 || subs[0] != gwstest.AdminEmail {
		t.Errorf("token calls = %d %v: a cached token must serve both pages", calls, subs)
	}
	if c.Requests() != 2 {
		t.Errorf("Requests() = %d, want 2", c.Requests())
	}
}

func TestGmailSettingsActsAsTheUserAndReadsOnlyTwoResources(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, nil)
	var af struct {
		Enabled      bool   `json:"enabled"`
		EmailAddress string `json:"emailAddress"`
	}
	if err := c.GmailSettings(context.Background(), "dana@example.com", "autoForwarding", &af); err != nil || !af.Enabled || af.EmailAddress != "dana.private@mail.example.org" {
		t.Fatalf("autoForwarding = %+v, err %v", af, err)
	}
	var fl struct {
		Filter []struct{ ID string } `json:"filter"`
	}
	if err := c.GmailSettings(context.Background(), "dana@example.com", "filters", &fl); err != nil || len(fl.Filter) != 1 {
		t.Fatalf("filters = %+v, err %v", fl, err)
	}
	for _, r := range s.Requests() {
		if r.Method != "GET" || r.Sub != "dana@example.com" || r.Scope != google.ScopeGmailReadonly || !strings.HasPrefix(r.Path, "/gmail/v1/users/me/settings/") {
			t.Errorf("request %+v", r)
		}
	}
	// There is no way to name a message, a label or another user's mailbox.
	for _, res := range []string{"messages", "labels", "../messages", "filters/ANe1", "sendAs", "delegates", ""} {
		if err := c.GmailSettings(context.Background(), "dana@example.com", res, &fl); err == nil {
			t.Errorf("GmailSettings accepted resource %q", res)
		}
	}
	if err := c.GmailSettings(context.Background(), "dana@example.com/../x", "filters", &fl); err == nil {
		t.Error("GmailSettings accepted a path as a user")
	}
	if n := len(s.Requests()); n != 2 {
		t.Errorf("rejected calls still made requests: %d in all", n)
	}
}

func TestSettingsBasicScopeIsUsedWhenChosen(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, func(cfg *google.Config) { cfg.GmailScope = google.ScopeGmailSettingsBasic })
	var out map[string]any
	if err := c.GmailSettings(context.Background(), "erin@example.com", "autoForwarding", &out); err != nil {
		t.Fatal(err)
	}
	if r := s.Requests()[0]; r.Scope != google.ScopeGmailSettingsBasic {
		t.Errorf("scope = %q", r.Scope)
	}
}

func TestTokensCachedPerUserAndRefreshedOn401(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, nil)
	var out map[string]any
	for i := 0; i < 3; i++ {
		if err := c.GmailSettings(context.Background(), "erin@example.com", "filters", &out); err != nil {
			t.Fatal(err)
		}
	}
	if calls, _ := s.TokenCalls(); calls != 1 {
		t.Errorf("3 reads of one user made %d token requests", calls)
	}
	s.RevokeTokens()
	if err := c.GmailSettings(context.Background(), "erin@example.com", "filters", &out); err != nil {
		t.Fatalf("a revoked token must be refreshed once: %v", err)
	}
	if calls, _ := s.TokenCalls(); calls != 2 {
		t.Errorf("token requests after revoke = %d, want 2", calls)
	}
	// A 401 that a new token does not cure is reported, not looped on.
	s.Fail("*", 401, -1, nil)
	err := c.GmailSettings(context.Background(), "erin@example.com", "filters", &out)
	if google.KindOf(err) != google.KindUnauthorized {
		t.Errorf("persistent 401 = %v (kind %q)", err, google.KindOf(err))
	}
}

func TestThrottlingIsRetriedWithBackoffAndReported(t *testing.T) {
	s := gwstest.New(t)
	var slept []time.Duration
	c := newClient(t, s, func(cfg *google.Config) {
		cfg.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	})
	// 429 with Retry-After: the wait asked for is the wait taken.
	s.Fail("/admin/directory/v1/users", 429, 2, map[string]string{"Retry-After": "7"})
	if n, err := listUsers(t, c); err != nil || n != 11 {
		t.Fatalf("after two 429s: %d users, %v", n, err)
	}
	if len(slept) != 2 || slept[0] != 7*time.Second || slept[1] != 7*time.Second {
		t.Errorf("slept %v, want two waits of 7s", slept)
	}

	// Google reports rate limits as 403 with a reason: retried like a 429, not
	// mistaken for a missing permission.
	slept = nil
	s.FailBody("/admin/directory/v1/users", 403, 2, nil, `{"error":{"code":403,"message":"User Rate Limit Exceeded","errors":[{"domain":"usageLimits","reason":"userRateLimitExceeded"}]}}`)
	if n, err := listUsers(t, c); err != nil || n != 11 {
		t.Fatalf("after two rate-limit 403s: %d users, %v", n, err)
	}
	if len(slept) != 2 || slept[0] != time.Second || slept[1] != 2*time.Second {
		t.Errorf("backoff = %v, want 1s then 2s", slept)
	}

	// The retries run out: the answer is "throttled", never an empty list.
	slept = nil
	s.Fail("/admin/directory/v1/users", 429, -1, nil)
	_, err := listUsers(t, c)
	if google.KindOf(err) != google.KindThrottled || !strings.Contains(google.Reason(err), "throttled") {
		t.Errorf("persistent 429 = %v", err)
	}
	if len(slept) != 4 {
		t.Errorf("slept %d times, want 4 (5 attempts)", len(slept))
	}

	// A wait longer than MaxWait is reported at once, not slept through.
	slept = nil
	s.Fail("/admin/directory/v1/users", 429, -1, map[string]string{"Retry-After": "3600"})
	_, err = listUsers(t, c)
	if google.KindOf(err) != google.KindThrottled || len(slept) != 0 {
		t.Errorf("long Retry-After: %v, slept %v", err, slept)
	}

	// The daily limit is not retried.
	slept = nil
	s.FailBody("/admin/directory/v1/users", 403, -1, nil, `{"error":{"code":403,"message":"Daily Limit Exceeded","errors":[{"domain":"usageLimits","reason":"dailyLimitExceeded"}]}}`)
	_, err = listUsers(t, c)
	if google.KindOf(err) != google.KindThrottled || len(slept) != 0 {
		t.Errorf("daily limit: %v, slept %v", err, slept)
	}
}

func TestServerErrorsAreRetriedThenReported(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, nil)
	s.Fail("/admin/directory/v1/users", 503, 1, nil)
	if n, err := listUsers(t, c); err != nil || n != 11 {
		t.Fatalf("after one 503: %d, %v", n, err)
	}
	s.Fail("/admin/directory/v1/users", 500, -1, nil)
	if _, err := listUsers(t, c); google.KindOf(err) != google.KindServer {
		t.Errorf("persistent 500 = %v", err)
	}
}

func TestForbiddenAndNotFoundAreClassified(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, nil)
	var out map[string]any
	cases := []struct {
		status    int
		body      string
		kind      google.Kind
		code      string
		reasonHas string
	}{
		{403, `{"error":{"code":403,"message":"Gmail API has not been used in project 123 before or it is disabled.","errors":[{"domain":"usageLimits","reason":"accessNotConfigured"}]}}`, google.KindForbidden, "accessNotConfigured", "not enabled in the service account's Google Cloud project"},
		{403, `{"error":{"code":403,"message":"The domain administrators have disabled Gmail apps.","errors":[{"domain":"global","reason":"domainPolicy"}]}}`, google.KindForbidden, "domainPolicy", "disabled this API for apps"},
		{403, `{"error":{"code":403,"message":"Insufficient Permission","errors":[{"reason":"insufficientPermissions"}]}}`, google.KindForbidden, "insufficientPermissions", "refused the read (403)"},
		{403, `{"error":{"code":403,"message":"x","status":"PERMISSION_DENIED"}}`, google.KindForbidden, "PERMISSION_DENIED", ""},
		{400, `{"error":{"code":400,"message":"Mail service not enabled","errors":[{"domain":"global","reason":"failedPrecondition","message":"Mail service not enabled"}],"status":"FAILED_PRECONDITION"}}`, google.KindNotFound, "failedPrecondition", ""},
		{400, `{"error":{"code":400,"message":"Precondition check failed.","errors":[{"reason":"failedPrecondition"}]}}`, google.KindNotFound, "failedPrecondition", ""},
		{400, `{"error":{"code":400,"message":"Precondition check failed.","status":"FAILED_PRECONDITION"}}`, google.KindNotFound, "FAILED_PRECONDITION", ""},
		{400, `{"error":{"code":400,"message":"Mail service not enabled","errors":[{"reason":"badRequest"}]}}`, google.KindNotFound, "badRequest", ""},
		{404, `{"error":{"code":404,"message":"Not Found"}}`, google.KindNotFound, "", ""},
		{400, `{"error":{"code":400,"message":"Invalid value","errors":[{"reason":"badRequest"}]}}`, google.KindBadResponse, "badRequest", ""},
	}
	for i, tc := range cases {
		s.FailBody("/gmail/v1/users/me/settings/filters", tc.status, 1, nil, tc.body)
		err := c.GmailSettings(context.Background(), "erin@example.com", "filters", &out)
		if google.KindOf(err) != tc.kind || google.CodeOf(err) != tc.code {
			t.Errorf("case %d: kind %q code %q (%v), want %q %q", i, google.KindOf(err), google.CodeOf(err), err, tc.kind, tc.code)
		}
		if tc.reasonHas != "" && !strings.Contains(google.Reason(err), tc.reasonHas) {
			t.Errorf("case %d: reason %q lacks %q", i, google.Reason(err), tc.reasonHas)
		}
	}
}

func TestTokenRefusalsAreClassified(t *testing.T) {
	// A key Google does not know: the credentials.
	s := gwstest.New(t)
	s.RejectKey = true
	c := newClient(t, s, nil)
	_, err := listUsers(t, c)
	if google.KindOf(err) != google.KindCredentials || google.CodeOf(err) != "invalid_grant" {
		t.Errorf("rejected key = %v (%q %q)", err, google.KindOf(err), google.CodeOf(err))
	}

	// Delegation missing for a scope: unauthorized_client is the delegation, with the
	// numeric-client-id hint, and no request reaches an API.
	s = gwstest.New(t)
	s.DelegatedScopes[google.ScopeGmailReadonly] = true
	c = newClient(t, s, nil)
	_, err = listUsers(t, c)
	if google.KindOf(err) != google.KindDelegation || !strings.Contains(google.Reason(err), "numeric client ID") {
		t.Errorf("missing delegation = %v", err)
	}
	if len(s.Requests()) != 0 {
		t.Errorf("a refused token still led to %d API requests", len(s.Requests()))
	}

	// The administrator is not a user: a credential failure for the whole read.
	s = gwstest.New(t)
	s.RejectSubjects[gwstest.AdminEmail] = true
	c = newClient(t, s, nil)
	_, err = listUsers(t, c)
	if google.KindOf(err) != google.KindCredentials || !strings.Contains(err.Error(), "administrator email") {
		t.Errorf("bad admin = %v (%q)", err, google.KindOf(err))
	}

	// A mailbox owner Google will not let us act as: that mailbox only.
	s = gwstest.New(t)
	s.RejectSubjects["erin@example.com"] = true
	c = newClient(t, s, nil)
	var out map[string]any
	err = c.GmailSettings(context.Background(), "erin@example.com", "filters", &out)
	if google.KindOf(err) != google.KindSubject {
		t.Errorf("rejected mailbox owner = %v (%q)", err, google.KindOf(err))
	}
}

func TestErrorTextNeverHoldsCredentialsOrBodies(t *testing.T) {
	s := gwstest.New(t)
	file, acct := s.NewKey()
	_ = acct
	var kf struct {
		PrivateKey string `json:"private_key"`
	}
	_ = json.Unmarshal(file, &kf)
	cfg := s.Config()
	_, acct2 := s.NewKey()
	cfg.Account = acct2
	c, _ := google.New(cfg)
	s.FailBody("/admin/directory/v1/users", 403, 1, nil, `{"error":{"code":403,"message":"secret-looking-body-text\nsecond line","errors":[{"reason":"forbidden"}]}}`)
	_, err := listUsers(t, c)
	if err == nil {
		t.Fatal("no error")
	}
	for _, text := range []string{err.Error(), google.Reason(err)} {
		if strings.Contains(text, "second line") || strings.Contains(text, "fixture-token") || strings.Contains(text, "BEGIN") || strings.Contains(text, kf.PrivateKey[:30]) {
			t.Errorf("error text leaks: %q", text)
		}
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(200)
	}))
	defer evil.Close()
	s := gwstest.New(t)
	cfg := s.Config()
	// Directory answers a redirect to another host: the bearer token must not follow.
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
	}))
	defer redirector.Close()
	cfg.DirectoryURL = redirector.URL
	c, err := google.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = listUsers(t, c)
	if err == nil || hits.Load() != 0 {
		t.Errorf("redirect: err %v, the other host was hit %d times", err, hits.Load())
	}
}

func TestRequestBudgetIsEnforced(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, func(cfg *google.Config) { cfg.MaxRequests = 1 })
	_, err := listUsers(t, c)
	if google.KindOf(err) != google.KindThrottled || !strings.Contains(err.Error(), "budget") {
		t.Errorf("budget = %v", err)
	}
}

func TestBadJSONIsABadResponseNotAnEmptyList(t *testing.T) {
	s := gwstest.New(t)
	c := newClient(t, s, nil)
	s.Override["/admin/directory/v1/users"] = `<html>not json</html>`
	n, err := listUsers(t, c)
	if google.KindOf(err) != google.KindBadResponse || n != 0 {
		t.Errorf("html answer: %d users, %v", n, err)
	}
}
