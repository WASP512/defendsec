// Package gwstest is a fake Google OAuth token endpoint, Admin SDK Directory API
// and Gmail settings API for tests, serving scrubbed fixtures (example.com
// addresses, made-up ids) shaped like the responses Google documents. It checks
// the service account's signed JWT (RS256, issuer, audience, scope, subject), so
// a test proves the client signs what Google asks for. It records every API
// request, so a test can prove the collector only ever reads, and it can be told
// to fail a route with a status (401, 403 with a reason, 429 with Retry-After,
// 503) or to refuse a token the way Google does when delegation is missing.
package gwstest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/gws/google"
)

// Fixture identifiers.
const (
	Domain       = "example.com"
	AdminEmail   = "alex@example.com"
	ServiceEmail = "defendsec-reader@fixture-project.iam.gserviceaccount.com"
	ClientID     = "100000000000000000001"

	UserAlex   = "u-1001" // super administrator, enrolled, enforced
	UserSam    = "u-1002" // super administrator, not enrolled
	UserPat    = "u-1003" // delegated administrator, not enrolled
	UserCasey  = "u-1004" // regular, not enrolled, hides invoice mail
	UserDana   = "u-1005" // enrolled, forwards everything outside and archives
	UserErin   = "u-1006" // enrolled, only harmless filters
	UserNoMail = "u-1007" // no Gmail mailbox
	UserFormer = "u-1008" // suspended
	UserGuest  = "u-1009" // guest
	UserFran   = "u-1010" // enrolled, a filter with no condition trashing everything
	UserGil    = "u-1011" // enrolled, hides security notices
)

// The fixtures. Empty lists are omitted, as Google omits them.
const usersPage1 = `{
  "kind": "admin#directory#users",
  "nextPageToken": "page-2-token",
  "users": [
    {"id":"u-1001","primaryEmail":"alex@example.com","name":{"fullName":"Alex Admin"},"isAdmin":true,"isDelegatedAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/"},
    {"id":"u-1002","primaryEmail":"sam@example.com","name":{"fullName":"Sam Super"},"isAdmin":true,"isDelegatedAdmin":false,"isEnrolledIn2Sv":false,"isEnforcedIn2Sv":false,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/"},
    {"id":"u-1003","primaryEmail":"pat@example.com","name":{"fullName":"Pat Helpdesk"},"isAdmin":false,"isDelegatedAdmin":true,"isEnrolledIn2Sv":false,"isEnforcedIn2Sv":false,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Staff"},
    {"id":"u-1004","primaryEmail":"casey@example.com","name":{"fullName":"Casey Books"},"aliases":["casey.books@alias.example.net"],"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":false,"isEnforcedIn2Sv":false,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Staff"},
    {"id":"u-1005","primaryEmail":"dana@example.com","name":{"fullName":"Dana Sales"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Staff"},
    {"id":"u-1006","primaryEmail":"erin@example.com","name":{"fullName":"Erin Ops"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Staff"}
  ]
}`

const usersPage2 = `{
  "kind": "admin#directory#users",
  "users": [
    {"id":"u-1007","primaryEmail":"nomail@example.com","name":{"fullName":"No Mailbox"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"suspended":false,"archived":false,"isMailboxSetup":false,"orgUnitPath":"/Staff"},
    {"id":"u-1008","primaryEmail":"former@example.com","name":{"fullName":"Former Staff"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":false,"isEnforcedIn2Sv":false,"suspended":true,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Former"},
    {"id":"u-1009","primaryEmail":"partner@other.example.org","name":{"fullName":"Guest Partner"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":false,"isEnforcedIn2Sv":false,"suspended":false,"archived":false,"isMailboxSetup":true,"isGuestUser":true,"orgUnitPath":"/"},
    {"id":"u-1010","primaryEmail":"fran@example.com","name":{"fullName":"Fran Front"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":false,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Staff"},
    {"id":"u-1011","primaryEmail":"gil@example.com","name":{"fullName":"Gil Guard"},"isAdmin":false,"isDelegatedAdmin":false,"isEnrolledIn2Sv":true,"isEnforcedIn2Sv":true,"suspended":false,"archived":false,"isMailboxSetup":true,"orgUnitPath":"/Staff"}
  ]
}`

// autoForwarding by user email.
var autoForwarding = map[string]string{
	"dana@example.com": `{"enabled":true,"emailAddress":"dana.private@mail.example.org","disposition":"archive"}`,
	"erin@example.com": `{"enabled":true,"emailAddress":"erin.backup@example.com","disposition":"leaveInInbox"}`,
	"gil@example.com":  `{"enabled":false,"emailAddress":"old.address@mail.example.org","disposition":"leaveInInbox"}`,
}

// filters by user email.
var filters = map[string]string{
	// The business-email-compromise lookalike: invoice mail from the books provider
	// is marked read and taken out of the inbox.
	"casey@example.com": `{"filter":[
	  {"id":"ANe1BmCaseyFilter1","criteria":{"from":"noreply@intuit.com","subject":"invoice"},"action":{"removeLabelIds":["INBOX","UNREAD"]}}
	]}`,
	"dana@example.com": `{"filter":[
	  {"id":"ANe1BmDanaFilter1","criteria":{"from":"billing@vendor.example.net"},"action":{"forward":"dana.private@mail.example.org","addLabelIds":["TRASH"]}}
	]}`,
	"erin@example.com": `{"filter":[
	  {"id":"ANe1BmErinFilter1","criteria":{"from":"newsletter@list.example.net"},"action":{"addLabelIds":["Label_17"],"removeLabelIds":["INBOX"]}},
	  {"id":"ANe1BmErinFilter2","criteria":{"to":"help@example.com"},"action":{"forward":"erin.backup@example.com"}},
	  {"id":"ANe1BmErinFilter3","criteria":{"query":"has:attachment filename:pdf"},"action":{"addLabelIds":["STARRED","CATEGORY_UPDATES"]}}
	]}`,
	"fran@example.com": `{"filter":[
	  {"id":"ANe1BmFranFilter1","criteria":{},"action":{"addLabelIds":["TRASH"]}}
	]}`,
	"gil@example.com": `{"filter":[
	  {"id":"ANe1BmGilFilter1","criteria":{"subject":"security alert"},"action":{"removeLabelIds":["INBOX"]}}
	]}`,
}

// Req is one API request the server saw (token requests are counted apart).
type Req struct {
	Method string
	Path   string
	Query  string
	// Sub and Scope are those of the access token the request carried.
	Sub   string
	Scope string
}

type forced struct {
	status  int
	headers map[string]string
	body    string
	left    int // requests still to fail; <0 means every one
}

type issued struct{ sub, scope string }

// Server is the fake endpoint.
type Server struct {
	*httptest.Server
	t  *testing.T
	mu sync.Mutex

	pub *rsa.PublicKey

	reqs       []Req
	tokenCalls int
	subjects   []string // subs of token requests, in order
	tokens     map[string]issued
	force      map[string]*forced

	// DelegatedScopes are the scopes the (fake) Admin console has delegated: a token
	// request for any other scope is refused with unauthorized_client. Empty means
	// every scope.
	DelegatedScopes map[string]bool
	// RejectSubjects are users Google will not issue a token for (invalid_grant).
	RejectSubjects map[string]bool
	// RejectKey makes the token endpoint refuse the signature (invalid_grant).
	RejectKey bool
	// TokenRefusal, when set, is the JSON body the token endpoint answers every
	// request with, as a 400 (for the OAuth error codes the other switches do not make).
	TokenRefusal string
	// Override replaces the body of a route (key: the request path, no query).
	Override map[string]string
	// AutoForwarding and Filters override the fixtures per user email.
	AutoForwarding map[string]string
	Filters        map[string]string
}

// New starts the server; it closes with the test.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{t: t, tokens: map[string]issued{}, force: map[string]*forced{}, Override: map[string]string{},
		DelegatedScopes: map[string]bool{}, RejectSubjects: map[string]bool{}, AutoForwarding: map[string]string{}, Filters: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// NewKey makes a service account with a fresh RSA key and returns its JSON key
// file as Google issues it, and the parsed account. The server accepts only
// assertions signed by it.
func (s *Server) NewKey() ([]byte, *google.ServiceAccount) {
	s.t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s.t.Fatal(err)
	}
	s.pub = &key.PublicKey
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		s.t.Fatal(err)
	}
	file, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "fixture-project", "private_key_id": "0123456789abcdef0123456789abcdef01234567",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": ServiceEmail, "client_id": ClientID,
		"token_uri": "https://oauth2.googleapis.com/token",
	})
	acct, err := google.ParseServiceAccountJSON(file)
	if err != nil {
		s.t.Fatal(err)
	}
	return file, acct
}

// Config is a client configuration pointed at the server, with a fresh key.
func (s *Server) Config() google.Config {
	_, acct := s.NewKey()
	return google.Config{
		Account: acct, AdminEmail: AdminEmail,
		TokenURL: s.URL + "/token", DirectoryURL: s.URL, GmailURL: s.URL,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
}

// Fail makes the next count requests to a route (the request path, or "*" for every
// API route) answer with status; count < 0 fails them all. headers are added.
func (s *Server) Fail(path string, status, count int, headers map[string]string) {
	s.FailBody(path, status, count, headers, "")
}

// FailBody is Fail with a body (Google's error JSON).
func (s *Server) FailBody(path string, status, count int, headers map[string]string, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.force[path] = &forced{status: status, headers: headers, body: body, left: count}
}

// RevokeTokens makes every token issued so far invalid (the APIs then answer 401).
func (s *Server) RevokeTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = map[string]issued{}
}

// Requests returns the API requests seen, in order (token requests excluded).
func (s *Server) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// TokenCalls is how many token requests were made, and for which subjects.
func (s *Server) TokenCalls() (int, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls, append([]string(nil), s.subjects...)
}

func b64d(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func writeErr(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokenCalls++
	n := s.tokenCalls // this request's own number: concurrent requests must not share a token
	s.mu.Unlock()
	if r.Method != http.MethodPost {
		writeErr(w, 405, `{"error":"invalid_request"}`)
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		writeErr(w, 400, `{"error":"unsupported_grant_type","error_description":"Invalid grant_type"}`)
		return
	}
	if s.TokenRefusal != "" {
		writeErr(w, 400, s.TokenRefusal)
		return
	}
	parts := strings.Split(r.PostForm.Get("assertion"), ".")
	if len(parts) != 3 {
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe."}`)
		return
	}
	hdr, e1 := b64d(parts[0])
	cl, e2 := b64d(parts[1])
	sig, e3 := b64d(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
		return
	}
	var h struct{ Alg, Typ, Kid string }
	var c struct {
		Iss, Sub, Scope, Aud string
		Iat, Exp             int64
	}
	_ = json.Unmarshal(hdr, &h)
	_ = json.Unmarshal(cl, &c)
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if s.RejectKey || s.pub == nil || h.Alg != "RS256" || rsa.VerifyPKCS1v15(s.pub, crypto.SHA256, sum[:], sig) != nil {
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
		return
	}
	now := time.Now().Unix()
	switch {
	case c.Iss != ServiceEmail:
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
		return
	case c.Aud != s.URL+"/token":
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid audience"}`)
		return
	case c.Exp-c.Iat > 3600 || c.Exp <= now || c.Iat > now+300:
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid JWT: Token must be a short-lived token (60 minutes) and in a reasonable timeframe. Check your 'iat' and 'exp' values and use a clock with skew to account for clock differences between systems."}`)
		return
	case strings.TrimSpace(c.Scope) == "":
		writeErr(w, 400, `{"error":"invalid_scope","error_description":"Invalid OAuth scope or ID token audience provided."}`)
		return
	}
	if len(s.DelegatedScopes) > 0 {
		for _, sc := range strings.Fields(c.Scope) {
			if !s.DelegatedScopes[sc] {
				writeErr(w, 401, `{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."}`)
				return
			}
		}
	}
	if c.Sub == "" || s.RejectSubjects[c.Sub] {
		writeErr(w, 400, `{"error":"invalid_grant","error_description":"Invalid email or User ID"}`)
		return
	}
	s.mu.Lock()
	s.subjects = append(s.subjects, c.Sub)
	tok := fmt.Sprintf("fixture-token-%d", n)
	s.tokens[tok] = issued{sub: c.Sub, scope: c.Scope}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599,"token_type":"Bearer"}`, tok)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		s.serveToken(w, r)
		return
	}
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	is, ok := s.tokens[tok]
	s.reqs = append(s.reqs, Req{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Sub: is.sub, Scope: is.scope})
	f := s.force[r.URL.Path]
	if f == nil {
		f = s.force["*"]
	}
	var fail *forced
	if f != nil && f.left != 0 {
		if f.left > 0 {
			f.left--
		}
		cp := *f
		fail = &cp
	}
	s.mu.Unlock()
	if r.Method != http.MethodGet {
		writeErr(w, 405, `{"error":{"code":405,"message":"Method Not Allowed"}}`)
		return
	}
	if !ok {
		writeErr(w, 401, `{"error":{"code":401,"message":"Invalid Credentials","errors":[{"domain":"global","reason":"authError","message":"Invalid Credentials"}]}}`)
		return
	}
	if fail != nil {
		for k, v := range fail.headers {
			w.Header().Set(k, v)
		}
		body := fail.body
		if body == "" {
			body = fmt.Sprintf(`{"error":{"code":%d,"message":"forced failure"}}`, fail.status)
		}
		writeErr(w, fail.status, body)
		return
	}
	if o, ok := s.Override[r.URL.Path]; ok {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, o)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/admin/directory/v1/users":
		if is.sub != AdminEmail || !strings.Contains(is.scope, "admin.directory.user.readonly") {
			writeErr(w, 403, `{"error":{"code":403,"message":"Not Authorized to access this resource/api","errors":[{"domain":"global","reason":"forbidden","message":"Not Authorized to access this resource/api"}]}}`)
			return
		}
		if r.URL.Query().Get("pageToken") == "page-2-token" {
			_, _ = io.WriteString(w, usersPage2)
			return
		}
		_, _ = io.WriteString(w, usersPage1)
	case r.URL.Path == "/gmail/v1/users/me/settings/autoForwarding":
		body, ok := s.AutoForwarding[is.sub]
		if !ok {
			body, ok = autoForwarding[is.sub]
		}
		if !ok {
			body = `{"disposition":"dispositionUnspecified"}`
		}
		_, _ = io.WriteString(w, body)
	case r.URL.Path == "/gmail/v1/users/me/settings/filters":
		body, ok := s.Filters[is.sub]
		if !ok {
			body, ok = filters[is.sub]
		}
		if !ok {
			body = `{}`
		}
		_, _ = io.WriteString(w, body)
	default:
		writeErr(w, 404, `{"error":{"code":404,"message":"Not Found"}}`)
	}
}
