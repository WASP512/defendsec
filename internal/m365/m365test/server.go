// Package m365test is a fake Microsoft Graph and Entra login endpoint for tests,
// serving scrubbed fixtures (example.com addresses, made-up GUIDs) shaped like
// the responses Microsoft documents. It records every request, so a test can
// prove the collector only ever reads, and it can be told to fail a route with
// a status (401, 403, 429 with Retry-After, 503).
package m365test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"defendsec/internal/m365/graph"
)

//go:embed fixtures/*.json
var fixtures embed.FS

// Fixture identifiers.
const (
	TenantID     = "aaaaaaaa-1111-4222-8333-444444444444"
	ClientID     = "bbbbbbbb-1111-4222-8333-555555555555"
	ClientSecret = "fixture-client-secret-not-a-secret"

	UserAlexAdmin = "11111111-0000-4000-8000-000000000001" // Global Administrator, MFA registered
	UserSamAdmin  = "11111111-0000-4000-8000-000000000002" // Global Administrator, no MFA
	UserPatHelp   = "11111111-0000-4000-8000-000000000003" // Helpdesk Administrator, no MFA
	UserCasey     = "11111111-0000-4000-8000-000000000004" // regular, no MFA, QuickBooks-to-RSS rule
	UserDana      = "11111111-0000-4000-8000-000000000005" // MFA, external forward with delete
	UserErin      = "11111111-0000-4000-8000-000000000006" // MFA, only harmless rules
	UserNoMailbox = "11111111-0000-4000-8000-000000000007" // member with no Exchange mailbox
	UserFormer    = "11111111-0000-4000-8000-000000000008" // disabled account
	UserGuest     = "11111111-0000-4000-8000-000000000009" // guest

	FolderRSS  = "AAMkADRSSFOLDER="
	FolderNews = "AAMkADNEWSFOLDER="
)

// Req is one request the server saw.
type Req struct {
	Method string
	Path   string
	Query  string
	Auth   string
}

type forced struct {
	status  int
	headers map[string]string
	body    string
	left    int // requests still to fail; <0 means every one
}

// Server is the fake endpoint.
type Server struct {
	*httptest.Server
	t  *testing.T
	mu sync.Mutex

	reqs       []Req
	tokenCalls int
	issued     map[string]bool
	jtis       map[string]bool
	force      map[string]*forced

	// SecurityDefaultsOn answers the security defaults policy with isEnabled true.
	SecurityDefaultsOn bool
	// BlockLegacy serves a Conditional Access policy that blocks legacy sign-in
	// (with an exclusion group) instead of the report-only one.
	BlockLegacy bool
	// RejectToken makes the token endpoint refuse the credentials.
	RejectToken bool
	// Cert, when set, is the certificate whose key signs the client assertion the
	// token endpoint will accept (and the secret is then not accepted).
	CertDER []byte
	CertPub *rsa.PublicKey
	// Override replaces the body of a route (key: the path after /v1.0, no query).
	Override map[string]string
}

// New starts the server; it closes with the test.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{t: t, issued: map[string]bool{}, jtis: map[string]bool{}, force: map[string]*forced{}, Override: map[string]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Config is a client configuration pointed at the server, with the client secret.
func (s *Server) Config() graph.Config {
	return graph.Config{
		TenantID: TenantID, ClientID: ClientID, Secret: ClientSecret,
		LoginURL: s.URL, GraphURL: s.URL,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
}

// Fail makes the next count requests to a route (path after /v1.0, or "*" for
// every Graph route) answer with status; count < 0 fails them all. headers are
// added (Retry-After).
func (s *Server) Fail(path string, status, count int, headers map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.force[path] = &forced{status: status, headers: headers, left: count}
}

// FailBody is Fail with a body (Graph's error JSON).
func (s *Server) FailBody(path string, status, count int, headers map[string]string, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.force[path] = &forced{status: status, headers: headers, body: body, left: count}
}

// RevokeTokens makes every token issued so far invalid (Graph then answers 401).
func (s *Server) RevokeTokens() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued = map[string]bool{}
}

// Requests returns the Graph requests seen, in order (token requests excluded).
func (s *Server) Requests() []Req {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Req(nil), s.reqs...)
}

// TokenRequests is how many token requests were made.
func (s *Server) TokenRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokenCalls
}

// Count returns how many Graph requests had a path with this prefix.
func (s *Server) Count(prefix string) int {
	n := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, prefix) {
			n++
		}
	}
	return n
}

func (s *Server) fixture(name string) string {
	b, err := fixtures.ReadFile("fixtures/" + name)
	if err != nil {
		s.t.Fatalf("fixture %s: %v", name, err)
	}
	return strings.ReplaceAll(string(b), "{{BASE}}", s.URL)
}

func write(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func graphErr(w http.ResponseWriter, status int, code, msg string) {
	write(w, status, fmt.Sprintf(`{"error":{"code":%q,"message":%q,"innerError":{"request-id":"00000000-0000-0000-0000-000000000000"}}}`, code, msg))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
		s.token(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1.0")
	if !strings.HasPrefix(r.URL.Path, "/v1.0/") {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	ok := strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && s.issued[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	s.reqs = append(s.reqs, Req{Method: r.Method, Path: path, Query: r.URL.RawQuery, Auth: r.Header.Get("Authorization")})
	var f *forced
	for _, k := range []string{path, "*"} {
		if c := s.force[k]; c != nil && c.left != 0 {
			if c.left > 0 {
				c.left--
			}
			f = c
			break
		}
	}
	s.mu.Unlock()
	if r.Method != http.MethodGet {
		graphErr(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "the fixture server only answers GET")
		return
	}
	if !ok {
		graphErr(w, http.StatusUnauthorized, "InvalidAuthenticationToken", "Access token is empty or invalid.")
		return
	}
	if f != nil {
		for k, v := range f.headers {
			w.Header().Set(k, v)
		}
		body := f.body
		if body == "" {
			body = fmt.Sprintf(`{"error":{"code":"Forced%d","message":"forced by the test"}}`, f.status)
		}
		write(w, f.status, body)
		return
	}
	if b, ok := s.Override[path]; ok {
		write(w, http.StatusOK, b)
		return
	}
	switch {
	case path == "/users":
		if strings.Contains(r.URL.RawQuery, "skiptoken=page2") {
			write(w, 200, s.fixture("users_page2.json"))
		} else {
			write(w, 200, s.fixture("users_page1.json"))
		}
	case path == "/reports/authenticationMethods/userRegistrationDetails":
		write(w, 200, s.fixture("registration_details.json"))
	case path == "/roleManagement/directory/roleDefinitions":
		write(w, 200, s.fixture("role_definitions.json"))
	case path == "/roleManagement/directory/roleAssignments":
		write(w, 200, s.fixture("role_assignments.json"))
	case path == "/policies/identitySecurityDefaultsEnforcementPolicy":
		if s.SecurityDefaultsOn {
			write(w, 200, s.fixture("security_defaults_on.json"))
		} else {
			write(w, 200, s.fixture("security_defaults_off.json"))
		}
	case path == "/identity/conditionalAccess/policies":
		if s.BlockLegacy {
			write(w, 200, s.fixture("ca_policies_block_legacy.json"))
		} else {
			write(w, 200, s.fixture("ca_policies_report_only.json"))
		}
	case strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/mailFolders/inbox/messageRules"):
		id := strings.Split(strings.TrimPrefix(path, "/users/"), "/")[0]
		switch id {
		case UserCasey:
			write(w, 200, s.fixture("rules_casey.json"))
		case UserDana:
			write(w, 200, s.fixture("rules_dana.json"))
		case UserErin:
			write(w, 200, s.fixture("rules_erin.json"))
		case UserNoMailbox:
			graphErr(w, http.StatusNotFound, "MailboxNotEnabledForRESTAPI", "The mailbox is either inactive, soft-deleted, or is hosted on-premise.")
		default:
			write(w, 200, s.fixture("rules_empty.json"))
		}
	case strings.HasPrefix(path, "/users/") && strings.Contains(path, "/mailFolders/"):
		folder, _ := url.PathUnescape(path[strings.LastIndex(path, "/")+1:])
		switch folder {
		case FolderRSS:
			write(w, 200, `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#users('x')/mailFolders(displayName)/$entity","id":"`+FolderRSS+`","displayName":"RSS Feeds"}`)
		case FolderNews:
			write(w, 200, `{"id":"`+FolderNews+`","displayName":"Newsletters"}`)
		default:
			graphErr(w, http.StatusNotFound, "ErrorItemNotFound", "The specified object was not found in the store.")
		}
	default:
		graphErr(w, http.StatusNotFound, "Request_ResourceNotFound", "Resource not found for the segment.")
	}
}

func b64d(s string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return b
}

func tokenErr(w http.ResponseWriter, status int, code, desc string) {
	write(w, status, fmt.Sprintf(`{"error":%q,"error_description":%q,"error_codes":[0],"timestamp":"2026-10-24 12:00:00Z","trace_id":"00000000-0000-0000-0000-000000000000","correlation_id":"00000000-0000-0000-0000-000000000000"}`, code, desc))
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokenCalls++
	s.mu.Unlock()
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		tokenErr(w, 400, "invalid_request", "AADSTS900144: bad form")
		return
	}
	if !strings.Contains(r.URL.Path, "/"+TenantID+"/") {
		tokenErr(w, 400, "invalid_request", "AADSTS90002: Tenant not found.\r\nTrace ID: 0000")
		return
	}
	if r.PostForm.Get("client_id") != ClientID || r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "https://graph.microsoft.com/.default" {
		tokenErr(w, 400, "invalid_request", "AADSTS900144: the request body is missing a required parameter")
		return
	}
	if s.RejectToken {
		tokenErr(w, 401, "invalid_client", "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID.\r\nTrace ID: 0000")
		return
	}
	if s.CertDER != nil {
		if !s.verifyAssertion(w, r) {
			return
		}
	} else if r.PostForm.Get("client_secret") != ClientSecret {
		tokenErr(w, 401, "invalid_client", "AADSTS7000215: Invalid client secret provided.\r\nTrace ID: 0000")
		return
	}
	tok := fmt.Sprintf("fixture-token-%d", time.Now().UnixNano())
	s.mu.Lock()
	s.issued[tok] = true
	s.mu.Unlock()
	write(w, 200, fmt.Sprintf(`{"token_type":"Bearer","expires_in":3599,"ext_expires_in":3599,"access_token":%q}`, tok))
}

func (s *Server) verifyAssertion(w http.ResponseWriter, r *http.Request) bool {
	bad := func(msg string) bool {
		tokenErr(w, 401, "invalid_client", "AADSTS700027: Client assertion failed signature validation: "+msg)
		return false
	}
	if r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		return bad("wrong assertion type")
	}
	if r.PostForm.Get("client_secret") != "" {
		return bad("a secret was sent beside the assertion")
	}
	parts := strings.Split(r.PostForm.Get("client_assertion"), ".")
	if len(parts) != 3 {
		return bad("not a JWT")
	}
	var hdr map[string]string
	if json.Unmarshal(b64d(parts[0]), &hdr) != nil || hdr["alg"] != "PS256" || hdr["typ"] != "JWT" {
		return bad("header")
	}
	sum := sha256.Sum256(s.CertDER)
	if hdr["x5t#S256"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return bad("thumbprint")
	}
	var c struct {
		Aud string `json:"aud"`
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Jti string `json:"jti"`
		Exp int64  `json:"exp"`
		Nbf int64  `json:"nbf"`
	}
	if json.Unmarshal(b64d(parts[1]), &c) != nil {
		return bad("claims")
	}
	if c.Aud != s.URL+"/"+TenantID+"/oauth2/v2.0/token" || c.Iss != ClientID || c.Sub != ClientID || c.Jti == "" {
		return bad("claims do not match")
	}
	now := time.Now().Unix()
	if c.Exp <= now || c.Exp > now+3600 || c.Nbf > now+60 {
		return bad("times")
	}
	s.mu.Lock()
	replay := s.jtis[c.Jti]
	s.jtis[c.Jti] = true
	s.mu.Unlock()
	if replay {
		return bad("jti replayed")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPSS(s.CertPub, crypto.SHA256, digest[:], b64d(parts[2]), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
		return bad("signature")
	}
	return true
}
