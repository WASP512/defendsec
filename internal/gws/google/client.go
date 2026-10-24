// Package google is DefendSec's Google Workspace client for the identity posture
// collector (slice 13). It only reads: GET requests, no write method.
//
// It authenticates as a service account with domain-wide delegation: it signs an
// RS256 JWT with the service account's private key, names the user to act as (the
// administrator for the Admin SDK Directory API, each mailbox owner for the Gmail
// settings reads) and exchanges it at Google's token endpoint. It makes GET
// requests only. The one other request it can make is the token request, a POST to
// the token endpoint. There is no method that creates, updates or deletes anything
// in a Workspace account. The Directory scope is read-only; the default Gmail scope
// (gmail.settings.basic) is a write scope for settings that this client never uses
// to write, and the alternative (gmail.readonly) can read mail (docs/GOOGLE-WORKSPACE.md).
//
// Failures are classified (see Kind) and described without a key, a token or a
// response body in the message, so a caller can say "delegation missing" or
// "throttled" and never confuse either with "nothing found".
package google

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The scopes. docs/GOOGLE-WORKSPACE.md says why these and not others (verified
// against Google's reference pages, with the date).
const (
	// ScopeDirectoryUsers reads users, including 2-Step Verification state and
	// administrator flags (Admin SDK Directory API, users.list).
	ScopeDirectoryUsers = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	// ScopeGmailSettingsBasic reads Gmail settings (auto-forwarding, filters): the
	// reference pages of getAutoForwarding, filters.list and forwardingAddresses.list
	// all list it. It is the DEFAULT because it cannot read a message; it is a write
	// scope for settings, which this client never uses (GET only).
	ScopeGmailSettingsBasic = "https://www.googleapis.com/auth/gmail.settings.basic"
	// ScopeGmailReadonly is the alternative for an operator who cannot accept a write
	// scope: the settings reads accept it too, but it could also read every message
	// if the key leaked. This client has no method that touches a message.
	ScopeGmailReadonly = "https://www.googleapis.com/auth/gmail.readonly"
)

const (
	defaultTokenURL     = "https://oauth2.googleapis.com/token"
	defaultDirectoryURL = "https://admin.googleapis.com"
	defaultGmailURL     = "https://gmail.googleapis.com"
)

// Kind classifies a failure.
type Kind string

const (
	// KindCredentials: Google refused the service account's key (bad, revoked or
	// expired key, a clock too far off, a deleted account) or the administrator to
	// act as is not a valid user. Nothing was read.
	KindCredentials Kind = "credentials"
	// KindDelegation: Google would not issue a token for the requested scopes:
	// domain-wide delegation is not set up for this service account and scope.
	KindDelegation Kind = "delegation"
	// KindSubject: Google would not let the service account act as one user (not
	// found, suspended, or the account cannot be impersonated).
	KindSubject Kind = "subject"
	// KindUnauthorized: an API answered 401 even after a new token.
	KindUnauthorized Kind = "unauthorized"
	// KindForbidden: an API answered 403: the API is not enabled in the project, the
	// domain's policy refuses it, or the acting user lacks the privilege.
	KindForbidden Kind = "forbidden"
	// KindNotFound: 404, or Gmail's "mail service not enabled" (no mailbox to read).
	KindNotFound Kind = "not_found"
	// KindThrottled: 429, or a 403 for a rate or quota limit, and the retries ran out.
	KindThrottled Kind = "throttled"
	// KindServer: 5xx and the retries ran out.
	KindServer Kind = "server"
	// KindNetwork: no usable answer (timeout, connection refused, TLS).
	KindNetwork Kind = "network"
	// KindBadResponse: an answer that is not what the API documents.
	KindBadResponse Kind = "bad_response"
)

// Error is a classified failure. Its text never holds a key, a token or a response
// body, only Google's error reason and the first line of its message.
type Error struct {
	Kind   Kind
	Status int
	// Code is Google's error reason ("rateLimitExceeded", "accessNotConfigured") or
	// the token endpoint's error ("invalid_grant", "unauthorized_client").
	Code string
	// Msg is Google's own message, first line only, bounded.
	Msg string
	// RetryAfter is the delay a 429 asked for.
	RetryAfter time.Duration
	// Path is the request path without its query.
	Path string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("google workspace")
	if e.Path != "" {
		b.WriteString(" " + e.Path)
	}
	b.WriteString(": " + string(e.Kind))
	if e.Status != 0 {
		b.WriteString(" (HTTP " + strconv.Itoa(e.Status) + ")")
	}
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Msg != "" {
		b.WriteString(": " + e.Msg)
	}
	return b.String()
}

// KindOf returns the Kind of an error from this package, or "" for another one.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// CodeOf returns Google's error reason, or "".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Reason is a sentence for the console: what went wrong and, where it is known,
// what to do. It is safe to store and show.
func Reason(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		if errors.Is(err, context.DeadlineExceeded) {
			return "the read ran out of time"
		}
		if errors.Is(err, context.Canceled) {
			return "the read was cancelled"
		}
		return "unexpected error"
	}
	detail := ""
	if e.Code != "" {
		detail = " (" + e.Code + ")"
	}
	switch e.Kind {
	case KindCredentials:
		return "Google refused the service account's credentials" + detail + ": check that the key file is the service account's current key, that the key has not been deleted or disabled, that this server's clock is right, and that the administrator email is a user of the domain"
	case KindDelegation:
		return "Google would not issue a token for the requested scope" + detail + ": domain-wide delegation is not set up for this service account and scope in the Admin console (Security > Access and data control > API controls > Domain-wide delegation, using the service account's numeric client ID), or it was added less than a few minutes ago"
	case KindSubject:
		return "Google would not let the service account act as that user" + detail + ": the user does not exist, is suspended, or is not in the domain"
	case KindUnauthorized:
		return "Google refused the access token" + detail
	case KindForbidden:
		switch e.Code {
		case "accessNotConfigured", "SERVICE_DISABLED":
			return "the API is not enabled in the service account's Google Cloud project" + detail + ": enable the Admin SDK API and the Gmail API there"
		case "domainPolicy":
			return "the domain's administrators have disabled this API for apps" + detail
		}
		return "Google refused the read (403)" + detail + ": the acting user lacks the administrator privilege, or the scope is not delegated"
	case KindNotFound:
		return "not found" + detail
	case KindThrottled:
		return "Google throttled the read and the retries ran out" + detail
	case KindServer:
		return "Google returned a server error" + detail
	case KindNetwork:
		return "Google could not be reached"
	}
	return "Google returned an unexpected answer" + detail
}

// ServiceAccount is a service account's key, read from the JSON key file Google
// issues. The private key is never exposed; the identifiers are not secrets.
type ServiceAccount struct {
	email, clientID, keyID, projectID string
	key                               *rsa.PrivateKey
}

// Email is the service account's address (the JWT's issuer).
func (s *ServiceAccount) Email() string { return s.email }

// ClientID is the numeric client ID an administrator enters in the Admin console's
// domain-wide delegation list.
func (s *ServiceAccount) ClientID() string { return s.clientID }

// KeyID is the private key's id (what the Cloud console lists under Keys).
func (s *ServiceAccount) KeyID() string { return s.keyID }

// ProjectID is the Google Cloud project that owns the account.
func (s *ServiceAccount) ProjectID() string { return s.projectID }

// ParseServiceAccountJSON reads a service account key file. Its errors say what is
// wrong with the file and never quote it.
func ParseServiceAccountJSON(data []byte) (*ServiceAccount, error) {
	var f struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
		ClientID     string `json:"client_id"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, errors.New("the key file is not JSON")
	}
	if f.Type != "service_account" {
		return nil, errors.New(`the key file is not a service account key (its "type" is not "service_account"): create a key under IAM & Admin > Service accounts > Keys, JSON`)
	}
	if !strings.Contains(f.ClientEmail, "@") {
		return nil, errors.New("the key file has no client_email")
	}
	blk, _ := pem.Decode([]byte(f.PrivateKey))
	if blk == nil {
		return nil, errors.New("the key file has no private_key in PEM form")
	}
	var rk *rsa.PrivateKey
	switch blk.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("the private key is not a valid PKCS #8 key")
		}
		var ok bool
		if rk, ok = k.(*rsa.PrivateKey); !ok {
			return nil, errors.New("the private key is not an RSA key")
		}
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, errors.New("the private key is not a valid PKCS #1 key")
		}
		rk = k
	default:
		return nil, errors.New("the private key is not a PKCS #8 or PKCS #1 RSA key")
	}
	return &ServiceAccount{email: f.ClientEmail, clientID: f.ClientID, keyID: f.PrivateKeyID, projectID: f.ProjectID, key: rk}, nil
}

// Config configures a Client.
type Config struct {
	Account *ServiceAccount
	// AdminEmail is the user the Directory API is read as: an administrator.
	AdminEmail string
	// GmailScope is the scope for the Gmail settings reads (default ScopeGmailSettingsBasic).
	GmailScope string

	// TokenURL, DirectoryURL and GmailURL override Google's endpoints. They must be
	// https, except for a loopback address (tests).
	TokenURL, DirectoryURL, GmailURL string

	HTTP *http.Client
	// MaxAttempts bounds the tries of one request (default 5: Google's own advice is
	// to retry a rate limit with growing waits up to about 32 seconds).
	MaxAttempts int
	// MaxWait bounds one Retry-After sleep (default 60 s).
	MaxWait time.Duration
	// MaxRequests bounds the API requests one Client makes (0 = 50000).
	MaxRequests int
	// Now and Sleep are replaceable for tests.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client reads one Workspace account.
type Client struct {
	cfg       Config
	tokenURL  *url.URL
	directory *url.URL
	gmail     *url.URL
	hc        *http.Client

	mu     sync.Mutex
	tokens map[string]token

	requests atomic.Int64
}

type token struct {
	value  string
	expiry time.Time
}

func endpointURL(raw, what string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%s URL is not a plain https URL", what)
	}
	if u.Scheme != "https" {
		host, _, _ := net.SplitHostPort(u.Host)
		if host == "" {
			host = u.Host
		}
		ip := net.ParseIP(host)
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("%s URL must be https", what)
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

// ValidEmail reports whether s can be the address of a user: one @, a dotted domain,
// no spaces. It is for a settings form, not a deliverability check.
func ValidEmail(s string) bool {
	i := strings.LastIndexByte(s, '@')
	if i < 1 || i == len(s)-1 || strings.ContainsAny(s, " \t\r\n,;<>\"") || strings.Count(s, "@") != 1 {
		return false
	}
	d := s[i+1:]
	return strings.Contains(d, ".") && !strings.HasPrefix(d, ".") && !strings.HasSuffix(d, ".") && !strings.Contains(d, "..")
}

// New validates the configuration and returns a client. It makes no request.
func New(cfg Config) (*Client, error) {
	if cfg.Account == nil || cfg.Account.key == nil {
		return nil, errors.New("no service account key")
	}
	if !ValidEmail(cfg.AdminEmail) {
		return nil, errors.New("the administrator email must be the address of a user of the domain")
	}
	switch cfg.GmailScope {
	case "":
		cfg.GmailScope = ScopeGmailSettingsBasic
	case ScopeGmailReadonly, ScopeGmailSettingsBasic:
	default:
		return nil, errors.New("the Gmail scope must be gmail.readonly or gmail.settings.basic")
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = defaultTokenURL
	}
	if cfg.DirectoryURL == "" {
		cfg.DirectoryURL = defaultDirectoryURL
	}
	if cfg.GmailURL == "" {
		cfg.GmailURL = defaultGmailURL
	}
	tu, err := endpointURL(cfg.TokenURL, "token")
	if err != nil {
		return nil, err
	}
	du, err := endpointURL(cfg.DirectoryURL, "directory")
	if err != nil {
		return nil, err
	}
	gu, err := endpointURL(cfg.GmailURL, "gmail")
	if err != nil {
		return nil, err
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 60 * time.Second
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 50000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}
	hc := cfg.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	// A redirect would carry the bearer token to wherever it points.
	hcCopy := *hc
	hcCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, tokenURL: tu, directory: du, gmail: gu, hc: &hcCopy, tokens: map[string]token{}}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Requests is how many API requests this client has made (token requests excluded).
func (c *Client) Requests() int { return int(c.requests.Load()) }

// AdminEmail is the user the Directory API is read as.
func (c *Client) AdminEmail() string { return c.cfg.AdminEmail }

// ---- token ---------------------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion builds the signed JWT for the token request: header RS256, claims iss,
// sub, scope, aud, iat and exp, as Google documents for service accounts with
// domain-wide delegation.
func (c *Client) assertion(sub, scope string) (string, error) {
	now := c.cfg.Now()
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if c.cfg.Account.keyID != "" {
		hdr["kid"] = c.cfg.Account.keyID
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(map[string]any{
		"iss": c.cfg.Account.email, "sub": sub, "scope": scope, "aud": c.tokenURL.String(),
		// iat a little in the past tolerates a clock slightly ahead of Google's; the
		// lifetime stays well inside the one hour Google allows.
		"iat": now.Add(-time.Minute).Unix(), "exp": now.Add(50 * time.Minute).Unix(),
	})
	signing := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.cfg.Account.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("could not sign the assertion")
	}
	return signing + "." + b64(sig), nil
}

func oneLine(s string, max int) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

// tokenError classifies an error answer of the token endpoint. The codes and
// descriptions are the ones Google lists on its server-to-server OAuth page.
func tokenError(status int, code, desc string) *Error {
	e := &Error{Status: status, Path: "token", Code: oneLine(code, 60), Msg: oneLine(desc, 200)}
	d := strings.ToLower(desc)
	switch {
	case status == http.StatusTooManyRequests:
		e.Kind = KindThrottled
	case status >= 500:
		e.Kind = KindServer
	case code == "unauthorized_client" || code == "access_denied" || code == "admin_policy_enforced" || code == "invalid_scope":
		e.Kind = KindDelegation
	case code == "invalid_grant" && (strings.Contains(d, "not a valid email") || strings.Contains(d, "invalid email") || strings.Contains(d, "user id")):
		e.Kind = KindSubject
	default:
		// invalid_grant (signature, clock, key), invalid_client, disabled_client,
		// deleted_client, org_internal and anything else: the credentials.
		e.Kind = KindCredentials
	}
	if e.Kind == KindCredentials || e.Kind == KindDelegation || e.Kind == KindSubject {
		// Google's description is not a secret, but keep only its first line.
		e.Msg = oneLine(desc, 160)
	}
	return e
}

// fetchToken exchanges the signed assertion for an access token acting as sub.
func (c *Client) fetchToken(ctx context.Context, sub, scope string) (string, time.Time, error) {
	a, err := c.assertion(sub, scope)
	if err != nil {
		return "", time.Time{}, &Error{Kind: KindCredentials, Path: "token", Msg: err.Error()}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {a}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, &Error{Kind: KindNetwork, Path: "token", Msg: "could not build the token request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", time.Time{}, ctx.Err()
		}
		return "", time.Time{}, &Error{Kind: KindNetwork, Path: "token"}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var te struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &te)
		e := tokenError(resp.StatusCode, te.Error, te.Description)
		if v := resp.Header.Get("Retry-After"); v != "" {
			e.RetryAfter = parseRetryAfter(v)
		}
		return "", time.Time{}, e
	}
	var tr struct {
		TokenType   string `json:"token_type"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", time.Time{}, &Error{Kind: KindBadResponse, Path: "token", Msg: "no bearer token in the answer"}
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 300
	}
	return tr.AccessToken, c.cfg.Now().Add(time.Duration(tr.ExpiresIn) * time.Second), nil
}

// bearer returns a token acting as sub for scope, from the cache while it lasts.
func (c *Client) bearer(ctx context.Context, sub, scope string, force bool) (string, error) {
	k := sub + "\x00" + scope
	c.mu.Lock()
	t, ok := c.tokens[k]
	c.mu.Unlock()
	if !force && ok && c.cfg.Now().Add(time.Minute).Before(t.expiry) {
		return t.value, nil
	}
	v, exp, err := c.fetchToken(ctx, sub, scope)
	if err != nil {
		c.mu.Lock()
		delete(c.tokens, k)
		c.mu.Unlock()
		return "", err
	}
	c.mu.Lock()
	c.tokens[k] = token{v, exp}
	// A long read acting as thousands of users must not keep thousands of tokens.
	if len(c.tokens) > 256 {
		for kk, tt := range c.tokens {
			if kk != k && !c.cfg.Now().Before(tt.expiry) {
				delete(c.tokens, kk)
			}
		}
	}
	c.mu.Unlock()
	return v, nil
}

func parseRetryAfter(v string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// ---- requests ------------------------------------------------------------------

// apiError classifies an error answer of the Directory or Gmail API.
func apiError(resp *http.Response, body []byte, path string) *Error {
	e := &Error{Status: resp.StatusCode, Path: path}
	var ge struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
			Errors  []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
			Details []struct {
				Reason string `json:"reason"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &ge) == nil {
		e.Msg = oneLine(ge.Error.Message, 200)
		switch {
		case len(ge.Error.Errors) > 0 && ge.Error.Errors[0].Reason != "":
			e.Code = oneLine(ge.Error.Errors[0].Reason, 80)
		case len(ge.Error.Details) > 0 && ge.Error.Details[0].Reason != "":
			e.Code = oneLine(ge.Error.Details[0].Reason, 80)
		default:
			e.Code = oneLine(ge.Error.Status, 80)
		}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		e.Kind = KindUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		switch e.Code {
		// Google reports rate and quota limits as 403 with these reasons.
		case "rateLimitExceeded", "userRateLimitExceeded", "quotaExceeded", "dailyLimitExceeded", "RATE_LIMIT_EXCEEDED":
			e.Kind = KindThrottled
		default:
			e.Kind = KindForbidden
		}
	case resp.StatusCode == http.StatusNotFound:
		e.Kind = KindNotFound
	case resp.StatusCode == http.StatusBadRequest && (e.Code == "failedPrecondition" || e.Code == "FAILED_PRECONDITION" || strings.Contains(strings.ToLower(e.Msg), "mail service not enabled")):
		// Gmail's answer for a user who has no Gmail (no licence, mailbox not set up).
		e.Kind = KindNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		e.Kind = KindThrottled
	case resp.StatusCode >= 500:
		e.Kind = KindServer
	default:
		e.Kind = KindBadResponse
	}
	e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	return e
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 32*time.Second {
		d = 32 * time.Second
	}
	return d
}

// do performs one GET acting as sub with scope: a new token once on 401, and the
// retry policy for rate limits and 5xx. It returns the body of a 200.
func (c *Client) do(ctx context.Context, sub, scope string, u *url.URL) ([]byte, error) {
	path := u.Path
	refreshed := false
	var last *Error
	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int(c.requests.Load()) >= c.cfg.MaxRequests {
			return nil, &Error{Kind: KindThrottled, Path: path, Msg: "DefendSec's own request budget for one read is spent"}
		}
		tok, err := c.bearer(ctx, sub, scope, false)
		if err != nil {
			return nil, c.asAdminCredentialError(sub, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, &Error{Kind: KindBadResponse, Path: path, Msg: "could not build the request"}
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		c.requests.Add(1)
		resp, err := c.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			last = &Error{Kind: KindNetwork, Path: path}
			if attempt < c.cfg.MaxAttempts {
				if err := c.cfg.Sleep(ctx, backoff(attempt)); err != nil {
					return nil, err
				}
				continue
			}
			return nil, last
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if rerr != nil {
			last = &Error{Kind: KindNetwork, Path: path}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return body, nil
		}
		e := apiError(resp, body, path)
		switch {
		case e.Kind == KindUnauthorized && !refreshed:
			refreshed = true
			if _, err := c.bearer(ctx, sub, scope, true); err != nil {
				return nil, c.asAdminCredentialError(sub, err)
			}
			attempt--
			continue
		case e.Kind == KindThrottled && e.Code != "dailyLimitExceeded", e.Kind == KindServer:
			last = e
			wait := e.RetryAfter
			if wait <= 0 {
				wait = backoff(attempt)
			}
			if wait > c.cfg.MaxWait || attempt == c.cfg.MaxAttempts {
				return nil, e
			}
			if err := c.cfg.Sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		return nil, e
	}
	if last == nil {
		last = &Error{Kind: KindServer, Path: path}
	}
	return nil, last
}

// asAdminCredentialError turns "cannot act as this user" into a credential failure
// when the user is the administrator: nothing can be read without that one.
func (c *Client) asAdminCredentialError(sub string, err error) error {
	var e *Error
	if errors.As(err, &e) && e.Kind == KindSubject && strings.EqualFold(sub, c.cfg.AdminEmail) {
		cp := *e
		cp.Kind = KindCredentials
		cp.Msg = "the administrator email is not a user the service account can act as"
		return &cp
	}
	return err
}

// ---- reads ---------------------------------------------------------------------

func join(base *url.URL, path string, q url.Values) *url.URL {
	u := *base
	u.Path = base.Path + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return &u
}

func decode(body []byte, path string, out any) error {
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(out); err != nil {
		return &Error{Kind: KindBadResponse, Path: path, Msg: "the answer is not the documented JSON"}
	}
	return nil
}

// maxPages bounds one paged read.
const maxPages = 1000

// EachUser reads the account's users (Admin SDK Directory API, users.list, as the
// administrator), following nextPageToken, and calls fn with each user object.
func (c *Client) EachUser(ctx context.Context, fn func(json.RawMessage) error) error {
	const path = "/admin/directory/v1/users"
	q := url.Values{
		"customer":   {"my_customer"},
		"maxResults": {"500"},
		"projection": {"basic"},
		"viewType":   {"admin_view"},
		"orderBy":    {"email"},
		"fields": {"nextPageToken,users(id,primaryEmail,name/fullName,aliases,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv," +
			"isEnforcedIn2Sv,suspended,archived,isMailboxSetup,isGuestUser,orgUnitPath)"},
	}
	for page := 0; ; page++ {
		if page >= maxPages {
			return &Error{Kind: KindBadResponse, Path: path, Msg: "more pages than DefendSec will follow"}
		}
		body, err := c.do(ctx, c.cfg.AdminEmail, ScopeDirectoryUsers, join(c.directory, path, q))
		if err != nil {
			return err
		}
		var p struct {
			Users []json.RawMessage `json:"users"`
			Next  string            `json:"nextPageToken"`
		}
		if err := decode(body, path, &p); err != nil {
			return err
		}
		for _, v := range p.Users {
			if err := fn(v); err != nil {
				return err
			}
		}
		if p.Next == "" {
			return nil
		}
		q.Set("pageToken", p.Next)
	}
}

// GmailSettings reads one Gmail settings resource of a user ("autoForwarding" or
// "filters"), acting as that user. The path is fixed to those two: this client has
// no way to name a message.
func (c *Client) GmailSettings(ctx context.Context, userEmail, resource string, out any) error {
	switch resource {
	case "autoForwarding", "filters":
	default:
		return errors.New("not a Gmail settings resource DefendSec reads")
	}
	if !ValidEmail(userEmail) {
		return errors.New("not a user address")
	}
	// "me" is the user the token acts as, so a read can only be of that mailbox.
	path := "/gmail/v1/users/me/settings/" + resource
	body, err := c.do(ctx, userEmail, c.cfg.GmailScope, join(c.gmail, path, nil))
	if err != nil {
		return err
	}
	return decode(body, path, out)
}
