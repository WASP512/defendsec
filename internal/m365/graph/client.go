// Package graph is DefendSec's read-only Microsoft Graph client for the M365
// identity posture collector (slice 12).
//
// It authenticates as an application (the OAuth 2.0 client-credentials flow)
// with either a certificate (a signed JWT client assertion, preferred) or a
// client secret, and it makes GET requests only. The one other request it can
// make is the token request, a POST to the login endpoint. There is no method
// that creates, updates or deletes anything in a tenant, and the application
// permissions DefendSec asks for are all *.Read.* (docs/M365.md).
//
// Failures are classified (see Kind) and described without a secret, a token or
// a response body in the message, so a caller can say "permission missing" or
// "throttled" and never confuse either with "nothing found".
package graph

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // an identifier the Entra portal shows, not a security use
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Cloud names the Microsoft cloud a tenant lives in.
type Cloud string

const (
	CloudGlobal Cloud = "global"
	CloudUSGov  Cloud = "usgov" // Microsoft 365 US Government (GCC High / DoD)
	CloudChina  Cloud = "china" // operated by 21Vianet
)

type endpoints struct{ login, graph string }

var clouds = map[Cloud]endpoints{
	CloudGlobal: {"https://login.microsoftonline.com", "https://graph.microsoft.com"},
	CloudUSGov:  {"https://login.microsoftonline.us", "https://graph.microsoft.us"},
	CloudChina:  {"https://login.partner.microsoftonline.cn", "https://microsoftgraph.chinacloudapi.cn"},
}

// ParseCloud validates a cloud name; empty means global.
func ParseCloud(s string) (Cloud, error) {
	c := Cloud(strings.ToLower(strings.TrimSpace(s)))
	if c == "" {
		return CloudGlobal, nil
	}
	if _, ok := clouds[c]; !ok {
		return "", fmt.Errorf("cloud must be global, usgov or china, not %q", s)
	}
	return c, nil
}

// Kind classifies a failure.
type Kind string

const (
	// KindCredentials: the login endpoint refused the application's credentials
	// (wrong or expired secret, unknown application, unknown tenant, bad
	// certificate). Nothing was read.
	KindCredentials Kind = "credentials"
	// KindUnauthorized: Graph answered 401; the token was refused even after a refresh.
	KindUnauthorized Kind = "unauthorized"
	// KindForbidden: Graph answered 403: a permission is missing or not consented,
	// the tenant lacks a licence the API needs, or an Exchange policy limits the app.
	KindForbidden Kind = "forbidden"
	// KindNotFound: Graph answered 404 (for a mailbox: there is none to read).
	KindNotFound Kind = "not_found"
	// KindThrottled: Graph answered 429 and the retries ran out.
	KindThrottled Kind = "throttled"
	// KindServer: Graph answered 5xx and the retries ran out.
	KindServer Kind = "server"
	// KindNetwork: no usable answer (timeout, connection refused, TLS).
	KindNetwork Kind = "network"
	// KindBadResponse: an answer that is not what the API documents.
	KindBadResponse Kind = "bad_response"
)

// Error is a classified failure. Its text never holds a credential, a token or
// a response body, only Graph's error code and the first line of its message.
type Error struct {
	Kind   Kind
	Status int
	// Code is Graph's error code ("Authorization_RequestDenied") or the login
	// endpoint's AADSTS code ("AADSTS7000215").
	Code string
	// Msg is Graph's own message, first line only, bounded.
	Msg string
	// RetryAfter is the delay a 429 asked for.
	RetryAfter time.Duration
	// Path is the request path without its query.
	Path string
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("microsoft graph")
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

// CodeOf returns Graph's error code, or "".
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
		return "Microsoft refused the application's credentials" + detail + ": check the tenant ID, the application (client) ID, and that the secret or certificate has not expired"
	case KindUnauthorized:
		return "Microsoft Graph refused the access token" + detail
	case KindForbidden:
		return "permission missing, not admin-consented, or the tenant is not licensed for this report" + detail
	case KindNotFound:
		return "not found" + detail
	case KindThrottled:
		return "Microsoft Graph throttled the read and the retries ran out" + detail
	case KindServer:
		return "Microsoft Graph returned a server error" + detail
	case KindNetwork:
		return "Microsoft Graph could not be reached"
	}
	return "Microsoft Graph returned an unexpected answer" + detail
}

// Certificate is an application's certificate credential: the RSA key that
// signs the client assertion and the certificate whose thumbprint Entra matches.
type Certificate struct {
	key *rsa.PrivateKey
	der []byte
}

// ParseCertificatePEM reads a PEM bundle holding one RSA private key (PKCS #8
// or PKCS #1) and its certificate, in any order. Entra ID accepts RSA only.
func ParseCertificatePEM(data []byte) (*Certificate, error) {
	var c Certificate
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			if c.der == nil {
				c.der = blk.Bytes
			}
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, errors.New("the private key is not a valid PKCS #8 key")
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("the private key is not an RSA key (Microsoft Entra ID certificate credentials are RSA)")
			}
			c.key = rk
		case "RSA PRIVATE KEY":
			rk, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
			if err != nil {
				return nil, errors.New("the private key is not a valid PKCS #1 key")
			}
			c.key = rk
		case "ENCRYPTED PRIVATE KEY":
			return nil, errors.New("the private key is encrypted: DefendSec cannot read it without a passphrase; export it unencrypted into a 0600 file")
		}
	}
	if c.key == nil {
		return nil, errors.New("no RSA private key in the PEM file")
	}
	if c.der == nil {
		return nil, errors.New("no certificate in the PEM file: put the certificate and its private key in one file")
	}
	crt, err := x509.ParseCertificate(c.der)
	if err != nil {
		return nil, errors.New("the certificate is not a valid X.509 certificate")
	}
	pub, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(c.key.N) != 0 || pub.E != c.key.E {
		return nil, errors.New("the certificate does not belong to the private key")
	}
	return &c, nil
}

// Thumbprint is the certificate's SHA-256 thumbprint, as hex. It is what the
// assertion's x5t#S256 header carries. The Entra portal lists the SHA-1 one
// (ThumbprintSHA1), so the status page shows both.
func (c *Certificate) Thumbprint() string {
	sum := sha256.Sum256(c.der)
	return fmt.Sprintf("%X", sum[:])
}

// ThumbprintSHA1 is the certificate's SHA-1 thumbprint, as hex (40 characters): the
// value Microsoft Graph keeps as the key credential's customKeyIdentifier and the
// one the portal's Certificates & secrets blade lists. It identifies a certificate
// to a person comparing two screens; nothing here relies on SHA-1's strength.
func (c *Certificate) ThumbprintSHA1() string {
	sum := sha1.Sum(c.der) //nolint:gosec // identifier, not a security use
	return fmt.Sprintf("%X", sum[:])
}

// Config configures a Client.
type Config struct {
	// TenantID is the directory (tenant) ID, or a verified domain name. For a
	// multi-tenant application it is the client's tenant, never "common".
	TenantID string
	// ClientID is the application (client) ID.
	ClientID string
	// Exactly one of Secret and Cert.
	Secret string
	Cert   *Certificate

	Cloud Cloud
	// LoginURL and GraphURL override the cloud's endpoints. They must be https,
	// except for a loopback address (tests).
	LoginURL, GraphURL string

	HTTP *http.Client
	// MaxAttempts bounds the tries of one request (default 4).
	MaxAttempts int
	// MaxWait bounds one Retry-After sleep (default 60 s). A longer ask is a
	// throttle the caller reports instead of waiting out.
	MaxWait time.Duration
	// MaxRequests bounds the Graph requests one Client makes (0 = 50000), so a
	// runaway loop cannot spend the tenant's quota.
	MaxRequests int
	// Now and Sleep are replaceable for tests.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

var (
	guidRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	domainRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
)

// ValidTenant reports whether s can be a tenant: a GUID or a domain name. The
// multi-tenant aliases (common, organizations, consumers) are refused: a tenant
// is named, so a client's data is never read through another's consent.
func ValidTenant(s string) bool { return guidRe.MatchString(s) || domainRe.MatchString(s) }

// ValidClientID reports whether s is an application (client) ID.
func ValidClientID(s string) bool { return guidRe.MatchString(s) }

// Client reads one tenant.
type Client struct {
	cfg      Config
	loginURL *url.URL
	graphURL *url.URL
	scope    string
	hc       *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time

	requests atomic.Int64
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

// New validates the configuration and returns a client. It makes no request.
func New(cfg Config) (*Client, error) {
	if !ValidTenant(cfg.TenantID) {
		return nil, errors.New("tenant ID must be a directory (tenant) ID or a domain name")
	}
	if !ValidClientID(cfg.ClientID) {
		return nil, errors.New("application (client) ID must be a GUID")
	}
	if (cfg.Secret == "") == (cfg.Cert == nil) {
		return nil, errors.New("configure exactly one of a client secret and a certificate")
	}
	if cfg.Cloud == "" {
		cfg.Cloud = CloudGlobal
	}
	ep, ok := clouds[cfg.Cloud]
	if !ok {
		return nil, fmt.Errorf("unknown cloud %q", cfg.Cloud)
	}
	if cfg.LoginURL == "" {
		cfg.LoginURL = ep.login
	}
	if cfg.GraphURL == "" {
		cfg.GraphURL = ep.graph
	}
	lu, err := endpointURL(cfg.LoginURL, "login")
	if err != nil {
		return nil, err
	}
	gu, err := endpointURL(cfg.GraphURL, "graph")
	if err != nil {
		return nil, err
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 4
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
	return &Client{cfg: cfg, loginURL: lu, graphURL: gu, scope: ep.graph + "/.default", hc: &hcCopy}, nil
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

// Requests is how many Graph requests this client has made (token requests excluded).
func (c *Client) Requests() int { return int(c.requests.Load()) }

// ---- token ---------------------------------------------------------------------

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// assertion builds the signed client assertion for the token request: header
// alg PS256 and x5t#S256, claims aud, exp, iss, jti, nbf and sub, as Microsoft
// documents for certificate credentials.
func (c *Client) assertion(tokenURL string) (string, error) {
	now := c.cfg.Now()
	sum := sha256.Sum256(c.cfg.Cert.der)
	hdr, _ := json.Marshal(map[string]string{"alg": "PS256", "typ": "JWT", "x5t#S256": b64(sum[:])})
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", err
	}
	jti[6] = jti[6]&0x0f | 0x40
	jti[8] = jti[8]&0x3f | 0x80
	claims, _ := json.Marshal(map[string]any{
		"aud": tokenURL,
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": c.cfg.ClientID,
		"jti": fmt.Sprintf("%x-%x-%x-%x-%x", jti[0:4], jti[4:6], jti[6:8], jti[8:10], jti[10:]),
		"nbf": now.Add(-time.Minute).Unix(),
		"sub": c.cfg.ClientID,
	})
	signing := b64(hdr) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPSS(rand.Reader, c.cfg.Cert.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", errors.New("could not sign the client assertion")
	}
	return signing + "." + b64(sig), nil
}

var aadstsRe = regexp.MustCompile(`AADSTS\d+`)

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

// fetchToken exchanges the application's credential for an access token.
func (c *Client) fetchToken(ctx context.Context) (string, time.Time, error) {
	tokenURL := c.loginURL.String() + "/" + url.PathEscape(c.cfg.TenantID) + "/oauth2/v2.0/token"
	form := url.Values{
		"client_id":  {c.cfg.ClientID},
		"scope":      {c.scope},
		"grant_type": {"client_credentials"},
	}
	if c.cfg.Cert != nil {
		a, err := c.assertion(tokenURL)
		if err != nil {
			return "", time.Time{}, &Error{Kind: KindCredentials, Msg: err.Error()}
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", a)
	} else {
		form.Set("client_secret", c.cfg.Secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, &Error{Kind: KindNetwork, Msg: "could not build the token request"}
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
		e := &Error{Kind: KindCredentials, Status: resp.StatusCode, Path: "token", Code: aadstsRe.FindString(te.Description)}
		switch {
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			e.Kind = KindServer
			if resp.StatusCode == http.StatusTooManyRequests {
				e.Kind = KindThrottled
			}
		case e.Code == "":
			e.Code = te.Error
		}
		if e.Kind == KindCredentials {
			e.Msg = oneLine(strings.TrimPrefix(te.Description, e.Code+":"), 200)
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

func (c *Client) bearer(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.cfg.Now().Add(time.Minute).Before(c.expiry) {
		return c.token, nil
	}
	tok, exp, err := c.fetchToken(ctx)
	if err != nil {
		c.token = ""
		return "", err
	}
	c.token, c.expiry = tok, exp
	return tok, nil
}

// ---- requests ------------------------------------------------------------------

// resolve turns a path ("/users") or a Graph nextLink into a URL on the Graph
// host. A link to any other host is refused: the bearer token goes only to Graph.
func (c *Client) resolve(pathOrURL string, q url.Values) (*url.URL, error) {
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		u, err := url.Parse(pathOrURL)
		if err != nil || u.Scheme != c.graphURL.Scheme || !strings.EqualFold(u.Host, c.graphURL.Host) || u.User != nil {
			return nil, &Error{Kind: KindBadResponse, Msg: "a page link points away from Microsoft Graph and was not followed"}
		}
		return u, nil
	}
	if !strings.HasPrefix(pathOrURL, "/") {
		return nil, errors.New("graph path must start with /")
	}
	u := *c.graphURL
	u.Path = c.graphURL.Path + "/v1.0" + pathOrURL
	if q != nil {
		u.RawQuery = q.Encode()
	}
	return &u, nil
}

// do performs one GET with token refresh on 401 and the retry policy for 429 and
// 5xx, and returns the body of a 200.
func (c *Client) do(ctx context.Context, u *url.URL) ([]byte, error) {
	path := u.Path
	if i := strings.Index(path, "/v1.0"); i >= 0 {
		path = path[i+len("/v1.0"):]
	}
	refreshed := false
	var last *Error
	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int(c.requests.Load()) >= c.cfg.MaxRequests {
			return nil, &Error{Kind: KindThrottled, Path: path, Msg: "DefendSec's own request budget for one read is spent"}
		}
		tok, err := c.bearer(ctx, false)
		if err != nil {
			return nil, err
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
		e := graphError(resp, body, path)
		switch {
		case resp.StatusCode == http.StatusUnauthorized && !refreshed:
			// The token may have been revoked or expired early: get a new one once.
			refreshed = true
			if _, err := c.bearer(ctx, true); err != nil {
				return nil, err
			}
			attempt--
			continue
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout:
			last = e
			wait := e.RetryAfter
			if wait <= 0 {
				wait = backoff(attempt)
			}
			if wait > c.cfg.MaxWait {
				// A throttle longer than we will wait is reported, not slept through.
				return nil, e
			}
			if attempt == c.cfg.MaxAttempts {
				return nil, e
			}
			if err := c.cfg.Sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		case resp.StatusCode >= 500:
			last = e
			if attempt == c.cfg.MaxAttempts {
				return nil, e
			}
			if err := c.cfg.Sleep(ctx, backoff(attempt)); err != nil {
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

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func graphError(resp *http.Response, body []byte, path string) *Error {
	e := &Error{Status: resp.StatusCode, Path: path}
	var ge struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &ge) == nil {
		e.Code = oneLine(ge.Error.Code, 80)
		e.Msg = oneLine(ge.Error.Message, 200)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		e.Kind = KindUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		e.Kind = KindForbidden
	case resp.StatusCode == http.StatusNotFound:
		e.Kind = KindNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		e.Kind = KindThrottled
	case resp.StatusCode >= 500:
		e.Kind = KindServer
	default:
		e.Kind = KindBadResponse
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			e.RetryAfter = time.Duration(n) * time.Second
		} else if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				e.RetryAfter = d
			}
		}
	}
	return e
}

// Get reads one resource into out.
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	u, err := c.resolve(path, q)
	if err != nil {
		return err
	}
	body, err := c.do(ctx, u)
	if err != nil {
		return err
	}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(out); err != nil {
		return &Error{Kind: KindBadResponse, Path: path, Msg: "the answer is not the documented JSON"}
	}
	return nil
}

// maxPages bounds one paged read: 999 users a page makes this a million users.
const maxPages = 1000

// Each reads a collection, following @odata.nextLink, and calls fn with every
// element of every page's value array.
func (c *Client) Each(ctx context.Context, path string, q url.Values, fn func(json.RawMessage) error) error {
	u, err := c.resolve(path, q)
	if err != nil {
		return err
	}
	for page := 0; ; page++ {
		if page >= maxPages {
			return &Error{Kind: KindBadResponse, Path: path, Msg: "more pages than DefendSec will follow"}
		}
		body, err := c.do(ctx, u)
		if err != nil {
			return err
		}
		var p struct {
			Value []json.RawMessage `json:"value"`
			Next  string            `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &p); err != nil {
			return &Error{Kind: KindBadResponse, Path: path, Msg: "the answer is not the documented JSON"}
		}
		for _, v := range p.Value {
			if err := fn(v); err != nil {
				return err
			}
		}
		if p.Next == "" {
			return nil
		}
		if u, err = c.resolve(p.Next, nil); err != nil {
			return err
		}
	}
}

// NotAfter is when the certificate expires, so a status page can say so before
// the sign-in starts failing.
func (c *Certificate) NotAfter() time.Time {
	crt, err := x509.ParseCertificate(c.der)
	if err != nil {
		return time.Time{}
	}
	return crt.NotAfter
}
