// Package datto is a read-only client for the Datto RMM REST API (v2).
//
// What it calls, and nothing else (checked against the vendor's OpenAPI
// document and help page on 2026-10-24; see docs/DATTO-RMM.md):
//
//	POST /auth/oauth/token                      token (OAuth2 password grant, public client)
//	GET  /api/v2/account/sites                  the site list the operator picks from
//	GET  /api/v2/site/{siteUid}/devices         the devices of one site
//	GET  /api/v2/audit/device/{deviceUid}       OS, build, BIOS serial
//	GET  /api/v2/audit/device/{deviceUid}/software
//	GET  /api/v2/device/{deviceUid}/patches?installStatus=
//	GET  /api/v2/system/pagination, /api/v2/system/request_rate
//
// Every request is a GET except the token request. The client has no method for
// jobs, components, quick jobs, alerts, variables, UDFs, warranty, moving a
// device or resetting keys, and a test fails if one is added.
//
// Credentials are an API key and secret, read by the caller from files; they
// are sent only to the platform's API host (a *-api.centrastage.net name, or
// whatever UnsafeAllowAnyURL permits in tests), never to a host named by a
// response, and never logged.
package datto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind classifies a failure so a caller can say why something was not assessed.
type Kind string

const (
	// KindAuth: the credentials were refused (400 from the token endpoint,
	// 401 from the API).
	KindAuth Kind = "auth"
	// KindForbidden: the API user may not read this (403). Datto also answers
	// 403 to an IP it has blocked for ignoring 429, so this is not always a
	// permission problem, and the client never retries one.
	KindForbidden Kind = "forbidden"
	// KindRateLimited: 429 persisted after the client waited and retried.
	KindRateLimited Kind = "rate_limited"
	// KindNotFound: 404.
	KindNotFound Kind = "not_found"
	// KindServer: 5xx after retries.
	KindServer Kind = "server"
	// KindNetwork: no usable response (DNS, TLS, timeout, reset).
	KindNetwork Kind = "network"
	// KindProtocol: a 2xx answer that is not the shape the API documents.
	KindProtocol Kind = "protocol"
)

// Error is a failed call. It carries the status and the operation, never a
// response body or a credential.
type Error struct {
	Kind   Kind
	Status int
	Op     string
	Err    error
}

func (e *Error) Error() string {
	s := "datto rmm " + e.Op + ": " + string(e.Kind)
	if e.Status != 0 {
		s += " (HTTP " + strconv.Itoa(e.Status) + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *Error) Unwrap() error { return e.Err }

// KindOf returns the Kind of err, or "" if it is not an *Error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return ""
}

// Reason words a failure for an operator, as the reason something was not
// assessed. It never includes a response body.
func Reason(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return "Datto RMM could not be read"
	}
	switch e.Kind {
	case KindAuth:
		return "Datto RMM refused the API key and secret (HTTP " + strconv.Itoa(e.Status) + "): check them, or generate new keys"
	case KindForbidden:
		return "Datto RMM answered 403 Forbidden: the API user's security level does not allow reading this (Sites > Sites: View and Sites > Devices: View are needed), or Datto has temporarily blocked this address after too many requests"
	case KindRateLimited:
		return "Datto RMM is rate limiting this account (HTTP 429); the read stopped rather than keep asking"
	case KindNotFound:
		return "Datto RMM does not know that site or device (HTTP 404)"
	case KindServer:
		return "Datto RMM answered with a server error (HTTP " + strconv.Itoa(e.Status) + ")"
	case KindNetwork:
		return "Datto RMM could not be reached from this server"
	case KindProtocol:
		return "Datto RMM sent an answer this version of DefendSec does not understand"
	}
	return "Datto RMM could not be read"
}

var platformHost = regexp.MustCompile(`^[a-z0-9]+-api\.centrastage\.net$`)

// ValidateAPIURL accepts only https://<platform>-api.centrastage.net, with no
// path, user info or port. The key and secret are sent to this host, so an
// operator typo (or an attacker-supplied setting) must not be able to point
// them elsewhere.
func ValidateAPIURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("api url: %w", err)
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || !platformHost.MatchString(strings.ToLower(u.Hostname())) {
		return nil, errors.New("api url must look like https://<platform>-api.centrastage.net (the API URL shown on the API user's page)")
	}
	return &url.URL{Scheme: "https", Host: strings.ToLower(u.Hostname())}, nil
}

// Config configures a Client.
type Config struct {
	// APIURL is the platform's API host, https://<platform>-api.centrastage.net.
	APIURL string
	// Key and Secret are the API user's keys.
	Key, Secret string

	HTTPClient *http.Client
	// RequestsPerSecond paces calls (default 5, which is 300 a minute against a
	// quota of 600 a minute shared by the whole RMM account).
	RequestsPerSecond float64
	// Wait429 is how long to wait after a 429 before retrying (default 60 s,
	// which is what Datto's documentation recommends). Retries429 is how many
	// times to retry (default 2).
	Wait429    time.Duration
	Retries429 int
	// PageSize overrides the page size (default: what /v2/system/pagination
	// reports, or 50 if that cannot be read).
	PageSize int
	// UnsafeAllowAnyURL skips ValidateAPIURL. Tests only: apid never sets it.
	UnsafeAllowAnyURL bool

	// Now and Sleep are replaceable so tests need not wait.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// Client reads Datto RMM. It is safe for concurrent use, though Sync uses it
// from one goroutine so the pace holds.
type Client struct {
	cfg  Config
	base *url.URL
	hc   *http.Client

	mu       sync.Mutex
	token    string
	expires  time.Time
	last     time.Time // when the previous request was released, for pacing
	requests int       // requests made, for the sync log
	pageSize int
}

// New validates the configuration and returns a client. It makes no request.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.Key) == "" || strings.TrimSpace(cfg.Secret) == "" {
		return nil, errors.New("datto rmm: API key and secret are both required")
	}
	var base *url.URL
	if cfg.UnsafeAllowAnyURL {
		u, err := url.Parse(strings.TrimSpace(cfg.APIURL))
		if err != nil || u.Host == "" {
			return nil, errors.New("datto rmm: bad api url")
		}
		base = &url.URL{Scheme: u.Scheme, Host: u.Host}
	} else {
		var err error
		if base, err = ValidateAPIURL(cfg.APIURL); err != nil {
			return nil, err
		}
	}
	if cfg.RequestsPerSecond <= 0 {
		cfg.RequestsPerSecond = 5
	}
	if cfg.Wait429 <= 0 {
		cfg.Wait429 = 60 * time.Second
	}
	if cfg.Retries429 <= 0 {
		cfg.Retries429 = 2
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	// Never follow a redirect: it could carry the bearer token to another host.
	hcCopy := *hc
	hcCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, base: base, hc: &hcCopy, pageSize: cfg.PageSize}, nil
}

// Requests is how many requests the client has made (the token request
// included), for the sync record.
func (c *Client) Requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.requests
}

// pace waits until the next request may go out and counts it.
func (c *Client) pace(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paceLocked(ctx)
}

const (
	tokenPath     = "/auth/oauth/token"
	publicClient  = "public-client"
	publicSecret  = "public"
	maxBodyBytes  = 32 << 20
	tokenSkew     = 5 * time.Minute
	defaultPageSz = 50
)

func (c *Client) tokenValid() bool {
	return c.token != "" && c.cfg.Now().Add(tokenSkew).Before(c.expires)
}

// authenticate exchanges the key and secret for a bearer token. Datto answers a
// wrong pair with 400.
func (c *Client) authenticate(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tokenValid() {
		return nil
	}
	if err := c.paceLocked(ctx); err != nil {
		return err
	}
	form := url.Values{"grant_type": {"password"}, "username": {c.cfg.Key}, "password": {c.cfg.Secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return &Error{Kind: KindProtocol, Op: "token", Err: errors.New("could not build the request")}
	}
	req.SetBasicAuth(publicClient, publicSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return &Error{Kind: KindNetwork, Op: "token", Err: scrubNet(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized:
		return &Error{Kind: KindAuth, Status: resp.StatusCode, Op: "token"}
	case resp.StatusCode == http.StatusForbidden:
		return &Error{Kind: KindForbidden, Status: resp.StatusCode, Op: "token"}
	case resp.StatusCode == http.StatusTooManyRequests:
		return &Error{Kind: KindRateLimited, Status: resp.StatusCode, Op: "token"}
	case resp.StatusCode >= 500:
		return &Error{Kind: KindServer, Status: resp.StatusCode, Op: "token"}
	case resp.StatusCode != http.StatusOK:
		return &Error{Kind: KindProtocol, Status: resp.StatusCode, Op: "token"}
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil || tok.AccessToken == "" {
		return &Error{Kind: KindProtocol, Status: resp.StatusCode, Op: "token", Err: errors.New("no access_token in the answer")}
	}
	ttl := time.Duration(tok.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	c.token, c.expires = tok.AccessToken, c.cfg.Now().Add(ttl)
	return nil
}

// paceLocked is pace for a caller that already holds c.mu.
func (c *Client) paceLocked(ctx context.Context) error {
	gap := time.Duration(float64(time.Second) / c.cfg.RequestsPerSecond)
	now := c.cfg.Now()
	wait := time.Duration(0)
	if !c.last.IsZero() {
		if next := c.last.Add(gap); next.After(now) {
			wait = next.Sub(now)
		}
	}
	c.last = now.Add(wait)
	c.requests++
	if wait > 0 {
		c.mu.Unlock()
		err := c.cfg.Sleep(ctx, wait)
		c.mu.Lock()
		return err
	}
	return nil
}

// scrubNet keeps a transport failure's cause without the URL it carries.
func scrubNet(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// get performs one authenticated GET of path (relative to /api, or an absolute
// nextPageUrl already checked to be on the API host) and decodes the JSON body
// into out.
func (c *Client) get(ctx context.Context, op, target string, out any) error {
	reauthed := false
	attempts429 := 0
	attempts5xx := 0
	for {
		if err := c.authenticate(ctx); err != nil {
			return err
		}
		if err := c.pace(ctx); err != nil {
			return &Error{Kind: KindNetwork, Op: op, Err: err}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return &Error{Kind: KindProtocol, Op: op, Err: errors.New("could not build the request")}
		}
		c.mu.Lock()
		tok := c.token
		c.mu.Unlock()
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return &Error{Kind: KindNetwork, Op: op, Err: ctx.Err()}
			}
			return &Error{Kind: KindNetwork, Op: op, Err: scrubNet(err)}
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if rerr != nil || len(body) > maxBodyBytes {
				return &Error{Kind: KindProtocol, Status: 200, Op: op, Err: errors.New("body unreadable or over the size limit")}
			}
			if err := json.Unmarshal(body, out); err != nil {
				return &Error{Kind: KindProtocol, Status: 200, Op: op, Err: errors.New("not the documented JSON")}
			}
			return nil
		case resp.StatusCode == http.StatusUnauthorized:
			// An expired token (they last 100 hours): get a new one once.
			if reauthed {
				return &Error{Kind: KindAuth, Status: 401, Op: op}
			}
			reauthed = true
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		case resp.StatusCode == http.StatusForbidden:
			return &Error{Kind: KindForbidden, Status: 403, Op: op}
		case resp.StatusCode == http.StatusNotFound:
			return &Error{Kind: KindNotFound, Status: 404, Op: op}
		case resp.StatusCode == http.StatusTooManyRequests:
			// Datto: wait 60 s; persistent requests after a breach earn a 403 and a
			// five minute block, so wait and retry a little, then give up.
			if attempts429 >= c.cfg.Retries429 {
				return &Error{Kind: KindRateLimited, Status: 429, Op: op}
			}
			attempts429++
			wait := c.cfg.Wait429
			if ra, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && ra > 0 {
				if d := time.Duration(ra) * time.Second; d > wait {
					wait = d
				}
			}
			if wait > 10*time.Minute {
				wait = 10 * time.Minute
			}
			if err := c.cfg.Sleep(ctx, wait); err != nil {
				return &Error{Kind: KindNetwork, Op: op, Err: err}
			}
			continue
		case resp.StatusCode >= 500:
			if attempts5xx >= 2 {
				return &Error{Kind: KindServer, Status: resp.StatusCode, Op: op}
			}
			attempts5xx++
			if err := c.cfg.Sleep(ctx, time.Duration(attempts5xx)*2*time.Second); err != nil {
				return &Error{Kind: KindNetwork, Op: op, Err: err}
			}
			continue
		default:
			return &Error{Kind: KindProtocol, Status: resp.StatusCode, Op: op}
		}
	}
}

func (c *Client) apiURL(path string, q url.Values) string {
	u := *c.base
	u.Path = "/api" + path
	u.RawQuery = q.Encode()
	return u.String()
}

// sameHost reports whether a nextPageUrl is on the API host. A response must
// not be able to send the bearer token somewhere else.
func (c *Client) sameHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == c.base.Scheme && strings.EqualFold(u.Host, c.base.Host) && strings.HasPrefix(u.Path, "/api/")
}

const maxPages = 400

// pages walks a paged list: it asks for the first page and follows nextPageUrl
// until it is null (Datto's documented way), handing each page body to each.
func (c *Client) pages(ctx context.Context, op, path string, q url.Values, each func(raw json.RawMessage) (next string, err error)) error {
	size, err := c.size(ctx)
	if err != nil {
		return err
	}
	if q == nil {
		q = url.Values{}
	}
	q.Set("max", strconv.Itoa(size))
	target := c.apiURL(path, q)
	for n := 0; ; n++ {
		if n >= maxPages {
			return &Error{Kind: KindProtocol, Op: op, Err: fmt.Errorf("still receiving pages after %d", maxPages)}
		}
		var raw json.RawMessage
		if err := c.get(ctx, op, target, &raw); err != nil {
			return err
		}
		next, err := each(raw)
		if err != nil {
			return &Error{Kind: KindProtocol, Op: op, Err: err}
		}
		if next == "" {
			return nil
		}
		if !c.sameHost(next) {
			return &Error{Kind: KindProtocol, Op: op, Err: errors.New("nextPageUrl is not on the API host; not following it")}
		}
		target = next
	}
}

// size is the page size: the configured one, else the server's own maximum.
func (c *Client) size(ctx context.Context) (int, error) {
	c.mu.Lock()
	if c.pageSize > 0 {
		n := c.pageSize
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()
	var cfg struct {
		Max int `json:"max"`
	}
	n := defaultPageSz
	if err := c.get(ctx, "system/pagination", c.apiURL("/v2/system/pagination", nil), &cfg); err == nil {
		if cfg.Max > 0 && cfg.Max <= 1000 {
			n = cfg.Max
		}
	} else if k := KindOf(err); k == KindAuth || k == KindForbidden || k == KindRateLimited {
		return 0, err
	}
	c.mu.Lock()
	c.pageSize = n
	c.mu.Unlock()
	return n, nil
}

// Millis is a Datto timestamp: Unix time in milliseconds, though the OpenAPI
// document calls some of them date-time. Both are accepted; null is zero.
type Millis struct{ time.Time }

func (m *Millis) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` || s == "" {
		m.Time = time.Time{}
		return nil
	}
	if s[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		if n, err := strconv.ParseInt(str, 10, 64); err == nil {
			return m.fromNumber(n)
		}
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
			if t, err := time.Parse(layout, str); err == nil {
				m.Time = t.UTC()
				return nil
			}
		}
		return fmt.Errorf("unrecognised timestamp %q", str)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		f, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return fmt.Errorf("unrecognised timestamp %s", s)
		}
		n = int64(f)
	}
	return m.fromNumber(n)
}

func (m *Millis) fromNumber(n int64) error {
	if n <= 0 {
		m.Time = time.Time{}
		return nil
	}
	// Milliseconds since the epoch; anything below 1e11 is seconds (before 5138),
	// which no Datto field uses but costs nothing to tolerate.
	if n < 100_000_000_000 {
		m.Time = time.Unix(n, 0).UTC()
		return nil
	}
	m.Time = time.UnixMilli(n).UTC()
	return nil
}
