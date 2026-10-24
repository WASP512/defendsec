// Package client is DefendSec's Autotask PSA REST client (slice 14).
//
// It does exactly what turning a Fix-this-week item into a ticket needs: look up
// the one company the instance maps to, read the ticket and note picklists, find
// and create and update tickets, and add notes. Nothing else. There is no delete
// call, no PUT, and no method for any other entity (docs/AUTOTASK.md lists every
// endpoint and where it was checked).
//
// What the Autotask documentation requires of an integration shapes the code:
//
//   - Authentication is three request headers (UserName, Secret, ApiIntegrationCode)
//     of an API-only user. The headers are set on every request and never logged.
//   - One request at a time. Autotask limits the simultaneous threads per tracking
//     identifier and object endpoint (three; a fourth is answered 429) and its best
//     practices say to serialise requests, so the client holds a lock for the whole
//     of a request.
//   - 10,000 requests an hour per database across every integration, with added
//     latency from 50 %. The client counts what it sends against a budget the
//     caller sets, and ThresholdInformation tells the caller what the database has
//     used so far.
//   - A create is not retried after a 5xx or a timeout: the ticket may exist. The
//     error says so (Error.Ambiguous) and the caller looks the ticket up by its tag
//     before creating again. A 429 is retried after Retry-After, because the
//     request was not executed.
//
// An error's text never holds a credential, a request header or a response body:
// only the status and the messages Autotask itself returned, bounded.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kind classifies a failure.
type Kind string

const (
	// KindAuth: 401 or 403. The user, secret or integration code is wrong, the user
	// is not an API user, or its security level cannot do this. Nothing was done.
	KindAuth Kind = "auth"
	// KindThrottled: 429 and the retries ran out (the thread limit or the hourly threshold).
	KindThrottled Kind = "throttled"
	// KindRejected: a 4xx other than 401, 403 or 429, or the 500 Autotask uses for a
	// business-rule error ("errors": [...]). The request was understood and refused.
	KindRejected Kind = "rejected"
	// KindServer: 5xx without an error list, after the retries a read gets.
	KindServer Kind = "server"
	// KindNetwork: no usable answer (timeout, refused, TLS).
	KindNetwork Kind = "network"
	// KindBadResponse: an answer that is not what the API documents.
	KindBadResponse Kind = "bad_response"
	// KindBudget: the caller's request budget is spent. Nothing was sent.
	KindBudget Kind = "budget"
)

// Error is a classified failure.
type Error struct {
	Kind   Kind
	Status int
	// Op names the call ("create ticket").
	Op string
	// Messages are Autotask's own error strings, bounded.
	Messages []string
	// Ambiguous is true when the request may have been executed although the
	// answer says otherwise (a 5xx or a timeout on a call that changes something).
	Ambiguous  bool
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("autotask " + e.Op + ": " + string(e.Kind))
	if e.Status != 0 {
		b.WriteString(" (HTTP " + strconv.Itoa(e.Status) + ")")
	}
	if len(e.Messages) > 0 {
		b.WriteString(": " + strings.Join(e.Messages, "; "))
	}
	if e.Ambiguous {
		b.WriteString(" (the request may have been carried out)")
	}
	return b.String()
}

// IsAuth reports whether err is a refused credential or a missing right.
func IsAuth(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Kind == KindAuth
}

// IsAmbiguous reports whether err leaves it open that the change happened.
func IsAmbiguous(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Ambiguous
}

// IsFatal reports whether the run should stop, not move to the next ticket: the
// credentials are refused, the hour's budget is spent, or the service keeps throttling.
func IsFatal(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Kind {
	case KindAuth, KindBudget, KindThrottled:
		return true
	}
	return false
}

// Config configures a Client.
type Config struct {
	// BaseURL is the zone's REST root, "https://webservices3.autotask.net/atservicesrest".
	BaseURL         string
	UserName        string
	Secret          string
	IntegrationCode string
	HTTP            *http.Client
	// MaxRequests bounds the requests (every attempt counts) this client sends in
	// its life; 0 means DefaultMaxRequests. A client is made per run.
	MaxRequests int
	// MaxWait bounds one Retry-After sleep (default 60 s). A longer ask fails the call.
	MaxWait time.Duration
	// Sleep waits between attempts (tests replace it).
	Sleep func(ctx context.Context, d time.Duration) error
	// UserAgent is sent on every request.
	UserAgent string
}

// DefaultMaxRequests is the budget of one run when the caller sets none.
const DefaultMaxRequests = 300

const (
	maxBody    = 16 << 20 // entityInformation/fields of Tickets is a few hundred KB
	apiVersion = "v1.0"
)

// Client talks to one Autotask zone as one API user. It is safe for concurrent
// use, and serialises what it sends.
type Client struct {
	cfg  Config
	base string

	mu   sync.Mutex
	sent int
}

// New validates the configuration and returns a client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("autotask: the zone URL is not a valid URL")
	}
	if cfg.UserName == "" || cfg.Secret == "" || cfg.IntegrationCode == "" {
		return nil, errors.New("autotask: the API user, its secret and the integration code are all required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = DefaultMaxRequests
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 60 * time.Second
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleepCtx
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "DefendSec-autotask/1"
	}
	base := strings.TrimRight(u.String(), "/") + "/" + apiVersion
	return &Client{cfg: cfg, base: base}, nil
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

// Requests is how many requests this client has sent.
func (c *Client) Requests() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sent
}

// ---- transport -------------------------------------------------------------------

// request sends one call and decodes the answer into out (nil for none). idem
// says whether a repeat after a 5xx or a timeout is safe.
func (c *Client) request(ctx context.Context, op, method, path string, body, out any, idem bool) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return &Error{Kind: KindBadResponse, Op: op, Messages: []string{"could not encode the request"}}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	attempts := 3
	var last error
	for i := 0; i < attempts; i++ {
		if c.sent >= c.cfg.MaxRequests {
			return &Error{Kind: KindBudget, Op: op, Messages: []string{fmt.Sprintf("this run's budget of %d requests is spent", c.cfg.MaxRequests)}}
		}
		c.sent++
		status, raw, retryAfter, err := c.once(ctx, method, path, payload)
		if err != nil {
			last = &Error{Kind: KindNetwork, Op: op, Messages: []string{netReason(err)}, Ambiguous: !idem}
			if ctx.Err() != nil || !idem {
				return last
			}
			if serr := c.cfg.Sleep(ctx, time.Duration(i+1)*time.Second); serr != nil {
				return last
			}
			continue
		}
		switch {
		case status == http.StatusOK || status == http.StatusCreated:
			if out == nil {
				return nil
			}
			if err := json.Unmarshal(raw, out); err != nil {
				return &Error{Kind: KindBadResponse, Op: op, Status: status, Messages: []string{"the answer is not the JSON the API documents"}}
			}
			return nil
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			return &Error{Kind: KindAuth, Op: op, Status: status, Messages: errorMessages(raw)}
		case status == http.StatusTooManyRequests:
			wait := retryAfter
			if wait <= 0 {
				wait = 5 * time.Second
			}
			last = &Error{Kind: KindThrottled, Op: op, Status: status, RetryAfter: retryAfter, Messages: errorMessages(raw)}
			if wait > c.cfg.MaxWait || i == attempts-1 {
				return last
			}
			if serr := c.cfg.Sleep(ctx, wait); serr != nil {
				return last
			}
			continue
		case status >= 500:
			msgs := errorMessages(raw)
			if len(msgs) > 0 {
				// Autotask answers 500 with {"errors": [...]} for a rule it enforces
				// (a required field, an inactive picklist value). It was refused.
				return &Error{Kind: KindRejected, Op: op, Status: status, Messages: msgs}
			}
			last = &Error{Kind: KindServer, Op: op, Status: status, Ambiguous: !idem}
			if !idem {
				return last
			}
			if serr := c.cfg.Sleep(ctx, time.Duration(i+1)*time.Second); serr != nil {
				return last
			}
			continue
		default:
			return &Error{Kind: KindRejected, Op: op, Status: status, Messages: errorMessages(raw)}
		}
	}
	return last
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte) (status int, raw []byte, retryAfter time.Duration, err error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, nil, 0, err
	}
	req.Header.Set("UserName", c.cfg.UserName)
	req.Header.Set("Secret", c.cfg.Secret)
	req.Header.Set("ApiIntegrationCode", c.cfg.IntegrationCode)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return 0, nil, 0, err
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		if n, perr := strconv.Atoi(strings.TrimSpace(v)); perr == nil && n >= 0 {
			retryAfter = time.Duration(n) * time.Second
		}
	}
	return resp.StatusCode, raw, retryAfter, nil
}

// netReason says why a request failed without echoing a URL or header.
func netReason(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out"
	case errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	}
	return "no answer from the service"
}

// errorMessages reads {"errors": ["..."]}, bounded; anything else yields none.
func errorMessages(raw []byte) []string {
	var doc struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []string
	for _, m := range doc.Errors {
		m = strings.Join(strings.Fields(m), " ")
		if len(m) > 300 {
			m = m[:300] + "…"
		}
		if m != "" {
			out = append(out, m)
		}
		if len(out) == 5 {
			break
		}
	}
	return out
}

// ---- zone discovery --------------------------------------------------------------

// ZoneInfo is the answer of the zoneInformation call.
type ZoneInfo struct {
	ZoneName string `json:"zoneName"`
	URL      string `json:"url"`
	WebURL   string `json:"webUrl"`
	CI       int64  `json:"ci"`
}

// ZoneDiscoveryURL is where every zone lookup starts: it needs no
// authentication and is not subject to thread limiting.
const ZoneDiscoveryURL = "https://webservices.autotask.net/atservicesrest/v1.0/zoneInformation"

// CheckZoneURL accepts only an https URL on autotask.net, because the credentials
// are sent to whatever URL this names. A zone URL typed into the settings or read
// from a discovery answer goes through here before it is used.
func CheckZoneURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", errors.New("the Autotask zone URL must be an https URL")
	}
	h := strings.ToLower(u.Hostname())
	if u.Port() != "" || !strings.HasSuffix(h, ".autotask.net") {
		return "", errors.New("the Autotask zone URL must be a host under autotask.net (for example https://webservices3.autotask.net/atservicesrest)")
	}
	p := strings.TrimRight(u.Path, "/")
	if strings.EqualFold(p, "/atservicesrest") || p == "" {
		return "https://" + h + "/atservicesrest", nil
	}
	return "", errors.New("the Autotask zone URL must end in /atservicesrest")
}

// Discover asks Autotask which zone the API user lives in. discoveryURL is
// ZoneDiscoveryURL unless a test points elsewhere. The answer's URL goes through
// CheckZoneURL unless allow is true (tests with a local server).
func Discover(ctx context.Context, hc *http.Client, discoveryURL, user string, allow bool) (ZoneInfo, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	u, err := url.Parse(discoveryURL)
	if err != nil {
		return ZoneInfo{}, errors.New("autotask zone discovery: bad URL")
	}
	q := u.Query()
	q.Set("user", user)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return ZoneInfo{}, errors.New("autotask zone discovery: bad request")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return ZoneInfo{}, &Error{Kind: KindNetwork, Op: "zone discovery", Messages: []string{netReason(err)}}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return ZoneInfo{}, &Error{Kind: KindRejected, Op: "zone discovery", Status: resp.StatusCode}
	}
	var z ZoneInfo
	if json.Unmarshal(raw, &z) != nil || z.URL == "" {
		return ZoneInfo{}, &Error{Kind: KindBadResponse, Op: "zone discovery", Status: resp.StatusCode, Messages: []string{"no zone URL in the answer"}}
	}
	if allow {
		return z, nil
	}
	checked, err := CheckZoneURL(z.URL)
	if err != nil {
		return ZoneInfo{}, &Error{Kind: KindBadResponse, Op: "zone discovery", Messages: []string{"the answer names a URL that is not an Autotask zone"}}
	}
	z.URL = checked
	return z, nil
}
