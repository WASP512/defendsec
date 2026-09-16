package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Destinations: syslog and webhook.
//
// OpenTelemetry is named in the roadmap and is deliberately not here. A real
// OTLP exporter means a substantial dependency and a semantic-convention
// mapping that is worth doing properly rather than approximately, and an
// almost-OTLP exporter that a collector rejects is worse than none. Syslog and
// a webhook reach every platform in practice today; OTLP is a follow-up, and
// saying so beats shipping something that looks like it.

// --- syslog (RFC 5424) ---

// SyslogDestination writes RFC 5424 messages over TCP, TLS or UDP.
type SyslogDestination struct {
	network string
	address string
	tag     string
	tlsConf *tls.Config

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslog creates a syslog destination.
//
// The address is "tcp://host:514", "udp://host:514" or "tls://host:6514".
// TCP by default: UDP silently discards under load, which is the wrong
// property for the record of a security event.
func NewSyslog(raw, tag string) (*SyslogDestination, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("syslog address %q: %w", raw, err)
	}
	network := strings.ToLower(u.Scheme)
	switch network {
	case "tcp", "udp", "tls":
	case "":
		network = "tcp"
	default:
		return nil, fmt.Errorf("syslog scheme %q is not tcp, udp or tls", u.Scheme)
	}
	host := u.Host
	if host == "" {
		host = raw
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return nil, fmt.Errorf("syslog address %q needs a host and port", raw)
	}
	if tag == "" {
		tag = "defendsec"
	}
	d := &SyslogDestination{network: network, address: host, tag: tag}
	if network == "tls" {
		d.tlsConf = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostOnly(host)}
	}
	return d, nil
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// Name identifies the destination.
func (d *SyslogDestination) Name() string { return "syslog:" + d.network + "://" + d.address }

func (d *SyslogDestination) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if d.network == "tls" {
		return tls.DialWithDialer(dialer, "tcp", d.address, d.tlsConf)
	}
	return dialer.DialContext(ctx, d.network, d.address)
}

// Send writes each record as one RFC 5424 line.
func (d *SyslogDestination) Send(ctx context.Context, records []Record) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn == nil {
		conn, err := d.dial(ctx)
		if err != nil {
			return err
		}
		d.conn = conn
	}

	var buf bytes.Buffer
	for _, r := range records {
		buf.WriteString(d.format(r))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = d.conn.SetWriteDeadline(deadline)
	}
	if _, err := d.conn.Write(buf.Bytes()); err != nil {
		// A collector that restarted leaves a half-open connection that only
		// fails on write. Closing here means the next batch redials rather
		// than failing forever against a socket that will never recover.
		_ = d.conn.Close()
		d.conn = nil
		return err
	}
	return nil
}

// facility is "local0", which is where security tooling conventionally lands
// and what most collectors are already configured to route.
const facility = 16

// format renders one RFC 5424 message, framed for the transport.
func (d *SyslogDestination) format(r Record) string {
	priority := facility*8 + severityToSyslog(r.Severity)
	timestamp := r.At.UTC().Format(time.RFC3339Nano)
	if r.At.IsZero() {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	host := r.Hostname
	if host == "" {
		host = "-"
	}

	// The structured payload goes in the message as JSON rather than as
	// SD-PARAMs: collectors parse JSON reliably, and RFC 5424 structured data
	// requires escaping that every implementation gets subtly differently.
	payload := map[string]any{
		"kind": r.Kind, "summary": r.Summary,
		"deviceId": r.DeviceID, "severity": r.Severity,
	}
	for k, v := range r.Body {
		payload[k] = v
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		encoded = []byte(`{"summary":"` + strings.ReplaceAll(r.Summary, `"`, `'`) + `"}`)
	}

	msg := fmt.Sprintf("<%d>1 %s %s %s - - - %s",
		priority, timestamp, sanitise(host), sanitise(d.tag), encoded)

	if d.network == "udp" {
		// UDP is one datagram per message, with no framing.
		return msg
	}
	// RFC 6587 octet counting. Newline framing breaks on any message
	// containing a newline, and JSON payloads routinely do.
	return fmt.Sprintf("%d %s", len(msg), msg)
}

// sanitise removes spaces from header fields, which RFC 5424 forbids there.
func sanitise(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r < 33 || r > 126 {
			return '_'
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	if len(s) > 48 {
		return s[:48]
	}
	return s
}

// severityToSyslog maps DefendSec severities onto syslog levels.
func severityToSyslog(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	default:
		return 6 // info
	}
}

// Close releases the connection.
func (d *SyslogDestination) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn == nil {
		return nil
	}
	err := d.conn.Close()
	d.conn = nil
	return err
}

// --- webhook ---

// WebhookDestination POSTs batches as JSON.
type WebhookDestination struct {
	url    string
	token  string
	client *http.Client
}

// NewWebhook creates a webhook destination. A token, when set, is sent as a
// bearer credential.
func NewWebhook(raw, token string) (*WebhookDestination, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("webhook url %q must be http or https", raw)
	}
	return &WebhookDestination{
		url: raw, token: token,
		client: &http.Client{Timeout: 20 * time.Second},
	}, nil
}

// Name identifies the destination, without the credential.
func (d *WebhookDestination) Name() string {
	if u, err := url.Parse(d.url); err == nil {
		// Query strings routinely carry tokens, so the name is the path only.
		return "webhook:" + u.Scheme + "://" + u.Host + u.Path
	}
	return "webhook"
}

// Send posts the batch.
func (d *WebhookDestination) Send(ctx context.Context, records []Record) error {
	body, err := json.Marshal(map[string]any{
		"source":  "defendsec",
		"count":   len(records),
		"records": records,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.token != "" {
		req.Header.Set("Authorization", "Bearer "+d.token)
	}
	res, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	// Drained so the connection can be reused rather than reopened per batch.
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", res.Status)
	}
	return nil
}

// Close is a no-op.
func (d *WebhookDestination) Close() error { return nil }

// --- file, for testing a pipeline without a collector ---

// FileDestination appends JSON lines. Useful for proving the pipeline works
// before pointing it at a real platform, and for an air-gapped deployment that
// ships files off the host by other means.
type FileDestination struct {
	path string
	mu   sync.Mutex
}

// NewFile creates a file destination.
func NewFile(path string) (*FileDestination, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("file destination needs a path")
	}
	return &FileDestination{path: path}, nil
}

// Name identifies the destination.
func (d *FileDestination) Name() string { return "file:" + d.path }

// Send appends one JSON object per line.
func (d *FileDestination) Send(_ context.Context, records []Record) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	f, err := os.OpenFile(d.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer
	for _, r := range records {
		encoded, err := json.Marshal(r)
		if err != nil {
			continue
		}
		buf.Write(encoded)
		buf.WriteByte('\n')
	}
	_, err = f.Write(buf.Bytes())
	return err
}

// Close is a no-op; the file is opened per batch so log rotation works.
func (d *FileDestination) Close() error { return nil }

// ParseDestinations reads the DEFENDSEC_FORWARD configuration: a
// comma-separated list of destinations.
//
//	syslog=tcp://collector:514,webhook=https://siem.example/ingest#token,file=/var/log/defendsec-events.jsonl
//
// A malformed entry is an error rather than a skip, for the same reason a
// mistyped anchor target is: an operator who believes their events are being
// forwarded and is wrong stops looking.
func ParseDestinations(raw, tag string) ([]Destination, error) {
	var out []Destination
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		kind, ref, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("forward target %q is not in kind=ref form", entry)
		}
		kind = strings.ToLower(strings.TrimSpace(kind))
		ref = strings.TrimSpace(ref)

		switch kind {
		case "syslog":
			d, err := NewSyslog(ref, tag)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		case "webhook":
			target, token, _ := strings.Cut(ref, "#")
			d, err := NewWebhook(target, token)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		case "file":
			d, err := NewFile(ref)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		case "otlp", "otel":
			// Named rather than silently ignored: an operator configuring
			// OTLP should be told it is not implemented, not left wondering
			// why nothing arrives.
			return nil, fmt.Errorf(
				"OpenTelemetry forwarding is not implemented yet; use syslog or webhook, both of which reach an OTel collector")
		default:
			return nil, fmt.Errorf("unknown forward target kind %q, want syslog, webhook or file", kind)
		}
	}
	return out, nil
}
