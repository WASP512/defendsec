// Package telemetry emits OpenTelemetry traces of apid's own work (roadmap
// 5.6), over OTLP/HTTP with JSON encoding, configured by the standard
// OTEL_* environment variables.
//
// It is a deliberately small implementation of the part of the OTLP
// specification DefendSec uses — spans with attributes and status, W3C
// traceparent propagation, batched export — rather than the OpenTelemetry
// SDK and its dependency tree. Its output was checked by decoding it with
// the collector's own OTLP JSON unmarshaler (pdata); see OPERATIONS.md.
//
// Tracing must never affect the work being traced: export is asynchronous,
// the queue is bounded, and a full queue or a failed export drops spans and
// counts them.
package telemetry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SpanKind values from the OTLP proto.
const (
	KindInternal = 1
	KindServer   = 2
	KindClient   = 3
)

// Span is one timed operation.
type Span struct {
	tracer  *Tracer
	traceID [16]byte
	spanID  [8]byte
	parent  [8]byte
	name    string
	kind    int
	start   time.Time
	mu      sync.Mutex
	attrs   map[string]any
	errMsg  string
	isError bool
	ended   atomic.Bool
	sampled bool
}

// SetAttr records an attribute: string, bool, int, int64 or float64.
func (s *Span) SetAttr(key string, value any) {
	if s == nil || !s.sampled {
		return
	}
	s.mu.Lock()
	s.attrs[key] = value
	s.mu.Unlock()
}

// SetError marks the span failed.
func (s *Span) SetError(err error) {
	if s == nil || err == nil || !s.sampled {
		return
	}
	s.mu.Lock()
	s.isError, s.errMsg = true, err.Error()
	s.mu.Unlock()
}

// End finishes the span and queues it for export.
func (s *Span) End() {
	if s == nil || !s.sampled || s.ended.Swap(true) {
		return
	}
	s.tracer.enqueue(s, time.Now())
}

// TraceParent renders the W3C traceparent header for this span.
func (s *Span) TraceParent() string {
	if s == nil {
		return ""
	}
	flags := "00"
	if s.sampled {
		flags = "01"
	}
	return "00-" + hex.EncodeToString(s.traceID[:]) + "-" + hex.EncodeToString(s.spanID[:]) + "-" + flags
}

type ctxKey struct{}

// FromContext returns the current span, or nil.
func FromContext(ctx context.Context) *Span {
	s, _ := ctx.Value(ctxKey{}).(*Span)
	return s
}

type finished struct {
	span *Span
	end  time.Time
}

// Tracer creates and exports spans. A nil *Tracer is valid and does nothing.
type Tracer struct {
	endpoint string
	headers  map[string]string
	service  string
	ratio    float64
	client   *http.Client
	log      *slog.Logger

	queue   chan finished
	done    chan struct{}
	exited  chan struct{}
	stopped sync.Once

	Exported atomic.Uint64
	Dropped  atomic.Uint64
	Failed   atomic.Uint64
}

// Config is what FromEnv reads.
type Config struct {
	Endpoint string            // full URL of the traces endpoint
	Headers  map[string]string // sent with every export
	Service  string            // service.name
	Ratio    float64           // sampling ratio, 0..1
	Interval time.Duration     // export interval
}

// FromEnv builds a tracer from OTEL_EXPORTER_OTLP_TRACES_ENDPOINT (or
// OTEL_EXPORTER_OTLP_ENDPOINT plus /v1/traces), OTEL_EXPORTER_OTLP_HEADERS,
// OTEL_SERVICE_NAME and OTEL_TRACES_SAMPLER / OTEL_TRACES_SAMPLER_ARG.
// With no endpoint it returns a nil tracer: tracing off, at no cost.
func FromEnv(log *slog.Logger) (*Tracer, error) {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	if endpoint == "" {
		if base := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); base != "" {
			endpoint = strings.TrimRight(base, "/") + "/v1/traces"
		}
	}
	if endpoint == "" {
		return nil, nil
	}
	cfg := Config{Endpoint: endpoint, Service: "defendsec-apid", Ratio: 1, Interval: 5 * time.Second}
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		cfg.Service = v
	}
	headers, err := ParseHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
	if err != nil {
		return nil, err
	}
	cfg.Headers = headers
	switch sampler := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")); sampler {
	case "", "always_on", "parentbased_always_on":
	case "always_off", "parentbased_always_off":
		cfg.Ratio = 0
	case "traceidratio", "parentbased_traceidratio":
		r, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")), 64)
		if err != nil || r < 0 || r > 1 {
			return nil, fmt.Errorf("OTEL_TRACES_SAMPLER_ARG must be a ratio between 0 and 1")
		}
		cfg.Ratio = r
	default:
		return nil, fmt.Errorf("OTEL_TRACES_SAMPLER %q is not supported; use always_on, always_off or traceidratio", sampler)
	}
	t, err := New(cfg, log)
	if err != nil {
		return nil, err
	}
	log.Info("opentelemetry tracing enabled", "endpoint", endpoint, "service", cfg.Service, "ratio", cfg.Ratio)
	return t, nil
}

// ParseHeaders reads the OTEL_EXPORTER_OTLP_HEADERS form: k=v,k2=v2, with
// values URL-encoded.
func ParseHeaders(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("OTEL_EXPORTER_OTLP_HEADERS entry %q is not key=value", part)
		}
		dec, err := url.QueryUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("OTEL_EXPORTER_OTLP_HEADERS value for %q: %w", k, err)
		}
		out[strings.TrimSpace(k)] = dec
	}
	return out, nil
}

// New starts a tracer that exports to cfg.Endpoint.
func New(cfg Config, log *slog.Logger) (*Tracer, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("OTLP endpoint %q must be an http(s) URL", cfg.Endpoint)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	t := &Tracer{
		endpoint: cfg.Endpoint, headers: cfg.Headers, service: cfg.Service, ratio: cfg.Ratio,
		client: &http.Client{Timeout: 10 * time.Second}, log: log,
		queue: make(chan finished, 4096), done: make(chan struct{}), exited: make(chan struct{}),
	}
	go t.run(cfg.Interval)
	return t, nil
}

// Start begins a span as a child of the span in ctx, if any.
func (t *Tracer) Start(ctx context.Context, name string, kind int) (context.Context, *Span) {
	if t == nil {
		return ctx, nil
	}
	parent := FromContext(ctx)
	s := &Span{tracer: t, name: name, kind: kind, start: time.Now(), attrs: map[string]any{}}
	_, _ = rand.Read(s.spanID[:])
	if parent != nil {
		s.traceID, s.parent, s.sampled = parent.traceID, parent.spanID, parent.sampled
	} else {
		_, _ = rand.Read(s.traceID[:])
		s.sampled = t.sample(s.traceID)
	}
	return context.WithValue(ctx, ctxKey{}, s), s
}

// StartRemote begins a server span continuing a W3C traceparent, when the
// caller sent a valid one.
func (t *Tracer) StartRemote(ctx context.Context, traceparent, name string) (context.Context, *Span) {
	if t == nil {
		return ctx, nil
	}
	if tid, sid, sampled, ok := ParseTraceParent(traceparent); ok {
		remote := &Span{traceID: tid, spanID: sid, sampled: sampled}
		ctx = context.WithValue(ctx, ctxKey{}, remote)
	}
	return t.Start(ctx, name, KindServer)
}

// ParseTraceParent reads a version-00 W3C traceparent header.
func ParseTraceParent(h string) (traceID [16]byte, spanID [8]byte, sampled, ok bool) {
	parts := strings.Split(strings.TrimSpace(h), "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return traceID, spanID, false, false
	}
	t, err1 := hex.DecodeString(parts[1])
	s, err2 := hex.DecodeString(parts[2])
	f, err3 := hex.DecodeString(parts[3])
	if err1 != nil || err2 != nil || err3 != nil {
		return traceID, spanID, false, false
	}
	copy(traceID[:], t)
	copy(spanID[:], s)
	if traceID == ([16]byte{}) || spanID == ([8]byte{}) {
		return traceID, spanID, false, false // all-zero ids are invalid per the spec
	}
	return traceID, spanID, f[0]&1 == 1, true
}

// sample decides from the trace id, so every service sampling the same
// trace at the same ratio agrees.
func (t *Tracer) sample(id [16]byte) bool {
	switch {
	case t.ratio >= 1:
		return true
	case t.ratio <= 0:
		return false
	}
	v := binary.BigEndian.Uint64(id[8:]) >> 1
	return float64(v) < t.ratio*float64(uint64(1)<<63)
}

func (t *Tracer) enqueue(s *Span, end time.Time) {
	select {
	case t.queue <- finished{s, end}:
	default:
		t.Dropped.Add(1)
	}
}

// Shutdown exports what is queued and stops.
func (t *Tracer) Shutdown(ctx context.Context) {
	if t == nil {
		return
	}
	t.stopped.Do(func() { close(t.done) })
	select {
	case <-t.exited:
	case <-ctx.Done():
	case <-time.After(15 * time.Second):
	}
}

func (t *Tracer) run(interval time.Duration) {
	defer close(t.exited)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var batch []finished
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := t.export(batch); err != nil {
			t.Failed.Add(uint64(len(batch)))
			if t.log != nil {
				t.log.Warn("otlp trace export", "err", err, "spans", len(batch))
			}
		} else {
			t.Exported.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case f := <-t.queue:
			batch = append(batch, f)
			if len(batch) >= 512 {
				flush()
			}
		case <-tick.C:
			flush()
		case <-t.done:
			for {
				select {
				case f := <-t.queue:
					batch = append(batch, f)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (t *Tracer) export(batch []finished) error {
	body, err := json.Marshal(Encode(t.service, batch))
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector returned %s", resp.Status)
	}
	return nil
}
