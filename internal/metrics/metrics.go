// Package metrics exposes DefendSec's own health in the Prometheus text
// format (roadmap 5.6).
//
// Hand-written rather than built on client_golang: the exposition format is
// small and stable, and every dependency is one more thing the supply-chain
// claims of 5.7 have to cover. What is exported is counts and latencies —
// never hostnames, device ids or anything else that would put fleet
// inventory into a metrics system with different access controls.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds every metric.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]metric
}

type metric interface {
	write(w io.Writer, name string)
	help() string
	kind() string
}

// Default is the process-wide registry.
var Default = NewRegistry()

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{metrics: map[string]metric{}} }

func (r *Registry) register(name string, m metric) metric {
	if !validName(name) {
		panic("metrics: invalid name " + name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.metrics[name]; ok {
		return existing
	}
	r.metrics[name] = m
	return m
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// Write renders the registry in the Prometheus text format 0.0.4.
func (r *Registry) Write(w io.Writer) {
	r.mu.Lock()
	names := make([]string, 0, len(r.metrics))
	for n := range r.metrics {
		names = append(names, n)
	}
	ms := make(map[string]metric, len(r.metrics))
	for n, m := range r.metrics {
		ms[n] = m
	}
	r.mu.Unlock()
	sort.Strings(names)
	for _, n := range names {
		m := ms[n]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", n, escapeHelp(m.help()), n, m.kind())
		m.write(w, n)
	}
}

func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(s)
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// labelSet renders {a="x",b="y"}; names and values must line up.
func labelSet(names, values []string, extra ...string) string {
	if len(names) == 0 && len(extra) == 0 {
		return ""
	}
	parts := make([]string, 0, len(names)+1)
	for i, n := range names {
		parts = append(parts, n+`="`+escapeLabel(values[i])+`"`)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		parts = append(parts, extra[i]+`="`+escapeLabel(extra[i+1])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ---- counters ----

// CounterVec is a counter with labels. Label values must come from a small,
// fixed set (a kind, a severity, a method) — never from hosts or users.
type CounterVec struct {
	h      string
	labels []string
	mu     sync.Mutex
	vals   map[string]*atomic.Uint64
	keys   map[string][]string
}

// NewCounterVec registers a labelled counter.
func (r *Registry) NewCounterVec(name, help string, labels ...string) *CounterVec {
	return r.register(name, &CounterVec{h: help, labels: labels, vals: map[string]*atomic.Uint64{}, keys: map[string][]string{}}).(*CounterVec)
}

// Inc adds one for the given label values.
func (c *CounterVec) Inc(values ...string) { c.Add(1, values...) }

// Add adds n.
func (c *CounterVec) Add(n uint64, values ...string) {
	if len(values) != len(c.labels) {
		return
	}
	key := strings.Join(values, "\x00")
	c.mu.Lock()
	v, ok := c.vals[key]
	if !ok {
		v = &atomic.Uint64{}
		c.vals[key] = v
		c.keys[key] = append([]string(nil), values...)
	}
	c.mu.Unlock()
	v.Add(n)
}

func (c *CounterVec) help() string { return c.h }
func (c *CounterVec) kind() string { return "counter" }
func (c *CounterVec) write(w io.Writer, name string) {
	c.mu.Lock()
	keys := make([]string, 0, len(c.vals))
	for k := range c.vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s%s %d\n", name, labelSet(c.labels, c.keys[k]), c.vals[k].Load())
	}
	c.mu.Unlock()
}

// ---- gauges ----

// GaugeFunc is a gauge read at scrape time, for values that already live
// somewhere (fleet counts, queue depth) and would only drift if copied.
type GaugeFunc struct {
	h      string
	labels []string
	fn     func() []Sample
}

// Sample is one labelled gauge value.
type Sample struct {
	Labels []string
	Value  float64
}

// NewGaugeFunc registers a gauge computed on scrape.
func (r *Registry) NewGaugeFunc(name, help string, labels []string, fn func() []Sample) {
	r.register(name, &GaugeFunc{h: help, labels: labels, fn: fn})
}

func (g *GaugeFunc) help() string { return g.h }
func (g *GaugeFunc) kind() string { return "gauge" }
func (g *GaugeFunc) write(w io.Writer, name string) {
	for _, s := range g.fn() {
		if len(s.Labels) != len(g.labels) {
			continue
		}
		fmt.Fprintf(w, "%s%s %s\n", name, labelSet(g.labels, s.Labels), formatFloat(s.Value))
	}
}

// ---- histograms ----

// DefaultBuckets are latency buckets in seconds, from 1 ms to 10 s.
var DefaultBuckets = []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}

// HistogramVec is a latency histogram with labels.
type HistogramVec struct {
	h       string
	labels  []string
	buckets []float64
	mu      sync.Mutex
	series  map[string]*histSeries
}

type histSeries struct {
	values []string
	counts []uint64
	count  uint64
	sum    float64
}

// NewHistogramVec registers a labelled histogram.
func (r *Registry) NewHistogramVec(name, help string, buckets []float64, labels ...string) *HistogramVec {
	if buckets == nil {
		buckets = DefaultBuckets
	}
	return r.register(name, &HistogramVec{h: help, labels: labels, buckets: buckets, series: map[string]*histSeries{}}).(*HistogramVec)
}

// Observe records one value.
func (h *HistogramVec) Observe(v float64, values ...string) {
	if len(values) != len(h.labels) {
		return
	}
	key := strings.Join(values, "\x00")
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.series[key]
	if !ok {
		s = &histSeries{values: append([]string(nil), values...), counts: make([]uint64, len(h.buckets))}
		h.series[key] = s
	}
	for i, b := range h.buckets {
		if v <= b {
			s.counts[i]++
		}
	}
	s.count++
	s.sum += v
}

// Since observes the seconds elapsed since start.
func (h *HistogramVec) Since(start time.Time, values ...string) {
	h.Observe(time.Since(start).Seconds(), values...)
}

func (h *HistogramVec) help() string { return h.h }
func (h *HistogramVec) kind() string { return "histogram" }
func (h *HistogramVec) write(w io.Writer, name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := make([]string, 0, len(h.series))
	for k := range h.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := h.series[k]
		for i, b := range h.buckets {
			fmt.Fprintf(w, "%s_bucket%s %d\n", name, labelSet(h.labels, s.values, "le", formatFloat(b)), s.counts[i])
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", name, labelSet(h.labels, s.values, "le", "+Inf"), s.count)
		fmt.Fprintf(w, "%s_sum%s %s\n", name, labelSet(h.labels, s.values), formatFloat(s.sum))
		fmt.Fprintf(w, "%s_count%s %d\n", name, labelSet(h.labels, s.values), s.count)
	}
}

// CounterFunc is a counter whose value is read at scrape time from a source
// that already counts (an atomic in another package).
type CounterFunc struct {
	h      string
	labels []string
	fn     func() []Sample
}

// NewCounterFunc registers a counter read on scrape.
func (r *Registry) NewCounterFunc(name, help string, labels []string, fn func() []Sample) {
	r.register(name, &CounterFunc{h: help, labels: labels, fn: fn})
}

func (c *CounterFunc) help() string { return c.h }
func (c *CounterFunc) kind() string { return "counter" }
func (c *CounterFunc) write(w io.Writer, name string) {
	for _, s := range c.fn() {
		if len(s.Labels) != len(c.labels) {
			continue
		}
		fmt.Fprintf(w, "%s%s %s\n", name, labelSet(c.labels, s.Labels), formatFloat(s.Value))
	}
}
