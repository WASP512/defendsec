package control

import (
	"context"
	"crypto/subtle"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"defendsec/internal/metrics"
)

// Metrics (roadmap 5.6). Labels are drawn from fixed sets — RPC method,
// route pattern, alert kind and severity — so series stay bounded and no
// host or user identity reaches the metrics system.
var (
	grpcRequests = metrics.Default.NewCounterVec("defendsec_grpc_requests_total",
		"Agent RPCs handled, by method and status code.", "method", "code")
	grpcLatency = metrics.Default.NewHistogramVec("defendsec_grpc_request_duration_seconds",
		"Agent RPC handling time.", nil, "method")
	httpRequests = metrics.Default.NewCounterVec("defendsec_admin_http_requests_total",
		"Admin API requests, by route and status.", "route", "code")
	httpLatency = metrics.Default.NewHistogramVec("defendsec_admin_http_request_duration_seconds",
		"Admin API handling time.", nil, "route")
	alertsCreated = metrics.Default.NewCounterVec("defendsec_alerts_created_total",
		"Alerts raised, by kind and severity.", "kind", "severity")
)

// RegisterMetrics adds the gauges that read the server's own state.
func (s *Server) RegisterMetrics(buildCommit string) {
	reg := metrics.Default
	reg.NewGaugeFunc("defendsec_build_info", "Build of the running apid; the value is always 1.",
		[]string{"commit"}, func() []metrics.Sample { return []metrics.Sample{{Labels: []string{buildCommit}, Value: 1}} })
	reg.NewGaugeFunc("defendsec_devices", "Enrolled devices, by platform and state.",
		[]string{"platform", "state"}, func() []metrics.Sample {
			var out []metrics.Sample
			now := time.Now()
			byPlatform := map[string][3]int{}
			for _, d := range s.store.List() {
				c := byPlatform[d.Platform]
				c[0]++
				if seen, err := time.Parse(time.RFC3339, d.LastSeen); err == nil && now.Sub(seen) < 2*time.Minute {
					c[1]++
				}
				if d.Isolated {
					c[2]++
				}
				byPlatform[d.Platform] = c
			}
			for p, c := range byPlatform {
				if p == "" {
					p = "unknown"
				}
				out = append(out,
					metrics.Sample{Labels: []string{p, "enrolled"}, Value: float64(c[0])},
					metrics.Sample{Labels: []string{p, "online"}, Value: float64(c[1])},
					metrics.Sample{Labels: []string{p, "isolated"}, Value: float64(c[2])})
			}
			return out
		})
	reg.NewCounterFunc("defendsec_forward_records_total", "Records offered to forwarding, by outcome.",
		[]string{"outcome"}, func() []metrics.Sample {
			if s.forwarder == nil {
				return nil
			}
			st := s.forwarder.Status()
			return []metrics.Sample{
				{Labels: []string{"accepted"}, Value: float64(st.Accepted)},
				{Labels: []string{"dropped"}, Value: float64(st.Dropped)},
				{Labels: []string{"sent"}, Value: float64(st.Sent)},
				{Labels: []string{"failed"}, Value: float64(st.Failed)},
			}
		})
	reg.NewGaugeFunc("defendsec_forward_destination_healthy", "1 when a forwarding destination's last send succeeded.",
		[]string{"destination"}, func() []metrics.Sample {
			if s.forwarder == nil {
				return nil
			}
			var out []metrics.Sample
			for _, d := range s.forwarder.Status().Destinations {
				v := 0.0
				if d.Healthy {
					v = 1
				}
				out = append(out, metrics.Sample{Labels: []string{d.Name}, Value: v})
			}
			return out
		})
	reg.NewGaugeFunc("go_goroutines", "Goroutines in the apid process.", nil, func() []metrics.Sample {
		return []metrics.Sample{{Value: float64(runtime.NumGoroutine())}}
	})
	reg.NewGaugeFunc("go_memstats_heap_inuse_bytes", "Heap bytes in use.", nil, func() []metrics.Sample {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return []metrics.Sample{{Value: float64(m.HeapInuse)}}
	})
}

// UnaryMetrics records every agent RPC.
func UnaryMetrics(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	grpcLatency.Since(start, info.FullMethod)
	grpcRequests.Inc(info.FullMethod, status.Code(err).String())
	return resp, err
}

// StreamMetrics records stream RPCs when they end.
func StreamMetrics(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	err := handler(srv, ss)
	grpcRequests.Inc(info.FullMethod, status.Code(err).String())
	return err
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// HTTPMetrics wraps the admin mux. The route label is the mux pattern that
// matched, never the raw path, so ids in paths cannot create new series.
func HTTPMetrics(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		if pattern == "" {
			pattern = "unmatched"
		}
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		start := time.Now()
		mux.ServeHTTP(sw, r)
		httpLatency.Since(start, pattern)
		httpRequests.Inc(pattern, strconv.Itoa(sw.code))
	})
}

// HandleMetrics serves the Prometheus exposition.
func HandleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.Default.Write(w)
}

// MetricsHandler serves /metrics on its own listener, with an optional
// bearer token compared in constant time.
func MetricsHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		HandleMetrics(w, r)
	})
}
