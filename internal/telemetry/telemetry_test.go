package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"
	"time"
)

func TestParseTraceParent(t *testing.T) {
	tid, sid, sampled, ok := ParseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if !ok || !sampled || tid[0] != 0x4b || sid[7] != 0xb7 {
		t.Fatalf("valid header rejected: %v %v", ok, sampled)
	}
	for _, bad := range []string{
		"", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace id
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero span id
		"00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",  // short
		"00-zzf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
	} {
		if _, _, _, ok := ParseTraceParent(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

type collector struct {
	mu   sync.Mutex
	reqs [][]byte
	hdr  http.Header
}

func (c *collector) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	c.reqs = append(c.reqs, b)
	c.hdr = r.Header.Clone()
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{}"))
}

func TestExportShape(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(http.HandlerFunc(c.handler))
	defer srv.Close()
	tr, err := New(Config{Endpoint: srv.URL + "/v1/traces", Headers: map[string]string{"Authorization": "Bearer x"},
		Service: "svc", Ratio: 1, Interval: 20 * time.Millisecond}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, parent := tr.StartRemote(context.Background(), "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "GET /v1/devices")
	_, child := tr.Start(ctx, "db.query", KindInternal)
	child.SetAttr("rows", 42)
	child.SetError(errors.New("boom"))
	child.End()
	parent.SetAttr("http.response.status_code", 200)
	parent.End()
	parent.End() // double End exports once
	tr.Shutdown(context.Background())

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reqs) != 1 || c.hdr.Get("Authorization") != "Bearer x" || c.hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("requests=%d headers=%v", len(c.reqs), c.hdr)
	}
	var doc struct {
		ResourceSpans []struct {
			Resource   struct{ Attributes []KeyValue }
			ScopeSpans []struct {
				Spans []map[string]any
			}
		}
	}
	if err := json.Unmarshal(c.reqs[0], &doc); err != nil {
		t.Fatal(err)
	}
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 2 {
		t.Fatalf("%d spans", len(spans))
	}
	hex32 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex16 := regexp.MustCompile(`^[0-9a-f]{16}$`)
	byName := map[string]map[string]any{}
	for _, s := range spans {
		byName[s["name"].(string)] = s
		if !hex32.MatchString(s["traceId"].(string)) || !hex16.MatchString(s["spanId"].(string)) {
			t.Errorf("ids must be lowercase hex: %v %v", s["traceId"], s["spanId"])
		}
		if _, ok := s["startTimeUnixNano"].(string); !ok {
			t.Error("timestamps must be JSON strings")
		}
	}
	p, ch := byName["GET /v1/devices"], byName["db.query"]
	if p["traceId"] != "4bf92f3577b34da6a3ce929d0e0e4736" || p["parentSpanId"] != "00f067aa0ba902b7" {
		t.Errorf("remote parent not continued: %v", p)
	}
	if ch["traceId"] != p["traceId"] || ch["parentSpanId"] != p["spanId"] {
		t.Error("child not linked to parent")
	}
	if st := ch["status"].(map[string]any); st["code"].(float64) != 2 || st["message"] != "boom" {
		t.Errorf("status: %v", st)
	}
	if p["kind"].(float64) != KindServer {
		t.Error("server kind")
	}
}

func TestSamplingIsDeterministicByTraceID(t *testing.T) {
	tr := &Tracer{ratio: 0.25}
	n := 0
	for i := 0; i < 4000; i++ {
		var id [16]byte
		_, _ = rand.Read(id[:])
		if tr.sample(id) {
			n++
		}
		if first, again := tr.sample(id), tr.sample(id); first != again {
			t.Fatal("not deterministic")
		}
	}
	if n < 700 || n > 1300 {
		t.Errorf("sampled %d of 4000 at 0.25", n)
	}
}

func TestNilTracerIsANoOp(t *testing.T) {
	var tr *Tracer
	ctx, s := tr.Start(context.Background(), "x", KindInternal)
	s.SetAttr("a", 1)
	s.End()
	tr.Shutdown(ctx)
}

func TestParseHeaders(t *testing.T) {
	h, err := ParseHeaders("Authorization=Bearer%20abc, x-team=sec")
	if err != nil || h["Authorization"] != "Bearer abc" || h["x-team"] != "sec" {
		t.Fatalf("%v %v", h, err)
	}
	if _, err := ParseHeaders("novalue"); err == nil {
		t.Error("malformed accepted")
	}
}
