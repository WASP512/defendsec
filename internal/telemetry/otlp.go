package telemetry

import (
	"encoding/hex"
	"strconv"
	"time"
)

// OTLP/JSON shapes (opentelemetry-proto, JSON mapping). Two details the
// mapping specifies and generic encoders get wrong: trace and span ids are
// hex strings, not base64; and 64-bit integers, including the nanosecond
// timestamps, are JSON strings.

// KeyValue is an OTLP attribute.
type KeyValue struct {
	Key   string   `json:"key"`
	Value AnyValue `json:"value"`
}

// AnyValue is an OTLP attribute value.
type AnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
}

// Attr converts a Go value to an OTLP attribute.
func Attr(key string, v any) KeyValue {
	var a AnyValue
	switch x := v.(type) {
	case string:
		a.StringValue = &x
	case bool:
		a.BoolValue = &x
	case int:
		s := strconv.FormatInt(int64(x), 10)
		a.IntValue = &s
	case int32:
		s := strconv.FormatInt(int64(x), 10)
		a.IntValue = &s
	case int64:
		s := strconv.FormatInt(x, 10)
		a.IntValue = &s
	case float64:
		a.DoubleValue = &x
	default:
		s := ""
		a.StringValue = &s
	}
	return KeyValue{Key: key, Value: a}
}

type exportRequest struct {
	ResourceSpans []resourceSpans `json:"resourceSpans"`
}

type resourceSpans struct {
	Resource   resource     `json:"resource"`
	ScopeSpans []scopeSpans `json:"scopeSpans"`
}

type resource struct {
	Attributes []KeyValue `json:"attributes"`
}

type scope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type scopeSpans struct {
	Scope scope      `json:"scope"`
	Spans []spanJSON `json:"spans"`
}

type spanStatus struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type spanJSON struct {
	TraceID           string     `json:"traceId"`
	SpanID            string     `json:"spanId"`
	ParentSpanID      string     `json:"parentSpanId,omitempty"`
	Name              string     `json:"name"`
	Kind              int        `json:"kind"`
	StartTimeUnixNano string     `json:"startTimeUnixNano"`
	EndTimeUnixNano   string     `json:"endTimeUnixNano"`
	Attributes        []KeyValue `json:"attributes,omitempty"`
	Status            spanStatus `json:"status"`
}

func nanos(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

// Encode renders finished spans as an ExportTraceServiceRequest.
func Encode(service string, batch []finished) any {
	spans := make([]spanJSON, 0, len(batch))
	for _, f := range batch {
		s := f.span
		s.mu.Lock()
		js := spanJSON{
			TraceID: hex.EncodeToString(s.traceID[:]), SpanID: hex.EncodeToString(s.spanID[:]),
			Name: s.name, Kind: s.kind, StartTimeUnixNano: nanos(s.start), EndTimeUnixNano: nanos(f.end),
		}
		if s.parent != ([8]byte{}) {
			js.ParentSpanID = hex.EncodeToString(s.parent[:])
		}
		for k, v := range s.attrs {
			js.Attributes = append(js.Attributes, Attr(k, v))
		}
		if s.isError {
			js.Status = spanStatus{Code: 2, Message: s.errMsg} // STATUS_CODE_ERROR
		}
		s.mu.Unlock()
		spans = append(spans, js)
	}
	return exportRequest{ResourceSpans: []resourceSpans{{
		Resource:   resource{Attributes: []KeyValue{Attr("service.name", service)}},
		ScopeSpans: []scopeSpans{{Scope: scope{Name: "defendsec"}, Spans: spans}},
	}}}
}
