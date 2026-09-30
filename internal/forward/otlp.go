package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"defendsec/internal/telemetry"
)

// OTLPLogsDestination sends records as OpenTelemetry log records over
// OTLP/HTTP JSON (roadmap 5.6), to /v1/logs on a collector.
type OTLPLogsDestination struct {
	url     string
	headers map[string]string
	client  *http.Client
}

// NewOTLPLogs creates the destination. raw is the collector base URL
// (https://collector:4318) or the full /v1/logs URL; opts is a bearer token
// or OTEL-style headers ("Authorization=Bearer%20x,x-tenant=a").
func NewOTLPLogs(raw, opts string) (*OTLPLogsDestination, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("otlp endpoint %q must be an http(s) URL", raw)
	}
	if !strings.HasSuffix(u.Path, "/v1/logs") {
		u.Path = strings.TrimRight(u.Path, "/") + "/v1/logs"
	}
	headers := map[string]string{}
	if opts != "" {
		if strings.Contains(opts, "=") {
			if headers, err = telemetry.ParseHeaders(opts); err != nil {
				return nil, err
			}
		} else {
			headers["Authorization"] = "Bearer " + opts
		}
	}
	return &OTLPLogsDestination{url: u.String(), headers: headers, client: &http.Client{Timeout: 20 * time.Second}}, nil
}

// Name identifies it without credentials.
func (d *OTLPLogsDestination) Name() string {
	if u, err := url.Parse(d.url); err == nil {
		return "otlp:" + u.Scheme + "://" + u.Host + u.Path
	}
	return "otlp"
}

// Close is a no-op.
func (d *OTLPLogsDestination) Close() error { return nil }

// severityNumber maps onto the OTel log data model (INFO=9, WARN=13,
// ERROR=17, FATAL=21).
func severityNumber(s string) (int, string) {
	switch strings.ToLower(s) {
	case "critical":
		return 21, "FATAL"
	case "high":
		return 17, "ERROR"
	case "medium":
		return 13, "WARN"
	default:
		return 9, "INFO"
	}
}

// LogsRequest builds an ExportLogsServiceRequest.
func LogsRequest(records []Record) any {
	type logRecord struct {
		TimeUnixNano         string               `json:"timeUnixNano"`
		ObservedTimeUnixNano string               `json:"observedTimeUnixNano"`
		SeverityNumber       int                  `json:"severityNumber"`
		SeverityText         string               `json:"severityText"`
		Body                 telemetry.AnyValue   `json:"body"`
		Attributes           []telemetry.KeyValue `json:"attributes"`
	}
	now := strconv.FormatInt(time.Now().UnixNano(), 10)
	logs := make([]logRecord, 0, len(records))
	for _, r := range records {
		at := r.At
		if at.IsZero() {
			at = time.Now()
		}
		num, text := severityNumber(r.Severity)
		summary := r.Summary
		attrs := []telemetry.KeyValue{telemetry.Attr("defendsec.kind", r.Kind)}
		if r.DeviceID != "" {
			attrs = append(attrs, telemetry.Attr("defendsec.device_id", r.DeviceID))
		}
		if r.Hostname != "" {
			attrs = append(attrs, telemetry.Attr("host.name", r.Hostname))
		}
		if r.Severity != "" {
			attrs = append(attrs, telemetry.Attr("defendsec.severity", r.Severity))
		}
		if len(r.Body) > 0 {
			if raw, err := json.Marshal(r.Body); err == nil {
				attrs = append(attrs, telemetry.Attr("defendsec.body", string(raw)))
			}
		}
		logs = append(logs, logRecord{
			TimeUnixNano: strconv.FormatInt(at.UnixNano(), 10), ObservedTimeUnixNano: now,
			SeverityNumber: num, SeverityText: text,
			Body: telemetry.Attr("", summary).Value, Attributes: attrs,
		})
	}
	return map[string]any{"resourceLogs": []any{map[string]any{
		"resource":  map[string]any{"attributes": []telemetry.KeyValue{telemetry.Attr("service.name", "defendsec")}},
		"scopeLogs": []any{map[string]any{"scope": map[string]any{"name": "defendsec.forward"}, "logRecords": logs}},
	}}}
}

// Send posts the batch.
func (d *OTLPLogsDestination) Send(ctx context.Context, records []Record) error {
	raw, err := json.Marshal(LogsRequest(records))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range d.headers {
		req.Header.Set(k, v)
	}
	res, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("otlp collector returned %s: %s", res.Status, strings.TrimSpace(string(body)))
	}
	// A 200 can still carry a partial rejection (partialSuccess).
	var ps struct {
		PartialSuccess struct {
			RejectedLogRecords json.Number `json:"rejectedLogRecords"`
			ErrorMessage       string      `json:"errorMessage"`
		} `json:"partialSuccess"`
	}
	if json.Unmarshal(body, &ps) == nil {
		if n, _ := ps.PartialSuccess.RejectedLogRecords.Int64(); n > 0 {
			return fmt.Errorf("otlp collector rejected %d log records: %s", n, ps.PartialSuccess.ErrorMessage)
		}
	}
	return nil
}
