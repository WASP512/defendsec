package forward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func TestCEFEscaping(t *testing.T) {
	r := Record{Kind: "alert", At: at, Severity: "high", Hostname: "web|01", DeviceID: "d1",
		Summary: "a=b\nnext", Body: map[string]any{"rule": `sig\x|y`, "path": "/etc/x=1"}}
	got := CEF(r)
	want := `CEF:0|DefendSec|DefendSec|1|sig\\x\|y|a=b next|8|rt=1790769600000 cat=alert msg=a\=b\nnext ` +
		`dvchost=web|01 deviceExternalId=d1 cs1Label=path cs1=/etc/x\=1 cs2Label=rule cs2=sig\\x|y`
	if got != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	// Exactly seven unescaped pipes separate the eight header fields.
	unescaped := 0
	for i := 0; i < len(got); i++ {
		if got[i] == '\\' {
			i++
			continue
		}
		if got[i] == '|' {
			unescaped++
		}
		if strings.HasPrefix(got[i:], "rt=") {
			break
		}
	}
	if unescaped != 7 {
		t.Errorf("header has %d separators, want 7", unescaped)
	}
}

func TestCEFSyslogFraming(t *testing.T) {
	d, err := NewCEF("tcp://127.0.0.1:514", "defendsec")
	if err != nil {
		t.Fatal(err)
	}
	line := d.format(Record{Kind: "alert", At: at, Severity: "critical", Summary: "x"})
	if !strings.Contains(line, " defendsec - - - CEF:0|DefendSec|") || !strings.HasPrefix(line[strings.Index(line, " ")+1:], "<130>1 ") {
		t.Errorf("framing: %q", line)
	}
}

func TestChatFiltersAndCaps(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &m)
		bodies = append(bodies, m)
	}))
	defer srv.Close()

	slack, err := NewChat("slack", srv.URL+"/services/x", "min=high")
	if err != nil {
		t.Fatal(err)
	}
	slack.client = srv.Client()
	var recs []Record
	recs = append(recs, Record{Kind: "event", Severity: "critical", Summary: "an event, never posted"})
	recs = append(recs, Record{Kind: "alert", Severity: "medium", Summary: "below threshold"})
	for i := 0; i < 12; i++ {
		recs = append(recs, Record{Kind: "alert", Severity: "high", Hostname: "h", Summary: "real"})
	}
	if err := slack.Send(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	if err := slack.Send(context.Background(), recs[:2]); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 1 {
		t.Fatalf("posts = %d, want 1 (a batch with nothing qualifying is not sent)", len(bodies))
	}
	text := bodies[0]["text"].(string)
	if !strings.HasPrefix(text, "DefendSec: 12 new alerts") || !strings.Contains(text, "…and 2 more") ||
		strings.Contains(text, "never posted") || strings.Contains(text, "below threshold") {
		t.Errorf("text: %s", text)
	}

	teams, _ := NewChat("teams", srv.URL+"/workflows/x", "")
	p := teams.Payload(recs).(map[string]any)
	att := p["attachments"].([]map[string]any)[0]
	if p["type"] != "message" || att["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("teams envelope: %v", p)
	}
}

func TestOTLPLogsRequestAndPartialSuccess(t *testing.T) {
	var got map[string]any
	reject := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/logs" || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		if reject {
			_, _ = w.Write([]byte(`{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"bad"}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	d, err := NewOTLPLogs(srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Send(context.Background(), []Record{{Kind: "alert", At: at, Severity: "high", Hostname: "h", Summary: "s", Body: map[string]any{"a": 1}}}); err != nil {
		t.Fatal(err)
	}
	lr := got["resourceLogs"].([]any)[0].(map[string]any)["scopeLogs"].([]any)[0].(map[string]any)["logRecords"].([]any)[0].(map[string]any)
	if lr["timeUnixNano"] != "1790769600000000000" || lr["severityNumber"].(float64) != 17 || lr["body"].(map[string]any)["stringValue"] != "s" {
		t.Errorf("log record: %v", lr)
	}
	reject = true
	if err := d.Send(context.Background(), []Record{{Kind: "event", Summary: "x"}}); err == nil || !strings.Contains(err.Error(), "rejected 1") {
		t.Errorf("partial rejection not surfaced: %v", err)
	}
}
