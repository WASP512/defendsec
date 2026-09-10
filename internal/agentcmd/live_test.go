package agentcmd

import (
	"strings"
	"testing"
)

func TestParseLiveQueryPayloadAllowlist(t *testing.T) {
	for _, q := range allowedLiveQueries {
		p, err := ParseLiveQueryPayload([]byte(`{"query":"` + q + `"}`))
		if err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		if p.Query != q {
			t.Fatalf("got %q want %q", p.Query, q)
		}
	}
}

func TestParseLiveQueryPayloadRejectsUnknown(t *testing.T) {
	_, err := ParseLiveQueryPayload([]byte(`{"query":"disk_usage"}`))
	if err == nil {
		t.Fatal("expected error for unknown query")
	}
	if !strings.Contains(err.Error(), "unsupported live_query") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseLiveQueryPayloadRequiresQuery(t *testing.T) {
	if _, err := ParseLiveQueryPayload(nil); err == nil {
		t.Fatal("expected error for empty payload")
	}
}

func TestRunLiveQueryOSInfo(t *testing.T) {
	out, err := RunLiveQuery("os_info")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "goos=") {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestLoggedInUsersEmptyOK(t *testing.T) {
	out, err := RunLiveQuery("logged_in_users")
	if err != nil {
		t.Fatalf("expected no error on empty who: %v", err)
	}
	if out == "" {
		t.Fatal("expected output")
	}
	t.Log(out)
}
