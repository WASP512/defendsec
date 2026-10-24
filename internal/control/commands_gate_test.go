package control

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"defendsec/internal/presence"
)

// Slice 6 removed the policy engine and every response command. What is left
// is a two-type allow-list that is empty by default; these tests pin that.

func TestParseAllowedCommandsDropsRemovedAndUnknownTypes(t *testing.T) {
	got := ParseAllowedCommands(" live_query, isolate ,run_script,agent_update,live_query,kill_process,quarantine_path,release,nonsense,")
	want := []string{"agent_update", "live_query"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseAllowedCommands = %v, want %v", got, want)
	}
	if got := ParseAllowedCommands(""); len(got) != 0 {
		t.Fatalf("empty setting enabled %v", got)
	}
}

func commandServer(t *testing.T, allowed ...string) *Server {
	t.Helper()
	s := testServer()
	s.store = presence.New(filepath.Join(t.TempDir(), "agents.json"))
	s.SetAllowedCommands(allowed)
	return s
}

func postCommand(s *Server, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/commands", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.HandleAdminCommands(rec, req)
	return rec
}

func TestRemovedCommandTypesAreRefusedWhateverIsEnabled(t *testing.T) {
	s := commandServer(t, "live_query", "agent_update")
	for _, typ := range []string{"isolate", "release", "kill_process", "quarantine_path", "run_script", "", "nonsense"} {
		rec := postCommand(s, "admin-token", `{"deviceId":"d1","type":"`+typ+`","payload":{}}`)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown command type") {
			t.Errorf("type %q: status %d body %q, want 400 unknown command type", typ, rec.Code, rec.Body.String())
		}
	}
}

func TestHostCommandsAreOffByDefault(t *testing.T) {
	s := commandServer(t)
	for _, typ := range []string{"live_query", "agent_update"} {
		rec := postCommand(s, "admin-token", `{"deviceId":"d1","type":"`+typ+`","payload":{}}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "DEFENDSEC_ALLOW_COMMANDS") {
			t.Errorf("type %q: status %d body %q, want 403 naming DEFENDSEC_ALLOW_COMMANDS", typ, rec.Code, rec.Body.String())
		}
	}
}

func TestAllowListIsPerType(t *testing.T) {
	s := commandServer(t, "live_query")
	// Past the gate, the next check is the device: a host this server has never
	// seen is a 404, which is how the test knows the gate let it through.
	rec := postCommand(s, "admin-token", `{"deviceId":"unknown","type":"live_query","payload":{"query":"os_info"}}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("enabled live_query: status %d body %q, want 404 unknown device", rec.Code, rec.Body.String())
	}
	rec = postCommand(s, "admin-token", `{"deviceId":"unknown","type":"agent_update","payload":{}}`)
	if rec.Code != http.StatusForbidden {
		t.Errorf("agent_update not enabled: status %d, want 403", rec.Code)
	}
}

func TestViewerAndAnonymousCannotIssueCommands(t *testing.T) {
	s := commandServer(t, "live_query", "agent_update")
	for name, token := range map[string]string{"viewer": "viewer-token", "anonymous": "", "wrong": "nope"} {
		rec := postCommand(s, token, `{"deviceId":"d1","type":"live_query","payload":{"query":"os_info"}}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, rec.Code)
		}
	}
}

func TestLiveQueryNoLongerOffersAProcessList(t *testing.T) {
	s := commandServer(t, "live_query")
	rec := postCommand(s, "admin-token", `{"deviceId":"d1","type":"live_query","payload":{"query":"processes"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("processes: status %d body %q, want 400", rec.Code, rec.Body.String())
	}
}
