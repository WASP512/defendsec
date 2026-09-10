package agentcmd

import "testing"

func TestParseRunScriptPayloadAllowlist(t *testing.T) {
	p, err := ParseRunScriptPayload([]byte(`{"scriptId":"collect_journal_tail"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.ScriptID != "collect_journal_tail" {
		t.Fatalf("got %q", p.ScriptID)
	}
	if _, err := ParseRunScriptPayload([]byte(`{"scriptId":"rm_rf_root"}`)); err == nil {
		t.Fatal("expected reject unknown script")
	}
	if _, err := ParseRunScriptPayload([]byte(`{}`)); err == nil {
		t.Fatal("expected missing scriptId")
	}
}

func TestIsAllowedScript(t *testing.T) {
	if !IsAllowedScript("flush_dns") {
		t.Fatal("flush_dns should be allowed")
	}
	if IsAllowedScript("shell") {
		t.Fatal("shell should not be allowed")
	}
}
