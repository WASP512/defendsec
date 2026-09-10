package agentcmd

import (
	"strings"
	"testing"
)

func TestApplyAgentUpdateRejectsBadHash(t *testing.T) {
	_, _, err := ApplyAgentUpdate(AgentUpdatePayload{
		Version: "9.9.9",
		URL:     "http://127.0.0.1:1/nonexistent",
		SHA256:  strings.Repeat("a", 64),
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestApplyAgentUpdateRejectsShortHash(t *testing.T) {
	_, _, err := ApplyAgentUpdate(AgentUpdatePayload{
		Version: "1.0.0",
		URL:     "http://example.com/agent",
		SHA256:  "abc",
	})
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("unexpected error: %v", err)
	}
}
