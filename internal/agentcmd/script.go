package agentcmd

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

const TypeRunScript = "run_script"

var allowedScripts = map[string]func() (string, error){
	"collect_journal_tail": runCollectJournalTail,
	"flush_dns":            runFlushDNS,
}

type RunScriptPayload struct {
	ScriptID string `json:"scriptId"`
}

func AllowedScriptIDs() []string {
	ids := make([]string, 0, len(allowedScripts))
	for id := range allowedScripts {
		ids = append(ids, id)
	}
	return ids
}

func IsAllowedScript(id string) bool {
	_, ok := allowedScripts[id]
	return ok
}

func ParseRunScriptPayload(raw []byte) (RunScriptPayload, error) {
	var p RunScriptPayload
	if len(raw) == 0 {
		return p, fmt.Errorf("run_script payload requires scriptId")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	p.ScriptID = strings.TrimSpace(p.ScriptID)
	if p.ScriptID == "" {
		return p, fmt.Errorf("run_script payload requires scriptId")
	}
	if !IsAllowedScript(p.ScriptID) {
		return p, fmt.Errorf("unknown scriptId %q (allowed: %s)", p.ScriptID, strings.Join(AllowedScriptIDs(), ", "))
	}
	return p, nil
}

func RunScript(scriptID string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("run_script is linux-only")
	}
	fn, ok := allowedScripts[scriptID]
	if !ok {
		return "", fmt.Errorf("unknown scriptId %q", scriptID)
	}
	return fn()
}

func runCollectJournalTail() (string, error) {
	if path, err := exec.LookPath("journalctl"); err == nil {
		out, err := exec.Command(path, "-n", "50", "--no-pager", "-o", "short-iso").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("journalctl: %w", err)
		}
		return strings.TrimSpace(string(out)), nil
	}
	return "journalctl not available; no journal tail collected", nil
}

func runFlushDNS() (string, error) {
	if path, err := exec.LookPath("resolvectl"); err == nil {
		out, err := exec.Command(path, "flush-caches").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("resolvectl flush-caches: %w", err)
		}
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "dns caches flushed via resolvectl"
		}
		return msg, nil
	}
	if path, err := exec.LookPath("systemd-resolve"); err == nil {
		out, err := exec.Command(path, "--flush-caches").CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("systemd-resolve --flush-caches: %w", err)
		}
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = "dns caches flushed via systemd-resolve"
		}
		return msg, nil
	}
	return "no supported dns flush tool found (resolvectl/systemd-resolve)", nil
}
