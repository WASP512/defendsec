//go:build windows

package agentcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// isolateSaved is what release needs to restore, kept beside the state file.
type isolateSaved struct {
	WindowsProfiles []windowsProfile `json:"windowsProfiles,omitempty"`
}

func savedPath(dir string) string { return filepath.Join(dir, "isolate-restore.json") }

func writeSaved(dir string, s isolateSaved) error {
	raw, _ := json.Marshal(s)
	return os.WriteFile(savedPath(dir), raw, 0o600)
}

func readSaved(dir string) isolateSaved {
	var s isolateSaved
	if raw, err := os.ReadFile(savedPath(dir)); err == nil {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}
