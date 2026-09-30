//go:build windows

package agentcmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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

func runCmd(argv []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", strings.Join(argv[:min(len(argv), 4)], " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func lookupHost(h string) ([]string, error) {
	return net.DefaultResolver.LookupHost(context.Background(), h)
}
