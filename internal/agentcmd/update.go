package agentcmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxUpdateBytes = 128 << 20

// ApplyAgentUpdate downloads, verifies, and atomically replaces the running binary.
// On success the caller should restart the process (e.g. exit 0 for systemd).
func ApplyAgentUpdate(p AgentUpdatePayload) (message string, restart bool, err error) {
	want := strings.ToLower(strings.TrimSpace(p.SHA256))
	if len(want) != 64 {
		return "", false, fmt.Errorf("sha256 must be 64 hex characters")
	}

	tmp, err := os.CreateTemp("", "defendsec-agent-update-*")
	if err != nil {
		return "", false, err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(strings.TrimSpace(p.URL))
	if err != nil {
		return "", false, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("download: HTTP %s", resp.Status)
	}
	hasher := sha256.New()
	written, err := io.Copy(tmp, io.LimitReader(io.TeeReader(resp.Body, hasher), maxUpdateBytes+1))
	if err != nil {
		return "", false, fmt.Errorf("download write: %w", err)
	}
	if written > maxUpdateBytes {
		return "", false, fmt.Errorf("download exceeds %d bytes", maxUpdateBytes)
	}
	if err := tmp.Close(); err != nil {
		return "", false, err
	}
	got := hex.EncodeToString(hasher.Sum(nil))
	if got != want {
		return "", false, fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}

	execPath, err := os.Executable()
	if err != nil {
		return "", false, err
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", false, err
	}
	backup := execPath + ".bak"
	if err := copyFile(execPath, backup); err != nil {
		return "", false, fmt.Errorf("backup: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return "", false, err
	}
	if err := os.Rename(tmpPath, execPath); err != nil {
		_ = copyFile(backup, execPath)
		return "", false, fmt.Errorf("replace binary: %w", err)
	}
	msg := fmt.Sprintf("applied agent update %s to %s (sha256=%s); restart required", p.Version, execPath, got)
	return msg, true, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
