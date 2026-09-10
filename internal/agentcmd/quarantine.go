package agentcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"defendsec/internal/hostinv"
)

const (
	TypeQuarantinePath      = "quarantine_path"
	quarantineStagingPrefix = "/tmp/defendsec-quarantine"
)

type QuarantinePayload struct {
	Path string `json:"path"`
}

func ParseQuarantinePayload(raw []byte) (QuarantinePayload, error) {
	var p QuarantinePayload
	if len(raw) == 0 {
		return p, fmt.Errorf("quarantine_path payload requires path")
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, err
	}
	p.Path = strings.TrimSpace(p.Path)
	if p.Path == "" {
		return p, fmt.Errorf("quarantine_path payload requires path")
	}
	return p, nil
}

func AllowedQuarantinePath(path string) bool {
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil || !filepath.IsAbs(abs) {
		return false
	}
	staging, _ := filepath.Abs(quarantineStagingPrefix)
	if abs == staging || strings.HasPrefix(abs, staging+string(filepath.Separator)) {
		return true
	}
	for _, watch := range hostinv.FimPaths() {
		watchAbs, err := filepath.Abs(filepath.Clean(watch))
		if err != nil {
			continue
		}
		if abs == watchAbs {
			return true
		}
	}
	return false
}

func QuarantinePath(stateDir, path string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("quarantine_path is linux-only")
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	if !AllowedQuarantinePath(abs) {
		return "", fmt.Errorf("path %q is not under FIM watch paths or %s", abs, quarantineStagingPrefix)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("refusing to quarantine directory %q", abs)
	}
	qdir := filepath.Join(stateDir, "quarantine")
	if err := os.MkdirAll(qdir, 0o700); err != nil {
		return "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dest := filepath.Join(qdir, filepath.Base(abs)+"."+stamp)
	if err := os.Rename(abs, dest); err != nil {
		return "", fmt.Errorf("move to quarantine: %w", err)
	}
	if err := os.Chmod(dest, 0o000); err != nil {
		return "", fmt.Errorf("chmod quarantine file: %w", err)
	}
	return dest, nil
}
