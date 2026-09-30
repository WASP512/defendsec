package posture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// ErrUnsupported is returned on platforms whose posture this package does not
// collect. Linux posture is covered by the SCA packs directly.
var ErrUnsupported = errors.New("posture: no collector for this platform")

// Collect runs the native tools for this platform.
func Collect(ctx context.Context) (Report, Facts, error) {
	switch runtime.GOOS {
	case "windows":
		return collectWindows(ctx)
	default:
		return nil, Facts{}, ErrUnsupported
	}
}

func collectWindows(ctx context.Context) (Report, Facts, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	// Windows PowerShell 5.1 is present on every supported Windows; pwsh is
	// not. -NoProfile so a user's profile cannot alter what is reported.
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", WindowsScript)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, Facts{}, fmt.Errorf("posture script: %w: %s", err, firstLine(stderr.String()))
	}
	return ParseWindows(stdout.Bytes())
}

// Inventory is what the non-posture half of a Windows report needs.
type Inventory struct {
	Software []Software
	Updates  []Update
	// UpdateStatus mirrors the Linux collector's values: ok, error, unsupported.
	UpdateStatus string
}

// CollectInventory gathers pending Windows updates. (Software comes with the
// posture script.)
func CollectInventory(ctx context.Context) Inventory {
	switch runtime.GOOS {
	case "windows":
		c, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		out, err := exec.CommandContext(c, "powershell.exe", "-NoProfile", "-NonInteractive",
			"-ExecutionPolicy", "Bypass", "-Command", WindowsUpdateScript).Output()
		if err != nil {
			return Inventory{UpdateStatus: "error"}
		}
		ups, err := ParseWindowsUpdates(out)
		if err != nil {
			return Inventory{UpdateStatus: "error"}
		}
		return Inventory{Updates: ups, UpdateStatus: "ok"}
	default:
		return Inventory{UpdateStatus: "unsupported"}
	}
}
