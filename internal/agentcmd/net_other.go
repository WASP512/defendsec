//go:build !linux && !windows

package agentcmd

import (
	"fmt"
	"os"
	"runtime"
)

func isolateDescription() string { return "" }

func privileged() bool { return os.Geteuid() == 0 }

func applyNetIsolate(string) error {
	return fmt.Errorf("network isolation is not implemented on %s", runtime.GOOS)
}

func clearNetIsolate(string) error { return nil }
