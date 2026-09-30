// Package proclist enumerates running processes on Windows, where
// there is no /proc to read (roadmap 5.1, 5.2). It feeds the polling process
// sensor and the kill_process command on those platforms.
package proclist

import "errors"

// Proc is one running process at the moment of listing.
type Proc struct {
	PID  int32
	PPID int32
	// Start distinguishes a process from a later one that reused its pid.
	// Its unit is platform-specific; only equality is meaningful.
	Start uint64
	// Image is the full executable path where the platform gives one, or
	// the short process name where it does not (see Name).
	Image string
	// Name is the short executable name.
	Name string
	// UID is -1 on Windows, where owners are SIDs.
	UID int
}

// ErrUnsupported is returned where this package has no implementation.
var ErrUnsupported = errors.New("proclist: unsupported platform")
