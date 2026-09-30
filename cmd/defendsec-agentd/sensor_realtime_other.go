//go:build !windows

package main

import (
	"log/slog"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

// platformRealtimeSensor: macOS's realtime path is EndpointSecurity, which
// needs an Apple-granted entitlement DefendSec does not yet hold. See
// docs/MACOS.md.
func platformRealtimeSensor(*slog.Logger, string, string, *events.Tree) sensor.Sensor { return nil }
