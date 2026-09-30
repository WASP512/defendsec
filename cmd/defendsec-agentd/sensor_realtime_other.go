//go:build !windows

package main

import (
	"log/slog"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

// platformRealtimeSensor is Windows-only (ETW); Linux uses eBPF directly.
func platformRealtimeSensor(*slog.Logger, string, string, *events.Tree) sensor.Sensor { return nil }
