package main

import (
	"log/slog"
	"os"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

// platformRealtimeSensor returns the ETW sensor when DEFENDSEC_ETW=1. It is
// opt-in until it has run on Windows hosts under DefendSec's own tests; see
// package etw. If the session cannot start, the runner falls back (below).
func platformRealtimeSensor(log *slog.Logger, deviceID, hostname string, tree *events.Tree) sensor.Sensor {
	if os.Getenv("DEFENDSEC_ETW") != "1" {
		return nil
	}
	log.Info("process sensor: ETW (Microsoft-Windows-Kernel-Process)")
	return &fallbackSensor{
		primary:  sensor.NewETWSensor(deviceID, hostname, tree),
		fallback: sensor.NewListSensor(deviceID, hostname, tree),
		log:      log,
	}
}
