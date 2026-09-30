package main

import (
	"log/slog"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

// platformRealtimeSensor is replaced by the ETW sensor once it lands.
func platformRealtimeSensor(*slog.Logger, string, string, *events.Tree) sensor.Sensor { return nil }
