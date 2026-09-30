package main

import (
	"log/slog"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

// pickPlatformSensor chooses the process sensor on Windows and macOS. The
// process-table poller is the default on both; see its Describe for what it
// misses. Windows may opt into ETW (see sensor_etw_windows.go).
func pickPlatformSensor(log *slog.Logger, deviceID, hostname string, tree *events.Tree) sensor.Sensor {
	if s := platformRealtimeSensor(log, deviceID, hostname, tree); s != nil {
		return s
	}
	log.Warn("process sensor: sampling the process table, which misses short-lived processes")
	return sensor.NewListSensor(deviceID, hostname, tree)
}
