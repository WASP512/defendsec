package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

// fallbackSensor runs primary and, if it fails to start or stops with an
// error, runs fallback instead. Describe reports whichever is actually
// running, so the coverage view never claims the stronger sensor after it
// has failed.
type fallbackSensor struct {
	primary, fallback sensor.Sensor
	log               *slog.Logger
	failed            atomic.Bool
}

func (f *fallbackSensor) active() sensor.Sensor {
	if f.failed.Load() {
		return f.fallback
	}
	return f.primary
}

func (f *fallbackSensor) Name() string                { return f.active().Name() }
func (f *fallbackSensor) Describe() sensor.Capability { return f.active().Describe() }

func (f *fallbackSensor) Run(ctx context.Context, sink func(*events.Event)) error {
	err := f.primary.Run(ctx, sink)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	f.log.Error("process sensor failed; falling back", "sensor", f.primary.Name(), "err", err, "fallback", f.fallback.Name())
	f.failed.Store(true)
	return f.fallback.Run(ctx, sink)
}
