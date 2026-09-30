package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"defendsec/internal/events"
	"defendsec/internal/sensor"
)

type stubSensor struct {
	name string
	err  error
}

func (s stubSensor) Name() string                { return s.name }
func (s stubSensor) Describe() sensor.Capability { return sensor.Capability{Name: s.name} }
func (s stubSensor) Run(ctx context.Context, _ func(*events.Event)) error {
	if s.err != nil {
		return s.err
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestFallbackSensorReportsWhatIsRunning(t *testing.T) {
	f := &fallbackSensor{
		primary:  stubSensor{name: "etw", err: errors.New("access denied")},
		fallback: stubSensor{name: "poll"},
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if f.Describe().Name != "etw" {
		t.Fatal("before running, the primary is described")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = f.Run(ctx, nil)
	if f.Describe().Name != "poll" {
		t.Fatalf("after the primary failed, coverage must describe the fallback, got %s", f.Describe().Name)
	}
}
