package main

import (
	"context"
	"log/slog"
	"time"

	"defendsec/internal/events"
	defendsecv1 "defendsec/internal/gen/defendsec/v1"
	"defendsec/internal/sensor"
)

// Shipping behavioural telemetry (roadmap 3.1-3.2).
//
// The event path is deliberately isolated from the command path. It shares the
// stream, but it never blocks it: the buffer drops when full rather than
// applying backpressure, and a failure to send ends the shipper rather than
// the connection. A sensor that stalls the command channel would make the
// response capability — the best part of the product — hostage to telemetry
// volume, which is exactly backwards.

const (
	// shipInterval is how often a batch goes out. Frequent enough that a
	// detection is not minutes stale, infrequent enough that a busy host
	// sends batches rather than messages.
	shipInterval = 2 * time.Second
	// maxBatch bounds one message. A host that has buffered thousands of
	// events sends them over several batches instead of one large frame.
	maxBatch = 512
)

// startEventShipper runs the sensor and forwards batches.
func startEventShipper(ctx context.Context, log *slog.Logger, deviceID, hostname string, send func(*defendsecv1.AgentToServer) error) {
	buffer := events.NewBuffer(0)
	tree := events.NewTree(0, 0)
	s := sensor.NewProcSensor(deviceID, hostname, tree)

	capability := s.Describe()
	log.Info("behavioural sensor started",
		"sensor", capability.Name, "kinds", capability.Kinds, "complete", capability.Complete)
	for _, limitation := range capability.Limitations {
		// Logged at start rather than buried in documentation: an operator
		// reading the agent's log should learn what it cannot see without
		// having to go and look it up.
		log.Info("sensor limitation", "sensor", capability.Name, "detail", limitation)
	}

	go func() {
		if err := s.Run(ctx, buffer.Add); err != nil && ctx.Err() == nil {
			log.Warn("behavioural sensor stopped", "err", err)
		}
	}()

	go func() {
		ticker := time.NewTicker(shipInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			batch := buffer.Drain(maxBatch)
			if len(batch.Events) == 0 && batch.DroppedSinceLast == 0 {
				continue
			}
			if !batch.Complete() {
				log.Warn("event buffer overflowed; some events were not sent",
					"dropped", batch.DroppedSinceLast, "total", batch.DroppedTotal)
			}
			if err := send(&defendsecv1.AgentToServer{
				Body: &defendsecv1.AgentToServer_Events{
					Events: events.BatchToProto(batch, s.Name()),
				},
			}); err != nil {
				// The stream is gone. Ending here is right: the command loop
				// owns reconnection, and a shipper that kept retrying on a
				// dead stream would fight it.
				if ctx.Err() == nil {
					log.Warn("event batch not sent", "err", err, "events", len(batch.Events))
				}
				return
			}
		}
	}()
}
