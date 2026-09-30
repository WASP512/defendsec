//go:build !linux

package sensor

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"defendsec/internal/events"
)

// The eBPF sensor is Linux-only. This stub exists so defendsec-agentd still
// compiles for other platforms and fails at the one place that matters — the
// constructor — with a reason, rather than not building at all.

// ErrBPFUnsupported reports that this platform cannot run the sensor.
var ErrBPFUnsupported = errors.New("ebpf sensor unsupported on this platform")

// BPFSensor is not available off Linux.
type BPFSensor struct{}

// NewBPFSensor always fails here. The caller falls back to the poller.
func NewBPFSensor(deviceID, hostname string, tree *events.Tree) (*BPFSensor, error) {
	return nil, fmt.Errorf("%w: eBPF is a Linux facility and this is %s",
		ErrBPFUnsupported, runtime.GOOS)
}

// Name identifies the sensor.
func (s *BPFSensor) Name() string { return "ebpf-exec" }

// Describe states that nothing is observed here.
func (s *BPFSensor) Describe() Capability {
	return Capability{Name: s.Name(), Limitations: []string{"eBPF is not available on " + runtime.GOOS + "."}}
}

// Lost is always zero; the stub never runs.
func (s *BPFSensor) Lost() uint64 { return 0 }

// Run fails immediately.
func (s *BPFSensor) Run(context.Context, func(*events.Event)) error { return ErrBPFUnsupported }

// Close does nothing.
func (s *BPFSensor) Close() error { return nil }
