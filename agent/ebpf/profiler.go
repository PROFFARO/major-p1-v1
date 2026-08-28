// Package ebpf provides Grafana Pyroscope profiling aggregation and flamegraph formatting.
package ebpf

import (
	"fmt"
	"strings"
	"sync"
)

// ProfileSample represents a continuous profiling sample stack trace.
type ProfileSample struct {
	PID        uint32   `json:"pid"`
	Comm       string   `json:"comm"`
	Stack      []string `json:"stack"`
	SampleCount uint64   `json:"sample_count"`
}

// PyroscopeProfiler aggregates eBPF stack trace samples into folded flamegraph format.
type PyroscopeProfiler struct {
	mu      sync.Mutex
	samples map[string]uint64
}

// NewPyroscopeProfiler creates a new profiler instance.
func NewPyroscopeProfiler() *PyroscopeProfiler {
	return &PyroscopeProfiler{
		samples: make(map[string]uint64),
	}
}

// RecordSample records a CPU profiling stack sample event.
func (p *PyroscopeProfiler) RecordSample(ev *Event) {
	if ev == nil || ev.Flags != 0xCEF0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Construct synthetic folded stack frame string: process_comm;kernel_frame;user_frame
	foldedKey := fmt.Sprintf("%s;pid_%d;cpu_cycle", ev.Comm, ev.PID)
	p.samples[foldedKey]++
}

// ExportFoldedFormat returns profile data in folded stack trace format for Grafana Pyroscope / Flamegraph renderers.
func (p *PyroscopeProfiler) ExportFoldedFormat() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var sb strings.Builder
	for stack, count := range p.samples {
		sb.WriteString(fmt.Sprintf("%s %d\n", stack, count))
	}
	return sb.String()
}
