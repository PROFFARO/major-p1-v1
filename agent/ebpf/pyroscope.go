// Package ebpf provides Pyroscope stack profile aggregation and flamegraph sampling.
package ebpf

import (
	"fmt"
	"sync"
)

// PyroscopeFlag enum (pyroscope_profile.h)
type PyroscopeFlag uint16

const (
	PyroscopeFlagCPUSample PyroscopeFlag = 0xCEF0
	PyroscopeFlagMemSample PyroscopeFlag = 0xCEF1
)

// PyroscopeStackKey mirror of struct pyroscope_stack_key_t
type PyroscopeStackKey struct {
	PID           uint32 `json:"pid"`
	TGID          uint32 `json:"tgid"`
	UserStackID   int32  `json:"user_stack_id"`
	KernelStackID int32  `json:"kernel_stack_id"`
	Comm          string `json:"comm"`
}

// PyroscopeAggregator aggregates continuous CPU stack profile keys into flamegraph sample counts.
type PyroscopeAggregator struct {
	mu           sync.RWMutex
	sampleCounts map[string]uint64
}

// NewPyroscopeAggregator initializes a Pyroscope stack profile aggregator.
func NewPyroscopeAggregator() *PyroscopeAggregator {
	return &PyroscopeAggregator{
		sampleCounts: make(map[string]uint64),
	}
}

// RecordStackSample increments the sample count for a process stack trace key.
func (pa *PyroscopeAggregator) RecordStackSample(key *PyroscopeStackKey, weight uint64) {
	if key == nil {
		return
	}
	stackIdentifier := fmt.Sprintf("%s;pid=%d;user_stack=%d;kernel_stack=%d", key.Comm, key.PID, key.UserStackID, key.KernelStackID)

	pa.mu.Lock()
	defer pa.mu.Unlock()
	pa.sampleCounts[stackIdentifier] += weight
}

// GetFlamegraphFormat exports stacked sample counts formatted for Pyroscope flamegraph visualization.
func (pa *PyroscopeAggregator) GetFlamegraphFormat() map[string]uint64 {
	pa.mu.RLock()
	defer pa.mu.RUnlock()

	snapshot := make(map[string]uint64, len(pa.sampleCounts))
	for k, v := range pa.sampleCounts {
		snapshot[k] = v
	}
	return snapshot
}
