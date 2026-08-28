// Package ebpf provides bpfman program lifecycle management and multi-probe attachment ordering.
package ebpf

import (
	"fmt"
	"sort"
	"sync"
)

// ProgramPriority defines attachment priority (lower value = higher execution priority).
type ProgramPriority int

const (
	PriorityHigh   ProgramPriority = 100
	PriorityMedium ProgramPriority = 500
	PriorityLow    ProgramPriority = 1000
)

// ProgramSpec defines a bpfman managed eBPF program load specification.
type ProgramSpec struct {
	Name         string          `json:"name"`
	Type         string          `json:"type"`
	Priority     ProgramPriority `json:"priority"`
	AttachTarget string          `json:"attach_target"`
	PinPath      string          `json:"pin_path,omitempty"`
	Loaded       bool            `json:"loaded"`
}

// BpfmanManager manages multi-probe attachment chains and map pinning lifecycles.
type BpfmanManager struct {
	mu       sync.Mutex
	programs map[string]*ProgramSpec
}

// NewBpfmanManager creates a new bpfman manager instance.
func NewBpfmanManager() *BpfmanManager {
	return &BpfmanManager{
		programs: make(map[string]*ProgramSpec),
	}
}

// RegisterProgram registers a program specification for management.
func (m *BpfmanManager) RegisterProgram(spec *ProgramSpec) error {
	if spec == nil || spec.Name == "" {
		return fmt.Errorf("invalid program spec")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.programs[spec.Name] = spec
	return nil
}

// GetOrderedChain returns programs sorted by priority ordering.
func (m *BpfmanManager) GetOrderedChain() []*ProgramSpec {
	m.mu.Lock()
	defer m.mu.Unlock()

	chain := make([]*ProgramSpec, 0, len(m.programs))
	for _, p := range m.programs {
		chain = append(chain, p)
	}

	sort.Slice(chain, func(i, j int) bool {
		return chain[i].Priority < chain[j].Priority
	})

	return chain
}

// SetLoaded updates program load status.
func (m *BpfmanManager) SetLoaded(name string, loaded bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if p, exists := m.programs[name]; exists {
		p.Loaded = loaded
	}
}
