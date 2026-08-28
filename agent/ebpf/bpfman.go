// Package ebpf provides bpfman program lifecycle management and multi-probe attachment ordering.
package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
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

// PinMode defines bpfman map pinning strategies.
type PinMode int

const (
	PinNone   PinMode = 0
	PinByName PinMode = 1
	PinCustom PinMode = 2
)

// ProgramSpec defines a bpfman managed eBPF program load specification.
type ProgramSpec struct {
	ID           uint32          `json:"id"`
	Name         string          `json:"name"`
	Type         string          `json:"type"`
	Priority     ProgramPriority `json:"priority"`
	PinMode      PinMode         `json:"pin_mode"`
	AttachTarget string          `json:"attach_target"`
	PinPath      string          `json:"pin_path,omitempty"`
	Loaded       bool            `json:"loaded"`
}

// BpfmanManager manages multi-probe attachment chains and map pinning lifecycles.
type BpfmanManager struct {
	mu       sync.RWMutex
	programs map[string]*ProgramSpec
	pinDir   string
}

// NewBpfmanManager creates a new bpfman manager instance.
func NewBpfmanManager(pinDir string) *BpfmanManager {
	if pinDir == "" {
		pinDir = "/sys/fs/bpf/ebpf_ml"
	}
	return &BpfmanManager{
		programs: make(map[string]*ProgramSpec),
		pinDir:   pinDir,
	}
}

// RegisterProgram registers a program specification for management.
func (m *BpfmanManager) RegisterProgram(spec *ProgramSpec) error {
	if spec == nil || spec.Name == "" {
		return fmt.Errorf("invalid program spec")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if spec.PinPath == "" && spec.PinMode == PinByName {
		spec.PinPath = filepath.Join(m.pinDir, spec.Name)
	}

	m.programs[spec.Name] = spec
	return nil
}

// GetOrderedChain returns programs sorted by priority ordering.
func (m *BpfmanManager) GetOrderedChain() []*ProgramSpec {
	m.mu.RLock()
	defer m.mu.RUnlock()

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

// EnsurePinDir creates the BPF virtual filesystem pinning directory if missing.
func (m *BpfmanManager) EnsurePinDir() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return os.MkdirAll(m.pinDir, 0755)
}

// GetProgram returns metadata for a registered bpfman program.
func (m *BpfmanManager) GetProgram(name string) (*ProgramSpec, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, exists := m.programs[name]
	return p, exists
}
