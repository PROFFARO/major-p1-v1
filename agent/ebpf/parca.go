// Package ebpf provides Parca continuous profiling telemetry and pprof sample formatting.
package ebpf

import (
	"fmt"
	"sync"
	"time"
)

// ParcaSample represents a Parca continuous CPU profiling record.
type ParcaSample struct {
	Timestamp time.Time `json:"timestamp"`
	PID       uint32    `json:"pid"`
	Comm      string    `json:"comm"`
	Samples   uint64    `json:"samples"`
	PprofKey  string    `json:"pprof_key"`
}

// ParcaEngine manages continuous profiling telemetry streams.
type ParcaEngine struct {
	mu      sync.Mutex
	samples []*ParcaSample
}

// NewParcaEngine creates a new Parca profiler engine instance.
func NewParcaEngine() *ParcaEngine {
	return &ParcaEngine{
		samples: make([]*ParcaSample, 0),
	}
}

// RecordProfileSample registers an eBPF CPU sample event as a Parca pprof record.
func (p *ParcaEngine) RecordProfileSample(ev *Event) {
	if ev == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	sample := &ParcaSample{
		Timestamp: time.Now(),
		PID:       ev.PID,
		Comm:      ev.Comm,
		Samples:   1,
		PprofKey:  fmt.Sprintf("process_cpu_samples{comm=\"%s\",pid=\"%d\"}", ev.Comm, ev.PID),
	}

	p.samples = append(p.samples, sample)
}

// GetPprofSummary returns formatted Parca pprof sample key metrics.
func (p *ParcaEngine) GetPprofSummary() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var summary []string
	for _, s := range p.samples {
		summary = append(summary, fmt.Sprintf("%s %d", s.PprofKey, s.Samples))
	}
	return summary
}
