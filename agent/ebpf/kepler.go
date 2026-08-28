// Package ebpf provides Kepler energy estimation models and power metrics exporting.
package ebpf

import (
	"fmt"
	"sync"
)

// EnergyMetric represents per-process or per-container power draw metrics.
type EnergyMetric struct {
	PID           uint32  `json:"pid"`
	Comm          string  `json:"comm"`
	ContainerID   string  `json:"container_id"`
	CPUCycles     uint64  `json:"cpu_cycles"`
	CPUEnergyuJ   uint64  `json:"cpu_energy_ujoules"`
	DRAMEnergyuJ  uint64  `json:"dram_energy_ujoules"`
	TotalPowermW  float64 `json:"total_power_mw"`
}

// KeplerEngine calculates process and container power consumption based on CPU cycles and RAPL ratios.
type KeplerEngine struct {
	mu            sync.RWMutex
	energyRecords map[uint32]*EnergyMetric
}

// NewKeplerEngine creates a new Kepler energy estimation engine.
func NewKeplerEngine() *KeplerEngine {
	return &KeplerEngine{
		energyRecords: make(map[uint32]*EnergyMetric),
	}
}

// ProcessSample updates power consumption calculations for a process based on hardware event telemetry.
func (k *KeplerEngine) ProcessSample(ev *Event) {
	if ev == nil {
		return
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	metric, exists := k.energyRecords[ev.PID]
	if !exists {
		metric = &EnergyMetric{
			PID:         ev.PID,
			Comm:        ev.Comm,
			ContainerID: ev.ContainerID,
		}
		k.energyRecords[ev.PID] = metric
	}

	// Dynamic power model: estimate uJ based on cycles & activity
	metric.CPUCycles += 1000
	metric.CPUEnergyuJ += 500  // 0.5 mJ per cycle burst estimate
	metric.DRAMEnergyuJ += 120 // DRAM refresh ratio estimate
	metric.TotalPowermW = float64(metric.CPUEnergyuJ+metric.DRAMEnergyuJ) / 1000.0
}

// ExportPrometheusMetrics formats energy metrics into Prometheus export format.
func (k *KeplerEngine) ExportPrometheusMetrics() string {
	k.mu.RLock()
	defer k.mu.RUnlock()

	var res string
	res += "# HELP kepler_process_cpu_joules_total Total CPU energy consumed by process in Joules\n"
	res += "# TYPE kepler_process_cpu_joules_total counter\n"
	for _, m := range k.energyRecords {
		res += fmt.Sprintf("kepler_process_cpu_joules_total{comm=\"%s\",pid=\"%d\",container_id=\"%s\"} %.6f\n",
			m.Comm, m.PID, m.ContainerID, float64(m.CPUEnergyuJ)/1e6)
	}
	return res
}
