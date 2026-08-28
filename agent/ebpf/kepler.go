// Package ebpf provides Kepler process and node energy consumption metrics processing.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
)

// KeplerProcEnergy mirror of struct kepler_proc_energy_t (kepler_energy.h)
type KeplerProcEnergy struct {
	PID             uint32 `json:"pid"`
	TGID            uint32 `json:"tgid"`
	CPUCycles       uint64 `json:"cpu_cycles"`
	CPUInstructions uint64 `json:"cpu_instructions"`
	CacheMisses     uint64 `json:"cache_misses"`
	PageCacheHits   uint64 `json:"page_cache_hits"`
	IRQCount        uint64 `json:"irq_count"`
	EnergyMicroJoules uint64 `json:"energy_ujoules"`
	Comm            string `json:"comm"`
	ContainerID     string `json:"container_id"`
}

// KeplerNodeEnergy mirror of struct kepler_node_energy_t
type KeplerNodeEnergy struct {
	PkgEnergyUJ  uint64  `json:"pkg_energy_uj"`  // CPU Package Energy
	DRAMEnergyUJ uint64  `json:"dram_energy_uj"` // DRAM Memory Energy
	GPUEnergyUJ  uint64  `json:"gpu_energy_uj"`  // GPU Hardware Energy
	TotalWatts   float64 `json:"total_watts"`    // Real-Time Power (W)
}

// KeplerCollector manages process and node power telemetry aggregation.
type KeplerCollector struct {
	mu           sync.RWMutex
	processStats map[uint32]*KeplerProcEnergy
	nodeEnergy   KeplerNodeEnergy
}

// NewKeplerCollector creates a new Kepler energy metrics collector.
func NewKeplerCollector() *KeplerCollector {
	return &KeplerCollector{
		processStats: make(map[uint32]*KeplerProcEnergy),
	}
}

// ParseProcEnergy unmarshals raw BPF bytes from kepler_energy probe.
func ParseProcEnergy(data []byte) (*KeplerProcEnergy, error) {
	if len(data) < 128 {
		return nil, fmt.Errorf("kepler energy data too short: %d bytes", len(data))
	}

	bo := binary.LittleEndian
	pid := bo.Uint32(data[0:4])
	tgid := bo.Uint32(data[4:8])
	cycles := bo.Uint64(data[8:16])
	instructions := bo.Uint64(data[16:24])
	cacheMisses := bo.Uint64(data[24:32])
	pageCacheHits := bo.Uint64(data[32:40])
	irqCount := bo.Uint64(data[40:48])
	energyUJ := bo.Uint64(data[48:56])

	comm := strings.TrimRight(string(data[56:72]), "\x00")
	containerID := strings.TrimRight(string(data[72:136]), "\x00")

	return &KeplerProcEnergy{
		PID:               pid,
		TGID:              tgid,
		CPUCycles:         cycles,
		CPUInstructions:   instructions,
		CacheMisses:       cacheMisses,
		PageCacheHits:     pageCacheHits,
		IRQCount:          irqCount,
		EnergyMicroJoules: energyUJ,
		Comm:              strings.TrimSpace(comm),
		ContainerID:       strings.TrimSpace(containerID),
	}, nil
}

// RecordProcEnergy updates internal energy state per PID.
func (kc *KeplerCollector) RecordProcEnergy(proc *KeplerProcEnergy) {
	if proc == nil || proc.PID == 0 {
		return
	}
	kc.mu.Lock()
	defer kc.mu.Unlock()
	kc.processStats[proc.PID] = proc
}

// GetTotalEnergySnapshot returns accumulated process energy metrics.
func (kc *KeplerCollector) GetTotalEnergySnapshot() map[uint32]*KeplerProcEnergy {
	kc.mu.RLock()
	defer kc.mu.RUnlock()
	copyMap := make(map[uint32]*KeplerProcEnergy, len(kc.processStats))
	for pid, stat := range kc.processStats {
		copyMap[pid] = stat
	}
	return copyMap
}
