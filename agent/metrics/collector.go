// Package metrics tracks telemetry event rates, BPF map statistics,
// and system metrics for monitoring and SOC dashboard visualizer.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	cilium "github.com/cilium/ebpf"
	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
)

// MetricsSnapshot represents the current telemetry throughput and counters.
type MetricsSnapshot struct {
	TotalEvents        uint64            `json:"total_events"`
	EventsPerSecond    float64           `json:"events_per_second"`
	EventTypeCounts    map[string]uint64 `json:"event_type_counts"`
	EventSourceCounts  map[string]uint64 `json:"event_source_counts"`
	TotalPacketsLogged uint64            `json:"total_packets_logged"`
	TotalDNSQueries    uint64            `json:"total_dns_queries"`
	UptimeSeconds      float64           `json:"uptime_seconds"`
}

// Collector records metrics in real time.
type Collector struct {
	mu                sync.RWMutex
	startTime         time.Time
	totalEvents       uint64
	lastSecondEvents  uint64
	currentEPS        float64
	eventTypeCounts   map[string]uint64
	eventSourceCounts map[string]uint64

	pktCounterMap *cilium.Map
	dnsCounterMap *cilium.Map
}

// NewCollector creates a new metrics collector.
func NewCollector(pktMap, dnsMap *cilium.Map) *Collector {
	c := &Collector{
		startTime:         time.Now(),
		eventTypeCounts:   make(map[string]uint64),
		eventSourceCounts: make(map[string]uint64),
		pktCounterMap:     pktMap,
		dnsCounterMap:     dnsMap,
	}
	go c.rateWorker()
	return c
}

// RecordEvent increments metrics for an incoming telemetry event.
func (c *Collector) RecordEvent(ev *agentebpf.Event) {
	if ev == nil {
		return
	}

	atomic.AddUint64(&c.totalEvents, 1)
	atomic.AddUint64(&c.lastSecondEvents, 1)

	c.mu.Lock()
	c.eventTypeCounts[ev.TypeStr]++
	c.eventSourceCounts[ev.Source]++
	c.mu.Unlock()
}

// rateWorker calculates events per second every second.
func (c *Collector) rateWorker() {
	ticker := time.NewTicker(1 * time.Second)
	for range ticker.C {
		count := atomic.SwapUint64(&c.lastSecondEvents, 0)
		c.mu.Lock()
		c.currentEPS = float64(count)
		c.mu.Unlock()
	}
}

// Snapshot returns the current metrics state.
func (c *Collector) Snapshot() MetricsSnapshot {
	c.mu.RLock()
	eps := c.currentEPS
	typesCopy := make(map[string]uint64, len(c.eventTypeCounts))
	for k, v := range c.eventTypeCounts {
		typesCopy[k] = v
	}
	sourcesCopy := make(map[string]uint64, len(c.eventSourceCounts))
	for k, v := range c.eventSourceCounts {
		sourcesCopy[k] = v
	}
	c.mu.RUnlock()

	return MetricsSnapshot{
		TotalEvents:        atomic.LoadUint64(&c.totalEvents),
		EventsPerSecond:    eps,
		EventTypeCounts:    typesCopy,
		EventSourceCounts:  sourcesCopy,
		TotalPacketsLogged: c.readCounterMapTotal(c.pktCounterMap),
		TotalDNSQueries:    c.readCounterMapTotal(c.dnsCounterMap),
		UptimeSeconds:      time.Since(c.startTime).Seconds(),
	}
}

// readCounterMapTotal sums all values in a BPF map.
func (c *Collector) readCounterMapTotal(m *cilium.Map) uint64 {
	if m == nil {
		return 0
	}

	var sum uint64
	var key uint32
	var val uint64

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sum += val
	}
	return sum
}
