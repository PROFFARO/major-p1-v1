// Package ebpf provides NetObserv network flow metrics aggregation and RTT calculation.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

type NetObservDirection uint8

const (
	NetObservIngress NetObservDirection = 0
	NetObservEgress  NetObservDirection = 1
)

// NetObservFlowID mirror of struct netobserv_flow_id (netobserv_flow.h)
type NetObservFlowID struct {
	SrcIP             string             `json:"src_ip"`
	DstIP             string             `json:"dst_ip"`
	SrcPort           uint16             `json:"src_port"`
	DstPort           uint16             `json:"dst_port"`
	TransportProtocol uint8              `json:"transport_protocol"`
	Direction         NetObservDirection `json:"direction"`
}

// NetObservFlowMetrics mirror of struct netobserv_flow_metrics
type NetObservFlowMetrics struct {
	StartTimeNs time.Duration `json:"start_time_ns"`
	EndTimeNs   time.Duration `json:"end_time_ns"`
	Bytes       uint64        `json:"bytes"`
	Packets     uint32        `json:"packets"`
	TCPFlags    uint32        `json:"tcp_flags"`
	RTTNs       uint32        `json:"rtt_ns"`
	IfIndex     uint32        `json:"if_index"`
}

// NetObservFlowRecord combines flow key and metric summary.
type NetObservFlowRecord struct {
	ID      NetObservFlowID      `json:"flow_id"`
	Metrics NetObservFlowMetrics `json:"metrics"`
}

// NetObservCollector aggregates flow statistics over sliding time windows.
type NetObservCollector struct {
	mu    sync.RWMutex
	flows map[string]*NetObservFlowRecord
}

// NewNetObservCollector creates a new network flow collector.
func NewNetObservCollector() *NetObservCollector {
	return &NetObservCollector{
		flows: make(map[string]*NetObservFlowRecord),
	}
}

// ParseNetObservFlow parses raw binary flow key and flow metrics structs.
func ParseNetObservFlow(keyData, valData []byte) (*NetObservFlowRecord, error) {
	if len(keyData) < 14 || len(valData) < 36 {
		return nil, fmt.Errorf("invalid NetObserv flow payload size (key=%d, val=%d)", len(keyData), len(valData))
	}

	bo := binary.LittleEndian

	srcIP := ipFromU32(bo.Uint32(keyData[0:4]))
	dstIP := ipFromU32(bo.Uint32(keyData[4:8]))
	srcPort := ntohs(bo.Uint16(keyData[8:10]))
	dstPort := ntohs(bo.Uint16(keyData[10:12]))
	protocol := keyData[12]
	dir := NetObservDirection(keyData[13])

	startTimeNs := bo.Uint64(valData[0:8])
	endTimeNs := bo.Uint64(valData[8:16])
	bytesCount := bo.Uint64(valData[16:24])
	packetsCount := bo.Uint32(valData[24:28])
	tcpFlags := bo.Uint32(valData[28:32])
	rttNs := bo.Uint32(valData[32:36])

	return &NetObservFlowRecord{
		ID: NetObservFlowID{
			SrcIP:             srcIP,
			DstIP:             dstIP,
			SrcPort:           srcPort,
			DstPort:           dstPort,
			TransportProtocol: protocol,
			Direction:         dir,
		},
		Metrics: NetObservFlowMetrics{
			StartTimeNs: time.Duration(startTimeNs) * time.Nanosecond,
			EndTimeNs:   time.Duration(endTimeNs) * time.Nanosecond,
			Bytes:       bytesCount,
			Packets:     packetsCount,
			TCPFlags:    tcpFlags,
			RTTNs:       rttNs,
		},
	}, nil
}

// RecordFlow updates flow aggregation records.
func (nc *NetObservCollector) RecordFlow(record *NetObservFlowRecord) {
	if record == nil {
		return
	}
	flowKey := fmt.Sprintf("%s:%d->%s:%d(%d)", record.ID.SrcIP, record.ID.SrcPort, record.ID.DstIP, record.ID.DstPort, record.ID.TransportProtocol)

	nc.mu.Lock()
	defer nc.mu.Unlock()

	existing, found := nc.flows[flowKey]
	if !found {
		nc.flows[flowKey] = record
	} else {
		existing.Metrics.Bytes += record.Metrics.Bytes
		existing.Metrics.Packets += record.Metrics.Packets
		existing.Metrics.EndTimeNs = record.Metrics.EndTimeNs
		if record.Metrics.RTTNs > 0 {
			existing.Metrics.RTTNs = (existing.Metrics.RTTNs + record.Metrics.RTTNs) / 2
		}
	}
}
