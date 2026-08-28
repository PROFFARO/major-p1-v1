// Package ebpf provides Inspektor Gadget container tracing event decoding and pod enrichment.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

// GadgetCategory mirror of enum gadget_event_category (gadget_types.h)
type GadgetCategory uint32

const (
	GadgetTypeTraceExec    GadgetCategory = 1
	GadgetTypeTraceOpen    GadgetCategory = 2
	GadgetTypeTraceDNS     GadgetCategory = 3
	GadgetTypeTraceTCP     GadgetCategory = 4
	GadgetTypeTraceCap     GadgetCategory = 5
	GadgetTypeTraceSNI     GadgetCategory = 6
	GadgetTypeTraceTCPDrop GadgetCategory = 7
	GadgetTypeTraceMount   GadgetCategory = 8
	GadgetTypeTraceSignal  GadgetCategory = 9
	GadgetTypeTraceOOMKill GadgetCategory = 10
)

func (c GadgetCategory) String() string {
	switch c {
	case GadgetTypeTraceExec:
		return "TRACE_EXEC"
	case GadgetTypeTraceOpen:
		return "TRACE_OPEN"
	case GadgetTypeTraceDNS:
		return "TRACE_DNS"
	case GadgetTypeTraceTCP:
		return "TRACE_TCP"
	case GadgetTypeTraceCap:
		return "TRACE_CAP"
	case GadgetTypeTraceSNI:
		return "TRACE_SNI"
	case GadgetTypeTraceTCPDrop:
		return "TRACE_TCPDROP"
	case GadgetTypeTraceMount:
		return "TRACE_MOUNT"
	case GadgetTypeTraceSignal:
		return "TRACE_SIGNAL"
	case GadgetTypeTraceOOMKill:
		return "TRACE_OOMKILL"
	default:
		return "UNKNOWN_GADGET"
	}
}

// GadgetContainerMeta mirror of struct gadget_container_meta_t
type GadgetContainerMeta struct {
	CgroupID      uint64 `json:"cgroup_id"`
	MntNSID       uint32 `json:"mnt_ns_id"`
	PidNSID       uint32 `json:"pid_ns_id"`
	ContainerName string `json:"container_name"`
	PodName       string `json:"pod_name"`
	Namespace     string `json:"namespace"`
}

// GadgetEvent mirror of struct gadget_event_t
type GadgetEvent struct {
	Timestamp   time.Duration       `json:"timestamp_ns"`
	Category    GadgetCategory      `json:"category"`
	CategoryStr string              `json:"category_str"`
	PID         uint32              `json:"pid"`
	TID         uint32              `json:"tid"`
	PPID        uint32              `json:"ppid"`
	UID         uint32              `json:"uid"`
	GID         uint32              `json:"gid"`
	Container   GadgetContainerMeta `json:"container"`
	Comm        string              `json:"comm"`
	Payload     string              `json:"payload"`
}

// GadgetTracer manages container gadget event subscription and enrichment.
type GadgetTracer struct {
	mu           sync.RWMutex
	containerMap map[uint64]*GadgetContainerMeta
}

// NewGadgetTracer initializes a new Inspektor Gadget container tracer.
func NewGadgetTracer() *GadgetTracer {
	return &GadgetTracer{
		containerMap: make(map[uint64]*GadgetContainerMeta),
	}
}

// ParseGadgetEvent parses a raw binary gadget_event_t struct.
func ParseGadgetEvent(data []byte) (*GadgetEvent, error) {
	if len(data) < 488 {
		return nil, fmt.Errorf("gadget event data too short: %d bytes, expected >= 488", len(data))
	}

	bo := binary.LittleEndian
	tsNs := bo.Uint64(data[0:8])
	category := bo.Uint32(data[8:12])
	pid := bo.Uint32(data[12:16])
	tid := bo.Uint32(data[16:20])
	ppid := bo.Uint32(data[20:24])
	uid := bo.Uint32(data[24:28])
	gid := bo.Uint32(data[28:32])

	cgroupID := bo.Uint64(data[32:40])
	mntNS := bo.Uint32(data[40:44])
	pidNS := bo.Uint32(data[44:48])

	cName := strings.TrimRight(string(data[48:112]), "\x00")
	pName := strings.TrimRight(string(data[112:176]), "\x00")
	nsName := strings.TrimRight(string(data[176:240]), "\x00")
	comm := strings.TrimRight(string(data[240:256]), "\x00")
	payload := strings.TrimRight(string(data[256:512]), "\x00")

	catObj := GadgetCategory(category)

	return &GadgetEvent{
		Timestamp:   time.Duration(tsNs) * time.Nanosecond,
		Category:    catObj,
		CategoryStr: catObj.String(),
		PID:         pid,
		TID:         tid,
		PPID:        ppid,
		UID:         uid,
		GID:         gid,
		Container: GadgetContainerMeta{
			CgroupID:      cgroupID,
			MntNSID:       mntNS,
			PidNSID:       pidNS,
			ContainerName: strings.TrimSpace(cName),
			PodName:       strings.TrimSpace(pName),
			Namespace:     strings.TrimSpace(nsName),
		},
		Comm:    strings.TrimSpace(comm),
		Payload: strings.TrimSpace(payload),
	}, nil
}

// RegisterContainer registers container metadata for Cgroup enrichment.
func (gt *GadgetTracer) RegisterContainer(meta *GadgetContainerMeta) {
	if meta == nil || meta.CgroupID == 0 {
		return
	}
	gt.mu.Lock()
	defer gt.mu.Unlock()
	gt.containerMap[meta.CgroupID] = meta
}

// LookupContainer retrieves cached Kubernetes container metadata by Cgroup ID.
func (gt *GadgetTracer) LookupContainer(cgroupID uint64) (*GadgetContainerMeta, bool) {
	gt.mu.RLock()
	defer gt.mu.RUnlock()
	meta, found := gt.containerMap[cgroupID]
	return meta, found
}
