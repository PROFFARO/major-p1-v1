// Package ebpf provides Inspektor Gadget tracer formatting and container metadata resolution.
package ebpf

import (
	"fmt"
	"time"
)

// GadgetCategory represents Inspektor Gadget tracer categories.
type GadgetCategory uint32

const (
	GadgetTraceExec    GadgetCategory = 1
	GadgetTraceOpen    GadgetCategory = 2
	GadgetTraceDNS     GadgetCategory = 3
	GadgetTraceTCP     GadgetCategory = 4
	GadgetTraceCap     GadgetCategory = 5
	GadgetTraceSNI     GadgetCategory = 6
	GadgetTraceTCPDrop GadgetCategory = 7
	GadgetTraceMount   GadgetCategory = 8
	GadgetTraceSignal  GadgetCategory = 9
	GadgetTraceOOMKill GadgetCategory = 10
)

// String returns a human-readable gadget name.
func (c GadgetCategory) String() string {
	switch c {
	case GadgetTraceExec:
		return "trace_exec"
	case GadgetTraceOpen:
		return "trace_open"
	case GadgetTraceDNS:
		return "trace_dns"
	case GadgetTraceTCP:
		return "trace_tcp"
	case GadgetTraceCap:
		return "trace_capabilities"
	case GadgetTraceSNI:
		return "trace_sni"
	case GadgetTraceTCPDrop:
		return "trace_tcpdrop"
	case GadgetTraceMount:
		return "trace_mount"
	case GadgetTraceSignal:
		return "trace_signal"
	case GadgetTraceOOMKill:
		return "trace_oomkill"
	default:
		return "gadget_unknown"
	}
}

// GadgetRecord represents an Inspektor Gadget formatted telemetry record.
type GadgetRecord struct {
	Timestamp     time.Duration  `json:"timestamp"`
	Gadget        string         `json:"gadget"`
	PID           uint32         `json:"pid"`
	PPID          uint32         `json:"ppid"`
	UID           uint32         `json:"uid"`
	Comm          string         `json:"comm"`
	ContainerName string         `json:"container_name,omitempty"`
	PodName       string         `json:"pod_name,omitempty"`
	Namespace     string         `json:"namespace,omitempty"`
	Details       string         `json:"details"`
}

// FormatGadgetRecord converts a core Event into an Inspektor Gadget record.
func FormatGadgetRecord(ev *Event) *GadgetRecord {
	if ev == nil {
		return nil
	}

	record := &GadgetRecord{
		Timestamp:     ev.Timestamp,
		PID:           ev.PID,
		PPID:          ev.PPID,
		UID:           ev.UID,
		Comm:          ev.Comm,
		ContainerName: ev.ContainerID,
		Namespace:     "default",
	}

	switch ev.Type {
	case EventTypeExec:
		record.Gadget = GadgetTraceExec.String()
		record.Details = fmt.Sprintf("execve %s (ppid=%d)", ev.Filename, ev.PPID)
	case EventTypeFile:
		record.Gadget = GadgetTraceOpen.String()
		record.Details = fmt.Sprintf("file %s (op=%d)", ev.Filename, ev.FileOp)
	case EventTypeNet:
		record.Gadget = GadgetTraceTCP.String()
		record.Details = fmt.Sprintf("tcp %s:%d -> %s:%d (proto=%d)", ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort, ev.Protocol)
	case EventTypePriv:
		record.Gadget = GadgetTraceCap.String()
		record.Details = fmt.Sprintf("privilege mutation (syscall=%d)", ev.SyscallID)
	case EventTypeMem:
		record.Gadget = "trace_mem"
		record.Details = fmt.Sprintf("memory modification (syscall=%d)", ev.SyscallID)
	default:
		record.Gadget = "trace_generic"
		record.Details = fmt.Sprintf("event type %d", ev.Type)
	}

	return record
}
