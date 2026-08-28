// Package ebpf provides Tracee forensic event parsing and memory protection anomaly detection.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// TraceeEventID mirror of enum tracee_event_id (tracee_events.h)
type TraceeEventID uint32

const (
	TraceeRawSysEnter          TraceeEventID = 100
	TraceeRawSysExit           TraceeEventID = 101
	TraceeSchedProcessFork     TraceeEventID = 102
	TraceeSchedProcessExec     TraceeEventID = 103
	TraceeSchedProcessExit     TraceeEventID = 104
	TraceeCommitCreds          TraceeEventID = 105
	TraceeSecurityBprmCheck    TraceeEventID = 106
	TraceeSecurityFileOpen     TraceeEventID = 107
	TraceeSecuritySocketConnect TraceeEventID = 108
	TraceeMemProtAlert         TraceeEventID = 109
	TraceeSharedObjectLoaded   TraceeEventID = 110
	TraceeMagicWrite            TraceeEventID = 111
	TraceeModuleLoad            TraceeEventID = 112
	TraceeSuspiciousSyscall     TraceeEventID = 113
	TraceeDirtyPipeSplice      TraceeEventID = 114
	TraceeHiddenModuleSeeker   TraceeEventID = 115
)

func (t TraceeEventID) String() string {
	switch t {
	case TraceeMemProtAlert:
		return "MemProtAlert"
	case TraceeMagicWrite:
		return "MagicWrite"
	case TraceeModuleLoad:
		return "ModuleLoad"
	case TraceeSuspiciousSyscall:
		return "SuspiciousSyscall"
	case TraceeDirtyPipeSplice:
		return "DirtyPipeSplice"
	case TraceeHiddenModuleSeeker:
		return "HiddenModuleSeeker"
	default:
		return fmt.Sprintf("TraceeEvent_%d", t)
	}
}

// TraceeMemProtType mirror of enum tracee_mem_prot_alert
type TraceeMemProtType uint32

const (
	TraceeAlertMmapWX   TraceeMemProtType = 1 // Write + Execute
	TraceeAlertMprotXAdd TraceeMemProtType = 2 // Mprotect added Execute
	TraceeAlertMprotWAdd TraceeMemProtType = 3 // Mprotect added Write
)

// TraceeTaskContext mirror of struct tracee_task_context_t
type TraceeTaskContext struct {
	StartTime time.Duration `json:"start_time"`
	CgroupID  uint64        `json:"cgroup_id"`
	PID       uint32        `json:"pid"`
	TID       uint32        `json:"tid"`
	PPID      uint32        `json:"ppid"`
	HostPID   uint32        `json:"host_pid"`
	HostTID   uint32        `json:"host_tid"`
	HostPPID  uint32        `json:"host_ppid"`
	UID       uint32        `json:"uid"`
	MntID     uint32        `json:"mnt_id"`
	PidID     uint32        `json:"pid_id"`
	Comm      string        `json:"comm"`
	Flags     uint32        `json:"flags"`
}

// TraceeEventContext mirror of struct tracee_event_context_t
type TraceeEventContext struct {
	Timestamp   time.Duration     `json:"timestamp"`
	Task        TraceeTaskContext `json:"task"`
	EventID     TraceeEventID     `json:"event_id"`
	EventName   string            `json:"event_name"`
	SyscallNR   int32             `json:"syscall_nr"`
	ProcessorID uint32            `json:"processor_id"`
}

// ParseTraceeEventContext parses a raw binary tracee_event_context_t header struct.
func ParseTraceeEventContext(data []byte) (*TraceeEventContext, error) {
	if len(data) < 80 {
		return nil, fmt.Errorf("tracee event context data too short: %d bytes", len(data))
	}

	bo := binary.LittleEndian
	tsNs := bo.Uint64(data[0:8])

	// Task context starts at byte 8 (64 bytes)
	tStartTime := bo.Uint64(data[8:16])
	tCgroupID := bo.Uint64(data[16:24])
	tPID := bo.Uint32(data[24:28])
	tTID := bo.Uint32(data[28:32])
	tPPID := bo.Uint32(data[32:36])
	tHostPID := bo.Uint32(data[36:40])
	tHostTID := bo.Uint32(data[40:44])
	tHostPPID := bo.Uint32(data[44:48])
	tUID := bo.Uint32(data[48:52])
	tMntID := bo.Uint32(data[52:56])
	tPidID := bo.Uint32(data[56:60])
	tComm := strings.TrimRight(string(data[60:76]), "\x00")
	tFlags := bo.Uint32(data[76:80])

	// Event context fields after byte 80
	eventID := bo.Uint32(data[80:84])
	syscallNR := int32(bo.Uint32(data[84:88]))
	processorID := bo.Uint32(data[88:92])

	evObj := TraceeEventID(eventID)

	return &TraceeEventContext{
		Timestamp: time.Duration(tsNs) * time.Nanosecond,
		Task: TraceeTaskContext{
			StartTime: time.Duration(tStartTime) * time.Nanosecond,
			CgroupID:  tCgroupID,
			PID:       tPID,
			TID:       tTID,
			PPID:      tPPID,
			HostPID:   tHostPID,
			HostTID:   tHostTID,
			HostPPID:  tHostPPID,
			UID:       tUID,
			MntID:     tMntID,
			PidID:     tPidID,
			Comm:      strings.TrimSpace(tComm),
			Flags:     tFlags,
		},
		EventID:     evObj,
		EventName:   evObj.String(),
		SyscallNR:   syscallNR,
		ProcessorID: processorID,
	}, nil
}
