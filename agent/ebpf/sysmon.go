// Package ebpf provides Sysmon for Linux Event ID translation and metadata formatting.
package ebpf

import (
	"fmt"
	"time"
)

// SysmonEventID represents Sysmon for Linux Event IDs (1-23).
type SysmonEventID uint32

const (
	SysmonProcessCreate       SysmonEventID = 1
	SysmonFileTimeChange     SysmonEventID = 2
	SysmonNetworkConnect      SysmonEventID = 3
	SysmonServiceStateChange SysmonEventID = 4
	SysmonProcessTerminate    SysmonEventID = 5
	SysmonDriverLoad          SysmonEventID = 6
	SysmonImageLoad           SysmonEventID = 7
	SysmonCreateRemoteThread  SysmonEventID = 8
	SysmonRawAccessRead       SysmonEventID = 9
	SysmonProcessAccess       SysmonEventID = 10
	SysmonFileCreate          SysmonEventID = 11
	SysmonPipeCreate          SysmonEventID = 17
	SysmonPipeConnect         SysmonEventID = 18
	SysmonDNSQuery            SysmonEventID = 22
	SysmonFileDelete          SysmonEventID = 23
)

// SysmonEvent represents a converted Sysmon telemetry audit event.
type SysmonEvent struct {
	EventID        SysmonEventID `json:"event_id"`
	EventName      string        `json:"event_name"`
	UtcTime        string        `json:"utc_time"`
	ProcessGuid    string        `json:"process_guid"`
	ProcessId      uint32        `json:"process_id"`
	Image          string        `json:"image"`
	CommandLine    string        `json:"command_line,omitempty"`
	User           string        `json:"user"`
	ParentProcessId uint32       `json:"parent_process_id"`
	ParentImage    string        `json:"parent_image,omitempty"`
	SourceIp       string        `json:"source_ip,omitempty"`
	SourcePort     uint16        `json:"source_port,omitempty"`
	DestinationIp  string        `json:"destination_ip,omitempty"`
	DestinationPort uint16       `json:"destination_port,omitempty"`
	TargetFilename string        `json:"target_filename,omitempty"`
}

// ConvertToSysmon translates a core kernel telemetry Event into a standard Sysmon record.
func ConvertToSysmon(ev *Event) *SysmonEvent {
	if ev == nil {
		return nil
	}

	sysEvent := &SysmonEvent{
		UtcTime:         time.Now().UTC().Format(time.RFC3339Nano),
		ProcessId:       ev.PID,
		ParentProcessId: ev.PPID,
		Image:           ev.ExePath,
		CommandLine:     ev.Cmdline,
		User:            fmt.Sprintf("UID:%d", ev.UID),
		ParentImage:     ev.ParentComm,
	}

	if sysEvent.Image == "" {
		sysEvent.Image = ev.Comm
	}

	switch ev.Type {
	case EventTypeExec:
		sysEvent.EventID = SysmonProcessCreate
		sysEvent.EventName = "ProcessCreate"
	case EventTypeExit:
		sysEvent.EventID = SysmonProcessTerminate
		sysEvent.EventName = "ProcessTerminate"
	case EventTypeNet:
		sysEvent.EventID = SysmonNetworkConnect
		sysEvent.EventName = "NetworkConnect"
		sysEvent.SourceIp = ev.SrcIP
		sysEvent.SourcePort = ev.SrcPort
		sysEvent.DestinationIp = ev.DstIP
		sysEvent.DestinationPort = ev.DstPort
	case EventTypeFile:
		if ev.FileOp == FileOpDelete {
			sysEvent.EventID = SysmonFileDelete
			sysEvent.EventName = "FileDelete"
		} else {
			sysEvent.EventID = SysmonFileCreate
			sysEvent.EventName = "FileCreate"
		}
		sysEvent.TargetFilename = ev.Filename
	case EventTypeMem:
		sysEvent.EventID = SysmonCreateRemoteThread
		sysEvent.EventName = "CreateRemoteThread"
	case EventTypePriv:
		sysEvent.EventID = SysmonDriverLoad
		sysEvent.EventName = "DriverLoad"
	default:
		sysEvent.EventID = SysmonProcessAccess
		sysEvent.EventName = "ProcessAccess"
	}

	sysEvent.ProcessGuid = fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		ev.PID, ev.PPID, ev.UID, ev.CgroupID, ev.Timestamp)

	return sysEvent
}
