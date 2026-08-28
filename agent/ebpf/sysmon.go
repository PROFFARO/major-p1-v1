// Package ebpf provides Sysmon for Linux Event ID translation and Windows-like security log generation.
package ebpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// SysmonEventID mirror of enum sysmon_event_id (sysmon_events.h)
type SysmonEventID uint32

const (
	SysmonProcessCreate       SysmonEventID = 1
	SysmonFileTimeChange      SysmonEventID = 2
	SysmonNetworkConnect      SysmonEventID = 3
	SysmonServiceStateChange  SysmonEventID = 4
	SysmonProcessTerminate    SysmonEventID = 5
	SysmonDriverLoad          SysmonEventID = 6
	SysmonImageLoad           SysmonEventID = 7
	SysmonCreateRemoteThread SysmonEventID = 8
	SysmonRawAccessRead       SysmonEventID = 9
	SysmonProcessAccess       SysmonEventID = 10
	SysmonFileCreate          SysmonEventID = 11
	SysmonRegCreateDelete     SysmonEventID = 12
	SysmonRegSetValue         SysmonEventID = 13
	SysmonRegRename           SysmonEventID = 14
	SysmonCreateStreamHash    SysmonEventID = 15
	SysmonServiceConfigChange SysmonEventID = 16
	SysmonPipeCreate          SysmonEventID = 17
	SysmonPipeConnect         SysmonEventID = 18
	SysmonWmiEvent            SysmonEventID = 19
	SysmonDnsQuery            SysmonEventID = 22
	SysmonFileDelete          SysmonEventID = 23
)

func (e SysmonEventID) String() string {
	switch e {
	case SysmonProcessCreate:
		return "ProcessCreate"
	case SysmonFileTimeChange:
		return "FileTimeChange"
	case SysmonNetworkConnect:
		return "NetworkConnect"
	case SysmonProcessTerminate:
		return "ProcessTerminate"
	case SysmonDriverLoad:
		return "DriverLoad"
	case SysmonImageLoad:
		return "ImageLoad"
	case SysmonCreateRemoteThread:
		return "CreateRemoteThread"
	case SysmonFileCreate:
		return "FileCreate"
	case SysmonDnsQuery:
		return "DnsQuery"
	case SysmonFileDelete:
		return "FileDelete"
	default:
		return fmt.Sprintf("SysmonEvent_%d", e)
	}
}

// SysmonEventHeader mirror of struct sysmon_event_header_t
type SysmonEventHeader struct {
	EventID         SysmonEventID `json:"event_id"`
	EventName       string        `json:"event_name"`
	TimestampNs     time.Duration `json:"timestamp_ns"`
	ProcessID       uint32        `json:"process_id"`
	ParentProcessID uint32        `json:"parent_process_id"`
	UserID          uint32        `json:"user_id"`
	ImagePath       string        `json:"image_path"`
	CommandLine     string        `json:"command_line"`
}

// TranslateSysmonEvent converts a raw byte slice into a Sysmon security event log structure.
func TranslateSysmonEvent(data []byte) (*SysmonEventHeader, error) {
	if len(data) < 532 {
		return nil, fmt.Errorf("sysmon event data too short: %d bytes", len(data))
	}

	bo := binary.LittleEndian
	eventID := bo.Uint32(data[0:4])
	tsNs := bo.Uint64(data[4:12])
	pid := bo.Uint32(data[12:16])
	ppid := bo.Uint32(data[16:20])
	uid := bo.Uint32(data[20:24])

	imgPath := strings.TrimRight(string(data[24:280]), "\x00")
	cmdLine := strings.TrimRight(string(data[280:536]), "\x00")

	sysIDObj := SysmonEventID(eventID)

	return &SysmonEventHeader{
		EventID:         sysIDObj,
		EventName:       sysIDObj.String(),
		TimestampNs:     time.Duration(tsNs) * time.Nanosecond,
		ProcessID:       pid,
		ParentProcessID: ppid,
		UserID:          uid,
		ImagePath:       strings.TrimSpace(imgPath),
		CommandLine:     strings.TrimSpace(cmdLine),
	}, nil
}
