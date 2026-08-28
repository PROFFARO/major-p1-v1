// Package ebpf provides native Falco event classification and behavioral tag mapping.
package ebpf

import (
	"strings"
	"time"
)

// FalcoPriority defines severity levels for Falco events.
type FalcoPriority string

const (
	FalcoPriorityEmergency FalcoPriority = "EMERGENCY"
	FalcoPriorityAlert     FalcoPriority = "ALERT"
	FalcoPriorityCritical  FalcoPriority = "CRITICAL"
	FalcoPriorityError     FalcoPriority = "ERROR"
	FalcoPriorityWarning   FalcoPriority = "WARNING"
	FalcoPriorityNotice    FalcoPriority = "NOTICE"
	FalcoPriorityInfo      FalcoPriority = "INFO"
	FalcoPriorityDebug     FalcoPriority = "DEBUG"
)

// FalcoEvent represents an enriched behavioral telemetry event format.
type FalcoEvent struct {
	Timestamp   time.Time         `json:"output_fields.evt.time"`
	Rule        string            `json:"rule"`
	Priority    FalcoPriority     `json:"priority"`
	Output      string            `json:"output"`
	Source      string            `json:"source"`
	Tags        []string          `json:"tags"`
	PID         uint32            `json:"output_fields.proc.pid"`
	PPID        uint32            `json:"output_fields.proc.ppid"`
	Comm        string            `json:"output_fields.proc.name"`
	Exe         string            `json:"output_fields.proc.exe"`
	Cmdline     string            `json:"output_fields.proc.cmdline"`
	ContainerID string            `json:"output_fields.container.id"`
	ExtraFields map[string]interface{} `json:"output_fields"`
}

// ConvertToFalcoEvent transforms a raw system Event into a normalized Falco telemetry structure.
func ConvertToFalcoEvent(ev *Event, ruleName string, priority FalcoPriority, output string, tags []string) *FalcoEvent {
	if ev == nil {
		return nil
	}

	return &FalcoEvent{
		Timestamp:   time.Now(),
		Rule:        ruleName,
		Priority:    priority,
		Output:      output,
		Source:      "syscall",
		Tags:        tags,
		PID:         ev.PID,
		PPID:        ev.PPID,
		Comm:        ev.Comm,
		Exe:         ev.ExePath,
		Cmdline:     ev.Cmdline,
		ContainerID: ev.ContainerID,
		ExtraFields: map[string]interface{}{
			"evt.type":        ev.TypeStr,
			"fd.name":         ev.Filename,
			"user.uid":        ev.UID,
			"proc.pname":      ev.ParentComm,
			"sys.syscall_id": ev.SyscallID,
		},
	}
}

// HasTag returns true if the Falco event contains a specific MITRE ATT&CK tag.
func (f *FalcoEvent) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}
