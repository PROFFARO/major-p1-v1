// Package ebpf provides types and utilities for interacting with
// the eBPF kernel probes (sys_tracer, lsm_enforcer, net_filter).
package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────
// Constants — must mirror bpf/include/common.h exactly
// ─────────────────────────────────────────────────────────────

const (
	TaskCommLen = 16
	MaxPathLen  = 256
)

// EventType classifies the telemetry event category.
type EventType uint32

const (
	EventTypeUnknown EventType = 0
	EventTypeSyscall EventType = 1
	EventTypeExec    EventType = 2
	EventTypeExit    EventType = 3
	EventTypeFile    EventType = 4
	EventTypeNet     EventType = 5
	EventTypePriv    EventType = 6
	EventTypeMem     EventType = 7
)

// String returns a human-readable label for the event type.
func (t EventType) String() string {
	switch t {
	case EventTypeSyscall:
		return "SYSCALL"
	case EventTypeExec:
		return "EXEC"
	case EventTypeExit:
		return "EXIT"
	case EventTypeFile:
		return "FILE"
	case EventTypeNet:
		return "NET"
	case EventTypePriv:
		return "PRIV"
	case EventTypeMem:
		return "MEM"
	default:
		return "UNKNOWN"
	}
}

// FileOp classifies the file operation type.
type FileOp uint16

const (
	FileOpRead   FileOp = 1
	FileOpWrite  FileOp = 2
	FileOpOpen   FileOp = 3
	FileOpCreate FileOp = 4
	FileOpDelete FileOp = 5
	FileOpRename FileOp = 6
)

// Action constants for block rules.
const (
	ActionAllow uint32 = 0
	ActionBlock uint32 = 1
	ActionLog   uint32 = 2
)

// ─────────────────────────────────────────────────────────────
// Event — Go mirror of C struct event_t (bpf/include/common.h)
//
// IMPORTANT: Field order, sizes, and padding MUST match the
// C struct exactly. The BPF ring buffer delivers raw bytes
// that we interpret directly with unsafe pointer casts.
// ─────────────────────────────────────────────────────────────

// RawEvent is the exact binary layout of C struct event_t.
// We use encoding/binary.Read to deserialize from the ring buffer,
// which handles the byte-by-byte layout without Go struct padding issues.
//
// C struct layout (x86_64, naturally aligned):
//   offset  0: u64 timestamp_ns
//   offset  8: u32 pid
//   offset 12: u32 tgid
//   offset 16: u32 ppid
//   offset 20: u32 uid
//   offset 24: u32 gid
//   offset 28: u32 cgroup_id
//   offset 32: u32 event_type
//   offset 36: [4 bytes padding for u64 alignment]
//   offset 40: u64 syscall_id
//   offset 48: s64 retval
//   offset 56: char comm[16]
//   offset 72: char filename[256]
//   offset 328: u32 src_ip
//   offset 332: u32 dst_ip
//   offset 336: u16 src_port
//   offset 338: u16 dst_port
//   offset 340: u16 protocol
//   offset 342: u16 file_op
//   offset 344: u32 flags
//   Total = 348 bytes
//
// Wait — let's recalculate properly:
//   7 × u32 = 28 bytes (offset 0-27), then event_type at 28 is u32 → offset 32.
//   But event_type is the 7th u32. Let me count:
//     timestamp_ns(8) + pid(4) + tgid(4) + ppid(4) + uid(4) + gid(4) + cgroup_id(4) + event_type(4) = 36
//   padding to align syscall_id(u64) = 4 bytes → offset 40
//   syscall_id(8) = offset 48, retval(8) = offset 56
//   comm(16) = offset 72, filename(256) = offset 328
//   src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + protocol(2) + file_op(2) + flags(4) = 20
//   Total = 328 + 20 = 348 bytes
//   But C pads struct size to alignment of largest member (8) → 352 bytes

// RawEventSize is the C struct size including trailing padding.
const RawEventSize = 352

func parseRawBytes(data []byte) (
	timestampNs uint64, pid, tgid, ppid, uid, gid, cgroupID, eventType uint32,
	syscallID uint64, retval int64,
	comm [TaskCommLen]byte, filename [MaxPathLen]byte,
	srcIP, dstIP uint32, srcPort, dstPort, protocol, fileOp uint16, flags uint32,
) {
	bo := binary.LittleEndian
	timestampNs = bo.Uint64(data[0:8])
	pid = bo.Uint32(data[8:12])
	tgid = bo.Uint32(data[12:16])
	ppid = bo.Uint32(data[16:20])
	uid = bo.Uint32(data[20:24])
	gid = bo.Uint32(data[24:28])
	cgroupID = bo.Uint32(data[28:32])
	eventType = bo.Uint32(data[32:36])
	// 4 bytes padding at [36:40]
	syscallID = bo.Uint64(data[40:48])
	retval = int64(bo.Uint64(data[48:56]))
	copy(comm[:], data[56:72])
	copy(filename[:], data[72:328])
	srcIP = bo.Uint32(data[328:332])
	dstIP = bo.Uint32(data[332:336])
	srcPort = bo.Uint16(data[336:338])
	dstPort = bo.Uint16(data[338:340])
	protocol = bo.Uint16(data[340:342])
	fileOp = bo.Uint16(data[342:344])
	flags = bo.Uint32(data[344:348])
	return
}

// ─────────────────────────────────────────────────────────────
// Event — rich, deserialized Go representation for user-space
// ─────────────────────────────────────────────────────────────

// Event is the user-friendly representation of a kernel telemetry event.
type Event struct {
	Timestamp time.Duration `json:"timestamp_ns"`
	PID       uint32        `json:"pid"`
	TGID      uint32        `json:"tgid"`
	PPID      uint32        `json:"ppid"`
	UID       uint32        `json:"uid"`
	GID       uint32        `json:"gid"`
	CgroupID  uint32        `json:"cgroup_id"`
	Type      EventType     `json:"event_type"`
	TypeStr   string        `json:"event_type_str"`
	SyscallID uint64        `json:"syscall_id"`
	RetVal    int64         `json:"retval"`
	Comm      string        `json:"comm"`
	Filename  string        `json:"filename"`
	SrcIP     string        `json:"src_ip,omitempty"`
	DstIP     string        `json:"dst_ip,omitempty"`
	SrcPort   uint16        `json:"src_port,omitempty"`
	DstPort   uint16        `json:"dst_port,omitempty"`
	Protocol  uint16        `json:"protocol,omitempty"`
	FileOp    FileOp        `json:"file_op,omitempty"`
	Flags      uint32    `json:"flags,omitempty"`
	Source     string    `json:"source"` // "sys_tracer", "lsm_enforcer", or "net_filter"

	// ── Process Context Enrichment (populated by agent/context) ──
	ExePath    string `json:"exe_path,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	ParentComm string `json:"parent_comm,omitempty"`
	ExeHash    string `json:"exe_hash,omitempty"` // SHA256 of binary
}

// ParseRawEvent converts a raw byte slice from the BPF ring buffer
// into a rich Event struct. The source parameter identifies which
// probe generated the event.
func ParseRawEvent(data []byte, source string) (*Event, error) {
	if len(data) < 348 {
		return nil, fmt.Errorf("event data too short: got %d, want >= 348",
			len(data))
	}

	timestampNs, pid, tgid, ppid, uid, gid, cgroupID, eventType,
		syscallID, retval, comm, filename,
		srcIP, dstIP, srcPort, dstPort, protocol, fileOp, flags := parseRawBytes(data)

	ev := &Event{
		Timestamp: time.Duration(timestampNs) * time.Nanosecond,
		PID:       pid,
		TGID:      tgid,
		PPID:      ppid,
		UID:       uid,
		GID:       gid,
		CgroupID:  cgroupID,
		Type:      EventType(eventType),
		TypeStr:   EventType(eventType).String(),
		SyscallID: syscallID,
		RetVal:    retval,
		Comm:      nullTermStr(comm[:]),
		Filename:  nullTermStr(filename[:]),
		SrcPort:   ntohs(srcPort),
		DstPort:   ntohs(dstPort),
		Protocol:  protocol,
		FileOp:    FileOp(fileOp),
		Flags:     flags,
		Source:    source,
	}

	// Convert raw IPv4 u32 to dotted-decimal string
	if srcIP != 0 {
		ev.SrcIP = ipFromU32(srcIP)
	}
	if dstIP != 0 {
		ev.DstIP = ipFromU32(dstIP)
	}

	return ev, nil
}

// ─────────────────────────────────────────────────────────────
// BlockRule — Go mirror of C struct block_rule_t
// ─────────────────────────────────────────────────────────────

// BlockRule is the Go representation of a BPF hash map block rule.
type BlockRule struct {
	RuleType    uint32    `json:"rule_type"`
	TargetPID   uint32    `json:"target_pid"`
	TargetIP    uint32    `json:"target_ip"`
	Action      uint32    `json:"action"`
	CreationTS  uint64    `json:"creation_ts"`
	HitCount    uint64    `json:"hit_count"`
	Description [64]byte  `json:"-"`
	Desc        string    `json:"description"` // human-readable, populated in Go
}

// ─────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────

// nullTermStr extracts a Go string from a null-terminated C byte buffer.
func nullTermStr(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return strings.TrimSpace(string(b[:n]))
}

// ipFromU32 converts a network-order uint32 to a dotted-decimal IP string.
func ipFromU32(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

// ntohs converts a network-order uint16 to host order.
func ntohs(n uint16) uint16 {
	return (n>>8)&0xFF | (n&0xFF)<<8
}

// IPToU32 converts a dotted-decimal IP string to a network-order uint32
// for use as a BPF hash map key.
func IPToU32(ip string) (uint32, error) {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ip)
	}
	return binary.LittleEndian.Uint32(parsed), nil
}
