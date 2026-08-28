package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestEventType_String(t *testing.T) {
	tests := []struct {
		eventType EventType
		expected  string
	}{
		{EventTypeSyscall, "SYSCALL"},
		{EventTypeExec, "EXEC"},
		{EventTypeExit, "EXIT"},
		{EventTypeFile, "FILE"},
		{EventTypeNet, "NET"},
		{EventTypePriv, "PRIV"},
		{EventTypeMem, "MEM"},
		{EventTypeUnknown, "UNKNOWN"},
	}

	for _, tt := range tests {
		if tt.eventType.String() != tt.expected {
			t.Errorf("Expected String() for %d to be %q, got %q", tt.eventType, tt.expected, tt.eventType.String())
		}
	}
}

func TestParseRawEvent_ValidData(t *testing.T) {
	data := make([]byte, 352)
	bo := binary.LittleEndian

	// Fill sample binary data
	bo.PutUint64(data[0:8], 1000000000) // timestamp
	bo.PutUint32(data[8:12], 1234)       // pid
	bo.PutUint32(data[12:16], 1234)      // tgid
	bo.PutUint32(data[16:20], 1)         // ppid
	bo.PutUint32(data[20:24], 1000)      // uid
	bo.PutUint32(data[24:28], 1000)      // gid
	bo.PutUint32(data[28:32], 100)       // cgroup_id
	bo.PutUint32(data[32:36], uint32(EventTypeExec)) // event_type
	bo.PutUint64(data[40:48], 59)        // syscall_id (execve)
	bo.PutUint64(data[48:56], 0)         // retval

	copy(data[56:72], "test_comm\x00")
	copy(data[72:328], "/usr/bin/test_app\x00")

	ev, err := ParseRawEvent(data, "sys_tracer")
	if err != nil {
		t.Fatalf("Unexpected error parsing raw event: %v", err)
	}

	if ev.PID != 1234 {
		t.Errorf("Expected PID 1234, got %d", ev.PID)
	}

	if ev.Comm != "test_comm" {
		t.Errorf("Expected Comm 'test_comm', got %q", ev.Comm)
	}

	if ev.Filename != "/usr/bin/test_app" {
		t.Errorf("Expected Filename '/usr/bin/test_app', got %q", ev.Filename)
	}

	if ev.TypeStr != "EXEC" {
		t.Errorf("Expected TypeStr 'EXEC', got %q", ev.TypeStr)
	}
}

func TestParseRawEvent_ShortData(t *testing.T) {
	shortData := make([]byte, 100)
	_, err := ParseRawEvent(shortData, "sys_tracer")
	if err == nil {
		t.Errorf("Expected error for short binary data, got nil")
	}
}

func TestIPToU32AndIPFromU32(t *testing.T) {
	ipStr := "192.168.1.100"
	u32Val, err := IPToU32(ipStr)
	if err != nil {
		t.Fatalf("Unexpected error converting IP to uint32: %v", err)
	}

	resStr := ipFromU32(u32Val)
	if resStr != ipStr {
		t.Errorf("Expected roundtrip IP %q, got %q", ipStr, resStr)
	}
}
