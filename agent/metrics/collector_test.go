package metrics

import (
	"testing"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
)

func TestCollector_RecordAndSnapshot(t *testing.T) {
	c := NewCollector(nil, nil)
	if c == nil {
		t.Fatal("Expected NewCollector to return non-nil instance")
	}

	ev1 := &agentebpf.Event{
		PID:     1234,
		TypeStr: "EXEC",
		Source:  "sys_tracer",
	}
	ev2 := &agentebpf.Event{
		PID:     1235,
		TypeStr: "OPEN",
		Source:  "lsm_enforcer",
	}

	c.RecordEvent(ev1)
	c.RecordEvent(ev2)
	c.RecordEvent(ev1)

	snap := c.Snapshot()

	if snap.TotalEvents != 3 {
		t.Errorf("Expected TotalEvents to be 3, got %d", snap.TotalEvents)
	}

	if snap.EventTypeCounts["EXEC"] != 2 {
		t.Errorf("Expected EXEC count to be 2, got %d", snap.EventTypeCounts["EXEC"])
	}

	if snap.EventTypeCounts["OPEN"] != 1 {
		t.Errorf("Expected OPEN count to be 1, got %d", snap.EventTypeCounts["OPEN"])
	}

	if snap.EventSourceCounts["sys_tracer"] != 2 {
		t.Errorf("Expected sys_tracer source count to be 2, got %d", snap.EventSourceCounts["sys_tracer"])
	}
}

func TestCollector_NilEventHandling(t *testing.T) {
	c := NewCollector(nil, nil)
	c.RecordEvent(nil)

	snap := c.Snapshot()
	if snap.TotalEvents != 0 {
		t.Errorf("Expected TotalEvents to be 0 for nil event, got %d", snap.TotalEvents)
	}
}
