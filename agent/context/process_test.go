package context

import (
	"os"
	"testing"

	agentebpf "github.com/proffaro/ebpf-ml-agent/ebpf"
)

func TestNewProcessResolver(t *testing.T) {
	pr := NewProcessResolver()
	if pr == nil {
		t.Fatal("Expected NewProcessResolver to return non-nil instance")
	}
	if pr.cache == nil || pr.hashCache == nil {
		t.Fatal("Expected caches to be initialized")
	}
}

func TestProcessResolver_Enrich_CurrentPID(t *testing.T) {
	pr := NewProcessResolver()
	pid := uint32(os.Getpid())
	ppid := uint32(os.Getppid())

	ev := &agentebpf.Event{
		PID:  pid,
		PPID: ppid,
		Comm: "test_process",
	}

	pr.Enrich(ev)

	if ev.ExePath == "" {
		t.Errorf("Expected ExePath to be non-empty for PID %d", pid)
	}
	if ev.Cmdline == "" {
		t.Errorf("Expected Cmdline to be non-empty for PID %d", pid)
	}
}

func TestProcessResolver_GetProcessTree(t *testing.T) {
	pr := NewProcessResolver()
	pid := uint32(os.Getpid())

	tree := pr.GetProcessTree(pid)
	if tree == nil {
		t.Fatal("Expected process tree to be returned")
	}

	chain, ok := tree["process_chain"].([]map[string]string)
	if !ok {
		t.Fatal("Expected process_chain to be []map[string]string")
	}

	if len(chain) == 0 {
		t.Fatal("Expected process chain to contain at least 1 node")
	}
}

func TestProcessResolver_CacheHit(t *testing.T) {
	pr := NewProcessResolver()
	pid := uint32(os.Getpid())

	ev1 := &agentebpf.Event{PID: pid, PPID: uint32(os.Getppid())}
	pr.Enrich(ev1)
	exe1 := ev1.ExePath

	ev2 := &agentebpf.Event{PID: pid, PPID: uint32(os.Getppid())}
	pr.Enrich(ev2)
	exe2 := ev2.ExePath

	if exe1 != exe2 {
		t.Errorf("Expected cached ExePath %q to match %q", exe1, exe2)
	}
}
