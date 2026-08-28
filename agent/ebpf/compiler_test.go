package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureBytecodeCompiled_UpToDate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "bpf_build_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	probes := []string{
		"sys_tracer",
		"lsm_enforcer",
		"net_filter",
		"ssl_tracer",
		"perf_profiler",
		"tetragon_lsm",
	}

	for _, p := range probes {
		objPath := filepath.Join(tempDir, p+".bpf.o")
		if err := os.WriteFile(objPath, []byte("fake bpf object"), 0644); err != nil {
			t.Fatalf("Failed to write fake object: %v", err)
		}
	}

	err = EnsureBytecodeCompiled(tempDir, true)
	if err != nil {
		t.Errorf("Expected EnsureBytecodeCompiled to succeed when objects exist, got %v", err)
	}
}
