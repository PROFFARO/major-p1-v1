// Package ebpf provides dynamic compilation and auto-building for eBPF C probes.
package ebpf

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// EnsureBytecodeCompiled checks if the compiled .bpf.o object files in bpfDir exist
// and are up-to-date relative to the .bpf.c source files in bpfSrcDir.
// If any file is missing or outdated, it automatically invokes clang/make to build them.
func EnsureBytecodeCompiled(bpfDir string, autoBuild bool) error {
	if !autoBuild {
		return nil
	}

	bpfSrcDir := filepath.Join(filepath.Dir(bpfDir), "probes")
	if _, err := os.Stat(bpfSrcDir); os.IsNotExist(err) {
		bpfSrcDir = filepath.Dir(bpfDir)
	}

	probes := []string{
		"sys_tracer",
		"lsm_enforcer",
		"net_filter",
		"ssl_tracer",
		"perf_profiler",
		"tetragon_lsm",
	}

	rebuildNeeded := false
	for _, probe := range probes {
		objPath := filepath.Join(bpfDir, probe+".bpf.o")
		srcPath := filepath.Join(bpfSrcDir, probe+".bpf.c")

		objInfo, errObj := os.Stat(objPath)
		srcInfo, errSrc := os.Stat(srcPath)

		if errObj != nil || (errSrc == nil && srcInfo.ModTime().After(objInfo.ModTime())) {
			log.Printf("[compiler] BPF bytecode out of date or missing: %s", objPath)
			rebuildNeeded = true
			break
		}
	}

	if !rebuildNeeded {
		log.Println("[compiler] All eBPF bytecode objects are up-to-date.")
		return nil
	}

	log.Println("[compiler] Rebuilding eBPF probe bytecode via clang/make ...")
	cmd := exec.Command("make", "-C", filepath.Dir(bpfDir))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Printf("[compiler] Makefile execution failed (%v), trying direct clang build ...", err)
		return buildWithClang(bpfDir, bpfSrcDir, probes)
	}

	log.Println("[compiler] ✓ Dynamic eBPF bytecode build completed successfully.")
	return nil
}

func buildWithClang(bpfDir, bpfSrcDir string, probes []string) error {
	incDir := filepath.Join(filepath.Dir(bpfDir), "include")
	for _, probe := range probes {
		srcPath := filepath.Join(bpfSrcDir, probe+".bpf.c")
		objPath := filepath.Join(bpfDir, probe+".bpf.o")

		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			continue
		}

		log.Printf("[compiler] Compiling %s -> %s", srcPath, objPath)
		cmd := exec.Command("clang",
			"-O2",
			"-target", "bpf",
			"-I"+incDir,
			"-c", srcPath,
			"-o", objPath,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("clang build failed for %s: %w", probe, err)
		}
	}
	return nil
}
