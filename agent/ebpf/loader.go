package ebpf

import (
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// ProbeSet holds all loaded eBPF programs, maps, and kernel attachments.
// Call Close() to detach everything and release kernel resources.
type ProbeSet struct {
	// Collections hold the loaded eBPF programs and maps per probe file
	SysTracer    *ebpf.Collection
	LSMEnforcer  *ebpf.Collection
	TetragonLSM  *ebpf.Collection
	NetFilter    *ebpf.Collection
	SSLTracer    *ebpf.Collection
	PerfProfiler *ebpf.Collection

	// Kernel attachment links (must be closed to detach probes)
	links []link.Link

	// ── Ring Buffer Maps (read by ringbuf.go) ──
	SysTracerEvents *ebpf.Map // "events"          from sys_tracer.bpf.o
	LSMEvents       *ebpf.Map // "lsm_events"      from lsm_enforcer.bpf.o
	TetragonEvents  *ebpf.Map // "tetragon_events" from tetragon_lsm.bpf.o
	NetEvents       *ebpf.Map // "net_events"       from net_filter.bpf.o
	SSLEvents       *ebpf.Map // "ssl_events"       from ssl_tracer.bpf.o
	PerfEvents      *ebpf.Map // "perf_events"      from perf_profiler.bpf.o

	// ── Telemetry Counter Maps (read-only for monitoring) ──
	PktCounter  *ebpf.Map // "pkt_counter"  from net_filter.bpf.o
	DNSCounter  *ebpf.Map // "dns_counter"  from net_filter.bpf.o
}

// LoadAndAttach loads the compiled eBPF object files and attaches
// every program to its corresponding kernel hook. Returns a ProbeSet
// that provides access to all telemetry maps and must be Close()d on shutdown.
//
// bpfDir is the directory containing the compiled .bpf.o files
// (e.g. "../bpf/probes").
func LoadAndAttach(bpfDir string) (*ProbeSet, error) {
	// Remove the memlock rlimit so the kernel allows BPF map allocation.
	// On kernels 5.11+ this is a no-op, but it's safe to call unconditionally.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	ps := &ProbeSet{}

	// ────────────────────────────────────────────────────
	// 1. Load sys_tracer.bpf.o
	// ────────────────────────────────────────────────────
	log.Println("[loader] Loading sys_tracer.bpf.o ...")
	sysSpec, err := ebpf.LoadCollectionSpec(bpfDir + "/sys_tracer.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("loading sys_tracer spec: %w", err)
	}
	ps.SysTracer, err = ebpf.NewCollection(sysSpec)
	if err != nil {
		return nil, fmt.Errorf("creating sys_tracer collection: %w", err)
	}

	// Grab the ring buffer map
	ps.SysTracerEvents = ps.SysTracer.Maps["events"]
	if ps.SysTracerEvents == nil {
		return nil, fmt.Errorf("sys_tracer: 'events' map not found")
	}

	// Attach sys_tracer programs to kernel hooks
	if err := ps.attachSysTracer(); err != nil {
		ps.Close()
		return nil, fmt.Errorf("attaching sys_tracer: %w", err)
	}
	log.Println("[loader] sys_tracer attached successfully")

	// ────────────────────────────────────────────────────
	// 2. Load lsm_enforcer.bpf.o
	// ────────────────────────────────────────────────────
	log.Println("[loader] Loading lsm_enforcer.bpf.o ...")
	lsmSpec, err := ebpf.LoadCollectionSpec(bpfDir + "/lsm_enforcer.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("loading lsm_enforcer spec: %w", err)
	}
	ps.LSMEnforcer, err = ebpf.NewCollection(lsmSpec)
	if err != nil {
		return nil, fmt.Errorf("creating lsm_enforcer collection: %w", err)
	}

	// Grab maps
	ps.LSMEvents = ps.LSMEnforcer.Maps["lsm_events"]
	if ps.LSMEvents == nil {
		return nil, fmt.Errorf("lsm_enforcer: 'lsm_events' map not found")
	}

	// Attach LSM programs
	if err := ps.attachLSMEnforcer(); err != nil {
		ps.Close()
		return nil, fmt.Errorf("attaching lsm_enforcer: %w", err)
	}
	log.Println("[loader] lsm_enforcer attached successfully")

	// ────────────────────────────────────────────────────
	// 3. Load net_filter.bpf.o (optional)
	// ────────────────────────────────────────────────────
	log.Println("[loader] Loading net_filter.bpf.o ...")
	netPath := bpfDir + "/net_filter.bpf.o"
	if _, err := os.Stat(netPath); err == nil {
		netSpec, err := ebpf.LoadCollectionSpec(netPath)
		if err != nil {
			log.Printf("[loader] WARNING: net_filter spec load failed: %v", err)
		} else {
			ps.NetFilter, err = ebpf.NewCollection(netSpec)
			if err != nil {
				log.Printf("[loader] WARNING: net_filter collection failed: %v", err)
			} else {
				ps.NetEvents = ps.NetFilter.Maps["net_events"]
				ps.PktCounter = ps.NetFilter.Maps["pkt_counter"]
				ps.DNSCounter = ps.NetFilter.Maps["dns_counter"]
				log.Println("[loader] net_filter loaded (TC attach requires separate step)")
			}
		}
	}

	// ────────────────────────────────────────────────────
	// 4. Load ssl_tracer.bpf.o (optional eCapture TLS probe)
	// ────────────────────────────────────────────────────
	sslPath := bpfDir + "/ssl_tracer.bpf.o"
	if _, err := os.Stat(sslPath); err == nil {
		sslSpec, err := ebpf.LoadCollectionSpec(sslPath)
		if err == nil {
			ps.SSLTracer, err = ebpf.NewCollection(sslSpec)
			if err == nil {
				ps.SSLEvents = ps.SSLTracer.Maps["ssl_events"]
				log.Println("[loader] ssl_tracer probe loaded")
			}
		}
	}

	// ────────────────────────────────────────────────────
	// 5. Load perf_profiler.bpf.o (optional Kepler/Parca probe)
	// ────────────────────────────────────────────────────
	perfPath := bpfDir + "/perf_profiler.bpf.o"
	if _, err := os.Stat(perfPath); err == nil {
		perfSpec, err := ebpf.LoadCollectionSpec(perfPath)
		if err == nil {
			ps.PerfProfiler, err = ebpf.NewCollection(perfSpec)
			if err == nil {
				ps.PerfEvents = ps.PerfProfiler.Maps["perf_events"]
				log.Println("[loader] perf_profiler probe loaded")
			}
		}
	}

	// ────────────────────────────────────────────────────
	// 6. Load tetragon_lsm.bpf.o (Cilium Tetragon probe)
	// ────────────────────────────────────────────────────
	tetraPath := bpfDir + "/tetragon_lsm.bpf.o"
	if _, err := os.Stat(tetraPath); err == nil {
		tetraSpec, err := ebpf.LoadCollectionSpec(tetraPath)
		if err == nil {
			ps.TetragonLSM, err = ebpf.NewCollection(tetraSpec)
			if err == nil {
				ps.TetragonEvents = ps.TetragonLSM.Maps["tetragon_events"]
				log.Println("[loader] tetragon_lsm probe loaded")
			}
		}
	}

	return ps, nil
}

// ────────────────────────────────────────────────────────────────
// Attachment helpers — one per probe file
// ────────────────────────────────────────────────────────────────

// attachSysTracer attaches all programs from sys_tracer.bpf.o.
func (ps *ProbeSet) attachSysTracer() error {
	coll := ps.SysTracer

	// ── Tracepoints ──
	tpProgs := map[string][2]string{
		"tp_sys_enter":  {"raw_syscalls", "sys_enter"},
		"tp_sys_exit":   {"raw_syscalls", "sys_exit"},
		"tp_sched_exec": {"sched", "sched_process_exec"},
		"tp_sched_exit": {"sched", "sched_process_exit"},
		"tp_sched_fork": {"sched", "sched_process_fork"},
	}
	for progName, tp := range tpProgs {
		prog := coll.Programs[progName]
		if prog == nil {
			log.Printf("[loader] WARN: sys_tracer program %q not found, skipping", progName)
			continue
		}
		l, err := link.Tracepoint(tp[0], tp[1], prog, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s/%s: %w", tp[0], tp[1], err)
		}
		ps.links = append(ps.links, l)
		log.Printf("[loader]   ✓ tp/%s/%s", tp[0], tp[1])
	}

	// ── Kprobes ──
	kprobeProgs := map[string]string{
		"kp_setuid":       "__x64_sys_setuid",
		"kp_setgid":       "__x64_sys_setgid",
		"kp_setreuid":     "__x64_sys_setreuid",
		"kp_setregid":     "__x64_sys_setregid",
		"kp_setresuid":    "__x64_sys_setresuid",
		"kp_setresgid":    "__x64_sys_setresgid",
		"kp_capset":       "__x64_sys_capset",
		"kp_ptrace":       "__x64_sys_ptrace",
		"kp_vm_writev":    "__x64_sys_process_vm_writev",
		"kp_vm_readv":     "__x64_sys_process_vm_readv",
		"kp_mprotect":     "__x64_sys_mprotect",
		"kp_mmap":         "__x64_sys_mmap",
		"kp_memfd_create": "__x64_sys_memfd_create",
		"kp_init_module":  "__x64_sys_init_module",
		"kp_finit_module": "__x64_sys_finit_module",
		"kp_delete_module":"__x64_sys_delete_module",
		"kp_setns":        "__x64_sys_setns",
		"kp_unshare":      "__x64_sys_unshare",
		"kp_pivot_root":   "__x64_sys_pivot_root",
		"kp_mount":        "__x64_sys_mount",
		"kp_umount":       "__x64_sys_umount",
		"kp_chroot":       "__x64_sys_chroot",
		"kp_unlinkat":     "__x64_sys_unlinkat",
		"kp_renameat2":    "__x64_sys_renameat2",
		"kp_truncate":     "__x64_sys_truncate",
		"kp_fchmodat":     "__x64_sys_fchmodat",
		"kp_fchownat":     "__x64_sys_fchownat",
	}
	for progName, symbol := range kprobeProgs {
		prog := coll.Programs[progName]
		if prog == nil {
			log.Printf("[loader] WARN: sys_tracer program %q not found, skipping", progName)
			continue
		}
		l, err := link.Kprobe(symbol, prog, nil)
		if err != nil {
			// Some kprobes may not exist on all kernels; warn and continue
			log.Printf("[loader] WARN: kprobe %s failed: %v", symbol, err)
			continue
		}
		ps.links = append(ps.links, l)
		log.Printf("[loader]   ✓ kprobe/%s", symbol)
	}

	return nil
}

// attachLSMEnforcer attaches all LSM programs from lsm_enforcer.bpf.o.
func (ps *ProbeSet) attachLSMEnforcer() error {
	coll := ps.LSMEnforcer

	// LSM programs are auto-attached by section name when using cilium/ebpf.
	// The SEC("lsm/xxx") programs are of type BPF_PROG_TYPE_LSM and
	// attach_type BPF_LSM_MAC. We iterate and attach each one.
	lsmProgs := []string{
		"lsm_bprm_check",
		"lsm_file_open",
		"lsm_file_permission",
		"lsm_path_unlink",
		"lsm_path_rename",
		"lsm_cred_prepare",
		"lsm_task_fix_setuid",
		"lsm_socket_connect",
		"lsm_socket_bind",
		"lsm_socket_accept",
		"lsm_socket_sendmsg",
		"lsm_file_mprotect",
		"lsm_kernel_read_file",
	}

	for _, progName := range lsmProgs {
		prog := coll.Programs[progName]
		if prog == nil {
			log.Printf("[loader] WARN: lsm program %q not found, skipping", progName)
			continue
		}

		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			log.Printf("[loader] WARN: LSM attach %q failed: %v", progName, err)
			continue
		}
		ps.links = append(ps.links, l)
		log.Printf("[loader]   ✓ lsm/%s", progName)
	}

	return nil
}

// Close detaches all kernel hooks and frees all eBPF resources.
func (ps *ProbeSet) Close() {
	log.Println("[loader] Detaching and closing all eBPF resources ...")

	// Close all kernel attachment links
	for _, l := range ps.links {
		if l != nil {
			l.Close()
		}
	}

	// Close collections (frees programs and maps)
	if ps.SysTracer != nil {
		ps.SysTracer.Close()
	}
	if ps.LSMEnforcer != nil {
		ps.LSMEnforcer.Close()
	}
	if ps.NetFilter != nil {
		ps.NetFilter.Close()
	}
	if ps.SSLTracer != nil {
		ps.SSLTracer.Close()
	}
	if ps.PerfProfiler != nil {
		ps.PerfProfiler.Close()
	}
	if ps.TetragonLSM != nil {
		ps.TetragonLSM.Close()
	}

	log.Println("[loader] All eBPF resources released.")
}
