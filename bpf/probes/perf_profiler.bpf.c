// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * perf_profiler.bpf.c — Kepler & Parca-style Continuous Hardware & CPU Profiling Probe
 *
 * Attaches to hardware performance events (CPU cycles, instructions, cache misses)
 * to stream hardware-level telemetry and detect anomaly patterns like crypto-mining,
 * high-entropy obfuscated shellcode execution, or CPU exhaustion attacks.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../include/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Ring buffer for hardware performance counter telemetry events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8 MB
} perf_events SEC(".maps");

// Per-process CPU cycles aggregator map
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);   // PID
    __type(value, u64); // Cycle count
} proc_cpu_cycles SEC(".maps");

SEC("perf_event")
int on_cpu_cycle(struct bpf_perf_event_data *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (pid == 0)
        return 0; // Skip idle thread

    // Aggregate CPU sample counter
    u64 *val = bpf_map_lookup_elem(&proc_cpu_cycles, &pid);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        u64 init = 1;
        bpf_map_update_elem(&proc_cpu_cycles, &pid, &init, BPF_ANY);
    }

    // Periodically emit telemetry event when threshold sample count reached
    if (val && (*val % 1000 == 0)) {
        struct event_t *out;
        out = bpf_ringbuf_reserve(&perf_events, sizeof(*out), 0);
        if (!out) return 0;

        __builtin_memset(out, 0, sizeof(*out));
        out->timestamp_ns = bpf_ktime_get_ns();
        out->pid = pid;
        out->tgid = (u32)pid_tgid;
        out->uid = bpf_get_current_uid_gid();
        out->gid = bpf_get_current_uid_gid() >> 32;
        out->event_type = EVENT_TYPE_MEM;
        out->syscall_id = *val; // Store sample cycle count in syscall_id field
        out->flags = 0xCEF0;    // CPU perf sample marker

        bpf_get_current_comm(&out->comm, sizeof(out->comm));
        bpf_ringbuf_submit(out, 0);
    }

    return 0;
}
