// SPDX-License-Identifier: GPL-2.0-only
/* Copyright Cilium Tetragon Integration for Observability Engine */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "common.h"
#include "tetragon_types.h"

char _license[] SEC("license") = "GPL";

/* Tetragon LSM Event Ring Buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tetragon_events SEC(".maps");

/* Real-time Tetragon Enforcement Map indexed by PID */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct tetragon_enforcer_data);
} tetragon_enforce_map SEC(".maps");

/*
 * SEC("lsm/bprm_check_security")
 * Tetragon process execution LSM check.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(tetragon_bprm_check, struct linux_binprm *bprm)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct tetragon_enforcer_data *enforcer = bpf_map_lookup_elem(&tetragon_enforce_map, &pid);
    if (enforcer && enforcer->error != 0) {
        if (enforcer->signal > 0) {
            bpf_send_signal(enforcer->signal);
        }
        return enforcer->error;
    }

    struct event_t *ev = bpf_ringbuf_reserve(&tetragon_events, sizeof(struct event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = pid;
    ev->tgid = (u32)pid_tgid;
    ev->uid = bpf_get_current_uid_gid();
    ev->gid = bpf_get_current_uid_gid() >> 32;
    ev->event_type = EVENT_TYPE_EXEC;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/*
 * SEC("lsm/task_fix_setuid")
 * Tetragon privilege escalation LSM audit probe.
 */
SEC("lsm/task_fix_setuid")
int BPF_PROG(tetragon_task_fix_setuid, struct cred *new_cred, const struct cred *old_cred, int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct event_t *ev = bpf_ringbuf_reserve(&tetragon_events, sizeof(struct event_t), 0);
    if (!ev)
        return 0;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->pid = pid;
    ev->tgid = (u32)pid_tgid;
    ev->uid = bpf_get_current_uid_gid();
    ev->event_type = EVENT_TYPE_PRIV;
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
