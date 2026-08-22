// SPDX-License-Identifier: GPL-2.0
// sys_tracer.bpf.c — Exhaustive system call, process, privilege,
//   memory-injection, and container-escape tracing via eBPF.
//   Streams every captured event to user-space through a BPF ring buffer.

#include "../include/vmlinux.h"
#include "../include/bpf_helpers.h"
#include "../include/bpf_tracing.h"
#include "../include/common.h"

char LICENSE[] SEC("license") = "GPL";

/* ───── Maps ───── */

// High-performance ring buffer for streaming telemetry to user-space agent
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Per-CPU scratch area to build events (avoids 512-byte stack limit)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct event_t);
} scratch SEC(".maps");

/* ───── Helpers ───── */

static __always_inline struct event_t *get_event(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&scratch, &zero);
}

static __always_inline void fill_common(struct event_t *e, u32 etype)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid          = (u32)(pid_tgid);
    e->tgid         = (u32)(pid_tgid >> 32);
    e->uid          = (u32)(uid_gid);
    e->gid          = (u32)(uid_gid >> 32);
    e->event_type   = etype;
    e->cgroup_id    = (u32)bpf_get_current_cgroup_id();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get parent PID via current task_struct
    struct task_struct *task = (void *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(struct task_struct *),
                              &task->real_parent);
        if (parent)
            bpf_probe_read_kernel(&e->ppid, sizeof(e->ppid),
                                  &parent->tgid);
    }
}

static __always_inline void submit(struct event_t *e)
{
    struct event_t *out;
    out = bpf_ringbuf_reserve(&events, sizeof(*out), 0);
    if (!out)
        return;
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
}

/* ════════════════════════════════════════════════════════════
   1. RAW SYSTEM CALL TRACING  (catches EVERY syscall)
   ════════════════════════════════════════════════════════════ */

SEC("tp/raw_syscalls/sys_enter")
int tp_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_SYSCALL);
    e->syscall_id = ctx->id;
    submit(e);
    return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int tp_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_SYSCALL);
    e->syscall_id = ctx->id;
    e->retval     = ctx->ret;
    e->flags      = 1;   // marks this as an exit event
    submit(e);
    return 0;
}

/* ════════════════════════════════════════════════════════════
   2. PROCESS LIFECYCLE
   ════════════════════════════════════════════════════════════ */

SEC("tp/sched/sched_process_exec")
int tp_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_EXEC);

    // Read the executed filename from the tracepoint
    unsigned short fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(e->filename, sizeof(e->filename),
                       (void *)ctx + fname_off);
    submit(e);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_EXIT);
    submit(e);
    return 0;
}

SEC("tp/sched/sched_process_fork")
int tp_sched_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_EXEC);
    e->flags = 2; // marks fork vs exec
    submit(e);
    return 0;
}

/* ════════════════════════════════════════════════════════════
   3. PRIVILEGE ESCALATION  (setuid/setgid/capset)
   ════════════════════════════════════════════════════════════ */

SEC("kprobe/__x64_sys_setuid")
int kp_setuid(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 105; // __NR_setuid
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_setgid")
int kp_setgid(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 106; // __NR_setgid
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_setreuid")
int kp_setreuid(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 113; // __NR_setreuid
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_setregid")
int kp_setregid(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 114; // __NR_setregid
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_setresuid")
int kp_setresuid(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 117; // __NR_setresuid
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_setresgid")
int kp_setresgid(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 119; // __NR_setresgid
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_capset")
int kp_capset(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 126; // __NR_capset
    submit(e);
    return 0;
}

/* ════════════════════════════════════════════════════════════
   4. MEMORY / CODE INJECTION  (ptrace, mprotect, mmap, memfd)
   ════════════════════════════════════════════════════════════ */

SEC("kprobe/__x64_sys_ptrace")
int kp_ptrace(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_MEM);
    e->syscall_id = 101; // __NR_ptrace
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_process_vm_writev")
int kp_vm_writev(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_MEM);
    e->syscall_id = 311; // __NR_process_vm_writev
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_process_vm_readv")
int kp_vm_readv(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_MEM);
    e->syscall_id = 310; // __NR_process_vm_readv
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_mprotect")
int kp_mprotect(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_MEM);
    e->syscall_id = 10; // __NR_mprotect
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_mmap")
int kp_mmap(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_MEM);
    e->syscall_id = 9; // __NR_mmap
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_memfd_create")
int kp_memfd_create(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_MEM);
    e->syscall_id = 319; // __NR_memfd_create — fileless malware
    submit(e);
    return 0;
}

/* ════════════════════════════════════════════════════════════
   5. KERNEL MODULE LOADING  (rootkit detection)
   ════════════════════════════════════════════════════════════ */

SEC("kprobe/__x64_sys_init_module")
int kp_init_module(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 175; // __NR_init_module
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int kp_finit_module(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 313; // __NR_finit_module
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_delete_module")
int kp_delete_module(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 176; // __NR_delete_module
    submit(e);
    return 0;
}

/* ════════════════════════════════════════════════════════════
   6. CONTAINER / NAMESPACE ESCAPE
   ════════════════════════════════════════════════════════════ */

SEC("kprobe/__x64_sys_setns")
int kp_setns(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 308; // __NR_setns
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_unshare")
int kp_unshare(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 272; // __NR_unshare
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_pivot_root")
int kp_pivot_root(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 155; // __NR_pivot_root
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_mount")
int kp_mount(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 165; // __NR_mount
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_umount")
int kp_umount(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 166; // __NR_umount2
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_chroot")
int kp_chroot(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_PRIV);
    e->syscall_id = 161; // __NR_chroot
    submit(e);
    return 0;
}

/* ════════════════════════════════════════════════════════════
   7. FILE SYSTEM – sensitive file access tracking
   ════════════════════════════════════════════════════════════ */

SEC("kprobe/__x64_sys_unlinkat")
int kp_unlinkat(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_FILE);
    e->syscall_id = 263; // __NR_unlinkat
    e->file_op    = FILE_OP_DELETE;
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_renameat2")
int kp_renameat2(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_FILE);
    e->syscall_id = 316; // __NR_renameat2
    e->file_op    = FILE_OP_RENAME;
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_truncate")
int kp_truncate(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_FILE);
    e->syscall_id = 76; // __NR_truncate
    e->file_op    = FILE_OP_WRITE;
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_fchmodat")
int kp_fchmodat(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_FILE);
    e->syscall_id = 268; // __NR_fchmodat
    submit(e);
    return 0;
}

SEC("kprobe/__x64_sys_fchownat")
int kp_fchownat(struct pt_regs *ctx)
{
    struct event_t *e = get_event();
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e));
    fill_common(e, EVENT_TYPE_FILE);
    e->syscall_id = 260; // __NR_fchownat
    submit(e);
    return 0;
}
