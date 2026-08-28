#ifndef __TRACEE_EVENTS_H__
#define __TRACEE_EVENTS_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Tracee Security Event ID Constants */
enum tracee_event_id {
    TRACEE_EVENT_RAW_SYS_ENTER           = 100,
    TRACEE_EVENT_RAW_SYS_EXIT            = 101,
    TRACEE_EVENT_SCHED_PROCESS_FORK      = 102,
    TRACEE_EVENT_SCHED_PROCESS_EXEC      = 103,
    TRACEE_EVENT_SCHED_PROCESS_EXIT      = 104,
    TRACEE_EVENT_COMMIT_CREDS            = 105,
    TRACEE_EVENT_SECURITY_BPRM_CHECK     = 106,
    TRACEE_EVENT_SECURITY_FILE_OPEN      = 107,
    TRACEE_EVENT_SECURITY_SOCKET_CONNECT = 108,
    TRACEE_EVENT_MEM_PROT_ALERT          = 109,
    TRACEE_EVENT_SHARED_OBJECT_LOADED    = 110,
    TRACEE_EVENT_MAGIC_WRITE             = 111,
    TRACEE_EVENT_MODULE_LOAD             = 112,
    TRACEE_EVENT_SUSPICIOUS_SYSCALL      = 113,
    TRACEE_EVENT_DIRTY_PIPE_SPLICE       = 114,
    TRACEE_EVENT_HIDDEN_MODULE_SEEKER    = 115,
};

/* Memory Protection Anomaly Alert Types */
enum tracee_mem_prot_alert {
    TRACEE_ALERT_MMAP_W_X  = 1, /* Memory mapped as Write + Execute */
    TRACEE_ALERT_MPROT_X_ADD = 2, /* Mprotect added Execute permission */
    TRACEE_ALERT_MPROT_W_ADD = 3, /* Mprotect added Write permission */
};

/* Tracee Task Context Metadata */
struct tracee_task_context_t {
    u64 start_time;
    u64 cgroup_id;
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 host_pid;
    u32 host_tid;
    u32 host_ppid;
    u32 uid;
    u32 mnt_id;
    u32 pid_id;
    char comm[16];
    u32 flags;
};

/* Tracee Event Context Metadata Header */
struct tracee_event_context_t {
    u64 ts;
    struct tracee_task_context_t task;
    u32 event_id;
    s32 syscall_nr;
    u32 processor_id;
};

#endif /* __TRACEE_EVENTS_H__ */
