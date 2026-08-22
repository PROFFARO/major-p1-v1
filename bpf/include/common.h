#ifndef __COMMON_H__
#define __COMMON_H__

/* Errno values (cannot include userspace errno.h in BPF programs) */
#ifndef EPERM
#define EPERM  1
#endif
#ifndef EACCES
#define EACCES 13
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_SYSCALL_ARGS 6

/* Event Types */
enum event_type {
    EVENT_TYPE_UNKNOWN = 0,
    EVENT_TYPE_SYSCALL = 1,
    EVENT_TYPE_EXEC    = 2,
    EVENT_TYPE_EXIT    = 3,
    EVENT_TYPE_FILE    = 4,
    EVENT_TYPE_NET     = 5,
    EVENT_TYPE_PRIV    = 6,
    EVENT_TYPE_MEM     = 7,
};

/* File Operation Types */
enum file_op {
    FILE_OP_READ   = 1,
    FILE_OP_WRITE  = 2,
    FILE_OP_OPEN   = 3,
    FILE_OP_CREATE = 4,
    FILE_OP_DELETE = 5,
    FILE_OP_RENAME = 6,
};

/* Unified Telemetry Event Structure streamed to User Space Ring Buffer */
struct event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tgid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 cgroup_id;
    u32 event_type;
    u64 syscall_id;
    s64 retval;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u16 protocol;
    u16 file_op;
    u32 flags;
};

/* Action Constants */
#define ACTION_ALLOW 0
#define ACTION_BLOCK 1
#define ACTION_LOG   2

/* Block Rule Types */
#define RULE_TYPE_PID         1
#define RULE_TYPE_IP          2
#define RULE_TYPE_FILE_HASH   3
#define RULE_TYPE_SYSCALL_SEQ 4

/* Real-time Threat Blocklist Structure stored in eBPF Hash Map */
struct block_rule_t {
    u32 rule_type;
    u32 target_pid;
    u32 target_ip;
    u32 action;          // 1 = BLOCK (-EPERM), 2 = LOG
    u64 creation_ts;
    u64 hit_count;
    char description[64];
};

#endif /* __COMMON_H__ */
