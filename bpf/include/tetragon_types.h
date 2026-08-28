#ifndef __TETRAGON_TYPES_H__
#define __TETRAGON_TYPES_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Tetragon LSM enforcement action codes */
#define TETRAGON_ACTION_POST     0
#define TETRAGON_ACTION_ENFORCE  1
#define TETRAGON_ACTION_SIGKILL  9

/* Tetragon process credentials and execution security structure */
struct tetragon_exec_cred_t {
    u32 uid;
    u32 gid;
    u32 euid;
    u32 egid;
    u32 suid;
    u32 sgid;
    u32 fsuid;
    u32 fsgid;
    u64 securebits;
    u64 cap_inheritable;
    u64 cap_permitted;
    u64 cap_effective;
    u64 cap_bset;
    u64 cap_ambient;
};

/* Tetragon LSM override structure */
struct tetragon_enforcer_act_info {
    u32 func_id;
    u32 arg;
};

struct tetragon_enforcer_data {
    s16 error;
    s16 signal;
    struct tetragon_enforcer_act_info act_info;
};

#endif /* __TETRAGON_TYPES_H__ */
