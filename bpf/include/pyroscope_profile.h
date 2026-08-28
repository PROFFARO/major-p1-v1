#ifndef __PYROSCOPE_PROFILE_H__
#define __PYROSCOPE_PROFILE_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_STACK_DEPTH 128

/* Stack trace key structure for Pyroscope/Parca profile aggregation */
struct pyroscope_stack_key_t {
    u32 pid;
    u32 tgid;
    s32 user_stack_id;
    s32 kernel_stack_id;
    char comm[16];
};

/* Profile Sample Marker Flags */
enum pyroscope_profile_flags {
    PYROSCOPE_FLAG_CPU_SAMPLE = 0xCEF0, /* Continuous CPU Stack Sample */
    PYROSCOPE_FLAG_MEM_SAMPLE = 0xCEF1, /* Memory Allocation Sample */
};

#endif /* __PYROSCOPE_PROFILE_H__ */
