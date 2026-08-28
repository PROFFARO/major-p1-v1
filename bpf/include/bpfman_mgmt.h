#ifndef __BPFMAN_MGMT_H__
#define __BPFMAN_MGMT_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* bpfman Program Attachment Priority Ordering */
enum bpfman_priority {
    BPFMAN_PRIO_HIGH   = 100,
    BPFMAN_PRIO_MEDIUM = 500,
    BPFMAN_PRIO_LOW    = 1000,
};

/* bpfman Map Pinning Mode */
enum bpfman_pin_mode {
    BPFMAN_PIN_NONE    = 0,
    BPFMAN_PIN_BY_NAME = 1,
    BPFMAN_PIN_CUSTOM  = 2,
};

/* bpfman Program Info Descriptor */
struct bpfman_prog_info_t {
    u32 id;
    u32 type;
    u32 priority;
    u32 pin_mode;
    char name[64];
    char attach_target[64];
    char pin_path[128];
};

#endif /* __BPFMAN_MGMT_H__ */
