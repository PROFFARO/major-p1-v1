#ifndef __GADGET_TYPES_H__
#define __GADGET_TYPES_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Inspektor Gadget Event Category Types */
enum gadget_event_category {
    GADGET_TYPE_TRACE_EXEC       = 1,  /* Process exec tracer */
    GADGET_TYPE_TRACE_OPEN       = 2,  /* File open tracer */
    GADGET_TYPE_TRACE_DNS        = 3,  /* DNS query tracer */
    GADGET_TYPE_TRACE_TCP        = 4,  /* TCP connect/accept tracer */
    GADGET_TYPE_TRACE_CAP        = 5,  /* Capabilities tracer */
    GADGET_TYPE_TRACE_SNI        = 6,  /* TLS SNI tracer */
    GADGET_TYPE_TRACE_TCPDROP    = 7,  /* TCP drop tracer */
    GADGET_TYPE_TRACE_MOUNT      = 8,  /* Mount/umount tracer */
    GADGET_TYPE_TRACE_SIGNAL     = 9,  /* Signal tracer */
    GADGET_TYPE_TRACE_OOMKILL    = 10, /* OOM kill tracer */
};

/* Inspektor Gadget Container Metadata Header */
struct gadget_container_meta_t {
    u64 cgroup_id;
    u32 mnt_ns_id;
    u32 pid_ns_id;
    char container_name[64];
    char pod_name[64];
    char namespace_name[64];
};

/* Inspektor Gadget Unified Event Header */
struct gadget_event_t {
    u64 timestamp_ns;
    u32 category;
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    u32 gid;
    struct gadget_container_meta_t container;
    char comm[16];
    char payload[256];
};

#endif /* __GADGET_TYPES_H__ */
