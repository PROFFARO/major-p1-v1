#ifndef __EUNOMIA_META_H__
#define __EUNOMIA_META_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* eunomia-bpf Dynamic Package Config Metadata */
struct eunomia_bpf_meta_t {
    char name[64];
    char version[32];
    char description[128];
    u32 bpf_skel_size;
    u32 export_types_count;
};

/* eunomia-bpf Dynamic Event Field Descriptor */
struct eunomia_field_meta_t {
    char name[32];
    char type_name[32];
    u32 offset;
    u32 size;
};

#endif /* __EUNOMIA_META_H__ */
