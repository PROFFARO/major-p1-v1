#ifndef __PARCA_TYPES_H__
#define __PARCA_TYPES_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

#define PARCA_MAX_STACK_DEPTH 128

/* Parca DWARF Stack Unwinding Frame Descriptor */
struct parca_frame_t {
    u64 ip;              /* Instruction Pointer */
    u64 mapping_end;     /* Memory Mapping End */
    u64 mapping_offset;  /* Binary Offset */
    u32 lineno;          /* Source Line Number */
    char symbol_name[64];/* Demangled Function Symbol Name */
};

/* Parca Continuous CPU Profile Sample Record */
struct parca_profile_sample_t {
    u32 pid;
    u32 tgid;
    u64 timestamp_ns;
    u64 sample_count;
    u32 num_frames;
    struct parca_frame_t frames[16];
};

#endif /* __PARCA_TYPES_H__ */
