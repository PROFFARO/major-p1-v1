#ifndef __KEPLER_ENERGY_H__
#define __KEPLER_ENERGY_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Kepler Process Energy Counter Record */
struct kepler_proc_energy_t {
    u32 pid;
    u32 tgid;
    u64 cpu_cycles;
    u64 cpu_instructions;
    u64 cache_misses;
    u64 page_cache_hits;
    u64 irq_count;
    u64 energy_ujoules; /* Microjoules (uJ) */
    char comm[16];
    char container_id[64];
};

/* Kepler Node Energy Summary */
struct kepler_node_energy_t {
    u64 pkg_energy_uj;  /* CPU Package Energy */
    u64 dram_energy_uj; /* DRAM Memory Energy */
    u64 gpu_energy_uj;  /* GPU Hardware Energy */
    u64 total_watts;    /* Real-Time Total Power Draw (W) */
};

#endif /* __KEPLER_ENERGY_H__ */
