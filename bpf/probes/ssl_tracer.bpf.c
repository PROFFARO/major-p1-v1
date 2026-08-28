// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * ssl_tracer.bpf.c — eCapture-style Plaintext TLS/SSL Inspection Probe
 *
 * Attaches uprobes to libssl.so (SSL_read, SSL_write) to capture unencrypted
 * TLS application layer payloads (HTTP headers, API payloads, C2 commands)
 * before encryption or after decryption.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_PAYLOAD_LEN 256

// Ring buffer for TLS/SSL plaintext payload telemetry
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8 MB
} ssl_events SEC(".maps");

// Up-probe event for OpenSSL write/read calls
SEC("uprobe/SSL_write")
int probe_ssl_write(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    size_t num = (size_t)PT_REGS_PARM3(ctx);

    if (!buf || num == 0)
        return 0;

    struct event_t *out;
    out = bpf_ringbuf_reserve(&ssl_events, sizeof(*out), 0);
    if (!out)
        return 0;

    __builtin_memset(out, 0, sizeof(*out));
    out->timestamp_ns = bpf_ktime_get_ns();
    out->pid = pid;
    out->tgid = (u32)pid_tgid;
    out->ppid = 0;
    out->uid = bpf_get_current_uid_gid();
    out->gid = bpf_get_current_uid_gid() >> 32;
    out->event_type = EVENT_TYPE_NET;
    out->flags = 0x554C; // 'SL' OpenSSL payload marker

    bpf_get_current_comm(&out->comm, sizeof(out->comm));

    u32 read_len = num < (MAX_PAYLOAD_LEN - 1) ? num : (MAX_PAYLOAD_LEN - 1);
    bpf_probe_read_user(&out->filename, read_len, buf);

    bpf_ringbuf_submit(out, 0);
    return 0;
}

SEC("uprobe/SSL_read")
int probe_ssl_read(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    size_t num = (size_t)PT_REGS_PARM3(ctx);

    if (!buf || num == 0)
        return 0;

    struct event_t *out;
    out = bpf_ringbuf_reserve(&ssl_events, sizeof(*out), 0);
    if (!out)
        return 0;

    __builtin_memset(out, 0, sizeof(*out));
    out->timestamp_ns = bpf_ktime_get_ns();
    out->pid = pid;
    out->tgid = (u32)pid_tgid;
    out->ppid = 0;
    out->uid = bpf_get_current_uid_gid();
    out->gid = bpf_get_current_uid_gid() >> 32;
    out->event_type = EVENT_TYPE_NET;
    out->flags = 0x5552; // 'SR' OpenSSL read payload marker

    bpf_get_current_comm(&out->comm, sizeof(out->comm));

    u32 read_len = num < (MAX_PAYLOAD_LEN - 1) ? num : (MAX_PAYLOAD_LEN - 1);
    bpf_probe_read_user(&out->filename, read_len, buf);

    bpf_ringbuf_submit(out, 0);
    return 0;
}
