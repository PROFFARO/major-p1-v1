// SPDX-License-Identifier: GPL-2.0
// lsm_enforcer.bpf.c — LSM (Linux Security Module) eBPF hooks for
//   real-time security monitoring and threat auditing across
//   binary execution, file access, credential changes, socket operations,
//   memory protection, and kernel module loading.

#include "../include/vmlinux.h"
#include "../include/bpf_helpers.h"
#include "../include/bpf_tracing.h"
#include "../include/common.h"

char LICENSE[] SEC("license") = "GPL";

/* ───── Ring Buffer & Scratch Maps for Telemetry Auditing ───── */

// Ring buffer for logging LSM security events to user-space
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22); // 4 MB
} lsm_events SEC(".maps");

// Per-CPU scratch
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct event_t);
} lsm_scratch SEC(".maps");

/* ───── Helpers ───── */

static __always_inline struct event_t *lsm_get_event(void) {
  u32 zero = 0;
  return bpf_map_lookup_elem(&lsm_scratch, &zero);
}

static __always_inline void lsm_fill_common(struct event_t *e, u32 etype) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 uid_gid = bpf_get_current_uid_gid();
  e->timestamp_ns = bpf_ktime_get_ns();
  e->pid = (u32)(pid_tgid);
  e->tgid = (u32)(pid_tgid >> 32);
  e->uid = (u32)(uid_gid);
  e->gid = (u32)(uid_gid >> 32);
  e->event_type = etype;
  e->cgroup_id = (u32)bpf_get_current_cgroup_id();
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void lsm_submit(struct event_t *e) {
  struct event_t *out;
  out = bpf_ringbuf_reserve(&lsm_events, sizeof(*out), 0);
  if (!out)
    return;
  __builtin_memcpy(out, e, sizeof(*out));
  bpf_ringbuf_submit(out, 0);
}

/* ════════════════════════════════════════════════════════════
   1. BINARY EXECUTION CONTROL
   ════════════════════════════════════════════════════════════ */

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_EXEC);

  // Read the binary filename being executed
  const char *fname = NULL;
  bpf_probe_read_kernel(&fname, sizeof(const char *), &bprm->filename);
  if (fname)
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname);

  lsm_submit(e);
  return 0;
}

/* ════════════════════════════════════════════════════════════
   2. FILE ACCESS CONTROL (open, read/write permissions)
   ════════════════════════════════════════════════════════════ */

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_FILE);
  e->file_op = FILE_OP_OPEN;

  // Read the file path from dentry
  struct dentry *dentry = NULL;
  bpf_probe_read_kernel(&dentry, sizeof(struct dentry *), &file->f_path.dentry);
  if (dentry) {
    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
    if (d_name.name)
      bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), d_name.name);
  }

  lsm_submit(e);
  return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission, struct file *file, int mask) {
  // Log write operations (mask & MAY_WRITE == 2)
  if (!(mask & 2))
    return 0;

  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_FILE);
  e->file_op = FILE_OP_WRITE;
  e->flags = (u32)mask;
  lsm_submit(e);
  return 0;
}

/* ════════════════════════════════════════════════════════════
   3. FILE DELETION / RENAME  (ransomware indicators)
   ════════════════════════════════════════════════════════════ */

SEC("lsm/path_unlink")
int BPF_PROG(lsm_path_unlink, const struct path *dir, struct dentry *dentry) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_FILE);
  e->file_op = FILE_OP_DELETE;

  struct qstr d_name;
  bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
  if (d_name.name)
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), d_name.name);
  lsm_submit(e);
  return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(lsm_path_rename, const struct path *old_dir,
             struct dentry *old_dentry, const struct path *new_dir,
             struct dentry *new_dentry, unsigned int flags) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_FILE);
  e->file_op = FILE_OP_RENAME;

  struct qstr d_name;
  bpf_probe_read_kernel(&d_name, sizeof(d_name), &old_dentry->d_name);
  if (d_name.name)
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), d_name.name);
  lsm_submit(e);
  return 0;
}

/* ════════════════════════════════════════════════════════════
   4. CREDENTIAL & PRIVILEGE CHANGES
   ════════════════════════════════════════════════════════════ */

SEC("lsm/cred_prepare")
int BPF_PROG(lsm_cred_prepare, struct cred *new_cred,
             const struct cred *old_cred, gfp_t gfp) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_PRIV);
  e->syscall_id = 0xC001; // sentinel: cred_prepare
  lsm_submit(e);
  return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(lsm_task_fix_setuid, struct cred *new_cred,
             const struct cred *old_cred, int flags) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_PRIV);
  e->syscall_id = 0xC002; // sentinel: task_fix_setuid
  e->flags = (u32)flags;
  lsm_submit(e);
  return 0;
}

/* ════════════════════════════════════════════════════════════
   5. SOCKET / NETWORK OPERATIONS
   ════════════════════════════════════════════════════════════ */

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_NET);

  // Extract destination IP:port for AF_INET
  u16 family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
  if (family == 2) { // AF_INET
    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    bpf_probe_read_kernel(&e->dst_ip, sizeof(e->dst_ip), &sin->sin_addr);
    bpf_probe_read_kernel(&e->dst_port, sizeof(e->dst_port), &sin->sin_port);
  }

  lsm_submit(e);
  return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(lsm_socket_bind, struct socket *sock, struct sockaddr *address,
             int addrlen) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_NET);
  e->flags = 0xB14D; // sentinel: bind

  u16 family = 0;
  bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
  if (family == 2) {
    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    bpf_probe_read_kernel(&e->src_port, sizeof(e->src_port), &sin->sin_port);
  }

  lsm_submit(e);
  return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(lsm_socket_accept, struct socket *sock, struct socket *newsock) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_NET);
  e->flags = 0xACC0; // sentinel: accept
  lsm_submit(e);
  return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(lsm_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size) {
  return 0; // pass-through telemetry
}

/* ════════════════════════════════════════════════════════════
   6. MEMORY PROTECTION (shellcode injection monitoring)
   ════════════════════════════════════════════════════════════ */

SEC("lsm/file_mprotect")
int BPF_PROG(lsm_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot) {
  // Flag W+X (write+execute) memory — shellcode injection indicator
  if ((prot & 0x4) && (prot & 0x2)) { // PROT_EXEC | PROT_WRITE
    struct event_t *e = lsm_get_event();
    if (!e)
      return 0;
    __builtin_memset(e, 0, sizeof(*e));
    lsm_fill_common(e, EVENT_TYPE_MEM);
    e->flags = (u32)prot;
    lsm_submit(e);
  }
  return 0;
}

/* ════════════════════════════════════════════════════════════
   7. KERNEL MODULE LOADING AUDIT
   ════════════════════════════════════════════════════════════ */

SEC("lsm/kernel_read_file")
int BPF_PROG(lsm_kernel_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents) {
  struct event_t *e = lsm_get_event();
  if (!e)
    return 0;
  __builtin_memset(e, 0, sizeof(*e));
  lsm_fill_common(e, EVENT_TYPE_PRIV);
  e->syscall_id = 0xC003; // sentinel: kernel_read_file
  e->flags = (u32)id;
  lsm_submit(e);
  return 0;
}
