#ifndef __SYSMON_EVENTS_H__
#define __SYSMON_EVENTS_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Official Sysmon for Linux Event IDs */
enum sysmon_event_id {
    SYSMON_PROCESS_CREATE        = 1,  /* Process Create */
    SYSMON_FILE_TIME_CHANGE      = 2,  /* File creation time changed */
    SYSMON_NETWORK_CONNECT       = 3,  /* Network connection detected */
    SYSMON_SERVICE_STATE_CHANGE  = 4,  /* Sysmon service state changed */
    SYSMON_PROCESS_TERMINATE     = 5,  /* Process terminated */
    SYSMON_DRIVER_LOAD           = 6,  /* Driver/Kernel Module loaded */
    SYSMON_IMAGE_LOAD            = 7,  /* Image/Shared object loaded */
    SYSMON_CREATE_REMOTE_THREAD  = 8,  /* CreateRemoteThread/ptrace injection */
    SYSMON_RAW_ACCESS_READ       = 9,  /* RawAccessRead */
    SYSMON_PROCESS_ACCESS        = 10, /* ProcessAccess (process memory open) */
    SYSMON_FILE_CREATE           = 11, /* FileCreate */
    SYSMON_REG_CREATE_DELETE     = 12, /* RegistryEvent Object Create/Delete */
    SYSMON_REG_SET_VALUE         = 13, /* RegistryEvent Value Set */
    SYSMON_REG_RENAME            = 14, /* RegistryEvent Key/Value Rename */
    SYSMON_CREATE_STREAM_HASH    = 15, /* FileCreateStreamHash */
    SYSMON_SERVICE_CONFIG_CHANGE = 16, /* ServiceConfigurationChange */
    SYSMON_PIPE_CREATE           = 17, /* PipeEvent (Pipe Created) */
    SYSMON_PIPE_CONNECT          = 18, /* PipeEvent (Pipe Connected) */
    SYSMON_WMI_EVENT             = 19, /* WmiEvent */
    SYSMON_DNS_QUERY             = 22, /* DNSEvent (DNS Query) */
    SYSMON_FILE_DELETE           = 23, /* FileDelete */
};

/* Sysmon Event Header Mirror Structure */
struct sysmon_event_header_t {
    u32 event_id;
    u64 timestamp_ns;
    u32 process_id;
    u32 parent_process_id;
    u32 user_id;
    char image_path[256];
    char command_line[256];
};

#endif /* __SYSMON_EVENTS_H__ */
