#ifndef __ECAPTURE_SSL_H__
#define __ECAPTURE_SSL_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

#define SSL_MASTER_KEY_LEN 48
#define SSL_CLIENT_RANDOM_LEN 32

/* eCapture SSL Master Key Capture Data */
struct ssl_master_key_t {
    u32 pid;
    u32 uid;
    u64 timestamp_ns;
    u8 client_random[SSL_CLIENT_RANDOM_LEN];
    u8 master_key[SSL_MASTER_KEY_LEN];
    char comm[16];
};

/* SSL Payload Marker Flags */
enum ecapture_ssl_flags {
    ECAPTURE_FLAG_SSL_WRITE    = 0x554C, /* SSL_write */
    ECAPTURE_FLAG_SSL_READ     = 0x5552, /* SSL_read */
    ECAPTURE_FLAG_SSL_WRITE_EX = 0x554D, /* SSL_write_ex */
    ECAPTURE_FLAG_SSL_READ_EX  = 0x5553, /* SSL_read_ex */
    ECAPTURE_FLAG_MASTER_KEY   = 0x554B, /* SSL Master Key */
};

#endif /* __ECAPTURE_SSL_H__ */
