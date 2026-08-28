#ifndef __NETOBSERV_FLOW_H__
#define __NETOBSERV_FLOW_H__

#include "vmlinux.h"
#include "bpf_helpers.h"

/* Direction Constants */
enum netobserv_direction {
    NETOBSERV_INGRESS = 0,
    NETOBSERV_EGRESS  = 1,
};

/* NetObserv Flow Key Structure */
struct netobserv_flow_id {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 transport_protocol;
    u8 direction;
};

/* NetObserv Flow Metrics Summary */
struct netobserv_flow_metrics {
    u64 start_time_ns;
    u64 end_time_ns;
    u64 bytes;
    u32 packets;
    u32 tcp_flags;
    u32 rtt_ns;
    u32 if_index;
};

#endif /* __NETOBSERV_FLOW_H__ */
