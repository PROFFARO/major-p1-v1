// SPDX-License-Identifier: GPL-2.0
// net_filter.bpf.c — TC (Traffic Control) ingress/egress eBPF classifiers
//   for deep packet inspection, DDoS detection, DNS exfiltration monitoring,
//   and IP-based real-time blocking at the network layer.

#include "../include/vmlinux.h"
#include "../include/bpf_helpers.h"
#include "../include/common.h"

char LICENSE[] SEC("license") = "GPL";

/* ───── Constants ───── */
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define IPPROTO_ICMP 1
#define DNS_PORT     53

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* ───── Packet header structures (minimal, from vmlinux may lack these) ─── */
struct ethhdr_t {
    unsigned char  h_dest[6];
    unsigned char  h_source[6];
    __be16         h_proto;
} __attribute__((packed));

struct iphdr_t {
    u8  ihl_ver;
    u8  tos;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u8  ttl;
    u8  protocol;
    u16 check;
    u32 saddr;
    u32 daddr;
} __attribute__((packed));

struct tcphdr_t {
    u16 source;
    u16 dest;
    u32 seq;
    u32 ack_seq;
    u16 flags;  // data offset + flags
    u16 window;
    u16 check;
    u16 urg_ptr;
} __attribute__((packed));

struct udphdr_t {
    u16 source;
    u16 dest;
    u16 len;
    u16 check;
} __attribute__((packed));

// ───── Maps ─────

// Ring buffer for network telemetry events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23); // 8 MB
} net_events SEC(".maps");

// Per-IP packet counter (for DDoS rate detection)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);    // source IP
    __type(value, u64);  // packet count
} pkt_counter SEC(".maps");

// DNS query counter per source IP (for DNS exfil detection)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, u32);    // source IP
    __type(value, u64);  // DNS query count
} dns_counter SEC(".maps");

/* ───── Helpers ───── */

static __always_inline void net_submit_event(u32 src_ip, u32 dst_ip,
    u16 src_port, u16 dst_port, u8 protocol, u32 flags)
{
    struct event_t *out;
    out = bpf_ringbuf_reserve(&net_events, sizeof(*out), 0);
    if (!out) return;
    __builtin_memset(out, 0, sizeof(*out));

    out->timestamp_ns = bpf_ktime_get_ns();
    out->event_type   = EVENT_TYPE_NET;
    out->src_ip       = src_ip;
    out->dst_ip       = dst_ip;
    out->src_port     = src_port;
    out->dst_port     = dst_port;
    out->protocol     = protocol;
    out->flags        = flags;

    bpf_ringbuf_submit(out, 0);
}

/* ════════════════════════════════════════════════════════════
   TC INGRESS CLASSIFIER  (inbound traffic telemetry)
   ════════════════════════════════════════════════════════════ */

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Only process IPv4
    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr_t *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    u32 src_ip = ip->saddr;
    u32 dst_ip = ip->daddr;
    u8  proto  = ip->protocol;

    // ── Per-IP Packet Rate Counter (DDoS heuristic) ──
    u64 *cnt = bpf_map_lookup_elem(&pkt_counter, &src_ip);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        u64 init = 1;
        bpf_map_update_elem(&pkt_counter, &src_ip, &init, BPF_ANY);
    }

    u16 src_port = 0, dst_port = 0;

    // ── Parse TCP ──
    if (proto == IPPROTO_TCP) {
        u8 ihl = (ip->ihl_ver & 0x0F) * 4;
        struct tcphdr_t *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;

        // Detect SYN floods (flags: SYN=0x02 in low byte of flags field)
        u16 tcp_flags = __builtin_bswap16(tcp->flags);
        u8 flag_bits  = (u8)(tcp_flags & 0x3F);
        if (flag_bits == 0x02) { // pure SYN
            net_submit_event(src_ip, dst_ip, src_port, dst_port,
                             proto, 0x5914); // SYN flood marker
        }
    }

    // ── Parse UDP ──
    if (proto == IPPROTO_UDP) {
        u8 ihl = (ip->ihl_ver & 0x0F) * 4;
        struct udphdr_t *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;

        // Track DNS queries (port 53) — DNS exfiltration detection
        if (dst_port == __builtin_bswap16(DNS_PORT) ||
            src_port == __builtin_bswap16(DNS_PORT)) {
            u64 *dcnt = bpf_map_lookup_elem(&dns_counter, &src_ip);
            if (dcnt) {
                __sync_fetch_and_add(dcnt, 1);
            } else {
                u64 init = 1;
                bpf_map_update_elem(&dns_counter, &src_ip, &init,
                                    BPF_ANY);
            }
            net_submit_event(src_ip, dst_ip, src_port, dst_port,
                             proto, 0xD145); // DNS marker
        }
    }

    // ── ICMP flood tracking ──
    if (proto == IPPROTO_ICMP) {
        net_submit_event(src_ip, dst_ip, 0, 0, proto, 0x1C3F);
    }

    // Emit general telemetry for all TCP/UDP
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
        net_submit_event(src_ip, dst_ip, src_port, dst_port, proto, 0);

    return TC_ACT_OK;
}

/* ════════════════════════════════════════════════════════════
   TC EGRESS CLASSIFIER  (outbound traffic — C2, reverse shells)
   ════════════════════════════════════════════════════════════ */

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr_t *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr_t *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    u32 dst_ip = ip->daddr;
    u8  proto  = ip->protocol;

    u16 src_port = 0, dst_port = 0;

    if (proto == IPPROTO_TCP) {
        u8 ihl = (ip->ihl_ver & 0x0F) * 4;
        struct tcphdr_t *tcp = (void *)ip + ihl;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = tcp->source;
        dst_port = tcp->dest;
    }

    if (proto == IPPROTO_UDP) {
        u8 ihl = (ip->ihl_ver & 0x0F) * 4;
        struct udphdr_t *udp = (void *)ip + ihl;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        src_port = udp->source;
        dst_port = udp->dest;

        // Outbound DNS exfil tracking
        if (dst_port == __builtin_bswap16(DNS_PORT)) {
            net_submit_event(ip->saddr, dst_ip, src_port, dst_port,
                             proto, 0xD146); // outbound DNS
        }
    }

    // Emit egress telemetry
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
        net_submit_event(ip->saddr, dst_ip, src_port, dst_port,
                         proto, 0xE600); // egress marker

    return TC_ACT_OK;
}
