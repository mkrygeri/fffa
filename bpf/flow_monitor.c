// flow_monitor.c: Unified eBPF XDP + TC program with GENEVE + native support and TCP flag tracking

#include <linux/bpf.h>
#include <linux/if_ether.h>
//#include "vmlinux.h"
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

#define GENEVE_PORT 6081

struct flow_key {
    __u32 outer_src_ip;
    __u32 outer_dst_ip;
    __u32 inner_src_ip;
    __u32 inner_dst_ip;
    __u16 inner_src_port;
    __u16 inner_dst_port;
    __u8  inner_proto;
    __u8  direction;         // 0 = ingress, 1 = egress
    __u8  is_encapsulated;   // 0 = native, 1 = geneve
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 start_ns;
    __u64 last_seen_ns;
    __u8  tcp_flags;
};

struct flow_event {
    struct flow_key key;
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(max_entries, 65536);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} flow_ring SEC(".maps");

static __always_inline void parse_tcp_flags(void *data, void *data_end, __u8 *flags, __u8 proto) {
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = data;
        if ((void *)(tcph + 1) > data_end) return;
        *flags = ((__u8 *)tcph)[13]; // Offset to TCP flags
    }
}

static __always_inline int parse_inner_ip(void *pos, void *data_end, struct flow_key *key, int direction) {
    struct ethhdr *eth = pos;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return 0;

    key->inner_src_ip = iph->saddr;
    key->inner_dst_ip = iph->daddr;
    key->inner_proto = iph->protocol;
    key->direction = direction;

    void *l4 = (void *)(iph + 1);
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4;
        if ((void *)(tcph + 1) > data_end) return 0;
        key->inner_src_port = tcph->source;
        key->inner_dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4;
        if ((void *)(udph + 1) > data_end) return 0;
        key->inner_src_port = udph->source;
        key->inner_dst_port = udph->dest;
    } else return 0;

    return 1;
}

static __always_inline int process_packet(void *data, void *data_end, int direction) {
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return 0;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return 0;

    struct flow_key key = {};
    key.outer_src_ip = iph->saddr;
    key.outer_dst_ip = iph->daddr;

    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end) return 0;

        if (__builtin_bswap16(udph->dest) == GENEVE_PORT) {
            void *inner = (void *)(udph + 1) + 8;
            if (!parse_inner_ip(inner, data_end, &key, direction)) return 0;
            key.is_encapsulated = 1;
        } else return 0;
    } else {
        key.inner_src_ip = iph->saddr;
        key.inner_dst_ip = iph->daddr;
        key.inner_proto = iph->protocol;
        key.direction = direction;
        key.is_encapsulated = 0;

        void *l4 = (void *)(iph + 1);
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = l4;
            if ((void *)(tcph + 1) > data_end) return 0;
            key.inner_src_port = tcph->source;
            key.inner_dst_port = tcph->dest;
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = l4;
            if ((void *)(udph + 1) > data_end) return 0;
            key.inner_src_port = udph->source;
            key.inner_dst_port = udph->dest;
        } else return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = data_end - data;

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_table, &key);
    if (stats) {
        stats->packets++;
        stats->bytes += pkt_len;
        stats->last_seen_ns = now;
        __u8 flags = 0;
        parse_tcp_flags((void *)(iph + 1), data_end, &flags, key.inner_proto);
        stats->tcp_flags |= flags;
    } else {
        struct flow_stats s = {
            .packets = 1,
            .bytes = pkt_len,
            .start_ns = now,
            .last_seen_ns = now,
            .tcp_flags = 0
        };
        parse_tcp_flags((void *)(iph + 1), data_end, &s.tcp_flags, key.inner_proto);
        bpf_map_update_elem(&flow_table, &key, &s, BPF_ANY);

        struct flow_event *ev = bpf_ringbuf_reserve(&flow_ring, sizeof(*ev), 0);
        if (ev) {
            ev->key = key;
            ev->timestamp_ns = now;
            bpf_ringbuf_submit(ev, 0);
        }
    }

    return 1;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    process_packet(data, data_end, 0); // ingress
    return XDP_PASS;
}

SEC("tc")
int tc_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    process_packet(data, data_end, 1); // egress
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";