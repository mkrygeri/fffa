// flow_monitor.c: Enhanced eBPF XDP + TC program with comprehensive network metrics
// Includes connection latency, retransmissions, jitter, and netfilter verdicts

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
#define MAX_LATENCY_SAMPLES 10
#define JITTER_WINDOW_SIZE 5

// Netfilter verdicts
#define NF_DROP     0
#define NF_ACCEPT   1
#define NF_STOLEN   2
#define NF_QUEUE    3
#define NF_REPEAT   4
#define NF_STOP     5

// Netfilter hooks
#define NF_INET_PRE_ROUTING     0
#define NF_INET_LOCAL_IN        1
#define NF_INET_FORWARD         2
#define NF_INET_LOCAL_OUT       3
#define NF_INET_POST_ROUTING    4

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

// Enhanced flow statistics with network quality metrics
struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 start_ns;
    __u64 last_seen_ns;
    __u8  tcp_flags;
    
    // Connection establishment metrics
    __u64 syn_timestamp;        // SYN packet timestamp
    __u64 syn_ack_timestamp;    // SYN-ACK packet timestamp  
    __u64 ack_timestamp;        // Final ACK timestamp
    __u32 handshake_latency_us; // 3-way handshake latency in microseconds
    
    // Retransmission tracking
    __u32 retransmissions;      // Total retransmission count
    __u32 fast_retransmits;     // Fast retransmit count
    __u32 timeout_retransmits;  // Timeout-based retransmit count
    __u32 last_seq;            // Last seen sequence number
    __u64 last_seq_timestamp;   // Timestamp of last sequence number
    
    // Jitter and timing metrics
    __u64 pkt_intervals[JITTER_WINDOW_SIZE];  // Inter-packet arrival times
    __u8  interval_index;       // Current index in intervals array
    __u32 avg_jitter_us;        // Average jitter in microseconds
    __u32 max_jitter_us;        // Maximum jitter observed
    
    // Window and congestion metrics
    __u16 last_window_size;     // Last advertised window size
    __u16 min_window_size;      // Minimum window size observed
    __u16 max_window_size;      // Maximum window size observed
    __u8  ecn_flags;           // ECN flags observed
    
    // Quality metrics
    __u32 out_of_order_pkts;    // Out-of-order packet count
    __u32 duplicate_acks;       // Duplicate ACK count
    __u64 total_rtt_samples;    // Total RTT samples for averaging
    __u64 sum_rtt_us;          // Sum of RTT samples
    __u32 min_rtt_us;          // Minimum RTT observed
    __u32 max_rtt_us;          // Maximum RTT observed
};

// Netfilter verdict and rule information
struct netfilter_info {
    __u32 verdict;             // NF_ACCEPT=1, NF_DROP=0, etc.
    __u32 hook;               // NF_INET_PRE_ROUTING=0, etc.
    __s32 priority;           // Hook priority
    char table_name[16];      // iptables table name
    char chain_name[32];      // iptables chain name  
    __u32 rule_num;           // Rule number in chain
    char rule_target[32];     // Target name
    char match_info[64];      // Match information
};

// Enhanced flow statistics with netfilter information
struct flow_stats_nf {
    __u64 packets;
    __u64 bytes;
    __u64 start_ns;
    __u64 last_seen_ns;
    __u8  tcp_flags;
    
    // Connection establishment metrics
    __u64 syn_timestamp;
    __u64 syn_ack_timestamp;
    __u64 ack_timestamp;
    __u32 handshake_latency_us;
    
    // Retransmission tracking
    __u32 retransmissions;
    __u32 fast_retransmits;
    __u32 timeout_retransmits;
    __u32 last_seq;
    __u64 last_seq_timestamp;
    
    // Jitter and timing metrics
    __u64 pkt_intervals[JITTER_WINDOW_SIZE];
    __u8  interval_index;
    __u32 avg_jitter_us;
    __u32 max_jitter_us;
    
    // Window and congestion metrics
    __u16 last_window_size;
    __u16 min_window_size;
    __u16 max_window_size;
    __u8  ecn_flags;
    
    // Quality metrics
    __u32 out_of_order_pkts;
    __u32 duplicate_acks;
    __u64 total_rtt_samples;
    __u64 sum_rtt_us;
    __u32 min_rtt_us;
    __u32 max_rtt_us;
    
    // Netfilter information
    struct netfilter_info netfilter_info;
    __u32 last_verdict;
};

// Connection state tracking for latency measurement
struct tcp_connection {
    __u32 seq_syn;             // Initial SYN sequence number
    __u32 seq_syn_ack;         // SYN-ACK sequence number
    __u32 ack_syn_ack;         // ACK number for SYN-ACK
    __u64 syn_timestamp;       // SYN packet timestamp
    __u64 syn_ack_timestamp;   // SYN-ACK timestamp
    __u8  state;              // Connection state (0=init, 1=syn_sent, 2=established)
};

struct flow_event {
    struct flow_key key;
    __u64 timestamp_ns;
    struct flow_stats_nf metrics;  // Use enhanced metrics with netfilter info
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct flow_stats_nf);
    __uint(max_entries, 65536);
} flow_table SEC(".maps");

// TCP connection state tracking for handshake latency
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct tcp_connection);
    __uint(max_entries, 32768);
} tcp_connections SEC(".maps");

// Netfilter verdict tracking per flow
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct flow_key);
    __type(value, struct netfilter_info);
    __uint(max_entries, 32768);
} netfilter_verdicts SEC(".maps");

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

// Calculate jitter from inter-packet arrival times
static __always_inline __u32 calculate_jitter(struct flow_stats_nf *stats, __u64 current_interval) {
    // Simplified jitter calculation to avoid verifier issues
    if (stats->last_seen_ns == 0) return 0;
    
    __u64 last_interval = stats->pkt_intervals[0]; // Just use the last interval
    if (last_interval == 0) return 0;
    
    __u64 diff = current_interval > last_interval ? 
                current_interval - last_interval : 
                last_interval - current_interval;
    
    return (__u32)(diff / 1000); // Convert to microseconds
}

// Update TCP connection state and calculate handshake latency
static __always_inline void update_tcp_connection(struct flow_key *key, struct tcphdr *tcph, 
                                                 __u64 timestamp, struct flow_stats_nf *stats) {
    __u8 flags = ((__u8 *)tcph)[13];
    __u32 seq = __builtin_bswap32(tcph->seq);
    __u32 ack = __builtin_bswap32(tcph->ack_seq);
    
    struct tcp_connection *conn = bpf_map_lookup_elem(&tcp_connections, key);
    
    if (flags & 0x02) { // SYN flag
        if (!(flags & 0x10)) { // SYN without ACK (initial SYN)
            struct tcp_connection new_conn = {
                .seq_syn = seq,
                .syn_timestamp = timestamp,
                .state = 1 // syn_sent
            };
            bpf_map_update_elem(&tcp_connections, key, &new_conn, BPF_ANY);
            stats->syn_timestamp = timestamp;
        } else if (conn && conn->state == 1) { // SYN-ACK
            conn->seq_syn_ack = seq;
            conn->ack_syn_ack = ack;
            conn->syn_ack_timestamp = timestamp;
            conn->state = 2; // syn_received
            stats->syn_ack_timestamp = timestamp;
        }
    } else if ((flags & 0x10) && conn && conn->state == 2) { // Final ACK
        if (ack == conn->seq_syn_ack + 1) {
            stats->ack_timestamp = timestamp;
            stats->handshake_latency_us = (__u32)((timestamp - conn->syn_timestamp) / 1000);
            conn->state = 3; // established
            bpf_map_delete_elem(&tcp_connections, key); // Clean up
        }
    }
}

// Detect retransmissions and update counters
static __always_inline void detect_retransmissions(struct flow_stats_nf *stats, struct tcphdr *tcph, __u64 timestamp) {
    __u32 seq = __builtin_bswap32(tcph->seq);
    __u8 flags = ((__u8 *)tcph)[13];
    
    if (stats->last_seq != 0) {
        // Check for retransmission (same or older sequence number)
        if (seq <= stats->last_seq && (flags & 0x08)) { // PSH flag indicates data
            stats->retransmissions++;
            
            // Distinguish between fast retransmit and timeout retransmit
            __u64 time_diff = timestamp - stats->last_seq_timestamp;
            if (time_diff < 200000000) { // < 200ms suggests fast retransmit
                stats->fast_retransmits++;
            } else {
                stats->timeout_retransmits++;
            }
        }
        
        // Check for out-of-order packets
        if (seq > stats->last_seq + 1460) { // Assuming standard MSS
            stats->out_of_order_pkts++;
        }
    }
    
    if (seq > stats->last_seq) {
        stats->last_seq = seq;
        stats->last_seq_timestamp = timestamp;
    }
}

// Update window size metrics
static __always_inline void update_window_metrics(struct flow_stats_nf *stats, struct tcphdr *tcph) {
    __u16 window = __builtin_bswap16(tcph->window);
    
    if (stats->last_window_size == 0) {
        stats->min_window_size = window;
        stats->max_window_size = window;
    } else {
        if (window < stats->min_window_size) stats->min_window_size = window;
        if (window > stats->max_window_size) stats->max_window_size = window;
    }
    stats->last_window_size = window;
}

// Update jitter calculations
static __always_inline void update_jitter_metrics(struct flow_stats_nf *stats, __u64 timestamp) {
    if (stats->last_seen_ns != 0) {
        __u64 interval = timestamp - stats->last_seen_ns;
        
        // Simple approach: just store the current interval in the first slot
        stats->pkt_intervals[0] = interval;
        stats->interval_index++;
        
        // Calculate simple jitter
        __u32 jitter = calculate_jitter(stats, interval);
        stats->avg_jitter_us = (stats->avg_jitter_us + jitter) / 2; // Simple average
        if (jitter > stats->max_jitter_us) {
            stats->max_jitter_us = jitter;
        }
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
    
    void *l4_header = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;

    if (iph->protocol == IPPROTO_UDP) {
        udph = (void *)(iph + 1);
        if ((void *)(udph + 1) > data_end) return 0;

        if (__builtin_bswap16(udph->dest) == GENEVE_PORT) {
            void *inner = (void *)(udph + 1) + 8;
            if (!parse_inner_ip(inner, data_end, &key, direction)) return 0;
            key.is_encapsulated = 1;
            
            // For encapsulated traffic, get the inner L4 header
            struct ethhdr *inner_eth = inner;
            if ((void *)(inner_eth + 1) > data_end) return 0;
            if (inner_eth->h_proto == __constant_htons(ETH_P_IP)) {
                struct iphdr *inner_iph = (void *)(inner_eth + 1);
                if ((void *)(inner_iph + 1) <= data_end) {
                    l4_header = (void *)(inner_iph + 1);
                    if (inner_iph->protocol == IPPROTO_TCP) {
                        tcph = l4_header;
                    }
                }
            }
        } else {
            // Regular UDP packet
            key.inner_src_ip = iph->saddr;
            key.inner_dst_ip = iph->daddr;
            key.inner_proto = iph->protocol;
            key.direction = direction;
            key.is_encapsulated = 0;
            key.inner_src_port = udph->source;
            key.inner_dst_port = udph->dest;
            l4_header = udph;
        }
    } else {
        key.inner_src_ip = iph->saddr;
        key.inner_dst_ip = iph->daddr;
        key.inner_proto = iph->protocol;
        key.direction = direction;
        key.is_encapsulated = 0;

        l4_header = (void *)(iph + 1);
        if (iph->protocol == IPPROTO_TCP) {
            tcph = l4_header;
            if ((void *)(tcph + 1) > data_end) return 0;
            key.inner_src_port = tcph->source;
            key.inner_dst_port = tcph->dest;
        } else if (iph->protocol == IPPROTO_UDP) {
            udph = l4_header;
            if ((void *)(udph + 1) > data_end) return 0;
            key.inner_src_port = udph->source;
            key.inner_dst_port = udph->dest;
        } else return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 pkt_len = data_end - data;

    struct flow_stats_nf *stats = bpf_map_lookup_elem(&flow_table, &key);
    if (stats) {
        stats->packets++;
        stats->bytes += pkt_len;
        
        // Update jitter metrics
        update_jitter_metrics(stats, now);
        stats->last_seen_ns = now;
        
        __u8 flags = 0;
        parse_tcp_flags(l4_header, data_end, &flags, key.inner_proto);
        stats->tcp_flags |= flags;
        
        // Enhanced TCP metrics collection
        if (key.inner_proto == IPPROTO_TCP && tcph && (void *)(tcph + 1) <= data_end) {
            // Update TCP connection state and handshake latency
            update_tcp_connection(&key, tcph, now, stats);
            
            // Detect retransmissions
            detect_retransmissions(stats, tcph, now);
            
            // Update window size metrics
            update_window_metrics(stats, tcph);
            
            // Extract ECN flags from IP header
            stats->ecn_flags |= (iph->tos & 0x03);
            
            // Count duplicate ACKs
            __u8 tcp_flags = ((__u8 *)tcph)[13];
            if ((tcp_flags & 0x10) && !(tcp_flags & 0x08)) { // ACK without PSH
                __u32 ack = __builtin_bswap32(tcph->ack_seq);
                static __u32 last_ack = 0;
                static __u8 dup_ack_count = 0;
                
                if (ack == last_ack) {
                    dup_ack_count++;
                    if (dup_ack_count >= 3) {
                        stats->duplicate_acks++;
                        dup_ack_count = 0;
                    }
                } else {
                    last_ack = ack;
                    dup_ack_count = 0;
                }
            }
        }
    } else {
        // Initialize new flow with comprehensive metrics
        struct flow_stats_nf s = {};
        s.packets = 1;
        s.bytes = pkt_len;
        s.start_ns = now;
        s.last_seen_ns = now;
        s.tcp_flags = 0;
        s.min_rtt_us = 0xFFFFFFFF; // Initialize to max value
        s.min_window_size = 0xFFFF; // Initialize to max value
        
        parse_tcp_flags(l4_header, data_end, &s.tcp_flags, key.inner_proto);
        
        // Initialize TCP-specific metrics
        if (key.inner_proto == IPPROTO_TCP && tcph && (void *)(tcph + 1) <= data_end) {
            update_tcp_connection(&key, tcph, now, &s);
            update_window_metrics(&s, tcph);
            s.ecn_flags = (iph->tos & 0x03);
        }
        
        bpf_map_update_elem(&flow_table, &key, &s, BPF_ANY);

        // Send flow event with metrics
        struct flow_event *ev = bpf_ringbuf_reserve(&flow_ring, sizeof(*ev), 0);
        if (ev) {
            ev->key = key;
            ev->timestamp_ns = now;
            ev->metrics = s;
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

// Note: Netfilter eBPF integration requires more complex setup and kernel support
// For now, focusing on XDP and TC programs which provide comprehensive flow monitoring
// Netfilter verdict tracking can be added through userspace integration with iptables logs
// or through other eBPF mechanisms when kernel support is available

char LICENSE[] SEC("license") = "GPL";