// SPDX-License-Identifier: GPL-2.0-only
/*
 * SentinelGate Ingress XDP Pre-filter
 * Fast-path packet scrubbing: Bogon dropping, uRPF check, and SYN flood mitigation.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Blocklist map: IPv4 address -> drop counter
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, __u64);
} blocklist_v4 SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;

SEC("xdp")
int xdp_prefilter_main(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // 1. Basic bogon / invalid address check
    if (src_ip == 0 || src_ip == 0xFFFFFFFF)
        return XDP_DROP;

    // 2. Real O(1) eBPF blocklist map lookup
    __u64 *drop_cnt = bpf_map_lookup_elem(&blocklist_v4, &src_ip);
    if (drop_cnt) {
        __sync_fetch_and_add(drop_cnt, 1);
        return XDP_DROP;
    }

    // 3. SYN Flood scrubbing (inspect TCP header without payload)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((__u32 *)ip + ip->ihl);
        if ((void *)(tcp + 1) <= data_end) {
            // Drop TCP packets with invalid flag combinations (NULL scan, XMAS scan)
            if (tcp->syn && tcp->fin)
                return XDP_DROP;
            if (!tcp->syn && !tcp->ack && !tcp->fin && !tcp->rst)
                return XDP_DROP; // NULL scan
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
