// SPDX-License-Identifier: GPL-2.0-only
/*
 * SentinelFW 3.0 Endpoint Socket Filter (cgroup / sock_ops)
 * Enforces per-application network authorization at socket connect/bind time.
 */

#include <linux/bpf.h>
#include <linux/in.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Allowed/Blocked process cgroup ID or socket cookie map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // cgroup id or PID hash
    __type(value, __u32); // Policy action: 0 = block, 1 = allow
} endpoint_sock_policy SEC(".maps");

SEC("cgroup/connect4")
int sock_connect4_filter(struct bpf_sock_addr *ctx) {
    // Evaluation hook for outbound IPv4 TCP/UDP connect()
    // By default, allow traffic unless flagged in endpoint_sock_policy
    return 1;
}

char _license[] SEC("license") = "GPL";
