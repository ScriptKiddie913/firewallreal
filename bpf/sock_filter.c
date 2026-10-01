// SPDX-License-Identifier: GPL-2.0-only
/*
 * SentinelFW 4.0 Endpoint Socket Filter (cgroup / sock_ops)
 * Enforces per-application network authorization at socket connect/bind time.
 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// BPF helper function prototypes
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) BPF_FUNC_get_current_cgroup_id;

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
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 *action = bpf_map_lookup_elem(&endpoint_sock_policy, &cgroup_id);

    if (action) {
        if (*action == 0) {
            // Explicit drop/block for this cgroup/process
            return 0;
        }
        return 1;
    }

    // Default policy: allow unless explicitly blocked by endpoint security policy
    return 1;
}

char _license[] SEC("license") = "GPL";
