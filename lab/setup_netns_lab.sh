#!/usr/bin/env bash
# SentinelGate Network Namespaces Virtual Lab Harness
# Simulates a full 3-zone gateway environment without Docker/Containerlab dependencies.

set -euo pipefail

NS_WAN="sg-wan"
NS_GW="sg-gw"
NS_LAN="sg-lan"

function lab_up() {
    echo "==> Creating network namespaces: $NS_WAN, $NS_GW, $NS_LAN..."
    ip netns add "$NS_WAN" 2>/dev/null || true
    ip netns add "$NS_GW" 2>/dev/null || true
    ip netns add "$NS_LAN" 2>/dev/null || true

    echo "==> Creating virtual ethernet (veth) pairs..."
    ip link add veth-wan type veth peer name veth-gw-wan 2>/dev/null || true
    ip link add veth-lan type veth peer name veth-gw-lan 2>/dev/null || true

    echo "==> Assigning interfaces to namespaces..."
    ip link set veth-wan netns "$NS_WAN"
    ip link set veth-gw-wan netns "$NS_GW"
    ip link set veth-lan netns "$NS_LAN"
    ip link set veth-gw-lan netns "$NS_GW"

    echo "==> Configuring WAN zone (198.51.100.0/24)..."
    ip -n "$NS_WAN" addr add 198.51.100.10/24 dev veth-wan
    ip -n "$NS_WAN" link set veth-wan up
    ip -n "$NS_WAN" link set lo up
    ip -n "$NS_WAN" route add 192.168.10.0/24 via 198.51.100.1

    echo "==> Configuring LAN zone (192.168.10.0/24)..."
    ip -n "$NS_LAN" addr add 192.168.10.50/24 dev veth-lan
    ip -n "$NS_LAN" link set veth-lan up
    ip -n "$NS_LAN" link set lo up
    ip -n "$NS_LAN" route add default via 192.168.10.1

    echo "==> Configuring SentinelGate appliance (IP forwarding)..."
    ip -n "$NS_GW" addr add 198.51.100.1/24 dev veth-gw-wan
    ip -n "$NS_GW" addr add 192.168.10.1/24 dev veth-gw-lan
    ip -n "$NS_GW" link set veth-gw-wan up
    ip -n "$NS_GW" link set veth-gw-lan up
    ip -n "$NS_GW" link set lo up
    ip netns exec "$NS_GW" sysctl -w net.ipv4.ip_forward=1 >/dev/null

    echo "==> Virtual lab successfully configured!"
    echo "    WAN Tester: 198.51.100.10 (netns: $NS_WAN)"
    echo "    SentinelGate: WAN=198.51.100.1, LAN=192.168.10.1 (netns: $NS_GW)"
    echo "    LAN Client: 192.168.10.50 (netns: $NS_LAN)"
}

function lab_down() {
    echo "==> Tearing down network namespaces..."
    ip netns delete "$NS_WAN" 2>/dev/null || true
    ip netns delete "$NS_GW" 2>/dev/null || true
    ip netns delete "$NS_LAN" 2>/dev/null || true
    echo "==> Lab cleaned up successfully."
}

function lab_status() {
    echo "==> Network Namespaces Status:"
    ip netns list
}

case "${1:-status}" in
    up)
        lab_up
        ;;
    down)
        lab_down
        ;;
    status)
        lab_status
        ;;
    *)
        echo "Usage: $0 {up|down|status}"
        exit 1
        ;;
esac
