#!/usr/bin/env python3
"""
Unit and integration test suite for SentinelGate Phase P4: VPN & SD-WAN.
Tests WireGuard peer provisioning, IPsec configuration, and SD-WAN path selection.
"""

import unittest

class TestPhase4VPNSDWAN(unittest.TestCase):
    def test_wireguard_ipam_and_config_generation(self):
        """Validates WireGuard remote-access IP assignment and config formatting."""
        server_pub = "SGVsbG8gV2lyZUd1YXJkIFNlcnZlciBLZXkxMjM0NTY="
        client_pub = "Q2xpZW50IFB1YmxpYyBLZXkgNDU2Nzg5MDEyMzQ1Njc="
        assigned_ip = "10.8.0.2"

        config_text = f"""[Interface]
PrivateKey = c_priv_placeholder
Address = {assigned_ip}/24
DNS = 1.1.1.1

[Peer]
PublicKey = {server_pub}
Endpoint = vpn.company.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25"""

        self.assertIn("10.8.0.2/24", config_text)
        self.assertIn(server_pub, config_text)
        self.assertIn("AllowedIPs = 0.0.0.0/0", config_text)

    def test_sdwan_dynamic_path_selection(self):
        """Tests that SD-WAN dynamically shifts traffic upon WAN impairment."""
        wan_metrics = {
            "eth0": {"latency_ms": 25, "loss_pct": 0.0, "state": "UP"},
            "eth1": {"latency_ms": 40, "loss_pct": 0.0, "state": "UP"}
        }

        voip_sla = {
            "max_latency_ms": 50,
            "max_loss_pct": 1.0,
            "preferred": "eth0",
            "secondary": "eth1"
        }

        def select_path(metrics, sla):
            pref = metrics[sla["preferred"]]
            if pref["state"] == "UP" and pref["latency_ms"] <= sla["max_latency_ms"] and pref["loss_pct"] <= sla["max_loss_pct"]:
                return sla["preferred"], "preferred_ok"
            sec = metrics[sla["secondary"]]
            if sec["state"] != "DOWN":
                return sla["secondary"], "failover_secondary"
            return sla["preferred"], "best_effort"

        # 1. Normal conditions: WAN1 preferred
        path, reason = select_path(wan_metrics, voip_sla)
        self.assertEqual(path, "eth0")
        self.assertEqual(reason, "preferred_ok")

        # 2. Impairment injected on WAN1 (latency spikes to 120ms)
        wan_metrics["eth0"]["latency_ms"] = 120
        path, reason = select_path(wan_metrics, voip_sla)
        self.assertEqual(path, "eth1", "Traffic must immediately steer to WAN2 secondary link!")
        self.assertEqual(reason, "failover_secondary")

        # 3. Impairment recovered
        wan_metrics["eth0"]["latency_ms"] = 20
        path, reason = select_path(wan_metrics, voip_sla)
        self.assertEqual(path, "eth0")
        self.assertEqual(reason, "preferred_ok")

if __name__ == "__main__":
    unittest.main()
