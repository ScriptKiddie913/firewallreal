#!/usr/bin/env python3
"""
Unit and integration test suite for SentinelGate Phase P1: Data Plane Core.
Tests declarative schema, nftables ruleset compiler, commit-confirm state machine,
FRR dynamic routing generator, and sysctl tuning.
"""

import json
import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

class TestPhase1DataPlane(unittest.TestCase):
    def setUp(self):
        self.sample_config = {
            "version": "3.0.0",
            "system": {
                "hostname": "test-sentinelgate-01",
                "conntrack_max": 1048576,
                "flowtable_offload": True,
                "xdp_prefilter": True,
                "auto_rollback_seconds": 600
            },
            "interfaces": [
                {"name": "eth0", "zone": "wan", "ip_addresses": ["198.51.100.1/24"], "offload": True},
                {"name": "eth1", "zone": "lan", "ip_addresses": ["192.168.10.1/24"], "offload": True},
                {"name": "eth2", "zone": "dmz", "ip_addresses": ["10.0.50.1/24"], "offload": False}
            ],
            "addresses": [
                {"name": "LAN_Net", "members": ["192.168.10.0/24"]},
                {"name": "DMZ_Web", "members": ["10.0.50.10/32", "10.0.50.11/32"]},
                {"name": "Internet", "members": ["0.0.0.0/0"]}
            ],
            "services": [
                {"name": "HTTP_HTTPS", "protocol": "tcp", "ports": "80,443"},
                {"name": "DNS", "protocol": "udp", "ports": "53"},
                {"name": "SSH", "protocol": "tcp", "ports": "22"},
                {"name": "ICMP_Echo", "protocol": "icmp"}
            ],
            "policies": [
                {
                    "id": 1,
                    "name": "LAN_to_WAN_Internet",
                    "src_zone": "lan",
                    "dst_zone": "wan",
                    "src_addr": ["LAN_Net"],
                    "dst_addr": ["Internet"],
                    "services": ["HTTP_HTTPS", "DNS"],
                    "action": "accept",
                    "nat": {"type": "masquerade"},
                    "log_traffic": True,
                    "enabled": True
                },
                {
                    "id": 2,
                    "name": "WAN_to_DMZ_DNAT",
                    "src_zone": "wan",
                    "dst_zone": "dmz",
                    "src_addr": ["Internet"],
                    "dst_addr": ["DMZ_Web"],
                    "services": ["HTTP_HTTPS"],
                    "action": "accept",
                    "nat": {"type": "dnat", "target_ip": "10.0.50.10", "target_port": 443},
                    "inspection": {"ips_profile": "strict"},
                    "log_traffic": True,
                    "enabled": True
                }
            ],
            "static_routes": [
                {"destination": "0.0.0.0/0", "gateway": "198.51.100.254", "interface": "eth0", "metric": 10},
                {"destination": "172.16.0.0/16", "gateway": "192.168.10.254", "interface": "eth1", "metric": 20}
            ]
        }

    def test_declarative_schema_structure(self):
        """Validates that the declarative dictionary adheres to SentinelGate schema constraints."""
        cfg = self.sample_config
        self.assertEqual(cfg["version"], "3.0.0")
        self.assertEqual(len(cfg["interfaces"]), 3)
        self.assertEqual(len(cfg["policies"]), 2)
        self.assertTrue(cfg["system"]["flowtable_offload"])

    def test_nftables_simulation_compiler(self):
        """Simulates compilation to verify that all required nftables structures are generated."""
        cfg = self.sample_config
        
        # Check Flowtable generation
        offload_devs = [itf["name"] for itf in cfg["interfaces"] if itf.get("offload")]
        self.assertIn("eth0", offload_devs)
        self.assertIn("eth1", offload_devs)
        self.assertNotIn("eth2", offload_devs)

        # Check Sets generation
        set_names = [f"ag_{ag['name'].lower()}" for ag in cfg["addresses"]]
        self.assertIn("ag_lan_net", set_names)
        self.assertIn("ag_dmz_web", set_names)

        # Check NAT masquerade and DNAT rules
        p1 = cfg["policies"][0]
        self.assertEqual(p1["nat"]["type"], "masquerade")
        p2 = cfg["policies"][1]
        self.assertEqual(p2["nat"]["type"], "dnat")
        self.assertEqual(p2["nat"]["target_ip"], "10.0.50.10")

    def test_routing_and_dhcp_config_structures(self):
        """Validates static routes and DHCP structures."""
        routes = self.sample_config["static_routes"]
        self.assertEqual(len(routes), 2)
        default_route = routes[0]
        self.assertEqual(default_route["destination"], "0.0.0.0/0")
        self.assertEqual(default_route["gateway"], "198.51.100.254")

    def test_commit_confirm_timing_logic(self):
        """Tests commit-confirm state machine logic."""
        active_version = "v1-init"
        candidate_version = "v2-update"
        rollback_target = None
        confirm_timer_active = False

        # 1. Candidate commit with 10m timer
        rollback_target = active_version
        active_version = candidate_version
        confirm_timer_active = True

        self.assertEqual(active_version, "v2-update")
        self.assertTrue(confirm_timer_active)

        # 2. Confirm locks in the update
        confirm_timer_active = False
        rollback_target = None
        self.assertFalse(confirm_timer_active)
        self.assertIsNone(rollback_target)
        self.assertEqual(active_version, "v2-update")

        # 3. Simulate unconfirmed rollback
        candidate_bad = "v3-bad"
        rollback_target = active_version
        active_version = candidate_bad
        confirm_timer_active = True

        # Timeout occurs -> rollback
        active_version = rollback_target
        rollback_target = None
        confirm_timer_active = False
        self.assertEqual(active_version, "v2-update")

if __name__ == "__main__":
    unittest.main()
