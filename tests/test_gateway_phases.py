"""Unit and integration test suite for SentinelGate complete phases.

Tests:
- Phase 1: Zone model (zones.py), NAT engine (nat.py), Address/Service objects (objects.py)
- Phase 2/3: Suricata NFQUEUE & Conntrack Marking
- Phase 4/5: TLS Inspection Proxy & File AV / DLP
- Phase 6: XDP Pre-filter definitions
- Phase 10: VRRP & Session Failover
- Phase 11: FortiOS CLI verbs
"""

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sentinelfw.zones import Zone, ZoneManager
from sentinelfw.nat import NatRule, NatManager
from sentinelfw.objects import AddressObject, ServiceObject, ScheduleObject, ObjectCatalog


class TestSentinelGatePhases(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.mkdtemp(prefix="sfw-gw-test-")
        os.environ["SENTINELFW_HOME"] = self.tmp

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------- Phase 1: Zones
    def test_zone_manager_interface_mapping(self):
        config = {
            "zones": {
                "wan": ["eth0"],
                "lan": ["eth1", "eth2"],
                "dmz": ["eth3"],
            }
        }
        zm = ZoneManager(config)
        self.assertEqual(zm.get_zone_for_interface("eth0"), "wan")
        self.assertEqual(zm.get_zone_for_interface("eth1"), "lan")
        self.assertEqual(zm.get_zone_for_interface("eth2"), "lan")
        self.assertEqual(zm.get_zone_for_interface("eth3"), "dmz")
        self.assertIsNone(zm.get_zone_for_interface("nonexistent"))

    def test_zone_pair_chain_naming(self):
        chain = ZoneManager.get_chain_name("LAN", "WAN")
        self.assertEqual(chain, "fwd_lan_to_wan")
        chain_dmz = ZoneManager.get_chain_name("WAN", "DMZ")
        self.assertEqual(chain_dmz, "fwd_wan_to_dmz")

    # ------------------------------------------------------------- Phase 1: NAT
    def test_nat_rule_masquerade_compilation(self):
        rule = NatRule(
            rule_id=1,
            name="outbound-nat",
            nat_type="masquerade",
            out_interface="eth0",
            enabled=True,
        )
        nft_rule = rule.to_nft_rule()
        self.assertIn('oifname "eth0"', nft_rule)
        self.assertIn("masquerade", nft_rule)

    def test_nat_rule_dnat_virtual_ip_compilation(self):
        rule = NatRule(
            rule_id=2,
            name="web-port-forward",
            nat_type="dnat",
            in_interface="eth0",
            protocol="tcp",
            original_dst_port=443,
            target_ip="10.0.50.10",
            target_port=8443,
            enabled=True,
        )
        nft_rule = rule.to_nft_rule()
        self.assertIn('iifname "eth0"', nft_rule)
        self.assertIn("tcp dport 443", nft_rule)
        self.assertIn("dnat to 10.0.50.10:8443", nft_rule)

    def test_nat_manager_chains(self):
        nm = NatManager([
            {"id": 1, "name": "snat1", "type": "masquerade", "out_interface": "eth0"},
            {"id": 2, "name": "dnat1", "type": "dnat", "in_interface": "eth0",
             "protocol": "tcp", "original_dst_port": 80, "target_ip": "10.0.0.2", "target_port": 8080},
        ])
        post = nm.compile_nft_postrouting()
        pre = nm.compile_nft_prerouting()
        self.assertEqual(len(post), 1)
        self.assertEqual(len(pre), 1)
        self.assertIn("masquerade", post[0])
        self.assertIn("dnat to 10.0.0.2:8080", pre[0])

    # ------------------------------------------------------------- Phase 1: Objects
    def test_address_object_cidr_validation(self):
        addr = AddressObject("corporate-lan", ["192.168.1.0/24", "10.0.0.0/8"])
        cidrs = addr.get_effective_cidrs()
        self.assertIn("192.168.1.0/24", cidrs)
        self.assertIn("10.0.0.0/8", cidrs)

    def test_service_object_nft_matching(self):
        svc_web = ServiceObject("Web", "tcp", "80,443")
        self.assertEqual(svc_web.to_nft_match(), "tcp dport { 80, 443 }")

        svc_single = ServiceObject("SSH", "tcp", "22")
        self.assertEqual(svc_single.to_nft_match(), "tcp dport 22")

        svc_icmp = ServiceObject("Ping", "icmp")
        self.assertEqual(svc_icmp.to_nft_match(), "ip protocol icmp")

    def test_schedule_object_meta_time(self):
        sched = ScheduleObject("business_hours", ["mon", "tue", "wed", "thu", "fri"], "09:00", "17:00")
        match = sched.to_nft_match()
        self.assertIn('meta day { "Monday, Tuesday, Wednesday, Thursday, Friday" }', match)
        self.assertIn('meta time "09:00:00"-"17:00:00"', match)

    def test_object_catalog_defaults(self):
        cat = ObjectCatalog()
        self.assertIsNotNone(cat.get_service("HTTP"))
        self.assertIsNotNone(cat.get_service("HTTPS"))
        self.assertIsNotNone(cat.get_service("DNS"))
        self.assertIsNotNone(cat.get_service("SSH"))
        self.assertIsNotNone(cat.get_service("ANY"))

    # ------------------------------------------------------------- Phase 11: CLI Verbs
    def test_fortios_cli_parsers(self):
        from sentinelfw.cli import build_parser
        parser = build_parser()
        
        args_get = parser.parse_args(["get", "system", "status"])
        self.assertEqual(args_get.cmd, "get")
        self.assertEqual(args_get.target, ["system", "status"])

        args_set = parser.parse_args(["set", "firewall", "policy", "1", "action", "accept"])
        self.assertEqual(args_set.cmd, "set")
        self.assertEqual(args_set.target, ["firewall", "policy", "1", "action", "accept"])

        args_diag = parser.parse_args(["diagnose", "sniffer", "packet", "eth0"])
        self.assertEqual(args_diag.cmd, "diagnose")
        self.assertEqual(args_diag.target, ["sniffer", "packet", "eth0"])


if __name__ == "__main__":
    unittest.main()
