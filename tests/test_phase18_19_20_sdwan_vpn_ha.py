"""Unit and integration tests for:
- Phase 18: Application-Aware SD-WAN Engine
- Phase 19: Enterprise VPN Subsystem (WireGuard & IPsec)
- Phase 20: Active/Passive High Availability (HA)
"""
import time
import pytest
from sentinelfw.sdwan import LinkMetrics, LinkState, SLAPolicy, SDWANPathSelector
from sentinelfw.vpn import WireGuardServer, IPsecConfigGenerator
from sentinelfw.ha import NodeRole, HAClusterConfig, FailoverManager


def test_sdwan_link_metrics_and_sla_path_selection():
    """Verify SLA policy evaluation, link quality states, and dynamic failover."""
    selector = SDWANPathSelector()

    # Link 1: Low latency fiber (healthy)
    wan1 = LinkMetrics("wan1", latency_ms=15.0, jitter_ms=2.0, loss_pct=0.0)
    # Link 2: Backup LTE (higher latency)
    wan2 = LinkMetrics("wan2", latency_ms=90.0, jitter_ms=10.0, loss_pct=0.5)

    selector.register_link(wan1)
    selector.register_link(wan2)

    # 1. VoIP traffic selects preferred low-latency wan1
    path_voip, reason1 = selector.select_path("voip")
    assert path_voip == "wan1"
    assert "preferred_link" in reason1

    # 2. Simulate wan1 degradation (packet loss 5%, latency 180ms)
    selector.update_metrics("wan1", latency_ms=180.0, jitter_ms=35.0, loss_pct=5.0)

    # VoIP traffic now fails over to secondary wan2
    path_failover, reason2 = selector.select_path("voip")
    assert path_failover == "wan2"
    assert "failover" in reason2

    # 3. Simulate total link outage
    selector.update_metrics("wan1", latency_ms=600.0, jitter_ms=50.0, loss_pct=100.0)
    assert selector._links["wan1"].state == LinkState.DOWN


def test_wireguard_server_ipam_and_config_generation():
    """Verify WireGuard client IPAM allocation, peer revocation, and configuration generators."""
    server = WireGuardServer(interface="wg0", port=51820, subnet_cidr="10.8.0.0/24")

    # Add peer 1
    p1 = server.add_peer("alice", public_key="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    assert p1.assigned_ip == "10.8.0.2"

    # Add peer 2
    p2 = server.add_peer("bob", public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    assert p2.assigned_ip == "10.8.0.3"

    # Server config contains both peers
    server_conf = server.generate_server_conf()
    assert "ListenPort = 51820" in server_conf
    assert "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in server_conf
    assert "PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" in server_conf

    # Client profile generation
    client_conf = server.generate_client_conf("alice", client_priv="CLIENT_PRIV_SECRET==")
    assert "Address = 10.8.0.2/24" in client_conf
    assert "Endpoint = vpn.company.com:51820" in client_conf

    # Revoke peer 1
    revoked = server.revoke_peer("alice")
    assert revoked is True
    assert len(server.list_peers()) == 1


def test_ipsec_strongswan_config_generation():
    """Verify strongSwan swanctl.conf generation for site-to-site tunnels."""
    conf = IPsecConfigGenerator.generate_swanctl_conf(
        site_name="Branch-Office-London",
        local_ip="198.51.100.1",
        remote_ip="203.0.113.5",
        local_subnets=["10.0.0.0/16"],
        remote_subnets=["10.20.0.0/16"],
        psk_secret="Enterprise-Site2Site-PSK-Secret-99",
    )
    assert "s2s-branch-office-london" in conf
    assert "local_ts = 10.0.0.0/16" in conf
    assert "remote_ts = 10.20.0.0/16" in conf
    assert "aes256gcm16" in conf


def test_ha_failover_and_split_brain_witness_fencing():
    """Verify VRRP role management, failover promotion, and witness fencing against split-brain."""
    # 1. Primary Master (priority 150)
    cfg_master = HAClusterConfig(priority=150, witness_ip="8.8.8.8")
    fm_master = FailoverManager(cfg_master)
    assert fm_master.role == NodeRole.MASTER

    # 2. Backup Node (priority 100)
    cfg_backup = HAClusterConfig(priority=100, witness_ip="8.8.8.8", failover_timeout=2.0)
    witness_up = True
    fm_backup = FailoverManager(cfg_backup, witness_check_fn=lambda ip: witness_up)
    assert fm_backup.role == NodeRole.BACKUP

    # Normal heartbeat from master keeps backup in BACKUP state
    t_now = 1000.0
    fm_backup.record_peer_heartbeat(peer_priority=150, peer_role=NodeRole.MASTER, timestamp=t_now)
    assert fm_backup.check_health_and_failover(now=t_now + 1.0) == NodeRole.BACKUP

    # 3. Master heartbeat lost: witness reachable -> promote to MASTER
    assert fm_backup.check_health_and_failover(now=t_now + 5.0) == NodeRole.MASTER
    assert len(fm_backup.failover_events) == 1
    assert "promoting to MASTER" in fm_backup.failover_events[-1]["reason"]

    # 4. Split-brain scenario: Heartbeat lost AND witness unreachable -> transition to FAULT
    fm_backup2 = FailoverManager(cfg_backup, witness_check_fn=lambda ip: False)
    fm_backup2.last_peer_heartbeat = t_now
    role_fenced = fm_backup2.check_health_and_failover(now=t_now + 5.0)
    assert role_fenced == NodeRole.FAULT
    assert "fencing" in fm_backup2.failover_events[-1]["reason"]

    # State sync
    fm_master.sync_state(bans=["198.51.100.99"], session_count=1450)
    assert "198.51.100.99" in fm_master.synced_bans
    assert fm_master.synced_sessions == 1450
