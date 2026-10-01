"""Comprehensive test suite for SentinelFW Phases 27 through 32:
- Phase 27: Defense-in-Depth System Hardening (systemd units, rate limiting, security headers)
- Phase 28: Cryptographic Secrets Management & Vault (sealed storage, key migration, env precedence)
- Phase 29: Multi-Tenancy & Virtual Domains (VDOMs, interface isolation, tenant quotas)
- Phase 30: Versioned REST API & OpenAPI 3.0 Spec
- Phase 31 & 32: Observability, Prometheus metrics, and OpenTelemetry OTLP log exports
"""
import os
import tempfile
import time
from pathlib import Path
import pytest

from sentinelfw.webui import APIRateLimiter, SentinelWebUI, SentinelRequestHandler
from sentinelfw.vault import Vault, KEY_MAPPINGS
from sentinelfw.vdom import VDOMManager, VDOMQuotaExceeded, VDOMInterfaceConflict, VDOMPermissionDenied
from sentinelfw.openapi import generate_openapi_spec
from sentinelfw.analytics import AnalyticsDataLake


def test_systemd_hardening_directives():
    """Verify systemd service unit contains required sandboxing and capability bounding."""
    service_file = Path("systemd/sentinelfw.service")
    assert service_file.exists()
    content = service_file.read_text(encoding="utf-8")
    
    assert "ProtectSystem=strict" in content
    assert "ProtectHome=yes" in content
    assert "NoNewPrivileges=yes" in content
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE" in content
    assert "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE" in content
    assert "PrivateTmp=yes" in content
    assert "ProtectKernelTunables=yes" in content
    assert "ProtectControlGroups=yes" in content


def test_api_rate_limiter():
    """Verify IP sliding-window rate limiting drops requests exceeding threshold."""
    limiter = APIRateLimiter(limit_per_minute=5)
    test_ip = "198.51.100.99"
    
    # First 5 calls allowed
    for _ in range(5):
        assert limiter.is_allowed(test_ip) is True
        
    # 6th call exceeds limit
    assert limiter.is_allowed(test_ip) is False
    
    # Loopback IP is exempted from rate limits
    for _ in range(10):
        assert limiter.is_allowed("127.0.0.1") is True


def test_secrets_vault_lifecycle_and_env_precedence():
    """Verify encrypted vault storage, sealed keys, and environment variable override precedence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.enc"
        v = Vault(vault_path=vault_path)
        
        # Test basic set and get
        v.set("custom_token", "super_secret_payload_123")
        assert v.get("custom_token") == "super_secret_payload_123"
        
        # Verify persistence across vault reload
        v2 = Vault(vault_path=vault_path)
        assert v2.get("custom_token") == "super_secret_payload_123"
        
        # Test env var override taking precedence
        os.environ["SFW_VT_KEY"] = "env_overridden_vt_key"
        try:
            v2.set("vt_api_key", "stored_vault_key")
            assert v2.get("vt_api_key") == "env_overridden_vt_key"
        finally:
            del os.environ["SFW_VT_KEY"]
            
        # After removing env var, stored vault key is returned
        assert v2.get("vt_api_key") == "stored_vault_key"


def test_vdom_creation_interface_isolation_and_quotas():
    """Verify VDOM creation, strict interface exclusivity, and quota enforcement."""
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = Path(tmpdir) / "vdoms.json"
        mgr = VDOMManager(storage_path=storage)
        
        # Default root VDOM exists
        assert mgr.get_vdom("root") is not None
        
        # Create tenant VDOM
        vdom_a = mgr.create_vdom(
            vdom_id="tenant-alpha",
            name="Alpha Corp",
            interfaces=["eth1", "vlan100"],
            quotas={"max_policies": 2, "max_sessions": 1000},
        )
        assert vdom_a.vdom_id == "tenant-alpha"
        assert "eth1" in vdom_a.interfaces
        
        # Interface conflict: another VDOM cannot take eth1
        with pytest.raises(VDOMInterfaceConflict):
            mgr.create_vdom("tenant-beta", "Beta Corp", interfaces=["eth1"])
            
        # Interface lookup resolves correctly
        assert mgr.get_vdom_for_interface("eth1").vdom_id == "tenant-alpha"
        assert mgr.get_vdom_for_interface("unknown_iface").vdom_id == "root"
        
        # Policy quota enforcement
        vdom_a.add_policy({"name": "Rule 1", "action": "allow"})
        vdom_a.add_policy({"name": "Rule 2", "action": "allow"})
        with pytest.raises(VDOMQuotaExceeded):
            vdom_a.add_policy({"name": "Rule 3", "action": "drop"})
            
        # Cross-tenant permission check
        with pytest.raises(VDOMPermissionDenied):
            mgr.get_vdom("tenant-alpha", requesting_tenant="tenant-beta")
            
        # Root can access all tenants
        assert mgr.get_vdom("tenant-alpha", requesting_tenant="root") is not None


def test_openapi_specification_schema():
    """Verify generated OpenAPI 3.0 specification adheres to standard schema."""
    spec = generate_openapi_spec()
    assert spec["openapi"] == "3.0.3"
    assert "info" in spec
    assert "components" in spec
    assert "schemas" in spec["components"]
    assert "PolicyRule" in spec["components"]["schemas"]
    assert "VDOM" in spec["components"]["schemas"]
    
    paths = spec["paths"]
    assert "/policies" in paths
    assert "/bans" in paths
    assert "/vdoms" in paths
    assert "/ztna/evaluate" in paths
    assert "/forensics/incident_bundle" in paths


def test_opentelemetry_otlp_log_export():
    """Verify security event serialization into OpenTelemetry OTLP JSON format."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_file = Path(tmpdir) / "otlp_test.db"
        lake = AnalyticsDataLake(db_path=db_file)
        
        lake.record_event({
            "subsystem": "firewall",
            "event_type": "port_scan",
            "severity": "high",
            "action": "DROP",
            "src_ip": "198.51.100.5",
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "threat_score": 85,
        })
        
        otlp = lake.export_otlp_json()
        assert "resourceLogs" in otlp
        r_logs = otlp["resourceLogs"]
        assert len(r_logs) >= 1
        scope_logs = r_logs[0]["scopeLogs"]
        assert len(scope_logs) >= 1
        records = scope_logs[0]["logRecords"]
        assert len(records) == 1
        assert records[0]["severityText"] == "HIGH"
        assert any(a["key"] == "src.ip" and a["value"]["stringValue"] == "198.51.100.5" for a in records[0]["attributes"])
