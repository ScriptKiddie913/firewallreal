"""Tests for SentinelFW configuration migration across policy versions."""
import json
import pytest
from pathlib import Path
from sentinelfw import config, common


def test_migrate_from_version_1(tmp_path, monkeypatch):
    """Test migration from legacy version 1 to demote destructive process-killing actions."""
    home = tmp_path / "sfw_home1"
    monkeypatch.setattr(common, "HOME", home)
    monkeypatch.setattr(config, "HOME", home)
    monkeypatch.setattr(common, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(config, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(common, "LISTS", home / "lists")
    monkeypatch.setattr(config, "LISTS", home / "lists")
    monkeypatch.setattr(common, "QUAR", home / "quarantine")
    monkeypatch.setattr(config, "QUAR", home / "quarantine")

    home.mkdir(parents=True, exist_ok=True)
    legacy_cfg = {
        "policy_version": 1,
        "actions": {
            "blocklisted_ip_connection": "kill+file",
            "blocked_port_connection": "kill"
        }
    }
    (home / "config.json").write_text(json.dumps(legacy_cfg, indent=2), encoding="utf-8")

    store = config.Store()
    assert store.cfg["policy_version"] == 10
    # Process killing actions demoted
    assert store.cfg["actions"]["blocklisted_ip_connection"] == "alert"
    assert store.cfg["actions"]["blocked_port_connection"] == "alert"


def test_migrate_from_version_7_and_8(tmp_path, monkeypatch):
    """Test migration from legacy version 7/8 (2.9 era) to version 10."""
    home = tmp_path / "sfw_home"
    monkeypatch.setattr(common, "HOME", home)
    monkeypatch.setattr(config, "HOME", home)
    monkeypatch.setattr(common, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(config, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(common, "LISTS", home / "lists")
    monkeypatch.setattr(config, "LISTS", home / "lists")
    monkeypatch.setattr(common, "QUAR", home / "quarantine")
    monkeypatch.setattr(config, "QUAR", home / "quarantine")

    home.mkdir(parents=True, exist_ok=True)
    legacy_cfg = {
        "policy_version": 7,
        "actions": {
            "blocklisted_ip_connection": "alert",
            "blocked_port_connection": "alert"
        },
        "webui": {
            "username": "sotanikai",
            "password_hash": "5912bf81c5053cf577f68fc4466b115f50ca6c71638ca26e746978f15881436c",
            "password_initialized": True
        }
    }
    (home / "config.json").write_text(json.dumps(legacy_cfg, indent=2), encoding="utf-8")

    store = config.Store()
    assert store.cfg["policy_version"] == 10
    # Legacy default hash wiped
    assert store.cfg["webui"]["password_hash"] == ""
    assert store.cfg["webui"]["password_initialized"] is False
    # Integrations auto_install safe default
    assert store.cfg["integrations"]["auto_install"] is False
    # 4.0 modules populated
    assert "waf" in store.cfg
    assert store.cfg["waf"]["enabled"] is True
    assert "dlp" in store.cfg
    assert "identity" in store.cfg
    assert "microsegmentation" in store.cfg
    assert "ztna" in store.cfg
    assert "wireguard" in store.cfg
    assert "otlp" in store.cfg

    # Verify persisted to disk
    persisted = json.loads((home / "config.json").read_text(encoding="utf-8"))
    assert persisted["policy_version"] == 10
    assert persisted["actions"]["blocklisted_ip_connection"] == "alert"


def test_migrate_from_version_9(tmp_path, monkeypatch):
    """Test migration from version 9 (3.0 era) to version 10 (4.0)."""
    home = tmp_path / "sfw_home"
    monkeypatch.setattr(common, "HOME", home)
    monkeypatch.setattr(config, "HOME", home)
    monkeypatch.setattr(common, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(config, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(common, "LISTS", home / "lists")
    monkeypatch.setattr(config, "LISTS", home / "lists")
    monkeypatch.setattr(common, "QUAR", home / "quarantine")
    monkeypatch.setattr(config, "QUAR", home / "quarantine")

    home.mkdir(parents=True, exist_ok=True)
    v9_cfg = {
        "policy_version": 9,
        "trusted_ips": ["10.0.0.0/8"],
        "webui": {
            "username": "custom_admin",
            "password_hash": "scrypt$customhash",
            "password_initialized": True
        }
    }
    (home / "config.json").write_text(json.dumps(v9_cfg, indent=2), encoding="utf-8")

    store = config.Store()
    assert store.cfg["policy_version"] == 10
    # Custom password and admin preserved
    assert store.cfg["webui"]["username"] == "custom_admin"
    assert store.cfg["webui"]["password_hash"] == "scrypt$customhash"
    assert store.cfg["webui"]["password_initialized"] is True
    # 4.0 sections added
    assert store.cfg["waf"]["enabled"] is True
    assert store.cfg["dlp"]["action"] == "alert"
    assert store.cfg["microsegmentation"]["mode"] == "learning"

    persisted = json.loads((home / "config.json").read_text(encoding="utf-8"))
    assert persisted["policy_version"] == 10
    assert persisted["webui"]["username"] == "custom_admin"


def test_clean_version_10_no_migration_needed(tmp_path, monkeypatch):
    """Test loading a clean policy_version 10 configuration requires no writes."""
    home = tmp_path / "sfw_home"
    monkeypatch.setattr(common, "HOME", home)
    monkeypatch.setattr(config, "HOME", home)
    monkeypatch.setattr(common, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(config, "CONFIG_FILE", home / "config.json")
    monkeypatch.setattr(common, "LISTS", home / "lists")
    monkeypatch.setattr(config, "LISTS", home / "lists")
    monkeypatch.setattr(common, "QUAR", home / "quarantine")
    monkeypatch.setattr(config, "QUAR", home / "quarantine")

    home.mkdir(parents=True, exist_ok=True)
    clean_cfg = dict(config.DEFAULT_CONFIG)
    clean_cfg["policy_version"] = 10
    (home / "config.json").write_text(json.dumps(clean_cfg, indent=2), encoding="utf-8")

    store = config.Store()
    assert store.cfg["policy_version"] == 10
    assert store._write_back is False
