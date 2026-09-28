"""SentinelFW config module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa


DEFAULT_CONFIG = {
    "never_block": [],
    "protect_private": True,
    "auto_ban_seconds": 86400,
    "monitor_interval": 2.0,
    "sniffer_enabled": True,
    "thresholds": {
        "port_scan_ports": 20, "port_scan_window": 10,
        "syn_flood_rate": 300, "syn_flood_window": 2,
        "brute_force_attempts": 15, "brute_force_window": 30,
        "brute_force_ports": [21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900],
        "icmp_flood_count": 100, "icmp_flood_window": 5,
        "sweep_hosts": 50, "sweep_window": 10,
    },
    "enforcement_profile": "aggressive",
    "exec_watch": True,
    "actions": {
        "blocklisted_ip_connection": "kill",
        "blocked_program": "kill+file",
        "malicious_hash": "kill+file",
        "temp_dir_network": "kill+file",
        "deleted_executable": "kill",
        "blocked_port_connection": "kill",
    },
    "malicious_file_action": "quarantine",
    "quarantine_retention_days": 7,
    "blocked_remote_ports": [],
    "suspicious_dirs": {
        "linux": ["/tmp/", "/dev/shm/", "/var/tmp/"],
        "windows": ["\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"],
    },
    "payload_signatures": [
        {"name": "path_traversal", "regex": "(?:\\.\\./){3,}|(?:%2e%2e%2f){2,}|(?:%252e%252e%252f){2,}"},
        {"name": "sql_injection_union", "regex": "(?i)union(?:\\s|%20|\\+)+(?:all\\s+)?select"},
        {"name": "sql_injection_blind", "regex": "(?i)(?:sleep\\s*\\(\\s*\\d+\\s*\\)|benchmark\\s*\\(\\s*\\d+|waitfor\\s+delay)"},
        {"name": "sql_injection_quotes", "regex": "(?i)(?:'|%27)(?:\\s|%20|\\+)*(?:or|and)(?:\\s|%20|\\+)*\\d+=\\d+"},
        {"name": "shellshock", "regex": "\\(\\)\\s*\\{\\s*:;\\s*\\}\\s*;"},
        {"name": "log4shell", "regex": "(?i)\\$\\{(?:lower:|upper:)?jndi:(?:ldap|ldaps|rmi|dns)://"},
        {"name": "spring4shell", "regex": "(?i)(?:class\\.module\\.classLoader|class\\[\"module\"\\])"},
        {"name": "proxylogon", "regex": "(?i)/owa/auth/x\\.js"},
        {"name": "proxyshell", "regex": "(?i)/autodiscover/autodiscover\\.json\\?.*(?:@|%40).*powershell"},
        {"name": "moveit_rce", "regex": "(?i)/human\\.aspx"},
        {"name": "citrix_bleed", "regex": "(?i)/oauth/idp/.*(?:logout|init)"},
        {"name": "etc_passwd_read", "regex": "(?:/etc/passwd|/etc/shadow|/etc/hosts)"},
        {"name": "cmd_injection_pipes", "regex": "(?:;|\\|\\||&&|`|\\$\\()\\s*(?:cat|ls|id|whoami|uname|curl|wget|bash|sh|nc|powershell|cmd\\.exe)\\b"},
        {"name": "xss_script_tags", "regex": "(?i)<script[\\s>].*?</script.*?>"},
        {"name": "xss_onerror", "regex": "(?i)(?:onerror|onload|onclick|onmouseover)\\s*="},
        {"name": "xxe_injection", "regex": "(?i)<!ENTITY\\s+.*?SYSTEM\\s+[\"'](?:file|http|ftp)://"},
        {"name": "php_eval_system", "regex": "(?i)(?:eval|system|passthru|shell_exec|exec|popen)\\s*\\(\\s*(?:\\$_GET|\\$_POST|\\$_REQUEST|base64_decode)"},
        {"name": "php_webshell", "regex": "(?i)(?:c99shell|r57shell|wso\\s*version|b374k|alfa\\s*team)"},
        {"name": "ssti_template", "regex": "(?:\\{\\{.*?__class__.*?\\}\\}|\\$\\{.*?java\\.lang\\.Runtime.*\\})"},
        {"name": "struts_rce", "regex": "(?i)multipart/form-data;\\s*boundary=.*?(?:#_memberAccess|ognl\\.OgnlContext)"},
        {"name": "exchange_ssrf", "regex": "(?i)/ecp/.*ExchangeServer"},
        {"name": "web_admin_probe", "regex": "(?i)(?:/wp-config\\.php|/\\.env|/\\.git/HEAD|/phpmyadmin/scripts/setup\\.php)"},
        {"name": "powershell_download", "regex": "(?i)(?:powershell(?:\\.exe)?|pwsh)\\s+.*?(?:-enc|-encodedcommand|downloadstring|invoke-webrequest|iex)"},
        {"name": "certutil_download", "regex": "(?i)certutil(?:\\.exe)?\\s+.*?-urlcache"},
        {"name": "bitsadmin_download", "regex": "(?i)bitsadmin(?:\\.exe)?\\s+.*?/transfer"},
        {"name": "ftp_bounce", "regex": "(?i)^PORT\\s+\\d+,\\d+,\\d+,\\d+,\\d+,\\d+"},
        {"name": "ftp_cmd_injection", "regex": "(?i)(?:USER|PASS|PORT|STOR|RETR)\\s+.*?(\\r|\\n|;|\\|)"},
        {"name": "llm_prompt_injection", "regex": "(?i)(?:ignore(?:\\s+all)?\\s+(?:previous|above)\\s+instructions|system\\s+prompt\\s+override|you\\s+are\\s+now\\s+dan\\b)"},
        {"name": "llm_jailbreak_pattern", "regex": "(?i)(?:jailbreak:|developer\\s+mode\\s+enabled|unrestricted\\s+ai)"},
        {"name": "smb_eternalblue_probe", "regex": "(?i)\\xffSMB[\\x72\\x73]"},
        {"name": "dns_tunnel_hex", "regex": "(?i)[0-9a-f]{32,}\\.[a-z0-9-]+\\.[a-z]{2,}"},
        {"name": "dns_tunnel_b32", "regex": "(?i)[a-z2-7]{32,}\\.[a-z0-9-]+\\.[a-z]{2,}"},
        {"name": "suspicious_user_agent", "regex": "(?i)(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan|hydra)"},
        {"name": "f5_bigip_auth_bypass", "regex": "(?i)/mgmt/tm/util/bash"},
        {"name": "confluence_rce", "regex": "(?i)/template/aui/text-inline\\.vm"},
        {"name": "tomcat_put_jsp", "regex": "(?i)PUT\\s+/.*\\.jsp/"},
        {"name": "cisco_rv_rce", "regex": "(?i)/cgi-bin/test-cgi"},
        {"name": "redis_unauth_cmd", "regex": "(?i)(?:CONFIG\\s+SET|SLAVEOF|REPLICAOF)"},
        {"name": "git_exposure", "regex": "(?i)/\\.git/(?:config|index|logs/HEAD)"},
        {"name": "svn_exposure", "regex": "(?i)/\\.svn/(?:entries|wc\\.db)"},
        {"name": "docker_api_unauth", "regex": "(?i)/v1\\.\\d+/(?:containers|images|version)"},
        {"name": "k8s_api_unauth", "regex": "(?i)/api/v1/namespaces/default/pods"},
        {"name": "fastjson_deser", "regex": "(?i)@type\\s*:\\s*[\"']com\\.sun\\.rowset"},
        {"name": "weblogic_t3_rce", "regex": "(?i)(?:t3|t3s)\\s+\\d+\\.\\d+\\.\\d+\\.\\d+"},
        {"name": "drupalgeddon", "regex": "(?i)/user/register\\?element_parents=account/mail"},
        {"name": "graphql_introspection", "regex": "(?i)__schema\\s*\\{\\s*types"},
        {"name": "actuator_heapdump", "regex": "(?i)/actuator/(?:heapdump|env|health)"},
        {"name": "aws_metadata_ssrf", "regex": "(?i)169\\.254\\.169\\.254/(?:latest/meta-data|latest/api/token)"},
        {"name": "gcp_metadata_ssrf", "regex": "(?i)metadata\\.google\\.internal/computeMetadata"},
    ],
    "feeds": [
        {"name": "firehol_level1", "type": "ip", "enabled": True,
         "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"},
        {"name": "feodo_c2", "type": "ip", "enabled": True,
         "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
        {"name": "et_compromised", "type": "ip", "enabled": True,
         "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
        {"name": "urlhaus_domains", "type": "domain", "enabled": True,
         "url": "https://urlhaus.abuse.ch/downloads/hostfile/"},
        {"name": "stevenblack_unified", "type": "domain", "enabled": False,
         "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"},
    ],
    "update_interval_hours": 12,
    "hosts_file_sinkhole": True,
    "hosts_file_max_domains": 20000,
    "dns_block_resolved_ips": True,
    "default_deny_inbound": False,
    "allow_inbound_ports": [],
    "suricata": {
        "enabled": True,
        "binary": "auto",
        "config_path": "auto",
        "eve_socket": "auto",
        "rules_update_interval_hours": 24,
        "custom_rules_dir": "",
        "home_net": "auto",
    },
    "application_firewall": {
        "enabled": True,
        "default_policy": "allow",
        "log_all_connections": True,
        "policies": [],
    },
    "connection_tracker": {
        "enabled": True,
        "geoip_enabled": True,
        "geoip_db_path": "auto",
        "bandwidth_tracking": True,
        "snapshot_interval_seconds": 2,
    },
    "honeypot": {
        "enabled": True,
        "auto_redirect_scanners": True,
        "redirect_window_seconds": 300,
        "services": {
            "ssh": {"enabled": True, "port": 2222},
            "http": {"enabled": True, "port": 8080},
            "ftp": {"enabled": True, "port": 2121},
            "mysql": {"enabled": False, "port": 3307},
            "smb": {"enabled": False, "port": 4450},
            "rdp": {"enabled": False, "port": 3390},
            "telnet": {"enabled": True, "port": 2323},
            "smtp": {"enabled": False, "port": 2525},
        },
    },
    "canary": {
        "enabled": True,
        "plant_fake_credentials": True,
        "plant_fake_ssh_keys": True,
        "plant_fake_env_files": True,
        "dns_canary_domain": "",
    },
    "sandbox": {
        "enabled": True,
        "auto_submit_honeypot_uploads": True,
        "auto_submit_quarantined": True,
        "max_execution_seconds": 60,
        "memory_limit_mb": 256,
        "network_allowed": False,
        "max_concurrent": 2,
    },
    "elasticsearch": {
        "enabled": False,
        "hosts": ["http://localhost:9200"],
        "username": "",
        "password": "",
        "index_prefix": "sentinelfw",
        "bulk_size": 500,
        "flush_interval_seconds": 5,
        "ilm_hot_days": 7,
        "ilm_warm_days": 30,
        "ilm_delete_days": 90,
    },
    "webui": {
        "enabled": True,
        "listen": "127.0.0.1",
        "port": 9443,
        "tls": True,
        "admin_password_hash": "",
        "session_timeout_minutes": 60,
    },
    "anomaly_detection": {
        "enabled": True,
        "baseline_window_days": 7,
        "alert_threshold_sigma": 3.0,
        "autorespond_threshold_sigma": 5.0,
        "tracked_metrics": [
            "connections_per_minute",
            "bandwidth_in_mbps",
            "bandwidth_out_mbps",
            "dns_queries_per_minute",
            "new_processes_per_minute",
            "failed_connections_per_minute",
        ],
    },
    "attack_mapping": {
        "mitre_attack_enabled": True,
        "kill_chain_tracking": True,
        "kill_chain_escalation": True,
        "auto_correlate_window_minutes": 30,
    },
    "threat_intel": {
        "stix_taxii_enabled": False,
        "taxii_server": "",
        "taxii_collection": "",
        "ioc_auto_extract": True,
        "ioc_sharing_enabled": False,
    },
    "self_protection": {
        "watchdog_enabled": True,
        "file_integrity_check": True,
        "anti_tampering": True,
    },
    "telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
        "alert_levels": ["critical", "warning"],
        "rate_limit_per_minute": 15,
        "message_format": "text",
        "include_ip_info": True,
    },
    "threat_intel": {
        "virustotal_api_key": "",
        "auto_scan_new_ips": True,
        "auto_ban_malicious": False,
        "min_malicious_votes": 3,
        "clean_rescan_days": 7,
        "request_interval_seconds": 16,
        "max_scans_per_hour": 220,
    },
    "firewall_policies": [],
}



SEED_LISTS = {
    "ip_manual.txt": "# One IP or CIDR per line. Edited by 'block-ip' or by hand; picked up automatically.\n",
    "domain_manual.txt": "# One domain per line (subdomains are matched too).\n",
    "hash_manual.txt": "# One SHA-256 per line. Any running process with a matching executable is killed.\n",
    "program_manual.txt": "# Executable paths or globs, e.g. C:\\Users\\*\\AppData\\Local\\Temp\\*.exe or /tmp/*\n",
}


class Store:
    def __init__(self):
        self.lock = threading.RLock()
        HOME.mkdir(parents=True, exist_ok=True)
        LISTS.mkdir(exist_ok=True)
        QUAR.mkdir(exist_ok=True)
        if not IS_WIN:
            os.chmod(HOME, 0o700)
        if not CONFIG_FILE.exists():
            atomic_write(CONFIG_FILE, json.dumps(DEFAULT_CONFIG, indent=2))
        for n, header in SEED_LISTS.items():
            if not (LISTS / n).exists():
                atomic_write(LISTS / n, header)
        self.cfg, self.bans, self.offenses, self.meta = {}, {}, {}, {}
        self._cfg_mtime = 0
        self.load_cfg()
        self.load_state()

    def load_cfg(self):
        try:
            m = CONFIG_FILE.stat().st_mtime_ns
            if m == self._cfg_mtime:
                return False
            self.cfg = deep_merge(DEFAULT_CONFIG, json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
            self._cfg_mtime = m
            return True
        except (OSError, ValueError) as e:
            event("config_error", "high", error=e)
            if not self.cfg:
                self.cfg = dict(DEFAULT_CONFIG)
            return False

    def load_state(self):
        with self.lock:
            try:
                s = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                s = {}
            self.bans, self.offenses, self.meta = s.get("bans", {}), s.get("offenses", {}), s.get("meta", {})

    def save(self):
        with self.lock:
            atomic_write(STATE_FILE, json.dumps({"bans": self.bans, "offenses": self.offenses, "meta": self.meta}))

    def purge(self):
        t = time.time()
        with self.lock:
            dead = [ip for ip, b in self.bans.items() if b["expires"] and b["expires"] <= t]
            for ip in dead:
                del self.bans[ip]
            if dead:
                self.save()
        return dead
