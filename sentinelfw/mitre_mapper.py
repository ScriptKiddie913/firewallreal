"""SentinelFW MITRE ATT&CK Mapping Module.

Maps detection signatures, attack taxonomy identifiers, and alert categories
to MITRE ATT&CK Enterprise tactics (TA00xx) and techniques (T1xxx).
"""

MITRE_TAXONOMY = {
    # Reconnaissance (TA0043)
    "port_scan_tcp_syn": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"},
    "port_scan_tcp_connect": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"},
    "port_scan_tcp_fin": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Port Scanning"},
    "port_scan_tcp_xmas": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Port Scanning"},
    "port_scan_tcp_null": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Port Scanning"},
    "port_scan_tcp_ack": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Vulnerability Scanning"},
    "port_scan_udp": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Port Scanning"},
    "host_sweep_icmp": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"},
    "host_sweep_tcp": {"tactic": "TA0043", "technique": "T1595.001", "name": "Active Scanning: Scanning IP Blocks"},
    "os_fingerprint": {"tactic": "TA0043", "technique": "T1592", "name": "Gather Victim Host Information"},
    "service_fingerprint": {"tactic": "TA0043", "technique": "T1595.002", "name": "Active Scanning: Vulnerability Scanning"},
    "web_crawl_aggressive": {"tactic": "TA0043", "technique": "T1595.003", "name": "Active Scanning: Wordlist Scanning"},
    "banner_grab": {"tactic": "TA0043", "technique": "T1595.002", "name": "Active Scanning: Vulnerability Scanning"},

    # Credential Access / Brute Force (TA0006)
    "ssh_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "rdp_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "ftp_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "telnet_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "smtp_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "http_auth_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "mysql_brute": {"tactic": "TA0006", "technique": "T1110.001", "name": "Brute Force: Password Guessing"},
    "credential_stuffing": {"tactic": "TA0006", "technique": "T1110.004", "name": "Brute Force: Credential Stuffing"},

    # Impact / Denial of Service (TA0040)
    "syn_flood": {"tactic": "TA0040", "technique": "T1498.001", "name": "Network Denial of Service: Direct Network Flood"},
    "udp_flood": {"tactic": "TA0040", "technique": "T1498.001", "name": "Network Denial of Service: Direct Network Flood"},
    "icmp_flood": {"tactic": "TA0040", "technique": "T1498.001", "name": "Network Denial of Service: Direct Network Flood"},
    "http_flood": {"tactic": "TA0040", "technique": "T1499.001", "name": "Endpoint Denial of Service: OS Exhaustion Flood"},
    "slowloris": {"tactic": "TA0040", "technique": "T1499.003", "name": "Endpoint Denial of Service: Application Exhaustion Flood"},

    # Initial Access / Exploitation (TA0001)
    "sql_injection_union": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: SQL Injection"},
    "sql_injection_blind": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: SQL Injection"},
    "sql_injection_quotes": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: SQL Injection"},
    "path_traversal": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Path Traversal"},
    "command_injection": {"tactic": "TA0001", "technique": "T1059", "name": "Command and Scripting Interpreter"},
    "cmd_injection_pipes": {"tactic": "TA0001", "technique": "T1059", "name": "Command and Scripting Interpreter"},
    "xss_script_tags": {"tactic": "TA0001", "technique": "T1189", "name": "Drive-by Compromise"},
    "log4shell": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Log4j CVE-2021-44228"},
    "spring4shell": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Spring4Shell CVE-2022-22965"},
    "shellshock": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Shellshock CVE-2014-6271"},
    "proxylogon": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Exchange ProxyLogon"},
    "proxyshell": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Exchange ProxyShell"},
    "moveit_rce": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: MOVEit Transfer SQLi"},
    "citrix_bleed": {"tactic": "TA0001", "technique": "T1190", "name": "Exploit Public-Facing Application: Citrix Bleed"},
    "web_admin_probe": {"tactic": "TA0043", "technique": "T1595.002", "name": "Active Scanning: Vulnerability Scanning"},

    # Command and Control (TA0011)
    "c2_dns_tunnel": {"tactic": "TA0011", "technique": "T1071.004", "name": "Application Layer Protocol: DNS C2"},
    "c2_beacon": {"tactic": "TA0011", "technique": "T1071.001", "name": "Application Layer Protocol: Web Protocols"},
    "c2_tor_usage": {"tactic": "TA0011", "technique": "T1090.003", "name": "Proxy: Multi-hop Proxy (Tor)"},
    "powershell_download": {"tactic": "TA0002", "technique": "T1059.001", "name": "Execution: PowerShell C2 Loader"},
    "certutil_download": {"tactic": "TA0005", "technique": "T1105", "name": "Ingress Tool Transfer: Certutil Abuse"},
    "bitsadmin_download": {"tactic": "TA0005", "technique": "T1197", "name": "BITS Jobs Ingress Transfer"},

    # Exfiltration (TA0010)
    "dns_exfil": {"tactic": "TA0010", "technique": "T1048.003", "name": "Exfiltration Over Alternative Protocol: DNS"},
    "http_exfil": {"tactic": "TA0010", "technique": "T1041", "name": "Exfiltration Over C2 Channel"},
    "ftp_data_exfil": {"tactic": "TA0010", "technique": "T1048.003", "name": "Exfiltration Over Unencrypted Protocol: FTP"},

    # Lateral Movement (TA0008)
    "smb_lateral": {"tactic": "TA0008", "technique": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"},
    "wmi_lateral": {"tactic": "TA0008", "technique": "T1047", "name": "Windows Management Instrumentation"},
    "smb_eternalblue_probe": {"tactic": "TA0008", "technique": "T1210", "name": "Exploitation of Remote Services: EternalBlue"},

    # LLM & AI Attacks
    "llm_prompt_injection": {"tactic": "TA0001", "technique": "T1190.AI", "name": "AI Prompt Injection & Instruction Bypass"},
    "llm_jailbreak_pattern": {"tactic": "TA0001", "technique": "T1190.AI", "name": "AI Jailbreak & Safety Alignment Bypass"},
}


class MITREMapper:
    """Enriches threat signatures and events with MITRE ATT&CK taxonomy metadata."""

    @staticmethod
    def map_attack(attack_type: str) -> dict:
        """Looks up tactic, technique, and descriptive name for an attack identifier."""
        clean_key = attack_type.lower().strip()
        # Direct match
        if clean_key in MITRE_TAXONOMY:
            return dict(MITRE_TAXONOMY[clean_key])

        # Partial matching by prefix
        for k, v in MITRE_TAXONOMY.items():
            if k in clean_key or clean_key in k:
                return dict(v)

        # Default fallback
        return {
            "tactic": "TA0043",
            "technique": "T1595",
            "name": f"Unclassified Network Threat: {attack_type}",
        }
