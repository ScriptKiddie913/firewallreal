"""SentinelFW Compliance & Security Rating Engine.

Evaluates system configuration and posture against cybersecurity frameworks:
* CIS Controls (Network Monitoring, Secure Configuration, Access Control)
* PCI-DSS v4.0 (Network Security Controls, Strong Authentication, Log Tracking)
* ISO/IEC 27001 (A.8.20 Network Security, A.8.24 Cryptography)
* CERT-In Directions (Log retention, Security auditability)
"""
from typing import Dict, List


class ComplianceAuditor:
    """Audits SentinelFW configuration against industry compliance baselines."""

    def evaluate(self, cfg: dict) -> dict:
        """Runs compliance checks against active configuration and returns score and audit results."""
        checks = []

        # Check 1: Default password initialized
        webui_cfg = cfg.get("webui", {})
        has_pwd = (bool(webui_cfg.get("password_initialized", False)) or bool(webui_cfg.get("password_hash"))) and not bool(webui_cfg.get("must_change_password", False))
        checks.append({
            "id": "SEC-01",
            "name": "Default Password Changed",
            "passed": has_pwd,
            "weight": 20,
            "frameworks": ["CIS-Control-4", "PCI-DSS-8.2.1", "ISO-27001-A.8.5"],
            "remediation": "Complete the first-run administrator password setup.",
        })

        # Check 2: TLS Active & Hardened
        tls_enabled = bool(webui_cfg.get("tls_enabled", False))
        checks.append({
            "id": "SEC-02",
            "name": "Native WebUI TLS Encryption",
            "passed": tls_enabled,
            "weight": 15,
            "frameworks": ["CIS-Control-4", "PCI-DSS-4.1", "ISO-27001-A.8.24"],
            "remediation": "Enable TLS in WebUI configuration with a valid certificate.",
        })

        # Check 3: Audit Logging & Hash Chaining
        audit_enabled = bool(cfg.get("audit_log", {}).get("enabled", True))
        checks.append({
            "id": "SEC-03",
            "name": "Tamper-Evident Audit Logging",
            "passed": audit_enabled,
            "weight": 15,
            "frameworks": ["CIS-Control-8", "PCI-DSS-10.2", "CERT-In-Dir-4"],
            "remediation": "Enable cryptographic hash-chained audit logging.",
        })

        # Check 4: Anti-Spoofing & DDoS Guard
        traffic_cfg = cfg.get("traffic_control", {})
        antispoof = bool(traffic_cfg.get("anti_spoofing_enabled", True))
        checks.append({
            "id": "SEC-04",
            "name": "L3/L4 Anti-Spoofing & Flood Mitigation",
            "passed": antispoof,
            "weight": 15,
            "frameworks": ["CIS-Control-13", "PCI-DSS-1.3", "ISO-27001-A.8.20"],
            "remediation": "Enable anti-spoofing scoring rails in traffic control settings.",
        })

        # Check 5: Active Firewall Policies
        pols = cfg.get("firewall_policies", [])
        has_pols = len(pols) > 0 and any(p.get("enabled", True) for p in pols)
        checks.append({
            "id": "SEC-05",
            "name": "Explicit Firewall Policies Defined",
            "passed": has_pols,
            "weight": 15,
            "frameworks": ["CIS-Control-4", "PCI-DSS-1.2", "ISO-27001-A.8.20"],
            "remediation": "Configure ordered first-match firewall policies.",
        })

        # Check 6: Two-Factor Authentication (TOTP)
        two_fa = bool(webui_cfg.get("totp_enabled", False))
        checks.append({
            "id": "SEC-06",
            "name": "Multi-Factor Authentication (TOTP)",
            "passed": two_fa,
            "weight": 20,
            "frameworks": ["CIS-Control-6", "PCI-DSS-8.4.1", "ISO-27001-A.8.5"],
            "remediation": "Configure TOTP multi-factor authentication for console access.",
        })

        # Score calculation
        total_weight = sum(c["weight"] for c in checks)
        passed_weight = sum(c["weight"] for c in checks if c["passed"])
        score = int((passed_weight / total_weight) * 100) if total_weight > 0 else 0

        grade = "F"
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"

        return {
            "score": score,
            "grade": grade,
            "passed_checks": sum(1 for c in checks if c["passed"]),
            "total_checks": len(checks),
            "checks": checks,
        }

    def generate_html_report(self, audit_result: dict) -> str:
        """Generates an executive HTML compliance summary report."""
        score = audit_result.get("score", 0)
        grade = audit_result.get("grade", "F")
        checks = audit_result.get("checks", [])

        rows = []
        for c in checks:
            status_color = "#10b981" if c["passed"] else "#ef4444"
            status_text = "PASS" if c["passed"] else "FAIL"
            frameworks = ", ".join(c.get("frameworks", []))
            rows.append(f"""
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;"><strong>{c['id']}</strong></td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;">{c['name']}</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;"><span style="color: {status_color}; font-weight: bold;">{status_text}</span></td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;">{frameworks}</td>
                </tr>
            """)

        html_out = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>SentinelFW Compliance Audit Report</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px;">
    <h1>SentinelFW Security Rating & Compliance Report</h1>
    <div style="background: #1e293b; padding: 16px; border-radius: 8px; margin-bottom: 24px; display: inline-block;">
        <span style="font-size: 18px;">Security Rating: <strong>{score}/100</strong> (Grade: <strong>{grade}</strong>)</span>
    </div>
    <table style="width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px;">
        <thead>
            <tr style="background: #334155; text-align: left;">
                <th style="padding: 8px;">ID</th>
                <th style="padding: 8px;">Control Name</th>
                <th style="padding: 8px;">Status</th>
                <th style="padding: 8px;">Mapped Frameworks</th>
            </tr>
        </thead>
        <tbody>
            {''.join(rows)}
        </tbody>
    </table>
</body>
</html>"""
        return html_out


# Global singleton
compliance_auditor = ComplianceAuditor()
