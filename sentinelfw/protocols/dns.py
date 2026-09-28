"""SentinelFW Deep DNS Protocol Inspector.

Detects DNS tunneling, DGA domains, zone transfers (AXFR), and suspicious TXT queries
using Shannon entropy calculation and lexical analysis.
"""
import math
import re
from typing import Dict, List, Optional, Tuple


def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DNSInspector:
    """Performs deep behavioral inspection on DNS queries and responses."""

    @classmethod
    def inspect_query(cls, qname: str, qtype: str = "A") -> Tuple[Optional[str], dict]:
        """
        Analyzes a DNS query name for tunneling, DGA, or exfiltration indicators.
        Returns: (attack_type or None, details_dict)
        """
        if not qname:
            return None, {}

        labels = qname.strip(".").split(".")
        if len(labels) < 2:
            return None, {}

        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else labels[0]
        longest_label = max(labels, key=len)
        entropy = shannon_entropy(longest_label)

        # 1. DNS Tunneling Detection (Large payload, high entropy, base32/hex characters)
        if len(longest_label) > 30 and entropy > 3.8:
            return "c2_dns_tunnel", {
                "qname": qname,
                "label_len": len(longest_label),
                "entropy": round(entropy, 2),
                "qtype": qtype
            }

        # 2. DGA Domain Detection (high entropy second-level domain)
        sld = labels[-2] if len(labels) >= 2 else labels[0]
        if len(sld) >= 12 and shannon_entropy(sld) > 3.6 and not re.search(r"[aeiou]{2,}", sld):
            return "c2_domain_gen", {
                "qname": qname,
                "sld": sld,
                "entropy": round(shannon_entropy(sld), 2)
            }

        # 3. Zone Transfer (AXFR) Attempt
        if qtype.upper() in ("AXFR", "IXFR", "252", "251"):
            return "dns_zone_transfer", {"qname": qname, "qtype": qtype}

        return None, {"qname": qname, "entropy": round(entropy, 2)}
