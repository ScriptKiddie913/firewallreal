"""SentinelGate NAT (Network Address Translation) Engine.

Supports Masquerade, Source NAT (SNAT), Destination NAT (DNAT / Virtual IPs / Port Forwarding),
and 1:1 Bi-directional NAT. Compiles into atomic nftables nat rules for Linux and
netsh portproxy rules for Windows.
"""

from typing import Dict, List, Optional


class NatRule:
    """Represents a single SNAT, Masquerade, or DNAT translation policy."""

    def __init__(
        self,
        rule_id: int,
        name: str,
        nat_type: str,  # "masquerade", "snat", "dnat"
        src_zone: Optional[str] = None,
        dst_zone: Optional[str] = None,
        in_interface: Optional[str] = None,
        out_interface: Optional[str] = None,
        protocol: str = "tcp",
        original_dst_ip: Optional[str] = None,
        original_dst_port: Optional[int] = None,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        enabled: bool = True,
        description: str = "",
    ):
        self.id = rule_id
        self.name = name
        self.nat_type = nat_type.lower().strip()
        self.src_zone = src_zone
        self.dst_zone = dst_zone
        self.in_interface = in_interface
        self.out_interface = out_interface
        self.protocol = protocol.lower().strip()
        self.original_dst_ip = original_dst_ip
        self.original_dst_port = original_dst_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.enabled = enabled
        self.description = description

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "nat_type": self.nat_type,
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "in_interface": self.in_interface,
            "out_interface": self.out_interface,
            "protocol": self.protocol,
            "original_dst_ip": self.original_dst_ip,
            "original_dst_port": self.original_dst_port,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "enabled": self.enabled,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NatRule":
        return cls(
            rule_id=data.get("id", 1),
            name=data.get("name", "nat-rule"),
            nat_type=data.get("nat_type") or data.get("type", "masquerade"),
            src_zone=data.get("src_zone"),
            dst_zone=data.get("dst_zone"),
            in_interface=data.get("in_interface"),
            out_interface=data.get("out_interface"),
            protocol=data.get("protocol", "tcp"),
            original_dst_ip=data.get("original_dst_ip"),
            original_dst_port=data.get("original_dst_port"),
            target_ip=data.get("target_ip"),
            target_port=data.get("target_port"),
            enabled=data.get("enabled", True),
            description=data.get("description", ""),
        )

    def to_nft_rule(self) -> Optional[str]:
        """Renders rule as an nftables statement."""
        if not self.enabled:
            return None

        if self.nat_type == "masquerade":
            # Egress masquerade
            oif = f'oifname "{self.out_interface}" ' if self.out_interface else ""
            return f"{oif}masquerade"

        if self.nat_type == "snat" and self.target_ip:
            oif = f'oifname "{self.out_interface}" ' if self.out_interface else ""
            return f"{oif}snat to {self.target_ip}"

        if self.nat_type == "dnat" and self.target_ip:
            # Ingress DNAT (virtual IP / port forward)
            iif = f'iifname "{self.in_interface}" ' if self.in_interface else ""
            proto = f"{self.protocol} " if self.protocol in ("tcp", "udp") else ""
            dport = f"dport {self.original_dst_port} " if self.original_dst_port else ""
            tport = f":{self.target_port}" if self.target_port else ""
            return f"{iif}{proto}{dport}dnat to {self.target_ip}{tport}"

        return None


class NatManager:
    """Manages NAT policies and compiles them for kernel enforcement."""

    def __init__(self, rules_data: Optional[List[dict]] = None):
        self._rules: Dict[int, NatRule] = {}
        if rules_data:
            self.load(rules_data)

    def load(self, rules_data: List[dict]) -> None:
        self._rules.clear()
        for idx, item in enumerate(rules_data, start=1):
            if isinstance(item, dict):
                rule = NatRule.from_dict({**item, "id": item.get("id", idx)})
                self._rules[rule.id] = rule

    def add_rule(self, rule: NatRule) -> None:
        self._rules[rule.id] = rule

    def get_rules(self) -> List[NatRule]:
        return sorted(self._rules.values(), key=lambda r: r.id)

    def compile_nft_prerouting(self) -> List[str]:
        """Compiles DNAT rules for nat prerouting chain."""
        lines = []
        for r in self.get_rules():
            if r.enabled and r.nat_type == "dnat":
                statement = r.to_nft_rule()
                if statement:
                    lines.append(f"        {statement} comment \"nat-dnat-{r.name}\"")
        return lines

    def compile_nft_postrouting(self) -> List[str]:
        """Compiles SNAT / Masquerade rules for nat postrouting chain."""
        lines = []
        for r in self.get_rules():
            if r.enabled and r.nat_type in ("masquerade", "snat"):
                statement = r.to_nft_rule()
                if statement:
                    lines.append(f"        {statement} comment \"nat-{r.nat_type}-{r.name}\"")
        return lines
