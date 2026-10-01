"""SentinelGate Address, Service, FQDN, and Schedule Objects Model.

Provides reusable policy objects that compile into O(1) interval sets, meta time rules,
and dynamic address definitions for the data plane.
"""

import ipaddress
import socket
import time
from typing import Dict, List, Optional, Set


class AddressObject:
    """Represents a named IP address, subnet CIDR, IP range, or FQDN."""

    def __init__(self, name: str, members: Optional[List[str]] = None,
                 obj_type: str = "ip", description: str = ""):
        self.name = name.strip()
        self.members: List[str] = list(members or [])
        self.obj_type = obj_type.lower()  # "ip", "fqdn", "geoip"
        self.description = description
        self._resolved_ips: Set[str] = set()
        self._last_resolved: float = 0.0

    def resolve_fqdn(self) -> Set[str]:
        """If this object is an FQDN, resolves it to current IPv4 addresses."""
        if self.obj_type != "fqdn":
            return set(self.members)

        now = time.time()
        # Cache for 60 seconds
        if self._resolved_ips and (now - self._last_resolved) < 60.0:
            return self._resolved_ips

        ips = set()
        for fqdn in self.members:
            try:
                results = socket.getaddrinfo(fqdn.strip(), None, socket.AF_INET)
                for res in results:
                    ip = res[4][0]
                    ips.add(ip)
            except Exception:
                pass
        if ips:
            self._resolved_ips = ips
            self._last_resolved = now
        return self._resolved_ips or set(self.members)

    def get_effective_cidrs(self) -> List[str]:
        """Returns valid CIDRs/IPs for set compilation."""
        if self.obj_type == "fqdn":
            return list(self.resolve_fqdn())
        result = []
        for m in self.members:
            m = m.strip()
            try:
                # Validate format
                ipaddress.ip_network(m, strict=False)
                result.append(m)
            except ValueError:
                # Might be single host
                result.append(m)
        return result

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "members": self.members,
            "type": self.obj_type,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AddressObject":
        return cls(
            name=data.get("name", "unnamed_addr"),
            members=data.get("members", []),
            obj_type=data.get("type", "ip"),
            description=data.get("description", ""),
        )


class ServiceObject:
    """Represents a protocol/port combination (e.g. TCP 443, UDP 53) or named service."""

    def __init__(self, name: str, protocol: str = "tcp",
                 ports: Optional[str] = None, description: str = ""):
        self.name = name.strip()
        self.protocol = protocol.lower().strip()  # "tcp", "udp", "icmp", "any"
        self.ports = ports.strip() if ports else ""  # e.g. "80,443", "1000-2000"
        self.description = description

    def to_nft_match(self) -> str:
        """Returns the nftables matching syntax for protocol and port."""
        if self.protocol == "any" or not self.protocol:
            return ""
        if self.protocol == "icmp":
            return "ip protocol icmp"
        if not self.ports:
            return f"meta l4proto {self.protocol}"

        # Single port or multiple ports
        parts = [p.strip() for p in self.ports.split(",") if p.strip()]
        if len(parts) == 1:
            p = parts[0]
            if "-" in p:
                return f"{self.protocol} dport {p}"
            return f"{self.protocol} dport {p}"
        ports_str = ", ".join(parts)
        return f"{self.protocol} dport {{ {ports_str} }}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "protocol": self.protocol,
            "ports": self.ports,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ServiceObject":
        return cls(
            name=data.get("name", "unnamed_svc"),
            protocol=data.get("protocol", "tcp"),
            ports=str(data.get("ports", "")) if data.get("ports") is not None else "",
            description=data.get("description", ""),
        )


class ScheduleObject:
    """Represents a time schedule (recurring or one-time) for time-based access control."""

    def __init__(self, name: str, days: Optional[List[str]] = None,
                 start_time: str = "00:00", end_time: str = "23:59",
                 description: str = ""):
        self.name = name.strip()
        self.days = list(days or ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
        self.start_time = start_time
        self.end_time = end_time
        self.description = description

    def to_nft_match(self) -> str:
        """Returns nftables meta day and meta time expression."""
        day_map = {
            "mon": "Monday", "tue": "Tuesday", "wed": "Wednesday",
            "thu": "Thursday", "fri": "Friday", "sat": "Saturday", "sun": "Sunday"
        }
        mapped_days = [day_map.get(d.lower()[:3], d) for d in self.days if d]
        parts = []
        if len(mapped_days) < 7 and mapped_days:
            parts.append(f'meta day {{ "{", ".join(mapped_days)}" }}')
        if self.start_time != "00:00" or self.end_time != "23:59":
            parts.append(f'meta time "{self.start_time}:00"-"{self.end_time}:00"')
        return " ".join(parts)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "days": self.days,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScheduleObject":
        return cls(
            name=data.get("name", "always"),
            days=data.get("days", []),
            start_time=data.get("start_time", "00:00"),
            end_time=data.get("end_time", "23:59"),
            description=data.get("description", ""),
        )


class ObjectCatalog:
    """Central registry for Address, Service, and Schedule objects."""

    def __init__(self, config_dict: Optional[dict] = None):
        self.addresses: Dict[str, AddressObject] = {}
        self.services: Dict[str, ServiceObject] = {}
        self.schedules: Dict[str, ScheduleObject] = {}
        self._init_defaults()
        if config_dict:
            self.load(config_dict)

    def _init_defaults(self) -> None:
        """Loads standard built-in service catalog."""
        default_services = [
            ServiceObject("HTTP", "tcp", "80", "Hypertext Transfer Protocol"),
            ServiceObject("HTTPS", "tcp", "443", "Secure HTTP (TLS)"),
            ServiceObject("HTTP_HTTPS", "tcp", "80,443", "Web Traffic"),
            ServiceObject("DNS", "udp", "53", "Domain Name System"),
            ServiceObject("DNS_TCP", "tcp", "53", "DNS Zone Transfers"),
            ServiceObject("SSH", "tcp", "22", "Secure Shell"),
            ServiceObject("RDP", "tcp", "3389", "Remote Desktop Protocol"),
            ServiceObject("SMB", "tcp", "445", "Server Message Block"),
            ServiceObject("MySQL", "tcp", "3306", "MySQL Database"),
            ServiceObject("PostgreSQL", "tcp", "5432", "PostgreSQL Database"),
            ServiceObject("NTP", "udp", "123", "Network Time Protocol"),
            ServiceObject("ICMP_Echo", "icmp", "", "ICMP Ping"),
            ServiceObject("ANY", "any", "", "All Protocols and Ports"),
        ]
        for svc in default_services:
            self.services[svc.name.upper()] = svc

    def load(self, config_dict: dict) -> None:
        # Load addresses
        for item in config_dict.get("addresses", []):
            if isinstance(item, dict):
                obj = AddressObject.from_dict(item)
                self.addresses[obj.name] = obj

        # Load custom services
        for item in config_dict.get("services", []):
            if isinstance(item, dict):
                obj = ServiceObject.from_dict(item)
                self.services[obj.name.upper()] = obj

        # Load schedules
        for item in config_dict.get("schedules", []):
            if isinstance(item, dict):
                obj = ScheduleObject.from_dict(item)
                self.schedules[obj.name] = obj

    def get_address(self, name: str) -> Optional[AddressObject]:
        return self.addresses.get(name)

    def get_service(self, name: str) -> Optional[ServiceObject]:
        return self.services.get(name.upper())

    def get_schedule(self, name: str) -> Optional[ScheduleObject]:
        return self.schedules.get(name)
