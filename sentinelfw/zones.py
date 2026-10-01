"""SentinelGate Zone Architecture and Interface Mapping Model.

Defines network security zones (wan, lan, dmz, guest, vpn, loopback) and
manages interface-to-zone bindings, intra-zone policies, and zone-pair chains.
"""

import re
from typing import Dict, List, Optional, Set


STANDARD_ZONES: Set[str] = {
    "wan",
    "lan",
    "dmz",
    "guest",
    "vpn",
    "loopback",
    "mgmt",
}


class Zone:
    """Represents an isolated security zone comprising one or more network interfaces."""

    def __init__(self, name: str, interfaces: Optional[List[str]] = None,
                 intra_zone_action: str = "allow", description: str = ""):
        self.name = name.lower().strip()
        self.interfaces: List[str] = list(interfaces or [])
        self.intra_zone_action = intra_zone_action.lower()  # "allow" or "deny"
        self.description = description

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "interfaces": self.interfaces,
            "intra_zone_action": self.intra_zone_action,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Zone":
        return cls(
            name=data.get("name", "lan"),
            interfaces=data.get("interfaces", []),
            intra_zone_action=data.get("intra_zone_action", "allow"),
            description=data.get("description", ""),
        )


class ZoneManager:
    """Coordinates zone configurations, interface lookups, and zone-pair chain names."""

    def __init__(self, config_dict: Optional[dict] = None):
        self._zones: Dict[str, Zone] = {}
        self._iface_to_zone: Dict[str, str] = {}
        self.load(config_dict or {})

    def load(self, config_dict: dict) -> None:
        """Loads zones from configuration mapping or interfaces list."""
        self._zones.clear()
        self._iface_to_zone.clear()

        # Direct zones definition: {"wan": ["eth0"], "lan": ["eth1"]}
        zones_data = config_dict.get("zones", {})
        if isinstance(zones_data, dict):
            for zname, ifaces in zones_data.items():
                if isinstance(ifaces, list):
                    self.add_zone(Zone(name=zname, interfaces=ifaces))
                elif isinstance(ifaces, dict):
                    self.add_zone(Zone.from_dict({**ifaces, "name": zname}))

        # Or inferred from interfaces list: [{"name": "eth0", "zone": "wan"}]
        for itf in config_dict.get("interfaces", []):
            if isinstance(itf, dict):
                iname = itf.get("name")
                zname = itf.get("zone", "lan")
                if iname and zname:
                    if zname not in self._zones:
                        self.add_zone(Zone(name=zname, interfaces=[iname]))
                    elif iname not in self._zones[zname].interfaces:
                        self._zones[zname].interfaces.append(iname)
                        self._iface_to_zone[iname] = zname

        # Ensure default zones exist if none were provided
        if not self._zones:
            self.add_zone(Zone(name="loopback", interfaces=["lo"]))
            self.add_zone(Zone(name="lan", interfaces=[]))
            self.add_zone(Zone(name="wan", interfaces=[]))

    def add_zone(self, zone: Zone) -> None:
        self._zones[zone.name] = zone
        for iface in zone.interfaces:
            self._iface_to_zone[iface] = zone.name

    def get_zone(self, name: str) -> Optional[Zone]:
        return self._zones.get(name.lower().strip())

    def get_zone_for_interface(self, interface: str) -> Optional[str]:
        return self._iface_to_zone.get(interface.strip())

    def list_zones(self) -> List[dict]:
        return [z.to_dict() for z in self._zones.values()]

    @staticmethod
    def get_chain_name(src_zone: str, dst_zone: str) -> str:
        """Returns the canonical nftables chain name for a zone pair."""
        s = re.sub(r"[^a-zA-Z0-9_]", "_", src_zone.lower().strip())
        d = re.sub(r"[^a-zA-Z0-9_]", "_", dst_zone.lower().strip())
        return f"fwd_{s}_to_{d}"

    def get_all_zone_pairs(self) -> List[tuple]:
        """Returns all ordered pairs of distinct active zones."""
        zone_names = list(self._zones.keys())
        pairs = []
        for src in zone_names:
            for dst in zone_names:
                if src != dst and src != "loopback" and dst != "loopback":
                    pairs.append((src, dst))
        return pairs
