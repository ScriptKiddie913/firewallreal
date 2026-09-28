"""SentinelFW GeoIP and ASN resolution module.

Provides lightweight IP-to-Country and ASN mapping with offline IP-range caching
and MaxMind MMDB / CSV support without requiring external non-stdlib dependencies.

Includes an automatic offline country database (sapics/ip-location-db, ODbL /
GeoLite2-derived, free) for IPv4 and IPv6, downloaded once into DATA_DIR/geoip
and refreshed every 14 days. A copy of the IPv4 database is bundled with the
package and used when the server has no internet access; if neither works, a
background thread retries the download every 15 minutes.
"""
import bisect
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.request
from pathlib import Path
from .common import DATA_DIR, event

# Fallback known bogon/cloud/special ASN and country blocks for offline evaluation
SPECIAL_RANGES = [
    (ipaddress.ip_network("10.0.0.0/8"), "PRIVATE", 0, "RFC1918 Private LAN"),
    (ipaddress.ip_network("172.16.0.0/12"), "PRIVATE", 0, "RFC1918 Private LAN"),
    (ipaddress.ip_network("192.168.0.0/16"), "PRIVATE", 0, "RFC1918 Private LAN"),
    (ipaddress.ip_network("127.0.0.0/8"), "LOOPBACK", 0, "Loopback"),
    (ipaddress.ip_network("169.254.0.0/16"), "LINKLOCAL", 0, "Link-Local / APIPA"),
    (ipaddress.ip_network("100.64.0.0/10"), "CGNAT", 0, "Shared Address Space"),
    (ipaddress.ip_network("8.8.8.0/24"), "US", 15169, "Google LLC"),
    (ipaddress.ip_network("8.8.4.0/24"), "US", 15169, "Google LLC"),
    (ipaddress.ip_network("1.1.1.0/24"), "AU", 13335, "Cloudflare, Inc."),
    (ipaddress.ip_network("1.0.0.0/24"), "AU", 13335, "Cloudflare, Inc."),
    (ipaddress.ip_network("9.9.9.0/24"), "US", 19281, "Quad9 DNS"),
]

# Coarse RIR fallback for IPv4 space not present in the country database
# (unallocated / reserved legacy blocks). Honest region labels, never a fake country.
RIR_FALLBACK = [
    (ipaddress.ip_network("0.0.0.0/8"), "ZZ", "IANA reserved"),
    (ipaddress.ip_network("11.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("22.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("26.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("28.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("29.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("30.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("33.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("55.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("214.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("215.0.0.0/8"), "ZZ", "DoD / unallocated"),
    (ipaddress.ip_network("240.0.0.0/4"), "ZZ", "IANA special-purpose"),
    (ipaddress.ip_network("192.0.2.0/24"), "ZZ", "RFC5737 documentation"),
    (ipaddress.ip_network("198.51.100.0/24"), "ZZ", "RFC5737 documentation"),
    (ipaddress.ip_network("203.0.113.0/24"), "ZZ", "RFC5737 documentation"),
]

COUNTRY_DB_URL = "https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/user-country/user-country-ipv4.csv"
COUNTRY_DB_URL_V6 = "https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/user-country/user-country-ipv6.csv"
COUNTRY_DB_MAX_AGE_DAYS = 14
DB_RETRY_SECONDS = 15 * 60

# A copy of the IPv4 CSV shipped inside the package (used when offline)
BUNDLED_DB_V4 = Path(__file__).resolve().parent / "bundled" / "geoip" / "user-country-ipv4.csv"


class _CountryDB:
    """In-memory sorted interval index over an IPv4/IPv6 start,end,country CSV."""

    FILENAME = "user-country-ipv4.csv"

    def __init__(self, family: int = 4):
        self.family = family
        self.starts: list = []
        self.ccs: list = []
        self.ready = False
        self.source = ""
        self.lock = threading.Lock()

    @property
    def path(self) -> Path:
        return DATA_DIR / "geoip" / self.FILENAME

    def load(self) -> bool:
        if not self.path.exists():
            return False
        starts, ccs = [], []
        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) != 3:
                        continue
                    try:
                        a = ipaddress.ip_address(parts[0])
                        b = ipaddress.ip_address(parts[1])
                    except ValueError:
                        continue
                    if a.version != self.family or b.version != self.family:
                        continue
                    starts.append(int(a))
                    ccs.append(parts[2].upper())
        except OSError as e:
            event("geoip_db_read_error", "low", error=str(e))
            return False
        if not starts:
            return False
        self.starts, self.ccs = starts, ccs
        self.ready = True
        self.source = str(self.path)
        return True

    def lookup(self, ip_int: int) -> str:
        i = bisect.bisect_right(self.starts, ip_int) - 1
        if i < 0:
            return ""
        # CSV rows never overlap and are sorted; start_i <= ip means row i is the
        # best candidate. The end bound is implicit: the next row's start.
        return self.ccs[i]

    def download(self, url: str) -> bool:
        dest_dir = DATA_DIR / "geoip"
        dest_dir.mkdir(parents=True, exist_ok=True)
        tmp = dest_dir / (self.FILENAME + ".tmp")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SentinelFW/3"})
            with urllib.request.urlopen(req, timeout=90) as resp, open(tmp, "wb") as out:
                total = 0
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
                    total += len(chunk)
                    if total > 200 * 1024 * 1024:
                        raise ValueError("country db suspiciously large")
            os.replace(tmp, self.path)
            (dest_dir / "downloaded_at").write_text(str(time.time()))
        except Exception as e:  # noqa: BLE001
            event("geoip_db_download_failed", "low", family=self.family, error=str(e))
            try:
                tmp.unlink()
            except OSError:
                pass
            return False
        return self.load()

    def install_bundled(self) -> bool:
        """Copies the packaged database into DATA_DIR and loads it (offline path)."""
        try:
            if not BUNDLED_DB_V4.exists() or self.family != 4:
                return False
            dest_dir = DATA_DIR / "geoip"
            dest_dir.mkdir(parents=True, exist_ok=True)
            data = BUNDLED_DB_V4.read_bytes()
            self.path.write_bytes(data)
            (dest_dir / "downloaded_at").write_text("0")  # marked bundled; refresh will retry network later
            event("geoip_db_bundled_installed", "info", rows_hint="bundled")
            return self.load()
        except Exception as e:  # noqa: BLE001
            event("geoip_db_bundled_failed", "low", error=str(e))
            return False

    def needs_refresh(self) -> bool:
        marker = DATA_DIR / "geoip" / "downloaded_at"
        if not marker.exists():
            return True
        try:
            return time.time() - float(marker.read_text()) > COUNTRY_DB_MAX_AGE_DAYS * 86400
        except ValueError:
            return True


class _V6DB(_CountryDB):
    FILENAME = "user-country-ipv6.csv"


_country_db = _CountryDB(4)
_country_db_v6 = _V6DB(6)
_country_db_lock = threading.Lock()

# Bumped whenever a DB finishes loading so resolvers can drop stale UNKNOWN caches
_db_generation = 0


def _bump_generation():
    global _db_generation
    _db_generation += 1


def country_lookup(ip_str: str) -> str:
    """Two-letter ISO country for a public IPv4/IPv6 string, '' when unknown."""
    try:
        a = ipaddress.ip_address(ip_str)
    except ValueError:
        return ""
    if a.version == 4:
        db = _country_db
    else:
        db = _country_db_v6
    if not db.ready:
        return ""
    return db.lookup(int(a))


def country_db_status() -> dict:
    with _country_db_lock:
        return {
            "ready": _country_db.ready or _country_db_v6.ready,
            "v4_ready": _country_db.ready,
            "v6_ready": _country_db_v6.ready,
            "rows": len(_country_db.starts) + len(_country_db_v6.starts),
            "source": _country_db.source,
        }


def ensure_country_db(background: bool = True):
    """Loads the offline country DB, downloading it if absent or stale.

    Keeps retrying in the background until the DB is available, and falls back
    to the bundled copy when the server cannot reach the internet.
    """

    def _do():
        global _db_generation
        while True:
            with _country_db_lock:
                v4_ok = _country_db.ready and not _country_db.needs_refresh()
                v6_ok = _country_db_v6.ready
                if not v4_ok:
                    if not _country_db.load() or _country_db.needs_refresh():
                        downloaded = _country_db.download(COUNTRY_DB_URL)
                        if not downloaded and not _country_db.ready:
                            _country_db.install_bundled()
                if not v6_ok:
                    _country_db_v6.download(COUNTRY_DB_URL_V6)
                if _country_db.ready and not _country_db_v6.ready:
                    pass  # v6 DB is a bonus; v4 alone is fine
                _bump_generation()
            if _country_db.ready:
                event("geoip_country_db_ready", "info",
                      rows=len(_country_db.starts), v6=len(_country_db_v6.starts))
                return
            # still not available — retry later
            time.sleep(DB_RETRY_SECONDS)

    if background:
        threading.Thread(target=_do, daemon=True, name="geoip_db_loader").start()
    else:
        _do()


class GeoIPResolver:
    """Resolves IP addresses to country codes, ASNs, and organization names.

    Unknown results are never cached while the country database is still
    loading, and the cache is invalidated whenever a new database generation
    finishes loading (so IPs first seen during the download window are
    re-resolved correctly instead of staying 'XX' forever).
    """

    def __init__(self, db_path=None):
        self.db_path = db_path
        self._cache = {}
        self._cache_gen = -1
        self._special = SPECIAL_RANGES
        self._custom_db = []
        self._load_custom_ranges()

    def _load_custom_ranges(self):
        """Loads optional local JSON/CSV mapping if present in DATA_DIR."""
        local_db = Path(self.db_path) if self.db_path and self.db_path != "auto" else DATA_DIR / "geoip_ranges.json"
        if local_db.exists():
            try:
                data = json.loads(local_db.read_text(encoding="utf-8"))
                for item in data:
                    net = ipaddress.ip_network(item["cidr"], strict=False)
                    self._custom_db.append((net, item.get("country", "XX"), int(item.get("asn", 0)), item.get("org", "Unknown")))
            except Exception as e:
                event("geoip_load_error", "low", error=str(e))

    def _remember(self, ip_str, res):
        if len(self._cache) > 10000:
            self._cache.clear()
        self._cache[ip_str] = res
        return res

    def resolve(self, ip_str: str) -> dict:
        """Resolves an IPv4 or IPv6 address string to geo/asn metadata."""
        if not ip_str or ip_str in ("::", "0.0.0.0", "localhost"):
            return {"country": "LOCAL", "asn": 0, "org": "Localhost"}

        # Drop stale cache when a new DB generation has loaded
        gen = _db_generation
        if self._cache_gen != gen:
            self._cache.clear()
            self._cache_gen = gen
        elif ip_str in self._cache:
            return self._cache[ip_str]

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return {"country": "UNKNOWN", "asn": 0, "org": "Invalid IP"}

        # Strip IPv4-mapped IPv6 to its real v4 address
        if ip_obj.version == 6 and int(ip_obj) >> 32 == 0xFFFF:
            ip_str = str(ipaddress.ip_address(int(ip_obj) & 0xFFFFFFFF))
            ip_obj = ipaddress.ip_address(ip_str)

        # Check special/private ranges first
        for net, country, asn, org in self._special:
            if ip_obj in net:
                return self._remember(ip_str, {"country": country, "asn": asn, "org": org})

        # Check custom/downloaded database
        for net, country, asn, org in self._custom_db:
            if ip_obj in net:
                return self._remember(ip_str, {"country": country, "asn": asn, "org": org})

        # Offline country blocks DB (auto-downloaded / bundled on demand)
        cc = country_lookup(ip_str)
        if cc:
            return self._remember(ip_str, {"country": cc, "asn": 0, "org": ""})

        # Unallocated/reserved legacy space — honest region label, never a fake country
        for net, rir, org in RIR_FALLBACK:
            if ip_obj in net:
                return self._remember(ip_str, {"country": rir, "asn": 0, "org": org})

        # Unknown AND the DB may still be loading — do NOT cache this result
        if not (_country_db.ready if ip_obj.version == 4 else _country_db_v6.ready):
            return {"country": "UNKNOWN", "asn": 0, "org": "GeoIP database still loading"}

        return self._remember(ip_str, {"country": "UNKNOWN", "asn": 0, "org": "Unallocated / unassigned"})
