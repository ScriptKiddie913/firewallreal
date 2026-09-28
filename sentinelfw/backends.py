"""SentinelFW backends module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa
from .policies import compile_nft, compile_windows


class NftBackend:
    name = "nftables"

    def __init__(self):
        self.ok = shutil.which("nft") is not None

    def begin(self):
        pass

    def commit(self):
        pass

    def _nft(self, script):
        rc, _, err = run(["nft", "-f", "-"], input=script)
        if rc:
            event("backend_error", "high", backend="nft", error=err.strip()[:400])
        return rc == 0

    def init(self):
        if not self.ok:
            raise RuntimeError("nft not found. Install it: sudo apt install nftables")
        L = ["add table inet sentinelfw"]
        for s, t in (("static4", "ipv4_addr; flags interval"), ("static6", "ipv6_addr; flags interval"),
                     ("dyn4", "ipv4_addr; flags timeout"), ("dyn6", "ipv6_addr; flags timeout")):
            L.append(f"add set inet sentinelfw {s} {{ type {t}; }}")
        for ch in ("input", "output", "forward"):
            L.append(f"add chain inet sentinelfw {ch} {{ type filter hook {ch} priority -10; policy accept; }}")
            L.append(f"flush chain inet sentinelfw {ch}")
        for ch, fields in (("input", ("saddr",)), ("output", ("daddr",)), ("forward", ("saddr", "daddr"))):
            for f in fields:
                for fam, n in (("ip", "4"), ("ip6", "6")):
                    for s in ("static", "dyn"):
                        L.append(f"add rule inet sentinelfw {ch} {fam} {f} @{s}{n} counter drop")
        return self._nft("\n".join(L) + "\n")

    def sync_static(self, nets):
        L = []
        for st, ver in (("static4", 4), ("static6", 6)):
            items = [str(n) for n in nets if n.version == ver]
            L.append(f"flush set inet sentinelfw {st}")
            for i in range(0, len(items), 1000):
                L.append(f"add element inet sentinelfw {st} {{ {', '.join(items[i:i + 1000])} }}")
        return self._nft("\n".join(L) + "\n")

    def sync_bans(self, bans):
        L = ["flush set inet sentinelfw dyn4", "flush set inet sentinelfw dyn6"]
        t = time.time()
        for ip, b in bans.items():
            rem = int(b["expires"] - t) if b["expires"] else 0
            if b["expires"] and rem <= 0:
                continue
            st = "dyn6" if ":" in ip else "dyn4"
            L.append(f"add element inet sentinelfw {st} {{ {ip}{f' timeout {rem}s' if rem else ''} }}")
        return self._nft("\n".join(L) + "\n")

    def ban(self, ip, seconds):
        st = "dyn6" if ":" in ip else "dyn4"
        run(["nft", "delete", "element", "inet", "sentinelfw", st, "{ " + ip + " }"])
        el = f"{ip} timeout {int(seconds)}s" if seconds else ip
        return run(["nft", "add", "element", "inet", "sentinelfw", st, "{ " + el + " }"])[0] == 0

    def unban(self, ip):
        st = "dyn6" if ":" in ip else "dyn4"
        run(["nft", "delete", "element", "inet", "sentinelfw", st, "{ " + ip + " }"])

    def sync_programs(self, paths):
        pass  # Linux has no per-executable netfilter match; enforced by the process monitor

    def sync_policies(self, policies):
        """Compiles and applies FortiGate-style ordered firewall policies."""
        if not self.ok:
            return False
        return self._nft(compile_nft(policies))

    def harden(self, ports, enable=True):
        L = ["add table inet sentinelfw_policy", "delete table inet sentinelfw_policy"]
        if enable:
            T = "inet sentinelfw_policy"
            L += [f"add table {T}",
                  f"add chain {T} input {{ type filter hook input priority 0; policy drop; }}",
                  f"add rule {T} input ct state established,related accept",
                  f"add rule {T} input ct state invalid drop",
                  f'add rule {T} input iifname "lo" accept',
                  f"add rule {T} input icmp type echo-request limit rate 5/second accept",
                  f"add rule {T} input icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept",
                  f"add rule {T} input meta l4proto ipv6-icmp accept",
                  f"add rule {T} input udp sport 67 udp dport 68 accept",
                  f"add rule {T} input udp sport 547 udp dport 546 accept"]
            if ports:
                L.append(f"add rule {T} input tcp dport {{ {', '.join(str(int(p)) for p in ports)} }} accept")
        return self._nft("\n".join(L) + "\n")

    def cleanup(self):
        run(["nft", "delete", "table", "inet", "sentinelfw"])
        run(["nft", "delete", "table", "inet", "sentinelfw_policy"])
        run(["nft", "delete", "table", "inet", "sentinelfw_pol"])


class WinBackend:
    name = "windows-advfirewall"
    PREFIX = "SentinelFW-"
    CHUNK = 200

    def __init__(self):
        self.static, self.dyn, self.programs, self.allow_ports = [], {}, set(), []
        self.existing, self.cache = set(), {}
        self.policy_rules = {}
        self.defer = False
        self.lock = threading.RLock()

    def begin(self):
        self.defer = True

    def commit(self):
        self.defer = False
        self._sync()

    def _list(self):
        rc, out, _ = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                          "(Get-NetFirewallRule -DisplayName 'SentinelFW-*' -ErrorAction SilentlyContinue).DisplayName"])
        return {ln.strip() for ln in out.splitlines() if ln.strip().startswith(self.PREFIX)} if rc == 0 else set()

    def init(self):
        self.existing = self._list()
        return True

    def _desired(self):
        d = {}
        nets = sorted(self.static, key=lambda n: (n.version, int(n.network_address), n.prefixlen))
        for grp, items in (("IPF", [str(n) for n in nets]), ("IPD", sorted(self.dyn))):
            for i in range(0, len(items), self.CHUNK):
                chunk = ",".join(items[i:i + self.CHUNK])
                for dr in ("in", "out"):
                    d[f"{self.PREFIX}{grp}-{i // self.CHUNK}-{dr}"] = {"dir": dr, "action": "block", "remoteip": chunk}
        for p in self.programs:
            hid = hashlib.sha1(p.lower().encode()).hexdigest()[:12]
            for dr in ("in", "out"):
                d[f"{self.PREFIX}APP-{hid}-{dr}"] = {"dir": dr, "action": "block", "program": p}
        if self.allow_ports:
            d[f"{self.PREFIX}ALLOW-TCP-in"] = {"dir": "in", "action": "allow", "protocol": "TCP",
                                                "localport": ",".join(str(int(p)) for p in self.allow_ports)}
        for name, spec in self.policy_rules.items():
            d[name] = spec
        return d

    def _add(self, name, spec):
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={spec['dir']}",
               f"action={spec['action']}", "enable=yes", "profile=any"]
        cmd += [f"{k}={spec[k]}" for k in ("program", "protocol", "localport", "remoteport", "remoteip") if k in spec]
        rc, out, err = run(cmd)
        if rc:
            event("backend_error", "high", backend="netsh", rule=name, error=(out + err).strip()[:300])
        return rc == 0

    def _del(self, name):
        run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        self.existing.discard(name)
        self.cache.pop(name, None)

    def _sync(self):
        with self.lock:
            want = self._desired()
            for name, spec in want.items():
                h = json.dumps(spec, sort_keys=True)
                if name in self.existing:
                    if self.cache.get(name) == h:
                        continue
                    new = [f"{k}={spec[k]}" for k in ("remoteip", "localport") if k in spec]
                    rc = run(["netsh", "advfirewall", "firewall", "set", "rule", f"name={name}", "new"] + new)[0] if new else 0
                    if rc:
                        self._del(name)
                        if not self._add(name, spec):
                            continue
                        self.existing.add(name)
                elif self._add(name, spec):
                    self.existing.add(name)
                else:
                    continue
                self.cache[name] = h
            for name in list(self.existing - set(want)):
                self._del(name)

    def _maybe(self):
        if not self.defer:
            self._sync()

    def sync_static(self, nets):
        self.static = list(nets)
        self._maybe()
        return True

    def sync_bans(self, bans):
        self.dyn = {ip: b["expires"] for ip, b in bans.items() if not b["expires"] or b["expires"] > time.time()}
        self._maybe()
        return True

    def ban(self, ip, seconds):
        self.dyn[ip] = time.time() + seconds if seconds else 0
        self._maybe()
        return True

    def unban(self, ip):
        self.dyn.pop(ip, None)
        self._maybe()

    def sync_programs(self, paths):
        self.programs = set(paths)
        self._maybe()

    def sync_policies(self, policies):
        """Compiles and applies FortiGate-style ordered firewall policies."""
        with self.lock:
            self.policy_rules = compile_windows(policies)
            self._maybe()
        return True

    def harden(self, ports, enable=True):
        run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
        run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"])
        self.allow_ports = list(ports) if enable else []
        self._maybe()
        return True

    def cleanup(self):
        for n in self._list():
            self._del(n)
        self.policy_rules = {}
