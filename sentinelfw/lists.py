"""SentinelFW lists module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa


NOISE_DOMAINS = {"localhost", "localhost.localdomain", "broadcasthost", "local", "ip6-localhost", "ip6-loopback"}


DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z][a-z0-9-]{1,62}$")


def clean_lines(text):
    for line in text.splitlines():
        line = line.split("#")[0].split(";")[0].strip()
        if line:
            yield line


def to_net(tok):
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None


def clean_domain(tok):
    tok = tok.strip().strip(".").lower()
    if tok in NOISE_DOMAINS or not DOMAIN_RE.match(tok):
        return None
    try:
        ipaddress.ip_address(tok)
        return None
    except ValueError:
        return tok


def extract_ips(text, feed=False):
    out = []
    for line in clean_lines(text):
        for tok in line.replace(",", " ").split():
            n = to_net(tok)
            if n is None or n.prefixlen < (8 if n.version == 4 else 16):
                continue
            if feed and not n.is_global:
                continue  # feeds may never make us block private/reserved space
            out.append(n)
    return out


def extract_domains(text):
    out = set()
    for line in clean_lines(text):
        toks = line.split()
        if toks and to_net(toks[0]) is not None and len(toks) > 1:
            toks = toks[1:]  # hosts-file format
        for t in toks:
            d = clean_domain(t)
            if d:
                out.add(d)
    return out


def extract_hashes(text):
    return {t.lower() for line in clean_lines(text) for t in line.split() if re.fullmatch(r"[0-9a-fA-F]{64}", t)}


class IPSet:
    """Merged-range IP set with O(log n) membership tests."""

    def __init__(self, nets=()):
        self.nets = []
        self._r = {4: ([], []), 6: ([], [])}
        for ver in (4, 6):
            merged = list(ipaddress.collapse_addresses([n for n in nets if n.version == ver]))
            self.nets += merged
            self._r[ver] = ([int(n.network_address) for n in merged], [int(n.broadcast_address) for n in merged])

    def __contains__(self, ip):
        try:
            a = addr(ip)
        except ValueError:
            return False
        starts, ends = self._r[a.version]
        v = int(a)
        i = bisect.bisect_right(starts, v) - 1
        return i >= 0 and v <= ends[i]

    def __len__(self):
        return len(self.nets)


class Lists:
    def __init__(self):
        self.ipset = IPSet()
        self.domains = set()
        self.manual_domains = set()
        self.hashes = set()
        self.programs = []
        self._sig = None

    def refresh(self):
        files = sorted(LISTS.glob("*.txt"))
        try:
            sig = tuple((f.name, f.stat().st_mtime_ns, f.stat().st_size) for f in files)
        except OSError:
            return False
        if sig == self._sig:
            return False
        nets, doms, mdoms, hashes, progs = [], set(), set(), set(), []
        for f in files:
            name = f.name.lower()
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            feed = "_feed_" in name
            if name.startswith("ip_"):
                nets += extract_ips(text, feed)
            elif name.startswith("domain_"):
                d = extract_domains(text)
                doms |= d
                if not feed:
                    mdoms |= d
            elif name.startswith("hash_"):
                hashes |= extract_hashes(text)
            elif name.startswith("program_"):
                progs += [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        self.ipset, self.domains, self.manual_domains = IPSet(nets), doms, mdoms
        self.hashes, self.programs, self._sig = hashes, progs, sig
        return True

    def exact_programs(self):
        return sorted({p for p in self.programs if not any(c in p for c in "*?[")})


def list_edit(fname, value, add=True):
    path = LISTS / fname
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    present = any(ln.strip() == value for ln in lines)
    if add and not present:
        lines.append(value)
    elif not add and present:
        lines = [ln for ln in lines if ln.strip() != value]
    else:
        return False
    atomic_write(path, "\n".join(lines) + "\n")
    return True


def fetch(url, timeout=30, limit=64 * 1024 * 1024):
    req = urllib.request.Request(url, headers={"User-Agent": f"SentinelFW/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("feed too large")
    return data.decode("utf-8", "replace")


def update_feeds(eng):
    ok = 0
    for fd in eng.cfg["feeds"]:
        if not fd.get("enabled", True):
            continue
        kind = "domain" if fd["type"] == "domain" else "hash" if fd["type"] == "hash" else "ip"
        name = re.sub(r"[^a-z0-9_-]", "_", fd["name"].lower())
        try:
            text = fetch(fd["url"])
            if kind == "ip":
                entries = sorted({str(n) for n in extract_ips(text, True)})
            elif kind == "domain":
                entries = sorted(extract_domains(text))
            else:
                entries = sorted(extract_hashes(text))
            if len(entries) < int(fd.get("min_entries", 1)):
                raise ValueError("feed returned no usable entries; keeping previous copy")
            atomic_write(LISTS / f"{kind}_feed_{name}.txt",
                         f"# {fd['url']}\n# fetched {time.strftime('%Y-%m-%d %H:%M:%S')}\n" + "\n".join(entries) + "\n")
            event("feed_updated", feed=name, entries=len(entries))
            ok += 1
        except Exception as ex:  # noqa: BLE001
            event("feed_failed", "medium", feed=name, error=repr(ex)[:200])
    with eng.store.lock:
        eng.store.meta["last_update"] = time.time()
        eng.store.save()
    if ok:
        eng.apply_all()
    return ok
