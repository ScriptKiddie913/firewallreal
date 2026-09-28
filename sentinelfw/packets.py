"""SentinelFW packets module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa


def parse_packet(buf, eth):
    off = 0
    if eth:
        if len(buf) < 14:
            return None
        et = struct.unpack("!H", buf[12:14])[0]
        off = 14
        if et == 0x8100 and len(buf) >= 18:
            et = struct.unpack("!H", buf[16:18])[0]
            off = 18
        v = 4 if et == 0x0800 else 6 if et == 0x86DD else 0
        if not v:
            return None
    else:
        if not buf:
            return None
        v = buf[0] >> 4
    frag = 0
    if v == 4:
        if len(buf) < off + 20:
            return None
        ihl = (buf[off] & 0x0F) * 4
        if ihl < 20 or len(buf) < off + ihl:
            return None
        tot = struct.unpack("!H", buf[off + 2:off + 4])[0]
        frag = struct.unpack("!H", buf[off + 6:off + 8])[0] & 0x1FFF
        proto = buf[off + 9]
        src, dst = socket.inet_ntoa(buf[off + 12:off + 16]), socket.inet_ntoa(buf[off + 16:off + 20])
        end = off + tot if 0 < tot <= len(buf) - off else len(buf)
        l4 = off + ihl
    elif v == 6:
        if len(buf) < off + 40:
            return None
        plen = struct.unpack("!H", buf[off + 4:off + 6])[0]
        nh = buf[off + 6]
        src, dst = socket.inet_ntop(socket.AF_INET6, buf[off + 8:off + 24]), socket.inet_ntop(socket.AF_INET6, buf[off + 24:off + 40])
        l4 = off + 40
        end = min(len(buf), l4 + plen)
        while nh in (0, 43, 60) and len(buf) >= l4 + 8:
            nh, l4 = buf[l4], l4 + (buf[l4 + 1] + 1) * 8
        proto = nh
        if nh == 44:
            frag = 1
    else:
        return None
    p = {"v": v, "proto": proto, "src": str(addr(src)), "dst": str(addr(dst)), "sport": 0, "dport": 0,
         "flags": 0, "payload": b"", "icmp": None}
    if frag:
        return p
    if proto == 6 and len(buf) >= l4 + 20:
        p["sport"], p["dport"] = struct.unpack("!HH", buf[l4:l4 + 4])
        doff = (buf[l4 + 12] >> 4) * 4
        p["flags"] = buf[l4 + 13]
        p["payload"] = buf[l4 + doff:end]
    elif proto == 17 and len(buf) >= l4 + 8:
        p["sport"], p["dport"] = struct.unpack("!HH", buf[l4:l4 + 4])
        p["payload"] = buf[l4 + 8:end]
    elif proto in (1, 58) and len(buf) > l4:
        p["icmp"] = buf[l4]
    return p


def dns_name(buf, off):
    labels, jumped, ret, hops = [], False, 0, 0
    while True:
        if off >= len(buf):
            raise ValueError("truncated")
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(buf):
                raise ValueError("truncated")
            if not jumped:
                ret = off + 2
            off = ((n & 0x3F) << 8) | buf[off + 1]
            jumped = True
            hops += 1
            if hops > 20:
                raise ValueError("loop")
            continue
        off += 1
        labels.append(buf[off:off + n].decode("ascii", "replace").lower())
        off += n
    return ".".join(labels), (ret if jumped else off)


def parse_dns(pl):
    try:
        if len(pl) < 12:
            return None
        _, flags, qd, an, _, _ = struct.unpack("!6H", pl[:12])
        off, qs, ans = 12, [], []
        for _ in range(min(qd, 4)):
            name, off = dns_name(pl, off)
            off += 4
            qs.append(name)
        resp = bool(flags & 0x8000)
        if resp:
            for _ in range(min(an, 32)):
                _, off = dns_name(pl, off)
                if off + 10 > len(pl):
                    break
                rtype, _, _, rdlen = struct.unpack("!HHIH", pl[off:off + 10])
                rd = pl[off + 10:off + 10 + rdlen]
                off += 10 + rdlen
                if rtype == 1 and rdlen == 4:
                    ans.append(socket.inet_ntoa(rd))
                elif rtype == 28 and rdlen == 16:
                    ans.append(socket.inet_ntop(socket.AF_INET6, rd))
        return {"response": resp, "questions": qs, "answers": ans}
    except (ValueError, struct.error, IndexError):
        return None
