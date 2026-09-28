"""SentinelFW procinfo module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa


LINUX_PROTECTED = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/boot/", "/etc/", "/snap/", "/proc/", "/sys/")


def linux_connections():
    inode_pid = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            for fd in os.listdir(f"/proc/{d}/fd"):
                try:
                    lk = os.readlink(f"/proc/{d}/fd/{fd}")
                except OSError:
                    continue
                if lk.startswith("socket:["):
                    inode_pid[int(lk[8:-1])] = int(d)
        except OSError:
            continue

    def dec(h):
        ip, port = h.split(":")
        if len(ip) == 8:
            a = socket.inet_ntoa(struct.pack("<I", int(ip, 16)))
        else:
            a = socket.inet_ntop(socket.AF_INET6, b"".join(struct.pack("<I", int(ip[i:i + 8], 16)) for i in range(0, 32, 8)))
        return str(addr(a)), int(port, 16)

    exe_cache, rows = {}, []
    for fname in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = Path(f"/proc/net/{fname}").read_text().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            f = ln.split()
            if len(f) < 10:
                continue
            try:
                la, lp = dec(f[1])
                ra, rp = dec(f[2])
            except (ValueError, struct.error):
                continue
            pid = inode_pid.get(int(f[9]))
            if pid is None:
                continue
            if pid not in exe_cache:
                try:
                    exe_cache[pid] = os.readlink(f"/proc/{pid}/exe")
                except OSError:
                    exe_cache[pid] = ""
            rows.append({"proto": fname, "laddr": la, "lport": lp, "raddr": "" if rp == 0 else ra, "rport": rp,
                         "state": f[3], "pid": pid, "exe": exe_cache[pid]})
    return rows


def win_exe(pid):
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    k.QueryFullProcessImageNameW.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    h = k.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(32768)
        n = wintypes.DWORD(len(buf))
        return buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else ""
    finally:
        k.CloseHandle(h)


def windows_connections():
    rc, out, _ = run(["netstat", "-ano"])
    if rc:
        return []
    exe_cache, rows = {}, []

    def split(a):
        h, _, p = a.rpartition(":")
        return h.strip("[]").split("%")[0], (int(p) if p.isdigit() else 0)

    for ln in out.splitlines():
        t = ln.split()
        if not t or t[0] not in ("TCP", "UDP"):
            continue
        try:
            if t[0] == "TCP" and len(t) >= 5:
                (la, lp), (ra, rp), state, pid = split(t[1]), split(t[2]), t[3], int(t[4])
            elif t[0] == "UDP" and len(t) >= 4:
                (la, lp), (ra, rp), state, pid = split(t[1]), split(t[2]) if t[2] != "*:*" else ("", 0), "", int(t[3])
            else:
                continue
        except ValueError:
            continue
        if pid not in exe_cache:
            exe_cache[pid] = win_exe(pid) if pid > 4 else ""
        if rp == 0 or ra in ("0.0.0.0", "::", ""):
            ra = ""
        rows.append({"proto": t[0].lower(), "laddr": la, "lport": lp, "raddr": ra, "rport": rp,
                     "state": state, "pid": pid, "exe": exe_cache[pid]})
    return rows


def get_connections():
    return windows_connections() if IS_WIN else linux_connections()


def kill_process(pid):
    if pid in (0, 1, 4) or pid == os.getpid():
        return False
    try:
        if IS_WIN:
            return run(["taskkill", "/PID", str(pid), "/F", "/T"])[0] == 0
        os.kill(pid, signal.SIGKILL)
        return True
    except OSError as e:
        event("kill_failed", "medium", pid=pid, error=e)
        return False


def is_protected_path(p):
    low = p.lower().replace("\\", "/")
    if low.startswith("/") or low.startswith(LINUX_PROTECTED):
        return low.startswith(LINUX_PROTECTED)
    if IS_WIN:
        sys_root = os.environ.get("SystemRoot", r"C:\Windows").lower().replace("\\", "/")
        prog_files = os.environ.get("ProgramFiles", r"C:\Program Files").lower().replace("\\", "/")
        prog_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower().replace("\\", "/")
        return low.startswith(sys_root + "/") or low.startswith(prog_files + "/") or low.startswith(prog_files_x86 + "/")
    return low.startswith(LINUX_PROTECTED)


_hash_cache = {}


def sha256_file(path, limit=256 * 1024 * 1024):
    st = os.stat(path)
    if st.st_size > limit:
        return None
    key = (path, st.st_size, st.st_mtime_ns)
    if key in _hash_cache:
        return _hash_cache[key]
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if len(_hash_cache) > 5000:
        _hash_cache.clear()
    _hash_cache[key] = h.hexdigest()
    return _hash_cache[key]


def manifest_load():
    try:
        return json.loads((QUAR / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def manifest_save(m):
    atomic_write(QUAR / "manifest.json", json.dumps(m, indent=2))


def dispose_file(path, reason, mode):
    """Quarantine (default) or permanently delete a malicious executable."""
    if not path or path.endswith(" (deleted)"):
        return "missing"
    if is_protected_path(path):
        event("file_action_refused", "high", path=path, reason="protected system path")
        return "protected"
    try:
        rp = os.path.realpath(path)
        if rp == os.path.realpath(sys.executable) or rp.startswith(str(PKG_DIR.parent) + os.sep):
            return "refused_self"
    except OSError:
        pass
    if not os.path.isfile(path):
        return "missing"
    try:
        sha = sha256_file(path)
        st = os.stat(path)
    except OSError as e:
        event("file_action_failed", "high", path=path, error=e)
        return "error"
    last = None
    for _ in range(8):  # the process may still be releasing the file
        try:
            if mode == "delete":
                os.remove(path)
                event("file_deleted", "high", path=path, sha256=sha, reason=reason)
                return "deleted"
            qid = uuid.uuid4().hex[:12]
            dest = QUAR / f"{qid}.quar"
            shutil.move(path, dest)
            if not IS_WIN:
                os.chmod(dest, 0o600)
            m = manifest_load()
            m[qid] = {"original": path, "sha256": sha, "reason": reason, "time": time.time(), "mode": st.st_mode}
            manifest_save(m)
            event("file_quarantined", "high", id=qid, path=path, sha256=sha, reason=reason)
            return "quarantined"
        except OSError as e:
            last = e
            time.sleep(0.5)
    event("file_action_failed", "high", path=path, error=last)
    return "error"


def quarantine_expire(days):
    """Permanently delete quarantined files older than `days` (0 = keep forever)."""
    if not days or days <= 0:
        return 0
    m = manifest_load()
    cut, n = time.time() - days * 86400, 0
    for k, v in list(m.items()):
        if v["time"] < cut:
            try:
                (QUAR / f"{k}.quar").unlink()
            except OSError:
                pass
            del m[k]
            n += 1
            event("quarantine_expired", id=k, path=v["original"])
    if n:
        manifest_save(m)
    return n
