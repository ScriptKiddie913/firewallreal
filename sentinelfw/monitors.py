"""SentinelFW monitors: response engine, socket monitor, exec watcher, housekeeping."""
import collections, fnmatch, os, socket, struct, threading, time
from .common import *  # noqa
from .procinfo import *  # noqa
from .lists import update_feeds  # noqa


class Responder:
    """Shared decision + enforcement logic. Acts autonomously - no prompts."""

    def __init__(self, eng):
        self.e = eng
        self.seen = {}
        self.lock = threading.Lock()

    def action_for(self, kind):
        if self.e.cfg.get("enforcement_profile", "aggressive") == "monitor":
            return "alert"
        return self.e.cfg["actions"].get(kind, "alert")

    def act(self, kind, pid, exe, detail):
        key, t = (pid, kind), time.time()
        with self.lock:
            if t - self.seen.get(key, 0) < 600:
                return False
            self.seen[key] = t
            if len(self.seen) > 5000:
                self.seen = {k: v for k, v in self.seen.items() if v > t - 600}
        action = self.action_for(kind)
        explicit = kind in ("blocked_program", "malicious_hash")
        if exe and is_protected_path(exe) and not explicit and action != "alert":
            event("action_downgraded", "low", kind=kind, exe=exe, note="OS-owned path: never killed by heuristics")
            action = "alert"
        event(kind, "high", pid=pid, exe=exe, detail=detail, action=action)
        killed = False
        if "kill" in action:
            killed = kill_process(pid)
        if "file" in action and exe:
            time.sleep(0.3 if killed else 0)
            dispose_file(exe, kind, self.e.cfg["malicious_file_action"])
        return killed

    def check_exe(self, pid, exe, exec_time=False):
        """Evaluate one executable. exec_time=True applies only rules that are safe before any network use."""
        if not exe:
            return False
        e, lists = self.e, self.e.lists
        deleted = exe.endswith(" (deleted)")
        path = exe[:-10] if deleted else exe
        if any(fnmatch.fnmatch(path, pat) for pat in lists.programs):
            return self.act("blocked_program", pid, path, "path rule")
        if lists.hashes and not deleted:
            try:
                h = sha256_file(path)
            except OSError:
                h = None
            if h and h in lists.hashes:
                return self.act("malicious_hash", pid, path, h)
        if exec_time:
            return False
        low = path.lower()
        dirs = e.cfg["suspicious_dirs"]["windows" if IS_WIN else "linux"]
        in_tmp = any(d.lower() in low for d in dirs)
        if deleted and (path.startswith("/memfd:") or in_tmp or not is_protected_path(path)):
            if self.act("deleted_executable", pid, exe, "binary removed from disk while running (fileless indicator)"):
                return True
        if in_tmp:
            return self.act("temp_dir_network", pid, path, "network activity from temp location")
        return False


class ProcessMonitor(threading.Thread):
    daemon = True

    def __init__(self, eng, resp):
        super().__init__(name="procmon")
        self.e, self.r = eng, resp

    def run(self):
        while not STOP.wait(float(self.e.cfg["monitor_interval"])):
            try:
                self.scan()
            except Exception as ex:  # noqa: BLE001
                event("monitor_error", "medium", error=repr(ex))

    def scan(self):
        e, r = self.e, self.r
        conns = get_connections()
        e.stats["scans"] += 1
        local, dead = e.guard.local, set()
        bad_ports = set(e.cfg["blocked_remote_ports"])
        by_pid = {}
        for c in conns:
            by_pid.setdefault(c["pid"], (c["exe"], []))[1].append(c)
        for pid, (exe, cs) in by_pid.items():
            for c in cs:
                rem = c["raddr"]
                if rem and rem not in local:
                    if e.blocked(rem) and r.act("blocklisted_ip_connection", pid, exe, f"{rem}:{c['rport']}"):
                        dead.add(pid)
                    if c["rport"] in bad_ports and r.act("blocked_port_connection", pid, exe, f"{rem}:{c['rport']}"):
                        dead.add(pid)
            if pid in dead or not exe:
                continue
            if r.check_exe(pid, exe):
                dead.add(pid)


# ---- exec-time hook: Linux netlink process connector / Windows process snapshots
def build_listen_msg():
    op = struct.pack("=I", 1)                                  # PROC_CN_MCAST_LISTEN
    cn = struct.pack("=IIIIHH", 1, 1, 0, 0, len(op), 0)        # CN_IDX_PROC, CN_VAL_PROC
    return struct.pack("=IHHII", 16 + len(cn) + len(op), 3, 0, 0, os.getpid()) + cn + op  # NLMSG_DONE


def parse_proc_events(data):
    """Return PIDs from PROC_EVENT_EXEC records in a netlink datagram."""
    out, off = [], 0
    while off + 16 <= len(data):
        ln, typ = struct.unpack_from("=IH", data, off)
        if ln < 16:
            break
        body = data[off + 16: off + ln]
        if typ == 3 and len(body) >= 44 and struct.unpack_from("=I", body, 20)[0] == 2:
            out.append(struct.unpack_from("=ii", body, 36)[1])  # (process_pid, process_tgid)
        off += (ln + 3) & ~3
    return out


class ExecWatcher(threading.Thread):
    """Kills blocked programs the instant they launch, before they can touch the network."""
    daemon = True

    def __init__(self, eng, resp):
        super().__init__(name="execwatch")
        self.e, self.r = eng, resp

    def check(self, pid):
        try:
            exe = os.readlink(f"/proc/{pid}/exe") if not IS_WIN else win_exe(pid)
        except OSError:
            return
        self.r.check_exe(pid, exe, exec_time=True)

    def run(self):
        (self.run_win if IS_WIN else self.run_linux)()

    def run_linux(self):
        try:
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 11)  # NETLINK_CONNECTOR
            s.bind((0, 1))
            s.send(build_listen_msg())
            s.settimeout(1.0)
        except OSError as ex:
            event("execwatch_unavailable", "medium", error=ex, note="falling back to socket polling only")
            return
        event("execwatch_started", mode="netlink proc connector")
        for d in os.listdir("/proc"):  # sweep processes that were already running
            if d.isdigit():
                self.check(int(d))
        while not STOP.is_set():
            try:
                data = s.recv(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            for pid in parse_proc_events(data):
                self.check(pid)

    def run_win(self):
        import ctypes
        from ctypes import wintypes

        class PE(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                        ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_wchar * 260)]

        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        for fn in (k.Process32FirstW, k.Process32NextW):
            fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]
            fn.restype = wintypes.BOOL
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        invalid = ctypes.c_void_p(-1).value
        event("execwatch_started", mode="process snapshot poll 0.4s")
        known = set()
        while not STOP.wait(0.4):
            snap = k.CreateToolhelp32Snapshot(0x2, 0)
            if snap in (None, 0, invalid):
                continue
            pe, pids = PE(), set()
            pe.dwSize = ctypes.sizeof(PE)
            ok = k.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                pids.add(pe.th32ProcessID)
                ok = k.Process32NextW(snap, ctypes.byref(pe))
            k.CloseHandle(snap)
            new, known = pids - known, pids
            for pid in new:
                if pid > 4:
                    self.check(pid)


class Housekeeper(threading.Thread):
    daemon = True

    def __init__(self, eng):
        super().__init__(name="housekeeper")
        self.e = eng
        self.updating = False
        self.last_guard = self.last_beat = self.last_q = time.time()

    def _update(self):
        try:
            update_feeds(self.e)
        finally:
            self.updating = False

    def run(self):
        e = self.e
        while not STOP.wait(5):
            try:
                e.store.load_cfg()
                for ip in e.store.purge():
                    e.backend.unban(ip)
                    event("ip_unbanned", ip=ip, reason="expired")
                if e.lists.refresh():
                    e.apply_all()
                t = time.time()
                if t - self.last_guard > 60:
                    e.guard.refresh()
                    self.last_guard = t
                if t - self.last_q > 300:
                    self.last_q = t
                    quarantine_expire(int(e.cfg["quarantine_retention_days"]))
                due = t - e.store.meta.get("last_update", 0) > float(e.cfg["update_interval_hours"]) * 3600
                if due and not self.updating:
                    self.updating = True
                    threading.Thread(target=self._update, daemon=True).start()
                if t - self.last_beat > 300:
                    self.last_beat = t
                    hb = dict(e.stats)
                    hb.update(bans=len(e.store.bans), blocked_ranges=len(e.lists.ipset),
                              blocked_domains=len(e.lists.domains), profile=e.cfg["enforcement_profile"])
                    event("heartbeat", **hb)
            except Exception as ex:  # noqa: BLE001
                event("housekeeper_error", "medium", error=repr(ex))
