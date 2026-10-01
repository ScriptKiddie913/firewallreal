"""SentinelFW cli module."""
import argparse, bisect, collections, fnmatch, functools, hashlib, ipaddress, json, logging, logging.handlers, math, os, re, shutil, signal, socket, struct, subprocess, sys, threading, time, urllib.request, uuid
from pathlib import Path
from .common import *  # noqa
from .config import *  # noqa
from .lists import *  # noqa
from .backends import *  # noqa
from .procinfo import *  # noqa
from .engine import *  # noqa
from .packets import *  # noqa
from .detector import *  # noqa
from .monitors import *  # noqa
from .procinfo import quarantine_expire  # noqa


ADMIN_ONLY_COMMANDS = {"run", "install-service", "cleanup", "harden", "unharden"}


def call_daemon_api(method="GET", endpoint="/api/v1/status", data=None):
    try:
        url = f"http://127.0.0.1:443{endpoint}"
        req_data = json.dumps(data).encode("utf-8") if data else None
        headers = {"Content-Type": "application/json"} if data else {}
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def need_admin():
    if not is_admin():
        sys.exit("SentinelFW needs root (Linux: sudo) or an elevated Administrator prompt (Windows).")


def cmd_status(a):
    eng = Engine()
    eng.lists.refresh()
    pid = int(PIDFILE.read_text()) if PIDFILE.exists() and PIDFILE.read_text().strip().isdigit() else 0
    print(f"SentinelFW {VERSION}  backend={eng.backend.name}  daemon={'running pid ' + str(pid) if pid and pid_alive(pid) else 'NOT running'}")
    print(f"data dir         : {HOME}")
    print(f"blocked ranges   : {len(eng.lists.ipset)}")
    print(f"blocked domains  : {len(eng.lists.domains)}")
    print(f"program rules    : {len(eng.lists.programs)}   hashes: {len(eng.lists.hashes)}")
    print(f"active bans      : {len(eng.store.bans)}")
    print(f"quarantined files: {len([k for k in manifest_load()])}")
    lu = eng.store.meta.get("last_update")
    print(f"last feed update : {time.strftime('%Y-%m-%d %H:%M', time.localtime(lu)) if lu else 'never'}")
    if IS_LINUX and eng.backend.ok:
        rc, out, _ = run(["nft", "list", "table", "inet", "sentinelfw"])
        print("nft table        :", "loaded" if rc == 0 else "not loaded")


def cmd_block_ip(a):
    net = to_net(a.target)
    if net is None or net.prefixlen < (8 if net.version == 4 else 16):
        sys.exit("invalid IP/CIDR (or range too large)")
    if not is_admin():
        dur = parse_duration(a.duration) if a.duration else 86400
        res = call_daemon_api("POST", "/api/v1/bans", {"ip": str(net.network_address), "duration": dur})
        if res and res.get("status") == "banned":
            print(f"[OK] Banned {net.network_address} via running SentinelFW daemon.")
            return
        sys.exit("SentinelFW background daemon is not running. Modifying rules directly requires an Administrator prompt.")
    eng = Engine()
    if a.duration:
        if net.num_addresses != 1:
            sys.exit("timed bans are for single IPs; permanent CIDR blocks omit --duration")
        eng.backend.init()
        eng.apply_all()
        ok = eng.ban(str(net.network_address), "manual", parse_duration(a.duration), "cli", force=a.force)
        print("banned" if ok else "not banned (protected or already banned; use --force)")
        return
    if not a.force and net.num_addresses == 1 and eng.guard.protected(str(net.network_address)):
        sys.exit("that address is protected (private/local/gateway/DNS). Use --force to override.")
    list_edit("ip_manual.txt", str(net))
    eng.backend.init()
    eng.apply_all()
    print("blocked", net)


def cmd_unblock_ip(a):
    n = to_net(a.target)
    if n is None:
        sys.exit("invalid IP/CIDR")
    if not is_admin():
        res = call_daemon_api("DELETE", f"/api/v1/bans/{n.network_address}")
        if res and res.get("status") == "unbanned":
            print(f"[OK] Unbanned {n.network_address} via running SentinelFW daemon.")
            return
        sys.exit("SentinelFW background daemon is not running. Modifying rules directly requires an Administrator prompt.")
    eng = Engine()
    eng.backend.init()
    r1 = eng.unban(str(n.network_address)) if n is not None and n.num_addresses == 1 else False
    r2 = list_edit("ip_manual.txt", str(n), add=False) if n is not None else False
    eng.apply_all()
    print("unblocked" if (r1 or r2) else "not found in bans or ip_manual.txt (feed entries: disable the feed or add to never_block)")


def _simple_list(fname, val, add, label):
    eng = Engine()
    eng.backend.init()
    changed = list_edit(fname, val, add)
    eng.apply_all()
    print(("added" if add else "removed") if changed else "no change", label, val)


def cmd_block_domain(a):
    d = clean_domain(a.target)
    if not d:
        sys.exit("invalid domain")
    _simple_list("domain_manual.txt", d, True, "domain")


def cmd_unblock_domain(a):
    _simple_list("domain_manual.txt", clean_domain(a.target) or a.target, False, "domain")


def cmd_block_program(a):
    _simple_list("program_manual.txt", a.target, True, "program")


def cmd_unblock_program(a):
    _simple_list("program_manual.txt", a.target, False, "program")


def cmd_block_hash(a):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", a.target):
        sys.exit("expected a SHA-256 hex digest")
    _simple_list("hash_manual.txt", a.target.lower(), True, "hash")


def cmd_list(a):
    eng = Engine()
    eng.lists.refresh()
    if a.what == "bans":
        for ip, b in sorted(eng.store.bans.items()):
            exp = time.strftime("%Y-%m-%d %H:%M", time.localtime(b["expires"])) if b["expires"] else "never"
            print(f"{ip:40} expires={exp:17} src={b['source']:5} {b['reason']}")
    elif a.what == "quarantine":
        for k, v in manifest_load().items():
            print(f"{k}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(v['time']))}  {v['original']}  sha256={v['sha256']}  ({v['reason']})")
    elif a.what == "domains":
        print("\n".join(sorted(eng.lists.domains)))
    elif a.what == "programs":
        print("\n".join(eng.lists.programs))


def cmd_update(a):
    eng = Engine()
    eng.backend.init()
    setup_logging()
    print(f"{update_feeds(eng)} feed(s) updated")


def cmd_quarantine_restore(a):
    m = manifest_load()
    v = m.get(a.id)
    if not v:
        sys.exit("unknown id")
    if os.path.exists(v["original"]):
        sys.exit("original path already exists; refusing to overwrite")
    os.makedirs(os.path.dirname(v["original"]), exist_ok=True)
    shutil.move(str(QUAR / f"{a.id}.quar"), v["original"])
    if not IS_WIN:
        os.chmod(v["original"], v["mode"] & 0o7777)
    del m[a.id]
    manifest_save(m)
    print("restored", v["original"])


def cmd_quarantine_purge(a):
    m = manifest_load()
    if a.id not in m:
        sys.exit("unknown id")
    try:
        (QUAR / f"{a.id}.quar").unlink()
    except OSError:
        pass
    del m[a.id]
    manifest_save(m)
    print("permanently deleted", a.id)


def cmd_harden(a):
    eng = Engine()
    ports = [] if (a.allow_ports or "").strip().lower() in ("", "none") else [int(p) for p in a.allow_ports.split(",")]
    if IS_LINUX and a.allow_ports is None:
        sys.exit("Linux default-deny inbound will drop SSH etc. Pass --allow-ports 22,443 (or 'none') explicitly.")
    eng.backend.init()
    cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    cfg["default_deny_inbound"], cfg["allow_inbound_ports"] = True, ports
    atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2))
    print("default-deny inbound enabled" if eng.backend.harden(ports, True) else "failed, see log", "| allowed TCP ports:", ports or "none")


def cmd_unharden(a):
    eng = Engine()
    eng.backend.init()
    cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    cfg["default_deny_inbound"] = False
    atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2))
    if IS_LINUX:
        eng.backend.harden([], False)
    else:
        eng.backend.harden([], False)
    print("default-deny inbound disabled")


def cmd_cleanup(a):
    eng = Engine()
    eng.backend.init() if IS_WIN else None
    eng.backend.cleanup()
    eng.cfg["hosts_file_sinkhole"] = False
    eng.lists.domains = set()
    sync_hosts(eng)
    print("all SentinelFW firewall rules and hosts entries removed (lists/config/quarantine kept)")


def cmd_uninstall_service(a):
    if IS_WIN:
        run(["schtasks", "/End", "/TN", "SentinelFW"])
        run(["schtasks", "/Delete", "/TN", "SentinelFW", "/F"])
    else:
        run(["systemctl", "disable", "--now", "sentinelfw"])
        try:
            Path("/etc/systemd/system/sentinelfw.service").unlink()
        except OSError:
            pass
        run(["systemctl", "daemon-reload"])
    print("service removed (firewall rules remain until 'cleanup')")


def build_parser():
    ap = argparse.ArgumentParser(prog="sentinelfw", description="SentinelFW - host firewall, IPS and autonomous threat response")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, *args):
        p = sub.add_parser(name, help=help_)
        for spec, kw in args:
            p.add_argument(spec, **kw)
        p.set_defaults(func=fn)

    add("run", cmd_run, "run the firewall daemon (foreground)", ("--no-sniffer", {"action": "store_true"}))

    def cmd_audit_verify(_args):
        from .mgmt import audit_verify
        r = audit_verify()
        print(f"audit chain: {'INTACT' if r.get('ok') else 'BROKEN'} · {r.get('records', 0)} record(s)"
              + (f" · first bad record: line {r['first_bad']}" if r.get("first_bad") else ""))
        sys.exit(0 if r.get("ok") else 1)

    add("audit-verify", cmd_audit_verify, "verify the hash-chained audit log")

    def cmd_commit_confirm(_args):
        from .engine import Engine
        e = Engine()
        r = e.commit_stage()
        print(json.dumps(r, indent=2))
        print("Changes are now STAGED. Re-run within the TTL to confirm:")
        print("  python sfwctl.py commit-confirmed     (keep changes)")
        print("  python sfwctl.py commit-rollback     (revert now)")

    def cmd_commit_confirmed(_args):
        from .engine import Engine
        print(json.dumps(Engine().commit_confirm(), indent=2))

    def cmd_commit_rollback(_args):
        from .engine import Engine
        print(json.dumps(Engine().commit_rollback("cli manual"), indent=2))

    def cmd_persistence_baseline(_args):
        from .forensics import PersistenceWatch
        n = PersistenceWatch(lambda: {}).baseline()
        print(f"persistence baseline set: {n} watched locations")

    add("commit-confirm", cmd_commit_confirm, "stage config changes (auto-rollback on timeout)")
    add("commit-confirmed", cmd_commit_confirmed, "confirm staged changes")
    def cmd_simulate(args):
        from .policies import FirewallPolicies
        store = Store()
        fp = FirewallPolicies(store.cfg)
        res = fp.simulate(
            src_ip=args.src, dst_ip=args.dst, port=args.port, proto=args.proto,
            user=args.user or "", app=args.app or ""
        )
        print("\n=== SentinelGate Policy Simulation Report ===")
        print(f"Matched Rule   : {'#' + str(res['policy_id']) + ' (' + res['policy_name'] + ')' if res['matched'] else 'None (Implicit Deny)'}")
        print(f"Final Action   : {res['action']}")
        print(f"Flow Path      : {res['flow_path']}")
        print(f"Reason         : {res['reason']}")
        print(f"NAT Translation: {res['nat']['type'].upper() + (' to ' + res['nat']['target'] if res['nat']['target'] else '') if res['nat']['enabled'] else 'None'}")
        print("\n--- Security Profiles Evaluated ---")
        for prof, active in res['security_profiles'].items():
            print(f"  {prof:<16}: {'ENABLED' if active else 'disabled'}")
        print("============================================\n")

    add("simulate", cmd_simulate, "simulate policy evaluation for virtual packet (Phase 46)",
        ("--src", {"required": True, "help": "Source IP address"}),
        ("--dst", {"required": True, "help": "Destination IP address"}),
        ("--port", {"type": int, "default": 443, "help": "Destination port (default 443)"}),
        ("--proto", {"default": "tcp", "help": "Transport protocol (tcp/udp/icmp)"}),
        ("--app", {"default": "", "help": "Application identifier (e.g. HTTPS, DNS)"}),
        ("--user", {"default": "", "help": "User identity (optional)"}))

    def cmd_fleet_agent(args):
        from .engine import Engine
        from .ops import FleetAgent
        e = Engine()
        agent = FleetAgent(lambda: e.cfg, e, args.relay, args.key,
                           interval=int(args.interval))
        agent.start()
        print(f"fleet agent running -> {args.relay} (ctrl-c to stop)")
        try:
            import time as _t
            while True:
                _t.sleep(3600)
        except KeyboardInterrupt:
            pass

    def cmd_tls_gencert(_args):
        from .integrations import generate_self_signed
        from .common import HOME
        cert = HOME / "console.crt"
        key = HOME / "console.key"
        if generate_self_signed(cert, key):
            print(f"self-signed cert written: {cert} / {key}")
            print("set webui_tls: {enabled: true, cert_file: <cert>, key_file: <key>}")
            print("(for production, use your PKI / Let's Encrypt instead)")
        else:
            print("openssl CLI not available — generate a cert manually and set webui_tls")
            sys.exit(1)

    add("tls-gencert", cmd_tls_gencert, "generate a self-signed console TLS certificate")

    def cmd_integrations(_args):
        from .integrations import IntegrationManager, GoServiceSupervisor
        im = IntegrationManager(lambda: {})
        gs = GoServiceSupervisor(lambda: {})
        det = im.detect()
        print(f"suricata: {'PRESENT' if det['suricata'] else 'MISSING (auto-install on start where possible)'}")
        print(f"clamav:   {'PRESENT' if det['clamav'] else 'MISSING (auto-install on start where possible)'}")
        print(f"go toolchain: {'PRESENT' if gs.go_available() else 'NOT INSTALLED (go_services supervisor idle)'}")

    add("integrations", cmd_integrations, "show integration (suricata/clamav/go) status")

    add("fleet-agent", cmd_fleet_agent, "report this host to a central SentinelFW relay",
        ("--relay", {"required": True, "help": "relay base URL, e.g. http://relay:443"}),
        ("--key", {"required": True, "help": "fleet shared key (set on the relay console)"}),
        ("--interval", {"default": "30", "help": "heartbeat seconds"}))
    add("status", cmd_status, "show state")
    add("block-ip", cmd_block_ip, "block IP/CIDR (permanent, or timed with --duration)", ("target", {}),
        ("--duration", {}), ("--force", {"action": "store_true"}))
    add("unblock-ip", cmd_unblock_ip, "remove a ban / manual block", ("target", {}))
    add("block-domain", cmd_block_domain, "add domain to blocklist", ("target", {}))
    add("unblock-domain", cmd_unblock_domain, "remove domain from manual list", ("target", {}))
    add("block-program", cmd_block_program, "block an executable path or glob", ("target", {}))
    add("unblock-program", cmd_unblock_program, "remove program rule", ("target", {}))
    add("block-hash", cmd_block_hash, "add SHA-256 of a malicious executable", ("target", {}))
    add("list", cmd_list, "list bans | quarantine | domains | programs", ("what", {"choices": ["bans", "quarantine", "domains", "programs"]}))
    add("update-lists", cmd_update, "download all enabled feeds now")
    add("quarantine-restore", cmd_quarantine_restore, "restore a quarantined file", ("id", {}))
    add("quarantine-purge", cmd_quarantine_purge, "permanently delete a quarantined file", ("id", {}))
    add("harden", cmd_harden, "enable default-deny inbound", ("--allow-ports", {"help": "e.g. 22,443 or 'none'"}))
    add("unharden", cmd_unharden, "disable default-deny inbound")
    add("cleanup", cmd_cleanup, "remove every firewall rule and hosts entry SentinelFW created")
    add("mode", cmd_mode, "set enforcement profile: aggressive (kill/delete) or monitor (log only)", ("profile", {"choices": ["aggressive", "monitor"]}))
    add("install-service", cmd_install_service, "start at boot (systemd / scheduled task)")
    add("conns", cmd_conns, "show live process network connections and GeoIP")
    add("appwall", cmd_appwall, "show per-application firewall policy rules")
    add("sandbox", cmd_sandbox_submit, "detonate a suspicious file in the behavioral sandbox", ("file", {}))
    add("honeypot", cmd_honeypot_sessions, "view honeypot decoy interactions")
    add("integrity", cmd_integrity_check, "verify source code integrity and anti-tampering state")
    add("modules", cmd_modules, "show runtime status and stats of all 18 SentinelFW 4.0 modules")
    add("get", cmd_fortios_get, "FortiOS-style get (e.g. 'get system status', 'get firewall policy')", ("target", {"nargs": "+"}))
    add("set", cmd_fortios_set, "FortiOS-style set (e.g. 'set firewall policy <id> <key> <val>')", ("target", {"nargs": "+"}))
    add("diagnose", cmd_fortios_diagnose, "FortiOS-style diagnose (e.g. 'diagnose sniffer packet any')", ("target", {"nargs": "+"}))
    return ap


def cmd_modules(a):
    eng = Engine()
    mods = [
        ("WAF Reverse Proxy", "waf", "active" if getattr(eng.waf, "running", False) else "standby"),
        ("Identity Directory", "identity", "active"),
        ("NAT Manager", "nat", "active"),
        ("Object Catalog", "objects", "active"),
        ("Zone Architecture", "zones", "active"),
        ("App-ID Classifier", "appid", "active"),
        ("DLP Inspector", "dlp", "active"),
        ("Playbook Engine", "playbook", "active"),
        ("Compliance Auditor", "compliance", "active"),
        ("Correlation Engine", "correlation", "active"),
        ("Asset & Flow Map", "assetmap", "active"),
        ("Threat Intel Feeds", "feeds", "active"),
        ("Advanced Decoys", "decoy_advanced", "active" if getattr(eng.advanced_decoys, "running", False) else "standby"),
        ("Tarpit Manager", "tarpit", "active" if getattr(eng.tarpit, "running", False) else "standby"),
        ("Anti-Tamper Watchdog", "watchdog", "active"),
        ("Fleet Manager", "fleet", "active"),
        ("Gateway Sync", "gateway_sync", "active" if eng.gateway_sync.configured() else "standby"),
        ("Kill Chain Tracker", "killchain", "active"),
        ("Protocol Analyzer", "protocols", "active"),
    ]
    print(f"{'Module':<24} {'Identifier':<16} {'Runtime Status'}")
    print("-" * 55)
    for title, mod_id, status in mods:
        print(f"{title:<24} {mod_id:<16} {status.upper()}")


def cmd_conns(a):
    records = None
    if not is_admin():
        records = call_daemon_api("GET", "/api/v1/connections")
    if records is None:
        eng = Engine()
        records = eng.conntrack.snapshot()
    if not records:
        print("No active connections found.")
        return
    print(f"{'PID':<7} {'PROTO':<6} {'LOCAL ADDR':<22} {'REMOTE ADDR':<22} {'GEO/ASN':<20} {'EXE'}")
    print("-" * 100)
    for r in records[:50]:
        geo_str = f"{r.get('country', '')} AS{r.get('asn', 0)}" if r.get('asn') else r.get('country', '')
        remote = f"{r['raddr']}:{r['rport']}" if r['raddr'] else "*"
        local = f"{r['laddr']}:{r['lport']}"
        print(f"{r['pid']:<7} {r['proto'].upper():<6} {local:<22} {remote:<22} {geo_str:<20} {r['exe']}")


def cmd_appwall(a):
    eng = Engine()
    pols = eng.cfg.get("application_firewall", {}).get("policies", [])
    if not pols:
        print("Application Firewall active. No custom rules configured (default policy: allow).")
        return
    print(f"Total Rules: {len(pols)}")
    for i, p in enumerate(pols, 1):
        print(f"Rule #{i}: match={p.get('match')} allow_out={p.get('allow_outbound')} deny_dests={p.get('deny_destinations')} action={p.get('action_on_violation')}")


def cmd_sandbox_submit(a):
    target = Path(a.file)
    if not target.is_file():
        sys.exit(f"Target file not found: {a.file}")
    eng = Engine()
    print(f"[*] Detonating sample in isolated sandbox: {target.name}...")
    report = eng.sandbox.analyze_file(target)
    print("\n--- Sandbox Detonation Report ---")
    print(f"Verdict:       {report.get('verdict')}")
    print(f"Risk Score:    {report.get('total_score')}")
    print(f"Duration:      {report.get('duration')}s")
    print(f"Indicators:    {', '.join(report.get('indicators', [])) or 'None'}")
    print(f"Files Dropped: {', '.join(report.get('files_created', [])) or 'None'}")


def cmd_honeypot_sessions(a):
    sessions = None
    if not is_admin():
        sessions = call_daemon_api("GET", "/api/v1/honeypot/sessions")
    if sessions is None:
        eng = Engine()
        sessions = eng.honeypot.get_sessions()
    if not sessions:
        print("No active honeypot sessions logged.")
        return
    for s in sessions:
        print(f"[{s['service'].upper()}] from {s['src_ip']}:{s['src_port']} ({s['duration']}s) - commands: {s['commands']}")


def cmd_integrity_check(a):
    eng = Engine()
    clean, tampered = eng.selfprotect.verify_integrity()
    if clean:
        print("[OK] Source code integrity verified. No unauthorized modifications detected.")
    else:
        print(f"[CRITICAL] Code tampering detected in {len(tampered)} files:")
        for t in tampered:
            print("  -", t)


def main(argv=None):
    a = build_parser().parse_args(argv)
    if a.cmd in ADMIN_ONLY_COMMANDS and not is_admin():
        sys.exit(f"SentinelFW command '{a.cmd}' requires an elevated Administrator prompt (or run 'install-service' as Admin once to run in the background).")
    setup_logging()
    Store()
    a.func(a)


def cmd_run(a):
    eng = Engine()
    eng.backend.init()
    eng.apply_all()
    PIDFILE.write_text(str(os.getpid()))
    event("started", version=VERSION, backend=eng.backend.name, profile=eng.cfg["enforcement_profile"],
          bans=len(eng.store.bans), blocked_ranges=len(eng.lists.ipset), blocked_domains=len(eng.lists.domains))
    for sig in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), lambda *_: STOP.set())
    resp = Responder(eng)
    threads = [
        ProcessMonitor(eng, resp),
        Housekeeper(eng),
        eng.conntrack,
        eng.canary,
        eng.baseline,
        eng.selfprotect,
    ]
    if eng.cfg["exec_watch"]:
        threads.append(ExecWatcher(eng, resp))
    if eng.cfg["sniffer_enabled"] and not a.no_sniffer:
        threads.append(Sniffer(eng))
    if eng.cfg.get("elasticsearch", {}).get("enabled", False):
        threads.append(eng.elastic)
    if eng.cfg.get("honeypot", {}).get("enabled", True):
        eng.honeypot.start()
    if eng.cfg.get("suricata", {}).get("enabled", True) and eng.suricata_mgr.is_available():
        eng.suricata_mgr.start()
        threads.append(eng.suricata_ingest)
    if eng.cfg.get("waf", {}).get("enabled", False):
        eng.waf.start()
    if eng.cfg.get("advanced_decoys", {}).get("enabled", False):
        eng.advanced_decoys.start()
    if eng.cfg.get("tarpit", {}).get("enabled", False):
        eng.tarpit.start()
    if eng.cfg.get("watchdog", {}).get("enabled", True):
        eng.watchdog.record_baseline(CONFIG_FILE)

    if eng.cfg.get("webui", {}).get("enabled", True):
        from .webui import SentinelWebUI
        wcfg = eng.cfg.get("webui", {})
        eng.webui = SentinelWebUI(
            host=wcfg.get("listen", "127.0.0.1"),
            port=int(wcfg.get("port", 443)),
            engine=eng,
            conntrack=eng.conntrack,
            honeypot=eng.honeypot,
            sandbox=eng.sandbox,
            baseline=eng.baseline,
        )
        eng.webui.start_background()

    for t in threads:
        t.start()
    while not STOP.wait(1):
        pass
    event("stopping", note="firewall rules stay active; run 'cleanup' to remove them")
    try:
        PIDFILE.unlink()
    except OSError:
        pass
    if eng.webui:
        eng.webui.stop()
    if hasattr(eng, "waf") and getattr(eng.waf, "running", False):
        eng.waf.stop()
    if hasattr(eng, "advanced_decoys") and getattr(eng.advanced_decoys, "running", False):
        eng.advanced_decoys.stop()
    if hasattr(eng, "tarpit") and getattr(eng.tarpit, "running", False):
        eng.tarpit.stop()
    eng.honeypot.stop()
    eng.suricata_mgr.stop()
    time.sleep(1.5)


def cmd_mode(a):
    store = Store()
    cfg = store.cfg
    cfg["enforcement_profile"] = a.profile
    atomic_write(CONFIG_FILE, json.dumps(cfg, indent=2))
    print("enforcement profile:", a.profile, "(a running daemon picks this up within seconds)")


def cmd_install_service(a):
    launcher = str(Path(__file__).resolve().parent.parent / "sfwctl.py")
    if IS_WIN:
        q = lambda x: x.replace("'", "''")  # noqa: E731
        ps = (f"$a=New-ScheduledTaskAction -Execute '{q(sys.executable)}' -Argument '\"{q(launcher)}\" run';"
              "$t=New-ScheduledTaskTrigger -AtStartup;"
              "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
              "$s=New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) "
              "-ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
              "Register-ScheduledTask -TaskName SentinelFW -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null;"
              "Start-ScheduledTask -TaskName SentinelFW")
        rc, out, err = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
        print("installed scheduled task 'SentinelFW' (boot, SYSTEM, auto-restart)" if rc == 0 else f"failed: {out}{err}")
        return
    unit = f"""[Unit]
Description=SentinelFW host firewall and threat response
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory={os.path.dirname(launcher)}
ExecStart={sys.executable} {launcher} run
Restart=always
RestartSec=2
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/sentinelfw.service").write_text(unit)
    run(["systemctl", "daemon-reload"])
    rc, out, err = run(["systemctl", "enable", "--now", "sentinelfw"])
    print("installed and started systemd unit sentinelfw" if rc == 0 else f"failed: {out}{err}")


def cmd_fortios_get(a):
    """FortiOS-style get: 'get system status', 'get firewall policy', etc."""
    tokens = [t.lower() for t in getattr(a, "target", [])]
    if not tokens:
        print("Usage: get system status | get firewall policy | get firewall address | get system interface")
        return

    path = " ".join(tokens)
    if path.startswith("system status"):
        eng = Engine()
        print(f"Version: SentinelGate / SentinelFW v{VERSION}")
        print(f"Hostname: {socket.gethostname()}")
        print(f"Backend: {eng.backend.name}")
        print(f"Operation Mode: {eng.cfg.get('enforcement_profile', 'aggressive')}")
        print(f"Active IP Bans: {len(eng.store.bans)}")
        print(f"Blocked Ranges: {len(eng.lists.ipset)}")
        print(f"Blocked Domains: {len(eng.lists.domains)}")
        print("HA State: standalone")
    elif path.startswith("firewall policy"):
        from .policies import FirewallPolicies
        fp = FirewallPolicies(Store().cfg)
        pols = fp.list()
        print(f"{'ID':<4} {'Name':<24} {'Src':<16} {'Dst':<16} {'Action':<8} {'NAT':<6} {'Status'}")
        print("-" * 88)
        for p in pols:
            src = ",".join(p.get("src", ["any"])[:2])
            dst = ",".join(p.get("dst", ["any"])[:2])
            status = "enabled" if p.get("enabled", True) else "disabled"
            nat = "yes" if p.get("nat") else "no"
            print(f"{p.get('id', 0):<4} {p.get('name', 'unnamed')[:23]:<24} {src[:15]:<16} {dst[:15]:<16} {p.get('action', 'deny'):<8} {nat:<6} {status}")
    elif path.startswith("firewall address"):
        store = Store()
        ag = store.cfg.get("address_groups", {})
        print(f"{'Group Name':<24} {'Members'}")
        print("-" * 60)
        for name, members in ag.items():
            print(f"{name:<24} {', '.join(members)}")
    elif path.startswith("system interface"):
        from .zones import ZoneManager
        zm = ZoneManager(Store().cfg)
        print(f"{'Zone':<12} {'Interfaces'}")
        print("-" * 40)
        for z in zm.list_zones():
            print(f"{z['name']:<12} {', '.join(z['interfaces']) if z['interfaces'] else '(none)'}")
    elif path.startswith("system modules"):
        cmd_modules(a)
    else:
        print(f"Unknown target: {path}. Try 'get system status' or 'get system modules' or 'get firewall policy'.")


def cmd_fortios_set(a):
    """FortiOS-style set: 'set firewall policy <id> <field> <value>'"""
    tokens = getattr(a, "target", [])
    if len(tokens) < 4 or tokens[0].lower() != "firewall" or tokens[1].lower() != "policy":
        print("Usage: set firewall policy <id> <field> <value>")
        return

    try:
        pol_id = int(tokens[2])
    except ValueError:
        print("Error: policy ID must be an integer.")
        return

    field = tokens[3].lower()
    value = " ".join(tokens[4:])
    from .policies import FirewallPolicies
    store = Store()
    fp = FirewallPolicies(store.cfg, config_persist=store.save)
    val = value.lower() == "true" if field == "enabled" else value
    res = fp.update(pol_id, {field: val})
    if "error" in res:
        print(f"Error: {res['error']}")
    else:
        print(f"Updated policy {pol_id}: {field} = {value}")


def cmd_fortios_diagnose(a):
    """FortiOS-style diagnose: 'diagnose sniffer packet <interface> <filter> <count>'"""
    tokens = getattr(a, "target", [])
    if not tokens:
        print("Usage: diagnose sniffer packet <interface> [filter] [count]")
        return

    sub = tokens[0].lower()
    if sub == "sniffer" and len(tokens) >= 2 and tokens[1].lower() == "packet":
        iface = tokens[2] if len(tokens) > 2 else "any"
        flt = tokens[3] if len(tokens) > 3 else "all"
        count = int(tokens[4]) if len(tokens) > 4 and tokens[4].isdigit() else 5
        print(f"Starting packet sniffer on '{iface}' (filter: {flt}, max {count} packets)...")
        from .detector import Sniffer
        captured = []
        def _cb(frame):
            if len(captured) < count:
                captured.append(frame)
                print(f"  [{len(captured)}] {len(frame)} bytes captured")
        sn = Sniffer(_cb)
        t = threading.Thread(target=sn.run, daemon=True)
        t.start()
        for _ in range(30):
            if len(captured) >= count:
                break
            time.sleep(0.1)
        sn.stop()
        print(f"Completed: captured {len(captured)} packets.")
    elif sub == "sys":
        eng = Engine()
        print(f"System status: Engine active={eng.running}, Backend={eng.backend.name}")
    else:
        print(f"Unknown diagnose command: {' '.join(tokens)}")

