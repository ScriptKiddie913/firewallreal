# SentinelFW — Enterprise Deployment Guide

Production hardening and rollout for SentinelFW 3.x (v2.9 codebase). Read this
before exposing the console to anything beyond loopback.

---

## 1. Choose the deployment shape

| Shape | Use it for | Notes |
|---|---|---|
| **Single host agent** | One server / workstation | Default mode. All enforcement is local. |
| **Gateway box** | Protecting a small segment | Machine has two NICs; enable DNS filter + default-deny inbound. |
| **Fleet (central relay)** | 3+ hosts | One console acts as relay; every other host runs the fleet agent and pulls the shared blocklist. |

The console binds `0.0.0.0:443` by default. **In production, prefer binding to
loopback and fronting with a TLS reverse proxy or accessing via VPN/SSH
tunnel** (section 4).

## 2. Install

Requirements: Python 3.8+ (stdlib only — no pip dependencies), root/Administrator.

```bash
# Linux (Ubuntu 22.04+)
sudo useradd -r -m -d /opt/sentinelfw -s /usr/sbin/nologin sentinelfw
sudo -u sentinelfw git clone <your-repo> /opt/sentinelfw/app   # or unzip the release
sudo -u sentinelfw python3 /opt/sentinelfw/app/sfwwctl.py migrate   # if upgrading
```

```powershell
# Windows 10/11/Server — copy the folder to C:\Program Files\SentinelFW
# Run elevated PowerShell:
cd "C:\Program Files\SentinelFW"
python sfwctl.py run
```

First boot creates `/var/lib/sentinelfw` (Linux) or
`C:\ProgramData\SentinelFW` (Windows) with `config.json` at `policy_version` 7.
Upgrades migrate automatically; `policy_version` never downgrades your config.

## 3. Run as a service

**Linux — systemd** (`/etc/systemd/system/sentinelfw.service`):

```ini
[Unit]
Description=SentinelFW host firewall & IPS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sentinelfw
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
WorkingDirectory=/opt/sentinelfw/app
ExecStart=/usr/bin/python3 sfwctl.py run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sentinelfw /opt/sentinelfw/app/_test_data

[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now sentinelfw` — the service drops to your
`sentinelfw` user but keeps the two capabilities it needs (net admin for
nftables, raw for the sniffer). Never run as full root if you can avoid it.

**Windows — NSSM** (recommended):

```powershell
nssm install SentinelFW "C:\Program Files\SentinelFW\python.exe" "sfwctl.py run"
nssm set SentinelFW AppDirectory "C:\Program Files\SentinelFW"
nssm set SentinelFW ObjectName LocalSystem   # needed for firewall + hosts + WFP
nssm start SentinelFW
```

(The built-in `sc create` works too but has no auto-restart without recovery
config; NSSM handles crashes, rotation-friendly stdout, and elevation.)

## 4. Network exposure & TLS

The built-in console is HTTP + strong auth (scrypt, sessions, CSRF, optional
TOTP). For enterprise use, terminate TLS in front of it:

**Caddy (simplest)**:

```
fw.example.internal {
    reverse_proxy 127.0.0.1:443
}
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name fw.example.internal;
    ssl_certificate     /etc/ssl/certs/fw.pem;
    ssl_certificate_key /etc/ssl/private/fw.key;
    location / {
        proxy_pass http://127.0.0.1:443;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;           # SSE live stream
        proxy_read_timeout 3600s;      # keep the event stream open
    }
}
```

Then restrict the console port itself: `ufw allow from 10.0.0.0/8 to any port 443`
or bind `webui.listen` to `127.0.0.1`. Fleet relay traffic inherits the same
TLS — point agents at `https://fw.example.internal`.

**Built-in TLS option:** instead of a reverse proxy you can set
`webui_tls: {enabled: true, cert_file: ..., key_file: ...}` and run
`sfwctl tls-gencert` for a lab cert. Inject API keys from the environment
rather than config.json: `SFW_VT_KEY`, `SFW_TELEGRAM_TOKEN`,
`SFW_SARVAM_KEY`, `SFW_FLEET_KEY` (systemd `Environment=`) — 3.0 never writes
them back to disk. On first login with the default password the console
forces a scrypt password change before allowing any configuration write.

**Access rules:** the console should only ever be reachable from your admin
VLAN / VPN. Add the VPN and admin ranges to `trusted_ips` so a fat-fingered
ban can never lock you out (the engine also hard-refuses to ban private,
gateway, DNS and its own IPs — keep that safety net on).

## 5. First-hour hardening checklist

1. **Change the console password** — anything but the shipped default:
   `python3 -c "from sentinelfw.mgmt import hash_password; print(hash_password('YOUR-PW'))"`
   → put the output in `webui.password_hash`. The console shows a red banner
   until you do.
2. **Enable 2FA** (Settings → Console Security → ENABLE 2FA) — TOTP with any
   authenticator app, 8 single-use recovery codes.
3. **Enable the Log Vault** with a seal key (Settings → Log Vault) —
   blockchain-grade tamper-evident sealing of the event log.
4. **Turn on commit-confirm** before making risky policy changes; stage, then
   confirm within 5 minutes or it reverts itself.
5. **Ship logs off-box**: Settings → Syslog (RFC 5424/CEF) to your SIEM, and
   scrape `GET /metrics` from Prometheus. STIX 2.1 export is one URL for your
   TIP.
6. **Disk encryption at rest** (this is the real "encrypted logs" control):
   LUKS on the data volume (Linux) or BitLocker (Windows) — the vault makes
   logs tamper-*evident*; volume encryption makes them *confidential*. Do both.
7. **Back up** `/var/lib/sentinelfw` (or `C:\ProgramData\SentinelFW`):
   config.json, state.json, vault/, lists/ — cron it; `sfwctl cleanup` is your
   rollback path if you ever decommission.
8. **Burn-in with learning mode ON** for a day on a new host, review
   `ban_suppressed_learning` events, then turn enforcement on.

## 6. Fleet rollout (3+ hosts)

1. On the central console: Settings → Fleet → enable, **regenerate key**.
2. On every other host: `sudo python sfwctl.py fleet-agent --relay https://fw.example.internal --key <KEY>`
   (systemd/NSSM service, same pattern as above).
3. Agents report bans/threats/events every 30 s and write the relay's shared
   blocklist to their own `lists/fleet_shared.txt` — one console, whole-fleet
   enforcement.

## 7. Operations runbook

- **Logs**: `logs/events.jsonl` rotates at 25 MB ×8. The vault seals it into
  `vault/chain.json`; `sfwctl audit-verify` (exit 1 on tampering) belongs in
  your daily cron. The FLUSH button wipes all stored logs on demand (events,
  audit chain, vault, intel cache, PCAPs) — it is audited itself.
- **PCAPs**: enable the ring only when investigating; each alert writes a
  Wireshark-ready capture to `pcaps/`. Leave off at steady state to save RAM.
- **Updates**: stop service, replace the code directory (data dir is
  untouched), start; config migrates on boot. Run `python -m pytest tests/` on a
  staging host first.
- **Disaster**: `sfwctl cleanup` removes every firewall/hosts rule SentinelFW
  created; data (bans, config, vault) is preserved for forensics.

## 8. Known limits (be honest with your auditors)

- TLS inspection is not implemented (roadmap: MITM proxy + JA3 blocklist is
  passive-only today).
- Fleet v1 is monitoring + shared blocklist — no remote command execution,
  by design (relay accepts only heartbeats; it never sends shell commands).
- The DNS filter is a UDP forwarder (no DNSSEC validation, TCP fallback in
  v2).
- At-rest confidentiality is delegated to LUKS/BitLocker; the vault provides
  integrity + authenticity, not encryption.
