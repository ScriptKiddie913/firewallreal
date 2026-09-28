# SentinelFW 2.0

Host firewall + IPS + autonomous threat response for **Ubuntu (nftables)** and **Windows (Windows Defender Firewall)**.
Python 3.8+ standard library only: no venv, no pip, no API keys. Runs as root / Administrator.
It acts on its own: no prompts, no confirmations.

## Install
Ubuntu:  `sudo ./install.sh`      Windows (elevated PowerShell, Python installed for all users): `.\install.ps1`
No install: `sudo python3 sfwctl.py run`

## Architecture
```
                        +-------------------- sentinelfw/ --------------------+
 kernel exec events --> | monitors.ExecWatcher --+                            |
 (netlink proc conn.,   |                        v                            |
  Win snapshots)        |                  monitors.Responder  <-- ProcessMonitor <-- procinfo (socket->pid->exe)
 raw packets ---------> | detector.Sniffer -> Detector (scan/flood/brute/signature/DNS)
 (AF_PACKET/RCVALL)     |                        |                            |
                        |                        v                            |
 feeds + drop-in lists->| lists.Lists ------> engine.Engine --> backends.NftBackend / WinBackend  --> OS firewall
                        |                        |                            |
                        |   config.Store (config.json, state.json bans)       |
                        |   Housekeeper: ban expiry, feed updates, quarantine expiry, heartbeat
                        +-----------------------------------------------------+
```
| Module | Role |
|---|---|
| `backends.py` | Real enforcement: nft table `inet sentinelfw` (drop sets, priority -10) / `netsh advfirewall` rules `SentinelFW-*` |
| `detector.py` | Packet capture + IDS/IPS logic |
| `monitors.py` | Exec-time hook, socket monitor, response engine (kill / quarantine / delete), housekeeping |
| `procinfo.py` | Socket-to-process-to-executable mapping, kill, hash, quarantine/delete |
| `lists.py` | IP/domain/hash/program lists, feed updater |
| `engine.py` | Ban logic with escalation, safety guard, hosts-file sinkhole |
| `config.py`, `common.py`, `packets.py`, `cli.py` | Config/state, helpers/logging, parsers, commands |

## What it enforces automatically (profile `aggressive`, the default)
| Trigger | Response |
|---|---|
| Program launched matching `program_*.txt` path/glob, or SHA-256 in `hash_*.txt` | Killed at exec, file quarantined (or deleted) |
| Executable in temp dir (`/tmp`, `/dev/shm`, `%TEMP%`...) using the network | Killed, file quarantined |
| Running binary deleted from disk / memfd (fileless) | Killed |
| Process connected to a blocklisted IP | Killed (traffic is already dropped by the firewall) |
| Scan / flood / brute force / bad flags / attack payload from a public IP | IP banned in the kernel firewall, doubling on repeats up to 30 days |
| Query or answer for a blocked domain | Hosts sinkhole; answer IPs banned for 1h |

Quarantined files are removed from their path immediately and hard-deleted after `quarantine_retention_days` (7). For instant permanent deletion set `"malicious_file_action": "delete"`.

## Commands (`python3 sfwctl.py ...`)
`run` `status` `block-ip IP|CIDR [--duration 6h] [--force]` `unblock-ip` `block-domain` `unblock-domain` `block-program PATH|GLOB` `unblock-program` `block-hash SHA256` `list bans|quarantine|domains|programs` `update-lists` `quarantine-restore ID` `quarantine-purge ID` `harden --allow-ports 22,443` `unharden` `mode aggressive|monitor` `install-service` `uninstall-service` `cleanup`

Extend lists any time by dropping files into the data dir `lists/` (`/var/lib/sentinelfw` or `C:\ProgramData\SentinelFW`):
`ip_*.txt`, `domain_*.txt`, `hash_*.txt`, `program_*.txt`. They are hot-reloaded. Feeds are set in `config.json` (`feeds`).

## Hard safety rails (deliberately not configurable off)
* Private, loopback, link-local, CGNAT, this host's own IPs, default gateway and DNS servers are never auto-banned (spoofed traffic cannot make it cut you off).
* Feeds can never inject private/reserved or huge (< /8) ranges.
* Heuristic triggers never kill or touch OS-owned paths (`/usr`, `/bin`, `/etc`, `/snap`, `C:\Windows`). Only your explicit path/hash rules may kill there; even then files there are never deleted.
* SentinelFW never deletes its own package or the Python interpreter.
* `mode monitor` switches every action to log-only if you need to investigate a false positive.

## Honest limits
* It is a host firewall, not a Fortinet appliance: no TLS inspection, VPN, full L7 app-ID, or line-rate DPI (the sniffer is Python).
* Linux per-app *network* blocking is enforced by kill-on-exec + kill-on-connect + file removal, not by a per-executable kernel rule (nftables has none). Windows gets real per-program firewall rules for exact paths.
* The Windows sniffer sees IPv4 on the primary interface. IPS bans follow the attack pattern, so the first packets get through.
* Windows exec-blocking polls every 0.4 s; Linux uses the kernel process connector (instant; needs root and host PID namespace, i.e. not inside a container).
* Feed URLs are public lists and may change; edit them in `config.json`.

## Tests
`python3 -m unittest discover -s tests -v`

---

## SentinelFW 2.1 — Defense Console Upgrade

**Bug fixes**
- `GET /api/v1/appwall` crashed (`get_policies`/`get_violations` were missing) — implemented in `appwall.py`.
- `POST /api/v1/sandbox/submit` called a non-existent `Sandbox.detonate()` — now uses `analyze_file()`.
- Traffic stats endpoint returned hardcoded fake numbers — now computed from real flow counters (with packet-buffer fallback).
- Ban records read the wrong timestamp key (`created` vs `added`).
- `ScannerRedirector.redirect_scanner()` failed whenever the kernel DNAT rule could not be applied — kernel rules are now best-effort with the redirect window still tracked (all 61 unit tests pass).

**Network Monitor (new)** — Wireshark-grade deep packet inspection page:
- Every inbound/outbound packet captured by the engine sniffer (run as root/admin) is deep-parsed (Ethernet/VLAN, IPv4/IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS ClientHello/SNI) into an 8000-packet ring buffer.
- Live table with Wireshark-style Info column, per-packet protocol/severity/verdict colouring, protocol chips and counters.
- Filters: protocol, severity, direction, verdict, time window (1m/5m/15m/1h) and free-text search.
- Click any packet for the full protocol tree (every header field) plus a hex + ASCII dump of the raw frame.

**Geo Threat Map (new)** — all connected IPs on a world map (MapLibre GL + free OpenFreeMap tiles, with CARTO dark raster fallback — no Leaflet, no API keys):
- Endpoint markers coloured by threat (malicious/banned, suspicious, normal) sized by traffic.
- Heatmap layer toggle weighting traffic volume and threat level.
- Country distribution bars, searchable endpoint list, click-to-fly, popup with per-IP stats and one-click ban.
- Offline GeoIP country database (290k IPv4 ranges) auto-downloaded and refreshed; private/local ranges labelled.

**Applications (new)** — full inventory of every application on the system:
- Cards with icons, process count, CPU %, memory, live connections, per-app bandwidth and remote IP count.
- Click an app for full detail: identity, SHA-256, command line, every live socket, remote endpoints with GeoIP.
- Actions per application: block network access, unblock, kill process, quarantine binary (all enforced through the engine).

**Honeypot Deception (rebuilt)** — services now spawn/stop properly from the UI:
- New emulators: MySQL, SMB, RDP, SMTP open-relay bait (plus the existing HTTP, SSH, FTP, Telnet).
- Per-service cards with status, hits, uptime, live port re-binding, SPAWN/STOP buttons, and a "spawn configured" bulk action; state persists to config.

**Dashboard (FortiGate-grade)** — system health gauges (CPU/memory/disk), host/engine info strip, real throughput + PPS KPIs, DPI protocol distribution, top talkers, service status chips (capture, honeypots, Telegram, Suricata), unique-IP and threat KPIs.

**Settings** — restructured: Telegram dispatcher with connection + alert-content columns, inline status, and a step-by-step BotFather setup guide; engine parameters; capture buffer controls.

**Dev/testing** — `SENTINELFW_SIM=1 python3 test_webui_server.py` runs the console with a deterministic synthetic packet source for offline demos.

---

## SentinelFW 2.2 — Console Round 2

- **Honeypot port fallback** — if a decoy port cannot be bound (WinError 10013: Windows reserved/excluded ranges, port in use, missing elevation), SentinelFW now automatically tries nearby ports, reports the actually-bound port (and what it fell back from), and persists it so restarts are stable.
- **Unified Network Monitor** — the deep packet inspector and the Geo threat map are one section: packets on top, live world map with malicious-IP heatmap below.
- **Country mapping fixed** — IPs seen while the GeoIP database was still downloading are no longer stuck as "XX"; the resolver cache is invalidated when the database finishes loading, unallocated ranges get an honest "Unallocated / reserved" label, IPv4-mapped IPv6 is resolved to its real IPv4 country, and the country database is bundled with the package (works offline; auto-refreshed from the network when possible).
- **VirusTotal threat intelligence** — configure a free API key in Settings. Every new remote IP is scanned once; detections are cached permanently (never rescanned), clean results re-validate after 7 days. Verdicts appear on the map, in the endpoint lists, and in per-app remote endpoints. Optional auto-ban of confirmed-malicious IPs. Background scanning respects the free-tier rate limit.
- **Applications upgraded** — real vector icons for known software categories, sort (traffic/memory/CPU/connections/name), filter chips (All / Network active / Blocked / System), and a right-click context menu on every application (view details, block/unblock network, kill, quarantine, copy path, ban remote IPs, VirusTotal scan remote IPs). Remote IPs in the detail view have their own right-click menu and inline VT buttons.
- **FortiGate-style Firewall Policies** — a new Policies page: ordered first-match policies with Create New / Edit / Delete, sequence reordering (▲▼), enable/disable toggles, source/destination CIDR lists, a 27-object service catalog (ANY, HTTPS, DNS, SSH, RDP, MySQL…), action ACCEPT/DENY, NAT and security-profile columns, search, and live kernel hit counters on Linux. Policies are enforced by nftables (Linux) or Windows Defender Firewall (Windows) directly from the console. The compiled chain defaults to ACCEPT, so you can never lock yourself out of the server.
