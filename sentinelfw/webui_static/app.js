/**
 * SentinelFW 3.0 Enterprise Defense Matrix — Client Engine
 * SPA navigation, live Canvas charts, SSE log tailing, Wireshark-grade packet
 * inspector, MapLibre geo threat map, application inventory, honeypot control,
 * rule management, manual bans, and Telegram bot configuration.
 */

document.addEventListener("DOMContentLoaded", () => {
  "use strict";

  // ---------- helpers ----------
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
  const fmtBytes = (b) => {
    b = Number(b) || 0;
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + " GB";
    if (b >= 1048576) return (b / 1048576).toFixed(2) + " MB";
    if (b >= 1024) return (b / 1024).toFixed(1) + " KB";
    return b + " B";
  };
  const fmtBps = (bps) => {
    bps = Number(bps) || 0;
    if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
    if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
    if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " Kbps";
    return bps + " bps";
  };
  const fmtUptime = (s) => {
    s = Number(s) || 0;
    const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return (d ? d + "d " : "") + (h ? h + "h " : "") + m + "m";
  };
  const fmtAgo = (ts) => {
    const d = Date.now() / 1000 - (Number(ts) || 0);
    if (d < 60) return Math.max(0, Math.floor(d)) + "s ago";
    if (d < 3600) return Math.floor(d / 60) + "m ago";
    if (d < 86400) return Math.floor(d / 3600) + "h ago";
    return Math.floor(d / 86400) + "d ago";
  };
  const COUNTRY_ALIASES = { ZZ: "Unallocated / reserved", LOCAL: "Local / private network", PRIVATE: "Private LAN", LOOPBACK: "Loopback", LINKLOCAL: "Link-local", CGNAT: "Carrier NAT", UNKNOWN: "GeoIP pending" };
  const countryName = (cc) => COUNTRY_ALIASES[cc] || ((window.COUNTRY_CENTROIDS && window.COUNTRY_CENTROIDS[cc]) ? window.COUNTRY_CENTROIDS[cc][2] : (cc || "Unknown"));
  const ccPos = (cc) => (window.COUNTRY_CENTROIDS && window.COUNTRY_CENTROIDS[cc]) ? window.COUNTRY_CENTROIDS[cc] : null;

  async function api(path, opts) {
    try {
      const res = await fetch(path, opts);
      if (!res.ok && res.status !== 400) return null;
      return await res.json().catch(() => null);
    } catch { return null; }
  }
  const jpost = (path, body) => api(path, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}),
  });

  // ---------- 1. Clock ----------
  const clockEl = $("clock-display");
  setInterval(() => {
    const d = new Date();
    clockEl.textContent = d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
  }, 1000);

  // ---------- 2. Sidebar ----------
  const sidebar = $("app-sidebar");
  const toggleBtn = $("btn-toggle-sidebar");
  if (localStorage.getItem("sentinelfw_sidebar_collapsed") === "true") sidebar.classList.add("collapsed");
  toggleBtn.addEventListener("click", () => {
    sidebar.classList.toggle("collapsed");
    localStorage.setItem("sentinelfw_sidebar_collapsed", sidebar.classList.contains("collapsed"));
    setTimeout(() => { window.mapObj && window.mapObj.resize(); }, 60);
  });

  // ---------- 3. Navigation ----------
  const navItems = document.querySelectorAll(".nav-item");
  const tabPanes = document.querySelectorAll(".tab-pane");
  const pageTitle = $("page-title");
  const titles = {
    overview: "Threat Overview & Real-Time Matrix",
    network: "Network Monitor — Deep Packet Inspection & Geo Threat Map",
    policies: "Firewall Policies — Sequence & Enforcement",
    applications: "Application & Software Inventory",
    connections: "Live Network Sockets & Process Attribution",
    rules: "Firewall Filter Rules Manager",
    appwall: "Per-Application Network Policies",
    honeypot: "Honeypot Deception & Attacker Engagements",
    sandbox: "Behavioral Sandbox Detonation Reports",
    bans: "Currently Enforced Host Bans",
    logs: "Real-Time Streaming Audit Logs",
    settings: "Control Plane & Telegram Dispatcher",
  };

  function switchTab(tabId) {
    if (!tabPanes.length || !titles[tabId]) return;
    navItems.forEach((b) => b.classList.toggle("active", b.getAttribute("data-tab") === tabId));
    tabPanes.forEach((p) => p.classList.toggle("active", p.id === `tab-${tabId}`));
    pageTitle.textContent = titles[tabId];
    window.location.hash = `#/${tabId}`;
    if (tabId === "settings") { loadTelegramConfig(); loadVTConfig(); }
    if (tabId === "rules") loadRules();
    if (tabId === "network") { setTimeout(() => { window.mapObj && window.mapObj.resize(); }, 60); refreshMap(); }
    if (tabId === "policies") loadPolicies();
    if (tabId === "applications") refreshApplications();
    if (tabId === "honeypot") refreshHoneypotServices();
    if (tabId === "appwall") loadAppwall();
  }
  navItems.forEach((btn) => btn.addEventListener("click", () => switchTab(btn.getAttribute("data-tab"))));
  const initialHash = window.location.hash.replace("#/", "");
  if (initialHash && titles[initialHash]) switchTab(initialHash);

  // ---------- 4. Modals ----------
  const modalBan = $("modal-ban");
  const modalRule = $("modal-rule");
  const modalApp = $("modal-app");
  const modalPolicy = $("modal-policy");
  $("btn-manual-ban-modal").addEventListener("click", () => modalBan.classList.add("open"));
  $("btn-close-modal-ban").addEventListener("click", () => modalBan.classList.remove("open"));
  $("btn-add-rule-modal").addEventListener("click", () => modalRule.classList.add("open"));
  $("btn-close-modal-rule").addEventListener("click", () => modalRule.classList.remove("open"));
  $("btn-close-modal-app").addEventListener("click", () => modalApp.classList.remove("open"));
  $("btn-close-modal-policy").addEventListener("click", () => modalPolicy.classList.remove("open"));
  $("btn-cancel-policy").addEventListener("click", () => modalPolicy.classList.remove("open"));
  [modalBan, modalRule, modalApp, modalPolicy].forEach((m) => m.addEventListener("click", (e) => { if (e.target === m) m.classList.remove("open"); }));

  // ---------- 5. Charts ----------
  const trafficCanvas = $("traffic-chart");
  const threatCanvas = $("threat-chart");
  const trafficHistory = { in: Array(40).fill(0), out: Array(40).fill(0) };
  let threatCategories = {};

  function renderTrafficChart() {
    if (!trafficCanvas) return;
    const ctx = trafficCanvas.getContext("2d");
    const w = trafficCanvas.parentElement.clientWidth, h = trafficCanvas.parentElement.clientHeight;
    trafficCanvas.width = w; trafficCanvas.height = h;
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = "#24262e"; ctx.lineWidth = 1;
    for (let y = 20; y < h; y += 35) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke(); }
    const maxVal = Math.max(1000, ...trafficHistory.in, ...trafficHistory.out);
    const step = w / (trafficHistory.in.length - 1);
    const line = (arr, color, fill) => {
      ctx.strokeStyle = color; ctx.fillStyle = fill; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(0, h);
      arr.forEach((v, i) => {
        const x = i * step, y = h - 12 - (v / maxVal) * (h - 34);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      if (fill) { ctx.lineTo(w, h); ctx.closePath(); ctx.fill(); }
      ctx.stroke();
    };
    line(trafficHistory.in, "#8c8f9c", "rgba(140,143,156,0.08)");
    line(trafficHistory.out, "#e6e8ed", null);
  }

  function renderThreatChart() {
    if (!threatCanvas) return;
    const ctx = threatCanvas.getContext("2d");
    const w = threatCanvas.parentElement.clientWidth, h = threatCanvas.parentElement.clientHeight;
    threatCanvas.width = w; threatCanvas.height = h;
    ctx.clearRect(0, 0, w, h);
    const keys = Object.keys(threatCategories).slice(0, 8);
    if (!keys.length) {
      ctx.fillStyle = "#6a6d78"; ctx.font = "11px JetBrains Mono";
      ctx.fillText("No protocol traffic captured yet", 10, 24);
      return;
    }
    const maxVal = Math.max(1, ...keys.map((k) => threatCategories[k]));
    const barHeight = 15, gap = 10;
    let y = 12;
    ctx.font = "10px JetBrains Mono";
    keys.forEach((k) => {
      const val = threatCategories[k];
      const barW = Math.max(6, (w - 130) * (val / maxVal));
      ctx.fillStyle = "#8c8f9c"; ctx.fillText(k.toUpperCase().slice(0, 12), 8, y + 11);
      ctx.fillStyle = "rgba(184, 134, 40, 0.35)"; ctx.fillRect(105, y, barW, barHeight);
      ctx.fillStyle = "#e6e8ed"; ctx.fillText(val, 110 + barW, y + 11);
      y += barHeight + gap;
    });
  }
  window.addEventListener("resize", () => { renderTrafficChart(); renderThreatChart(); });

  // ---------- 6. Dashboard sync ----------
  async function syncDashboard() {
    const s = await api("/api/v1/status");
    if (s) {
      $("kpi-bans").textContent = s.bans_count || 0;
      $("kpi-conns").textContent = s.active_connections || 0;
      $("kpi-rules").textContent = s.total_rules || 0;
      $("sidebar-engine-text").textContent = `ENGINE ${s.status}`;
      $("sidebar-backend-text").textContent = `${(s.backend || "").toUpperCase()} (${(s.mode || "").toUpperCase()})`;
    }

    const tr = await api("/api/v1/stats/traffic");
    if (tr) {
      trafficHistory.in.shift(); trafficHistory.in.push(tr.bps_in || 0);
      trafficHistory.out.shift(); trafficHistory.out.push(tr.bps_out || 0);
      renderTrafficChart();
      $("kpi-throughput").textContent = `${fmtBps(tr.bps_in)} / ${fmtBps(tr.bps_out)}`;
      $("kpi-pps").textContent = `${tr.pps_in || 0} pps in / ${tr.pps_out || 0} pps out`;
    }

    const ov = await api("/api/v1/overview");
    if (ov) renderOverview(ov);

    const t = await api("/api/v1/stats/threats");
    if (t) {
      $("kpi-threats").textContent = t.total_threats_intercepted || 0;
      renderAttacksTable(t.recent_events || []);
    }

    const conns = await api("/api/v1/connections");
    if (conns) renderConnectionsTable(conns);

    const bans = await api("/api/v1/bans");
    if (bans) renderBansTable(bans);

    const hp = await api("/api/v1/honeypot/sessions");
    if (hp) renderHoneypotTable(hp);

    const sb = await api("/api/v1/sandbox/results");
    if (sb) renderSandboxTable(sb);
  }

  function renderOverview(ov) {
    const sys = ov.system || {};
    if (sys.cpu_percent != null) {
      $("gauge-cpu").style.width = Math.min(100, sys.cpu_percent) + "%";
      $("gauge-cpu-v").textContent = sys.cpu_percent + "%";
    }
    if (sys.memory_percent != null) {
      $("gauge-mem").style.width = Math.min(100, sys.memory_percent) + "%";
      $("gauge-mem-v").textContent = sys.memory_percent + "%";
    }
    if (sys.disk_percent != null) {
      $("gauge-disk").style.width = Math.min(100, sys.disk_percent) + "%";
      $("gauge-disk-v").textContent = sys.disk_percent + "%";
    }
    const health = (sys.cpu_percent > 90 || sys.memory_percent > 92) ? "DEGRADED" : "HEALTHY";
    const hb = $("ov-health-badge");
    hb.textContent = health;
    hb.className = "badge " + (health === "HEALTHY" ? "badge-safe" : "badge-danger");
    $("ov-sysinfo").innerHTML = [
      `Host <b>${esc(sys.host || "")}</b> · ${esc(sys.os_name || "")} · ${esc(sys.platform || "")}`,
      `Engine v${esc(sys.version)} · backend <b>${esc(sys.backend || "")}</b> · profile <b>${esc((sys.profile || "").toUpperCase())}</b>`,
      `Console uptime ${fmtUptime(sys.uptime_seconds)}`,
    ].map((x) => `<div>${x}</div>`).join("");

    const svc = ov.services || {};
    const chip = (ok, label) => `<span class="svc-chip ${ok ? "ok" : "off"}"><span class="svc-dot"></span>${label}</span>`;
    const hpRunning = (svc.honeypot || []).filter((x) => x.running).length;
    $("ov-services").innerHTML = [
      chip(svc.sniffer_active, "PACKET CAPTURE"),
      chip(hpRunning > 0, `HONEYPOTS ${hpRunning}/${(svc.honeypot || []).length}`),
      chip(svc.telegram_active, "TELEGRAM"),
      chip(svc.suricata, "SURICATA"),
    ].join("");

    const pk = ov.packets || {};
    $("kpi-packets").textContent = (pk.buffered || 0).toLocaleString();
    $("kpi-pkterr").textContent = pk.capture_error ? "capture unavailable: " + esc(pk.capture_error).slice(0, 60) : "netlens ring buffer";

    if (ov.map) {
      $("kpi-ips").textContent = ov.map.unique_ips ?? "—";
      $("kpi-ips-bad").textContent = `${ov.map.malicious ?? 0} malicious / ${ov.map.suspicious ?? 0} suspicious`;
    }
    const hpSvcs = (svc.honeypot || []);
    $("kpi-honeypots").textContent = `${hpSvcs.filter((x) => x.running).length}/${hpSvcs.length}`;

    if (ov.protocol_distribution && Object.keys(ov.protocol_distribution).length) {
      threatCategories = ov.protocol_distribution;
      renderThreatChart();
    }

    const tt = $("talkers-table").querySelector("tbody");
    if (ov.top_talkers && ov.top_talkers.length) {
      tt.innerHTML = ov.top_talkers.map((x) => `
        <tr>
          <td class="mono"><strong>${esc(x.ip)}</strong></td>
          <td><span class="badge badge-muted">${esc(x.country || "—")}</span></td>
          <td class="mono">${fmtBytes(x.bytes)}</td>
          <td class="mono">${x.conns}</td>
          <td><button class="btn btn-sm btn-danger" onclick="window.quickBan('${esc(x.ip)}')">BAN</button></td>
        </tr>`).join("");
    } else {
      tt.innerHTML = '<tr><td colspan="5" class="empty-state">No active remote endpoints</td></tr>';
    }
  }

  function renderAttacksTable(events) {
    const tbody = document.querySelector("#attacks-table tbody");
    if (!tbody) return;
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No critical attack detections recorded in current operational window</td></tr>';
      return;
    }
    tbody.innerHTML = "";
    events.slice(0, 15).forEach((e) => {
      const sevClass = (e.severity === "critical" || e.severity === "high") ? "badge-danger" : "badge-warn";
      const src = e.src_ip || e.ip || e.remote || e.src || "LOCAL";
      const detail = e.detail || e.reason || e.note || e.request || e.qname || "";
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td class="mono">${esc(e.ts || "--")}</td>
          <td class="mono"><strong>${esc(src)}</strong></td>
          <td><span class="badge ${sevClass}">${esc((e.kind || "ATTACK")).toUpperCase()}</span></td>
          <td><span class="badge ${sevClass}">${esc((e.severity || "WARN")).toUpperCase()}</span></td>
          <td class="mono" style="font-size:10px; color:var(--text-secondary); max-width:340px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${esc(detail)}</td>
          <td><button class="btn btn-sm btn-danger" onclick="window.quickBan('${esc(src)}')">DROP IP</button></td>
        </tr>`);
    });
  }

  function renderConnectionsTable(conns) {
    const tbody = document.querySelector("#conns-table tbody");
    if (!tbody) return;
    const search = ($("conns-search").value || "").toLowerCase();
    const filtered = conns.filter((c) => {
      if (!search) return true;
      return `${c.pid} ${c.exe} ${c.proto} ${c.laddr} ${c.raddr} ${c.country} ${c.state}`.toLowerCase().includes(search);
    });
    tbody.innerHTML = "";
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No active sockets matching criteria</td></tr>';
      return;
    }
    filtered.slice(0, 60).forEach((c) => {
      const raddr = c.raddr ? `${c.raddr}:${c.rport}` : "*";
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td class="mono">${c.pid}</td>
          <td><strong title="${esc(c.exe)}">${esc((c.exe || "System").split(/[\\/]/).pop())}</strong></td>
          <td><span class="badge badge-info">${esc((c.proto || "TCP").toUpperCase())}</span></td>
          <td class="mono">${esc(c.laddr)}:${c.lport}</td>
          <td class="mono">${esc(raddr)}</td>
          <td><span class="badge badge-muted">${esc(c.country || "LOCAL")}${c.org ? ` (${esc(c.org)})` : ""}</span></td>
          <td><span class="badge badge-safe">${esc(c.state || "ESTABLISHED")}</span></td>
          <td>${c.raddr && c.raddr !== "127.0.0.1" ? `<button class="btn btn-sm btn-danger" onclick="window.quickBan('${esc(c.raddr)}')">BAN</button>` : "-"}</td>
        </tr>`);
    });
  }

  function renderBansTable(bans) {
    const tbody = document.querySelector("#bans-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    const entries = Object.entries(bans || {});
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No active host bans enforced</td></tr>';
      return;
    }
    entries.forEach(([ip, meta]) => {
      const rem = meta.remaining_seconds !== null && meta.remaining_seconds !== undefined
        ? (meta.remaining_seconds >= 86400 ? Math.floor(meta.remaining_seconds / 86400) + "d" : Math.floor(meta.remaining_seconds / 3600) + "h " + Math.floor((meta.remaining_seconds % 3600) / 60) + "m")
        : "PERMANENT";
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td class="mono"><strong>${esc(ip)}</strong></td>
          <td>${esc(meta.reason || "Autonomous Threat Mitigation")}</td>
          <td><span class="badge badge-info">${esc((meta.source || "ENGINE").toUpperCase())}</span></td>
          <td class="mono"><span class="badge badge-warn">${rem}</span></td>
          <td><button class="btn btn-sm" onclick="window.unbanIP('${esc(ip)}')">UNBAN</button></td>
        </tr>`);
    });
  }

  function renderHoneypotTable(sessions) {
    const tbody = document.querySelector("#honeypot-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!sessions.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No decoy trap probes captured in active cycle</td></tr>';
      return;
    }
    sessions.slice().reverse().forEach((s) => {
      const creds = s.credentials && s.credentials.length
        ? s.credentials.map((c) => `${esc(c.user)} / ${esc(c.password)}`).join("; ") : "None";
      const cmds = (s.commands || []).map(esc).join(" | ") || "Handshake reconnaissance";
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td><span class="badge badge-warn">${esc((s.service || "").toUpperCase())}</span></td>
          <td class="mono"><strong>${esc(s.src_ip)}:${s.src_port}</strong></td>
          <td class="mono">${creds}</td>
          <td class="mono" style="max-width:420px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${cmds}</td>
          <td class="mono">${s.duration}s</td>
        </tr>`);
    });
  }

  function renderSandboxTable(reports) {
    const tbody = document.querySelector("#sandbox-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!reports.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No suspicious detonation reports available</td></tr>';
      return;
    }
    reports.slice().reverse().forEach((r) => {
      const badgeClass = r.verdict === "MALICIOUS" ? "badge-danger" : (r.verdict === "SUSPICIOUS" ? "badge-warn" : "badge-safe");
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td class="mono"><strong>${esc(r.sample_name)}</strong></td>
          <td><span class="badge ${badgeClass}">${esc(r.verdict)}</span></td>
          <td class="mono"><strong>${r.total_score} / 100</strong></td>
          <td class="mono">${(r.indicators || []).map(esc).join(", ") || "None"}</td>
          <td class="mono">${(r.files_created || []).map(esc).join(", ") || "None"}</td>
        </tr>`);
    });
  }

  async function loadAppwall() {
    const tbody = document.querySelector("#appwall-table tbody");
    if (!tbody) return;
    const d = await api("/api/v1/appwall");
    if (!d) return;
    tbody.innerHTML = "";
    const pols = d.policies || [];
    if (!pols.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Application firewall active with default policy (allow). Configure policies in config.json.</td></tr>';
      return;
    }
    pols.forEach((p) => {
      const m = p.match || {};
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td class="mono">${esc(m.exe_glob || m.exe_path || m.sha256 || "*")}</td>
          <td><span class="badge badge-info">${esc((p.allow_outbound || ["*"]).join(", "))}</span></td>
          <td><span class="badge badge-muted">${esc((p.allow_inbound || ["NONE"]).join(", "))}</span></td>
          <td><span class="badge badge-danger">${esc((p.deny_destinations || ["*"]).join(", "))}</span></td>
          <td><span class="badge badge-warn">${esc((p.action_on_violation || "block+alert").toUpperCase())}</span></td>
        </tr>`);
    });
  }

  // =========================================================
  // 7. NETWORK MONITOR (Wireshark-grade)
  // =========================================================
  let pktLive = true;
  let pktCursor = 0;
  let pktBuffer = [];       // newest-last, capped
  let pktSelected = null;
  const PKT_MAX = 900;

  function pktFilters() {
    return {
      proto: $("pkt-filter-proto").value,
      sev: $("pkt-filter-sev").value,
      dir: $("pkt-filter-dir").value,
      verdict: $("pkt-filter-verdict").value,
      q: $("pkt-search").value,
    };
  }

  function clientFilter(p) {
    // time window (client-side, since server buffer is all-time)
    const tw = parseInt($("pkt-filter-time").value || "0", 10);
    if (tw && (Date.now() / 1000 - p.ts) > tw) return false;
    return true;
  }

  async function pollPackets() {
    if (!pktLive) return;
    const f = pktFilters();
    const params = new URLSearchParams();
    if (f.proto) params.set("proto", f.proto);
    if (f.sev) params.set("sev", f.sev);
    if (f.dir) params.set("dir", f.dir);
    if (f.verdict) params.set("verdict", f.verdict);
    if (f.q) params.set("q", f.q);
    params.set("limit", "400");
    params.set("after_id", String(pktCursor));
    const d = await api(`/api/v1/packets?${params.toString()}`);
    if (!d) return;
    const st = d.stats || {};
    const badge = $("cap-status-badge");
    if (st.capture_active) { badge.textContent = "CAPTURING"; badge.className = "badge badge-safe"; }
    else if (st.capture_error) { badge.textContent = "CAPTURE OFFLINE"; badge.className = "badge badge-danger"; }
    else { badge.textContent = "NO SOURCE (run as root)"; badge.className = "badge badge-warn"; }
    $("cap-counter").textContent = `${(st.buffered || 0).toLocaleString()} pkts · in ${fmtBytes((st.bytes || {}).in || 0)} · out ${fmtBytes((st.bytes || {}).out || 0)}`;
    $("cap-buffer-info").textContent = `${(st.buffered || 0).toLocaleString()} / ${(st.capacity || 0).toLocaleString()} buffered · dropped: ${st.dropped || 0}`;

    const protoChips = $("proto-chips");
    const pcs = st.proto_counts || {};
    protoChips.innerHTML = Object.entries(pcs).slice(0, 6)
      .map(([k, v]) => `<span class="proto-chip">${esc(k)} <b>${v}</b></span>`).join("");

    const fresh = (d.packets || []).filter(clientFilter);
    if (fresh.length) {
      pktBuffer = pktBuffer.concat(fresh).slice(-PKT_MAX);
      pktCursor = Math.max(pktCursor, d.latest_id || fresh[fresh.length - 1].id);
      renderPackets();
    }
    // refresh selected packet detail (it may have been filtered out)
    if (pktSelected) {
      const cur = pktBuffer.find((p) => p.id === pktSelected.id);
      if (!cur) { pktSelected = null; $("packet-detail").innerHTML = '<div class="pd-placeholder">Select a packet to inspect full protocol tree and hex dump</div>'; }
    }
  }

  const sevBadge = (sev) => {
    const s = (sev || "info").toLowerCase();
    const cls = s === "critical" ? "badge-danger" : s === "high" ? "badge-warn" : s === "medium" ? "badge-warn" : "badge-muted";
    return `<span class="badge ${cls}">${s.toUpperCase()}</span>`;
  };
  const protoColor = (pr) => {
    const p = (pr || "").toUpperCase();
    if (p === "DNS") return "#7fb069";
    if (["HTTP", "HTTPS", "TLS"].includes(p)) return "#5d9ccc";
    if (["SSH", "SMB", "RDP"].includes(p)) return "#c98b40";
    if (p.startsWith("ICMP")) return "#a06ec9";
    if (["TCP", "UDP"].includes(p)) return "#8c8f9c";
    return "#8c8f9c";
  };

  function renderPackets() {
    const tbody = document.querySelector("#packets-table tbody");
    const empty = $("pkt-empty");
    if (!tbody) return;
    if (!pktBuffer.length) {
      tbody.innerHTML = ""; empty.style.display = "block";
      return;
    }
    empty.style.display = "none";
    const rows = pktBuffer.slice(-400).reverse(); // newest first
    const frag = [];
    const t0 = pktBuffer[0] ? pktBuffer[0].ts : Date.now() / 1000;
    rows.forEach((p) => {
      const d = new Date(p.ts * 1000);
      const rel = Math.max(0, p.ts - t0).toFixed(3);
      const dirArrow = p.direction === "out" ? "▲ OUT" : "▼ IN";
      const blocked = (p.verdict || "").toUpperCase() === "BLOCKED";
      frag.push(`
        <tr class="pkt-row ${blocked ? "pkt-blocked" : ""} ${p.id === (pktSelected && pktSelected.id) ? "pkt-selected" : ""}" data-id="${p.id}">
          <td class="mono">${p.id}</td>
          <td class="mono" title="${d.toISOString()}">${d.toTimeString().slice(0, 8)}.${String(d.getMilliseconds()).padStart(3, "0")}<span class="pkt-rel">+${rel}s</span></td>
          <td class="mono"><span class="dir-tag ${p.direction === "out" ? "dir-out" : "dir-in"}">${dirArrow}</span> ${esc(p.src)}${p.src_port ? `:${p.src_port}` : ""}</td>
          <td class="mono">${esc(p.dst)}${p.dst_port ? `:${p.dst_port}` : ""}</td>
          <td><span class="badge" style="color:${protoColor(p.protocol)}; border-color:${protoColor(p.protocol)}40;">${esc(p.protocol)}</span></td>
          <td class="mono">${p.length}</td>
          <td>${sevBadge(p.severity)}${blocked ? '<span class="badge badge-danger">DROP</span>' : ""}</td>
          <td class="mono pkt-info">${esc(p.info || "")}</td>
        </tr>`);
    });
    tbody.innerHTML = frag.join("");
    tbody.querySelectorAll(".pkt-row").forEach((tr) => {
      tr.addEventListener("click", () => selectPacket(parseInt(tr.dataset.id, 10)));
    });
  }

  function layerRow(k, v) { return `<div class="pd-row"><span class="pd-k">${esc(k)}</span><span class="pd-v mono">${esc(v)}</span></div>`; }

  function selectPacket(id) {
    const p = pktBuffer.find((x) => x.id === id);
    if (!p) return;
    pktSelected = p;
    renderPackets();
    const L = p.layers || {};
    let html = `<div class="pd-head"><b>#${p.id}</b> ${esc(p.protocol)} · ${p.length} B · ${p.direction === "out" ? "OUTBOUND" : "INBOUND"} ${p.iface ? "· " + esc(p.iface) : ""}</div>`;
    html += `<div class="pd-tree">`;
    if (L.ethernet) {
      html += `<details open><summary>Ethernet II</summary>${layerRow("Destination", L.ethernet.dst_mac)}${layerRow("Source", L.ethernet.src_mac)}${layerRow("Type", L.ethernet.ethertype)}</details>`;
    }
    if (L.vlan) html += `<details open><summary>802.1Q VLAN</summary>${layerRow("VLAN ID", L.vlan.vid)}</details>`;
    const ip = L.ip || L.ipv6;
    if (L.ip) {
      html += `<details open><summary>Internet Protocol Version 4</summary>${layerRow("Source", L.ip.src)}${layerRow("Destination", L.ip.dst)}${layerRow("Header Length", L.ip.header_len + " bytes")}${layerRow("Total Length", L.ip.total_len)}${layerRow("Identification", "0x" + (L.ip.id || 0).toString(16))}${layerRow("Flags", L.ip.flags)}${layerRow("Fragment Offset", L.ip.frag_offset)}${layerRow("TTL", L.ip.ttl)}${layerRow("Protocol", L.ip.proto)}${layerRow("Checksum", L.ip.checksum)}</details>`;
    } else if (L.ipv6) {
      html += `<details open><summary>Internet Protocol Version 6</summary>${layerRow("Source", L.ipv6.src)}${layerRow("Destination", L.ipv6.dst)}${layerRow("Flow Label", L.ipv6.flow_label)}${layerRow("Payload Length", L.ipv6.payload_len)}${layerRow("Next Header", L.ipv6.next_header)}${layerRow("Hop Limit", L.ipv6.hop_limit)}</details>`;
    }
    if (L.tcp) {
      html += `<details open><summary>Transmission Control Protocol</summary>${layerRow("Source Port", L.tcp.src_port)}${layerRow("Destination Port", L.tcp.dst_port)}${layerRow("Sequence Number", L.tcp.seq)}${layerRow("Acknowledgment", L.tcp.ack)}${layerRow("Header Length", L.tcp.header_len + " bytes")}${layerRow("Flags", L.tcp.flags)}${layerRow("Window Size", L.tcp.window)}${layerRow("Checksum", L.tcp.checksum)}${layerRow("Payload Length", L.tcp.payload_len)}</details>`;
    }
    if (L.udp) {
      html += `<details open><summary>User Datagram Protocol</summary>${layerRow("Source Port", L.udp.src_port)}${layerRow("Destination Port", L.udp.dst_port)}${layerRow("Length", L.udp.length)}${layerRow("Checksum", L.udp.checksum)}</details>`;
    }
    if (L.icmp) {
      html += `<details open><summary>ICMP</summary>${layerRow("Type", L.icmp.type)}${layerRow("Code", L.icmp.code)}${layerRow("Info", L.icmp.name)}</details>`;
    }
    if (L.dns) {
      html += `<details open><summary>Domain Name System</summary>${layerRow("Questions", (L.dns.questions || []).join(", "))}${layerRow("Answers", (L.dns.answers || []).join(", "))}${layerRow("Response", L.dns.response ? "Yes" : "No")}</details>`;
    }
    if (L.http) html += `<details open><summary>Hypertext Transfer Protocol</summary>${layerRow("Request Line", L.http.request_line)}</details>`;
    if (L.tls) html += `<details open><summary>Transport Layer Security</summary>${layerRow("Handshake Type", L.tls.type)}${layerRow("Server Name (SNI)", L.tls.sni || "—")}</details>`;
    html += `</div>`;

    // hex dump
    html += `<div class="pd-hex-title">Frame (${p.hex_total} bytes${p.hex_total > (p.hex.length / 2) ? `, first ${p.hex.length / 2} shown` : ""})</div>`;
    html += hexDump(p.hex || "");
    $("packet-detail").innerHTML = html;
    $("packet-detail").scrollTop = 0;
  }

  function hexDump(hex) {
    if (!hex) return '<div class="pd-placeholder">No raw bytes retained</div>';
    const bytes = hex.match(/.{2}/g) || [];
    let out = '<div class="hexdump"><table>';
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.slice(i, i + 16);
      const off = i.toString(16).padStart(4, "0");
      const hexPart = chunk.join(" ").padEnd(47, " ");
      const ascii = chunk.map((b) => { const c = parseInt(b, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "."; }).join("");
      out += `<tr><td class="hd-off">${off}</td><td class="hd-bytes">${hexPart}</td><td class="hd-ascii">${esc(ascii)}</td></tr>`;
    }
    out += "</table></div>";
    return out;
  }

  $("btn-pause-capture").addEventListener("click", () => {
    pktLive = !pktLive;
    $("pause-capture-label").textContent = pktLive ? "PAUSE" : "RESUME";
    $("btn-pause-capture").classList.toggle("btn-danger", !pktLive);
  });
  $("btn-clear-packets").addEventListener("click", async () => {
    pktBuffer = []; pktCursor = 0; pktSelected = null;
    $("packet-detail").innerHTML = '<div class="pd-placeholder">Select a packet to inspect</div>';
    renderPackets();
    await jpost("/api/v1/packets/clear");
  });
  $("btn-clear-pkts-settings").addEventListener("click", async () => {
    pktBuffer = []; pktCursor = 0; renderPackets();
    await jpost("/api/v1/packets/clear");
    showTelegramBanner("Packet capture buffer cleared.", true);
  });
  ["pkt-filter-proto", "pkt-filter-sev", "pkt-filter-dir", "pkt-filter-verdict", "pkt-filter-time"].forEach((id) => {
    $(id).addEventListener("change", () => { pktCursor = 0; pktBuffer = []; renderPackets(); });
  });
  let pktSearchTimer = null;
  $("pkt-search").addEventListener("input", () => {
    clearTimeout(pktSearchTimer);
    pktSearchTimer = setTimeout(() => { pktCursor = 0; pktBuffer = []; renderPackets(); }, 350);
  });
  setInterval(pollPackets, 1000);
  pollPackets();

  // =========================================================
  // 8. GEO THREAT MAP (MapLibre GL)
  // =========================================================
  let mapObj = null, mapMode = "markers", mapReady = false;
  let mapData = { points: [], countries: [], totals: {} };

  function buildMapStyleFallback() {
    return {
      version: 8,
      sources: {
        carto: {
          type: "raster",
          tiles: ["a", "b", "c", "d"].map((s) => `https://${s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}@2x.png`),
          tileSize: 256,
          attribution: "© OpenStreetMap contributors © CARTO",
        },
      },
      layers: [{ id: "carto", type: "raster", source: "carto" }],
    };
  }

  function initMap() {
    const el = $("threat-map");
    if (!el || typeof maplibregl === "undefined") return;
    mapObj = new maplibregl.Map({
      container: "threat-map",
      style: "https://tiles.openfreemap.org/styles/dark",
      center: [20, 25],
      zoom: 1.4,
      attributionControl: { compact: true },
    });
    window.mapObj = mapObj;
    let styleOk = false;
    mapObj.once("style.load", () => { styleOk = true; mapReady = true; addMapLayers(); refreshMap(); });
    // Fallback if OpenFreeMap style is unreachable
    setTimeout(() => {
      if (!styleOk && mapObj) {
        try { mapObj.setStyle(buildMapStyleFallback()); } catch (e) { /* noop */ }
        mapObj.once("style.load", () => { mapReady = true; addMapLayers(); refreshMap(); });
      }
    }, 6000);
    mapObj.on("style.load", () => { if (mapReady) addMapLayers(); });
    mapObj.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
  }

  function addMapLayers() {
    if (!mapObj || !mapObj.getSource || !mapObj.getSource("endpoints")) {
      mapObj.addSource("endpoints", { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      // Heatmap layer (below markers)
      mapObj.addLayer({
        id: "endpoints-heat",
        type: "heatmap",
        source: "endpoints",
        layout: { visibility: mapMode === "heat" ? "visible" : "none" },
        paint: {
          "heatmap-weight": ["interpolate", ["linear"], ["get", "weight"], 0, 0.15, 10, 1],
          "heatmap-intensity": 1.1,
          "heatmap-color": ["interpolate", ["linear"], ["heatmap-density"],
            0, "rgba(8,12,20,0)", 0.25, "#2c4a63", 0.5, "#3f7492", 0.7, "#c98b40", 0.85, "#e04f4f", 1, "#ff2d2d"],
          "heatmap-radius": 34,
          "heatmap-opacity": 0.85,
        },
      });
      // Circle markers colored by threat
      mapObj.addLayer({
        id: "endpoints-circles",
        type: "circle",
        source: "endpoints",
        layout: { visibility: mapMode === "markers" ? "visible" : "none" },
        paint: {
          "circle-color": ["match", ["get", "threat"], "malicious", "#e04f4f", "suspicious", "#d9a036", "#6e93b8"],
          "circle-radius": ["interpolate", ["linear"], ["get", "weight"], 0, 4, 5, 7, 20, 14],
          "circle-stroke-color": "rgba(230,232,237,0.35)",
          "circle-stroke-width": 1,
          "circle-opacity": 0.9,
        },
      });
      mapObj.on("click", "endpoints-circles", (e) => {
        const f = e.features[0];
        const p = f.properties;
        new maplibregl.Popup({ closeButton: true })
          .setLngLat(e.lngLat)
          .setHTML(`<div class="map-pop">
            <div class="map-pop-ip">${esc(p.ip)}</div>
            <div>${esc(countryName(p.country))} (${esc(p.country)})</div>
            <div class="map-pop-row">Threat: <b class="threat-${esc(p.threat)}">${esc(p.threat.toUpperCase())}</b></div>
            <div class="map-pop-row">Packets: ${p.packets} · Conns: ${p.connections}</div>
            <div class="map-pop-row">↓ ${fmtBytes(p.bytes_in)} · ↑ ${fmtBytes(p.bytes_out)}</div>
            <div class="map-pop-row">Ports: ${esc(p.ports || "—")}</div>
            <div class="map-pop-row vt-row" id="vt-row-${esc(p.ip)}">${vtPopupHtml(p)}</div>
            <div style="display:flex; gap:6px; margin-top:6px;">
              <button class="btn btn-sm btn-danger" onclick="window.quickBan('${esc(p.ip)}')">BAN IP</button>
              <button class="btn btn-sm" onclick="window.vtScan('${esc(p.ip)}', true)">VT SCAN</button>
            </div>
          </div>`)
          .addTo(mapObj);
      });
      mapObj.on("mouseenter", "endpoints-circles", () => { mapObj.getCanvas().style.cursor = "pointer"; });
      mapObj.on("mouseleave", "endpoints-circles", () => { mapObj.getCanvas().style.cursor = ""; });
    }
  }

  function mapFeatures() {
    const feats = [];
    const maxBytes = Math.max(1, ...mapData.points.map((p) => p.bytes_in + p.bytes_out + p.packets * 54));
    mapData.points.forEach((p) => {
      if (p.country === "LOCAL" || p.country === "XX" || p.country === "ZZ" || p.country === "PRIVATE" || p.country === "LOOPBACK") return;
      const c = ccPos(p.country);
      if (!c) return;
      const intensity = (p.bytes_in + p.bytes_out + p.packets * 54) / maxBytes;
      const jitter = ((parseInt(p.ip.replace(/\D/g, "").slice(-6) || "7", 10) % 400) - 200) / 900; // small spread so same-country IPs separate
      feats.push({
        type: "Feature",
        geometry: { type: "Point", coordinates: [c[1] + jitter, c[0] + jitter * 0.6] },
        properties: {
          ip: p.ip, country: p.country, threat: p.threat, packets: p.packets,
          connections: p.connections, bytes_in: p.bytes_in, bytes_out: p.bytes_out,
          ports: (p.ports || []).join(", "),
          weight: Math.max(0.2, Math.round(Math.log10(1 + intensity * 1000) * 4 * (p.threat === "malicious" ? 1.6 : p.threat === "suspicious" ? 1.2 : 1))),
        },
      });
    });
    return { type: "FeatureCollection", features: feats };
  }

  async function refreshMap() {
    const d = await api("/api/v1/map/data");
    if (!d) return;
    mapData = d;
    const totals = d.totals || {};
    $("map-ips-badge").textContent = `${totals.unique_ips || 0} IPs · ${totals.malicious || 0} malicious`;
    const gdb = d.geo_db || {};
    $("map-geo-badge").textContent = "GEO DB: " + (gdb.ready ? `${(gdb.rows || 0).toLocaleString()} ranges` : "loading…");
    const hpBadge = $("hp-geo-badge");
    if (hpBadge) hpBadge.textContent = "GEO DB: " + (gdb.ready ? "READY" : "loading…");
    const ti = d.threat_intel || {};
    const vtb = $("vt-badge-net");
    if (vtb) vtb.textContent = ti.configured ? `VT: ${ti.detected_malicious} flagged / ${ti.cached_ips} cached` : "VT: NO KEY";
    if (vtb) vtb.className = "badge mono " + (ti.configured ? (ti.detected_malicious ? "badge-danger" : "badge-muted") : "badge-warn");
    if (mapObj && mapReady) {
      const src = mapObj.getSource("endpoints");
      if (src) src.setData(mapFeatures());
    }
    renderMapLists();
  }

  function renderMapLists() {
    const search = ($("map-search").value || "").toLowerCase();
    const list = $("map-ip-list");
    const pts = (mapData.points || [])
      .filter((p) => !search || p.ip.toLowerCase().includes(search) || (p.country || "").toLowerCase().includes(search))
      .sort((a, b) => (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out))
      .slice(0, 60);
    if (!pts.length) { list.innerHTML = '<div class="empty-state">No remote endpoints observed yet</div>'; }
    else {
      list.innerHTML = pts.map((p) => `
        <div class="map-ip-item threat-${esc(p.threat)}" data-ip="${esc(p.ip)}" data-cc="${esc(p.country)}">
          <span class="mi-dot"></span>
          <span class="mi-ip mono">${esc(p.ip)}${p.vt ? ` <span class="vt-mini vt-${esc(p.vt.verdict)}">${esc(p.vt.verdict)}</span>` : ""}</span>
          <span class="mi-cc" title="${esc(countryName(p.country))}">${esc(countryName(p.country))}</span>
          <span class="mi-bytes mono">${fmtBytes(p.bytes_in + p.bytes_out)}</span>
        </div>`).join("");
      list.querySelectorAll(".map-ip-item").forEach((el) => {
        el.addEventListener("click", () => {
          const cc = el.dataset.cc;
          const c = ccPos(cc);
          if (c && mapObj) mapObj.flyTo({ center: [c[1], c[0]], zoom: 4 });
        });
        el.addEventListener("contextmenu", (e) => {
          e.preventDefault();
          openCtxMenu(e, ipMenuItems(el.dataset.ip));
        });
      });
    }
    const cl = $("country-list");
    const countries = (mapData.countries || []).sort((a, b) => b.bytes - a.bytes).slice(0, 12);
    const maxB = Math.max(1, ...countries.map((c) => c.bytes));
    if (!countries.length) { cl.innerHTML = '<div class="empty-state">No country data</div>'; }
    else {
      cl.innerHTML = countries.map((c) => `
        <div class="country-row">
          <span class="cr-name">${esc(countryName(c.country))}</span>
          <div class="cr-bar"><div class="cr-fill ${c.threats > 0 ? "cr-bad" : ""}" style="width:${Math.max(4, (c.bytes / maxB) * 100)}%"></div></div>
          <span class="cr-ips mono">${c.ips} IP${c.ips > 1 ? "s" : ""}${c.threats ? ` · <b style="color:var(--accent-danger)">${c.threats}⚠</b>` : ""}</span>
        </div>`).join("");
    }
  }
  $("map-search").addEventListener("input", renderMapLists);
  $("map-mode-markers").addEventListener("click", () => setMapMode("markers"));
  $("map-mode-heat").addEventListener("click", () => setMapMode("heat"));
  function setMapMode(m) {
    mapMode = m;
    $("map-mode-markers").classList.toggle("active", m === "markers");
    $("map-mode-heat").classList.toggle("active", m === "heat");
    if (mapObj && mapReady) {
      try {
        mapObj.setLayoutProperty("endpoints-circles", "visibility", m === "markers" ? "visible" : "none");
        mapObj.setLayoutProperty("endpoints-heat", "visibility", m === "heat" ? "visible" : "none");
      } catch (e) { /* style may not have layers yet */ }
    }
  }
  initMap();
  setInterval(() => { if (mapObj && document.querySelector("#tab-network").classList.contains("active")) refreshMap(); }, 5000);

  // =========================================================
  // 9. APPLICATIONS (inventory, icons, right-click menu, VT)
  // =========================================================
  let appData = { applications: [] };
  let appFilter = "all";
  let appSort = "traffic";

  // Real vector icon set (24x24 SVGs, colored per category)
  const sv = (inner, hue) => ({ svg: `<svg viewBox="0 0 24 24" fill="none" stroke="hsl(${hue} 55% 68%)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>`, hue });
  const APP_ICONS = [
    { re: /chrome|chromium/i, icon: sv('<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.6"/><path d="M12 3.6l4.5 7.8M20.8 15.4h-9M8.4 20.2 12 14"/>', 210) },
    { re: /msedge|edge/i, icon: sv('<circle cx="12" cy="12" r="9"/><path d="M4 15c3-1 6.5-.5 8 2M7 6c4 0 9 2.5 9 7 0 1.6-.8 3-2.5 3-3 0-4-2.5-4-4.5 0-3-1-5-2.5-5.5"/>', 195) },
    { re: /firefox/i, icon: sv('<circle cx="12" cy="12" r="9"/><path d="M15.5 4.5c-1.5 2-1 4-3 5.5-1.8 1.3-5 1-7.5 3.5M18 17c-2.5 1.5-6 2-8.5.5C7 16 7 12.5 9 11c2.8-2.1 6-1.5 7-3.5.7-1.4 1.6-2.6 2.9-3.4"/>', 25) },
    { re: /python/i, icon: sv('<path d="M12 3c-3 0-4 1.3-4 3v2h6v1.5H7c-2.3 0-4 1.2-4 4s1.7 4 4 4h1v-2.6c0-2 1.4-3.4 3.4-3.4h3.2c1.9 0 3.4-1.5 3.4-3.4V6c0-1.7-1.5-3-3.5-3z"/><circle cx="10" cy="6.2" r=".7" fill="currentColor"/>', 45) },
    { re: /node|bun|deno/i, icon: sv('<path d="M12 2.5 20 7v10l-8 4.5L4 17V7z"/><path d="M9 10v4.5M15 10v4.5"/>', 120) },
    { re: /docker|containerd|podman/i, icon: sv('<path d="M4 14h13v-3h-2V9h-2.5v2h-3V9H7v2H4zM4 14c0 3 2.5 5 7 5s7-2 7-5"/><path d="M16 11V9M19 11V9M19 11h1.5c1.4 0 2.5 1.3 2.5 3"/>', 195) },
    { re: /ssh|sshd|putty|telnet/i, icon: sv('<circle cx="8" cy="14" r="4"/><path d="M12 14h9M17.5 14v3M20.5 14v2.5"/>', 30) },
    { re: /postgres|mysql|mariadb|mongo|redis|mssql|sql/i, icon: sv('<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>', 160) },
    { re: /nginx|apache|caddy|httpd|iis/i, icon: sv('<rect x="3.5" y="4" width="17" height="6" rx="1"/><rect x="3.5" y="14" width="17" height="6" rx="1"/><path d="M6.8 7h.1M6.8 17h.1"/>', 130) },
    { re: /smtp|postfix|mail|dovecot|outlook|thunderbird/i, icon: sv('<rect x="3" y="6" width="18" height="12" rx="1.5"/><path d="m3.5 7 8.5 6 8.5-6"/>', 350) },
    { re: /bash|zsh|fish|ksh|pwsh|powershell|cmd/i, icon: sv('<rect x="3" y="4.5" width="18" height="15" rx="1.5"/><path d="m7 9 3 2.5L7 14M12.5 15h4"/>', 30) },
    { re: /curl|wget|http/i, icon: sv('<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5M8.5 11h5"/>', 240) },
    { re: /java|openjdk|eclipse/i, icon: sv('<path d="M5 8h10c-.5 6-2 9-5 9s-4.5-3-5-9zM15 8c.6.8 2.5 1.6 2.5 3.5S15.5 14 15.5 14"/><path d="M7 20c2 1.2 7 1.2 9-1"/>', 15) },
    { re: /git/i, icon: sv('<circle cx="6" cy="6" r="2.5"/><circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="12" r="2.5"/><path d="M6 8.5v7M8.2 7.2c4 1 7 2 9.2 2.6"/>', 25) },
    { re: /code|vscode|vim|nvim|emacs|sublime/i, icon: sv('<path d="m9 8-4 4 4 4M15 8l4 4-4 4M13 5l-2 14"/>', 265) },
    { re: /onedrive|gdrive|dropbox|drive|cloud/i, icon: sv('<path d="M7 18a4 4 0 0 1-.5-8A5.5 5.5 0 0 1 17 8.5 4 4 0 0 1 17 18z"/>', 205) },
    { re: /spotify|music|vlc|media/i, icon: sv('<circle cx="12" cy="12" r="9"/><path d="M8 10c3-.8 5.5-.4 7.5 1M8.5 13c2.5-.6 4.4-.3 6 .8M9 16c1.6-.4 2.9-.2 4 .4"/>', 145) },
    { re: /signal|whatsapp|telegram|discord|teams|slack|chat/i, icon: sv('<path d="M20 12a8 8 0 0 1-11.6 7.1L4 20.5l1.5-4.2A8 8 0 1 1 20 12z"/><path d="M8.8 12.2c1.8-2.4 4.6-2.4 6.4 0M9.8 14c1.3-1.6 3-1.6 4.4 0"/>', 170) },
    { re: /claude|copilot|chatgpt|gpt|ollama|llm|ai/i, icon: sv('<path d="M12 3v5M12 16v5M4.2 7.5l4.3 2.5M15.5 14l4.3 2.5M4.2 16.5 8.5 14M15.5 10l4.3-2.5"/><circle cx="12" cy="12" r="1.6"/>', 285) },
    { re: /wps|office|word|excel|powerpoint|notepad|writer/i, icon: sv('<path d="M6 3h9l4 4v14H6z"/><path d="M15 3v4h4M9 12h6M9 16h6"/>', 200) },
    { re: /search|searchhost|spotlight|indexer/i, icon: sv('<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4.5 4.5"/>', 210) },
    { re: /svchost|services|system|kernel|init|daemon|watchdog|agent|host|helper|updater|update|setup|install/i, icon: sv('<circle cx="12" cy="12" r="3"/><path d="M12 3.5v3M12 17.5v3M3.5 12h3M17.5 12h3M6 6l2.1 2.1M15.9 15.9 18 18M18 6l-2.1 2.1M8.1 15.9 6 18"/>', 220) },
    { re: /svchost/i, icon: sv('<circle cx="12" cy="12" r="3"/><path d="M12 3.5v3M12 17.5v3M3.5 12h3M17.5 12h3M6 6l2.1 2.1M15.9 15.9 18 18M18 6l-2.1 2.1M8.1 15.9 6 18"/>', 220) },
  ];
  function appIcon(name, blocked) {
    const n = (name || "?").toLowerCase();
    for (const it of APP_ICONS) {
      if (it.re.test(n)) {
        return `<span class="app-tile svg" style="--tile-h:${blocked ? 0 : it.icon.hue};${blocked ? "opacity:.55;" : ""}">${it.icon.svg}</span>`;
      }
    }
    const hue = [...n].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
    return `<span class="app-tile" style="--tile-h:${blocked ? 0 : hue};${blocked ? "opacity:.55;" : ""}">${esc((name || "?").slice(0, 2).toUpperCase())}</span>`;
  }

  async function refreshApplications() {
    const d = await api("/api/v1/applications");
    if (!d) return;
    appData = d;
    $("apps-count-badge").textContent = `${d.total || 0} apps`;
    $("apps-blocked-badge").textContent = `${d.blocked_count || 0} blocked`;
    renderApps();
  }

  function appMatchesFilter(a) {
    if (appFilter === "net") return a.connections > 0 || a.remote_ip_count > 0;
    if (appFilter === "blocked") return !!a.network_blocked;
    if (appFilter === "system") return !!a.signed;
    return true;
  }

  function appSortKey(a) {
    switch (appSort) {
      case "mem": return -(a.mem_mb || 0);
      case "cpu": return -(a.cpu_percent || 0);
      case "conns": return -((a.connections || 0) + (a.remote_ip_count || 0));
      case "name": return (a.name || "").toLowerCase();
      default: return -((a.bytes_in || 0) + (a.bytes_out || 0));
    }
  }

  function renderApps() {
    const grid = $("apps-grid");
    const search = ($("apps-search").value || "").toLowerCase();
    const apps = (appData.applications || [])
      .filter((a) => !search || a.name.toLowerCase().includes(search) || (a.exe || "").toLowerCase().includes(search))
      .filter(appMatchesFilter)
      .sort((x, y) => {
        const kx = appSortKey(x), ky = appSortKey(y);
        if (typeof kx === "string" || typeof ky === "string") return String(kx).localeCompare(String(ky));
        return ky - kx;
      });
    if (!apps.length) { grid.innerHTML = '<div class="empty-state" style="grid-column:1/-1;">No applications match the filter</div>'; return; }
    grid.innerHTML = apps.map((a, i) => `
      <div class="app-card ${a.network_blocked ? "app-blocked" : ""}" data-idx="${i}">
        ${appIcon(a.name, a.network_blocked)}
        <div class="app-card-body">
          <div class="app-card-name" title="${esc(a.exe)}">${esc(a.name)}${a.process_count > 1 ? ` <span class="app-procs">×${a.process_count}</span>` : ""}</div>
          <div class="app-card-stats mono">
            <span title="CPU / Memory">⚙ ${a.cpu_percent}% · ${a.mem_mb} MB</span>
            <span title="Active connections">⇄ ${a.connections}</span>
            <span title="Traffic ↓/↑">↓${fmtBytes(a.bytes_in)} ↑${fmtBytes(a.bytes_out)}</span>
          </div>
          <div class="app-card-badges">
            ${a.remote_ip_count ? `<span class="badge badge-info">${a.remote_ip_count} IP${a.remote_ip_count > 1 ? "s" : ""}</span>` : '<span class="badge badge-muted">IDLE NET</span>'}
            ${a.network_blocked ? '<span class="badge badge-danger">NETWORK BLOCKED</span>' : ""}
            ${a.signed ? '<span class="badge badge-muted">SYSTEM</span>' : ""}
          </div>
        </div>
      </div>`).join("");
    grid.querySelectorAll(".app-card").forEach((el) => {
      const app = apps[parseInt(el.dataset.idx, 10)];
      el.addEventListener("click", () => openAppDetail(app));
      el.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        openCtxMenu(e, [
          { label: "View Details", action: () => openAppDetail(app) },
          { sep: true },
          app.network_blocked
            ? { label: "Unblock Network", action: () => appAction(app, "unblock_network") }
            : { label: "Block Network Access", action: () => appAction(app, "block_network") },
          { label: "Kill Process" + (app.process_count > 1 ? "es" : ""), danger: true, action: () => { if (confirm(`Kill ${app.name} (PID ${app.pids.join(", ")})?`)) appAction(app, "kill", { pid: app.pids[0] }); } },
          { label: "Quarantine Binary", danger: true, action: () => { if (confirm(`Quarantine ${app.exe}? The application will be disabled.`)) appAction(app, "quarantine"); } },
          { sep: true },
          { label: "Copy Executable Path", action: () => navigator.clipboard && navigator.clipboard.writeText(app.exe) },
          { label: "Ban All Remote IPs", danger: true, action: () => { if (confirm(`Ban all ${app.remote_ip_count} remote IPs of ${app.name}?`)) (app.remote_ips || []).forEach((ip) => window.quickBan(ip, true)); } },
          { label: "VirusTotal: Scan Remote IPs", action: () => (app.remote_ips || []).slice(0, 5).forEach((ip, i) => setTimeout(() => window.vtScan(ip, false), i * 300)) },
        ]);
      });
    });
  }
  $("apps-search").addEventListener("input", renderApps);
  $("apps-sort").addEventListener("change", () => { appSort = $("apps-sort").value; renderApps(); });
  document.querySelectorAll("[data-appfilter]").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll("[data-appfilter]").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      appFilter = chip.getAttribute("data-appfilter");
      renderApps();
    });
  });

  async function appAction(a, action, extra, confirmMsg) {
    if (confirmMsg && !confirm(confirmMsg)) return;
    const res = await jpost("/api/v1/applications/action", Object.assign({ action, exe: a.exe }, extra || {}));
    if (res && !res.error) refreshApplications();
  }

  async function openAppDetail(a) {
    if (!a) return;
    $("app-modal-title").innerHTML = `${appIcon(a.name, a.network_blocked)} ${esc(a.name)}`;
    let html = `
      <div class="appd-path mono">${esc(a.exe)}</div>
      <div class="appd-kv">
        <div><span>Processes</span><b class="mono">${a.process_count} (PIDs: ${a.pids.slice(0, 8).join(", ")}${a.pids.length > 8 ? "…" : ""})</b></div>
        <div><span>CPU / Memory</span><b class="mono">${a.cpu_percent}% / ${a.mem_mb} MB</b></div>
        <div><span>Active connections</span><b class="mono">${a.connections}</b></div>
        <div><span>Traffic ↓ / ↑</span><b class="mono">${fmtBytes(a.bytes_in)} / ${fmtBytes(a.bytes_out)}</b></div>
        <div><span>Unique remote IPs</span><b class="mono">${a.remote_ip_count}</b></div>
        <div><span>Network status</span><b>${a.network_blocked ? '<span style="color:var(--accent-danger)">BLOCKED</span>' : "ALLOWED"}</b></div>
        <div><span>SHA-256</span><b class="mono" style="font-size:10px;">${esc((a.sha256 || "—").slice(0, 32))}${a.sha256 ? "…" : ""}</b></div>
        <div><span>Command line</span><b class="mono" style="font-size:10px; word-break:break-all;">${esc((a.cmdline || "—").slice(0, 160))}</b></div>
      </div>`;

    html += `<div class="appd-sec-title">Remote endpoints <span style="float:right; color:var(--text-muted); font-weight:400;">click = ban · right-click = menu · VT = VirusTotal</span></div>`;
    if (a.remote_ips && a.remote_ips.length) {
      html += `<div class="appd-ips">${a.remote_ips.map((ip) => `<span class="appd-ip mono" data-ip="${esc(ip)}" onclick="window.quickBan('${esc(ip)}')" oncontextmenu="event.preventDefault(); window.ipCtx(event, '${esc(ip)}')">${esc(ip)}</span><span class="appd-vt mono" id="vt-mini-${esc(ip)}" onclick="window.vtScan('${esc(ip)}', true)">VT ▸</span>`).join("")}</div>`;
    } else {
      html += '<div class="empty-state">No remote endpoints in the current window</div>';
    }

    // live connection details for primary pid
    const detail = await api(`/api/v1/applications/detail?pid=${a.pids[0]}`);
    if (detail && detail.connections && detail.connections.length) {
      html += `<div class="appd-sec-title">Live sockets (PID ${a.pids[0]})</div>
        <table class="data-table">
          <thead><tr><th>Proto</th><th>Local</th><th>Remote</th><th>Country</th><th>State</th></tr></thead>
          <tbody>${detail.connections.slice(0, 25).map((c) => `
            <tr>
              <td><span class="badge badge-info">${esc((c.proto || "").toUpperCase())}</span></td>
              <td class="mono">${esc(c.laddr)}:${c.lport}</td>
              <td class="mono">${esc(c.raddr)}:${c.rport}</td>
              <td>${esc(countryName(c.country || "—"))}</td>
              <td class="mono">${esc(c.state || "")}</td>
            </tr>`).join("")}</tbody>
        </table>`;
      const geo = detail.remote_geo || {};
      const geoEntries = Object.entries(geo).filter(([, v]) => v && v.country && !["XX", "ZZ", "UNKNOWN", "LOCAL"].includes(v.country));
      if (geoEntries.length) {
        html += `<div class="appd-sec-title">GeoIP attribution</div><div class="appd-ips">${geoEntries.map(([ip, g]) =>
          `<span class="appd-ip mono">${esc(ip)} <span style="color:var(--text-muted)">${esc(g.country)}</span></span>`).join("")}</div>`;
      }
    }

    html += `<div class="appd-actions">
      ${a.network_blocked
        ? `<button class="btn" id="btn-app-unblock">UNBLOCK NETWORK</button>`
        : `<button class="btn btn-warn" id="btn-app-block">BLOCK NETWORK ACCESS</button>`}
      <button class="btn btn-danger" id="btn-app-kill">KILL PROCESSES</button>
      <button class="btn btn-danger" id="btn-app-quarantine">QUARANTINE BINARY</button>
    </div>`;
    $("app-modal-body").innerHTML = html;
    modalApp.classList.add("open");

    const call = (action, extra, confirmMsg) => async (ev) => {
      if (confirmMsg && !confirm(confirmMsg)) return;
      const btn = ev.target;
      btn.disabled = true;
      const res = await jpost("/api/v1/applications/action", Object.assign({ action, exe: a.exe }, extra || {}));
      if (res && !res.error) {
        showBanner($("app-modal-body"), res.status || "done", true);
        setTimeout(() => { modalApp.classList.remove("open"); refreshApplications(); }, 700);
      } else {
        showBanner($("app-modal-body"), (res && res.error) || "action failed", false);
        btn.disabled = false;
      }
    };
    const bBlock = $("btn-app-block");
    const bUnblock = $("btn-app-unblock");
    const bKill = $("btn-app-kill");
    const bQuar = $("btn-app-quarantine");
    if (bBlock) bBlock.addEventListener("click", call("block_network"));
    if (bUnblock) bUnblock.addEventListener("click", call("unblock_network"));
    if (bKill) bKill.addEventListener("click", call("kill", { pid: a.pids[0] }, `Kill ${a.process_count > 1 ? "primary" : ""} process PID ${a.pids[0]} (${a.name})?`));
    if (bQuar) bQuar.addEventListener("click", call("quarantine", {}, `Quarantine the binary ${a.exe}? The application will be disabled.`));
  }

  function showBanner(container, msg, ok) {
    const b = document.createElement("div");
    b.className = `status-banner show ${ok ? "success" : "error"}`;
    b.textContent = msg;
    container.prepend(b);
    setTimeout(() => b.classList.remove("show"), 6000);
  }

  // =========================================================
  // 9b. CONTEXT MENU + VIRUSTOTAL
  // =========================================================
  const ctxMenu = $("ctx-menu");
  let ctxCloseHandler = null;
  function openCtxMenu(e, items) {
    ctxMenu.innerHTML = items.map((it, i) => it.sep
      ? '<div class="ctx-sep"></div>'
      : `<div class="ctx-item ${it.danger ? "danger" : ""}" data-i="${i}">${it.icon || ""}${esc(it.label)}</div>`).join("");
    ctxMenu.classList.add("open");
    const mw = 240, x = Math.min(e.clientX, window.innerWidth - mw - 10), y = Math.min(e.clientY, window.innerHeight - items.length * 30 - 20);
    ctxMenu.style.left = x + "px";
    ctxMenu.style.top = y + "px";
    ctxMenu.querySelectorAll(".ctx-item").forEach((el) => {
      el.addEventListener("click", () => { closeCtxMenu(); items[parseInt(el.dataset.i, 10)].action && items[parseInt(el.dataset.i, 10)].action(); });
    });
    if (ctxCloseHandler) document.removeEventListener("click", ctxCloseHandler);
    ctxCloseHandler = (ev) => { if (!ctxMenu.contains(ev.target)) closeCtxMenu(); };
    setTimeout(() => document.addEventListener("click", ctxCloseHandler), 0);
  }
  function closeCtxMenu() { ctxMenu.classList.remove("open"); }

  function ipMenuItems(ip) {
    return [
      { label: "Ban IP (24h kernel ban)", danger: true, action: () => window.quickBan(ip, true) },
      { label: "Unban IP", action: () => window.unbanIP(ip) },
      { sep: true },
      { label: "VirusTotal scan", action: () => window.vtScan(ip, true) },
      { label: "Copy IP", action: () => navigator.clipboard && navigator.clipboard.writeText(ip) },
    ];
  }
  window.ipCtx = (e, ip) => { e.preventDefault(); openCtxMenu(e, ipMenuItems(ip)); };

  function vtPopupHtml(p) {
    const vt = p.vt;
    if (!vt) return '<span style="color:var(--text-muted)">VT: not scanned</span>';
    const cls = vt.verdict === "MALICIOUS" ? "threat-malicious" : vt.verdict === "SUSPICIOUS" ? "threat-suspicious" : "threat-normal";
    return `<b class="${cls}">VT: ${esc(vt.verdict)}</b> <span style="color:var(--text-muted)">(${vt.malicious}/${vt.suspicious + vt.malicious + (vt.harmless || 0) + (vt.undetected || 0)} engines)${vt.as_owner ? " · " + esc(vt.as_owner) : ""}</span>`;
  }

  window.vtScan = async (ip, verbose) => {
    if (!ip) return;
    const targets = document.querySelectorAll(`#vt-mini-${CSS.escape(ip)}, #vt-row-${CSS.escape(ip)}`);
    targets.forEach((t) => { if (t) t.innerHTML = '<span style="color:var(--text-muted)">VT: scanning…</span>'; });
    const res = await jpost("/api/v1/vt/scan", { ip });
    let htmlOut;
    if (res && res.error) {
      htmlOut = `<span style="color:var(--accent-warn)">VT: ${esc(res.error)}</span>`;
    } else if (res && res.verdict) {
      const cls = res.verdict === "MALICIOUS" ? "threat-malicious" : res.verdict === "SUSPICIOUS" ? "threat-suspicious" : "threat-normal";
      htmlOut = `<b class="${cls}">VT: ${esc(res.verdict)}</b> <span style="color:var(--text-muted)">${res.malicious}/${res.suspicious + res.malicious + (res.harmless || 0) + (res.undetected || 0)} engines</span>`;
      if (res.verdict === "MALICIOUS" && verbose) showBanner($("app-modal-body") || document.body, `VirusTotal: ${ip} is MALICIOUS (${res.malicious} engines)`, false);
    } else {
      htmlOut = '<span style="color:var(--text-muted)">VT: no data</span>';
    }
    targets.forEach((t) => { if (t) t.innerHTML = htmlOut; });
    refreshMap();
  };

  // =========================================================
  // 9c. FIREWALL POLICIES (FortiGate-style)
  // =========================================================
  let polData = { policies: [] };
  let polServices = [];
  let polProfiles = [];
  let polEditingId = null;

  async function loadPolicies() {
    const [d, s] = await Promise.all([api("/api/v1/policies"), api("/api/v1/policies/services")]);
    if (d) polData = d;
    if (s) { polServices = s.services || []; polProfiles = s.profiles || []; }
    const st = await api("/api/v1/status");
    if (st) $("pol-engine-badge").textContent = `ENFORCED VIA ${(st.backend || "").toUpperCase()}`;
    renderPolicies();
  }

  function renderPolicies() {
    const tbody = document.querySelector("#policies-table tbody");
    if (!tbody) return;
    const search = ($("pol-search").value || "").toLowerCase();
    const pols = (polData.policies || []).filter((p) =>
      !search || (p.name || "").toLowerCase().includes(search) || (p.src || []).join(" ").includes(search) || (p.dst || []).join(" ").includes(search));
    $("pol-count-badge").textContent = `${(polData.policies || []).length} policies`;
    if (!pols.length) {
      tbody.innerHTML = '<tr><td colspan="12" class="empty-state">No firewall policies defined — click CREATE NEW to add the first one</td></tr>';
      return;
    }
    tbody.innerHTML = pols.map((p) => {
      const actionBadge = p.action === "accept" ? "badge-safe" : "badge-danger";
      const actionLabel = p.action === "accept" ? "ACCEPT" : "DENY";
      const profiles = Object.entries(p.profiles || {}).map(([k, v]) => `<span class="pol-prof pol-${esc(k)}">${esc(v)}</span>`).join(" ");
      return `
        <tr class="${p.enabled ? "" : "pol-disabled"}">
          <td class="mono">${p.id}</td>
          <td class="mono">${p.position}</td>
          <td><strong>${esc(p.name)}</strong></td>
          <td class="mono">${esc((p.src || ["any"]).join(", "))}</td>
          <td class="mono">${esc((p.dst || ["any"]).join(", "))}</td>
          <td class="mono">${esc((p.services || ["ANY"]).join(", "))}</td>
          <td><span class="badge ${actionBadge}">${actionLabel}</span></td>
          <td class="mono">${p.nat ? "On" : "—"}</td>
          <td>${profiles || '<span class="badge badge-muted">none</span>'}</td>
          <td class="mono">${p.hits != null ? (p.hits || 0).toLocaleString() : "—"}</td>
          <td><label class="switch"><input type="checkbox" data-poltoggle="${p.id}" ${p.enabled ? "checked" : ""}><span class="slider"></span></label></td>
          <td>
            <button class="btn btn-sm" data-polup="${p.id}" title="Move up">▲</button>
            <button class="btn btn-sm" data-poldown="${p.id}" title="Move down">▼</button>
            <button class="btn btn-sm" data-poledit="${p.id}" title="Edit">EDIT</button>
            <button class="btn btn-sm btn-danger" data-poldel="${p.id}" title="Delete">DEL</button>
          </td>
        </tr>`;
    }).join("");

    tbody.querySelectorAll("[data-poltoggle]").forEach((el) => el.addEventListener("change", async () => {
      await jpost(`/api/v1/policies/${el.dataset.poltoggle}/toggle`);
      loadPolicies();
    }));
    tbody.querySelectorAll("[data-polup]").forEach((el) => el.addEventListener("click", async () => {
      await jpost(`/api/v1/policies/${el.dataset.polup}/reorder`, { up: true });
      loadPolicies();
    }));
    tbody.querySelectorAll("[data-poldown]").forEach((el) => el.addEventListener("click", async () => {
      await jpost(`/api/v1/policies/${el.dataset.poldown}/reorder`, { up: false });
      loadPolicies();
    }));
    tbody.querySelectorAll("[data-poledit]").forEach((el) => el.addEventListener("click", () => openPolicyModal(parseInt(el.dataset.poledit, 10))));
    tbody.querySelectorAll("[data-poldel]").forEach((el) => el.addEventListener("click", async () => {
      const p = polData.policies.find((x) => x.id === parseInt(el.dataset.poldel, 10));
      if (!confirm(`Delete policy ${p ? p.name : el.dataset.poldel}?`)) return;
      await fetch(`/api/v1/policies/${el.dataset.poldel}`, { method: "DELETE" });
      loadPolicies();
    }));
  }
  $("pol-search").addEventListener("input", renderPolicies);
  $("btn-new-policy").addEventListener("click", () => openPolicyModal(null));

  function openPolicyModal(editId) {
    polEditingId = editId;
    const p = editId != null ? (polData.policies || []).find((x) => x.id === editId) : null;
    $("policy-modal-title").textContent = p ? `Edit Policy #${p.id}` : "Create New Policy";
    $("pol-name").value = p ? p.name : "";
    $("pol-direction").value = p ? p.direction : "both";
    $("pol-action").value = p ? p.action : "deny";
    $("pol-enabled").checked = p ? p.enabled : true;
    $("pol-log").checked = p ? p.log : true;
    $("pol-nat").checked = p ? !!p.nat : false;
    $("pol-src").value = p ? (p.src || ["any"]).join(", ") : "any";
    $("pol-dst").value = p ? (p.dst || ["any"]).join(", ") : "any";
    const activeSvcs = new Set(p ? (p.services || ["ANY"]) : ["ANY"]);
    $("pol-services").innerHTML = polServices.map((s) =>
      `<label class="pol-svc-chip"><input type="checkbox" value="${esc(s.name)}" ${activeSvcs.has(s.name) ? "checked" : ""}>${esc(s.name)}</label>`).join("");
    const activeProf = new Set(Object.keys(p ? (p.profiles || {}) : {}));
    $("pol-profiles").innerHTML = polProfiles.map((pr) =>
      `<label class="pol-svc-chip"><input type="checkbox" value="${esc(pr.id)}" ${activeProf.has(pr.id) ? "checked" : ""}>${esc(pr.name)}</label>`).join("");
    modalPolicy.classList.add("open");
  }

  $("btn-submit-policy").addEventListener("click", async () => {
    const services = [...$("pol-services").querySelectorAll("input:checked")].map((i) => i.value);
    const profiles = {};
    $("pol-profiles").querySelectorAll("input:checked").forEach((i) => { profiles[i.value] = { av: "g-default", web: "g-default", dns: "default", app: "g-default", ips: "g-default", ssl: "certificate-inspection" }[i.value] || "g-default"; });
    const body = {
      name: $("pol-name").value.trim() || `Policy-${Date.now()}`,
      direction: $("pol-direction").value,
      action: $("pol-action").value,
      enabled: $("pol-enabled").checked,
      log: $("pol-log").checked,
      nat: $("pol-nat").checked,
      src: $("pol-src").value.trim() || "any",
      dst: $("pol-dst").value.trim() || "any",
      services: services.length ? services : ["ANY"],
      profiles,
    };
    let res;
    if (polEditingId != null) {
      res = await api(`/api/v1/policies/${polEditingId}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } else {
      res = await jpost("/api/v1/policies", body);
    }
    if (res && !res.error) {
      modalPolicy.classList.remove("open");
      loadPolicies();
    } else {
      alert("Policy save failed: " + ((res && res.error) || "unknown error"));
    }
  });

  // =========================================================
  // 9d. VIRUSTOTAL SETTINGS
  // =========================================================
  async function loadVTConfig() {
    const s = await api("/api/v1/vt/config");
    if (!s) return;
    $("vt-auto-scan").checked = !!s.auto_scan_new_ips;
    $("vt-auto-ban").checked = !!s.auto_ban_malicious;
    $("vt-min-votes").value = s.min_malicious_votes || 3;
    if (s.configured) $("vt-api-key").placeholder = "(API key configured — enter a new key to replace it)";
    $("vt-status-inline").textContent = s.configured
      ? `ACTIVE · ${s.cached_ips} IPs scanned · ${s.detected_malicious} flagged malicious · auto-ban ${s.auto_ban_malicious ? "ON" : "off"}`
      : "Not configured — paste a free API key from virustotal.com (Account → API key).";
    const vtb = $("vt-badge-net");
    if (vtb && s.configured) { vtb.textContent = `VT: ${s.detected_malicious} flagged / ${s.cached_ips} cached`; vtb.className = "badge mono " + (s.detected_malicious ? "badge-danger" : "badge-muted"); }
  }

  $("btn-save-vt").addEventListener("click", async () => {
    const body = {
      virustotal_api_key: $("vt-api-key").value.trim(),
      auto_scan_new_ips: $("vt-auto-scan").checked,
      auto_ban_malicious: $("vt-auto-ban").checked,
      min_malicious_votes: parseInt($("vt-min-votes").value, 10) || 3,
    };
    const res = await jpost("/api/v1/vt/config", body);
    const b = $("vt-banner");
    if (res && !res.error) {
      b.className = "status-banner show success";
      b.textContent = `VirusTotal saved — ${res.cached_ips} cached IPs, ${res.detected_malicious} flagged malicious.`;
      $("vt-api-key").value = "";
      loadVTConfig();
    } else {
      b.className = "status-banner show error";
      b.textContent = "Failed to save VirusTotal configuration.";
    }
    setTimeout(() => b.classList.remove("show"), 8000);
  });

  // =========================================================
  // 10. HONEYPOT services
  // =========================================================
  async function refreshHoneypotServices() {
    const d = await api("/api/v1/honeypot/services");
    if (!d) return;
    const grid = $("hp-services-grid");
    const badges = { http: "WEB/HTTP", ssh: "SSH", ftp: "FTP", telnet: "TELNET", mysql: "MYSQL", smb: "SMB", rdp: "RDP", smtp: "SMTP/RELAY" };
    grid.innerHTML = (d.services || []).map((s) => `
      <div class="hp-card ${s.running ? "hp-running" : "hp-stopped"}">
        <div class="hp-card-head">
          <span class="hp-dot"></span>
          <span class="hp-name">${badges[s.service] || s.service.toUpperCase()}</span>
          <span class="hp-port mono">:${s.port}</span>
        </div>
        <div class="hp-card-stats mono">
          <span>${s.running ? "ARMED" : "OFFLINE"}</span>
          <span>hits ${s.hits || 0}</span>
          <span>${s.running ? fmtUptime(s.uptime_seconds) : "—"}</span>
        </div>
        ${s.bind_error ? `<div class="hp-err mono" title="${esc(s.hint || s.bind_error)}">${esc((s.hint || s.bind_error).slice(0, 120))}</div>` : ""}
        ${s.fallback_from ? `<div class="hp-note mono">auto-fell back from :${s.fallback_from} (original port blocked)</div>` : ""}
        <div class="hp-card-actions">
          ${s.running
            ? `<button class="btn btn-sm" data-hp="${s.service}" data-act="stop">STOP</button>`
            : `<button class="btn btn-sm btn-primary" data-hp="${s.service}" data-act="start">SPAWN</button>`}
          ${s.running ? `<input type="number" class="form-input mono hp-rebind" data-hp="${s.service}" value="${s.port}" min="1" max="65535" title="Change port and restart">` : ""}
        </div>
      </div>`).join("");
    grid.querySelectorAll("button[data-hp]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const name = btn.dataset.hp, act = btn.dataset.act;
        btn.disabled = true;
        let port;
        if (act === "start") {
          const inp = grid.querySelector(`.hp-rebind[data-hp="${name}"]`);
          port = inp ? parseInt(inp.value, 10) : undefined;
        }
        const res = await jpost("/api/v1/honeypot/services", { name, action: act, port });
        if (res && res.error) alert("Honeypot error: " + res.error);
        else if (res && res.bind_error) alert("Bind failed: " + res.bind_error);
        refreshHoneypotServices();
      });
    });
    grid.querySelectorAll(".hp-rebind").forEach((inp) => {
      inp.addEventListener("change", async () => {
        const name = inp.dataset.hp;
        await jpost("/api/v1/honeypot/services", { name, action: "stop" });
        const res = await jpost("/api/v1/honeypot/services", { name, action: "start", port: parseInt(inp.value, 10) });
        if (res && res.bind_error) alert("Bind failed: " + res.bind_error);
        refreshHoneypotServices();
      });
    });
  }
  $("btn-spawn-all").addEventListener("click", async () => {
    const d = await api("/api/v1/honeypot/services");
    for (const s of (d && d.services) || []) {
      if (!s.running) await jpost("/api/v1/honeypot/services", { name: s.service, action: "start" });
    }
    refreshHoneypotServices();
  });
  $("btn-stop-all-hp").addEventListener("click", async () => {
    const d = await api("/api/v1/honeypot/services");
    for (const s of (d && d.services) || []) {
      if (s.running) await jpost("/api/v1/honeypot/services", { name: s.service, action: "stop" });
    }
    refreshHoneypotServices();
  });

  // =========================================================
  // 11. Rules view
  // =========================================================
  async function loadRules() {
    const rules = await api("/api/v1/rules");
    const tbody = document.querySelector("#rules-table tbody");
    if (!tbody || !rules) return;
    tbody.innerHTML = "";
    const all = [
      ...rules.ip.map((v) => ({ type: "ip", val: v })),
      ...rules.domain.map((v) => ({ type: "domain", val: v })),
      ...rules.program.map((v) => ({ type: "program", val: v })),
      ...rules.hash.map((v) => ({ type: "hash", val: v })),
    ];
    if (!all.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No manual firewall rules defined</td></tr>';
      return;
    }
    all.forEach((r) => {
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td><span class="badge badge-info">${esc(r.type.toUpperCase())}</span></td>
          <td class="mono"><strong>${esc(r.val)}</strong></td>
          <td><span class="badge badge-danger">DROP / DENY</span></td>
          <td><button class="btn btn-sm btn-danger" onclick="window.removeRule('${r.type}', '${esc(r.val)}')">REMOVE</button></td>
        </tr>`);
    });
  }

  // =========================================================
  // 12. SSE live logs
  // =========================================================
  let sseActive = true;
  let eventSource = null;
  const logLinesBox = $("log-lines");
  const logFilterChips = document.querySelectorAll(".filter-chip");
  let activeSevFilter = "";

  logFilterChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      logFilterChips.forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      activeSevFilter = chip.getAttribute("data-sev");
      applyLogFilters();
    });
  });
  $("logs-search").addEventListener("input", applyLogFilters);

  function applyLogFilters() {
    const q = $("logs-search").value.toLowerCase();
    logLinesBox.querySelectorAll(".log-line").forEach((l) => {
      const sev = l.getAttribute("data-sev") || "";
      const text = l.textContent.toLowerCase();
      const matchSev = !activeSevFilter || sev.includes(activeSevFilter);
      l.style.display = (matchSev && (!q || text.includes(q))) ? "flex" : "none";
    });
  }

  function appendLogEvent(evt) {
    if (!logLinesBox) return;
    const sev = (evt.severity || "info").toLowerCase();
    const div = document.createElement("div");
    div.className = `log-line ${sev}`;
    div.setAttribute("data-sev", sev);
    const ts = evt.ts || new Date().toISOString().substring(11, 19);
    const kind = (evt.kind || "EVENT").toUpperCase();
    const details = Object.entries(evt)
      .filter(([k]) => !["ts", "severity", "kind"].includes(k))
      .map(([k, v]) => `${k}=${v}`).join(" ");
    div.innerHTML = `
      <span class="log-line-ts">${esc(ts)}</span>
      <span class="log-line-sev">[${esc(sev.toUpperCase())}]</span>
      <span><strong>${esc(kind)}</strong> ${esc(details)}</span>`;
    logLinesBox.insertBefore(div, logLinesBox.firstChild);
    while (logLinesBox.children.length > 250) logLinesBox.removeChild(logLinesBox.lastChild);
    applyLogFilters();
  }

  function initSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource("/api/v1/logs/stream");
    eventSource.onmessage = (e) => {
      if (!sseActive) return;
      try { appendLogEvent(JSON.parse(e.data)); } catch { /* ignore */ }
    };
    eventSource.onerror = () => { setTimeout(initSSE, 5000); };
  }
  fetch("/api/v1/logs?limit=50").then((r) => r.json()).then((logs) => { logs.reverse().forEach(appendLogEvent); }).catch(() => {});
  initSSE();

  const toggleStreamBtn = $("btn-toggle-stream");
  toggleStreamBtn.addEventListener("click", () => {
    sseActive = !sseActive;
    $("stream-status-label").textContent = sseActive ? "STREAMING" : "PAUSED";
    toggleStreamBtn.classList.toggle("btn-danger", !sseActive);
  });
  $("btn-clear-logs").addEventListener("click", () => { logLinesBox.innerHTML = ""; });

  // =========================================================
  // 13. Telegram
  // =========================================================
  async function loadTelegramConfig() {
    const tc = await api("/api/v1/telegram/config");
    if (!tc) return;
    $("telegram-enabled").checked = tc.enabled;
    $("telegram-chat-id").value = tc.chat_id || "";
    $("telegram-rate").value = tc.rate_limit_per_minute || 15;
    if (tc.has_token) $("telegram-token").placeholder = "(Token securely configured; enter new to change)";
    if (tc.alert_levels) {
      $("sev-critical").checked = tc.alert_levels.includes("critical");
      $("sev-warning").checked = tc.alert_levels.includes("warning");
      $("sev-info").checked = tc.alert_levels.includes("info");
    }
    $("telegram-status-inline").textContent = tc.enabled
      ? `Dispatcher ACTIVE · chat ${tc.chat_id || "?"} · levels: ${(tc.alert_levels || []).join(", ")}`
      : "Dispatcher DISABLED — alerts are only stored locally.";
  }

  function showTelegramBanner(msg, isSuccess) {
    const b = $("telegram-banner");
    b.className = `status-banner show ${isSuccess ? "success" : "error"}`;
    b.textContent = msg;
    setTimeout(() => b.classList.remove("show"), 8000);
  }

  $("btn-test-telegram").addEventListener("click", async () => {
    const token = $("telegram-token").value;
    const cid = $("telegram-chat-id").value;
    const res = await jpost("/api/v1/telegram/test", { bot_token: token, chat_id: cid });
    if (res && res.ok) showTelegramBanner("Telegram bot connected! Verification alert dispatched.", true);
    else showTelegramBanner(`Telegram error: ${(res && res.error) || "request failed"}`, false);
  });

  $("btn-save-telegram").addEventListener("click", async () => {
    const levels = [];
    if ($("sev-critical").checked) levels.push("critical");
    if ($("sev-warning").checked) levels.push("warning");
    if ($("sev-info").checked) levels.push("info");
    const res = await jpost("/api/v1/telegram/config", {
      bot_token: $("telegram-token").value,
      chat_id: $("telegram-chat-id").value,
      enabled: $("telegram-enabled").checked,
      alert_levels: levels,
      rate_limit_per_minute: parseInt($("telegram-rate").value, 10) || 15,
      include_ip_info: $("telegram-geo").checked,
    });
    if (res && !res.error) showTelegramBanner("Telegram configuration saved and dispatcher updated.", true);
    else showTelegramBanner("Failed to save Telegram configuration.", false);
  });

  // =========================================================
  // 14. Sandbox detonate
  // =========================================================
  $("btn-detonate").addEventListener("click", async () => {
    const path = $("sandbox-path").value.trim();
    if (!path) return;
    const btn = $("btn-detonate");
    btn.disabled = true;
    btn.textContent = "DETONATING…";
    const res = await jpost("/api/v1/sandbox/submit", { path });
    btn.disabled = false;
    btn.textContent = "DETONATE";
    if (res && !res.error) {
      showBanner($("sandbox-banner") || document.body, `Verdict: ${res.verdict} (score ${res.total_score}/100)`, res.verdict !== "MALICIOUS");
      const sb = await api("/api/v1/sandbox/results");
      if (sb) renderSandboxTable(sb);
    } else {
      showBanner($("sandbox-banner") || document.body, (res && res.error) || "detonation failed", false);
    }
  });

  // =========================================================
  // 15. Global actions
  // =========================================================
  window.quickBan = async (ip, noConfirm) => {
    if (!ip || (!noConfirm && !confirm(`Enforce immediate autonomous kernel ban for IP ${ip}?`))) return;
    await jpost("/api/v1/bans", { ip, reason: "Manual mitigation via console", duration: 86400 });
    syncDashboard(); refreshMap();
  };
  window.unbanIP = async (ip) => {
    await fetch(`/api/v1/bans/${encodeURIComponent(ip)}`, { method: "DELETE" });
    syncDashboard(); refreshMap();
  };
  window.removeRule = async (type, val) => {
    await fetch(`/api/v1/rules/${type}/${encodeURIComponent(val)}`, { method: "DELETE" });
    loadRules();
  };

  $("btn-submit-ban").addEventListener("click", async () => {
    const ip = $("ban-ip-input").value.trim();
    const dur = parseInt($("ban-duration-input").value, 10) || 86400;
    const reason = $("ban-reason-input").value.trim();
    if (!ip) return;
    await jpost("/api/v1/bans", { ip, duration: dur, reason });
    modalBan.classList.remove("open");
    syncDashboard();
  });

  $("btn-submit-rule").addEventListener("click", async () => {
    const type = $("rule-type-select").value;
    const val = $("rule-value-input").value.trim();
    if (!val) return;
    await jpost("/api/v1/rules", { type, value: val });
    modalRule.classList.remove("open");
    loadRules();
  });

  $("btn-save-engine").addEventListener("click", async () => {
    const profile = $("engine-profile").value;
    const dur = parseInt($("cfg-ban-duration").value, 10) || 86400;
    const res = await jpost("/api/v1/config", { enforcement_profile: profile, auto_ban_seconds: dur });
    if (res && !res.error) showTelegramBanner("Engine parameters updated.", true);
  });

  $("btn-manual-refresh").addEventListener("click", () => {
    syncDashboard(); loadRules(); refreshMap(); refreshApplications();
  });

  // Kick off
  syncDashboard();
  setInterval(syncDashboard, 3000);
});
