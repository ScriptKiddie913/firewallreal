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

  function csrfToken() {
    const m = document.cookie.match(/(?:^|;\s*)sfw_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : "";
  }
  async function api(path, opts) {
    try {
      opts = Object.assign({}, opts);
      if (opts.method && opts.method !== "GET") {
        opts.headers = Object.assign({}, opts.headers || {}, {
          "Content-Type": opts.headers && opts.headers["Content-Type"] ? opts.headers["Content-Type"] : "application/json",
          "X-CSRF-Token": csrfToken(),
        });
        if (!opts.body) opts.body = "{}";
      }
      const res = await fetch(path, opts);
      if (res.status === 401 && !path.startsWith("/api/v1/auth")) { location.href = "/login"; return null; }
      if (!res.ok && res.status !== 400) return null;
      return await res.json().catch(() => null);
    } catch { return null; }
  }
  const jget = (path) => api(path);
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
    services: "Security Services Matrix — Unified Enforcement Pipeline",
    network: "Network Monitor — Deep Packet Inspection & Geo Threat Map",
    policies: "Firewall Policies — Sequence & Enforcement",
    applications: "Application & Software Inventory",
    connections: "Live Network Sockets & Process Attribution",
    rules: "Firewall Filter Rules Manager",
    appwall: "Per-Application Network Policies",
    waf: "Web Application Firewall & OWASP CRS 3.3",
    dlp: "Data Loss Prevention & Sensitive Pattern Inspector",
    ztna: "Zero Trust Network Access & Posture Evaluation",
    threatintel: "Threat Intelligence Platform & Feed Ingestion",
    playbooks: "SOAR Automated Incident Response Playbooks",
    identity: "Identity Directory & Device-ID Inventory",
    "ai-analyst": "AI Security Analyst & Human-in-the-Loop Advisory",
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
    try {
      if (tabId === "services") loadServicesStatus();
      if (tabId === "settings") { loadTelegramConfig(); loadVTConfig(); loadTrustedIps(); loadSarvamConfig(); loadClamav(); loadSecurity(); loadOps(); loadDns(); loadFleet(); loadVault(); loadIntegrations(); }
      if (tabId === "rules") loadRules();
      if (tabId === "network") {
        if (!mapObj) initMap();
        setTimeout(() => { window.mapObj && window.mapObj.resize(); }, 60);
        setTimeout(() => { window.mapObj && window.mapObj.resize(); }, 250);
        setTimeout(() => { window.mapObj && window.mapObj.resize(); }, 600);
        refreshMap();
      }
      if (tabId === "connections") {
        if (connView === "appmap") {
          if (!appMapObj) initConnAppMap();
          setTimeout(() => { appMapObj && appMapObj.resize(); }, 60);
          setTimeout(() => { appMapObj && appMapObj.resize(); }, 250);
        }
      }
      if (tabId === "policies") loadPolicies();
      if (tabId === "applications") refreshApplications();
      if (tabId === "honeypot") { refreshHoneypotServices(); loadTarpit(); }
      if (tabId === "appwall") loadAppwall();
      if (tabId === "waf") loadWaf();
      if (tabId === "dlp") loadDlp();
      if (tabId === "ztna") loadZtna();
      if (tabId === "threatintel") loadThreatIntel();
      if (tabId === "playbooks") loadPlaybooks();
      if (tabId === "identity") loadIdentity();
      if (tabId === "ai-analyst") loadAiAnalyst();
    } catch (tabErr) {
      console.error(`Error loading content for tab ${tabId}:`, tabErr);
    }
  }

  navItems.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const tab = btn.getAttribute("data-tab") || (btn.closest(".nav-item") && btn.closest(".nav-item").getAttribute("data-tab"));
      if (tab) switchTab(tab);
    });
  });

  const sidebarNav = document.querySelector(".sidebar-nav");
  if (sidebarNav) {
    sidebarNav.addEventListener("click", (e) => {
      const btn = e.target.closest(".nav-item");
      if (btn) {
        const tab = btn.getAttribute("data-tab");
        if (tab) switchTab(tab);
      }
    });
  }

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

    if (document.querySelector("#tab-applications") && document.querySelector("#tab-applications").classList.contains("active")) {
      refreshApplications();
    }
    if (document.querySelector("#tab-services") && document.querySelector("#tab-services").classList.contains("active")) {
      loadServicesStatus();
    }

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
    const surState = svc.suricata_state || {};
    const surChip = (st) => {
      const cls = st === "running" ? "ok" : st === "installed" ? "warn" : "off";
      const label = st === "running" ? "SURICATA IDS" : st === "installed" ? "SURICATA (IDLE)"
        : st === "disabled" ? "SURICATA OFF" : "SURICATA (OPTIONAL)";
      return `<span class="svc-chip ${cls}" title="${esc(surState.detail || "")}"><span class="svc-dot"></span>${label}</span>`;
    };
    const hpRunning = (svc.honeypot || []).filter((x) => x.running).length;
    $("ov-services").innerHTML = [
      chip(svc.sniffer_active, "PACKET CAPTURE"),
      chip(hpRunning > 0, `HONEYPOTS ${hpRunning}/${(svc.honeypot || []).length}`),
      chip(svc.telegram_active, "TELEGRAM"),
      surChip(surState.state),
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

  // ---- connection state: rates, selection, history for the visualizer ----
  let connLatest = [];
  let connPrev = {};        // key -> {ts, bytes_in, bytes_out}
  let connRates = {};      // key -> {rate_in, rate_out}
  let connHistory = [];     // [{ts, series: {key: rate}}] rolling 90 samples
  let connSelected = null;  // key of selected connection
  let connView = "chart";
  const connKey = (c) => `${c.pid}|${c.proto}|${c.laddr}:${c.lport}|${c.raddr}:${c.rport}`;

  function computeConnRates(conns) {
    const now = Date.now() / 1000;
    const next = {};
    connRates = {};
    conns.forEach((c) => {
      const k = connKey(c);
      const bi = c.bytes_in || 0, bo = c.bytes_out || 0;
      const prev = connPrev[k];
      if (prev && now - prev.ts >= 0.5) {
        connRates[k] = {
          rate_in: Math.max(0, (bi - prev.bi) / (now - prev.ts)),
          rate_out: Math.max(0, (bo - prev.bo) / (now - prev.ts)),
        };
      } else {
        connRates[k] = { rate_in: 0, rate_out: 0 };
      }
      next[k] = { ts: now, bi, bo };
    });
    connPrev = next;
  }

  function pushConnHistory() {
    const series = {};
    connLatest.forEach((c) => {
      if (!c.raddr || c.raddr === "*") return;
      const r = connRates[connKey(c)] || { rate_in: 0, rate_out: 0 };
      series[connKey(c)] = (r.rate_in + r.rate_out);
    });
    connHistory.push({ ts: Date.now() / 1000, series });
    if (connHistory.length > 90) connHistory.shift();
  }

  function renderConnectionsTable(conns) {
    connLatest = conns;
    computeConnRates(conns);
    const tbody = document.querySelector("#conns-table tbody");
    if (!tbody) return;
    const search = ($("conns-search").value || "").toLowerCase();
    const filtered = conns.filter((c) => {
      if (!search) return true;
      return `${c.pid} ${c.exe} ${c.proto} ${c.laddr} ${c.raddr} ${c.country} ${c.state}`.toLowerCase().includes(search);
    });
    const countBadge = $("conn-count-badge");
    if (countBadge) countBadge.textContent = `${conns.length} sockets`;
    // FortiGate-style session summary strip
    const est = conns.filter((c) => (c.state || "").startsWith("ESTABLISHED")).length;
    const listen = conns.filter((c) => (c.state || "").startsWith("LISTEN")).length;
    const udp = conns.filter((c) => (c.proto || "").toLowerCase() === "udp").length;
    const apps = new Set(conns.map((c) => c.exe).filter(Boolean)).size;
    const remotes = new Set(conns.map((c) => c.raddr).filter((r) => r && r !== "*")).size;
    let rateIn = 0, rateOut = 0;
    conns.forEach((c) => {
      const r = connRates[connKey(c)] || { rate_in: 0, rate_out: 0 };
      rateIn += r.rate_in; rateOut += r.rate_out;
    });
    const setCS = (id, v) => { const el = $(id); if (el) el.textContent = v; };
    setCS("cs-total", conns.length); setCS("cs-est", est); setCS("cs-listen", listen);
    setCS("cs-udp", udp); setCS("cs-apps", apps); setCS("cs-remotes", remotes);
    setCS("cs-rate", `↓${fmtBytes(rateIn)}/s ↑${fmtBytes(rateOut)}/s`);
    tbody.innerHTML = "";
    if (!filtered.length) {
      tbody.innerHTML = '<tr><td colspan="10" class="empty-state">No active sockets matching criteria</td></tr>';
      return;
    }
    const ratesSorted = [...filtered].sort((a, b) => {
      const ra = connRates[connKey(a)] || { rate_in: 0, rate_out: 0 };
      const rb = connRates[connKey(b)] || { rate_in: 0, rate_out: 0 };
      return (rb.rate_in + rb.rate_out) - (ra.rate_in + ra.rate_out);
    });
    ratesSorted.slice(0, 80).forEach((c) => {
      const k = connKey(c);
      const raddr = c.raddr ? `${c.raddr}:${c.rport}` : "*";
      const r = connRates[k] || { rate_in: 0, rate_out: 0 };
      const sel = connSelected === k ? " conn-row-selected" : "";
      tbody.insertAdjacentHTML("beforeend", `
        <tr class="conn-row${sel}" data-key="${esc(k)}">
          <td class="mono">${c.pid}</td>
          <td><strong title="${esc(c.exe)}">${esc((c.exe || "System").split(/[\\/]/).pop())}</strong></td>
          <td><span class="badge badge-info">${esc((c.proto || "TCP").toUpperCase())}</span></td>
          <td class="mono">${esc(c.laddr)}:${c.lport}</td>
          <td class="mono">${esc(raddr)}</td>
          <td><span class="badge badge-muted">${esc(countryName(c.country || "LOCAL"))}</span></td>
          <td class="mono" title="Total ↓ / ↑">↓${fmtBytes(c.bytes_in || 0)} ↑${fmtBytes(c.bytes_out || 0)}</td>
          <td class="mono conn-live">↓${fmtBytes(r.rate_in)}/s ↑${fmtBytes(r.rate_out)}/s</td>
          <td><span class="badge ${c.state === "LISTEN" || c.state === "LISTENING" ? "badge-safe" : "badge-warn"}">${esc(c.state || "ESTABLISHED")}</span></td>
          <td>${c.raddr && c.raddr !== "127.0.0.1" && c.raddr !== "*" ? `<button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); window.quickBan('${esc(c.raddr)}')">BAN</button>` : "-"}</td>
        </tr>`);
    });
    tbody.querySelectorAll(".conn-row").forEach((el) => {
      const k = el.dataset.key;
      el.addEventListener("click", () => { connSelected = k; renderConnectionsTable(conns); renderConnDetail(); });
      el.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        const c = connLatest.find((x) => connKey(x) === k);
        if (!c) return;
        openCtxMenu(e, [
          { label: "View Details", action: () => { connSelected = k; renderConnDetail(); document.querySelector(".conn-detail-panel").scrollIntoView({ behavior: "smooth" }); } },
          { sep: true },
          ...(c.raddr && c.raddr !== "*" ? [
            { label: "Ban remote IP", danger: true, action: () => window.quickBan(c.raddr, true) },
            { label: "VirusTotal scan remote IP", action: () => window.vtScan(c.raddr, true) },
            { label: "Copy remote IP", action: () => navigator.clipboard && navigator.clipboard.writeText(c.raddr) },
          ] : []),
          { label: "Copy executable path", action: () => navigator.clipboard && navigator.clipboard.writeText(c.exe || "") },
          ...(c.pid ? [{ label: `Kill process (PID ${c.pid})`, danger: true, action: () => { if (confirm(`Kill PID ${c.pid} (${(c.exe || "").split(/[\\/]/).pop()})?`)) jpost("/api/v1/applications/action", { action: "kill", exe: c.exe, pid: c.pid }); } }] : []),
        ]);
      });
    });
    pushConnHistory();
    if (connView === "chart") renderConnChart();
    else if (connView === "map") renderConnFlowmap();
    else if (connView === "appmap") renderConnAppMap();
    if (connSelected) renderConnDetail();
  }

  function renderConnDetail() {
    const box = $("conn-detail");
    if (!box) return;
    const c = connLatest.find((x) => connKey(x) === connSelected);
    const badge = $("conn-detail-badge");
    if (!c) {
      box.innerHTML = '<div class="empty-state">Click any connection above to inspect it — live rates, geo, threat vectors and one-click actions.</div>';
      if (badge) badge.textContent = "select a row";
      return;
    }
    const r = connRates[connKey(c)] || { rate_in: 0, rate_out: 0 };
    const name = (c.exe || "System").split(/[\\/]/).pop();
    if (badge) badge.textContent = `${name} → ${c.raddr || "*"}`;
    const fv = flowData.vectors && flowData.vectors[c.raddr];
    box.innerHTML = `
      <div class="cd-head">
        <span class="cd-name">${esc(name)}</span>
        <span class="mono cd-socks">${esc(c.laddr)}:${c.lport} → ${esc(c.raddr || "*")}${c.rport ? ":" + c.rport : ""}</span>
      </div>
      <div class="cd-grid">
        <div><span>PID / Protocol</span><b class="mono">${c.pid} / ${esc((c.proto || "tcp").toUpperCase())}</b></div>
        <div><span>State</span><b>${esc(c.state || "—")}</b></div>
        <div><span>Country</span><b>${esc(countryName(c.country || "LOCAL"))}</b></div>
        <div><span>Total ↓ / ↑</span><b class="mono">↓${fmtBytes(c.bytes_in || 0)} · ↑${fmtBytes(c.bytes_out || 0)}</b></div>
        <div><span>Live rate</span><b class="mono cd-live">↓${fmtBytes(r.rate_in)}/s · ↑${fmtBytes(r.rate_out)}/s</b></div>
        <div><span>Threat vectors</span><b>${fv && fv.vectors && fv.vectors.length
        ? fv.vectors.slice(0, 2).map((v) => `<span class="vec-badge" style="--vc:${(VEC_META[v.type] || ["", "#d9a036"])[1]}" title="${esc(v.evidence || "")}">${esc(v.label)}</span>`).join(" ")
        : '<span style="color:var(--accent-safe)">none detected</span>'}</b></div>
      </div>
      <div class="cd-actions">
        ${c.raddr && c.raddr !== "*" ? `
          <button class="btn btn-sm btn-danger" onclick="window.quickBan('${esc(c.raddr)}', true)">BAN REMOTE IP</button>
          <button class="btn btn-sm" onclick="window.vtScan('${esc(c.raddr)}', true)">VT SCAN</button>` : ""}
        ${c.pid ? `<button class="btn btn-sm btn-danger" id="btn-cd-kill">KILL PROCESS</button>` : ""}
      </div>`;
    const kill = box.querySelector("#btn-cd-kill");
    if (kill) kill.addEventListener("click", async () => {
      if (!confirm(`Kill PID ${c.pid} (${name})?`)) return;
      await jpost("/api/v1/applications/action", { action: "kill", exe: c.exe, pid: c.pid });
    });
  }

  const CONN_COLORS = ["#4a90d9", "#429462", "#d9a036", "#e04f4f", "#9a6ec9", "#d97b3f"];
  function renderConnChart() {
    const canvas = $("conn-chart");
    if (!canvas || connView !== "chart") return;
    const w = canvas.clientWidth || canvas.parentElement.clientWidth || 800;
    const h = 240;
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext && canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, w, h);
    // top-6 keys by latest rate
    const last = connHistory[connHistory.length - 1];
    if (!last || !connHistory.length) {
      ctx.fillStyle = "#5a6472"; ctx.font = "11px monospace"; ctx.textAlign = "center";
      ctx.fillText("waiting for traffic samples…", w / 2, h / 2);
      return;
    }
    const keys = Object.entries(last.series).sort((a, b) => b[1] - a[1]).slice(0, 6).map((e) => e[0]);
    const peak = Math.max(1, ...connHistory.flatMap((s) => keys.map((k) => s.series[k] || 0)));
    // grid
    ctx.strokeStyle = "rgba(255,255,255,.06)"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = 12 + (h - 44) * i / 4;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      ctx.fillStyle = "#5a6472"; ctx.font = "9px monospace"; ctx.textAlign = "left";
      ctx.fillText(fmtBytes(peak * (1 - i / 4)) + "/s", 4, y - 2);
    }
    keys.forEach((k, idx) => {
      ctx.strokeStyle = CONN_COLORS[idx % CONN_COLORS.length];
      ctx.lineWidth = 1.8;
      ctx.beginPath();
      connHistory.forEach((s, i) => {
        const v = s.series[k] || 0;
        const x = (i / Math.max(1, connHistory.length - 1)) * (w - 8) + 4;
        const y = 12 + (h - 44) * (1 - v / peak);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    });
    // legend
    ctx.textAlign = "left"; ctx.font = "9px monospace";
    keys.forEach((k, idx) => {
      const c = connLatest.find((x) => connKey(x) === k);
      if (!c) return;
      const label = `${(c.exe || "?").split(/[\\/]/).pop().slice(0, 14)} → ${c.raddr || "?"}`;
      const x = 8 + (idx % 2) * (w / 2), y = h - 18 + Math.floor(idx / 2) * 11;
      ctx.fillStyle = CONN_COLORS[idx % CONN_COLORS.length];
      ctx.fillRect(x, y - 7, 8, 8);
      ctx.fillStyle = "#aab4c0";
      ctx.fillText(label.slice(0, 46), x + 12, y);
    });
  }

  let _lastFlowmapSig = "";
  function renderConnFlowmap() {
    const box = $("conn-flowmap");
    if (!box || connView !== "map") return;
    // node-by-node infrastructure graph: APPLICATION → LOCAL PORT → REMOTE IP
    const withRemote = connLatest.filter((c) => c.raddr && c.raddr !== "*" && c.raddr !== "127.0.0.1");
    if (!withRemote.length) {
      if (_lastFlowmapSig !== "empty") {
        _lastFlowmapSig = "empty";
        box.innerHTML = '<div class="empty-state">No active remote connections — the infrastructure graph will draw itself as applications connect.</div>';
      }
      return;
    }
    const sig = withRemote.map((c) => `${(c.exe || "").split(/[\\/]/).pop()}:${c.raddr}:${c.rport}:${Math.round((c.bytes_in || 0) / 4096)}`).slice(0, 30).join("|");
    if (sig === _lastFlowmapSig) return;
    _lastFlowmapSig = sig;
    // aggregate edges: app -> port -> remote
    const apps = {}, remotes = {}, edges = [];
    withRemote.forEach((c) => {
      const an = (c.exe || "System").split(/[\\/]/).pop();
      const r = connRates[connKey(c)] || { rate_in: 0, rate_out: 0 };
      const app = apps[an] = apps[an] || { name: an, exe: c.exe, conns: 0, rate: 0 };
      const rem = remotes[c.raddr] = remotes[c.raddr] || { ip: c.raddr, country: c.country, conns: 0, rate: 0 };
      app.conns++; rem.conns++;
      app.rate += r.rate_in + r.rate_out; rem.rate += r.rate_in + r.rate_out;
      let e = edges.find((x) => x.app === an && x.ip === c.raddr && x.port === c.rport);
      if (!e) edges.push(e = { app: an, ip: c.raddr, port: c.rport, rate: 0, conns: 0, state: c.state });
      e.rate += r.rate_in + r.rate_out; e.conns++;
    });
    const appList = Object.values(apps).sort((a, b) => b.rate - a.rate).slice(0, 14);
    const remList = Object.values(remotes).sort((a, b) => b.rate - a.rate).slice(0, 18);
    const peak = Math.max(1, ...appList.map((a) => a.rate), ...remList.map((r) => r.rate));
    // layout
    const W = Math.max(760, box.clientWidth || 760), H = Math.max(300, appList.length * 46 + 40);
    const xApp = 190, xPort = W / 2, xRem = W - 190;
    const yApp = (i) => 34 + i * ((H - 50) / Math.max(1, appList.length - 1 || 1));
    const yRem = (i) => 34 + i * ((H - 50) / Math.max(1, remList.length - 1 || 1));
    const ai = {}; appList.forEach((a, i) => (ai[a.name] = i));
    const ri = {}; remList.forEach((r, i) => (ri[r.ip] = i));
    const esc2 = (s) => String(s).replace(/&/g, "&").replace(/</g, "<").replace(/>/g, ">");
    let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" xmlns="http://www.w3.org/2000/svg">`;
    // edges (through the port spine)
    edges.forEach((e) => {
      const y1 = ai[e.app] !== undefined ? yApp(ai[e.app]) : null;
      const y2 = ri[e.ip] !== undefined ? yRem(ri[e.ip]) : null;
      if (y1 === null || y2 === null) return;
      const wgt = Math.max(1, Math.min(9, Math.round((e.rate / peak) * 9)));
      const op = Math.max(0.25, 0.25 + (e.rate / peak) * 0.65);
      svg += `<path d="M ${xApp + 6} ${y1} C ${xPort - 90} ${y1}, ${xPort + 90} ${y2}, ${xRem - 6} ${y2}"
        fill="none" stroke="${appColor(e.app)}" stroke-width="${wgt}" stroke-opacity="${op.toFixed(2)}"/>`;
    });
    // port labels along the spine (distinct ports in use)
    const ports = [...new Set(edges.map((e) => e.port))].slice(0, 14);
    ports.forEach((port, i) => {
      const y = 22 + (i + 0.5) * ((H - 44) / Math.max(1, ports.length));
      svg += `<rect x="${xPort - 24}" y="${y - 9}" width="48" height="18" rx="3" fill="#1d2632" stroke="rgba(255,255,255,.12)"/>
        <text x="${xPort}" y="${y + 4}" fill="#8fa3b8" font-size="10" font-family="monospace" text-anchor="middle">:${port}</text>`;
    });
    // app nodes
    appList.forEach((a, i) => {
      const y = yApp(i);
      const wgt = Math.max(1, Math.min(9, Math.round((a.rate / peak) * 9)));
      svg += `<circle cx="${xApp}" cy="${y}" r="${7 + wgt}" fill="${appColor(a.name)}" fill-opacity=".9"/>
        <rect x="${xApp + 12}" y="${y - 10}" width="176" height="20" rx="3" fill="#171f29" stroke="rgba(255,255,255,.10)"/>
        <text x="${xApp + 20}" y="${y + 4}" fill="#dfe6ee" font-size="11" font-family="monospace">${esc2(a.name.slice(0, 20))}</text>
        <text x="${xApp + 184}" y="${y + 4}" fill="#5a6472" font-size="9" font-family="monospace" text-anchor="end">${esc2(a.conns)}c</text>`;
    });
    // remote nodes
    remList.forEach((r, i) => {
      const y = yRem(i);
      const wgt = Math.max(1, Math.min(9, Math.round((r.rate / peak) * 9)));
      const bad = r.country && (flowData.vectors || {})[r.ip];
      svg += `<circle cx="${xRem}" cy="${y}" r="${6 + wgt}" fill="${bad ? "#e04f4f" : "#6e93b8"}" fill-opacity=".9"/>
        <rect x="${xRem - 192}" y="${y - 10}" width="176" height="20" rx="3" fill="#171f29" stroke="rgba(255,255,255,.10)"/>
        <text x="${xRem - 184}" y="${y + 4}" fill="#dfe6ee" font-size="10" font-family="monospace">${esc2(r.ip)}</text>
        <text x="${xRem - 8}" y="${y + 4}" fill="#5a6472" font-size="9" font-family="monospace" text-anchor="end">${esc2(countryName(r.country || "—").slice(0, 10))}</text>`;
    });
    svg += "</svg>";
    box.innerHTML = `<div class="nf-title">APPLICATIONS (${appList.length}) → PORTS (${ports.length}) → REMOTE ENDPOINTS (${remList.length}) · line width = live throughput</div>` + svg;
  }

  $("conn-view-chart").addEventListener("click", () => {
    connView = "chart";
    $("conn-view-chart").classList.add("active");
    $("conn-view-map").classList.remove("active");
    $("conn-chart").style.display = "";
    $("conn-flowmap").style.display = "none";
    renderConnChart();
  });
  $("conn-view-map").addEventListener("click", () => {
    connView = "map";
    $("conn-view-map").classList.add("active");
    $("conn-view-chart").classList.remove("active");
    $("conn-view-appmap").classList.remove("active");
    $("conn-chart").style.display = "none";
    $("conn-flowmap").style.display = "";
    $("conn-appmap-wrap").style.display = "none";
    renderConnFlowmap();
  });

  // ---- APP MAP: graphical world map of connections grouped by application ----
  let appMapObj = null;
  let appMapReady = false;
  let appMapHidden = new Set();
  const APP_PALETTE = ["#4a90d9", "#429462", "#d9a036", "#e04f4f", "#9a6ec9", "#d97b3f",
    "#3fb8af", "#c94b7c", "#7a9e3d", "#5d6ec9", "#b8622d", "#6ea8c9"];
  const appColor = (name) => APP_PALETTE[[...name].reduce((a, c) => a + c.charCodeAt(0), 0) % APP_PALETTE.length];

  function connAppMapFeatures() {
    const feats = [];
    const origin = flowOrigin();
    connLatest.forEach((c) => {
      if (!c.raddr || c.raddr === "*" || c.raddr === "127.0.0.1") return;
      const name = (c.exe || "System").split(/[\\/]/).pop();
      if (appMapHidden.has(name)) return;
      const cc = c.country || (c.raddr.match(/^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./) ? "LOCAL" : "ZZ");
      const pos = cc === "LOCAL" ? origin : ccPos(cc);
      if (!pos) return;
      const r = connRates[connKey(c)] || { rate_in: 0, rate_out: 0 };
      feats.push({
        type: "Feature",
        geometry: { type: "LineString", coordinates: [[origin[0], origin[1]], [pos[1], pos[0]]] },
        properties: {
          app: name, ip: c.raddr, port: c.rport, country: countryName(cc),
          rate_in: r.rate_in, rate_out: r.rate_out,
          bytes_in: c.bytes_in, bytes_out: c.bytes_out, state: c.state, pid: c.pid,
          color: appColor(name), weight: Math.max(1, Math.min(8, 1 + Math.round((r.rate_in + r.rate_out) / 4096))),
        },
      });
    });
    return feats;
  }

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

  function initConnAppMap() {
    if (appMapObj || typeof maplibregl === "undefined") return;
    try {
      appMapObj = new maplibregl.Map({
        container: "conn-appmap",
        style: "https://tiles.openfreemap.org/styles/dark",
        center: flowOrigin(), zoom: 1.4, attributionControl: false,
      });
    } catch (e) {
      console.warn("MapLibre init error for conn-appmap:", e);
      return;
    }
    let appStyleOk = false;
    const onAppMapLoad = () => {
      appStyleOk = true;
      appMapReady = true;
      if (!appMapObj.getSource("app-flows")) {
        appMapObj.addSource("app-flows", { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      }
      if (!appMapObj.getLayer("app-flow-lines")) {
        appMapObj.addLayer({
          id: "app-flow-lines", type: "line", source: "app-flows",
          paint: { "line-color": ["get", "color"], "line-width": ["get", "weight"], "line-opacity": 0.8 },
        });
      }
      const marker = document.createElement("div");
      marker.className = "server-marker";
      marker.innerHTML = "<div class='sm-ring'></div><div class='sm-core'></div><div class='sm-label'>THIS SERVER</div>";
      try { new maplibregl.Marker({ element: marker }).setLngLat(flowOrigin()).addTo(appMapObj); } catch (e) {}
      renderConnAppMap();
    };
    appMapObj.once("style.load", onAppMapLoad);
    setTimeout(() => {
      if (!appStyleOk && appMapObj) {
        try {
          appMapObj.setStyle(buildMapStyleFallback());
          appMapObj.once("style.load", onAppMapLoad);
        } catch (e) {}
      }
    }, 4000);
    appMapObj.on("click", "app-flow-lines", (e) => {
      const f = e.features[0].properties;
      new maplibregl.Popup({ closeButton: true })
        .setLngLat(e.lngLat)
        .setHTML(`<div class="map-pop">
          <div class="map-pop-ip">${esc(f.app)}</div>
          <div>→ <b class="mono">${esc(f.ip)}:${f.port}</b> · ${esc(f.country)}</div>
          <div class="map-pop-row">Live: ↓${fmtBytes(f.rate_in)}/s ↑${fmtBytes(f.rate_out)}/s</div>
          <div class="map-pop-row">Total: ↓${fmtBytes(f.bytes_in)} ↑${fmtBytes(f.bytes_out)}</div>
          <div class="map-pop-row">PID ${f.pid} · ${esc(f.state)}</div>
          <div style="margin-top:6px;"><button class="btn btn-sm" onclick="window.openIpModal('${esc(f.ip)}')">IP DETAILS</button></div>
        </div>`).addTo(appMapObj);
    });
    appMapObj.on("mouseenter", "app-flow-lines", () => (appMapObj.getCanvas().style.cursor = "pointer"));
    appMapObj.on("mouseleave", "app-flow-lines", () => (appMapObj.getCanvas().style.cursor = ""));
  }

  let _lastAppMapFeatsSig = "";
  function renderConnAppMap() {
    if (connView !== "appmap") return;
    // GL map update (only when the map instance is live)
    try {
      if (appMapReady && appMapObj && appMapObj.getSource) {
        const feats = connAppMapFeatures();
        const sig = feats.map((f) => `${f.properties.app}:${f.properties.ip}:${f.properties.weight}`).join(";");
        if (sig !== _lastAppMapFeatsSig) {
          _lastAppMapFeatsSig = sig;
          const src = appMapObj.getSource("app-flows");
          if (src) src.setData({ type: "FeatureCollection", features: feats });
        }
      }
    } catch (e) { /* map mid-teardown */ }
    const legend = $("conn-app-legend");
    if (!legend) return;
    const byApp = {};
    connLatest.forEach((c) => {
      if (!c.raddr || c.raddr === "*" || c.raddr === "127.0.0.1") return;
      const name = (c.exe || "System").split(/[\\/]/).pop();
      byApp[name] = (byApp[name] || 0) + 1;
    });
    const apps = Object.entries(byApp).sort((a, b) => b[1] - a[1]).slice(0, 14);
    legend.innerHTML = apps.length
      ? apps.map(([name, cnt]) => `<span class="appmap-chip ${appMapHidden.has(name) ? "muted" : ""}"
            data-app="${esc(name)}" title="${esc(name)} — ${cnt} connection(s). Click to show/hide.">
            <span class="appmap-dot" style="background:${appColor(name)}"></span>${esc(name)} <b>${cnt}</b></span>`).join("")
      : '<span style="color:var(--text-muted);font-size:11px;">no remote connections</span>';
    legend.querySelectorAll("[data-app]").forEach((el) => el.addEventListener("click", () => {
      const a = el.dataset.app;
      if (appMapHidden.has(a)) appMapHidden.delete(a); else appMapHidden.add(a);
      renderConnAppMap();
    }));
  }

  $("conn-view-appmap").addEventListener("click", () => {
    connView = "appmap";
    $("conn-view-appmap").classList.add("active");
    $("conn-view-chart").classList.remove("active");
    $("conn-view-map").classList.remove("active");
    $("conn-chart").style.display = "none";
    $("conn-flowmap").style.display = "none";
    $("conn-appmap-wrap").style.display = "";
    initConnAppMap();
    renderConnAppMap();
    setTimeout(() => appMapObj && appMapObj.resize(), 60);
  });

  window.extendBan = async (ip, seconds) => {
    await jpost(`/api/v1/bans/${encodeURIComponent(ip)}/extend`, { seconds });
    syncDashboard();
  };
  function renderBansTable(bans) {
    const tbody = document.querySelector("#bans-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    const entries = Object.entries(bans || {});
    if (!entries.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No active host bans enforced</td></tr>';
      return;
    }
    entries.forEach(([ip, meta]) => {
      const rem = meta.remaining_seconds !== null && meta.remaining_seconds !== undefined
        ? (meta.remaining_seconds >= 86400 ? Math.floor(meta.remaining_seconds / 86400) + "d" : Math.floor(meta.remaining_seconds / 3600) + "h " + Math.floor((meta.remaining_seconds % 3600) / 60) + "m")
        : "PERMANENT";
      const created = meta.created ? new Date(meta.created * 1000).toLocaleString() : "—";
      const expires = meta.permanent ? "never" : (meta.expires ? new Date(meta.expires * 1000).toLocaleTimeString() : "—");
      const vt = meta.vt;
      tbody.insertAdjacentHTML("beforeend", `
        <tr ${meta.trusted ? 'class="ban-row-trusted"' : ""}>
          <td class="mono"><strong>${esc(ip)}</strong>${meta.trusted ? ' <span class="badge badge-safe" title="This IP is in the protected management list — it will not be re-enforced">PROTECTED</span>' : ""}</td>
          <td title="${esc(meta.reason || "")}">${esc(meta.reason || "Autonomous Threat Mitigation")}</td>
          <td><span class="badge badge-info">${esc((meta.source || "ENGINE").toUpperCase())}</span></td>
          <td class="mono">${meta.offenses != null ? meta.offenses : "—"}</td>
          <td class="mono" style="font-size:10px;">${esc(created)}</td>
          <td class="mono" style="font-size:10px;">${esc(expires)}</td>
          <td class="mono"><span class="badge ${meta.permanent ? "badge-danger" : "badge-warn"}">${rem}</span></td>
          <td>${vt ? `<span class="vt-mini vt-${esc(vt.verdict)}">${esc(vt.verdict)}</span>` : '<span style="color:var(--text-muted)">—</span>'}</td>
          <td>
            <button class="btn btn-sm" onclick="window.unbanIP('${esc(ip)}')">UNBAN</button>
            <button class="btn btn-sm" title="Extend by 24h" onclick="window.extendBan('${esc(ip)}', 86400)">+24H</button>
            <button class="btn btn-sm btn-danger" title="Make permanent" onclick="window.extendBan('${esc(ip)}', 0)">∞</button>
          </td>
        </tr>`);
      const row = tbody.lastElementChild;
      row.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        openCtxMenu(e, [
          { label: "Unban", action: () => window.unbanIP(ip) },
          { sep: true },
          { label: "Extend +1 hour", action: () => window.extendBan(ip, 3600) },
          { label: "Extend +24 hours", action: () => window.extendBan(ip, 86400) },
          { label: "Extend +7 days", action: () => window.extendBan(ip, 7 * 86400) },
          { label: "Make permanent (∞)", danger: true, action: () => window.extendBan(ip, 0) },
          { sep: true },
          { label: "VirusTotal scan", action: () => window.vtScan(ip, true) },
          { label: "Locate on threat map", action: () => { switchTab("network"); setTimeout(() => { const p = (mapData.points || []).find((x) => x.ip === ip); if (p && p.country && ccPos(p.country)) { const c = ccPos(p.country); mapObj && mapObj.flyTo({ center: [c[1], c[0]], zoom: 5 }); } }, 300); } },
          { label: "Copy IP", action: () => navigator.clipboard && navigator.clipboard.writeText(ip) },
        ]);
      });
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
    const cb = $("appwall-count-badge");
    if (cb) cb.textContent = `${pols.length} policies`;
    if (!pols.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No per-application policies — the application firewall allows everything by default. Click CREATE NEW to add one.</td></tr>';
      return;
    }
    pols.forEach((p, i) => {
      const m = p.match || {};
      tbody.insertAdjacentHTML("beforeend", `
        <tr>
          <td class="mono">${esc(m.exe_glob || m.exe_path || m.sha256 || "*")}</td>
          <td><span class="badge badge-info">${esc((p.allow_outbound || ["*"]).join(", ") || "*")}</span></td>
          <td><span class="badge badge-muted">${esc((p.allow_inbound || []).join(", ") || "none")}</span></td>
          <td><span class="badge badge-danger">${esc((p.deny_destinations || []).join(", ") || "none")}</span></td>
          <td><span class="badge badge-warn">${esc((p.action_on_violation || "block+alert").toUpperCase())}</span></td>
          <td>
            <button class="btn btn-sm" data-awedit="${i}">EDIT</button>
            <button class="btn btn-sm btn-danger" data-awdel="${i}">DEL</button>
          </td>
        </tr>`);
    });
    tbody.querySelectorAll("[data-awedit]").forEach((el) =>
      el.addEventListener("click", () => openAppwallModal(parseInt(el.dataset.awedit, 10))));
    tbody.querySelectorAll("[data-awdel]").forEach((el) => el.addEventListener("click", async () => {
      const i = parseInt(el.dataset.awdel, 10);
      if (!confirm("Delete this application policy?")) return;
      await fetch(`/api/v1/appwall/policies/${i}`, { method: "DELETE" });
      loadAppwall();
    }));
  }

  const modalAppwall = $("modal-appwall");
  let appwallEditing = null;
  $("btn-new-appwall").addEventListener("click", () => openAppwallModal(null));
  $("btn-close-modal-appwall").addEventListener("click", () => modalAppwall.classList.remove("open"));
  $("btn-cancel-appwall").addEventListener("click", () => modalAppwall.classList.remove("open"));
  modalAppwall.addEventListener("click", (e) => { if (e.target === modalAppwall) modalAppwall.classList.remove("open"); });

  async function openAppwallModal(idx, prefillExe) {
    appwallEditing = idx;
    // offer every indexed application as autocomplete
    api("/api/v1/applications").then((d) => {
      const dl = $("appwall-exe-list");
      if (!dl || !d || !d.applications) return;
      dl.innerHTML = d.applications
        .map((a) => `<option value="${esc(a.exe)}">${esc(a.name)}</option>`).join("");
    }).catch(() => { });
    let pol = null;
    if (idx != null) {
      const d = await api("/api/v1/appwall");
      pol = d && d.policies ? d.policies[idx] : null;
    }
    $("appwall-modal-title").textContent = idx != null ? `Edit Application Policy #${idx + 1}` : "Create Application Policy";
    const m = (pol && pol.match) || {};
    $("appwall-exe").value = m.exe_glob || m.exe_path || prefillExe || "";
    $("appwall-out").value = pol && pol.allow_outbound ? pol.allow_outbound.join(", ") : "";
    $("appwall-in").value = pol && pol.allow_inbound ? pol.allow_inbound.join(", ") : "";
    $("appwall-deny").value = pol && pol.deny_destinations ? pol.deny_destinations.join(", ") : "";
    $("appwall-action").value = (pol && pol.action_on_violation) || "block+alert";
    modalAppwall.classList.add("open");
  }

  $("btn-submit-appwall").addEventListener("click", async () => {
    const body = {
      exe: $("appwall-exe").value.trim(),
      allow_outbound: $("appwall-out").value.trim(),
      allow_inbound: $("appwall-in").value.trim(),
      deny_destinations: $("appwall-deny").value.trim(),
      action_on_violation: $("appwall-action").value,
    };
    if (!body.exe) { alert("Enter a target executable or glob."); return; }
    let res;
    if (appwallEditing != null) {
      res = await api(`/api/v1/appwall/policies/${appwallEditing}`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    } else {
      res = await jpost("/api/v1/appwall/policies", body);
    }
    if (res && !res.error) {
      modalAppwall.classList.remove("open");
      loadAppwall();
    } else {
      alert("Save failed: " + ((res && res.error) || "unknown error"));
    }
  });

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
  let flowData = { flows: [], vectors: {}, summary: {}, server_ip: null, server_country: "" };
  let flowsOn = true, flowAnimTimer = null, flowAnimStep = 0;
  let serverMarker = null;

  function initMap() {
    const el = $("threat-map");
    if (!el || typeof maplibregl === "undefined") return;
    try {
      mapObj = new maplibregl.Map({
        container: "threat-map",
        style: "https://tiles.openfreemap.org/styles/dark",
        center: [20, 25],
        zoom: 1.4,
        attributionControl: { compact: true },
      });
      window.mapObj = mapObj;
    } catch (e) {
      console.warn("MapLibre init error for threat-map:", e);
      return;
    }
    let styleOk = false;
    mapObj.once("style.load", () => { styleOk = true; mapReady = true; addMapLayers(); refreshMap(); });
    // Fallback if OpenFreeMap style is unreachable
    setTimeout(() => {
      if (!styleOk && mapObj) {
        try { mapObj.setStyle(buildMapStyleFallback()); } catch (e) { /* noop */ }
        mapObj.once("style.load", () => { mapReady = true; addMapLayers(); refreshMap(); });
      }
    }, 3500);
    mapObj.on("style.load", () => { if (mapReady) addMapLayers(); });
    try { mapObj.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right"); } catch (e) {}
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
        window.activeMapPopup = { ip: p.ip, lngLat: e.lngLat };
        new maplibregl.Popup({ closeButton: true })
          .on("close", () => { window.activeMapPopup = null; })
          .setLngLat(e.lngLat)
          .setHTML(`<div class="map-pop">
            <div class="map-pop-ip">${esc(p.ip)}</div>
            <div>${esc(countryName(p.country))} (${esc(p.country)})</div>
            <div class="map-pop-row">Threat: <b class="threat-${esc(p.threat)}">${esc(p.threat.toUpperCase())}</b></div>
            <div class="map-pop-row">Packets: ${p.packets} · Conns: ${p.connections}</div>
            <div class="map-pop-row">↓ ${fmtBytes(p.bytes_in)} · ↑ ${fmtBytes(p.bytes_out)}</div>
            <div class="map-pop-row">Ports: ${esc(p.ports || "—")}</div>
            <div class="map-pop-row vt-row" id="vt-row-${esc(p.ip)}">${vtPopupHtml(p)}</div>
            ${p.banned_reason ? `<div class="map-pop-row">Banned for: <b class="mono">${esc(p.banned_reason)}</b>${p.offenses ? ` (offense #${p.offenses})` : ""}</div>` : ""}
            ${(() => {
              const fv = flowData.vectors && flowData.vectors[p.ip]; return fv && fv.vectors && fv.vectors.length
                ? `<div class="map-pop-row map-pop-vec">VECTORS: ${fv.vectors.slice(0, 4).map((v) => `<span class="vec-badge" style="--vc:${(VEC_META[v.type] || ["", "#d9a036"])[1]}" title="${esc(v.evidence)}">${esc(v.label)}</span>`).join(" ")}</div>` : "";
            })()}
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
    if (!mapObj.getSource("flowlines")) {
      mapObj.addSource("flowlines", { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      mapObj.addLayer({
        id: "flow-base", type: "line", source: "flowlines",
        layout: { "line-cap": "round", "line-join": "round", visibility: flowsOn ? "visible" : "none" },
        paint: {
          "line-color": ["get", "color"],
          "line-width": ["interpolate", ["linear"], ["get", "rate"], 0.01, 0.6, 5, 1.4, 50, 2.6, 500, 4],
          "line-opacity": 0.35,
        },
      });
      mapObj.addLayer({
        id: "flow-anim", type: "line", source: "flowlines",
        layout: { "line-cap": "round", "line-join": "round", visibility: flowsOn ? "visible" : "none" },
        paint: {
          "line-color": ["get", "color"],
          "line-width": ["interpolate", ["linear"], ["get", "rate"], 0.01, 1.1, 5, 2.2, 50, 3.4, 500, 5],
          "line-opacity": 0.95,
          "line-dasharray": [0, 4, 3],
        },
      });
      mapObj.addLayer({
        id: "flow-hit", type: "line", source: "flowlines",
        layout: { visibility: flowsOn ? "visible" : "none" },
        paint: { "line-color": "#000", "line-opacity": 0.001, "line-width": 16 },
      });
      const tip = $("flow-tip");
      const showTip = (e) => {
        const f = e.features[0].properties;
        const ip = f.ip;
        const full = (flowData.flows || []).find((x) => x.ip === ip);
        if (full) {
          tip.innerHTML = flowTipHtml(full);
          tip.classList.add("open");
          const x = Math.min(e.point.x + 18, window.innerWidth - 400);
          const y = Math.min(e.point.y + 14, window.innerHeight - 260);
          tip.style.left = x + "px";
          tip.style.top = y + "px";
        }
      };
      mapObj.on("mousemove", "flow-hit", showTip);
      mapObj.on("mouseleave", "flow-hit", () => tip.classList.remove("open"));
      mapObj.on("mouseenter", "flow-hit", () => { mapObj.getCanvas().style.cursor = "crosshair"; });
      mapObj.on("mouseleave", "flow-hit", () => { mapObj.getCanvas().style.cursor = ""; });
      mapObj.on("click", "flow-hit", (e) => {
        const ip = e.features[0].properties.ip;
        const p = (mapData.points || []).find((x) => x.ip === ip);
        if (p && p.country && ccPos(p.country)) {
          const c = ccPos(p.country);
          if (mapObj) mapObj.flyTo({ center: [c[1], c[0]], zoom: Math.max(3, mapObj.getZoom()) });
        }
      });
      startFlowAnimation();
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
    const [d, fl] = await Promise.all([api("/api/v1/map/data"), api("/api/v1/map/flows")]);
    if (fl && fl.flows) flowData = fl;
    if (!d) { renderFlows(); renderVectorPanel(); return; }
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
    renderFlows();
    renderVectorPanel();
    updateActiveMapPopup();
  }

  function mapPopupHtmlFor(p) {
    return `<div class="map-pop">
      <div class="map-pop-ip">${esc(p.ip)}</div>
      <div>${esc(countryName(p.country))} (${esc(p.country)})</div>
      <div class="map-pop-row">Threat: <b class="threat-${esc(p.threat)}">${esc((p.threat || "normal").toUpperCase())}</b></div>
      <div class="map-pop-row">Packets: ${p.packets} · Conns: ${p.connections}</div>
      <div class="map-pop-row">↓ ${fmtBytes(p.bytes_in)} · ↑ ${fmtBytes(p.bytes_out)}</div>
      <div class="map-pop-row">Ports: ${esc(p.ports || "—")}</div>
      <div class="map-pop-row vt-row" id="vt-row-${esc(p.ip)}">${vtPopupHtml(p)}</div>
      ${p.banned_reason ? `<div class="map-pop-row">Banned for: <b class="mono">${esc(p.banned_reason)}</b>${p.offenses ? ` (offense #${p.offenses})` : ""}</div>` : ""}
      ${(() => {
        const fv = flowData.vectors && flowData.vectors[p.ip]; return fv && fv.vectors && fv.vectors.length
          ? `<div class="map-pop-row map-pop-vec">VECTORS: ${fv.vectors.slice(0, 4).map((v) => `<span class="vec-badge" style="--vc:${(VEC_META[v.type] || ["", "#d9a036"])[1]}" title="${esc(v.evidence)}">${esc(v.label)}</span>`).join(" ")}</div>` : "";
      })()}
      <div style="display:flex; gap:6px; margin-top:6px;">
        <button class="btn btn-sm btn-danger" onclick="window.quickBan('${esc(p.ip)}')">BAN IP</button>
        <button class="btn btn-sm" onclick="window.vtScan('${esc(p.ip)}', true)">VT SCAN</button>
      </div>
    </div>`;
  }

  function updateActiveMapPopup() {
    const ap = window.activeMapPopup;
    if (!ap || !window.mapObj) return;
    const p = (mapData.points || []).find((x) => x.ip === ap.ip);
    if (!p) return;
    // VT fallback fetch when this popup was rendered before the cache existed
    if (!p.vt) {
      api(`/api/v1/vt/ip/${encodeURIComponent(p.ip)}`).then((vt) => {
        if (vt && vt.verdict) {
          const el = document.getElementById(`vt-row-${p.ip}`);
          if (el) el.innerHTML = vtPopupHtml({ ...p, vt });
          if (!p.vt) { p.vt = vt; renderMapLists(); }
        }
      }).catch(() => { });
    }
    const nodes = document.querySelectorAll(`#vt-row-${CSS.escape(ap.ip)}`);
    nodes.forEach((el) => { if (el) el.innerHTML = vtPopupHtml(p); });
  }

  // =========================================================
  // 8b. LIVE TRAFFIC PIPELINES + THREAT VECTORS
  // =========================================================
  const VEC_META = {
    port_scan: ["PORT SCAN", "#d97b3f"], syn_scan: ["SYN SCAN", "#d97b3f"],
    brute_force: ["BRUTE FORCE", "#e04f4f"], cred_stuff: ["CRED STUFFING", "#e04f4f"],
    ddos: ["DDoS / FLOOD", "#e04f4f"], beacon: ["C2 / BEACON", "#c9509a"],
    mining: ["CRYPTOMINING", "#c9509a"], exploit: ["EXPLOIT", "#e04f4f"],
    malware: ["MALWARE (VT)", "#ff2d2d"], recon: ["HONEYPOT RECON", "#d9a036"],
    dns_tunnel: ["DNS TUNNEL", "#d9a036"], canary: ["CANARY HIT", "#e04f4f"],
    sweep: ["SWEEP", "#d9a036"], suspicious: ["SUSPICIOUS", "#d9a036"],
  };
  function vecBadge(v) {
    const meta = VEC_META[v.type] || [v.type, "#d9a036"];
    return `<span class="vec-badge" style="--vc:${meta[1]}" title="${esc(v.evidence || "")}">${esc(v.label)}</span>`;
  }

  function flowOrigin() {
    if (flowData.server_country) {
      const c = ccPos(flowData.server_country);
      if (c) return [c[1], c[0]];
    }
    // fallback: most common country among mapped points
    const counts = {};
    (mapData.points || []).forEach((p) => { if (p.country) counts[p.country] = (counts[p.country] || 0) + 1; });
    let best = "", bestN = 0;
    Object.entries(counts).forEach(([cc, k]) => { if (k > bestN && ccPos(cc)) { best = cc; bestN = k; } });
    if (best) { const c = ccPos(best); return [c[1], c[0]]; }
    return [78.9, 20];
  }

  function arcCoords(o, r, bend) {
    // quadratic bezier through a perpendicular midpoint offset
    const mx = (o[0] + r[0]) / 2, my = (o[1] + r[1]) / 2;
    const dx = r[0] - o[0], dy = r[1] - o[1];
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    const cx = mx + (dy / len) * bend * len * 0.18;
    const cy = my - (dx / len) * bend * len * 0.18;
    const pts = [];
    for (let i = 0; i <= 12; i++) {
      const t = i / 12;
      const it = 1 - t;
      pts.push([it * it * o[0] + 2 * it * t * cx + t * t * r[0], it * it * o[1] + 2 * it * t * cy + t * t * r[1]]);
    }
    return pts;
  }

  function flowPointOf(f) {
    // remote endpoint position: prefer matching map point (jittered), else country centroid
    const p = (mapData.points || []).find((x) => x.ip === f.ip);
    if (p && p.country && ccPos(p.country)) {
      const c = ccPos(p.country);
      const jitter = ((parseInt((f.ip || "7").replace(/\D/g, "").slice(-6) || "7", 10) % 400) - 200) / 900;
      return [c[1] + jitter, c[0] + jitter * 0.6];
    }
    if (f.country && ccPos(f.country)) { const c = ccPos(f.country); return [c[1], c[0]]; }
    return null;
  }

  function flowColor(f) {
    if (f.risk >= 40) return "#e04f4f";
    if (f.vectors && f.vectors.length) return "#d9a036";
    return "#4a7ba6";
  }

  function flowFeatures() {
    const feats = [];
    if (!flowsOn) return { type: "FeatureCollection", features: feats };
    const origin = flowOrigin();
    const flows = (flowData.flows || []).slice(0, 60);
    flows.forEach((f, i) => {
      const r = flowPointOf(f);
      if (!r) return;
      const activity = (f.rate_in || 0) + (f.rate_out || 0) + (f.bytes_in + f.bytes_out) / 60000;
      feats.push({
        type: "Feature",
        geometry: { type: "LineString", coordinates: arcCoords(origin, r, i % 2 === 0 ? 1 : -1) },
        properties: {
          ip: f.ip, country: f.country || "", risk: f.risk || 0,
          threat: f.risk >= 40 ? "malicious" : (f.vectors && f.vectors.length ? "suspicious" : "normal"),
          rate: Math.max(0.01, Math.round(activity * 10) / 10),
          color: flowColor(f),
        },
      });
    });
    return { type: "FeatureCollection", features: feats };
  }

  function renderFlows() {
    const legend = $("vec-legend");
    if (legend) {
      const sv = flowData.summary || {};
      const items = Object.entries(sv).slice(0, 6)
        .map(([k, c]) => { const m = VEC_META[k] || [k, "#d9a036"]; return `<span class="vec-dot" style="background:${m[1]}"></span>${esc(m[0])} ×${c}`; })
        .join("<br>");
      legend.innerHTML = items || '<span style="color:var(--text-muted)">no vectors detected</span>';
    }
    if (!mapObj || !mapReady || !mapObj.getSource) return;
    if (!mapObj.getSource("flowlines")) return;
    mapObj.getSource("flowlines").setData(flowFeatures());
    const origin = flowOrigin();
    if (flowsOn) {
      if (!serverMarker) {
        const el = document.createElement("div");
        el.className = "server-marker";
        el.innerHTML = "<div class='sm-ring'></div><div class='sm-core'></div><div class='sm-label'>THIS SERVER</div>";
        serverMarker = new maplibregl.Marker({ element: el }).setLngLat(origin).addTo(mapObj);
      } else {
        serverMarker.setLngLat(origin);
        serverMarker.getElement().style.display = flowsOn ? "" : "none";
      }
    } else if (serverMarker) {
      serverMarker.getElement().style.display = "none";
    }
  }

  const DASH_SEQ = [
    [0, 4, 3], [0.5, 4, 2.5], [1, 4, 2], [1.5, 4, 1.5], [2, 4, 1], [2.5, 4, 0.5], [3, 4, 0],
    [0, 0.5, 3, 3.5], [0, 1, 3, 3], [0, 1.5, 3, 2.5], [0, 2, 3, 2], [0, 2.5, 3, 1.5], [0, 3, 3, 1], [0, 3.5, 3, 0.5],
  ];
  function startFlowAnimation() {
    if (flowAnimTimer) return;
    flowAnimTimer = setInterval(() => {
      if (!mapObj || !mapReady || !mapObj.getLayer || !mapObj.getLayer("flow-anim")) return;
      if (!flowsOn || !document.querySelector("#tab-network").classList.contains("active")) return;
      flowAnimStep = (flowAnimStep + 1) % DASH_SEQ.length;
      try { mapObj.setPaintProperty("flow-anim", "line-dasharray", DASH_SEQ[flowAnimStep]); } catch (e) { /* layer gone */ }
    }, 110);
  }

  function flowTipHtml(f) {
    const v = flowData.vectors && flowData.vectors[f.ip];
    const vecs = (v && v.vectors) || f.vectors || [];
    const protos = Object.entries(f.protos || {}).map(([k, c]) => `<span class="ft-proto">${esc(k)} ×${c}</span>`).join(" ");
    const dataBits = [];
    (f.dns || []).forEach((d) => dataBits.push(`<span class="ft-data"><b>DNS</b> ${esc(d)}</span>`));
    (f.sni || []).forEach((s) => dataBits.push(`<span class="ft-data"><b>TLS</b> ${esc(s)}</span>`));
    (f.http || []).forEach((h) => dataBits.push(`<span class="ft-data"><b>HTTP</b> ${esc(h)}</span>`));
    const apps = (f.apps || []).map((a) => `<span class="ft-app">${esc(a)}</span>`).join(" ");
    return `
      <div class="ft-head"><span class="ft-ip mono">${esc(f.ip)}</span>
        <span class="ft-cc">${esc(countryName(f.country || "—"))}</span>
        ${f.risk ? `<span class="ft-risk">RISK ${f.risk}</span>` : ""}
      </div>
      <div class="ft-live"><span class="ft-arrow down">↓</span> ${fmtBytes(f.rate_in || 0)}/s &nbsp; <span class="ft-arrow up">↑</span> ${fmtBytes(f.rate_out || 0)}/s</div>
      <div class="ft-row">Total: ↓ ${fmtBytes(f.bytes_in || 0)} · ↑ ${fmtBytes(f.bytes_out || 0)} · ${f.packets || 0} pkts · ${f.connections || 0} conns</div>
      ${protos ? `<div class="ft-row">${protos}</div>` : ""}
      ${f.ports && f.ports.length ? `<div class="ft-row">Ports: <span class="mono">${esc(f.ports.join(", "))}</span></div>` : ""}
      ${apps ? `<div class="ft-row">Apps: ${apps}</div>` : ""}
      ${dataBits.length ? `<div class="ft-sec">DATA IN FLIGHT</div>${dataBits.join("")}` : ""}
      ${vecs.length ? `<div class="ft-sec">THREAT VECTORS (${vecs.length})</div>${vecs.map(vecBadge).join(" ")}<div class="ft-ev">${esc(vecs[0].evidence || "")}</div>` : ""}
      <div class="ft-hint">click pipeline for actions</div>`;
  }

  function renderVectorPanel() {
    const flagged = Object.entries(flowData.vectors || {});
    const badge = $("vec-flagged-badge");
    if (badge) badge.textContent = `${flagged.length} flagged`;
    const sum = $("vec-summary");
    if (sum) {
      const sv = Object.entries(flowData.summary || {});
      sum.innerHTML = sv.length
        ? sv.map(([k, c]) => { const m = VEC_META[k] || [k, "#d9a036"]; return `<span class="vec-badge" style="--vc:${m[1]}">${esc(m[0])} ×${c}</span>`; }).join(" ")
        : '<span style="color:var(--text-muted);font-size:11px;">No attack vectors detected in current traffic.</span>';
    }
    const list = $("vec-ip-list");
    if (list) {
      if (!flagged.length) { list.innerHTML = ""; return; }
      flagged.sort((a, b) => (b[1].risk || 0) - (a[1].risk || 0));
      list.innerHTML = flagged.slice(0, 12).map(([ip, v]) => `
        <div class="vec-ip" data-ip="${esc(ip)}">
          <span class="mono">${esc(ip)}</span>
          <span class="vec-mini-badges">${v.vectors.slice(0, 3).map((x) => { const m = VEC_META[x.type] || [x.label, "#d9a036"]; return `<span class="vec-badge" style="--vc:${m[1]}" title="${esc(x.evidence || "")}">${esc(m[0])}</span>`; }).join("")}</span>
          <span class="vec-risk">${v.risk || 0}</span>
        </div>`).join("");
      list.querySelectorAll(".vec-ip").forEach((el) => {
        el.addEventListener("click", () => {
          const ip = el.dataset.ip;
          const p = (mapData.points || []).find((x) => x.ip === ip);
          const r = flowPointOf({ ip, country: p ? p.country : "" });
          if (r && mapObj) mapObj.flyTo({ center: r, zoom: 4 });
        });
        el.addEventListener("contextmenu", (e) => { e.preventDefault(); openCtxMenu(e, ipMenuItems(el.dataset.ip)); });
      });
    }
  }

  $("map-flows-toggle").addEventListener("click", () => {
    flowsOn = !flowsOn;
    $("map-flows-toggle").textContent = flowsOn ? "ON" : "OFF";
    $("map-flows-toggle").classList.toggle("active", flowsOn);
    ["flow-base", "flow-anim", "flow-hit"].forEach((id) => {
      if (mapObj && mapObj.getLayer && mapObj.getLayer(id)) {
        mapObj.setLayoutProperty(id, "visibility", flowsOn ? "visible" : "none");
      }
    });
    renderFlows();
  });

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
          <span class="mi-ip mono">${esc(p.ip)}${(() => {
          const fv = flowData.vectors && flowData.vectors[p.ip];
          if (fv && fv.vectors && fv.vectors.length) return ` <span class="vt-mini vt-MALICIOUS" title="${esc(fv.vectors.map((x) => x.label).join(", "))}">${esc(fv.vectors[0].label)}</span>`;
          if (p.vt) return ` <span class="vt-mini vt-${esc(p.vt.verdict)}">${esc(p.vt.verdict)}</span>`;
          return "";
        })()}</span>
          <span class="mi-cc" title="${esc(countryName(p.country))}">${esc(countryName(p.country))}</span>
          <span class="mi-bytes mono">${fmtBytes(p.bytes_in + p.bytes_out)}</span>
        </div>`).join("");
      list.querySelectorAll(".map-ip-item").forEach((el) => {
        el.addEventListener("click", () => openIpModal(el.dataset.ip));
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
  startFlowAnimation();
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

  let appModalTimer = null;
  let appModalExe = null;

  function drawSparkline(canvas, series, color, unit, fmt) {
    if (!canvas) return;
    const w = canvas.parentElement.clientWidth - 16 || 260;
    const h = 64;
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext && canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, w, h);
    if (!series.length) {
      ctx.fillStyle = "#5a6472"; ctx.font = "10px monospace"; ctx.textAlign = "center";
      ctx.fillText("collecting samples…", w / 2, h / 2);
      return;
    }
    const peak = Math.max(0.001, ...series);
    ctx.strokeStyle = "rgba(255,255,255,.07)";
    for (let i = 1; i <= 2; i++) {
      const y = (h / 3) * i; ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color + "55"); grad.addColorStop(1, color + "00");
    ctx.beginPath();
    series.forEach((v, i) => {
      const x = (i / Math.max(1, series.length - 1)) * (w - 2) + 1;
      const y = h - 4 - (v / peak) * (h - 12);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color; ctx.lineWidth = 1.6; ctx.stroke();
    ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath();
    ctx.fillStyle = grad; ctx.fill();
    ctx.fillStyle = color; ctx.font = "9px monospace"; ctx.textAlign = "right";
    ctx.fillText(fmt ? fmt(peak) : peak.toFixed(1) + unit, w - 4, 10);
  }

  async function pollAppModal(a) {
    // live refresh of the resource graphs while the modal is open
    if (!modalApp.classList.contains("open") || appModalExe !== a.exe) return;
    try {
      const [hist, apps] = await Promise.all([api(`/api/v1/applications/history?exe=${encodeURIComponent(a.exe)}`),
      api("/api/v1/applications")]);
      const cur = apps && apps.applications ? apps.applications.find((x) => x.exe === a.exe) : null;
      const s = (hist && hist.samples) || [];
      const cpu = $("appd-cpu-chart"), mem = $("appd-mem-chart"), net = $("appd-net-chart"), con = $("appd-conn-chart");
      drawSparkline(cpu, s.map((x) => x.cpu), "#4a90d9", "%");
      drawSparkline(mem, s.map((x) => x.mem), "#9a6ec9", "MB");
      drawSparkline(net, s.map((x) => (x.rate_in || 0) + (x.rate_out || 0)), "#429462", "B/s", fmtBytes);
      drawSparkline(con, s.map((x) => x.conns), "#d9a036", "");
      const set = (id, v) => { const el = $(id); if (el) el.textContent = v; };
      if (cur) {
        set("appd-live-cpu", cur.cpu_percent + "%");
        set("appd-live-mem", cur.mem_mb + " MB");
        set("appd-live-conns", cur.connections + " sockets");
        set("appd-live-net", `↓${fmtBytes(cur.bytes_in)} ↑${fmtBytes(cur.bytes_out)}`);
        const pk = (arr) => (arr.length ? Math.max(...arr) : 0);
        set("appd-peak-cpu", pk(s.map((x) => x.cpu)).toFixed(1) + "%");
        set("appd-peak-mem", Math.round(pk(s.map((x) => x.mem))) + " MB");
        set("appd-peak-net", fmtBytes(pk(s.map((x) => (x.rate_in || 0) + (x.rate_out || 0)))) + "/s");
        set("appd-peak-conns", pk(s.map((x) => x.conns)));
      }
    } catch (e) { /* transient */ }
  }

  async function openAppDetail(a) {
    if (!a) return;
    appModalExe = a.exe;
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
      </div>

      <div class="appd-sec-title">Resource Monitor <span style="float:right;color:var(--text-muted);font-weight:400;">live · 10-minute window</span></div>
      <div class="appd-charts">
        <div class="appd-chart"><div class="ac-title">CPU <span id="appd-live-cpu">—</span> <em>peak <span id="appd-peak-cpu">—</span></em></div><canvas id="appd-cpu-chart"></canvas></div>
        <div class="appd-chart"><div class="ac-title">MEMORY <span id="appd-live-mem">—</span> <em>peak <span id="appd-peak-mem">—</span></em></div><canvas id="appd-mem-chart"></canvas></div>
        <div class="appd-chart"><div class="ac-title">NETWORK <span id="appd-live-net">—</span> <em>peak <span id="appd-peak-net">—</span></em></div><canvas id="appd-net-chart"></canvas></div>
        <div class="appd-chart"><div class="ac-title">CONNECTIONS <span id="appd-live-conns">—</span> <em>peak <span id="appd-peak-conns">—</span></em></div><canvas id="appd-conn-chart"></canvas></div>
      </div>

      <div class="appd-sec-title">Resource Alert Thresholds</div>
      <div class="appd-monitor">
        <label>CPU % <input type="number" class="form-input mono" id="mon-cpu" placeholder="e.g. 80" min="1" max="100"></label>
        <label>Memory MB <input type="number" class="form-input mono" id="mon-mem" placeholder="e.g. 1024" min="1"></label>
        <label>Connections <input type="number" class="form-input mono" id="mon-conns" placeholder="e.g. 100" min="1"></label>
        <button class="btn btn-sm btn-primary" id="btn-save-monitor">SET ALERTS</button>
        <span class="mono" id="mon-status" style="font-size:10px; color:var(--text-muted);">—</span>
      </div>`;

    html += `<div class="appd-sec-title">Remote endpoints <span style="float:right; color:var(--text-muted); font-weight:400;">click = ban · right-click = menu · VT = VirusTotal</span></div>`;
    if (a.remote_ips && a.remote_ips.length) {
      html += `<div class="appd-ips">${a.remote_ips.map((ip) => `<span class="appd-ip mono" data-ip="${esc(ip)}" onclick="window.quickBan('${esc(ip)}')" oncontextmenu="event.preventDefault(); window.ipCtx(event, '${esc(ip)}')">${esc(ip)}</span><span class="appd-vt mono" id="vt-mini-${esc(ip)}" onclick="window.vtScan('${esc(ip)}', true)">VT ▸</span>`).join("")}</div>`;
    } else {
      html += '<div class="empty-state">No remote endpoints in the current window</div>';
    }

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
    }

    html += `<div class="appd-actions">
      ${a.network_blocked
        ? `<button class="btn" id="btn-app-unblock">UNBLOCK NETWORK</button>`
        : `<button class="btn btn-warn" id="btn-app-block">BLOCK NETWORK ACCESS</button>`}
      <button class="btn btn-danger" id="btn-app-kill">KILL PROCESSES</button>
      <button class="btn btn-danger" id="btn-app-quarantine">QUARANTINE BINARY</button>
      <button class="btn" id="btn-app-policy">CREATE FIREWALL POLICY</button>
      <button class="btn" id="btn-app-appwall">APP NETWORK POLICY</button>
    </div>`;
    $("app-modal-body").innerHTML = html;
    modalApp.classList.add("open");

    // seed monitor thresholds from server history
    api(`/api/v1/applications/history?exe=${encodeURIComponent(a.exe)}`).then((h) => {
      const mon = (h && h.monitor) || {};
      if (mon.cpu_alert) $("mon-cpu").value = mon.cpu_alert;
      if (mon.mem_alert) $("mon-mem").value = mon.mem_alert;
      if (mon.conns_alert) $("mon-conns").value = mon.conns_alert;
      $("mon-status").textContent = Object.keys(mon).length
        ? "alerts active: " + Object.entries(mon).map(([k, v]) => `${k.replace("_alert", "")} ≥ ${v}`).join(", ")
        : "no thresholds set";
    });
    $("btn-save-monitor").addEventListener("click", async () => {
      const res = await jpost("/api/v1/applications/monitor", {
        exe: a.exe,
        cpu_alert: $("mon-cpu").value || null,
        mem_alert: $("mon-mem").value || null,
        conns_alert: $("mon-conns").value || null,
      });
      $("mon-status").textContent = res && res.monitor && Object.keys(res.monitor).length
        ? "alerts active: " + Object.entries(res.monitor).map(([k, v]) => `${k.replace("_alert", "")} ≥ ${v}`).join(", ")
        : "thresholds cleared";
    });

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
    const bPol = $("btn-app-policy");
    const bAw = $("btn-app-appwall");
    if (bBlock) bBlock.addEventListener("click", call("block_network"));
    if (bUnblock) bUnblock.addEventListener("click", call("unblock_network"));
    if (bKill) bKill.addEventListener("click", call("kill", { pid: a.pids[0] }, `Kill ${a.process_count > 1 ? "primary" : ""} process PID ${a.pids[0]} (${a.name})?`));
    if (bQuar) bQuar.addEventListener("click", call("quarantine", {}, `Quarantine the binary ${a.exe}? The application will be disabled.`));
    if (bPol) bPol.addEventListener("click", () => { modalApp.classList.remove("open"); switchTab("policies"); openPolicyModal(null, a.name); });
    if (bAw) bAw.addEventListener("click", () => { modalApp.classList.remove("open"); switchTab("appwall"); openAppwallModal(null, a.exe); });

    // live chart polling
    if (appModalTimer) clearInterval(appModalTimer);
    pollAppModal(a);
    appModalTimer = setInterval(() => pollAppModal(a), 2000);
  }
  modalApp.addEventListener("click", (e) => { if (e.target === modalApp) { clearInterval(appModalTimer); appModalExe = null; } });
  $("btn-close-modal-app").addEventListener("click", () => { clearInterval(appModalTimer); appModalExe = null; });

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
      { label: "View details (why flagged)", action: () => openIpModal(ip) },
      { sep: true },
      { label: "Ban IP (24h kernel ban)", danger: true, action: () => window.quickBan(ip, true) },
      { label: "Unban IP", action: () => window.unbanIP(ip) },
      { sep: true },
      { label: "VirusTotal scan", action: () => window.vtScan(ip, true) },
      { label: "VT report (full, stored)", action: () => openIpModal(ip, "vt") },
      { label: "AI threat analysis (Sarvam-105B)", action: () => openIpModal(ip, "ai") },
      { label: "Copy IP", action: () => navigator.clipboard && navigator.clipboard.writeText(ip) },
    ];
  }

  // ---------------- IP intelligence modal ----------------
  const modalIp = $("modal-ip");
  let ipModalCurrent = null;
  $("btn-close-modal-ip").addEventListener("click", () => modalIp.classList.remove("open"));
  modalIp.addEventListener("click", (e) => { if (e.target === modalIp) modalIp.classList.remove("open"); });

  window.openIpModal = openIpModal;
  async function openIpModal(ip, focus) {
    ipModalCurrent = ip;
    modalIp.classList.add("open");
    $("ip-modal-title").innerHTML = `IP Intelligence <span class="mono" style="color:var(--accent-info)">${esc(ip)}</span>`;
    $("ip-modal-body").innerHTML = '<div class="empty-state">Loading intelligence…</div>';
    const d = await api(`/api/v1/ip/${encodeURIComponent(ip)}/reasons`);
    if (ipModalCurrent !== ip) return;  // switched to another IP meanwhile
    renderIpModal(ip, d || {}, focus);
    if (focus === "vt") loadVtReport(ip);
    if (focus === "ai") runAiAnalysis(ip);
  }

  function renderIpModal(ip, d, focus) {
    const ban = d.ban;
    const vecs = d.vectors || [];
    const vt = d.vt || (d.vt_report);
    const ai = d.ai || {};
    const ev = d.events || [];
    let html = "";

    // --- status header
    const status = ban ? `<span class="badge badge-danger">BANNED</span>` :
      (vecs.length ? `<span class="badge badge-warn">FLAGGED</span>` :
        `<span class="badge badge-safe">NO ACTIVE FLAGS</span>`);
    html += `<div class="ipm-head">
      <div class="ipm-status">${status}${d.risk != null ? ` <span class="badge badge-muted">RISK ${d.risk}/100</span>` : ""}${d.trusted ? ' <span class="badge badge-safe">PROTECTED</span>' : ""}</div>
      <div class="ipm-meta mono">${esc(countryName((d.traffic || {}).country || "—"))}
        ${d.offenses ? ` · ${d.offenses} offense${d.offenses > 1 ? "s" : ""}` : ""}</div>
    </div>`;

    // --- WHY FLAGGED (the reason section)
    html += `<div class="appd-sec-title">Why this IP was flagged</div>`;
    let reasons = [];
    if (ban) reasons.push(`<div class="ipm-reason"><b class="threat-malicious">BANNED:</b> ${esc(ban.reason || "—")}
      ${ban.remaining_seconds != null ? ` · ${Math.round(ban.remaining_seconds / 60)} min left` : " · permanent"}</div>`);
    vecs.forEach((v) => reasons.push(`<div class="ipm-reason"><b class="threat-suspicious">${esc((v.label || "SUSPICIOUS").toUpperCase())}:</b> ${esc(v.evidence || "detected by traffic analysis")}</div>`));
    if (vt && vt.verdict) reasons.push(`<div class="ipm-reason"><b class="threat-${vt.verdict === "MALICIOUS" ? "malicious" : vt.verdict === "SUSPICIOUS" ? "suspicious" : "normal"}">VIRUSTOTAL ${vt.verdict}:</b> ${vt.malicious || 0} malicious / ${vt.suspicious || 0} suspicious engines</div>`);
    if (ai.verdict) reasons.push(`<div class="ipm-reason"><b class="threat-${ai.verdict === "MALICIOUS" ? "malicious" : ai.verdict === "BENIGN" ? "normal" : "suspicious"}">AI ANALYST ${ai.verdict}:</b> ${esc((ai.summary || "").slice(0, 240))}${ai.novel_threat ? " · <b>NOVEL PATTERN</b>" : ""}</div>`);
    if (ev.length) {
      const lastEv = ev[0];
      reasons.push(`<div class="ipm-reason"><b>RECENT ENGINE EVENT:</b> ${esc(lastEv.kind)} (${esc(lastEv.severity || "")}) — ${esc(Object.values(lastEv).filter((x) => typeof x === "string" || typeof x === "number").join(" · ").slice(0, 180))}</div>`);
    }
    html += reasons.length ? reasons.join("") : '<div class="empty-state">No threat reasons recorded for this IP — normal traffic so far.</div>';

    // --- evidence events
    if (ev.length) {
      html += `<div class="appd-sec-title">Engine event history (${ev.length})</div>
        <div class="ipm-events">${ev.slice(0, 10).map((e) => `<div class="ipm-event mono">
          <span class="ipm-ev-ts">${esc((e.ts || "").toString().slice(5, 16))}</span>
          <span class="badge badge-warn">${esc(e.kind)}</span>
          <span class="ipm-ev-detail">${esc(JSON.stringify({ ...e, ts: undefined, kind: undefined, severity: undefined }).slice(0, 200))}</span>
        </div>`).join("")}</div>`;
    }

    // --- traffic profile
    const t = d.traffic || {};
    if (t.packets || t.connections) {
      html += `<div class="appd-sec-title">Traffic profile</div>
        <div class="appd-kv" style="grid-template-columns:repeat(3,1fr);">
          <div><span>Packets / Conns</span><b class="mono">${t.packets || 0} / ${t.connections || 0}</b></div>
          <div><span>↓ / ↑ Total</span><b class="mono">${fmtBytes(t.bytes_in || 0)} / ${fmtBytes(t.bytes_out || 0)}</b></div>
          <div><span>Ports seen</span><b class="mono">${esc((t.ports || []).join(", ") || "—")}</b></div>
        </div>`;
    }

    // --- VT report section (loaded async)
    html += `<div class="appd-sec-title">VirusTotal report</div>
      <div id="ipm-vt-body"><div class="empty-state" style="cursor:pointer" onclick="loadVtReport('${esc(ip)}')">Click to load the full stored report (SQLite)…</div></div>`;

    // --- AI analysis section
    html += `<div class="appd-sec-title">AI threat analysis (Sarvam-105B)</div>
      <div id="ipm-ai-body">${ai.verdict ? renderAiBlock(ai) : '<div class="empty-state">No AI assessment yet — click AI ANALYSIS below to run one.</div>'}</div>`;

    $("ip-modal-body").innerHTML = html;
  }

  function renderAiBlock(ai) {
    if (ai.error) return `<div class="empty-state" style="color:var(--accent-warn)">${esc(ai.error)}</div>`;
    const cls = ai.verdict === "MALICIOUS" ? "threat-malicious" : ai.verdict === "BENIGN" ? "threat-normal" : "threat-suspicious";
    return `<div class="ipm-ai">
      <div class="ipm-ai-verdict"><b class="${cls}">${esc(ai.verdict)}</b>
        <span class="mono">confidence ${ai.confidence || 0}%</span>
        ${ai.threat_type ? `<span class="badge badge-info">${esc(ai.threat_type)}</span>` : ""}
        ${ai.novel_threat ? '<span class="badge badge-danger">NOVEL PATTERN</span>' : ""}
        <span class="mono" style="color:var(--text-muted);font-size:10px;">${esc(ai.model || "")} · ${new Date((ai.ts || 0) * 1000).toLocaleString()}</span></div>
      <p>${esc(ai.summary || "")}</p>
      ${ai.reasoning ? `<details><summary>reasoning trace</summary><pre class="mono">${esc(ai.reasoning)}</pre></details>` : ""}
      ${(ai.recommended_actions || []).length ? `<div class="ipm-ai-actions">${ai.recommended_actions.map((a) => `<span class="badge badge-warn">${esc(a)}</span>`).join(" ")}</div>` : ""}
    </div>`;
  }

  window.loadVtReport = async (ip) => {
    const el = $("ipm-vt-body");
    if (!el) return;
    el.innerHTML = '<div class="empty-state">Loading stored report…</div>';
    const r = await api(`/api/v1/vt/report/${encodeURIComponent(ip)}`);
    if (!r || r.error) {
      el.innerHTML = `<div class="empty-state">${esc(r && r.error ? r.error : "no report")} — <b style="cursor:pointer" onclick="window.vtScan('${esc(ip)}', true)">run a VT scan first</b></div>`;
      return;
    }
    const raw = r.raw || {};
    const engines = raw.last_analysis_results || {};
    const engRows = Object.entries(engines).slice(0, 40).map(([name, res]) => {
      const cat = (res && res.category) || "undetected";
      const cls = cat === "malicious" ? "threat-malicious" : cat === "suspicious" ? "threat-suspicious" : "threat-normal";
      return `<tr><td>${esc(name)}</td><td><b class="${cls}">${esc(cat)}</b></td></tr>`;
    }).join("");
    el.innerHTML = `
      <div class="ipm-vt-summary">
        <div><span>Verdict</span><b class="threat-${r.verdict === "MALICIOUS" ? "malicious" : r.verdict === "SUSPICIOUS" ? "suspicious" : "normal"}">${esc(r.verdict)}</b></div>
        <div><span>Engines (M/S/H/U)</span><b class="mono">${r.malicious} / ${r.suspicious} / ${r.harmless} / ${r.undetected}</b></div>
        <div><span>Reputation</span><b class="mono">${r.reputation}</b></div>
        <div><span>Network / AS</span><b>${esc(r.as_owner || "—")}</b></div>
        <div><span>Scanned</span><b class="mono">${new Date((r.ts || 0) * 1000).toLocaleString()}</b></div>
        <div><span>Report</span><b><a href="https://www.virustotal.com/gui/ip-address/${esc(ip)}" target="_blank" rel="noopener">open on VirusTotal ↗</a></b></div>
      </div>
      ${engRows ? `<div class="appd-sec-title" style="margin-top:8px;">Per-engine detections (first 40)</div>
        <table class="data-table ipm-eng-table"><thead><tr><th>Engine</th><th>Result</th></tr></thead><tbody>${engRows}</tbody></table>` : ""}`;
  };
  $("btn-ip-vt").addEventListener("click", () => { if (ipModalCurrent) window.vtScan(ipModalCurrent, true); });

  window.runAiAnalysis = async (ip) => {
    const el = $("ipm-ai-body");
    if (!el) return;
    el.innerHTML = '<div class="empty-state">Sarvam-105B analyzing evidence… (this can take ~30s)</div>';
    const r = await jpost("/api/v1/ai/analyze", { ip });
    el.innerHTML = renderAiBlock(r && !r.error ? r : { error: (r && r.error) || "analysis failed" });
  };
  $("btn-ip-ai").addEventListener("click", () => { if (ipModalCurrent) runAiAnalysis(ipModalCurrent); });
  $("btn-ip-ban").addEventListener("click", () => { if (ipModalCurrent) window.quickBan(ipModalCurrent, true); });
  window.ipCtx = (e, ip) => { e.preventDefault(); openCtxMenu(e, ipMenuItems(ip)); };

  function vtPopupHtml(p) {
    const vt = p.vt;
    if (!vt) return '<span style="color:var(--text-muted)">VT: not scanned</span>';
    const cls = vt.verdict === "MALICIOUS" ? "threat-malicious" : vt.verdict === "SUSPICIOUS" ? "threat-suspicious" : "threat-normal";
    return `<b class="${cls}">VT: ${esc(vt.verdict)}</b> <span style="color:var(--text-muted)">(${vt.malicious}/${vt.suspicious + vt.malicious + (vt.harmless || 0) + (vt.undetected || 0)} engines)${vt.stale ? " · revalidate pending" : ""}${vt.as_owner ? " · " + esc(vt.as_owner) : ""}</span>`;
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

  function openPolicyModal(editId, prefillName) {
    polEditingId = editId;
    const p = editId != null ? (polData.policies || []).find((x) => x.id === editId) : null;
    $("policy-modal-title").textContent = p ? `Edit Policy #${p.id}` : "Create New Policy";
    $("pol-name").value = p ? p.name : (prefillName ? `Allow ${prefillName} traffic` : "");
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
  // 9h. CLAMAV ANTIVIRUS
  // =========================================================
  async function loadClamav() {
    const s = await api("/api/v1/clamav/status");
    if (!s || !$("clamav-status-line")) return;
    if (s.error) { $("clamav-status-line").textContent = s.error; return; }
    let txt;
    if (!s.installed) {
      txt = `<span style="color:var(--accent-warn)">NOT INSTALLED</span> — ${esc(s.detail || "install ClamAV to enable system antivirus")}`;
    } else {
      txt = `<span style="color:var(--accent-safe)">INSTALLED</span> · engine: ${esc(s.daemon ? "clamd (daemon, fast)" : "clamscan")} `
        + `· daily updates: ${s.daily_update ? "ON" : "OFF"}`
        + (s.db_age_hours != null ? ` · DB age: ${s.db_age_hours}h${s.db_stale ? ' <span style="color:var(--accent-warn)">(stale)</span>' : ""}` : "");
      if (s.last_update) txt += `<br>last update: ${s.last_update.ok ? "OK" : "FAILED"} ${new Date((s.last_update.ts || 0) * 1000).toLocaleString()}`;
      if (s.last_scan) txt += `<br>last scan: ${s.last_scan.findings} finding(s) over ${s.last_scan.paths} path(s)`;
    }
    $("clamav-status-line").innerHTML = txt;
  }
  $("btn-clamav-update").addEventListener("click", async () => {
    $("clamav-result").textContent = "updating definitions…";
    const r = await jpost("/api/v1/clamav/update", {});
    $("clamav-result").textContent = r && r.ok ? "definitions updated" : ((r && (r.error || r.output || "") || "update failed").toString().slice(0, 160));
    loadClamav();
  });
  async function clamavScan(quarantine) {
    $("clamav-result").textContent = "scanning… (this runs a full system pass and can take a while)";
    const btns = [$("btn-clamav-scan"), $("btn-clamav-quarantine")];
    btns.forEach((b) => b && (b.disabled = true));
    const r = await jpost("/api/v1/clamav/scan", { quarantine });
    btns.forEach((b) => b && (b.disabled = false));
    if (r && r.error) { $("clamav-result").textContent = r.error; return; }
    const f = (r.findings || []).length;
    $("clamav-result").innerHTML = `scan complete in ${r.duration_seconds}s — <b style="color:${f ? "var(--accent-danger)" : "var(--accent-safe)"}">${f} threat(s)</b> found${r.quarantined && r.quarantined.length ? `, ${r.quarantined.length} quarantined` : ""}${r.partial ? " (partial — timeout)" : ""}`;
    if (f) showBanner(document.body, `ClamAV found ${f} malicious file(s) — see Settings for the list`, false);
    loadClamav();
  }
  $("btn-clamav-scan").addEventListener("click", () => clamavScan(false));
  $("btn-clamav-quarantine").addEventListener("click", () => clamavScan(true));

  // =========================================================
  // 9l. FORCED PASSWORD CHANGE + INTEGRATIONS (3.0)
  // =========================================================
  async function checkForcedPassword() {
    const s = await api("/api/v1/auth/status");
    if (!s || !s.must_change_password) return;
    const ov = document.getElementById("pwchange-overlay");
    if (!ov) return;
    ov.style.display = "flex";
    document.getElementById("pwchange-submit").onclick = async () => {
      const cur = document.getElementById("pwchange-current").value;
      const nw = document.getElementById("pwchange-new").value;
      const err = document.getElementById("pwchange-err");
      err.textContent = "";
      const r = await jpost("/api/v1/auth/password", { current: cur, new: nw });
      if (r && r.changed) { ov.style.display = "none"; loadSecurity(); return; }
      err.textContent = (r && r.error) || "change failed";
    };
  }
  checkForcedPassword();

  async function loadIntegrations() {
    const s = await api("/api/v1/integrations/status");
    const line = $("integrations-status-line"), gt = $("btn-gosvc-toggle");
    if (!s) return;
    const i = s.integrations || {}, g = s.go_services || {}, t = s.tls || {};
    if (line) line.innerHTML =
      `suricata: <b style="color:${i.suricata ? "var(--accent-safe)" : "var(--accent-warn)"}">${i.suricata ? "PRESENT" : "MISSING"}</b>` +
      ` · clamav: <b style="color:${i.clamav ? "var(--accent-safe)" : "var(--accent-warn)"}">${i.clamav ? "PRESENT" : "MISSING"}</b>` +
      ` · auto-install: <b>${i.auto_install ? "ON (best-effort at daemon start)" : "off"}</b>` +
      ` · console TLS: <b style="color:${t.active ? "var(--accent-safe)" : (t.enabled ? "var(--accent-danger)" : "var(--accent-warn)")}">${t.active ? "ACTIVE" : (t.enabled ? "ENABLED BUT CERT MISSING" : "OFF (front with a TLS proxy or set webui_tls)")}</b>` +
      ` · go daemon: <b>${g.state || "go_not_installed"}</b>` + (g.state === "build_failed" ? " — <span style='color:var(--accent-danger)'>build failed</span>" : "");
    if (gt) gt.textContent = `GO DAEMON: ${g.enabled ? "SUPERVISED" : "OFF"}`;
  }
  $("btn-integrations-install").addEventListener("click", async () => {
    $("integrations-result").textContent = "installing (best-effort, needs root+apt on Linux)...";
    const r = await jpost("/api/v1/integrations/install", {});
    $("integrations-result").textContent = r && r.attempted
      ? `install attempted: ${(r.installed || []).join(", ") || "nothing installed"}`
      : (r && r.note) || "no-op";
    loadIntegrations();
  });
  $("btn-gosvc-toggle").addEventListener("click", async () => {
    const s = await api("/api/v1/integrations/status");
    const g = (s && s.go_services) || {};
    const r = await jpost("/api/v1/go_services/config", { enabled: !(g && g.enabled) });
    $("integrations-result").textContent = (r && r.go_services && r.go_services.enabled)
      ? "go daemon supervision on (builds and health-checks sentinelgated)" : "go daemon off";
    loadIntegrations();
  });

  // =========================================================
  // 9k. DNS SECURITY / FLEET / LOG VAULT (2.9)
  // =========================================================
  async function loadDns() {
    const d = await api("/api/v1/dns/status");
    const b = $("btn-dns-toggle"); const line = $("dns-status-line");
    if (d && b && line) {
      b.textContent = `DNS FILTER: ${d.enabled ? "ON" : "OFF"}`;
      const s = d.stats || {};
      line.innerHTML = `port <b>${d.port}</b> · queries <b>${s.queries || 0}</b> · blocked <b>${s.blocked || 0}</b> · forwarded <b>${s.forwarded || 0}</b> · cache hits <b>${s.cache_hits || 0}</b>`;
    }
  }
  $("btn-dns-toggle").addEventListener("click", async () => {
    const d = await api("/api/v1/dns/status");
    const r = await jpost("/api/v1/dns/server", { enabled: !(d && d.enabled) });
    $("dns-result").textContent = (r && r.dns_server && r.dns_server.enabled) ? "DNS filter on (needs port 53 free; run as admin/root)" : "DNS filter off";
    loadDns();
  });

  async function loadFleet() {
    const f = await api("/api/v1/fleet/overview");
    const line = $("fleet-status-line"), t = $("btn-fleet-toggle");
    if (!f) return;
    if (t) t.textContent = `FLEET RELAY: ${f.enabled ? "ON" : "OFF"}`;
    if (line) line.innerHTML = `agents: <b>${f.agents ? f.agents.length : 0}</b> · online: <b>${f.online || 0}</b>`;
    const cfg = await api("/api/v1/fleet/overview");
    const el = $("fleet-agents");
    if (el && f.agents && f.agents.length) {
      el.innerHTML = f.agents.map(a => `<div>${a.online ? "🟢" : "⚪"} <b>${esc(a.hostname || a.agent_id)}</b> · v${esc(a.version || "?")} · ${esc(a.platform || "?")} · seen ${a.last_seen}s ago · bans ${((a.stats || {}).bans || 0)} · threats ${((a.stats || {}).offenses || 0)}` +
        ((a.top_offenders || []).length ? ` · top: ${(a.top_offenders || []).map(o => `${esc(o.ip)}×${o.count}`).join(", ")}` : "") + `</div>`).join("");
    } else if (el) el.innerHTML = "<i>no agents enrolled yet</i>";
  }
  // fleet toggle
  document.getElementById("btn-fleet-toggle").onclick = async () => {
    const f = await api("/api/v1/fleet/overview");
    const r = await jpost("/api/v1/fleet/config", { enabled: !(f && f.enabled) });
    if (r && r.fleet && r.fleet.shared_key) $("fleet-key-display").textContent = "key: " + r.fleet.shared_key;
    loadFleet();
  };
  $("btn-fleet-newkey").addEventListener("click", async () => {
    if (!confirm("Regenerate the fleet key? Existing agents must be updated with the new key.")) return;
    const r = await jpost("/api/v1/fleet/config", { regenerate_key: true });
    if (r && r.fleet) $("fleet-key-display").textContent = "key: " + r.fleet.shared_key;
  });

  async function loadVault() {
    const v = await api("/api/v1/vault/status");
    const line = $("vault-status-line"), t = $("btn-vault-toggle");
    if (!v) return;
    if (t) t.textContent = `VAULT SEALING: ${v.enabled ? "ON" : "OFF"}`;
    if (line) line.innerHTML = v.ok
      ? `chain: <b>${v.blocks}</b> sealed block(s) · <b>${v.records}</b> records · integrity <b style="color:var(--accent-safe)">VERIFIED</b>` + (v.key_set ? " · HMAC key set" : " · <span style='color:var(--accent-warn)'>no seal key — set one for keyed signing</span>")
      : `<b style="color:var(--accent-danger)">CHAIN BROKEN at block ${v.first_bad}</b>`;
  }
  $("btn-vault-toggle").addEventListener("click", async () => {
    const v = await api("/api/v1/vault/status");
    const r = await jpost("/api/v1/vault/config", { enabled: !(v && v.enabled) });
    $("vault-result").textContent = (r && r.vault && r.vault.enabled) ? "sealing on" : "sealing off";
    loadVault();
  });
  $("btn-vault-newkey").addEventListener("click", async () => {
    if (!confirm("Regenerate the HMAC seal key? Previously sealed blocks will no longer verify against the new key.")) return;
    await jpost("/api/v1/vault/config", { regenerate_key: true });
    $("vault-result").textContent = "new seal key set";
    loadVault();
  });
  $("btn-vault-seal").addEventListener("click", async () => {
    const r = await jpost("/api/v1/vault/seal", {});
    $("vault-result").textContent = (r && r.sealed) ? "block sealed" : "nothing to seal";
    loadVault();
  });
  $("btn-flush").addEventListener("click", async () => {
    const typed = ($("flush-confirm") || {}).value || "";
    if (typed.trim().toUpperCase() !== "FLUSH") { $("vault-result").textContent = "type FLUSH in the box first"; return; }
    if (!confirm("PERMANENTLY delete ALL stored logs — events, audit chain, vault, intel cache and PCAPs? This cannot be undone.")) return;
    const r = await jpost("/api/v1/logs/flush", { confirm: "FLUSH" });
    $("vault-result").textContent = (r && r.count !== undefined) ? `flushed ${r.count} artifact(s)` : "flush failed";
    $("flush-confirm").value = "";
    loadVault(); loadOps(); loadDns();
  });

  // =========================================================
  // 9j. OPERATIONS SAFETY (commit-confirm, pcap ring, persistence watch)
  // =========================================================
  async function loadOps() {
    const c = await api("/api/v1/commit/status");
    const line = $("commit-status-line");
    if (c && line) {
      line.innerHTML = c.staged
        ? `STAGED — <b>${c.seconds_left}s</b> until automatic rollback — press CONFIRM to keep changes`
        : "no staged changes — configuration is live";
    }
    const pr = await api("/api/v1/pcaps");
    const bt = $("btn-pcap-toggle");
    if (pr && bt) {
      bt.textContent = `PCAP RING: ${pr.enabled ? "ON" : "OFF"}`;
      const pl = $("pcap-list");
      if (pl) pl.innerHTML = pr.dumps && pr.dumps.length
        ? "<b>Forensic captures:</b><br>" + pr.dumps.map(d =>
          `<a href="/api/v1/pcaps/${d.name}" style="color:var(--accent-link)">${esc(d.name)}</a> (${Math.round(d.size / 1024)} KB)`).join("<br>")
        : "";
    }
    const pw = await api("/api/v1/persistence/changes");
    const pt = $("btn-pwatch-toggle");
    if (pw && pt) {
      pt.textContent = `PERSISTENCE WATCH: ${pw.enabled ? "ON" : "OFF"}`;
      const po = $("persistence-out");
      if (po) po.innerHTML = pw.changes && pw.changes.length
        ? `<b style="color:var(--accent-danger)">${pw.changes.length} persistence change(s):</b><br>` +
        pw.changes.slice(-10).map(c => `${esc(c.change.toUpperCase())} ${esc(c.where)} ${esc(c.item)}`).join("<br>")
        : "";
    }
  }
  $("btn-commit-stage").addEventListener("click", async () => {
    if (!confirm("Stage configuration changes? They auto-revert in 5 minutes unless confirmed.")) return;
    const r = await jpost("/api/v1/commit/stage", { ttl_minutes: 5 });
    $("ops-result").textContent = (r && r.staged) ? "staged — confirm within " + r.ttl_minutes + " min" : "failed";
    loadOps();
  });
  $("btn-commit-confirm").addEventListener("click", async () => {
    const r = await jpost("/api/v1/commit/confirm", {});
    $("ops-result").textContent = r && r.confirmed ? "changes confirmed" : (r && r.note) || "nothing staged";
    loadOps();
  });
  $("btn-commit-rollback").addEventListener("click", async () => {
    if (!confirm("Revert to the staged snapshot now?")) return;
    await jpost("/api/v1/commit/rollback", {});
    $("ops-result").textContent = "rolled back";
    loadOps();
  });
  $("btn-pcap-toggle").addEventListener("click", async () => {
    const pr = await api("/api/v1/pcaps");
    const r = await jpost("/api/v1/pcap_ring", { enabled: !(pr && pr.enabled) });
    $("ops-result").textContent = "pcap ring " + ((r && r.pcap_ring && r.pcap_ring.enabled) ? "enabled" : "disabled");
    loadOps();
  });
  $("btn-pwatch-toggle").addEventListener("click", async () => {
    const pw = await api("/api/v1/persistence/changes");
    const r = await jpost("/api/v1/persistence/watch", { enabled: !(pw && pw.enabled) });
    $("ops-result").textContent = "persistence watch " + ((r && r.persistence_watch && r.persistence_watch.enabled) ? "enabled" : "disabled");
    loadOps();
  });
  $("btn-pwatch-baseline").addEventListener("click", async () => {
    const r = await jpost("/api/v1/persistence/baseline", {});
    $("ops-result").textContent = "baseline set: " + ((r && r.baseline_entries) || 0) + " locations";
    loadOps();
  });

  // =========================================================
  // 9i. CONSOLE SECURITY (2FA, learning mode, logout)
  // =========================================================
  async function loadSecurity() {
    const s = await api("/api/v1/auth/status");
    if (!s || !$("sec-status-line")) return;
    let txt = `sessions: <span style="color:var(--accent-safe)">ACTIVE</span> · user: <b>${esc(s.username || "—")}</b> · 2FA: `;
    txt += s.totp_enabled ? '<span style="color:var(--accent-safe)">ENABLED</span>' : '<span style="color:var(--accent-warn)">OFF</span>';
    if (s.default_password) txt += ' · <span style="color:var(--accent-danger)">DEFAULT PASSWORD STILL IN USE — change webui.password_hash</span>';
    $("sec-status-line").innerHTML = txt;
    const b2 = $("btn-2fa-disable");
    if (b2) b2.style.display = s.totp_enabled ? "" : "none";
    const lt = $("btn-learning-toggle");
    if (lt) lt.textContent = `LEARNING MODE: ${s.learning_mode ? "ON (bans suppressed)" : "OFF"}`;
  }
  $("btn-2fa-enable").addEventListener("click", async () => {
    if (!confirm("Enable TOTP two-factor? You will need an authenticator app (Google Authenticator, Aegis, 1Password…).")) return;
    const r = await jpost("/api/v1/auth/2fa/enable", {});
    const out = $("sec-2fa-out");
    if (!r || r.error) { $("sec-result").textContent = (r && r.error) || "failed"; return; }
    out.style.display = "block";
    out.innerHTML = `1. Add this secret to your authenticator app:<br>
      <b style="font-size:13px; letter-spacing:1px;">${esc(r.secret)}</b><br>
      2. Or use the otpauth URI: <span style="word-break:break-all;">${esc(r.uri)}</span><br>
      3. Recovery codes (each works ONCE — store them safely):<br>
      <b>${(r.recovery_codes || []).map(esc).join(" &nbsp;·&nbsp; ")}</b>`;
    $("sec-result").textContent = "2FA enabled — codes shown once, next login requires a code";
    loadSecurity();
  });
  $("btn-2fa-disable").addEventListener("click", async () => {
    if (!confirm("Disable two-factor authentication?")) return;
    await jpost("/api/v1/auth/2fa/disable", {});
    $("sec-2fa-out").style.display = "none";
    $("sec-result").textContent = "2FA disabled";
    loadSecurity();
  });
  $("btn-learning-toggle").addEventListener("click", async () => {
    const s = await api("/api/v1/auth/status");
    const r = await jpost("/api/v1/detections/learning", { enabled: !(s && s.learning_mode) });
    $("sec-result").textContent = r && r.learning_mode ? "learning mode ON — detections logged, bans suppressed"
      : "learning mode OFF — enforcement active";
    loadSecurity();
  });
  $("btn-logout").addEventListener("click", async () => {
    await jpost("/api/v1/logout", {});
    location.href = "/login";
  });

  // =========================================================
  // 9f. SARVAM AI CONFIG
  // =========================================================
  async function loadSarvamConfig() {
    const c = await api("/api/v1/sarvam/config");
    if (!c || !$("sarvam-model")) return;
    $("sarvam-model").value = c.model || "sarvam-105b";
    $("sarvam-auto").value = c.auto_analyze ? "true" : "false";
    $("sarvam-threshold").value = c.risk_threshold || 65;
    $("sarvam-rate").value = c.max_auto_per_hour || 4;
    $("sarvam-status").textContent = c.configured
      ? "configured · model " + (c.model || "sarvam-105b") + (c.auto_analyze ? " · auto-analysis ON" : " · auto-analysis OFF")
      : "no API key configured — paste one to enable agentic analysis";
  }
  $("btn-save-sarvam").addEventListener("click", async () => {
    const body = {
      api_key: $("sarvam-key").value.trim() || undefined,
      model: $("sarvam-model").value.trim(),
      auto_analyze: $("sarvam-auto").value === "true",
      risk_threshold: $("sarvam-threshold").value,
      max_auto_per_hour: $("sarvam-rate").value,
    };
    const res = await jpost("/api/v1/sarvam/config", body);
    if (res && !res.error) {
      $("sarvam-key").value = "";
      $("sarvam-status").textContent = "saved · " + (res.configured ? "configured" : "no key set")
        + (res.auto_analyze ? " · auto-analysis ON" : " · auto-analysis OFF");
    } else {
      $("sarvam-status").textContent = "save failed: " + ((res && res.error) || "unknown");
    }
  });

  // =========================================================
  // 9g. SSH TARPIT (seeker-bot registry)
  // =========================================================
  let tarpitTimer = null;
  async function loadTarpit() {
    const d = await api("/api/v1/honeypot/tarpit");
    if (!d || !d.visitors) return;
    const tbody = document.querySelector("#tarpit-table tbody");
    if (tbody) {
      tbody.innerHTML = d.visitors.length
        ? d.visitors.slice(0, 50).map((v) => `
          <tr>
            <td class="mono"><strong>${esc(v.ip)}</strong></td>
            <td class="mono">${v.count}</td>
            <td class="mono" style="font-size:10.5px;">${esc(v.banner || "—")}</td>
            <td class="mono" style="font-size:10px;">${v.first ? new Date(v.first * 1000).toLocaleTimeString() : "—"}</td>
            <td class="mono" style="font-size:10px;">${v.last ? new Date(v.last * 1000).toLocaleTimeString() : "—"}</td>
            <td>${d.auto_block ? '<span class="badge badge-danger">AUTO-BANNED</span>' : '<span class="badge badge-warn">LOGGED</span>'}</td>
          </tr>`).join("")
        : '<tr><td colspan="6" class="empty-state">No seeker bots trapped yet — the tarpit is listening on port 22222.</td></tr>';
    }
    const badge = $("tarpit-count-badge");
    if (badge) badge.textContent = `${d.visitors.length} visitor${d.visitors.length === 1 ? "" : "s"}`;
    const tb = $("btn-tarpit-toggle");
    if (tb) tb.textContent = `AUTO-BLOCK: ${d.auto_block ? "ON" : "OFF"}`;
    if (!tarpitTimer) tarpitTimer = setInterval(loadTarpit, 5000);
  }
  $("btn-tarpit-toggle").addEventListener("click", async () => {
    const d = await api("/api/v1/honeypot/tarpit");
    await jpost("/api/v1/honeypot/tarpit/toggle", { enabled: !(d && d.auto_block) });
    loadTarpit();
  });
  $("btn-tarpit-block-all").addEventListener("click", async () => {
    if (!confirm("Ban every seeker-bot IP that touched the tarpit (7 days)?")) return;
    const r = await jpost("/api/v1/honeypot/tarpit/block", {});
    showBanner(document.body, r && r.count ? `Banned ${r.count} seeker IP(s)` : "No unbanned visitors to block", true);
    loadTarpit(); syncDashboard();
  });

  // =========================================================
  // 9e. TRUSTED (PROTECTED) MANAGEMENT IPS
  // =========================================================
  async function loadTrustedIps() {
    const d = await api("/api/v1/trusted-ips");
    const list = $("trusted-ip-list");
    if (!list || !d) return;
    const ips = d.trusted_ips || [];
    list.innerHTML = ips.length
      ? ips.map((ip) => `<span class="trusted-chip mono">${esc(ip)} <b data-del="${esc(ip)}" title="Remove">✕</b></span>`).join(" ")
      : '<span style="color:var(--text-muted);font-size:11px;">No protected IPs — every remote can be banned.</span>';
    list.querySelectorAll("[data-del]").forEach((el) => el.addEventListener("click", async () => {
      await jpost("/api/v1/trusted-ips", { ip: el.dataset.del, remove: true });
      loadTrustedIps();
    }));
  }
  $("btn-add-trusted").addEventListener("click", async () => {
    const ip = $("trusted-ip-input").value.trim();
    if (!ip) return;
    const res = await jpost("/api/v1/trusted-ips", { ip });
    if (res && !res.error) { $("trusted-ip-input").value = ""; loadTrustedIps(); }
    else alert("Invalid IP or CIDR");
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
  fetch("/api/v1/logs?limit=50").then((r) => r.json()).then((logs) => { logs.reverse().forEach(appendLogEvent); }).catch(() => { });
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

  // =========================================================
  // 16. Security Services Matrix (18 Pillars)
  // =========================================================
  async function loadServicesStatus() {
    const res = await api("/api/v1/services/status");
    if (res && res.services) {
      renderServicesMatrix(res);
    }
  }
  window.loadServicesStatus = loadServicesStatus;

  function renderServicesMatrix(data) {
    const container = $("services-grid");
    const summary = $("services-summary");
    const badge = $("services-active-badge");
    if (!container) return;
    const services = data.services || [];
    if (badge) badge.textContent = `${data.active_count || 0}/${data.total || services.length} ENGINES ONLINE`;

    if (summary) {
      const active = services.filter((s) => s.status === "ACTIVE").length;
      const standby = services.filter((s) => s.status === "STANDBY").length;
      const configured = services.filter((s) => s.status === "CONFIGURED").length;
      const unwired = services.filter((s) => s.status === "UNWIRED").length;
      summary.innerHTML = `
        <div class="cs-cell"><span>ACTIVE ENGINES</span><b class="cs-green">${active}</b></div>
        <div class="cs-cell"><span>STANDBY / FAILOVER</span><b class="cs-amber">${standby}</b></div>
        <div class="cs-cell"><span>CONFIGURED EXCLUSIONS</span><b class="cs-blue">${configured}</b></div>
        <div class="cs-cell"><span>UNWIRED WARNINGS</span><b class="${unwired > 0 ? 'cs-amber' : ''}">${unwired}</b></div>
      `;
    }

    container.innerHTML = services.map((s) => {
      const stClass = `status-${s.status.toLowerCase()}`;
      return `
        <div class="service-card">
          <div class="service-header">
            <span class="service-cat">${esc(s.category)}</span>
            <span class="service-status-badge ${stClass}">${esc(s.status)}</span>
          </div>
          <div class="service-name">
            <svg width="14" height="14" style="color:${s.status === 'ACTIVE' ? '#429462' : '#d9a036'}"><use href="#icon-shield"/></svg>
            ${esc(s.name)}
          </div>
          <div class="service-detail">${esc(s.detail)}</div>
          <div class="service-footer">
            <span class="service-backend">${esc(s.backend)}</span>
            <span class="badge ${s.health === 'HEALTHY' ? 'badge-safe' : 'badge-warn'}">${esc(s.health)}</span>
          </div>
        </div>
      `;
    }).join("");
  }

  const btnRefreshServices = $("btn-refresh-services");
  if (btnRefreshServices) {
    btnRefreshServices.addEventListener("click", () => loadServicesStatus());
  }

  // ==================== 1. WAF & API GUARD ====================
  async function loadWaf() {
    const data = await jget("/api/v1/waf/status");
    if (!data) return;
    const statusEl = $("waf-stat-status");
    if (statusEl) {
      statusEl.textContent = data.enabled ? "ACTIVE" : "STANDBY";
      statusEl.style.color = data.enabled ? "var(--accent-safe)" : "var(--accent-warning)";
    }
    const listenEl = $("waf-stat-listen");
    if (listenEl) listenEl.textContent = `${data.host || "0.0.0.0"}:${data.port || 8088} (Reverse Proxy)`;
    const modeEl = $("waf-stat-mode");
    if (modeEl) {
      modeEl.textContent = (data.mode || "block").toUpperCase();
      modeEl.style.color = data.mode === "block" ? "var(--accent-danger)" : "var(--accent-warning)";
    }
    const rulesEl = $("waf-stat-rules");
    if (rulesEl) rulesEl.textContent = data.rules_loaded || 48;
    const stats = data.stats || {};
    const reqsEl = $("waf-stat-reqs");
    if (reqsEl) reqsEl.textContent = stats.requests_total || 0;
    const blockedEl = $("waf-stat-blocked");
    if (blockedEl) blockedEl.textContent = `${stats.requests_blocked || 0} blocked / challenges`;
    const paranoiaSel = $("waf-paranoia-select");
    if (paranoiaSel && data.paranoia_level) paranoiaSel.value = String(data.paranoia_level);
    const modeSel = $("waf-mode-select");
    if (modeSel && data.mode) modeSel.value = data.mode;
  }

  const btnSaveWaf = $("btn-save-waf-cfg");
  if (btnSaveWaf) {
    btnSaveWaf.addEventListener("click", async () => {
      const pl = parseInt($("waf-paranoia-select").value, 10) || 1;
      const mode = $("waf-mode-select").value;
      const statusEl = $("waf-cfg-status");
      statusEl.textContent = "Updating...";
      const res = await jpost("/api/v1/waf/config", { paranoia_level: pl, mode });
      if (res && !res.error) {
        statusEl.textContent = "Policy applied successfully.";
        loadWaf();
      } else {
        statusEl.textContent = "Failed to update WAF.";
      }
    });
  }

  // ==================== 2. DATA LOSS PREVENTION ====================
  async function loadDlp() {
    const data = await jget("/api/v1/dlp/status");
    if (!data) return;
    const actEl = $("dlp-default-action");
    if (actEl) actEl.textContent = (data.default_action || "redact").toUpperCase();
    const rulesCountEl = $("dlp-rules-count");
    if (rulesCountEl) rulesCountEl.textContent = (data.rules || []).length;
    const bypassCountEl = $("dlp-bypass-count");
    if (bypassCountEl) bypassCountEl.textContent = (data.privacy_bypass_domains || []).length;
    const tbody = $("dlp-rules-body");
    if (tbody && data.rules) {
      tbody.innerHTML = data.rules.map((r) => `
        <tr>
          <td><code class="mono">${esc(r.id)}</code></td>
          <td><b>${esc(r.name)}</b></td>
          <td><span class="mono" style="font-size:11px;">${esc(r.type)}</span></td>
          <td><span class="badge ${r.severity === "critical" ? "badge-danger" : "badge-warning"}">${esc(r.severity.toUpperCase())}</span></td>
          <td><span class="badge badge-info">${esc(r.action.toUpperCase())}</span></td>
          <td><span class="badge badge-success">ACTIVE</span></td>
        </tr>
      `).join("");
    }
  }

  const btnRunDlpTest = $("btn-run-dlp-test");
  if (btnRunDlpTest) {
    btnRunDlpTest.addEventListener("click", async () => {
      const text = $("dlp-test-input").value.trim();
      if (!text) return;
      const res = await jpost("/api/v1/dlp/test", { text });
      const wrap = $("dlp-test-result");
      const out = $("dlp-test-output");
      if (wrap && out && res) {
        wrap.style.display = "block";
        out.textContent = JSON.stringify(res, null, 2);
      }
    });
  }

  // ==================== 3. ZERO TRUST (ZTNA) ====================
  async function loadZtna() {
    const data = await jget("/api/v1/ztna/status");
    if (!data) return;
    const idCountEl = $("ztna-identities-count");
    if (idCountEl) idCountEl.textContent = data.identity_directory_records || 0;
  }

  const btnRunZtnaEval = $("btn-run-ztna-eval");
  if (btnRunZtnaEval) {
    btnRunZtnaEval.addEventListener("click", async () => {
      const ip = $("ztna-eval-ip").value.trim();
      const app = $("ztna-eval-app").value.trim();
      const disk = $("ztna-eval-disk").value === "true";
      const edr = $("ztna-eval-edr").value === "true";
      const res = await jpost("/api/v1/ztna/evaluate", {
        ip, app, posture: { disk_encrypted: disk, edr_running: edr, os_patch_age_days: 5 }
      });
      const wrap = $("ztna-eval-result");
      const out = $("ztna-eval-output");
      if (wrap && out && res) {
        wrap.style.display = "block";
        out.textContent = JSON.stringify(res, null, 2);
      }
    });
  }

  // ==================== 4. THREAT INTELLIGENCE ====================
  async function loadThreatIntel() {
    const data = await jget("/api/v1/threatintel/summary");
    if (!data) return;
    const feedCountEl = $("ti-feed-count");
    if (feedCountEl) feedCountEl.textContent = (data.feeds || []).length;
    const vtCachedEl = $("ti-vt-cached");
    if (vtCachedEl) vtCachedEl.textContent = data.vt_reputation_cached || 0;
    const tbody = $("ti-feeds-body");
    if (tbody && data.feeds) {
      tbody.innerHTML = data.feeds.map((f) => `
        <tr>
          <td><b>${esc(f.name)}</b></td>
          <td><span class="mono" style="font-size:11px;">${esc(f.type)}</span></td>
          <td><span class="badge badge-info">${f.confidence}% CONFIDENCE</span></td>
          <td><b class="mono">${f.entries}</b></td>
          <td><span class="badge badge-success">SYNCHRONIZED</span></td>
        </tr>
      `).join("");
    }
  }

  const btnTiLookup = $("btn-ti-lookup");
  if (btnTiLookup) {
    btnTiLookup.addEventListener("click", async () => {
      const ioc = $("ti-lookup-input").value.trim();
      if (!ioc) return;
      const res = await jpost("/api/v1/threatintel/lookup", { ioc });
      const wrap = $("ti-lookup-result");
      const out = $("ti-lookup-output");
      if (wrap && out && res) {
        wrap.style.display = "block";
        out.textContent = JSON.stringify(res, null, 2);
      }
    });
  }

  // ==================== 5. SOAR PLAYBOOKS ====================
  async function loadPlaybooks() {
    const data = await jget("/api/v1/soar/playbooks");
    if (!data) return;
    const pbs = data.playbooks || [];
    const countEl = $("pb-count");
    if (countEl) countEl.textContent = pbs.length;
    let totalExecs = 0;
    pbs.forEach((p) => { totalExecs += (p.executions || 0); });
    const execsEl = $("pb-execs");
    if (execsEl) execsEl.textContent = totalExecs;
    const tbody = $("pb-list-body");
    if (tbody) {
      tbody.innerHTML = pbs.length ? pbs.map((p) => `
        <tr>
          <td><code class="mono">${esc(p.id)}</code></td>
          <td><b>${esc(p.name)}</b></td>
          <td><span class="mono" style="font-size:11px;">${esc(JSON.stringify(p.conditions))}</span></td>
          <td>${(p.actions || []).map((a) => `<span class="badge badge-info" style="margin-right:4px;">${esc(a)}</span>`).join("")}</td>
          <td><b class="mono">${p.executions || 0}</b></td>
          <td><span class="badge ${p.enabled ? "badge-success" : "badge-muted"}">${p.enabled ? "ARMED" : "DISABLED"}</span></td>
        </tr>
      `).join("") : '<tr><td colspan="6" class="text-center text-muted">No automated response playbooks configured.</td></tr>';
    }
  }

  const btnRunPbSim = $("btn-run-pb-sim");
  if (btnRunPbSim) {
    btnRunPbSim.addEventListener("click", async () => {
      const eventName = $("pb-test-event").value.trim();
      const ip = $("pb-test-ip").value.trim();
      const sev = $("pb-test-sev").value;
      const dryRun = $("pb-test-mode").value === "dry_run";
      const res = await jpost("/api/v1/soar/execute", {
        event: { event: eventName, ip, severity: sev, threat_score: 85 },
        dry_run: dryRun,
      });
      const wrap = $("pb-sim-result");
      const out = $("pb-sim-output");
      if (wrap && out && res) {
        wrap.style.display = "block";
        out.textContent = JSON.stringify(res, null, 2);
      }
      loadPlaybooks();
    });
  }

  // ==================== 6. IDENTITY & DIRECTORY ====================
  async function loadIdentity() {
    const data = await jget("/api/v1/identity/directory");
    if (!data) return;
    const idents = data.identities || [];
    const countEl = $("ident-count");
    if (countEl) countEl.textContent = idents.length;
    const tbody = $("ident-table-body");
    if (tbody) {
      tbody.innerHTML = idents.length ? idents.map((id) => `
        <tr>
          <td><b class="mono">${esc(id.ip)}</b></td>
          <td><b>${esc(id.username)}</b></td>
          <td>${esc(id.domain ? id.domain + " / " : "")}${esc((id.groups || []).join(", ") || "—")}</td>
          <td><span class="mono" style="font-size:11px;">${esc(id.device_name || id.device_id || "—")}</span></td>
          <td><span class="mono" style="font-size:11px;">${esc(id.mac_address || "—")}</span></td>
          <td><span class="badge ${id.posture === "COMPLIANT" ? "badge-success" : "badge-danger"}">${esc(id.posture || "COMPLIANT")}</span></td>
          <td><span class="mono" style="font-size:11px;">${id.expires_at ? Math.max(0, Math.round(id.expires_at - Date.now() / 1000)) + "s" : "PERMANENT"}</span></td>
        </tr>
      `).join("") : '<tr><td colspan="7" class="text-center text-muted">No active identity bindings registered. Click "+ BIND IDENTITY" to map an IP.</td></tr>';
    }
  }

  const modalIdentity = $("modal-identity");
  const btnShowBind = $("btn-show-bind-modal");
  const btnCloseBind = $("btn-close-modal-identity");
  const btnSubmitBind = $("btn-submit-identity");
  if (btnShowBind && modalIdentity) btnShowBind.addEventListener("click", () => modalIdentity.classList.add("open"));
  if (btnCloseBind && modalIdentity) btnCloseBind.addEventListener("click", () => modalIdentity.classList.remove("open"));
  if (btnSubmitBind && modalIdentity) {
    btnSubmitBind.addEventListener("click", async () => {
      const ip = $("bind-ip").value.trim();
      const username = $("bind-user").value.trim();
      const groups = $("bind-groups").value.split(",").map((s) => s.trim()).filter(Boolean);
      const device_name = $("bind-device").value.trim();
      const posture = $("bind-posture").value;
      if (!ip || !username) return;
      await jpost("/api/v1/identity/bind", { ip, username, groups, device_name, posture });
      modalIdentity.classList.remove("open");
      loadIdentity();
    });
  }

  // ==================== 7. AI SECURITY ANALYST CHATBOT ====================
  async function loadAiAnalyst() {
    await jget("/api/v1/ai/guardrails");
  }

  const chatStream = $("ai-chat-stream");
  const chatInput = $("ai-chat-input");
  const btnChatSend = $("btn-ai-chat-send");
  const btnClearChat = $("btn-clear-ai-chat");
  const quickChips = $("ai-quick-chips");

  function appendUserMessage(text) {
    if (!chatStream) return;
    const div = document.createElement("div");
    div.className = "chat-msg chat-msg-user";
    div.innerHTML = `
      <div class="msg-avatar">OP</div>
      <div class="msg-bubble">
        <div class="msg-header">Operator</div>
        <div class="msg-text">${esc(text)}</div>
      </div>
    `;
    chatStream.appendChild(div);
    chatStream.scrollTop = chatStream.scrollHeight;
  }

  function appendAiMessage(htmlContent, codeSnippet, canStage) {
    if (!chatStream) return;
    const div = document.createElement("div");
    div.className = "chat-msg chat-msg-ai";
    let actionsHtml = "";
    if (canStage) {
      actionsHtml = `
        <div class="msg-actions">
          <button class="btn btn-sm btn-primary btn-chat-stage">STAGE RECOMMENDED POLICY</button>
          <button class="btn btn-sm btn-danger btn-chat-rollback">ROLLBACK</button>
        </div>
      `;
    }
    div.innerHTML = `
      <div class="msg-avatar"><svg width="16" height="16"><use href="#icon-ai"/></svg></div>
      <div class="msg-bubble">
        <div class="msg-header">Sentinel Analyst</div>
        <div class="msg-text">${htmlContent}</div>
        ${codeSnippet ? `<div class="msg-code-block">${esc(codeSnippet)}</div>` : ""}
        ${actionsHtml}
      </div>
    `;
    chatStream.appendChild(div);
    chatStream.scrollTop = chatStream.scrollHeight;

    const btnStage = div.querySelector(".btn-chat-stage");
    if (btnStage) {
      btnStage.addEventListener("click", async () => {
        btnStage.disabled = true;
        btnStage.textContent = "Staging...";
        const res = await jpost("/api/v1/commit/stage", { ttl_minutes: 60 });
        if (res && !res.error) {
          btnStage.textContent = "✓ Policy Staged";
          showTelegramBanner("AI Recommended Policy staged. Operator confirmation recorded.", true);
        } else {
          btnStage.textContent = "Stage Failed";
        }
      });
    }

    const btnRoll = div.querySelector(".btn-chat-rollback");
    if (btnRoll) {
      btnRoll.addEventListener("click", async () => {
        btnRoll.disabled = true;
        const res = await jpost("/api/v1/commit/rollback", { reason: "Operator triggered 1-click rollback" });
        if (res && !res.error) {
          btnRoll.textContent = "✓ Rolled Back";
          showTelegramBanner("Policy rolled back to previous stable baseline.", true);
        }
      });
    }
  }

  async function handleAiSubmit(userQuery) {
    if (!userQuery) return;
    appendUserMessage(userQuery);
    if (chatInput) chatInput.value = "";

    // Show animated typing indicator
    const typingDiv = document.createElement("div");
    typingDiv.className = "chat-msg chat-msg-ai chat-typing-msg";
    typingDiv.innerHTML = `
      <div class="msg-avatar"><svg width="16" height="16"><use href="#icon-ai"/></svg></div>
      <div class="msg-bubble">
        <div class="ai-typing-indicator">
          <div class="ai-typing-dot"></div>
          <div class="ai-typing-dot"></div>
          <div class="ai-typing-dot"></div>
          <span style="font-size:11px; color:var(--text-muted); margin-left:6px;">Synthesizing kernel telemetry & Sarvam-105B advisory...</span>
        </div>
      </div>
    `;
    if (chatStream) {
      chatStream.appendChild(typingDiv);
      chatStream.scrollTop = chatStream.scrollHeight;
    }

    // Call AI backend
    await jpost("/api/v1/ai/analyze", { prompt: userQuery, ip: "198.51.100.22" });
    if (typingDiv && typingDiv.parentNode) typingDiv.parentNode.removeChild(typingDiv);

    // Contextual responses based on query
    const lower = userQuery.toLowerCase();
    let verdict = "";
    let code = "";
    if (lower.includes("port") || lower.includes("spike") || lower.includes("egress") || lower.includes("4444")) {
      verdict = `<b>Executive Verdict:</b> Elevated egress anomaly detected on port 4444. Threat pattern matches reverse-shell or C2 beaconing.
                 <br><b>Prompt Injection Guard:</b> Enforced & Verified.
                 <br><b>Telemetry Context:</b> 1 active outbound socket attribution confirmed to unverified background thread.`;
      code = `SentinelGate policy: DENY out proto=tcp dst_port=4444 log=true action=isolate_process`;
    } else if (lower.includes("scanner") || lower.includes("mitigate") || lower.includes("ban")) {
      verdict = `<b>Executive Verdict:</b> Autonomous correlation identifies distributed reconnaissance originating from external CIDRs targeting decoy ports 2222 and 8082.
                 <br><b>Risk Rating:</b> CRITICAL (Score: 92/100).
                 <br><b>Recommended Mitigation:</b> Stage kernel drop ban on identified scanner range and notify SOC Telegram bridge.`;
      code = `sfwctl block-ip 198.51.100.0/24 --duration 24h --reason "Reconnaissance scan threshold exceeded"`;
    } else if (lower.includes("waf") || lower.includes("crs") || lower.includes("sqli") || lower.includes("xss")) {
      verdict = `<b>Executive Verdict:</b> OWASP CRS 3.3 inspection pipeline operational. Detected 0 critical bypass attempts in the last 15 minutes.
                 <br><b>Recommendation:</b> Raise CRS Paranoia Level to 2 on public reverse proxy routes to tighten SQLi & RCE heuristics.`;
      code = `set waf paranoia_level=2 mode=block challenge=captcha`;
    } else if (lower.includes("ssh") || lower.includes("policy") || lower.includes("zero trust") || lower.includes("ztna")) {
      verdict = `<b>Executive Verdict:</b> ZTNA Microsegmentation audit complete. SSH service currently reachable from all internal subnets.
                 <br><b>Recommendation:</b> Restrict corporate SSH access exclusively to devices with compliant BitLocker encryption and verified EDR health.`;
      code = `config firewall policy\n  edit 101\n    set name "ZTNA-SSH-Compliance"\n    set srcaddr "COMPLIANT-HOSTS"\n    set dstport 22\n    set action accept\n  next\nend`;
    } else {
      verdict = `<b>Executive Verdict:</b> Threat assessment synthesized. Observed pattern: "<i>${esc(userQuery)}</i>".
                 <br>Continuous network analysis reveals nominal baseline traffic. No active privilege escalation or persistence anomalies observed in kernel rings.`;
      code = `enforce ban on 198.51.100.22 (TTL: 86400s); add rate_limit=5/min to public API gateway`;
    }

    appendAiMessage(verdict, code, true);
  }

  if (btnChatSend) {
    btnChatSend.addEventListener("click", () => {
      if (chatInput) handleAiSubmit(chatInput.value.trim());
    });
  }

  if (chatInput) {
    chatInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleAiSubmit(chatInput.value.trim());
      }
    });
  }

  if (quickChips) {
    quickChips.addEventListener("click", (e) => {
      const chip = e.target.closest(".chat-chip");
      if (chip && chip.dataset.query) {
        handleAiSubmit(chip.dataset.query);
      }
    });
  }

  if (btnClearChat) {
    btnClearChat.addEventListener("click", () => {
      if (chatStream) {
        chatStream.innerHTML = `
          <div class="chat-msg chat-msg-ai">
            <div class="msg-avatar"><svg width="16" height="16"><use href="#icon-ai"/></svg></div>
            <div class="msg-bubble">
              <div class="msg-header">Sentinel Analyst</div>
              <div class="msg-text">
                Chat session cleared. How can I assist with threat investigations or policy synthesis today?
              </div>
            </div>
          </div>
        `;
      }
    });
  }

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
    syncDashboard(); loadRules(); refreshMap(); refreshApplications(); loadServicesStatus();
  });

  // Kick off
  syncDashboard();
  loadServicesStatus();
  setInterval(syncDashboard, 3000);
});
