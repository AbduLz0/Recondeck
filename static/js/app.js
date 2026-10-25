/* ReconDeck client workspace.
   No framework, no third-party runtime, no network calls. */
"use strict";

(() => {
  const TOKEN_META = document.querySelector('meta[name="recon-token"]');
  const API_TOKEN = TOKEN_META ? TOKEN_META.content : "";
  const PAGE_META = {
    overview: { title: "Overview", document: "Overview" },
    discover: { title: "Discovery", document: "Discovery" },
    assets: { title: "Assets", document: "Assets" },
    ports: { title: "Port scan", document: "Port scan" },
    history: { title: "History", document: "History" },
  };
  const ROUTES = new Set(Object.keys(PAGE_META));
  const ACTIVE_STATUSES = new Set(["queued", "running", "cancelling"]);
  const FINISHED_STATUSES = new Set(["completed", "failed", "cancelled", "interrupted"]);
  const PROFILE_LABELS = {
    discover: "Network discovery",
    quick: "Quick sweep",
    standard: "Standard sweep",
    full: "Deep sweep",
    services: "Service audit",
    safe: "Safe audit",
    custom: "Custom ports",
  };
  const PROFILE_LIMITS = {
    quick: { maxHosts: 256, portCount: 100, label: "top 100 ports" },
    standard: { maxHosts: 128, portCount: 1000, label: "top 1,000 ports" },
    full: { maxHosts: 8, portCount: 65535, label: "all TCP ports" },
    services: { maxHosts: 64, portCount: 1000, label: "top 1,000 ports + versions" },
    safe: { maxHosts: 16, portCount: 1000, label: "top 1,000 ports + safe checks" },
    custom: { maxHosts: 128, portCount: null, label: "custom ports" },
  };
  const SAFE_AUDIT_SCRIPTS =
    "banner,http-title,http-headers,http-security-headers,http-methods," +
    "ssl-cert,ssl-enum-ciphers,ssh-hostkey,ssh-auth-methods," +
    "ssh2-enum-algos,smb-os-discovery";
  const SURFACE_CATEGORIES = [
    {
      key: "remote-access",
      label: "Remote access",
      icon: "terminal",
      blurb: "Shells, desktops, and remote management.",
    },
    {
      key: "file-sharing",
      label: "File sharing",
      icon: "copy",
      blurb: "SMB, NFS, FTP, and sync surfaces.",
    },
    {
      key: "management",
      label: "Management planes",
      icon: "sliders",
      blurb: "APIs, Windows management, and admin control.",
    },
    {
      key: "database",
      label: "Data stores",
      icon: "database",
      blurb: "Databases and in-memory services that merit restriction.",
    },
    {
      key: "web",
      label: "Web services",
      icon: "globe",
      blurb: "HTTP(S) applications and alternate web ports.",
    },
    {
      key: "infrastructure",
      label: "Infrastructure",
      icon: "wifi",
      blurb: "DNS, RPC, and supporting network services.",
    },
    {
      key: "mail",
      label: "Mail services",
      icon: "mail",
      blurb: "Mail transport and submission endpoints.",
    },
    {
      key: "printing",
      label: "Printing",
      icon: "printer",
      blurb: "Printers and their embedded management interfaces.",
    },
    {
      key: "other",
      label: "Other services",
      icon: "ports",
      blurb: "Open services that still need an owner.",
    },
  ];
  const RISK_WORD = {
    high: { label: "Review", cls: "danger" },
    medium: { label: "Check", cls: "amber" },
    low: { label: "Low signal", cls: "blue" },
    info: { label: "Info", cls: "" },
  };

  const state = {
    system: null,
    stats: null,
    inventory: [],
    inventoryByAddress: new Map(),
    recentScans: [],
    bootstrapped: false,
    targetsInitialised: false,
    route: "overview",
    activeLive: null,
    liveCursor: 0,
    liveLogOpen: true,
    liveLogPinned: true,
    pollTimer: null,
    pollBusy: false,
    pollFailures: 0,
    terminalHandled: null,
    startPending: null,
    discoveryScan: null,
    latestLoaded: { discover: false, ports: false },
    latestLoading: { discover: false, ports: false },
    currentDiscoveryHosts: [],
    portScan: null,
    filters: { discovery: "", ports: "" },
    assetTab: "inventory",
    assetFilter: "all",
    assetSearch: "",
    assetCategory: null,
    assetDetail: null,
    historyScans: [],
    historyKind: "",
    historyStatus: "",
    historyQuery: "",
    historyRequest: 0,
    historyTimer: null,
    drawerScan: null,
    drawerAsset: null,
    drawerRequest: 0,
    drawerReturnFocus: null,
    gPending: false,
    gTimer: null,
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const byId = (id) => document.getElementById(id);

  /* ---------------------------------------------------------------------
     API and small utilities
  --------------------------------------------------------------------- */

  async function api(path, { method = "GET", body } = {}) {
    const headers = {
      "X-ReconDeck-Token": API_TOKEN,
      Accept: "application/json",
    };
    const options = { method, headers, cache: "no-store" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(path, options);
    } catch (error) {
      const wrapped = new Error("Could not reach the local ReconDeck server.");
      wrapped.cause = error;
      throw wrapped;
    }
    let payload = null;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      payload = await response.json().catch(() => null);
    } else {
      payload = await response.text().catch(() => "");
    }
    if (!response.ok) {
      const error = new Error(
        (payload && payload.error) || `ReconDeck returned HTTP ${response.status}.`
      );
      error.status = response.status;
      error.code = payload && payload.code;
      error.activeId = payload && payload.activeId;
      throw error;
    }
    return payload;
  }

  function escapeHtml(value) {
    return String(value === null || value === undefined ? "" : value).replace(
      /[&<>"']/g,
      (character) => {
        switch (character) {
          case "&":
            return "&amp;";
          case "<":
            return "&lt;";
          case ">":
            return "&gt;";
          case '"':
            return "&quot;";
          case "'":
            return "&#39;";
          default:
            return character;
        }
      }
    );
  }

  function icon(name, className = "") {
    return `<svg class="icon ${className}" aria-hidden="true"><use href="#i-${escapeHtml(
      name
    )}"/></svg>`;
  }

  function formatNumber(value) {
    const number = Number(value) || 0;
    return new Intl.NumberFormat("en").format(number);
  }

  function plural(count, one, many) {
    return `${formatNumber(count)} ${count === 1 ? one : many || `${one}s`}`;
  }

  function parseDate(value) {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatAgo(value) {
    const date = parseDate(value);
    if (!date) return "—";
    const seconds = Math.max(0, Math.round((Date.now() - date.getTime()) / 1000));
    if (seconds < 12) return "just now";
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    return new Intl.DateTimeFormat("en", {
      day: "2-digit",
      month: "short",
    }).format(date);
  }

  function formatDateTime(value) {
    const date = parseDate(value);
    if (!date) return "—";
    return new Intl.DateTimeFormat("en", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }

  function formatDateParts(value) {
    const date = parseDate(value);
    if (!date) return { date: "—", time: "" };
    return {
      date: new Intl.DateTimeFormat("en", {
        day: "2-digit",
        month: "short",
        year: "numeric",
      })
        .format(date)
        .toUpperCase(),
      time: new Intl.DateTimeFormat("en", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }).format(date),
    };
  }

  function formatDuration(seconds) {
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) return "—";
    if (value === 0) return "<0.1s";
    if (value < 1) return `${value.toFixed(2)}s`;
    if (value < 60) return `${value.toFixed(value < 10 ? 1 : 0)}s`;
    const minutes = Math.floor(value / 60);
    const remaining = Math.round(value % 60);
    if (minutes < 60) return `${minutes}m ${remaining}s`;
    return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
  }

  function formatElapsed(startValue) {
    const start = parseDate(startValue);
    if (!start) return "00:00";
    const seconds = Math.max(0, Math.floor((Date.now() - start.getTime()) / 1000));
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
  }

  function profileLabel(profile) {
    return PROFILE_LABELS[profile] || profile || "Scan";
  }

  function engineLabel(scan) {
    if (!scan) return "—";
    if (scan.kind === "discover") {
      return scan.engine === "arp" ? "arp-scan" : "Nmap ping";
    }
    if (scan.engine === "nmap" || !scan.engine) {
      const resolved = scan.request && scan.request.resolvedEngine;
      return resolved === "nmap-syn" ? "Nmap SYN" : "Nmap connect";
    }
    return scan.engine;
  }

  function statusLabel(status) {
    switch (status) {
      case "completed":
        return "Completed";
      case "failed":
        return "Failed";
      case "cancelled":
        return "Stopped";
      case "interrupted":
        return "Interrupted";
      case "running":
        return "Running";
      case "cancelling":
        return "Stopping";
      case "queued":
        return "Queued";
      default:
        return status || "Unknown";
    }
  }

  function statusPill(status) {
    return `<span class="status-pill ${escapeHtml(status)}">${escapeHtml(
      statusLabel(status)
    )}</span>`;
  }

  function statusDotClass(status) {
    if (status === "failed" || status === "interrupted") return "danger";
    if (status === "cancelled") return "warn";
    if (status === "running" || status === "queued" || status === "cancelling") {
      return "scanning";
    }
    return "";
  }

  function scanSummaryText(scan) {
    const summary = (scan && scan.summary) || {};
    if (scan && scan.kind === "discover") {
      const hosts = summary.hostsFound ?? 0;
      return plural(hosts, "host");
    }
    const hosts = summary.hostsFound ?? 0;
    const ports = summary.openPorts ?? 0;
    return `${formatNumber(hosts)}h · ${formatNumber(ports)}p`;
  }

  function stripAnsi(value) {
    return String(value || "").replace(
      // eslint-disable-next-line no-control-regex
      /\u001b\[[0-?]*[ -/]*[@-~]/g,
      ""
    );
  }

  function hostPortCount(host) {
    if (!host) return 0;
    if (Array.isArray(host.ports)) return host.ports.length;
    return Number(host.openPorts) || 0;
  }

  function hostTitle(host) {
    return host.hostname || host.address || "Unknown host";
  }

  function primaryInterface() {
    const interfaces = (state.system && state.system.interfaces) || [];
    return interfaces.find((item) => item.isDefault) || interfaces[0] || null;
  }

  function nmapTool() {
    return (state.system && state.system.tools && state.system.tools.nmap) || {};
  }

  function arpTool() {
    return (state.system && state.system.tools && state.system.tools.arp_scan) || {};
  }

  function setText(id, value) {
    const node = byId(id);
    if (node) node.textContent = value;
  }

  function refreshInventoryMap() {
    state.inventoryByAddress = new Map(
      state.inventory.filter((host) => host && host.address).map((host) => [host.address, host])
    );
  }

  function enrichHost(host) {
    const inventoryHost = state.inventoryByAddress.get(host.address);
    if (!inventoryHost) return host;
    const hostPorts = Array.isArray(host.ports) ? host.ports : [];
    const inventoryPorts = Array.isArray(inventoryHost.ports) ? inventoryHost.ports : [];
    return {
      ...inventoryHost,
      ...host,
      ports: hostPorts.length ? hostPorts : inventoryPorts,
      openPorts: hostPorts.length ? hostPorts.length : inventoryHost.openPorts || 0,
      riskFlags:
        typeof host.riskFlags === "number" ? host.riskFlags : inventoryHost.riskFlags || 0,
      lastSeen: host.lastSeen || inventoryHost.lastSeen,
      firstSeen: host.firstSeen || inventoryHost.firstSeen,
      hostname: host.hostname || inventoryHost.hostname,
      mac: host.mac || inventoryHost.mac,
      vendor: host.vendor || inventoryHost.vendor,
    };
  }

  function classifyDevice(host) {
    const ports = Array.isArray(host.ports) ? host.ports : [];
    const portNumbers = new Set(ports.map((port) => Number(port.port)));
    const haystack = `${host.vendor || ""} ${host.hostname || ""} ${ports
      .map((port) => port.service || "")
      .join(" ")}`.toLowerCase();
    const gateway = primaryInterface()?.gateway;
    if (
      (gateway && host.address === gateway) ||
      portNumbers.has(53) ||
      portNumbers.has(67) ||
      /router|gateway|access point|ubiquiti|unifi|aruba|meraki|ruckus|openwrt|mikrotik|tp-link|netgear|draytek|linksys|eero/.test(
        haystack
      )
    ) {
      return { type: "router", icon: "router" };
    }
    if (
      portNumbers.has(631) ||
      portNumbers.has(9100) ||
      /printer|hewlett|canon|epson|brother/.test(haystack)
    ) {
      return { type: "printer", icon: "printer" };
    }
    if (/desktop|laptop|workstation|thinkpad|macbook/.test(haystack)) {
      return { type: "workstation", icon: "monitor" };
    }
    if (
      ports.some((port) => [22, 80, 443, 445, 8080, 8443, 3306, 5432].includes(Number(port.port))) ||
      /server|synology|qnap|linux|ubuntu|debian|windows server/.test(haystack)
    ) {
      return { type: "server", icon: "server" };
    }
    return { type: "workstation", icon: "monitor" };
  }

  function deviceTypeLabel(type) {
    return (
      {
        router: "AP / router",
        server: "Server",
        printer: "Printer",
        workstation: "Workstation",
      }[type] || "Asset"
    );
  }

  function riskShort(risk) {
    const level = (risk && risk.level) || "info";
    const definition = RISK_WORD[level] || RISK_WORD.info;
    return `<span class="exposure-badge level-${escapeHtml(level)}" title="${escapeHtml(
      (risk && risk.label) || "Open service"
    )}: ${escapeHtml((risk && risk.note) || "")}">${escapeHtml(definition.label)}</span>`;
  }

  /* ---------------------------------------------------------------------
     Bootstrapping and shared renderers
  --------------------------------------------------------------------- */

  async function loadBootstrap({ initial = false } = {}) {
    const data = await api("/api/bootstrap");
    applyBootstrapData(data, { initial });
    return data;
  }

  function applyBootstrapData(data, { initial = false } = {}) {
    state.system = data.system || state.system;
    state.stats = data.stats || state.stats;
    state.inventory = Array.isArray(data.inventory) ? data.inventory : [];
    state.recentScans = Array.isArray(data.recentScans) ? data.recentScans : [];
    refreshInventoryMap();
    renderSystem({ initial });
    renderStats();
    renderRadar();
    renderRecentScans();
    renderHistorySummary();
    renderAssets();
    renderEngineList();
    setText("appVersion", `v${(data.app && data.app.version) || "1.0"}`);
    state.bootstrapped = true;

    const active = data.live && data.live.active;
    if (active && (!state.activeLive || state.activeLive.id !== active.id)) {
      state.activeLive = liveShellFromActive(active);
      state.liveCursor = 0;
      state.liveLogOpen = true;
    }
    renderLiveHeader();
    updateFormAvailability();
    updateHeaderClock();
  }

  async function refreshSharedData({ quiet = true } = {}) {
    try {
      const data = await loadBootstrap({ initial: false });
      const active = data.live && data.live.active;
      if (active && (!state.activeLive || state.activeLive.id !== active.id)) {
        state.activeLive = liveShellFromActive(active);
        state.liveCursor = 0;
        state.liveLogOpen = true;
        renderLiveHeader();
        renderLive();
        updateFormAvailability();
        beginLivePolling();
      }
      if (state.route === "discover") renderDiscovery();
      if (state.route === "assets") renderAssets();
      if (state.route === "ports") renderPortScan();
      if (state.route === "history") {
        void loadHistory({ quiet: true });
      }
      return data;
    } catch (error) {
      if (!quiet) {
        toast("Refresh failed", error.message, "error");
      }
      return null;
    }
  }

  function liveShellFromActive(active) {
    return {
      id: active.id,
      kind: active.kind,
      target: active.target,
      profileLabel: active.kind === "discover" ? "Network discovery" : "Port scan",
      engine: active.engine || (active.kind === "discover" ? "nmap" : "nmap"),
      status: active.status || "queued",
      progress: Number(active.progress) || 0,
      startedAt: active.startedAt || null,
      createdAt: active.createdAt || new Date().toISOString(),
      logs: [],
      logCount: 0,
      summary: {},
      results: null,
      error: null,
      profile: active.profile || "",
    };
  }

  function renderSystem({ initial = false } = {}) {
    const system = state.system;
    if (!system) return;
    const interfaces = system.interfaces || [];
    const iface = primaryInterface();
    const nmap = nmapTool();
    const arp = arpTool();
    const raw = Boolean(system.rawAccess);

    const hostLabel =
      system.hostname && !["unknown", "localhost.localdomain"].includes(String(system.hostname).toLowerCase())
        ? system.hostname
        : "Local workstation";
    setText("nodeName", hostLabel);
    setText(
      "nodeIp",
      iface ? `${iface.address}/${iface.prefix}` : "No active IPv4 interface"
    );
    setText("privBadge", raw ? "raw access" : system.privileged ? "root" : "user");
    byId("privBadge")?.classList.toggle("is-elevated", Boolean(raw));
    setText("discoverIfaceMeta", iface ? iface.name : "—");
    setText("discoverNetMeta", iface ? iface.cidr : "—");
    setText("portModeMeta", raw ? "TCP SYN" : "TCP connect");
    setText("portPrivMeta", raw ? "Available" : "Unavailable");
    setText(
      "nmapMini",
      nmap.available ? nmap.version || "ready" : "not found"
    );
    setText(
      "arpMini",
      arp.available ? (arp.usable ? "raw access" : "cap required") : "not found"
    );
    const nmapMini = byId("nmapMini");
    if (nmapMini) {
      nmapMini.className = `tool-mini-state ${
        nmap.available ? (raw ? "is-ready" : "is-limited") : "is-missing"
      }`;
      nmapMini.title = nmap.path || "Nmap not found on PATH";
    }
    const arpMini = byId("arpMini");
    if (arpMini) {
      arpMini.className = `tool-mini-state ${
        arp.usable ? "is-ready" : arp.available ? "is-limited" : "is-missing"
      }`;
      arpMini.title = arp.path || "arp-scan not found on PATH";
    }
    setText(
      "engineMode",
      nmap.available ? `${nmap.version || "Nmap"} / ${raw ? "raw" : "connect"}` : "nmap missing"
    );

    renderPrivilegeCard();
    renderInterfaceSelect(interfaces);
    renderTargetChips(interfaces, iface);
    lockArpOption();
    configureOsOption(raw);
    setCapabilityCommand();

    const portMode = byId("portModeMeta");
    if (portMode) {
      portMode.textContent = raw ? "TCP SYN" : "TCP connect";
    }

    if (initial || !state.targetsInitialised) {
      const discoverInput = byId("discoverTarget");
      if (discoverInput && !discoverInput.value.trim() && iface) {
        discoverInput.value = iface.cidr;
      }
      state.targetsInitialised = true;
    }
    updateCommandPreviews();
    updateTargetEstimate();
    updateFormAvailability();
  }

  function renderPrivilegeCard() {
    const system = state.system;
    if (!system) return;
    const arp = arpTool();
    const card = byId("privilegeCard");
    const stateNode = byId("privilegeState");
    const copyNode = byId("privilegeCopy");
    const modeNode = byId("privilegeMode");
    if (!card || !stateNode || !copyNode || !modeNode) return;
    card.classList.toggle("is-warning", !arp.usable);
    modeNode.classList.toggle("is-elevated", Boolean(arp.usable));
    if (arp.usable) {
      stateNode.textContent = "Raw packet access available";
      copyNode.textContent =
        "ARP discovery is available. Local devices can include MAC address and vendor details.";
      modeNode.textContent = "enabled";
    } else if (arp.available) {
      stateNode.textContent = "User mode · Nmap fallback active";
      copyNode.textContent =
        "arp-scan is installed but needs CAP_NET_RAW. Auto will use Nmap ping discovery, which does not report MAC addresses.";
      modeNode.textContent = "user mode";
    } else {
      stateNode.textContent = "arp-scan is not installed";
      copyNode.textContent =
        "Auto uses Nmap ping discovery. Install arp-scan and grant raw access to see MAC addresses and vendors.";
      modeNode.textContent = "unavailable";
    }
    const note = byId("arpPrivilegeNote");
    if (note) {
      note.innerHTML = arp.usable
        ? "ARP has raw packet access. Use a specific interface when multiple networks are present."
        : "ARP packet capture needs <span class=\"mono\">CAP_NET_RAW</span>. Auto falls back to Nmap ping without it.";
    }
  }

  function renderInterfaceSelect(interfaces) {
    const select = byId("discoverInterface");
    if (!select) return;
    const current = select.value;
    const options = [
      '<option value="">Auto-select</option>',
      ...interfaces.map(
        (iface) =>
          `<option value="${escapeHtml(iface.name)}">${escapeHtml(iface.name)} — ${escapeHtml(
            iface.address
          )}</option>`
      ),
    ];
    select.innerHTML = options.join("");
    if (current && interfaces.some((iface) => iface.name === current)) {
      select.value = current;
    }
  }

  function renderTargetChips(interfaces, iface) {
    const discoverChips = byId("networkChips");
    if (discoverChips) {
      const seen = new Set();
      const chips = [];
      for (const item of interfaces) {
        if (!item.cidr || seen.has(item.cidr)) continue;
        seen.add(item.cidr);
        chips.push(
          `<button class="chip-button" type="button" data-fill-target="discover" data-target="${escapeHtml(
            item.cidr
          )}" title="Use ${escapeHtml(item.cidr)}">${icon("wifi")}<span>${escapeHtml(
            item.cidr
          )}</span></button>`
        );
      }
      if (!chips.length) {
        chips.push(
          `<button class="chip-button" type="button" data-fill-target="discover" data-target="127.0.0.0/30" title="Use loopback network">${icon(
            "wifi"
          )}<span>127.0.0.0/30</span></button>`
        );
      }
      discoverChips.innerHTML = chips.slice(0, 3).join("");
    }

    const portChips = byId("portTargetChips");
    if (portChips) {
      const suggestions = ["127.0.0.1"];
      if (iface) {
        suggestions.push(iface.address);
        if (iface.gateway) suggestions.push(iface.gateway);
      }
      const unique = [...new Set(suggestions.filter(Boolean))].slice(0, 3);
      portChips.innerHTML = unique
        .map(
          (target) =>
            `<button class="chip-button" type="button" data-fill-target="ports" data-target="${escapeHtml(
              target
            )}" title="Use ${escapeHtml(target)}">${icon("ports")}<span>${escapeHtml(
              target
            )}</span></button>`
        )
        .join("");
    }
  }

  function lockArpOption() {
    const arp = arpTool();
    const label = $('[data-engine-option="arp"]');
    if (!label) return;
    const radio = label.querySelector('input[type="radio"]');
    const strong = label.querySelector(".engine-body strong");
    if (!radio || !strong) return;
    let lock = strong.querySelector(".engine-lock");
    if (!lock) {
      lock = document.createElement("span");
      lock.className = "engine-lock lock-inline";
      lock.innerHTML = `${icon("lock")}<span>cap</span>`;
      strong.appendChild(lock);
    }
    lock.hidden = Boolean(arp.usable);
    radio.disabled = !arp.usable;
    label.classList.toggle("is-locked", !arp.usable);
    label.title = arp.usable
      ? "arp-scan is available for local Layer 2 discovery."
      : arp.available
        ? "arp-scan needs raw packet access. Auto uses Nmap ping instead."
        : "arp-scan is not installed.";
    if (!arp.usable && radio.checked) {
      const auto = $('input[name="discoverEngine"][value="auto"]');
      if (auto) auto.checked = true;
      syncDiscoveryControls();
    }
  }

  function configureOsOption(raw) {
    const osOption = byId("optOs");
    const osRow = byId("osOptionRow");
    const osLock = byId("osLock");
    if (!osOption) return;
    osOption.disabled = !raw;
    if (!raw) osOption.checked = false;
    if (osLock) osLock.hidden = Boolean(raw);
    if (osRow) {
      osRow.title = raw
        ? "Nmap can attempt OS fingerprinting with raw socket access."
        : "OS fingerprinting needs raw socket access (CAP_NET_RAW).";
    }
  }

  function setCapabilityCommand() {
    const code = byId("capCommand");
    if (!code || !state.system) return;
    const nmapPath = (state.system.tools.nmap && state.system.tools.nmap.path) || "/usr/bin/nmap";
    const arpPath =
      (state.system.tools.arp_scan && state.system.tools.arp_scan.path) || "/usr/sbin/arp-scan";
    code.textContent = `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ${nmapPath}
sudo setcap cap_net_raw+eip ${arpPath}`;
  }

  function renderEngineList() {
    const container = byId("engineList");
    if (!container) return;
    const nmap = nmapTool();
    const arp = arpTool();
    const pills = [
      {
        label: nmap.available ? `nmap ${nmap.version || ""}`.trim() : "nmap missing",
        cls: nmap.available ? "is-ready" : "is-missing",
      },
      {
        label: arp.available ? (arp.usable ? "arp-scan raw" : "arp-scan cap required") : "arp-scan missing",
        cls: arp.usable ? "is-ready" : arp.available ? "is-limited" : "is-missing",
      },
      {
        label: "loopback only",
        cls: "is-ready",
      },
    ];
    container.innerHTML = pills
      .map(
        (pill) =>
          `<span class="engine-pill ${pill.cls}"><span class="status-dot"></span>${escapeHtml(
            pill.label
          )}</span>`
      )
      .join("");
  }

  function renderStats() {
    if (!state.stats) return;
    const stats = state.stats;
    setText("statHosts", formatNumber(stats.hosts));
    setText("statOpenPorts", formatNumber(stats.openPorts));
    setText("statRisks", formatNumber(stats.riskFlags));
    setText("statScans", formatNumber(stats.completedScans));
    setText(
      "statLastScan",
      stats.lastScan ? `Last scan ${formatAgo(stats.lastScan)}` : "No scans yet"
    );
    setText(
      "statServiceNote",
      stats.services && stats.services.length
        ? `Top service: ${stats.services[0].name}`
        : "Most recent observation per host"
    );
    renderActivity();
    renderHistorySummary();
  }

  function renderActivity() {
    const container = byId("activityInline");
    if (!container) return;
    const activity = (state.stats && state.stats.activity) || [];
    if (!activity.length) {
      container.innerHTML = "";
      return;
    }
    const max = Math.max(1, ...activity.map((item) => item.count));
    container.innerHTML = activity
      .map((item) => {
        const height = item.count ? 4 + Math.round((item.count / max) * 13) : 2;
        return `<span class="activity-bar ${item.count ? "has-scans" : ""}" style="height:${height}px" title="${escapeHtml(
          `${item.count} ${item.count === 1 ? "scan" : "scans"} · ${item.date}`
        )}"></span>`;
      })
      .join("");
  }

  function renderRecentScans() {
    const container = byId("recentScans");
    if (!container) return;
    if (!state.recentScans.length) {
      container.innerHTML = `<div class="recent-empty">
        <span class="recent-empty-icon">${icon("history")}</span>
        <span><strong>No sweeps in the log yet</strong><span>Start with a discovery sweep or a quick port scan.</span></span>
        <button class="text-link" type="button" data-go="discover" style="margin-left:auto">Start <span aria-hidden="true">→</span></button>
      </div>`;
      return;
    }
    container.innerHTML = state.recentScans
      .map((scan) => {
        const dot = statusDotClass(scan.status);
        const summary = (scan.summary && scan.summary) || {};
        const findings =
          scan.kind === "discover"
            ? plural(summary.hostsFound || 0, "host")
            : `${plural(summary.hostsFound || 0, "host")} · ${plural(
                summary.openPorts || 0,
                "port"
              )}`;
        const title =
          scan.kind === "discover"
            ? `Discover ${scan.target}`
            : `${profileLabel(scan.profile)} on ${scan.target}`;
        return `<button class="recent-row" type="button" data-open-scan="${escapeHtml(
          scan.id
        )}" title="${escapeHtml(title)}">
          <span class="recent-icon ${scan.kind === "ports" ? "is-ports" : ""}">${icon(
            scan.kind === "discover" ? "radar" : "ports"
          )}</span>
          <span class="recent-copy">
            <strong>${escapeHtml(scan.target)}</strong>
            <span>${escapeHtml(profileLabel(scan.profile))} <i class="dot-sep"></i> ${escapeHtml(
              engineLabel(scan)
            )}</span>
          </span>
          <span class="recent-meta">
            <span class="recent-findings">${findings}</span>
            <span class="recent-status"><span class="status-dot tiny ${dot}"></span>${escapeHtml(
              statusLabel(scan.status)
            )}</span>
            <span>${escapeHtml(formatAgo(scan.createdAt))}</span>
          </span>
        </button>`;
      })
      .join("");
  }

  function renderRadar() {
    const nodes = byId("radarNodes");
    const empty = byId("radarEmpty");
    if (!nodes) return;
    const iface = primaryInterface();
    setText("radarCidr", iface ? iface.cidr : "No active IPv4 segment");
    setText("radarInterface", iface ? `${iface.name} · ${iface.address}` : "no interface");
    setText("radarCount", formatNumber(state.inventory.length));
    const visibleHosts = state.inventory.slice(0, 12);
    if (!visibleHosts.length) {
      nodes.innerHTML = "";
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;
    nodes.innerHTML = visibleHosts
      .map((host, index) => {
        let hash = 0;
        for (const character of String(host.address || "")) {
          hash = (hash * 31 + character.charCodeAt(0)) >>> 0;
        }
        const angle = ((hash % 360) * Math.PI) / 180;
        const radius = 13 + ((hash >>> 8) % 28);
        const left = 50 + Math.cos(angle) * radius;
        const top = 50 + Math.sin(angle) * radius;
        const delay = ((index * 0.41) % 2.8).toFixed(2);
        const risky = Number(host.riskFlags) > 0;
        return `<button class="radar-node ${risky ? "has-risk" : ""}" type="button" data-host-address="${escapeHtml(
          host.address
        )}" style="left:${left.toFixed(2)}%;top:${top.toFixed(
          2
        )}%;--delay:${delay}s" aria-label="${escapeHtml(
          `Open ${host.address}${host.hostname ? ` (${host.hostname})` : ""}`
        )}" title="${escapeHtml(
          `${host.hostname || host.address}${host.vendor ? ` · ${host.vendor}` : ""}${
            host.openPorts ? ` · ${host.openPorts} open ports` : ""
          }`
        )}">
          <span class="radar-node-label">${escapeHtml(host.hostname || host.address)}</span>
        </button>`;
      })
      .join("");
  }

  function renderHistorySummary() {
    if (!state.stats) return;
    setText("historyTotal", formatNumber(state.stats.totalScans));
    setText("historyCompleted", formatNumber(state.stats.completedScans));
    setText("historyHosts", formatNumber(state.stats.hosts));
    setText(
      "historyLatest",
      state.stats.lastScan ? formatAgo(state.stats.lastScan) : "—"
    );
  }

  function updateHeaderClock() {
    const target = byId("heroDate");
    if (!target) return;
    target.textContent = new Intl.DateTimeFormat("en", {
      weekday: "short",
      day: "2-digit",
      month: "short",
      year: "numeric",
    }).format(new Date());
  }

  /* ---------------------------------------------------------------------
     Routing
  --------------------------------------------------------------------- */

  function currentRouteFromHash() {
    const match = window.location.hash.match(/^#\/([a-z]+)/);
    if (match && ROUTES.has(match[1])) return match[1];
    return "overview";
  }

  function navigate(route) {
    if (!ROUTES.has(route)) return;
    closeNewScanMenu();
    closeMobileNav();
    if (window.location.hash === `#/${route}`) {
      void applyRoute();
    } else {
      window.location.hash = `#/${route}`;
    }
  }

  async function applyRoute() {
    const route = currentRouteFromHash();
    const previous = state.route;
    if (
      previous &&
      previous !== route &&
      state.activeLive &&
      FINISHED_STATUSES.has(state.activeLive.status)
    ) {
      state.activeLive = null;
      clearLivePolling();
    }
    state.route = route;
    renderLiveHeader();

    $$(".page").forEach((page) => {
      page.classList.toggle("is-active", page.dataset.page === route);
    });
    $$("[data-route]").forEach((link) => {
      const active = link.dataset.route === route;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
    const meta = PAGE_META[route] || PAGE_META.overview;
    setText("pageCrumb", meta.title);
    document.title =
      route === "overview"
        ? "ReconDeck — network reconnaissance, visual"
        : `${meta.document} · ReconDeck`;
    renderLive();
    updateFormAvailability();

    if (!state.bootstrapped) return;

    if (route === "discover") {
      renderDiscovery();
      if (!isCurrentLive("discover")) {
        await ensureLatestScan("discover");
        renderDiscovery();
      }
    } else if (route === "assets") {
      renderAssets();
    } else if (route === "ports") {
      renderPortScan();
      if (!isCurrentLive("ports")) {
        await ensureLatestScan("ports");
        renderPortScan();
      }
    } else if (route === "history") {
      await loadHistory();
    }
    if (previous !== route) {
      window.scrollTo({ top: 0, behavior: "auto" });
    }
  }

  async function ensureLatestScan(kind, { force = false } = {}) {
    if (!state.bootstrapped) return null;
    if (isCurrentLive(kind)) return null;
    if (state.latestLoading[kind]) return null;
    if (state.latestLoaded[kind] && !force) return null;
    state.latestLoading[kind] = true;
    try {
      const list = await api(`/api/scans?kind=${encodeURIComponent(kind)}&status=completed&limit=1`);
      const latest = list.scans && list.scans[0];
      if (latest) {
        const detail = await api(`/api/scans/${encodeURIComponent(latest.id)}?after=0`);
        if (kind === "discover") state.discoveryScan = detail.scan;
        else state.portScan = detail.scan;
      } else if (force) {
        if (kind === "discover") state.discoveryScan = null;
        else state.portScan = null;
      }
    } catch (error) {
      console.error("Latest scan load failed", error);
    } finally {
      state.latestLoading[kind] = false;
      state.latestLoaded[kind] = true;
    }
    return kind === "discover" ? state.discoveryScan : state.portScan;
  }

  function isCurrentLive(kind) {
    return Boolean(
      state.activeLive &&
        state.activeLive.kind === kind &&
        ACTIVE_STATUSES.has(state.activeLive.status)
    );
  }

  /* ---------------------------------------------------------------------
     Command previews and form state
  --------------------------------------------------------------------- */

  function selectedDiscoveryEngine() {
    const checked = $('input[name="discoverEngine"]:checked');
    return checked ? checked.value : "auto";
  }

  function selectedProfile() {
    const checked = $('input[name="scanProfile"]:checked');
    return checked ? checked.value : "quick";
  }

  function updateDiscoveryPreview() {
    const target = (byId("discoverTarget")?.value || "").trim();
    const engine = selectedDiscoveryEngine();
    const ifaceSelect = byId("discoverInterface");
    const iface = primaryInterface();
    const interfaceName =
      (ifaceSelect && ifaceSelect.value) || (iface && iface.name) || "<interface>";
    const arp = arpTool();
    let command;
    if (engine === "arp") {
      command = `arp-scan --interface=${interfaceName} ${target || "<network>"}`;
    } else if (engine === "nmap") {
      command = `nmap -sn -T4 --stats-every 2s ${target || "<network>"}`;
    } else {
      const local = targetIsLocalNetwork(target);
      if (arp.usable && local) {
        command = `arp-scan --interface=${interfaceName} ${target || "<network>"}`;
      } else {
        command = `nmap -sn -T4 --stats-every 2s ${target || "<network>"}`;
      }
    }
    setText("discoverCommandPreview", command);
  }

  function updatePortPreview() {
    const target = (byId("portTarget")?.value || "").trim();
    const profile = selectedProfile();
    const raw = Boolean(state.system && state.system.rawAccess);
    const pieces = ["nmap", raw ? "-sS" : "-sT"];
    const timing = byId("optTiming")?.value || "normal";
    const timingFlag = { polite: "-T3", normal: "-T4", aggressive: "-T5" }[timing] || "-T4";
    pieces.push(timingFlag);
    const limit = PROFILE_LIMITS[profile];
    if (profile === "quick") pieces.push("--top-ports", "100");
    if (profile === "standard") pieces.push("--top-ports", "1000");
    if (profile === "full") pieces.push("-p-");
    if (profile === "services" || profile === "safe") {
      pieces.push("--top-ports", "1000");
    }
    if (profile === "custom") {
      const ports = (byId("customPorts")?.value || "").trim() || "<ports>";
      pieces.push("-p", ports);
    }
    const serviceForced = profile === "services" || profile === "safe";
    if (serviceForced || byId("optService")?.checked) {
      pieces.push("-sV", "--version-light");
    }
    if (profile === "safe") {
      pieces.push(`--script=${SAFE_AUDIT_SCRIPTS}`);
    } else if (byId("optScripts")?.checked) {
      pieces.push("--script=default");
    }
    if (byId("optOs")?.checked && raw) pieces.push("-O", "--osscan-limit");
    if (byId("optSkipPing")?.checked) pieces.push("-Pn");
    pieces.push("--stats-every", "1s", target || "<target>");
    setText("portCommandPreview", pieces.join(" "));
    updateTargetEstimate();
  }

  function updateCommandPreviews() {
    updateDiscoveryPreview();
    updatePortPreview();
  }

  function syncDiscoveryControls() {
    $$("[data-engine-option]").forEach((label) => {
      const radio = label.querySelector('input[type="radio"]');
      label.classList.toggle("is-selected", Boolean(radio && radio.checked));
    });
    updateDiscoveryPreview();
  }

  function syncPortControls({ changedProfile = false } = {}) {
    $$("[data-profile-option]").forEach((label) => {
      const radio = label.querySelector('input[type="radio"]');
      label.classList.toggle("is-selected", Boolean(radio && radio.checked));
    });
    const profile = selectedProfile();
    const customWrap = byId("customPortsWrap");
    if (customWrap) customWrap.hidden = profile !== "custom";
    const serviceToggle = byId("optService");
    const forcedService = profile === "services" || profile === "safe";
    if (serviceToggle) {
      if (forcedService) {
        serviceToggle.checked = true;
        serviceToggle.disabled = true;
      } else {
        serviceToggle.disabled = false;
        if (changedProfile) serviceToggle.checked = false;
      }
    }
    const scriptsToggle = byId("optScripts");
    if (scriptsToggle) {
      const safeProfile = profile === "safe";
      scriptsToggle.disabled = safeProfile;
      if (safeProfile) scriptsToggle.checked = false;
      const row = scriptsToggle.closest(".switch-row");
      if (row) {
        row.title = safeProfile
          ? "Safe audit already uses a curated allowlist of non-intrusive NSE scripts."
          : "Nmap default scripts can perform active checks. Only use with permission.";
      }
    }
    updatePortPreview();
  }

  function updateFormAvailability() {
    const busy = isCurrentLiveAny() || Boolean(state.startPending);
    const nmapAvailable = Boolean(nmapTool().available);
    const configs = [
      {
        id: "discoverSubmit",
        kind: "discover",
        defaultLabel: "Start discovery",
        activeLabel: "Sweeping network",
      },
      {
        id: "portSubmit",
        kind: "ports",
        defaultLabel: "Launch port scan",
        activeLabel: "Scanning ports",
      },
    ];
    for (const config of configs) {
      const button = byId(config.id);
      if (!button) continue;
      const ownActive =
        (state.activeLive &&
          state.activeLive.kind === config.kind &&
          ACTIVE_STATUSES.has(state.activeLive.status)) ||
        state.startPending === config.kind;
      const label = button.querySelector(".btn-label");
      button.classList.toggle("is-loading", Boolean(ownActive));
      button.disabled = busy || !nmapAvailable;
      if (label) {
        label.textContent = ownActive ? config.activeLabel : config.defaultLabel;
      }
      button.title = !nmapAvailable
        ? "Nmap is required before scans can run."
        : busy
          ? "Wait for the current scan to finish or stop it."
          : "";
    }
    const discoveryInput = byId("discoverTarget");
    const portInput = byId("portTarget");
    if (discoveryInput) discoveryInput.disabled = !nmapAvailable;
    if (portInput) portInput.disabled = !nmapAvailable;
  }

  function isCurrentLiveAny() {
    return Boolean(state.activeLive && ACTIVE_STATUSES.has(state.activeLive.status));
  }

  function updateTargetEstimate() {
    const estimate = byId("targetEstimate");
    if (!estimate) return;
    const target = (byId("portTarget")?.value || "").trim();
    if (!target) {
      estimate.classList.remove("is-warning");
      estimate.innerHTML = `<span class="mono">SCOPE</span><span>No target selected</span>`;
      return;
    }
    const profile = selectedProfile();
    const limit = PROFILE_LIMITS[profile] || PROFILE_LIMITS.quick;
    const hostCount = estimateHostCount(target);
    if (hostCount === null) {
      estimate.classList.add("is-warning");
      estimate.innerHTML = `<span class="mono">SCOPE</span><span>Check the target format — expected IPv4, CIDR, range, or hostname</span>`;
      return;
    }
    let portCount = limit.portCount;
    if (profile === "custom") {
      portCount = estimatePortCount(byId("customPorts")?.value || "");
    }
    let message = `${plural(hostCount, "address", "addresses")} · ${
      portCount === null
        ? "choose ports"
        : portCount
          ? `${formatNumber(portCount)} ports`
          : "no valid ports"
    }`;
    let warning = hostCount > limit.maxHosts;
    if (
      profile === "custom" &&
      portCount &&
      portCount > 5000 &&
      hostCount > 16
    ) {
      warning = true;
    }
    if (warning) {
      message = `${message} — above the ${limit.maxHosts}-address profile limit`;
    }
    estimate.classList.toggle("is-warning", warning);
    estimate.innerHTML = `<span class="mono">SCOPE</span><span>${escapeHtml(message)}</span>`;
  }

  function estimateHostCount(target) {
    const trimmed = target.trim();
    if (!trimmed) return 0;
    const cidr = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
    if (cidr) {
      if (!isValidOctets(cidr[1]) || Number(cidr[2]) > 32) return null;
      return Math.pow(2, 32 - Number(cidr[2]));
    }
    const fullRange = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (fullRange) {
      if (!isValidOctets(fullRange[1]) || !isValidOctets(fullRange[2])) return null;
      const start = ipv4ToInt(fullRange[1]);
      const end = ipv4ToInt(fullRange[2]);
      if (start === null || end === null || end < start) return null;
      return end - start + 1;
    }
    const shortRange = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})$/);
    if (shortRange) {
      if (!isValidOctets(shortRange[1]) || Number(shortRange[2]) > 255) return null;
      const start = ipv4ToInt(shortRange[1]);
      const last = Number(shortRange[2]);
      if (start === null) return null;
      const startOctet = Number(shortRange[1].split(".")[3]);
      if (last < startOctet) return null;
      return last - startOctet + 1;
    }
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) {
      return isValidOctets(trimmed) ? 1 : null;
    }
    if (/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(trimmed)) return 1;
    return null;
  }

  function isValidOctets(value) {
    return value.split(".").every((part) => {
      if (!/^\d{1,3}$/.test(part)) return false;
      const number = Number(part);
      return number >= 0 && number <= 255;
    });
  }

  function ipv4ToInt(value) {
    if (!isValidOctets(value)) return null;
    return value.split(".").reduce((result, part) => result * 256 + Number(part), 0);
  }

  function estimatePortCount(spec) {
    if (!spec.trim()) return 0;
    let total = 0;
    for (const chunk of spec.replace(/\s+/g, "").split(",")) {
      if (!chunk) return 0;
      if (chunk.includes("-")) {
        const [start, end] = chunk.split("-").map(Number);
        if (!Number.isInteger(start) || !Number.isInteger(end) || end < start) return 0;
        total += end - start + 1;
      } else {
        const port = Number(chunk);
        if (!Number.isInteger(port) || port < 1 || port > 65535) return 0;
        total += 1;
      }
    }
    return total;
  }

  function targetIsLocalNetwork(target) {
    if (!target) return false;
    const first = target.split(/[\/\-]/)[0];
    const address = ipv4ToInt(first);
    if (address === null) return false;
    const interfaces = (state.system && state.system.interfaces) || [];
    for (const item of interfaces) {
      if (!item.cidr) continue;
      const [network, prefix] = item.cidr.split("/");
      const networkInt = ipv4ToInt(network);
      const prefixNumber = Number(prefix);
      if (networkInt === null || !Number.isInteger(prefixNumber)) continue;
      const size = Math.pow(2, 32 - prefixNumber);
      if (address >= networkInt && address < networkInt + size) return true;
    }
    return false;
  }

  /* ---------------------------------------------------------------------
     Discovery rendering
  --------------------------------------------------------------------- */

  function filteredDiscoveryHosts() {
    let hosts;
    let source = "inventory";
    if (state.discoveryScan && state.discoveryScan.results) {
      hosts = (state.discoveryScan.results.hosts || []).map(enrichHost);
      source = "scan";
    } else {
      hosts = state.inventory.map(enrichHost);
    }
    state.currentDiscoveryHosts = hosts;
    return { hosts, source };
  }

  function renderDiscovery() {
    const results = byId("discoveryResults");
    if (!results) return;
    const { hosts, source } = filteredDiscoveryHosts();
    const scan = state.discoveryScan;
    const query = state.filters.discovery.trim().toLowerCase();
    const filtered = query
      ? hosts.filter((host) => {
          const serviceText = (host.ports || []).map((port) => port.service || "").join(" ");
          return `${host.address || ""} ${host.hostname || ""} ${host.mac || ""} ${
            host.vendor || ""
          } ${serviceText}`
            .toLowerCase()
            .includes(query);
        })
      : hosts;
    setText("discoveryCount", formatNumber(filtered.length));
    const sub = byId("discoverySub");
    if (sub) {
      if (state.activeLive && state.activeLive.kind === "discover" && ACTIVE_STATUSES.has(state.activeLive.status)) {
        sub.textContent = "Discovery probe in progress — this list will update when it completes.";
      } else if (source === "scan" && scan) {
        sub.textContent = `${scan.target} · ${engineLabel(scan)} · ${
          scan.finishedAt ? formatAgo(scan.finishedAt) : "completed"
        }`;
      } else if (hosts.length) {
        sub.textContent = "Known hosts from your local scan history. Run a discovery sweep to refresh.";
      } else {
        sub.textContent = "Your latest discovery results will land here.";
      }
    }

    const foot = byId("discoveryFoot");
    if (foot) {
      foot.hidden = !(scan && source === "scan");
      if (!foot.hidden && scan) {
        setText(
          "discoveryScanMeta",
          `${engineLabel(scan)} · ${formatDuration(scan.duration)} · ${formatDateTime(
            scan.finishedAt
          )}`
        );
      }
    }

    if (!hosts.length) {
      results.innerHTML = discoveryEmptyHtml(Boolean(scan));
      return;
    }
    if (!filtered.length) {
      results.innerHTML = `<div class="filter-empty">
        ${icon("search")}
        <strong>No devices match “${escapeHtml(state.filters.discovery)}”</strong>
        <span>Try an address, vendor, MAC, or service name.</span>
      </div>`;
      return;
    }
    const limited = filtered.slice(0, 150);
    results.innerHTML = `<div class="device-table">
      <div class="device-table-head">
        <span>Device</span><span>MAC / vendor</span><span>Open ports</span><span>Last seen</span><span></span>
      </div>
      ${limited.map(discoveryRowHtml).join("")}
      ${
        filtered.length > limited.length
          ? `<p class="microcopy" style="padding:10px 0">Showing ${limited.length} of ${formatNumber(
              filtered.length
            )} devices. Refine the filter to narrow the view.</p>`
          : ""
      }
    </div>`;
  }

  function discoveryEmptyHtml(scanned) {
    return `<div class="empty-state" id="discoveryEmpty">
      <div class="empty-orbit" aria-hidden="true"><span></span><span></span><i></i></div>
      <p class="panel-kicker">${
        scanned ? "No response" : "Awaiting signal"
      }</p>
      <h3>${scanned ? "No devices answered" : "No devices mapped yet"}</h3>
      <p>${
        scanned
          ? "The last discovery completed without finding hosts in that range. Some networks filter ARP or ICMP probes — try a port scan with “treat hosts as online” instead."
          : "Choose a network on the left and start a discovery sweep. Local devices will appear here with address, vendor, and open ports."
      }</p>
      <button class="btn btn-secondary" type="button" data-focus="discoverTarget">${
        scanned ? "Adjust the sweep" : "Configure a sweep"
      } ${icon("arrow-right")}</button>
    </div>`;
  }

  function discoveryRowHtml(host) {
    const device = classifyDevice(host);
    const ports = hostPortCount(host);
    const ago = formatAgo(host.lastSeen || (state.discoveryScan && state.discoveryScan.finishedAt));
    const name = host.hostname || (host.hostnames && host.hostnames[0]) || "Hostname not resolved";
    return `<button class="device-row" type="button" data-host-address="${escapeHtml(
      host.address
    )}" aria-label="${escapeHtml(`Open details for ${host.address}`)}">
      <span class="device-main">
        <span class="device-glyph is-${device.type}">${icon(device.icon)}</span>
        <span class="device-name">
          <strong>${escapeHtml(host.address)}</strong>
          <small>${escapeHtml(name)}</small>
        </span>
      </span>
      <span class="device-vendor">
        ${escapeHtml(host.vendor || "Vendor unavailable")}
        <small>${escapeHtml(host.mac || "No MAC address")}</small>
      </span>
      <span class="port-count">${formatNumber(ports)}<small>open</small></span>
      <span class="device-time" title="${escapeHtml(formatDateTime(host.lastSeen))}">${escapeHtml(
        ago
      )}</span>
      ${icon("chevron-right", "device-go")}
    </button>`;
  }

  function findHost(address) {
    const fromCurrent = state.currentDiscoveryHosts.find((host) => host.address === address);
    if (fromCurrent) return fromCurrent;
    const fromInventory = state.inventory.find((host) => host.address === address);
    if (fromInventory) return enrichHost(fromInventory);
    return null;
  }

  /* ---------------------------------------------------------------------
     Assets and attack surface
  --------------------------------------------------------------------- */

  function renderAssets() {
    if (!byId("assetList")) return;
    renderAssetSummary();
    syncAssetTabs();
    renderAssetList();
    renderAttackSurface();
  }

  function renderAssetSummary() {
    const assets = state.inventory || [];
    const aps = assets.filter((host) => classifyDevice(host).type === "router").length;
    const openPorts = assets.reduce((total, host) => total + hostPortCount(host), 0);
    const flags = assets.reduce((total, host) => total + (Number(host.riskFlags) || 0), 0);
    setText("assetStatTotal", formatNumber(assets.length));
    setText("assetStatAps", formatNumber(aps));
    setText("assetStatPorts", formatNumber(openPorts));
    setText("assetStatFlags", formatNumber(flags));
    setText("assetMetaSource", assets.length ? `${formatNumber(assets.length)} observed` : "Local evidence");
  }

  function syncAssetTabs() {
    const inventory = state.assetTab !== "surface";
    const inventoryView = byId("assetInventoryView");
    const surfaceView = byId("assetSurfaceView");
    if (inventoryView) inventoryView.hidden = !inventory;
    if (surfaceView) surfaceView.hidden = inventory;
    $$("[data-asset-tab]").forEach((button) => {
      const active = button.dataset.assetTab === state.assetTab;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", String(active));
    });
    $$("[data-asset-filter]").forEach((button) => {
      const active = button.dataset.assetFilter === state.assetFilter;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-pressed", String(active));
    });
  }

  function setAssetTab(tab) {
    if (!["inventory", "surface"].includes(tab)) return;
    state.assetTab = tab;
    if (tab === "surface") state.assetCategory = null;
    syncAssetTabs();
    renderAssets();
  }

  function setAssetFilter(filter) {
    state.assetFilter = ["all", "aps", "servers", "review", "unscanned"].includes(filter)
      ? filter
      : "all";
    state.assetCategory = null;
    renderAssets();
  }

  function assetSearchText(host) {
    const ports = host.ports || [];
    return `${host.address || ""} ${host.hostname || ""} ${host.mac || ""} ${
      host.vendor || ""
    } ${ports
      .map(
        (port) =>
          `${port.port || ""} ${port.protocol || ""} ${port.service || ""} ${
            port.product || ""
          } ${port.version || ""} ${(port.risk && port.risk.categoryLabel) || ""}`
      )
      .join(" ")}`.toLowerCase();
  }

  function filteredAssets() {
    const query = state.assetSearch.trim().toLowerCase();
    let assets = state.inventory.map((host) => ({
      host,
      device: classifyDevice(host),
    }));
    if (state.assetFilter === "aps") {
      assets = assets.filter((entry) => entry.device.type === "router");
    } else if (state.assetFilter === "servers") {
      assets = assets.filter((entry) => entry.device.type === "server");
    } else if (state.assetFilter === "review") {
      assets = assets.filter((entry) => Number(entry.host.riskFlags) > 0);
    } else if (state.assetFilter === "unscanned") {
      assets = assets.filter((entry) => !entry.host.lastPortScanAt);
    }
    if (state.assetCategory) {
      assets = assets.filter((entry) =>
        (entry.host.ports || []).some(
          (port) => ((port.risk && port.risk.category) || "other") === state.assetCategory
        )
      );
    }
    if (query) {
      assets = assets.filter((entry) => assetSearchText(entry.host).includes(query));
    }
    return assets;
  }

  function renderAssetList() {
    const container = byId("assetList");
    if (!container) return;
    const head = $(".asset-list-head");
    const assets = filteredAssets();
    const context = byId("assetActiveContext");
    if (context) {
      if (state.assetCategory) {
        const meta = SURFACE_CATEGORIES.find((item) => item.key === state.assetCategory);
        context.hidden = false;
        context.innerHTML = `<span class="asset-context-label">${icon(
          meta ? meta.icon : "layers"
        )} Filtered to ${escapeHtml(meta ? meta.label : state.assetCategory)}</span>
          <button class="chip-button" type="button" data-clear-asset-category>${icon(
            "x"
          )} Clear category</button>`;
      } else {
        context.hidden = true;
        context.innerHTML = "";
      }
    }
    setText("assetListMeta", `${plural(assets.length, "asset")} in view`);
    if (!state.inventory.length) {
      if (head) head.hidden = true;
      container.innerHTML = `<div class="empty-state asset-empty">
        <div class="empty-orbit" aria-hidden="true"><span></span><span></span><i></i></div>
        <p class="panel-kicker">No evidence yet</p>
        <h3>No assets observed</h3>
        <p>Run a local discovery sweep. Each access point, router, and host you find will get its own asset record and port context here.</p>
        <button class="btn btn-secondary" type="button" data-go="discover">Discover the network ${icon(
          "arrow-right"
        )}</button>
      </div>`;
      return;
    }
    if (!assets.length) {
      if (head) head.hidden = true;
      container.innerHTML = `<div class="filter-empty">${icon(
        "search"
      )}<strong>No assets match this view</strong><span>Clear the filter or try a different search.</span></div>`;
      return;
    }
    if (head) head.hidden = false;
    container.innerHTML = assets
      .map(({ host, device }) => assetRowHtml(host, device))
      .join("");
  }

  function assetRowHtml(host, device) {
    const ports = host.ports || [];
    const visiblePorts = ports.slice(0, 5);
    const extraPorts = Math.max(0, ports.length - visiblePorts.length);
    const stats = host.portStats;
    const scannedLabel = host.lastPortScanAt
      ? `${formatAgo(host.lastPortScanAt)}`
      : "Not port-scanned";
    const coverage = stats
      ? `${formatNumber(stats.open || 0)} open · ${formatNumber(stats.scanned || 0)} scanned`
      : ports.length
        ? `${formatNumber(ports.length)} known open · coverage n/a`
        : "No coverage yet";
    let portCells = "";
    if (visiblePorts.length) {
      portCells = visiblePorts.map(assetPortChip).join("");
      if (extraPorts) {
        portCells += `<span class="asset-port-more">+${formatNumber(extraPorts)}</span>`;
      }
    } else if (host.lastPortScanAt) {
      portCells = `<span class="asset-no-ports">${icon(
        "check"
      )} No open ports observed</span>`;
    } else {
      portCells = `<span class="asset-unscanned">${icon(
        "ports"
      )} Scan to map this asset</span>`;
    }
    let signals;
    if (Number(host.riskFlags) > 0) {
      const high = ports.filter(
        (port) => port.risk && port.risk.level === "high"
      ).length;
      signals = `<span class="tag ${high ? "danger" : "amber"}">${plural(
        host.riskFlags,
        "signal"
      )}</span>`;
    } else if (ports.length) {
      signals = '<span class="tag">Low only</span>';
    } else if (host.lastPortScanAt) {
      signals = '<span class="tag">No open ports</span>';
    } else {
      signals = '<span class="tag amber">Unscanned</span>';
    }
    return `<button class="asset-row" type="button" data-host-address="${escapeHtml(
      host.address
    )}" aria-label="${escapeHtml(`Open asset ${host.address}`)}">
      <span class="asset-ident">
        <span class="device-glyph is-${device.type}">${icon(device.icon)}</span>
        <span class="asset-name">
          <strong>${escapeHtml(host.address)}</strong>
          <small>${escapeHtml(host.hostname || host.mac || "Hostname not resolved")}</small>
        </span>
      </span>
      <span class="asset-type-cell">
        <span class="asset-type-badge">${escapeHtml(deviceTypeLabel(device.type))}</span>
        <small>${escapeHtml(host.vendor || (host.mac ? host.mac : "Vendor unavailable"))}</small>
      </span>
      <span class="asset-ports-cell">${portCells}</span>
      <span class="asset-coverage-cell">
        <strong>${escapeHtml(coverage)}</strong>
        <small>${escapeHtml(scannedLabel)}</small>
      </span>
      <span class="asset-signal-cell">${signals}</span>
      <span class="asset-row-open">${icon("chevron-right", "device-go")}</span>
    </button>`;
  }

  function assetPortChip(port) {
    const risk = port.risk || {};
    const level = risk.level || "info";
    const serviceName = port.service || "unknown";
    return `<span class="asset-port-chip level-${escapeHtml(level)}" title="${escapeHtml(
      `${port.port}/${port.protocol || "tcp"} ${serviceName}${
        risk.label ? ` · ${risk.label}` : ""
      }`
    )}"><strong>${escapeHtml(port.port)}</strong><small>${escapeHtml(
      serviceName
    )}</small>${risk.cleartext ? '<i title="Cleartext service">C</i>' : ""}</span>`;
  }

  function buildSurfaceGroups() {
    const groups = new Map(
      SURFACE_CATEGORIES.map((category) => [
        category.key,
        { category, items: [], hosts: new Map() },
      ])
    );
    for (const host of state.inventory) {
      for (const port of host.ports || []) {
        const risk = port.risk || {};
        const key = groups.has(risk.category) ? risk.category : "other";
        const group = groups.get(key);
        group.items.push({ host, port });
        group.hosts.set(host.address, host);
      }
    }
    return [...groups.values()].filter((group) => group.items.length);
  }

  function renderAttackSurface() {
    const groups = buildSurfaceGroups();
    const categoryContainer = byId("surfaceCategories");
    const priority = byId("surfacePriority");
    if (!categoryContainer || !priority) return;
    const hosts = state.inventory;
    const hostsWithSignals = hosts.filter((host) => Number(host.riskFlags) > 0);
    let highSignals = 0;
    let cleartext = 0;
    for (const host of hosts) {
      for (const port of host.ports || []) {
        const risk = port.risk || {};
        if (risk.level === "high") highSignals += 1;
        if (risk.cleartext) cleartext += 1;
      }
    }
    setText("surfaceStatHosts", formatNumber(hostsWithSignals.length));
    setText("surfaceStatHigh", formatNumber(highSignals));
    setText("surfaceStatCleartext", formatNumber(cleartext));
    setText(
      "surfaceStatUnscanned",
      formatNumber(hosts.filter((host) => !host.lastPortScanAt).length)
    );

    if (!groups.length) {
      categoryContainer.innerHTML = `<div class="surface-empty">
        <div class="empty-orbit" aria-hidden="true"><span></span><span></span><i></i></div>
        <p class="panel-kicker">No exposed services mapped</p>
        <h3>No attack surface to group yet</h3>
        <p>Discovery finds assets. A port scan is what populates the categories above — start with a quick sweep of one asset from the inventory.</p>
        <button class="btn btn-secondary" type="button" data-asset-tab-jump="inventory">Open inventory ${icon(
          "arrow-right"
        )}</button>
      </div>`;
    } else {
      categoryContainer.innerHTML = groups
        .map((group) => {
          const { category } = group;
          const uniqueHosts = [...group.hosts.values()].slice(0, 4);
          const highCount = group.items.filter(
            (item) => item.port.risk && item.port.risk.level === "high"
          ).length;
          return `<button class="surface-category" type="button" data-surface-category="${escapeHtml(
            category.key
          )}" aria-label="Filter inventory by ${escapeHtml(category.label)}">
            <span class="surface-category-head">
              <span class="surface-category-icon">${icon(category.icon)}</span>
              <span class="surface-category-name">${escapeHtml(category.label)}</span>
              ${highCount ? `<span class="tag danger">${formatNumber(highCount)} high</span>` : ""}
              <span class="surface-category-count">${formatNumber(group.items.length)}</span>
            </span>
            <span class="surface-category-blurb">${escapeHtml(category.blurb)}</span>
            <span class="surface-category-hosts">
              ${uniqueHosts
                .map((host) => {
                  const hostPorts = group.items.filter((item) => item.host.address === host.address);
                  return `<span class="surface-host-chip"><strong>${escapeHtml(
                    host.address
                  )}</strong>${hostPorts
                    .slice(0, 3)
                    .map(
                      (item) =>
                        `<span>${escapeHtml(item.port.port)}/${escapeHtml(
                          item.port.service || "?"
                        )}</span>`
                    )
                    .join("")}</span>`;
                })
                .join("")}
              ${group.hosts.size > uniqueHosts.length ? `<span class="surface-more">+${group.hosts.size - uniqueHosts.length} assets</span>` : ""}
            </span>
            <span class="surface-category-foot">${plural(
              group.hosts.size,
              "asset"
            )} · View in inventory ${icon("arrow-right")}</span>
          </button>`;
        })
        .join("");
    }

    const priorityHosts = [...hosts]
      .filter((host) => (host.ports || []).length || !host.lastPortScanAt)
      .sort((a, b) => {
        const flagDiff = (Number(b.riskFlags) || 0) - (Number(a.riskFlags) || 0);
        if (flagDiff) return flagDiff;
        return (b.ports || []).length - (a.ports || []).length;
      })
      .slice(0, 5);
    if (!priorityHosts.length) {
      priority.innerHTML = `<div class="surface-priority-empty">No assets with ports to review yet.</div>`;
    } else {
      priority.innerHTML = priorityHosts
        .map((host) => {
          const device = classifyDevice(host);
          const flags = Number(host.riskFlags) || 0;
          const ports = (host.ports || []).slice(0, 3);
          return `<button class="surface-priority-row" type="button" data-host-address="${escapeHtml(
            host.address
          )}">
            <span class="device-glyph is-${device.type}">${icon(device.icon)}</span>
            <span class="surface-priority-copy">
              <strong>${escapeHtml(host.address)}</strong>
              <small>${escapeHtml(
                host.hostname || (host.lastPortScanAt ? "No hostname" : "Not port-scanned")
              )}</small>
            </span>
            <span class="surface-priority-ports">
              ${
                ports.length
                  ? ports
                      .map(
                        (port) =>
                          `<span class="mini-port level-${escapeHtml(
                            (port.risk && port.risk.level) || "info"
                          )}">${escapeHtml(port.port)}</span>`
                      )
                      .join("")
                  : `<span class="asset-unscanned">${icon("ports")} not scanned</span>`
              }
            </span>
            ${
              flags
                ? `<span class="tag ${
                    (host.ports || []).some(
                      (port) => port.risk && port.risk.level === "high"
                    )
                      ? "danger"
                      : "amber"
                  }">${plural(flags, "signal")}</span>`
                : `<span class="tag">${
                    host.lastPortScanAt
                      ? (host.ports || []).length
                        ? "Low only"
                        : "No open ports"
                      : "Unscanned"
                  }</span>`
            }
            ${icon("chevron-right", "device-go")}
          </button>`;
        })
        .join("");
    }
  }

  async function downloadInventory(format) {
    closeAllExportMenus();
    try {
      const response = await fetch(
        `/api/inventory/export?format=${encodeURIComponent(format)}`,
        {
          headers: { "X-ReconDeck-Token": API_TOKEN },
          cache: "no-store",
        }
      );
      if (!response.ok) {
        let message = `Export failed (HTTP ${response.status}).`;
        try {
          const payload = await response.json();
          if (payload && payload.error) message = payload.error;
        } catch (_) {
          /* Use the generic message. */
        }
        throw new Error(message);
      }
      const blob = await response.blob();
      const disposition = response.headers.get("content-disposition") || "";
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const filename = match ? match[1] : `recondeck-inventory.${format}`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1500);
      toast("Inventory exported", `${filename} was saved by your browser.`, "success");
    } catch (error) {
      toast("Inventory export failed", error.message, "error");
    }
  }

  /* ---------------------------------------------------------------------
     Port scan rendering
  --------------------------------------------------------------------- */

  function filteredPortHosts(scan) {
    const query = state.filters.ports.trim().toLowerCase();
    const hosts = (scan.results && scan.results.hosts) || [];
    if (!query) return { hosts, total: hosts.length };
    const filtered = [];
    for (const host of hosts) {
      const hostText = `${host.address || ""} ${host.hostname || ""} ${host.vendor || ""}`.toLowerCase();
      const hostMatches = hostText.includes(query);
      const ports = (host.ports || []).filter((port) => {
        const text = `${port.port || ""} ${port.protocol || ""} ${port.service || ""} ${
          port.product || ""
        } ${port.version || ""} ${(port.risk && port.risk.label) || ""}`.toLowerCase();
        return text.includes(query);
      });
      if (hostMatches) filtered.push(host);
      else if (ports.length) filtered.push({ ...host, ports, filteredPorts: true });
    }
    return { hosts: filtered, total: hosts.length };
  }

  function renderPortScan() {
    const container = byId("portResults");
    if (!container) return;
    const scan = state.portScan;
    if (!scan) {
      container.innerHTML = portEmptyHtml();
      return;
    }
    if (!scan.results) {
      container.innerHTML = portUnavailableHtml(scan);
      return;
    }
    const summary = scan.summary || scan.results.summary || {};
    const hosts = scan.results.hosts || [];
    const { hosts: filteredHosts } = filteredPortHosts(scan);
    const attention =
      summary.attention ??
      hosts.reduce(
        (total, host) =>
          total +
          (host.ports || []).filter((port) => ["high", "medium"].includes(port.risk && port.risk.level))
            .length,
        0
      );
    const logText = stripAnsi(
      Array.isArray(scan.logs) ? scan.logs.join("\n") : scan.log || ""
    );

    container.innerHTML = `<div class="port-results-container">
      <header class="scan-result-head">
        <div class="scan-result-titles">
          <p class="panel-kicker">Port scan · ${escapeHtml(engineLabel(scan))}</p>
          <h2>${escapeHtml(scan.target)}</h2>
          <div class="result-meta">
            <span class="tag accent">${escapeHtml(profileLabel(scan.profile))}</span>
            ${statusPill(scan.status)}
            <span class="tag">${escapeHtml(formatAgo(scan.finishedAt || scan.createdAt))}</span>
          </div>
        </div>
        <div class="result-actions">
          <button class="btn btn-secondary" type="button" data-open-scan="${escapeHtml(
            scan.id
          )}">${icon("list")} Details</button>
          <div class="export-menu-wrap">
            <button class="btn btn-secondary" type="button" data-export-toggle aria-expanded="false">${icon(
              "download"
            )} Export ${icon("chevron-down")}</button>
            <div class="export-menu" hidden>
              <button type="button" data-download="${escapeHtml(scan.id)}" data-format="json">${icon(
                "copy"
              )} JSON <span class="mono">.json</span></button>
              <button type="button" data-download="${escapeHtml(scan.id)}" data-format="csv">${icon(
                "list"
              )} Spreadsheet <span class="mono">.csv</span></button>
              <button type="button" data-download="${escapeHtml(scan.id)}" data-format="txt">${icon(
                "terminal"
              )} Raw log <span class="mono">.txt</span></button>
            </div>
          </div>
        </div>
      </header>
      <div class="result-metric-grid">
        <div class="result-metric"><span>Hosts up</span><strong>${formatNumber(
          summary.hostsFound || hosts.length
        )}</strong></div>
        <div class="result-metric"><span>Open ports</span><strong>${formatNumber(
          summary.openPorts ?? 0
        )}</strong></div>
        <div class="result-metric"><span>Services</span><strong>${formatNumber(
          summary.services || (scan.results.services || []).length || 0
        )}</strong></div>
        <div class="result-metric ${attention ? "attention" : ""}"><span>Attention flags</span><strong>${formatNumber(
          attention
        )}</strong></div>
      </div>
      <div class="result-filter-row">
        <div class="search-shell result-search">
          ${icon("search")}
          <input id="portResultSearch" type="search" value="${escapeHtml(
            state.filters.ports
          )}" placeholder="Filter hosts, ports, or services" aria-label="Filter port scan results" autocomplete="off">
        </div>
        <span class="result-filter-count">${formatNumber(filteredHosts.length)} of ${formatNumber(
          hosts.length
        )} hosts · ${escapeHtml(formatDuration(scan.duration))}</span>
      </div>
      <div id="portHostCards">
        ${
          !hosts.length
            ? `<div class="no-hosts-card">${icon("ports")}<strong>No hosts reported</strong><span>The target may be down or filtering probes. Consider enabling “treat hosts as online” and scan again.</span></div>`
            : !filteredHosts.length
              ? `<div class="filter-empty">${icon("search")}<strong>No results match “${escapeHtml(
                  state.filters.ports
                )}”</strong><span>Try a port number, service, or hostname.</span></div>`
              : filteredHosts.slice(0, 100).map((host) => portHostHtml(host, scan)).join("")
        }
        ${
          filteredHosts.length > 100
            ? `<p class="microcopy" style="padding:4px 2px">Showing the first 100 hosts. Refine the filter for a closer look.</p>`
            : ""
        }
      </div>
      ${
        logText
          ? `<details class="log-panel">
              <summary class="log-panel-head">
                <span>${icon("terminal")} Scanner output</span>
                <span>${formatNumber(logText.split("\n").length)} lines ${icon("chevron-down", "log-chevron")}</span>
              </summary>
              <pre>${escapeHtml(logText)}</pre>
            </details>`
          : ""
      }
      <p class="microcopy result-disclaimer">Exposure flags are review prompts based on the service and port — not vulnerability findings. Confirm findings manually.</p>
    </div>`;

    const search = byId("portResultSearch");
    if (search) {
      search.addEventListener("input", (event) => {
        state.filters.ports = event.target.value;
        renderPortScan();
        const next = byId("portResultSearch");
        if (next) {
          next.focus();
          const length = next.value.length;
          try {
            next.setSelectionRange(length, length);
          } catch (_) {
            /* Some browsers disallow selection changes on search inputs. */
          }
        }
      });
    }
  }

  function portEmptyHtml() {
    return `<section class="panel results-panel" id="portEmptyPanel">
      <div class="results-head">
        <div class="results-title"><p class="panel-kicker">Scan workspace</p><h2>No scan loaded</h2><p class="results-sub">Configure a target and profile on the left.</p></div>
        <span class="method-badge quiet">TCP</span>
      </div>
      <div class="empty-state ports-empty">
        <div class="empty-port-art" aria-hidden="true">
          <span class="port-node p1"></span><span class="port-node p2"></span><span class="port-node p3"></span>
          <span class="port-line l1"></span><span class="port-line l2"></span><span class="port-line l3"></span>
          <span class="port-target">${icon("ports")}</span>
        </div>
        <p class="panel-kicker">Signal quiet</p>
        <h3>Every open port tells a story</h3>
        <p>Run a quick sweep to enumerate common services, or choose the service audit profile to identify what is listening and which version is answering.</p>
        <button class="btn btn-secondary" type="button" data-focus="portTarget">Set a target ${icon(
          "arrow-right"
        )}</button>
      </div>
    </section>`;
  }

  function portUnavailableHtml(scan) {
    return `<section class="panel results-panel">
      <div class="results-head">
        <div class="results-title"><p class="panel-kicker">Scan workspace</p><h2>${escapeHtml(
          scan.target
        )}</h2><p class="results-sub">${escapeHtml(statusLabel(scan.status))} · ${escapeHtml(
          formatAgo(scan.createdAt)
        )}</p></div>
        ${statusPill(scan.status)}
      </div>
      <div class="empty-state ports-empty">
        <div class="empty-orbit" aria-hidden="true"><span></span><span></span><i></i></div>
        <p class="panel-kicker">No result payload</p>
        <h3>This scan has no port data</h3>
        <p>${escapeHtml(
          scan.error || "The scan did not complete far enough to produce results."
        )}</p>
        <button class="btn btn-secondary" type="button" data-go="ports" data-focus="portTarget">Adjust and rescan ${icon(
          "arrow-right"
        )}</button>
      </div>
    </section>`;
  }

  function portCoverageStrip(stats) {
    if (!stats) return "";
    const open = Number(stats.open) || 0;
    const filtered = (Number(stats.filtered) || 0) + (Number(stats.other) || 0);
    const closed = (Number(stats.closed) || 0) + (Number(stats.unfiltered) || 0);
    const scanned = Number(stats.scanned) || open + filtered + closed;
    return `<div class="coverage-strip">
      <span><i class="open"></i><strong>${formatNumber(open)}</strong> open</span>
      <span><i class="filtered"></i><strong>${formatNumber(filtered)}</strong> filtered</span>
      <span><i class="closed"></i><strong>${formatNumber(closed)}</strong> closed</span>
      <span class="coverage-total">${formatNumber(scanned)} TCP ports scanned</span>
    </div>`;
  }

  function portHostHtml(host, scan) {
    const device = classifyDevice(host);
    const ports = host.ports || [];
    const flags = ports.reduce(
      (counts, port) => {
        const level = port.risk && port.risk.level;
        if (level) counts[level] = (counts[level] || 0) + 1;
        return counts;
      },
      { high: 0, medium: 0, low: 0, info: 0 }
    );
    const highCount = (flags.high || 0) + (flags.medium || 0);
    const osText = (host.os || [])
      .slice(0, 2)
      .map((match) => `${match.name}${match.accuracy ? ` (${match.accuracy}%)` : ""}`)
      .join(" · ");
    const subtitleParts = [];
    if (host.mac) subtitleParts.push(host.mac);
    if (host.vendor) subtitleParts.push(host.vendor);
    if (host.latency !== null && host.latency !== undefined) {
      subtitleParts.push(`${host.latency} ms`);
    }
    return `<article class="host-card">
      <header class="host-card-head">
        <span class="device-glyph is-${device.type}">${icon(device.icon)}</span>
        <div class="host-identity">
          <h3>${escapeHtml(host.address)} ${
            host.hostname ? `<span>${escapeHtml(host.hostname)}</span>` : ""
          }</h3>
          <div class="host-subline">
            ${
              subtitleParts.length
                ? subtitleParts.map((part) => `<span>${escapeHtml(part)}</span>`).join("")
                : "<span>No MAC or latency data</span>"
            }
          </div>
        </div>
        <div class="host-flags">
          ${
            flags.high
              ? `<span class="tag danger">${formatNumber(flags.high)} review</span>`
              : ""
          }
          ${
            flags.medium
              ? `<span class="tag amber">${formatNumber(flags.medium)} check</span>`
              : ""
          }
          <span class="tag">${formatNumber(ports.length)} open</span>
        </div>
      </header>
      ${portCoverageStrip(host.portStats)}
      ${
        osText
          ? `<div class="os-line"><strong>OS guess</strong><span class="os-match">${escapeHtml(
              osText
            )}</span></div>`
          : ""
      }
      ${
        ports.length
          ? `<div class="port-list-head"><span>Port</span><span>Service</span><span>Exposure</span><span></span></div>
             ${ports.map((port) => portRowHtml(host, port, scan)).join("")}`
          : `<div class="no-open-ports">${icon(
              "check"
            )}<span>Host is up, but no open TCP ports were found in this profile.</span></div>`
      }
      ${
        host.scripts && host.scripts.length
          ? `<div class="host-scripts">${host.scripts
              .map(
                (script) =>
                  `<details class="script-disclosure"><summary>${icon(
                    "terminal"
                  )} ${escapeHtml(script.id)}</summary><pre>${escapeHtml(
                    script.output
                  )}</pre></details>`
              )
              .join("")}</div>`
          : ""
      }
    </article>`;
  }

  function portRowHtml(host, port, scan) {
    const risk = port.risk || { level: "info", label: "Open service", note: "" };
    const definition = RISK_WORD[risk.level] || RISK_WORD.info;
    const serviceParts = [port.service || "unknown"];
    const productText = [port.product, port.version, port.extra]
      .filter(Boolean)
      .join(" ");
    const cpes = Array.isArray(port.cpes) ? port.cpes : [];
    const hasDetails =
      Boolean(risk.note) ||
      Boolean(productText) ||
      Boolean(cpes.length) ||
      Boolean(port.scripts && port.scripts.length);
    return `<div class="port-row-wrap">
      <button class="port-row" type="button" data-port-toggle aria-expanded="false">
        <span class="port-id"><strong>${escapeHtml(port.port)}</strong><span>/${escapeHtml(
          port.protocol || "tcp"
        )}</span></span>
        <span class="port-desc">
          <strong>${escapeHtml(serviceParts.join(""))}</strong>
          <span>${escapeHtml(productText || risk.label || "Open service")}</span>
        </span>
        ${riskShort(risk)}
        ${icon("chevron-right", "port-expand")}
      </button>
      <div class="port-detail" hidden>
        <div class="port-detail-inner">
          <p><span class="port-detail-label">Exposure</span><strong>${escapeHtml(
            risk.label || definition.label
          )}</strong>${risk.note ? ` — ${escapeHtml(risk.note)}` : ""}</p>
          ${
            productText
              ? `<p><span class="port-detail-label">Banner</span>${escapeHtml(productText)}</p>`
              : ""
          }
          ${
            cpes.length
              ? `<p><span class="port-detail-label">CPE</span>${cpes
                  .map((cpe) => `<span class="mono">${escapeHtml(cpe)}</span>`)
                  .join(" · ")}</p>`
              : ""
          }
          ${
            port.scripts && port.scripts.length
              ? port.scripts
                  .map(
                    (script) =>
                      `<div class="script-block"><span class="port-detail-label">${escapeHtml(
                        script.id
                      )}</span><pre>${escapeHtml(script.output)}</pre></div>`
                  )
                  .join("")
              : ""
          }
        </div>
      </div>
    </div>`;
  }

  /* ---------------------------------------------------------------------
     History
  --------------------------------------------------------------------- */

  async function loadHistory({ quiet = false } = {}) {
    const container = byId("historyTable");
    if (!container) return;
    const requestId = ++state.historyRequest;
    if (!quiet && !state.historyScans.length) {
      container.innerHTML = `<div class="history-empty">
        <div class="skeleton-row"><span></span><span></span><span></span></div>
        <div class="skeleton-row"><span></span><span></span><span></span></div>
        <div class="skeleton-row"><span></span><span></span><span></span></div>
      </div>`;
    }
    const params = new URLSearchParams({ limit: "100" });
    if (state.historyKind) params.set("kind", state.historyKind);
    if (state.historyStatus) params.set("status", state.historyStatus);
    if (state.historyQuery) params.set("q", state.historyQuery);
    try {
      const data = await api(`/api/scans?${params.toString()}`);
      if (requestId !== state.historyRequest) return;
      state.historyScans = data.scans || [];
      renderHistory();
    } catch (error) {
      if (requestId !== state.historyRequest) return;
      container.innerHTML = `<div class="history-empty-message">
        <div class="confirm-icon">${icon("alert")}</div>
        <strong>History could not be loaded</strong>
        <span>${escapeHtml(error.message)}</span>
      </div>`;
      if (!quiet) toast("History unavailable", error.message, "error");
    }
  }

  function renderHistory() {
    const container = byId("historyTable");
    if (!container) return;
    renderHistorySummary();
    if (!state.historyScans.length) {
      const filtered = Boolean(state.historyKind || state.historyStatus || state.historyQuery);
      container.innerHTML = `<div class="history-empty-message">
        <div class="empty-orbit" aria-hidden="true"><span></span><span></span><i></i></div>
        <strong>${filtered ? "No sweeps match these filters" : "No scans in the archive yet"}</strong>
        <span>${
          filtered
            ? "Clear the filters or try a different target."
            : "Run a discovery or port scan and it will be stored here locally."
        }</span>
      </div>`;
      return;
    }
    container.innerHTML = `<div class="history-table">
      <div class="history-head">
        <span>Date</span><span>Type</span><span>Target</span><span>Profile</span><span>Findings</span><span>Duration</span><span>Status</span><span></span>
      </div>
      ${state.historyScans.map(historyRowHtml).join("")}
    </div>`;
  }

  function historyRowHtml(scan) {
    const parts = formatDateParts(scan.createdAt);
    const summary = scan.summary || {};
    const findings =
      scan.kind === "discover"
        ? plural(summary.hostsFound || 0, "host")
        : `${formatNumber(summary.hostsFound || 0)} hosts · ${formatNumber(
            summary.openPorts || 0
          )} ports`;
    return `<button class="history-row" type="button" data-open-scan="${escapeHtml(
      scan.id
    )}" aria-label="Open scan of ${escapeHtml(scan.target)}">
      <span class="history-date">${escapeHtml(parts.date)}<small>${escapeHtml(
        parts.time
      )}</small></span>
      <span class="scan-kind ${scan.kind === "ports" ? "is-ports" : ""}">${icon(
        scan.kind === "discover" ? "radar" : "ports"
      )} ${scan.kind === "discover" ? "Discovery" : "Ports"}</span>
      <span class="history-target">
        <strong>${escapeHtml(scan.target)}</strong>
        <span>${escapeHtml(scan.command || engineLabel(scan))}</span>
      </span>
      <span class="history-profile">${escapeHtml(profileLabel(scan.profile))}</span>
      <span class="history-findings">${findings}</span>
      <span class="history-duration">${escapeHtml(formatDuration(scan.duration))}</span>
      ${statusPill(scan.status)}
      ${icon("chevron-right", "device-go")}
    </button>`;
  }

  /* ---------------------------------------------------------------------
     Live scan state and rendering
  --------------------------------------------------------------------- */

  function beginLiveScan(meta) {
    clearLivePolling();
    state.startPending = null;
    state.activeLive = meta;
    state.liveCursor = Number(meta.logCount) || 0;
    state.pollFailures = 0;
    state.terminalHandled = null;
    state.liveLogOpen = true;
    state.liveLogPinned = true;
    renderLiveHeader();
    renderLive();
    updateFormAvailability();
    beginLivePolling();
  }

  function beginLivePolling() {
    if (!state.activeLive) return;
    if (state.pollTimer) return;
    if (ACTIVE_STATUSES.has(state.activeLive.status)) {
      state.pollTimer = window.setInterval(() => {
        void pollLiveScan();
      }, 1000);
    }
    // A fast localhost scan can finish before the POST response is serialized.
    // Always fetch one detail view, even if the returned status is already final.
    void pollLiveScan(!ACTIVE_STATUSES.has(state.activeLive.status));
  }

  async function pollLiveScan(force = false) {
    const active = state.activeLive;
    if (!active || state.pollBusy) return;
    if (!force && !ACTIVE_STATUSES.has(active.status)) return;
    state.pollBusy = true;
    const scanId = active.id;
    try {
      const data = await api(
        `/api/scans/${encodeURIComponent(scanId)}?after=${state.liveCursor}`
      );
      if (!state.activeLive || state.activeLive.id !== scanId) return;
      const incoming = data.scan;
      if (!incoming) return;
      const incomingLogs = Array.isArray(incoming.logs) ? incoming.logs : [];
      const reportedCount = Number(incoming.logCount);
      let mergedLogs;
      if (Number.isFinite(reportedCount) && reportedCount < state.liveCursor) {
        mergedLogs = incomingLogs.slice();
        state.liveCursor = incomingLogs.length;
      } else {
        mergedLogs = state.activeLive.logs.concat(incomingLogs);
        state.liveCursor = Number.isFinite(reportedCount)
          ? reportedCount
          : state.liveCursor + incomingLogs.length;
      }
      const previousStatus = state.activeLive.status;
      state.activeLive = {
        ...state.activeLive,
        ...incoming,
        logs: mergedLogs,
        logCount: mergedLogs.length,
      };
      state.pollFailures = 0;
      if (incoming.results) {
        state.activeLive.results = incoming.results;
      }
      renderLiveHeader();
      if (state.route === (active.kind === "discover" ? "discover" : "ports")) {
        renderLive();
      }
      updateFormAvailability();
      if (FINISHED_STATUSES.has(incoming.status)) {
        await handleLiveFinished(incoming);
      } else if (previousStatus !== incoming.status) {
        renderLive();
      }
    } catch (error) {
      state.pollFailures += 1;
      if (state.pollFailures >= 4) {
        clearLivePolling();
        const message = error.message || "Lost contact with the scan.";
        if (state.activeLive) {
          state.activeLive.error = message;
          state.activeLive.status = "failed";
        }
        updateFormAvailability();
        renderLiveHeader();
        renderLive();
        toast("Lost scan connection", message, "error", 7000);
      }
    } finally {
      state.pollBusy = false;
    }
  }

  async function handleLiveFinished(incoming) {
    if (!state.activeLive || state.terminalHandled === incoming.id) return;
    state.terminalHandled = incoming.id;
    clearLivePolling();
    state.startPending = null;
    const finished = {
      ...state.activeLive,
      ...incoming,
      logs: state.activeLive.logs,
      logCount: state.activeLive.logs.length,
    };
    state.activeLive = finished;
    state.liveLogOpen = false;
    updateFormAvailability();
    renderLiveHeader();
    renderLive();
    if (finished.status === "completed") {
      if (finished.kind === "discover") {
        state.discoveryScan = finished;
        state.latestLoaded.discover = true;
        if (state.route === "discover") renderDiscovery();
      } else {
        state.portScan = finished;
        state.latestLoaded.ports = true;
        if (state.route === "ports") renderPortScan();
      }
      toast(
        "Scan complete",
        `${profileLabel(finished.profile)} · ${
          finished.kind === "discover"
            ? plural((finished.summary && finished.summary.hostsFound) || 0, "host")
            : plural((finished.summary && finished.summary.openPorts) || 0, "open port")
        }`,
        "success",
        5000
      );
    } else if (finished.status === "cancelled") {
      toast("Scan stopped", "No partial results were saved.", "warning", 5000);
    } else {
      toast(
        "Scan failed",
        finished.error || "Nmap did not complete this sweep.",
        "error",
        8000
      );
    }
    await refreshSharedData();
    if (state.route === "discover" && finished.kind === "discover") renderDiscovery();
    if (state.route === "ports" && finished.kind === "ports") renderPortScan();
    if (state.route === "assets") renderAssets();
    if (state.route === "history") void loadHistory({ quiet: true });
    updateFormAvailability();
  }

  function clearLivePolling() {
    if (state.pollTimer) {
      window.clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
    state.pollBusy = false;
    state.pollFailures = 0;
  }

  function renderLiveHeader() {
    const livePill = byId("livePill");
    const readyPill = byId("readyPill");
    const text = byId("livePillText");
    const progress = byId("livePillProgress");
    if (!livePill || !readyPill) return;
    const active = state.activeLive && ACTIVE_STATUSES.has(state.activeLive.status);
    livePill.hidden = !active;
    readyPill.hidden = Boolean(active);
    if (!active) return;
    if (text) {
      text.textContent =
        state.activeLive.kind === "discover" ? "Discovering" : "Scanning";
    }
    if (progress) {
      const raw = Number(state.activeLive.progress) || 0;
      progress.textContent = raw > 3 ? `${Math.round(raw)}%` : "LIVE";
    }
    livePill.title = `Open ${state.activeLive.target || "active scan"}`;
  }

  function renderLive() {
    const discoveryContainer = byId("discoveryActive");
    const portsContainer = byId("portsActive");
    if (discoveryContainer) discoveryContainer.innerHTML = "";
    if (portsContainer) portsContainer.innerHTML = "";
    const runningPortScan = Boolean(
      state.activeLive &&
        state.activeLive.kind === "ports" &&
        ACTIVE_STATUSES.has(state.activeLive.status)
    );
    const portResults = byId("portResults");
    if (portResults) portResults.hidden = runningPortScan;
    if (!state.activeLive) return;
    const targetContainer =
      state.activeLive.kind === "discover" ? discoveryContainer : portsContainer;
    const expectedRoute = state.activeLive.kind === "discover" ? "discover" : "ports";
    if (!targetContainer || state.route !== expectedRoute) return;
    const oldTerminal = targetContainer.querySelector(".live-terminal");
    const wasPinned = oldTerminal
      ? oldTerminal.scrollHeight - oldTerminal.scrollTop - oldTerminal.clientHeight < 28
      : true;
    targetContainer.innerHTML = liveRunnerHtml(state.activeLive);
    const newTerminal = targetContainer.querySelector(".live-terminal");
    if (newTerminal && state.liveLogOpen && wasPinned) {
      newTerminal.scrollTop = newTerminal.scrollHeight;
    }
    if (state.activeLive.status === "running" || state.activeLive.status === "queued") {
      const header = targetContainer.querySelector(".live-runner");
      if (header) header.dataset.started = "1";
    }
  }

  function liveRunnerHtml(scan) {
    const active = ACTIVE_STATUSES.has(scan.status);
    const completedOk = scan.status === "completed";
    const error = scan.error;
    const progress = Math.max(
      2,
      Math.min(100, Number(scan.progress) || (completedOk ? 100 : 2))
    );
    const indeterminate = active && progress < 3;
    const logText = stripAnsi((scan.logs || []).join("\n"));
    const logLines = scan.logs ? scan.logs.length : 0;
    const title =
      scan.kind === "discover"
        ? active
          ? "Discovering the local segment"
          : scan.status === "cancelled"
            ? "Discovery stopped"
            : completedOk
              ? "Discovery complete"
              : "Discovery failed"
        : active
          ? "Scanning open ports"
          : scan.status === "cancelled"
            ? "Port scan stopped"
            : completedOk
              ? "Port scan complete"
              : "Port scan failed";
    const summaryLine =
      scan.kind === "discover"
        ? "Real-time host discovery"
        : `${profileLabel(scan.profile)} · ${engineLabel(scan)}`;
    const note = completedOk
      ? `${plural((scan.summary && scan.summary.hostsFound) || 0, "host")} · ${
          scan.kind === "discover"
            ? "MAC data depends on ARP access"
            : plural((scan.summary && scan.summary.openPorts) || 0, "open port")
        }`
      : "";
    return `<section class="live-runner ${state.liveLogOpen ? "log-open" : ""} ${
      active ? "" : "is-complete"
    }" aria-label="${escapeHtml(title)}">
      <div class="live-runner-head">
        <div class="live-title">
          <span class="status-dot ${
            active ? "scanning" : completedOk ? "" : "danger"
          }"></span>
          <div>
            <strong>${escapeHtml(title)} <span class="live-timer">${
              active ? escapeHtml(formatElapsed(scan.startedAt || scan.createdAt)) : ""
            }</span></strong>
            <span class="mono">${escapeHtml(scan.target || "target")} · ${escapeHtml(
              summaryLine
            )}</span>
          </div>
        </div>
        <div class="live-controls">
          ${
            active
              ? `<button class="live-stop" type="button" data-cancel-live>Stop scan</button>`
              : `<button class="live-stop live-dismiss" type="button" data-dismiss-live>Dismiss</button>`
          }
        </div>
      </div>
      <div class="live-progress">
        <div class="live-progress-track ${indeterminate ? "is-indeterminate" : ""}">
          <div class="live-progress-fill" style="width:${indeterminate ? 34 : progress}%"></div>
        </div>
        <span class="live-progress-label">${
          active
            ? indeterminate
              ? "IN PROGRESS"
              : `${Math.round(progress)}%`
            : completedOk
              ? "COMPLETE"
              : scan.status === "cancelled"
                ? "STOPPED"
                : "FAILED"
        }</span>
      </div>
      ${error ? `<div class="live-error">${escapeHtml(error)}</div>` : ""}
      ${
        note && completedOk
          ? `<div class="live-result-note">${escapeHtml(note)}</div>`
          : ""
      }
      <button class="live-log-toggle" type="button" data-live-log-toggle>
        <span>${icon("terminal")} Run log <span class="mono">${formatNumber(
          logLines
        )} lines</span></span>
        ${icon("chevron-down")}
      </button>
      <div class="live-terminal">${escapeHtml(logText || (active ? "Waiting for scanner output…" : "No scanner output was captured."))}</div>
    </section>`;
  }

  async function cancelActiveScan() {
    if (!state.activeLive || !ACTIVE_STATUSES.has(state.activeLive.status)) return;
    const scanId = state.activeLive.id;
    const confirmed = await confirmAction({
      title: "Stop this scan?",
      message:
        "Nmap will be terminated. A partial scan is not saved and port results from this run will be discarded.",
      okLabel: "Stop scan",
    });
    if (!confirmed) return;
    try {
      await api(`/api/scans/${encodeURIComponent(scanId)}/cancel`, { method: "POST" });
      if (state.activeLive && state.activeLive.id === scanId) {
        state.activeLive.status = "cancelling";
        renderLiveHeader();
        renderLive();
        updateFormAvailability();
      }
      toast("Stopping scan", "Waiting for Nmap to exit.", "warning", 3500);
    } catch (error) {
      toast("Could not stop scan", error.message, "error");
    }
  }

  function dismissLive() {
    if (!state.activeLive) return;
    state.activeLive = null;
    clearLivePolling();
    renderLiveHeader();
    renderLive();
    updateFormAvailability();
    if (state.route === "discover") renderDiscovery();
    if (state.route === "ports") renderPortScan();
  }

  /* ---------------------------------------------------------------------
     Starting scans
  --------------------------------------------------------------------- */

  async function startDiscoveryScan(event) {
    if (event) event.preventDefault();
    if (state.startPending || isCurrentLiveAny()) return;
    const target = (byId("discoverTarget")?.value || "").trim();
    if (!target) {
      toast("A target is required", "Enter an IPv4 address, network, or range.", "warning");
      byId("discoverTarget")?.focus();
      return;
    }
    const engine = selectedDiscoveryEngine();
    if (engine === "arp" && !arpTool().usable) {
      toast(
        "ARP is unavailable",
        "arp-scan needs raw packet access. Choose Auto or Nmap ping, or grant CAP_NET_RAW.",
        "warning",
        6500
      );
      return;
    }
    if (!nmapTool().available) {
      toast("Nmap is missing", "Install Nmap before starting a scan.", "error");
      return;
    }
    const ifaceSelect = byId("discoverInterface");
    state.startPending = "discover";
    updateFormAvailability();
    try {
      const data = await api("/api/scans", {
        method: "POST",
        body: {
          kind: "discover",
          target,
          engine,
          interface: ifaceSelect ? ifaceSelect.value || null : null,
        },
      });
      if (!data.scan || !data.scan.id) throw new Error("The scan did not start correctly.");
      state.startPending = null;
      beginLiveScan({
        ...data.scan,
        logs: [],
        logCount: 0,
        progress: Number(data.scan.progress) || 0,
      });
    } catch (error) {
      state.startPending = null;
      updateFormAvailability();
      handleStartError(error);
    }
  }

  async function startPortScan(event) {
    if (event) event.preventDefault();
    if (state.startPending || isCurrentLiveAny()) return;
    const target = (byId("portTarget")?.value || "").trim();
    if (!target) {
      toast("A target is required", "Enter a hostname, IPv4 address, range, or subnet.", "warning");
      byId("portTarget")?.focus();
      return;
    }
    const profile = selectedProfile();
    if (profile === "custom") {
      const ports = (byId("customPorts")?.value || "").trim();
      if (!ports) {
        toast("Choose your ports", "Enter a port list or range for the custom profile.", "warning");
        byId("customPorts")?.focus();
        return;
      }
    }
    if (!nmapTool().available) {
      toast("Nmap is missing", "Install Nmap before starting a scan.", "error");
      return;
    }
    const options = {
      serviceDetection:
        Boolean(byId("optService")?.checked) ||
        profile === "services" ||
        profile === "safe",
      scripts: profile !== "safe" && Boolean(byId("optScripts")?.checked),
      osDetection: Boolean(byId("optOs")?.checked) && Boolean(state.system && state.system.rawAccess),
      skipPing: Boolean(byId("optSkipPing")?.checked),
      timing: byId("optTiming")?.value || "normal",
    };
    state.startPending = "ports";
    updateFormAvailability();
    try {
      const data = await api("/api/scans", {
        method: "POST",
        body: {
          kind: "ports",
          target,
          profile,
          ports: profile === "custom" ? (byId("customPorts")?.value || "").trim() : "",
          options,
        },
      });
      if (!data.scan || !data.scan.id) throw new Error("The scan did not start correctly.");
      state.startPending = null;
      beginLiveScan({
        ...data.scan,
        logs: [],
        logCount: 0,
        progress: Number(data.scan.progress) || 0,
      });
    } catch (error) {
      state.startPending = null;
      updateFormAvailability();
      handleStartError(error);
    }
  }

  async function handleStartError(error) {
    let title = "Scan could not start";
    let message = error.message;
    if (error.code === "privilege_required") {
      title = "Raw access required";
      message = `${error.message} Open the field guide for capability setup.`;
    } else if (error.code === "scan_busy") {
      title = "A scan is already running";
      message = "ReconDeck supports one live scan at a time. Wait for it to finish or open the active sweep.";
      void refreshSharedData();
    } else if (error.code === "target_too_large") {
      title = "Target is too broad";
    } else if (error.status === 403) {
      title = "Local session expired";
      message = "Refresh this page to get a new ReconDeck session token.";
    }
    toast(title, message, "error", 7000);
  }

  /* ---------------------------------------------------------------------
     History/scan details and drawers
  --------------------------------------------------------------------- */

  async function openScanDrawer(scanId) {
    if (!scanId) return;
    const requestId = ++state.drawerRequest;
    state.drawerScan = null;
    openDrawer({
      kicker: "Scan details",
      title: "Loading scan…",
      body: `<div class="drawer-empty">${icon("refresh", "spin")}<br>Reading the local archive…</div>`,
    });
    try {
      const data = await api(`/api/scans/${encodeURIComponent(scanId)}?after=0`);
      if (requestId !== state.drawerRequest) return;
      state.drawerScan = data.scan;
      renderScanDrawer(data.scan);
    } catch (error) {
      if (requestId !== state.drawerRequest) return;
      byId("drawerBody").innerHTML = `<div class="drawer-empty">${escapeHtml(
        error.message
      )}</div>`;
      setText("drawerTitle", "Scan unavailable");
      toast("Could not open scan", error.message, "error");
    }
  }

  function renderScanDrawer(scan) {
    const title = scan.target || "Scan";
    setText("drawerTitle", title);
    setText("drawerKicker", scan.kind === "discover" ? "Discovery scan" : "Port scan");
    const summary = scan.summary || {};
    const logs = stripAnsi(Array.isArray(scan.logs) ? scan.logs.join("\n") : scan.log || "");
    const results = scan.results || {};
    const hosts = results.hosts || [];
    const active = ACTIVE_STATUSES.has(scan.status);
    const finished = ["completed", "failed", "cancelled", "interrupted"].includes(scan.status);
    const body = byId("drawerBody");
    if (!body) return;
    const date = formatDateTime(scan.finishedAt || scan.createdAt);
    const request = scan.request || {};
    const canUseSettings = Boolean(request && request.kind);
    body.innerHTML = `
      <section class="drawer-section">
        <div class="drawer-meta-list" style="margin-bottom:12px">
          <div class="drawer-meta-row"><span>Status</span><span>${statusPill(scan.status)}</span></div>
          <div class="drawer-meta-row"><span>Started</span><span>${escapeHtml(date)}</span></div>
          <div class="drawer-meta-row"><span>Engine</span><span class="mono">${escapeHtml(
            engineLabel(scan)
          )}</span></div>
          <div class="drawer-meta-row"><span>Profile</span><span>${escapeHtml(
            profileLabel(scan.profile)
          )}</span></div>
        </div>
        <div class="drawer-metrics">
          <div class="drawer-metric"><span>Hosts up</span><strong>${formatNumber(
            summary.hostsFound || hosts.length
          )}</strong></div>
          <div class="drawer-metric"><span>Open ports</span><strong>${formatNumber(
            summary.openPorts || 0
          )}</strong></div>
          <div class="drawer-metric"><span>Duration</span><strong>${escapeHtml(
            formatDuration(scan.duration || summary.durationSeconds)
          )}</strong></div>
        </div>
        ${
          scan.error
            ? `<div class="drawer-empty" style="text-align:left;padding:16px 0 0;color:var(--danger)">${escapeHtml(
                scan.error
              )}</div>`
            : ""
        }
        <div class="drawer-actions">
          <button class="btn btn-secondary" type="button" data-download="${escapeHtml(
            scan.id
          )}" data-format="json" ${active ? "disabled" : ""}>${icon("copy")} JSON</button>
          <button class="btn btn-secondary" type="button" data-download="${escapeHtml(
            scan.id
          )}" data-format="csv" ${active ? "disabled" : ""}>${icon("list")} CSV</button>
          <button class="btn btn-secondary" type="button" data-download="${escapeHtml(
            scan.id
          )}" data-format="txt" ${active || !logs ? "disabled" : ""}>${icon(
            "terminal"
          )} Log</button>
          ${
            canUseSettings && finished
              ? `<button class="btn btn-secondary" type="button" data-use-settings>${icon(
                  "refresh"
                )} Load settings</button>`
              : ""
          }
        </div>
      </section>
      ${
        scan.command
          ? `<section class="drawer-section"><h3>Command</h3><div class="drawer-command">${escapeHtml(
              scan.command
            )}</div></section>`
          : ""
      }
      ${
        results.hosts
          ? `<section class="drawer-section"><h3>Hosts <span class="count-badge">${formatNumber(
              hosts.length
            )}</span></h3>
              ${
                hosts.length
                  ? `<div class="drawer-host-list">${hosts
                      .slice(0, 50)
                      .map(
                        (host) => `<div class="drawer-host-row">
                          ${icon(classifyDevice(host).icon)}
                          <strong>${escapeHtml(host.address)}</strong>
                          <span>${escapeHtml(
                            host.hostname || host.mac || host.vendor || "no hostname"
                          )}</span>
                          <span class="tag">${
                            scan.kind === "ports"
                              ? plural((host.ports || []).length, "port")
                              : "host up"
                          }</span>
                        </div>`
                      )
                      .join("")}</div>`
                  : `<div class="drawer-empty">No hosts responded in this scan.</div>`
              }
            </section>`
          : ""
      }
      ${
        scan.kind === "ports" && results.hosts && hosts.some((host) => (host.ports || []).length)
          ? `<section class="drawer-section"><h3>Ports in this scan</h3>
              <div class="drawer-open-ports">
                ${hosts
                  .flatMap((host) =>
                    (host.ports || []).slice(0, 15).map((port) => ({
                    host,
                    port,
                  }))
                  )
                  .slice(0, 40)
                  .map(
                    ({ host, port }) => `<div class="drawer-port">
                      <strong>${escapeHtml(port.port)}<span class="mono">/${escapeHtml(
                        port.protocol || "tcp"
                      )}</span></strong>
                      <span>${escapeHtml(host.address)} · ${escapeHtml(
                        [port.service, port.product, port.version].filter(Boolean).join(" ")
                      )}</span>
                      ${riskShort(port.risk || { level: "info" })}
                    </div>`
                  )
                  .join("")}
              </div>
            </section>`
          : ""
      }
      ${
        logs
          ? `<section class="drawer-section"><h3>Scanner output</h3><details class="log-panel"><summary class="log-panel-head"><span>Raw log</span><span>${formatNumber(
              logs.split("\n").length
            )} lines ${icon("chevron-down", "log-chevron")}</span></summary><pre>${escapeHtml(
              logs
            )}</pre></details></section>`
          : ""
      }
      ${
        finished
          ? `<section class="drawer-section drawer-danger-zone">
              <button class="btn btn-secondary" type="button" data-delete-scan="${escapeHtml(
                scan.id
              )}">${icon("trash")} Delete this scan</button>
              <p class="microcopy">Deleting a sweep also recomputes the observed-host inventory from the scans that remain.</p>
            </section>`
          : ""
      }
    `;
  }

  async function openHostDrawer(host) {
    if (!host) return;
    const address = host.address;
    const requestId = ++state.drawerRequest;
    state.drawerScan = null;
    state.drawerAsset = null;
    openDrawer({
      kicker: "Asset detail",
      title: host.hostname || address || "Asset",
      body: `<div class="drawer-empty">${icon(
        "refresh",
        "spin"
      )}<br>Gathering asset evidence…</div>`,
    });
    try {
      const data = await api(`/api/assets/${encodeURIComponent(address)}`);
      if (requestId !== state.drawerRequest) return;
      state.drawerAsset = data.asset;
      renderHostDrawer(data.asset.host || host, data.asset.scans || []);
    } catch (error) {
      if (requestId !== state.drawerRequest) return;
      state.drawerAsset = { host, scans: [] };
      renderHostDrawer(host, [], error.message);
    }
  }

  function renderHostDrawer(host, scans, historyError = "") {
    const enriched = enrichHost(host);
    const device = classifyDevice(enriched);
    const ports = [...(enriched.ports || [])].sort(
      (a, b) => Number(a.port) - Number(b.port)
    );
    const stats = enriched.portStats || null;
    const scanned = stats ? Number(stats.scanned) || 0 : 0;
    const firstDate = formatDateTime(enriched.firstSeen);
    const lastDate = formatDateTime(enriched.lastSeen);
    const coverage = hostCoverageHtml(stats, ports.length);
    const history = hostScanHistoryHtml(scans, historyError);
    setText("drawerKicker", "Asset detail");
    setText("drawerTitle", enriched.hostname || enriched.address || "Asset");
    const body = byId("drawerBody");
    if (!body) return;
    body.innerHTML = `
      <section class="drawer-section">
        <div class="asset-drawer-heading">
          <span class="device-glyph is-${device.type}">${icon(device.icon)}</span>
          <div>
            <span class="asset-type-badge">${escapeHtml(deviceTypeLabel(device.type))}</span>
            <strong class="mono">${escapeHtml(enriched.address)}</strong>
            <small>${escapeHtml(
              enriched.vendor || (enriched.mac ? enriched.mac : "Vendor not identified")
            )}</small>
          </div>
          <span class="asset-scanned-chip ${host.lastPortScanAt ? "" : "is-unscanned"}">
            ${icon(host.lastPortScanAt ? "check" : "ports")}
            ${escapeHtml(host.lastPortScanAt ? formatAgo(host.lastPortScanAt) : "Never port-scanned")}
          </span>
        </div>
        <div class="drawer-metrics">
          <div class="drawer-metric"><span>Open ports</span><strong>${formatNumber(
            enriched.openPorts || ports.length
          )}</strong></div>
          <div class="drawer-metric"><span>Review flags</span><strong>${formatNumber(
            enriched.riskFlags || 0
          )}</strong></div>
          <div class="drawer-metric"><span>Ports scanned</span><strong>${
            stats ? formatNumber(scanned) : "—"
          }</strong></div>
        </div>
      </section>

      <section class="drawer-section asset-scan-section">
        <div class="asset-scan-copy">
          <p class="panel-kicker">Per-asset scan</p>
          <h3>Map this asset's ports</h3>
          <p>Run a focused scan against <span class="mono">${escapeHtml(
            enriched.address
          )}</span>. Results appear in the port workspace.</p>
        </div>
        <div class="asset-scan-controls">
          <div class="select-shell">
            <select id="hostScanProfile" class="select-input" aria-label="Scan profile for this asset">
              <option value="quick">Quick · top 100</option>
              <option value="standard">Standard · top 1,000</option>
              <option value="services" selected>Service audit · versions</option>
              <option value="safe">Safe audit · TLS / headers / keys</option>
            </select>
            <svg class="icon"><use href="#i-chevron-down"/></svg>
          </div>
          <button class="btn btn-primary" type="button" data-scan-host-profile="${escapeHtml(
            enriched.address
          )}">${icon("play")} Scan this ${
            device.type === "router" ? "AP" : "asset"
          }</button>
        </div>
        <p class="microcopy">Only the selected asset is scanned. Safe audit uses a curated, non-intrusive NSE set.</p>
      </section>

      <section class="drawer-section">
        <h3>Port picture <span class="count-badge">${formatNumber(ports.length)}</span></h3>
        ${coverage}
        ${
          ports.length
            ? `<div class="host-port-list">${ports
                .map((port) => hostPortRowHtml(port))
                .join("")}</div>`
            : `<div class="drawer-empty">No open ports have been recorded for this asset.${
                host.lastPortScanAt
                  ? " The latest scan may have covered a different port range."
                  : " Run its first scan above."
              }</div>`
        }
        ${
          Number(enriched.openPorts) > ports.length
            ? `<p class="microcopy">Showing ${formatNumber(
                ports.length
              )} of ${formatNumber(enriched.openPorts)} recorded open ports.</p>`
            : ""
        }
      </section>

      <section class="drawer-section">
        <h3>Recent evidence</h3>
        <div id="hostScanHistory">${history}</div>
      </section>

      <section class="drawer-section">
        <h3>Identity</h3>
        <div class="drawer-meta-list">
          <div class="drawer-meta-row"><span>IPv4</span><span class="mono">${escapeHtml(
            enriched.address
          )}</span></div>
          <div class="drawer-meta-row"><span>Hostname</span><span class="mono">${escapeHtml(
            enriched.hostname || "not resolved"
          )}</span></div>
          <div class="drawer-meta-row"><span>MAC</span><span class="mono">${escapeHtml(
            enriched.mac || "unavailable"
          )}</span></div>
          <div class="drawer-meta-row"><span>Vendor</span><span>${escapeHtml(
            enriched.vendor || "unknown"
          )}</span></div>
          <div class="drawer-meta-row"><span>First seen</span><span>${escapeHtml(
            firstDate
          )}</span></div>
          <div class="drawer-meta-row"><span>Last seen</span><span>${escapeHtml(
            lastDate
          )}</span></div>
        </div>
      </section>
      <section class="drawer-section">
        <p class="microcopy">Port and service notes are review prompts, not vulnerability findings. ReconDeck does not perform exploitation or credential attacks.</p>
      </section>
    `;
  }

  function hostCoverageHtml(stats, knownOpenPorts = 0) {
    if (!stats) {
      return `<div class="host-coverage host-coverage-empty">${icon(
        "info"
      )} ${
        knownOpenPorts
          ? `Legacy evidence has ${plural(
              knownOpenPorts,
              "known open port"
            )}. Rescan this asset to populate open, closed, and filtered coverage.`
          : "No port coverage recorded yet. Run a scan to populate open, closed, and filtered counts."
      }</div>`;
    }
    const keys = ["open", "filtered", "closed", "unfiltered", "other"];
    const counts = {};
    for (const key of keys) counts[key] = Math.max(0, Number(stats[key]) || 0);
    const total = Math.max(
      Number(stats.scanned) || 0,
      keys.reduce((sum, key) => sum + counts[key], 0),
      1
    );
    const pct = (value) => Math.min(100, (value / total) * 100);
    return `<div class="host-coverage">
      <div class="host-coverage-head">
        <span>Last scan coverage</span>
        <strong>${formatNumber(total)} ports</strong>
      </div>
      <div class="coverage-bar" role="img" aria-label="${escapeHtml(
        `${counts.open} open, ${counts.filtered} filtered, ${counts.closed} closed`
      )}">
        <span class="coverage-open" style="width:${pct(counts.open).toFixed(2)}%"></span>
        <span class="coverage-filtered" style="width:${pct(
          counts.filtered + counts.other
        ).toFixed(2)}%"></span>
        <span class="coverage-closed" style="width:${pct(
          counts.closed + counts.unfiltered
        ).toFixed(2)}%"></span>
      </div>
      <div class="coverage-legend">
        <span><i class="open"></i><strong>${formatNumber(counts.open)}</strong> open</span>
        <span><i class="filtered"></i><strong>${formatNumber(
          counts.filtered + counts.other
        )}</strong> filtered</span>
        <span><i class="closed"></i><strong>${formatNumber(
          counts.closed + counts.unfiltered
        )}</strong> closed</span>
      </div>
    </div>`;
  }

  function hostPortRowHtml(port) {
    const risk = port.risk || { level: "info", label: "Open service" };
    const category = risk.categoryLabel || "Other services";
    const product = [port.product, port.version, port.extra].filter(Boolean).join(" ");
    return `<div class="host-port-row">
      <span class="host-port-number">${escapeHtml(port.port)}<small>/${escapeHtml(
        port.protocol || "tcp"
      )}</small></span>
      <span class="host-port-service">
        <strong>${escapeHtml(port.service || "unknown")}</strong>
        <small>${escapeHtml(product || risk.note || "Open service")}</small>
      </span>
      <span class="host-port-category">${escapeHtml(category)}${
        risk.cleartext ? '<i title="Cleartext service">cleartext</i>' : ""
      }</span>
      <span class="host-port-risk level-${escapeHtml(risk.level || "info")}">${escapeHtml(
        (RISK_WORD[risk.level] || RISK_WORD.info).label
      )}</span>
    </div>`;
  }

  function hostScanHistoryHtml(scans, error) {
    if (error) {
      return `<div class="drawer-empty">${escapeHtml(error)}</div>`;
    }
    if (!scans.length) {
      return `<div class="drawer-empty">No completed scans have observed this asset yet.</div>`;
    }
    return `<div class="host-scan-history">${scans
      .slice(0, 8)
      .map((scan) => {
        const stats = scan.portStats;
        const summary = scan.summary || {};
        return `<button class="host-scan-row" type="button" data-open-scan="${escapeHtml(
          scan.id
        )}" aria-label="Open ${escapeHtml(profileLabel(scan.profile))} scan">
          <span class="recent-icon ${scan.kind === "ports" ? "is-ports" : ""}">${icon(
            scan.kind === "ports" ? "ports" : "radar"
          )}</span>
          <span class="host-scan-copy">
            <strong>${escapeHtml(profileLabel(scan.profile))}</strong>
            <small>${escapeHtml(formatDateTime(scan.finishedAt))} · ${escapeHtml(
              engineLabel(scan)
            )}</small>
          </span>
          <span class="host-scan-metrics">
            <strong>${formatNumber(scan.openPorts || 0)} open</strong>
            <small>${
              stats
                ? `${formatNumber(stats.scanned || 0)} scanned`
                : `${formatNumber(summary.openPorts || 0)} observed`
            }</small>
          </span>
          ${icon("chevron-right", "device-go")}
        </button>`;
      })
      .join("")}</div>`;
  }

  function startHostScanFromDrawer(address, profile) {
    if (!address) return;
    if (isCurrentLiveAny() || state.startPending) {
      toast(
        "A scan is already running",
        "Wait for the current sweep to finish before starting another.",
        "warning"
      );
      return;
    }
    const allowed = ["quick", "standard", "services", "safe"];
    const selectedProfile = allowed.includes(profile) ? profile : "services";
    closeDrawer();
    const targetInput = byId("portTarget");
    if (targetInput) targetInput.value = address;
    const radio = $(`input[name="scanProfile"][value="${selectedProfile}"]`);
    if (radio) {
      radio.checked = true;
      syncPortControls({ changedProfile: true });
    } else {
      const servicesRadio = $('input[name="scanProfile"][value="services"]');
      if (servicesRadio) servicesRadio.checked = true;
      syncPortControls({ changedProfile: true });
    }
    updatePortPreview();
    navigate("ports");
    toast(
      "Starting per-asset scan",
      `${profileLabel(selectedProfile)} against ${address}.`,
      "success",
      3000
    );
    window.setTimeout(() => {
      if (!isCurrentLiveAny() && !state.startPending) {
        void startPortScan();
      }
    }, 180);
  }

  function openDrawer({ kicker, title, body }) {
    const drawer = byId("detailDrawer");
    const scrim = byId("drawerScrim");
    if (!drawer || !scrim) return;
    if (drawer.hidden) {
      state.drawerReturnFocus =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
    }
    setText("drawerKicker", kicker || "Details");
    setText("drawerTitle", title || "Details");
    const bodyNode = byId("drawerBody");
    if (bodyNode) bodyNode.innerHTML = body || "";
    drawer.hidden = false;
    drawer.setAttribute("aria-hidden", "false");
    scrim.hidden = false;
    refreshBodyLock();
    if (bodyNode) bodyNode.scrollTop = 0;
    const closeButton = byId("drawerClose");
    if (closeButton) closeButton.focus({ preventScroll: true });
  }

  function closeDrawer() {
    const drawer = byId("detailDrawer");
    const scrim = byId("drawerScrim");
    if (!drawer || drawer.hidden) return;
    drawer.hidden = true;
    drawer.setAttribute("aria-hidden", "true");
    if (scrim) scrim.hidden = true;
    refreshBodyLock();
    if (state.drawerReturnFocus && document.contains(state.drawerReturnFocus)) {
      state.drawerReturnFocus.focus({ preventScroll: true });
    }
    state.drawerReturnFocus = null;
    state.drawerScan = null;
    state.drawerAsset = null;
    state.drawerRequest += 1;
  }

  async function deleteScan(scanId) {
    if (!scanId) return;
    const confirmed = await confirmAction({
      title: "Delete this scan?",
      message:
        "Its results and raw output will be removed from the local archive. The observed-host inventory will be rebuilt from your remaining scans.",
      okLabel: "Delete scan",
    });
    if (!confirmed) return;
    try {
      await api(`/api/scans/${encodeURIComponent(scanId)}`, { method: "DELETE" });
      closeDrawer();
      if (state.discoveryScan && state.discoveryScan.id === scanId) {
        state.discoveryScan = null;
        state.latestLoaded.discover = false;
      }
      if (state.portScan && state.portScan.id === scanId) {
        state.portScan = null;
        state.latestLoaded.ports = false;
      }
      if (state.activeLive && state.activeLive.id === scanId) {
        dismissLive();
      }
      await refreshSharedData();
      if (state.route === "history") await loadHistory({ quiet: true });
      if (state.route === "discover") {
        await ensureLatestScan("discover", { force: true });
        renderDiscovery();
      }
      if (state.route === "ports") {
        await ensureLatestScan("ports", { force: true });
        renderPortScan();
      }
      toast("Scan deleted", "The local archive and host inventory were updated.", "success");
    } catch (error) {
      toast("Could not delete scan", error.message, "error");
    }
  }

  function loadScanSettings(scan) {
    if (!scan || !scan.request || !scan.request.kind) {
      toast("No reusable settings", "This scan does not have a stored request.", "warning");
      return;
    }
    const request = scan.request;
    if (request.kind === "discover") {
      const targetInput = byId("discoverTarget");
      if (targetInput) targetInput.value = request.target || scan.target || "";
      const engine = request.engine || "auto";
      const radio = $(`input[name="discoverEngine"][value="${CSS.escape(engine)}"]`);
      if (radio && !radio.disabled) radio.checked = true;
      const ifaceSelect = byId("discoverInterface");
      if (ifaceSelect && request.interface) {
        const available = $$("option", ifaceSelect).some((option) => option.value === request.interface);
        if (available) ifaceSelect.value = request.interface;
      }
      syncDiscoveryControls();
      navigate("discover");
      window.setTimeout(() => byId("discoverTarget")?.focus(), 60);
      toast("Settings loaded", "Review the discovery target, then start the sweep.", "success");
      closeDrawer();
      return;
    }
    const profile = request.profile || scan.profile || "quick";
    const targetInput = byId("portTarget");
    if (targetInput) targetInput.value = request.target || scan.target || "";
    const radio = $(`input[name="scanProfile"][value="${CSS.escape(profile)}"]`);
    if (radio) radio.checked = true;
    syncPortControls({ changedProfile: true });
    const custom = byId("customPorts");
    if (custom) custom.value = request.ports || "";
    const options = request.options || {};
    const timing = byId("optTiming");
    if (timing && options.timing) timing.value = options.timing;
    const service = byId("optService");
    if (service) {
      service.checked =
        Boolean(options.serviceDetection) ||
        profile === "services" ||
        profile === "safe";
    }
    const scripts = byId("optScripts");
    if (scripts) scripts.checked = Boolean(options.scripts);
    const os = byId("optOs");
    if (os) os.checked = Boolean(options.osDetection) && Boolean(state.system && state.system.rawAccess);
    const skip = byId("optSkipPing");
    if (skip) skip.checked = Boolean(options.skipPing);
    updatePortPreview();
    navigate("ports");
    window.setTimeout(() => byId("portTarget")?.focus(), 60);
    toast("Settings loaded", "Review the target and profile, then launch the scan.", "success");
    closeDrawer();
  }

  /* ---------------------------------------------------------------------
     Exports, clipboard, modals, toasts
  --------------------------------------------------------------------- */

  async function downloadScan(scanId, format) {
    if (!scanId) return;
    closeAllExportMenus();
    try {
      const response = await fetch(
        `/api/scans/${encodeURIComponent(scanId)}/export?format=${encodeURIComponent(format)}`,
        {
          headers: { "X-ReconDeck-Token": API_TOKEN },
          cache: "no-store",
        }
      );
      if (!response.ok) {
        let message = `Export failed (HTTP ${response.status}).`;
        try {
          const payload = await response.json();
          if (payload && payload.error) message = payload.error;
        } catch (_) {
          /* Use the generic message. */
        }
        throw new Error(message);
      }
      const blob = await response.blob();
      const disposition = response.headers.get("content-disposition") || "";
      const match = disposition.match(/filename="?([^";]+)"?/i);
      const extension = format === "txt" ? "log.txt" : format;
      const filename = match
        ? match[1]
        : `recondeck-${scanId}.${extension}`;
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1500);
      toast("Export ready", `${filename} was saved by your browser.`, "success");
    } catch (error) {
      toast("Export failed", error.message, "error");
    }
  }

  async function copyText(text, successMessage = "Copied to clipboard.") {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        area.remove();
      }
      toast("Copied", successMessage, "success", 2600);
    } catch (_) {
      toast("Copy failed", "Clipboard access was not available.", "error");
    }
  }

  function toast(title, message, kind = "success", timeout = 5000) {
    const region = byId("toastRegion");
    if (!region) return;
    const node = document.createElement("div");
    node.className = `toast ${kind === "error" ? "is-error" : kind === "warning" ? "is-warning" : ""}`;
    node.setAttribute("role", kind === "error" ? "alert" : "status");
    const iconName = kind === "error" ? "alert" : kind === "warning" ? "info" : "check";
    node.innerHTML = `<span class="toast-icon">${icon(iconName)}</span>
      <span class="toast-copy"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(
        message || ""
      )}</span></span>
      <button class="toast-close" type="button" aria-label="Dismiss notification">${icon("x")}</button>`;
    region.appendChild(node);
    const close = () => {
      node.classList.add("is-leaving");
      window.setTimeout(() => node.remove(), 200);
    };
    node.querySelector(".toast-close")?.addEventListener("click", close);
    window.setTimeout(close, timeout);
  }

  let confirmResolver = null;

  function confirmAction({ title, message, okLabel = "Confirm" }) {
    const host = byId("confirmModal");
    if (!host) return Promise.resolve(false);
    setText("confirmTitle", title);
    setText("confirmCopy", message);
    setText("confirmOk", okLabel);
    host.hidden = false;
    refreshBodyLock();
    byId("confirmCancel")?.focus();
    return new Promise((resolve) => {
      confirmResolver = resolve;
    });
  }

  function settleConfirm(value) {
    const host = byId("confirmModal");
    if (host) host.hidden = true;
    refreshBodyLock();
    if (confirmResolver) {
      const resolve = confirmResolver;
      confirmResolver = null;
      resolve(value);
    }
  }

  function openGuide() {
    closeDrawer();
    const host = byId("guideModal");
    if (!host) return;
    host.hidden = false;
    refreshBodyLock();
    host.querySelector(".icon-btn")?.focus({ preventScroll: true });
  }

  function closeGuide() {
    const host = byId("guideModal");
    if (!host) return;
    host.hidden = true;
    refreshBodyLock();
  }

  function openNewScanMenu() {
    const menu = byId("newScanMenu");
    const button = byId("newScanBtn");
    if (!menu) return;
    const open = menu.hidden;
    menu.hidden = !open;
    if (button) button.setAttribute("aria-expanded", String(open));
  }

  function closeNewScanMenu() {
    const menu = byId("newScanMenu");
    const button = byId("newScanBtn");
    if (!menu) return;
    menu.hidden = true;
    if (button) button.setAttribute("aria-expanded", "false");
  }

  function closeAllExportMenus(except) {
    $$(".export-menu").forEach((menu) => {
      if (menu !== except) {
        menu.hidden = true;
        const toggle = menu.parentElement?.querySelector("[data-export-toggle]");
        if (toggle) toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  function openMobileNav() {
    const sidebar = byId("sidebar");
    const scrim = byId("mobileScrim");
    if (!sidebar) return;
    sidebar.classList.add("is-open");
    if (scrim) scrim.hidden = false;
    byId("mobileMenuBtn")?.setAttribute("aria-expanded", "true");
    refreshBodyLock();
  }

  function closeMobileNav() {
    const sidebar = byId("sidebar");
    const scrim = byId("mobileScrim");
    if (!sidebar || !sidebar.classList.contains("is-open")) return;
    sidebar.classList.remove("is-open");
    if (scrim) scrim.hidden = true;
    byId("mobileMenuBtn")?.setAttribute("aria-expanded", "false");
    refreshBodyLock();
  }

  function refreshBodyLock() {
    const locked =
      !byId("detailDrawer")?.hidden ||
      !byId("guideModal")?.hidden ||
      !byId("confirmModal")?.hidden ||
      Boolean(byId("sidebar")?.classList.contains("is-open"));
    document.body.classList.toggle("overlay-open", Boolean(locked));
  }

  /* ---------------------------------------------------------------------
     Theme and form wiring
  --------------------------------------------------------------------- */

  function initTheme() {
    const stored = window.localStorage.getItem("recondeck-theme");
    const theme = stored === "light" || stored === "dark" ? stored : "dark";
    document.documentElement.dataset.theme = theme;
    updateThemeToggleLabel();
  }

  function updateThemeToggleLabel() {
    const button = byId("themeToggle");
    if (!button) return;
    const isDark = document.documentElement.dataset.theme === "dark";
    button.setAttribute(
      "aria-label",
      isDark ? "Switch to light theme" : "Switch to dark theme"
    );
    button.title = isDark ? "Switch to light theme" : "Switch to dark theme";
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.content = isDark ? "dark light" : "light dark";
  }

  function toggleTheme() {
    const next =
      document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("recondeck-theme", next);
    updateThemeToggleLabel();
  }

  function fillTarget(kind, target) {
    if (!target) return;
    const input = byId(kind === "discover" ? "discoverTarget" : "portTarget");
    if (!input) return;
    input.value = target;
    input.focus();
    if (kind === "discover") updateDiscoveryPreview();
    else updatePortPreview();
  }

  function focusElement(id) {
    const node = byId(id);
    if (!node) return;
    node.focus({ preventScroll: false });
    node.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  function setupForms() {
    byId("discoverForm")?.addEventListener("submit", startDiscoveryScan);
    byId("portForm")?.addEventListener("submit", startPortScan);
    byId("discoverTarget")?.addEventListener("input", updateDiscoveryPreview);
    byId("discoverInterface")?.addEventListener("change", updateDiscoveryPreview);
    byId("portTarget")?.addEventListener("input", () => {
      updatePortPreview();
    });
    byId("customPorts")?.addEventListener("input", () => {
      updatePortPreview();
    });
    $$('input[name="discoverEngine"]').forEach((radio) => {
      radio.addEventListener("change", () => {
        if (radio.checked) syncDiscoveryControls();
      });
    });
    $$('input[name="scanProfile"]').forEach((radio) => {
      radio.addEventListener("change", () => {
        if (radio.checked) syncPortControls({ changedProfile: true });
      });
    });
    ["optService", "optScripts", "optOs", "optSkipPing"].forEach((id) => {
      byId(id)?.addEventListener("change", updatePortPreview);
    });
    byId("optTiming")?.addEventListener("change", updatePortPreview);
    byId("discoverySearch")?.addEventListener("input", (event) => {
      state.filters.discovery = event.target.value;
      renderDiscovery();
    });
    byId("historySearch")?.addEventListener("input", (event) => {
      state.historyQuery = event.target.value;
      window.clearTimeout(state.historyTimer);
      state.historyTimer = window.setTimeout(() => {
        void loadHistory();
      }, 240);
    });
    byId("historyStatus")?.addEventListener("change", (event) => {
      state.historyStatus = event.target.value;
      void loadHistory();
    });
    $$("[data-history-kind]").forEach((button) => {
      button.addEventListener("click", () => {
        state.historyKind = button.dataset.historyKind || "";
        $$("[data-history-kind]").forEach((item) => {
          const active = item === button;
          item.classList.toggle("is-active", active);
          item.setAttribute("aria-selected", String(active));
        });
        void loadHistory();
      });
    });
    byId("discoveryRefresh")?.addEventListener("click", refreshDiscovery);
    byId("historyRefresh")?.addEventListener("click", () => {
      void loadHistory();
    });
    byId("assetSearch")?.addEventListener("input", (event) => {
      state.assetSearch = event.target.value;
      renderAssetList();
    });
    byId("assetRefresh")?.addEventListener("click", async () => {
      const button = byId("assetRefresh");
      const iconNode = button?.querySelector(".icon");
      if (iconNode) iconNode.classList.add("spin");
      try {
        await refreshSharedData();
        renderAssets();
        toast("Asset inventory refreshed", "Local evidence is up to date.", "success", 2600);
      } finally {
        if (iconNode) iconNode.classList.remove("spin");
      }
    });
    $$("[data-asset-tab]").forEach((button) => {
      button.addEventListener("click", () => {
        setAssetTab(button.dataset.assetTab || "inventory");
      });
    });
    $$("[data-asset-filter]").forEach((button) => {
      button.addEventListener("click", () => {
        setAssetFilter(button.dataset.assetFilter || "all");
      });
    });
    byId("discoveryOpenScan")?.addEventListener("click", () => {
      if (state.discoveryScan) void openScanDrawer(state.discoveryScan.id);
    });
    byId("livePill")?.addEventListener("click", () => {
      if (!state.activeLive) return;
      navigate(state.activeLive.kind === "discover" ? "discover" : "ports");
    });
    byId("newScanBtn")?.addEventListener("click", (event) => {
      event.stopPropagation();
      openNewScanMenu();
    });
    byId("themeToggle")?.addEventListener("click", toggleTheme);
    byId("mobileMenuBtn")?.addEventListener("click", openMobileNav);
    byId("mobileScrim")?.addEventListener("click", closeMobileNav);
    byId("drawerClose")?.addEventListener("click", closeDrawer);
    byId("drawerScrim")?.addEventListener("click", closeDrawer);
    $$("[data-open-guide]").forEach((button) => {
      button.addEventListener("click", openGuide);
    });
    $$("[data-close-guide]").forEach((button) => {
      button.addEventListener("click", closeGuide);
    });
    byId("confirmCancel")?.addEventListener("click", () => settleConfirm(false));
    byId("confirmOk")?.addEventListener("click", () => settleConfirm(true));
    byId("confirmModal")
      ?.querySelector(".modal-scrim")
      ?.addEventListener("click", () => settleConfirm(false));
    setupFormInitialState();
  }

  function setupFormInitialState() {
    syncDiscoveryControls();
    syncPortControls({ changedProfile: true });
    updateCommandPreviews();
  }

  async function refreshDiscovery() {
    const button = byId("discoveryRefresh");
    if (button) button.classList.add("is-loading");
    const iconNode = button?.querySelector(".icon");
    if (iconNode) iconNode.classList.add("spin");
    try {
      await refreshSharedData();
      state.latestLoaded.discover = false;
      await ensureLatestScan("discover", { force: true });
      renderDiscovery();
      toast("Inventory refreshed", "Hosts and scan history are up to date.", "success", 2600);
    } catch (error) {
      toast("Refresh failed", error.message, "error");
    } finally {
      if (iconNode) iconNode.classList.remove("spin");
      if (button) button.classList.remove("is-loading");
    }
  }

  /* ---------------------------------------------------------------------
     Global interactions
  --------------------------------------------------------------------- */

  function handleDocumentClick(event) {
    const target = event.target instanceof Element ? event.target : event.target?.parentElement;
    if (!target) return;

    if (!target.closest(".export-menu-wrap")) closeAllExportMenus();
    if (!target.closest(".new-scan-wrap")) closeNewScanMenu();

    const go = target.closest("[data-go]");
    if (go) {
      navigate(go.dataset.go);
      return;
    }
    const focus = target.closest("[data-focus]");
    if (focus) {
      focusElement(focus.dataset.focus);
      return;
    }
    const fill = target.closest("[data-fill-target]");
    if (fill) {
      fillTarget(fill.dataset.fillTarget, fill.dataset.target);
      return;
    }
    const quick = target.closest("[data-quick-action]");
    if (quick) {
      handleQuickAction(quick.dataset.quickAction);
      return;
    }
    if (target.closest("[data-open-guide]")) {
      openGuide();
      return;
    }
    if (target.closest("[data-close-guide]")) {
      closeGuide();
      return;
    }
    const inventoryFormat = target.closest("[data-inventory-format]");
    if (inventoryFormat) {
      void downloadInventory(inventoryFormat.dataset.inventoryFormat || "csv");
      return;
    }
    const assetTabJump = target.closest("[data-asset-tab-jump]");
    if (assetTabJump) {
      setAssetTab(assetTabJump.dataset.assetTabJump || "inventory");
      byId("page-assets")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    const surfaceCategory = target.closest("[data-surface-category]");
    if (surfaceCategory) {
      state.assetCategory = surfaceCategory.dataset.surfaceCategory;
      state.assetFilter = "all";
      state.assetTab = "inventory";
      renderAssets();
      byId("page-assets")?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    if (target.closest("[data-clear-asset-category]")) {
      state.assetCategory = null;
      renderAssets();
      return;
    }
    if (target.closest("[data-safe-audit]")) {
      configureSafeAudit();
      return;
    }
    const hostScan = target.closest("[data-scan-host-profile]");
    if (hostScan) {
      const select = byId("hostScanProfile");
      startHostScanFromDrawer(
        hostScan.dataset.scanHostProfile,
        select ? select.value : "services"
      );
      return;
    }
    const hostTarget = target.closest("[data-host-address]");
    if (hostTarget) {
      const host = findHost(hostTarget.dataset.hostAddress);
      if (host) {
        openHostDrawer(host);
      } else {
        toast("Host not found", "This host is no longer in the local inventory.", "warning");
      }
      return;
    }
    const openScan = target.closest("[data-open-scan]");
    if (openScan) {
      void openScanDrawer(openScan.dataset.openScan);
      return;
    }
    if (target.closest("[data-close-drawer]")) {
      closeDrawer();
      return;
    }
    const download = target.closest("[data-download]");
    if (download) {
      void downloadScan(download.dataset.download, download.dataset.format || "json");
      return;
    }
    const exportToggle = target.closest("[data-export-toggle]");
    if (exportToggle) {
      const wrap = exportToggle.closest(".export-menu-wrap");
      const menu = wrap?.querySelector(".export-menu");
      if (menu) {
        const willOpen = menu.hidden;
        closeAllExportMenus(willOpen ? menu : null);
        menu.hidden = !willOpen;
        exportToggle.setAttribute("aria-expanded", String(willOpen));
      }
      return;
    }
    if (target.closest("[data-live-log-toggle]")) {
      state.liveLogOpen = !state.liveLogOpen;
      renderLive();
      return;
    }
    if (target.closest("[data-dismiss-live]")) {
      dismissLive();
      return;
    }
    if (target.closest("[data-cancel-live]")) {
      void cancelActiveScan();
      return;
    }
    const portToggle = target.closest("[data-port-toggle]");
    if (portToggle) {
      const wrap = portToggle.closest(".port-row-wrap");
      const detail = wrap?.querySelector(".port-detail");
      if (wrap && detail) {
        const open = wrap.classList.toggle("is-open");
        portToggle.setAttribute("aria-expanded", String(open));
        detail.hidden = !open;
      }
      return;
    }
    const useSettings = target.closest("[data-use-settings]");
    if (useSettings) {
      loadScanSettings(state.drawerScan);
      return;
    }
    const deleteButton = target.closest("[data-delete-scan]");
    if (deleteButton) {
      void deleteScan(deleteButton.dataset.deleteScan);
      return;
    }
    const copyButton = target.closest("[data-copy-target]");
    if (copyButton) {
      const node = byId(copyButton.dataset.copyTarget);
      if (node) void copyText(node.textContent.trim(), "Capability commands copied.");
      return;
    }
    if (target.closest("#drawerScrim")) {
      closeDrawer();
      return;
    }
    if (target.closest("[data-close-guide]")) {
      closeGuide();
      return;
    }
    if (target.closest("[data-confirm-close]")) {
      settleConfirm(false);
      return;
    }
  }

  function configureSafeAudit() {
    if (isCurrentLiveAny()) {
      toast(
        "A scan is already running",
        "Wait for the current sweep to finish before starting another.",
        "warning"
      );
      return;
    }
    const radio = $('input[name="scanProfile"][value="safe"]');
    if (radio) {
      radio.checked = true;
      syncPortControls({ changedProfile: true });
    }
    if (state.inventory.length === 1) {
      const onlyHost = state.inventory[0].address;
      const target = byId("portTarget");
      if (target && !target.value.trim()) target.value = onlyHost;
      updatePortPreview();
    }
    navigate("ports");
    window.setTimeout(() => {
      focusElement("portTarget");
    }, 100);
    toast(
      "Safe audit selected",
      "Choose an authorized target, then launch the scan. Curated non-intrusive checks only.",
      "success",
      4200
    );
  }

  function handleQuickAction(action) {
    closeNewScanMenu();
    if (action === "discover") {
      navigate("discover");
      window.setTimeout(() => focusElement("discoverTarget"), 90);
    } else if (action === "ports") {
      navigate("ports");
      const radio = $('input[name="scanProfile"][value="quick"]');
      if (radio) {
        radio.checked = true;
        syncPortControls({ changedProfile: true });
      }
      window.setTimeout(() => focusElement("portTarget"), 90);
    } else if (action === "services") {
      navigate("ports");
      const radio = $('input[name="scanProfile"][value="services"]');
      if (radio) {
        radio.checked = true;
        syncPortControls({ changedProfile: true });
      }
      window.setTimeout(() => focusElement("portTarget"), 90);
    } else if (action === "safe") {
      navigate("ports");
      const radio = $('input[name="scanProfile"][value="safe"]');
      if (radio) {
        radio.checked = true;
        syncPortControls({ changedProfile: true });
      }
      window.setTimeout(() => focusElement("portTarget"), 90);
    } else if (action === "surface") {
      state.assetTab = "surface";
      navigate("assets");
      window.setTimeout(() => {
        syncAssetTabs();
        renderAssets();
        byId("page-assets")?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 100);
    }
  }

  function handleKeydown(event) {
    const activeElement = document.activeElement;
    const tag = (activeElement?.tagName || "").toLowerCase();
    const typing =
      ["input", "textarea", "select"].includes(tag) || activeElement?.isContentEditable;

    if (event.key === "Escape") {
      if (!byId("confirmModal")?.hidden) {
        settleConfirm(false);
        return;
      }
      if (!byId("guideModal")?.hidden) {
        closeGuide();
        return;
      }
      if (!byId("detailDrawer")?.hidden) {
        closeDrawer();
        return;
      }
      if (!byId("newScanMenu")?.hidden) {
        closeNewScanMenu();
        return;
      }
      closeMobileNav();
      closeAllExportMenus();
      return;
    }
    if (typing) return;
    if (event.key === "g" || event.key === "G") {
      state.gPending = true;
      window.clearTimeout(state.gTimer);
      state.gTimer = window.setTimeout(() => {
        state.gPending = false;
      }, 1400);
      return;
    }
    if (state.gPending && ["1", "2", "3", "4"].includes(event.key)) {
      event.preventDefault();
      state.gPending = false;
      navigate(
        { "1": "overview", "2": "discover", "3": "assets", "4": "ports", "5": "history" }[
          event.key
        ]
      );
      return;
    }
    if (event.key === "/") {
      event.preventDefault();
      const target =
        state.route === "discover"
          ? byId("discoverySearch")
          : state.route === "assets"
            ? byId("assetSearch")
            : state.route === "history"
              ? byId("historySearch")
              : byId("portResultSearch");
      target?.focus();
    }
  }

  function setupGlobalEvents() {
    document.addEventListener("click", handleDocumentClick);
    document.addEventListener("keydown", handleKeydown);
    window.addEventListener("hashchange", () => {
      void applyRoute();
    });
    window.addEventListener("resize", () => {
      if (window.innerWidth > 960) closeMobileNav();
    });
    document.querySelectorAll(".nav-link").forEach((link) => {
      link.addEventListener("click", () => closeMobileNav());
    });
    window.addEventListener("beforeunload", () => {
      if (state.pollTimer) window.clearInterval(state.pollTimer);
    });
  }

  function showFatalBootError(error) {
    const message = error.message || "The local API did not answer.";
    toast("ReconDeck could not start", `${message} Refresh the page or restart the local app.`, "error", 12000);
    const recent = byId("recentScans");
    if (recent) {
      recent.innerHTML = `<div class="recent-empty"><span class="recent-empty-icon">${icon(
        "alert"
      )}</span><span><strong>Local API unavailable</strong><span>${escapeHtml(
        message
      )}</span></span></div>`;
    }
    setText("nodeIp", "API not reachable");
    setText("nmapMini", "unavailable");
    setText("arpMini", "unavailable");
    const submit = byId("discoverSubmit");
    if (submit) submit.disabled = true;
    state.bootstrapped = false;
  }

  async function init() {
    initTheme();
    updateHeaderClock();
    setupGlobalEvents();
    setupForms();
    updateCommandPreviews();
    renderLiveHeader();

    const initialRoute = currentRouteFromHash();
    state.route = initialRoute;
    $$(".page").forEach((page) => {
      page.classList.toggle("is-active", page.dataset.page === initialRoute);
    });
    $$("[data-route]").forEach((link) => {
      link.classList.toggle("is-active", link.dataset.route === initialRoute);
    });
    setText("pageCrumb", (PAGE_META[initialRoute] || PAGE_META.overview).title);

    if (!API_TOKEN) {
      showFatalBootError(new Error("The page is missing its local session token."));
      return;
    }
    try {
      await loadBootstrap({ initial: true });
      await applyRoute();
      if (state.activeLive && ACTIVE_STATUSES.has(state.activeLive.status)) {
        updateFormAvailability();
        beginLivePolling();
      }
    } catch (error) {
      showFatalBootError(error);
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
