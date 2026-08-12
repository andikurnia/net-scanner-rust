const REFRESH_MS = 3000;

let state = null;
let activeSubnet = 0;
let view = "grid";
let sort = { key: "ip", dir: 1 };
let filters = { used: false, available: false };
let pageSize = 50;
let page = 0;

const PAGE_SIZES = [25, 50, 100, 250, 500];

try {
  view = localStorage.getItem("net-scanner-view") || "grid";
  const saved = JSON.parse(localStorage.getItem("net-scanner-filters") || "null");
  if (saved) filters = { used: !!saved.used, available: !!saved.available };
  const ps = parseInt(localStorage.getItem("net-scanner-page-size") || "50", 10);
  if (PAGE_SIZES.includes(ps)) pageSize = ps;
} catch (_) { /* storage unavailable */ }

function saveFilters() {
  try { localStorage.setItem("net-scanner-filters", JSON.stringify(filters)); } catch (_) {}
}

const LIST_COLUMNS = [
  ["ip", "IP"],
  ["status", "Status"],
  ["device", "Device"],
  ["os", "OS"],
  ["mac", "MAC"],
  ["rtt", "RTT"],
];

const SORTERS = {
  ip: (h) => ({ v: h.ip.split(".").map(Number), missing: false }),
  status: (h) => ({ v: h.used ? 0 : 1, missing: false }),
  device: (h) => {
    const name = h.hostname || h.vendor || h.mac || "";
    return { v: name.toLowerCase(), missing: name === "" };
  },
  os: (h) => ({ v: h.os || "", missing: !h.os }),
  mac: (h) => ({ v: h.mac || "", missing: !h.mac }),
  rtt: (h) => ({ v: h.rtt_ms, missing: h.rtt_ms == null }),
};

function sortedHosts(hosts) {
  const get = SORTERS[sort.key];
  return [...hosts].sort((a, b) => {
    const av = get(a);
    const bv = get(b);
    if (av.missing && bv.missing) return 0;
    if (av.missing) return 1;
    if (bv.missing) return -1;
    let cmp;
    if (typeof av.v === "number") {
      cmp = av.v - bv.v;
    } else if (Array.isArray(av.v)) {
      const len = Math.max(av.v.length, bv.v.length);
      for (let i = 0; i < len; i++) {
        cmp = (av.v[i] ?? 0) - (bv.v[i] ?? 0);
        if (cmp) break;
      }
    } else {
      cmp = String(av.v).localeCompare(String(bv.v), undefined, { numeric: true });
    }
    return cmp * sort.dir;
  });
}

try {
  view = localStorage.getItem("net-scanner-view") || "grid";
} catch (_) { /* storage unavailable */ }

const $ = (id) => document.getElementById(id);

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

async function refresh() {
  try {
    const res = await fetch("/api/state");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state = await res.json();
    render();
  } catch (err) {
    $("statusPill").textContent = "offline";
    $("statusPill").className = "pill";
    $("errorBanner").textContent = "Cannot reach backend: " + err.message;
    $("errorBanner").classList.remove("hidden");
  }
}

function render() {
  renderStatus();
  renderStats();
  renderProgress();
  renderSubnets();
  renderViewToggle();
  renderFilterBar();
  renderGrid();
  $("errorBanner").classList.toggle("hidden", !state.error);
  $("errorBanner").textContent = state.error || "";
}

function renderStatus() {
  const pill = $("statusPill");
  const scanning = state.status === "scanning";
  pill.textContent = scanning ? `scanning\u2026 ${state.phase}` : "idle";
  pill.className = "pill " + (scanning ? "scanning" : "idle");
  $("scanBtn").disabled = scanning;
}

function fmtTime(unix) {
  if (!unix) return "never";
  const d = new Date(unix * 1000);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function renderStats() {
  $("statTotal").textContent = state.total_ips.toLocaleString();
  $("statUsed").textContent = state.used_total.toLocaleString();
  $("statAvail").textContent = state.available_total.toLocaleString();
  $("statLast").textContent = fmtTime(state.last_scan_unix);
  const dur = state.last_duration_ms != null ? `took ${state.last_duration_ms} ms` : "";
  $("statMeta").textContent = [state.method.toUpperCase(), dur].filter(Boolean).join(" \u00b7 ") || "\u2013";
}

function renderProgress() {
  $("phaseLabel").textContent = state.status === "scanning" ? state.phase : "idle";
  const pct = state.status === "scanning" && state.total_ips > 0
    ? Math.round((state.scanned / state.total_ips) * 100)
    : 100;
  $("progressBar").style.width = pct + "%";
  $("progressText").textContent = state.status === "scanning"
    ? `${state.scanned.toLocaleString()} / ${state.total_ips.toLocaleString()}`
    : state.total_ips > 0 ? `${state.total_ips.toLocaleString()} IPs scanned` : "";
}

function renderSubnets() {
  const bar = $("subnetBar");
  if (state.subnets.length === 0) {
    bar.innerHTML = "";
    return;
  }
  if (activeSubnet >= state.subnets.length) activeSubnet = 0;

  bar.innerHTML = state.subnets.map((s, i) => {
    const cls = i === activeSubnet ? "subnet-tab active" : "subnet-tab";
    return `<button class="${cls}" data-idx="${i}" title="interface ${esc(s.interface)}">
        ${esc(s.cidr)} <span class="tab-count">(${s.used}/${s.total})</span>
      </button>`;
  }).join("");

  bar.querySelectorAll(".subnet-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeSubnet = Number(btn.dataset.idx);
      page = 0;
      renderSubnets();
      renderGrid();
    });
  });
}

function renderViewToggle() {
  $("viewGrid").classList.toggle("active", view === "grid");
  $("viewList").classList.toggle("active", view === "list");
}

function renderFilterBar() {
  $("filterUsed").checked = filters.used;
  $("filterAvailable").checked = filters.available;
}

function applyFilters(hosts) {
  const anyActive = filters.used || filters.available;
  if (!anyActive) return hosts;
  return hosts.filter((h) => (filters.used && h.used) || (filters.available && !h.used));
}

function cellLabel(h) {
  if (h.hostname) return h.hostname;
  if (h.vendor) return h.vendor;
  if (h.os) return h.os;
  if (h.mac) return h.mac;
  return "unknown";
}

function renderGrid() {
  const subnet = state.subnets[activeSubnet];
  const title = $("gridTitle");
  if (!subnet) {
    $("grid").innerHTML = "<p>No data yet. Waiting for the first scan\u2026</p>";
    $("pager").innerHTML = "";
    title.textContent = "Hosts";
    return;
  }

  const selfIps = new Set(state.self_ips || []);
  const visible = applyFilters(subnet.hosts);
  const sorted = view === "list" ? sortedHosts(visible) : visible;

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  if (page < 0) page = 0;
  if (page >= totalPages) page = totalPages - 1;
  const start = page * pageSize;
  const paged = sorted.slice(start, start + pageSize);

  const anyFilter = filters.used || filters.available;
  title.textContent = anyFilter
    ? `${subnet.cidr} \u00b7 showing ${visible.length} of ${subnet.hosts.length} (${subnet.used} used, ${subnet.available} available)`
    : `${subnet.cidr} \u00b7 ${subnet.used} used, ${subnet.available} available`;

  $("grid").className = view === "grid" ? "grid" : "grid list";
  $("grid").innerHTML = view === "grid"
    ? gridMarkup(paged, selfIps)
    : listMarkup(paged, selfIps);

  if (paged.length === 0) {
    $("grid").innerHTML = "<p class=\"empty\">No hosts match the current filter.</p>";
  }

  $("grid").querySelectorAll("[data-ip]").forEach((el) => {
    el.addEventListener("click", () => showDetails(el.dataset.ip));
  });

  if (view === "list") {
    $("grid").querySelectorAll("th.sortable").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        if (sort.key === key) {
          sort.dir = -sort.dir;
        } else {
          sort = { key, dir: 1 };
        }
        renderGrid();
      });
    });
  }

  renderPager(sorted.length, totalPages);
}

function renderPager(total, totalPages) {
  const pager = $("pager");
  pager.innerHTML = `
    <button class="page-btn" id="pagePrev" ${page <= 0 ? "disabled" : ""} title="Previous page">&#8249; Prev</button>
    <span class="page-info">Page ${page + 1} of ${totalPages} \u00b7 ${total} host${total === 1 ? "" : "s"}</span>
    <button class="page-btn" id="pageNext" ${page >= totalPages - 1 ? "disabled" : ""} title="Next page">Next &#8250;</button>
    <label class="page-size-label">Per page
      <select id="pageSizeSel" title="Items per page">
        ${PAGE_SIZES.map((n) => `<option value="${n}" ${n === pageSize ? "selected" : ""}>${n}</option>`).join("")}
      </select>
    </label>`;

  $("pagePrev").addEventListener("click", () => {
    if (page > 0) {
      page--;
      renderGrid();
    }
  });
  $("pageNext").addEventListener("click", () => {
    if (page < totalPages - 1) {
      page++;
      renderGrid();
    }
  });
  $("pageSizeSel").addEventListener("change", (e) => {
    pageSize = Number(e.target.value);
    page = 0;
    try { localStorage.setItem("net-scanner-page-size", String(pageSize)); } catch (_) {}
    renderGrid();
  });
}

function gridMarkup(hosts, selfIps) {
  return hosts.map((h) => {
    const isSelf = selfIps.has(h.ip);
    const cls = ["cell", h.used ? "used" : "available", isSelf ? "self" : ""].filter(Boolean).join(" ");
    const label = h.used ? cellLabel(h) : "available";
    const clickable = h.used ? `data-ip="${esc(h.ip)}"` : "";
    const hint = h.used
      ? `${h.ip} \u2014 used${h.os ? ` \u00b7 ${h.os}` : ""}${h.vendor ? ` \u00b7 ${h.vendor}` : ""}`
      : `${h.ip} \u2014 available`;
    return `<div class="${cls}" ${clickable} title="${esc(hint)}">
        <div class="cell-ip">${esc(h.ip)}</div>
        <div class="cell-label">${esc(label)}</div>
      </div>`;
  }).join("");
}

function listMarkup(hosts, selfIps) {
  const sorted = sortedHosts(hosts);
  const headers = LIST_COLUMNS.map(([key, label]) => {
    const indicator = sort.key === key ? (sort.dir === 1 ? " \u25b2" : " \u25bc") : "";
    const cls = sort.key === key ? "sortable sorted" : "sortable";
    return `<th class="${cls}" data-sort="${key}" title="Sort by ${label}">${label}${indicator}</th>`;
  }).join("");

  return `<table class="host-table">
    <thead><tr>${headers}</tr></thead>
    <tbody>${sorted.map((h) => {
      const isSelf = selfIps.has(h.ip);
      const cls = ["host-row", h.used ? "used" : "available", isSelf ? "self" : ""].filter(Boolean).join(" ");
      const identity = [h.hostname, h.vendor].filter(Boolean).join(" \u00b7 ") || "unknown";
      const statusText = h.used ? (isSelf ? "Used \u00b7 this host" : "Used") : "Available";
      return `<tr class="${cls}" data-ip="${esc(h.ip)}" title="${esc(h.ip)} \u2014 ${statusText.toLowerCase()}">
        <td class="list-ip">${esc(h.ip)}</td>
        <td><span class="status-badge ${h.used ? "used" : "available"}">${statusText}</span></td>
        <td class="list-device">${esc(identity)}</td>
        <td class="list-os">${esc(h.os || "\u2013")}</td>
        <td class="list-mac">${esc(h.mac || "\u2013")}</td>
        <td class="list-rtt">${h.rtt_ms != null ? `${h.rtt_ms} ms` : "\u2013"}</td>
      </tr>`;
    }).join("")}</tbody>
  </table>`;
}

function showDetails(ip) {
  const subnet = state.subnets[activeSubnet];
  const h = subnet.hosts.find((x) => x.ip === ip);
  if (!h) return;

  $("modalTitle").textContent = h.ip;
  const rows = [
    ["Status", h.used ? "Used" : "Available"],
    ["MAC", h.mac || "\u2013"],
    ["Vendor", h.vendor || "\u2013"],
    ["OS", h.os || "\u2013"],
    ["Hostname", h.hostname || "\u2013"],
    ["Response time", h.rtt_ms != null ? `${h.rtt_ms} ms` : "\u2013"],
  ];
  $("modalBody").innerHTML = rows
    .map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`)
    .join("");
  $("detailModal").classList.remove("hidden");
}

function hideModal() {
  $("detailModal").classList.add("hidden");
}

document.addEventListener("DOMContentLoaded", () => {
  $("scanBtn").addEventListener("click", async () => {
    try {
      await fetch("/api/scan", { method: "POST" });
    } catch (_) { /* backend will flag offline on next refresh */ }
  });
  $("modalClose").addEventListener("click", hideModal);
  $("detailModal").addEventListener("click", (e) => {
    if (e.target === $("detailModal")) hideModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideModal();
  });
  $("viewGrid").addEventListener("click", () => {
    view = "grid";
    try { localStorage.setItem("net-scanner-view", view); } catch (_) {}
    renderViewToggle();
    renderGrid();
  });
  $("viewList").addEventListener("click", () => {
    view = "list";
    try { localStorage.setItem("net-scanner-view", view); } catch (_) {}
    renderViewToggle();
    renderGrid();
  });
  $("filterUsed").addEventListener("change", (e) => {
    filters.used = e.target.checked;
    saveFilters();
    renderGrid();
  });
  $("filterAvailable").addEventListener("change", (e) => {
    filters.available = e.target.checked;
    saveFilters();
    renderGrid();
  });
  $("filterClear").addEventListener("click", () => {
    filters = { used: false, available: false };
    saveFilters();
    renderFilterBar();
    renderGrid();
  });

  refresh();
  setInterval(refresh, REFRESH_MS);
});
