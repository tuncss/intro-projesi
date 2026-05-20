// Adjust these interface sets if your VM names differ.
const LAB_IFACES = new Set(["eth0", "enp0s3", "enp0s8", "wlo1", "lab0", "lo"]);
const INET_IFACES = new Set(["eth1", "enp0s9"]);

function ifaceBadge(name) {
  if (LAB_IFACES.has(name)) return { label: "lab", color: "purple" };
  if (INET_IFACES.has(name)) return { label: "inet", color: "blue" };
  return { label: name || "?", color: "gray" };
}

function escapeHtml(str) {
  const p = document.createElement("p");
  p.textContent = str;
  return p.innerHTML;
}

const state = {
  flows: [],
  blocks: [],
  lastTotal: 0,
  latestRate: 0,
  lastAlertAt: null,
  tick: 0,
  rateLabels: [],
  rateData: []
};

const el = {
  status: document.getElementById("statusBadge"),
  uptime: document.getElementById("uptime"),
  total: document.getElementById("totalFlows"),
  benign: document.getElementById("benignFlows"),
  threats: document.getElementById("threatFlows"),
  blocked: document.getElementById("blockedCount"),
  postureThreatRatio: document.getElementById("postureThreatRatio"),
  postureFlowRate: document.getElementById("postureFlowRate"),
  postureBlocks: document.getElementById("postureBlocks"),
  postureLastAlert: document.getElementById("postureLastAlert"),
  flowTable: document.getElementById("flowTable"),
  flowHint: document.getElementById("flowCountHint"),
  flowPanel: document.querySelector(".flow-panel"),
  threatOnlyToggle: document.getElementById("threatOnlyToggle"),
  blockedList: document.getElementById("blockedList"),
  emptyBlocks: document.getElementById("emptyBlocks"),
  topTalkers: document.getElementById("topTalkers"),
  attackTimeline: document.getElementById("attackTimeline"),
  resetBtn: document.getElementById("resetBtn"),
  toastHost: document.getElementById("toastHost")
};

let isPaused = false;
let pendingFlush = false;
let activeFilter = "ALL";
let threatsOnly = false;
let countdownTimer = null;

Chart.defaults.color = "#94a3b8";
Chart.defaults.font.family = "'Inter', sans-serif";

const classChart = new Chart(document.getElementById("classChart"), {
  type: "doughnut",
  data: { 
    labels: [], 
    datasets: [{ 
      data: [], 
      backgroundColor: ["#10b981", "#f43f5e", "#f59e0b", "#8b5cf6"],
      borderColor: "#0f172a",
      borderWidth: 2,
      hoverOffset: 4
    }] 
  },
  options: { 
    responsive: true, 
    maintainAspectRatio: false, 
    cutout: '75%',
    plugins: { 
      legend: { position: 'bottom', labels: { boxWidth: 10, padding: 15 } } 
    } 
  }
});

const rateChart = new Chart(document.getElementById("rateChart"), {
  type: "line",
  data: { 
    labels: [], 
    datasets: [{ 
      label: "Packets/sec", 
      data: [], 
      borderColor: "#00f0ff", 
      backgroundColor: "rgba(0, 240, 255, 0.15)", 
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4,
      tension: 0.4, 
      fill: true 
    }] 
  },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { intersect: false, mode: 'index' },
    scales: {
      x: { 
        ticks: { maxTicksLimit: 10, font: { family: "'JetBrains Mono'" } }, 
        grid: { display: false } 
      },
      y: { 
        beginAtZero: true, 
        grid: { color: "rgba(255,255,255,0.05)", borderDash: [5, 5] },
        border: { display: false }
      }
    },
    plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } }
  }
});

function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return `${h.toString().padStart(2,'0')}:${m.toString().padStart(2,'0')}:${r.toString().padStart(2,'0')}`;
}

function fmtTime(ts) {
  const d = new Date((ts || Date.now() / 1000) * 1000);
  return d.toISOString().split('T')[1].slice(0, -1);
}

function className(label, conf) {
  if (label === "BENIGN") return "tag tag-green";
  if (conf < 0.85) return "tag tag-yellow";
  return "tag tag-red";
}

function badgeHtml(iface) {
  const badge = ifaceBadge(iface);
  return `<span class="iface iface-${badge.color}">${badge.label}</span>`;
}

function flowRow(evt) {
  const conf = Number(evt.confidence || 0);
  const dst = `${evt.dst_ip || "?"}:${evt.dst_port || "?"}`;
  const pct = Math.round(conf * 100);
  const color = conf > 0.85 ? "#f43f5e" : "#f59e0b";
  const evtData = JSON.stringify({
    proto: evt.proto,
    src_port: evt.src_port,
    n_packets: evt.n_packets,
    detection_source: evt.detection_source,
    close_reason: evt.close_reason
  });

  return `<tr data-src="${escapeHtml(evt.src_ip || "")}" data-evt='${escapeHtml(evtData)}' class="group ${evt.label === "BENIGN" ? "hover:bg-white/5" : "threat-row"} transition-colors cursor-pointer">
    <td class="px-4 py-2 text-slate-500">${fmtTime(evt.ts)}</td>
    <td class="px-4 py-2">${badgeHtml(evt.interface)}</td>
    <td class="truncate px-4 py-2 text-slate-400 group-hover:text-slate-300 transition-colors">${escapeHtml(evt.src_ip || "?")} <span class="text-slate-600">→</span> ${escapeHtml(dst)}</td>
    <td class="px-4 py-2"><span class="${className(evt.label, conf)}">${escapeHtml(evt.label || "?")}</span></td>
    <td class="px-4 py-2 text-right">
      <div class="flex items-center justify-end gap-2">
        <div class="h-1.5 w-16 bg-black/40 rounded-full overflow-hidden border border-white/5"><div class="h-full rounded-full" style="width:${pct}%;background:${color}"></div></div>
        <span class="font-mono text-xs w-8" style="color:${color}">${pct}%</span>
      </div>
    </td>
  </tr>`;
}

function matchesViewFilters(flow) {
  if (activeFilter !== "ALL" && flow.label !== activeFilter) return false;
  if (threatsOnly && flow.label === "BENIGN") return false;
  return true;
}

function getVisibleFlows() {
  return state.flows.filter(matchesViewFilters);
}

function renderTopTalkers() {
  if (!el.topTalkers) return;
  const counts = {};
  state.flows.forEach((flow) => {
    if (!flow.src_ip || flow.label === "BENIGN") return;
    counts[flow.src_ip] = (counts[flow.src_ip] || 0) + 1;
  });

  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  if (!sorted.length) {
    el.topTalkers.innerHTML = `<div class="text-center py-4 text-slate-500 text-xs">No threat sources</div>`;
    return;
  }

  const max = sorted[0][1];
  el.topTalkers.innerHTML = sorted.map(([ip, count]) => {
    const pct = Math.round(count / max * 100);
    return `<div class="talker-item">
      <div class="talker-header">
        <span class="font-mono text-xs text-rose-400">${escapeHtml(ip)}</span>
        <span class="font-mono text-xs text-slate-500">${count}</span>
      </div>
      <div class="talker-bar-track">
        <div class="talker-bar-fill" style="width:${pct}%"></div>
      </div>
    </div>`;
  }).join("");
}

function blockStatusForIp(ip) {
  const now = Date.now() / 1000;
  return state.blocks.some((block) => block.ip === ip && (block.expires_at || 0) > now)
    ? "blocked"
    : "observed";
}

function renderAttackTimeline() {
  if (!el.attackTimeline) return;
  const threats = state.flows.filter((flow) => flow.label && flow.label !== "BENIGN").slice(0, 6);
  if (!threats.length) {
    el.attackTimeline.innerHTML = `<div class="text-center py-4 text-slate-500 text-xs">No threat events yet</div>`;
    return;
  }

  el.attackTimeline.innerHTML = threats.map((flow) => {
    const conf = Math.round(Number(flow.confidence || 0) * 100);
    const status = blockStatusForIp(flow.src_ip);
    return `<div class="timeline-item ${status === "blocked" ? "is-blocked" : ""}">
      <div class="timeline-dot"></div>
      <div class="min-w-0">
        <div class="timeline-title">
          <span>${escapeHtml(flow.label)}</span>
          <strong>${conf}%</strong>
        </div>
        <div class="timeline-detail">
          ${escapeHtml(flow.src_ip || "?")} - ${escapeHtml(flow.detection_source || "ml")} - <span class="${status === "blocked" ? "text-rose-500" : "text-orange-400"}">${status}</span>
        </div>
      </div>
    </div>`;
  }).join("");
}

function renderSituation(metrics = {}) {
  const total = Number(metrics.total_flows ?? el.total.textContent ?? state.flows.length) || 0;
  const threats = Number(metrics.threats ?? el.threats.textContent ?? 0) || 0;
  const ratio = total ? Math.round((threats / total) * 100) : 0;

  el.postureThreatRatio.textContent = `${ratio}%`;
  el.postureFlowRate.textContent = `${state.latestRate}/s`;
  el.postureBlocks.textContent = String(state.blocks.length);
  el.postureLastAlert.textContent = state.lastAlertAt
    ? `${fmtUptime((Date.now() - state.lastAlertAt) / 1000)} ago`
    : "none";
}

function renderFlowInsights(metrics = {}) {
  renderTopTalkers();
  renderAttackTimeline();
  renderSituation(metrics);
}

const MAX_FLOWS = 100;
let renderQueued = false;

function renderFlows() {
  if (isPaused) {
    pendingFlush = true;
    return;
  }
  el.flowTable.innerHTML = getVisibleFlows().map(flowRow).join("");
  el.flowHint.textContent = `${state.flows.length} records`;
}

function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    renderFlows();
  });
}

function startCountdown() {
  if (countdownTimer) clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    const now = Date.now() / 1000;
    document.querySelectorAll(".countdown").forEach(el => {
      const exp = Number(el.dataset.exp);
      const left = Math.max(0, Math.ceil(exp - now));
      el.textContent = left ? `${left}s remaining` : "expired";
      if (left === 0) el.closest(".block-item")?.classList.add("expired");
    });
  }, 1000);
}

function ingestFlows(batch) {
  const incoming = batch.slice().reverse();
  state.flows = incoming.concat(state.flows);
  if (state.flows.length > MAX_FLOWS) state.flows.length = MAX_FLOWS;
  scheduleRender();
}

function renderBlocks(blocks) {
  state.blocks = blocks || [];
  el.blocked.textContent = state.blocks.length;
  
  if (!state.blocks.length) {
    el.emptyBlocks.classList.remove("hidden");
    el.blockedList.innerHTML = "";
    return;
  }
  
  el.emptyBlocks.classList.add("hidden");
  const now = Date.now() / 1000;
  
  el.blockedList.innerHTML = state.blocks.map((block) => {
    const start = Number(block.blocked_at || now);
    const exp = Number(block.expires_at || now);
    const ttl = Math.max(1, exp - start);
    const left = Math.max(0, Math.ceil(exp - now));
    const pct = Math.round((Math.max(0, exp - now) / ttl) * 100);

    return `<div class="block-item ${left ? "" : "expired"}">
      <div class="min-w-0 flex-1">
        <div class="flex items-center justify-between mb-1">
          <span class="font-mono text-sm text-rose-400 font-medium">${escapeHtml(block.ip)}</span>
          <span class="countdown font-mono text-[10px] text-slate-500 tabular-nums" data-exp="${exp}">${left ? `${left}s remaining` : "expired"}</span>
        </div>
        <div class="text-xs text-slate-400 mb-2 truncate">${escapeHtml(block.reason || "blocked")}</div>
        <div class="block-progress"><div class="block-progress-fill" data-start="${start}" data-exp="${exp}" style="width:${pct}%"></div></div>
      </div>
      <button class="unblock ml-4" data-ip="${escapeHtml(block.ip)}">Unblock</button>
    </div>`;
  }).join("");

  startCountdown();
  renderFlowInsights();
}

function updateMetrics(metrics) {
  el.uptime.textContent = fmtUptime(metrics.uptime);
  el.total.textContent = (metrics.total_flows ?? 0).toLocaleString();
  el.benign.textContent = (metrics.benign ?? 0).toLocaleString();
  el.threats.textContent = (metrics.threats ?? 0).toLocaleString();
  el.blocked.textContent = metrics.blocked ?? state.blocks.length;

  const perClass = metrics.per_class || {};
  classChart.data.labels = Object.keys(perClass);
  classChart.data.datasets[0].data = Object.values(perClass);
  classChart.update("none");

  const delta = Math.max(0, (metrics.total_flows || 0) - state.lastTotal);
  state.latestRate = delta;
  state.lastTotal = metrics.total_flows || 0;
  state.rateLabels.push(new Date().toLocaleTimeString());
  state.rateData.push(delta);
  if (state.rateLabels.length > 60) {
    state.rateLabels.shift();
    state.rateData.shift();
  }
  rateChart.data.labels = state.rateLabels;
  rateChart.data.datasets[0].data = state.rateData;
  rateChart.update("none");
  renderSituation(metrics);
}

async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    state.flows = (data.recent || []).slice(0, MAX_FLOWS);
    state.lastTotal = data.total_flows || 0;
    renderFlows();
    renderBlocks(data.blocked || []);
    updateMetrics({ ...data, blocked: (data.blocked || []).length });
  } catch (err) {
    console.error("fetchStatus error", err);
  }
}

function toast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.innerHTML = `<i data-feather="alert-circle" class="w-4 h-4 text-rose-500"></i> <span>${message}</span>`;
  el.toastHost.appendChild(node);
  feather.replace();
  setTimeout(() => node.remove(), 4500);
}

document.getElementById("pauseBtn").addEventListener("click", () => {
  isPaused = !isPaused;
  const btn = document.getElementById("pauseBtn");
  const badge = document.getElementById("liveBadge");

  if (isPaused) {
    btn.innerHTML = `<i data-feather="play" class="w-3 h-3"></i> Resume`;
    btn.classList.add("paused");
    badge.textContent = "PAUSED";
    badge.classList.add("paused-badge");
    el.flowPanel?.classList.add("is-paused");
  } else {
    btn.innerHTML = `<i data-feather="pause" class="w-3 h-3"></i> Pause`;
    btn.classList.remove("paused");
    badge.textContent = "LIVE";
    badge.classList.remove("paused-badge");
    el.flowPanel?.classList.remove("is-paused");
    if (pendingFlush) {
      pendingFlush = false;
      renderFlows();
    }
  }
  feather.replace();
});

document.getElementById("filterPills").addEventListener("click", (event) => {
  const pill = event.target.closest(".filter-pill");
  if (!pill) return;
  document.querySelectorAll(".filter-pill").forEach((item) => item.classList.remove("active"));
  pill.classList.add("active");
  activeFilter = pill.dataset.filter;
  renderFlows();
});

el.threatOnlyToggle?.addEventListener("change", (event) => {
  threatsOnly = event.target.checked;
  renderFlows();
});

el.flowTable.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-evt]");
  if (!row) return;

  const next = row.nextElementSibling;
  if (next?.classList.contains("detail-row")) {
    next.remove();
    return;
  }

  let detailData;
  try {
    detailData = JSON.parse(row.dataset.evt);
  } catch {
    return;
  }

  const detail = document.createElement("tr");
  detail.className = "detail-row";
  detail.innerHTML = `<td colspan="5" class="detail-cell">
    <div class="detail-grid">
      <div><div class="dl">Proto</div><div class="dv">${escapeHtml(detailData.proto || "?")}</div></div>
      <div><div class="dl">Src Port</div><div class="dv">${escapeHtml(detailData.src_port || "?")}</div></div>
      <div><div class="dl">Packets</div><div class="dv">${escapeHtml(detailData.n_packets ?? "?")}</div></div>
      <div><div class="dl">Detection</div><div class="dv">${escapeHtml(detailData.detection_source || "ml")}</div></div>
      <div><div class="dl">Close</div><div class="dv">${escapeHtml(detailData.close_reason || "?")}</div></div>
    </div>
  </td>`;
  row.after(detail);
});

el.blockedList.addEventListener("click", async (event) => {
  const button = event.target.closest(".unblock");
  if (!button) return;
  button.innerHTML = '<span class="w-3 h-3 rounded-full border-2 border-slate-400 border-t-transparent animate-spin block"></span>';
  await fetch("/api/unblock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: button.dataset.ip }) });
  await fetchStatus();
});

el.resetBtn.addEventListener("click", async () => {
  if (!confirm("Reset demo counters and unblock managed IPs?")) return;
  const originalHtml = el.resetBtn.innerHTML;
  el.resetBtn.innerHTML = '<span class="w-4 h-4 rounded-full border-2 border-white border-t-transparent animate-spin block"></span> Resetting...';
  await fetch("/api/reset", { method: "POST" });
  state.flows = [];
  state.blocks = [];
  state.lastTotal = 0;
  state.latestRate = 0;
  state.lastAlertAt = null;
  state.rateLabels = [];
  state.rateData = [];
  renderFlows();
  renderBlocks([]);
  await fetchStatus();
  el.resetBtn.innerHTML = originalHtml;
});

const socket = io();
socket.on("connect", () => {
  el.status.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 block indicator-pulse"></span><span class="status-text tracking-widest">SYSTEM ONLINE</span>';
  el.status.className = "status-dot online flex items-center gap-2";
  fetchStatus();
});
socket.on("disconnect", () => {
  el.status.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-slate-400 block"></span><span class="status-text tracking-widest">SYSTEM OFFLINE</span>';
  el.status.className = "status-dot offline flex items-center gap-2";
});
socket.on("flows", ingestFlows);
// Backward compat
socket.on("flow", (evt) => ingestFlows([evt]));
socket.on("alert", (evt) => {
  state.lastAlertAt = Date.now();
  toast(`${evt.type || "alert"} ${evt.ip || ""} ${evt.reason || ""}`.trim());
  document.querySelectorAll("tr[data-src]").forEach((row) => {
    if (row.dataset.src === evt.ip) row.classList.add("alert-row");
  });
  renderSituation();
});
socket.on("metrics", async (metrics) => {
  state.tick += 1;
  updateMetrics(metrics);
  if (state.tick % 5 === 0) {
    const res = await fetch("/api/status");
    const data = await res.json();
    renderBlocks(data.blocked || []);
  } else {
    renderBlocks(state.blocks);
  }
});
