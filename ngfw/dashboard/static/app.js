// Adjust these interface sets if your VM names differ.
const LAB_IFACES = new Set(["eth0", "enp0s3", "enp0s8"]);
const INET_IFACES = new Set(["eth1", "enp0s9"]);
function ifaceBadge(name) {
  if (LAB_IFACES.has(name)) return { label: "lab", color: "purple" };
  if (INET_IFACES.has(name)) return { label: "inet", color: "blue" };
  return { label: name || "?", color: "gray" };
}

const state = {
  flows: [],
  blocks: [],
  lastTotal: 0,
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
  flowTable: document.getElementById("flowTable"),
  flowHint: document.getElementById("flowCountHint"),
  blockedList: document.getElementById("blockedList"),
  resetBtn: document.getElementById("resetBtn"),
  toastHost: document.getElementById("toastHost")
};

const classChart = new Chart(document.getElementById("classChart"), {
  type: "doughnut",
  data: { labels: [], datasets: [{ data: [], backgroundColor: ["#22c55e", "#ef4444", "#f97316", "#eab308"] }] },
  options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#cbd5e1" } } } }
});

const rateChart = new Chart(document.getElementById("rateChart"), {
  type: "line",
  data: { labels: [], datasets: [{ label: "flows/sec", data: [], borderColor: "#38bdf8", backgroundColor: "rgba(56,189,248,.15)", tension: .25, fill: true }] },
  options: {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      x: { ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
      y: { beginAtZero: true, ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } }
    },
    plugins: { legend: { labels: { color: "#cbd5e1" } } }
  }
});

function fmtUptime(seconds) {
  const s = Math.max(0, Math.floor(seconds || 0));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return h ? `${h}h ${m}m` : m ? `${m}m ${r}s` : `${r}s`;
}

function fmtTime(ts) {
  return new Date((ts || Date.now() / 1000) * 1000).toLocaleTimeString();
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
  return `<tr data-src="${evt.src_ip || ""}" class="${evt.label === "BENIGN" ? "" : "threat-row"}">
    <td class="px-3 py-3 text-slate-400">${fmtTime(evt.ts)}</td>
    <td class="px-3 py-3">${badgeHtml(evt.interface)}</td>
    <td class="truncate px-3 py-3 font-mono text-xs">${evt.src_ip || "?"} -> ${dst}</td>
    <td class="px-3 py-3"><span class="${className(evt.label, conf)}">${evt.label || "?"}</span></td>
    <td class="px-3 py-3">${Math.round(conf * 100)}%</td>
  </tr>`;
}

function renderFlows() {
  el.flowTable.innerHTML = state.flows.map(flowRow).join("");
  el.flowHint.textContent = `${state.flows.length} rows`;
}

function renderBlocks(blocks) {
  state.blocks = blocks || [];
  el.blocked.textContent = state.blocks.length;
  if (!state.blocks.length) {
    el.blockedList.innerHTML = `<div class="empty">No blocked IPs</div>`;
    return;
  }
  const now = Date.now() / 1000;
  el.blockedList.innerHTML = state.blocks.map((b) => {
    const left = Math.max(0, Math.ceil((b.expires_at || now) - now));
    return `<div class="block-item">
      <div class="min-w-0"><div class="font-mono text-sm">${b.ip}</div><div class="truncate text-xs text-slate-400">${b.reason || ""} · ${left}s</div></div>
      <button class="unblock" data-ip="${b.ip}">Unblock</button>
    </div>`;
  }).join("");
}

function updateMetrics(metrics) {
  el.uptime.textContent = fmtUptime(metrics.uptime);
  el.total.textContent = metrics.total_flows ?? 0;
  el.benign.textContent = metrics.benign ?? 0;
  el.threats.textContent = metrics.threats ?? 0;
  el.blocked.textContent = metrics.blocked ?? state.blocks.length;

  const perClass = metrics.per_class || {};
  classChart.data.labels = Object.keys(perClass);
  classChart.data.datasets[0].data = Object.values(perClass);
  classChart.update("none");

  const delta = Math.max(0, (metrics.total_flows || 0) - state.lastTotal);
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
}

async function fetchStatus() {
  const res = await fetch("/api/status");
  const data = await res.json();
  state.flows = (data.recent || []).slice(0, 50);
  state.lastTotal = data.total_flows || 0;
  renderFlows();
  renderBlocks(data.blocked || []);
  updateMetrics({ ...data, blocked: (data.blocked || []).length });
}

function toast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = message;
  el.toastHost.appendChild(node);
  setTimeout(() => node.remove(), 4500);
}

el.blockedList.addEventListener("click", async (event) => {
  const button = event.target.closest(".unblock");
  if (!button) return;
  await fetch("/api/unblock", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: button.dataset.ip }) });
  await fetchStatus();
});

el.resetBtn.addEventListener("click", async () => {
  if (!confirm("Reset demo counters and unblock managed IPs?")) return;
  await fetch("/api/reset", { method: "POST" });
  state.flows = [];
  state.blocks = [];
  state.lastTotal = 0;
  state.rateLabels = [];
  state.rateData = [];
  renderFlows();
  renderBlocks([]);
  await fetchStatus();
});

const socket = io();
socket.on("connect", () => {
  el.status.textContent = "online";
  el.status.className = "status-dot online";
  fetchStatus();
});
socket.on("disconnect", () => {
  el.status.textContent = "offline";
  el.status.className = "status-dot offline";
});
socket.on("flow", (evt) => {
  state.flows.unshift(evt);
  state.flows = state.flows.slice(0, 50);
  renderFlows();
});
socket.on("alert", (evt) => {
  toast(`${evt.type || "alert"} ${evt.ip || ""} ${evt.reason || ""}`.trim());
  document.querySelectorAll(`[data-src="${evt.ip}"]`).forEach((row) => row.classList.add("alert-row"));
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
