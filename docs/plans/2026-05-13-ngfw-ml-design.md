# NGFW — Real-time Threat Detection using ML — Implementation Plan

<!-- EXECUTION CONTRACT — read before touching any task -->
> When the user asks for a specific task (e.g. "do TASK-03"):
> 1. Read **only** that task's block. Do not preview other tasks.
> 2. Stay strictly inside its **Targets** — do not edit files outside that list.
> 3. Follow the **Implementation Notes**; do not invent extra scope.
> 4. When **Done When** and **Verification** are satisfied, **stop and report**. Wait for approval before moving to the next task.
> 5. If verification fails, report the failure and stop. Do not attempt fixes outside the task's Targets.

**Goal:** Build a mini Next-Generation Firewall that captures live flows on a Linux VM, classifies each flow with a Random Forest trained on CICIDS2017 (BENIGN / PORT_SCAN / DOS / BRUTE_FORCE), auto-blocks malicious source IPs via iptables, and surfaces everything on a Flask + Socket.IO dashboard.

**Architecture:** Single Python process inside an Ubuntu VM. Scapy sniffer pushes packets into a queue; a flow builder reassembles them into 5-tuple flows with idle/active timeouts; a feature extractor produces a 15-feature vector that a pre-trained RandomForestClassifier scores; flows above 0.85 confidence and not BENIGN trigger an iptables DROP rule (5 min TTL). All bus events stream over Socket.IO to a single-page dashboard. A second VM (Kali) on a VirtualBox Internal Network plays attacker. The firewall VM has a second NIC on NAT for real-world BENIGN baseline traffic.

**Tech / dependencies:** Python 3.12.x (pin to a single minor — e.g. 3.12.7 — for both training and runtime; do not use 3.13), Scapy 2.5, Flask 3 + Flask-SocketIO 5.3, scikit-learn 1.4, joblib, pandas, imbalanced-learn (SMOTE), Chart.js, Tailwind CDN. Host: Windows 11. VMs: VirtualBox 7.x (Ubuntu 22.04 + Kali). Linux: iptables, libpcap-dev, tcpdump.

**File map:**
- `README.md` — clone-and-run instructions, demo runbook
- `requirements.txt` — pinned Python deps (training + runtime in one env)
- `.gitignore` — venv, pycache, *.pkl in models/ stay in repo (or LFS note), pcap caches excluded
- `ngfw/__init__.py` — empty marker
- `ngfw/config.py` — single source of truth for thresholds, timeouts, NIC names, paths
- `ngfw/event_bus.py` — thread-safe in-process pub/sub on top of `queue.Queue`
- `ngfw/sniffer.py` — Scapy-based packet capture thread, multi-NIC, publishes `packet` events
- `ngfw/flow_builder.py` — 5-tuple flow aggregation with FIN/RST + idle/active timeout closure
- `ngfw/feature_extractor.py` — closed-flow → 15-dim numpy vector
- `ngfw/classifier.py` — joblib model + scaler wrapper, `predict(vec) -> (label, conf)`
- `ngfw/action_engine.py` — iptables block + TTL cleanup thread + thread-safe blocked-IP set
- `ngfw/main.py` — wires threads + event bus, starts Flask app
- `ngfw/dashboard/app.py` — Flask routes + Socket.IO emitters subscribed to event bus
- `ngfw/dashboard/templates/dashboard.html` — single-page dashboard
- `ngfw/dashboard/static/app.js` — Socket.IO client + Chart.js rendering
- `ngfw/dashboard/static/style.css` — minimal custom CSS on top of Tailwind CDN
- `notebooks/01_train_model.ipynb` — CICIDS2017 → trained RF + scaler + metrics
- `notebooks/02_real_world_fpr.ipynb` — capture own traffic, score, report FPR
- `models/rf_model.pkl`, `models/scaler.pkl`, `models/metrics.json` — training artifacts
- `attacker/01_normal_traffic.sh`, `02_port_scan.sh`, `03_brute_force.sh`, `04_dos_synflood.sh`, `run_demo.sh`, `reset_demo.sh` — demo scenario scripts
- `tests/test_flow_builder.py`, `tests/test_feature_extractor.py`, `tests/test_classifier.py` — unit tests
- `setup/firewall_vm_setup.sh` — Ubuntu provisioning (apt deps, setcap, victim services)
- `setup/kali_vm_setup.sh` — Kali provisioning (hydra wordlist, helpful aliases)
- `docs/report/report.tex` — IEEE template scaffold + section outline
- `docs/report/references.bib` — initial bib entries
- `docs/report/figures/` — populated by notebooks
- `docs/presentation/outline.md` — slide-by-slide outline (PDF built later)

---

### TASK-01: Project bootstrap

**Targets:**
- `README.md` (create)
- `requirements.txt` (create)
- `.gitignore` (create)
- `.python-version` (create)
- `ngfw/__init__.py` (create)
- `ngfw/dashboard/__init__.py` (create)
- `tests/__init__.py` (create)

**Model Tier:** T1

**Implementation Notes:**
- Python: **3.12.x** (recommend 3.12.7). Add a `.python-version` file at repo root containing `3.12.7` so `pyenv` users pick it up automatically. Mention in README that 3.13 is not yet validated against this dependency set.
- `requirements.txt` pinned exactly (versions chosen for Python 3.12 cp312 wheel availability on Windows — do not downgrade pandas/numpy or the build will fall back to source compilation and fail):
  ```
  scapy==2.5.0
  flask==3.0.0
  flask-socketio==5.3.6
  python-socketio==5.10.0
  eventlet==0.35.2
  joblib==1.3.2
  numpy==1.26.4
  scikit-learn==1.4.2
  pandas==2.2.3
  matplotlib==3.8.4
  seaborn==0.13.2
  imbalanced-learn==0.12.3
  jupyter==1.0.0
  pytest==8.0.0
  ```
- `.gitignore` includes: `__pycache__/`, `*.pyc`, `.venv/`, `*.pcap`, `*.pcapng`, `models/*.pkl` (note: model files will be tracked via Git LFS — add `models/*.pkl filter=lfs diff=lfs merge=lfs -text` to a `.gitattributes` in a later task only if LFS is set up; for now just keep `.pkl` excluded and add README note that trained model must be regenerated by running TASK-04 notebook), `docs/report/*.pdf`, `docs/presentation/*.pdf`, `.ipynb_checkpoints/`, `node_modules/`.
- `README.md` skeleton (do not finalize runbook — that lands in TASK-15):
  ```markdown
  # Mini NGFW — Real-time Threat Detection with ML
  Mini Next-Generation Firewall PoC for "Introduction to Computer Security".
  Captures live network flows, classifies with a Random Forest trained on CICIDS2017,
  auto-blocks malicious source IPs via iptables.

  ## Status
  In active development. See `docs/specs/2026-05-13-ngfw-ml-design.md` for full design.

  ## Quick links
  - Spec: `docs/specs/2026-05-13-ngfw-ml-design.md`
  - Plan: `docs/plans/2026-05-13-ngfw-ml-design.md`

  ## Setup, run, and demo runbook
  Filled in once implementation is complete (see plan TASK-15).
  ```
- `ngfw/__init__.py`, `ngfw/dashboard/__init__.py`, `tests/__init__.py` are empty.

**Done When:**
- All six files exist with the contents above
- `.python-version` contains exactly `3.12.7`
- `pip install -r requirements.txt` succeeds in a fresh Python 3.12.x venv

**Verification:**
- Manual: `python --version` reports 3.12.x
- Manual: `python -m venv .venv && .venv/Scripts/activate && pip install -r requirements.txt` completes without errors on Windows host
- Manual: `python -c "import sys; assert sys.version_info[:2]==(3,12); import scapy, flask, flask_socketio, sklearn, joblib, pandas; print('ok')"` prints `ok`

---

### TASK-02: VM provisioning scripts

**Targets:**
- `setup/firewall_vm_setup.sh` (create)
- `setup/kali_vm_setup.sh` (create)

**Model Tier:** T1

**Implementation Notes:**
- Both scripts must be idempotent (re-runnable). Use `set -euo pipefail`.
- `firewall_vm_setup.sh` does:
  1. `apt update && apt install -y python3-pip python3-venv iptables tcpdump libpcap-dev openssh-server vsftpd`
  2. Create test user `testuser` with weak password `password123` (clearly noted as INSECURE LAB-ONLY)
  3. Enable + start `ssh` and `vsftpd` (the brute-force victim services); set vsftpd to allow `testuser` login
  4. `setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))` so Scapy works without sudo
  5. Drop in `/etc/sudoers.d/ngfw` granting the current user passwordless iptables: write the line `$USER ALL=(root) NOPASSWD: /usr/sbin/iptables` via `tee` + `chmod 0440`. This is what lets ActionEngine call `sudo iptables` without prompting during the demo.
  6. Print final summary: NIC names (`ip -br link`), IPs (`ip -br addr`), status of services
- `kali_vm_setup.sh` does:
  1. `apt update && apt install -y nmap hydra hping3 slowhttptest curl`
  2. Ensure `/usr/share/wordlists/rockyou.txt` exists (Kali ships `rockyou.txt.gz`; `gunzip` if needed). If not present, write `rockyou.txt` with 10 weak passwords including `password123` so demo works without external wordlist downloads.
  3. Print attacker VM IP and a one-liner reminder of available demo scripts (`attacker/run_demo.sh`).
- No Vagrant / no automation beyond bash — student runs these manually inside each VM after install.
- Add a header comment in each script linking to the spec.

**Done When:**
- Both scripts present, executable bit set is not required on Windows host (set by `chmod +x` in VM)
- Each script begins with `#!/usr/bin/env bash` + `set -euo pipefail`
- Each prints a clear final summary

**Verification:**
- Manual: `bash -n setup/firewall_vm_setup.sh && bash -n setup/kali_vm_setup.sh` (syntax check on host) passes
- Manual (later, in VM): running each script on a fresh VM completes without error and services come up

---

### TASK-03: Config and event bus

**Targets:**
- `ngfw/config.py` (create)
- `ngfw/event_bus.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- `ngfw/config.py` exposes a single `Config` dataclass (frozen) with class-level defaults and an environment-override loader. All runtime constants live here so other modules import from `ngfw.config`:
  ```python
  from dataclasses import dataclass
  from pathlib import Path
  import os

  @dataclass(frozen=True)
  class Config:
      # NICs to sniff (comma-separated env override)
      interfaces: tuple[str, ...] = ("eth0", "eth1")
      # Flow timeouts (seconds)
      flow_idle_timeout: float = 10.0
      flow_active_timeout: float = 120.0
      # Classifier
      confidence_threshold: float = 0.85
      model_path: Path = Path("models/rf_model.pkl")
      scaler_path: Path = Path("models/scaler.pkl")
      labels: tuple[str, ...] = ("BENIGN", "PORT_SCAN", "DOS", "BRUTE_FORCE")
      # Action engine
      block_ttl: float = 300.0
      cleanup_interval: float = 60.0
      iptables_chain: str = "INPUT"
      # Dashboard
      flask_host: str = "0.0.0.0"
      flask_port: int = 5000
      # Outbound allowlist (skip blocking on these dst ports from firewall VM itself)
      outbound_safe_ports: tuple[int, ...] = (80, 443, 53)

  def load_config() -> Config:
      kwargs = {}
      if v := os.getenv("NGFW_INTERFACES"):
          kwargs["interfaces"] = tuple(v.split(","))
      if v := os.getenv("NGFW_ACTIVE_TIMEOUT"):
          kwargs["flow_active_timeout"] = float(v)
      if v := os.getenv("NGFW_CONFIDENCE"):
          kwargs["confidence_threshold"] = float(v)
      return Config(**kwargs)
  ```
- `ngfw/event_bus.py` is a synchronous fan-out pub/sub used by all threads. Subscribers receive a `queue.Queue` they own:
  ```python
  import queue
  import threading
  from typing import Any

  class EventBus:
      def __init__(self) -> None:
          self._subs: dict[str, list[queue.Queue]] = {}
          self._lock = threading.Lock()

      def subscribe(self, topic: str, maxsize: int = 1000) -> queue.Queue:
          q: queue.Queue = queue.Queue(maxsize=maxsize)
          with self._lock:
              self._subs.setdefault(topic, []).append(q)
          return q

      def publish(self, topic: str, event: Any) -> None:
          with self._lock:
              subs = list(self._subs.get(topic, ()))
          for q in subs:
              try:
                  q.put_nowait(event)
              except queue.Full:
                  pass  # drop on slow consumer; do not block producer
  ```
- Topics used downstream (document at top of `event_bus.py` as a docstring): `"packet"`, `"flow_closed"`, `"classified"`, `"action"`, `"metrics_tick"`.

**Done When:**
- `from ngfw.config import load_config; cfg = load_config()` works and returns defaults
- `from ngfw.event_bus import EventBus; bus = EventBus(); q = bus.subscribe("x"); bus.publish("x", 1); assert q.get_nowait() == 1` passes
- Topic list documented in `event_bus.py` docstring

**Verification:**
- Manual: `python -c "from ngfw.event_bus import EventBus; b=EventBus(); q=b.subscribe('t'); b.publish('t','hi'); print(q.get_nowait())"` prints `hi`
- Manual: `python -c "from ngfw.config import load_config; print(load_config())"` prints a `Config(...)` with the documented defaults

---

### TASK-04: Train Random Forest on CICIDS2017

**Targets:**
- `notebooks/01_train_model.ipynb` (create)
- `models/rf_model.pkl` (create — generated by notebook)
- `models/scaler.pkl` (create — generated by notebook)
- `models/metrics.json` (create — generated by notebook)
- `docs/report/figures/confusion_matrix.png` (create — generated by notebook)
- `docs/report/figures/feature_importance.png` (create — generated by notebook)

**Model Tier:** T3

**Implementation Notes:**
- Notebook cells in this order:
  1. **Imports** — pandas, numpy, sklearn (RandomForestClassifier, StandardScaler, train_test_split, classification_report, confusion_matrix), imblearn.over_sampling.SMOTE, matplotlib, seaborn, joblib, json, pathlib.
  2. **Dataset download instructions (markdown)** — direct user to download CICIDS2017 "MachineLearningCSV.zip" from `https://www.unb.ca/cic/datasets/ids-2017.html`, extract under `data/cicids2017/`, expects files like `Friday-WorkingHours-Morning.pcap_ISCX.csv`, `Monday-WorkingHours.pcap_ISCX.csv`, etc.
  3. **Load + concat CSVs** — glob `data/cicids2017/*.csv`, read into one DataFrame, strip whitespace from column names (`df.columns = df.columns.str.strip()`).
  4. **Filter to 4 classes** — keep rows where ` Label` is in: `BENIGN`, `PortScan`, `DoS Hulk`, `DoS slowloris`, `DoS Slowhttptest`, `DoS GoldenEye`, `FTP-Patator`, `SSH-Patator`. Map to: `BENIGN`, `PORT_SCAN`, `DOS`, `DOS`, `DOS`, `DOS`, `BRUTE_FORCE`, `BRUTE_FORCE`. Drop other rows.
  5. **Down-sample BENIGN** — random 200,000 rows max with `random_state=42`.
  6. **Select 15 features** — exactly these CICIDS column names (CICIDS uses these exact strings):
     ```python
     FEATURES = [
         "Flow Duration",
         "Total Fwd Packets",
         "Total Backward Packets",
         "Total Length of Fwd Packets",
         "Total Length of Bwd Packets",
         "Fwd Packet Length Mean",
         "Bwd Packet Length Mean",
         "Flow IAT Mean",
         "SYN Flag Count",
         "ACK Flag Count",
         "RST Flag Count",
         "Average Packet Size",
         "Fwd Packets/s",
         "Bwd Packets/s",
         "Down/Up Ratio",
     ]
     ```
  7. **Clean** — replace inf with NaN, drop NaN rows, ensure all features are numeric.
  8. **Encode labels** — `LABELS = ["BENIGN","PORT_SCAN","DOS","BRUTE_FORCE"]`, map to 0..3.
  9. **Train/test split** — stratified 80/20, `random_state=42`.
  10. **Scale** — `StandardScaler` fit on train, transform both.
  11. **Train RF** — exactly `RandomForestClassifier(n_estimators=100, max_depth=20, class_weight="balanced", n_jobs=-1, random_state=42)`.
  12. **Evaluate** — `classification_report(y_test, y_pred, target_names=LABELS, output_dict=True)`. Save as `models/metrics.json` along with: macro F1, per-class precision/recall, confusion matrix as a list-of-lists.
  13. **Plot confusion matrix** — seaborn heatmap, save to `docs/report/figures/confusion_matrix.png` at 150 dpi.
  14. **Plot top-15 feature importance** — bar chart, save to `docs/report/figures/feature_importance.png`.
  15. **Save artifacts** — `joblib.dump(model, "models/rf_model.pkl")`, `joblib.dump(scaler, "models/scaler.pkl")`. Also serialize the `LABELS` and `FEATURES` lists inside `metrics.json` under keys `"labels"` and `"features"` so the classifier wrapper can verify alignment.
- Acceptance: macro F1 ≥ **0.93** on test set (calibrated 2026-05-13 against the 15-feature subset — literature's 0.97–0.99 figures use 70+ features; we cut down for runtime feasibility). If lower, surface and stop — do not silently accept.
- BRUTE_FORCE class is expected to be the weakest (small training population). Per-class F1 ≥ 0.75 acceptable; report exact numbers in `metrics.json` for transparent inclusion in report §11.
- Notebook must run top-to-bottom on a typical laptop in <30 minutes.

**Done When:**
- Notebook executes top-to-bottom without errors
- `models/rf_model.pkl`, `models/scaler.pkl`, `models/metrics.json` exist
- `models/metrics.json` contains `labels`, `features`, `macro_f1`, `per_class`, `confusion_matrix` keys
- Both figure PNGs exist
- `metrics.json["macro_f1"] >= 0.93`
- `metrics.json["per_class"]["BRUTE_FORCE"]["f1-score"] >= 0.75`

**Verification:**
- Manual: open notebook, "Run All Cells", confirm last cell prints a summary table with macro F1
- Manual: `python -c "import json; m=json.load(open('models/metrics.json')); print(m['macro_f1'])"` prints a number ≥ 0.93
- Manual: `python -c "import joblib; m=joblib.load('models/rf_model.pkl'); print(type(m).__name__)"` prints `RandomForestClassifier`

---

### TASK-05: Classifier wrapper

**Targets:**
- `ngfw/classifier.py` (create)
- `tests/test_classifier.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- `ngfw/classifier.py` exposes one class:
  ```python
  import json
  import joblib
  import numpy as np
  from pathlib import Path
  from ngfw.config import Config

  class Classifier:
      def __init__(self, cfg: Config) -> None:
          self.model = joblib.load(cfg.model_path)
          self.scaler = joblib.load(cfg.scaler_path)
          # labels MUST come from training metrics to avoid drift
          metrics_path = cfg.model_path.parent / "metrics.json"
          with open(metrics_path) as f:
              meta = json.load(f)
          self.labels: list[str] = meta["labels"]
          self.feature_names: list[str] = meta["features"]
          if tuple(self.labels) != cfg.labels:
              raise RuntimeError(
                  f"Label mismatch: model has {self.labels}, config expects {cfg.labels}"
              )

      def predict(self, vec: np.ndarray) -> tuple[str, float]:
          if vec.shape != (len(self.feature_names),):
              raise ValueError(f"Expected shape ({len(self.feature_names)},), got {vec.shape}")
          x = self.scaler.transform(vec.reshape(1, -1))
          proba = self.model.predict_proba(x)[0]
          idx = int(np.argmax(proba))
          return self.labels[idx], float(proba[idx])
  ```
- `tests/test_classifier.py` uses pytest. Because the real model exists after TASK-04, write tests against the real artifact (skip with `pytest.skip` if `models/rf_model.pkl` not present yet so the test file is still importable):
  ```python
  import os, pytest, numpy as np
  from ngfw.config import load_config
  from ngfw.classifier import Classifier

  pytestmark = pytest.mark.skipif(
      not os.path.exists("models/rf_model.pkl"),
      reason="Model artifact missing; run notebooks/01_train_model.ipynb first.",
  )

  def test_predict_returns_label_and_confidence():
      clf = Classifier(load_config())
      vec = np.zeros(len(clf.feature_names), dtype=float)
      label, conf = clf.predict(vec)
      assert label in clf.labels
      assert 0.0 <= conf <= 1.0

  def test_wrong_shape_raises():
      clf = Classifier(load_config())
      with pytest.raises(ValueError):
          clf.predict(np.zeros(3))
  ```

**Done When:**
- `Classifier` loads model + scaler + labels on init, raises on label drift
- `predict(vec)` returns `(label: str, conf: float)` with conf in [0,1]
- Wrong-shape input raises `ValueError`
- Tests pass when model artifacts exist; cleanly skip otherwise

**Verification:**
- Manual: `pytest tests/test_classifier.py -v` — either all pass or all skip with the documented reason
- Manual: `python -c "from ngfw.classifier import Classifier; from ngfw.config import load_config; c=Classifier(load_config()); import numpy as np; print(c.predict(np.zeros(len(c.feature_names))))"` prints a `(label, conf)` tuple

---

### TASK-06: Flow builder

**Targets:**
- `ngfw/flow_builder.py` (create)
- `tests/test_flow_builder.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- Define a `Flow` dataclass storing per-packet records needed by feature extraction:
  ```python
  from dataclasses import dataclass, field
  from typing import Literal

  Direction = Literal["fwd", "bwd"]

  @dataclass
  class PacketRecord:
      ts: float           # epoch seconds
      direction: Direction
      length: int         # IP total length
      tcp_flags: int      # 0 if non-TCP
      interface: str

  @dataclass
  class Flow:
      key: tuple          # (src_ip, dst_ip, src_port, dst_port, proto)
      start_ts: float
      last_ts: float
      packets: list[PacketRecord] = field(default_factory=list)
      closed: bool = False
      close_reason: str = ""
  ```
- `FlowBuilder` consumes packets (already parsed into a small dict by the sniffer) and emits closed flows to a callback. Single-threaded — runs inside the flow-processor thread.
  ```python
  import time
  from typing import Callable
  from ngfw.config import Config

  class FlowBuilder:
      def __init__(self, cfg: Config, on_flow_closed: Callable[[Flow], None]) -> None:
          self.cfg = cfg
          self.on_flow_closed = on_flow_closed
          self.flows: dict[tuple, Flow] = {}

      def add_packet(self, pkt: dict) -> None:
          """pkt = {src_ip,dst_ip,src_port,dst_port,proto,length,tcp_flags,ts,interface}"""
          fwd_key = (pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], pkt["proto"])
          bwd_key = (pkt["dst_ip"], pkt["src_ip"], pkt["dst_port"], pkt["src_port"], pkt["proto"])
          if fwd_key in self.flows:
              key, direction = fwd_key, "fwd"
          elif bwd_key in self.flows:
              key, direction = bwd_key, "bwd"
          else:
              key, direction = fwd_key, "fwd"
              self.flows[key] = Flow(key=key, start_ts=pkt["ts"], last_ts=pkt["ts"])
          flow = self.flows[key]
          flow.last_ts = pkt["ts"]
          flow.packets.append(PacketRecord(
              ts=pkt["ts"], direction=direction, length=pkt["length"],
              tcp_flags=pkt.get("tcp_flags", 0), interface=pkt["interface"],
          ))
          # Close on FIN (0x01) or RST (0x04)
          if pkt["proto"] == "TCP" and (pkt.get("tcp_flags", 0) & 0x05):
              self._close(key, "FIN_OR_RST")

      def sweep_timeouts(self, now: float | None = None) -> None:
          now = now if now is not None else time.time()
          for key in list(self.flows.keys()):
              flow = self.flows[key]
              if now - flow.last_ts >= self.cfg.flow_idle_timeout:
                  self._close(key, "IDLE")
              elif now - flow.start_ts >= self.cfg.flow_active_timeout:
                  self._close(key, "ACTIVE")

      def _close(self, key: tuple, reason: str) -> None:
          flow = self.flows.pop(key, None)
          if flow is None:
              return
          flow.closed = True
          flow.close_reason = reason
          self.on_flow_closed(flow)
  ```
- Caller is expected to invoke `sweep_timeouts()` periodically (e.g. every 1 s) from the flow-processor thread loop.
- `tests/test_flow_builder.py` covers:
  - **test_fwd_then_bwd_same_flow**: feed two packets reversing src/dst — same flow key, second packet is `bwd`.
  - **test_fin_closes_flow**: TCP packet with FIN flag → callback fires with `close_reason="FIN_OR_RST"`.
  - **test_idle_timeout_closes_flow**: feed one packet at ts=0, sweep at ts=11 with default `flow_idle_timeout=10` → callback fires with `close_reason="IDLE"`.
  - **test_active_timeout_closes_flow**: feed packet at ts=0, then ts=1, sweep at ts=121 → `close_reason="ACTIVE"`.

**Done When:**
- `Flow`, `PacketRecord`, `FlowBuilder` exported from `ngfw/flow_builder.py`
- All four unit tests pass

**Verification:**
- Automated: `pytest tests/test_flow_builder.py -v` — 4 passed

---

### TASK-07: Feature extractor

**Targets:**
- `ngfw/feature_extractor.py` (create)
- `tests/test_feature_extractor.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- Function-style API; takes a closed `Flow` and returns a `numpy.ndarray` of shape `(15,)` in the **exact order** that matches `metrics.json["features"]` from TASK-04:
  ```python
  import numpy as np
  from ngfw.flow_builder import Flow

  # MUST match training feature order exactly
  FEATURE_ORDER = [
      "Flow Duration",
      "Total Fwd Packets",
      "Total Backward Packets",
      "Total Length of Fwd Packets",
      "Total Length of Bwd Packets",
      "Fwd Packet Length Mean",
      "Bwd Packet Length Mean",
      "Flow IAT Mean",
      "SYN Flag Count",
      "ACK Flag Count",
      "RST Flag Count",
      "Average Packet Size",
      "Fwd Packets/s",
      "Bwd Packets/s",
      "Down/Up Ratio",
  ]

  def extract(flow: Flow) -> np.ndarray:
      pkts = flow.packets
      if not pkts:
          return np.zeros(len(FEATURE_ORDER))
      duration = max(flow.last_ts - flow.start_ts, 1e-6)  # seconds
      fwd = [p for p in pkts if p.direction == "fwd"]
      bwd = [p for p in pkts if p.direction == "bwd"]
      fwd_lens = [p.length for p in fwd]
      bwd_lens = [p.length for p in bwd]
      total_fwd_bytes = sum(fwd_lens)
      total_bwd_bytes = sum(bwd_lens)
      iats = [pkts[i].ts - pkts[i-1].ts for i in range(1, len(pkts))]
      flow_iat_mean = float(np.mean(iats)) if iats else 0.0
      syn_count = sum(1 for p in pkts if p.tcp_flags & 0x02)
      ack_count = sum(1 for p in pkts if p.tcp_flags & 0x10)
      rst_count = sum(1 for p in pkts if p.tcp_flags & 0x04)
      avg_pkt_size = float(np.mean([p.length for p in pkts]))
      fwd_per_sec = len(fwd) / duration
      bwd_per_sec = len(bwd) / duration
      down_up_ratio = (total_bwd_bytes / total_fwd_bytes) if total_fwd_bytes > 0 else 0.0
      return np.array([
          duration * 1_000_000,  # CICIDS Flow Duration is microseconds
          len(fwd),
          len(bwd),
          total_fwd_bytes,
          total_bwd_bytes,
          float(np.mean(fwd_lens)) if fwd_lens else 0.0,
          float(np.mean(bwd_lens)) if bwd_lens else 0.0,
          flow_iat_mean * 1_000_000,  # IAT also microseconds in CICIDS
          syn_count,
          ack_count,
          rst_count,
          avg_pkt_size,
          fwd_per_sec,
          bwd_per_sec,
          down_up_ratio,
      ], dtype=float)
  ```
- Tests in `tests/test_feature_extractor.py`:
  - **test_shape_is_15**: build a minimal flow with 2 packets, assert returned shape == (15,).
  - **test_empty_flow_returns_zeros**: flow with no packets → all zeros.
  - **test_syn_flag_counted**: flow with 3 TCP packets, 2 with SYN flag → SYN count == 2 at index 8.
  - **test_down_up_ratio_zero_when_no_fwd_bytes**: flow with only bwd packets → ratio == 0.0 at index 14.
  - **test_fwd_packets_per_sec_scales_with_duration**: flow lasting 2 s with 10 fwd packets → `fwd_per_sec == 5.0` at index 12.

**Done When:**
- `extract(flow)` returns `np.ndarray` shape `(15,)`, dtype float
- `FEATURE_ORDER` list matches `metrics.json["features"]` from TASK-04 element-by-element
- All five unit tests pass

**Verification:**
- Automated: `pytest tests/test_feature_extractor.py -v` — 5 passed
- Manual: `python -c "import json; from ngfw.feature_extractor import FEATURE_ORDER; m=json.load(open('models/metrics.json')); assert FEATURE_ORDER == m['features']; print('aligned')"` prints `aligned`

---

### TASK-08: Sniffer

**Targets:**
- `ngfw/sniffer.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- Wraps Scapy's `sniff()` in a thread. Publishes parsed packet dicts to the event bus under topic `"packet"`.
  ```python
  import threading
  import time
  from scapy.all import sniff, IP, TCP, UDP
  from ngfw.event_bus import EventBus
  from ngfw.config import Config

  class Sniffer:
      def __init__(self, cfg: Config, bus: EventBus) -> None:
          self.cfg = cfg
          self.bus = bus
          self._stop = threading.Event()
          self._thread: threading.Thread | None = None

      def start(self) -> None:
          self._thread = threading.Thread(target=self._run, daemon=True, name="sniffer")
          self._thread.start()

      def stop(self) -> None:
          self._stop.set()

      def _run(self) -> None:
          sniff(
              iface=list(self.cfg.interfaces),
              prn=self._handle,
              store=False,
              stop_filter=lambda _pkt: self._stop.is_set(),
          )

      def _handle(self, pkt) -> None:
          if IP not in pkt:
              return
          ip = pkt[IP]
          proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
          src_port = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
          dst_port = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
          tcp_flags = int(pkt[TCP].flags) if TCP in pkt else 0
          # Scapy doesn't expose iface per-packet reliably across versions; use sniffed_on if present
          iface = getattr(pkt, "sniffed_on", None) or self.cfg.interfaces[0]
          self.bus.publish("packet", {
              "ts": time.time(),
              "src_ip": ip.src, "dst_ip": ip.dst,
              "src_port": src_port, "dst_port": dst_port,
              "proto": proto, "length": int(ip.len),
              "tcp_flags": tcp_flags, "interface": iface,
          })
  ```
- Daemon thread so process exits cleanly on Ctrl+C.
- Multi-NIC support is via Scapy's list-of-ifaces; if a NIC name in `cfg.interfaces` doesn't exist, Scapy will raise — surface that clearly to the user (let exception propagate; `main.py` catches and prints a friendly message).

**Done When:**
- `Sniffer` exported from `ngfw/sniffer.py` with `start()` and `stop()` methods
- Publishes packet dicts containing all required keys (`ts, src_ip, dst_ip, src_port, dst_port, proto, length, tcp_flags, interface`) to topic `"packet"`

**Verification:**
- Manual (on Ubuntu VM): ad-hoc script in REPL:
  ```python
  from ngfw.event_bus import EventBus
  from ngfw.config import load_config
  from ngfw.sniffer import Sniffer
  bus = EventBus(); cfg = load_config(); q = bus.subscribe("packet")
  s = Sniffer(cfg, bus); s.start()
  # In another terminal: ping 8.8.8.8 (or curl http://...)
  print(q.get(timeout=10))  # should print a packet dict
  s.stop()
  ```
  prints a packet dict within 10 s when traffic is generated.

---

### TASK-09: Action engine

**Targets:**
- `ngfw/action_engine.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- Manages blocked-IP set, calls `iptables` via `subprocess`, and runs a TTL cleanup thread.
  ```python
  import subprocess
  import threading
  import time
  from dataclasses import dataclass
  from ngfw.config import Config
  from ngfw.event_bus import EventBus

  @dataclass
  class BlockEntry:
      ip: str
      reason: str
      blocked_at: float
      expires_at: float

  class ActionEngine:
      def __init__(self, cfg: Config, bus: EventBus) -> None:
          self.cfg = cfg
          self.bus = bus
          self._blocks: dict[str, BlockEntry] = {}
          self._lock = threading.Lock()
          self._stop = threading.Event()
          self._cleanup_thread: threading.Thread | None = None

      def start(self) -> None:
          self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True, name="action-cleanup")
          self._cleanup_thread.start()

      def stop(self) -> None:
          self._stop.set()

      def block(self, ip: str, reason: str) -> bool:
          """Returns True if newly blocked, False if already blocked."""
          with self._lock:
              if ip in self._blocks:
                  return False
              now = time.time()
              entry = BlockEntry(ip=ip, reason=reason, blocked_at=now, expires_at=now + self.cfg.block_ttl)
              self._blocks[ip] = entry
          self._iptables_add(ip)
          self.bus.publish("action", {"type": "block", "ip": ip, "reason": reason, "ttl": self.cfg.block_ttl})
          return True

      def unblock(self, ip: str) -> bool:
          with self._lock:
              if ip not in self._blocks:
                  return False
              del self._blocks[ip]
          self._iptables_del(ip)
          self.bus.publish("action", {"type": "unblock", "ip": ip})
          return True

      def list_blocks(self) -> list[BlockEntry]:
          with self._lock:
              return list(self._blocks.values())

      def _cleanup_loop(self) -> None:
          while not self._stop.wait(self.cfg.cleanup_interval):
              now = time.time()
              expired = [e.ip for e in self.list_blocks() if e.expires_at <= now]
              for ip in expired:
                  self.unblock(ip)

      def _iptables_add(self, ip: str) -> None:
          subprocess.run(
              ["sudo", "iptables", "-A", self.cfg.iptables_chain, "-s", ip, "-j", "DROP"],
              check=True,
          )

      def _iptables_del(self, ip: str) -> None:
          subprocess.run(
              ["sudo", "iptables", "-D", self.cfg.iptables_chain, "-s", ip, "-j", "DROP"],
              check=False,  # ignore if already gone
          )
  ```
- `sudo iptables` works without a password prompt because TASK-02 installed a `/etc/sudoers.d/ngfw` drop-in granting NOPASSWD for `/usr/sbin/iptables`. If you discover this missing during testing, **stop and report** — do not edit `firewall_vm_setup.sh` from this task.
- Idempotent block: blocking the same IP twice does nothing the second time and returns `False`.

**Done When:**
- `ActionEngine` exported with `start()`, `stop()`, `block(ip, reason)`, `unblock(ip)`, `list_blocks()`
- Calling `block()` twice for the same IP only adds one iptables rule (returns `False` on second call)
- Cleanup thread removes entries past `expires_at`

**Verification:**
- Manual (on Ubuntu VM): REPL
  ```python
  from ngfw.event_bus import EventBus
  from ngfw.config import Config
  from ngfw.action_engine import ActionEngine
  ae = ActionEngine(Config(block_ttl=3, cleanup_interval=1), EventBus()); ae.start()
  print(ae.block("203.0.113.5", "TEST"))  # True
  print(ae.block("203.0.113.5", "TEST"))  # False
  # iptables -L INPUT -n | grep 203.0.113.5  → 1 line
  import time; time.sleep(5)
  print(ae.list_blocks())  # []
  # iptables -L INPUT -n | grep 203.0.113.5  → no output
  ```

---

### TASK-10: NGFW main entry point

**Targets:**
- `ngfw/main.py` (create)

**Model Tier:** T3

**Implementation Notes:**
- Wires every component, runs flow-processor thread, starts Flask app last (blocking).
  ```python
  import threading
  import time
  import logging
  from ngfw.config import load_config
  from ngfw.event_bus import EventBus
  from ngfw.sniffer import Sniffer
  from ngfw.flow_builder import FlowBuilder, Flow
  from ngfw.feature_extractor import extract
  from ngfw.classifier import Classifier
  from ngfw.action_engine import ActionEngine
  from ngfw.dashboard.app import create_app  # see TASK-11

  log = logging.getLogger("ngfw")

  def main() -> None:
      logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
      cfg = load_config()
      bus = EventBus()
      clf = Classifier(cfg)
      action = ActionEngine(cfg, bus); action.start()

      def on_flow_closed(flow: Flow) -> None:
          vec = extract(flow)
          label, conf = clf.predict(vec)
          event = {
              "ts": time.time(),
              "src_ip": flow.key[0], "dst_ip": flow.key[1],
              "src_port": flow.key[2], "dst_port": flow.key[3],
              "proto": flow.key[4],
              "interface": flow.packets[0].interface if flow.packets else "?",
              "label": label, "confidence": conf,
              "n_packets": len(flow.packets),
              "close_reason": flow.close_reason,
          }
          bus.publish("classified", event)
          if label != "BENIGN" and conf >= cfg.confidence_threshold:
              # Don't block our own outbound traffic to safe ports
              if flow.key[3] in cfg.outbound_safe_ports:
                  return
              action.block(flow.key[0], f"{label} ({conf:.2f})")

      flow_builder = FlowBuilder(cfg, on_flow_closed=on_flow_closed)
      pkt_q = bus.subscribe("packet")

      def flow_processor() -> None:
          last_sweep = time.time()
          while True:
              try:
                  pkt = pkt_q.get(timeout=1.0)
                  flow_builder.add_packet(pkt)
              except Exception:
                  pass
              now = time.time()
              if now - last_sweep >= 1.0:
                  flow_builder.sweep_timeouts(now)
                  last_sweep = now

      threading.Thread(target=flow_processor, daemon=True, name="flow-processor").start()

      sniffer = Sniffer(cfg, bus); sniffer.start()
      log.info("Sniffer started on %s", cfg.interfaces)

      app, socketio = create_app(cfg, bus, action)
      log.info("Dashboard on http://%s:%d", cfg.flask_host, cfg.flask_port)
      socketio.run(app, host=cfg.flask_host, port=cfg.flask_port)

  if __name__ == "__main__":
      main()
  ```
- Catch the common startup error from `Sniffer` (bad NIC name) and print a friendly message naming the interfaces it tried and a hint to set `NGFW_INTERFACES=eth0,eth1`.
- The contract with TASK-11: `create_app(cfg, bus, action) -> (Flask, SocketIO)`.

**Done When:**
- `python -m ngfw.main` starts sniffer + flow processor + action cleanup + Flask, logs all three startup lines
- A classified event flows: pkt → flow → classify → action (verified end-to-end in TASK-15)

**Verification:**
- Manual: `python -m ngfw.main` on Ubuntu VM starts and binds to port 5000. Hitting `http://<vm-ip>:5000/api/status` (after TASK-11) returns JSON.
- Manual: Ctrl+C exits cleanly within 2 s.

---

### TASK-11: Dashboard backend (Flask + Socket.IO)

**Targets:**
- `ngfw/dashboard/app.py` (create)

**Model Tier:** T2

**Implementation Notes:**
- Exposes `create_app(cfg, bus, action) -> (Flask, SocketIO)`. Subscribes to bus topics and re-emits as Socket.IO events. Maintains in-memory counters and a ring buffer of the last 50 classified flows.
  ```python
  import threading
  import time
  from collections import deque
  from flask import Flask, jsonify, request, send_from_directory
  from flask_socketio import SocketIO
  from ngfw.config import Config
  from ngfw.event_bus import EventBus
  from ngfw.action_engine import ActionEngine

  def create_app(cfg: Config, bus: EventBus, action: ActionEngine):
      app = Flask(__name__, template_folder="templates", static_folder="static")
      socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

      state = {
          "started_at": time.time(),
          "total_flows": 0,
          "benign": 0,
          "threats": 0,
          "per_class": {l: 0 for l in cfg.labels},
          "recent": deque(maxlen=50),
      }
      state_lock = threading.Lock()

      @app.route("/")
      def index():
          return send_from_directory(app.template_folder, "dashboard.html")

      @app.route("/api/status")
      def status():
          with state_lock:
              return jsonify({
                  "uptime": time.time() - state["started_at"],
                  "total_flows": state["total_flows"],
                  "benign": state["benign"],
                  "threats": state["threats"],
                  "per_class": dict(state["per_class"]),
                  "blocked": [
                      {"ip": e.ip, "reason": e.reason, "blocked_at": e.blocked_at, "expires_at": e.expires_at}
                      for e in action.list_blocks()
                  ],
                  "recent": list(state["recent"]),
              })

      @app.route("/api/unblock", methods=["POST"])
      def unblock():
          ip = (request.json or {}).get("ip", "")
          ok = action.unblock(ip)
          return jsonify({"ok": ok})

      @app.route("/api/reset", methods=["POST"])
      def reset():
          # Unblock all + zero counters; do NOT flush other iptables rules
          for entry in action.list_blocks():
              action.unblock(entry.ip)
          with state_lock:
              state["total_flows"] = 0
              state["benign"] = 0
              state["threats"] = 0
              for k in state["per_class"]:
                  state["per_class"][k] = 0
              state["recent"].clear()
          return jsonify({"ok": True})

      def classified_pump():
          q = bus.subscribe("classified")
          while True:
              evt = q.get()
              with state_lock:
                  state["total_flows"] += 1
                  state["per_class"][evt["label"]] = state["per_class"].get(evt["label"], 0) + 1
                  if evt["label"] == "BENIGN":
                      state["benign"] += 1
                  else:
                      state["threats"] += 1
                  state["recent"].appendleft(evt)
              socketio.emit("flow", evt)

      def action_pump():
          q = bus.subscribe("action")
          while True:
              evt = q.get()
              socketio.emit("alert", evt)

      def metrics_tick():
          while True:
              socketio.sleep(1.0)
              with state_lock:
                  snapshot = {
                      "uptime": time.time() - state["started_at"],
                      "total_flows": state["total_flows"],
                      "benign": state["benign"],
                      "threats": state["threats"],
                      "blocked": len(action.list_blocks()),
                      "per_class": dict(state["per_class"]),
                  }
              socketio.emit("metrics", snapshot)

      socketio.start_background_task(classified_pump)
      socketio.start_background_task(action_pump)
      socketio.start_background_task(metrics_tick)

      return app, socketio
  ```
- `eventlet` async mode is intentional (matches `requirements.txt` from TASK-01).
- The `/api/reset` route is the "Reset Demo" button backing.

**Done When:**
- `create_app(cfg, bus, action)` returns `(Flask, SocketIO)`
- `GET /` serves the dashboard HTML
- `GET /api/status` returns the JSON shape above
- `POST /api/unblock {"ip":"..."}` removes a block
- `POST /api/reset` zeros counters and unblocks all
- Socket.IO emits `flow`, `alert`, `metrics` events as documented

**Verification:**
- Manual: with `ngfw.main` running, `curl http://<vm-ip>:5000/api/status` returns JSON with all documented keys
- Manual: open browser to `/`, Chrome devtools → Network → WS frames show `flow`/`metrics` events flowing

---

### TASK-12: Dashboard frontend

**Targets:**
- `ngfw/dashboard/templates/dashboard.html` (create)
- `ngfw/dashboard/static/app.js` (create)
- `ngfw/dashboard/static/style.css` (create)

**Model Tier:** T2

**Implementation Notes:**
- Single HTML page, Tailwind via CDN, Chart.js via CDN, Socket.IO client via CDN. No build step.
- Layout per spec §6:
  - Header bar: status badge, uptime (live), "Reset Demo" button.
  - Four metric cards: Total Flows / Benign / Threats / Blocked IPs.
  - Live flow stream (left, ~60% width): table with columns `time | iface | src→dst:port | class | conf`. Newest on top, max 50 rows. Class colors: BENIGN=green, others=red (yellow if conf<0.85 — but those wouldn't be blocked anyway; we still display them).
  - Threat breakdown pie chart (right top, Chart.js doughnut, classes from `metrics.per_class`).
  - Blocked IPs list (right middle): IP, reason, time-left countdown, Unblock button → POST `/api/unblock`.
  - Traffic rate line chart (bottom): pkts/sec over last 60 s, updated each `metrics` tick (compute delta of `total_flows` between ticks).
- `app.js` responsibilities:
  - Connect Socket.IO to same origin.
  - On connect, GET `/api/status` to seed.
  - Listen to `flow`: prepend row to flow stream table; trim to 50; color-code; show `[lab]` / `[inet]` badge derived from `interface` (lookup map: known internal NIC names → `[lab]`, NAT NIC → `[inet]`; configurable via top-of-file constants).
  - Listen to `alert`: flash a toast at top-right; also tag corresponding row red.
  - Listen to `metrics`: update card numbers, doughnut data, traffic-rate chart, blocked-IP list (re-fetch `/api/status` blocks section every 5 ticks to refresh expiry countdowns).
  - "Reset Demo" button: confirm dialog → POST `/api/reset` → wipe local state.
- Hardcoded NIC mapping (top of `app.js`, document with comment):
  ```js
  const LAB_IFACES = new Set(["eth0", "enp0s3", "enp0s8"]);   // adjust if your VM differs
  const INET_IFACES = new Set(["eth1", "enp0s9"]);
  function ifaceBadge(name) {
    if (LAB_IFACES.has(name)) return { label: "lab", color: "purple" };
    if (INET_IFACES.has(name)) return { label: "inet", color: "blue" };
    return { label: name, color: "gray" };
  }
  ```
- `style.css` is minimal overrides on top of Tailwind: row hover, badge shapes, toast animation. Keep under ~80 lines.

**Done When:**
- Visiting `http://<vm-ip>:5000/` renders the dashboard with header, 4 cards, flow table, doughnut, blocked list, rate chart
- Live socket events update the UI without page reload
- "Reset Demo" zeroes all counters and clears the table
- Unblock button removes an IP from the list

**Verification:**
- Manual: with `ngfw.main` running and a packet generator (`ping`, `curl`), the flow stream populates rows; metric cards tick up.
- Manual: trigger a port scan from attacker VM — within ~10 s a red row appears, an alert toast fires, and the IP shows in the Blocked list. Clicking Unblock removes it.

---

### TASK-13: Attacker demo scripts

**Targets:**
- `attacker/01_normal_traffic.sh` (create)
- `attacker/02_port_scan.sh` (create)
- `attacker/03_brute_force.sh` (create)
- `attacker/04_dos_synflood.sh` (create)
- `attacker/run_demo.sh` (create)
- `attacker/reset_demo.sh` (create)

**Model Tier:** T1

**Implementation Notes:**
- Every script: `#!/usr/bin/env bash` + `set -euo pipefail`. Target IP read from `VICTIM_IP` env var with a default (`192.168.56.10`) and a help line if unset.
- `01_normal_traffic.sh`:
  ```bash
  curl -s -o /dev/null "http://$VICTIM_IP/" || true
  sshpass -p password123 ssh -o StrictHostKeyChecking=no testuser@$VICTIM_IP "echo hello" || true
  ```
  (Note: this requires `sshpass`; add to `kali_vm_setup.sh` if not present — but DO NOT modify that file from this task; just print a friendly error if `sshpass` is missing.)
- `02_port_scan.sh`: `nmap -sS -p 1-1000 -T4 "$VICTIM_IP"`
- `03_brute_force.sh`: `hydra -l testuser -P /usr/share/wordlists/rockyou.txt -t 4 ssh://$VICTIM_IP -f -V || true`
- `04_dos_synflood.sh`: `timeout 15 hping3 -S -p 80 -i u1000 "$VICTIM_IP"`  ← rate-limited (one packet per 1 ms, ~1000 pps), NOT `--flood`, to keep VM responsive.
- `run_demo.sh`:
  ```bash
  : "${VICTIM_IP:?Set VICTIM_IP first}"
  HERE="$(cd "$(dirname "$0")" && pwd)"
  pause() { read -r -p "[Press Enter for next scene] " _; }
  echo "=== Scene 1: Normal traffic ==="; bash "$HERE/01_normal_traffic.sh"; pause
  echo "=== Scene 2: Port scan ==="; bash "$HERE/02_port_scan.sh"; pause
  echo "=== Scene 3: SSH brute force ==="; bash "$HERE/03_brute_force.sh"; pause
  echo "=== Scene 4: DoS (rate-limited SYN) ==="; bash "$HERE/04_dos_synflood.sh"; pause
  echo "Demo complete."
  ```
- `reset_demo.sh` runs **on the firewall VM** (note in script header). Removes only iptables rules added by NGFW (matches `-s <ip> -j DROP` on INPUT). The simplest reliable approach: call the dashboard `POST /api/reset` endpoint — script just does `curl -s -X POST http://localhost:5000/api/reset`.

**Done When:**
- Six scripts exist, each begins with shebang + `set -euo pipefail`
- `bash -n` syntax check passes for all
- `run_demo.sh` walks all four scenes with Enter prompts between

**Verification:**
- Manual: `bash -n attacker/*.sh` exits 0 for every file
- Manual (on Kali VM, with VICTIM_IP set): `bash attacker/02_port_scan.sh` runs `nmap` and produces output

---

### TASK-14: Real-world FPR notebook

**Targets:**
- `notebooks/02_real_world_fpr.ipynb` (create)
- `docs/report/figures/fpr_summary.png` (create — generated by notebook)

**Model Tier:** T2

**Implementation Notes:**
- Cells:
  1. **Markdown — capture instructions**: show command `sudo tcpdump -i <iface> -w real_traffic.pcap` and direct user to browse normal sites (youtube, github, wikipedia, gmail) for ~30 minutes, then Ctrl+C.
  2. **Load pcap with Scapy**: `from scapy.all import rdpcap; pkts = rdpcap("data/real_traffic.pcap")`. Note: large pcaps may need batching — if `len(pkts) > 500_000`, sample down to 500k.
  3. **Reconstruct flows** — reuse `ngfw.flow_builder.FlowBuilder`. Feed each packet (parsed identically to `Sniffer._handle`) with monotonically increasing `ts` taken from `pkt.time`. After all packets, call `sweep_timeouts(ts=last_ts + 200)` to close remaining flows.
  4. **Extract features** — apply `ngfw.feature_extractor.extract` to each closed flow.
  5. **Score with the trained classifier** — `from ngfw.classifier import Classifier; from ngfw.config import load_config; clf = Classifier(load_config())`. For each feature vector, get `(label, conf)`.
  6. **Compute FPR** — among all scored flows (which are by construction all BENIGN ground truth), count those predicted not-BENIGN with `conf >= 0.85`. FPR = false_positives / total.
  7. **Plot** — bar chart of `per-predicted-class` counts, save to `docs/report/figures/fpr_summary.png`. Display FPR number prominently in the last cell.
- Acceptance: notebook runs end-to-end; FPR is **reported honestly**, no threshold tuning to "fix" it. If FPR > 5%, the notebook surfaces a discussion cell explaining the domain-shift hypothesis (modern HTTPS vs CICIDS lab BENIGN).

**Done When:**
- Notebook executes top-to-bottom without errors when `data/real_traffic.pcap` exists
- `docs/report/figures/fpr_summary.png` produced
- Final cell prints a single-number FPR

**Verification:**
- Manual: open notebook, "Run All Cells" after capturing a real pcap; last cell prints `FPR = X.XX%`; PNG file exists.

---

### TASK-15: End-to-end demo runbook and README

**Targets:**
- `README.md` (modify — replace status section)

**Model Tier:** T2

**Implementation Notes:**
- Replace the placeholder runbook section. Final README has these sections:
  1. **What this is** (2 sentences).
  2. **Repo layout** (tree of top-level dirs).
  3. **One-time setup** (host machine):
     - Install VirtualBox 7.x
     - Create two VMs: Ubuntu 22.04 ("firewall"), Kali Linux ("attacker"). Networking:
       - VirtualBox → File → Host Network Manager → create Internal Network named `ngfw-lab`.
       - Firewall VM: Adapter 1 = Internal Network `ngfw-lab` (static IP `192.168.56.10/24`); Adapter 2 = NAT.
       - Kali VM: Adapter 1 = Internal Network `ngfw-lab` (static IP `192.168.56.5/24`).
     - On firewall VM: `bash setup/firewall_vm_setup.sh`.
     - On Kali VM: `bash setup/kali_vm_setup.sh`.
  4. **Train the model** (on host laptop, not VM):
     - Download CICIDS2017 from `https://www.unb.ca/cic/datasets/ids-2017.html` → extract to `data/cicids2017/`
     - `pip install -r requirements.txt && jupyter notebook notebooks/01_train_model.ipynb` → Run All
     - Copy `models/` directory to firewall VM (e.g. via shared folder, `scp`, or `git lfs`).
  5. **Run the firewall** (on firewall VM):
     - `cd ~/introProjesi && python3 -m ngfw.main`
     - Open `http://192.168.56.10:5000/` from host browser.
  6. **Run the demo** (on Kali VM):
     - `cd ~/introProjesi/attacker && VICTIM_IP=192.168.56.10 bash run_demo.sh`
     - Press Enter between scenes; watch the dashboard.
  7. **Reset between rehearsals**: click "Reset Demo" in dashboard or `curl -s -X POST http://192.168.56.10:5000/api/reset`.
  8. **Known limitations** (link to spec §11).
  9. **Etik kullanım** (link to spec §12).
- Keep the runbook tight — under 200 lines total including the existing intro.

**Done When:**
- README contains all 9 sections, no placeholders
- Repo-relative paths in the README correspond to files that exist after TASKs 01–14

**Verification:**
- Manual: `grep -niE "TBD|TODO|FIXME|\[\[" README.md` returns no matches
- Manual: a fresh reader (you) following the README from scratch can run the demo end-to-end (this is the integration acceptance test for the whole project)

---

### TASK-16: Report scaffold (LaTeX, IEEE template)

**Targets:**
- `docs/report/report.tex` (create)
- `docs/report/references.bib` (create)

**Model Tier:** T2

**Implementation Notes:**
- Use IEEE conference template (`\documentclass[conference]{IEEEtran}`). Single file. Section skeleton per spec §9 with one-line placeholder paragraphs that **name the content** to be written (these are content directives, not content):
  ```latex
  \section{Introduction}
  % What an NGFW is, how it differs from classical packet-filter firewalls,
  % why ML is needed for behavioral attack detection. 3–4 paragraphs.

  \section{Background and Related Work}
  % Survey: CICIDS2017 dataset, ML-IDS literature (cite 5–8 papers).
  ...
  ```
- Include `\input{}` placeholders for figures from `figures/`:
  ```latex
  \begin{figure}[h]
      \centering
      \includegraphics[width=0.9\linewidth]{figures/confusion_matrix.png}
      \caption{Confusion matrix on the CICIDS2017 test split.}
      \label{fig:cm}
  \end{figure}
  ```
  for: `confusion_matrix.png`, `feature_importance.png`, `fpr_summary.png`, plus a placeholder note for a hand-drawn architecture diagram (`figures/architecture.png` — created later, not in this plan).
- `references.bib` seeded with 6 entries:
  - CICIDS2017 paper (Sharafaldin, Lashkari, Ghorbani 2018)
  - Random Forest (Breiman 2001)
  - Scapy (project URL as misc entry)
  - One survey on ML-IDS (e.g. Buczak & Guven 2016)
  - SMOTE (Chawla et al. 2002)
  - StandardScaler / scikit-learn (Pedregosa et al. 2011)

**Done When:**
- `report.tex` compiles to PDF with `pdflatex` (assuming IEEEtran.cls is installed) — placeholder paragraphs render
- `references.bib` has 6 well-formed BibTeX entries

**Verification:**
- Manual: `pdflatex docs/report/report.tex && bibtex report && pdflatex docs/report/report.tex && pdflatex docs/report/report.tex` produces `report.pdf` with the section skeleton and no `??` citation markers.

---

### TASK-17: Presentation outline

**Targets:**
- `docs/presentation/outline.md` (create)

**Model Tier:** T1

**Implementation Notes:**
- Slide-by-slide outline (12–15 slides), each as a markdown subheading with 3-5 bullet points describing slide content. Not a styled deck — actual slides are built later from this outline in Keynote/PowerPoint/Beamer.
- Slide list:
  1. Title
  2. Motivation: why ML in firewalls (1 chart: attack growth, or threat sophistication)
  3. NGFW vs classical firewall (comparison table)
  4. System architecture diagram
  5. CICIDS2017 dataset overview (4 classes, sample counts)
  6. 15 features chosen + why
  7. Random Forest results (confusion matrix screenshot)
  8. Live demo intro (what jury is about to see)
  9. [LIVE DEMO — no slide content, just placeholder]
  10. Real-world FPR result (the honesty slide)
  11. Limitations (domain shift, zero-day, encrypted traffic)
  12. Future work (more classes, ensemble + signatures, retraining loop)
  13. Conclusion
  14. Q&A
- Each bullet point is concrete content, not "talk about X".

**Done When:**
- `outline.md` exists with all slides, each with 3–5 concrete bullet points
- No `TBD` / `TODO`

**Verification:**
- Manual: `wc -l docs/presentation/outline.md` ≥ 60 lines; eyeball-read confirms each slide has content bullets, not placeholders.

---

## End of plan
