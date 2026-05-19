You're picking up an implementation plan in this repo.

**Project:** Mini NGFW — Real-time Threat Detection with ML — Mini Next-Generation Firewall PoC for "Introduction to Computer Security" that captures live network flows, classifies with a Random Forest trained on CICIDS2017, and auto-blocks malicious source IPs via iptables.

**Plan:** `docs/plans/2026-05-13-ngfw-ml-design.md`
**Spec:** `docs/specs/2026-05-13-ngfw-ml-design.md`

**Goal:** Build a mini Next-Generation Firewall that captures live flows on a Linux VM, classifies each flow with a Random Forest trained on CICIDS2017 (BENIGN / PORT_SCAN / DOS / BRUTE_FORCE), auto-blocks malicious source IPs via iptables, and surfaces everything on a Flask + Socket.IO dashboard.

**Tech:** Python 3.12.x (pin to 3.12.7 for both training and runtime; do not use 3.13), Scapy 2.5, Flask 3 + Flask-SocketIO 5.3, scikit-learn 1.4, joblib, pandas, imbalanced-learn (SMOTE), Chart.js, Tailwind CDN. Host: Windows 11. VMs: VirtualBox 7.x (Ubuntu 22.04 + Kali). Linux: iptables, libpcap-dev, tcpdump.

**Tasks:**
- TASK-01: Project bootstrap
- TASK-02: VM provisioning scripts
- TASK-03: Config and event bus
- TASK-04: Train Random Forest on CICIDS2017
- TASK-05: Classifier wrapper
- TASK-06: Flow builder
- TASK-07: Feature extractor
- TASK-08: Sniffer
- TASK-09: Action engine
- TASK-10: NGFW main entry point
- TASK-11: Dashboard backend (Flask + Socket.IO)
- TASK-12: Dashboard frontend
- TASK-13: Attacker demo scripts
- TASK-14: Real-world FPR notebook
- TASK-15: End-to-end demo runbook and README
- TASK-16: Report scaffold (LaTeX, IEEE template)
- TASK-17: Presentation outline

**How to execute (full execution contract is at the top of the plan file):**
1. When I ask for a task ("do TASK-03"), read **only** that task's block in the plan.
2. Stay strictly inside its **Targets** — don't edit files outside that list.
3. Follow the **Implementation Notes**; don't invent extra scope.
4. When **Done When** and **Verification** are satisfied, **stop and report**. Wait for my approval before moving on.
5. If verification fails, report and stop. Don't attempt fixes outside the task's Targets.

Start by reading `docs/plans/2026-05-13-ngfw-ml-design.md` end-to-end, then wait for me to ask for the first task. Don't begin TASK-01 until I ask.
