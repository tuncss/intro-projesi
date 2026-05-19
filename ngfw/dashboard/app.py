import queue
import threading
import time
from collections import deque

from flask import Flask, jsonify, request, send_from_directory
from flask_socketio import SocketIO

from ngfw.action_engine import ActionEngine
from ngfw.config import Config
from ngfw.event_bus import EventBus


def create_app(cfg: Config, bus: EventBus, action: ActionEngine):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

    state = {
        "started_at": time.time(),
        "total_flows": 0,
        "benign": 0,
        "threats": 0,
        "per_class": {label: 0 for label in cfg.labels},
        "recent": deque(maxlen=50),
    }
    state_lock = threading.Lock()

    @app.route("/")
    def index():
        return send_from_directory(app.template_folder, "dashboard.html")

    @app.route("/api/status")
    def status():
        with state_lock:
            return jsonify(
                {
                    "uptime": time.time() - state["started_at"],
                    "total_flows": state["total_flows"],
                    "benign": state["benign"],
                    "threats": state["threats"],
                    "per_class": dict(state["per_class"]),
                    "blocked": [
                        {
                            "ip": entry.ip,
                            "reason": entry.reason,
                            "blocked_at": entry.blocked_at,
                            "expires_at": entry.expires_at,
                        }
                        for entry in action.list_blocks()
                    ],
                    "recent": list(state["recent"]),
                }
            )

    @app.route("/api/unblock", methods=["POST"])
    def unblock():
        ip = (request.json or {}).get("ip", "")
        ok = action.unblock(ip)
        return jsonify({"ok": ok})

    @app.route("/api/reset", methods=["POST"])
    def reset():
        # Unblock all + zero counters; do NOT flush other iptables rules.
        for entry in action.list_blocks():
            action.unblock(entry.ip)
        with state_lock:
            state["total_flows"] = 0
            state["benign"] = 0
            state["threats"] = 0
            for key in state["per_class"]:
                state["per_class"][key] = 0
            state["recent"].clear()
        return jsonify({"ok": True})

    def classified_pump():
        q = bus.subscribe("classified")
        while True:
            try:
                evt = q.get_nowait()
            except queue.Empty:
                socketio.sleep(0.1)
                continue
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
            try:
                evt = q.get_nowait()
            except queue.Empty:
                socketio.sleep(0.1)
                continue
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
