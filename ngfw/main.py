import logging
import threading
import time
from collections import defaultdict, deque

from ngfw.action_engine import ActionEngine
from ngfw.classifier import Classifier
from ngfw.config import load_config
from ngfw.event_bus import EventBus
from ngfw.feature_extractor import extract
from ngfw.flow_builder import Flow, FlowBuilder
from ngfw.sniffer import Sniffer


log = logging.getLogger("ngfw")

PORT_SCAN_WINDOW = 10.0
PORT_SCAN_UNIQUE_PORTS = 20
DOS_SYN_COUNT = 100
DOS_SYN_RATE = 100.0


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    cfg = load_config()
    bus = EventBus()
    clf = Classifier(cfg)
    action = ActionEngine(cfg, bus)
    action.start()
    log.info("Action cleanup started")

    def sniffer_excepthook(args: threading.ExceptHookArgs) -> None:
        if args.thread.name == "sniffer":
            log.error(
                "Sniffer failed for interfaces %s. Check NIC names or set "
                "NGFW_INTERFACES=eth0,eth1.",
                cfg.interfaces,
                exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
            )
            return
        threading.__excepthook__(args)

    threading.excepthook = sniffer_excepthook
    port_scan_windows: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)

    def behavior_override(flow: Flow, label: str, conf: float) -> tuple[str, float, str]:
        now = time.time()
        syn_count = sum(1 for pkt in flow.packets if pkt.tcp_flags & 0x02)
        duration = max(flow.last_ts - flow.start_ts, 1e-6)
        syn_rate = syn_count / duration

        if flow.key[4] == "TCP" and (syn_count >= DOS_SYN_COUNT or syn_rate >= DOS_SYN_RATE):
            return "DOS", 0.99, "behavior"

        src_ip, dst_ip, _src_port, dst_port, proto = flow.key
        if proto == "TCP":
            window_key = (src_ip, dst_ip)
            window = port_scan_windows[window_key]
            window.append((now, dst_port))
            while window and now - window[0][0] > PORT_SCAN_WINDOW:
                window.popleft()
            if len({port for _ts, port in window}) >= PORT_SCAN_UNIQUE_PORTS:
                return "PORT_SCAN", 0.99, "behavior"

        return label, conf, "ml"

    def on_flow_closed(flow: Flow) -> None:
        vec = extract(flow)
        label, conf = clf.predict(vec)
        label, conf, source = behavior_override(flow, label, conf)
        event = {
            "ts": time.time(),
            "src_ip": flow.key[0],
            "dst_ip": flow.key[1],
            "src_port": flow.key[2],
            "dst_port": flow.key[3],
            "proto": flow.key[4],
            "interface": flow.packets[0].interface if flow.packets else "?",
            "label": label,
            "confidence": conf,
            "detection_source": source,
            "n_packets": len(flow.packets),
            "close_reason": flow.close_reason,
        }
        bus.publish("classified", event)
        if label != "BENIGN" and conf >= cfg.confidence_threshold:
            # Don't block our own outbound safe-port traffic on low-context ML hits.
            if source == "ml" and flow.key[3] in cfg.outbound_safe_ports:
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
    log.info("Flow processor started")

    sniffer = Sniffer(cfg, bus)
    sniffer.start()
    log.info("Sniffer started on %s", cfg.interfaces)

    from ngfw.dashboard.app import create_app

    app, socketio = create_app(cfg, bus, action)
    log.info("Dashboard on http://%s:%d", cfg.flask_host, cfg.flask_port)
    socketio.run(app, host=cfg.flask_host, port=cfg.flask_port)


if __name__ == "__main__":
    main()
