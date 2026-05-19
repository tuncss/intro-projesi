import logging
import threading
import time

from ngfw.action_engine import ActionEngine
from ngfw.classifier import Classifier
from ngfw.config import load_config
from ngfw.event_bus import EventBus
from ngfw.feature_extractor import extract
from ngfw.flow_builder import Flow, FlowBuilder
from ngfw.sniffer import Sniffer


log = logging.getLogger("ngfw")


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

    def on_flow_closed(flow: Flow) -> None:
        vec = extract(flow)
        label, conf = clf.predict(vec)
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
            "n_packets": len(flow.packets),
            "close_reason": flow.close_reason,
        }
        bus.publish("classified", event)
        if label != "BENIGN" and conf >= cfg.confidence_threshold:
            # Don't block our own outbound traffic to safe ports.
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
