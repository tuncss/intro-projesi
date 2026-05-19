import ipaddress
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

    # Behavior layer state - aggregated across flows, keyed by src_ip
    lab_net = ipaddress.ip_network(cfg.lab_subnet)

    def in_lab(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip) in lab_net
        except ValueError:
            return False

    # (src_ip, dst_ip) -> deque[(ts, dst_port)]  for PORT_SCAN
    port_scan_windows: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
    # src_ip -> deque[(ts, dst_ip)]              for DOS  (each entry = one SYN seen)
    syn_events: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
    # (src_ip, dst_ip, dst_port) -> deque[ts]    for BRUTE_FORCE  (each entry = one closed flow)
    brute_events: dict[tuple[str, str, int], deque[float]] = defaultdict(deque)

    def behavior_override(flow: Flow, label: str, conf: float) -> tuple[str, float, str]:
        src_ip, dst_ip, _src_port, dst_port, proto = flow.key

        # Gate: only override on lab-internal traffic. NAT/internet stays ML-only,
        # which prevents normal browsing from being labeled DOS.
        if not (in_lab(src_ip) and in_lab(dst_ip)):
            return label, conf, "ml"
        if proto != "TCP":
            return label, conf, "ml"

        now = time.time()
        syn_count = sum(1 for pkt in flow.packets if pkt.tcp_flags & 0x02)

        # ---- PORT_SCAN: unique dst ports from src_ip to dst_ip within window ----
        ps_window = port_scan_windows[(src_ip, dst_ip)]
        ps_window.append((now, dst_port))
        while ps_window and now - ps_window[0][0] > cfg.port_scan_window:
            ps_window.popleft()
        unique_ports = {p for _t, p in ps_window}
        if len(unique_ports) >= cfg.port_scan_unique_ports:
            return "PORT_SCAN", 0.99, "behavior"

        # ---- DOS: aggregate SYNs per src_ip across flows within window ----
        # hping3 random-port SYN flood produces one SYN per flow, so aggregate.
        syn_q = syn_events[src_ip]
        for _ in range(syn_count):
            syn_q.append((now, dst_ip))
        while syn_q and now - syn_q[0][0] > cfg.dos_window:
            syn_q.popleft()
        if len(syn_q) >= cfg.dos_syn_threshold:
            same_dst = sum(1 for _t, d in syn_q if d == dst_ip)
            if same_dst >= cfg.dos_syn_threshold * cfg.dos_same_dst_ratio:
                return "DOS", 0.99, "behavior"

        # ---- BRUTE_FORCE: many *established* flows to (dst, brute-port) ----
        # Established = real TCP handshake + payload exchange on both sides.
        # This excludes SYN floods (1-2 packets, mostly one-direction) which
        # would otherwise be mislabeled as brute force on port 22.
        if dst_port in cfg.brute_ports and len(flow.packets) <= 60:
            fwd_count = sum(1 for p in flow.packets if p.direction == "fwd")
            bwd_count = sum(1 for p in flow.packets if p.direction == "bwd")
            if fwd_count >= cfg.brute_min_fwd and bwd_count >= cfg.brute_min_bwd:
                bk = (src_ip, dst_ip, dst_port)
                bq = brute_events[bk]
                bq.append(now)
                while bq and now - bq[0] > cfg.brute_window:
                    bq.popleft()
                if len(bq) >= cfg.brute_flow_threshold:
                    return "BRUTE_FORCE", 0.95, "behavior"

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
        sweep_interval = 0.1
        while True:
            try:
                pkt = pkt_q.get(timeout=sweep_interval)
                flow_builder.add_packet(pkt)
            except Exception:
                pass
            now = time.time()
            if now - last_sweep >= sweep_interval:
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
