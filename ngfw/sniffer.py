import threading
import time

from scapy.all import IP, TCP, UDP, sniff

from ngfw.config import Config
from ngfw.event_bus import EventBus


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
        # Scapy does not expose iface per-packet reliably across versions.
        iface = getattr(pkt, "sniffed_on", None) or self.cfg.interfaces[0]

        length = int(ip.len) if ip.len is not None else len(ip)

        self.bus.publish(
            "packet",
            {
                "ts": time.time(),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "length": length,
                "tcp_flags": tcp_flags,
                "interface": iface,
            },
        )
