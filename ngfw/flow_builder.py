import time
from dataclasses import dataclass, field
from typing import Callable, Literal

from ngfw.config import Config


Direction = Literal["fwd", "bwd"]


@dataclass
class PacketRecord:
    ts: float
    direction: Direction
    length: int
    tcp_flags: int
    interface: str


@dataclass
class Flow:
    key: tuple
    start_ts: float
    last_ts: float
    packets: list[PacketRecord] = field(default_factory=list)
    closed: bool = False
    close_reason: str = ""


class FlowBuilder:
    def __init__(self, cfg: Config, on_flow_closed: Callable[[Flow], None]) -> None:
        self.cfg = cfg
        self.on_flow_closed = on_flow_closed
        self.flows: dict[tuple, Flow] = {}

    def add_packet(self, pkt: dict) -> None:
        """pkt = {src_ip,dst_ip,src_port,dst_port,proto,length,tcp_flags,ts,interface}"""
        fwd_key = (
            pkt["src_ip"],
            pkt["dst_ip"],
            pkt["src_port"],
            pkt["dst_port"],
            pkt["proto"],
        )
        bwd_key = (
            pkt["dst_ip"],
            pkt["src_ip"],
            pkt["dst_port"],
            pkt["src_port"],
            pkt["proto"],
        )
        if fwd_key in self.flows:
            key, direction = fwd_key, "fwd"
        elif bwd_key in self.flows:
            key, direction = bwd_key, "bwd"
        else:
            key, direction = fwd_key, "fwd"
            self.flows[key] = Flow(key=key, start_ts=pkt["ts"], last_ts=pkt["ts"])

        flow = self.flows[key]
        flow.last_ts = pkt["ts"]
        flow.packets.append(
            PacketRecord(
                ts=pkt["ts"],
                direction=direction,
                length=pkt["length"],
                tcp_flags=pkt.get("tcp_flags", 0),
                interface=pkt["interface"],
            )
        )
        # Close on FIN (0x01) or RST (0x04).
        if pkt["proto"] == "TCP" and (pkt.get("tcp_flags", 0) & 0x05):
            self._close(key, "FIN_OR_RST")

    def sweep_timeouts(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if now - flow.start_ts >= self.cfg.flow_active_timeout:
                self._close(key, "ACTIVE")
                continue
            # Scan/flood probes are tiny (1-3 packets) and stale fast.
            # Established sessions keep the full idle window.
            if len(flow.packets) <= self.cfg.short_flow_max_packets:
                idle = self.cfg.flow_idle_timeout_short
            else:
                idle = self.cfg.flow_idle_timeout
            if now - flow.last_ts >= idle:
                self._close(key, "IDLE")

    def _close(self, key: tuple, reason: str) -> None:
        flow = self.flows.pop(key, None)
        if flow is None:
            return
        flow.closed = True
        flow.close_reason = reason
        self.on_flow_closed(flow)
