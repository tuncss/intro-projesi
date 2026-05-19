from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(frozen=True)
class Config:
    # NICs to sniff (comma-separated env override)
    interfaces: tuple[str, ...] = ("eth0", "eth1")
    # Flow timeouts (seconds)
    flow_idle_timeout: float = 2.0
    flow_active_timeout: float = 120.0
    # Short idle timeout for tiny/scan-like flows (<= short_flow_max_packets)
    flow_idle_timeout_short: float = 0.4
    short_flow_max_packets: int = 3
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
    # Behavior layer - only applied to traffic inside this subnet (avoids NAT FPs)
    lab_subnet: str = "192.168.56.0/24"
    # Never block or behavior-override traffic originating from these IPs.
    # Local interface IPs are auto-detected at startup and merged with this list.
    protected_ips: tuple[str, ...] = ()
    # Port scan: unique dst ports per (src,dst) within window
    port_scan_window: float = 10.0
    port_scan_unique_ports: int = 15
    # DOS: aggregated SYNs from one src_ip toward one dst_ip within window
    dos_window: float = 5.0
    dos_syn_threshold: int = 60
    dos_same_dst_ratio: float = 0.7
    # Brute force: many *established* flows from one src to one (dst, dst_port)
    # An "established" flow has bidirectional traffic AND real payload -
    # excludes SYN floods (no payload) and stays decoupled from packet count
    # (Hydra reuses TCP connections via MaxAuthTries, producing 60-150 packets/flow).
    brute_window: float = 30.0
    brute_flow_threshold: int = 3
    brute_min_fwd: int = 3
    brute_min_bwd: int = 3
    brute_min_payload: int = 200  # any one packet > this many bytes means real KEX/auth
    brute_ports: tuple[int, ...] = (22, 21, 23, 3389)


def load_config() -> Config:
    kwargs = {}
    if v := os.getenv("NGFW_INTERFACES"):
        kwargs["interfaces"] = tuple(v.split(","))
    if v := os.getenv("NGFW_IDLE_TIMEOUT"):
        kwargs["flow_idle_timeout"] = float(v)
    if v := os.getenv("NGFW_IDLE_TIMEOUT_SHORT"):
        kwargs["flow_idle_timeout_short"] = float(v)
    if v := os.getenv("NGFW_ACTIVE_TIMEOUT"):
        kwargs["flow_active_timeout"] = float(v)
    if v := os.getenv("NGFW_CONFIDENCE"):
        kwargs["confidence_threshold"] = float(v)
    return Config(**kwargs)
