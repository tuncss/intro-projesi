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
    if v := os.getenv("NGFW_IDLE_TIMEOUT"):
        kwargs["flow_idle_timeout"] = float(v)
    if v := os.getenv("NGFW_ACTIVE_TIMEOUT"):
        kwargs["flow_active_timeout"] = float(v)
    if v := os.getenv("NGFW_CONFIDENCE"):
        kwargs["confidence_threshold"] = float(v)
    return Config(**kwargs)
