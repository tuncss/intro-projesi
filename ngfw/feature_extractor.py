import numpy as np

from ngfw.flow_builder import Flow


# MUST match training feature order exactly.
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

    duration = max(flow.last_ts - flow.start_ts, 1e-6)
    fwd = [p for p in pkts if p.direction == "fwd"]
    bwd = [p for p in pkts if p.direction == "bwd"]
    fwd_lens = [p.length for p in fwd]
    bwd_lens = [p.length for p in bwd]
    total_fwd_bytes = sum(fwd_lens)
    total_bwd_bytes = sum(bwd_lens)
    iats = [pkts[i].ts - pkts[i - 1].ts for i in range(1, len(pkts))]
    flow_iat_mean = float(np.mean(iats)) if iats else 0.0
    syn_count = sum(1 for p in pkts if p.tcp_flags & 0x02)
    ack_count = sum(1 for p in pkts if p.tcp_flags & 0x10)
    rst_count = sum(1 for p in pkts if p.tcp_flags & 0x04)
    avg_pkt_size = float(np.mean([p.length for p in pkts]))
    fwd_per_sec = len(fwd) / duration
    bwd_per_sec = len(bwd) / duration
    down_up_ratio = (total_bwd_bytes / total_fwd_bytes) if total_fwd_bytes > 0 else 0.0

    return np.array(
        [
            duration * 1_000_000,
            len(fwd),
            len(bwd),
            total_fwd_bytes,
            total_bwd_bytes,
            float(np.mean(fwd_lens)) if fwd_lens else 0.0,
            float(np.mean(bwd_lens)) if bwd_lens else 0.0,
            flow_iat_mean * 1_000_000,
            syn_count,
            ack_count,
            rst_count,
            avg_pkt_size,
            fwd_per_sec,
            bwd_per_sec,
            down_up_ratio,
        ],
        dtype=float,
    )
