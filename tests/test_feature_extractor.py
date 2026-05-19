import numpy as np

from ngfw.feature_extractor import extract
from ngfw.flow_builder import Flow, PacketRecord


def flow_with_packets(packets, start_ts=0.0, last_ts=None):
    if last_ts is None:
        last_ts = packets[-1].ts if packets else start_ts
    return Flow(
        key=("10.0.0.1", "10.0.0.2", 12345, 80, "TCP"),
        start_ts=start_ts,
        last_ts=last_ts,
        packets=packets,
        closed=True,
        close_reason="TEST",
    )


def record(ts, direction="fwd", length=100, tcp_flags=0):
    return PacketRecord(
        ts=ts,
        direction=direction,
        length=length,
        tcp_flags=tcp_flags,
        interface="eth0",
    )


def test_shape_is_15():
    flow = flow_with_packets([record(0.0), record(1.0, direction="bwd")])

    vec = extract(flow)

    assert vec.shape == (15,)
    assert vec.dtype == float


def test_empty_flow_returns_zeros():
    flow = flow_with_packets([])

    vec = extract(flow)

    assert np.all(vec == 0.0)


def test_syn_flag_counted():
    flow = flow_with_packets(
        [
            record(0.0, tcp_flags=0x02),
            record(1.0, tcp_flags=0x12),
            record(2.0, tcp_flags=0x10),
        ]
    )

    vec = extract(flow)

    assert vec[8] == 2


def test_down_up_ratio_zero_when_no_fwd_bytes():
    flow = flow_with_packets(
        [
            record(0.0, direction="bwd", length=100),
            record(1.0, direction="bwd", length=200),
        ]
    )

    vec = extract(flow)

    assert vec[14] == 0.0


def test_fwd_packets_per_sec_scales_with_duration():
    packets = [record(i * 0.1, direction="fwd") for i in range(10)]
    flow = flow_with_packets(packets, start_ts=0.0, last_ts=2.0)

    vec = extract(flow)

    assert vec[12] == 5.0
