from ngfw.config import Config
from ngfw.flow_builder import FlowBuilder


def packet(**overrides):
    pkt = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 12345,
        "dst_port": 80,
        "proto": "TCP",
        "length": 60,
        "tcp_flags": 0,
        "ts": 0.0,
        "interface": "eth0",
    }
    pkt.update(overrides)
    return pkt


def test_fwd_then_bwd_same_flow():
    closed = []
    builder = FlowBuilder(Config(), closed.append)

    builder.add_packet(packet(ts=1.0))
    builder.add_packet(
        packet(
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=80,
            dst_port=12345,
            ts=2.0,
        )
    )

    assert len(builder.flows) == 1
    flow = next(iter(builder.flows.values()))
    assert flow.key == ("10.0.0.1", "10.0.0.2", 12345, 80, "TCP")
    assert [record.direction for record in flow.packets] == ["fwd", "bwd"]
    assert closed == []


def test_fin_closes_flow():
    closed = []
    builder = FlowBuilder(Config(), closed.append)

    builder.add_packet(packet(tcp_flags=0x01))

    assert len(closed) == 1
    assert closed[0].closed is True
    assert closed[0].close_reason == "FIN_OR_RST"
    assert builder.flows == {}


def test_idle_timeout_closes_flow():
    closed = []
    builder = FlowBuilder(Config(), closed.append)

    builder.add_packet(packet(ts=0.0))
    builder.sweep_timeouts(now=11.0)

    assert len(closed) == 1
    assert closed[0].close_reason == "IDLE"
    assert builder.flows == {}


def test_active_timeout_closes_flow():
    closed = []
    builder = FlowBuilder(Config(), closed.append)

    builder.add_packet(packet(ts=0.0))
    builder.add_packet(packet(ts=1.0))
    builder.sweep_timeouts(now=121.0)

    assert len(closed) == 1
    assert closed[0].close_reason == "ACTIVE"
    assert builder.flows == {}
