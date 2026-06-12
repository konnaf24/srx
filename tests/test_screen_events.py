"""Detection rows 3-6: screen events — scans, floods, fragmentation, malformed.

Offline tests validate the stimulus descriptors and the correlation of screen
events; live tests (requires_srx) drive nmap/hping3/scapy and assert screen
telemetry + counters.
"""

from __future__ import annotations

import time

import pytest

from generators.packet_gen import PacketGenerator
from generators.scan_gen import ScanGenerator
from validation.assertions import assert_event_present
from validation.correlator import Correlator, Detection, FiveTuple, TelemetryEvent

SRC = "198.51.100.5"
DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
def test_nmap_cmd_builder_scan_types():
    for scan_type, flag in [("syn", "-sS"), ("xmas", "-sX"), ("fin", "-sF")]:
        # build_nmap_cmd requires nmap on PATH; skip the binary check by only
        # asserting the flag mapping via the internal table when nmap missing.
        try:
            cmd = ScanGenerator.build_nmap_cmd(DST, scan_type, max_ports=100)
        except FileNotFoundError:
            from generators.scan_gen import _NMAP_SCAN_FLAGS

            assert _NMAP_SCAN_FLAGS[scan_type] == flag
            continue
        assert flag in cmd
        assert DST in cmd


def test_hping3_flood_cmd_is_bounded():
    try:
        cmd = ScanGenerator.build_hping3_flood_cmd(DST, "syn", 80, count=2000, rate_pps=500)
    except FileNotFoundError:
        pytest.skip("hping3 not installed")
    assert "-c" in cmd and "2000" in cmd  # bounded packet count
    assert any(a.startswith("u") for a in cmd)  # paced inter-packet interval
    assert "-S" in cmd


@pytest.mark.parametrize(
    "builder,expected_type",
    [
        ("malformed_flags", "RT_SCREEN_TCP"),
        ("bad_checksum", "RT_SCREEN_TCP"),
        ("tiny_ttl", "RT_SCREEN_IP"),
        ("overlapping_fragments", "RT_SCREEN_IP"),
    ],
)
def test_packet_stimulus_descriptors(builder, expected_type):
    gen = PacketGenerator(SRC, DST)
    stim = getattr(gen, builder)(send=False)
    assert stim.expected_event_type == expected_type
    assert stim.five_tuple.src_ip == SRC
    assert stim.five_tuple.dst_ip == DST


def test_scan_event_correlates_on_ip_pair_without_port():
    """Scans sweep ports, so the stimulus 5-tuple has no dst_port; matching must
    still succeed against an event that carries a concrete port (wildcard rule)."""
    gen = ScanGenerator(SRC, DST)
    stim = gen.tcp_scan("syn", max_ports=100, run=False)
    event = TelemetryEvent(
        "RT_SCREEN_TCP",
        FiveTuple(SRC, DST, "TCP", 51000, 443),
        stim.timestamp + 1,
        fields={"source-address": SRC, "destination-address": DST, "attack-name": "tcp port scan"},
    )
    corr = Correlator()
    verdict = corr.evaluate(stim, [event], ground_truth=[stim.five_tuple])
    assert verdict.logged is Detection.YES
    assert verdict.passed


# ---------------------------------------------------------------------------
# Live tests
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
@pytest.mark.parametrize("scan_type", ["syn", "xmas", "fin"])
def test_live_tcp_scan(config, syslog_collector, scan_type):
    targets = config["targets"]
    limits = config["attack_limits"]
    gen = ScanGenerator(config.get("src_ip", "0.0.0.0"), targets["primary_host"])
    stim = gen.tcp_scan(scan_type, max_ports=limits["scan_max_ports"], run=True)
    time.sleep(3)
    events = syslog_collector.query(event_type="RT_SCREEN_TCP", five_tuple=stim.five_tuple)
    assert_event_present(events, "RT_SCREEN_TCP", stim.five_tuple)


@pytest.mark.requires_srx
@pytest.mark.parametrize("flood_type", ["syn", "icmp", "udp"])
def test_live_flood(config, syslog_collector, flood_type):
    targets = config["targets"]
    limits = config["attack_limits"]
    gen = ScanGenerator(config.get("src_ip", "0.0.0.0"), targets["primary_host"])
    stim = gen.flood(
        flood_type,
        dst_port=targets["allowed_tcp_port"],
        count=limits["flood_packets"],
        rate_pps=limits["flood_rate_pps"],
        run=True,
    )
    time.sleep(3)
    events = syslog_collector.query(five_tuple=stim.five_tuple)
    assert any(e.event_type.startswith("RT_SCREEN") for e in events)


@pytest.mark.requires_srx
def test_live_fragmentation(config, syslog_collector):
    targets = config["targets"]
    limits = config["attack_limits"]
    gen = PacketGenerator(config.get("src_ip", "0.0.0.0"), targets["primary_host"])
    stim = gen.overlapping_fragments(
        targets["allowed_tcp_port"], frag_count=limits["frag_count"], send=True
    )
    time.sleep(2)
    events = syslog_collector.query(five_tuple=stim.five_tuple)
    assert any(e.event_type.startswith("RT_SCREEN") for e in events)
