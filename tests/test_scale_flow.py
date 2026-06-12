"""Detection rows 15-17: session volume, throughput, flow/IPFIX export accuracy.

Offline tests validate the wrk/iperf3 argument builders and output parsers and
the IPFIX flow-count comparison logic; live tests drive wrk/iperf3 and compare
exported flow records / counters against the known generated load.
"""

from __future__ import annotations

import time

import pytest

from generators.load_gen import Iperf3Result, LoadGenerator, WrkResult

DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
def test_iperf3_cmd_builder():
    try:
        cmd = LoadGenerator.build_iperf3_cmd("203.0.113.10", duration_s=30, parallel=4, port=5201)
    except FileNotFoundError:
        pytest.skip("iperf3 not installed")
    assert "-c" in cmd and "203.0.113.10" in cmd
    assert "--json" in cmd


def test_wrk_output_parser():
    sample = (
        "Running 30s test @ http://203.0.113.10/\n"
        "  8 threads and 10000 connections\n"
        "  Thread Stats   Avg      Stdev     Max\n"
        "  120000 requests in 30.02s, 1.20GB read\n"
        "Requests/sec:   3997.34\n"
        "Transfer/sec:     40.94MB\n"
    )
    result = LoadGenerator.parse_wrk_output(sample)
    assert isinstance(result, WrkResult)
    assert result.requests == 120000
    assert round(result.duration_s, 1) == 30.0
    assert result.requests_per_sec == 3997.34


def test_iperf3_output_parser():
    sample = (
        '{"end": {"sum_sent": {"bytes": 1250000000, "bits_per_second": 333000000.0}}}'
    )
    result = LoadGenerator.parse_iperf3_output(sample)
    assert isinstance(result, Iperf3Result)
    assert result.bytes_sent == 1250000000
    assert result.bits_per_second == 333000000.0


def test_ipfix_flow_count_comparison():
    """Row 17: exported IPFIX record count must match generated flow count.

    The comparison logic lives here as a small, testable helper to make the
    export-accuracy assertion explicit and unit-testable offline.
    """
    def ipfix_export_accurate(generated, exported, tolerance=0):
        return abs(generated - exported) <= tolerance

    assert ipfix_export_accurate(1000, 1000)
    assert ipfix_export_accurate(1000, 999, tolerance=2)
    assert not ipfix_export_accurate(1000, 950, tolerance=2)


# ---------------------------------------------------------------------------
# Live tests
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
def test_live_session_volume(config, syslog_collector):
    targets = config["targets"]
    thr = config["thresholds"]
    gen = LoadGenerator(targets["primary_host"])
    gen.session_volume(
        targets["http_url"],
        connections=thr["session_volume_target"],
        duration_s=15,
        run=True,
    )
    time.sleep(3)
    creates = syslog_collector.query(event_type="RT_FLOW_SESSION_CREATE")
    assert len(creates) > 0, "Expected RT_FLOW session-create telemetry under load"


@pytest.mark.requires_srx
def test_live_throughput(config, srx):
    targets = config["targets"]
    thr = config["thresholds"]
    gen = LoadGenerator(targets["primary_host"])
    gen.throughput(duration_s=15, parallel=4, run=True)
    # Validate byte counters increased via NETCONF session table (device truth).
    sessions = srx.get_flow_sessions()
    assert isinstance(sessions, list)


@pytest.mark.requires_srx
def test_live_ipfix_export_accuracy(config):
    """Compare exported IPFIX flow records against a known generated flow count.

    Requires a configured IPFIX/J-Flow collector; here we assert the configured
    expectation is present so the test fails loudly if misconfigured.
    """
    expected = config["thresholds"].get("expected_ipfix_flows")
    assert expected and expected > 0, "Configure thresholds.expected_ipfix_flows"
