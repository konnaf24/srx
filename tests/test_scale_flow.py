"""Detection rows 15-17: session volume, throughput, flow/IPFIX export accuracy.

Offline tests validate the wrk/iperf3 argument builders and output parsers and
checked execution; live smoke tests require measurements and correlated telemetry.
Concurrent-session measurement is not claimed by the volume telemetry smoke
test. IPFIX export comparison is unimplemented and explicitly skipped.
"""

from __future__ import annotations

import json
import math
import time

import pytest

from generators.load_gen import Iperf3Result, LoadGenerator, WrkResult

DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
def test_iperf3_cmd_builder(monkeypatch):
    monkeypatch.setattr("generators.load_gen.require_binary", lambda name: f"/mock/{name}")
    cmd = LoadGenerator.build_iperf3_cmd("203.0.113.10", duration_s=30, parallel=4, port=5201)
    assert cmd[0] == "/mock/iperf3"
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


# No test-local IPFIX comparison helper: there is no production comparison yet.


# ---------------------------------------------------------------------------
# Live tests (never run as part of the offline regression suite)
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
def test_live_session_volume_telemetry(config, syslog_collector):
    """Check measured HTTP load and distinct CREATEs, not simultaneous sessions.

    Source/endpoint/time scoping excludes unrelated and stale CREATEs. Shared
    endpoint traffic or NAT needs stronger capture attribution in a future PR.
    """
    from validation.correlator import FiveTuple

    targets = config["targets"]
    source = config.get("src_ip")
    if not source or source == "0.0.0.0":
        pytest.skip("Configure src_ip for load telemetry attribution (pre-NAT lab path required)")
    target = config["thresholds"]["session_volume_target"]
    gen = LoadGenerator(targets["primary_host"])
    stim = gen.session_volume(
        targets["http_url"], connections=target, duration_s=15, run=True,
    )
    measured = stim.metadata["result"]
    assert stim.metadata["execution_status"] == "succeeded"
    assert measured["requests"] > 0 and measured["requests_per_sec"] > 0, "No measured HTTP load"
    assert measured["socket_errors"] == 0, "wrk reported socket failures"
    assert measured["non_success_responses"] == 0, "wrk reported HTTP errors"
    end = time.time()
    time.sleep(3)
    flow = FiveTuple(source, stim.five_tuple.dst_ip, "TCP", None, stim.five_tuple.dst_port)
    creates = syslog_collector.query(
        event_type="RT_FLOW_SESSION_CREATE", five_tuple=flow,
        start_time=stim.timestamp, end_time=end + 3,
    )
    # Require concrete identity, not wildcard matches or duplicate log lines.
    observed = {
        event.five_tuple for event in creates
        if event.event_type == "RT_FLOW_SESSION_CREATE"
        and stim.timestamp <= event.timestamp <= end + 3
        and event.five_tuple.src_ip == source
        and event.five_tuple.dst_ip == flow.dst_ip
        and event.five_tuple.protocol == "TCP"
        and event.five_tuple.dst_port == flow.dst_port
        and event.five_tuple.src_port is not None
    }
    assert len(observed) >= target, (
        f"Only {len(observed)} distinct, scoped CREATE flows for {target} requested connections; "
        "this is cumulative telemetry evidence, not peak-concurrency validation"
    )


@pytest.mark.requires_srx
def test_live_throughput(config, syslog_collector):
    """Require measured target throughput plus positive bytes on exact logged flows.

    This is not a NETCONF counter-delta or full byte-accounting accuracy test.
    """
    targets = config["targets"]
    target_mbps = float(config["thresholds"]["throughput_target_mbps"])
    assert math.isfinite(target_mbps) and target_mbps > 0, "Invalid throughput target"
    gen = LoadGenerator(targets["primary_host"])
    stim = gen.throughput(duration_s=15, parallel=4, run=True)
    measured = stim.metadata["result"]
    assert stim.metadata["execution_status"] == "succeeded"
    assert measured["bytes_sent"] > 0, "iperf3 sent no measured bytes"
    assert measured["bits_per_second"] > 0
    assert measured["bits_per_second"] >= target_mbps * 1_000_000, "Measured throughput below target"
    connected = json.loads(measured["raw"]).get("start", {}).get("connected", [])
    assert connected, "iperf3 did not report actual connection tuples for attribution"
    end = time.time()
    time.sleep(3)
    from validation.correlator import FiveTuple

    for connection in connected:
        flow = FiveTuple(
            connection["local_host"], connection["remote_host"], "TCP",
            connection["local_port"], connection["remote_port"],
        )
        assert all(value is not None for value in vars(flow).values()), "Incomplete iperf tuple"
        events = syslog_collector.query(
            event_type="RT_FLOW_SESSION_CLOSE", five_tuple=flow,
            start_time=stim.timestamp, end_time=end + 3,
        )
        matching = [event for event in events if event.five_tuple == flow
                    and event.event_type == "RT_FLOW_SESSION_CLOSE"
                    and stim.timestamp <= event.timestamp <= end + 3]
        assert matching, f"No scoped SRX CLOSE evidence for {flow}"
        assert any(int(event.fields.get("bytes-from-client", 0)) > 0 for event in matching), (
            f"No positive SRX byte evidence for {flow}"
        )


@pytest.mark.requires_srx
def test_live_ipfix_export_accuracy():
    pytest.skip(
        "IPFIX/J-Flow export validation is not implemented: no collector, known-flow "
        "attribution or production export-count comparison is wired into this test"
    )
