"""Mock-only regression tests: no traffic, binary execution, SSH or SRX access.

Every test has fail-closed process/socket guards. Tests exercising a run=True
path replace subprocess.run with deterministic CompletedProcess/exception fakes.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
from dataclasses import fields

import pytest

from deploy import srx_workload as workload
from generators import load_gen, scan_gen
from generators.load_gen import DEFAULT_LIMITS, LoadGenerator, WorkloadLimits
from generators.scan_gen import ScanGenerator
from validation.correlator import FiveTuple, Stimulus, TelemetryEvent

DST = "203.0.113.10"
SRC = "198.51.100.5"
WRK = "120 requests in 1.00s, 10KB read\nRequests/sec: 120.00\n"
IPERF = json.dumps({"end": {"sum_sent": {"bytes": 125000000, "bits_per_second": 1000000000}}})


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Unmocked external execution/network access in workload regression")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(load_gen, "require_binary", forbidden)
    monkeypatch.setattr(scan_gen, "require_binary", forbidden)


@pytest.fixture
def mock_resolvers(monkeypatch):
    monkeypatch.setattr(load_gen, "require_binary", lambda name: f"/mock/{name}")
    monkeypatch.setattr(scan_gen, "require_binary", lambda name: f"/mock/{name}")


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "2", float("nan"), float("inf")])
@pytest.mark.parametrize("field", [f.name for f in fields(WorkloadLimits)])
def test_configurable_ceilings_must_be_positive_finite_integers(field, bad):
    with pytest.raises(ValueError):
        WorkloadLimits(**{field: bad})


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "2", float("nan"), float("inf"), 10**12])
@pytest.mark.parametrize("kind", ["rate", "count", "ports", "duration", "connections", "threads", "parallel", "port"])
def test_invalid_builder_inputs_rejected_before_binary_resolution(kind, bad):
    calls = {
        "rate": lambda: ScanGenerator.build_hping3_flood_cmd(DST, "syn", 80, 2000, bad),
        "count": lambda: ScanGenerator.build_hping3_flood_cmd(DST, "syn", 80, bad, 500),
        "ports": lambda: ScanGenerator.build_nmap_cmd(DST, "syn", bad),
        "duration": lambda: LoadGenerator.build_iperf3_cmd(DST, bad),
        "connections": lambda: LoadGenerator.build_wrk_cmd(f"http://{DST}", bad, 1, 30),
        "threads": lambda: LoadGenerator.build_wrk_cmd(f"http://{DST}", 100, bad, 30),
        "parallel": lambda: LoadGenerator.build_iperf3_cmd(DST, 30, bad),
        "port": lambda: LoadGenerator.build_iperf3_cmd(DST, 30, port=bad),
    }
    with pytest.raises(ValueError):
        calls[kind]()


@pytest.mark.parametrize("run", [False, True])
@pytest.mark.parametrize("method,kwargs", [
    ("throughput", {"duration_s": 0}), ("throughput", {"parallel": 33}),
    ("throughput", {"port": 65536}),
    ("session_volume", {"url": f"http://{DST}", "connections": 10001}),
    ("session_volume", {"url": f"http://{DST}", "threads": 0}),
    ("tcp_scan", {"max_ports": 4097}), ("tcp_scan", {"scan_type": "invalid"}),
    ("flood", {"count": 10001}), ("flood", {"rate_pps": 0}),
    ("flood", {"flood_type": "invalid"}), ("flood", {"dst_port": 0}),
])
def test_direct_generator_apis_validate_even_descriptor_mode(method, kwargs, run):
    generator = LoadGenerator(DST) if method in {"throughput", "session_volume"} else ScanGenerator(SRC, DST)
    with pytest.raises(ValueError):
        getattr(generator, method)(run=run, **kwargs)


def test_default_descriptors_do_not_need_binaries():
    stimuli = [LoadGenerator(DST).session_volume(f"http://{DST}"),
               LoadGenerator(DST).throughput(), ScanGenerator(SRC, DST).flood(),
               ScanGenerator(SRC, DST).tcp_scan()]
    assert stimuli[0].metadata["connections"] == 10000
    assert stimuli[0].metadata["threads"] == 8
    assert stimuli[1].metadata["duration_s"] == 30
    assert stimuli[1].metadata["parallel"] == 4
    assert all(stim.metadata["execution_status"] == "not_run" for stim in stimuli)
    assert all(stim.metadata["detection_status"] == "not_evaluated" for stim in stimuli)
    assert all("result" not in stim.metadata for stim in stimuli)


def test_configured_limits_apply_to_builders_and_instances(mock_resolvers):
    limits = WorkloadLimits(max_connections=12000, max_rate_pps=1500)
    cmd = LoadGenerator.build_wrk_cmd(f"http://{DST}", 12000, 8, 30, limits=limits)
    assert cmd[cmd.index("-c") + 1] == "12000"
    assert LoadGenerator(DST, limits=limits).session_volume(f"http://{DST}", 12000).metadata["connections"] == 12000
    cmd = ScanGenerator.build_hping3_flood_cmd(DST, "syn", 80, 2000, 1500, limits=limits)
    assert cmd[cmd.index("-i") + 1] == "u667"
    with pytest.raises(ValueError):
        ScanGenerator(SRC, DST, limits=WorkloadLimits(max_packets=100)).flood()


def test_pacing_rounds_up_and_flood_duration_is_bounded(mock_resolvers):
    cmd = ScanGenerator.build_hping3_flood_cmd(DST, "syn", 80, 100, 333)
    assert int(cmd[cmd.index("-i") + 1][1:]) == 3004
    with pytest.raises(ValueError, match="duration"):
        ScanGenerator.build_hping3_flood_cmd(DST, "syn", 80, 10000, 1)


def test_protocol_specific_ports_and_wrk_thread_relationship(mock_resolvers):
    assert "--icmp" in ScanGenerator.build_hping3_flood_cmd(DST, "icmp", 0, 1, 1)
    for protocol in ("syn", "udp"):
        with pytest.raises(ValueError):
            ScanGenerator.build_hping3_flood_cmd(DST, protocol, 0, 1, 1)
    with pytest.raises(ValueError):
        LoadGenerator.build_wrk_cmd(f"http://{DST}", 2, 3, 30)
    with pytest.raises(ValueError):
        WorkloadLimits(max_ports=65536)


@pytest.mark.parametrize("url", [f"http://{DST}:0", f"http://{DST}:65536", "file:///tmp/nope", "--help"])
def test_invalid_url_or_url_port_precedes_resolution(url):
    with pytest.raises(ValueError):
        LoadGenerator.build_wrk_cmd(url, 100, 4, 30)


def test_wrk_descriptor_has_actual_url_port():
    assert LoadGenerator(DST).session_volume(f"https://{DST}").five_tuple.dst_port == 443
    assert LoadGenerator(DST).session_volume(f"http://{DST}:8080").five_tuple.dst_port == 8080


@pytest.mark.parametrize("args", [
    ["all", "--duration", "301"], ["wrk", "--duration", "nan"],
    ["wrk", "--connections", "10001"], ["wrk", "--threads", "65"],
    ["iperf", "--parallel", "33"], ["flood", "--count", "10001"],
    ["flood", "--rate", "1001"], ["flood", "--rate", "0"],
    ["flood", "--count", "10000", "--rate", "1"], ["scan", "--max-ports", "4097"],
    ["frag", "--count", "65"], ["frag", "--count", "0"], ["ttl", "--ttl", "256"],
    ["http", "--port", "0"], ["handshake", "--port", "65536"],
    ["--limit-fragments", "4", "all"], ["--limit-workloads", "17", "all"],
    ["--limit-rate-pps", "0", "all"],
])
def test_cli_preflight_rejects_before_route_resolution_or_senders(args):
    with pytest.raises(SystemExit) as exc:
        workload.main(["--target", DST, "--yes", *args])
    assert exc.value.code == 2


def test_cli_explicit_ceiling_keeps_requested_value():
    args = workload.build_parser().parse_args([
        "--target", DST, "--limit-duration-s", "600", "wrk", "--duration", "500",
    ])
    assert args.duration == 500 and args.limits.max_duration_s == 600


@pytest.mark.parametrize("method,kwargs", [
    ("do_frag", {"port": 80, "count": 65}),
    ("do_ttl", {"port": 80, "ttl": 256}),
    ("do_badcsum", {"port": 0}), ("do_malformed", {"port": 65536}),
    ("do_deny", {"port": -1}),
])
def test_direct_crafted_workload_rejects_before_packet_generator(monkeypatch, method, kwargs):
    def forbidden(*args, **kwargs):
        pytest.fail("PacketGenerator instantiated before validation")
    monkeypatch.setattr(workload, "PacketGenerator", forbidden)
    with pytest.raises(ValueError):
        getattr(workload, method)(argparse.Namespace(target=DST, src=SRC, **kwargs))


def test_suite_validates_every_workload_before_start(monkeypatch):
    started = []
    good = workload.Workload("good", lambda args: started.append(True) or 0, argparse.Namespace())
    bad = workload.Workload("bad", workload.do_frag, argparse.Namespace(port=80, count=65))
    with pytest.raises(ValueError):
        workload.run_concurrently([good, bad])
    assert not started
    with pytest.raises(ValueError):
        workload.run_concurrently([good] * (DEFAULT_LIMITS.max_workloads + 1))
    assert not started


@pytest.mark.parametrize("method,output", [("throughput", IPERF), ("session_volume", WRK)])
def test_success_retains_actual_measurements_and_diagnostics(monkeypatch, mock_resolvers, method, output):
    def fake(cmd, **kwargs):
        assert kwargs["timeout"] == 60
        assert kwargs["capture_output"] and kwargs["text"]
        return subprocess.CompletedProcess(cmd, 0, output, "diagnostic")
    monkeypatch.setattr(subprocess, "run", fake)
    gen = LoadGenerator(DST)
    stim = gen.throughput(run=True) if method == "throughput" else gen.session_volume(f"http://{DST}", run=True)
    assert stim.metadata["execution_status"] == "succeeded"
    assert stim.metadata["detection_status"] == "not_evaluated"
    assert stim.metadata["returncode"] == 0
    assert stim.metadata["stderr"] == "diagnostic"
    assert stim.metadata["elapsed_s"] >= 0
    assert stim.metadata["result"]["raw"] == output
    if method == "throughput":
        assert stim.metadata["result"]["bytes_sent"] == 125000000
    else:
        assert stim.metadata["result"]["requests"] == 120


@pytest.mark.parametrize("method", ["throughput", "session_volume", "tcp_scan", "flood"])
@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_tool_failure_or_timeout_cannot_return_success(monkeypatch, mock_resolvers, method, failure):
    def fake(cmd, **kwargs):
        assert 0 < kwargs["timeout"] <= DEFAULT_LIMITS.max_duration_s + 30
        if failure == "timeout":
            raise subprocess.TimeoutExpired(cmd, kwargs["timeout"], output="partial", stderr="timeout detail")
        return subprocess.CompletedProcess(cmd, 7, WRK if method == "session_volume" else IPERF, "tool failed")
    monkeypatch.setattr(subprocess, "run", fake)
    gen = LoadGenerator(DST) if method in {"throughput", "session_volume"} else ScanGenerator(SRC, DST)
    kwargs = {"url": f"http://{DST}"} if method == "session_volume" else {}
    expected = subprocess.TimeoutExpired if failure == "timeout" else subprocess.CalledProcessError
    with pytest.raises(expected) as exc:
        getattr(gen, method)(run=True, **kwargs)
    assert exc.value.stderr == ("timeout detail" if failure == "timeout" else "tool failed")


@pytest.mark.parametrize("output", ["", "{}", "[]", '{"error":"server busy"}',
    '{"end":{}}', '{"end":{"sum_sent":{"bytes":0}}}',
    '{"end":{"sum_sent":{"bytes":-1,"bits_per_second":1}}}',
    '{"end":{"sum_sent":{"bytes":1.5,"bits_per_second":1}}}',
    '{"end":{"sum_sent":{"bytes":true,"bits_per_second":1}}}',
    '{"end":{"sum_sent":{"bytes":1,"bits_per_second":NaN}}}',
    '{"end":{"sum_sent":{"bytes":1,"bits_per_second":Infinity}}}',
    '{"end":{"sum_sent":{"bytes":1,"bits_per_second":-1}}}',
])
def test_malformed_iperf_is_not_successful_zero(monkeypatch, mock_resolvers, output):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, output, ""))
    with pytest.raises(ValueError):
        LoadGenerator(DST).throughput(run=True)


@pytest.mark.parametrize("output", ["", "connection refused", "Requests/sec: 0", "0 requests in 1.00s",
    "10 requests in 1.00days\nRequests/sec: 10\n", "10 requests in 0s\nRequests/sec: 10\n",
    "10 requests in 1s\nRequests/sec: nan\n", "10 requests in 1s\nRequests/sec: -1\n",
    "-10 requests in 1s\nRequests/sec: 10\n", WRK + "Socket errors: invalid\n",
    WRK + "Non-2xx or 3xx responses: invalid\n"])
def test_malformed_wrk_is_not_successful_zero(monkeypatch, mock_resolvers, output):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, output, ""))
    with pytest.raises(ValueError):
        LoadGenerator(DST).session_volume(f"http://{DST}", run=True)


def test_valid_zero_measurements_are_explicit_not_fabricated():
    assert LoadGenerator.parse_wrk_output("0 requests in 1s\nRequests/sec: 0\n").requests == 0
    assert LoadGenerator.parse_iperf3_output('{"end":{"sum_sent":{"bytes":0,"bits_per_second":0}}}').bytes_sent == 0


def test_wrk_retains_socket_and_http_error_counts():
    result = LoadGenerator.parse_wrk_output(WRK + "Socket errors: connect 1, read 2, write 3, timeout 4\nNon-2xx or 3xx responses: 20\n")
    assert result.socket_errors == 10 and result.non_success_responses == 20


@pytest.mark.parametrize("failure,expected", [("exit", 7), ("timeout", 124), ("missing", 127)])
def test_runner_preserves_failure_elapsed_and_output(monkeypatch, failure, expected):
    times = iter([10.0, 12.5])
    monkeypatch.setattr(workload.time, "monotonic", lambda: next(times))
    def fake(args):
        if failure == "exit":
            raise subprocess.CalledProcessError(7, ["mock"], output="partial", stderr="detail")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(["mock"], 2, output="partial", stderr="detail")
        raise FileNotFoundError("missing mock")
    result = workload._run_workload(workload.Workload("fake", fake, argparse.Namespace()))
    assert result.returncode == expected
    assert result.elapsed_s == 2.5
    assert result.execution_status == "failed" and result.detection_status == "not_evaluated"
    assert "missing mock" in result.error if failure == "missing" else "partial" in result.error and "detail" in result.error


def test_runner_carries_parsed_load_measurements(monkeypatch, mock_resolvers):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, IPERF, ""))
    args = argparse.Namespace(target=DST, port=5201, duration=30, parallel=4)
    result = workload._run_workload(workload.Workload("iperf", workload.do_iperf, args))
    assert result.returncode == 0
    assert result.metadata["result"]["bytes_sent"] == 125000000
    assert result.detection_status == "not_evaluated"


# Exercise the actual live assertion bodies with fakes, not new comparison helpers.
def _mock_live(monkeypatch, output=IPERF, events=()):
    import test_scale_flow as live
    connection = {"local_host": SRC, "remote_host": DST, "local_port": 40000, "remote_port": 5201}
    data = json.loads(output)
    data["start"] = {"connected": [connection]}
    parsed = LoadGenerator.parse_iperf3_output(json.dumps(data))
    stim = Stimulus(FiveTuple(SRC, DST, "TCP", 40000, 5201), 100, "RT_FLOW_SESSION_CLOSE",
                    metadata={"execution_status": "succeeded", "result": vars(parsed)})
    monkeypatch.setattr(live.LoadGenerator, "throughput", lambda *args, **kw: stim)
    monkeypatch.setattr(live.time, "sleep", lambda *args: None)
    monkeypatch.setattr(live.time, "time", lambda: 115)
    class Collector:
        def query(self, **kwargs):
            assert kwargs["start_time"] == 100 and kwargs["end_time"] == 118
            return list(events)
    config = {"targets": {"primary_host": DST}, "thresholds": {"throughput_target_mbps": 1000}}
    return live, config, Collector()


@pytest.mark.parametrize("bytes_sent,bps", [(0, 0), (1, 999999999)])
def test_live_throughput_assertion_rejects_zero_or_below_target(monkeypatch, bytes_sent, bps):
    output = json.dumps({"end": {"sum_sent": {"bytes": bytes_sent, "bits_per_second": bps}}})
    live, config, collector = _mock_live(monkeypatch, output)
    with pytest.raises(AssertionError):
        live.test_live_throughput(config, collector)


@pytest.mark.parametrize("kind", ["none", "unrelated", "stale", "missing_fields", "zero_bytes"])
def test_live_throughput_requires_scoped_byte_evidence(monkeypatch, kind):
    flow = FiveTuple(SRC, DST if kind != "unrelated" else "203.0.113.99", "TCP", 40000, 5201)
    events = [] if kind == "none" else [TelemetryEvent(
        "RT_FLOW_SESSION_CLOSE", flow, 99 if kind == "stale" else 110,
        {} if kind == "missing_fields" else {"bytes-from-client": "0" if kind == "zero_bytes" else "100"},
    )]
    live, config, collector = _mock_live(monkeypatch, events=events)
    with pytest.raises(AssertionError):
        live.test_live_throughput(config, collector)


def test_live_throughput_accepts_measured_target_with_exact_byte_evidence(monkeypatch):
    event = TelemetryEvent("RT_FLOW_SESSION_CLOSE", FiveTuple(SRC, DST, "TCP", 40000, 5201), 110,
                           {"bytes-from-client": "125000000"})
    live, config, collector = _mock_live(monkeypatch, events=[event])
    live.test_live_throughput(config, collector)


@pytest.mark.parametrize("kind", ["unrelated", "stale", "duplicate", "missing_tuple"])
def test_live_volume_rejects_unrelated_stale_or_duplicate_creates(monkeypatch, kind):
    import test_scale_flow as live
    stim = Stimulus(FiveTuple(None, DST, "TCP", None, 80), 100, "RT_FLOW_SESSION_CREATE", metadata={
        "execution_status": "succeeded", "result": vars(LoadGenerator.parse_wrk_output(WRK)),
    })
    monkeypatch.setattr(live.LoadGenerator, "session_volume", lambda *args, **kw: stim)
    monkeypatch.setattr(live.time, "sleep", lambda *args: None)
    monkeypatch.setattr(live.time, "time", lambda: 115)
    event = TelemetryEvent("RT_FLOW_SESSION_CREATE", FiveTuple(
        SRC if kind != "missing_tuple" else None,
        DST if kind != "unrelated" else "203.0.113.99", "TCP", 40000, 80,
    ), 99 if kind == "stale" else 110)
    class Collector:
        def query(self, **kwargs):
            assert kwargs["five_tuple"].src_ip == SRC
            return [event] * 10
    config = {"src_ip": SRC, "targets": {"primary_host": DST, "http_url": f"http://{DST}"},
              "thresholds": {"session_volume_target": 2}}
    with pytest.raises(AssertionError):
        live.test_live_session_volume_telemetry(config, Collector())


def test_unimplemented_ipfix_check_explicitly_skips():
    import test_scale_flow as live
    with pytest.raises(pytest.skip.Exception, match="not implemented"):
        live.test_live_ipfix_export_accuracy()


def test_runner_keeps_successful_process_diagnostics(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "summary", "warning"))
    result = workload._run_workload(workload.Workload(
        "command", lambda args: workload.run_cmd(["mock"]), argparse.Namespace(),
    ))
    assert result.returncode == 0
    assert result.metadata["stdout"] == "summary"
    assert result.metadata["stderr"] == "warning"
    assert result.detection_status == "not_evaluated"


@pytest.mark.parametrize("return_value", [None, True, "0"])
def test_malformed_runner_return_is_failure(return_value):
    result = workload._run_workload(workload.Workload(
        "broken", lambda args: return_value, argparse.Namespace(),
    ))
    assert result.returncode == 1 and "integer exit code" in result.error
