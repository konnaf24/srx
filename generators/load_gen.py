"""Bounded wrk / iperf3 wrappers with checked execution and actual measurements.

Builders validate before resolving binaries. Direct APIs validate even in
``run=False`` descriptor mode. Configure ceilings with ``WorkloadLimits``;
raising them is an explicit caller decision for an authorized isolated lab.
Execution success never establishes SRX detection or concurrent session count.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import time
from dataclasses import asdict, dataclass, fields
from typing import List, Optional
from urllib.parse import urlsplit

from generators import require_binary
from validation.correlator import FiveTuple, Stimulus


def bounded_int(name: str, value: int, maximum: int, minimum: int = 1) -> int:
    """Reject coercion, booleans, fractions, non-finite and out-of-range values."""
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


@dataclass(frozen=True)
class WorkloadLimits:
    """Per-workload ceilings; defaults preserve existing CLI and API defaults.

    Concurrent suites multiply per-workload load; these are not aggregate caps.
    Every configurable ceiling must itself be a finite positive integer.
    """

    max_packets: int = 10000
    max_rate_pps: int = 1000
    max_ports: int = 4096
    max_duration_s: int = 300
    max_connections: int = 10000
    max_threads: int = 64
    max_parallel: int = 32
    max_fragments: int = 64
    max_workloads: int = 32

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field.name} must be a finite positive integer")
        bounded_int("max_ports", self.max_ports, 65535)

    def wrk(self, connections: int, threads: int, duration_s: int) -> None:
        bounded_int("connections", connections, self.max_connections)
        bounded_int("threads", threads, min(self.max_threads, connections))
        bounded_int("duration_s", duration_s, self.max_duration_s)

    def iperf(self, duration_s: int, parallel: int, port: int) -> None:
        bounded_int("duration_s", duration_s, self.max_duration_s)
        bounded_int("parallel", parallel, self.max_parallel)
        bounded_int("port", port, 65535)

    def scan(self, max_ports: int) -> None:
        bounded_int("max_ports", max_ports, self.max_ports)

    def flood(self, flood_type: str, port: int, count: int, rate_pps: int) -> None:
        if flood_type not in {"syn", "icmp", "udp"}:
            raise ValueError("flood_type must be syn|icmp|udp")
        bounded_int("port", port, 65535, 0 if flood_type == "icmp" else 1)
        bounded_int("count", count, self.max_packets)
        bounded_int("rate_pps", rate_pps, self.max_rate_pps)
        # Integer ceiling avoids rounding pacing above the requested packet rate.
        interval_us = (1_000_000 + rate_pps - 1) // rate_pps
        if count * interval_us > self.max_duration_s * 1_000_000:
            raise ValueError("paced flood exceeds max_duration_s")


DEFAULT_LIMITS = WorkloadLimits()


def _nonnegative_number(name: str, value) -> float:
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be a finite nonnegative number")
    try:
        valid = math.isfinite(value) and value >= 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError(f"{name} must be a finite nonnegative number")
    return float(value)


@dataclass
class WrkResult:
    """Measured HTTP requests, not measured concurrent TCP sessions."""

    requests: int
    duration_s: float
    requests_per_sec: float
    raw: str
    socket_errors: int = 0
    non_success_responses: int = 0


@dataclass
class Iperf3Result:
    bytes_sent: int
    bits_per_second: float
    raw: str


class LoadGenerator:
    """Drive load; return a compatible Stimulus with execution metadata.

    ``metadata['result']`` contains parsed measurements and raw stdout after a
    successful run; ``stderr``, ``returncode`` and ``elapsed_s`` are retained.
    Nonzero exits and timeouts raise standard subprocess exceptions (including
    captured output); malformed summaries raise ValueError, never a zero result.
    """

    def __init__(self, dst_ip: str, *, limits: WorkloadLimits = DEFAULT_LIMITS):
        self.dst_ip = dst_ip
        self.limits = limits

    @staticmethod
    def build_wrk_cmd(
        url: str, connections: int, threads: int, duration_s: int,
        *, limits: WorkloadLimits = DEFAULT_LIMITS,
    ) -> List[str]:
        limits.wrk(connections, threads, duration_s)
        LoadGenerator._http_port(url)
        binary = require_binary("wrk")
        return [binary, "-c", str(connections), "-t", str(threads),
                "-d", f"{duration_s}s", "--latency", url]

    @staticmethod
    def _http_port(url: str) -> int:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("url must be an absolute HTTP(S) URL")
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return bounded_int("URL port", port, 65535)

    @staticmethod
    def parse_wrk_output(output: str) -> WrkResult:
        summary = re.search(r"^\s*(\d+)\s+requests in\s+(\d+(?:\.\d+)?)(ms|s|m)\b", output, re.MULTILINE)
        rate = re.search(r"^\s*Requests/sec:\s+(\d+(?:\.\d+)?)\s*(?:\n|$)", output, re.MULTILINE)
        if not summary or not rate:
            raise ValueError("wrk output missing a valid request/duration/rate summary")
        duration = float(summary[2]) * {"s": 1, "ms": 0.001, "m": 60}[summary[3]]
        rps = _nonnegative_number("requests_per_sec", float(rate[1]))
        if not math.isfinite(duration) or duration <= 0:
            raise ValueError("wrk duration must be finite and positive")
        errors = re.search(r"Socket errors: connect (\d+), read (\d+), write (\d+), timeout (\d+)", output)
        non_success = re.search(r"Non-2xx or 3xx responses:\s+(\d+)", output)
        if ("Socket errors:" in output and errors is None) or (
            "Non-2xx or 3xx responses:" in output and non_success is None
        ):
            raise ValueError("wrk output contains malformed error counters")
        return WrkResult(
            int(summary[1]), duration, rps, output,
            sum(map(int, errors.groups())) if errors else 0,
            int(non_success[1]) if non_success else 0,
        )

    @staticmethod
    def _execute(cmd: List[str], duration_s: int, parser) -> dict:
        started = time.monotonic()
        completed = subprocess.run(
            cmd, capture_output=True, text=True, check=False, timeout=duration_s + 30,
        )
        completed.check_returncode()
        result = parser(completed.stdout)
        return {"execution_status": "succeeded", "detection_status": "not_evaluated",
                "returncode": completed.returncode, "elapsed_s": time.monotonic() - started,
                "stderr": completed.stderr, "result": asdict(result)}

    def session_volume(
        self, url: str, connections: int = 10000, threads: int = 8,
        duration_s: int = 30, run: bool = False,
    ) -> Stimulus:
        self.limits.wrk(connections, threads, duration_s)
        port = self._http_port(url)
        ts = time.time()
        metadata = {"connections": connections, "threads": threads, "duration_s": duration_s,
                    "url": url, "execution_status": "not_run", "detection_status": "not_evaluated"}
        if run:
            cmd = self.build_wrk_cmd(url, connections, threads, duration_s, limits=self.limits)
            metadata.update(self._execute(cmd, duration_s, self.parse_wrk_output))
        return Stimulus(
            five_tuple=FiveTuple(None, self.dst_ip, "TCP", None, port), timestamp=ts,
            expected_event_type="RT_FLOW_SESSION_CREATE", payload_class="session-volume",
            detection_target="Session volume", expected_fields=("source-address", "destination-address"),
            metadata=metadata,
        )

    @staticmethod
    def build_iperf3_cmd(
        server: str, duration_s: int, parallel: int = 1, port: int = 5201,
        *, limits: WorkloadLimits = DEFAULT_LIMITS,
    ) -> List[str]:
        limits.iperf(duration_s, parallel, port)
        binary = require_binary("iperf3")
        return [binary, "-c", server, "-t", str(duration_s), "-P", str(parallel),
                "-p", str(port), "--json"]

    @staticmethod
    def parse_iperf3_output(output: str) -> Iperf3Result:
        data = json.loads(output)
        if not isinstance(data, dict) or "error" in data:
            raise ValueError("iperf3 returned an error or invalid summary")
        end = data.get("end")
        if not isinstance(end, dict):
            raise ValueError("iperf3 output missing end summary")
        summary = end.get("sum_sent", end.get("sum"))
        if not isinstance(summary, dict) or not {"bytes", "bits_per_second"} <= summary.keys():
            raise ValueError("iperf3 output missing byte/rate measurements")
        byte_count = summary["bytes"]
        if type(byte_count) is not int or byte_count < 0:
            raise ValueError("iperf3 bytes must be a nonnegative integer")
        bps = _nonnegative_number("bits_per_second", summary["bits_per_second"])
        return Iperf3Result(byte_count, bps, output)

    def throughput(
        self, server: Optional[str] = None, duration_s: int = 30, parallel: int = 4,
        port: int = 5201, run: bool = False,
    ) -> Stimulus:
        self.limits.iperf(duration_s, parallel, port)
        server = server or self.dst_ip
        ts = time.time()
        metadata = {"duration_s": duration_s, "parallel": parallel,
                    "execution_status": "not_run", "detection_status": "not_evaluated"}
        if run:
            cmd = self.build_iperf3_cmd(server, duration_s, parallel, port, limits=self.limits)
            metadata.update(self._execute(cmd, duration_s, self.parse_iperf3_output))
        return Stimulus(
            five_tuple=FiveTuple(None, server, "TCP", None, port), timestamp=ts,
            expected_event_type="RT_FLOW_SESSION_CLOSE", payload_class="throughput-stream",
            detection_target="Throughput",
            expected_fields=("source-address", "destination-address", "bytes-from-client"),
            metadata=metadata,
        )
