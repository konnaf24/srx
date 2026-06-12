"""wrk / iperf3 wrappers for scale generation (rows 15, 16, 17).

* :meth:`LoadGenerator.session_volume` - drive many concurrent HTTP sessions
  with ``wrk`` (row 15: session-count threshold).
* :meth:`LoadGenerator.throughput`     - drive a sustained throughput stream
  with ``iperf3`` (row 16: byte counters) and underpin flow/IPFIX export
  validation (row 17).

Both wrap system binaries via ``subprocess`` with explicit argument builders and
parse the tools' output into structured results. Missing binaries raise a clear
error via :func:`generators.require_binary`. The argument builders and parsers
are side-effect-free and unit-testable offline.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from generators import require_binary
from validation.correlator import FiveTuple, Stimulus


@dataclass
class WrkResult:
    """Parsed summary from a wrk run."""

    requests: int
    duration_s: float
    requests_per_sec: float
    raw: str


@dataclass
class Iperf3Result:
    """Parsed summary from an iperf3 run."""

    bytes_sent: int
    bits_per_second: float
    raw: str


class LoadGenerator:
    """Drive session-volume and throughput load against a target."""

    def __init__(self, dst_ip: str):
        self.dst_ip = dst_ip

    # -- row 15: session volume (wrk) -----------------------------------------
    @staticmethod
    def build_wrk_cmd(
        url: str, connections: int, threads: int, duration_s: int
    ) -> List[str]:
        """Build a wrk argument list."""
        binary = require_binary("wrk")
        return [
            binary,
            "-c", str(int(connections)),
            "-t", str(int(threads)),
            "-d", f"{int(duration_s)}s",
            "--latency",
            url,
        ]

    @staticmethod
    def parse_wrk_output(output: str) -> WrkResult:
        """Parse wrk stdout into a :class:`WrkResult`."""
        req = 0
        dur = 0.0
        rps = 0.0
        m = re.search(r"([\d]+)\s+requests in\s+([\d.]+)([a-z]+)", output)
        if m:
            req = int(m.group(1))
            val, unit = float(m.group(2)), m.group(3)
            dur = val * {"s": 1, "ms": 0.001, "m": 60}.get(unit, 1)
        m = re.search(r"Requests/sec:\s+([\d.]+)", output)
        if m:
            rps = float(m.group(1))
        return WrkResult(requests=req, duration_s=dur, requests_per_sec=rps, raw=output)

    def session_volume(
        self,
        url: str,
        connections: int = 10000,
        threads: int = 8,
        duration_s: int = 30,
        run: bool = False,
    ) -> Stimulus:
        """Drive high concurrent connection volume (validates session counters)."""
        ts = time.time()
        if run:
            cmd = self.build_wrk_cmd(url, connections, threads, duration_s)
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        return Stimulus(
            five_tuple=FiveTuple(None, self.dst_ip, "TCP", None, 80),
            timestamp=ts,
            expected_event_type="RT_FLOW_SESSION_CREATE",
            payload_class="session-volume",
            detection_target="Session volume",
            expected_fields=("source-address", "destination-address"),
            metadata={"connections": connections, "duration_s": duration_s},
        )

    # -- row 16/17: throughput (iperf3) ---------------------------------------
    @staticmethod
    def build_iperf3_cmd(
        server: str, duration_s: int, parallel: int = 1, port: int = 5201
    ) -> List[str]:
        """Build an iperf3 client argument list (JSON output)."""
        binary = require_binary("iperf3")
        return [
            binary,
            "-c", server,
            "-t", str(int(duration_s)),
            "-P", str(int(parallel)),
            "-p", str(int(port)),
            "--json",
        ]

    @staticmethod
    def parse_iperf3_output(output: str) -> Iperf3Result:
        """Parse iperf3 --json stdout into an :class:`Iperf3Result`."""
        data = json.loads(output)
        end = data.get("end", {})
        sum_sent = end.get("sum_sent", end.get("sum", {}))
        return Iperf3Result(
            bytes_sent=int(sum_sent.get("bytes", 0)),
            bits_per_second=float(sum_sent.get("bits_per_second", 0.0)),
            raw=output,
        )

    def throughput(
        self,
        server: Optional[str] = None,
        duration_s: int = 30,
        parallel: int = 4,
        port: int = 5201,
        run: bool = False,
    ) -> Stimulus:
        """Drive a sustained throughput stream (validates byte counters / J-Flow)."""
        server = server or self.dst_ip
        ts = time.time()
        if run:
            cmd = self.build_iperf3_cmd(server, duration_s, parallel, port)
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        return Stimulus(
            five_tuple=FiveTuple(None, server, "TCP", None, port),
            timestamp=ts,
            expected_event_type="RT_FLOW_SESSION_CLOSE",
            payload_class="throughput-stream",
            detection_target="Throughput",
            expected_fields=("source-address", "destination-address", "bytes-from-client"),
            metadata={"duration_s": duration_s, "parallel": parallel},
        )
