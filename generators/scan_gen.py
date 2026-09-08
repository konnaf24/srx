"""nmap / hping3 wrappers for scan and flood generation (rows 3, 6).

Wraps the ``nmap`` and ``hping3`` system binaries via ``subprocess`` with
explicit argument builders and light output parsing. Floods and scans are
**bounded and rate-limited** by the caller (driven from
``config.attack_limits``) so the suite stays safe in an authorized lab.

If a required binary is missing, :func:`generators.require_binary` raises a
clear, actionable error. Builders that only construct argument lists are
side-effect-free and unit-testable offline.
"""

from __future__ import annotations

import subprocess
import time
from typing import List

from generators import require_binary
from generators.load_gen import DEFAULT_LIMITS, WorkloadLimits
from validation.correlator import FiveTuple, Stimulus

# nmap scan-type flag for each supported scan.
_NMAP_SCAN_FLAGS = {"syn": "-sS", "xmas": "-sX", "fin": "-sF", "null": "-sN", "ack": "-sA"}


class ScanGenerator:
    """Generate TCP scans (nmap) and floods (hping3) against a target."""

    def __init__(self, src_ip: str, dst_ip: str, *, limits: WorkloadLimits = DEFAULT_LIMITS):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.limits = limits

    # -- nmap scans (row 3) ---------------------------------------------------
    @staticmethod
    def build_nmap_cmd(
        dst_ip: str, scan_type: str, max_ports: int = 1024,
        *, limits: WorkloadLimits = DEFAULT_LIMITS,
    ) -> List[str]:
        """Build the nmap argument list for a given scan type.

        ``scan_type`` is one of: syn, xmas, fin, null, ack.
        """
        limits.scan(max_ports)
        scan_type = scan_type.lower()
        if scan_type not in _NMAP_SCAN_FLAGS:
            raise ValueError(
                f"Unsupported scan_type {scan_type!r}; choose from {sorted(_NMAP_SCAN_FLAGS)}"
            )
        binary = require_binary("nmap")
        return [
            binary,
            _NMAP_SCAN_FLAGS[scan_type],
            "-Pn",                     # skip host discovery (target is behind SRX)
            "-n",                      # no DNS
            "-p", f"1-{int(max_ports)}",
            "--max-retries", "1",
            "--max-rate", str(limits.max_rate_pps),
            "--host-timeout", f"{limits.max_duration_s}s",
            dst_ip,
        ]

    def tcp_scan(self, scan_type: str = "syn", max_ports: int = 1024, run: bool = False) -> Stimulus:
        """Run (or just describe) a TCP port scan.

        Expected telemetry: SRX screen scan event(s) + screen counter increment.
        """
        self.limits.scan(max_ports)
        scan_type = scan_type.lower()
        if scan_type not in _NMAP_SCAN_FLAGS:
            raise ValueError(f"Unsupported scan_type {scan_type!r}")
        ts = time.time()
        metadata = {"scan_type": scan_type, "max_ports": max_ports,
                    "execution_status": "not_run", "detection_status": "not_evaluated"}
        if run:
            cmd = self.build_nmap_cmd(self.dst_ip, scan_type, max_ports, limits=self.limits)
            metadata.update(self._execute(cmd))
        return Stimulus(
            # dst_port is intentionally None: a scan sweeps many ports.
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", None, None),
            timestamp=ts,
            expected_event_type="RT_SCREEN_TCP",
            payload_class=f"nmap-{scan_type}-scan",
            detection_target="TCP scan",
            expected_fields=("source-address", "destination-address", "attack-name"),
            metadata=metadata,
        )

    # -- hping3 floods (row 6) ------------------------------------------------
    @staticmethod
    def build_hping3_flood_cmd(
        dst_ip: str, flood_type: str, dst_port: int, count: int, rate_pps: int,
        *, limits: WorkloadLimits = DEFAULT_LIMITS,
    ) -> List[str]:
        """Build an hping3 argument list for a bounded flood.

        ``flood_type`` is one of: syn, icmp, udp. The flood is capped at
        ``count`` packets and paced to ``rate_pps`` packets/sec via ``-i uX``.
        """
        flood_type = flood_type.lower()
        limits.flood(flood_type, dst_port, count, rate_pps)
        binary = require_binary("hping3")
        # Round up so pacing never exceeds the requested rate.
        interval_us = (1_000_000 + rate_pps - 1) // rate_pps
        cmd = [binary, "-c", str(int(count)), "-i", f"u{interval_us}"]
        ft = flood_type.lower()
        if ft == "syn":
            cmd += ["-S", "-p", str(int(dst_port))]
        elif ft == "icmp":
            cmd += ["--icmp"]
        elif ft == "udp":
            cmd += ["--udp", "-p", str(int(dst_port))]
        else:
            raise ValueError(f"Unsupported flood_type {flood_type!r}; choose syn|icmp|udp")
        cmd += [dst_ip]
        return cmd

    def flood(
        self,
        flood_type: str = "syn",
        dst_port: int = 80,
        count: int = 2000,
        rate_pps: int = 500,
        run: bool = False,
    ) -> Stimulus:
        """Run (or describe) a bounded SYN/ICMP/UDP flood.

        Expected telemetry: SRX screen flood threshold event.
        """
        flood_type = flood_type.lower()
        self.limits.flood(flood_type, dst_port, count, rate_pps)
        ts = time.time()
        proto = {"syn": "TCP", "icmp": "ICMP", "udp": "UDP"}[flood_type]
        metadata = {"flood_type": flood_type, "count": count, "rate_pps": rate_pps,
                    "execution_status": "not_run", "detection_status": "not_evaluated"}
        if run:
            cmd = self.build_hping3_flood_cmd(
                self.dst_ip, flood_type, dst_port, count, rate_pps, limits=self.limits,
            )
            metadata.update(self._execute(cmd))
        return Stimulus(
            five_tuple=FiveTuple(
                self.src_ip, self.dst_ip, proto, None,
                dst_port if proto != "ICMP" else None,
            ),
            timestamp=ts,
            expected_event_type="RT_SCREEN_TCP" if proto == "TCP" else f"RT_SCREEN_{proto}",
            payload_class=f"hping3-{flood_type}-flood",
            detection_target="Flood (SYN/ICMP/UDP)",
            expected_fields=("source-address", "destination-address", "attack-name"),
            metadata=metadata,
        )

    def _execute(self, cmd: List[str]) -> dict:
        started = time.monotonic()
        completed = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            timeout=self.limits.max_duration_s + 30,
        )
        completed.check_returncode()
        return {"execution_status": "succeeded", "detection_status": "not_evaluated",
                "returncode": completed.returncode, "elapsed_s": time.monotonic() - started,
                "stdout": completed.stdout, "stderr": completed.stderr}
