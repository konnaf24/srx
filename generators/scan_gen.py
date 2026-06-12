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
from validation.correlator import FiveTuple, Stimulus

# nmap scan-type flag for each supported scan.
_NMAP_SCAN_FLAGS = {"syn": "-sS", "xmas": "-sX", "fin": "-sF", "null": "-sN", "ack": "-sA"}


class ScanGenerator:
    """Generate TCP scans (nmap) and floods (hping3) against a target."""

    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    # -- nmap scans (row 3) ---------------------------------------------------
    @staticmethod
    def build_nmap_cmd(dst_ip: str, scan_type: str, max_ports: int = 1024) -> List[str]:
        """Build the nmap argument list for a given scan type.

        ``scan_type`` is one of: syn, xmas, fin, null, ack.
        """
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
            dst_ip,
        ]

    def tcp_scan(self, scan_type: str = "syn", max_ports: int = 1024, run: bool = False) -> Stimulus:
        """Run (or just describe) a TCP port scan.

        Expected telemetry: SRX screen scan event(s) + screen counter increment.
        """
        ts = time.time()
        if run:
            cmd = self.build_nmap_cmd(self.dst_ip, scan_type, max_ports)
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        return Stimulus(
            # dst_port is intentionally None: a scan sweeps many ports.
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", None, None),
            timestamp=ts,
            expected_event_type="RT_SCREEN_TCP",
            payload_class=f"nmap-{scan_type}-scan",
            detection_target="TCP scan",
            expected_fields=("source-address", "destination-address", "attack-name"),
            metadata={"scan_type": scan_type, "max_ports": max_ports},
        )

    # -- hping3 floods (row 6) ------------------------------------------------
    @staticmethod
    def build_hping3_flood_cmd(
        dst_ip: str, flood_type: str, dst_port: int, count: int, rate_pps: int
    ) -> List[str]:
        """Build an hping3 argument list for a bounded flood.

        ``flood_type`` is one of: syn, icmp, udp. The flood is capped at
        ``count`` packets and paced to ``rate_pps`` packets/sec via ``-i uX``.
        """
        binary = require_binary("hping3")
        # Inter-packet interval in microseconds derived from the rate cap.
        interval_us = max(1, int(1_000_000 / max(1, rate_pps)))
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
        ts = time.time()
        proto = {"syn": "TCP", "icmp": "ICMP", "udp": "UDP"}[flood_type.lower()]
        if run:
            cmd = self.build_hping3_flood_cmd(self.dst_ip, flood_type, dst_port, count, rate_pps)
            subprocess.run(cmd, capture_output=True, text=True, check=False)
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
            metadata={"flood_type": flood_type, "count": count, "rate_pps": rate_pps},
        )
