"""Independent egress ground-truth packet capture.

Wraps ``tshark`` (preferred) or ``tcpdump`` to record traffic at a configured
egress/transit interface. Presence supports observation at that capture point,
not a security action; absence cannot establish non-arrival at the SRX
(see ``docs/05-correlation-model.md``).

The capture runs as a subprocess for the duration of a test, writes a pcap, and
(optionally) a parser extracts 5-tuples from the pcap for ground-truth matching.
5-tuple extraction uses ``tshark -T fields`` so it does not require scapy, but a
scapy-based reader is also provided as a fallback.

If neither ``tshark`` nor ``tcpdump`` is on ``PATH``, a clear error is raised.
"""

from __future__ import annotations

import os
import ipaddress
import shutil
import subprocess
import time
from typing import List, Optional

from validation.correlator import FiveTuple

_PROTO_NUM = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP"}


def _require_binary(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(
            f"Required capture binary '{name}' was not found on PATH. "
            f"Install it (e.g. Wireshark/tshark or tcpdump) to capture egress "
            f"ground truth."
        )
    return path


class PcapCapture:
    """Start/stop an egress capture and extract 5-tuples for ground truth.

    Parameters
    ----------
    interface:
        Capture interface on the egress/transit path.
    output_path:
        Where to write the pcap.
    tool:
        ``"tshark"`` or ``"tcpdump"``.
    bpf_filter:
        Optional BPF capture filter to limit captured traffic (e.g. a target
        host) and keep the pcap small.
    snaplen:
        Bytes captured per packet.
    """

    def __init__(
        self,
        interface: str,
        output_path: str,
        tool: str = "tshark",
        bpf_filter: Optional[str] = None,
        snaplen: int = 256,
    ):
        self.interface = interface
        self.output_path = output_path
        self.tool = tool.lower()
        self.bpf_filter = bpf_filter
        self.snaplen = int(snaplen)
        self._proc: Optional[subprocess.Popen] = None

    # -- argument builders ----------------------------------------------------
    def _build_cmd(self) -> List[str]:
        if self.tool == "tshark":
            binary = _require_binary("tshark")
            cmd = [binary, "-i", self.interface, "-w", self.output_path, "-s", str(self.snaplen)]
            if self.bpf_filter:
                cmd += ["-f", self.bpf_filter]
            return cmd
        if self.tool == "tcpdump":
            binary = _require_binary("tcpdump")
            cmd = [binary, "-i", self.interface, "-w", self.output_path, "-s", str(self.snaplen), "-U"]
            if self.bpf_filter:
                cmd += [self.bpf_filter]
            return cmd
        raise ValueError(f"Unsupported capture tool: {self.tool!r}")

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> "PcapCapture":
        """Launch the capture subprocess."""
        out_dir = os.path.dirname(self.output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        cmd = self._build_cmd()
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        # Give the sniffer a moment to attach before traffic is generated.
        time.sleep(1.0)
        if self._proc.poll() is not None:
            err = self._proc.stderr.read().decode("utf-8", "replace") if self._proc.stderr else ""
            raise RuntimeError(f"Capture failed to start: {err.strip()}")
        return self

    def stop(self) -> None:
        """Terminate the capture subprocess and flush the pcap."""
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self._proc.kill()
            finally:
                self._proc = None

    def __enter__(self) -> "PcapCapture":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- ground-truth extraction ---------------------------------------------
    def extract_five_tuples(self) -> List[FiveTuple]:
        """Parse the written pcap into a list of :class:`FiveTuple`.

        Uses ``tshark -r <pcap> -T fields`` to avoid a hard scapy dependency.
        Falls back to scapy if tshark is unavailable but scapy is installed.
        """
        if shutil.which("tshark"):
            return self._extract_with_tshark()
        return self._extract_with_scapy()

    def _extract_with_tshark(self) -> List[FiveTuple]:
        binary = _require_binary("tshark")
        fields = [
            "ip.src", "ip.dst", "ip.proto",
            "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        ]
        cmd = [binary, "-r", self.output_path, "-T", "fields"]
        for f in fields:
            cmd += ["-e", f]
        # One outer IPv4 tuple per packet; do not let nested IP field lists
        # shift the CSV columns. Non-IP and IPv6-only rows are rejected below.
        cmd += ["-E", "separator=,", "-E", "occurrence=f"]
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout

        tuples: List[FiveTuple] = []
        for line in out.splitlines():
            cols = line.split(",")
            if len(cols) != 7:
                continue
            ip_src, ip_dst, ip_proto, tsp, tdp, usp, udp = (c.strip() for c in cols)
            try:
                ipaddress.IPv4Address(ip_src)
                ipaddress.IPv4Address(ip_dst)
                if not 0 <= int(ip_proto) <= 255:
                    continue
                ip_proto = str(int(ip_proto))
                # Select ports from the IP protocol, not an unrelated inner
                # transport dissected elsewhere in a tunnel/ICMP error.
                sport, dport = (tsp, tdp) if ip_proto == "6" else (
                    (usp, udp) if ip_proto == "17" else ("", "")
                )
                sport = int(sport) if sport else None
                dport = int(dport) if dport else None
                if any(p is not None and not 0 <= p <= 65535 for p in (sport, dport)):
                    continue
            except ValueError:
                continue
            tuples.append(
                FiveTuple(
                    src_ip=ip_src,
                    dst_ip=ip_dst,
                    protocol=_PROTO_NUM.get(ip_proto, ip_proto),
                    src_port=sport,
                    dst_port=dport,
                )
            )
        return tuples

    def _extract_with_scapy(self) -> List[FiveTuple]:
        try:
            from scapy.all import IP, TCP, UDP, rdpcap  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise FileNotFoundError(
                "Neither tshark nor scapy is available to read the pcap. "
                "Install Wireshark/tshark or scapy."
            ) from exc

        tuples: List[FiveTuple] = []
        for pkt in rdpcap(self.output_path):
            if IP not in pkt:
                continue
            ip = pkt[IP]
            sport = dport = None
            proto = str(ip.proto)
            if TCP in pkt:
                proto, sport, dport = "TCP", pkt[TCP].sport, pkt[TCP].dport
            elif UDP in pkt:
                proto, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
            else:
                proto = _PROTO_NUM.get(str(ip.proto), str(ip.proto))
            tuples.append(
                FiveTuple(src_ip=ip.src, dst_ip=ip.dst, protocol=proto,
                          src_port=sport, dst_port=dport)
            )
        return tuples
