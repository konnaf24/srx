"""scapy-based L3/L4 packet crafting (detection rows 1, 2, 4, 5).

Produces stimuli that a normalizing OS stack / browser could never emit:
malformed TCP flag combinations, bad checksums, tiny TTLs, and overlapping /
oversized IP fragments. These exercise the SRX **screen** anomaly and
fragmentation detectors and IDP anomaly subtypes.

Each builder returns a :class:`~validation.correlator.Stimulus` describing what
was sent so the correlator can match the resulting telemetry. ``send=True``
actually transmits via scapy (requires root/raw-socket privileges); with
``send=False`` the packet is built and the descriptor returned without sending,
which keeps the module importable and unit-testable offline.

scapy is imported lazily so this module can be imported in environments where
scapy is not installed (the offline test suite does not call the senders).
"""

from __future__ import annotations

import random
import time
from typing import List, Optional

from validation.correlator import FiveTuple, Stimulus


def _scapy():
    """Import scapy lazily, raising a clear error if unavailable."""
    try:
        from scapy import all as scapy_all  # type: ignore

        return scapy_all
    except Exception as exc:  # pragma: no cover - only without scapy
        raise ImportError(
            "scapy is required for packet generation but is not installed. "
            "Install it with `pip install scapy` (see requirements.txt). "
            "Sending crafted packets also requires root/raw-socket privileges."
        ) from exc


def _ephemeral_port() -> int:
    return random.randint(20000, 60000)


class PacketGenerator:
    """Craft and optionally send L3/L4 stimulus packets via scapy.

    Parameters
    ----------
    src_ip:
        Source address to stamp on crafted packets (the generator host's
        address on the transit path).
    dst_ip:
        Destination/target address (must route through the SRX).
    """

    def __init__(self, src_ip: str, dst_ip: str):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    # -- helpers --------------------------------------------------------------
    def _send(self, pkt) -> None:
        scapy_all = _scapy()
        scapy_all.send(pkt, verbose=False)

    # -- row 1: legitimate session create -------------------------------------
    def tcp_connection(self, dst_port: int, send: bool = False) -> Stimulus:
        """A well-formed TCP SYN to open a session (RT_FLOW_SESSION_CREATE).

        For a full session create/close the test harness typically uses the L7
        client; this provides a pure-scapy SYN when raw control is preferred.
        """
        scapy_all = _scapy() if send else None
        sport = _ephemeral_port()
        ts = time.time()
        if send:
            pkt = scapy_all.IP(src=self.src_ip, dst=self.dst_ip) / scapy_all.TCP(
                sport=sport, dport=dst_port, flags="S"
            )
            self._send(pkt)
        return Stimulus(
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", sport, dst_port),
            timestamp=ts,
            expected_event_type="RT_FLOW_SESSION_CREATE",
            payload_class="tcp-syn",
            detection_target="Session create",
            expected_fields=("source-address", "destination-address", "policy-name", "application"),
        )

    # -- row 2: session deny --------------------------------------------------
    def tcp_to_denied_port(self, denied_port: int, send: bool = False) -> Stimulus:
        """A TCP SYN to a policy-denied port (expects RT_FLOW_SESSION_DENY).

        The correlator must additionally assert that NO ``RT_FLOW_SESSION_CREATE``
        accompanies this 5-tuple.
        """
        scapy_all = _scapy() if send else None
        sport = _ephemeral_port()
        ts = time.time()
        if send:
            pkt = scapy_all.IP(src=self.src_ip, dst=self.dst_ip) / scapy_all.TCP(
                sport=sport, dport=denied_port, flags="S"
            )
            self._send(pkt)
        return Stimulus(
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", sport, denied_port),
            timestamp=ts,
            expected_event_type="RT_FLOW_SESSION_DENY",
            payload_class="tcp-syn-denied",
            detection_target="Session deny",
            expected_fields=("source-address", "destination-address", "destination-port"),
        )

    # -- row 4: malformed packets --------------------------------------------
    def malformed_flags(self, dst_port: int = 80, send: bool = False) -> Stimulus:
        """TCP with an illegal flag combination (SYN+FIN) — anomaly stimulus."""
        scapy_all = _scapy() if send else None
        sport = _ephemeral_port()
        ts = time.time()
        if send:
            pkt = scapy_all.IP(src=self.src_ip, dst=self.dst_ip) / scapy_all.TCP(
                sport=sport, dport=dst_port, flags="FS"  # SYN+FIN, illegal
            )
            self._send(pkt)
        return Stimulus(
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", sport, dst_port),
            timestamp=ts,
            expected_event_type="RT_SCREEN_TCP",
            payload_class="malformed-flags-synfin",
            detection_target="Malformed packets",
            expected_fields=("source-address", "destination-address", "attack-name"),
        )

    def bad_checksum(self, dst_port: int = 80, send: bool = False) -> Stimulus:
        """TCP segment with a deliberately wrong checksum."""
        scapy_all = _scapy() if send else None
        sport = _ephemeral_port()
        ts = time.time()
        if send:
            pkt = scapy_all.IP(src=self.src_ip, dst=self.dst_ip) / scapy_all.TCP(
                sport=sport, dport=dst_port, flags="S", chksum=0xDEAD
            )
            self._send(pkt)
        return Stimulus(
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", sport, dst_port),
            timestamp=ts,
            expected_event_type="RT_SCREEN_TCP",
            payload_class="bad-checksum",
            detection_target="Malformed packets",
            expected_fields=("source-address", "destination-address", "attack-name"),
        )

    def tiny_ttl(self, dst_port: int = 80, ttl: int = 1, send: bool = False) -> Stimulus:
        """A packet with an abnormally small TTL (IP anomaly)."""
        scapy_all = _scapy() if send else None
        sport = _ephemeral_port()
        ts = time.time()
        if send:
            pkt = scapy_all.IP(src=self.src_ip, dst=self.dst_ip, ttl=ttl) / scapy_all.TCP(
                sport=sport, dport=dst_port, flags="S"
            )
            self._send(pkt)
        return Stimulus(
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", sport, dst_port),
            timestamp=ts,
            expected_event_type="RT_SCREEN_IP",
            payload_class=f"tiny-ttl-{ttl}",
            detection_target="Malformed packets",
            expected_fields=("source-address", "destination-address", "attack-name"),
        )

    # -- row 5: fragmentation -------------------------------------------------
    def overlapping_fragments(
        self, dst_port: int = 80, frag_count: int = 8, send: bool = False
    ) -> Stimulus:
        """Overlapping / oversized IP fragments (teardrop-style frag attack).

        Builds ``frag_count`` fragments with overlapping offsets so the SRX
        screen fragmentation detector should raise a frag-attack event.
        """
        sport = _ephemeral_port()
        ts = time.time()
        if send:
            scapy_all = _scapy()
            payload = b"X" * 64
            frags: List = []
            for i in range(frag_count):
                # Deliberately overlap offsets (each advances by less than the
                # previous payload length) to trigger teardrop-style detection.
                offset = max(0, i * 6 - 2)
                more = 1 if i < frag_count - 1 else 0
                pkt = scapy_all.IP(
                    src=self.src_ip, dst=self.dst_ip, flags="MF" if more else 0, frag=offset
                ) / scapy_all.TCP(sport=sport, dport=dst_port) / scapy_all.Raw(load=payload)
                frags.append(pkt)
            scapy_all.send(frags, verbose=False)
        return Stimulus(
            five_tuple=FiveTuple(self.src_ip, self.dst_ip, "TCP", sport, dst_port),
            timestamp=ts,
            expected_event_type="RT_SCREEN_IP",
            payload_class="overlapping-fragments",
            detection_target="Fragmentation",
            expected_fields=("source-address", "destination-address", "attack-name"),
        )
