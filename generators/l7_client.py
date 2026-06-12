"""Scriptable L7 client generators (rows 1, 8, 13, 14).

Drives deterministic, byte-exact L7 stimuli using ``requests`` and raw sockets:

* raw HTTP (App-ID generic, content filtering),
* DNS / FTP / SSH handshakes (App-ID generic),
* EICAR antivirus test-file delivery (UTM/AV),
* GTUBE spam test-string delivery (content/IDP).

These are preferred over a browser for signature/content tests because they
deliver the exact bytes the inspection engine must match, over plain HTTP, with
a single known 5-tuple (see ``docs/04-workload-layer-rationale.md``).

All payloads are SAFE, standard test artifacts — never live malware.
"""

from __future__ import annotations

import socket
import time
from typing import Optional

from validation.correlator import FiveTuple, Stimulus

# Standard, harmless test artifacts.
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
GTUBE = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"


def _local_addr_for(dst_ip: str, dst_port: int) -> tuple:
    """Discover the local (src_ip, src_port) the OS would use to reach a target.

    Connects a UDP socket (no packets sent) to learn the chosen source address,
    so the returned :class:`Stimulus` carries the real 5-tuple for correlation.
    Falls back to (None, None) if it cannot be determined offline.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dst_ip, dst_port))
        src_ip, src_port = s.getsockname()
        s.close()
        return src_ip, src_port
    except OSError:
        return None, None


class L7Client:
    """Issue scriptable L7 requests and return stimulus descriptors."""

    def __init__(self, dst_ip: str):
        self.dst_ip = dst_ip

    # -- row 1 / 8: HTTP session + App-ID -------------------------------------
    def http_get(self, url: str, dst_port: int = 80, send: bool = True) -> Stimulus:
        """Perform a raw HTTP GET (App-ID generic + RT_FLOW session).

        Uses a single socket so the 5-tuple is deterministic.
        """
        src_ip, src_port = _local_addr_for(self.dst_ip, dst_port)
        ts = time.time()
        if send:
            src_ip, src_port = self._raw_http(dst_port, path=url)
        return Stimulus(
            five_tuple=FiveTuple(src_ip, self.dst_ip, "TCP", src_port, dst_port),
            timestamp=ts,
            expected_event_type="APPTRACK_SESSION_CREATE",
            payload_class="http-get",
            detection_target="App-ID generic",
            expected_fields=("source-address", "destination-address", "application"),
            metadata={"expected_app": "HTTP"},
        )

    def _raw_http(self, dst_port: int, path: str = "/", body: Optional[str] = None) -> tuple:
        """Open a TCP socket, send a minimal HTTP request, return the 5-tuple ends."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((self.dst_ip, dst_port))
        src_ip, src_port = s.getsockname()
        if body is None:
            req = f"GET {path} HTTP/1.1\r\nHost: {self.dst_ip}\r\nConnection: close\r\n\r\n"
        else:
            req = (
                f"POST {path} HTTP/1.1\r\nHost: {self.dst_ip}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n{body}"
            )
        s.sendall(req.encode())
        try:
            s.recv(4096)
        except socket.timeout:
            pass
        finally:
            s.close()
        return src_ip, src_port

    # -- row 14: EICAR over HTTP (UTM/AV) -------------------------------------
    def deliver_eicar_http(self, dst_port: int = 80, path: str = "/eicar.com", send: bool = True) -> Stimulus:
        """Fetch/deliver the EICAR test file over plain HTTP (AV_VIRUS_DETECTED).

        Expected telemetry: an antivirus event naming the EICAR test file.
        """
        src_ip, src_port = _local_addr_for(self.dst_ip, dst_port)
        ts = time.time()
        if send:
            src_ip, src_port = self._raw_http(dst_port, path=path)
        return Stimulus(
            five_tuple=FiveTuple(src_ip, self.dst_ip, "TCP", src_port, dst_port),
            timestamp=ts,
            expected_event_type="AV_VIRUS_DETECTED_MT",
            payload_class="EICAR",
            detection_target="Antivirus/UTM",
            expected_fields=("source-address", "destination-address", "virus-name"),
            metadata={"expected_av_name": "EICAR-Test-File"},
        )

    # -- row 7/13: GTUBE / content (IDP/content filtering) --------------------
    def deliver_gtube_http(self, dst_port: int = 80, path: str = "/submit", send: bool = True) -> Stimulus:
        """POST the GTUBE spam test string over HTTP (IDP/content match)."""
        src_ip, src_port = _local_addr_for(self.dst_ip, dst_port)
        ts = time.time()
        if send:
            src_ip, src_port = self._raw_http(dst_port, path=path, body=GTUBE)
        return Stimulus(
            five_tuple=FiveTuple(src_ip, self.dst_ip, "TCP", src_port, dst_port),
            timestamp=ts,
            expected_event_type="RT_IDP_ATTACK_LOG_EVENT",
            payload_class="GTUBE",
            detection_target="IDP signature match",
            expected_fields=("source-address", "destination-address", "attack-name"),
            metadata={"signature": "GTUBE"},
        )

    # -- row 8: DNS / FTP / SSH App-ID ----------------------------------------
    def dns_query(self, dns_server: str, qname: str = "example.com", send: bool = True) -> Stimulus:
        """Send a single UDP DNS query (App-ID = DNS)."""
        src_ip, src_port = _local_addr_for(dns_server, 53)
        ts = time.time()
        if send:
            src_ip, src_port = self._raw_dns(dns_server, qname)
        return Stimulus(
            five_tuple=FiveTuple(src_ip, dns_server, "UDP", src_port, 53),
            timestamp=ts,
            expected_event_type="APPTRACK_SESSION_CREATE",
            payload_class="dns-query",
            detection_target="App-ID generic",
            expected_fields=("source-address", "destination-address", "application"),
            metadata={"expected_app": "DNS"},
        )

    def _raw_dns(self, dns_server: str, qname: str) -> tuple:
        """Build and send a minimal DNS A query over UDP."""
        # Minimal DNS query packet (header + question).
        txn = b"\xab\xcd"
        header = txn + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        question = b""
        for label in qname.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00\x00\x01\x00\x01"  # type A, class IN
        packet = header + question

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((dns_server, 53))
        src_ip, src_port = s.getsockname()
        s.send(packet)
        try:
            s.recv(512)
        except socket.timeout:
            pass
        finally:
            s.close()
        return src_ip, src_port

    def tcp_handshake(self, dst_port: int, app: str, send: bool = True) -> Stimulus:
        """Open a TCP connection to an FTP(21)/SSH(22) port for App-ID.

        Reads the service banner (which AppTrack uses to classify the app).
        """
        src_ip, src_port = _local_addr_for(self.dst_ip, dst_port)
        ts = time.time()
        if send:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.dst_ip, dst_port))
            src_ip, src_port = s.getsockname()
            try:
                s.recv(256)  # grab banner
            except socket.timeout:
                pass
            finally:
                s.close()
        return Stimulus(
            five_tuple=FiveTuple(src_ip, self.dst_ip, "TCP", src_port, dst_port),
            timestamp=ts,
            expected_event_type="APPTRACK_SESSION_CREATE",
            payload_class=f"{app.lower()}-handshake",
            detection_target="App-ID generic",
            expected_fields=("source-address", "destination-address", "application"),
            metadata={"expected_app": app.upper()},
        )
