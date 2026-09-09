"""Structured Junos ``sd-syslog`` collector.

A threaded UDP/TCP listener that receives the security log stream emitted by an
SRX configured with::

    set security log mode stream
    set security log format sd-syslog

It parses each structured line into a :class:`~validation.correlator.TelemetryEvent`,
timestamps it, and stores it in a thread-safe buffer that can be queried by
event type / 5-tuple within a time window.

The **parser is pure Python** and is exercised by the offline unit tests; only
``start()``/``stop()`` touch real sockets.

Junos structured security logs look roughly like::

    <14>1 2024-05-01T12:00:00.000Z srx RT_FLOW - RT_FLOW_SESSION_CREATE [junos@2636.1.1.1.2.36
      source-address="198.51.100.5" source-port="44321"
      destination-address="203.0.113.10" destination-port="80"
      protocol-id="6" application="HTTP" policy-name="transit-permit" ...]

This module extracts the event tag (``RT_FLOW_SESSION_CREATE``), the structured
``key="value"`` pairs, and maps the address/port/protocol fields into a
:class:`FiveTuple`.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from collections import deque
from typing import Dict, List, Optional

from validation.correlator import FiveTuple, TelemetryEvent

# Matches key="value" or key=value structured-data pairs.
_KEY = r'[A-Za-z0-9_\-\.]+'
_QUOTED = r'"(?:\\.|[^"\\])*"'
_SD_QUOTED = r'"(?:\\.|[^"\\\]])*"'
_KV_RE = re.compile(rf'({_KEY})=({_QUOTED})|({_KEY})=([^\s\]"]+)')
_SD_RE = re.compile(rf'\[[^\s\]"=]+(?:\s+{_KEY}={_SD_QUOTED})*\]')
_HEADER_RE = re.compile(
    r'^<\d{1,3}>[1-9]\d*\s+\S+\s+\S+\s+\S+\s+\S+\s+'
    r'(?P<msgid>\S+)\s+(?P<body>.*)$'
)

# Matches the Junos event tag (e.g. RT_FLOW_SESSION_CREATE, RT_IDP_ATTACK_LOG_EVENT,
# APPTRACK_SESSION_CREATE, WEBFILTER_URL_BLOCKED, AV_VIRUS_DETECTED_MT).
_TAG_RE = re.compile(r'\b([A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+)\b')
_LEGACY_TAG_RE = re.compile(
    r'(?<!\S)((?:RT_[A-Z0-9]+_|APPTRACK_|WEBFILTER_|AV_)[A-Z0-9_]+)(?=[:\s]|$)'
)

# Maps Junos sd-syslog field names to 5-tuple components. Multiple aliases are
# accepted because field names vary slightly across features/Junos versions.
_SRC_IP_KEYS = ("source-address", "src-ip", "nat-source-address")
_DST_IP_KEYS = ("destination-address", "dst-ip", "nat-destination-address")
_SRC_PORT_KEYS = ("source-port", "src-port")
_DST_PORT_KEYS = ("destination-port", "dst-port")
_PROTO_KEYS = ("protocol-id", "protocol", "ip-protocol")

# Numeric IP-protocol -> name, for protocol-id fields.
_PROTO_NUM = {"1": "ICMP", "6": "TCP", "17": "UDP", "47": "GRE", "50": "ESP"}


def _first(fields: Dict[str, str], keys) -> Optional[str]:
    for k in keys:
        if k in fields and fields[k] != "":
            return fields[k]
    return None


def _to_int(val: Optional[str]) -> Optional[int]:
    try:
        return int(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def parse_syslog_line(line: str, recv_time: Optional[float] = None) -> Optional[TelemetryEvent]:
    """Parse a single structured Junos sd-syslog line into a TelemetryEvent.

    RFC5424 MSGID is authoritative; structured fields are read only from SD
    elements, not the free-text message. RFC5424 escapes for quotes, backslashes
    and closing brackets are decoded; unknown escapes are preserved literally.
    Legacy lines use the first known event-family tag before structured data or
    key/value fields, never an uppercase field value. Malformed structured
    headers/data and absent or unrecognizable tags return ``None``.
    ``recv_time`` (epoch seconds) defaults to "now"; it is used as the event
    timestamp so correlation does not depend on parsing the textual syslog
    timestamp (clock skew is handled by the correlator window).
    """
    if recv_time is None:
        recv_time = time.time()

    line = line.strip()
    if not line:
        return None

    header = _HEADER_RE.match(line)
    if header is not None:
        event_type = header.group("msgid")
        if _TAG_RE.fullmatch(event_type) is None:
            return None
        body = header.group("body")
        chunks = []
        pos = 0
        if body == "-" or body.startswith("- "):
            field_text = ""
        else:
            while pos < len(body) and body[pos] == "[":
                sd = _SD_RE.match(body, pos)
                if sd is None:
                    return None
                chunks.append(sd.group())
                pos = sd.end()
            if not chunks or (pos < len(body) and body[pos] != " "):
                return None
            field_text = " ".join(chunks)
    else:
        # Do not reinterpret a broken RFC5424 record as a legacy record.
        if re.match(r'^<\d+>\d+\s', line):
            return None
        preamble = line.split("[", 1)[0].split("=", 1)[0]
        tag = _LEGACY_TAG_RE.search(preamble)
        if tag is None:
            return None
        event_type = tag.group(1)
        field_text = line[tag.end():]

    fields: Dict[str, str] = {}
    for m in _KV_RE.finditer(field_text):
        if m.group(1) is not None:
            fields[m.group(1)] = re.sub(r'\\(["\\\]])', r'\1', m.group(2)[1:-1])
        else:
            fields[m.group(3)] = m.group(4)

    proto_raw = _first(fields, _PROTO_KEYS)
    protocol = _PROTO_NUM.get(proto_raw, proto_raw.upper() if isinstance(proto_raw, str) else None)

    ft = FiveTuple(
        src_ip=_first(fields, _SRC_IP_KEYS),
        dst_ip=_first(fields, _DST_IP_KEYS),
        protocol=protocol,
        src_port=_to_int(_first(fields, _SRC_PORT_KEYS)),
        dst_port=_to_int(_first(fields, _DST_PORT_KEYS)),
    )

    return TelemetryEvent(
        event_type=event_type,
        five_tuple=ft,
        timestamp=recv_time,
        fields=fields,
        raw=line,
    )


class SyslogCollector:
    """Threaded UDP/TCP listener that buffers parsed Junos security events.

    Parameters
    ----------
    bind_addr, bind_port:
        Listen address/port (SRX log stream destination).
    protocol:
        ``"udp"`` or ``"tcp"``.
    max_events:
        Ring-buffer cap; oldest events are dropped beyond this.
    """

    def __init__(
        self,
        bind_addr: str = "0.0.0.0",
        bind_port: int = 5514,
        protocol: str = "udp",
        max_events: int = 100000,
    ):
        self.bind_addr = bind_addr
        self.bind_port = int(bind_port)
        self.protocol = protocol.lower()
        self.max_events = int(max_events)
        if self.max_events <= 0:
            raise ValueError("max_events must be positive")

        self._events = deque(maxlen=self.max_events)
        self._dropped_events = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        """Open the socket and begin receiving in a background thread."""
        if self.protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif self.protocol == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            raise ValueError(f"Unsupported syslog protocol: {self.protocol!r}")

        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_addr, self.bind_port))
        self._sock.settimeout(0.5)
        if self.protocol == "tcp":
            self._sock.listen(8)

        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="syslog-collector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the listener thread and close the socket."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> "SyslogCollector":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- receive loop ---------------------------------------------------------
    def _run(self) -> None:
        if self.protocol == "udp":
            self._run_udp()
        else:
            self._run_tcp()

    def _run_udp(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, _ = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self._ingest(data)

    def _run_tcp(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(0.5)
                buf = b""
                while not self._stop.is_set():
                    try:
                        chunk = conn.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    # TCP syslog is newline-delimited (RFC 6587 non-transparent).
                    while b"\n" in buf:
                        raw_line, buf = buf.split(b"\n", 1)
                        self._ingest(raw_line)

    def _ingest(self, data: bytes) -> None:
        recv_time = time.time()
        for raw_line in data.decode("utf-8", errors="replace").splitlines():
            event = parse_syslog_line(raw_line, recv_time=recv_time)
            if event is not None:
                self.add_event(event)

    # -- buffer access --------------------------------------------------------
    def add_event(self, event: TelemetryEvent) -> None:
        """Append a parsed event (used by the receive loop and by tests)."""
        with self._lock:
            if len(self._events) == self._events.maxlen:
                self._dropped_events += 1
            self._events.append(event)

    @property
    def dropped_events(self) -> int:
        """Lifetime count of events evicted by the buffer cap (not clear())."""
        with self._lock:
            return self._dropped_events

    def clear(self) -> None:
        with self._lock:
            self._events.clear()

    def snapshot(self) -> List[TelemetryEvent]:
        """Return a copy of all buffered events."""
        with self._lock:
            return list(self._events)

    def query(
        self,
        event_type: Optional[str] = None,
        five_tuple: Optional[FiveTuple] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
    ) -> List[TelemetryEvent]:
        """Return buffered events filtered by type / 5-tuple / time window."""
        from validation.correlator import observation_matches

        with self._lock:
            events = list(self._events)

        out = []
        for ev in events:
            if event_type is not None and ev.event_type != event_type:
                continue
            if five_tuple is not None and not observation_matches(five_tuple, ev.five_tuple):
                continue
            if start_time is not None and ev.timestamp < start_time:
                continue
            if end_time is not None and ev.timestamp > end_time:
                continue
            out.append(ev)
        return out
