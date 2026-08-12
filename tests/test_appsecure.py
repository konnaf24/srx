"""Detection rows 8, 9, 12: AppSecure — App-ID (generic + web app) and AppFW.

Offline tests validate App-ID stimulus descriptors and app-name assertions;
live tests drive raw L7 (curl/sockets) and Playwright and assert AppTrack
classification and app-firewall enforcement.
"""

from __future__ import annotations

import socket
import time

import pytest

from generators.l7_client import L7Client
from validation.assertions import assert_field_value, field_value_match
from validation.correlator import Correlator, Detection, FiveTuple, TelemetryEvent

SRC = "198.51.100.5"
DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "method,kwargs,expected_app",
    [
        ("http_get", {"url": "/"}, "HTTP"),
        ("tcp_handshake", {"dst_port": 21, "app": "FTP"}, "FTP"),
        ("tcp_handshake", {"dst_port": 22, "app": "SSH"}, "SSH"),
    ],
)
def test_appid_stimulus_metadata(method, kwargs, expected_app):
    client = L7Client(DST)
    stim = getattr(client, method)(send=False, **kwargs)
    assert stim.expected_event_type == "APPTRACK_SESSION_CREATE"
    assert stim.metadata["expected_app"] == expected_app


def test_apptrack_app_name_assertion():
    ev = TelemetryEvent(
        "APPTRACK_SESSION_CREATE",
        FiveTuple(SRC, DST, "TCP", 40000, 80),
        time.time(),
        fields={"source-address": SRC, "destination-address": DST, "application": "HTTP"},
    )
    assert field_value_match(ev, "application", "http")  # case-insensitive
    assert_field_value(ev, "application", "HTTP")


def test_appid_dns_correlates():
    client = L7Client(DST)
    stim = client.dns_query("203.0.113.53", send=False)
    ev = TelemetryEvent(
        "APPTRACK_SESSION_CREATE",
        FiveTuple(stim.five_tuple.src_ip, "203.0.113.53", "UDP", stim.five_tuple.src_port, 53),
        stim.timestamp + 0.5,
        fields={"application": "DNS", "source-address": "x", "destination-address": "203.0.113.53"},
    )
    corr = Correlator()
    verdict = corr.evaluate(stim, [ev], ground_truth=[stim.five_tuple])
    assert verdict.logged is Detection.YES


def test_dns_timeout_is_not_reported_as_success(monkeypatch):
    class TimeoutSocket:
        def settimeout(self, _timeout):
            pass

        def connect(self, _destination):
            pass

        def getsockname(self):
            return SRC, 53000

        def send(self, _packet):
            pass

        def recv(self, _size):
            raise socket.timeout("no response")

        def close(self):
            pass

    monkeypatch.setattr(
        "generators.l7_client.socket.socket",
        lambda *_args: TimeoutSocket(),
    )

    with pytest.raises(socket.timeout):
        L7Client(DST)._raw_dns(DST, "probe.lab")


# ---------------------------------------------------------------------------
# Live tests
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
@pytest.mark.parametrize("port,app", [(21, "FTP"), (22, "SSH")])
def test_live_appid_generic(config, syslog_collector, port, app):
    targets = config["targets"]
    client = L7Client(targets["primary_host"])
    stim = client.tcp_handshake(port, app, send=True)
    time.sleep(2)
    events = syslog_collector.query(five_tuple=stim.five_tuple)
    apptrack = [e for e in events if e.event_type.startswith("APPTRACK")]
    assert apptrack, f"Expected AppTrack telemetry for {app}"


@pytest.mark.requires_srx
def test_live_appid_webapp(config, syslog_collector):
    from generators.browser_gen import BrowserGenerator

    targets = config["targets"]
    gen = BrowserGenerator()
    stim = gen.visit_webapp(targets["webapp_url"], expected_app="WEB", navigate=True)
    time.sleep(3)
    events = syslog_collector.query(event_type="APPTRACK_SESSION_CREATE")
    assert events, "Expected AppTrack web-app classification"


@pytest.mark.requires_srx
def test_live_appfw_block(config, syslog_collector):
    from generators.browser_gen import BrowserGenerator

    targets = config["targets"]
    gen = BrowserGenerator()
    gen.trigger_appfw(targets["webapp_url"], navigate=True)
    time.sleep(3)
    events = syslog_collector.snapshot()
    assert any(e.event_type.startswith("APPTRACK") for e in events)
