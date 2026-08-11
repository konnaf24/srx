"""Detection rows 13-14: UTM antivirus and content filtering (EICAR).

Offline tests validate AV-event correlation and the EICAR delivery descriptor;
live tests fetch the EICAR test file over plain HTTP and assert an
AV_VIRUS_DETECTED event naming the EICAR test file.
"""

from __future__ import annotations

import time

import pytest

from generators.l7_client import EICAR, L7Client
from validation.assertions import assert_event_present, assert_field_value, field_contains
from validation.correlator import Correlator, Detection, FiveTuple, TelemetryEvent

DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
def test_eicar_constant_is_standard_test_string():
    assert "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in EICAR


def test_eicar_stimulus_descriptor():
    client = L7Client(DST)
    stim = client.deliver_eicar_http(send=False)
    assert stim.expected_event_type == "AV_VIRUS_DETECTED_MT"
    assert stim.payload_class == "EICAR"
    assert stim.metadata["expected_av_name"] == "EICAR-Test-File"


def test_eicar_delivery_requires_test_payload_in_response(monkeypatch):
    client = L7Client(DST)
    call = {}

    def fake_raw_http(
        dst_port,
        path="/",
        body=None,
        expected_response_body=None,
    ):
        call.update(
            dst_port=dst_port,
            path=path,
            body=body,
            expected_response_body=expected_response_body,
        )
        return "198.51.100.5", 40000

    monkeypatch.setattr(client, "_raw_http", fake_raw_http)

    client.deliver_eicar_http(send=True)

    assert call["path"] == "/eicar.com"
    assert call["expected_response_body"] == EICAR


@pytest.mark.parametrize(
    "status,accepted",
    [
        (403, True),
        (451, True),
        (404, False),
    ],
)
def test_eicar_http_accepts_security_blocks_but_not_missing_files(
    monkeypatch,
    status,
    accepted,
):
    class HttpSocket:
        def __init__(self):
            self.responses = [
                f"HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n".encode(),
                b"",
            ]

        def settimeout(self, _timeout):
            pass

        def connect(self, _destination):
            pass

        def getsockname(self):
            return "198.51.100.5", 40000

        def sendall(self, _request):
            pass

        def recv(self, _size):
            return self.responses.pop(0)

        def close(self):
            pass

    monkeypatch.setattr(
        "generators.l7_client.socket.socket",
        lambda *_args: HttpSocket(),
    )
    client = L7Client(DST)

    if accepted:
        assert client._raw_http(
            80,
            path="/eicar.com",
            expected_response_body=EICAR,
        ) == ("198.51.100.5", 40000)
    else:
        with pytest.raises(RuntimeError, match="neither contained"):
            client._raw_http(
                80,
                path="/eicar.com",
                expected_response_body=EICAR,
            )


def test_av_event_correlates_and_names_eicar():
    client = L7Client(DST)
    stim = client.deliver_eicar_http(send=False)
    ev = TelemetryEvent(
        "AV_VIRUS_DETECTED_MT",
        FiveTuple(stim.five_tuple.src_ip, DST, "TCP", stim.five_tuple.src_port, 80),
        stim.timestamp + 1,
        fields={"source-address": "x", "destination-address": DST, "virus-name": "EICAR-Test-File"},
    )
    corr = Correlator()
    verdict = corr.evaluate(stim, [ev], ground_truth=[stim.five_tuple])
    assert verdict.logged is Detection.YES
    assert_field_value(ev, "virus-name", "EICAR-Test-File")
    assert field_contains(ev, "virus-name", "eicar")


# ---------------------------------------------------------------------------
# Live tests
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
def test_live_antivirus_eicar(config, syslog_collector):
    targets = config["targets"]
    expected = config.get("signatures", {}).get("expected_av_name", "EICAR-Test-File")
    client = L7Client(targets["primary_host"])
    stim = client.deliver_eicar_http(dst_port=targets["allowed_tcp_port"], send=True)
    time.sleep(2)
    events = syslog_collector.query(five_tuple=stim.five_tuple)
    av = [e for e in events if e.event_type.startswith("AV_VIRUS")]
    assert av, "Expected an antivirus detection event for EICAR"
    assert any(field_contains(e, "virus-name", "eicar") or
               (e.fields.get("virus-name") == expected) for e in av)
