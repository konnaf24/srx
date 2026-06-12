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
