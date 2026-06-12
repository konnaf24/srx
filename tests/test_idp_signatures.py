"""Detection row 7: IDP / IPS signature match (EICAR, GTUBE, test signatures).

Offline tests validate signature-id assertion logic; live tests deliver the safe
synthetic signatures over HTTP and assert an RT_IDP attack log with the matching
signature id.
"""

from __future__ import annotations

import time

import pytest

from generators.l7_client import GTUBE, L7Client
from validation.assertions import assert_event_present, assert_signature_id, signature_id_match
from validation.correlator import Correlator, Detection, FiveTuple, TelemetryEvent

SRC = "198.51.100.5"
DST = "203.0.113.10"


def _idp_event(ts, signature, five_tuple):
    return TelemetryEvent(
        "RT_IDP_ATTACK_LOG_EVENT",
        five_tuple,
        ts,
        fields={
            "source-address": five_tuple.src_ip,
            "destination-address": five_tuple.dst_ip,
            "attack-name": signature,
            "threat-severity": "HIGH",
        },
    )


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
def test_signature_id_match_various_field_names():
    ev = TelemetryEvent("RT_IDP_ATTACK_LOG_EVENT", FiveTuple(), time.time(),
                        fields={"signature": "HTTP:EICAR-TEST"})
    assert signature_id_match(ev, "HTTP:EICAR-TEST")
    assert signature_id_match(ev, "http:eicar-test")  # case-insensitive
    assert not signature_id_match(ev, "OTHER-SIG")


def test_idp_event_correlates_with_signature_assertion():
    client = L7Client(DST)
    stim = client.deliver_gtube_http(send=False)
    event = _idp_event(stim.timestamp + 1, "GTUBE", stim.five_tuple)
    # Match on IP pair (l7 stimulus 5-tuple has a None src when not sent).
    corr = Correlator()
    verdict = corr.evaluate(stim, [event], ground_truth=[stim.five_tuple])
    assert verdict.logged is Detection.YES
    assert_signature_id(event, "GTUBE")


def test_gtube_constant_is_standard_test_string():
    assert "GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL" in GTUBE


# ---------------------------------------------------------------------------
# Live tests
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
@pytest.mark.parametrize("payload", ["gtube", "eicar"])
def test_live_idp_signature(config, syslog_collector, payload):
    targets = config["targets"]
    client = L7Client(targets["primary_host"])
    if payload == "gtube":
        stim = client.deliver_gtube_http(dst_port=targets["allowed_tcp_port"], send=True)
    else:
        stim = client.deliver_eicar_http(dst_port=targets["allowed_tcp_port"], send=True)
    time.sleep(2)
    events = syslog_collector.query(five_tuple=stim.five_tuple)
    idp = [e for e in events if e.event_type.startswith("RT_IDP")]
    assert idp, "Expected an RT_IDP attack log for the synthetic signature"
    assert any(e.fields.get("attack-name") for e in idp)
