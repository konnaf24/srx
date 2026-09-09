"""Detection rows 1-2: session create / close / deny (RT_FLOW).

Contains BOTH:
* offline unit tests of the correlation/assertion logic (run in CI, no SRX), and
* live tests marked ``requires_srx`` that drive real stimulus and assert against
  collected telemetry.
"""

from __future__ import annotations

import time

import pytest

from generators.packet_gen import PacketGenerator
from validation.assertions import (
    assert_event_absent,
    assert_event_present,
    assert_fields_complete,
)
from validation.correlator import (
    Correlator,
    Detection,
    FiveTuple,
    Stimulus,
    TelemetryEvent,
)


SRC = "198.51.100.5"
DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests (no hardware) — these MUST pass in CI.
# ---------------------------------------------------------------------------
def _flow_create_event(ts: float, sport: int) -> TelemetryEvent:
    return TelemetryEvent(
        event_type="RT_FLOW_SESSION_CREATE",
        five_tuple=FiveTuple(SRC, DST, "TCP", sport, 80),
        timestamp=ts,
        fields={
            "source-address": SRC,
            "destination-address": DST,
            "policy-name": "transit-permit",
            "application": "HTTP",
        },
    )


def test_session_create_correlates_and_passes():
    stim = PacketGenerator(SRC, DST).tcp_connection(80, send=False)
    # Force a known src port so we can build a matching event.
    stim = Stimulus(
        five_tuple=FiveTuple(SRC, DST, "TCP", 44321, 80),
        timestamp=time.time(),
        expected_event_type="RT_FLOW_SESSION_CREATE",
        detection_target="Session create",
        expected_fields=("source-address", "destination-address", "policy-name", "application"),
    )
    event = _flow_create_event(stim.timestamp + 0.5, 44321)
    corr = Correlator(window_s=10, skew_s=2)

    verdict = corr.evaluate(stim, [event], ground_truth=[stim.five_tuple])
    assert verdict.passed
    assert verdict.detected is Detection.YES
    assert verdict.logged is Detection.YES
    assert verdict.fields_complete is Detection.YES


def test_session_create_missing_field_flagged():
    stim = Stimulus(
        five_tuple=FiveTuple(SRC, DST, "TCP", 44321, 80),
        timestamp=time.time(),
        expected_event_type="RT_FLOW_SESSION_CREATE",
        expected_fields=("source-address", "destination-address", "policy-name", "application"),
    )
    event = _flow_create_event(stim.timestamp + 0.5, 44321)
    del event.fields["policy-name"]  # incomplete log
    corr = Correlator()
    verdict = corr.evaluate(stim, [event], ground_truth=[stim.five_tuple])
    assert verdict.logged is Detection.YES
    assert verdict.fields_complete is Detection.NO
    assert "policy-name" in verdict.missing_fields
    assert not verdict.passed


def test_session_deny_has_no_create():
    """Row 2: a denied session must produce DENY and NO create event."""
    deny_ft = FiveTuple(SRC, DST, "TCP", 50001, 9)
    events = [
        TelemetryEvent(
            "RT_FLOW_SESSION_DENY",
            deny_ft,
            time.time(),
            fields={"source-address": SRC, "destination-address": DST, "destination-port": "9"},
        )
    ]
    assert_event_present(events, "RT_FLOW_SESSION_DENY", deny_ft)
    assert_event_absent(events, "RT_FLOW_SESSION_CREATE", deny_ft)


def test_inconclusive_when_no_ground_truth_and_no_log():
    """No egress evidence + no log => INCONCLUSIVE, not a false detection gap."""
    stim = Stimulus(
        five_tuple=FiveTuple(SRC, DST, "TCP", 44321, 80),
        timestamp=time.time(),
        expected_event_type="RT_FLOW_SESSION_CREATE",
    )
    corr = Correlator()
    verdict = corr.evaluate(stim, [], ground_truth=[])  # ground truth says not seen
    assert verdict.logged is Detection.INCONCLUSIVE
    assert verdict.detected is Detection.INCONCLUSIVE
    assert "Absence does not establish non-arrival" in verdict.note


def test_syslog_parser_extracts_rt_flow_five_tuple():
    """The sd-syslog parser must map structured fields into a 5-tuple + type."""
    from collectors.syslog_collector import parse_syslog_line

    line = (
        '<14>1 2024-05-01T12:00:00.000Z srx RT_FLOW - RT_FLOW_SESSION_CREATE '
        '[junos@2636 source-address="198.51.100.5" source-port="44321" '
        'destination-address="203.0.113.10" destination-port="80" '
        'protocol-id="6" application="HTTP" policy-name="transit-permit"]'
    )
    event = parse_syslog_line(line, recv_time=1000.0)
    assert event is not None
    assert event.event_type == "RT_FLOW_SESSION_CREATE"
    assert event.five_tuple.src_ip == "198.51.100.5"
    assert event.five_tuple.dst_ip == "203.0.113.10"
    assert event.five_tuple.protocol == "TCP"  # protocol-id 6 -> TCP
    assert event.five_tuple.src_port == 44321
    assert event.five_tuple.dst_port == 80
    assert event.fields["policy-name"] == "transit-permit"


def test_syslog_collector_query_filters_by_type_and_window():
    """The in-memory buffer must support type/5-tuple/time-window queries."""
    from collectors.syslog_collector import SyslogCollector

    coll = SyslogCollector()
    ft = FiveTuple(SRC, DST, "TCP", 44321, 80)
    coll.add_event(TelemetryEvent("RT_FLOW_SESSION_CREATE", ft, 100.0,
                                   fields={"source-address": SRC}))
    coll.add_event(TelemetryEvent("RT_FLOW_SESSION_CLOSE", ft, 105.0))
    assert len(coll.query(event_type="RT_FLOW_SESSION_CREATE")) == 1
    assert len(coll.query(five_tuple=ft)) == 2
    assert len(coll.query(start_time=104.0)) == 1
    assert len(coll.query(event_type="RT_IDP_ATTACK_LOG_EVENT")) == 0


# ---------------------------------------------------------------------------
# Live tests (require SRX + collectors + privileges).
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
def test_live_session_create(config, syslog_collector, correlator):
    """Open a real TCP session and assert RT_FLOW_SESSION_CREATE is logged."""
    targets = config["targets"]
    gen = PacketGenerator(config.get("src_ip", "0.0.0.0"), targets["primary_host"])
    stim = gen.tcp_connection(targets["allowed_tcp_port"], send=True)

    time.sleep(2)  # allow telemetry to arrive
    events = syslog_collector.query(
        event_type="RT_FLOW_SESSION_CREATE", five_tuple=stim.five_tuple
    )
    event = assert_event_present(events, "RT_FLOW_SESSION_CREATE", stim.five_tuple)
    assert_fields_complete(event, stim.expected_fields)


@pytest.mark.requires_srx
def test_live_session_deny(config, syslog_collector):
    """Send to a denied port and assert DENY with no CREATE."""
    targets = config["targets"]
    gen = PacketGenerator(config.get("src_ip", "0.0.0.0"), targets["primary_host"])
    stim = gen.tcp_to_denied_port(targets["denied_tcp_port"], send=True)

    time.sleep(2)
    events = syslog_collector.snapshot()
    assert_event_present(events, "RT_FLOW_SESSION_DENY", stim.five_tuple)
    assert_event_absent(events, "RT_FLOW_SESSION_CREATE", stim.five_tuple)
