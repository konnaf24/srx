"""Collector regressions using in-memory events and mocked subprocesses only."""

from types import SimpleNamespace

import pytest

from collectors import pcap_capture
from collectors.pcap_capture import PcapCapture
from collectors.syslog_collector import SyslogCollector, parse_syslog_line
from validation.correlator import Correlator, FiveTuple, Stimulus, TelemetryEvent

TYPE = "RT_FLOW_SESSION_CREATE"
FT = FiveTuple("198.51.100.5", "203.0.113.10", "TCP", 44321, 80)
HEADER = f"<14>1 2024-05-01T12:00:00Z srx RT_FLOW - {TYPE} "


def test_rfc5424_msgid_wins_over_long_uppercase_policy_and_message():
    line = HEADER + (
        '[junos@2636 source-address="198.51.100.5" '
        'policy-name="VERY_LONG_UPPERCASE_SECURITY_POLICY_NOT_AN_EVENT"] '
        'RT_IDP_ATTACK_LOG_EVENT source-address="203.0.113.99"'
    )
    event = parse_syslog_line(line, recv_time=123)
    assert event.event_type == TYPE
    assert event.timestamp == 123
    assert event.five_tuple.src_ip == FT.src_ip  # MSG must not overwrite SD
    assert event.fields["policy-name"] == "VERY_LONG_UPPERCASE_SECURITY_POLICY_NOT_AN_EVENT"
    assert event.raw == line


def test_rfc5424_escaped_quote_backslash_and_bracket_decode_once():
    line = HEADER + (
        r'[junos@2636 policy-name="ALLOW_\"QUOTED\"_PATH\\END\]" '
        r'unknown="keep\q" literal="\\n" source-address="198.51.100.5" '
        r'source-port="0" protocol-id="6"]'
    )
    event = parse_syslog_line(line, recv_time=1)
    assert event.fields["policy-name"] == 'ALLOW_"QUOTED"_PATH\\END]'
    assert event.fields["unknown"] == r"keep\q"
    assert event.fields["literal"] == r"\n"  # no unicode_escape/control conversion
    assert event.five_tuple.src_port == 0
    assert event.five_tuple.protocol == "TCP"


def test_rfc5424_multiple_sd_elements_and_duplicate_keys_use_last_value():
    line = HEADER + (
        '[junos@2636 source-address="198.51.100.5" policy-name="old"]'
        '[extra@2636 destination-address="203.0.113.10" policy-name="new"]'
    )
    event = parse_syslog_line(line, recv_time=1)
    assert event.five_tuple.src_ip == FT.src_ip
    assert event.five_tuple.dst_ip == FT.dst_ip
    assert event.fields["policy-name"] == "new"


def test_rfc5424_nil_sd_is_parseable_but_not_correlatable_without_identity():
    event = parse_syslog_line(HEADER + '- source-address="198.51.100.5"', recv_time=100)
    assert event.event_type == TYPE
    assert event.fields == {}
    assert Correlator().correlate(Stimulus(FT, 100, TYPE), [event]) is None


@pytest.mark.parametrize("line", [
    "", "not syslog", 'policy-name="RT_FLOW_SESSION_CREATE"',
    '<14>1 incomplete RT_FLOW_SESSION_CREATE',
    HEADER.replace(TYPE, "-") + '[junos@2636 policy-name="RT_FLOW_SESSION_CREATE"]',
    HEADER + '[junos@2636 policy-name="unterminated]',
    HEADER + '[junos@2636 policy-name="unescaped]bracket"]',
    HEADER + '[junos@2636 source-address="198.51.100.5"]garbage',
    HEADER + '[junos@2636 source-address="198.51.100.5"][broken',
])
def test_missing_tag_or_malformed_structured_line_rejected(line):
    assert parse_syslog_line(line, recv_time=1) is None


@pytest.mark.parametrize("prefix", [
    "", "May  1 12:00:00 srx RT_FLOW: ", "<14>May  1 12:00:00 srx RT_FLOW: ",
])
def test_legacy_first_known_tag_before_fields_not_longest_value(prefix):
    line = prefix + TYPE + ': source-address=198.51.100.5 protocol-id=6 ' + (
        r'policy-name="LONG_UPPERCASE_POLICY_\"NAME\"_NOT_EVENT"'
    )
    event = parse_syslog_line(line, recv_time=1)
    assert event.event_type == TYPE
    assert event.five_tuple.src_ip == FT.src_ip
    assert event.fields["policy-name"] == 'LONG_UPPERCASE_POLICY_"NAME"_NOT_EVENT'


def test_legacy_field_value_cannot_supply_event_tag():
    assert parse_syslog_line('May 1 srx message policy=RT_FLOW_SESSION_CREATE') is None


def test_collector_ring_buffer_drops_oldest_and_counts_evictions_only():
    collector = SyslogCollector(max_events=2)
    events = [TelemetryEvent(TYPE, FT, ts) for ts in range(4)]
    for ev in events:
        collector.add_event(ev)
    assert collector.snapshot() == events[-2:]
    assert collector.dropped_events == 2
    snapshot = collector.snapshot()
    snapshot.clear()
    assert collector.snapshot() == events[-2:]
    collector.clear()
    assert collector.snapshot() == []
    assert collector.dropped_events == 2
    collector.add_event(events[0])
    assert collector.dropped_events == 2


@pytest.mark.parametrize("cap", [0, -1])
def test_collector_rejects_nonpositive_buffer_capacity(cap):
    with pytest.raises(ValueError, match="max_events must be positive"):
        SyslogCollector(max_events=cap)


def test_collector_query_uses_observed_identity_and_inclusive_boundaries():
    collector = SyslogCollector()
    good = [TelemetryEvent(TYPE, FT, ts) for ts in (98, 100, 112)]
    for ev in good + [
        TelemetryEvent(TYPE, FiveTuple(), 100),
        TelemetryEvent(TYPE, FiveTuple(dst_ip="203.0.113.99"), 100),
        TelemetryEvent(TYPE, FT, 97.999),
        TelemetryEvent(TYPE, FT, 112.001),
        TelemetryEvent("RT_FLOW_SESSION_DENY", FT, 100),
    ]:
        collector.add_event(ev)
    assert collector.query(TYPE, FT, 98, 112) == good


def test_ingest_is_offline_and_uses_receive_time(monkeypatch):
    monkeypatch.setattr("collectors.syslog_collector.time.time", lambda: 100.0)
    collector = SyslogCollector()
    collector._ingest((HEADER + '[junos@2636 source-address="198.51.100.5"]\ninvalid\n').encode())
    assert len(collector.snapshot()) == 1
    assert collector.snapshot()[0].timestamp == 100.0


def mock_tshark(monkeypatch, stdout):
    calls = []
    monkeypatch.setattr(pcap_capture.shutil, "which", lambda name: "/fake/tshark")

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout=stdout)

    monkeypatch.setattr(pcap_capture.subprocess, "run", run)
    return calls


@pytest.mark.parametrize("row", [
    ",,,,,,", "", ",,6,1234,80,,", "198.51.100.5,,6,1234,80,,",
    "not-an-ip,203.0.113.10,6,1234,80,,",
    "198.51.100.5,999.0.0.1,6,1234,80,,",
    "198.51.100.5,203.0.113.10,,1234,80,,",
    "198.51.100.5,203.0.113.10,999,1234,80,,",
    "198.51.100.5,203.0.113.10,6,invalid,80,,",
    "198.51.100.5,203.0.113.10,6,65536,80,,",
    "198.51.100.5,203.0.113.10,6,-1,80,,",
    "198.51.100.5,203.0.113.10,6,1234,80,,,extra",
    "2001:db8::1,2001:db8::2,6,1234,80,,",
])
def test_tshark_rejects_empty_non_ip_or_malformed_rows(monkeypatch, row):
    calls = mock_tshark(monkeypatch, row + "\n")
    assert PcapCapture("unused", "/fake/offline.pcap").extract_five_tuples() == []
    assert len(calls) == 1  # mocked; no capture or real tshark execution


def test_tshark_keeps_valid_ipv4_rows_and_ignores_unrelated_transport(monkeypatch):
    calls = mock_tshark(monkeypatch, "\n".join([
        "198.51.100.5,203.0.113.10,6,44321,80,,",
        ",,,,,,",  # ARP/non-IP packet cannot become a wildcard witness
        "198.51.100.5,203.0.113.10,17,,,0,53",
        "198.51.100.5,203.0.113.10,1,44321,80,,",  # quoted TCP in ICMP
        "198.51.100.5,203.0.113.10,6,,,,",  # noninitial fragment
        "198.51.100.5,203.0.113.10,47,,,,",
    ]))
    tuples = PcapCapture("unused", "/fake/offline.pcap").extract_five_tuples()
    assert tuples == [
        FT, FiveTuple(FT.src_ip, FT.dst_ip, "UDP", 0, 53),
        FiveTuple(FT.src_ip, FT.dst_ip, "ICMP"),
        FiveTuple(FT.src_ip, FT.dst_ip, "TCP"),
        FiveTuple(FT.src_ip, FT.dst_ip, "GRE"),
    ]
    cmd, kwargs = calls[0]
    assert cmd[:5] == ["/fake/tshark", "-r", "/fake/offline.pcap", "-T", "fields"]
    assert "occurrence=f" in cmd
    assert "-i" not in cmd
    assert kwargs == {"capture_output": True, "text": True, "check": True}


def test_tshark_failure_is_not_silently_converted_to_empty_evidence(monkeypatch):
    monkeypatch.setattr(pcap_capture.shutil, "which", lambda name: "/fake/tshark")

    def fail(cmd, **kwargs):
        raise pcap_capture.subprocess.CalledProcessError(2, cmd)

    monkeypatch.setattr(pcap_capture.subprocess, "run", fail)
    with pytest.raises(pcap_capture.subprocess.CalledProcessError):
        PcapCapture("unused", "/fake/offline.pcap").extract_five_tuples()
