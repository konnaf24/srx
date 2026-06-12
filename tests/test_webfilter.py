"""Detection rows 10-11: URL / web filtering and SSL-proxy (Playwright).

Offline tests validate the webfilter event correlation and field assertions;
live tests navigate to categorized/blocked URLs and varied-SNI TLS endpoints and
assert WEBFILTER telemetry plus a captured block-page screenshot.
"""

from __future__ import annotations

import time

import pytest

from validation.assertions import assert_event_present, assert_field_value
from validation.correlator import Correlator, Detection, FiveTuple, Stimulus, TelemetryEvent

DST = "203.0.113.10"


# ---------------------------------------------------------------------------
# Offline logic tests
# ---------------------------------------------------------------------------
def test_webfilter_block_event_fields():
    ev = TelemetryEvent(
        "WEBFILTER_URL_BLOCKED",
        FiveTuple(None, None, "TCP", None, 443),
        time.time(),
        fields={"url": "https://blocked.lab.example/", "category": "Malware", "reason": "BY-CATEGORY"},
    )
    assert_event_present([ev], "WEBFILTER_URL_BLOCKED")
    assert_field_value(ev, "category", "Malware")


def test_webfilter_correlation_by_dst_port():
    """Browser fans out connections, so we correlate on protocol/dst-port only."""
    stim = Stimulus(
        five_tuple=FiveTuple(None, None, "TCP", None, 443),
        timestamp=time.time(),
        expected_event_type="WEBFILTER_URL_BLOCKED",
        detection_target="URL/web filtering",
        expected_fields=("url", "category"),
    )
    ev = TelemetryEvent(
        "WEBFILTER_URL_BLOCKED",
        FiveTuple("198.51.100.5", "203.0.113.10", "TCP", 51234, 443),
        stim.timestamp + 1,
        fields={"url": "https://blocked.lab.example/", "category": "Malware"},
    )
    corr = Correlator()
    verdict = corr.evaluate(stim, [ev])  # no ground truth channel for browser
    assert verdict.logged is Detection.YES
    assert verdict.fields_complete is Detection.YES


# ---------------------------------------------------------------------------
# Live tests
# ---------------------------------------------------------------------------
@pytest.mark.requires_srx
def test_live_url_filtering_blockpage(config, syslog_collector):
    from generators.browser_gen import BrowserGenerator

    targets = config["targets"]
    gen = BrowserGenerator()
    stim = gen.visit_filtered_url(targets["filtered_url"], navigate=True)
    time.sleep(3)
    events = syslog_collector.query(event_type="WEBFILTER_URL_BLOCKED")
    assert_event_present(events, "WEBFILTER_URL_BLOCKED")
    # The block-page screenshot is captured as evidence at stim.metadata["screenshot"].
    assert "screenshot" in stim.metadata


@pytest.mark.requires_srx
def test_live_ssl_proxy(config, syslog_collector):
    from generators.browser_gen import BrowserGenerator

    targets = config["targets"]
    gen = BrowserGenerator()
    gen.tls_handshakes(targets["webapp_url"], targets.get("tls_sni_hosts", []), navigate=True)
    time.sleep(3)
    events = syslog_collector.snapshot()
    assert any(e.event_type.startswith("WEBFILTER") for e in events)
