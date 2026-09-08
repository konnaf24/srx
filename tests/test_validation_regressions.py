"""Offline regressions for correlation identity, timing and evidence semantics."""

from dataclasses import replace

import pytest

from validation.assertions import field_complete, find_events
from validation.correlator import (
    Correlator, Detection, FiveTuple, Stimulus, TelemetryEvent,
    five_tuple_matches, observation_matches, within_window,
)

FT = FiveTuple("198.51.100.5", "203.0.113.10", "TCP", 44321, 80)
TYPE = "RT_FLOW_SESSION_CREATE"


def stimulus(ft=FT):
    return Stimulus(ft, 100.0, TYPE, expected_fields=("packets",))


def event(ft=FT, ts=100.5, event_type=TYPE, fields=None):
    return TelemetryEvent(event_type, ft, ts, {"packets": 0} if fields is None else fields)


@pytest.mark.parametrize("field,value", [
    ("src_ip", "198.51.100.99"),
    ("dst_ip", "203.0.113.99"),
    ("protocol", "UDP"),
    ("src_port", 44322),
    ("dst_port", 443),
])
def test_each_conflicting_concrete_tuple_field_rejects_match(field, value):
    wrong = replace(FT, **{field: value})
    ev = event(wrong)
    assert Correlator().correlate(stimulus(), [ev]) is None
    assert not find_events([ev], TYPE, FT)
    assert Correlator.saw_ground_truth(stimulus(), [wrong]) is False


@pytest.mark.parametrize("observed", [
    FiveTuple(),
    FiveTuple(protocol="TCP", dst_port=80),
    FiveTuple(src_ip=""),
    FiveTuple(dst_ip="not-an-ip"),
    FiveTuple(src_ip="198.51.100.5", dst_ip=""),
])
def test_missing_or_invalid_observed_identity_cannot_pass(observed):
    ev = event(observed)
    assert not observation_matches(FiveTuple(), observed)
    assert Correlator().correlate(stimulus(), [ev]) is None
    assert Correlator.saw_ground_truth(stimulus(), [observed]) is False
    assert not Correlator().evaluate(stimulus(), [ev], [observed]).passed
    assert not find_events([ev], TYPE, FiveTuple())
    # Type-only inspection is not a correlation claim and remains available.
    assert find_events([ev], TYPE) == [ev]


@pytest.mark.parametrize("requested,observed", [
    (FiveTuple(FT.src_ip, FT.dst_ip, "TCP"), FT),  # scan/aggregate ports
    (FiveTuple(protocol="TCP", dst_port=80), FT),  # browser fan-out
    (FT, FiveTuple(dst_ip=FT.dst_ip, protocol="tcp")),  # partial SRX log
    (FiveTuple(FT.src_ip, FT.dst_ip, "ICMP"), FiveTuple(FT.src_ip, FT.dst_ip, "ICMP")),
    (FiveTuple(), FT),  # explicitly unconstrained aggregate
])
def test_legitimate_partial_and_aggregate_tuples_still_match(requested, observed):
    assert observation_matches(requested, observed)
    assert Correlator().evaluate(stimulus(requested), [event(observed)], [observed]).passed


def test_symmetric_compatibility_primitive_retains_wildcard_contract():
    assert five_tuple_matches(FiveTuple(), FT)
    assert five_tuple_matches(FT, FiveTuple())
    assert not observation_matches(FT, FiveTuple())


@pytest.mark.parametrize("ts,accepted", [
    (97.999, False), (98.0, True), (100.0, True),
    (110.0, True), (112.0, True), (112.001, False),
    (float("nan"), False), (float("inf"), False),
])
def test_inclusive_time_boundaries_and_nonfinite_events(ts, accepted):
    assert within_window(100, ts, 10, 2) is accepted
    assert (Correlator(10, 2).correlate(stimulus(), [event(ts=ts)]) is not None) is accepted


@pytest.mark.parametrize("window,skew", [
    (-1, 0), (1, -1), (float("inf"), 0), (1, float("nan")),
])
def test_invalid_correlation_windows_rejected(window, skew):
    with pytest.raises(ValueError, match="finite and non-negative"):
        Correlator(window, skew)


def test_wrong_event_type_rejected_even_with_exact_tuple_and_time():
    assert Correlator().correlate(stimulus(), [event(event_type="RT_FLOW_SESSION_DENY")]) is None


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_stimulus_time_never_matches(timestamp):
    stim = replace(stimulus(), timestamp=timestamp)
    assert Correlator().correlate(stim, [event(ts=timestamp)]) is None


def test_closest_event_chosen_after_filtering_not_for_field_completeness():
    farther = event(ts=103)
    closest_incomplete = event(ts=100.1, fields={})
    wrong_type = event(ts=100, event_type="RT_FLOW_SESSION_DENY")
    result = Correlator().evaluate(stimulus(), [farther, wrong_type, closest_incomplete])
    assert result.matched_event is closest_incomplete
    assert result.fields_complete is Detection.NO


def test_equal_distance_ambiguity_uses_stable_input_order_not_unique_attribution():
    first, second = event(ts=99), event(ts=101)
    corr = Correlator()
    assert corr.candidates(stimulus(), [first, second]) == [first, second]
    assert corr.correlate(stimulus(), [first, second]) is first
    assert corr.correlate(stimulus(), [second, first]) is second


def test_aggregate_event_can_support_multiple_stimuli_without_consumption():
    shared = event(FiveTuple(FT.src_ip, FT.dst_ip, "TCP"))
    stimuli = [stimulus(), stimulus(replace(FT, dst_port=443))]
    matrix = Correlator().build_matrix(iter(stimuli), iter([shared]), iter([shared.five_tuple]))
    assert matrix.passed
    assert all(row.matched_event is shared for row in matrix.rows)


@pytest.mark.parametrize("value,complete", [
    (0, True), (0.0, True), (False, True), ("0", True), (None, False), ("", False),
])
def test_completeness_has_one_definition_in_assertions_and_verdicts(value, complete):
    ev = event(fields={"packets": value})
    ok, missing = field_complete(ev, stimulus().expected_fields)
    result = Correlator().evaluate(stimulus(), [ev])
    assert ok is complete
    assert result.missing_fields == missing
    assert result.fields_complete is (Detection.YES if complete else Detection.NO)


def test_absent_required_field_rejected():
    result = Correlator().evaluate(stimulus(), [event(fields={})])
    assert result.missing_fields == ["packets"]
    assert not result.passed


def test_telemetry_only_default_is_explicitly_inferred():
    result = Correlator().evaluate(stimulus(), [event()])
    assert result.passed
    assert "inferred from telemetry only" in result.note


def test_strict_mode_requires_independent_evidence_without_hiding_log():
    result = Correlator(require_ground_truth=True).evaluate(stimulus(), [event()])
    assert result.detected is Detection.INCONCLUSIVE
    assert result.logged is Detection.YES
    assert result.fields_complete is Detection.YES
    assert not result.passed


@pytest.mark.parametrize("strict", [False, True])
def test_independent_presence_is_observation_not_action(strict):
    result = Correlator(require_ground_truth=strict).evaluate(stimulus(), [event()], [FT])
    assert result.passed
    assert "not proof of a security action" in result.note


@pytest.mark.parametrize("events", [[], [event()]])
def test_capture_absence_never_proves_non_arrival_or_non_detection(events):
    result = Correlator().evaluate(stimulus(), events, [])
    assert result.detected is Detection.INCONCLUSIVE
    assert result.logged is (Detection.YES if events else Detection.INCONCLUSIVE)
    assert "Absence does not establish non-arrival" in result.note
    assert not result.passed


def test_presence_without_log_is_only_possible_logging_gap():
    result = Correlator().evaluate(stimulus(), [], [FT])
    assert result.logged is Detection.NO
    assert result.fields_complete is Detection.INCONCLUSIVE
    assert "possible logging gap" in result.note
    assert "genuine detection" not in result.note


def test_empty_matrix_is_not_a_pass():
    assert not Correlator().build_matrix([], []).passed
