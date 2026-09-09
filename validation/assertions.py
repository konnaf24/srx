"""Assertion helpers for the SRX detection probe.

These are small, pure-Python predicates and ``assert_*`` wrappers used by the
pytest suite to express detection expectations clearly. They operate on
:class:`~validation.correlator.TelemetryEvent` objects (and lists thereof) and
have no live-infrastructure dependency, so they are fully unit-testable offline.

Two flavours are provided for most checks:

* a boolean predicate (``event_present``) for use in custom logic, and
* an ``assert_*`` wrapper that raises :class:`AssertionError` with a helpful
  message for direct use in tests.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from .correlator import FiveTuple, TelemetryEvent, observation_matches


# ---------------------------------------------------------------------------
# Presence
# ---------------------------------------------------------------------------
def find_events(
    events: Iterable[TelemetryEvent],
    event_type: str,
    five_tuple: Optional[FiveTuple] = None,
) -> List[TelemetryEvent]:
    """Return all events of ``event_type`` (optionally matching ``five_tuple``)."""
    out = []
    for ev in events:
        if ev.event_type != event_type:
            continue
        if five_tuple is not None and not observation_matches(five_tuple, ev.five_tuple):
            continue
        out.append(ev)
    return out


def event_present(
    events: Iterable[TelemetryEvent],
    event_type: str,
    five_tuple: Optional[FiveTuple] = None,
) -> bool:
    """Return ``True`` if at least one matching event exists."""
    return len(find_events(events, event_type, five_tuple)) > 0


def event_absent(
    events: Iterable[TelemetryEvent],
    event_type: str,
    five_tuple: Optional[FiveTuple] = None,
) -> bool:
    """Return ``True`` if **no** matching event exists.

    Useful for negative assertions, e.g. a denied session must produce a DENY
    event and **no** ``RT_FLOW_SESSION_CREATE`` (detection row 2).
    """
    return not event_present(events, event_type, five_tuple)


# ---------------------------------------------------------------------------
# Field completeness
# ---------------------------------------------------------------------------
def field_complete(
    event: TelemetryEvent, required_fields: Sequence[str]
) -> Tuple[bool, List[str]]:
    """Check an event carries every required field with a non-empty value.

    Returns ``(ok, missing)`` where ``missing`` lists absent/empty fields.
    A field counts as present only if its value is not ``None`` and not an
    empty string. Numeric zero and ``False`` are valid present values;
    completeness does not assert their semantic correctness.
    """
    missing = [
        f
        for f in required_fields
        if event.fields.get(f) is None or event.fields.get(f) == ""
    ]
    return (len(missing) == 0, missing)


# ---------------------------------------------------------------------------
# Identity checks
# ---------------------------------------------------------------------------
def signature_id_match(
    event: TelemetryEvent,
    expected_id,
    field_names: Sequence[str] = ("signature", "attack-name", "attack_id", "threat-name"),
) -> bool:
    """Return ``True`` if any signature/attack field equals ``expected_id``.

    SRX IDP events label the matched signature under several possible keys
    depending on format/version, so we check a small set of common field names.
    Comparison is string-based and case-insensitive.
    """
    want = str(expected_id).lower()
    for name in field_names:
        val = event.fields.get(name)
        if val is not None and str(val).lower() == want:
            return True
    return False


def field_value_match(event: TelemetryEvent, field_name: str, expected) -> bool:
    """Return ``True`` if ``event.fields[field_name]`` equals ``expected``.

    Case-insensitive for strings. Used for app-name, url category, AV name, etc.
    """
    val = event.fields.get(field_name)
    if val is None:
        return False
    if isinstance(expected, str) and isinstance(val, str):
        return val.lower() == expected.lower()
    return val == expected


def field_contains(event: TelemetryEvent, field_name: str, needle: str) -> bool:
    """Return ``True`` if ``needle`` is a substring of a string field (ci)."""
    val = event.fields.get(field_name)
    return isinstance(val, str) and needle.lower() in val.lower()


# ---------------------------------------------------------------------------
# assert_* wrappers (raise AssertionError with helpful messages)
# ---------------------------------------------------------------------------
def assert_event_present(
    events: Iterable[TelemetryEvent],
    event_type: str,
    five_tuple: Optional[FiveTuple] = None,
) -> TelemetryEvent:
    """Assert a matching event exists; return the first match."""
    matches = find_events(events, event_type, five_tuple)
    assert matches, (
        f"Expected event '{event_type}'"
        + (f" for 5-tuple {five_tuple}" if five_tuple else "")
        + " but none was found in collected telemetry."
    )
    return matches[0]


def assert_event_absent(
    events: Iterable[TelemetryEvent],
    event_type: str,
    five_tuple: Optional[FiveTuple] = None,
) -> None:
    """Assert no matching event exists."""
    matches = find_events(events, event_type, five_tuple)
    assert not matches, (
        f"Expected NO event '{event_type}'"
        + (f" for 5-tuple {five_tuple}" if five_tuple else "")
        + f" but found {len(matches)}."
    )


def assert_fields_complete(
    event: TelemetryEvent, required_fields: Sequence[str]
) -> None:
    """Assert an event carries every required field."""
    ok, missing = field_complete(event, required_fields)
    assert ok, (
        f"Event '{event.event_type}' is missing required field(s): "
        f"{', '.join(missing)}."
    )


def assert_signature_id(event: TelemetryEvent, expected_id) -> None:
    """Assert an IDP/IPS event matched the expected signature/attack id."""
    assert signature_id_match(event, expected_id), (
        f"Event '{event.event_type}' did not report expected signature "
        f"'{expected_id}'. Fields: {event.fields!r}"
    )


def assert_field_value(event: TelemetryEvent, field_name: str, expected) -> None:
    """Assert a specific field equals the expected value."""
    assert field_value_match(event, field_name, expected), (
        f"Event '{event.event_type}' field '{field_name}'="
        f"{event.fields.get(field_name)!r}, expected {expected!r}."
    )
