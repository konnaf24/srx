"""Correlation engine for the SRX detection probe.

Implements the correlation contract described in ``docs/05-correlation-model.md``:

    "Does the SRX telemetry match this stimulus descriptor and time window,
     with complete fields and clearly identified observation evidence?"

Everything here is pure Python with no external dependencies, so the matching
logic can be unit-tested offline without a live SRX, collectors, or generators.

Core concepts
-------------
* :class:`FiveTuple`      - a (src_ip, dst_ip, protocol, src_port, dst_port) key.
* :class:`Stimulus`       - a known event we generated (what we *sent*).
* :class:`TelemetryEvent` - an event the SRX emitted (what we *observed*).
* :class:`Correlator`     - matches stimuli to telemetry by 5-tuple + time window.
* :class:`Verdict` / :class:`CoverageMatrix` - the detection-coverage output.
"""

from __future__ import annotations

import enum
import ipaddress
import math
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class FiveTuple:
    """A network 5-tuple used as the correlation key.

    Ports may be ``None`` for protocols that have none (e.g. ICMP) or when an
    event legitimately omits them. ``None`` is treated as a wildcard during
    matching (see :func:`five_tuple_matches`): it never *conflicts* with a
    concrete value, but two concrete values must be equal to match.
    """

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    def normalized(self) -> "FiveTuple":
        """Return a copy with protocol upper-cased for stable comparison."""
        proto = self.protocol.upper() if isinstance(self.protocol, str) else self.protocol
        return FiveTuple(self.src_ip, self.dst_ip, proto, self.src_port, self.dst_port)


@dataclass
class Stimulus:
    """A known event emitted by a generator (the thing we *sent*).

    Attributes
    ----------
    five_tuple:
        Known tuple constraints of the traffic generated; aggregate stimuli
        may leave fields as wildcards.
    timestamp:
        Epoch seconds (float) at which the stimulus was sent.
    expected_event_type:
        The Junos event type that *should* be emitted for this stimulus,
        e.g. ``"RT_FLOW_SESSION_CREATE"`` or ``"RT_IDP_ATTACK_LOG"``.
    payload_class:
        A label for the payload kind (e.g. ``"EICAR"``, ``"GTUBE"``,
        ``"malformed-flags"``). Informational; aids reporting.
    detection_target:
        Human-readable name of the detection row being exercised.
    expected_fields:
        Field names that a correlated event must carry to be "complete".
    metadata:
        Arbitrary extra context (signature id, app name, url category, ...).
    """

    five_tuple: FiveTuple
    timestamp: float
    expected_event_type: str
    payload_class: str = ""
    detection_target: str = ""
    expected_fields: Sequence[str] = field(default_factory=tuple)
    metadata: dict = field(default_factory=dict)


@dataclass
class TelemetryEvent:
    """An event observed from the SRX (the thing we *saw*).

    Produced by the syslog collector or NETCONF queries and normalized into
    this shape for correlation.
    """

    event_type: str
    five_tuple: FiveTuple
    timestamp: float
    fields: dict = field(default_factory=dict)
    raw: str = ""


# ---------------------------------------------------------------------------
# Matching primitives
# ---------------------------------------------------------------------------
def _value_compatible(a, b) -> bool:
    """Two field values are compatible if either is ``None`` (wildcard) or equal."""
    if a is None or b is None:
        return True
    return a == b


def five_tuple_matches(a: FiveTuple, b: FiveTuple) -> bool:
    """Return ``True`` if two 5-tuples are compatible.

    ``None`` fields act as wildcards (they match anything). Two concrete,
    differing values never match. Protocol comparison is case-insensitive.
    """
    a = a.normalized()
    b = b.normalized()
    return (
        _value_compatible(a.src_ip, b.src_ip)
        and _value_compatible(a.dst_ip, b.dst_ip)
        and _value_compatible(a.protocol, b.protocol)
        and _value_compatible(a.src_port, b.src_port)
        and _value_compatible(a.dst_port, b.dst_port)
    )


def observation_matches(stimulus: FiveTuple, observed: FiveTuple) -> bool:
    """Match compatible tuples only when the observation has an IP endpoint.

    Stimuli may describe aggregates (including wildcard addresses/ports).
    Observations must contain at least one valid IP address; any supplied
    address must be valid. Missing ports remain legitimate for aggregate logs,
    fragments and protocols without ports. This is not exact flow attribution.
    """
    addresses = [ip for ip in (observed.src_ip, observed.dst_ip) if ip is not None]
    if not addresses:
        return False
    try:
        for address in addresses:
            ipaddress.ip_address(address)
    except ValueError:
        return False
    return five_tuple_matches(stimulus, observed)


def within_window(
    stimulus_time: float,
    event_time: float,
    window_s: float,
    skew_s: float = 0.0,
) -> bool:
    """Return ``True`` if ``event_time`` falls inside the correlation window.

    The window is ``[stimulus_time - skew_s, stimulus_time + window_s + skew_s]``.
    ``skew_s`` absorbs bounded clock skew between generator, SRX, and collector;
    ``window_s`` absorbs SRX processing / session-close latency.
    Non-finite timestamps cannot establish a bounded-time match.
    """
    if not math.isfinite(stimulus_time) or not math.isfinite(event_time):
        return False
    lower = stimulus_time - skew_s
    upper = stimulus_time + window_s + skew_s
    return lower <= event_time <= upper


# ---------------------------------------------------------------------------
# Verdicts / coverage matrix
# ---------------------------------------------------------------------------
class Detection(enum.Enum):
    """Three-state verdict used throughout the coverage matrix."""

    YES = "yes"
    NO = "no"
    INCONCLUSIVE = "inconclusive"


@dataclass
class Verdict:
    """The per-detection-target outcome (one row of the coverage matrix)."""

    detection_target: str
    event_type: str
    detected: Detection           # legacy observation/inference flag, not proof of action
    logged: Detection             # did a correlating telemetry event appear?
    fields_complete: Detection    # did the correlated event carry all fields?
    matched_event: Optional[TelemetryEvent] = None
    missing_fields: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def passed(self) -> bool:
        """A target passes only when detected, logged, and fields complete."""
        return (
            self.detected is Detection.YES
            and self.logged is Detection.YES
            and self.fields_complete is Detection.YES
        )


@dataclass
class CoverageMatrix:
    """Collection of :class:`Verdict` rows with simple reporting helpers."""

    rows: List[Verdict] = field(default_factory=list)

    def add(self, verdict: Verdict) -> None:
        self.rows.append(verdict)

    @property
    def passed(self) -> bool:
        return all(r.passed for r in self.rows) and bool(self.rows)

    def failures(self) -> List[Verdict]:
        return [r for r in self.rows if not r.passed]

    def as_table(self) -> str:
        """Render a compact text table (used in reports)."""
        header = f"{'Detection target':35} | {'Event type':28} | Det | Log | Fields"
        sep = "-" * len(header)
        lines = [header, sep]
        for r in self.rows:
            lines.append(
                f"{r.detection_target[:35]:35} | {r.event_type[:28]:28} | "
                f"{r.detected.value[:3]:3} | {r.logged.value[:3]:3} | "
                f"{r.fields_complete.value}"
            )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------
class Correlator:
    """Match stimuli against collected telemetry and build coverage verdicts.

    Parameters
    ----------
    window_s:
        Correlation time window (seconds) after the stimulus timestamp.
    skew_s:
        Allowed clock skew (seconds) between generator, SRX, and collector.
    require_ground_truth:
        Opt-in strict evidence mode: do not infer observation from telemetry
        alone. A matching independent tuple is required for ``detected=YES``.
        Neither mode proves a security action from egress presence.
    """

    def __init__(
        self, window_s: float = 10.0, skew_s: float = 2.0,
        *, require_ground_truth: bool = False,
    ):
        self.window_s = float(window_s)
        self.skew_s = float(skew_s)
        if any(not math.isfinite(v) or v < 0 for v in (self.window_s, self.skew_s)):
            raise ValueError("Correlation window and skew must be finite and non-negative")
        self.require_ground_truth = require_ground_truth

    # -- core matching --------------------------------------------------------
    def candidates(
        self, stimulus: Stimulus, events: Iterable[TelemetryEvent]
    ) -> List[TelemetryEvent]:
        """Return all events that match the stimulus on type, 5-tuple, and time.

        Results are sorted by absolute time distance from the stimulus so the
        closest event is first.
        """
        matches = [
            ev
            for ev in events
            if ev.event_type == stimulus.expected_event_type
            and observation_matches(stimulus.five_tuple, ev.five_tuple)
            and within_window(
                stimulus.timestamp, ev.timestamp, self.window_s, self.skew_s
            )
        ]
        matches.sort(key=lambda ev: abs(ev.timestamp - stimulus.timestamp))
        return matches

    def correlate(
        self, stimulus: Stimulus, events: Iterable[TelemetryEvent]
    ) -> Optional[TelemetryEvent]:
        """Return the closest match, or ``None``; equal distances use input order.

        Events are not consumed: aggregate observations may support multiple
        stimuli. Selection does not establish unique per-packet attribution.
        """
        cands = self.candidates(stimulus, events)
        return cands[0] if cands else None

    # -- ground truth ---------------------------------------------------------
    @staticmethod
    def saw_ground_truth(
        stimulus: Stimulus, ground_truth: Optional[Iterable[FiveTuple]]
    ) -> Optional[bool]:
        """Is a compatible tuple present in the supplied independent capture?

        Returns ``True``/``False`` when ground truth is supplied, or ``None``
        when no ground-truth channel was provided. Absence is not proof that
        traffic never reached the device; tuples carry no timestamps/path proof.
        """
        if ground_truth is None:
            return None
        return any(observation_matches(stimulus.five_tuple, gt) for gt in ground_truth)

    # -- verdict construction -------------------------------------------------
    def evaluate(
        self,
        stimulus: Stimulus,
        events: Iterable[TelemetryEvent],
        ground_truth: Optional[Iterable[FiveTuple]] = None,
    ) -> Verdict:
        """Produce a :class:`Verdict` for a single stimulus.

        Decision logic (see ``docs/05-correlation-model.md``):

        * ``logged``  - YES if a correlating event was found, else NO.
        * ``detected`` - legacy observation flag: independent tuple presence,
          or telemetry inference when allowed. Never proof of security action.
        * ``fields_complete`` - YES if the matched event carries every expected
          field; NO with ``missing_fields`` populated; INCONCLUSIVE if nothing
          was logged.

        Missing egress evidence is inconclusive, not proof of non-arrival.
        ``require_ground_truth`` disables telemetry-only inference.
        """
        from .assertions import field_complete

        events = list(events)
        matched = self.correlate(stimulus, events)
        gt = self.saw_ground_truth(stimulus, ground_truth)

        # logged?
        logged = Detection.YES if matched is not None else Detection.NO

        # detected?
        if gt is True:
            detected = Detection.YES
        elif gt is None and matched is not None and not self.require_ground_truth:
            detected = Detection.YES
        else:
            detected = Detection.INCONCLUSIVE

        # fields complete?
        missing: List[str] = []
        if matched is None:
            fields_complete = Detection.INCONCLUSIVE
        else:
            complete, missing = field_complete(matched, stimulus.expected_fields)
            fields_complete = Detection.YES if complete else Detection.NO

        if gt is True:
            note = (
                "Independent capture contains a compatible tuple; this supports "
                "traffic observation, not proof of a security action."
            )
            if matched is None:
                note += " Expected telemetry not found: possible logging gap; verify capture scope and policy."
        elif gt is False:
            note = (
                "No compatible tuple in independent egress capture: INCONCLUSIVE. "
                "Absence does not establish non-arrival or lack of security action "
                "(blocking, capture loss, timing, NAT or path differences are possible)."
            )
            if matched is None:
                logged = Detection.INCONCLUSIVE
        elif matched is not None and not self.require_ground_truth:
            note = "Observation inferred from telemetry only; no independent evidence or proof of security action."
        else:
            note = "Independent evidence unavailable; observation is INCONCLUSIVE."

        return Verdict(
            detection_target=stimulus.detection_target or stimulus.payload_class,
            event_type=stimulus.expected_event_type,
            detected=detected,
            logged=logged,
            fields_complete=fields_complete,
            matched_event=matched,
            missing_fields=missing,
            note=note,
        )

    def build_matrix(
        self,
        stimuli: Iterable[Stimulus],
        events: Iterable[TelemetryEvent],
        ground_truth: Optional[Iterable[FiveTuple]] = None,
    ) -> CoverageMatrix:
        """Evaluate many stimuli against one telemetry set into a matrix."""
        events = list(events)
        gt = list(ground_truth) if ground_truth is not None else None
        matrix = CoverageMatrix()
        for stim in stimuli:
            matrix.add(self.evaluate(stim, events, gt))
        return matrix
