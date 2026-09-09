# 05 — Correlation model

The validation engine correlates a generated **stimulus descriptor** with
telemetry using compatible tuple fields, event type and a bounded time window.
A descriptor may represent one connection or an aggregate (a scan, flood,
browser fan-out or load run). A match is evidence consistent with the descriptor,
**not necessarily unique attribution of a log to one packet or payload**.

## Matching and minimum evidence

A telemetry candidate must satisfy all of these conditions:

1. **Observation identity exists.** The observed tuple must contain at least
   one valid source or destination IP address, and every supplied IP address
   must be valid. A completely missing tuple, protocol/ports alone, or an empty
   or malformed address cannot serve as a correlation witness. This rule also
   applies to independent capture tuples and tuple-filtered collector/assertion
   queries. Type-only queries remain available for inspecting uncorrelated logs.
2. **Concrete tuple fields do not conflict.** `src_ip`, `dst_ip`, `protocol`,
   `src_port` and `dst_port` must agree wherever both values are concrete.
   Protocol comparison is case-insensitive. `None` remains a wildcard: scans
   can omit ports, browser stimuli can omit endpoint addresses, partial logs
   can omit fields, and ICMP/fragments need not have transport ports. The
   low-level symmetric `five_tuple_matches` helper is compatibility only;
   `observation_matches` additionally enforces the observation identity rule.
3. **Time is in the inclusive window**
   `[stimulus_time - skew, stimulus_time + window + skew]`. Window and skew
   must be finite and non-negative. This admits bounded delay and clock skew.
4. **Event type equals the expected type.** A session deny does not substitute
   for a create, even if its tuple and timestamp match.

This minimum is deliberately not blanket exact-five-tuple matching: destination-
only logs and aggregate stimuli remain useful. Broad descriptors can correlate
unrelated traffic sharing their concrete constraints; callers should supply the
narrowest known tuple and bound/isolate the collection interval. Payload labels,
URL categories and signature metadata are not automatic correlation constraints;
use the explicit field/signature assertions when those identities matter.

Candidates are ordered by absolute distance from the stimulus timestamp.
The closest candidate wins **before** field completeness is checked; an
incomplete close match is not silently replaced with a more complete distant one.
Equal-distance candidates retain input order. Selection does not resolve semantic
ambiguity. Events are not consumed and can support multiple stimuli, which is
necessary for legitimate aggregate observations. The engine does not provide
one-event-per-stimulus accounting or claim unique attribution for reused events.

## Syslog normalization

For RFC5424 records (`<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD [MSG]`),
**MSGID is authoritative**. A longer uppercase policy, signature or message token
cannot replace it. Only the structured-data elements supply fields; free-text
MSG cannot overwrite their values. Adjacent SD elements are supported; duplicate
field names currently use the last value in SD order.

Quoted values decode RFC5424 `\"`, `\\` and `\]` exactly once. Other backslash
sequences are preserved literally, not interpreted as Python/control escapes.
Malformed structured headers/data and NIL/unrecognizable event IDs are rejected.
NIL structured data can produce a parseable event, but no tuple correlation until
an observed IP endpoint exists.

A conservative **legacy fallback** supports bare Junos tags and RFC3164-style
prefixes: use the first standalone `RT_<family>_*`, `APPTRACK_*`, `WEBFILTER_*`
or `AV_*` tag before the first structured-data block or key/value field. It
accepts quoted and unquoted key/value pairs, never searches field values for an
event ID, and is not a general parser for every Junos positional text format.
Malformed RFC5424-looking records do not fall back to legacy parsing. Prefer
`sd-syslog` when possible.

Event timestamps are **collector receive time**, not parsed device timestamps.
Thus the window bounds reception delay, not device processing time alone; replayed
logs must not be treated as newly generated device events merely because they
were recently received.

The collector uses a bounded deque. `max_events` must be positive; oldest events
are evicted on overflow. `dropped_events` reports lifetime buffer evictions and
is not reset by `clear()`. It does not measure kernel/network loss, parse rejects
or TCP framing loss. TCP remains newline-delimited (not octet-counted RFC6587);
this PR does not change listener concurrency or bound an unterminated TCP frame.

## Independent evidence versus inferred observation

Egress capture is independent of SRX logging, but **presence is not proof of a
security action**. It supports observation at the configured capture point; it
does not establish that IDP detected a signature, that a policy denied traffic,
or even that the capture point really is behind the SRX without topology checks.

**Absence is not proof that traffic never reached the SRX.** A successful block,
capture loss, asymmetric routing, NAT, a narrow filter, or timing can all explain
missing egress packets. Do not turn missing egress into a claim about non-arrival
or a failed security feature.

The legacy `Verdict.detected` field is retained for API/report compatibility.
Read it as an **observation/evidence flag**, not an independently proved detection
or enforcement action:

| Independent tuple evidence | Matching log | `detected` | `logged` | Interpretation |
| --- | --- | --- | --- | --- |
| Present | Yes | YES | YES | Compatible independent observation and telemetry |
| Present | No | YES | NO | Expected telemetry absent; possible logging gap, verify scope/policy |
| Supplied, no match | Yes | INCONCLUSIVE | YES | Telemetry exists; independent observation not established |
| Supplied, no match | No | INCONCLUSIVE | INCONCLUSIVE | Neither channel establishes the requested observation |
| Not supplied | Yes | YES by default | YES | Observation inferred from telemetry only |
| Not supplied | No | INCONCLUSIVE | NO | No independent evidence and no matching log |

`Correlator(require_ground_truth=True)` is an opt-in strict evidence mode: with
no independent channel, a matching log still has `logged=YES` and gets its fields
checked, but `detected=INCONCLUSIVE`, so the row cannot pass. Existing constructor
calls remain supported. The caller is responsible for channel independence; the
API cannot verify the provenance of a supplied iterable of tuples. Strict mode
does not add unique flow attribution, capture timing, or proof of security action.
Every verdict note distinguishes independent, missing or inferred evidence.

## Capture extraction limits

The tshark reader accepts only rows with valid **IPv4 source and destination**,
a numeric IP protocol, and valid transport ports when present. Empty/non-IP rows
(e.g. ARP), malformed rows and out-of-range values are ignored, never emitted as
wildcard ground truth. Port zero is valid. Missing ports remain valid for partial
captures/fragments. It requests the first field occurrence to keep nested fields
from shifting CSV columns and selects TCP/UDP port columns by the IP protocol.
Subprocess failures propagate rather than masquerading as empty evidence.

Both current readers are IPv4-only. Extracted tuples have no packet timestamp,
capture-point identity, NAT mapping, or complete tunnel-layer association. Isolate
the capture per run; a reused tuple in a long/stale pcap can otherwise support an
unrelated stimulus. Full IPv6, time-aware capture correlation, NAT and IPFIX
accounting are outside this first correctness PR.

## Field completeness and coverage

After selecting a match, `validation.assertions.field_complete` supplies the
single completeness rule: a required field is missing if absent, `None`, or the
empty string. Numeric zero (and `False`) count as present. Completeness is not
value correctness: signature, policy, counters or action expectations need
separate value assertions. No match means completeness is INCONCLUSIVE.

`Verdict.passed` requires all three legacy flags (`detected`, `logged`,
`fields_complete`) to be YES. A coverage matrix passes only when nonempty and all
rows pass. A default-mode pass can rely on telemetry inference; a strict-mode pass
requires a compatible independent tuple as well. Neither should be presented as
proof of every security action or complete per-packet detection coverage.
