# 05 — Correlation model

The validation engine enforces a single, strict **correlation contract**:

> *"I sent **exactly** this 5-tuple + payload at **this** timestamp. Did the SRX
> log **exactly** that event, with **complete** fields?"*

Counting telemetry is not enough. We bind each generated stimulus to a specific
log line.

## The matching algorithm

A collected telemetry event is considered a **match** for a stimulus when:

1. **5-tuple matches.** `src_ip`, `dst_ip`, `protocol`, and — where applicable —
   `src_port` / `dst_port` align. (Some events legitimately omit a field, e.g.
   ICMP has no ports; the matcher treats `None`/wildcard fields leniently but
   never matches across a *conflicting* concrete value.)
2. **Timestamp falls within the window.** The event timestamp lies within
   `[stimulus_time - skew, stimulus_time + window]`. The window absorbs SRX
   processing latency, session close delay, and bounded clock skew between the
   generator host, the SRX, and the collector.
3. **Event type matches** the expected Junos event for that detection target
   (e.g. `RT_FLOW_SESSION_CREATE`, `RT_IDP_ATTACK_LOG`, `AV_VIRUS_DETECTED`).

When multiple candidate events fall in the window, the correlator selects the
**closest in time** that satisfies the 5-tuple and type constraints.

## Why independent ground truth (egress pcap)

A missing log is **ambiguous** on its own. It can mean:

- **(a)** the SRX received the traffic but failed to detect/log it (a real
  finding), or
- **(b)** the traffic never reached the SRX at all (a test-environment problem:
  routing, NAT, a dropped flood packet, a closed target port, etc.).

The **independent egress packet capture** disambiguates: if the stimulus appears
in the egress pcap (it crossed the SRX) but no correlating telemetry exists,
that is a genuine **detection/logging gap (a)**. If it never appears in the
pcap, the test is **inconclusive** — we flag the environment, not the SRX.

This is why ground truth is captured on a channel completely independent of the
SRX's own logging: we never let the system under test be the sole witness to its
own behavior.

```
stimulus sent ──► in egress pcap? ──► telemetry correlated?
                       │                     │
        no ◄───────────┘                     ├── yes ──► PASS (detected + logged)
        │                                     └── no  ──► FAIL (detection/logging gap)
        └──► INCONCLUSIVE (traffic never crossed SRX — fix environment)
```

## Field completeness

Even a correlated event can be a partial failure if the SRX omits required
fields. After a match, assertions check **field completeness** against the
expected field set for that event type (e.g. an `RT_FLOW_SESSION_CREATE` must
carry policy name, zones, application, and byte/packet counters; an
`RT_IDP_ATTACK_LOG` must carry an attack/signature id and severity).

## Output: the detection-coverage matrix

The engine produces a matrix — one row per detection target — with three
independent verdicts:

| Event type | Detected? | Logged? | All fields present? |
| --- | --- | --- | --- |
| RT_FLOW_SESSION_CREATE | ✅ | ✅ | ✅ |
| RT_FLOW_SESSION_DENY | ✅ | ✅ | ⚠️ (missing policy name) |
| RT_IDP_ATTACK_LOG (EICAR) | ✅ | ❌ | — |
| ... | | | |

- **Detected?** — ground truth (egress pcap / device counters) shows the SRX saw
  and acted on the stimulus.
- **Logged?** — a correlating telemetry event was found.
- **All fields present?** — the correlated event carried every required field.

This separation is what makes findings actionable: "detected but not logged"
points at the logging pipeline (stream config, collector, format); "logged but
fields missing" points at log format/profile; "not detected" points at the
security feature/policy itself.
