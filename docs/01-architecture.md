# 01 — Architecture

The probe is a **stimulus → observation → correlation** pipeline. We push a
*known* event through the Juniper SRX (operating as an internet transit
enforcement point), capture every telemetry stream the SRX produces, and then
prove that the expected events appeared with the expected fields.

## Pipeline diagram

```
[Test Workload Generator]
        |
        |  internet-bound traffic (known 5-tuple + payload @ known timestamp)
        v
[Juniper SRX transit enforcement point] ----------------> Internet / external
        |
        |  SRX emits telemetry
        |   - RT_FLOW session logs (create/close/deny)
        |   - RT_IDP / IPS attack events
        |   - AppSecure (AppTrack App-ID, AppFW, URL/content filtering)
        |   - UTM / antivirus events
        |   - screen (anomaly/flood/scan/frag) events
        |   - flow / IPFIX (J-Flow) export
        v
[Log / Event Collector]
        |  (syslog listener + NETCONF queries + INDEPENDENT egress pcap)
        v
[Validation / Correlation Engine]
        |  match sent stimulus <-> collected telemetry by 5-tuple + time window
        v
[Report / Findings]
        |  detection-coverage matrix: detected? logged? all fields present?
        v
   (pass / fail)
```

## The four functional layers

### 1. Generation
Produces a known event. Each generator returns a **stimulus descriptor**: the
5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`), the payload
class (e.g. EICAR, GTUBE, malformed-flags), and a precise timestamp. Because the
stimulus is known exactly, every downstream assertion can be unambiguous.

Tooling spans layers: scapy / hping3 / nmap for L3/L4; curl / `requests` /
custom sockets for scriptable L7; Playwright for browser-driven L7; wrk / iperf3
for scale. See `04-workload-layer-rationale.md`.

### 2. Telemetry sources
The SRX features under test that *should* emit logs/events for a given stimulus.
Enumerated fully in `02-telemetry-sources.md`. The mapping from a stimulus to
the telemetry it should trigger is the table in `03-detection-tool-mapping.md`.

### 3. Collection pipeline
Three independent observation channels:

- **syslog collector** — a threaded UDP/TCP listener that parses structured
  Junos `sd-syslog` lines into dicts, timestamps them, and stores them in a
  thread-safe buffer queryable by event type / 5-tuple / time window.
- **NETCONF (PyEZ)** — pulls authoritative device state: `show security flow
  session`, screen statistics, IDP counters.
- **egress pcap** — an independent `tshark`/`tcpdump` capture on the egress
  interface that records *ground truth* about what actually crossed the wire.

### 4. Validation engine
Correlates stimulus against telemetry and asserts. The correlator matches by
5-tuple within a time window; the assertion helpers verify event presence,
field completeness, and signature / app / category identity. Output is a
detection-coverage matrix.

## The core loop

```
for each detection target:
    1. generate a known event (record stimulus descriptor)
    2. capture every telemetry stream (syslog + NETCONF + egress pcap)
    3. assert the expected events appeared with the expected fields
```

## Design principles (non-negotiable)

- **Always capture independent ground truth.** The egress pcap lets us
  distinguish *"the SRX missed/failed to log it"* from *"the traffic never
  actually arrived at the SRX"*. Without it, a missing log is ambiguous.
- **Correlate, don't just count.** Counting "we saw N RT_FLOW events" proves
  nothing — bursts, retries, and unrelated traffic inflate counts. We match
  each specific stimulus 5-tuple to a specific log line.
- **Use stream-mode security logging.** Configure the SRX with
  `set security log mode stream` and a **structured** (sd-syslog) format so
  security events are emitted directly from the data plane and bypass the
  control plane (RE). Under load, event-mode logging via the RE drops events
  and skews results; stream mode is required for accurate, high-rate validation.
