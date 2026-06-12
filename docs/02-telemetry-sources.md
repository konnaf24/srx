# 02 — Telemetry sources

This is the catalogue of Juniper SRX telemetry sources the probe validates.
Each is something the SRX *should* emit when it processes a matching stimulus.
The probe never assumes a source is working — it proves it by correlation.

## Logging mode and format (prerequisite)

For accurate, high-rate validation, the SRX must be configured for
**stream-mode** security logging with a **structured** format:

```
set security log mode stream
set security log format sd-syslog          # structured-data syslog (RFC 5424-style)
set security log source-address <srx-ip>
set security log stream <name> host <collector-ip> port <port>
```

- **Stream mode** emits security events directly from the data plane (PFE),
  bypassing the routing engine (RE). Under load, **event mode** (RE-processed)
  drops events and serializes through the control plane — unsuitable for
  validation.
- **Structured / sd-syslog** format produces machine-parseable key=value fields
  (e.g. `source-address`, `destination-address`, `application`, `threat-name`),
  which the syslog collector parses deterministically.

## Telemetry sources validated

### RT_FLOW — session lifecycle
- `RT_FLOW_SESSION_CREATE` — a session was permitted and established.
- `RT_FLOW_SESSION_CLOSE` — a session ended (with close reason, byte/packet
  counts).
- `RT_FLOW_SESSION_DENY` — a packet/session was denied by policy (no create
  should accompany it).

Key fields: 5-tuple, policy name, application, ingress/egress zone, byte/packet
counters, session id, reason.

### RT_IDP — IPS / IDP attack logs
- `RT_IDP_ATTACK_LOG_EVENT` (and `_LS` log-set variants) — an IDP/IPS signature
  matched.

Key fields: `attack-name`, `signature` / attack id, severity, action, 5-tuple,
protocol, service.

### AppSecure
- **AppTrack (App-ID)** — `APPTRACK_SESSION_CREATE` / `_CLOSE` /
  `_VOL_UPDATE` carrying the classified `application` / `application-name` (and
  nested app for web apps).
- **AppFW (application firewall)** — application-aware policy enforcement
  events; correlated with AppTrack app classification + policy action.
- **Content / URL filtering** —
  - `WEBFILTER_URL_PERMITTED` / `WEBFILTER_URL_BLOCKED` carrying `url`,
    `category`, `reason`.
  - `CONTENT_FILTERING_*` for MIME/type/protocol-command blocking.

### UTM / antivirus
- `AV_VIRUS_DETECTED_MT` / antivirus events carrying `virus-name` (e.g.
  `EICAR-Test-File`), action, and 5-tuple.

### Screen (IDS anomaly) events
Screen protects against L3/L4 anomalies and volumetric attacks:
- **scan** detection (TCP/UDP port scans),
- **flood** detection (SYN/ICMP/UDP floods),
- **anomaly** (bad TCP flags, bad options, malformed headers),
- **fragmentation** (teardrop, oversized/overlapping fragments).

Emitted as `RT_SCREEN_TCP` / `RT_SCREEN_IP` / `RT_SCREEN_UDP` attack events with
the screen profile, attack subtype, and 5-tuple. Also exposed as **screen
counters** via NETCONF.

### Session table (NETCONF)
Authoritative device state pulled via PyEZ:
- `show security flow session` — live session entries (validates create/close
  and volume).
- `show security screen statistics` — screen hit counters.
- `show security idp counters` / status — IDP engine counters.

### Flow export — J-Flow / IPFIX
- **J-Flow v9 / IPFIX** flow records exported to a collector, validating
  exported flow counts and byte/packet counters against known generated flows.

### Junos Telemetry Interface (JTI)
- **gRPC / gNMI** streaming telemetry (model-driven). Where enabled, provides
  high-rate counters (interface, flow, firewall) as an additional observation
  channel. The probe treats JTI as an optional ground-truth/counter source
  alongside NETCONF.

## Stream vs event mode (summary)

| Aspect | Stream mode (required) | Event mode |
| --- | --- | --- |
| Path | Data plane (PFE) direct to collector | Routing engine (RE) processes then logs |
| Throughput | High; survives load | Low; drops under load |
| Use | Security telemetry validation | Light/diagnostic only |
| Format | `sd-syslog` (structured) recommended | syslog/structured |
