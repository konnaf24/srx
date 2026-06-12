# 04 — Workload layer rationale

The workload (generation) layer is deliberately **layered**. We always drive a
detection target from the *lowest layer that can produce the stimulus
deterministically*. This document explains why, and in particular why
browser automation (Selenium / Playwright / Chrome MCP) is **not** used for most
detection targets — and exactly where it *is* the right tool.

## Why layered, and why not "just use a browser"

A browser is an L7 client sitting on top of a fully normalizing OS network
stack. That makes it the wrong instrument for most of the table in
`03-detection-tool-mapping.md`:

1. **Browsers only speak L7.** They cannot emit malformed packets, port scans,
   crafted fragments, bad TCP flags, or byte-exact IDP signatures. The OS TCP/IP
   stack **normalizes everything**: it computes correct checksums, sets sane
   TTLs, reassembles fragments, and refuses to send the malformed frames that
   screen / IDP anomaly detection exists to catch. Rows 2–7 are simply
   impossible from a browser.

2. **TLS hides payloads.** For signature/content inspection (IDP, AV, content
   filtering), the SRX must see the bytes. Over HTTPS the payload is encrypted
   and invisible to inspection **unless SSL-proxy/decryption is enabled** on the
   SRX. A browser firing HTTPS gives you nothing to inspect by default; a
   scriptable client over plain HTTP delivers the exact bytes (e.g. EICAR /
   GTUBE) the engine needs to match.

3. **Browsers are nondeterministic.** Connection pooling, DNS/resource
   prefetch, speculative preconnect, automatic retries, HTTP/2 multiplexing, and
   QUIC/HTTP3 all mean a single "navigation" produces an unpredictable fan-out
   of connections. That **breaks 1:1 stimulus↔log correlation** — the core
   contract of this suite (see `05-correlation-model.md`). A raw socket or
   scapy packet produces exactly one known 5-tuple.

4. **Browsers are heavy and low-throughput.** For session-volume and throughput
   tests (rows 15–17) you need tens of thousands of connections or sustained
   Gbps. Spinning up browser contexts for that is wasteful and slow; `wrk` and
   `iperf3` are purpose-built.

## Where Playwright IS the right tool (rows 9–12)

Browser automation is the *correct* instrument precisely when the detection
target **is** browser-driven L7 behavior that lower layers cannot faithfully
reproduce:

- **Row 9 — Web-app App-ID.** Real web applications are identified by the SRX
  from realistic browser traffic patterns (headers, TLS fingerprint, request
  sequences). A real navigation exercises this; a raw socket does not.
- **Row 10 — URL / web filtering.** Validating category lookup *and* the
  user-facing **block-page** requires a real browser that follows redirects and
  renders the block response (we screenshot it as evidence).
- **Row 11 — SSL proxy / decryption.** Validating that the SRX intercepts and
  decrypts TLS requires a **real TLS handshake** with varied SNI and proper
  certificate handling — exactly what a browser performs.
- **Row 12 — AppFW.** Application-firewall enforcement against real application
  traffic (and observing the resulting block) is best driven by a real client.

## Playwright over Selenium; Chrome MCP for exploration only

- **Playwright > Selenium** for this suite: faster, first-class headless mode,
  built-in **network interception/inspection**, auto-waiting (fewer flaky
  timing hacks), and a cleaner async API — all of which improve determinism.
- **Chrome MCP** (driving a real Chrome ad hoc) is fine for **exploratory**,
  one-off investigation of how the SRX treats a given site, but it is **too
  nondeterministic** for a repeatable, asserted suite. Use it to discover; use
  Playwright to validate.

## Layered coverage summary

| Layer | Tools | Approx. coverage | Detection rows |
| --- | --- | --- | --- |
| **L3 / L4** | scapy, hping3, nmap | ~50% | 2–7, parts of 1, 17 |
| **L7 scriptable** | curl, `requests`, custom sockets | broad | 1, 8, 13, 14 |
| **L7 browser** | Playwright | targeted | 9–12 |
| **Scale** | wrk, iperf3 | volume/throughput | 15–17 |

Principle: **use the lowest layer that can produce the stimulus
deterministically; escalate to a browser only when the behavior under test is
itself browser-driven L7.**
