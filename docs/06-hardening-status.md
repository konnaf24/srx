# Validation and dashboard hardening: first implementation batch

This batch fixes concrete correctness and reliability defects. It does not
implement every feature in the detection-coverage design matrix.

## Implemented

- RFC5424 message-id parsing and escaped structured-data regressions.
- Rejection of unidentified observations and empty/non-IP capture rows.
- Consistent field completeness, including valid numeric zero values.
- Explicit evidence notes and opt-in independent-evidence correlation.
- Bounded syslog buffers with eviction counts.
- Positive numeric workload controls, explicit configurable per-workload
  ceilings, paced/rate-limited scans and floods, checked subprocess failures,
  and retained actual load measurements.
- Execution status is separate from `detection_status="not_evaluated"`.
- More meaningful scoped scale telemetry checks. The unimplemented IPFIX test
  is explicitly skipped rather than passing on a configuration value.
- Typed/replayable dashboard SSE, atomic completion, bounded subscribers/logs,
  source auto-discovery, single-active-run admission and retry deduplication.
- Loopback default, Host/Origin validation, request limits and server-side
  aggressive confirmation. Network authentication remains an operator-managed
  reverse-proxy responsibility, not a built-in dashboard feature.
- Offline regression tests and CI; live tests require explicit `--live-srx`.

## Compatibility and operating notes

The workload summary uses `SUCCEEDED`/`FAILED` and explicitly says detection
has not been evaluated. The dashboard accepts both old and new summary text.
Nonzero hping exits are no longer converted to success merely because output
mentions a transmitted-packet count; a sender can transmit traffic and still
report an execution failure. Inspect raw diagnostics separately.

`WorkloadLimits` defaults are 10,000 packets, 1,000 packets/sec, 4,096 scan ports,
300 seconds, 10,000 connections, 64 threads, 32 parallel streams, 64 fragments,
and 32 concurrent workloads. CLI `--limit-*` options are explicit lab-operator
overrides; use `--help` for exact names. Run All currently uses its established
18 workload instances and rejects a ceiling that cannot accommodate them.
These are **per-workload** bounds, not aggregate budgets or proof of safety.
The dashboard deliberately uses the conservative defaults and does not expose
ceiling overrides.

The correlator retains legacy aggregate/wildcard behavior and event reuse;
its minimum observed-IP requirement does not prove unique session attribution.
`require_ground_truth=True` requires a compatible independent tuple but does
not turn egress visibility into proof of a security action. See
[the correlation model](05-correlation-model.md).

## Follow-up work, not claimed by this PR

1. Full timestamped ingress/egress, NAT-aware and IPv6 evidence attribution;
   real IPFIX collection and directional byte accounting.
2. Exact feature/signature/application/action assertions and negative controls
   across supported Junos releases; event-driven live waits.
3. Shared CLI/dashboard manifest, destination allowlists and aggregate budgets;
   Smoke/Detection/Scale/Mixed profiles and measured session occupancy.
4. Structured end-to-end result protocol instead of stdout-summary parsing;
   guaranteed remote cancellation and durable execution recovery after restart.
5. A reviewed least-privilege launcher replacing the legacy broad Python sudo
   grant; authenticated reverse-proxy deployment validation.
6. Evidence drill-down, accessible history tables, run comparisons and real
   browser/authorized-hardware integration validation.

No live SRX behavior or throughput improvement is established by offline tests.
