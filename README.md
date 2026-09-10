# Juniper SRX Transit Security Detection Probe

## Detection coverage matrix

| # | SRX telemetry / detection target | Junos log/event | Best generator | Concrete stimulus | Ground-truth check |
|---|---|---|---|---|---|
| 1 | Session create/close (basic flow) | `RT_FLOW_SESSION_CREATE` / `_CLOSE` | curl / scapy | Single TCP connection to known dst | `show security flow session` + syslog 5-tuple match |
| 2 | Session deny (policy drop) | `RT_FLOW_SESSION_DENY` | scapy / hping3 | Packet to a denied port/dst | Deny event present, no create event |
| 3 | TCP scan detection | `RT_IDP` / screen events | nmap / hping3 | nmap -sS, -sX, -sF (SYN/Xmas/FIN) | Screen counter incr + per-scan log |
| 4 | Malformed / anomalous packets | screen / IDP anomaly | scapy | Bad flag combos, bad checksums, tiny TTL | Anomaly event with correct subtype |
| 5 | IP fragmentation attacks | screen (teardrop, frag) | scapy | Overlapping/oversized fragments | Frag-attack screen event |
| 6 | Flood / rate-based (SYN, ICMP, UDP) | screen flood events | hping3 / scapy | hping3 --flood -S controlled rate | Flood threshold event at expected rate |
| 7 | IDS/IPS signature match | `RT_IDP_ATTACK_LOG` | scapy / custom client | EICAR over HTTP, GTUBE, Juniper test sigs | IDP attack event w/ correct signature ID |
| 8 | App-ID (generic protocols) | `APPTRACK_SESSION_*` | curl / custom client | Raw HTTP, DNS, FTP, SSH handshakes | AppTrack app-name field correct |
| 9 | App-ID (web apps) | `APPTRACK` app-name | Playwright | Real navigation to the web app | App correctly classified (e.g. dropbox) |
| 10 | URL / web filtering | `WEBFILTER_URL_*` | Playwright | Navigate to categorized/blocked URLs | Category match + block-page rendered |
| 11 | SSL proxy / decryption | SSL-proxy logs | Playwright | Real TLS handshake, varied SNI/certs | Cert/SNI fields + decryption status |
| 12 | AppFW (app-based policy) | `APPTRACK` + policy | Playwright / curl | App that violates app-firewall rule | Block + app-fw event |
| 13 | Content filtering (file/MIME) | `CONTENT_FILTERING_*` | curl / Playwright | Download blocked MIME / EICAR file | Content-filter block event |
| 14 | Antivirus / UTM | `AV_VIRUS_DETECTED` | curl | EICAR test file over HTTP | AV event, correct virus name (EICAR) |
| 15 | Session volume / scale events | flow counters | wrk / iperf3 | High concurrent connection count | Session-count threshold telemetry |
| 16 | Throughput / bandwidth | flow stats, J-Flow | iperf3 | Sustained N Gbps stream | Byte counters in flow records |
| 17 | Flow export / IPFIX accuracy | J-Flow / IPFIX | iperf3 + scapy | Known flow count/sizes | Exported records match sent flows |

---

A **telemetry-validation test suite** that verifies a Juniper SRX deployed in
**internet transit mode** correctly **emits security telemetry** when it
processes internet-bound traffic — including malicious / synthetic-attack
patterns.

> This suite validates **DETECTION & LOGGING behavior**, not configuration,
> zone, policy, or routing correctness. The question it answers is:
>
> *"When a known stimulus crosses the SRX, does the SRX emit the expected
> telemetry, with complete fields, that we can correlate back to exactly that
> stimulus?"*

The telemetry sources validated include: `RT_FLOW` session logs (create / close
/ deny), `RT_IDP` / IPS attack events, AppSecure (AppTrack App-ID, AppFW,
content/URL filtering), UTM / antivirus, screen (anomaly / flood / scan / frag)
events, the NETCONF session table, and flow / IPFIX (J-Flow) export.

---

## ⚠️ Safety warning

- **Synthetic / safe signatures only.** This suite uses industry-standard
  *test* artifacts: the [EICAR](https://www.eicar.org/) antivirus test string,
  the [GTUBE](https://spamassassin.apache.org/gtube/) spam test string, and
  standard `nmap` scan types. **It never uses or transmits live malware.**
- **Authorized environments only.** Scan, flood, and malformed-packet
  generation can disrupt networks and may be illegal against systems you do not
  own. Run this **only** in an authorized lab or transit test environment
  against targets you control or have written permission to test.
- Floods and scans are **rate-limited and bounded** by configuration; review
  `config/probe_config.example.yaml` before running live tests.

---

## Architecture

```
[Test Workload Generator] --internet-bound traffic-->
        [Juniper SRX transit enforcement point] --> Internet / external
                          |
                          | SRX emits telemetry
                          v
              [Log / Event Collector]
                          |
                          v
        [Validation / Correlation Engine]
                          |
                          v
                 [Report / Findings]
```

Four functional layers:

1. **Generation** — produce a *known* event (a specific 5-tuple + payload at a
   known timestamp).
2. **Telemetry sources** — the SRX features under test that should emit logs /
   events.
3. **Collection pipeline** — a syslog listener, NETCONF queries, and an
   independent egress packet capture (ground truth).
4. **Validation engine** — correlate sent stimulus against collected telemetry
   and assert the expected events appeared with the expected fields.

Core loop: **generate a known event → capture every telemetry stream → assert
the expected events appeared with the expected fields.** See `docs/` for the
full design.

---

## Repository layout

| Path | Description |
| --- | --- |
| `README.md` | This file. |
| `requirements.txt` | Python dependencies (+ notes on required system binaries). |
| `.gitignore` | Ignores venvs, caches, pcaps, Playwright artifacts, local config. |
| `docs/01-architecture.md` | Stimulus→observation→correlation pipeline and the four layers. |
| `docs/02-telemetry-sources.md` | Enumeration of every SRX telemetry source validated. |
| `docs/03-detection-tool-mapping.md` | Detection target → Junos event → generator → stimulus → ground-truth table. |
| `docs/04-workload-layer-rationale.md` | Why the workload layer is layered, and when (not) to use a browser. |
| `docs/05-correlation-model.md` | The correlation contract and the detection-coverage matrix. |
| `config/probe_config.example.yaml` | Documented example configuration (copy to `probe_config.yaml`). |
| `generators/packet_gen.py` | scapy: malformed packets, bad flags/checksums, fragmentation, crafted L3/L4. |
| `generators/scan_gen.py` | nmap / hping3 wrappers: SYN/XMAS/FIN scans, flood / rate patterns. |
| `generators/l7_client.py` | curl/requests: raw HTTP, DNS, FTP, SSH; EICAR & GTUBE delivery. |
| `generators/browser_gen.py` | Playwright: web-app App-ID, URL filtering, SSL-proxy, block-page screenshot. |
| `generators/load_gen.py` | wrk / iperf3 wrappers: session volume + throughput. |
| `collectors/syslog_collector.py` | Threaded UDP/TCP syslog listener; parses structured Junos sd-syslog. |
| `collectors/srx_query.py` | PyEZ (junos-eznc) NETCONF wrapper: flow sessions, screen stats, IDP counters. |
| `collectors/pcap_capture.py` | tshark / tcpdump egress ground-truth capture wrapper. |
| `validation/correlator.py` | Match sent stimulus (5-tuple + timestamp) against collected telemetry. |
| `validation/assertions.py` | Helper assertions: event_present, field_complete, signature_id_match, etc. |
| `pingapp/` | Standalone live ping + WiFi-signal monitor with 24h/7d history and a browser dashboard. Independent of the SRX suite; ships here for convenience. |
| `srx-dashboard/` | Browser front-end that runs any workload (or all of them) from `deploy/srx_workload.py`, streams stdout live, and records every "Run All" batch into a persistent heatmap. Runs the CLI locally or SSHes into a remote client host. |
| `scripts/` | Idempotent launchers for both dashboards (safe under `@reboot` cron plus a `*/5` watchdog) and a scoped-sudoers installer for the client host. |
| `tests/conftest.py` | pytest fixtures: load config, start collectors, teardown; marker registration. |
| `tests/test_session_events.py` | Session create / close / deny (scapy / curl). |
| `tests/test_screen_events.py` | Scans, floods, fragmentation, malformed (nmap / hping3 / scapy). |
| `tests/test_idp_signatures.py` | IDP / IPS signature match (EICAR / GTUBE / test sigs). |
| `tests/test_appsecure.py` | App-ID generic + web-app, AppFW (l7_client + Playwright). |
| `tests/test_webfilter.py` | URL / web filtering, block-page (Playwright). |
| `tests/test_utm_av.py` | Antivirus / content filtering (EICAR file via curl / Playwright). |
| `tests/test_scale_flow.py` | Session volume, throughput, IPFIX export accuracy (wrk / iperf3). |

---

## Install

For the complete two-host setup, SRX collection configuration, workload and
live-test validation, dashboard deployment, authenticated HTTPS exposure,
persistence, upgrades, and troubleshooting, follow **[INSTALL.md](INSTALL.md)**.

### Base probe suite

```bash
# 1. Create and activate a virtual environment
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install Playwright browser binaries (needed for browser_gen.py)
playwright install

# 4. Ensure system binaries are present for live tests:
#    nmap, hping3, wrk, iperf3, tshark (or tcpdump)
```

### Optional web dashboards

Both dashboards are stdlib-only (no `pip install` needed). Each has its own
`config.env.example`:

```bash
# Ping / WiFi monitor (independent of the SRX suite)
cp pingapp/config.env.example pingapp/config.env
$EDITOR pingapp/config.env

# SRX workload dashboard (wraps deploy/srx_workload.py)
cp srx-dashboard/config.env.example srx-dashboard/config.env
$EDITOR srx-dashboard/config.env
```

Run manually:

```bash
source pingapp/config.env && python3 pingapp/server.py           # :8080
source srx-dashboard/config.env && python3 srx-dashboard/dashboard.py  # :8081
```

Or wire them up as autostart jobs (see the [Web dashboards](#web-dashboards)
section for the cron pattern).

---

## Configure

```bash
cp config/probe_config.example.yaml config/probe_config.yaml
# Edit config/probe_config.yaml with your SRX host, NETCONF credentials,
# syslog collector bind address, egress capture interface, target hosts/URLs,
# and thresholds.
```

`config/probe_config.yaml` is **gitignored** — only the `.example` file is
tracked. Never commit real credentials.

The collectors and generators read configuration via `PROBE_CONFIG`
(environment variable pointing at the YAML file) or default to
`config/probe_config.yaml`.

---

## Run

**Offline logic tests** (pure-Python correlator / assertion logic; no hardware
required — these run green in CI):

```bash
pytest -m "not requires_srx"
```

**Full run against a live SRX** (requires configured hardware, system binaries,
and elevated privileges for packet capture / crafting):

```bash
# Explicitly opt in to tests that contact hardware and generate traffic:
sudo PROBE_CONFIG=config/probe_config.yaml pytest --live-srx
```

Tests that require live infrastructure are marked `@pytest.mark.requires_srx`
and are **deselected** by `-m "not requires_srx"`, so the suite can always be
collected and the logic layer can be exercised without an SRX.
An ordinary `pytest` invocation **skips** live tests unless `--live-srx` is
provided, even when a local probe configuration exists. Offline CI installs
only pytest and coverage.py; it does not need packet tools or an SRX.

---

---

## Web dashboards

Two optional single-file Python dashboards ship in this repo:

### `pingapp/` — live ping + WiFi monitor (port `8080`)

Continuous default-size and do-not-fragment ICMP probes, with an optional
remote WiFi signal probe over SSH. 24h at 1-minute resolution and 7 days at
15-minute aggregation, persisted across restarts.

```bash
cd pingapp
cp config.env.example config.env
$EDITOR config.env                     # PING_TARGET, WIFI_HOST, etc.
source config.env
python3 server.py
```

See [`pingapp/README.md`](pingapp/README.md).

### `srx-dashboard/` — browser UI for the SRX workloads (port `8081`)

Every subcommand of `deploy/srx_workload.py` becomes a card with editable
parameters; a prominent **Run All** button runs the whole suite and each
batch is captured into a persistent execution-result heatmap. A successful
process exit is **not** a detection-validation pass: telemetry and independent
evidence still require validation. The dashboard binds to loopback by default;
see its README for access restrictions and remote deployment. Two execution modes:

- **Local mode** (leave `SRX_CLIENT_HOST` unset) — the dashboard runs the CLI
  directly on the same host. Requires the same setup as running the CLI
  manually (venv, system binaries, sudo on that host).
- **Remote mode** (set `SRX_CLIENT_HOST=user@client`) — the dashboard sits on
  one host (e.g. your laptop) and SSHes to the client generator host for
  every run. Requires SSH key auth to the client and a separately reviewed
  privilege policy. The legacy `scripts/install-client-sudoers.sh` grants
  general Python interpreters root execution and is **not** a narrow security
  boundary; do not treat it as safe for an untrusted dashboard user.

```bash
cd srx-dashboard
cp config.env.example config.env
$EDITOR config.env                     # SRX_TARGET, SRX_SRC, optional SRX_CLIENT_HOST
source config.env
python3 dashboard.py
```

See [`srx-dashboard/README.md`](srx-dashboard/README.md).

### Autostart

The idempotent launchers in `scripts/` are safe to run repeatedly.
Suggested crontab:

```
@reboot     /path/to/srx/scripts/pingapp-start.sh
*/5 * * * * /path/to/srx/scripts/pingapp-start.sh
@reboot     /path/to/srx/scripts/srx-dashboard-start.sh
*/5 * * * * /path/to/srx/scripts/srx-dashboard-start.sh
```

`config.env` and runtime state (`state.json`, `runall-history.json`, logs)
are gitignored; nothing operator-specific ends up in the repo.

---

## How it all fits together

1. A **generator** emits a known stimulus and records its 5-tuple + timestamp.
2. The **syslog collector** (and NETCONF queries + egress pcap) capture
   everything the SRX emits.
3. The **correlator** matches the stimulus to telemetry by 5-tuple within a
   time window.
4. **assertions** verify the event is present, fields are complete, and (where
   relevant) the signature / app / category matches.
5. The result is a **detection-coverage matrix**: for each event type — was it
   detected? logged? were all fields present?

See `docs/05-correlation-model.md` for the correlation contract.
