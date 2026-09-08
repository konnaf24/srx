# srx-dashboard — browser UI for the SRX detection probe

A single-file HTTP dashboard for the workloads in
[`deploy/srx_workload.py`](../deploy/srx_workload.py). Runs the CLI either
locally or on a remote client host over SSH and streams the results back to
the browser.

- Cards for every workload the CLI exposes (`http`, `dns`, `handshake`,
  `eicar`, `gtube`, `scan`, `flood`, `malformed`, `badcsum`, `ttl`, `frag`,
  `deny`, `wrk`, `iperf`), each with its own parameters.
- A prominent **Run All** button with a duration control.
- **Batch history heatmap**: every column is one "Run All", every row is a
  workload, colours are execution OK / error / missing, **not detection verdicts**. Persisted to
  `runall-history.json` (last 30 batches).
- Live stdout/stderr via typed Server-Sent Events (`log`, `reset`, `end`).
  Reconnect uses `Last-Event-ID`; terminal state is replayed even to late clients.
- Stop requests terminate the local process group (the SSH client in remote
  mode). Remote workload termination is best-effort, not guaranteed by SSH exit.
- Aggressive workloads (scans, floods, crafted packets) show a red badge and
  require browser confirmation plus an explicit server-checked boolean.
  This confirmation is a safety interlock, not authentication.

## Deployment modes

- **Local** (default when `SRX_CLIENT_HOST` is unset): the dashboard runs
  `../deploy/srx_workload.py` directly on this host. Needs the srx repo's
  usual generator prerequisites here (venv, scapy, nmap, hping3, wrk,
  iperf3, tshark) and sudo for root workloads.
- **Remote** (`SRX_CLIENT_HOST=user@client`): the dashboard SSHes into the
  client for every run. Only the dashboard host needs Python 3; the client
  needs everything else. This is the right mode when you want the browser
  on a laptop and the traffic origin on a lab host.

## Prerequisites

- The `srx` repo's usual setup on the host that will run the CLI (see
  [RUNNING.md](../RUNNING.md)).
- If using remote mode: SSH key auth to the client and an operator-reviewed
  privilege policy. The legacy `scripts/install-client-sudoers.sh` grants
  general Python interpreters root execution; it is **not** a narrowly scoped
  rule suitable for untrusted dashboard users.

## Run

```bash
cp config.env.example config.env
$EDITOR config.env
source config.env
python3 dashboard.py
```

Open <http://localhost:8081>. The default bind is **127.0.0.1**, not all
interfaces. Fill in target/src (populated from the env), pick a workload or
press **Run All**. A blank source omits `--src`, leaving CLI source selection
intact.

### Network exposure and trust boundary

This stdlib dashboard has **no built-in authentication**. Host/Origin checks
prevent browser cross-origin launches and DNS-rebinding access; they do not
stop an HTTP client from supplying those headers. Every person/process that
can directly reach the backend is trusted to launch workloads with its OS
permissions. Do not publish it directly to a LAN or the Internet.

For network access, put it behind an **authenticated HTTPS reverse proxy**:

- Prefer keeping `SRX_DASH_BIND=127.0.0.1` with a same-host proxy.
- Set `SRX_DASH_PUBLIC_ORIGIN=https://dashboard.example.org` to the exact browser
  origin, with no trailing slash/path. The proxy must preserve that `Host` and
  the browser's `Origin`; forwarded headers are deliberately ignored.
- Authenticate/authorize **all** paths, including HTML, history, status and SSE;
  disable SSE buffering and allow long-lived streams.
- If a separate proxy requires a nonloopback backend bind, explicitly set
  `SRX_DASH_TRUST_PROXY=1` and the HTTPS public origin. Startup otherwise fails
  closed. Firewall/private-network controls must restrict backend access to
  that proxy. The flag declares this operator-managed boundary; it does not
  install or verify authentication/firewall rules.
- Keep credentials at the proxy/OS boundary, never in this page or env example.

Mutating requests require an exact allowed `Host`/`Origin` pair (including the
port when present). Missing or cross-origin `Origin`, cross-site fetch metadata,
unknown hosts, and attempted forwarded-header overrides are rejected.

### Admission, limits and status

Only **one active run** is admitted per dashboard process, including launches
from another tab. `request_id` is an optional 8–80 character alphanumeric,
underscore or hyphen retry key; the browser supplies one. Reusing the key with
the same normalized arguments returns the retained run, while changing its
arguments returns HTTP 409. Other launches while active return 409. Keys and
runs are retained in memory for the last 30 runs; deduplication does **not**
survive restart or eviction. Run one dashboard process per execution boundary;
this is not a distributed scheduler.

Requests must be JSON objects no larger than 16 KiB, with known fields/params,
valid types and choices. Numeric fields accept integers or decimal digit
strings (browser inputs), never booleans/fractions. All must be positive;
maximums mirror default CLI limits: port 65535, scan max-ports 4096, TTL 255,
duration 300 seconds, flood count 10000, fragment count 64, rate 1000,
connections 10000, threads 64, parallel 32. Threads cannot exceed connections;
paced floods cannot exceed 300 seconds. These are input bounds,
not a guarantee that a workload is safe for a particular lab. Aggressive requests
must include `confirm_aggressive: true`.

Each run retains at most 2000 log chunks of 4096 characters and 2000 SSE events;
slow subscribers are disconnected for replay, with 256 events per subscriber
and at most 16 subscribers per run. A `reset` event marks an unavailable older
prefix. Terminal publication is atomic and idempotent, and disconnected
subscriptions are removed. The browser bounds its displayed tail, reconnects,
polls execution status as a fallback, and recovers active runs after refresh.
Persisted batch history is limited to `SRX_HISTORY_MAX` (clamped to 1–100).
It may lack summary rows if those lines have fallen out of the retained tail.
Failed/cancelled batches without a CLI summary are retained with
`summary_available: false`, not silently dropped or treated as passing tests.
History-write failures are reported in the terminal event and browser status.

**Execution rc=0 is not proof of SRX detection.** The dashboard does not collect
or correlate SRX evidence. Network loss is shown as unknown/reconnecting, not
success; after a dashboard restart, prior process execution state is unknown.

### Offline tests

Run `python -m pytest -q tests/test_dashboard.py` from the repository root in
an environment with pytest. Tests import the module without serving, use
in-memory HTTP connections and fake subprocesses, and never run workloads,
SSH, or contact SRX. They cover terminal/reconnect races, bounds, validation,
origin checks, duplicate admission, and process-session flags.

## What executes where (remote mode)

```
[ your browser ] --HTTP--> [ dashboard.py (this host) ]
                                       |
                                       | ssh user@client 'cd ~/srx && ...'
                                       v
                              [ srx client host ] --stimulus--> [ server ]
                                       ^
                                       | live stdout streams back via SSE
```

In local mode there's no SSH hop; `dashboard.py` execs the CLI in a child
process on the same host and reads its stdout directly.
