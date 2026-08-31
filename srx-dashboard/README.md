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
  workload, colours are pass / fail / missing. Persisted to
  `runall-history.json` (last 30 batches).
- Live stdout/stderr via Server-Sent Events. Stop button kills the SSH
  process group cleanly.
- Aggressive workloads (scans, floods, crafted packets) show a red badge and
  require a browser confirm before firing.

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
- If using remote mode: SSH key auth to the client and passwordless sudo
  scoped to the probe's binaries. `scripts/install-client-sudoers.sh` at
  the repo root installs the correct rule.

## Run

```bash
cp config.env.example config.env
$EDITOR config.env
source config.env
python3 dashboard.py
```

Open <http://localhost:8081>. Fill in target/src (populated from the env),
pick a workload or press **Run All**.

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
