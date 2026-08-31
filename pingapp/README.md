# pingapp — live ping + WiFi signal monitor

A tiny Python stdlib service that pings a target (default and DF probes),
optionally streams WiFi signal from a remote host via SSH, retains 24h at
1-minute resolution and 7 days at 15-minute aggregates, and serves a live
dashboard on HTTP.

## Run

```bash
cp config.env.example config.env
$EDITOR config.env
source config.env
python3 server.py
```

Then open <http://localhost:8080>.

## Data

| Probe | Cadence | Purpose |
| --- | --- | --- |
| Ping, default payload | `PING_INTERVAL` (default 1s) | latency + loss baseline |
| Ping, DF `PING_BIG_SIZE` payload | `PING_INTERVAL` | MTU / fragmentation health |
| WiFi signal (dBm) | `WIFI_INTERVAL` (default 3s) | signal strength on a remote host |

Aggregated into 1-min buckets kept for `PING_RETAIN_DAYS` days.
Persisted to `state.json` every 15s and on SIGTERM/SIGINT/SIGHUP (`fsync` +
directory `fsync`), so `wsl --shutdown` and Windows reboots don't lose data.

## Nightly pause

Currently hard-coded to 23:59 → 08:00 local time. During the window, both
probes idle and the SSH session to the WiFi host is dropped (rather than held
open all night). The HTTP dashboard stays up so history remains viewable.

## Autostart

See `../scripts/pingapp-start.sh`. Point cron at it:

```
@reboot   /home/you/net-monitoring/scripts/pingapp-start.sh
*/5 * * * * /home/you/net-monitoring/scripts/pingapp-start.sh
```

Idempotent: checks for both an existing process and port 8080 before starting.
