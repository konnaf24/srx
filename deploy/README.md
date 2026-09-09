# deploy/ — reproducible lab provisioning + ad-hoc workload driver

These scripts codify the two-host lab used to exercise the probe's traffic
generators end-to-end. They turn the manual SSH setup into repeatable code.

> **Authorization:** the scan / flood / malformed-packet workloads are attack
> traffic. Only run them between hosts you own or are authorized to test.

## Topology

```
[ generator host ]  --workloads-->  [ target host ]
  setup_generator.sh                  setup_target.sh
  (tools + venv + driver)             (nginx/dnsmasq/vsftpd/iperf3)
```

Reference lab used during development:
- generator = `10.10.10.46`
- target    = `10.10.10.45`

## 1. Generator host

```bash
sudo ./deploy/setup_generator.sh
```
Installs `nmap hping3 wrk iperf3 tshark`, creates the venv, installs Python deps
+ Playwright (with Ubuntu 24.04 chromium libs), seeds the config, and runs the
offline test suite.

## 2. Target host

```bash
sudo BIND_IP=<target-public-ip> ./deploy/setup_target.sh
```
Brings up the services the generators talk to so every workload completes:

| Service | Port | Purpose |
| --- | --- | --- |
| nginx | 80 | HTTP GET, EICAR file, GTUBE POST, wrk load |
| dnsmasq | 53 | Authoritative-only `probe.lab` DNS workload |
| vsftpd | 21 | FTP banner for App-ID handshake |
| iperf3 | 5201 | throughput workload |

## 3. Run workloads (`srx_workload.py`)

Ad-hoc CLI wrapping the repo's generators. Run from the repo root with the venv.

```bash
# everything (aggressive workloads need root + a confirm prompt; --yes skips it)
sudo ./venv/bin/python deploy/srx_workload.py \
    --target 10.10.10.45 --src 10.10.10.46 --yes all

# single workloads
./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 http --port 80
sudo ./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 scan --type xmas
sudo ./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 flood --type syn --count 2000 --rate 500
```

Subcommands: `all http crawl dns handshake eicar gtube scan flood malformed badcsum
ttl frag deny wrk iperf`. Each subcommand's `--help` lists its options.

`all` launches all 18 workloads concurrently. The sustained `wrk` and `iperf3`
workloads run for 60 seconds by default, so the complete suite normally finishes
in a little over one minute instead of running each workload serially. Override
the sustained duration with `all --duration <seconds>`. Single `wrk` and `iperf`
runs also default to 60 seconds.

Root is required for `scan`, `flood`, and the scapy packet workloads
(`malformed/badcsum/ttl/frag/deny`); benign L7 + `wrk`/`iperf` are not.

## 4. Bounded single-page crawl (standalone, benign)

The dashboard's **crawl** card fetches one page from the configured target and
streams JSON metrics plus extracted title, text, and HTTP(S) links into its log.
Use the target field for an authorized server and run the workload on an
authorized client using the dashboard's existing local/remote execution
configuration. This feature does not change that configuration or deploy anything
automatically. No root or aggressive confirmation is needed. **Crawl is deliberately
excluded from `all` (still 18 workloads).**

```bash
# Execute only in an authorized lab, when ready to generate traffic:
./venv/bin/python deploy/srx_workload.py --target lab.example crawl
./venv/bin/python deploy/srx_workload.py --target lab.example crawl \
    --path '/index.html?q=lab' --max-bytes 1048576 --timeout 10
# HTTPS verifies the server certificate; no insecure-TLS switch:
./venv/bin/python deploy/srx_workload.py --target lab.example crawl --scheme https
```

- Default URL: `http://<target>/`. The target is an IP/hostname, not a URL.
  `--scheme http|https` and optional `--port` select the service; CLI ports default
  to 80/443 by scheme. The dashboard has an explicit port field defaulting to 80;
  change it to 443 when selecting HTTPS.
- Path must start with a single `/`, at most 2048 ASCII characters. Query strings
  are allowed; URL-encode non-ASCII characters/spaces. Scheme-relative `//host`,
  full URLs, backslashes, fragments, and literal/percent-encoded controls (including
  CR/LF) are rejected before I/O. Credential-bearing URLs are never accepted.
- One GET on one connection; **all redirects are rejected**, including same-origin
  redirects. Links are only extracted, never visited. No recursion, assets,
  JavaScript execution, cookies, environment proxy usage, or retry of HTTP requests.
- Body cap defaults to **1 MiB**, configurable from 1 byte through **4 MiB**.
  Incremental reads are at most 16 KiB; underlying HTTP buffering can read ahead
  by a fixed buffer. `bytes_received` counts accepted HTTP body bytes, excluding
  headers/chunk framing. No unbounded body buffering or decompression:
  `Accept-Encoding: identity` is sent and compressed responses are rejected.
- Global deadline defaults to **10 seconds**, configurable from 1 through **30**.
  Remaining time bounds DNS waiting, connection establishment, verified TLS,
  each socket read (including slow headers/chunk framing), and extraction checks.
  A timed-out system hostname resolver may finish in a daemon thread, but cannot
  open a connection or send a request; numeric lab targets avoid DNS resolution.
- Result includes `status_code` (null before headers), `bytes_received`,
  `elapsed_s`, `response_complete`, `truncated`, `execution_status`, and `error`.
  HTTP errors, incomplete framing, redirects, compression, byte caps, and timeout
  are failures (CLI exits nonzero), not successful detections. Partial content can
  still be extracted and is explicitly marked incomplete. For unknown-length
  bodies that reach the exact cap, completion is conservatively unverified rather
  than reading an extra byte. `detection_status` always remains `not_evaluated`.
- Extraction is bounded to a 512-character title, 2048-character text excerpt and
  20 unique links of at most 1024 characters; `output_truncated` reports clipping.
  Script/style/template content is omitted. Content-Type charset is honored,
  with a bounded HTML meta-charset sniff when absent, BOM precedence and UTF-8
  fallback/replacement for unknown encodings or malformed byte sequences. This is
  lightweight extraction, not a browser's complete encoding/rendering algorithm.

**Existing-library preflight:** this repository already pins `requests` and has
Playwright browser workloads. Neither a browser nor a recursive crawling framework
is necessary for one page. The implementation reuses Python's maintained stdlib
`http.client`, `html.parser`, and incremental codecs, adding only bounded deadline
and extraction handling. This avoids new dependencies, implicit redirects/proxies,
and automatic decompression; no gzip optimization is claimed.

Offline verification (fake sockets/HTTP wire data; no lab access):

```bash
/tmp/srx-pr-test-env/bin/python -m pytest -m 'not requires_srx'
```
