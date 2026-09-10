# Installation and deployment guide

This guide installs the complete SRX telemetry-validation suite: the target
services, generator and collector dependencies, live-test configuration, workload
CLI, workload dashboard, and optional ping/WiFi dashboard.

The automated provisioning scripts are verified for **Ubuntu 24.04**. Other
Linux distributions can run the Python code, but package names and service setup
must be adapted.

> **Authorized environments only.** Several workloads create scans, floods, or
> malformed packets. Install and run them only in a lab or network where you have
> explicit permission. The EICAR and GTUBE strings are harmless test signatures;
> do not replace them with malware.

## 1. Choose the topology

Use two hosts with the SRX in the traffic path:

```text
[generator / optional collector] --> [SRX under test] --> [target services]
              |
              +-- workload dashboard (local or separate control host)
```

- **Target host:** receives test traffic and serves DNS, HTTP, FTP, and iperf3.
- **Generator host:** runs the CLI, packet tools, Python generators, and tests.
- **Collector host:** receives SRX syslog and can capture egress traffic. It may
  be the generator when the required interfaces and routes are available.
- **Dashboard host (optional):** runs the web UI locally or invokes the generator
  through SSH key authentication.

Before installation:

1. Confirm generator-to-target traffic traverses the SRX policies/features under
   test in both directions.
2. Synchronize the generator, target, collector, and SRX clocks.
3. Restrict target service ports to the generator at the host/cloud firewall.
4. Prepare a read-only SRX NETCONF account and preferably an SSH key.
5. Record interface names, approved target hostnames/addresses, and the collector
   bind interface. Keep those values outside Git.

## 2. Get the repository

Run this on every host that needs a setup script or the application code:

```bash
git clone <repository-url> ~/srx
cd ~/srx
git status --short --branch
```

Use a reviewed release tag or commit for repeatable installations rather than
installing an unreviewed moving branch.

## 3. Provision the target host

The target setup installs and enables:

| Service | Port | Purpose |
| --- | ---: | --- |
| nginx | TCP 80 | HTTP, EICAR, GTUBE, crawl, and wrk |
| dnsmasq | UDP/TCP 53 | authoritative `probe.lab` response |
| vsftpd | TCP 21 | FTP handshake/App-ID stimulus |
| iperf3 | TCP 5201 | throughput and flow-volume stimulus |

On the authorized target host:

```bash
cd ~/srx
sudo BIND_IP=<target-bind-address> ./deploy/setup_target.sh
```

The script changes system packages and service configuration. Review it before
running on a host that already provides DNS, HTTP, FTP, or iperf3; it is intended
for a dedicated lab target.

Verify listeners and test content:

```bash
ss -tulnp | grep -E ':(21|53|80|5201) '
curl --fail http://localhost/
test "$(wc -c </var/www/html/eicar.com)" -gt 0
```

Allow those service ports only from the generator's approved network path. Do
not expose the lab services broadly.

## 4. Provision the generator host

The supplied script installs the system packet/load tools, creates `venv/`,
installs pinned Python dependencies, installs Playwright browser support, seeds a
local configuration, and runs the hardware-free tests:

```bash
cd ~/srx
sudo ./deploy/setup_generator.sh
```

The reference package set is:

- Python 3, `venv`, pip, and Git
- `nmap`, `hping3`, `wrk`, `iperf3`, and `tshark`
- packages pinned in [`requirements.txt`](requirements.txt)
- Playwright browser binaries and Ubuntu 24.04 Chromium runtime libraries

Verify the installation without generating lab traffic:

```bash
cd ~/srx
./venv/bin/python --version
./venv/bin/python -m pytest -m 'not requires_srx'
./venv/bin/python deploy/srx_workload.py --help
```

The offline selection uses fakes and fixtures; it does not contact an SRX or
launch live workloads.

### Manual Python-only installation

For development on a system where you will not run packet or load generators:

```bash
python3 -m venv venv
./venv/bin/python -m pip install --upgrade pip
./venv/bin/python -m pip install -r requirements.txt
./venv/bin/playwright install
./venv/bin/python -m pytest -m 'not requires_srx'
```

This does not install `nmap`, `hping3`, `wrk`, `iperf3`, or packet-capture tools,
so the corresponding live workloads remain unavailable.

## 5. Configure SRX collection and validation

Create the ignored local configuration:

```bash
cp config/probe_config.example.yaml config/probe_config.yaml
chmod 600 config/probe_config.yaml
${EDITOR:-vi} config/probe_config.yaml
```

Set and verify:

- SRX management hostname, NETCONF port, read-only account, and SSH key
- syslog bind address, port, and protocol
- capture interface and `tshark` or `tcpdump`
- approved L3/L4, HTTP, DNS, FTP, SSH, browser, and EICAR targets
- correlation window, expected clock skew, load thresholds, and conservative
  attack limits

Prefer `srx.ssh_key` to a password. Never commit `probe_config.yaml`, private
keys, captures, dashboard environment files, histories, or logs.

Point the suite at a non-default configuration when needed:

```bash
export PROBE_CONFIG="$PWD/config/probe_config.yaml"
```

Configure the SRX to send structured security syslog to the selected collector
and enable NETCONF-over-SSH for the read-only account. The exact Junos policy,
security-log stream, IDP/AppSecure, screen, and flow-export configuration is
site-specific and intentionally not changed by these scripts.

## 6. Run a bounded smoke test

First verify the target services from the generator:

```bash
curl --fail http://<target-host>/
./venv/bin/python deploy/srx_workload.py --target <target-host> dns --qname probe.lab
./venv/bin/python deploy/srx_workload.py --target <target-host> iperf --duration 3 --parallel 1
```

Then inspect one command before running it:

```bash
./venv/bin/python deploy/srx_workload.py --target <target-host> crawl --help
./venv/bin/python deploy/srx_workload.py --target <target-host> crawl \
  --path / --max-bytes 65536 --timeout 5
```

Aggressive workloads require root and an interactive confirmation unless
`--yes` is supplied. Use `--yes` only in reviewed automation:

```bash
sudo ./venv/bin/python deploy/srx_workload.py \
  --target <target-host> --src <generator-address> \
  scan --type syn --max-ports 128
```

Run the full 18-workload batch only after individual smoke tests and SRX logging
are confirmed:

```bash
sudo ./venv/bin/python deploy/srx_workload.py \
  --target <target-host> --src <generator-address> \
  --yes all --duration 10
```

The standalone `crawl` command is intentionally not part of `all`. Every command
supports `--help` and enforces its documented bounds.

> A zero process exit or green dashboard heatmap means **execution succeeded**.
> It does not prove that the SRX detected, blocked, or logged the stimulus.

## 7. Run live validation

Live tests are opt-in and can contact hardware, open listeners, capture packets,
and generate traffic. Review the selected tests and configuration first, then run:

```bash
sudo PROBE_CONFIG="$PWD/config/probe_config.yaml" \
  ./venv/bin/python -m pytest --live-srx
```

Correlate generator timestamps and 5-tuples with:

- SRX structured syslog events
- NETCONF session, screen, and IDP observations
- independent packet-capture evidence

Treat endpoint failures, successful traffic generation, policy blocks, and
validated detections as separate outcomes.

## 8. Install the workload dashboard

The dashboard has no built-in authentication. Keep it on loopback unless it is
behind an authenticated HTTPS reverse proxy.

### Local execution mode

On the generator host:

```bash
cd ~/srx
cp srx-dashboard/config.env.example srx-dashboard/config.env
chmod 600 srx-dashboard/config.env
${EDITOR:-vi} srx-dashboard/config.env
```

Leave `SRX_CLIENT_HOST` empty and set `SRX_TARGET` and, when needed, `SRX_SRC`.
Start it:

```bash
./scripts/srx-dashboard-start.sh
curl --fail http://127.0.0.1:8081/ >/dev/null
```

Open it through an SSH tunnel rather than exposing the backend:

```bash
ssh -N -L 8081:127.0.0.1:8081 <dashboard-host>
```

Then browse to <http://127.0.0.1:8081>.

### Remote execution mode

Install the complete generator dependencies on the remote generator first. On
the dashboard host, set these values in `srx-dashboard/config.env`:

```bash
export SRX_CLIENT_HOST=<ssh-destination>
export SRX_CLIENT_REPO=/absolute/path/to/srx
export SRX_TARGET=<target-host>
export SRX_SRC=<generator-address>
```

Requirements:

1. The dashboard account must reach the generator with SSH key authentication;
   password prompts cannot work in background execution.
2. Verify `ssh -o BatchMode=yes <ssh-destination> true` before starting the UI.
3. Root workloads use `sudo -n` on the generator. Prefer a narrowly scoped,
   operator-reviewed execution wrapper. The legacy sudoers helper permits general
   Python interpreters and is not a safe boundary for untrusted dashboard users.
4. Stopping the local SSH process only requests remote termination; verify the
   generator after interrupted runs.

### Persistent backend service

Prefer a service manager to cron. Create the unit below (for example with
`sudoedit /etc/systemd/system/srx-dashboard.service`) after replacing every
placeholder with the real absolute checkout path and a dedicated unprivileged
account:

```ini
# /etc/systemd/system/srx-dashboard.service
[Unit]
Description=SRX workload dashboard backend
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<service-user>
Group=<service-group>
WorkingDirectory=/absolute/path/to/srx
ExecStart=/bin/bash -lc 'source /absolute/path/to/srx/srx-dashboard/config.env; exec /absolute/path/to/srx/venv/bin/python /absolute/path/to/srx/srx-dashboard/dashboard.py'
Restart=on-failure
RestartSec=5
KillSignal=SIGINT
KillMode=mixed
TimeoutStopSec=70
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Inspect existing units before installing a new one, then:

```bash
sudo systemd-analyze verify /etc/systemd/system/srx-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable --now srx-dashboard.service
sudo systemctl status --no-pager srx-dashboard.service
```

Do not configure both this unit and the cron launcher. One startup owner avoids
duplicate processes and ambiguous restarts. With `NoNewPrivileges=true`, local
root-required workloads are intentionally unavailable; use remote mode with a
separately reviewed generator policy, or create a narrower privileged execution
boundary before changing that setting.

## 9. Publish the dashboard with authenticated HTTPS

For shared access, use a DNS name and a trusted certificate. Keep the backend at
`127.0.0.1:8081` and set its exact external origin:

```bash
export SRX_DASH_BIND=127.0.0.1
export SRX_DASH_PORT=8081
export SRX_DASH_PUBLIC_ORIGIN=https://dashboard.lab.example
```

Put those values in `srx-dashboard/config.env`, restart the backend, and configure
your existing reverse proxy. In Nginx's `http` context, define a request-rate
zone and a server block such as:

```nginx
limit_req_zone $binary_remote_addr zone=srx_dashboard:10m rate=120r/m;

server {
    listen 443 ssl;
    server_name dashboard.lab.example;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/private-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    auth_basic "SRX Dashboard";
    auth_basic_user_file /etc/nginx/srx-dashboard.htpasswd;
    client_max_body_size 16k;

    location / {
        limit_req zone=srx_dashboard burst=60 nodelay;
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_set_header Host $host;
        proxy_set_header Origin $http_origin;
        proxy_set_header Connection "";
    }
}
```

Create the authentication file with a private interactive prompt; never put a
password in a command argument, URL, environment file, or Git:

```bash
sudo htpasswd -c /etc/nginx/srx-dashboard.htpasswd <dashboard-user>
sudo chown root:www-data /etc/nginx/srx-dashboard.htpasswd
sudo chmod 0640 /etc/nginx/srx-dashboard.htpasswd
```

Install `apache2-utils` if `htpasswd` is unavailable. `www-data` is the default
Nginx worker group on Ubuntu; use the configured worker group if it differs.
Authenticate **every path**,
including status, history, run, stop, and event-stream endpoints. Restrict direct
access to the backend with loopback binding and host firewall rules.

Validate before reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Verify the complete boundary:

```bash
# Backend remains local only.
ss -lnt | grep '127.0.0.1:8081'

# Public endpoint requires authentication.
curl -sS -o /dev/null -w '%{http_code}\n' https://dashboard.lab.example/  # expected: 401
```

Also confirm in a browser that valid credentials load the dashboard, live SSE
logs work, and an intentionally wrong password returns 401 rather than 500.
Use a publicly trusted certificate when possible. A self-signed certificate is
appropriate only for a controlled lab whose clients explicitly trust it.

## 10. Install the optional ping/WiFi dashboard

This service is independent of SRX validation. It needs Python 3 and the system
`ping` command; the optional WiFi probe also needs SSH key access and `iw` on the
remote WiFi host. Unlike the workload dashboard, it currently listens on
`0.0.0.0`; it has no bind-address setting and no built-in authentication. Apply
host firewall rules that restrict TCP 8080 to loopback or an authenticated proxy
**before** starting it. Do not expose port 8080 directly to a LAN or the Internet.

```bash
cd ~/srx
cp pingapp/config.env.example pingapp/config.env
chmod 600 pingapp/config.env
${EDITOR:-vi} pingapp/config.env
./scripts/pingapp-start.sh
curl --fail http://127.0.0.1:8080/ >/dev/null
```

For shared access, use a separate HTTPS server name and proxy it to
`127.0.0.1:8080` with authentication on every path. Keep the firewall restriction
in place because the backend itself still listens on all host interfaces.

For persistence, create a dedicated systemd service analogous to the workload
dashboard. Because the tracked config files contain shell `export` statements,
source the file through a shell rather than using systemd `EnvironmentFile=`:

```ini
ExecStart=/bin/bash -lc 'source /absolute/path/to/srx/pingapp/config.env; exec /usr/bin/python3 /absolute/path/to/srx/pingapp/server.py'
```

Do not combine the unit with a cron watchdog.

## 11. Upgrade and rollback

Before changing a live installation:

1. Preserve local ignored configuration, state/history, captures, and logs.
2. Fetch and review the target tag or commit.
3. Run the offline suite against the new checkout.
4. Stop active workloads before restarting a dashboard.
5. Update one component at a time and repeat its health checks.

For a normal Git checkout with no local tracked changes:

```bash
cd ~/srx
git fetch --tags origin
git status --short
git switch --detach <reviewed-tag-or-commit>
./venv/bin/python -m pytest -m 'not requires_srx'
sudo systemctl restart srx-dashboard.service   # when that unit is installed
```

Rollback by switching back to the previously recorded commit and restarting the
same service. Never overwrite environment files or histories during an upgrade.

## 12. Troubleshooting

- **Target connection refused:** check target listeners and firewall scope.
- **Raw socket permission denied:** run only the documented root-required command
  with `sudo`; do not make the entire checkout writable by a service account.
- **Remote dashboard exits immediately:** verify SSH `BatchMode=yes`, repository
  path, virtual environment, and `sudo -n` policy on the generator.
- **Dashboard rejects requests:** ensure browser URL, `SRX_DASH_PUBLIC_ORIGIN`,
  proxy `Host`, and proxy `Origin` match exactly, including scheme and port.
- **SSE output buffers:** disable proxy buffering and retain the long read timeout.
- **Heatmap is green but no alert exists:** the heatmap reports execution status,
  not SRX detection evidence.
- **Live tests are skipped:** pass `--live-srx` explicitly and verify
  `PROBE_CONFIG` points to the intended file.
- **Browser tests fail:** rerun `./venv/bin/playwright install` and confirm the
  required OS libraries are installed.

More detail is available in [`RUNNING.md`](RUNNING.md),
[`deploy/README.md`](deploy/README.md), [`srx-dashboard/README.md`](srx-dashboard/README.md),
and [`pingapp/README.md`](pingapp/README.md).
