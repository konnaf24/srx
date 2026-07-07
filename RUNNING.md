# RUNNING — end-to-end guide

How to stand up the two-host lab and run the SRX detection-probe workloads.
This complements the top-level `README.md` (design) and `deploy/README.md`
(script reference).

> **Authorization notice**
> The scan / flood / malformed-packet workloads generate **attack traffic**.
> Only run them between hosts you **own** or are **authorized** to test.
> Doing so against third-party systems is illegal in most jurisdictions.

---

## 0. Topology

```
[ generator host ]  ── workloads ──►  [ target host ]
  runs the probe                        serves the endpoints
  e.g. 10.10.10.46                      e.g. 10.10.10.45
```

- **Generator host** — has the repo, Python venv, and the CLI tools
  (`nmap`, `hping3`, `wrk`, `iperf3`, `tshark`). It *sends* the traffic.
- **Target host** — runs `nginx`, `dnsmasq`, `vsftpd`, `iperf3` so every
  workload has something to talk to. It *receives* the traffic.

Both are Ubuntu 24.04 in the reference lab. `sudo` is required on both.

---

## 1. Provision the target host

On the host that will **receive** traffic (e.g. `10.10.10.45`):

```bash
git clone https://github.com/konnaf24/srx ~/srx
cd ~/srx
sudo BIND_IP=<this-host-public-ip> ./deploy/setup_target.sh
```

This installs and starts:

| Service | Port | Used by |
| --- | --- | --- |
| nginx (+ `/eicar.com`) | 80 | http, eicar, gtube, wrk |
| dnsmasq (public-IP bind) | 53 | dns |
| vsftpd | 21 | handshake (FTP) |
| iperf3 server | 5201 | iperf |

Verify:

```bash
ss -tulnp | grep -E ':(21|53|80|5201) '
```

---

## 2. Provision the generator host

On the host that will **send** traffic (e.g. `10.10.10.46`):

```bash
git clone https://github.com/konnaf24/srx ~/srx
cd ~/srx
sudo ./deploy/setup_generator.sh
```

This installs the system binaries, builds the venv, installs the Python deps +
Playwright browser, seeds `config/probe_config.yaml`, and runs the offline
logic tests (`pytest -m "not requires_srx"`), which should report all passed.

---

## 3. Run the workloads

From the repo root on the **generator host**, using the venv:

### Run everything

```bash
cd ~/srx
sudo ./venv/bin/python deploy/srx_workload.py \
    --target 10.10.10.45 \
    --src    10.10.10.46 \
    --yes all
```

- `--target` — the host from step 1.
- `--src` — this host's IP, stamped onto crafted (scapy) packets.
- `--yes` — skip the confirmation prompt on aggressive workloads.
- Aggressive workloads (`scan`, `flood`, `malformed`, `badcsum`, `ttl`,
  `frag`, `deny`) need **root**; that's why the whole run uses `sudo`.

### Run a single workload

```bash
# benign L7 (no root needed)
./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 http --port 80
./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 dns  --qname example.com
./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 eicar
./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 iperf --duration 5

# aggressive (root)
sudo ./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 scan  --type xmas
sudo ./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 flood --type syn --count 2000 --rate 500
sudo ./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 --src 10.10.10.46 frag --count 8
```

### All subcommands

`all http dns handshake eicar gtube scan flood malformed badcsum ttl frag deny wrk iperf`

Each supports `--help`, e.g.:

```bash
./venv/bin/python deploy/srx_workload.py --target 10.10.10.45 flood --help
```

---

## 4. What "success" looks like

Each workload prints either the crafted 5-tuple (`[OK] ...`) or the wrapped
tool's output. A fully-served target yields, for example:

```
✅ HTTP GET → 200
✅ DNS query → answered
✅ EICAR + GTUBE over HTTP → delivered
✅ nmap SYN/XMAS/FIN → ports 21,22,53,80 open
✅ hping3 SYN/ICMP/UDP flood → 2000 pkts each
✅ scapy malformed / badcsum / ttl / frag / deny → sent
✅ wrk  → tens of thousands of requests
✅ iperf3 → multi-Gbit/s across parallel streams
```

`Connection refused` on http/dns/ftp/wrk/iperf means the corresponding service
isn't up on the target — re-check step 1.

---

## 5. Notes & troubleshooting

- **This lab has no SRX in the path**, so traffic is generated but not
  correlated. With a real SRX in transit, point the collectors at it via
  `config/probe_config.yaml` and run `sudo PROBE_CONFIG=config/probe_config.yaml pytest`.
- **AppImage / FUSE** and unrelated app tooling are not needed here.
- **`hping3`/`nmap` need root** for raw sockets; run those under `sudo`.
- **Firewall** — ensure the target's `ufw` (or cloud security group) allows
  ports 21/53/80/5201 from the generator.
- **Rotate credentials** used to set up the hosts; prefer SSH keys over
  passwords.
