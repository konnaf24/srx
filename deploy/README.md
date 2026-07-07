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
| dnsmasq | 53 | DNS query workload (bound to the public IP) |
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

Subcommands: `all http dns handshake eicar gtube scan flood malformed badcsum
ttl frag deny wrk iperf`. Each subcommand's `--help` lists its options.

Root is required for `scan`, `flood`, and the scapy packet workloads
(`malformed/badcsum/ttl/frag/deny`); benign L7 + `wrk`/`iperf` are not.
