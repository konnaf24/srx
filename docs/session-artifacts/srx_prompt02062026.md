# srx_prompt02062026

Session transcript — SRX Transit Security Detection Probe deployment & workload run
Date: 2026-07-02

Hosts:
- Generator host: 84.254.1.46 (Ubuntu 24.04, user kostas)
- Target host:    84.254.1.45 (Ubuntu 24.04, user kostas) — reverse DNS ipa45.1.tellas.gr

Repo: https://github.com/konnaf24/srx

---

## Thread summary

### 1. Clone
Cloned https://github.com/konnaf24/srx locally to
`/home/kostas/Downloads/githubcopilotapp1/srx`.

### 2. "What does it require to deploy locally + all tools?"
The project is the **Juniper SRX Transit Security Detection Probe** — a pytest-based
telemetry-validation suite (not a server app). It generates known network stimuli,
collects the telemetry a Juniper SRX firewall emits, and correlates them.

Requirements:
- Python + venv; `pip install -r requirements.txt`
- Python packages: scapy 2.5.0, requests 2.31.0, PyYAML 6.0.1, junos-eznc 2.7.1,
  playwright 1.44.0, pytest 8.2.0
- `playwright install` (browser binaries)
- System binaries (NOT pip-installable): nmap, hping3, wrk, iperf3, tshark (tcpdump fallback)
- For a full live run: a real Juniper SRX (NETCONF), syslog collector, egress capture
  iface, root privileges
- Config: `cp config/probe_config.example.yaml config/probe_config.yaml`

Run:
- Offline logic tests: `pytest -m "not requires_srx"`
- Full live: `sudo PROBE_CONFIG=config/probe_config.yaml pytest`

### 3. Deploy to remote Linux (84.254.1.46)
Connected via SSH (paramiko; sshpass unavailable). Installed:
- apt: nmap, hping3, wrk, iperf3, tshark, python3-venv, python3-pip, git
  (non-interactive; preseeded wireshark-common setuid + iperf3 no-daemon)
- Cloned repo to ~/srx
- venv + `pip install -r requirements.txt`
- `playwright install` + Ubuntu 24.04 chromium runtime libs (t64/updated package names,
  because playwright 1.44 install-deps targets old names: libasound2->libasound2t64,
  libicu70->libicu74, libffi7->libffi8)
- `cp` config example -> probe_config.yaml
- Verified: Chromium launches (125.0.6422.26); `pytest -m "not requires_srx"` = 30 passed, 21 deselected

### 4. "What does tests passed mean? I want to run tools with workloads against destinations"
Clarified: "30 passed" = offline pure-Python correlator/assertion logic; NO real traffic sent.
The generators are Python library classes (send=True/run=True to emit traffic), no CLI.
Two risk categories:
- Benign: l7_client (HTTP/DNS/FTP/SSH handshakes, EICAR/GTUBE), load_gen (wrk/iperf3)
- Aggressive: scan_gen (nmap scans, hping3 floods), packet_gen (malformed/frag, scapy)

User asked to run "everything against arbitrary internet destinations" — DECLINED
(unauthorized scans/floods against third-party hosts are illegal/harmful). Offered to run
against hosts the user owns/is authorized to test.

### 5. Run against 84.254.1.45 (user-owned)
Built `run_workload.py` driver, ran the full matrix from .46 -> .45. All generators fired.
Only SSH/22 was open on the target initially, so HTTP/DNS/FTP/EICAR/GTUBE/wrk/iperf3
returned "connection refused" (no services), while scans/floods/scapy packets sent fine.

### 6. Built ad-hoc CLI: srx_workload.py
Self-contained argparse CLI with per-workload subcommands
(all/http/dns/handshake/eicar/gtube/scan/flood/malformed/badcsum/ttl/frag/deny/wrk/iperf),
tunable options, `--target`/`--src`/`--yes`, and a confirmation gate on aggressive workloads.
Deployed to ~/srx/srx_workload.py on .46 (also saved to session files/).

Usage:
    cd ~/srx
    sudo ./venv/bin/python srx_workload.py --target 84.254.1.45 --yes all
    ./venv/bin/python srx_workload.py --target <ip> http --port 80
    sudo ./venv/bin/python srx_workload.py --target <ip> scan --type xmas

### 7. Set up server side on 84.254.1.45 so workloads complete
Connected to .45, installed & configured:
- nginx (port 80) + /var/www/html/eicar.com (EICAR string) + index.html
- dnsmasq (port 53, bound to 84.254.1.45 public IP, bind-interfaces, so it coexists
  with systemd-resolved on loopback)
- vsftpd (port 21)
- iperf3 server (port 5201, systemd)
- ufw inactive (no firewall blocking)

Re-ran full suite .46 -> .45. All green:
- HTTP GET 200, DNS answered, SSH handshake, EICAR + GTUBE delivered
- nmap now sees 21,22,53,80 open
- hping3 SYN/ICMP/UDP floods: 2000 pkts each
- scapy malformed/badcsum/ttl/frag/deny sent
- wrk: 133,302 requests in 5s, 26,563 req/s, 32 MB
- iperf3: connected, ~3.5 Gbit/s per stream (4 streams)

Note: in `all` mode scapy defaults --src to target; pass `--src 84.254.1.46` to stamp
the real generator IP.

---

## Final state

Generator host 84.254.1.46:
- ~/srx (repo) + ~/srx/venv + all Python deps + playwright chromium
- system tools: nmap, hping3, wrk, iperf3, tshark
- ~/srx/srx_workload.py (ad-hoc CLI driver)
- config/probe_config.yaml

Target host 84.254.1.45:
- nginx:80 (+ eicar.com), dnsmasq:53, vsftpd:21, iperf3:5201

## Re-run command
    ssh kostas@84.254.1.46
    cd ~/srx
    sudo ./venv/bin/python srx_workload.py --target 84.254.1.45 --src 84.254.1.46 --yes all

## Security notes
- SSH passwords were shared in plaintext during this session — rotate them and switch to
  key-based auth.
- Aggressive workloads (scans/floods/malformed packets) are attack traffic; only run them
  against hosts you own or are authorized to test.
