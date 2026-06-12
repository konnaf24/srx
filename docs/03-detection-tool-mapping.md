# 03 — Detection-to-tool mapping

This is the master table that drives the test suite. Each row is a **detection
target**: a thing the SRX should detect/log, the Junos log/event it should
emit, the best generator to stimulate it, the concrete stimulus, and the
independent ground-truth check used to confirm the traffic actually crossed the
SRX.

The pytest modules parametrize over these rows (see `tests/`).

| # | Detection target | Junos log / event | Best generator | Concrete stimulus | Ground-truth check |
|---|---|---|---|---|---|
| 1 | Session create/close | `RT_FLOW_SESSION_CREATE` / `_CLOSE` | curl / scapy | single TCP connection | `show security flow session` + syslog 5-tuple |
| 2 | Session deny | `RT_FLOW_SESSION_DENY` | scapy / hping3 | packet to denied port | deny event present, **no** create event |
| 3 | TCP scan | `RT_IDP` / screen | nmap / hping3 | `nmap -sS` / `-sX` / `-sF` | screen scan counter + per-scan log |
| 4 | Malformed packets | screen / IDP anomaly | scapy | bad flags / checksums, tiny TTL | anomaly event subtype |
| 5 | Fragmentation | screen (teardrop / frag) | scapy | overlapping / oversized fragments | frag-attack event |
| 6 | Flood (SYN/ICMP/UDP) | screen flood | hping3 / scapy | `hping3 --flood -S` (controlled) | flood threshold event |
| 7 | IDP signature match | `RT_IDP_ATTACK_LOG` | scapy / custom | EICAR over HTTP, GTUBE, test sigs | IDP event with signature ID |
| 8 | App-ID generic | `APPTRACK_SESSION_*` | curl / custom | raw HTTP / DNS / FTP / SSH | AppTrack app-name |
| 9 | App-ID web apps | `APPTRACK` app-name | Playwright | real navigation | app classified correctly |
| 10 | URL / web filtering | `WEBFILTER_URL_*` | Playwright | navigate categorized / blocked URL | category + block-page |
| 11 | SSL proxy / decryption | SSL-proxy logs | Playwright | real TLS handshake, varied SNI | cert / SNI fields + decryption |
| 12 | AppFW | `APPTRACK` + policy | Playwright / curl | app violating app-fw rule | block + app-fw event |
| 13 | Content filtering | `CONTENT_FILTERING_*` | curl / Playwright | blocked MIME / EICAR | content-filter block |
| 14 | Antivirus / UTM | `AV_VIRUS_DETECTED` | curl | EICAR file over HTTP | AV event `name=EICAR` |
| 15 | Session volume | flow counters | wrk / iperf3 | high concurrent connections | session-count threshold |
| 16 | Throughput | flow stats / J-Flow | iperf3 | sustained Gbps stream | byte counters |
| 17 | Flow / IPFIX export | J-Flow / IPFIX | iperf3 + scapy | known flow count / sizes | exported records match |

## How to read a row

- **Detection target** — the security behavior being validated.
- **Junos log / event** — the telemetry the SRX must emit (see
  `02-telemetry-sources.md`).
- **Best generator** — the lowest layer that can produce the stimulus
  *deterministically* (see `04-workload-layer-rationale.md` for why the lowest
  capable layer is preferred and why browsers are reserved for rows 9–12).
- **Concrete stimulus** — the exact action taken. All attack stimuli are
  synthetic/safe (EICAR, GTUBE, standard nmap scan types).
- **Ground-truth check** — the independent confirmation (egress pcap and/or
  NETCONF device state) used to disambiguate a missing log from missing
  traffic.

## Coverage notes

- Rows **1–8, 13–14, 17** can be driven from L3/L4 + scriptable L7 generators
  (scapy / hping3 / nmap / curl / custom sockets) for byte-exact, repeatable
  stimuli.
- Rows **9–12** require a real browser (Playwright) because they validate
  browser-driven L7 behavior: web-app App-ID, URL filtering UX, SSL-proxy on a
  real TLS handshake, and AppFW on real app traffic.
- Rows **15–17** are scale/volume tests driven by wrk / iperf3.
