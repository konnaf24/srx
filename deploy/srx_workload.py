#!/usr/bin/env python3
"""
srx_workload.py — ad-hoc driver for the Juniper SRX detection-probe generators.

Run individual workloads (or all of them) against a target you OWN or are
AUTHORIZED to test. Wraps the repo's generators (l7_client, scan_gen,
packet_gen, load_gen) and actually emits traffic.

Run from the repo root (so `generators` / `validation` import), using the venv:

    sudo ./venv/bin/python srx_workload.py --target 84.254.1.45 all
    ./venv/bin/python srx_workload.py --target 1.2.3.4 http --port 80
    sudo ./venv/bin/python srx_workload.py --target 1.2.3.4 scan --type syn

Root is required for: scan (SYN/XMAS/FIN), flood, and all scapy packet
workloads (malformed/badcsum/ttl/frag/deny). Benign L7 + wrk + iperf3 do not.

--------------------------------------------------------------------------
SAFETY: scan / flood / malformed-packet workloads are ATTACK traffic. Only
run them against hosts you own or have WRITTEN permission to test. Doing so
against third-party systems is illegal in most jurisdictions. Aggressive
subcommands require confirmation unless you pass --yes.
--------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time

# Generators live in the repo; run this from the repo root.
try:
    from generators.l7_client import L7Client
    from generators.scan_gen import ScanGenerator
    from generators.packet_gen import PacketGenerator
    from generators.load_gen import LoadGenerator
except ImportError as exc:  # pragma: no cover
    sys.exit(
        f"Cannot import generators ({exc}).\n"
        "Run this from the srx repo root, e.g.:\n"
        "  cd ~/srx && ./venv/bin/python srx_workload.py --target <ip> all"
    )

AGGRESSIVE = {"scan", "flood", "malformed", "badcsum", "ttl", "frag", "deny", "all"}


def hdr(title: str) -> None:
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


def run_cmd(cmd: list[str], timeout: int = 180) -> int:
    print("$ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        print("  [ERR] binary not found on PATH")
        return 127
    except subprocess.TimeoutExpired:
        print("  [ERR] timed out")
        return 124
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    print(out[:2000] or "(no output)")
    return p.returncode


def emit(label: str, fn) -> None:
    """Call a generator method that returns a Stimulus, report the 5-tuple."""
    try:
        s = fn()
        print(f"  [OK] {label}: 5-tuple={s.five_tuple} expect={s.expected_event_type}")
    except Exception as exc:  # noqa: BLE001 - report any generator/socket error
        print(f"  [ERR] {label}: {type(exc).__name__}: {exc}")


def confirm(cmd_name: str, target: str, assume_yes: bool) -> None:
    if cmd_name not in AGGRESSIVE or assume_yes:
        return
    print(
        f"\n!! '{cmd_name}' generates ATTACK traffic against {target}.\n"
        "!! Only proceed if you OWN or are AUTHORIZED to test this host.\n"
    )
    if input("Type 'yes' to continue: ").strip().lower() != "yes":
        sys.exit("Aborted.")


# --------------------------- workload implementations ---------------------------
def do_http(a):
    hdr("HTTP GET (l7_client)")
    l7 = L7Client(a.target)
    emit(f"http_get {a.path}", lambda: l7.http_get(a.path, dst_port=a.port, send=True))


def do_dns(a):
    hdr("DNS query (l7_client)")
    l7 = L7Client(a.target)
    emit(f"dns_query {a.qname}", lambda: l7.dns_query(a.target, a.qname, send=True))


def do_handshake(a):
    hdr(f"TCP handshake :{a.port} (l7_client)")
    l7 = L7Client(a.target)
    emit(f"{a.app}:{a.port}", lambda: l7.tcp_handshake(a.port, a.app, send=True))


def do_eicar(a):
    hdr("EICAR over HTTP (l7_client)")
    l7 = L7Client(a.target)
    emit("eicar_http", lambda: l7.deliver_eicar_http(dst_port=a.port, send=True))


def do_gtube(a):
    hdr("GTUBE over HTTP (l7_client)")
    l7 = L7Client(a.target)
    emit("gtube_http", lambda: l7.deliver_gtube_http(dst_port=a.port, send=True))


def do_scan(a):
    hdr(f"nmap {a.type} scan (scan_gen)")
    run_cmd(ScanGenerator.build_nmap_cmd(a.target, a.type, max_ports=a.max_ports))


def do_flood(a):
    hdr(f"hping3 {a.type} flood — {a.count} pkts @ {a.rate}pps (scan_gen)")
    run_cmd(
        ScanGenerator.build_hping3_flood_cmd(
            a.target, a.type, a.port, count=a.count, rate_pps=a.rate
        )
    )


def do_malformed(a):
    hdr("Malformed SYN+FIN (packet_gen/scapy)")
    emit("malformed_flags", lambda: PacketGenerator(a.src, a.target).malformed_flags(a.port, send=True))


def do_badcsum(a):
    hdr("Bad checksum (packet_gen/scapy)")
    emit("bad_checksum", lambda: PacketGenerator(a.src, a.target).bad_checksum(a.port, send=True))


def do_ttl(a):
    hdr(f"Tiny TTL={a.ttl} (packet_gen/scapy)")
    emit("tiny_ttl", lambda: PacketGenerator(a.src, a.target).tiny_ttl(a.port, ttl=a.ttl, send=True))


def do_frag(a):
    hdr(f"Overlapping fragments x{a.count} (packet_gen/scapy)")
    emit("overlapping_fragments", lambda: PacketGenerator(a.src, a.target).overlapping_fragments(a.port, frag_count=a.count, send=True))


def do_deny(a):
    hdr(f"SYN to denied port :{a.port} (packet_gen/scapy)")
    emit("tcp_to_denied_port", lambda: PacketGenerator(a.src, a.target).tcp_to_denied_port(a.port, send=True))


def do_wrk(a):
    hdr(f"wrk load — {a.connections} conns / {a.threads} thr / {a.duration}s (load_gen)")
    run_cmd(
        LoadGenerator.build_wrk_cmd(a.url or f"http://{a.target}/", a.connections, a.threads, a.duration),
        timeout=a.duration + 30,
    )


def do_iperf(a):
    hdr(f"iperf3 -> {a.target}:{a.port} for {a.duration}s (load_gen)")
    run_cmd(
        LoadGenerator.build_iperf3_cmd(a.target, a.duration, a.parallel, a.port),
        timeout=a.duration + 30,
    )


def do_all(a):
    # Benign L7
    do_http(argparse.Namespace(**{**vars(a), "path": "/", "port": 80}))
    do_dns(argparse.Namespace(**{**vars(a), "qname": "example.com"}))
    do_handshake(argparse.Namespace(**{**vars(a), "port": 22, "app": "SSH"}))
    do_eicar(argparse.Namespace(**{**vars(a), "port": 80}))
    do_gtube(argparse.Namespace(**{**vars(a), "port": 80}))
    # Aggressive
    for st in ("syn", "xmas", "fin"):
        do_scan(argparse.Namespace(**{**vars(a), "type": st, "max_ports": 1024}))
    for ft, port in (("syn", 80), ("icmp", 0), ("udp", 53)):
        do_flood(argparse.Namespace(**{**vars(a), "type": ft, "port": port, "count": 2000, "rate": 500}))
    do_malformed(argparse.Namespace(**{**vars(a), "port": 80}))
    do_badcsum(argparse.Namespace(**{**vars(a), "port": 80}))
    do_ttl(argparse.Namespace(**{**vars(a), "port": 80, "ttl": 1}))
    do_frag(argparse.Namespace(**{**vars(a), "port": 80, "count": 8}))
    do_deny(argparse.Namespace(**{**vars(a), "port": 9}))
    # Load
    do_wrk(argparse.Namespace(**{**vars(a), "url": None, "connections": 100, "threads": 4, "duration": 5}))
    do_iperf(argparse.Namespace(**{**vars(a), "port": 5201, "duration": 5, "parallel": 4}))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", required=True, help="Destination IP/host (must be yours/authorized)")
    p.add_argument("--src", default=None, help="Source IP for crafted packets (default: target)")
    p.add_argument("--yes", action="store_true", help="Skip the aggressive-workload confirmation prompt")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("all", help="Run every workload (benign + aggressive)")
    sp.set_defaults(func=do_all)

    sp = sub.add_parser("http", help="HTTP GET")
    sp.add_argument("--path", default="/"); sp.add_argument("--port", type=int, default=80)
    sp.set_defaults(func=do_http)

    sp = sub.add_parser("dns", help="UDP DNS query")
    sp.add_argument("--qname", default="example.com")
    sp.set_defaults(func=do_dns)

    sp = sub.add_parser("handshake", help="TCP handshake + banner grab (FTP/SSH/...)")
    sp.add_argument("--port", type=int, default=22); sp.add_argument("--app", default="SSH")
    sp.set_defaults(func=do_handshake)

    sp = sub.add_parser("eicar", help="EICAR test file over HTTP")
    sp.add_argument("--port", type=int, default=80); sp.set_defaults(func=do_eicar)

    sp = sub.add_parser("gtube", help="GTUBE spam test string over HTTP")
    sp.add_argument("--port", type=int, default=80); sp.set_defaults(func=do_gtube)

    sp = sub.add_parser("scan", help="[root] nmap TCP scan")
    sp.add_argument("--type", choices=["syn", "xmas", "fin", "null", "ack"], default="syn")
    sp.add_argument("--max-ports", type=int, default=1024); sp.set_defaults(func=do_scan)

    sp = sub.add_parser("flood", help="[root] hping3 bounded flood")
    sp.add_argument("--type", choices=["syn", "icmp", "udp"], default="syn")
    sp.add_argument("--port", type=int, default=80)
    sp.add_argument("--count", type=int, default=2000); sp.add_argument("--rate", type=int, default=500)
    sp.set_defaults(func=do_flood)

    sp = sub.add_parser("malformed", help="[root] scapy SYN+FIN illegal flags")
    sp.add_argument("--port", type=int, default=80); sp.set_defaults(func=do_malformed)

    sp = sub.add_parser("badcsum", help="[root] scapy bad TCP checksum")
    sp.add_argument("--port", type=int, default=80); sp.set_defaults(func=do_badcsum)

    sp = sub.add_parser("ttl", help="[root] scapy tiny TTL")
    sp.add_argument("--port", type=int, default=80); sp.add_argument("--ttl", type=int, default=1)
    sp.set_defaults(func=do_ttl)

    sp = sub.add_parser("frag", help="[root] scapy overlapping fragments")
    sp.add_argument("--port", type=int, default=80); sp.add_argument("--count", type=int, default=8)
    sp.set_defaults(func=do_frag)

    sp = sub.add_parser("deny", help="[root] scapy SYN to a denied port")
    sp.add_argument("--port", type=int, default=9); sp.set_defaults(func=do_deny)

    sp = sub.add_parser("wrk", help="wrk HTTP session-volume load")
    sp.add_argument("--url", default=None); sp.add_argument("--connections", type=int, default=100)
    sp.add_argument("--threads", type=int, default=4); sp.add_argument("--duration", type=int, default=5)
    sp.set_defaults(func=do_wrk)

    sp = sub.add_parser("iperf", help="iperf3 throughput (needs iperf3 -s on target)")
    sp.add_argument("--port", type=int, default=5201); sp.add_argument("--duration", type=int, default=5)
    sp.add_argument("--parallel", type=int, default=4); sp.set_defaults(func=do_iperf)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.src is None:
        args.src = args.target
    confirm(args.cmd, args.target, args.yes)
    start = time.time()
    args.func(args)
    hdr(f"DONE in {time.time() - start:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
