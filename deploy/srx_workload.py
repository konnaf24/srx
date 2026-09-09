#!/usr/bin/env python3
"""
srx_workload.py — ad-hoc driver for the Juniper SRX detection-probe generators.

Run individual workloads (or all of them) against a target you OWN or are
AUTHORIZED to test. Wraps the repo's generators (l7_client, scan_gen,
packet_gen, load_gen) and actually emits traffic.

Run from the repo root (so `generators` / `validation` import), using the venv:

    sudo ./venv/bin/python srx_workload.py --target 10.10.10.45 all
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
import socket
import subprocess
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, fields
from functools import wraps
from pathlib import Path
from threading import Event
from typing import Callable

# Make direct execution (`python deploy/srx_workload.py`) resolve repo modules.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from generators.l7_client import L7Client
    from generators.scan_gen import ScanGenerator
    from generators.packet_gen import PacketGenerator
    from generators.load_gen import LoadGenerator, WorkloadLimits, DEFAULT_LIMITS, bounded_int
except ImportError as exc:  # pragma: no cover
    sys.exit(
        f"Cannot import generators ({exc}).\n"
        "Run this from the srx repo root, e.g.:\n"
        "  cd ~/srx && ./venv/bin/python deploy/srx_workload.py "
        "--target <ip> all"
    )

AGGRESSIVE = {"scan", "flood", "malformed", "badcsum", "ttl", "frag", "deny", "all"}
CRAFTED = {"malformed", "badcsum", "ttl", "frag", "deny", "all"}
DEFAULT_DURATION_S = 60


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _limits(a: argparse.Namespace) -> WorkloadLimits:
    return getattr(a, "limits", DEFAULT_LIMITS)


def validate_args(a: argparse.Namespace, command: str | None = None) -> None:
    """Validate all numeric controls before routing, prompting or sending."""
    limits = _limits(a)
    command = command or a.cmd
    if hasattr(a, "port"):
        bounded_int("port", a.port, 65535, 0 if command == "flood" and a.type == "icmp" else 1)
    if command == "all":
        bounded_int("duration", a.duration, limits.max_duration_s)
    elif command == "scan":
        limits.scan(a.max_ports)
    elif command == "flood":
        limits.flood(a.type, a.port, a.count, a.rate)
    elif command == "frag":
        bounded_int("fragment count", a.count, limits.max_fragments)
    elif command == "ttl":
        bounded_int("ttl", a.ttl, 255)
    elif command == "wrk":
        limits.wrk(a.connections, a.threads, a.duration)
        LoadGenerator._http_port(a.url or f"http://{a.target}/")
    elif command == "iperf":
        limits.iperf(a.duration, a.parallel, a.port)


def validated(func):
    """Also guard callers that bypass argparse and invoke a sender directly."""
    @wraps(func)
    def wrapped(a):
        validate_args(a, func.__name__.removeprefix("do_"))
        return func(a)
    return wrapped


class WorkloadParser(argparse.ArgumentParser):
    def parse_args(self, args=None, namespace=None):
        parsed = super().parse_args(args, namespace)
        try:
            parsed.limits = WorkloadLimits(**{
                field.name: getattr(parsed, f"limit_{field.name}")
                for field in fields(WorkloadLimits)
            })
            validate_args(parsed)
            if parsed.cmd == "all":
                build_all_workloads(parsed)
        except ValueError as exc:
            self.error(str(exc))
        return parsed


def resolve_source_ip(target: str) -> str:
    """Return the source address selected by the route to target."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((target, 9))
        return sock.getsockname()[0]


@dataclass(frozen=True)
class Workload:
    name: str
    func: Callable[[argparse.Namespace], int]
    args: argparse.Namespace


@dataclass(frozen=True)
class WorkloadResult:
    name: str
    returncode: int
    elapsed_s: float
    error: str = ""
    detection_status: str = "not_evaluated"
    metadata: dict = field(default_factory=dict)

    @property
    def execution_status(self) -> str:
        return "succeeded" if self.returncode == 0 else "failed"


class CommandResult(int):
    """An int-compatible exit code retaining captured execution diagnostics."""
    def __new__(cls, returncode: int, *, error: str = "", output: str = "", metadata=None):
        result = super().__new__(cls, returncode)
        result.error = error
        result.output = output
        result.metadata = metadata or {}
        return result


def hdr(title: str) -> None:
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)


def run_cmd(
    cmd: list[str],
    timeout: int = 180,
    success_output: str | None = None,
) -> int:
    print("$ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        print("  [ERR] binary not found on PATH")
        return CommandResult(127, error=f"binary not found on PATH: {exc}")
    except subprocess.TimeoutExpired as exc:
        print("  [ERR] timed out")
        return CommandResult(124, error=f"timed out after {timeout}s; stdout={exc.stdout!r}; stderr={exc.stderr!r}")
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    print(out[:2000] or "(no output)")
    # success_output is retained for caller compatibility, never an exit override.
    return CommandResult(
        p.returncode, error=out if p.returncode else "", output=out,
        metadata={"stdout": p.stdout, "stderr": p.stderr, "returncode": p.returncode,
                  "execution_status": "succeeded" if p.returncode == 0 else "failed",
                  "detection_status": "not_evaluated"},
    )


def emit(label: str, fn) -> int:
    """Call a generator method that returns a Stimulus, report the 5-tuple."""
    stimulus = fn()
    print(
        f"  [EXECUTED] {label}: 5-tuple={stimulus.five_tuple} "
        f"expect={stimulus.expected_event_type}; detection=not_evaluated"
    )
    if "result" in stimulus.metadata:
        measurements = {key: value for key, value in stimulus.metadata["result"].items() if key != "raw"}
        print(f"  measurements={measurements}")
    return CommandResult(0, metadata=stimulus.metadata)


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
@validated
def do_http(a):
    hdr("HTTP GET (l7_client)")
    l7 = L7Client(a.target)
    return emit(
        f"http_get {a.path}",
        lambda: l7.http_get(a.path, dst_port=a.port, send=True),
    )


@validated
def do_dns(a):
    hdr("DNS query (l7_client)")
    l7 = L7Client(a.target)
    return emit(
        f"dns_query {a.qname}",
        lambda: l7.dns_query(a.target, a.qname, send=True),
    )


@validated
def do_handshake(a):
    hdr(f"TCP handshake :{a.port} (l7_client)")
    l7 = L7Client(a.target)
    return emit(
        f"{a.app}:{a.port}",
        lambda: l7.tcp_handshake(a.port, a.app, send=True),
    )


@validated
def do_eicar(a):
    hdr("EICAR over HTTP (l7_client)")
    l7 = L7Client(a.target)
    return emit(
        "eicar_http",
        lambda: l7.deliver_eicar_http(dst_port=a.port, send=True),
    )


@validated
def do_gtube(a):
    hdr("GTUBE over HTTP (l7_client)")
    l7 = L7Client(a.target)
    return emit(
        "gtube_http",
        lambda: l7.deliver_gtube_http(dst_port=a.port, send=True),
    )


@validated
def do_scan(a):
    hdr(f"nmap {a.type} scan (scan_gen)")
    return run_cmd(
        ScanGenerator.build_nmap_cmd(a.target, a.type, max_ports=a.max_ports, limits=_limits(a)),
        timeout=_limits(a).max_duration_s + 30,
    )


@validated
def do_flood(a):
    hdr(f"hping3 {a.type} flood — {a.count} pkts @ {a.rate}pps (scan_gen)")
    return run_cmd(
        ScanGenerator.build_hping3_flood_cmd(
            a.target, a.type, a.port, count=a.count, rate_pps=a.rate, limits=_limits(a)
        ),
        timeout=_limits(a).max_duration_s + 30,
    )


@validated
def do_malformed(a):
    hdr("Malformed SYN+FIN (packet_gen/scapy)")
    return emit(
        "malformed_flags",
        lambda: PacketGenerator(a.src, a.target).malformed_flags(a.port, send=True),
    )


@validated
def do_badcsum(a):
    hdr("Bad checksum (packet_gen/scapy)")
    return emit(
        "bad_checksum",
        lambda: PacketGenerator(a.src, a.target).bad_checksum(a.port, send=True),
    )


@validated
def do_ttl(a):
    hdr(f"Tiny TTL={a.ttl} (packet_gen/scapy)")
    return emit(
        "tiny_ttl",
        lambda: PacketGenerator(a.src, a.target).tiny_ttl(
            a.port, ttl=a.ttl, send=True
        ),
    )


@validated
def do_frag(a):
    hdr(f"Overlapping fragments x{a.count} (packet_gen/scapy)")
    return emit(
        "overlapping_fragments",
        lambda: PacketGenerator(a.src, a.target).overlapping_fragments(
            a.port, frag_count=a.count, send=True
        ),
    )


@validated
def do_deny(a):
    hdr(f"SYN to denied port :{a.port} (packet_gen/scapy)")
    return emit(
        "tcp_to_denied_port",
        lambda: PacketGenerator(a.src, a.target).tcp_to_denied_port(
            a.port, send=True
        ),
    )


@validated
def do_wrk(a):
    hdr(f"wrk load — {a.connections} conns / {a.threads} thr / {a.duration}s (load_gen)")
    return emit("wrk", lambda: LoadGenerator(a.target, limits=_limits(a)).session_volume(
        a.url or f"http://{a.target}/", a.connections, a.threads, a.duration, run=True,
    ))


@validated
def do_iperf(a):
    hdr(f"iperf3 -> {a.target}:{a.port} for {a.duration}s (load_gen)")
    return emit("iperf3", lambda: LoadGenerator(a.target, limits=_limits(a)).throughput(
        duration_s=a.duration, parallel=a.parallel, port=a.port, run=True,
    ))


def _args(a: argparse.Namespace, **overrides) -> argparse.Namespace:
    return argparse.Namespace(**{**vars(a), **overrides})


def build_all_workloads(a: argparse.Namespace) -> list[Workload]:
    """Build the complete workload suite without starting traffic."""
    workloads = [
        Workload("http", do_http, _args(a, path="/", port=80)),
        Workload("dns", do_dns, _args(a, qname="probe.lab")),
        Workload("handshake-ftp", do_handshake, _args(a, port=21, app="FTP")),
        Workload("eicar", do_eicar, _args(a, port=80)),
        Workload("gtube", do_gtube, _args(a, port=80)),
    ]
    workloads.extend(
        Workload(
            f"scan-{scan_type}",
            do_scan,
            _args(a, type=scan_type, max_ports=1024),
        )
        for scan_type in ("syn", "xmas", "fin")
    )
    workloads.extend(
        Workload(
            f"flood-{flood_type}",
            do_flood,
            _args(
                a,
                type=flood_type,
                port=port,
                count=2000,
                rate=500,
            ),
        )
        for flood_type, port in (("syn", 80), ("icmp", 0), ("udp", 53))
    )
    workloads.extend(
        [
            Workload("malformed", do_malformed, _args(a, port=80)),
            Workload("bad-checksum", do_badcsum, _args(a, port=80)),
            Workload("tiny-ttl", do_ttl, _args(a, port=80, ttl=1)),
            Workload("fragments", do_frag, _args(a, port=80, count=8)),
            Workload("denied-port", do_deny, _args(a, port=9)),
            Workload(
                "wrk",
                do_wrk,
                _args(
                    a,
                    url=None,
                    connections=100,
                    threads=4,
                    duration=a.duration,
                ),
            ),
            Workload(
                "iperf3",
                do_iperf,
                _args(a, port=5201, duration=a.duration, parallel=4),
            ),
        ]
    )
    bounded_int("concurrent workloads", len(workloads), _limits(a).max_workloads)
    for workload in workloads:
        validate_args(workload.args, workload.func.__name__.removeprefix("do_"))
    return workloads


def _run_workload(workload: Workload) -> WorkloadResult:
    start = time.monotonic()
    error = ""
    metadata = {}
    try:
        returncode = workload.func(workload.args)
        if not isinstance(returncode, int) or isinstance(returncode, bool):
            raise TypeError("workload must return an integer exit code")
        metadata = getattr(returncode, "metadata", {})
        error = getattr(returncode, "error", "")
        if returncode != 0 and not error:
            error = f"process exited with status {returncode}"
    except Exception as exc:
        returncode = 1
        if isinstance(exc, subprocess.CalledProcessError):
            returncode = exc.returncode
        elif isinstance(exc, subprocess.TimeoutExpired):
            returncode = 124
        elif isinstance(exc, FileNotFoundError):
            returncode = 127
        error = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            error += f"; stdout={exc.stdout!r}; stderr={exc.stderr!r}"
    return WorkloadResult(
        name=workload.name, returncode=int(returncode),
        elapsed_s=time.monotonic() - start, error=error, metadata=metadata,
    )


def run_concurrently(
    workloads: list[Workload], *, limits: WorkloadLimits = DEFAULT_LIMITS,
) -> list[WorkloadResult]:
    """Start every workload concurrently and collect every result."""
    if not workloads:
        return []

    bounded_int("concurrent workloads", len(workloads), limits.max_workloads)
    # Fail the whole preflight before submitting any sender, not halfway through.
    for workload in workloads:
        if workload.func.__name__.startswith("do_"):
            validate_args(workload.args, workload.func.__name__.removeprefix("do_"))
    start_gate = Event()

    def run_after_release(workload: Workload) -> WorkloadResult:
        start_gate.wait()
        return _run_workload(workload)

    results: list[WorkloadResult] = []
    with ThreadPoolExecutor(
        max_workers=len(workloads),
        thread_name_prefix="srx-workload",
    ) as executor:
        futures: dict[Future[WorkloadResult], Workload] = {
            executor.submit(run_after_release, workload): workload
            for workload in workloads
        }
        start_gate.set()
        for future in as_completed(futures):
            results.append(future.result())
    return results


@validated
def do_all(a):
    workloads = build_all_workloads(a)
    hdr(
        f"STARTING {len(workloads)} CONCURRENT WORKLOADS "
        f"({a.duration}s sustained duration)"
    )
    results = run_concurrently(workloads, limits=_limits(a))
    failures = [result for result in results if result.returncode != 0]

    hdr("WORKLOAD SUMMARY")
    for result in sorted(results, key=lambda item: item.name):
        status = result.execution_status.upper()
        detail = f" - {result.error}" if result.error else ""
        print(
            f"[{status}] {result.name}: rc={result.returncode} "
            f"elapsed={result.elapsed_s:.1f}s detection={result.detection_status}{detail}"
        )
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    p = WorkloadParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", required=True, help="Destination IP/host (must be yours/authorized)")
    p.add_argument(
        "--src",
        default=None,
        help="Source IP for crafted packets (default: address routed to target)",
    )
    p.add_argument("--yes", action="store_true", help="Skip the aggressive-workload confirmation prompt")
    for field in fields(WorkloadLimits):
        p.add_argument(
            "--limit-" + field.name.removeprefix("max_").replace("_", "-"),
            dest=f"limit_{field.name}", type=positive_int,
            default=getattr(DEFAULT_LIMITS, field.name),
            help=f"Authorized-lab ceiling for {field.name} (default: %(default)s)",
        )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser(
        "all",
        help="Run every workload concurrently (benign + aggressive)",
    )
    sp.add_argument(
        "--duration",
        type=positive_int,
        default=DEFAULT_DURATION_S,
        help="Sustained wrk/iperf3 duration in seconds (default: 60)",
    )
    sp.set_defaults(func=do_all)

    sp = sub.add_parser("http", help="HTTP GET")
    sp.add_argument("--path", default="/"); sp.add_argument("--port", type=int, default=80)
    sp.set_defaults(func=do_http)

    sp = sub.add_parser("dns", help="UDP DNS query")
    sp.add_argument("--qname", default="probe.lab")
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
    sp.add_argument("--threads", type=int, default=4); sp.add_argument("--duration", type=positive_int, default=DEFAULT_DURATION_S)
    sp.set_defaults(func=do_wrk)

    sp = sub.add_parser("iperf", help="iperf3 throughput (needs iperf3 -s on target)")
    sp.add_argument("--port", type=int, default=5201); sp.add_argument("--duration", type=positive_int, default=DEFAULT_DURATION_S)
    sp.add_argument("--parallel", type=int, default=4); sp.set_defaults(func=do_iperf)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.src is None and args.cmd in CRAFTED:
        try:
            args.src = resolve_source_ip(args.target)
        except OSError as exc:
            parser.error(
                f"cannot determine the source address for {args.target!r}: {exc}; "
                "pass --src explicitly"
            )
    confirm(args.cmd, args.target, args.yes)
    result = _run_workload(Workload(args.cmd, args.func, args))
    hdr(f"DONE in {result.elapsed_s:.1f}s; execution={result.execution_status}; detection=not_evaluated")
    if result.error:
        print(f"[ERR] {result.error}")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
