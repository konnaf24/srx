#!/usr/bin/env python3
"""Web dashboard for the SRX detection-probe workloads.

Wraps the repo's `deploy/srx_workload.py` (either directly on this host or
over SSH to a remote client) and streams live stdout/stderr into the
browser. Configure host/target via env vars (see `config.env.example`).
"""
from __future__ import annotations

import html
import ipaddress
import json
import os
import queue
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
import re
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO = Path(__file__).resolve().parent
PORT = int(os.environ.get("SRX_DASH_PORT", "8081"))
BIND = os.environ.get("SRX_DASH_BIND", "127.0.0.1")
PUBLIC_ORIGIN = os.environ.get("SRX_DASH_PUBLIC_ORIGIN", "")
TRUST_PROXY = os.environ.get("SRX_DASH_TRUST_PROXY", "") == "1"
MAX_BODY = 16384
MAX_LINES = 2000
MAX_LINE_CHARS = 4096
QUEUE_SIZE = 256
MAX_SUBSCRIBERS = 16
MAX_RUNS = 30


def allowed_origins():
    """Validate the operator's boundary; forwarded headers are never trusted."""
    loopback = ipaddress.ip_address(BIND).is_loopback
    if not loopback and not (TRUST_PROXY and PUBLIC_ORIGIN):
        raise ValueError("nonloopback bind requires authenticated proxy boundary: "
                         "SRX_DASH_TRUST_PROXY=1 and SRX_DASH_PUBLIC_ORIGIN")
    if PUBLIC_ORIGIN:
        parsed = urlparse(PUBLIC_ORIGIN)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.path or parsed.query or parsed.fragment
                or parsed.username or parsed.password
                or PUBLIC_ORIGIN != f"{parsed.scheme}://{parsed.netloc}"):
            raise ValueError("SRX_DASH_PUBLIC_ORIGIN must be an exact HTTP(S) origin")
        if not loopback and parsed.scheme != "https":
            raise ValueError("network proxy origin must use HTTPS")
        return {PUBLIC_ORIGIN}
    return {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}",
            f"http://[::1]:{PORT}"}


# Client (where the probe runs) and server (traffic destination).
# An unset client selects local execution; each run still requires a target.
CLIENT_HOST = os.environ.get("SRX_CLIENT_HOST", "")         # e.g. user@203.0.113.10
CLIENT_REPO = os.environ.get("SRX_CLIENT_REPO", "/home/user/srx")
DEFAULT_TARGET = os.environ.get("SRX_TARGET", "")           # server IP
DEFAULT_SRC = os.environ.get("SRX_SRC", "")                 # client IP stamped on scapy packets

HISTORY_FILE = Path(os.environ.get("SRX_HISTORY_FILE", str(REPO / "runall-history.json")))
HISTORY_MAX = max(1, min(100, int(os.environ.get("SRX_HISTORY_MAX", "30"))))
_SUMMARY_RE = re.compile(
    r"^\[(OK|ERR|SUCCEEDED|FAILED)\] ([^:]+): rc=(-?\d+) elapsed=(\d+(?:\.\d+)?)s"
    r"(?: detection=\S+)?(?: - (.+))?$")

# Workload catalog. Mirrors deploy/srx_workload.py's subparsers, adding
# aggressive/root flags for UI labelling. `params` is (name, kind, default, choices?).
WORKLOADS = OrderedDict([
    ("http",       {"desc": "Benign HTTP GET (App-ID generic, session create)",
                    "root": False, "aggressive": False,
                    "params": [("port", "int", 80, None), ("path", "str", "/", None)]}),
    ("dns",        {"desc": "UDP DNS query (App-ID generic)",
                    "root": False, "aggressive": False,
                    "params": [("qname", "str", "probe.lab", None)]}),
    ("handshake",  {"desc": "TCP handshake + banner grab (FTP/SSH/…)",
                    "root": False, "aggressive": False,
                    "params": [("port", "int", 22, None),
                               ("app", "str", "SSH", ["SSH", "FTP", "HTTP"])]}),
    ("eicar",      {"desc": "EICAR antivirus test string over HTTP",
                    "root": False, "aggressive": False,
                    "params": [("port", "int", 80, None)]}),
    ("gtube",      {"desc": "GTUBE spam test string over HTTP",
                    "root": False, "aggressive": False,
                    "params": [("port", "int", 80, None)]}),
    ("scan",       {"desc": "nmap TCP scan (SYN/XMAS/FIN/NULL/ACK)",
                    "root": True,  "aggressive": True,
                    "params": [("type", "str", "syn",
                                ["syn", "xmas", "fin", "null", "ack"]),
                               ("max-ports", "int", 1024, None)]}),
    ("flood",      {"desc": "hping3 bounded flood (rate-limited)",
                    "root": True,  "aggressive": True,
                    "params": [("type", "str", "syn", ["syn", "icmp", "udp"]),
                               ("port", "int", 80, None),
                               ("count", "int", 2000, None),
                               ("rate", "int", 500, None)]}),
    ("malformed",  {"desc": "scapy SYN+FIN illegal-flags packet",
                    "root": True,  "aggressive": True,
                    "params": [("port", "int", 80, None)]}),
    ("badcsum",    {"desc": "scapy TCP with bad checksum",
                    "root": True,  "aggressive": True,
                    "params": [("port", "int", 80, None)]}),
    ("ttl",        {"desc": "scapy TCP with tiny TTL",
                    "root": True,  "aggressive": True,
                    "params": [("port", "int", 80, None), ("ttl", "int", 1, None)]}),
    ("frag",       {"desc": "scapy overlapping IP fragments",
                    "root": True,  "aggressive": True,
                    "params": [("port", "int", 80, None), ("count", "int", 8, None)]}),
    ("deny",       {"desc": "scapy SYN to denied port (policy-drop test)",
                    "root": True,  "aggressive": True,
                    "params": [("port", "int", 9, None)]}),
    ("wrk",        {"desc": "wrk HTTP session-volume load",
                    "root": False, "aggressive": False,
                    "params": [("connections", "int", 100, None),
                               ("threads", "int", 4, None),
                               ("duration", "int", 60, None)]}),
    ("iperf",      {"desc": "iperf3 throughput (needs iperf3 -s on target)",
                    "root": False, "aggressive": False,
                    "params": [("port", "int", 5201, None),
                               ("parallel", "int", 4, None),
                               ("duration", "int", 60, None)]}),
    ("all",        {"desc": "Run every workload concurrently",
                    "root": True,  "aggressive": True,
                    "params": [("duration", "int", 60, None)]}),
])

# --------------------------------------------------------------------- runs

_hist_lock = threading.Lock()


def _load_history():
    try:
        with open(HISTORY_FILE) as f:
            data = json.load(f)
        if isinstance(data, list):
            return data[-max(1, HISTORY_MAX):]
    except (OSError, ValueError):
        pass
    return []


def _save_history(hist):
    tmp = str(HISTORY_FILE) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(hist, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, str(HISTORY_FILE))


HISTORY = _load_history()


def parse_batch_from_lines(lines):
    """Extract per-workload results from the CLI's WORKLOAD SUMMARY block."""
    results = []
    in_summary = False
    for line in lines:
        if "WORKLOAD SUMMARY" in line:
            in_summary = True
            continue
        if not in_summary:
            continue
        m = _SUMMARY_RE.match(line.strip())
        if m:
            status, name, rc, elapsed, err = m.groups()
            results.append({
                "name": name.strip(),
                "rc": int(rc),
                "elapsed": float(elapsed),
                "ok": status in {"OK", "SUCCEEDED"} and int(rc) == 0,
                "execution_status": "succeeded" if int(rc) == 0 else "failed",
                "detection_status": "not_evaluated",
                "error": err or "",
            })
    return results


def record_batch(run):
    """Called when a `run all` finishes; parse output and append to history."""
    results = parse_batch_from_lines(run.lines)
    passed = sum(1 for r in results if r["ok"])
    entry = {
        "id": run.id,
        "started": run.started,
        "ended": run.ended,
        "elapsed": (run.ended or time.time()) - run.started,
        "rc": run.returncode,
        "summary_available": bool(results),
        "execution_status": "succeeded" if run.returncode == 0 else "failed",
        "detection_status": "not_evaluated",
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }
    with _hist_lock:
        HISTORY.append(entry)
        while len(HISTORY) > HISTORY_MAX:
            HISTORY.pop(0)
        _save_history(HISTORY)
    return entry


class Run:
    def __init__(self, run_id, cmdline, use_sudo, workload=None):
        self.id = run_id
        self.cmdline = cmdline
        self.use_sudo = use_sudo
        self.workload = workload
        self.started = time.time()
        self.ended = None
        self.returncode = None
        self.lines = deque(maxlen=MAX_LINES)
        self.events = deque(maxlen=MAX_LINES)
        self.sequence = 0
        self.terminal = None
        self.subscribers = set()
        self.lock = threading.Lock()
        self.proc = None
        self.stop_requested = False
        self.request_id = None
        self.request = None

    def _publish(self, kind, data):
        # Caller holds lock. Slow subscribers reconnect and replay the ring.
        self.sequence += 1
        event = (self.sequence, kind, data)
        self.events.append(event)
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except queue.Full:
                self.subscribers.remove(q)
                while True:
                    try:
                        q.get_nowait()
                    except queue.Empty:
                        break
                q.put_nowait(None)
        return event

    def emit(self, line):
        with self.lock:
            if self.terminal is not None:
                return
            line = line[:MAX_LINE_CHARS]
            self.lines.append(line)
            self._publish("log", line)

    def finish(self, rc):
        with self.lock:
            if self.terminal is not None:
                return
            self.returncode = rc
            self.ended = time.time()
            payload = {"rc": rc, "elapsed": self.ended - self.started}
            try:
                batch = record_batch(self) if self.workload == "all" else None
                if batch:
                    payload["batch"] = {k: batch[k] for k in
                                        ("id", "passed", "failed", "total")}
            except Exception:
                payload["history_error"] = True
            self.terminal = self._publish("end", payload)

    def subscribe(self, last_id=0):
        q = queue.Queue(maxsize=QUEUE_SIZE)
        with self.lock:
            if len(self.subscribers) >= MAX_SUBSCRIBERS:
                raise ValueError("too many subscribers")
            backlog = [e for e in self.events if e[0] > last_id]
            if self.events and (last_id < self.events[0][0] - 1
                                or last_id > self.sequence):
                backlog = [(0, "reset", "Older output unavailable; showing retained tail.")]
                backlog += list(self.events)
            done = self.terminal is not None
            # Always replay terminal state, even when Last-Event-ID is terminal.
            if done and self.terminal not in backlog:
                backlog.append(self.terminal)
            if not done:
                self.subscribers.add(q)
        return q, backlog, done

    def unsubscribe(self, q):
        with self.lock:
            self.subscribers.discard(q)

    def snapshot(self):
        with self.lock:
            return {"id": self.id, "cmd": self.cmdline, "started": self.started,
                    "ended": self.ended, "rc": self.returncode,
                    "request_id": self.request_id,
                    "terminal": self.terminal[2] if self.terminal else None}


RUNS = OrderedDict()
RUNS_LOCK = threading.Lock()


def make_cmd(workload, target, src, params, root_ok):
    """Build the argv to run the SRX workload.

    Two modes:
      * Remote mode (SRX_CLIENT_HOST set): SSH into the client, cd to
        SRX_CLIENT_REPO, and invoke the CLI there.
      * Local mode (no SRX_CLIENT_HOST): run the CLI on this host, using the
        sibling `deploy/srx_workload.py` at the repo root.

    Root-required workloads are prefixed with `sudo -n`. The operator must
    review the privilege boundary: the legacy installer grants unrestricted
    Python execution and is not a narrow workload authorization policy.
    """
    remote = bool(CLIENT_HOST)

    if remote:
        py = f"{CLIENT_REPO}/venv/bin/python"
        cli = f"{CLIENT_REPO}/deploy/srx_workload.py"
        cwd = CLIENT_REPO
    else:
        # dashboard.py sits in srx-dashboard/, CLI is at ../deploy/
        parent = REPO.parent
        venv_py = parent / "venv" / "bin" / "python"
        py = str(venv_py) if venv_py.exists() else sys.executable
        cli = str(parent / "deploy" / "srx_workload.py")
        cwd = str(parent)

    remote_argv = [py, cli, "--target", target]
    if src:
        remote_argv += ["--src", src]
    remote_argv += ["--yes", workload]
    for name, kind, _default, _choices in WORKLOADS[workload]["params"]:
        val = params.get(name)
        if val is None or val == "":
            continue
        remote_argv += [f"--{name}", str(val)]
    use_sudo = WORKLOADS[workload]["root"] and root_ok
    if use_sudo:
        remote_argv = ["sudo", "-n"] + remote_argv

    if remote:
        remote_cmd = "cd " + shlex.quote(cwd) + " && exec " + \
                     " ".join(shlex.quote(a) for a in remote_argv)
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=3", "-tt", CLIENT_HOST, remote_cmd]
    else:
        argv = remote_argv
    return argv, use_sudo


class AdmissionError(ValueError):
    pass


def validate_request(body):
    if not isinstance(body, dict) or set(body) - {
            "workload", "target", "src", "params", "confirm_aggressive", "request_id"}:
        raise ValueError("invalid request object or unknown fields")
    wl = body.get("workload")
    if not isinstance(wl, str) or wl not in WORKLOADS:
        raise ValueError("unknown workload")
    def text(value, label, limit):
        if (not isinstance(value, str) or len(value) > limit
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError("invalid " + label)
        return value.strip()
    target = text(body.get("target"), "target", 253)
    if not target or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:%_-]*", target):
        raise ValueError("target must be an IP address or hostname")
    src = text(body.get("src", ""), "src", 45)
    if src:
        ipaddress.ip_address(src)
    if "confirm_aggressive" in body and type(body["confirm_aggressive"]) is not bool:
        raise ValueError("confirm_aggressive must be boolean")
    if WORKLOADS[wl]["aggressive"] and body.get("confirm_aggressive") is not True:
        raise ValueError("explicit aggressive confirmation required")
    request_id = body.get("request_id")
    if request_id is not None and (not isinstance(request_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", request_id)):
        raise ValueError("invalid request_id")
    params = body.get("params", {})
    if not isinstance(params, dict) or set(params) - {p[0] for p in WORKLOADS[wl]["params"]}:
        raise ValueError("invalid params or unknown parameter")
    # Mirror default CLI WorkloadLimits without importing generator dependencies.
    limits = {"port": 65535, "max-ports": 4096, "ttl": 255,
              "duration": 300, "count": 64 if wl == "frag" else 10000, "rate": 1000,
              "connections": 10000, "threads": 64, "parallel": 32}
    clean = {}
    for name, kind, default, choices in WORKLOADS[wl]["params"]:
        value = params.get(name, default)
        if value == "":
            value = default
        if kind == "int":
            if type(value) is not int:
                if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,8}", value):
                    raise ValueError(name + " must be an integer")
                value = int(value)
            if not 1 <= value <= limits[name]:
                raise ValueError(name + " out of range")
        else:
            value = text(value, name, 2048 if name == "path" else 253)
            if not value or (choices and value not in choices):
                raise ValueError("invalid " + name)
            if name == "path" and not value.startswith("/"):
                raise ValueError("path must start with /")
            if name == "qname" and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", value):
                raise ValueError("invalid qname")
        clean[name] = value
    if wl == "wrk" and clean["threads"] > clean["connections"]:
        raise ValueError("threads must not exceed connections")
    if wl == "flood" and clean["count"] * ((1000000 + clean["rate"] - 1) // clean["rate"]) > 300000000:
        raise ValueError("paced flood exceeds 300 seconds")
    return wl, target, src, clean, request_id


def spawn_run(workload, target, src, params, root_ok, request_id=None):
    argv, use_sudo = make_cmd(workload, target, src, params, root_ok)
    request = (workload, target, src, params, root_ok)
    with RUNS_LOCK:
        for existing in RUNS.values():
            if request_id and existing.request_id == request_id:
                if existing.request != request:
                    raise AdmissionError("request_id already used with different arguments")
                return existing
        if any(r.snapshot()["ended"] is None for r in RUNS.values()):
            raise AdmissionError("a run is already active; stop or wait for it")
        run_id = uuid.uuid4().hex[:12]
        run = Run(run_id, " ".join(shlex.quote(a) for a in argv), use_sudo,
                  workload=workload)
        run.request_id, run.request = request_id, request
        RUNS[run_id] = run
        while len(RUNS) > MAX_RUNS:
            RUNS.popitem(last=False)

    def target_thread():
        rc = 1
        proc = None
        try:
            with run.lock:
                if run.stop_requested:
                    rc = -signal.SIGTERM
                else:
                    proc = subprocess.Popen(
                        argv, cwd=str(REPO), stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1,
                        start_new_session=True)
                    run.proc = proc
            if proc is not None:
                run.emit("$ " + run.cmdline)
                # Bounded reads also protect against output without newlines.
                while True:
                    line = proc.stdout.readline(MAX_LINE_CHARS)
                    if not line:
                        break
                    run.emit(line.rstrip("\n"))
                rc = proc.wait()
        except Exception as e:
            run.emit("ERROR: %s" % e)
            rc = 127 if isinstance(e, FileNotFoundError) else 1
            if proc is not None and proc.poll() is None:
                kill_run(run)
        finally:
            try:
                if proc is not None and proc.stdout is not None:
                    proc.stdout.close()
            finally:
                run.finish(rc)

    try:
        threading.Thread(target=target_thread, daemon=True).start()
    except Exception as e:
        run.emit("ERROR starting worker: %s" % e)
        run.finish(1)
    return run


def kill_run(run):
    with run.lock:
        if run.terminal is not None:
            return False
        run.stop_requested = True
        if run.proc is None:
            return True
    if run.proc and run.proc.poll() is None:
        try:
            os.killpg(run.proc.pid, signal.SIGTERM)
            time.sleep(2)
            if run.proc.poll() is None:
                os.killpg(run.proc.pid, signal.SIGKILL)
            return True
        except Exception as e:
            run.emit("ERROR killing: %s" % e)
    return False


# --------------------------------------------------------------------- HTML

PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>SRX Workload Console</title>
<style>
 body{background:#0d1117;color:#e6edf3;font-family:system-ui,Segoe UI,sans-serif;margin:0;padding:1.5rem;max-width:1400px}
 h1{font-size:1.3rem;margin:0 0 .3rem;font-weight:600}
 .sub{color:#8b949e;font-size:.85rem;margin-bottom:1.2rem}
 .warn{background:#3c1c1e;border:1px solid #f8514966;color:#ffa198;
       padding:.7rem 1rem;border-radius:8px;margin-bottom:1.2rem;font-size:.85rem}
 .row{display:grid;grid-template-columns:1fr 1fr auto;gap:.6rem;margin-bottom:1rem;align-items:end}
 label{display:block;color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.2rem}
 input,select{background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:.45rem .6rem;width:100%;font-family:inherit;font-size:.9rem;box-sizing:border-box}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
 @media (max-width:900px){.grid{grid-template-columns:1fr}}
 .card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1rem}
 .card h3{margin:0 0 .3rem;font-size:1rem;display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
 .card p{margin:0 0 .7rem;color:#8b949e;font-size:.8rem}
 .badge{font-size:.65rem;padding:.15rem .4rem;border-radius:4px;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
 .b-agg{background:#3c1c1e;color:#ffa198}
 .b-root{background:#1e2a3c;color:#79c0ff}
 .params{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin-bottom:.7rem}
 button{background:#238636;color:#fff;border:0;border-radius:6px;padding:.5rem 1rem;font-weight:600;cursor:pointer;font-size:.85rem}
 button:hover{background:#2ea043}
 button.stop{background:#da3633}
 button.stop:hover{background:#f85149}
 button:disabled{opacity:.5;cursor:not-allowed}
 #console{background:#010409;border:1px solid #30363d;border-radius:10px;padding:1rem;
          font-family:ui-monospace,Consolas,monospace;font-size:.78rem;color:#c9d1d9;
          height:420px;overflow:auto;white-space:pre-wrap;margin-top:1.2rem}
 .status{color:#8b949e;font-size:.8rem;margin-top:.5rem}
 .ok{color:#3fb950}.err{color:#f85149}
 .runall{background:linear-gradient(90deg,#0f2436,#161b22);border:1px solid #30363d;
         border-radius:10px;padding:1.1rem 1.3rem;margin-bottom:1.2rem;
         display:flex;align-items:center;gap:1.2rem;flex-wrap:wrap}
 .runall h2{margin:0;font-size:1rem;flex:1}
 .runall .duration{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:#8b949e}
 .runall input{width:5rem}
 .runall .runbtn{background:#1f6feb}
 .runall .runbtn:hover{background:#388bfd}
 #history-wrap{background:#161b22;border:1px solid #30363d;border-radius:10px;
               padding:1rem;margin-bottom:1.2rem}
 #history-wrap h3{margin:0 0 .3rem;font-size:.95rem}
 #history-wrap p{margin:0 0 .8rem;color:#8b949e;font-size:.78rem}
 #heatmap{width:100%;background:#010409;border-radius:6px}
 .legend{display:flex;gap:1rem;font-size:.72rem;color:#8b949e;margin-top:.5rem;flex-wrap:wrap}
 .legend span{display:inline-block;width:11px;height:11px;border-radius:2px;
              margin-right:.3rem;vertical-align:middle}
</style></head><body>
<h1>SRX Workload Console</h1>
<div class="sub">Wraps <code>deploy/srx_workload.py</code> on <code id="client"></code>. Streams live output.<br>Local repo: <code id="repo"></code></div>

<div class="warn"><strong>⚠ Attack traffic.</strong> scan/flood/malformed workloads send hostile packets.
Only run against hosts you own or are authorized to test. Aggressive workloads pass <code>--yes</code>.</div>

<div class="row">
 <div><label>Destination (server, traffic target)</label><input id="target" value="__TARGET__"></div>
 <div><label>Client-side source IP (--src on scapy packets)</label><input id="src" value="__SRC__"></div>
 <div><button id="killbtn" class="stop" onclick="killCurrent()" disabled>Stop current run</button></div>
</div>

<div class="runall">
 <h2>Run the complete workload suite concurrently</h2>
 <div class="duration"><label style="margin:0">duration (s)</label>
  <input id="all_duration" type="number" value="60" min="1"></div>
 <button class="runbtn" onclick="runIt('all')">Run All</button>
</div>

<div id="history-wrap">
 <h3>Batch history <span id="hist-count" style="color:#8b949e;font-weight:400"></span></h3>
 <p>Each column is one "Run All" invocation. Rows are workloads. Green=execution OK, red=execution error, grey=not run. Detection is not validated.
    Output replay is limited to the retained tail.</p>
 <canvas id="heatmap" height="380"></canvas>
 <div class="legend">
  <span style="background:#3fb950"></span>OK (rc=0)
  <span style="background:#f85149"></span>ERR (rc≠0)
  <span style="background:#30363d"></span>missing
 </div>
</div>

<div class="grid" id="cards"></div>

<h3 style="margin-top:1.5rem">Output</h3>
<div class="status" id="status">idle</div>
<div id="console">Ready. Pick a workload and press Run.</div>

<script>
const WORKLOADS = __CATALOG__;
document.getElementById('repo').textContent = __REPO__;
document.getElementById('client').textContent = __CLIENT__;
const cardsEl = document.getElementById('cards');
const consoleEl = document.getElementById('console');
const statusEl = document.getElementById('status');
const killBtn = document.getElementById('killbtn');
let currentRun = null, currentEs = null, launching = false, recovering = false;
let pendingRequest = null;
const outputLines = [];
let outputFrame = null;
function appendOutput(line){
 outputLines.push(line);
 if(outputLines.length>2000) outputLines.shift();
 if(outputFrame===null) outputFrame=requestAnimationFrame(() => {
  consoleEl.textContent = outputLines.join('\n');
  consoleEl.scrollTop = consoleEl.scrollHeight;
  outputFrame=null;
 });
}
function finished(d){
 if(currentEs) currentEs.close();
 currentEs = null; currentRun = null; killBtn.disabled = true;
 statusEl.textContent = `execution finished rc=${d.rc} in ${d.elapsed.toFixed(1)}s — detection not validated`;
 if(d.history_error) statusEl.textContent += ' — WARNING: history could not be saved';
 if(d.batch) loadHistory();
}
function followRun(id){
 if(currentEs) currentEs.close();
 currentRun = id; killBtn.disabled = false;
 statusEl.textContent = `running (id=${id}) — detection not validated`;
 const es = new EventSource('/api/stream?id=' + id);
 currentEs = es;
 es.addEventListener('log', ev => { if(currentEs===es) appendOutput(JSON.parse(ev.data)); });
 es.addEventListener('reset', ev => {
  if(currentEs!==es) return;
  outputLines.length=0; appendOutput(JSON.parse(ev.data));
 });
 es.addEventListener('end', ev => { if(currentEs===es) finished(JSON.parse(ev.data)); });
 es.onopen = () => { if(currentEs===es) statusEl.textContent = `running (id=${id}) — detection not validated`; };
 es.onerror = () => {
  if(currentEs!==es) return;
  statusEl.textContent = 'stream disconnected — reconnecting; checking execution state…';
  reconcile();
 };
}
async function reconcile(){
 if(recovering) return;
 recovering = true;
 try{
  const r = await fetch('/api/runs');
  if(!r.ok) throw new Error('status unavailable');
  const runs = await r.json();
  const run = runs.find(r => r.id===currentRun) ||
              runs.find(r => pendingRequest && r.request_id===pendingRequest.request_id) ||
              runs.find(r => r.ended===null);
  if(run){
   pendingRequest=null;
   if(run.terminal) finished(run.terminal);
   else if(!currentEs) followRun(run.id);
  }else if(currentRun){
   if(currentEs) currentEs.close();
   currentEs=null; currentRun=null; killBtn.disabled=true;
   statusEl.textContent='run no longer retained — execution status unknown';
  }
 }catch(e){ statusEl.textContent='Cannot reach dashboard — execution status unknown; retrying.'; }
 finally{ recovering=false; }
}
// Recover after refresh and use status polling as a fallback to SSE reconnect.
reconcile();
setInterval(() => { if(currentRun || pendingRequest) reconcile(); }, 5000);

function makeCard(name, w){
 const c = document.createElement('div'); c.className='card';
 const badges = (w.aggressive?'<span class="badge b-agg">aggressive</span>':'') +
                (w.root?'<span class="badge b-root">root</span>':'');
 let params='';
 w.params.forEach(p=>{
  const [pn,kind,def,choices]=p;
  const inp = choices ?
    `<select id="p_${name}_${pn}">${choices.map(o=>`<option${o==def?' selected':''}>${o}</option>`).join('')}</select>` :
    `<input id="p_${name}_${pn}" value="${def}" type="${kind=='int'?'number':'text'}">`;
  params += `<div><label>${pn}</label>${inp}</div>`;
 });
 c.innerHTML = `
  <h3>${name} ${badges}</h3>
  <p>${w.desc}</p>
  <div class="params">${params}</div>
  <button onclick="runIt('${name}')">Run</button>`;
 cardsEl.appendChild(c);
}
Object.entries(WORKLOADS).filter(([n])=>n!=='all').forEach(([n,w])=>makeCard(n,w));

function readParams(name){
 const out = {};
 if(name==='all'){
  out['duration'] = document.getElementById('all_duration').value;
  return out;
 }
 WORKLOADS[name].params.forEach(p=>{
  const el = document.getElementById(`p_${name}_${p[0]}`);
  if(el) out[p[0]] = el.value;
 });
 return out;
}
async function runIt(name){
 if(launching || currentRun){ statusEl.textContent = 'a run is starting or active — stop it first'; return; }
 const w = WORKLOADS[name];
 if(w.aggressive && !confirm(`Send ${name} attack traffic to ${document.getElementById('target').value}?\n\nOnly proceed if you are authorized.`)) return;
 const body = {workload:name, target:document.getElementById('target').value,
               src:document.getElementById('src').value, params:readParams(name),
               confirm_aggressive:!!w.aggressive};
 // Keep the key after an ambiguous network failure, so a retry cannot relaunch.
 const signature = JSON.stringify(body);
 if(pendingRequest && pendingRequest.signature!==signature){
  statusEl.textContent='Previous launch outcome unknown — retry the same request or reload to reconcile.'; return;
 }
 if(!pendingRequest) pendingRequest = {signature, request_id:crypto.randomUUID()};
 body.request_id = pendingRequest.request_id;
 launching = true; outputLines.length=0; consoleEl.textContent = '';
 statusEl.textContent = 'starting…';
 try{
  const r = await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j = await r.json();
  if(r.status>=500) throw new Error('launch outcome unknown');
  if(!r.ok){
   pendingRequest=null; statusEl.textContent = 'ERROR: ' + (j.error||r.status);
   if(r.status===409) await reconcile();
   return;
  }
  pendingRequest=null; followRun(j.id);
 }catch(e){
  statusEl.textContent='Launch response lost — checking state; retry uses the same request ID.';
  await reconcile();
 }finally{ launching=false; }
}

let cachedHistory = [];
async function loadHistory(){
 let hist;
 try{ hist = await (await fetch('/api/history')).json(); }
 catch(e){ return; }
 cachedHistory = hist;
 document.getElementById('hist-count').textContent =
   hist.length ? `(${hist.length} batch${hist.length===1?'':'es'})` : '(no batches yet — press Run All)';
 drawHeatmap(hist);
}
function drawHeatmap(hist){
 const c = document.getElementById('heatmap');
 const dpr = window.devicePixelRatio||1;
 const width = c.clientWidth;
 // Collect the union of workload names across all batches.
 const namesSet = new Set();
 hist.forEach(b => b.results.forEach(r => namesSet.add(r.name)));
 const names = Array.from(namesSet).sort();
 const rows = Math.max(names.length, 1);
 const cols = Math.max(hist.length, 1);
 const rowH = 22, colW = Math.max(28, Math.min(60, (width - 180) / cols));
 const padL = 160, padT = 30, padB = 30;
 const H = padT + rows * rowH + padB;
 c.width = width * dpr; c.height = H * dpr;
 c.style.height = H + 'px';
 const x = c.getContext('2d');
 x.scale(dpr, dpr);
 x.clearRect(0,0,width,H);
 x.font = '11px system-ui,sans-serif';
 // Row labels.
 x.fillStyle = '#c9d1d9';
 x.textAlign = 'right'; x.textBaseline = 'middle';
 names.forEach((n,i) => x.fillText(n, padL - 8, padT + i*rowH + rowH/2));
 // Column headers (batch number, newest right).
 x.fillStyle = '#8b949e';
 x.textAlign = 'center'; x.textBaseline = 'bottom';
 hist.forEach((b, ci) => {
  const cx = padL + ci*colW + colW/2;
  const d = new Date(b.started * 1000);
  const label = d.toTimeString().slice(0,5);
  x.fillText(label, cx, padT - 4);
 });
 // Cells.
 hist.forEach((b, ci) => {
  const byName = {};
  b.results.forEach(r => { byName[r.name] = r; });
  names.forEach((n, ri) => {
   const r = byName[n];
   let color = '#30363d';
   if(r) color = r.ok ? '#3fb950' : '#f85149';
   x.fillStyle = color;
   x.fillRect(padL + ci*colW + 2, padT + ri*rowH + 2, colW - 4, rowH - 4);
   if(r){
    x.fillStyle = r.ok ? '#0d1117' : '#0d1117';
    x.textAlign = 'center'; x.textBaseline = 'middle';
    x.font = '10px ui-monospace,Consolas,monospace';
    x.fillText(r.elapsed<10 ? r.elapsed.toFixed(1) : Math.round(r.elapsed),
               padL + ci*colW + colW/2, padT + ri*rowH + rowH/2);
    x.font = '11px system-ui,sans-serif';
   }
  });
 });
 // Bottom summary row.
 x.fillStyle = '#8b949e'; x.textAlign = 'center'; x.textBaseline = 'top';
 hist.forEach((b, ci) => {
  const cx = padL + ci*colW + colW/2;
  x.fillText(b.summary_available===false ? 'no summary' : `${b.passed}/${b.total}`, cx, padT + rows*rowH + 4);
 });
}
loadHistory();
let resizeFrame = null;
window.addEventListener('resize', () => {
 if(resizeFrame===null) resizeFrame=requestAnimationFrame(() => {
  drawHeatmap(cachedHistory); resizeFrame=null;
 });
});

async function killCurrent(){
 if(!currentRun) return;
 try{
  const r = await fetch('/api/kill?id=' + currentRun, {method:'POST'});
  const j = await r.json();
  statusEl.textContent = r.ok ? (j.killed?'stop requested — awaiting execution exit':'no active process to stop') : 'Stop failed: '+j.error;
 }catch(e){ statusEl.textContent='Stop response lost — execution status unknown'; }
 await reconcile();
}
</script></body></html>"""


# --------------------------------------------------------------------- server

def sse_frame(event):
    sequence, kind, data = event
    return (f"id: {sequence}\nevent: {kind}\ndata: " + json.dumps(data)
            + "\n\n").encode()


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(20)

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, message):
        self.close_connection = True
        return self._send(code, json.dumps({"error": message}), "application/json")

    def _authorized(self, mutation=False):
        origins = allowed_origins()
        hosts = {urlparse(origin).netloc for origin in origins}
        host = self.headers.get_all("Host", [])
        origin = self.headers.get_all("Origin", [])
        if (len(host) != 1 or host[0] not in hosts
                or len(origin) > 1
                or (origin and origin[0] not in origins)
                or (mutation and not origin)
                or self.headers.get("Sec-Fetch-Site") == "cross-site"):
            self._error(403, "Host/Origin not allowed; same-origin requests required")
            return False
        # When multiple local origins are allowed, still require an exact pair.
        if origin and urlparse(origin[0]).netloc != host[0]:
            self._error(403, "Origin and Host must match")
            return False
        return True

    def _run(self, query):
        rid = parse_qs(query).get("id", [""])[0]
        with RUNS_LOCK:
            return RUNS.get(rid)

    def do_GET(self):
        if not self._authorized():
            return
        p = urlparse(self.path)
        if p.path in ("/", "/index.html"):
            page = (PAGE
                    .replace("__TARGET__", html.escape(DEFAULT_TARGET))
                    .replace("__SRC__", html.escape(DEFAULT_SRC))
                    .replace("__REPO__", json.dumps(str(REPO)).replace("<", "\\u003c"))
                    .replace("__CLIENT__", json.dumps(CLIENT_HOST or "local host").replace("<", "\\u003c"))
                    .replace("__CATALOG__", json.dumps({k: {
                        "desc": v["desc"], "root": v["root"],
                        "aggressive": v["aggressive"], "params": v["params"],
                    } for k, v in WORKLOADS.items()})))
            return self._send(200, page, "text/html; charset=utf-8")
        if p.path == "/api/stream":
            run = self._run(p.query)
            if not run:
                return self._error(404, "unknown run")
            try:
                value = self.headers.get("Last-Event-ID", "0")
                if not re.fullmatch(r"[0-9]{1,16}", value):
                    raise ValueError("invalid Last-Event-ID")
                q, backlog, done = run.subscribe(int(value))
            except ValueError as e:
                return self._error(400, str(e))
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                self.wfile.write(b"retry: 2000\n\n")
                for event in backlog:
                    self.wfile.write(sse_frame(event))
                self.wfile.flush()
                if done:
                    return
                while True:
                    try:
                        event = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        continue
                    if event is None:
                        return  # slow consumer: reconnect with Last-Event-ID
                    self.wfile.write(sse_frame(event))
                    self.wfile.flush()
                    if event[1] == "end":
                        return
            except OSError:
                return
            finally:
                run.unsubscribe(q)
                self.close_connection = True
        if p.path == "/api/history":
            with _hist_lock:
                data = list(HISTORY)
            return self._send(200, json.dumps(data), "application/json")
        if p.path == "/api/runs":
            with RUNS_LOCK:
                data = [r.snapshot() for r in RUNS.values()]
            return self._send(200, json.dumps(data), "application/json")
        return self._error(404, "not found")

    def do_POST(self):
        if not self._authorized(mutation=True):
            return
        p = urlparse(self.path)
        if self.headers.get("Transfer-Encoding"):
            return self._error(400, "Transfer-Encoding is not supported")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,8}", lengths[0]):
            return self._error(400, "valid Content-Length required")
        length = int(lengths[0])
        if length > MAX_BODY:
            return self._error(413, "request too large")
        if p.path == "/api/run":
            if self.headers.get_content_type() != "application/json":
                return self._error(415, "application/json required")
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete request body")
                body = json.loads(raw)
                wl, target, src, params, request_id = validate_request(body)
            except (ValueError, UnicodeError, RecursionError, OSError) as e:
                return self._error(400, "invalid request: " + str(e))
            try:
                run = spawn_run(wl, target, src, params, root_ok=True,
                                request_id=request_id)
            except AdmissionError as e:
                return self._error(409, str(e))
            return self._send(200, json.dumps({"id": run.id, "cmd": run.cmdline}),
                              "application/json")
        if p.path == "/api/kill":
            if length:
                return self._error(400, "kill request must have an empty body")
            run = self._run(p.query)
            if not run:
                return self._error(404, "unknown run")
            killed = kill_run(run)
            return self._send(200, json.dumps({"killed": killed}),
                              "application/json")
        return self._error(404, "not found")


def main():
    allowed_origins()  # Fail closed before opening a socket.
    print(f"SRX workload dashboard bind={BIND}:{PORT}")
    print(f"repo: {REPO}")
    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in BIND else socket.AF_INET
    Server((BIND, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
