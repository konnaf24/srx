#!/usr/bin/env python3
"""Web dashboard for the SRX detection-probe workloads.

Wraps the repo's `deploy/srx_workload.py` (either directly on this host or
over SSH to a remote client) and streams live stdout/stderr into the
browser. Configure host/target via env vars (see `config.env.example`).
"""
from __future__ import annotations

import html
import json
import os
import queue
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid
import re
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO = Path(__file__).resolve().parent
PORT = int(os.environ.get("SRX_DASH_PORT", "8081"))

# Client (where the probe runs) and server (traffic destination). No values
# are hard-coded; if unset the dashboard still starts but rejects runs with
# a clear "configure SRX_CLIENT_HOST" error.
CLIENT_HOST = os.environ.get("SRX_CLIENT_HOST", "")         # e.g. user@203.0.113.10
CLIENT_REPO = os.environ.get("SRX_CLIENT_REPO", "/home/user/srx")
DEFAULT_TARGET = os.environ.get("SRX_TARGET", "")           # server IP
DEFAULT_SRC = os.environ.get("SRX_SRC", "")                 # client IP stamped on scapy packets

HISTORY_FILE = Path(os.environ.get("SRX_HISTORY_FILE", str(REPO / "runall-history.json")))
HISTORY_MAX = int(os.environ.get("SRX_HISTORY_MAX", "30"))
_SUMMARY_RE = re.compile(r"^\[(OK|ERR)\] ([^:]+): rc=(-?\d+) elapsed=([\d.]+)s(?: - (.+))?$")

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
            return data
    except (OSError, ValueError):
        pass
    return []


def _save_history(hist):
    try:
        tmp = str(HISTORY_FILE) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(hist, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(HISTORY_FILE))
    except OSError:
        pass


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
                "ok": status == "OK",
                "error": err or "",
            })
    return results


def record_batch(run):
    """Called when a `run all` finishes; parse output and append to history."""
    results = parse_batch_from_lines(run.lines)
    if not results:
        return None
    passed = sum(1 for r in results if r["ok"])
    entry = {
        "id": run.id,
        "started": run.started,
        "ended": run.ended,
        "elapsed": (run.ended or time.time()) - run.started,
        "rc": run.returncode,
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
        self.lines = []              # captured output for late subscribers
        self.subscribers = []        # active queues for SSE
        self.lock = threading.Lock()
        self.proc = None

    def emit(self, line):
        with self.lock:
            self.lines.append(line)
            dead = []
            for q in self.subscribers:
                try:
                    q.put_nowait(line)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self.subscribers.remove(q)

    def finish(self, rc):
        self.returncode = rc
        self.ended = time.time()
        batch = None
        if self.workload == "all":
            batch = record_batch(self)
        payload = {"__event__": "end", "rc": rc,
                   "elapsed": self.ended - self.started}
        if batch:
            payload["batch"] = {"id": batch["id"], "passed": batch["passed"],
                                "failed": batch["failed"], "total": batch["total"]}
        self.emit(json.dumps(payload))

    def subscribe(self):
        q = queue.Queue(maxsize=4096)
        with self.lock:
            backlog = list(self.lines)
            done = self.ended is not None
            self.subscribers.append(q)
        return q, backlog, done


RUNS = OrderedDict()
RUNS_LOCK = threading.Lock()


def make_cmd(workload, target, src, params, root_ok):
    """Build the argv to run the SRX workload.

    Two modes:
      * Remote mode (SRX_CLIENT_HOST set): SSH into the client, cd to
        SRX_CLIENT_REPO, and invoke the CLI there.
      * Local mode (no SRX_CLIENT_HOST): run the CLI on this host, using the
        sibling `deploy/srx_workload.py` at the repo root.

    Root-required workloads are prefixed with `sudo -n`; the sudoers rule
    installed by `scripts/install-client-sudoers.sh` grants exactly the
    binaries the probe needs.
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

    remote_argv = [py, cli, "--target", target, "--src", src, "--yes", workload]
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


def spawn_run(workload, target, src, params, root_ok):
    argv, use_sudo = make_cmd(workload, target, src, params, root_ok)
    run_id = uuid.uuid4().hex[:12]
    run = Run(run_id, " ".join(shlex.quote(a) for a in argv), use_sudo,
              workload=workload)
    with RUNS_LOCK:
        RUNS[run_id] = run
        # Trim old finished runs, keep last 30.
        while len(RUNS) > 30:
            oldest = next(iter(RUNS))
            if RUNS[oldest].ended is not None:
                del RUNS[oldest]
            else:
                break

    def target_thread():
        try:
            proc = subprocess.Popen(
                argv, cwd=str(REPO), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                preexec_fn=os.setsid)
        except FileNotFoundError as e:
            run.emit("ERROR: %s" % e)
            run.finish(127)
            return
        except PermissionError as e:
            run.emit("ERROR: %s" % e)
            run.finish(126)
            return
        run.proc = proc
        run.emit("$ " + run.cmdline)
        for line in proc.stdout:
            run.emit(line.rstrip("\n"))
        proc.wait()
        run.finish(proc.returncode)

    threading.Thread(target=target_thread, daemon=True).start()
    return run


def kill_run(run):
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
<div class="sub">Wraps <code>deploy/srx_workload.py</code> on <code id="client"></code> via SSH. Streams live output.<br>Local repo: <code id="repo"></code></div>

<div class="warn"><strong>⚠ Attack traffic.</strong> scan/flood/malformed workloads send hostile packets.
Only run against hosts you own or are authorized to test. Aggressive workloads pass <code>--yes</code>.</div>

<div class="row">
 <div><label>Destination (server, traffic target)</label><input id="target" value="__TARGET__"></div>
 <div><label>Client-side source IP (--src on scapy packets)</label><input id="src" value="__SRC__"></div>
 <div><button id="killbtn" class="stop" onclick="killCurrent()" disabled>Stop current run</button></div>
</div>

<div class="runall">
 <h2>Run all 14 workloads concurrently</h2>
 <div class="duration"><label style="margin:0">duration (s)</label>
  <input id="all_duration" type="number" value="60" min="1"></div>
 <button class="runbtn" onclick="runIt('all')">Run All</button>
</div>

<div id="history-wrap">
 <h3>Batch history <span id="hist-count" style="color:#8b949e;font-weight:400"></span></h3>
 <p>Each column is one "Run All" invocation. Rows are workloads. Green=OK, red=ERR, grey=not run.
    Click a column to load its full output.</p>
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
let currentRun = null, currentEs = null;

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
Object.entries(WORKLOADS).forEach(([n,w])=>makeCard(n,w));

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
 if(currentEs){ statusEl.textContent = 'a run is already active — stop it first'; return; }
 const w = WORKLOADS[name];
 if(w.aggressive){
  if(!confirm(`Send ${name} attack traffic to ${document.getElementById('target').value}?\n\nOnly proceed if you are authorized.`)) return;
 }
 const body = {workload:name, target:document.getElementById('target').value,
               src:document.getElementById('src').value, params:readParams(name)};
 consoleEl.textContent = '';
 statusEl.textContent = 'starting…';
 const r = await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const j = await r.json();
 if(!r.ok){ statusEl.textContent = 'ERROR: ' + (j.error||r.status); return; }
 currentRun = j.id;
 killBtn.disabled = false;
 statusEl.textContent = `running (id=${j.id})`;
 currentEs = new EventSource('/api/stream?id=' + j.id);
 currentEs.onmessage = ev => {
  if(ev.data.startsWith('{"__event__":"end"')){
   const d = JSON.parse(ev.data);
   const cls = d.rc===0?'ok':'err';
   let extra = '';
   if(d.batch){ extra = ` — ${d.batch.passed}/${d.batch.total} OK, ${d.batch.failed} failed`; }
   statusEl.innerHTML = `<span class="${cls}">finished rc=${d.rc}</span> in ${d.elapsed.toFixed(1)}s${extra}`;
   currentEs.close(); currentEs = null; currentRun = null;
   killBtn.disabled = true;
   if(d.batch) loadHistory();
   return;
  }
  consoleEl.textContent += ev.data + '\n';
  consoleEl.scrollTop = consoleEl.scrollHeight;
 };
 currentEs.onerror = () => { statusEl.textContent = 'stream disconnected'; };
}

async function loadHistory(){
 let hist;
 try{ hist = await (await fetch('/api/history')).json(); }
 catch(e){ return; }
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
  x.fillText(`${b.passed}/${b.total}`, cx, padT + rows*rowH + 4);
 });
}
loadHistory();
window.addEventListener('resize', loadHistory);

async function killCurrent(){
 if(!currentRun) return;
 await fetch('/api/kill?id=' + currentRun, {method:'POST'});
 statusEl.textContent = 'sent stop signal';
}
</script></body></html>"""


# --------------------------------------------------------------------- server

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = urlparse(self.path)
        if p.path in ("/", "/index.html"):
            page = (PAGE
                    .replace("__TARGET__", html.escape(DEFAULT_TARGET))
                    .replace("__SRC__", html.escape(DEFAULT_SRC))
                    .replace("__REPO__", json.dumps(str(REPO)))
                    .replace("__CLIENT__", json.dumps(CLIENT_HOST))
                    .replace("__CATALOG__", json.dumps({k: {
                        "desc": v["desc"], "root": v["root"],
                        "aggressive": v["aggressive"], "params": v["params"],
                    } for k, v in WORKLOADS.items()})))
            return self._send(200, page, "text/html; charset=utf-8")
        if p.path == "/api/stream":
            rid = parse_qs(p.query).get("id", [""])[0]
            run = RUNS.get(rid)
            if not run:
                return self._send(404, "unknown run")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            q, backlog, done = run.subscribe()
            try:
                for line in backlog:
                    self.wfile.write(b"data: " + line.encode() + b"\n\n")
                self.wfile.flush()
                if done:
                    return
                while True:
                    try:
                        line = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        continue
                    self.wfile.write(b"data: " + line.encode() + b"\n\n")
                    self.wfile.flush()
                    if line.startswith('{"__event__":"end"'):
                        return
            except (BrokenPipeError, ConnectionResetError):
                return
        if p.path == "/api/history":
            with _hist_lock:
                data = list(HISTORY)
            return self._send(200, json.dumps(data), "application/json")
        if p.path == "/api/runs":
            data = [{"id": r.id, "cmd": r.cmdline, "started": r.started,
                     "ended": r.ended, "rc": r.returncode} for r in RUNS.values()]
            return self._send(200, json.dumps(data), "application/json")
        return self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == "/api/run":
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            wl = body.get("workload")
            if wl not in WORKLOADS:
                return self._send(400, json.dumps({"error": "unknown workload"}),
                                  "application/json")
            # Remote client mode requires SRX_CLIENT_HOST; local mode is fine.
            target = (body.get("target") or "").strip()
            src = (body.get("src") or "").strip()
            if not target:
                return self._send(400, json.dumps({"error": "target required"}),
                                  "application/json")
            run = spawn_run(wl, target, src, body.get("params") or {}, root_ok=True)
            return self._send(200, json.dumps({"id": run.id, "cmd": run.cmdline}),
                              "application/json")
        if p.path == "/api/kill":
            rid = parse_qs(p.query).get("id", [""])[0]
            run = RUNS.get(rid)
            if not run:
                return self._send(404, json.dumps({"error": "unknown run"}),
                                  "application/json")
            killed = kill_run(run)
            return self._send(200, json.dumps({"killed": killed}),
                              "application/json")
        return self._send(404, "not found")


if __name__ == "__main__":
    print(f"SRX workload dashboard on http://0.0.0.0:{PORT}")
    print(f"repo: {REPO}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
