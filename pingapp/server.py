#!/usr/bin/env python3
"""Ping a target with default-size AND large do-not-fragment packets; expose live stats over HTTP."""
import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- Configuration ---------------------------------------------------------
# All host-, IP-, and identifier-bearing settings come from the environment so
# nothing operator-specific ends up in git. See `config.env.example`.

def _envstr(name, default):
    return os.environ.get(name, default)


def _envint(name, default):
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


def _envfloat(name, default):
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


# Ping targets and cadence
TARGET = _envstr("PING_TARGET", "192.0.2.1")            # RFC 5737 TEST-NET-1 placeholder
INTERVAL = _envfloat("PING_INTERVAL", 1.0)
BIG_SIZE = _envint("PING_BIG_SIZE", 1252)               # payload for DF probe

# HTTP server
PORT = _envint("PING_PORT", 8080)

# Retention
HISTORY = _envint("PING_HISTORY_SAMPLES", 300)          # raw samples for live chart
BUCKET_SEC = _envint("PING_BUCKET_SEC", 60)             # aggregation window
RETAIN_DAYS = _envint("PING_RETAIN_DAYS", 7)
BUCKETS = 60 * 24 * RETAIN_DAYS // (BUCKET_SEC // 60 or 1)
_APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.environ.get("PING_STATE_FILE", os.path.join(_APP_DIR, "state.json"))

# WiFi monitor (remote SSH). Leave WIFI_HOST empty to disable the WiFi probe.
WIFI_HOST = _envstr("WIFI_HOST", "")                    # e.g. user@192.0.2.10
WIFI_IFACE = _envstr("WIFI_IFACE", "wlan0")
WIFI_SSID = _envstr("WIFI_SSID", "")                    # displayed label only
WIFI_INTERVAL = _envfloat("WIFI_INTERVAL", 3.0)

# --- Nightly quiet window: pause probing 23:59 -> 08:00 local time ---
QUIET_START = (23, 59)   # inclusive
QUIET_END = (8, 0)       # exclusive


def in_quiet_hours(ts=None):
    """True when local time is inside the nightly pause window."""
    lt = time.localtime(ts if ts is not None else time.time())
    now = lt.tm_hour * 60 + lt.tm_min
    a = QUIET_START[0] * 60 + QUIET_START[1]
    b = QUIET_END[0] * 60 + QUIET_END[1]
    return (now >= a or now < b) if a > b else (a <= now < b)

lock = threading.Lock()
samples = deque(maxlen=HISTORY)
big_samples = deque(maxlen=HISTORY)
wifi_samples = deque(maxlen=HISTORY)
wifi_state = {"connected": False, "ssid": None, "bssid": None, "freq": None,
              "signal": None, "rx_bitrate": None, "tx_bitrate": None,
              "error": "starting", "last_ok": None, "samples_ok": 0, "samples_total": 0}
buckets = {"default": deque(maxlen=BUCKETS), "big": deque(maxlen=BUCKETS),
           "wifi": deque(maxlen=BUCKETS)}
cur = {"default": None, "big": None, "wifi": None}
stats = {"sent": 0, "recv": 0, "big_sent": 0, "big_recv": 0,
         "big_err": "", "started": time.time()}


def _bucket_id(ts):
    return int(ts // BUCKET_SEC) * BUCKET_SEC


def add_to_bucket(kind, ts, rtt):
    """Fold one sample into the rolling 1-minute buckets (24h window)."""
    bid = _bucket_id(ts)
    b = cur[kind]
    if b is None or b["id"] != bid:
        if b is not None:
            buckets[kind].append(b)
        b = {"id": bid, "sent": 0, "recv": 0, "sum": 0.0,
             "min": None, "max": None}
        cur[kind] = b
    b["sent"] += 1
    if rtt is not None:
        b["recv"] += 1
        b["sum"] += rtt
        b["min"] = rtt if b["min"] is None else min(b["min"], rtt)
        b["max"] = rtt if b["max"] is None else max(b["max"], rtt)


def bucket_series(kind, hours=24):
    out = []
    cutoff = time.time() - hours * 3600
    src = list(buckets[kind]) + ([cur[kind]] if cur[kind] else [])
    for b in src:
        if b["id"] < cutoff:
            continue
        out.append({
            "t": b["id"],
            "avg": (b["sum"] / b["recv"]) if b["recv"] else None,
            "min": b["min"], "max": b["max"],
            "sent": b["sent"], "recv": b["recv"],
            "loss_pct": 100.0 * (b["sent"] - b["recv"]) / b["sent"] if b["sent"] else 0.0,
        })
    return out


def day_summary(kind, hours=24, downsample=1):
    ser = bucket_series(kind, hours)
    sent = sum(b["sent"] for b in ser)
    recv = sum(b["recv"] for b in ser)
    avgs = [b["avg"] for b in ser if b["avg"] is not None]
    mins = [b["min"] for b in ser if b["min"] is not None]
    maxs = [b["max"] for b in ser if b["max"] is not None]
    outage = sum(1 for b in ser if b["recv"] == 0 and b["sent"] > 0)
    return {
        "sent": sent, "recv": recv, "lost": sent - recv,
        "loss_pct": 100.0 * (sent - recv) / sent if sent else 0.0,
        "avg": sum(avgs) / len(avgs) if avgs else None,
        "min": min(mins) if mins else None,
        "max": max(maxs) if maxs else None,
        "availability": 100.0 * recv / sent if sent else 0.0,
        "outage_min": outage,
        "window_min": len(ser),
        "hours": hours,
        "series": downsample_series(ser, downsample),
    }


def downsample_series(ser, factor):
    """Merge every `factor` buckets so week charts stay light over the wire."""
    if factor <= 1 or not ser:
        return ser
    out = []
    for i in range(0, len(ser), factor):
        chunk = ser[i:i + factor]
        avgs = [c["avg"] for c in chunk if c["avg"] is not None]
        mins = [c["min"] for c in chunk if c["min"] is not None]
        maxs = [c["max"] for c in chunk if c["max"] is not None]
        sent = sum(c["sent"] for c in chunk)
        recv = sum(c["recv"] for c in chunk)
        out.append({
            "t": chunk[0]["t"],
            "avg": sum(avgs) / len(avgs) if avgs else None,
            "min": min(mins) if mins else None,
            "max": max(maxs) if maxs else None,
            "sent": sent, "recv": recv,
            "loss_pct": 100.0 * (sent - recv) / sent if sent else 0.0,
        })
    return out


def save_state():
    try:
        with lock:
            data = {"buckets": {k: list(v) for k, v in buckets.items()},
                    "cur": cur, "stats": stats}
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE_FILE)
        try:
            dfd = os.open(_APP_DIR, os.O_RDONLY)
            os.fsync(dfd)
            os.close(dfd)
        except Exception:
            pass
    except Exception:
        pass


def load_state():
    try:
        with open(STATE_FILE) as f:
            d = json.load(f)
        floor = time.time() - RETAIN_DAYS * 24 * 3600
        for k in ("default", "big", "wifi"):
            for b in d.get("buckets", {}).get(k, []):
                if b.get("id", 0) >= floor:
                    buckets[k].append(b)
            cur[k] = d.get("cur", {}).get(k)
        stats.update({k: v for k, v in d.get("stats", {}).items() if k in stats})
    except Exception:
        pass

RTT_RE = re.compile(r"time[=<]([\d.]+)\s*ms")


def ping_once(size=None):
    """Return (rtt_ms_or_None, error_text)."""
    cmd = ["ping", "-c", "1", "-W", "2"]
    if size is not None:
        cmd += ["-s", str(size), "-M", "do"]
    cmd.append(TARGET)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = (p.stdout + p.stderr).lower()
        m = RTT_RE.search(out)
        if m:
            return float(m.group(1)), ""
        if "too long" in out:
            return None, "local interface MTU too small for %d+28 bytes" % (size or 0)
        if "frag needed" in out:
            return None, "fragmentation needed (path MTU is smaller)"
        return None, "timeout / no reply"
    except Exception as e:
        return None, str(e)


def worker():
    while True:
        if in_quiet_hours():
            save_state()
            time.sleep(20)
            continue
        rtt, _ = ping_once()
        brtt, berr = ping_once(BIG_SIZE)
        now = time.time()
        with lock:
            stats["sent"] += 1
            if rtt is not None:
                stats["recv"] += 1
            samples.append({"t": now, "rtt": rtt})
            stats["big_sent"] += 1
            if brtt is not None:
                stats["big_recv"] += 1
            stats["big_err"] = berr
            big_samples.append({"t": now, "rtt": brtt})
            add_to_bucket("default", now, rtt)
            add_to_bucket("big", now, brtt)
        if now - stats.get("_last_save", 0) >= 15:
            stats["_last_save"] = now
            save_state()
        time.sleep(INTERVAL)



def parse_link(text):
    """Parse `iw dev <if> link` output."""
    out = {"connected": False, "ssid": None, "bssid": None, "freq": None,
           "signal": None, "rx_bitrate": None, "tx_bitrate": None}
    if "Not connected" in text:
        return out
    m = re.search(r"Connected to ([0-9a-f:]{17})", text, re.I)
    if m:
        out["connected"] = True
        out["bssid"] = m.group(1)
    m = re.search(r"SSID:\s*(.+)", text)
    if m:
        out["ssid"] = m.group(1).strip()
    m = re.search(r"freq:\s*([\d.]+)", text)
    if m:
        out["freq"] = float(m.group(1))
    m = re.search(r"signal:\s*(-?\d+)\s*dBm", text)
    if m:
        out["signal"] = int(m.group(1))
    m = re.search(r"rx bitrate:\s*([\d.]+)\s*MBit/s", text)
    if m:
        out["rx_bitrate"] = float(m.group(1))
    m = re.search(r"tx bitrate:\s*([\d.]+)\s*MBit/s", text)
    if m:
        out["tx_bitrate"] = float(m.group(1))
    return out


def wifi_worker():
    """Hold one SSH session open, emitting a link snapshot every WIFI_INTERVAL."""
    remote = ("while true; do echo '===MARK==='; "
              "iw dev %s link 2>&1; sleep %s; done" % (WIFI_IFACE, WIFI_INTERVAL))
    while True:
        if in_quiet_hours():
            with lock:
                wifi_state["error"] = "paused (quiet hours 23:59-08:00)"
                wifi_state["connected"] = False
            time.sleep(20)
            continue
        proc = None
        try:
            proc = subprocess.Popen(
                ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
                 "-o", "ServerAliveCountMax=3", WIFI_HOST, remote],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            block_lines = []
            for line in proc.stdout:
                if in_quiet_hours():
                    break
                if "===MARK===" in line:
                    if block_lines:
                        record_wifi("".join(block_lines))
                    block_lines = []
                else:
                    block_lines.append(line)
            record_wifi_error("ssh stream ended")
        except Exception as e:
            record_wifi_error("ssh error: %s" % e)
        finally:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
        time.sleep(5)


def record_wifi(text):
    info = parse_link(text)
    now = time.time()
    with lock:
        wifi_state.update(info)
        wifi_state["samples_total"] += 1
        if info["connected"] and info["signal"] is not None:
            wifi_state["error"] = ""
            wifi_state["last_ok"] = now
            wifi_state["samples_ok"] += 1
        else:
            wifi_state["error"] = "not connected"
        wifi_samples.append({"t": now, "rtt": info["signal"],
                             "rx": info["rx_bitrate"], "tx": info["tx_bitrate"]})
        add_to_bucket("wifi", now, info["signal"])


def record_wifi_error(msg):
    now = time.time()
    with lock:
        wifi_state["error"] = msg
        wifi_state["connected"] = False
        wifi_state["signal"] = None
        wifi_state["samples_total"] += 1
        wifi_samples.append({"t": now, "rtt": None, "rx": None, "tx": None})
        add_to_bucket("wifi", now, None)


def block(data, sent, recv):
    ok = [s["rtt"] for s in data if s["rtt"] is not None]
    jit = None
    if len(ok) > 1:
        jit = sum(abs(ok[i] - ok[i - 1]) for i in range(1, len(ok))) / (len(ok) - 1)
    return {
        "sent": sent, "recv": recv, "lost": sent - recv,
        "loss_pct": 100.0 * (sent - recv) / sent if sent else 0.0,
        "last": data[-1]["rtt"] if data else None,
        "min": min(ok) if ok else None,
        "max": max(ok) if ok else None,
        "avg": sum(ok) / len(ok) if ok else None,
        "jitter": jit,
        "samples": data,
    }



def wifi_block():
    with lock:
        data = list(wifi_samples)
        st = dict(wifi_state)
    sig = [s["rtt"] for s in data if s["rtt"] is not None]
    return {
        "host": WIFI_HOST, "iface": WIFI_IFACE, "ssid_target": WIFI_SSID,
        "connected": st["connected"], "ssid": st["ssid"], "bssid": st["bssid"],
        "freq": st["freq"], "error": st["error"],
        "rx_bitrate": st["rx_bitrate"], "tx_bitrate": st["tx_bitrate"],
        "last": data[-1]["rtt"] if data else None,
        "min": min(sig) if sig else None,
        "max": max(sig) if sig else None,
        "avg": sum(sig) / len(sig) if sig else None,
        "sent": st["samples_total"], "recv": st["samples_ok"],
        "loss_pct": (100.0 * (st["samples_total"] - st["samples_ok"]) / st["samples_total"]
                     if st["samples_total"] else 0.0),
        "samples": data,
    }


def snapshot():
    with lock:
        data, bdata = list(samples), list(big_samples)
        s, r = stats["sent"], stats["recv"]
        bs, br, berr = stats["big_sent"], stats["big_recv"], stats["big_err"]
        started = stats["started"]
    big = block(bdata, bs, br)
    big.update({"size": BIG_SIZE, "total": BIG_SIZE + 28, "error": berr})
    return {
        "target": TARGET,
        "interval": INTERVAL,
        "uptime": time.time() - started,
        "default": block(data, s, r),
        "big": big,
        "paused": in_quiet_hours(),
        "quiet_window": "%02d:%02d-%02d:%02d" % (QUIET_START[0], QUIET_START[1],
                                                 QUIET_END[0], QUIET_END[1]),
        "wifi": wifi_block(),
        "day": {"default": day_summary("default"), "big": day_summary("big"),
                "wifi": day_summary("wifi"), "bucket_sec": BUCKET_SEC},
        "week": {"default": day_summary("default", 24 * RETAIN_DAYS, 15),
                 "big": day_summary("big", 24 * RETAIN_DAYS, 15),
                 "wifi": day_summary("wifi", 24 * RETAIN_DAYS, 15),
                 "days": RETAIN_DAYS},
    }


PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Ping Monitor</title>
<style>
 body{background:#0d1117;color:#e6edf3;font-family:system-ui,Segoe UI,sans-serif;margin:0;padding:2rem}
 h1{font-size:1.3rem;font-weight:600;margin:0 0 .3rem}
 h2{font-size:.95rem;font-weight:600;margin:2rem 0 .8rem;color:#c9d1d9}
 .sub{color:#8b949e;font-size:.85rem}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1rem}
 .card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1rem}
 .lbl{color:#8b949e;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
 .val{font-size:1.6rem;font-weight:600;margin-top:.3rem}
 .sm{font-size:1.1rem}
 .good{color:#3fb950}.warn{color:#d29922}.bad{color:#f85149}
 canvas{background:#161b22;border:1px solid #30363d;border-radius:10px;width:100%;height:200px}
 .err{background:#2d1618;border:1px solid #f8514966;color:#ffa198;border-radius:8px;
      padding:.6rem .9rem;font-size:.82rem;margin-bottom:1rem;display:none}
</style></head><body>
<h1>Ping Monitor &mdash; <span id="target">...</span></h1>
<div class="sub" id="sub">connecting...</div>

<h2>Default packet (56 bytes payload)</h2>
<div class="grid">
 <div class="card"><div class="lbl">Last RTT</div><div class="val" id="a_last">-</div></div>
 <div class="card"><div class="lbl">Average</div><div class="val" id="a_avg">-</div></div>
 <div class="card"><div class="lbl">Min / Max</div><div class="val sm" id="a_mm">-</div></div>
 <div class="card"><div class="lbl">Jitter</div><div class="val" id="a_jit">-</div></div>
 <div class="card"><div class="lbl">Packet Loss</div><div class="val" id="a_loss">-</div></div>
 <div class="card"><div class="lbl">Sent / Recv</div><div class="val sm" id="a_sr">-</div></div>
</div>
<canvas id="c1"></canvas>

<h2 id="bigh">Large packet, do-not-fragment</h2>
<div class="err" id="bigerr"></div>
<div class="grid">
 <div class="card"><div class="lbl">Last RTT</div><div class="val" id="b_last">-</div></div>
 <div class="card"><div class="lbl">Average</div><div class="val" id="b_avg">-</div></div>
 <div class="card"><div class="lbl">Min / Max</div><div class="val sm" id="b_mm">-</div></div>
 <div class="card"><div class="lbl">Jitter</div><div class="val" id="b_jit">-</div></div>
 <div class="card"><div class="lbl">Packet Loss</div><div class="val" id="b_loss">-</div></div>
 <div class="card"><div class="lbl">Sent / Recv</div><div class="val sm" id="b_sr">-</div></div>
</div>
<canvas id="c2"></canvas>

<h2 id="wifih">WiFi signal</h2>
<div class="err" id="wifierr"></div>
<div class="grid">
 <div class="card"><div class="lbl">Signal</div><div class="val" id="w_last">-</div></div>
 <div class="card"><div class="lbl">Average</div><div class="val" id="w_avg">-</div></div>
 <div class="card"><div class="lbl">Min / Max</div><div class="val sm" id="w_mm">-</div></div>
 <div class="card"><div class="lbl">Quality</div><div class="val" id="w_q">-</div></div>
 <div class="card"><div class="lbl">RX / TX rate</div><div class="val sm" id="w_rate">-</div></div>
 <div class="card"><div class="lbl">BSSID / Freq</div><div class="val sm" id="w_bss">-</div></div>
</div>
<canvas id="c4"></canvas>

<h2>Last 24 hours &mdash; 1-minute aggregates</h2>
<div class="grid">
 <div class="card"><div class="lbl">Availability (default)</div><div class="val" id="d_avail">-</div></div>
 <div class="card"><div class="lbl">Availability (DF)</div><div class="val" id="d_bavail">-</div></div>
 <div class="card"><div class="lbl">Avg RTT (default)</div><div class="val" id="d_avg">-</div></div>
 <div class="card"><div class="lbl">Avg RTT (DF)</div><div class="val" id="d_bavg">-</div></div>
 <div class="card"><div class="lbl">Min / Max 24h</div><div class="val sm" id="d_mm">-</div></div>
 <div class="card"><div class="lbl">Outage minutes</div><div class="val" id="d_out">-</div></div>
 <div class="card"><div class="lbl">Packets 24h</div><div class="val sm" id="d_pk">-</div></div>
 <div class="card"><div class="lbl">Window covered</div><div class="val sm" id="d_win">-</div></div>
 <div class="card"><div class="lbl">Avg signal 24h</div><div class="val" id="d_wavg">-</div></div>
 <div class="card"><div class="lbl">Signal min / max 24h</div><div class="val sm" id="d_wmm">-</div></div>
 <div class="card"><div class="lbl">WiFi uptime 24h</div><div class="val" id="d_wup">-</div></div>
 <div class="card"><div class="lbl">WiFi drop minutes</div><div class="val" id="d_wout">-</div></div>
</div>
<canvas id="c3" style="height:220px"></canvas>
<div class="sub" style="margin-top:.5rem;margin-bottom:1.2rem">
 <span style="color:#58a6ff">&#9632;</span> default RTT &nbsp;
 <span style="color:#d29922">&#9632;</span> DF RTT &nbsp;
 <span style="color:#f85149">&#9632;</span> ping loss
</div>
<canvas id="c5" style="height:200px"></canvas>
<div class="sub" style="margin-top:.5rem">
 <span style="color:#3fb950">&#9632;</span> WiFi signal dBm (24h) &nbsp;
 <span style="color:#f85149">&#9632;</span> disconnects
</div>

<h2>Last 7 days &mdash; 15-minute aggregates</h2>
<div class="grid">
 <div class="card"><div class="lbl">Availability (default)</div><div class="val" id="k_avail">-</div></div>
 <div class="card"><div class="lbl">Availability (DF)</div><div class="val" id="k_bavail">-</div></div>
 <div class="card"><div class="lbl">Avg RTT (default)</div><div class="val" id="k_avg">-</div></div>
 <div class="card"><div class="lbl">Avg signal</div><div class="val" id="k_wavg">-</div></div>
 <div class="card"><div class="lbl">RTT min / max</div><div class="val sm" id="k_mm">-</div></div>
 <div class="card"><div class="lbl">Signal min / max</div><div class="val sm" id="k_wmm">-</div></div>
 <div class="card"><div class="lbl">Outage minutes</div><div class="val" id="k_out">-</div></div>
 <div class="card"><div class="lbl">History covered</div><div class="val sm" id="k_win">-</div></div>
</div>
<canvas id="c6" style="height:220px"></canvas>
<div class="sub" style="margin-top:.5rem;margin-bottom:1.2rem">
 <span style="color:#58a6ff">&#9632;</span> default RTT &nbsp;
 <span style="color:#d29922">&#9632;</span> DF RTT &nbsp;
 <span style="color:#f85149">&#9632;</span> ping loss
</div>
<canvas id="c7" style="height:200px"></canvas>
<div class="sub" style="margin-top:.5rem">
 <span style="color:#3fb950">&#9632;</span> WiFi signal dBm (7d) &nbsp;
 <span style="color:#f85149">&#9632;</span> disconnects
</div>

<script>
var $=function(i){return document.getElementById(i)};
function f(v,u){if(u===undefined)u=' ms';return v==null?'-':v.toFixed(1)+u}
function cls(el,v,a,b){el.className='val '+(v==null?'bad':v<a?'good':v<b?'warn':'bad')}
function sigcls(el,v){var c=v==null?'bad':(v>=-60?'good':v>=-70?'warn':'bad');
 el.className=el.className.replace(/good|warn|bad/g,'')+' '+c}
function quality(d){return d>=-50?'Excellent':d>=-60?'Good':d>=-67?'Fair':d>=-75?'Weak':'Very weak'}
function fill(p,d,failtext){
 $(p+'_last').textContent=d.last==null?failtext:f(d.last); cls($(p+'_last'),d.last,30,120);
 $(p+'_avg').textContent=f(d.avg);
 $(p+'_mm').textContent=d.min==null?'-':f(d.min,'')+' / '+f(d.max);
 $(p+'_jit').textContent=f(d.jitter);
 $(p+'_loss').textContent=d.loss_pct.toFixed(1)+' %'; cls($(p+'_loss'),d.loss_pct,0.001,5);
 $(p+'_loss').className+=' sm';
 $(p+'_sr').textContent=d.sent+' / '+d.recv;
}
function tick(){
 fetch('/api/stats').then(function(r){return r.json()}).then(function(d){
  $('target').textContent=d.target;
  $('sub').textContent='every '+d.interval+'s \\u00b7 running '+Math.floor(d.uptime/60)+'m '+Math.floor(d.uptime%60)+'s';
  fill('a',d.default,'TIMEOUT');
  fill('b',d.big,'FAIL');
  $('bigh').textContent='Large packet, do-not-fragment ('+d.big.size+' B payload / '+d.big.total+' B on wire)';
  var e=$('bigerr');
  if(d.big.error){e.style.display='block';e.textContent='\\u26a0 '+d.big.error}else{e.style.display='none'}
  draw('c1',d.default.samples,'#58a6ff');
  draw('c2',d.big.samples,'#d29922');
  var A=d.day.default,B=d.day.big;
  $('d_avail').textContent=A.availability.toFixed(2)+' %'; cls($('d_avail'),100-A.availability,0.01,1);
  $('d_bavail').textContent=B.availability.toFixed(2)+' %'; cls($('d_bavail'),100-B.availability,0.01,1);
  $('d_avg').textContent=f(A.avg);
  $('d_bavg').textContent=f(B.avg);
  $('d_mm').textContent=A.min==null?'-':f(A.min,'')+' / '+f(A.max);
  $('d_mm').className='val sm';
  $('d_out').textContent=A.outage_min+' min'; cls($('d_out'),A.outage_min,1,5);
  $('d_pk').textContent=(A.sent+B.sent)+' sent, '+(A.lost+B.lost)+' lost';
  $('d_pk').className='val sm';
  var h=Math.floor(A.window_min/60),m=A.window_min%60;
  $('d_win').textContent=h+'h '+m+'m of 24h';
  $('d_win').className='val sm';
  var w=d.wifi;
  $('wifih').textContent='WiFi signal \u2014 '+(w.ssid||w.ssid_target)+' ('+w.iface+' @ '+w.host+')';
  $('w_last').textContent=w.last==null?'DOWN':w.last+' dBm';
  sigcls($('w_last'),w.last);
  $('w_avg').textContent=w.avg==null?'-':w.avg.toFixed(1)+' dBm';
  $('w_mm').textContent=w.min==null?'-':w.min+' / '+w.max+' dBm';
  $('w_mm').className='val sm';
  $('w_q').textContent=w.last==null?'-':quality(w.last);
  sigcls($('w_q'),w.last);
  $('w_rate').textContent=(w.rx_bitrate==null?'-':w.rx_bitrate.toFixed(1))+' / '+
                          (w.tx_bitrate==null?'-':w.tx_bitrate.toFixed(1))+' Mb/s';
  $('w_rate').className='val sm';
  $('w_bss').textContent=(w.bssid||'-')+(w.freq?' @ '+w.freq+' MHz':'');
  $('w_bss').className='val sm';
  var we=$('wifierr');
  if(w.error){we.style.display='block';we.textContent='\u26a0 '+w.error}else{we.style.display='none'}
  draw('c4',w.samples,'#3fb950',true);

  var Wd=d.day.wifi;
  $('d_wavg').textContent=Wd.avg==null?'-':Wd.avg.toFixed(1)+' dBm';
  sigcls($('d_wavg'),Wd.avg);
  $('d_wmm').textContent=Wd.min==null?'-':Wd.min+' / '+Wd.max+' dBm';
  $('d_wmm').className='val sm';
  $('d_wup').textContent=Wd.availability.toFixed(2)+' %';
  cls($('d_wup'),100-Wd.availability,0.01,1);
  $('d_wout').textContent=Wd.outage_min+' min';
  cls($('d_wout'),Wd.outage_min,1,5);

  drawDay(A.series,B.series);
  drawWifiDay(Wd.series);

  var K=d.week.default,KB=d.week.big,KW=d.week.wifi;
  $('k_avail').textContent=K.availability.toFixed(2)+' %'; cls($('k_avail'),100-K.availability,0.01,1);
  $('k_bavail').textContent=KB.availability.toFixed(2)+' %'; cls($('k_bavail'),100-KB.availability,0.01,1);
  $('k_avg').textContent=f(K.avg);
  $('k_wavg').textContent=KW.avg==null?'-':KW.avg.toFixed(1)+' dBm'; sigcls($('k_wavg'),KW.avg);
  $('k_mm').textContent=K.min==null?'-':f(K.min,'')+' / '+f(K.max); $('k_mm').className='val sm';
  $('k_wmm').textContent=KW.min==null?'-':KW.min+' / '+KW.max+' dBm'; $('k_wmm').className='val sm';
  $('k_out').textContent=K.outage_min+' min'; cls($('k_out'),K.outage_min,1,15);
  var kd=Math.floor(K.window_min/1440),kh=Math.floor((K.window_min%1440)/60);
  $('k_win').textContent=kd+'d '+kh+'h of '+d.week.days+'d'; $('k_win').className='val sm';
  drawRange('c6',[[K.series,'#58a6ff'],[KB.series,'#d29922']],K.series,d.week.days,false);
  drawRange('c7',[[KW.series,'#3fb950']],KW.series,d.week.days,true);
 }).catch(function(){$('sub').textContent='disconnected'});
}
function draw(id,s,color,dbm){
 var c=$(id),dpr=window.devicePixelRatio||1;
 c.width=c.clientWidth*dpr;c.height=c.clientHeight*dpr;
 var x=c.getContext('2d');x.scale(dpr,dpr);
 var W=c.clientWidth,H=c.clientHeight,P=24;
 x.clearRect(0,0,W,H);
 var ok=s.filter(function(v){return v.rtt!=null}).map(function(v){return v.rtt});
 var lo=dbm?-90:0, hi=dbm?-30:Math.max.apply(null,[10].concat(ok))*1.15;
 x.strokeStyle='#21262d';x.fillStyle='#8b949e';x.font='10px sans-serif';
 for(var i=0;i<=4;i++){var y=P+(H-2*P)*i/4;x.beginPath();x.moveTo(P,y);x.lineTo(W-8,y);x.stroke();
  x.fillText((hi-(hi-lo)*i/4).toFixed(0),2,y+3)}
 if(!s.length)return;
 var px=function(i){return P+(W-P-8)*(s.length<2?0:i/(s.length-1))};
 var py=function(v){var t=(Math.max(lo,Math.min(hi,v))-lo)/(hi-lo);return P+(H-2*P)*(1-t)};
 s.forEach(function(v,i){if(v.rtt==null){x.fillStyle='rgba(248,81,73,.35)';x.fillRect(px(i)-1,P,2,H-2*P)}});
 x.beginPath();x.strokeStyle=color;x.lineWidth=1.5;var st=false;
 s.forEach(function(v,i){if(v.rtt==null){st=false;return}
  if(!st){x.moveTo(px(i),py(v.rtt));st=true}else{x.lineTo(px(i),py(v.rtt))}});
 x.stroke();
}
function drawDay(a,b){
 var c=$('c3'),dpr=window.devicePixelRatio||1;
 c.width=c.clientWidth*dpr;c.height=c.clientHeight*dpr;
 var x=c.getContext('2d');x.scale(dpr,dpr);
 var W=c.clientWidth,H=c.clientHeight,P=30,B=18;
 x.clearRect(0,0,W,H);
 var now=Date.now()/1000, t0=now-86400;
 var all=a.concat(b).filter(function(v){return v.avg!=null}).map(function(v){return v.avg});
 var mx=Math.max.apply(null,[10].concat(all))*1.15;
 x.strokeStyle='#21262d';x.fillStyle='#8b949e';x.font='10px sans-serif';
 for(var i=0;i<=4;i++){var y=P+(H-P-B-P/2)*i/4;x.beginPath();x.moveTo(P,y);x.lineTo(W-8,y);x.stroke();
  x.fillText((mx*(1-i/4)).toFixed(0)+'ms',2,y+3)}
 for(var hh=24;hh>=0;hh-=6){var xx=P+(W-P-8)*(1-hh/24);
  x.fillText(hh===0?'now':'-'+hh+'h',xx-8,H-4)}
 var px=function(t){return P+(W-P-8)*Math.max(0,Math.min(1,(t-t0)/86400))};
 var py=function(v){return P+(H-P-B-P/2)*(1-Math.min(v,mx)/mx)};
 a.forEach(function(v){if(v.loss_pct>0){
   x.fillStyle='rgba(248,81,73,'+Math.min(1,0.2+v.loss_pct/100)+')';
   x.fillRect(px(v.t),H-B-6,Math.max(1,(W-P-8)/1440),6)}});
 [[a,'#58a6ff'],[b,'#d29922']].forEach(function(pair){
  var ser=pair[0];x.beginPath();x.strokeStyle=pair[1];x.lineWidth=1.4;var st=false;
  ser.forEach(function(v){if(v.avg==null){st=false;return}
   if(!st){x.moveTo(px(v.t),py(v.avg));st=true}else{x.lineTo(px(v.t),py(v.avg))}});
  x.stroke()});
}
function drawWifiDay(ser){
 var c=$('c5'),dpr=window.devicePixelRatio||1;
 c.width=c.clientWidth*dpr;c.height=c.clientHeight*dpr;
 var x=c.getContext('2d');x.scale(dpr,dpr);
 var W=c.clientWidth,H=c.clientHeight,P=30,B=18;
 x.clearRect(0,0,W,H);
 var now=Date.now()/1000,t0=now-86400,lo=-90,hi=-30;
 x.strokeStyle='#21262d';x.fillStyle='#8b949e';x.font='10px sans-serif';
 for(var i=0;i<=4;i++){var y=P+(H-P-B-P/2)*i/4;x.beginPath();x.moveTo(P,y);x.lineTo(W-8,y);x.stroke();
  x.fillText((hi-(hi-lo)*i/4).toFixed(0)+'dBm',2,y+3)}
 for(var hh=24;hh>=0;hh-=6){var xx=P+(W-P-8)*(1-hh/24);
  x.fillText(hh===0?'now':'-'+hh+'h',xx-8,H-4)}
 var px=function(t){return P+(W-P-8)*Math.max(0,Math.min(1,(t-t0)/86400))};
 var py=function(v){var t=(Math.max(lo,Math.min(hi,v))-lo)/(hi-lo);return P+(H-P-B-P/2)*(1-t)};
 ser.forEach(function(v){if(v.loss_pct>0){
   x.fillStyle='rgba(248,81,73,'+Math.min(1,0.2+v.loss_pct/100)+')';
   x.fillRect(px(v.t),H-B-6,Math.max(1,(W-P-8)/1440),6)}});
 x.beginPath();x.strokeStyle='#3fb950';x.lineWidth=1.4;var st=false;
 ser.forEach(function(v){if(v.avg==null){st=false;return}
  if(!st){x.moveTo(px(v.t),py(v.avg));st=true}else{x.lineTo(px(v.t),py(v.avg))}});
 x.stroke();
}
function drawRange(id,sets,lossSer,days,dbm){
 var c=$(id),dpr=window.devicePixelRatio||1;
 c.width=c.clientWidth*dpr;c.height=c.clientHeight*dpr;
 var x=c.getContext('2d');x.scale(dpr,dpr);
 var W=c.clientWidth,H=c.clientHeight,P=34,B=18;
 x.clearRect(0,0,W,H);
 var span=days*86400, now=Date.now()/1000, t0=now-span;
 var all=[];
 sets.forEach(function(p){p[0].forEach(function(v){if(v.avg!=null)all.push(v.avg)})});
 var lo=dbm?-90:0, hi=dbm?-30:Math.max.apply(null,[10].concat(all))*1.15;
 x.strokeStyle='#21262d';x.fillStyle='#8b949e';x.font='10px sans-serif';
 for(var i=0;i<=4;i++){var y=P+(H-P-B-P/2)*i/4;x.beginPath();x.moveTo(P,y);x.lineTo(W-8,y);x.stroke();
  x.fillText((hi-(hi-lo)*i/4).toFixed(0)+(dbm?'dBm':'ms'),2,y+3)}
 for(var dd=days;dd>=0;dd--){var xx=P+(W-P-8)*(1-dd/days);
  x.fillText(dd===0?'now':'-'+dd+'d',xx-8,H-4)}
 var px=function(t){return P+(W-P-8)*Math.max(0,Math.min(1,(t-t0)/span))};
 var py=function(v){var t=(Math.max(lo,Math.min(hi,v))-lo)/(hi-lo);return P+(H-P-B-P/2)*(1-t)};
 var bw=Math.max(1,(W-P-8)/(lossSer.length||1));
 lossSer.forEach(function(v){if(v.loss_pct>0){
   x.fillStyle='rgba(248,81,73,'+Math.min(1,0.2+v.loss_pct/100)+')';
   x.fillRect(px(v.t),H-B-6,bw,6)}});
 sets.forEach(function(pair){
  var ser=pair[0];x.beginPath();x.strokeStyle=pair[1];x.lineWidth=1.3;var st=false;
  ser.forEach(function(v){if(v.avg==null){st=false;return}
   if(!st){x.moveTo(px(v.t),py(v.avg));st=true}else{x.lineTo(px(v.t),py(v.avg))}});
  x.stroke()});
}
tick();setInterval(tick,1000);window.addEventListener('resize',tick);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/stats"):
            body, ctype = json.dumps(snapshot()).encode(), "application/json"
        elif self.path in ("/", "/index.html"):
            body, ctype = PAGE.encode(), "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _graceful(signum, frame):
    save_state()
    raise SystemExit(0)


if __name__ == "__main__":
    import signal
    for _sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            signal.signal(_sig, _graceful)
        except Exception:
            pass
    load_state()
    threading.Thread(target=worker, daemon=True).start()
    if WIFI_HOST:
        threading.Thread(target=wifi_worker, daemon=True).start()
    else:
        with lock:
            wifi_state["error"] = "WIFI_HOST unset (WiFi probe disabled)"
    print("Pinging %s (default + %dB DF) every %ss -> http://0.0.0.0:%d"
          % (TARGET, BIG_SIZE, INTERVAL, PORT))
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
