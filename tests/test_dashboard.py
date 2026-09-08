"""Offline dashboard tests: actual handler/functions, no sockets or workloads."""
import importlib.util
import io
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest


@pytest.fixture
def dash(monkeypatch, tmp_path):
    monkeypatch.setenv("SRX_HISTORY_FILE", str(tmp_path / "history.json"))
    monkeypatch.setenv("SRX_DASH_BIND", "127.0.0.1")
    monkeypatch.setenv("SRX_DASH_PORT", "8081")
    monkeypatch.delenv("SRX_DASH_PUBLIC_ORIGIN", raising=False)
    monkeypatch.delenv("SRX_DASH_TRUST_PROXY", raising=False)
    monkeypatch.delenv("SRX_CLIENT_HOST", raising=False)
    spec = importlib.util.spec_from_file_location(
        "dashboard_under_test", Path(__file__).parents[1] / "srx-dashboard/dashboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Any test that needs process creation must install its own fake explicitly.
    def forbidden(*args, **kwargs):
        raise AssertionError("real process/network execution forbidden")
    monkeypatch.setattr(module.subprocess, "Popen", forbidden)
    monkeypatch.setattr(module.os, "killpg", forbidden)
    monkeypatch.setattr(module, "ThreadingHTTPServer", forbidden)
    return module


class FakeConnection:
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()

    def makefile(self, mode, *args):
        assert mode == "rb"
        return self.input

    def sendall(self, data):
        self.output.extend(data)

    def settimeout(self, seconds):
        pass


def request(dash, method="POST", path="/api/run", body=None, headers=None, raw=None):
    if raw is None:
        raw = json.dumps(body).encode() if body is not None else b""
    hdr = {"Host": "localhost:8081", "Origin": "http://localhost:8081",
           "Content-Type": "application/json", "Content-Length": str(len(raw))}
    for key, value in (headers or {}).items():
        if value is None:
            hdr.pop(key, None)
        else:
            hdr[key] = value
    wire = f"{method} {path} HTTP/1.0\r\n".encode()
    wire += "".join(f"{k}: {v}\r\n" for k, v in hdr.items()).encode() + b"\r\n" + raw
    connection = FakeConnection(wire)
    dash.Handler(connection, ("127.0.0.1", 1234), SimpleNamespace())
    head, payload = bytes(connection.output).split(b"\r\n\r\n", 1)
    return int(head.split()[1]), payload


def valid(**extra):
    return {"workload": "http", "target": "192.0.2.1", "src": "", "params": {}, **extra}


def test_blank_src_local_and_remote(dash, monkeypatch):
    for host in ("", "tester@client"):
        monkeypatch.setattr(dash, "CLIENT_HOST", host)
        argv, sudo = dash.make_cmd("http", "192.0.2.1", "", {}, True)
        assert "--src" not in " ".join(argv)
        assert not sudo
        argv, _ = dash.make_cmd("http", "192.0.2.1", "192.0.2.2", {}, True)
        assert "--src" in " ".join(argv)


def test_terminal_typed_atomic_and_idempotent(dash):
    run = dash.Run("test", "fake", False)
    q, backlog, done = run.subscribe()
    assert not backlog and not done
    run.emit('{"__event__":"end","rc":99}')
    assert q.get_nowait()[1] == "log"  # logs cannot impersonate terminal events
    run.finish(0)
    terminal = q.get_nowait()
    assert terminal[1:] == ("end", {"rc": 0, "elapsed": run.ended - run.started})
    assert b"event: end\n" in dash.sse_frame(terminal)
    run.finish(99)
    run.emit("too late")
    assert run.returncode == 0 and len(run.events) == 2
    for last_id in (0, terminal[0], terminal[0] + 50):
        late, replay, done = run.subscribe(last_id)
        assert done and replay[-1] == terminal and late not in run.subscribers
    run.unsubscribe(q)
    assert not run.subscribers


def test_finish_subscribe_race(dash):
    for _ in range(50):
        run = dash.Run("race", "fake", False)
        barrier = threading.Barrier(2)
        def complete():
            barrier.wait()
            run.finish(0)
        worker = threading.Thread(target=complete)
        worker.start()
        barrier.wait()
        q, backlog, done = run.subscribe()
        worker.join(timeout=2)
        assert not worker.is_alive()
        events = backlog if done else [q.get(timeout=1)]
        assert sum(event[1] == "end" for event in events) == 1
        run.unsubscribe(q)


def test_logs_queues_and_replay_bounded(dash, monkeypatch):
    monkeypatch.setattr(dash, "MAX_LINES", 3)
    monkeypatch.setattr(dash, "MAX_LINE_CHARS", 8)
    monkeypatch.setattr(dash, "QUEUE_SIZE", 2)
    run = dash.Run("bounded", "fake", False)
    q, _, _ = run.subscribe()
    for _ in range(20):
        run.emit("x" * 100)
    assert len(run.lines) == len(run.events) == 3
    assert all(len(line) == 8 for line in run.lines)
    assert q.qsize() == 1 and q.get_nowait() is None
    assert q not in run.subscribers
    q, backlog, done = run.subscribe(1)
    assert backlog[0][1] == "reset" and len(backlog) == 4
    assert not done
    run.finish(0)
    assert q.get_nowait()[1] == "end"


@pytest.mark.parametrize("body", [
    [], None, "x", {"workload": []}, valid(extra=True), valid(target=[]),
    valid(target="--help"), valid(target="x\nHost: evil"), valid(src="not-ip"),
    valid(params=[]), valid(params={"unknown": 1}), valid(params={"port": True}),
    valid(params={"port": 1.5}), valid(params={"port": 0}),
    valid(params={"port": 65536}), valid(params={"port": "NaN"}),
    valid(params={"path": []}), valid(params={"path": "-bad"}),
    valid(workload="scan"), valid(workload="scan", confirm_aggressive="true"),
    valid(workload="scan", confirm_aggressive=True, params={"type": "bogus"}),
    valid(workload="wrk", params={"duration": 3601}), valid(request_id=[]),
])
def test_invalid_schema_never_spawns(dash, monkeypatch, body):
    called = []
    monkeypatch.setattr(dash, "spawn_run", lambda *a, **kw: called.append(a))
    status, _ = request(dash, body=body)
    assert status == 400 and not called


@pytest.mark.parametrize("headers,raw,status", [
    ({"Content-Length": "-1"}, b"{}", 400),
    ({"Content-Length": "abc"}, b"{}", 400),
    ({"Content-Length": None}, b"{}", 400),
    ({"Content-Length": "16385"}, b"{}", 413),
    ({"Content-Length": "100"}, b"{}", 400),
    ({"Transfer-Encoding": "chunked"}, b"{}", 400),
    ({"Content-Type": "text/plain"}, b"{}", 415),
    ({}, b"{bad", 400), ({}, b"\xff", 400),
])
def test_invalid_http_bodies(dash, headers, raw, status):
    assert request(dash, headers=headers, raw=raw)[0] == status


@pytest.mark.parametrize("headers", [
    {"Host": "attacker.example"}, {"Host": None}, {"Origin": None},
    {"Origin": "null"}, {"Origin": "http://attacker.example"},
    {"Origin": "http://127.0.0.1:8081"}, {"Sec-Fetch-Site": "cross-site"},
    {"Host": "attacker.example", "X-Forwarded-Host": "localhost:8081"},
])
def test_unauthorized_launch_and_kill(dash, headers):
    for path in ("/api/run", "/api/kill?id=unknown"):
        assert request(dash, path=path, body=valid(), headers=headers)[0] == 403


def test_get_host_origin_and_no_origin_navigation(dash):
    assert request(dash, "GET", "/api/runs", headers={"Origin": None})[0] == 200
    assert request(dash, "GET", "/", headers={"Host": "evil.example"})[0] == 403
    assert request(dash, "GET", "/api/history", headers={"Origin": "null"})[0] == 403


def test_nonloopback_fails_closed(dash, monkeypatch):
    monkeypatch.setattr(dash, "BIND", "0.0.0.0")
    with pytest.raises(ValueError, match="nonloopback"):
        dash.main()
    monkeypatch.setattr(dash, "TRUST_PROXY", True)
    with pytest.raises(ValueError):
        dash.allowed_origins()
    monkeypatch.setattr(dash, "PUBLIC_ORIGIN", "http://dashboard.example")
    with pytest.raises(ValueError, match="HTTPS"):
        dash.allowed_origins()
    monkeypatch.setattr(dash, "PUBLIC_ORIGIN", "https://dashboard.example")
    assert dash.allowed_origins() == {"https://dashboard.example"}
    assert request(dash, "GET", "/api/runs")[0] == 403
    assert request(dash, "GET", "/api/runs", headers={
        "Host": "dashboard.example", "Origin": "https://dashboard.example"})[0] == 200


def test_handler_completed_stream_and_cleanup(dash):
    run = dash.Run("done", "fake", False)
    dash.RUNS[run.id] = run
    run.emit("one\ntwo")
    run.finish(0)
    status, data = request(dash, "GET", "/api/stream?id=done")
    assert status == 200
    assert b'event: log\ndata: "one\\ntwo"' in data
    assert data.count(b"event: end") == 1
    assert not run.subscribers
    status, data = request(dash, "GET", "/api/stream?id=done",
                           headers={"Last-Event-ID": str(run.sequence)})
    assert status == 200 and data.count(b"event: end") == 1
    assert b"event: log" not in data
    assert request(dash, "GET", "/api/stream?id=done",
                   headers={"Last-Event-ID": "bad"})[0] == 400


def test_handler_disconnect_cleans_subscription(dash, monkeypatch):
    run = dash.Run("active", "fake", False)
    dash.RUNS[run.id] = run
    def broken(*a):
        raise BrokenPipeError()
    monkeypatch.setattr(FakeConnection, "sendall", broken)
    with pytest.raises(ValueError):  # helper cannot split an intentionally absent response
        request(dash, "GET", "/api/stream?id=active")
    assert not run.subscribers


def test_duplicate_admission_and_process_flags(dash, monkeypatch):
    started, release, done = threading.Event(), threading.Event(), threading.Event()
    calls = []
    class Output(io.StringIO):
        def readline(self, size=-1):
            started.set()
            assert release.wait(3)
            return super().readline(size)
    class Process:
        stdout = Output("fake output\n")
        returncode = 0
        def wait(self):
            return 0
        def poll(self):
            return 0
    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return Process()
    monkeypatch.setattr(dash.subprocess, "Popen", popen)
    original_finish = dash.Run.finish
    def finish(run, rc):
        original_finish(run, rc)
        done.set()
    monkeypatch.setattr(dash.Run, "finish", finish)
    body = valid(request_id="request-123")
    try:
        status, response = request(dash, body=body)
        assert status == 200 and started.wait(2)
        run_id = json.loads(response)["id"]
        assert request(dash, body=valid(request_id="request-456"))[0] == 409
        status, response = request(dash, body=body)
        assert status == 200 and json.loads(response)["id"] == run_id
        assert request(dash, body=valid(request_id="request-123", target="192.0.2.3"))[0] == 409
        assert len(calls) == 1
        assert calls[0][1]["start_new_session"] is True
        assert "preexec_fn" not in calls[0][1]
        assert "--src" not in calls[0][0]
    finally:
        release.set()
    assert done.wait(2)
    status, response = request(dash, body=body)
    assert status == 200 and json.loads(response)["id"] == run_id
    assert len(calls) == 1


def test_unexpected_process_failure_finishes(dash, monkeypatch):
    done = threading.Event()
    original = dash.Run.finish
    def finish(run, rc):
        original(run, rc)
        done.set()
    monkeypatch.setattr(dash.Run, "finish", finish)
    def fail(*args, **kwargs):
        raise RuntimeError("fake spawn failure")
    monkeypatch.setattr(dash.subprocess, "Popen", fail)
    run = dash.spawn_run("http", "192.0.2.1", "", {}, True)
    assert done.wait(2)
    assert run.snapshot()["terminal"]["rc"] == 1


def test_batch_history_failure_cannot_hide_terminal(dash, monkeypatch):
    def fail(run):
        raise OSError("fake history failure")
    monkeypatch.setattr(dash, "record_batch", fail)
    run = dash.Run("batch", "fake", False, workload="all")
    run.finish(0)
    assert run.snapshot()["terminal"]["history_error"] is True


def test_batch_history_old_and_new_cli_summary(dash):
    run = dash.Run("batch", "fake", False, workload="all")
    for line in ("WORKLOAD SUMMARY", "[OK] http: rc=0 elapsed=0.2s",
                 "[SUCCEEDED] dns: rc=0 elapsed=0.1s detection=not_evaluated",
                 "[FAILED] wrk: rc=1 elapsed=1.0s detection=not_evaluated - fake failure",
                 "[ERR] scan: rc=127 elapsed=0.0s - missing binary"):
        run.emit(line)
    run.finish(1)
    assert run.terminal[2]["batch"] == {"id": "batch", "passed": 2, "failed": 2, "total": 4}
    assert dash.HISTORY[0]["results"][2]["error"] == "fake failure"
    assert all(row["detection_status"] == "not_evaluated" for row in dash.HISTORY[0]["results"])


@pytest.mark.parametrize("workload,params", [
    ("wrk", {"duration": 301}), ("wrk", {"connections": 2, "threads": 3}),
    ("wrk", {"threads": 65}), ("iperf", {"parallel": 33}),
    ("scan", {"max-ports": 4097}), ("frag", {"count": 65}),
    ("flood", {"count": 10001}), ("flood", {"rate": 1001}),
    ("flood", {"count": 1000, "rate": 1}),
])
def test_default_cli_limits_checked_before_spawn(dash, workload, params):
    assert request(dash, body=valid(workload=workload, params=params,
                                    confirm_aggressive=True))[0] == 400


def test_simultaneous_admission(dash, monkeypatch):
    release, finished = threading.Event(), threading.Event()
    calls = []
    class Process:
        stdout = io.StringIO("")
        def wait(self):
            assert release.wait(3)
            return 0
        def poll(self):
            return None
    def popen(*args, **kwargs):
        calls.append(args)
        return Process()
    monkeypatch.setattr(dash.subprocess, "Popen", popen)
    original_finish = dash.Run.finish
    def finish(run, rc):
        original_finish(run, rc)
        finished.set()
    monkeypatch.setattr(dash.Run, "finish", finish)
    barrier = threading.Barrier(6)
    results = []
    def launch(index):
        barrier.wait()
        results.append(request(dash, body=valid(request_id=f"request-{index}"))[0])
    threads = [threading.Thread(target=launch, args=(i,)) for i in range(6)]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        assert sorted(results) == [200, 409, 409, 409, 409, 409]
        assert len(calls) == 1
    finally:
        release.set()
    assert finished.wait(2)


def test_stop_before_worker_start_prevents_spawn(dash, monkeypatch):
    workers = []
    class DeferredThread:
        def __init__(self, target, **kwargs):
            workers.append(target)
        def start(self):
            pass
    monkeypatch.setattr(dash, "threading", SimpleNamespace(Thread=DeferredThread, Lock=threading.Lock))
    run = dash.spawn_run("http", "192.0.2.1", "", {}, True)
    assert dash.kill_run(run)
    workers[0]()
    assert run.proc is None
    assert run.snapshot()["terminal"]["rc"] == -dash.signal.SIGTERM


def test_live_handler_stream_finishes_and_unsubscribes(dash, monkeypatch):
    run = dash.Run("live", "fake", False)
    dash.RUNS[run.id] = run
    original_sendall = FakeConnection.sendall
    def complete_on_headers(connection, data):
        original_sendall(connection, data)
        if b"Content-Type: text/event-stream" in data:
            run.emit("during stream")
            run.finish(0)
    monkeypatch.setattr(FakeConnection, "sendall", complete_on_headers)
    status, body = request(dash, "GET", "/api/stream?id=live")
    assert status == 200 and body.count(b"event: end") == 1
    assert b"during stream" in body and not run.subscribers


def test_subscriber_limit(dash, monkeypatch):
    monkeypatch.setattr(dash, "MAX_SUBSCRIBERS", 1)
    run = dash.Run("test", "fake", False)
    q, _, _ = run.subscribe()
    with pytest.raises(ValueError, match="subscribers"):
        run.subscribe()
    run.unsubscribe(q)
    run.subscribe()


def test_aborted_batch_without_summary_remains_in_history(dash):
    run = dash.Run("aborted", "fake", False, workload="all")
    run.emit("execution failed before summary")
    run.finish(127)
    entry = dash.HISTORY[-1]
    assert entry["id"] == "aborted"
    assert entry["summary_available"] is False
    assert entry["execution_status"] == "failed"
    assert entry["detection_status"] == "not_evaluated"
    assert entry["results"] == []
    assert run.terminal[2]["batch"]["total"] == 0
    assert json.loads(dash.HISTORY_FILE.read_text())[-1]["rc"] == 127


def test_real_history_write_failure_is_visible_in_terminal(dash, monkeypatch, tmp_path):
    monkeypatch.setattr(dash, "HISTORY_FILE", tmp_path / "missing" / "history.json")
    run = dash.Run("unwritable", "fake", False, workload="all")
    run.finish(1)
    assert run.terminal[2]["history_error"] is True
    assert run.terminal[2]["rc"] == 1
