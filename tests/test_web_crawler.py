"""Offline crawl coverage: real HTTP parser over in-memory sockets, never traffic."""
import importlib.util
import io
import json
from pathlib import Path
import socket
import ssl

import pytest

from deploy import srx_workload as cli
from generators import web_crawler as crawler

CONNECT = crawler._connect


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("real network forbidden in crawl tests")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(crawler, "_connect", forbidden)


class WireSocket:
    def __init__(self, wire, raw=None):
        self.raw = raw if raw is not None else io.BytesIO(wire)
        self.requests = []
        self.timeouts = []
        self.closed = False

    def makefile(self, mode, buffering=0):
        assert mode == "rb"
        return self.raw

    def setsockopt(self, *args):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def sendall(self, data):
        self.requests.append(data)

    def close(self):
        self.closed = True


def install(monkeypatch, body=b"", status=200, headers=None, raw=None):
    headers = {"Content-Type": "text/html; charset=utf-8", **(headers or {})}
    wire = f"HTTP/1.1 {status} Test\r\n".encode()
    wire += b"".join(f"{k}: {v}\r\n".encode() for k, v in headers.items())
    wire += b"\r\n" + body
    sock = WireSocket(wire, raw)
    connections = []
    def connect(address, deadline):
        connections.append(address)
        return sock
    monkeypatch.setattr(crawler, "_connect", connect)
    return sock, connections


def test_html_one_connection_no_assets_or_links_fetched(monkeypatch):
    body = ('<title>Café &amp; Test</title><p>Hello <b>world</b></p>'
            '<script>secret()</script><style>hidden</style><template>invisible</template>'
            '<img src="/asset"><a href="/local">Local</a>'
            '<a href="https://external.example/a">External</a>'
            '<a href="/local">Duplicate</a><a href="javascript:alert(1)">JS</a>'
            '<a href="http://user:password@example.com/">Credentials</a>').encode()
    sock, connections = install(monkeypatch, body, headers={"Content-Length": str(len(body))})
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["execution_status"] == "succeeded"
    assert result["status_code"] == 200
    assert result["bytes_received"] == len(body)
    assert result["response_complete"] and not result["truncated"]
    assert result["title"] == "Café & Test"
    assert "Hello world" in result["text"] and "secret" not in result["text"]
    assert "hidden" not in result["text"] and "invisible" not in result["text"]
    assert result["links"] == ["http://192.0.2.1/local", "https://external.example/a"]
    assert result["detection_status"] == "not_evaluated"
    assert result["elapsed_s"] >= 0
    assert len(connections) == len(sock.requests) == 1
    assert b"Accept-Encoding: identity" in sock.requests[0]
    assert sock.closed and sock.raw.closed
    json.dumps(result)


@pytest.mark.parametrize("location", ["https://evil.example/", "//evil.example/", "/same-origin"])
def test_all_redirects_rejected_before_destination_fetch(monkeypatch, location):
    sock, connections = install(monkeypatch, b"redirect body", 302, {"Location": location})
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["status_code"] == 302 and result["bytes_received"] == 0
    assert "redirect rejected" in result["error"]
    assert len(connections) == len(sock.requests) == 1


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://192.0.2.1/",
    "http://user:pass@192.0.2.1/", "http://@192.0.2.1/", "http://192.0.2.1:0/",
    "http://192.0.2.1:99999/", "http://192.0.2.1/\r\nX: bad",
    "http://192.0.2.1/%0aX", "http://192.0.2.1/#fragment", "http://192.0.2.1//evil"])
def test_bad_urls_fail_before_io(url):
    with pytest.raises(ValueError):
        crawler.crawl_page(url)


@pytest.mark.parametrize("path", ["//evil.example/", "https://evil.example/", "\\evil",
    "/\\evil", "/x\r\n", "/%0d%0aHost:x", "/%5cevil", "/a b", "/#fragment", "/" + "x" * 2048])
def test_bad_scoped_paths(path):
    with pytest.raises(ValueError):
        crawler.target_url("192.0.2.1", path)


def test_url_construction():
    assert crawler.target_url("192.0.2.1") == "http://192.0.2.1/"
    assert crawler.target_url("::1", "/a?q=b", "https", 8443) == "https://[::1]:8443/a?q=b"
    for target in ("a@evil.example", "http://evil.example", "host/path", "host:80"):
        with pytest.raises(ValueError):
            crawler.target_url(target)


@pytest.mark.parametrize("limits", [{"max_bytes": 0}, {"max_bytes": 4194305},
    {"timeout": 31}, {"timeout": 0}, {"timeout": True}, {"timeout": 1.5}])
def test_invalid_limits_before_io(limits):
    with pytest.raises(ValueError):
        crawler.crawl_page("http://192.0.2.1/", **limits)


@pytest.mark.parametrize("headers", [{}, {"Content-Length": "1000"}])
def test_byte_limit_retains_marked_partial_content(monkeypatch, headers):
    install(monkeypatch, b"<p>" + b"x" * 997, headers=headers)
    result = crawler.crawl_page("http://192.0.2.1/", max_bytes=80)
    assert result["bytes_received"] == 80
    assert result["truncated"] and not result["response_complete"]
    assert result["execution_status"] == "failed" and result["text"]


def test_exact_known_length_limit_succeeds(monkeypatch):
    install(monkeypatch, b"12345", headers={"Content-Length": "5"})
    assert crawler.crawl_page("http://192.0.2.1/", max_bytes=5)["response_complete"]


@pytest.mark.parametrize("body,headers", [
    (b"short", {"Content-Length": "100"}),
    (b"5\r\nabc", {"Transfer-Encoding": "chunked"}),
    (b"3\r\nabc\r\n", {"Transfer-Encoding": "chunked"}),
    (b"bad", {"Content-Length": "-1"}),
    (b"bad", {"Content-Length": "3", "Transfer-Encoding": "chunked"}),
])
def test_incomplete_or_bad_framing_fails(monkeypatch, body, headers):
    install(monkeypatch, body, headers=headers)
    result = crawler.crawl_page("http://192.0.2.1/")
    assert not result["response_complete"] and result["execution_status"] == "failed"
    assert result["error"]


def test_chunked_success(monkeypatch):
    install(monkeypatch, b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n", headers={"Transfer-Encoding": "chunked"})
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["response_complete"] and result["bytes_received"] == 5
    assert result["text"] == "abcde"


def test_compression_rejected_without_decompression(monkeypatch):
    install(monkeypatch, b"compressed", headers={"Content-Encoding": "gzip"})
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["bytes_received"] == 0 and "identity required" in result["error"]


@pytest.mark.parametrize("body,content_type,expected", [
    (b"<title>Caf\xe9</title>", "text/html; charset=iso-8859-1", "Café"),
    (b"<title>\xff</title>", "text/html; charset=unknown-charset", "�"),
    ("<title>Snow ☃</title>".encode("utf-16"), "text/html", "Snow ☃"),
])
def test_byte_charset_decoding(monkeypatch, body, content_type, expected):
    install(monkeypatch, body, headers={"Content-Type": content_type})
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["execution_status"] == "succeeded" and result["title"] == expected


def test_multibyte_boundary_and_bounded_output(monkeypatch):
    body = ("<title>" + "t" * 1000 + "</title><p>" + "é" * 20000 + "</p>" +
            "".join(f'<a href="/{i}">link</a>' for i in range(200))).encode()
    install(monkeypatch, body)
    result = crawler.crawl_page("http://192.0.2.1/")
    assert len(result["title"]) == 512 and len(result["text"]) == 2048
    assert "�" not in result["text"]
    assert len(result["links"]) == 20 and result["output_truncated"]


def test_plain_and_nontext_and_http_failure(monkeypatch):
    install(monkeypatch, b"<not-markup>", headers={"Content-Type": "text/plain"})
    assert crawler.crawl_page("http://192.0.2.1/")["text"] == "<not-markup>"
    install(monkeypatch, b"binary", headers={"Content-Type": "image/png"})
    assert crawler.crawl_page("http://192.0.2.1/")["text"] == ""
    install(monkeypatch, b"missing", status=404)
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["status_code"] == 404 and result["response_complete"]
    assert result["execution_status"] == "failed"


def test_deadline_covers_slow_headers_without_real_sleep(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(crawler.time, "monotonic", lambda: now[0])
    class SlowBytes(io.BytesIO):
        def readinto(self, buffer):
            now[0] += 0.4
            data = self.read(1)
            buffer[:len(data)] = data
            return len(data)
    sock, _ = install(monkeypatch, raw=SlowBytes(b"HTTP/1.1 200 OK\r\n\r\nhello"))
    result = crawler.crawl_page("http://192.0.2.1/", timeout=1)
    assert "deadline" in result["error"] and result["elapsed_s"] < 1.5
    assert sock.closed and sock.timeouts[-1] < sock.timeouts[0]


def test_https_verification_and_default_port(monkeypatch):
    sock, connections = install(monkeypatch, b"ok")
    def wrap(context, raw, server_hostname=None, **kwargs):
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        assert raw is sock and server_hostname == "192.0.2.1"
        return raw
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
    assert crawler.crawl_page("https://192.0.2.1/")["execution_status"] == "succeeded"
    assert connections == [("192.0.2.1", 443)]


def test_cli_metrics_and_standalone(monkeypatch, capsys):
    install(monkeypatch, b"<title>Lab</title>")
    args = cli.build_parser().parse_args(["--target", "192.0.2.1", "crawl"])
    result = args.func(args)
    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status_code"] == 200 and output["title"] == "Lab"
    assert output == result.metadata["result"]
    assert "crawl" not in cli.AGGRESSIVE | cli.CRAFTED
    all_args = cli.build_parser().parse_args(["--target", "192.0.2.1", "all"])
    assert len(cli.build_all_workloads(all_args)) == 18


@pytest.mark.parametrize("options", [["--path", "//evil"], ["--max-bytes", "4194305"],
    ["--timeout", "31"], ["--scheme", "ftp"], ["--port", "0"]])
def test_cli_validation(options):
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--target", "192.0.2.1", "crawl", *options])


@pytest.fixture
def dash(monkeypatch, tmp_path):
    monkeypatch.setenv("SRX_HISTORY_FILE", str(tmp_path / "history.json"))
    monkeypatch.delenv("SRX_CLIENT_HOST", raising=False)
    spec = importlib.util.spec_from_file_location("crawl_dashboard", Path(__file__).parents[1] / "srx-dashboard/dashboard.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_dashboard_card_and_string_numeric_validation(dash):
    card = dash.WORKLOADS["crawl"]
    assert not card["aggressive"] and not card["root"]
    wl, target, src, params, _ = dash.validate_request({"workload": "crawl", "target": "192.0.2.1",
        "params": {"path": "/page?q=1", "max-bytes": "1048576", "timeout": "10", "port": "80"}})
    argv, sudo = dash.make_cmd(wl, target, src, params, True)
    assert "crawl" in argv and "/page?q=1" in argv and not sudo
    assert params["max-bytes"] == 1048576


@pytest.mark.parametrize("params", [{"path": "//evil"}, {"path": "/%0d%0aX"},
    {"path": "/x\r\n"}, {"path": "/\\evil"}, {"path": "/#x"},
    {"max-bytes": 4194305}, {"timeout": 31}, {"timeout": True}, {"timeout": "1.5"}])
def test_dashboard_rejects_bad_crawl_params(dash, params):
    with pytest.raises(ValueError):
        dash.validate_request({"workload": "crawl", "target": "192.0.2.1", "params": params})


def test_meta_charset_and_decoder_boundary(monkeypatch):
    install(monkeypatch, b'<meta charset="iso-8859-1"><title>Caf\xe9</title>',
            headers={"Content-Type": "text/html"})
    result = crawler.crawl_page("http://192.0.2.1/")
    assert result["title"] == "Café" and result["charset"] == "iso-8859-1"
    # Split a two-byte code point across the 16 KiB decoder boundary.
    body = (" " * 16376 + "<title>" + "éclair</title>").encode()
    install(monkeypatch, body)
    assert crawler.crawl_page("http://192.0.2.1/")["title"] == "éclair"


def test_network_failure_is_structured_and_cli_nonzero(monkeypatch, capsys):
    def refused(*args):
        raise ConnectionRefusedError("fake connection refused")
    monkeypatch.setattr(crawler, "_connect", refused)
    assert cli.main(["--target", "192.0.2.1", "crawl"]) == 1
    output = capsys.readouterr().out
    assert '"status_code": null' in output
    assert '"bytes_received": 0' in output and "fake connection refused" in output


def test_slow_body_uses_remaining_global_time(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(crawler.time, "monotonic", lambda: now[0])
    headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    class SlowBody(io.BytesIO):
        def readinto(self, buffer):
            if self.tell() < len(headers):
                chunk = self.read(len(headers))
            else:
                now[0] += 0.4
                chunk = self.read(1)
            buffer[:len(chunk)] = chunk
            return len(chunk)
    sock, _ = install(monkeypatch, raw=SlowBody(headers + b"x" * 100))
    result = crawler.crawl_page("http://192.0.2.1/", timeout=1)
    assert result["status_code"] == 200 and result["bytes_received"] == 3
    assert result["execution_status"] == "failed" and not result["response_complete"]
    assert "deadline" in result["error"] and sock.closed


def test_connect_sets_remaining_timeout_and_closes_failed_socket(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(crawler.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw:
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 80))])
    sock = WireSocket(b"")
    sock.connect = lambda address: now.__setitem__(0, 0.5)
    monkeypatch.setattr(socket, "socket", lambda *a: sock)
    assert CONNECT(("192.0.2.1", 80), crawler._Deadline(1)) is sock
    assert sock.timeouts == [1, 0.5]
    def failed(address):
        raise ConnectionRefusedError("fake refusal")
    sock.connect = failed
    with pytest.raises(ConnectionRefusedError):
        CONNECT(("192.0.2.1", 80), crawler._Deadline(1))
    assert sock.closed


def test_dns_deadline_cannot_open_socket(monkeypatch):
    # Fake stalled DNS thread and timed-out Queue; no sleep, DNS, or socket.
    calls = []
    class StalledThread:
        def __init__(self, target, daemon):
            assert daemon
        def start(self):
            calls.append("resolver started")
    class TimedOutQueue:
        def __init__(self, maxsize):
            pass
        def get(self, timeout):
            assert 0 < timeout <= 1
            raise crawler.queue.Empty
    monkeypatch.setattr(crawler.threading, "Thread", StalledThread)
    monkeypatch.setattr(crawler.queue, "Queue", TimedOutQueue)
    with pytest.raises(TimeoutError, match="DNS deadline"):
        CONNECT(("lab.example", 80), crawler._Deadline(1))
    assert calls == ["resolver started"]
