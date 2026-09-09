"""Bounded, single-page HTTP(S) extraction; never follows redirects or assets."""
from __future__ import annotations

import codecs
import http.client
import io
import ipaddress
import queue
import re
import socket
import threading
import time
from email.message import Message
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

DEFAULT_MAX_BYTES = 1024 * 1024
MAX_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 10
MAX_TIMEOUT = 30


def validate_limits(max_bytes=DEFAULT_MAX_BYTES, timeout=DEFAULT_TIMEOUT):
    for name, value, maximum in (("max_bytes", max_bytes, MAX_BYTES),
                                  ("timeout", timeout, MAX_TIMEOUT)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer in 1..{maximum}")


def validate_path(path):
    if (not isinstance(path, str) or len(path) > 2048 or not path.startswith("/")
            or path.startswith("//") or "\\" in path or "#" in path
            or any(ord(c) <= 32 or ord(c) >= 127 for c in path)
            or re.search(r"[\x00-\x1f\x7f\\]", unquote(path))):
        raise ValueError("path must be an ASCII target-relative /path (no //, controls, backslashes or fragment)")
    return path


def validate_url(url):
    if (not isinstance(url, str) or len(url) > 4096
            or any(ord(c) <= 32 or ord(c) >= 127 for c in url) or "\\" in url):
        raise ValueError("invalid HTTP(S) URL")
    parsed = urlsplit(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or parsed.port == 0):
        raise ValueError("HTTP(S) URL required, without credentials or fragment")
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
            raise ValueError("invalid target hostname") from None
    validate_path((parsed.path or "/") + ("?" + parsed.query if parsed.query else ""))
    return parsed


def target_url(target, path="/", scheme="http", port=None):
    validate_path(path)
    if not isinstance(target, str) or not target:
        raise ValueError("target must be an IP address or hostname")
    try:
        address = ipaddress.ip_address(target)
        host = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", target):
            raise ValueError("target must be an IP address or hostname") from None
        host = target
    if port is not None and (type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("port must be an integer in 1..65535")
    url = f"{scheme}://{host}" + (f":{port}" if port is not None else "") + path
    validate_url(url)
    return url


class _Deadline:
    def __init__(self, timeout):
        self.end = time.monotonic() + timeout

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("crawl deadline exceeded")
        return remaining


class _DeadlineReader(io.RawIOBase):
    """Reset to *remaining* time on every recv, including headers/chunk framing."""
    def __init__(self, sock, deadline):
        super().__init__()
        self.sock = sock
        self.raw = sock.makefile("rb", buffering=0)
        self.deadline = deadline

    def readinto(self, buffer):
        self.sock.settimeout(self.deadline.remaining())
        return self.raw.readinto(buffer)

    def readable(self):
        return True

    def close(self):
        self.raw.close()
        super().close()


class _DeadlineSocket:
    def __init__(self, sock, deadline):
        self.sock, self.deadline = sock, deadline

    def sendall(self, data):
        self.sock.settimeout(self.deadline.remaining())
        return self.sock.sendall(data)

    def makefile(self, mode):
        assert mode == "rb"
        return io.BufferedReader(_DeadlineReader(self.sock, self.deadline))

    def close(self):
        self.sock.close()


def _connect(address, deadline):
    host, port = address
    # getaddrinfo has no timeout API. A daemon resolver may finish after the
    # caller's deadline, but can never open a connection or emit HTTP traffic.
    answers = queue.Queue(maxsize=1)
    def resolve():
        try:
            answers.put(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as exc:
            answers.put(exc)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        threading.Thread(target=resolve, daemon=True).start()
    else:
        resolve()  # numeric address: no DNS lookup
    try:
        addresses = answers.get(timeout=deadline.remaining())
    except queue.Empty:
        raise TimeoutError("DNS deadline exceeded") from None
    if isinstance(addresses, Exception):
        raise addresses
    error = OSError("no addresses for target")
    for family, kind, proto, _, sockaddr in addresses:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(deadline.remaining())
            sock.connect(sockaddr)
            sock.settimeout(deadline.remaining())
            return sock
        except OSError as exc:
            error = exc
            sock.close()
    raise error


class _PageParser(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url = url
        self.title = ""
        self.text = ""
        self.links = []
        self.in_title = False
        self.hidden = []
        self.output_truncated = False

    def _text_boundary(self):
        if self.text and not self.text.endswith(" ") and len(self.text) < 2048:
            self.text += " "

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "template"):
            self.hidden.append(tag)
        if self.hidden:
            return
        if not self.in_title:
            self._text_boundary()
        if tag == "title":
            self.in_title = True
        if tag == "a":
            href = dict(attrs).get("href")
            if not href:
                return
            if len(href) > 2048:
                self.output_truncated = True
                return
            try:
                link = urljoin(self.url, href)
                parsed = urlsplit(link)
                if (parsed.scheme not in ("http", "https") or not parsed.hostname
                        or parsed.username is not None or parsed.password is not None
                        or any(ord(c) < 32 or ord(c) == 127 for c in link)):
                    return
            except ValueError:
                return
            if link in self.links:
                return
            if len(self.links) < 20 and len(link) <= 1024:
                self.links.append(link)
            else:
                self.output_truncated = True

    def handle_endtag(self, tag):
        if self.hidden:
            if tag == self.hidden[-1]:
                self.hidden.pop()
            return
        if tag == "title":
            self.in_title = False
        elif not self.in_title:
            self._text_boundary()

    def handle_data(self, data):
        if self.hidden:
            return
        text = re.sub(r"\s+", " ", data)
        if not text:
            return
        name, limit = ("title", 512) if self.in_title else ("text", 2048)
        old = getattr(self, name)
        combined = old + (text.lstrip(" ") if old.endswith(" ") else text)
        self.output_truncated |= len(combined) > limit
        setattr(self, name, combined[:limit])


def crawl_page(url, *, max_bytes=DEFAULT_MAX_BYTES, timeout=DEFAULT_TIMEOUT):
    """Return JSON-safe metrics/extraction. Validation errors occur before I/O.

    bytes_received counts body bytes only, not headers/framing. An oversized,
    incomplete, redirected, compressed, or non-2xx response is a failed crawl.
    Partial extraction is retained and explicitly marked response_complete=False.
    """
    validate_limits(max_bytes, timeout)
    parsed = validate_url(url)
    started = time.monotonic()
    deadline = _Deadline(timeout)
    result = dict(url=url, status_code=None, bytes_received=0, elapsed_s=0.0,
                  response_complete=False, truncated=False, title="", text="",
                  links=[], output_truncated=False, content_type="", charset="",
                  execution_status="failed", detection_status="not_evaluated", error="")
    conn = response = None
    body = bytearray()
    declared_charset = None
    try:
        cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        conn = cls(parsed.hostname, parsed.port, timeout=deadline.remaining())
        conn._create_connection = lambda address, *a, **kw: _connect(address, deadline)
        conn.connect()  # HTTPS uses the default verifying SSL context.
        conn.sock = _DeadlineSocket(conn.sock, deadline)
        path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
        conn.request("GET", path, headers={"Accept-Encoding": "identity",
                     "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1",
                     "User-Agent": "SRX-SinglePageCrawler/1.0", "Connection": "close"})
        response = conn.getresponse()
        result["status_code"] = response.status
        if 300 <= response.status < 400:
            raise ValueError("redirect rejected; no redirect destination fetched")
        if response.getheader("Content-Encoding", "identity").lower().strip() not in ("", "identity"):
            raise ValueError("unsupported Content-Encoding; identity required")
        message = Message()
        message["content-type"] = response.getheader("Content-Type", "application/octet-stream")
        result["content_type"] = message.get_content_type()[:128]
        declared_charset = message.get_content_charset()
        if declared_charset and len(declared_charset) > 64:
            declared_charset = None
        result["charset"] = declared_charset or "utf-8"
        length = response.getheader("Content-Length")
        expected = None
        if length is not None:
            if not re.fullmatch(r"[0-9]{1,20}", length):
                raise ValueError("invalid Content-Length")
            expected = int(length)
        if response.getheader("Transfer-Encoding"):
            if response.getheader("Transfer-Encoding").lower().strip() != "chunked" or expected is not None:
                raise ValueError("ambiguous or unsupported response framing")
        while True:
            deadline.remaining()
            if len(body) == max_bytes:
                # For a known exact length no extra byte is needed. Otherwise
                # conservatively stop without exceeding the response byte cap.
                if expected == len(body):
                    break
                result["truncated"] = True
                raise ValueError("response byte limit reached")
            chunk = response.read1(min(16384, max_bytes - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if expected is not None and len(body) != expected:
            raise ValueError("incomplete response: Content-Length mismatch")
        result["response_complete"] = True
        if not 200 <= response.status < 300:
            raise ValueError(f"HTTP status {response.status}")
        result["execution_status"] = "succeeded"
    except (OSError, ValueError, http.client.HTTPException) as exc:
        if isinstance(exc, http.client.IncompleteRead):
            body.extend(exc.partial[:max_bytes - len(body)])
        result["error"] = str(exc)[:512] or type(exc).__name__
    finally:
        if response is not None:
            response.close()
        if conn is not None:
            conn.close()
    result["bytes_received"] = len(body)
    if body and result["content_type"] in ("text/html", "application/xhtml+xml", "text/plain"):
        try:
            charset = result["charset"]
            if not declared_charset and result["content_type"] == "text/html":
                # Bounded HTML charset sniff; no browser or heuristic detector.
                match = re.search(br"<meta\b[^>]*\bcharset\s*=\s*[\"']?([A-Za-z0-9_-]+)",
                                  body[:1024], re.I)
                if match:
                    charset = match[1].decode("ascii")
            # BOM takes precedence; invalid/unknown encodings never crash a run.
            if body.startswith(codecs.BOM_UTF8):
                charset = "utf-8-sig"
            elif body.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                charset = "utf-16"
            try:
                decoder = codecs.getincrementaldecoder(charset)(errors="replace")
            except (LookupError, TypeError):
                charset = "utf-8"
                decoder = codecs.getincrementaldecoder(charset)(errors="replace")
            result["charset"] = charset
            parser = _PageParser(url)
            for offset in range(0, len(body), 16384):
                deadline.remaining()
                text = decoder.decode(body[offset:offset + 16384], final=offset + 16384 >= len(body))
                if result["content_type"] == "text/plain":
                    parser.handle_data(text)
                else:
                    parser.feed(text)
            parser.close()
            result.update(title=parser.title.strip(), text=parser.text.strip(), links=parser.links,
                          output_truncated=parser.output_truncated)
        except (ValueError, OSError, LookupError, TypeError) as exc:
            result.update(execution_status="failed", error=str(exc)[:512])
    try:
        deadline.remaining()
    except TimeoutError as exc:
        result.update(execution_status="failed", error=str(exc))
    result["elapsed_s"] = round(time.monotonic() - started, 6)
    return result
