"""Playwright browser-driven L7 generators (rows 9-12).

Browser automation is the *correct* instrument only for detection targets that
**are** browser-driven L7 behavior and that lower layers cannot faithfully
reproduce (see ``docs/04-workload-layer-rationale.md``):

* row 9  - web-app App-ID from a real navigation,
* row 10 - URL/web filtering + user-facing block-page (screenshotted),
* row 11 - SSL-proxy / decryption on a real TLS handshake with varied SNI,
* row 12 - AppFW on real application traffic.

Playwright is preferred over Selenium (faster, first-class headless, native
network interception). Chrome MCP is fine for ad-hoc exploration but too
nondeterministic for a repeatable suite, so it is not used here.

Playwright is imported lazily so this module is importable without it installed;
the offline test suite does not launch a browser.
"""

from __future__ import annotations

import os
import time
from typing import List, Optional

from validation.correlator import FiveTuple, Stimulus


def _playwright():
    """Import Playwright lazily with a clear error if unavailable."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore

        return sync_playwright
    except Exception as exc:  # pragma: no cover - only without playwright
        raise ImportError(
            "playwright is required for browser-driven tests but is not "
            "installed. Install it with `pip install playwright` and then run "
            "`playwright install` to download browser binaries (see README.md)."
        ) from exc


class BrowserGenerator:
    """Drive a headless browser to produce realistic web-app L7 traffic.

    Parameters
    ----------
    screenshot_dir:
        Where block-page screenshots are written (gitignored).
    headless:
        Run headless (default True).
    """

    def __init__(self, screenshot_dir: str = "screenshots", headless: bool = True):
        self.screenshot_dir = screenshot_dir
        self.headless = headless

    def _navigate(self, url: str, screenshot_path: Optional[str] = None,
                  sni_hosts: Optional[List[str]] = None) -> None:
        """Open a browser, navigate to ``url``, optionally screenshot."""
        sync_playwright = _playwright()
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.goto(url, wait_until="load", timeout=30000)
                if screenshot_path:
                    os.makedirs(os.path.dirname(screenshot_path) or ".", exist_ok=True)
                    page.screenshot(path=screenshot_path, full_page=True)
                # Visit additional SNI hosts to exercise SSL-proxy variety.
                for host in sni_hosts or []:
                    try:
                        page.goto(f"https://{host}/", wait_until="commit", timeout=15000)
                    except Exception:
                        pass
            finally:
                browser.close()

    # -- row 9: web-app App-ID ------------------------------------------------
    def visit_webapp(self, url: str, expected_app: str, navigate: bool = True) -> Stimulus:
        """Navigate to a web application (validates AppTrack web-app App-ID)."""
        ts = time.time()
        if navigate:
            self._navigate(url)
        return Stimulus(
            # Browser fans out many connections; correlate on dst + protocol only.
            five_tuple=FiveTuple(None, None, "TCP", None, 443),
            timestamp=ts,
            expected_event_type="APPTRACK_SESSION_CREATE",
            payload_class="web-app-navigation",
            detection_target="App-ID web apps",
            expected_fields=("application", "application-sub-name"),
            metadata={"url": url, "expected_app": expected_app},
        )

    # -- row 10: URL/web filtering + block-page -------------------------------
    def visit_filtered_url(self, url: str, navigate: bool = True) -> Stimulus:
        """Navigate to a categorized/blocked URL and screenshot the block-page."""
        ts = time.time()
        shot = os.path.join(self.screenshot_dir, f"blockpage_{int(ts)}.png")
        if navigate:
            self._navigate(url, screenshot_path=shot)
        return Stimulus(
            five_tuple=FiveTuple(None, None, "TCP", None, 443),
            timestamp=ts,
            expected_event_type="WEBFILTER_URL_BLOCKED",
            payload_class="filtered-url-navigation",
            detection_target="URL/web filtering",
            expected_fields=("url", "category"),
            metadata={"url": url, "screenshot": shot},
        )

    # -- row 11: SSL proxy / decryption ---------------------------------------
    def tls_handshakes(self, base_url: str, sni_hosts: List[str], navigate: bool = True) -> Stimulus:
        """Perform real TLS handshakes with varied SNI (validates SSL-proxy)."""
        ts = time.time()
        if navigate:
            self._navigate(base_url, sni_hosts=sni_hosts)
        return Stimulus(
            five_tuple=FiveTuple(None, None, "TCP", None, 443),
            timestamp=ts,
            expected_event_type="WEBFILTER_URL_PERMITTED",
            payload_class="tls-handshake-varied-sni",
            detection_target="SSL proxy/decryption",
            expected_fields=("url",),
            metadata={"sni_hosts": sni_hosts},
        )

    # -- row 12: AppFW --------------------------------------------------------
    def trigger_appfw(self, url: str, navigate: bool = True) -> Stimulus:
        """Navigate to an app that violates an app-firewall rule (block expected)."""
        ts = time.time()
        shot = os.path.join(self.screenshot_dir, f"appfw_block_{int(ts)}.png")
        if navigate:
            self._navigate(url, screenshot_path=shot)
        return Stimulus(
            five_tuple=FiveTuple(None, None, "TCP", None, 443),
            timestamp=ts,
            expected_event_type="APPTRACK_SESSION_CLOSE",
            payload_class="appfw-violation",
            detection_target="AppFW",
            expected_fields=("application", "reason"),
            metadata={"url": url, "screenshot": shot},
        )
