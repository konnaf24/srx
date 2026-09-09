"""pytest fixtures and configuration for the SRX detection probe suite.

Responsibilities:

* make the project package importable (insert the project root on ``sys.path``),
* register the ``requires_srx`` marker (also in ``pytest.ini``),
* load probe configuration from YAML (``PROBE_CONFIG`` env var or default),
* provide collector fixtures that start/stop the syslog collector and pcap
  capture around live tests, and a NETCONF query fixture.

The fixtures that touch live infrastructure are only consumed by tests marked
``@pytest.mark.requires_srx``; the offline logic tests use none of them, so the
suite collects and the logic layer runs without any hardware or system binaries.
"""

from __future__ import annotations

import os
import sys

import pytest

# Ensure the project root (this file's parent) is importable as the top-level
# package location for generators/collectors/validation.
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_PROJECT_ROOT)  # tests/ -> project root
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


DEFAULT_CONFIG_PATH = os.path.join("config", "probe_config.yaml")


def pytest_addoption(parser):
    parser.addoption(
        "--live-srx", action="store_true", default=False,
        help="Explicitly allow live SRX tests in an authorized lab.",
    )


def pytest_collection_modifyitems(config, items):
    """Ordinary pytest runs must not generate traffic or contact hardware."""
    if config.getoption("--live-srx"):
        return
    skip_live = pytest.mark.skip(reason="Live hardware tests require --live-srx")
    for item in items:
        if item.get_closest_marker("requires_srx") is not None:
            item.add_marker(skip_live)


def pytest_configure(config):
    """Register the requires_srx marker (kept in sync with pytest.ini)."""
    config.addinivalue_line(
        "markers",
        "requires_srx: test requires a live SRX and/or system binaries / "
        "privileges (deselect with -m \"not requires_srx\")",
    )


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def config():
    """Load probe configuration from YAML.

    Path resolution order:
      1. ``PROBE_CONFIG`` environment variable, then
      2. ``config/probe_config.yaml``.

    Skips dependent tests cleanly if the config (or PyYAML) is unavailable —
    this fixture is only used by live (requires_srx) tests.
    """
    path = os.environ.get("PROBE_CONFIG", DEFAULT_CONFIG_PATH)
    if not os.path.exists(path):
        pytest.skip(
            f"No probe config found at {path!r}. Copy "
            f"config/probe_config.example.yaml to config/probe_config.yaml "
            f"(or set PROBE_CONFIG) to run live tests."
        )
    try:
        import yaml
    except ImportError:
        pytest.skip("PyYAML is not installed; cannot load probe configuration.")
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# ---------------------------------------------------------------------------
# Collector fixtures (live)
# ---------------------------------------------------------------------------
@pytest.fixture
def syslog_collector(config):
    """Start a syslog collector for the duration of a test, then stop it."""
    from collectors.syslog_collector import SyslogCollector

    cfg = config["syslog"]
    collector = SyslogCollector(
        bind_addr=cfg.get("bind_addr", "0.0.0.0"),
        bind_port=cfg.get("bind_port", 5514),
        protocol=cfg.get("protocol", "udp"),
        max_events=cfg.get("buffer_max_events", 100000),
    )
    collector.start()
    try:
        yield collector
    finally:
        collector.stop()


@pytest.fixture
def srx(config):
    """Provide a connected PyEZ SrxQuery for the duration of a test."""
    from collectors.srx_query import SrxQuery

    cfg = config["srx"]
    query = SrxQuery(
        host=cfg["host"],
        user=cfg["username"],
        password=cfg.get("password") or None,
        ssh_key=cfg.get("ssh_key") or None,
        port=cfg.get("netconf_port", 830),
        connect_timeout=cfg.get("connect_timeout", 30),
    )
    query.connect()
    try:
        yield query
    finally:
        query.close()


@pytest.fixture
def correlator(config):
    """A correlator tuned from configured thresholds."""
    from validation.correlator import Correlator

    thr = config.get("thresholds", {})
    return Correlator(
        window_s=thr.get("correlation_window_s", 10.0),
        skew_s=thr.get("clock_skew_s", 2.0),
    )
