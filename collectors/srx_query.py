"""NETCONF / PyEZ collector for authoritative SRX device state.

Wraps :class:`jnpr.junos.Device` (junos-eznc / "PyEZ") to pull device state that
serves as ground truth alongside syslog:

* :meth:`SrxQuery.get_flow_sessions` - ``show security flow session`` entries.
* :meth:`SrxQuery.get_screen_stats`  - ``show security screen statistics``.
* :meth:`SrxQuery.get_idp_counters`  - ``show security idp counters`` / status.

If ``junos-eznc`` is not installed, importing/using this collector raises a
clear, actionable error rather than a bare ``ModuleNotFoundError`` — the offline
test suite never instantiates it.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:  # PyEZ is optional at import time so offline tests can collect.
    from jnpr.junos import Device  # type: ignore
    from jnpr.junos.exception import ConnectError  # type: ignore

    _PYEZ_AVAILABLE = True
    _PYEZ_IMPORT_ERROR: Optional[Exception] = None
except Exception as exc:  # pragma: no cover - exercised only without PyEZ
    Device = None  # type: ignore
    ConnectError = Exception  # type: ignore
    _PYEZ_AVAILABLE = False
    _PYEZ_IMPORT_ERROR = exc


_INSTALL_HINT = (
    "junos-eznc (PyEZ) is required for NETCONF queries but is not installed. "
    "Install it with `pip install junos-eznc` (see requirements.txt). "
    "Live SRX queries also require NETCONF-over-SSH enabled on the device "
    "(`set system services netconf ssh`)."
)


class SrxQuery:
    """Thin PyEZ wrapper for SRX device-state queries.

    Parameters
    ----------
    host:
        SRX management address/hostname.
    user:
        NETCONF username (a read-only account suffices).
    password:
        Password (mutually exclusive with ``ssh_key``; ``ssh_key`` wins).
    ssh_key:
        Path to a private key for key-based auth.
    port:
        NETCONF-over-SSH port (default 830).
    connect_timeout:
        Connection timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        port: int = 830,
        connect_timeout: int = 30,
    ):
        if not _PYEZ_AVAILABLE:
            raise ImportError(_INSTALL_HINT) from _PYEZ_IMPORT_ERROR

        self.host = host
        self.user = user
        self.password = password
        self.ssh_key = ssh_key or None
        self.port = int(port)
        self.connect_timeout = int(connect_timeout)
        self._dev: Optional["Device"] = None

    # -- lifecycle ------------------------------------------------------------
    def connect(self) -> "SrxQuery":
        """Open the NETCONF session."""
        kwargs: Dict[str, Any] = dict(host=self.host, user=self.user, port=self.port)
        if self.ssh_key:
            kwargs["ssh_private_key_file"] = self.ssh_key
        elif self.password:
            kwargs["password"] = self.password

        self._dev = Device(**kwargs)
        try:
            self._dev.open()
        except ConnectError as exc:  # pragma: no cover - needs live device
            raise ConnectionError(
                f"Failed to open NETCONF session to {self.host}:{self.port}: {exc}"
            ) from exc
        self._dev.timeout = self.connect_timeout
        return self

    def close(self) -> None:
        """Close the NETCONF session."""
        if self._dev is not None:
            try:
                self._dev.close()
            finally:
                self._dev = None

    def __enter__(self) -> "SrxQuery":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def _require_dev(self) -> "Device":
        if self._dev is None:
            raise RuntimeError("Not connected. Call connect() (or use as a context manager).")
        return self._dev

    # -- queries --------------------------------------------------------------
    def get_flow_sessions(self) -> List[Dict[str, Any]]:
        """Return current security flow sessions as a list of dicts.

        Mirrors ``show security flow session``. Each dict contains at least
        the 5-tuple, protocol, policy, and byte/packet counters where present.
        """
        dev = self._require_dev()
        rpc = dev.rpc.get_flow_session_information()
        sessions: List[Dict[str, Any]] = []
        # The RPC reply is lxml; extract flow-session elements defensively.
        for sess in rpc.findall(".//flow-session"):
            entry: Dict[str, Any] = {}
            for child in sess.iter():
                tag = child.tag
                if child.text and child.text.strip():
                    entry[tag] = child.text.strip()
            sessions.append(entry)
        return sessions

    def get_screen_stats(self, zone: Optional[str] = None) -> Dict[str, Any]:
        """Return screen (IDS) statistics counters.

        Mirrors ``show security screen statistics zone <zone>``. Returns a flat
        dict of counter-name -> value.
        """
        dev = self._require_dev()
        if zone:
            rpc = dev.rpc.get_screen_statistics_information(zone_name=zone)
        else:
            rpc = dev.rpc.get_screen_statistics_information()
        stats: Dict[str, Any] = {}
        for el in rpc.iter():
            if el.text and el.text.strip() and len(el):  # skip container nodes
                continue
            if el.text and el.text.strip():
                stats[el.tag] = el.text.strip()
        return stats

    def get_idp_counters(self) -> Dict[str, Any]:
        """Return IDP/IPS engine counters.

        Mirrors ``show security idp counters application-identification`` /
        status. Returns a flat dict of counter-name -> value.
        """
        dev = self._require_dev()
        rpc = dev.rpc.get_idp_counter_information()
        counters: Dict[str, Any] = {}
        for el in rpc.iter():
            if el.text and el.text.strip() and not len(el):
                counters[el.tag] = el.text.strip()
        return counters
