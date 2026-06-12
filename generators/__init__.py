"""Traffic generators (the "workload layer") for the SRX detection probe.

Each generator produces a *known* stimulus and returns a
:class:`~validation.correlator.Stimulus` descriptor (5-tuple + timestamp +
expected event type) so downstream correlation is unambiguous.

Layering (see ``docs/04-workload-layer-rationale.md``):

* :mod:`generators.packet_gen`  - scapy L3/L4 crafting (malformed, frags, ...).
* :mod:`generators.scan_gen`    - nmap / hping3 scans & floods.
* :mod:`generators.l7_client`   - scriptable L7 (HTTP/DNS/FTP/SSH, EICAR/GTUBE).
* :mod:`generators.browser_gen` - Playwright browser-driven L7 (rows 9-12).
* :mod:`generators.load_gen`    - wrk / iperf3 scale generation.
"""

import shutil


def require_binary(name: str) -> str:
    """Return the path to a required system binary or raise a clear error.

    Used by generators that wrap external tools (nmap, hping3, wrk, iperf3) so
    that a missing dependency fails loudly with installation guidance rather
    than an obscure ``FileNotFoundError`` deep in a subprocess call.
    """
    path = shutil.which(name)
    if path is None:
        raise FileNotFoundError(
            f"Required system binary '{name}' was not found on PATH. "
            f"Install it before running tests that use it (see README.md). "
            f"Tests requiring live infrastructure are marked @pytest.mark.requires_srx."
        )
    return path
