"""Telemetry collectors for the SRX detection probe.

Three independent observation channels:

* :mod:`collectors.syslog_collector` - structured Junos sd-syslog listener.
* :mod:`collectors.srx_query`        - NETCONF/PyEZ device-state queries.
* :mod:`collectors.pcap_capture`     - independent egress ground-truth capture.
"""
