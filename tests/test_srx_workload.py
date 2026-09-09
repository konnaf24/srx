from __future__ import annotations

import argparse
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from deploy import srx_workload

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _all_args(duration: int = 60) -> argparse.Namespace:
    return argparse.Namespace(
        target="203.0.113.10",
        src="198.51.100.5",
        yes=True,
        cmd="all",
        duration=duration,
        func=srx_workload.do_all,
    )


def test_sustained_workloads_default_to_one_minute():
    parser = srx_workload.build_parser()

    all_args = parser.parse_args(["--target", "203.0.113.10", "all"])
    wrk_args = parser.parse_args(["--target", "203.0.113.10", "wrk"])
    iperf_args = parser.parse_args(["--target", "203.0.113.10", "iperf"])

    assert all_args.duration == 60
    assert wrk_args.duration == 60
    assert iperf_args.duration == 60


@pytest.mark.parametrize("command", ["all", "wrk", "iperf"])
def test_duration_must_be_positive(command):
    parser = srx_workload.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(
            ["--target", "203.0.113.10", command, "--duration", "0"]
        )


def test_documented_script_entrypoint_can_load_generators():
    result = subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "deploy" / "srx_workload.py"),
            "--target",
            "203.0.113.10",
            "all",
            "--help",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--duration" in result.stdout


def test_complete_suite_contains_every_workload_and_uses_suite_duration():
    workloads = srx_workload.build_all_workloads(_all_args(duration=75))
    names = {workload.name for workload in workloads}

    assert len(workloads) == 18
    assert names == {
        "http",
        "dns",
        "handshake-ftp",
        "eicar",
        "gtube",
        "scan-syn",
        "scan-xmas",
        "scan-fin",
        "flood-syn",
        "flood-icmp",
        "flood-udp",
        "malformed",
        "bad-checksum",
        "tiny-ttl",
        "fragments",
        "denied-port",
        "wrk",
        "iperf3",
    }
    sustained = {
        workload.name: workload.args.duration
        for workload in workloads
        if workload.name in {"wrk", "iperf3"}
    }
    assert sustained == {"wrk": 75, "iperf3": 75}


def test_workloads_reach_a_start_barrier_concurrently():
    barrier = threading.Barrier(3, timeout=2)

    def synchronized_workload(_args):
        barrier.wait()
        return 0

    workloads = [
        srx_workload.Workload(
            name=f"workload-{index}",
            func=synchronized_workload,
            args=argparse.Namespace(),
        )
        for index in range(3)
    ]

    results = srx_workload.run_concurrently(workloads)

    assert {result.name for result in results} == {
        "workload-0",
        "workload-1",
        "workload-2",
    }
    assert all(result.returncode == 0 for result in results)


def test_source_ip_uses_the_route_selected_address(monkeypatch):
    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def connect(self, destination):
            assert destination == ("203.0.113.10", 9)

        def getsockname(self):
            return "198.51.100.5", 54321

    monkeypatch.setattr(
        srx_workload.socket,
        "socket",
        lambda *_args: FakeSocket(),
    )

    assert srx_workload.resolve_source_ip("203.0.113.10") == "198.51.100.5"


def test_run_cmd_retains_nonzero_exit_even_with_transmission_summary(monkeypatch):
    monkeypatch.setattr(
        srx_workload.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["hping3"],
            returncode=1,
            stdout=(
                "--- 203.0.113.10 hping statistic ---\n"
                "2000 packets transmitted, 0 packets received, 100% packet loss"
            ),
            stderr="",
        ),
    )

    assert srx_workload.run_cmd(
        ["hping3"],
        success_output="2000 packets transmitted",
    ) == 1


def test_run_cmd_does_not_hide_other_hping_errors(monkeypatch):
    monkeypatch.setattr(
        srx_workload.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["hping3"],
            returncode=1,
            stdout="",
            stderr="permission denied",
        ),
    )

    assert srx_workload.run_cmd(
        ["hping3"],
        success_output="2000 packets transmitted",
    ) == 1


def test_concurrent_runner_reports_failures_without_stopping_other_workloads():
    executed = []

    def successful(_args):
        executed.append("successful")
        return 0

    def unsuccessful(_args):
        executed.append("unsuccessful")
        return 7

    def crashing(_args):
        executed.append("crashing")
        raise RuntimeError("boom")

    workloads = [
        srx_workload.Workload("successful", successful, argparse.Namespace()),
        srx_workload.Workload("unsuccessful", unsuccessful, argparse.Namespace()),
        srx_workload.Workload("crashing", crashing, argparse.Namespace()),
    ]

    results = {
        result.name: result
        for result in srx_workload.run_concurrently(workloads)
    }

    assert set(executed) == {"successful", "unsuccessful", "crashing"}
    assert results["successful"].returncode == 0
    assert results["unsuccessful"].returncode == 7
    assert results["crashing"].returncode == 1
    assert results["crashing"].error == "RuntimeError: boom"
    assert results["crashing"].elapsed_s > 0
    assert results["successful"].execution_status == "succeeded"
    assert results["unsuccessful"].error == "process exited with status 7"
    assert all(result.detection_status == "not_evaluated" for result in results.values())
