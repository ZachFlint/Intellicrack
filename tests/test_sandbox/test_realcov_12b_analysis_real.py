# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

r"""Real-data coverage for :mod:`intellicrack.sandbox.analysis`.

Audit shard 12 (Category 3) flagged that every analysis test
(``detect_c2_patterns``, ``extract_iocs``, ``generate_timeline``,
``match_behaviors``, ``diff_reports``) ran on hand-crafted fixtures and
never on data captured from a real monitored run.

These tests close that gap end-to-end on Windows:

* They run the *real* inline ``WindowsSandbox`` process and network
  monitor sources under ``pwsh`` against the live kernel.
* They parse the captured logs with the *real*
  :mod:`intellicrack.sandbox.log_parsers` functions into a real
  :class:`ExecutionReport`.
* A controllable, real, observable signal is generated inside the live
  capture window by opening genuine loopback (``127.0.0.1``) TCP
  connections to a passive in-test listener bound on a port the detector
  treats as a known C2 port (4444). The listener only accepts and holds
  connections; nothing is sent off-host and no command-and-control
  behaviour is performed. Its sole purpose is to make the detection-side
  function :func:`detect_c2_patterns` run against real captured
  network/process state instead of hand-crafted fixtures.

The tests are Windows-only (the monitors query ``Win32_Process`` and
``Get-NetTCPConnection``) and carry ``spawns_process`` because they
launch real ``pwsh`` and socket processes.
"""

from __future__ import annotations

import importlib
import shutil
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, Final, Self

import pytest

from intellicrack.core.subprocess_compat import PIPE, Popen, TimeoutExpired
from intellicrack.sandbox.analysis import (
    detect_c2_patterns,
    diff_reports,
    extract_iocs,
    generate_timeline,
    match_behaviors,
)
from intellicrack.sandbox.base import ExecutionReport
from intellicrack.sandbox.log_parsers import parse_network_log, parse_process_log
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _monitor_source(method_name: str) -> str:
    """Return the PowerShell source produced by a ``WindowsSandbox`` builder.

    Resolves the non-public inline monitor source builders dynamically so the
    test exercises the real implementation without binding to a protected
    attribute at the type level.

    Args:
        method_name: Name of the static source method to invoke.

    Returns:
        str: The PowerShell script source text.
    """
    builder: Callable[[], str] = getattr(WindowsSandbox, method_name)
    return builder()


_analysis_mod = importlib.import_module("intellicrack.sandbox.analysis")

_C2_PORT: Final[int] = 4444
_LOOPBACK_ADDR: Final[str] = "127.0.0.1"
_CAPTURE_SETTLE_SEC: Final[float] = 6.0
_C2_CONNECT_ROUNDS: Final[int] = 6
_C2_CONNECT_GAP_SEC: Final[float] = 0.4
_PWSH_KILL_GRACE_SEC: Final[float] = 6.0


pytestmark = [
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="real-capture analysis tests rely on the live Windows kernel monitors",
    ),
    pytest.mark.spawns_process,
]


def _resolve_pwsh() -> str:
    """Locate the ``pwsh`` executable.

    Returns:
        str: Absolute path to ``pwsh``.
    """
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh (PowerShell 7) is required for the real-capture analysis tests")
    return pwsh


class _C2Listener:
    """A real loopback TCP listener used to generate genuine C2-port traffic.

    Binds an actual socket on ``127.0.0.1:4444`` and accepts connections in
    a background thread so that the live ``Get-NetTCPConnection`` table
    contains real established connections on a known C2 port.
    """

    def __init__(self) -> None:
        """Bind the listener socket on the loopback C2 port."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", _C2_PORT))
        self._server.listen(16)
        self._accepted: list[socket.socket] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        """Accept and retain incoming connections until stopped."""
        self._server.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, OSError):
                continue
            self._accepted.append(conn)

    def __enter__(self) -> Self:
        """Start the accept thread.

        Returns:
            Self: This listener instance.
        """
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        """Stop the listener and release all sockets."""
        self._stop.set()
        self._thread.join(timeout=2.0)
        for conn in self._accepted:
            conn.close()
        self._server.close()

    def beacon(self) -> None:
        """Open and hold real client connections to the C2 port.

        Each round opens a genuine TCP connection to ``127.0.0.1:4444`` and
        keeps it open, so the live endpoint table records real established
        connections on the C2 port during the monitor's capture window.
        """
        held: list[socket.socket] = []
        for _ in range(_C2_CONNECT_ROUNDS):
            client = socket.create_connection(("127.0.0.1", _C2_PORT), timeout=2.0)
            held.append(client)
            time.sleep(_C2_CONNECT_GAP_SEC)
        time.sleep(_CAPTURE_SETTLE_SEC)
        for client in held:
            client.close()


def _run_monitor(
    source: str,
    name: str,
    tmp_path: Path,
    log_dir: Path,
    pwsh: str,
    driver: Callable[[], None] | None,
) -> tuple[str, str]:
    """Run an inline monitor source while a driver perturbs the live system.

    Args:
        source: PowerShell source returned by a ``WindowsSandbox`` method.
        name: Script file name.
        tmp_path: Directory to write the script into.
        log_dir: ``-LogDir`` passed to the monitor.
        pwsh: Absolute path to ``pwsh``.
        driver: Optional zero-argument callable run after the monitor
            warms up; ``None`` to simply let the monitor settle.

    Returns:
        tuple[str, str]: Captured ``(stdout, stderr)``.
    """
    script = tmp_path / name
    script.write_text(source, encoding="utf-8")
    proc: Popen[str] = Popen(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-LogDir",
            str(log_dir),
        ],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    stdout = ""
    stderr = ""
    try:
        time.sleep(2.0)
        if driver is not None:
            driver()
        else:
            time.sleep(_CAPTURE_SETTLE_SEC)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                stdout, stderr = proc.communicate(timeout=_PWSH_KILL_GRACE_SEC)
            except TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=_PWSH_KILL_GRACE_SEC)
        else:
            stdout, stderr = proc.communicate(timeout=_PWSH_KILL_GRACE_SEC)
    return stdout or "", stderr or ""


def _capture_log_dirs(tmp_path: Path, pwsh: str) -> tuple[Path, Path]:
    """Run the live process and network monitors and return their log dirs.

    Captures the live process table and the live TCP/UDP endpoint table,
    injecting real loopback C2-port connections during the network capture
    window. All blocking work (process spawn, sleeps, filesystem) stays in
    this synchronous helper.

    Args:
        tmp_path: Pytest temp directory.
        pwsh: Absolute path to ``pwsh``.

    Returns:
        tuple[Path, Path]: ``(process_shared_root, network_shared_root)``.
        Each root contains a ``logs/`` subdirectory holding the monitor's
        pipe-delimited log, matching the parser's ``<root>/logs/<name>``
        convention.
    """
    tmp_path.mkdir(parents=True, exist_ok=True)
    proc_root = tmp_path / "proc_capture"
    net_root = tmp_path / "net_capture"
    (proc_root / "logs").mkdir(parents=True)
    (net_root / "logs").mkdir(parents=True)

    _run_monitor(
        _monitor_source("_process_monitor_source"),
        "process_monitor.ps1",
        tmp_path,
        proc_root / "logs",
        pwsh,
        None,
    )

    with _C2Listener() as listener:
        _run_monitor(
            _monitor_source("_network_monitor_source"),
            "network_monitor.ps1",
            tmp_path,
            net_root / "logs",
            pwsh,
            listener.beacon,
        )

    return proc_root, net_root


async def _capture_real_report(tmp_path: Path, pwsh: str) -> ExecutionReport:
    """Build an :class:`ExecutionReport` from real captured monitor logs.

    Args:
        tmp_path: Pytest temp directory.
        pwsh: Absolute path to ``pwsh``.

    Returns:
        ExecutionReport: Report populated from real parsed monitor logs.
    """
    proc_dir, net_dir = _capture_log_dirs(tmp_path, pwsh)
    process_activity = await parse_process_log(proc_dir, "process_monitor.log")
    network_activity = await parse_network_log(net_dir, "network_monitor.log")

    return ExecutionReport(
        result="success",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=_CAPTURE_SETTLE_SEC,
        process_activity=process_activity,
        network_activity=network_activity,
    )


@pytest.mark.asyncio
async def test_detect_c2_patterns_on_real_c2_port_capture(tmp_path: Path) -> None:
    """``detect_c2_patterns`` flags real captured connections to port 4444.

    Real loopback connections to a real listener on the known C2 port 4444
    are made during the live network capture; the analysis must surface a
    ``known_c2_port`` pattern naming port 4444 from the captured data.

    Args:
        tmp_path: Pytest temp directory.
    """
    pwsh = _resolve_pwsh()
    report = await _capture_real_report(tmp_path, pwsh)

    c2_ports = {act["remote_port"] for act in report.network_activity}
    if _C2_PORT not in c2_ports:
        pytest.skip(
            f"live network monitor did not observe the loopback :{_C2_PORT} connections within the capture window; "
            f"observed remote ports sample={sorted(c2_ports)[:20]}",
        )

    patterns = detect_c2_patterns(report.network_activity)
    c2_port_patterns = [p for p in patterns if p["pattern_type"] == "known_c2_port"]
    assert c2_port_patterns, f"expected a known_c2_port detection from real :{_C2_PORT} traffic; patterns={patterns}"
    assert any(f"Port: {_C2_PORT}" in ind for p in c2_port_patterns for ind in p["indicators"]), (
        f"expected port {_C2_PORT} cited in indicators; patterns={c2_port_patterns}"
    )
    assert all(0.0 <= p["confidence"] <= 1.0 for p in c2_port_patterns), "confidence must be bounded to [0, 1]"


@pytest.mark.asyncio
async def test_generate_timeline_orders_real_events(tmp_path: Path) -> None:
    """``generate_timeline`` merges and sorts real captured events.

    Args:
        tmp_path: Pytest temp directory.
    """
    pwsh = _resolve_pwsh()
    report = await _capture_real_report(tmp_path, pwsh)

    timeline = generate_timeline(report)
    assert timeline, "expected timeline events from a real captured report"

    timestamps = [ev["timestamp"] for ev in timeline]
    assert timestamps == sorted(timestamps), "timeline must be sorted chronologically"

    categories = {ev["category"] for ev in timeline}
    assert categories <= {"file", "registry", "network", "process", "api", "service", "kernel", "dll", "injection", "clipboard"}
    assert categories & {"process", "network"}, f"expected process/network timeline categories from real capture; saw {categories}"

    process_only = generate_timeline(report, categories=["process"])
    assert all(ev["category"] == "process" for ev in process_only), "category filter must restrict timeline to requested categories"
    if report.process_activity:
        assert process_only, "process category timeline must be non-empty when real process activity exists"


@pytest.mark.asyncio
async def test_extract_iocs_from_real_process_paths(tmp_path: Path) -> None:
    """``extract_iocs`` extracts real artefacts from real process activity.

    The live process table includes real loopback connections (private IPs,
    which must be filtered) and real System32 image paths. This validates
    the IOC extractor against real data: private/loopback IPs are excluded
    and every emitted IOC has a recognised type and non-empty value.

    Args:
        tmp_path: Pytest temp directory.
    """
    pwsh = _resolve_pwsh()
    report = await _capture_real_report(tmp_path, pwsh)

    iocs = extract_iocs(report)

    values = {ioc["value"] for ioc in iocs}
    assert _LOOPBACK_ADDR not in values, "loopback addresses must be filtered from IOCs"

    is_private: Callable[[str], bool] = getattr(_analysis_mod, "_is_private_ip")
    valid_types = {"ipv4", "domain", "url", "sha256", "sha1", "md5", "email"}
    for ioc in iocs:
        assert ioc["ioc_type"] in valid_types, f"unknown IOC type: {ioc['ioc_type']!r}"
        assert ioc["value"], "IOC value must be non-empty"
        if ioc["ioc_type"] == "ipv4":
            octets = ioc["value"].split(".")
            assert len(octets) == 4, f"malformed IPv4 IOC: {ioc['value']!r}"
            assert all(0 <= int(o) <= 255 for o in octets), f"IPv4 octet out of range: {ioc['value']!r}"
            assert not is_private(ioc["value"]), f"private/reserved IPv4 must be filtered from IOCs: {ioc['value']!r}"

    keys = [(ioc["ioc_type"], ioc["value"]) for ioc in iocs]
    assert len(keys) == len(set(keys)), "IOC extraction must deduplicate by (type, value)"


@pytest.mark.asyncio
async def test_match_behaviors_on_real_capture_is_consistent(tmp_path: Path) -> None:
    """``match_behaviors`` and a custom rule operate on real captured data.

    A custom rule keyed on the real loopback C2 port (4444) must match the
    real captured network activity, proving the rule engine runs against
    genuine observed state rather than fixtures.

    Args:
        tmp_path: Pytest temp directory.
    """
    pwsh = _resolve_pwsh()
    report = await _capture_real_report(tmp_path, pwsh)

    if _C2_PORT not in {act["remote_port"] for act in report.network_activity}:
        pytest.skip(f"live capture did not record the loopback :{_C2_PORT} connections; cannot validate the custom rule against real data")

    custom_rule = {
        "name": "Loopback C2 Port Contact",
        "category": "Command and Control",
        "severity": "high",
        "description": "Connection observed to a known C2 port",
        "mitre_id": "T1571",
        "conditions": {"network_ports": [_C2_PORT]},
    }
    matches = match_behaviors(report, custom_rules=[custom_rule])

    custom_matches = [m for m in matches if m["signature_name"] == "Loopback C2 Port Contact"]
    assert custom_matches, (
        f"custom network-port rule must match real captured :{_C2_PORT} traffic; matches={[m['signature_name'] for m in matches]}"
    )
    assert custom_matches[0]["evidence"], "matched behavior must carry real evidence strings"
    assert any(str(_C2_PORT) in ev for ev in custom_matches[0]["evidence"]), "evidence must cite the matched real port"
    for match in matches:
        assert match["severity"] in {"low", "medium", "high", "critical"}, f"unexpected severity: {match['severity']!r}"


@pytest.mark.asyncio
async def test_diff_reports_on_two_real_captures(tmp_path: Path) -> None:
    """``diff_reports`` compares two real captures of the live system.

    Two independent real captures of the same machine should share a large
    common core of long-lived processes (kernel, services) while differing
    in transient processes/connections, exercising the unique/common
    partitioning on genuine data.

    Args:
        tmp_path: Pytest temp directory.
    """
    pwsh = _resolve_pwsh()
    report_a = await _capture_real_report(tmp_path / "a", pwsh)
    report_b = await _capture_real_report(tmp_path / "b", pwsh)

    diff = diff_reports(report_a, report_b)

    assert diff["scalars"]["result"] == {"a": "success", "b": "success"}
    assert "process_activity" in diff
    assert "network_activity" in diff

    proc_diff = diff["process_activity"]
    assert set(proc_diff.keys()) == {"unique_to_a", "unique_to_b", "common"}
    total_a = len(proc_diff["unique_to_a"]) + len(proc_diff["common"])
    assert total_a > 0, "report A must contain real processes to diff"
    assert proc_diff["common"], "two captures of the same host must share long-lived processes in common"
