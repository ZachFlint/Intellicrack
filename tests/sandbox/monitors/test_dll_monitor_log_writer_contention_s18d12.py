# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""S18-D12: the DLL monitor must not drop records while the host reads its log.

``Write-DllRecord`` appended with ``Add-Content``, which opens the file afresh
for every single record. The host collects the monitor logs off the guest while
the run is still going, and ``qemu-guest-agent`` opens them for reading *without*
sharing writes, so for as long as it holds a handle no writer can open the file
at all and the record is lost. Measured live in the guest once S18-D10 made the
diagnostic reachable:

    ...|dll_event_handler_error|The process cannot access the file
    'C:\intellicrack\logs\dll_monitor.log' because it is being used by another process.

Holding a handle open instead only reverses the victim - measured live, a
retained writer locked the collector out of all three DLL logs for the whole run,
so they came back empty. The writer therefore opens for as short a time as it can
and waits the collision out. The gate models the collector's reader exactly:
``FILE_SHARE_READ`` only, which is what excludes a writer.
"""

from __future__ import annotations

import ctypes
import shutil
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.subprocess_compat import run
from tests.sandbox.monitors.powershell_lift import lift_function


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[3]
_SCRIPT: Final[Path] = _REPO_ROOT / "src" / "intellicrack" / "sandbox" / "scripts" / "dll_monitor.ps1"
_WRITER_FUNCTIONS: Final[tuple[str, ...]] = ("Write-DllLine", "Write-DllRecord")
_RECORD_COUNT: Final[int] = 200
_POWERSHELL_TIMEOUT_S: Final[float] = 180.0

# CreateFileW arguments that reproduce qemu-guest-agent's read of a guest log:
# read access shared with other readers only, which is what locks a writer out.
_GENERIC_READ: Final[int] = 0x80000000
_FILE_SHARE_READ: Final[int] = 0x00000001
_OPEN_EXISTING: Final[int] = 3
_INVALID_HANDLE_VALUE: Final[int] = -1
_COLLECTOR_HOLD_S: Final[float] = 0.75


def _hold_like_the_collector(log_path: Path) -> None:
    """Hold the log open the way qemu-guest-agent holds it while collecting.

    ``CreateFileW`` with ``FILE_SHARE_READ`` and nothing else is what the guest
    agent's read amounts to: other readers are welcome, writers are refused
    outright. Python's own ``open`` shares writes and so cannot model it.

    Args:
        log_path: Log file to hold open.
    """
    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(log_path),
        wintypes.DWORD(_GENERIC_READ),
        wintypes.DWORD(_FILE_SHARE_READ),
        None,
        wintypes.DWORD(_OPEN_EXISTING),
        wintypes.DWORD(0),
        None,
    )
    if handle in {None, _INVALID_HANDLE_VALUE, ctypes.c_void_p(-1).value}:
        return
    try:
        time.sleep(_COLLECTOR_HOLD_S)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _drive_writer(tmp_path: Path, *, hold_open: bool) -> list[str]:
    """Write records through the script's own writer, optionally under a reader.

    Args:
        tmp_path: Directory the test may write to.
        hold_open: Whether to hold the log open for reading the way the host's
            log collection does while the guest is still writing.

    Returns:
        list[str]: The non-empty lines the writer managed to land in the log.
    """
    log_path = tmp_path / "dll_monitor.log"
    log_path.touch()

    script_text = _SCRIPT.read_text(encoding="utf-8")
    lifted = "\n".join(part for part in (lift_function(script_text, name) for name in _WRITER_FUNCTIONS) if part)

    harness = tmp_path / "harness.ps1"
    harness.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"$script:LogPath = '{log_path}'\n"
        "$script:FilterPid = 0\n"
        "$script:LogWriterLock = [System.Object]::new()\n"
        "$script:LogWriteTimeoutMs = 3000\n"
        "$script:LogWriteRetryMs = 25\n"
        "$script:LogWriteDropped = 0\n"
        "function Write-DllDiagnostic {\n"
        "    param([string]$Timestamp, [string]$Category, [string]$Detail)\n"
        "}\n" + lifted + "\n" + f"foreach ($i in 1..{_RECORD_COUNT}) {{\n"
        "    Write-DllRecord -Timestamp ('2026-08-15T00:00:00.{0:0000}+00:00' -f $i) -ProcessId $i "
        "-ProcessName 'svchost' -ImagePath \"\\Device\\HarddiskVolume2\\Windows\\System32\\mod$i.dll\" "
        "-BaseAddress '0x7FFF9B500000' -ImageSize 77824 -EventId 5\n"
        "}\n"
        "if (Get-Command Close-DllLogWriters -ErrorAction SilentlyContinue) { Close-DllLogWriters }\n",
        encoding="utf-8",
    )

    argv = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(harness)]
    collector: threading.Thread | None = None
    if hold_open:
        collector = threading.Thread(target=_hold_like_the_collector, args=(log_path,), daemon=True)
        collector.start()
    run(argv, capture_output=True, text=True, timeout=_POWERSHELL_TIMEOUT_S, check=False)
    if collector is not None:
        collector.join(timeout=_POWERSHELL_TIMEOUT_S)

    return [line for line in log_path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


@pytest.mark.skipif(shutil.which("powershell.exe") is None, reason="Windows PowerShell is the guest's own host")
class TestTheDllMonitorKeepsEveryRecordUnderCollection:
    """A record observed by the collector has to reach the log."""

    def test_the_writer_is_defined_in_the_script(self) -> None:
        """Without the shared writer there is nothing holding a handle open."""
        text = _SCRIPT.read_text(encoding="utf-8")
        missing = [name for name in _WRITER_FUNCTIONS if not lift_function(text, name)]
        assert not missing, f"dll_monitor.ps1 defines no {missing}, so every record reopens the log to append"

    def test_no_record_is_lost_while_the_host_reads_the_log(self, tmp_path: Path) -> None:
        """Every record survives a concurrent read of the log."""
        lines = _drive_writer(tmp_path, hold_open=True)
        assert len(lines) == _RECORD_COUNT, (
            f"{_RECORD_COUNT - len(lines)} of {_RECORD_COUNT} records were dropped while the host held the "
            f"log open, exactly as the guest reported: got {len(lines)}"
        )

    def test_the_records_are_intact_and_not_interleaved(self, tmp_path: Path) -> None:
        """A retained handle must not corrupt the eight-field record schema."""
        lines = _drive_writer(tmp_path, hold_open=False)
        assert len(lines) == _RECORD_COUNT, f"expected {_RECORD_COUNT} records with no reader, got {len(lines)}"
        malformed = [line for line in lines if len(line.split("|")) != 8]
        assert not malformed, f"records were interleaved into malformed rows: {malformed[:3]}"
