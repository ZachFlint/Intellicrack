# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Gate on the reservation that keeps the shared monitor stop event from leaking between tests.

A real PowerShell process creates the named ``IntellicrackMonitorStop`` event,
signals it and keeps it open, which is the state a test in another pytest
process leaves behind while its own monitors are stopping. A second real
PowerShell process then reads the event's state, as a monitor starting at that
moment would.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from typing import TYPE_CHECKING, Final

import pytest

from tests._helpers.monitor_stop_event import MONITOR_STOP_EVENT_NAME, monitor_stop_event_reserved


if TYPE_CHECKING:
    from pathlib import Path


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="named kernel events are a Windows facility")

_PROBE_TIMEOUT_SEC: Final[float] = 60.0
_HOLDER_LIFETIME_SEC: Final[int] = 600
_SIGNALED: Final[str] = "signaled"
_UNSIGNALED: Final[str] = "unsignaled"
_ABSENT: Final[str] = "absent"


def _resolve_pwsh() -> str:
    """Locate ``pwsh.exe``.

    Returns:
        str: Absolute path to ``pwsh.exe``.
    """
    pwsh = shutil.which("pwsh")
    assert pwsh is not None, "pwsh (PowerShell 7) is required to hold and read the named event"
    return pwsh


def _event_state(pwsh: str) -> str:
    """Read the state of the named stop event the way a starting monitor sees it.

    Args:
        pwsh: Absolute path to ``pwsh.exe``.

    Returns:
        str: ``signaled``, ``unsignaled``, or ``absent`` when no process holds the event open.
    """
    script = (
        "$h = $null;"
        f"if (-not [System.Threading.EventWaitHandle]::TryOpenExisting('{MONITOR_STOP_EVENT_NAME}', [ref]$h)) {{ '{_ABSENT}'; exit 0 }};"
        f"try {{ if ($h.WaitOne(0)) {{ '{_SIGNALED}' }} else {{ '{_UNSIGNALED}' }} }} finally {{ $h.Dispose() }}"
    )
    completed = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=_PROBE_TIMEOUT_SEC,
    )
    return completed.stdout.strip()


def test_reservation_clears_a_stop_signal_another_process_still_holds(tmp_path: Path) -> None:
    """Entering the reservation unsignals an event that another live process signaled and still holds open.

    Args:
        tmp_path: Directory for the file through which the holder reports that the event is signaled.
    """
    pwsh = _resolve_pwsh()
    held = tmp_path / "held.txt"
    holder_script = (
        "$created = $false;"
        "$h = [System.Threading.EventWaitHandle]::new($false, [System.Threading.EventResetMode]::ManualReset,"
        f" '{MONITOR_STOP_EVENT_NAME}', [ref]$created);"
        "$null = $h.Set();"
        f"[IO.File]::WriteAllText('{held}', 'held');"
        f"Start-Sleep -Seconds {_HOLDER_LIFETIME_SEC}"
    )
    holder = subprocess.Popen(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", holder_script],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        while not held.exists():
            try:
                exit_code = holder.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                continue
            pytest.fail(f"the process that holds the event exited with {exit_code} before signaling it", pytrace=False)
        assert _event_state(pwsh) == _SIGNALED

        with monitor_stop_event_reserved():
            assert _event_state(pwsh) == _UNSIGNALED
            assert holder.poll() is None
    finally:
        holder.kill()
        holder.wait(timeout=_PROBE_TIMEOUT_SEC)
