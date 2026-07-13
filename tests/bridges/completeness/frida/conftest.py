# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Pytest fixtures shared by the Frida bridge-completeness gate tests."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.subprocess_compat import DEVNULL, Popen


if TYPE_CHECKING:
    from collections.abc import Generator


_NOTEPAD_STARTUP_DELAY_S: Final[float] = 1.0


@pytest.fixture(scope="session")
def qapp() -> Generator[QApplication]:
    """Provide a QApplication instance for the test session.

    Qt requires exactly one QApplication instance per process; this
    fixture creates one for the entire session and yields it so every
    widget-construction test in this package can run without re-creating
    (or conflicting on) the singleton application instance.

    Yields:
        Generator[QApplication]: The application instance.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def notepad_process() -> Generator[Popen[bytes]]:
    """Spawn a real, uniquely-named ``notepad.exe`` process for name-based attach gates.

    Attaching by process *name* is ambiguous against the current test
    process (``python.exe``/``pytest.exe``) because multiple same-named
    interpreter processes are routinely running concurrently in CI and
    dev sandboxes, so a real ``attach_by_name`` call can legitimately
    resolve to a different PID than ``os.getpid()`` without the
    production code being at fault. Spawning a dedicated ``notepad.exe``
    gives each test a target whose PID is known unambiguously (via the
    ``Popen`` handle) so the assertion is a genuine regression gate
    rather than a race against ambient same-named processes.

    Yields:
        Popen[bytes]: The running notepad process handle.
    """
    notepad_path = shutil.which("notepad.exe") or str(Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "notepad.exe")
    proc = Popen([notepad_path], stdout=DEVNULL, stderr=DEVNULL)
    time.sleep(_NOTEPAD_STARTUP_DELAY_S)
    yield proc
    proc.terminate()
    proc.wait(timeout=5)
