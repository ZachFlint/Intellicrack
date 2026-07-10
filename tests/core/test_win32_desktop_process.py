# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable tests for launching processes on a hidden Windows desktop.

These exercise the real Win32 desktop-isolation path Intellicrack uses to keep
x64dbg's Qt windows off the user's screen: a genuine ``CreateDesktopW`` desktop,
a genuine ``CreateProcessW`` child bound to it, and the property that makes the
child invisible - its threads run on a desktop that is never the input desktop.
No mocks: every assertion is backed by a live OS object and fails loudly if the
isolation regresses.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path

import pytest

from intellicrack.core.win32_desktop_process import (
    HiddenDesktop,
    get_thread_desktop_name,
    spawn_on_hidden_desktop,
)


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="hidden-desktop isolation is a Windows-only Win32 facility",
)

_DESKTOP_READOBJECTS = 0x0001
_CHILD_WAIT_SECONDS = 30.0

_REPORT_DESKTOP_CHILD = (
    "import sys\n"
    "from intellicrack.core.win32_desktop_process import get_thread_desktop_name\n"
    "with open(sys.argv[1], 'w', encoding='utf-8') as fh:\n"
    "    fh.write(get_thread_desktop_name())\n"
)

_REPORT_ENV_CHILD = (
    "import os, sys\n"
    "with open(sys.argv[1], 'w', encoding='utf-8') as fh:\n"
    "    fh.write(os.environ.get('INTELLICRACK_TEST_MARKER', '<missing>'))\n"
)

_SLEEP_CHILD = "import time\ntime.sleep(30)\n"


def _open_desktop(name: str) -> int:
    """Attempt to open a desktop by name, returning the handle or 0.

    Args:
        name: The desktop name to open in the current window station.

    Returns:
        int: A non-zero desktop handle if the desktop exists, else 0.
    """
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    open_desktop = user32.OpenDesktopW
    open_desktop.restype = wintypes.HANDLE
    open_desktop.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    handle = open_desktop(name, 0, 0, _DESKTOP_READOBJECTS)
    if handle:
        close_desktop = user32.CloseDesktop
        close_desktop.argtypes = [wintypes.HANDLE]
        close_desktop(wintypes.HANDLE(handle))
    return int(handle) if handle else 0


def test_hidden_desktop_created_then_destroyed_on_close() -> None:
    """A created desktop is a live OS object that is destroyed by ``close``."""
    desktop = HiddenDesktop()
    try:
        assert _open_desktop(desktop.name) != 0, "desktop should exist while open"
    finally:
        desktop.close()
    assert _open_desktop(desktop.name) == 0, "desktop must be destroyed after close"


def test_hidden_desktop_names_are_unique() -> None:
    """Two hidden desktops get distinct names so they never collide."""
    first = HiddenDesktop()
    second = HiddenDesktop()
    try:
        assert first.name != second.name
    finally:
        first.close()
        second.close()


def test_child_runs_on_hidden_desktop(tmp_path: Path) -> None:
    """The spawned child's thread desktop is the hidden desktop, not the visible one.

    This is the invisibility guarantee: a window created by a process whose
    threads live on a non-input desktop is never composited to the screen. If
    ``lpDesktop`` were ignored the child would report the parent's desktop and
    this test would fail.

    Args:
        tmp_path: Pytest-provided temporary directory for the child's report.
    """
    report = tmp_path / "child_desktop.txt"
    proc = spawn_on_hidden_desktop(
        Path(sys.executable),
        ["-c", _REPORT_DESKTOP_CHILD, str(report)],
    )
    try:
        exit_code = proc.wait(timeout=_CHILD_WAIT_SECONDS)
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.close()

    assert exit_code == 0, f"child exited {exit_code}"
    child_desktop = report.read_text(encoding="utf-8").strip()
    assert child_desktop == proc.desktop_name, (
        f"child ran on {child_desktop!r}, expected hidden desktop {proc.desktop_name!r}"
    )
    assert child_desktop != get_thread_desktop_name(), (
        "child must not share the test process's visible desktop"
    )


def test_child_receives_supplied_environment(tmp_path: Path) -> None:
    """The environment mapping is delivered to the child intact.

    The bridge relies on this to pass ``INTELLICRACK_X64DBG_HEADLESS`` to
    x64dbg's plugin; a broken environment block would silently drop it.

    Args:
        tmp_path: Pytest-provided temporary directory for the child's report.
    """
    report = tmp_path / "child_env.txt"
    marker = "headless-marker-42"
    child_env = dict(os.environ)
    child_env["INTELLICRACK_TEST_MARKER"] = marker
    proc = spawn_on_hidden_desktop(
        Path(sys.executable),
        ["-c", _REPORT_ENV_CHILD, str(report)],
        child_env,
    )
    try:
        exit_code = proc.wait(timeout=_CHILD_WAIT_SECONDS)
    finally:
        if proc.poll() is None:
            proc.terminate()
        proc.close()

    assert exit_code == 0, f"child exited {exit_code}"
    assert report.read_text(encoding="utf-8").strip() == marker


def test_process_lifecycle_poll_terminate_wait() -> None:
    """poll/terminate/wait reflect the real process state transitions."""
    proc = spawn_on_hidden_desktop(
        Path(sys.executable),
        ["-c", _SLEEP_CHILD],
    )
    try:
        assert proc.poll() is None, "sleeping child must report as running"
        assert proc.returncode is None
        proc.terminate()
        code = proc.wait(timeout=_CHILD_WAIT_SECONDS)
        assert code is not None
        assert proc.poll() is not None, "terminated child must report an exit code"
    finally:
        proc.close()
