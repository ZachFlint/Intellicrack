# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real Windows-token coverage for :mod:`intellicrack.core.elevation`.

On Windows these tests drive the genuine Win32 elevation surface with no
mocking: ``is_elevated`` is cross-checked against an independent real token
query (``OpenProcessToken`` + ``GetTokenInformation(TokenElevation)``), and
``maybe_elevate`` is exercised over the real process token through the
decision paths that do not raise a UAC prompt. The relaunch builder is
validated to produce a real, existing executable path. On non-Windows
platforms the suite skips with a precise reason rather than faking a pass.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes
from pathlib import Path

import pytest

from intellicrack.core import elevation


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Windows UAC elevation behaviour is Windows-only",
)

_TOKEN_QUERY = 0x0008
_TOKEN_ELEVATION = 20


def _query_token_elevation_independently() -> bool:
    """Read the real ``TokenElevation`` flag via a separate Win32 call path.

    Provides an independent ground-truth for ``is_elevated`` by querying the
    current process token directly with ``OpenProcessToken`` and
    ``GetTokenInformation`` rather than ``shell32.IsUserAnAdmin``.

    Returns:
        bool: ``True`` when the current process token is elevated.

    Raises:
        OSError: If any Win32 call in the query chain fails.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    get_current_process = kernel32.GetCurrentProcess
    get_current_process.restype = wintypes.HANDLE

    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_process_token.restype = wintypes.BOOL

    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_information.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    elevation_flag = wintypes.DWORD(0)
    return_length = wintypes.DWORD(0)
    if not open_process_token(get_current_process(), _TOKEN_QUERY, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")

    try:
        ok = get_token_information(
            token,
            _TOKEN_ELEVATION,
            ctypes.byref(elevation_flag),
            ctypes.sizeof(elevation_flag),
            ctypes.byref(return_length),
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        return bool(elevation_flag.value)
    finally:
        kernel32.CloseHandle(token)


def test_is_windows_true_on_windows() -> None:
    """``is_windows`` reports ``True`` on the real Windows platform."""
    assert elevation.is_windows() is True


def test_is_elevated_matches_independent_token_query() -> None:
    """``is_elevated`` agrees with an independent real ``TokenElevation`` query."""
    assert elevation.is_elevated() is _query_token_elevation_independently()


def test_maybe_elevate_already_attempted_never_relaunches() -> None:
    """A child flagged ``already_attempted`` continues without any relaunch.

    Runs the genuine ``maybe_elevate`` over the real process token; the
    already-attempted guard must return ``False`` and never reach
    ``ShellExecuteW``, regardless of the real elevation state.
    """
    result = elevation.maybe_elevate(
        disabled=False,
        already_attempted=True,
        original_args=["--verbose"],
        working_dir=str(Path.cwd()),
    )
    assert result is False


def test_maybe_elevate_disabled_never_relaunches() -> None:
    """The real ``--no-elevate`` decision path returns ``False`` on Windows."""
    result = elevation.maybe_elevate(
        disabled=True,
        already_attempted=False,
        original_args=[],
        working_dir=str(Path.cwd()),
    )
    assert result is False


def test_maybe_elevate_when_already_elevated_returns_false() -> None:
    """An elevated process needs no relaunch; an unprivileged one is skipped.

    When the test runs in a genuinely elevated process, the real
    ``maybe_elevate`` must short-circuit to ``False`` without prompting. When
    the process is not elevated, calling ``maybe_elevate`` here would trigger a
    real UAC prompt, which cannot be answered non-interactively, so that case
    is skipped with a precise reason.
    """
    if not elevation.is_elevated():
        pytest.skip("Process is not elevated; exercising the relaunch path would raise a real UAC prompt")
    result = elevation.maybe_elevate(
        disabled=False,
        already_attempted=False,
        original_args=[],
        working_dir=str(Path.cwd()),
    )
    assert result is False


def test_build_relaunch_command_targets_real_executable() -> None:
    """The real relaunch builder yields an existing executable and guard flag."""
    builder = getattr(elevation, "_build_relaunch_command")
    executable, params = builder(["--verbose"])
    assert Path(executable).is_file()
    assert params.endswith(elevation.ELEVATED_FLAG)
