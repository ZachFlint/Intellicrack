# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.core.subprocess_compat`.

The compat wrapper is the single auditable point through which the whole
codebase reaches the standard-library ``subprocess`` module. These tests
validate the genuinely exported objects, the platform-correct Win32 creation
constants, the non-Windows ``_StartupInfoFallback`` surface, and that a real
subprocess actually runs through the re-exported ``run``/``Popen`` callables
against a real System32 executable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from intellicrack.core import subprocess_compat
from intellicrack.core.subprocess_compat import (
    CREATE_NEW_CONSOLE,
    CREATE_NEW_PROCESS_GROUP,
    CREATE_NO_WINDOW,
    DEVNULL,
    PIPE,
    STARTF_USESHOWWINDOW,
    STARTUPINFO,
    CalledProcessError,
    CompletedProcess,
    Popen,
    SubprocessError,
    TimeoutExpired,
    list2cmdline,
    run,
)


_EXPECTED_EXIT_CODE = 7
_SYSTEM32_WHERE = Path("C:/Windows/System32/where.exe")


def test_reexports_are_the_real_stdlib_objects() -> None:
    """Every re-exported symbol is identical to its ``subprocess`` original."""
    assert DEVNULL is subprocess.DEVNULL
    assert PIPE is subprocess.PIPE
    assert CalledProcessError is subprocess.CalledProcessError
    assert CompletedProcess is subprocess.CompletedProcess
    assert Popen is subprocess.Popen
    assert SubprocessError is subprocess.SubprocessError
    assert TimeoutExpired is subprocess.TimeoutExpired
    assert list2cmdline is subprocess.list2cmdline
    assert run is subprocess.run


def test_list2cmdline_quotes_real_argument_list() -> None:
    """``list2cmdline`` joins a real argument list into one quoted string."""
    rendered = list2cmdline(["app.exe", "--config", "C:/a b/c.toml"])
    assert isinstance(rendered, str)
    assert rendered.startswith("app.exe --config ")
    assert '"C:/a b/c.toml"' in rendered


def test_creation_constants_match_platform() -> None:
    """Win32 creation flags are real non-zero ints on Windows, zero elsewhere."""
    constants = (
        CREATE_NEW_CONSOLE,
        CREATE_NEW_PROCESS_GROUP,
        CREATE_NO_WINDOW,
        STARTF_USESHOWWINDOW,
    )
    assert all(isinstance(value, int) for value in constants)
    if sys.platform == "win32":
        assert CREATE_NEW_CONSOLE == subprocess.CREATE_NEW_CONSOLE
        assert CREATE_NEW_PROCESS_GROUP == subprocess.CREATE_NEW_PROCESS_GROUP
        assert CREATE_NO_WINDOW == subprocess.CREATE_NO_WINDOW
        assert STARTF_USESHOWWINDOW == subprocess.STARTF_USESHOWWINDOW
        assert CREATE_NEW_CONSOLE != 0
    else:
        assert constants == (0, 0, 0, 0)


def test_startupinfo_selection_matches_platform() -> None:
    """``STARTUPINFO`` is the real Win32 class on Windows, the fallback else."""
    if sys.platform == "win32":
        assert STARTUPINFO is subprocess.STARTUPINFO
    else:
        fallback_cls = getattr(subprocess_compat, "_StartupInfoFallback")
        assert STARTUPINFO is fallback_cls


def test_startupinfo_fallback_attribute_surface() -> None:
    """The non-Windows fallback exposes the full Win32 ``STARTUPINFO`` surface."""
    fallback_cls = cast(
        "type[object]",
        getattr(subprocess_compat, "_StartupInfoFallback"),
    )
    info = fallback_cls()
    assert getattr(info, "dwFlags") == 0
    assert getattr(info, "wShowWindow") == 0
    assert getattr(info, "hStdInput") is None
    assert getattr(info, "hStdOutput") is None
    assert getattr(info, "hStdError") is None
    assert getattr(info, "lpAttributeList") == {}


@pytest.mark.spawns_process
def test_run_executes_real_process_and_captures_output() -> None:
    """``run`` launches a real interpreter and captures its real stdout."""
    completed = run(
        [sys.executable, "-c", "print('real-subprocess-output')"],
        stdout=PIPE,
        stderr=DEVNULL,
        check=True,
        text=True,
    )
    assert isinstance(completed, subprocess.CompletedProcess)
    assert completed.returncode == 0
    assert "real-subprocess-output" in completed.stdout


@pytest.mark.spawns_process
def test_run_raises_real_called_process_error_on_failure() -> None:
    """A non-zero real exit code raises the re-exported ``CalledProcessError``."""
    with pytest.raises(CalledProcessError) as exc_info:
        run(
            [sys.executable, "-c", f"import sys; sys.exit({_EXPECTED_EXIT_CODE})"],
            check=True,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )
    assert exc_info.value.returncode == _EXPECTED_EXIT_CODE


@pytest.mark.spawns_process
def test_popen_runs_real_system_executable() -> None:
    """``Popen`` launches a real System32 PE and reaps a real exit code.

    Uses ``where.exe`` from System32, a genuine console PE that terminates on
    its own, so the test reaps a real process exit code rather than relying on
    a synthetic stand-in.
    """
    if sys.platform != "win32" or not _SYSTEM32_WHERE.is_file():
        pytest.skip(f"Real System32 where.exe unavailable at {_SYSTEM32_WHERE}")
    process = Popen(
        [str(_SYSTEM32_WHERE), "where.exe"],
        stdout=PIPE,
        stderr=DEVNULL,
    )
    try:
        stdout_bytes, _ = process.communicate(timeout=30)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=30)
    assert process.returncode == 0
    assert b"where.exe" in stdout_bytes.lower()
