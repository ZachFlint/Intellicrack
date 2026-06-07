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
import os
import subprocess
import sys
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core import elevation


if TYPE_CHECKING:
    from collections.abc import Generator


def _build_relaunch_command(original_args: list[str]) -> tuple[str, str]:
    """Invoke the real private relaunch builder via a typed accessor.

    Routes through the module ``__dict__`` so the private production helper is
    exercised without a private-usage type error, while keeping a precise
    return type for callers.

    Args:
        original_args: Command-line arguments forwarded to the elevated child.

    Returns:
        tuple[str, str]: The executable path and ``ShellExecuteW`` parameter
        string produced by the real builder.
    """
    builder = elevation.__dict__["_build_relaunch_command"]
    executable, params = builder(original_args)
    return str(executable), str(params)


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


_PIXI_ENV_KEYS: tuple[str, str, str] = (
    "PIXI_EXE",
    "PIXI_PROJECT_MANIFEST",
    "PIXI_ENVIRONMENT_NAME",
)


@contextmanager
def _frozen_executable(executable: str) -> Generator[None]:
    """Temporarily present the interpreter as a frozen build.

    Sets the real ``sys.frozen`` marker and ``sys.executable`` that
    :func:`elevation._build_relaunch_command` reads, restoring both afterwards
    so other tests observe the genuine interpreter state. This drives real
    state into the production code, it does not stub the code under test.

    Args:
        executable: Absolute path that ``sys.executable`` reports while frozen.

    Yields:
        None: Control returns to the caller with the frozen state active.
    """
    frozen_attr = "frozen"
    had_frozen = hasattr(sys, frozen_attr)
    saved_frozen = getattr(sys, frozen_attr, None)
    saved_executable = sys.executable
    setattr(sys, frozen_attr, True)
    sys.executable = executable
    try:
        yield
    finally:
        sys.executable = saved_executable
        if had_frozen:
            setattr(sys, frozen_attr, saved_frozen)
        else:
            delattr(sys, frozen_attr)


@contextmanager
def _environment(overrides: dict[str, str | None]) -> Generator[None]:
    """Apply real environment-variable overrides and restore them afterwards.

    Args:
        overrides: Mapping of variable name to its new value, or ``None`` to
            remove the variable for the duration of the context.

    Yields:
        None: Control returns to the caller with the overrides applied.
    """
    saved: dict[str, str | None] = {key: os.environ.get(key) for key in overrides}
    for key, value in overrides.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_relaunch_command_frozen_targets_application_binary(tmp_path: Path) -> None:
    """A frozen build relaunches its own binary with args and the guard flag.

    In a frozen build ``sys.executable`` is the self-contained application
    binary, so the relaunch must invoke exactly that binary with the original
    arguments followed by :data:`elevation.ELEVATED_FLAG`. The parameter string
    is cross-checked against :func:`subprocess.list2cmdline`, an independent
    Win32-quoting oracle, not against the production builder's own output.

    Args:
        tmp_path: Per-test temporary directory for the fake frozen binary.
    """
    binary = tmp_path / "intellicrack.exe"
    binary.write_bytes(b"MZ")
    original_args = ["target.exe", "--analyze", "path with space"]

    with _frozen_executable(str(binary)):
        executable, params = _build_relaunch_command(original_args)

    expected_params = subprocess.list2cmdline([*original_args, elevation.ELEVATED_FLAG])
    assert executable == str(binary)
    assert params == expected_params
    assert params == 'target.exe --analyze "path with space" --elevated'


def test_build_relaunch_command_pixi_targets_pixi_executable(tmp_path: Path) -> None:
    """A pixi launch relaunches through pixi re-activating the environment.

    Under a ``pixi run`` launch (``PIXI_EXE`` set and not frozen) the builder
    must invoke the pixi executable and forward ``run`` with the manifest and
    environment coordinates, then ``python -m intellicrack`` plus the original
    arguments and the guard flag. The expected command is assembled
    independently and verified field-by-field, including that every original
    argument survives in order.

    Args:
        tmp_path: Per-test temporary directory for the fake pixi executable.
    """
    pixi_exe = tmp_path / "pixi.exe"
    pixi_exe.write_bytes(b"MZ")
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text("[project]\n", encoding="utf-8")
    original_args = ["--gui", "--project", "demo"]
    overrides: dict[str, str | None] = {
        "PIXI_EXE": str(pixi_exe),
        "PIXI_PROJECT_MANIFEST": str(manifest),
        "PIXI_ENVIRONMENT_NAME": "default",
    }

    with _environment(overrides):
        executable, params = _build_relaunch_command(original_args)

    # Independent hand-built oracle: every token is asserted literally. The
    # static prefix and suffix are full string literals; the only dynamic token
    # is the manifest path, which is quoted exactly as Win32 requires.
    quoted_manifest = f'"{manifest}"' if " " in str(manifest) else str(manifest)
    expected_params = f"run --manifest-path {quoted_manifest} --environment default python -m intellicrack --gui --project demo --elevated"
    assert executable == str(pixi_exe)
    assert params == expected_params
    assert manifest.is_file()
    assert params.startswith("run --manifest-path ")
    assert params.endswith(" --environment default python -m intellicrack --gui --project demo --elevated")


def test_build_relaunch_command_pixi_missing_executable_falls_back_to_interpreter(tmp_path: Path) -> None:
    """A stale ``PIXI_EXE`` path falls back to the ``python -m`` launch.

    When ``PIXI_EXE`` points at a path that no longer exists the pixi branch is
    rejected and the builder relaunches the current interpreter with
    ``-m intellicrack``. This exercises the real missing-executable boundary.

    Args:
        tmp_path: Per-test temporary directory used to build a non-existent
            pixi path.
    """
    missing_pixi = tmp_path / "does_not_exist" / "pixi.exe"
    original_args = ["--headless"]

    with _environment({"PIXI_EXE": str(missing_pixi)}):
        executable, params = _build_relaunch_command(original_args)

    expected_params = subprocess.list2cmdline(["-m", elevation.PACKAGE_NAME, *original_args, elevation.ELEVATED_FLAG])
    assert executable == sys.executable
    assert params == expected_params
    assert params == "-m intellicrack --headless --elevated"


def test_build_relaunch_command_plain_interpreter_uses_module_launch() -> None:
    """A plain interpreter launch restarts via ``python -m intellicrack``.

    With no frozen marker and no pixi launcher the builder must return the
    current ``sys.executable`` and a ``-m intellicrack`` parameter string that
    preserves the original arguments before the guard flag.
    """
    original_args = ["--no-gui", "sample.bin"]
    cleared_pixi: dict[str, str | None] = dict.fromkeys(_PIXI_ENV_KEYS)

    with _environment(cleared_pixi):
        executable, params = _build_relaunch_command(original_args)

    expected_params = subprocess.list2cmdline(["-m", elevation.PACKAGE_NAME, *original_args, elevation.ELEVATED_FLAG])
    assert executable == sys.executable
    assert Path(executable).is_file()
    assert params == expected_params
    assert params == "-m intellicrack --no-gui sample.bin --elevated"


def test_build_relaunch_command_empty_args_still_appends_guard_flag() -> None:
    """With no original arguments the relaunch carries only the guard flag.

    The boundary case of an empty argument list must still append
    :data:`elevation.ELEVATED_FLAG` so the elevated child never re-prompts.
    """
    cleared_pixi: dict[str, str | None] = dict.fromkeys(_PIXI_ENV_KEYS)

    with _environment(cleared_pixi):
        executable, params = _build_relaunch_command([])

    assert executable == sys.executable
    assert params == subprocess.list2cmdline(["-m", elevation.PACKAGE_NAME, elevation.ELEVATED_FLAG])
    assert params == "-m intellicrack --elevated"
