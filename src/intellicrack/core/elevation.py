# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Windows UAC self-elevation for Intellicrack.

Detects whether the current process holds an elevated (administrative) token
and, when it does not, relaunches the application through the Windows
``runas`` verb so the user is presented with a User Account Control (UAC)
prompt.

Elevation is what allows ``SeDebugPrivilege`` to be enabled on the process
token (see :mod:`intellicrack.bridges.process`), which in turn grants the
process bridge full access to protected, elevated, and cross-user target
processes. Without it those operations fail with access-denied even though the
rest of the application runs normally.

The relaunch is guarded against prompt loops: the elevated child is started
with the internal :data:`ELEVATED_FLAG` argument, and a child that is still
not elevated (for example because the user dismissed the UAC dialog) continues
unprivileged instead of prompting again.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import Final

from intellicrack.core.logging import get_logger
from intellicrack.core.subprocess_compat import list2cmdline


_logger = get_logger(__name__)

PACKAGE_NAME: Final[str] = "intellicrack"
ELEVATED_FLAG: Final[str] = "--elevated"
NO_ELEVATE_FLAG: Final[str] = "--no-elevate"

# Environment variables exported by ``pixi run`` that let the elevated relaunch
# reconstruct the exact pixi invocation. The elevated child is spawned by the
# Windows AppInfo service and does NOT inherit the activated pixi/conda
# environment, so relaunching the bare interpreter would lose ``CONDA_PREFIX``,
# the activated ``PATH``, and the native DLL directories that packages such as
# ``capstone`` and PyQt6 require. Relaunching through pixi re-activates the
# environment inside the elevated process instead.
_PIXI_EXE_ENV: Final[str] = "PIXI_EXE"
_PIXI_MANIFEST_ENV: Final[str] = "PIXI_PROJECT_MANIFEST"
_PIXI_ENVIRONMENT_ENV: Final[str] = "PIXI_ENVIRONMENT_NAME"

# ``ShellExecuteW`` returns an ``HINSTANCE`` cast to an integer; any value
# greater than 32 indicates success, lower values are ``SE_ERR_*`` codes.
_SHELL_EXECUTE_SUCCESS_THRESHOLD: Final[int] = 32
_SW_SHOWNORMAL: Final[int] = 1
# ``GetLastError`` value set when the user dismisses the UAC consent dialog.
_ERROR_CANCELLED: Final[int] = 1223


def is_windows() -> bool:
    """Return whether the current platform is Windows.

    Returns:
        bool: ``True`` on Windows, ``False`` on every other platform.
    """
    return sys.platform == "win32"


def is_elevated() -> bool:
    """Return whether the current process token is elevated.

    Uses ``shell32.IsUserAnAdmin`` to test for membership in the local
    Administrators group on the process token, which is only present when the
    process is running with an elevated token.

    Returns:
        bool: ``True`` when the process holds an elevated token; ``False`` on
        non-Windows platforms or on any Win32 error.
    """
    if not is_windows():
        return False
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    is_user_an_admin = shell32.IsUserAnAdmin
    is_user_an_admin.restype = wintypes.BOOL
    is_user_an_admin.argtypes = []
    try:
        return bool(is_user_an_admin())
    except OSError as exc:
        _logger.warning("is_user_an_admin_failed", error=str(exc))
        return False


def _build_pixi_relaunch_command(relaunch_args: list[str]) -> tuple[str, str] | None:
    """Build a ``pixi run`` relaunch command when launched under pixi.

    When the application is started through ``pixi run`` (the supported
    Windows launcher), the activated environment is what makes native
    dependencies importable. Because the elevated child cannot inherit that
    environment, it must be relaunched through pixi so the environment is
    re-activated inside the elevated process. The required pixi coordinates are
    read from the environment variables pixi exports on activation.

    Args:
        relaunch_args: The forwarded arguments with :data:`ELEVATED_FLAG`
            already appended.

    Returns:
        tuple[str, str] | None: The ``pixi`` executable path and the argument
        string to pass to ``ShellExecuteW``, or ``None`` when pixi is not the
        active launcher (no ``PIXI_EXE``) or its executable no longer exists.
    """
    pixi_exe = os.environ.get(_PIXI_EXE_ENV)
    if not pixi_exe or not Path(pixi_exe).is_file():
        return None

    pixi_args: list[str] = ["run"]
    if manifest := os.environ.get(_PIXI_MANIFEST_ENV):
        pixi_args += ["--manifest-path", manifest]
    if environment := os.environ.get(_PIXI_ENVIRONMENT_ENV):
        pixi_args += ["--environment", environment]
    pixi_args += ["python", "-m", PACKAGE_NAME, *relaunch_args]
    return pixi_exe, list2cmdline(pixi_args)


def _build_relaunch_command(original_args: list[str]) -> tuple[str, str]:
    """Build the executable and parameter string used to relaunch elevated.

    Handles three launch modes, in priority order:

    * A frozen build (PyInstaller/Nuitka), where ``sys.executable`` is the
      self-contained application binary and no environment activation is
      needed.
    * A ``pixi run`` launch, which is relaunched through pixi so the elevated
      child re-activates the pixi/conda environment (see
      :func:`_build_pixi_relaunch_command`).
    * A plain interpreter launch, restarted via ``python -m intellicrack``.

    The internal :data:`ELEVATED_FLAG` is appended so the elevated child does
    not attempt to elevate again.

    Args:
        original_args: The original command-line arguments (``sys.argv[1:]``)
            to forward to the elevated instance.

    Returns:
        tuple[str, str]: The executable path to invoke and the argument string
        to pass to ``ShellExecuteW``.
    """
    relaunch_args = [*original_args, ELEVATED_FLAG]
    if getattr(sys, "frozen", False):
        return sys.executable, list2cmdline(relaunch_args)
    if (pixi_command := _build_pixi_relaunch_command(relaunch_args)) is not None:
        return pixi_command
    return sys.executable, list2cmdline(["-m", PACKAGE_NAME, *relaunch_args])


def _relaunch_elevated(original_args: list[str], working_dir: str) -> bool:
    """Relaunch the application elevated via the Windows ``runas`` verb.

    Args:
        original_args: The original command-line arguments to forward to the
            elevated instance.
        working_dir: Working directory for the elevated process so relative
            paths (``.env``, config, logs) resolve identically.

    Returns:
        bool: ``True`` when an elevated process was successfully started (the
        caller should exit); ``False`` when the request failed or the user
        declined the UAC prompt.
    """
    executable, params = _build_relaunch_command(original_args)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell_execute = shell32.ShellExecuteW
    shell_execute.restype = ctypes.c_ssize_t
    shell_execute.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]

    result: int = shell_execute(None, "runas", executable, params, working_dir, _SW_SHOWNORMAL)
    if result > _SHELL_EXECUTE_SUCCESS_THRESHOLD:
        _logger.info("relaunched_elevated", executable=executable, params=params)
        return True

    last_error = ctypes.get_last_error()
    if last_error == _ERROR_CANCELLED:
        _logger.warning("elevation_declined_by_user", result_code=result)
    else:
        _logger.warning("shell_execute_runas_failed", result_code=result, last_error=last_error)
    return False


def maybe_elevate(*, disabled: bool, already_attempted: bool, original_args: list[str], working_dir: str) -> bool:
    """Relaunch the application elevated when required and possible.

    Decision order:

    * Non-Windows platforms never elevate.
    * ``--no-elevate`` disables elevation entirely.
    * A child started with :data:`ELEVATED_FLAG` never re-prompts; if it is
      still unprivileged the user declined the prompt and the app continues
      with limited rights.
    * An already-elevated process needs nothing further.
    * Otherwise a UAC relaunch is attempted.

    Args:
        disabled: ``True`` when elevation was disabled via ``--no-elevate``.
        already_attempted: ``True`` when this process was started with
            :data:`ELEVATED_FLAG` by a prior relaunch.
        original_args: Original command-line arguments to forward when
            relaunching.
        working_dir: Working directory to assign to the elevated process.

    Returns:
        bool: ``True`` when an elevated instance was started and the current
        process should exit immediately; ``False`` when the current process
        should continue running as-is.
    """
    if not is_windows():
        return False
    if disabled:
        _logger.debug("elevation_disabled_by_flag")
        return False
    if already_attempted:
        if not is_elevated():
            _logger.info("running_unprivileged_after_elevation_attempt")
        return False
    if is_elevated():
        _logger.debug("already_elevated")
        return False
    if _relaunch_elevated(original_args, working_dir):
        return True
    _logger.warning("running_unprivileged_elevation_unavailable")
    return False
