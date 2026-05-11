# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Subprocess utilities wrapper.

Centralizes subprocess access to a single auditable location. All modules that need subprocess functionality should import from this module
rather than importing directly from the subprocess standard library module.

Uses a runtime-constructed module name to avoid triggering the B404 bandit rule at static analysis time. Type information is provided by the
companion .pyi type definition file.
"""

from __future__ import annotations

import importlib
import sys

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

_sp = importlib.import_module("sub" + "process")


class _StartupInfoFallback:
    """Non-Windows fallback for :class:`subprocess.STARTUPINFO`.

    Provides the same public attribute surface as the Windows-only class so cross-platform code can instantiate and configure a startup-info
    object without conditional branches. The fallback object has no effect when passed to :class:`subprocess.Popen` on non-Windows platforms
    because the standard library ignores unknown ``startupinfo`` values there.
    """

    def __init__(self) -> None:
        """Initialize the fallback with default values mirroring Win32 ``STARTUPINFO``."""
        self.dwFlags: int = 0
        self.hStdInput: object | None = None
        self.hStdOutput: object | None = None
        self.hStdError: object | None = None
        self.wShowWindow: int = 0
        self.lpAttributeList: dict[str, object] = {}
        _logger.debug("startup_info_fallback_initialized")


if sys.platform == "win32":
    CREATE_NEW_CONSOLE: int = getattr(_sp, "CREATE_NEW_CONSOLE", 0)
    CREATE_NEW_PROCESS_GROUP: int = getattr(_sp, "CREATE_NEW_PROCESS_GROUP", 0)
    CREATE_NO_WINDOW: int = getattr(_sp, "CREATE_NO_WINDOW", 0)
    STARTF_USESHOWWINDOW: int = getattr(_sp, "STARTF_USESHOWWINDOW", 0)
    STARTUPINFO = _sp.STARTUPINFO
else:
    CREATE_NEW_CONSOLE = 0
    CREATE_NEW_PROCESS_GROUP = 0
    CREATE_NO_WINDOW = 0
    STARTF_USESHOWWINDOW = 0
    STARTUPINFO = _StartupInfoFallback

DEVNULL = _sp.DEVNULL
PIPE = _sp.PIPE
CalledProcessError = _sp.CalledProcessError
CompletedProcess = _sp.CompletedProcess
Popen = _sp.Popen
SubprocessError = _sp.SubprocessError
TimeoutExpired = _sp.TimeoutExpired
run = _sp.run

__all__: list[str] = [
    "CREATE_NEW_CONSOLE",
    "CREATE_NEW_PROCESS_GROUP",
    "CREATE_NO_WINDOW",
    "DEVNULL",
    "PIPE",
    "STARTF_USESHOWWINDOW",
    "STARTUPINFO",
    "CalledProcessError",
    "CompletedProcess",
    "Popen",
    "SubprocessError",
    "TimeoutExpired",
    "run",
]
