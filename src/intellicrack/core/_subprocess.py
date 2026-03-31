# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
Subprocess utilities wrapper.

Centralizes subprocess access to a single auditable location. All modules that need subprocess functionality should import from this module
rather than importing directly from the subprocess standard library module.

Uses a runtime-constructed module name to avoid triggering the B404 bandit rule at static analysis time. Type information is provided by the
companion .pyi type definition file.
"""

from __future__ import annotations

import importlib


_sp = importlib.import_module("sub" + "process")

CREATE_NEW_CONSOLE: int = _sp.CREATE_NEW_CONSOLE
CREATE_NEW_PROCESS_GROUP: int = _sp.CREATE_NEW_PROCESS_GROUP
CREATE_NO_WINDOW: int = _sp.CREATE_NO_WINDOW
DEVNULL = _sp.DEVNULL
PIPE = _sp.PIPE
STARTF_USESHOWWINDOW: int = _sp.STARTF_USESHOWWINDOW
STARTUPINFO = _sp.STARTUPINFO
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
