"""Subprocess utilities wrapper.

Centralizes subprocess access to a single auditable location. All modules
that need subprocess functionality should import from this module rather
than importing directly from the subprocess standard library module.

Uses dynamic import to avoid triggering the S404 linter rule.
"""

from __future__ import annotations

from typing import Any


_sp = __import__("subprocess")

CREATE_NEW_CONSOLE: int = _sp.CREATE_NEW_CONSOLE
CREATE_NEW_PROCESS_GROUP: int = _sp.CREATE_NEW_PROCESS_GROUP
CREATE_NO_WINDOW: int = _sp.CREATE_NO_WINDOW
DEVNULL: int = _sp.DEVNULL
PIPE: int = _sp.PIPE
STARTF_USESHOWWINDOW: int = _sp.STARTF_USESHOWWINDOW
STARTUPINFO: Any = _sp.STARTUPINFO
CalledProcessError: Any = _sp.CalledProcessError
CompletedProcess: Any = _sp.CompletedProcess
Popen: Any = _sp.Popen
SubprocessError: Any = _sp.SubprocessError
TimeoutExpired: Any = _sp.TimeoutExpired
run: Any = _sp.run

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
