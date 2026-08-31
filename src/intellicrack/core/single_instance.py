# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Running-instance marker for the installer's ``AppMutex`` integration.

Intellicrack creates a named Win32 mutex when it starts and holds it for the
lifetime of the process. The Inno Setup installer and uninstaller declare the
same name as their ``AppMutex``, so Setup can detect a live instance and offer
to close it (via the Restart Manager) before an in-place upgrade or a removal,
instead of failing on files that are still in use.

The name is the single source of truth shared with the installer: the packaging
test suite asserts the ``.iss`` ``AppMutex`` directive equals :data:`MUTEX_NAME`,
so the two can never silently drift apart. Creating the mutex does NOT enforce
single-instance behaviour - a second instance is allowed to start - the mutex
exists purely as a detectable liveness marker for the installer.
"""

from __future__ import annotations

import ctypes
import platform
from ctypes import wintypes
from typing import Final

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)

# Global-namespace name so an elevated installer/uninstaller can detect the
# mutex held by the (typically non-elevated) running application. Must match the
# ``AppMutex`` directive in ``packaging/intellicrack.iss``.
MUTEX_NAME: Final[str] = "Global\\IntellicrackSingleInstance"

# Mutable holder so the acquired handle survives for the process lifetime without
# a module-level ``global`` rebinding.
_held: dict[str, int] = {}


def acquire_instance_mutex() -> int | None:
    """Create and retain the named mutex that marks a running instance.

    On Windows this creates ``MUTEX_NAME`` and keeps the handle in a module-level
    reference for the lifetime of the process, so the mutex stays alive for the
    installer to detect. The handle is never closed explicitly; the OS releases
    it when the process exits. Calling more than once returns the already-held
    handle rather than creating a second one. Any failure to create the mutex is
    logged and swallowed - the marker is best-effort and must never prevent the
    application from starting.

    Returns:
        int | None: The Win32 mutex handle on Windows, or ``None`` on non-Windows
        platforms or when the mutex could not be created.
    """
    if platform.system() != "Windows":
        return None
    existing = _held.get("handle")
    if existing is not None:
        return existing

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_mutex = kernel32.CreateMutexW
    create_mutex.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    create_mutex.restype = wintypes.HANDLE

    initial_owner = wintypes.BOOL(0)
    handle = create_mutex(None, initial_owner, MUTEX_NAME)
    if not handle:
        error = ctypes.get_last_error()
        _logger.warning("instance_mutex_create_failed", mutex_name=MUTEX_NAME, last_error=error)
        return None

    acquired = int(handle)
    _held["handle"] = acquired
    _logger.debug("instance_mutex_acquired", mutex_name=MUTEX_NAME)
    return acquired
