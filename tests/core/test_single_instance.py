# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for the running-instance mutex marker.

Intellicrack creates a named Win32 mutex on startup so the Inno Setup installer,
which declares the same name as its ``AppMutex``, can detect a live instance and
close it via the Restart Manager before an in-place upgrade or uninstall. Two
things must hold for that integration to work:

* the name the application creates must equal the ``AppMutex`` the ``.iss``
  declares (a cross-file contract that must never silently drift); and
* :func:`acquire_instance_mutex` must actually create a kernel mutex object that
  another opener can find by that exact name.

Both are exercised here against the real Win32 API and the real ``.iss`` script.
"""

from __future__ import annotations

import ctypes
import platform
from ctypes import wintypes
from pathlib import Path
from typing import Final

import pytest

from intellicrack.core.single_instance import MUTEX_NAME, acquire_instance_mutex


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_ISS_PATH: Final[Path] = _REPO_ROOT / "packaging" / "intellicrack.iss"

# Access right sufficient to open an existing mutex by name for a liveness probe.
_SYNCHRONIZE: Final[int] = 0x00100000


def _iss_app_mutex(iss_text: str) -> str | None:
    """Extract the ``AppMutex`` value from the ``[Setup]`` section of an ``.iss``.

    Only the ``[Setup]`` section is scanned so a same-named directive elsewhere
    cannot shadow the real value.

    Args:
        iss_text: The full text of an Inno Setup ``.iss`` script.

    Returns:
        str | None: The ``AppMutex`` value, or ``None`` if the section declares
        none.
    """
    in_setup = False
    for line in iss_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_setup = stripped.lower() == "[setup]"
            continue
        if in_setup and stripped.lower().startswith("appmutex="):
            return stripped.split("=", 1)[1].strip()
    return None


def _open_named_mutex(name: str) -> int:
    """Open an existing named mutex, returning its handle or ``0`` if absent.

    Args:
        name: The fully qualified mutex name, including any ``Global`` namespace prefix.

    Returns:
        int: A non-zero handle when a mutex of that name exists, otherwise ``0``.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_mutex = kernel32.OpenMutexW
    open_mutex.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    open_mutex.restype = wintypes.HANDLE
    inherit = wintypes.BOOL(0)
    handle = open_mutex(_SYNCHRONIZE, inherit, name)
    return int(handle) if handle else 0


def _close_handle(handle: int) -> None:
    """Close a Win32 handle.

    Args:
        handle: A non-zero Win32 handle to close.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    close(wintypes.HANDLE(handle))


def test_mutex_name_matches_iss_app_mutex() -> None:
    """The source ``MUTEX_NAME`` equals the ``AppMutex`` the real ``.iss`` declares.

    This is the anti-drift contract: if either the constant or the installer
    directive changes without the other, Setup would create/detect a different
    mutex than the app holds and the running-instance handoff would silently
    break. Reading the real ``.iss`` makes this fail the moment they diverge.
    """
    assert _ISS_PATH.is_file(), f"Inno Setup script missing: {_ISS_PATH}"
    app_mutex = _iss_app_mutex(_ISS_PATH.read_text(encoding="utf-8-sig"))
    assert app_mutex is not None, "the .iss [Setup] section declares no AppMutex"
    assert app_mutex == MUTEX_NAME, (
        f"AppMutex/{MUTEX_NAME!r} drift: the .iss declares {app_mutex!r} but the app creates {MUTEX_NAME!r}"
    )


def test_iss_app_mutex_parser_is_section_scoped() -> None:
    """The ``AppMutex`` parser reads only ``[Setup]`` and ignores other sections.

    Proves a same-named line under another section does not shadow the real
    value; a section-blind parser would return the wrong string.
    """
    sample = (
        "[Setup]\n"
        "AppMutex=Global\\Correct\n"
        "\n"
        "[UninstallRun]\n"
        "AppMutex=Global\\Wrong\n"
    )
    assert _iss_app_mutex(sample) == "Global\\Correct"
    assert _iss_app_mutex("[Setup]\nAppName=x\n") is None


@pytest.mark.skipif(platform.system() != "Windows", reason="the named-mutex marker is Windows-only")
def test_acquire_creates_kernel_mutex_discoverable_by_name() -> None:
    """``acquire_instance_mutex`` creates a kernel mutex findable by its name.

    Exercises the real Win32 path: after acquiring, an independent
    ``OpenMutexW`` for :data:`MUTEX_NAME` must succeed, proving a genuine named
    kernel object was created (not merely a handle value returned). The paired
    absent-name probe below shows this discovery can fail, so success here is
    meaningful.
    """
    handle = acquire_instance_mutex()
    assert handle is not None, "acquire_instance_mutex returned None on Windows"
    assert handle != 0, "acquire_instance_mutex returned a null handle on Windows"

    opened = _open_named_mutex(MUTEX_NAME)
    try:
        assert opened != 0, (
            f"no kernel mutex named {MUTEX_NAME!r} exists after acquire "
            f"(OpenMutexW failed, last error {ctypes.get_last_error()})"
        )
    finally:
        if opened:
            _close_handle(opened)


@pytest.mark.skipif(platform.system() != "Windows", reason="the named-mutex marker is Windows-only")
def test_open_named_mutex_probe_returns_zero_for_absent_name() -> None:
    """The discovery probe returns ``0`` for a name that was never created.

    Without this, the create-test's ``OpenMutexW`` success could be vacuous (for
    example if the probe always returned a handle); this pins the probe as a real
    discriminator of mutex existence.
    """
    absent = MUTEX_NAME + "_never_created_probe_marker"
    opened = _open_named_mutex(absent)
    try:
        assert opened == 0, f"OpenMutexW unexpectedly found a mutex named {absent!r}"
    finally:
        if opened:
            _close_handle(opened)


@pytest.mark.skipif(platform.system() != "Windows", reason="the named-mutex marker is Windows-only")
def test_acquire_is_idempotent_within_process() -> None:
    """Repeated acquisition returns the same retained handle, not a new mutex.

    The marker is created once and held for the process lifetime; a second call
    must return the cached handle rather than opening a second object.
    """
    first = acquire_instance_mutex()
    second = acquire_instance_mutex()
    assert first is not None
    assert first == second, "acquire_instance_mutex must return the already-held handle on repeat calls"
