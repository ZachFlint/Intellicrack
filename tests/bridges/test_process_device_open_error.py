# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-syscall regression test for the D26 ``device_open`` error-discard defect.

Exercises ``ProcessBridge.device_open`` against real Win32
``CreateFileW`` targets - a raw disk device that a medium-integrity
(non-elevated) process cannot open, and a device namespace path that
does not exist - and asserts the raised ``ToolError`` carries the real
Win32 error code (``5`` / ``ERROR_ACCESS_DENIED`` and ``2`` /
``ERROR_FILE_NOT_FOUND`` respectively) instead of the bare, code-less
failure constant. A regression back to the bare constant leaves
``error_code`` ``None`` and drops the number from the message, so this
test fails whenever the discard defect reappears.
"""

from __future__ import annotations

import ctypes
import sys

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.elevation import is_windows
from intellicrack.core.types import ToolError


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
    pytest.mark.integration,
]

_WIN32_ERROR_ACCESS_DENIED = 5
_WIN32_ERROR_FILE_NOT_FOUND = 2
_NONEXISTENT_DEVICE_PATH = r"\\.\IntellicrackS19D26NonexistentDevice"
_PHYSICAL_DRIVE_0_PATH = r"\\.\PhysicalDrive0"


def _is_elevated() -> bool:
    """Report whether the current process token is elevated (admin).

    Uses ``shell32.IsUserAnAdmin`` as an independent oracle: under UAC a
    medium-integrity process (even one launched by an administrator
    account) carries a filtered token that is not a member of the
    Administrators group in this check, so it reports ``False`` exactly
    when the process is running at medium integrity.

    Returns:
        bool: ``True`` when the calling process token is elevated.
            Always ``False`` off Windows, where ``ctypes.windll`` does
            not exist; this keeps the module importable (and its
            ``skipif`` decorators evaluable at collection time) on
            every platform even though the tests themselves are
            Windows-only.
    """
    if not is_windows():
        return False
    shell32 = ctypes.windll.shell32
    return bool(shell32.IsUserAnAdmin())


@pytest_asyncio.fixture
async def bridge() -> ProcessBridge:
    """Create and initialize a ``ProcessBridge`` for a single test.

    Returns:
        ProcessBridge: Initialized bridge with a live ``self._kernel32``
            handle, ready for real ``CreateFileW`` calls.
    """
    instance = ProcessBridge()
    await instance.initialize()
    return instance


@pytest.mark.skipif(_is_elevated(), reason="requires a medium-integrity (non-elevated) process")
async def test_device_open_physical_drive_reports_access_denied(bridge: ProcessBridge) -> None:
    """device_open of PhysicalDrive0 at medium integrity raises ACCESS_DENIED.

    Opening a raw disk device with ``GENERIC_READ | GENERIC_WRITE``
    requires an elevated token, so on a host that exposes the device a
    medium-integrity process must receive ``ERROR_ACCESS_DENIED`` (5)
    from ``CreateFileW``. Some restricted execution environments (for
    example a container without a physical disk namespace) instead
    report ``ERROR_FILE_NOT_FOUND`` (2) for every ``PhysicalDriveN``
    path, even a read-only open; that specific, independently-verified
    code is treated as an environment limitation and skipped rather
    than asserted on, since the elevation gate cannot be exercised
    there. Any other outcome - including the pre-fix bare, code-less
    failure (``error_code is None``) - fails the test: the real Win32
    error number must always be threaded through into the raised
    ``ToolError`` rather than discarded.

    Args:
        bridge: Initialized ``ProcessBridge`` fixture.
    """
    with pytest.raises(ToolError) as exc_info:
        await bridge.device_open(_PHYSICAL_DRIVE_0_PATH)

    error = exc_info.value
    assert error.error_code in {_WIN32_ERROR_ACCESS_DENIED, _WIN32_ERROR_FILE_NOT_FOUND}, (
        f"expected a real Win32 error code ({_WIN32_ERROR_ACCESS_DENIED}=ACCESS_DENIED or "
        f"{_WIN32_ERROR_FILE_NOT_FOUND}=FILE_NOT_FOUND depending on environment), "
        f"got {error.error_code!r} (message={error.message!r})"
    )
    assert str(error.error_code) in error.message, (
        f"ToolError message must contain the Win32 error number, got {error.message!r}"
    )
    if error.error_code == _WIN32_ERROR_FILE_NOT_FOUND:
        pytest.skip(
            "PhysicalDrive0 is not exposed as a device object in this execution "
            "environment (CreateFileW reports ERROR_FILE_NOT_FOUND); the "
            "ACCESS_DENIED elevation gate cannot be exercised here",
        )
    assert "access is denied. Retry from an elevated (Administrator) process." in error.message, (
        "ACCESS_DENIED message must read as two grammatical sentences (period between the "
        f"cause and the remedy, no comma splice) and hint at retrying elevated, got {error.message!r}"
    )


async def test_device_open_nonexistent_path_reports_file_not_found(bridge: ProcessBridge) -> None:
    """device_open of a nonexistent device path raises ERROR_FILE_NOT_FOUND.

    A device namespace path that no driver has registered must fail
    ``CreateFileW`` with ``ERROR_FILE_NOT_FOUND`` (2), and that real
    Win32 error number must be threaded through into the raised
    ``ToolError`` rather than discarded.

    Args:
        bridge: Initialized ``ProcessBridge`` fixture.
    """
    with pytest.raises(ToolError) as exc_info:
        await bridge.device_open(_NONEXISTENT_DEVICE_PATH)

    error = exc_info.value
    assert error.error_code == _WIN32_ERROR_FILE_NOT_FOUND, (
        f"expected error_code={_WIN32_ERROR_FILE_NOT_FOUND}, got {error.error_code!r} "
        f"(message={error.message!r})"
    )
    assert str(_WIN32_ERROR_FILE_NOT_FOUND) in error.message, (
        f"ToolError message must contain the Win32 error number, got {error.message!r}"
    )
    assert error.message.startswith("Device open failed (Win32 error 2)"), (
        "message must lead with the capitalized, formatted failure text "
        f"'Device open failed (Win32 error 2)', got {error.message!r}"
    )
