# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Fixture files that are large in size and small on disk.

Some gates need a file whose size is gigabytes -- install media the provisioner
sizes before it reads a header, a patch source too large to hold in memory --
while only a few sectors of it carry data. Extending a file with
:meth:`io.IOBase.truncate` leaves a hole on the filesystems Linux and macOS
use, but NTFS allocates every cluster of the extension unless the file was
first marked sparse. Every such fixture therefore cost its full size in real
disk on Windows, and pytest keeps each test's directory until the session
ends, so one run held tens of gigabytes and exhausted the CI runner's disk.

:func:`extend_sparse` marks the file sparse on Windows before extending it, so
the extension is a hole everywhere, and :func:`allocated_bytes` reports what a
file really occupies so a gate can hold the fixtures to that.
"""

from __future__ import annotations

import ctypes
import sys
from typing import TYPE_CHECKING, BinaryIO, Final


if sys.platform == "win32":
    import msvcrt
    from ctypes import wintypes

if TYPE_CHECKING:
    from pathlib import Path


_FSCTL_SET_SPARSE: Final[int] = 0x000900C4
_INVALID_FILE_SIZE: Final[int] = 0xFFFFFFFF
_NO_ERROR: Final[int] = 0
_HIGH_PART_SHIFT: Final[int] = 32
_POSIX_BLOCK_BYTES: Final[int] = 512


def extend_sparse(handle: BinaryIO, size: int) -> None:
    """Grow an open file to ``size`` bytes without storing the bytes it gains.

    What has already been written stays as it is; everything between the end
    of that data and ``size`` reads back as zeros and occupies no clusters.

    Args:
        handle: The file, open for writing in binary mode.
        size: The size the file ends up with, in bytes.

    Raises:
        ctypes.WinError: If Windows refuses to mark the file sparse.
    """
    handle.flush()
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        returned = wintypes.DWORD(0)
        os_handle = wintypes.HANDLE(msvcrt.get_osfhandle(handle.fileno()))
        if not kernel32.DeviceIoControl(os_handle, _FSCTL_SET_SPARSE, None, 0, None, 0, ctypes.byref(returned), None):
            raise ctypes.WinError(ctypes.get_last_error())
    _ = handle.truncate(size)


def allocated_bytes(path: Path) -> int:
    """Report how much storage a file really occupies, as opposed to its size.

    Args:
        path: The file.

    Returns:
        int: The bytes allocated to the file on disk.

    Raises:
        ctypes.WinError: If Windows cannot report the file's allocation.
    """
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetCompressedFileSizeW.restype = wintypes.DWORD
        high = wintypes.DWORD(0)
        ctypes.set_last_error(_NO_ERROR)
        low = int(kernel32.GetCompressedFileSizeW(str(path), ctypes.byref(high)))
        if low == _INVALID_FILE_SIZE and ctypes.get_last_error() != _NO_ERROR:
            raise ctypes.WinError(ctypes.get_last_error())
        return (high.value << _HIGH_PART_SHIFT) | low
    return path.stat().st_blocks * _POSIX_BLOCK_BYTES
