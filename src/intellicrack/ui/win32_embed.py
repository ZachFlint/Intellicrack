# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Win32 window embedding utilities for Intellicrack.

Provides helpers for capturing external application windows by PID and embedding them inside Qt widgets using QWindow.fromWinId and
QWidget.createWindowContainer.  Windows-only; on other platforms all functions return None / no-op.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import platform
from ctypes import POINTER
from typing import TYPE_CHECKING, Final, cast

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QWindow
from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.sip import voidptr


_logger = get_logger(__name__)

_EMBED_MIN_WIDTH: Final[int] = 200
_EMBED_MIN_HEIGHT: Final[int] = 150

_GW_OWNER: Final[int] = 4
_MAX_TITLE_LEN: Final[int] = 256
GW_OWNER: Final[int] = _GW_OWNER
MAX_TITLE_LEN: Final[int] = _MAX_TITLE_LEN

_GWL_STYLE: Final[int] = -16
_WS_CHILD: Final[int] = 0x40000000
_WS_VISIBLE: Final[int] = 0x10000000
_WS_POPUP: Final[int] = 0x80000000
_WS_CAPTION: Final[int] = 0x00C00000
_WS_THICKFRAME: Final[int] = 0x00040000
_WS_MINIMIZEBOX: Final[int] = 0x00020000
_WS_MAXIMIZEBOX: Final[int] = 0x00010000
_WS_SYSMENU: Final[int] = 0x00080000


def _is_windows() -> bool:
    """Return True when running on the Windows platform.

    Returns:
        bool: True if the current platform is Windows, False otherwise.
    """
    return platform.system() == "Windows"


def _configure_user32(user32: ctypes.WinDLL) -> None:
    """Apply argtypes and restype annotations to user32 functions used here.

    Without explicit annotations, ctypes defaults to c_int which mis-signs
    HWND values above INT_MAX and truncates LONG_PTR return values on 64-bit.
    This function is idempotent and safe to call multiple times.

    Args:
        user32: The ``ctypes.windll.user32`` module-like object to annotate.
    """
    wt = ctypes.wintypes

    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, POINTER(wt.DWORD)]
    user32.GetWindowThreadProcessId.restype = wt.DWORD

    user32.IsWindowVisible.argtypes = [wt.HWND]
    user32.IsWindowVisible.restype = wt.BOOL

    user32.GetWindow.argtypes = [wt.HWND, wt.UINT]
    user32.GetWindow.restype = wt.HWND

    user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int

    enum_proc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    user32.EnumWindows.argtypes = [enum_proc, wt.LPARAM]
    user32.EnumWindows.restype = wt.BOOL

    user32.SetParent.argtypes = [wt.HWND, wt.HWND]
    user32.SetParent.restype = wt.HWND

    user32.SetWindowLongPtrW.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_longlong]
    user32.SetWindowLongPtrW.restype = ctypes.c_longlong

    user32.GetWindowLongPtrW.argtypes = [wt.HWND, ctypes.c_int]
    user32.GetWindowLongPtrW.restype = ctypes.c_longlong


def _get_user32() -> ctypes.WinDLL | None:
    """Return the annotated user32 DLL handle, or None off-Windows.

    Returns:
        ctypes.WinDLL | None: Annotated ``ctypes.windll.user32`` handle,
            or None when running on a non-Windows platform or when
            ``ctypes.windll`` is unavailable for any reason.
    """
    if not _is_windows() or not hasattr(ctypes, "windll"):
        return None

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    _configure_user32(user32)
    return user32


def find_window_by_pid(pid: int) -> int | None:
    """Find the main visible window handle for a given process ID.

    Enumerates all top-level windows and returns the first visible,
    unowned window belonging to the specified process.

    Args:
        pid: Process ID to search for.

    Returns:
        int | None: Window handle (HWND) as int, or None if not found or not on Windows.
    """
    user32 = _get_user32()
    if user32 is None:
        return None

    result_hwnd: list[int] = []

    enum_func_type = ctypes.WINFUNCTYPE(
        ctypes.wintypes.BOOL,
        ctypes.wintypes.HWND,
        ctypes.wintypes.LPARAM,
    )

    def _enum_callback(hwnd: int, _lparam: int) -> bool:
        window_pid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
        if window_pid.value != pid:
            return True

        if not user32.IsWindowVisible(hwnd):
            return True

        owner_handle = user32.GetWindow(hwnd, _GW_OWNER)
        owner_int = int(owner_handle) if owner_handle else 0
        if owner_int != 0:
            return True

        title_buf = ctypes.create_unicode_buffer(_MAX_TITLE_LEN)
        user32.GetWindowTextW(hwnd, title_buf, _MAX_TITLE_LEN)
        if not title_buf.value:
            return True

        result_hwnd.append(int(hwnd))
        return False

    callback = enum_func_type(_enum_callback)
    user32.EnumWindows(callback, 0)

    if result_hwnd:
        _logger.debug(
            "win32_window_found",
            pid=pid,
            hwnd=hex(result_hwnd[0]),
        )
        return result_hwnd[0]

    return None


def _reparent_foreign_hwnd(user32: ctypes.WinDLL, hwnd: int, parent_hwnd: int) -> bool:
    """Coerce a top-level HWND into a child of the given parent HWND.

    Strips top-level-only style bits (caption, popup, thick frame,
    min/max/system buttons), sets WS_CHILD | WS_VISIBLE, and reparents
    the window using SetParent.  This is required before handing the
    HWND to QWindow.fromWinId so Qt can position it inside the container.

    Args:
        user32: Annotated ``ctypes.windll.user32`` handle.
        hwnd: Foreign window handle to reparent.
        parent_hwnd: Handle of the Qt container that should own the window.

    Returns:
        bool: True on success, False if any Win32 call reported failure.
    """
    current_style = int(user32.GetWindowLongPtrW(hwnd, _GWL_STYLE))
    if current_style == 0:
        return False

    stripped = current_style & ~(_WS_POPUP | _WS_CAPTION | _WS_THICKFRAME | _WS_MINIMIZEBOX | _WS_MAXIMIZEBOX | _WS_SYSMENU)
    new_style = stripped | _WS_CHILD | _WS_VISIBLE

    ctypes.set_last_error(0)
    user32.SetWindowLongPtrW(hwnd, _GWL_STYLE, new_style)
    style_err = ctypes.get_last_error()
    if style_err != 0:
        _logger.warning(
            "win32_setwindowlongptr_failed",
            hwnd=hex(hwnd),
            error=style_err,
        )
        return False

    ctypes.set_last_error(0)
    previous_parent = user32.SetParent(hwnd, parent_hwnd)
    parent_err = ctypes.get_last_error()
    if not previous_parent and parent_err != 0:
        _logger.warning(
            "win32_setparent_failed",
            hwnd=hex(hwnd),
            parent=hex(parent_hwnd),
            error=parent_err,
        )
        return False

    return True


def embed_window(hwnd: int, parent: QWidget) -> QWidget | None:
    """Embed an external window inside a Qt parent widget.

    Reparents the foreign HWND as a WS_CHILD of the Qt parent using
    SetWindowLongPtrW and SetParent, then wraps it with
    QWindow.fromWinId and QWidget.createWindowContainer so it renders
    as a normal child widget.

    Args:
        hwnd: Native window handle (HWND) to embed.
        parent: Qt parent widget that will contain the embedded window.

    Returns:
        QWidget | None: The container QWidget wrapping the embedded window, or None on failure.
    """
    if hwnd <= 0:
        _logger.warning("win32_embed_invalid_hwnd", hwnd=hex(hwnd) if hwnd else "0")
        return None

    user32 = _get_user32()
    if user32 is None:
        _logger.warning("win32_embed_unsupported_platform")
        return None

    try:
        parent_hwnd = int(parent.winId())
        if not _reparent_foreign_hwnd(user32, hwnd, parent_hwnd):
            return None

        foreign_window = QWindow.fromWinId(cast("voidptr", hwnd))
        if foreign_window is None:
            _logger.warning("win32_embed_from_winid_failed", hwnd=hex(hwnd))
            return None

        container = QWidget.createWindowContainer(foreign_window, parent)
        container.setMinimumSize(_EMBED_MIN_WIDTH, _EMBED_MIN_HEIGHT)

    except (RuntimeError, OSError, ValueError):
        _logger.exception("win32_embed_failed", hwnd=hex(hwnd))
        return None

    _logger.info(
        "win32_window_embedded",
        hwnd=hex(hwnd),
    )
    return container


def poll_and_embed(
    pid: int,
    parent: QWidget,
    callback: Callable[[QWidget], None],
    max_retries: int = 15,
    interval_ms: int = 500,
) -> None:
    """Poll for a window by PID and embed it when found.

    Starts a QTimer-based polling loop that searches for the main
    window of the given process.  Once found, embeds it and invokes
    the callback with the container widget.

    Args:
        pid: Process ID whose window to capture.
        parent: Qt parent widget for embedding.
        callback: Called with the container QWidget once embedding succeeds.
        max_retries: Maximum polling attempts before giving up.
        interval_ms: Milliseconds between polling attempts.
    """
    attempt_count = [0]

    def _try_embed() -> None:
        attempt_count[0] += 1
        hwnd = find_window_by_pid(pid)

        if hwnd is not None:
            container = embed_window(hwnd, parent)
            if container is not None:
                callback(container)
                return

        if attempt_count[0] < max_retries:
            QTimer.singleShot(interval_ms, _try_embed)
        else:
            _logger.warning(
                "win32_embed_polling_exhausted",
                pid=pid,
                attempts=attempt_count[0],
            )

    QTimer.singleShot(interval_ms, _try_embed)
