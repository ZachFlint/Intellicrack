# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""
Win32 window embedding utilities for Intellicrack.

Provides helpers for capturing external application windows by PID and embedding them inside Qt widgets using QWindow.fromWinId and
QWidget.createWindowContainer.  Windows-only; on other platforms all functions return None / no-op.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
from typing import TYPE_CHECKING, Any, Final

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QWindow
from PyQt6.QtWidgets import QWidget
from PyQt6.sip import voidptr

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable


_logger = get_logger("ui.win32_embed")

_EMBED_MIN_WIDTH: Final[int] = 200
_EMBED_MIN_HEIGHT: Final[int] = 150

_GW_OWNER: Final[int] = 4
_MAX_TITLE_LEN: Final[int] = 256


def find_window_by_pid(pid: int) -> int | None:
    """
    Find the main visible window handle for a given process ID.

    Enumerates all top-level windows and returns the first visible,
    unowned window belonging to the specified process.

    Args:
        pid: Process ID to search for.

    Returns:
        int | None: Window handle (HWND) as int, or None if not found or not on Windows.
    """
    if not hasattr(ctypes, "windll"):
        return None

    windll: Any = ctypes.windll
    user32: Any = windll.user32
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

        owner: int = user32.GetWindow(hwnd, _GW_OWNER)
        if owner != 0:
            return True

        title_buf = ctypes.create_unicode_buffer(_MAX_TITLE_LEN)
        user32.GetWindowTextW(hwnd, title_buf, _MAX_TITLE_LEN)
        if not title_buf.value:
            return True

        result_hwnd.append(hwnd)
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


def embed_window(hwnd: int, parent: QWidget) -> QWidget | None:
    """
    Embed an external window inside a Qt parent widget.

    Uses QWindow.fromWinId to wrap the native window handle and
    QWidget.createWindowContainer to embed it.

    Args:
        hwnd: Native window handle (HWND) to embed.
        parent: Qt parent widget that will contain the embedded window.

    Returns:
        QWidget | None: The container QWidget wrapping the embedded window, or None on failure.
    """
    try:
        foreign_window: Any = QWindow.fromWinId(voidptr(hwnd))
        if foreign_window is None:
            _logger.warning("win32_embed_from_winid_failed", hwnd=hex(hwnd))
            return None

        container: QWidget = QWidget.createWindowContainer(foreign_window, parent)
        container.setMinimumSize(_EMBED_MIN_WIDTH, _EMBED_MIN_HEIGHT)

    except Exception:
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
    """
    Poll for a window by PID and embed it when found.

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
