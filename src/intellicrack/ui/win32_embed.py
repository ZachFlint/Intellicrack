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
import threading
from ctypes import POINTER
from typing import TYPE_CHECKING, ClassVar, Final, cast

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QImage, QWindow
from PyQt6.QtWidgets import QWidget

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.sip import voidptr


_logger = get_logger(__name__)

_EMBED_MIN_WIDTH: Final[int] = 200
_EMBED_MIN_HEIGHT: Final[int] = 150

_PW_RENDERFULLCONTENT: Final[int] = 2
_BI_RGB: Final[int] = 0
_DIB_RGB_COLORS: Final[int] = 0
_CAPTURE_BYTES_PER_PIXEL: Final[int] = 4

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

    _logger.debug("win32_user32_configured")


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
    _logger.debug("win32_user32_loaded")
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
    _logger.debug("win32_find_window_by_pid_started", pid=pid)
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
        """Capture the first top-level window for ``pid`` during ``EnumWindows``.

        Continues enumeration for windows that fail the ownership, visibility,
        owner, or title checks, and stops once a matching hwnd is recorded.

        Args:
            hwnd: Window handle under inspection.
            _lparam: Unused application-defined EnumWindows parameter.

        Returns:
            bool: ``True`` to keep enumerating, ``False`` once a match is stored.
        """
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

    _logger.debug("win32_window_not_found", pid=pid)
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

    _logger.info("win32_reparent_foreign_hwnd_completed", hwnd=hex(hwnd), parent=hex(parent_hwnd))
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
        container = _reparent_and_wrap_hwnd(user32, hwnd, parent)
    except (RuntimeError, OSError, ValueError):
        _logger.exception("win32_embed_failed", hwnd=hex(hwnd))
        return None

    if container is None:
        return None

    _logger.info(
        "win32_window_embedded",
        hwnd=hex(hwnd),
    )
    return container


def _reparent_and_wrap_hwnd(user32: ctypes.WinDLL, hwnd: int, parent: QWidget) -> QWidget | None:
    """Reparent ``hwnd`` under ``parent`` and wrap it in a ``QWidget`` container.

    Args:
        user32: Loaded ``user32`` dynamic library handle from ``_get_user32``.
        hwnd: Native window handle to reparent.
        parent: Qt parent widget that will own the container.

    Returns:
        QWidget | None: The container QWidget on success, or ``None`` when
        reparenting fails or the foreign window cannot be wrapped.
    """
    parent_hwnd = int(parent.winId())
    if not _reparent_foreign_hwnd(user32, hwnd, parent_hwnd):
        return None

    foreign_window = QWindow.fromWinId(cast("voidptr", hwnd))
    if foreign_window is None:
        _logger.warning("win32_embed_from_winid_failed", hwnd=hex(hwnd))
        return None

    container = QWidget.createWindowContainer(foreign_window, parent)
    container.setMinimumSize(_EMBED_MIN_WIDTH, _EMBED_MIN_HEIGHT)
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
        """Attempt one embed poll and reschedule until success or exhaustion."""
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


class _BitmapInfoHeader(ctypes.Structure):
    """Win32 ``BITMAPINFOHEADER`` describing an uncompressed 32bpp top-down DIB.

    Used with ``GetDIBits`` to pull a captured window's pixels out of a GDI bitmap in a layout (``BGRX``, top-down rows) that matches
    :class:`PyQt6.QtGui.QImage`'s ``Format_RGB32`` directly, with no channel reordering or row-flipping required.
    """

    _fields_: ClassVar = [
        ("biSize", ctypes.wintypes.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", ctypes.wintypes.WORD),
        ("biBitCount", ctypes.wintypes.WORD),
        ("biCompression", ctypes.wintypes.DWORD),
        ("biSizeImage", ctypes.wintypes.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", ctypes.wintypes.DWORD),
        ("biClrImportant", ctypes.wintypes.DWORD),
    ]


class _CaptureBindings:
    """Lazily bound ``user32``/``gdi32`` entry points for window-content capture.

    x64dbg's debugger window is deliberately kept on a dedicated Win32
    desktop that is never made the input desktop (see
    :mod:`intellicrack.core.win32_desktop_process`), so its window can be
    found (:func:`intellicrack.ui.panels.x64dbg_panel.find_window_by_pid_on_desktop`)
    but can never be reparented into a Qt container: ``SetParent`` fails
    with ``ERROR_INVALID_PARAMETER`` whenever the child and new-parent
    windows belong to different desktops, which is confirmed empirically
    and is why :func:`embed_window` can never succeed for it. GDI capture
    operations such as ``PrintWindow`` are not restricted this way, so this
    class backs :func:`capture_window_image`, which mirrors the window's
    live rendered content instead of reparenting the real ``HWND``.
    """

    def __init__(self) -> None:
        """Load ``user32``/``gdi32`` and bind the entry points this capture needs."""
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        wt = ctypes.wintypes

        self.get_window_rect = user32.GetWindowRect
        self.get_window_rect.restype = wt.BOOL
        self.get_window_rect.argtypes = [wt.HWND, POINTER(wt.RECT)]

        self.get_dc = user32.GetDC
        self.get_dc.restype = wt.HDC
        self.get_dc.argtypes = [wt.HWND]

        self.release_dc = user32.ReleaseDC
        self.release_dc.restype = ctypes.c_int
        self.release_dc.argtypes = [wt.HWND, wt.HDC]

        self.print_window = user32.PrintWindow
        self.print_window.restype = wt.BOOL
        self.print_window.argtypes = [wt.HWND, wt.HDC, wt.UINT]

        self.create_compatible_dc = gdi32.CreateCompatibleDC
        self.create_compatible_dc.restype = wt.HDC
        self.create_compatible_dc.argtypes = [wt.HDC]

        self.create_compatible_bitmap = gdi32.CreateCompatibleBitmap
        self.create_compatible_bitmap.restype = wt.HBITMAP
        self.create_compatible_bitmap.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int]

        self.select_object = gdi32.SelectObject
        self.select_object.restype = wt.HGDIOBJ
        self.select_object.argtypes = [wt.HDC, wt.HGDIOBJ]

        self.delete_dc = gdi32.DeleteDC
        self.delete_dc.restype = wt.BOOL
        self.delete_dc.argtypes = [wt.HDC]

        self.delete_object = gdi32.DeleteObject
        self.delete_object.restype = wt.BOOL
        self.delete_object.argtypes = [wt.HGDIOBJ]

        self.get_dibits = gdi32.GetDIBits
        self.get_dibits.restype = ctypes.c_int
        self.get_dibits.argtypes = [
            wt.HDC,
            wt.HBITMAP,
            wt.UINT,
            wt.UINT,
            wt.LPVOID,
            POINTER(_BitmapInfoHeader),
            wt.UINT,
        ]


_capture_bindings_cache: list[_CaptureBindings] = []
_capture_bindings_lock = threading.Lock()


def _get_capture_bindings() -> _CaptureBindings | None:
    """Return the lazily-bound capture entry points, creating them on first use.

    Returns:
        _CaptureBindings | None: The cached bindings, or ``None`` when not
        running on Windows.
    """
    if not _is_windows() or not hasattr(ctypes, "windll"):
        return None
    if not _capture_bindings_cache:
        with _capture_bindings_lock:
            if not _capture_bindings_cache:
                _capture_bindings_cache.append(_CaptureBindings())
    return _capture_bindings_cache[0]


def capture_window_image(hwnd: int) -> QImage | None:
    """Capture a foreign window's current rendered contents as a ``QImage``.

    Renders ``hwnd`` into an off-screen GDI bitmap via ``PrintWindow`` with
    ``PW_RENDERFULLCONTENT`` and copies the pixels into a ``QImage``. Unlike
    :func:`embed_window`, this succeeds even when ``hwnd`` belongs to a
    Win32 desktop other than the calling thread's own current desktop -
    confirmed empirically against a real hidden-desktop child process,
    where ``SetParent`` fails with ``ERROR_INVALID_PARAMETER`` but
    ``PrintWindow`` renders correctly. This is how the x64dbg panel shows a
    live mirror of its debugger window's real content when the window
    itself cannot be embedded as a native child widget (S20-D01).

    Args:
        hwnd: Native window handle (HWND) to capture.

    Returns:
        QImage | None: A deep copy of the captured frame, or ``None`` when
        ``hwnd`` is invalid, the platform is unsupported, the window has
        no area, or any Win32/GDI call in the capture sequence fails.
    """
    if hwnd <= 0:
        return None

    api = _get_capture_bindings()
    if api is None:
        return None

    rect = ctypes.wintypes.RECT()
    if not api.get_window_rect(hwnd, ctypes.byref(rect)):
        _logger.debug("win32_capture_get_window_rect_failed", hwnd=hex(hwnd))
        return None

    width = int(rect.right - rect.left)
    height = int(rect.bottom - rect.top)
    if width <= 0 or height <= 0:
        return None

    screen_dc = api.get_dc(None)
    if not screen_dc:
        _logger.debug("win32_capture_get_screen_dc_failed", hwnd=hex(hwnd))
        return None

    try:
        return _capture_via_memory_dc(api, hwnd, screen_dc, width, height)
    finally:
        api.release_dc(None, screen_dc)


def _capture_via_memory_dc(
    api: _CaptureBindings,
    hwnd: int,
    screen_dc: int,
    width: int,
    height: int,
) -> QImage | None:
    """Render ``hwnd`` into a memory DC and extract the pixels as a ``QImage``.

    Args:
        api: Bound capture entry points from :func:`_get_capture_bindings`.
        hwnd: Native window handle to capture.
        screen_dc: Screen device context used as the compatibility
            reference for the memory DC and bitmap.
        width: Window width in pixels, from ``GetWindowRect``.
        height: Window height in pixels, from ``GetWindowRect``.

    Returns:
        QImage | None: The captured frame, or ``None`` if any step of the
        capture sequence fails.
    """
    mem_dc = api.create_compatible_dc(screen_dc)
    if not mem_dc:
        _logger.debug("win32_capture_create_compatible_dc_failed", hwnd=hex(hwnd))
        return None

    try:
        bitmap = api.create_compatible_bitmap(screen_dc, width, height)
        if not bitmap:
            _logger.debug("win32_capture_create_compatible_bitmap_failed", hwnd=hex(hwnd))
            return None

        try:
            old_object = api.select_object(mem_dc, bitmap)
            try:
                if not api.print_window(hwnd, mem_dc, _PW_RENDERFULLCONTENT):
                    _logger.debug("win32_capture_print_window_failed", hwnd=hex(hwnd))
                    return None
                return _read_bitmap_pixels(api, mem_dc, bitmap, width, height)
            finally:
                if old_object:
                    api.select_object(mem_dc, old_object)
        finally:
            api.delete_object(bitmap)
    finally:
        api.delete_dc(mem_dc)


def _read_bitmap_pixels(
    api: _CaptureBindings,
    mem_dc: int,
    bitmap: int,
    width: int,
    height: int,
) -> QImage | None:
    """Read a compatible bitmap's pixels into a top-down 32bpp ``QImage``.

    Args:
        api: Bound capture entry points from :func:`_get_capture_bindings`.
        mem_dc: Memory device context the bitmap is selected into.
        bitmap: Compatible bitmap already painted via ``PrintWindow``.
        width: Bitmap width in pixels.
        height: Bitmap height in pixels.

    Returns:
        QImage | None: A deep copy of the decoded frame, or ``None`` when
        ``GetDIBits`` reports no scanlines were copied.
    """
    header = _BitmapInfoHeader()
    header.biSize = ctypes.sizeof(_BitmapInfoHeader)
    header.biWidth = width
    header.biHeight = -height
    header.biPlanes = 1
    header.biBitCount = 32
    header.biCompression = _BI_RGB

    stride = width * _CAPTURE_BYTES_PER_PIXEL
    pixel_buffer = ctypes.create_string_buffer(stride * height)
    scanlines = api.get_dibits(
        mem_dc,
        bitmap,
        0,
        height,
        pixel_buffer,
        ctypes.byref(header),
        _DIB_RGB_COLORS,
    )
    if scanlines <= 0:
        _logger.debug("win32_capture_get_dibits_failed", width=width, height=height)
        return None

    image = QImage(
        bytes(pixel_buffer),
        width,
        height,
        stride,
        QImage.Format.Format_RGB32,
    )
    return image.copy()
