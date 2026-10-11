# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the window capture, GDI cleanup and window lookup paths of ``intellicrack.ui.win32_embed``.

Every expectation comes from the Win32 documentation rather than from the code under test. Invalid handles make ``GetWindowRect``,
``CreateCompatibleDC``, ``PrintWindow`` and ``GetDIBits`` fail, which drives the product's failure branches deterministically. Real GDI
objects the tests create themselves (a memory device context and a monochrome bitmap painted with ``PatBlt``) drive the pixel decoding, and
the process GDI object count from ``GetGuiResources`` proves the product releases every device context and bitmap it creates. Window
lookup is compared against an independent ``EnumWindows`` pass written with its own ctypes prototypes. Nothing here creates, reparents,
restyles or closes a window; the container has no interactive desktop, so the lines that need a real foreign window are not exercised.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.wintypes
import os
from typing import TYPE_CHECKING, Any, NamedTuple

import pytest
from PyQt6 import sip
from PyQt6.QtGui import QImage
from PyQt6.QtWidgets import QWidget

from intellicrack.ui import win32_embed as win32_embed_mod
from intellicrack.ui.win32_embed import capture_window_image, embed_window, find_window_by_pid


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from PyQt6.QtWidgets import QApplication


_GARBAGE_HWND: int = 0xDEADBEEF
_HUGE_EXTENT: int = 0x7FFFFFFF
_GW_OWNER: int = 4
_TITLE_CAPACITY: int = 256
_GR_GDIOBJECTS: int = 0
_PATBLT_WHITENESS: int = 0x00FF0062
_PATBLT_BLACKNESS: int = 0x00000042
_BITMAP_WIDTH: int = 8
_BITMAP_HEIGHT: int = 4
_WHITE_ROWS: int = 2
_OPAQUE_WHITE: int = 0xFFFFFFFF
_OPAQUE_BLACK: int = 0xFF000000

_get_capture_bindings: Callable[[], Any] = getattr(win32_embed_mod, "_get_capture_bindings")
_capture_via_memory_dc: Callable[[Any, int, int, int, int], QImage | None] = getattr(win32_embed_mod, "_capture_via_memory_dc")
_read_bitmap_pixels: Callable[[Any, int, int, int, int], QImage | None] = getattr(win32_embed_mod, "_read_bitmap_pixels")
_capture_bindings_cache: list[Any] = getattr(win32_embed_mod, "_capture_bindings_cache")
_CaptureBindings: type = getattr(win32_embed_mod, "_CaptureBindings")
_BitmapInfoHeader: type[ctypes.Structure] = getattr(win32_embed_mod, "_BitmapInfoHeader")


class _TopLevelWindow(NamedTuple):
    """One top-level window as reported by the independent enumeration.

    Attributes:
        hwnd: Native window handle.
        pid: Identifier of the process that owns the window.
        visible: Whether ``IsWindowVisible`` reported the window as visible.
        owned: Whether ``GetWindow(GW_OWNER)`` returned a non-null owner.
        title: Window caption, read only for visible unowned windows.
    """

    hwnd: int
    pid: int
    visible: bool
    owned: bool
    title: str


class _Win32:
    """Independent ctypes bindings the tests use as an oracle for the product's Win32 calls.

    The bindings load their own ``WinDLL`` instances, so their prototypes never touch the ones the product declares.
    """

    def __init__(self) -> None:
        """Load ``user32``, ``gdi32`` and ``kernel32`` and declare the prototypes from the Windows SDK."""
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        wt = ctypes.wintypes

        self.enum_proc_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

        self.enum_windows = user32.EnumWindows
        self.enum_windows.restype = wt.BOOL
        self.enum_windows.argtypes = [self.enum_proc_type, wt.LPARAM]

        self.get_window_thread_process_id = user32.GetWindowThreadProcessId
        self.get_window_thread_process_id.restype = wt.DWORD
        self.get_window_thread_process_id.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]

        self.is_window_visible = user32.IsWindowVisible
        self.is_window_visible.restype = wt.BOOL
        self.is_window_visible.argtypes = [wt.HWND]

        self.get_window = user32.GetWindow
        self.get_window.restype = wt.HWND
        self.get_window.argtypes = [wt.HWND, wt.UINT]

        self.get_window_text = user32.GetWindowTextW
        self.get_window_text.restype = ctypes.c_int
        self.get_window_text.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]

        self.get_window_rect = user32.GetWindowRect
        self.get_window_rect.restype = wt.BOOL
        self.get_window_rect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]

        self.get_desktop_window = user32.GetDesktopWindow
        self.get_desktop_window.restype = wt.HWND
        self.get_desktop_window.argtypes = []

        self.get_gui_resources = user32.GetGuiResources
        self.get_gui_resources.restype = wt.DWORD
        self.get_gui_resources.argtypes = [wt.HANDLE, wt.DWORD]

        self.get_current_process = kernel32.GetCurrentProcess
        self.get_current_process.restype = wt.HANDLE
        self.get_current_process.argtypes = []

        self.create_compatible_dc = gdi32.CreateCompatibleDC
        self.create_compatible_dc.restype = wt.HDC
        self.create_compatible_dc.argtypes = [wt.HDC]

        self.create_bitmap = gdi32.CreateBitmap
        self.create_bitmap.restype = wt.HBITMAP
        self.create_bitmap.argtypes = [ctypes.c_int, ctypes.c_int, wt.UINT, wt.UINT, wt.LPVOID]

        self.select_object = gdi32.SelectObject
        self.select_object.restype = wt.HGDIOBJ
        self.select_object.argtypes = [wt.HDC, wt.HGDIOBJ]

        self.delete_object = gdi32.DeleteObject
        self.delete_object.restype = wt.BOOL
        self.delete_object.argtypes = [wt.HGDIOBJ]

        self.delete_dc = gdi32.DeleteDC
        self.delete_dc.restype = wt.BOOL
        self.delete_dc.argtypes = [wt.HDC]

        self.pat_blt = gdi32.PatBlt
        self.pat_blt.restype = wt.BOOL
        self.pat_blt.argtypes = [wt.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.DWORD]

    def gdi_object_count(self) -> int:
        """Return how many GDI objects the current process owns.

        Returns:
            int: The ``GR_GDIOBJECTS`` count from ``GetGuiResources`` for this process.
        """
        return int(self.get_gui_resources(self.get_current_process(), _GR_GDIOBJECTS))

    def window_extent(self, hwnd: int) -> tuple[int, int] | None:
        """Return the width and height ``GetWindowRect`` reports for a window.

        Args:
            hwnd: Native window handle to measure.

        Returns:
            tuple[int, int] | None: ``(width, height)`` in pixels, or ``None`` when the call fails.
        """
        rect = ctypes.wintypes.RECT()
        if not self.get_window_rect(hwnd, ctypes.byref(rect)):
            return None
        return int(rect.right - rect.left), int(rect.bottom - rect.top)

    def enumerate_top_level_windows(self) -> list[_TopLevelWindow]:
        """Enumerate every top-level window on the calling thread's desktop.

        Returns:
            list[_TopLevelWindow]: One entry per window in ``EnumWindows`` order.
        """
        handles: list[int] = []

        def _collect(hwnd: int, _lparam: int) -> bool:
            """Record one window handle and keep enumerating.

            Args:
                hwnd: Handle supplied by ``EnumWindows``.
                _lparam: Unused application-defined parameter.

            Returns:
                bool: Always ``True`` so that enumeration visits every window.
            """
            handles.append(hwnd)
            return True

        callback = self.enum_proc_type(_collect)
        self.enum_windows(callback, 0)

        windows: list[_TopLevelWindow] = []
        for hwnd in handles:
            pid = ctypes.wintypes.DWORD()
            self.get_window_thread_process_id(hwnd, ctypes.byref(pid))
            visible = bool(self.is_window_visible(hwnd))
            owned = bool(self.get_window(hwnd, _GW_OWNER))
            title = ""
            if visible and not owned:
                title_buf = ctypes.create_unicode_buffer(_TITLE_CAPACITY)
                self.get_window_text(hwnd, title_buf, _TITLE_CAPACITY)
                title = title_buf.value
            windows.append(_TopLevelWindow(hwnd=hwnd, pid=int(pid.value), visible=visible, owned=owned, title=title))
        return windows


@pytest.fixture(scope="module")
def win32() -> _Win32:
    """Provide the independent Win32 oracle bindings.

    Returns:
        _Win32: Bindings with their own prototypes for the calls the tests make.
    """
    return _Win32()


@pytest.fixture
def memory_dc(win32: _Win32) -> Generator[int]:
    """Provide a real memory device context and delete it afterwards.

    Args:
        win32: Independent Win32 oracle bindings.

    Yields:
        int: Handle of a memory device context compatible with the application's screen.
    """
    dc = win32.create_compatible_dc(None)
    assert dc, "CreateCompatibleDC(NULL) must produce a memory device context"
    try:
        yield int(dc)
    finally:
        win32.delete_dc(dc)


@contextlib.contextmanager
def _painted_bitmap(win32: _Win32, dc: int) -> Generator[int]:
    """Create a monochrome bitmap that is black below ``_WHITE_ROWS`` rows and white above.

    The bitmap is painted through ``PatBlt`` and deselected from ``dc`` before it is yielded, as ``GetDIBits`` requires, and it is deleted
    when the context exits.

    Args:
        win32: Independent Win32 oracle bindings.
        dc: Memory device context the bitmap is painted through.

    Yields:
        int: Handle of the painted ``_BITMAP_WIDTH`` by ``_BITMAP_HEIGHT`` bitmap.
    """
    bitmap = win32.create_bitmap(_BITMAP_WIDTH, _BITMAP_HEIGHT, 1, 1, None)
    assert bitmap, "CreateBitmap must produce a monochrome bitmap"
    try:
        previous = win32.select_object(dc, bitmap)
        assert win32.pat_blt(dc, 0, 0, _BITMAP_WIDTH, _BITMAP_HEIGHT, _PATBLT_BLACKNESS)
        assert win32.pat_blt(dc, 0, 0, _BITMAP_WIDTH, _WHITE_ROWS, _PATBLT_WHITENESS)
        win32.select_object(dc, previous)
        yield int(bitmap)
    finally:
        win32.delete_object(bitmap)


def test_gdi_object_count_tracks_a_bitmap_the_test_creates(win32: _Win32) -> None:
    """Prove the GDI object count used by the leak checks reacts to a real bitmap.

    Args:
        win32: Independent Win32 oracle bindings.
    """
    baseline = win32.gdi_object_count()
    bitmap = win32.create_bitmap(_BITMAP_WIDTH, _BITMAP_HEIGHT, 1, 1, None)
    assert bitmap
    try:
        assert win32.gdi_object_count() == baseline + 1
    finally:
        win32.delete_object(bitmap)
    assert win32.gdi_object_count() == baseline


def test_embed_window_returns_none_when_parent_widget_was_deleted(qapp: QApplication) -> None:
    """A deleted parent makes ``winId`` raise, and ``embed_window`` must report failure instead of propagating it.

    ``sip.delete`` destroys the C++ widget so ``parent.winId()`` raises ``RuntimeError``, one of the exception types ``embed_window`` is
    documented to translate into ``None``.

    Args:
        qapp: Session-scoped QApplication fixture.
    """
    parent = QWidget()
    sip.delete(parent)
    assert sip.isdeleted(parent)

    assert embed_window(_GARBAGE_HWND, parent) is None
    qapp.processEvents()


def test_capture_window_image_rejects_non_positive_handles() -> None:
    """Handles at or below zero are never valid window handles and must yield no image."""
    assert capture_window_image(0) is None
    assert capture_window_image(-1) is None


def test_capture_window_image_returns_none_for_invalid_window_handle(win32: _Win32) -> None:
    """``GetWindowRect`` fails for a handle that names no window, so no image can be captured.

    Args:
        win32: Independent Win32 oracle bindings.
    """
    assert win32.window_extent(_GARBAGE_HWND) is None

    before = win32.gdi_object_count()
    assert capture_window_image(_GARBAGE_HWND) is None
    assert win32.gdi_object_count() == before


def test_capture_bindings_are_built_once_and_cached() -> None:
    """The first call builds the bindings, and every later call returns that same object."""
    saved = list(_capture_bindings_cache)
    _capture_bindings_cache.clear()
    try:
        first = _get_capture_bindings()
        assert isinstance(first, _CaptureBindings)
        assert _capture_bindings_cache == [first]

        second = _get_capture_bindings()
        assert second is first
        assert len(_capture_bindings_cache) == 1
    finally:
        _capture_bindings_cache.clear()
        _capture_bindings_cache.extend(saved)


def test_capture_bindings_declare_the_documented_win32_prototypes() -> None:
    """Every bound entry point carries the argument and return types the Windows SDK documents.

    Handles are pointer sized (``c_void_p``), ``BOOL`` is a 32-bit ``long``, ``UINT`` is ``c_uint`` and ``ReleaseDC`` and ``GetDIBits``
    return ``int``. Without them ctypes would truncate a 64-bit handle to ``int``.
    """
    handle = ctypes.c_void_p
    rect_pointer = ctypes.POINTER(ctypes.wintypes.RECT)
    header_pointer = ctypes.POINTER(_BitmapInfoHeader)
    expected: dict[str, tuple[type, list[type]]] = {
        "get_window_rect": (ctypes.c_long, [handle, rect_pointer]),
        "get_dc": (handle, [handle]),
        "release_dc": (ctypes.c_int, [handle, handle]),
        "print_window": (ctypes.c_long, [handle, handle, ctypes.c_uint]),
        "create_compatible_dc": (handle, [handle]),
        "create_compatible_bitmap": (handle, [handle, ctypes.c_int, ctypes.c_int]),
        "select_object": (handle, [handle, handle]),
        "delete_dc": (ctypes.c_long, [handle]),
        "delete_object": (ctypes.c_long, [handle]),
        "get_dibits": (ctypes.c_int, [handle, handle, ctypes.c_uint, ctypes.c_uint, handle, header_pointer, ctypes.c_uint]),
    }

    api = _get_capture_bindings()

    for name, (restype, argtypes) in expected.items():
        function = getattr(api, name)
        assert function.restype is restype, name
        assert list(function.argtypes) == argtypes, name


def test_read_bitmap_pixels_decodes_a_painted_bitmap_top_down(win32: _Win32, memory_dc: int) -> None:
    """The decoded image has the bitmap's size and keeps its top rows on top.

    The bitmap is white in its first two rows and black in the rest. ``GetDIBits`` is asked for a negative-height (top-down) DIB, so the
    first scanline of the ``QImage`` is the first row of the bitmap; a bottom-up request would swap the white and black rows.

    Args:
        win32: Independent Win32 oracle bindings.
        memory_dc: Real memory device context the bitmap is painted through.
    """
    api = _get_capture_bindings()
    with _painted_bitmap(win32, memory_dc) as bitmap:
        image = _read_bitmap_pixels(api, memory_dc, bitmap, _BITMAP_WIDTH, _BITMAP_HEIGHT)

    assert image is not None
    assert not image.isNull()
    assert image.format() == QImage.Format.Format_RGB32
    assert (image.width(), image.height()) == (_BITMAP_WIDTH, _BITMAP_HEIGHT)
    for y in range(_BITMAP_HEIGHT):
        expected = _OPAQUE_WHITE if y < _WHITE_ROWS else _OPAQUE_BLACK
        for x in range(_BITMAP_WIDTH):
            assert image.pixel(x, y) == expected, (x, y)


def test_read_bitmap_pixels_returns_none_when_get_dibits_copies_nothing() -> None:
    """``GetDIBits`` returns zero for handles it does not know, which must produce no image."""
    api = _get_capture_bindings()

    assert _read_bitmap_pixels(api, _GARBAGE_HWND, _GARBAGE_HWND, _BITMAP_WIDTH, _BITMAP_HEIGHT) is None


def test_capture_via_memory_dc_returns_none_and_frees_gdi_objects_when_print_window_fails(win32: _Win32, memory_dc: int) -> None:
    """``PrintWindow`` fails for an invalid window, and the memory DC and bitmap created for it must be deleted.

    Args:
        win32: Independent Win32 oracle bindings.
        memory_dc: Real memory device context used as the compatibility reference.
    """
    api = _get_capture_bindings()
    before = win32.gdi_object_count()

    result = _capture_via_memory_dc(api, _GARBAGE_HWND, memory_dc, _BITMAP_WIDTH, _BITMAP_HEIGHT)

    assert result is None
    assert win32.gdi_object_count() == before


def test_capture_via_memory_dc_returns_none_when_reference_dc_is_invalid(win32: _Win32) -> None:
    """``CreateCompatibleDC`` fails for an invalid reference DC, so nothing can be captured and nothing leaks.

    Args:
        win32: Independent Win32 oracle bindings.
    """
    api = _get_capture_bindings()
    before = win32.gdi_object_count()

    result = _capture_via_memory_dc(api, _GARBAGE_HWND, _GARBAGE_HWND, _BITMAP_WIDTH, _BITMAP_HEIGHT)

    assert result is None
    assert win32.gdi_object_count() == before


def test_capture_via_memory_dc_returns_none_and_frees_dc_when_bitmap_cannot_be_created(win32: _Win32, memory_dc: int) -> None:
    """``CreateCompatibleBitmap`` cannot allocate an enormous bitmap, and the memory DC created before it must be deleted.

    Args:
        win32: Independent Win32 oracle bindings.
        memory_dc: Real memory device context used as the compatibility reference.
    """
    api = _get_capture_bindings()
    before = win32.gdi_object_count()

    result = _capture_via_memory_dc(api, _GARBAGE_HWND, memory_dc, _HUGE_EXTENT, _HUGE_EXTENT)

    assert result is None
    assert win32.gdi_object_count() == before


def test_capture_window_image_of_desktop_window_matches_its_rect_and_leaks_nothing(win32: _Win32) -> None:
    """Capturing the desktop window either fails cleanly or returns an image of exactly the window's rectangle.

    The desktop window always exists, and capturing only reads from it. Whether ``PrintWindow`` succeeds depends on the session, so the
    test checks the invariants that hold either way: a zero-area window yields no image, a returned image is a non-null ``Format_RGB32``
    frame of the size ``GetWindowRect`` reports, and the screen DC, memory DC and bitmap the capture opens are all released.

    Args:
        win32: Independent Win32 oracle bindings.
    """
    desktop = win32.get_desktop_window()
    assert desktop
    extent = win32.window_extent(int(desktop))
    assert extent is not None
    width, height = extent

    before = win32.gdi_object_count()
    image = capture_window_image(int(desktop))
    after = win32.gdi_object_count()

    assert after == before
    if width <= 0 or height <= 0:
        assert image is None
    elif image is not None:
        assert not image.isNull()
        assert image.format() == QImage.Format.Format_RGB32
        assert (image.width(), image.height()) == (width, height)


def test_find_window_by_pid_agrees_with_independent_enumeration(win32: _Win32) -> None:
    """For every process that owns a top-level window the lookup returns a visible, unowned, titled window or nothing.

    The expected answer comes from a separate ``EnumWindows`` pass with its own prototypes: a process with at least one visible, unowned
    window that has a caption must resolve to one of those windows, and any other process must resolve to ``None``.

    Args:
        win32: Independent Win32 oracle bindings.
    """
    windows = win32.enumerate_top_level_windows()
    qualifying: dict[int, set[int]] = {}
    for window in windows:
        if window.visible and not window.owned and window.title:
            qualifying.setdefault(window.pid, set()).add(window.hwnd)

    pids = {window.pid for window in windows} | {os.getpid()}
    for pid in sorted(pids):
        found = find_window_by_pid(pid)
        if pid in qualifying:
            assert found in qualifying[pid], pid
        else:
            assert found is None, pid
