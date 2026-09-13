# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for S20-D01: the x64dbg embed tab must show a real window.

x64dbg is launched on a dedicated, never-visible Win32 desktop (see
``intellicrack.core.win32_desktop_process.spawn_on_hidden_desktop``). A prior
fix already taught the panel to *locate* that window via
``EnumDesktopWindows`` scoped to the correct ``HDESK``
(``intellicrack.ui.panels.x64dbg_panel._resolve_debugger_window_hwnd``,
covered by ``tests/ui/test_x64dbg_embed_finds_window_s13d04.py``), but
``_poll_embed_tick`` kept feeding the located handle to
``intellicrack.ui.win32_embed.embed_window``, which reparents via
``SetParent`` - an API that always fails with ``ERROR_INVALID_PARAMETER``
when the child and new-parent windows live on different Win32 desktops. So
even once the window was found, every embed attempt still failed, and the
poll ran out its retry budget and left the "x64dbg Window" tab on its empty
placeholder (S20-D01, re-confirmed live).

The fix: once ``_poll_embed_tick`` learns (via
``intellicrack.core.win32_desktop_process.get_desktop_handle_for_pid``) that
the debugger's window lives on a registered hidden desktop, it stops trying
to reparent the real ``HWND`` at all and instead starts a live mirror -
``_start_mirror_capture``/``_refresh_mirror_frame`` periodically render the
window's content via ``intellicrack.ui.win32_embed.capture_window_image``
(``PrintWindow``, which is not desktop-scoped) into a ``QLabel`` hosted in the
same embed tab. This module spawns a real, titled, visible top-level window
on a real hidden desktop (the same technique test_x64dbg_embed_finds_window_
s13d04.py uses, reproduced here as this file must not import from or modify
that other domain's test module) and drives the panel's real, un-mocked poll
and mirror-refresh methods against it.

Reverting ``_poll_embed_tick`` to unconditionally call ``embed_window``
(dropping the ``get_desktop_handle_for_pid`` branch) makes
``test_poll_embed_tick_starts_mirror_for_hidden_desktop_window`` fail: the
reparent attempt fails every tick (its result is asserted directly), so
``panel._mirror_label`` never gets created and the embed tab stays empty
exactly as in the original defect.
"""

from __future__ import annotations

import sys
import textwrap
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QImage, QPixmap
from PyQt6.QtWidgets import QLabel

from intellicrack.core.win32_desktop_process import spawn_on_hidden_desktop
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel
from intellicrack.ui.win32_embed import embed_window


if TYPE_CHECKING:
    from collections.abc import Iterator

    from PyQt6.QtWidgets import QApplication

    from intellicrack.core.win32_desktop_process import DesktopProcess

_POLL_TIMEOUT_SEC: float = 15.0
_POLL_INTERVAL_SEC: float = 0.15
_HELPER_WINDOW_TITLE: str = "IntellicrackS20X1TestWindow"
_CHILD_LIFETIME_SEC: int = 30
_SEED_PIXEL_ARGB: int = 0xFF112233
_INVALID_HWND: int = 0

_HELPER_SCRIPT: str = textwrap.dedent(
    f"""\
    import ctypes
    import sys
    import time
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPVOID,
    ]
    user32.SetWindowLongPtrW.restype = ctypes.c_longlong
    user32.SetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_longlong]
    user32.GetWindowLongPtrW.restype = ctypes.c_longlong
    user32.GetWindowLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]


    class _MSG(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("message", wintypes.UINT),
            ("wParam", wintypes.WPARAM),
            ("lParam", wintypes.LPARAM),
            ("time", wintypes.DWORD),
            ("pt_x", wintypes.LONG),
            ("pt_y", wintypes.LONG),
        ]


    user32.PeekMessageW.restype = wintypes.BOOL
    user32.PeekMessageW.argtypes = [
        ctypes.POINTER(_MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user32.TranslateMessage.argtypes = [ctypes.POINTER(_MSG)]
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(_MSG)]

    _WS_OVERLAPPEDWINDOW = 0x00CF0000
    _WS_VISIBLE = 0x10000000
    _GWL_STYLE = -16
    _PM_REMOVE = 1

    hwnd = user32.CreateWindowExW(
        0,
        "Static",
        {_HELPER_WINDOW_TITLE!r},
        _WS_OVERLAPPEDWINDOW,
        0, 0, 240, 180,
        None, None, None, None,
    )
    if not hwnd:
        sys.exit(1)

    # A window created on a desktop that has never been the input desktop
    # does not reliably keep WS_VISIBLE from CreateWindowExW's own style or a
    # later ShowWindow(SW_SHOWNORMAL) call; writing the style bit directly
    # with SetWindowLongPtrW (and never calling ShowWindow afterwards) is
    # what reliably sticks on this desktop kind.
    current_style = user32.GetWindowLongPtrW(hwnd, _GWL_STYLE)
    user32.SetWindowLongPtrW(hwnd, _GWL_STYLE, current_style | _WS_VISIBLE)
    if not bool(user32.IsWindowVisible(hwnd)):
        sys.exit(2)

    msg = _MSG()
    deadline = time.monotonic() + {_CHILD_LIFETIME_SEC}
    while time.monotonic() < deadline:
        while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, _PM_REMOVE):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        time.sleep(0.05)
    """,
)


@pytest.fixture
def spawned_window_process(tmp_path: Path) -> Iterator[DesktopProcess]:
    """Spawn a real Win32 window on a fresh hidden desktop for one test.

    Args:
        tmp_path: Pytest-provided per-test temporary directory used to host
            the helper script file.

    Yields:
        DesktopProcess: The spawned process, terminated with its handles
        closed on teardown.
    """
    script_path = tmp_path / "s20_x1_window_helper.py"
    script_path.write_text(_HELPER_SCRIPT, encoding="utf-8")

    process = spawn_on_hidden_desktop(Path(sys.executable), [str(script_path)])
    try:
        yield process
    finally:
        process.terminate()
        process.close()


@pytest.mark.host_native
@pytest.mark.skipif(sys.platform != "win32", reason="hidden-desktop window mirroring is Windows-only")
@pytest.mark.usefixtures("qapp")
def test_poll_embed_tick_starts_mirror_for_hidden_desktop_window(
    spawned_window_process: DesktopProcess,
    qapp: QApplication,
) -> None:
    """A window on a registered hidden desktop must be mirrored, not reparented.

    Drives ``X64DbgPanel._poll_embed_tick`` against a real window on a real
    hidden desktop until it resolves, then asserts the panel switched to the
    ``PrintWindow``-based mirror path: a live captured frame is showing, the
    window was never handed to ``embed_window`` for reparenting (``embedded_
    container`` stays ``None``), and the embed-poll timer stopped once the
    window was found rather than exhausting its retry budget.

    Args:
        spawned_window_process: Real Win32-window-owning child process on its
            own hidden desktop, from the module fixture.
        qapp: Session-scoped QApplication fixture.
    """
    pid = spawned_window_process.pid
    panel = X64DbgPanel()
    try:
        deadline = time.monotonic() + _POLL_TIMEOUT_SEC
        while panel._mirror_label is None and time.monotonic() < deadline:
            panel._poll_embed_tick(pid)
            qapp.processEvents()
            if panel._mirror_label is None:
                time.sleep(_POLL_INTERVAL_SEC)

        assert panel._mirror_hwnd is not None, "the panel never resolved the hidden-desktop debugger window"
        assert panel._mirror_hwnd > 0
        assert panel._mirror_label is not None, "the embed tab must show a live mirror once the window is found"
        assert panel.embedded_container is None, "a window on a hidden desktop must never be handed to embed_window for reparenting"
        assert panel._embed_timer is None, "the embed-poll timer must stop once the window is mirrored"
        assert panel._main_tabs.currentWidget() is panel.embed_host, "the panel must switch to the embed tab"

        qapp.processEvents()
        pixmap = panel._mirror_label.pixmap()
        assert pixmap is not None, "expected a real PrintWindow-captured frame"
        assert not pixmap.isNull(), "expected a real PrintWindow-captured frame"
        assert pixmap.width() > 0
        assert pixmap.height() > 0

        # Empirical premise the fix rests on: SetParent-based reparenting
        # genuinely cannot embed a window living on a different Win32
        # desktop, which is exactly why the mirror path exists at all.
        assert embed_window(panel._mirror_hwnd, panel.embed_host) is None, "embed_window unexpectedly reparented a window across desktops"
    finally:
        panel._stop_mirror_timer()
        panel._stop_embed_timer()
        panel.close()
        qapp.processEvents()


@pytest.mark.usefixtures("qapp")
def test_refresh_mirror_frame_preserves_last_frame_when_capture_fails(qapp: QApplication) -> None:
    """A failed capture must leave the previously rendered mirror frame alone.

    Seeds the mirror label with a known frame, points ``_mirror_hwnd`` at an
    handle ``capture_window_image`` always rejects immediately, and asserts
    the label's pixmap is unchanged - a transient ``PrintWindow`` failure
    must never blank the mirror.

    Args:
        qapp: Session-scoped QApplication fixture.
    """
    panel = X64DbgPanel()
    try:
        label = QLabel()
        seed_image = QImage(4, 4, QImage.Format.Format_RGB32)
        seed_image.fill(_SEED_PIXEL_ARGB)
        seed_pixmap = QPixmap.fromImage(seed_image)
        label.setPixmap(seed_pixmap)
        panel._mirror_label = label
        panel._mirror_hwnd = _INVALID_HWND

        panel._refresh_mirror_frame()

        current = label.pixmap()
        assert current is not None, "the seeded frame must not be cleared"
        assert current.toImage() == seed_pixmap.toImage(), "a failed capture must not alter the last good frame"
    finally:
        panel.close()
        qapp.processEvents()


@pytest.mark.usefixtures("qapp")
def test_refresh_mirror_frame_stops_timer_when_mirror_state_cleared(qapp: QApplication) -> None:
    """Refreshing after the mirror state is torn down must stop the timer.

    Reproduces the state left by ``_cleanup``/``_reset_debug_views`` (mirror
    hwnd and label cleared but a timer tick still in flight) and asserts the
    guard clause stops and discards the timer instead of leaving it running
    against cleared state.

    Args:
        qapp: Session-scoped QApplication fixture.
    """
    panel = X64DbgPanel()
    try:
        panel._mirror_hwnd = None
        panel._mirror_label = None
        timer = QTimer(panel)
        timer.setInterval(250)
        timer.start()
        panel._mirror_timer = timer

        panel._refresh_mirror_frame()

        assert panel._mirror_timer is None, "the mirror timer must be discarded once mirror state is cleared"
        assert not timer.isActive(), "the underlying QTimer must actually be stopped"
    finally:
        panel.close()
        qapp.processEvents()
