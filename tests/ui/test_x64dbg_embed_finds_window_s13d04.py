# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable gates for S13-D04: x64dbg embed must locate the debugger's real window.

x64dbg is launched on a dedicated, never-visible Win32 desktop (see
``intellicrack.core.win32_desktop_process.spawn_on_hidden_desktop``) so its
window never flashes on screen before Intellicrack can embed it. The x64dbg
panel's embed poll previously resolved the debugger window with
``intellicrack.ui.win32_embed.find_window_by_pid``, which enumerates via
``EnumWindows`` - an API that only ever sees windows belonging to the
*calling thread's own current desktop*. Because x64dbg's real window lives on
a different (hidden) desktop, that enumeration could never find it, so the
"x64dbg Window" sub-tab stayed stuck on the "No debugger process active"
placeholder even with a live, fully-connected debugging session.

The fix adds two pieces, both exercised directly here:

* ``intellicrack.core.win32_desktop_process.get_desktop_handle_for_pid`` - a
  registry, populated by ``spawn_on_hidden_desktop`` and cleared by
  ``DesktopProcess.close``, that lets a caller discover which ``HDESK`` a
  spawned child actually runs on.
* ``intellicrack.ui.panels.x64dbg_panel.find_window_by_pid_on_desktop`` - a
  window finder that enumerates via ``EnumDesktopWindows`` against an
  explicit desktop handle instead of the calling thread's own desktop, plus
  ``_resolve_debugger_window_hwnd``, which wires the two together (falling
  back to the legacy ``find_window_by_pid`` for processes not spawned by
  ``spawn_on_hidden_desktop``, e.g. an externally attached x64dbg instance).

Test strategy: rather than launching the real (large, slow-starting) x64dbg
binary, these tests spawn a tiny, self-contained Win32 GUI process - a
handful of raw ``ctypes`` calls that create one real, titled, visible
top-level window - via the exact same production ``spawn_on_hidden_desktop``
call x64dbg goes through. This reproduces the precise failure geometry (a
real window, in a real separate process, on a real hidden desktop that is
not the test process's own current desktop) without any dependency on
x64dbg being installed, and without the same-process ``GetWindowText``
cross-thread message-pump hazard a same-process/same-desktop QWidget fake
would introduce (per Win32 docs, ``GetWindowText`` dispatches ``WM_GETTEXT``
synchronously only for same-process windows, which can deadlock a caller on
a different thread than the window's own message pump; a separate child
process sidesteps this entirely because Windows returns its cached title
without dispatch for foreign-process windows).

Reverting ``find_window_by_pid_on_desktop`` to ignore its ``hdesk`` argument
(i.e. falling back to plain ``EnumWindows``-style, calling-thread-desktop-only
enumeration) makes
``test_desktop_scoped_finder_locates_window_plain_enum_windows_cannot`` fail
outright, because the assertion is that the *plain* enumerator
(``find_window_by_pid``, still imported unmodified from ``win32_embed``)
genuinely cannot see this window - proving desktop-scoping, not just a PID
match, is what makes the difference. Breaking the PID match (e.g. matching
the first window found on the desktop regardless of owning process) is
separately caught by
``test_desktop_scoped_finder_returns_none_for_mismatched_pid``.

Helper window lifecycle: measured directly against this repository's own
``spawn_on_hidden_desktop`` (not merely assumed - see
``get_desktop_handle_for_pid``/``find_window_by_pid_on_desktop`` above), a
window created on a desktop that has never been the input desktop does not
reliably end up with the ``WS_VISIBLE`` style bit applied - neither
requesting ``WS_VISIBLE`` in ``CreateWindowExW``'s own ``dwStyle``, nor a
later explicit ``ShowWindow(SW_SHOWNORMAL)`` call, was sufficient in
repeated measurement (``ShowWindow`` was observed to actively clear the bit
back off again on this desktop kind, even after it had briefly read as set).
Writing the style bit directly with ``SetWindowLongPtrW`` - and never
calling ``ShowWindow`` afterwards - is what reliably sticks (confirmed
repeatedly: ``IsWindowVisible`` reads ``True`` immediately and
``find_window_by_pid_on_desktop`` then finds the window right away), so the
helper below does exactly that instead of relying on ``ShowWindow`` or the
creation style alone. The helper also runs a real
``PeekMessage``/``DispatchMessage`` loop for its whole lifetime instead of a
bare ``time.sleep`` so it stays a live, message-pumping top-level window for
as long as the test needs it, and it self-terminates after a bounded
lifetime so a crashed test can never leave it orphaned.
"""

from __future__ import annotations

import sys
import textwrap
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.win32_desktop_process import (
    get_desktop_handle_for_pid,
    spawn_on_hidden_desktop,
)
from intellicrack.ui.panels.x64dbg_panel import (
    _resolve_debugger_window_hwnd,
    find_window_by_pid_on_desktop,
)
from intellicrack.ui.win32_embed import find_window_by_pid


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from intellicrack.core.win32_desktop_process import DesktopProcess

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="hidden-desktop window embedding is Windows-only")

_POLL_TIMEOUT_SEC: float = 10.0
_POLL_INTERVAL_SEC: float = 0.1
_HELPER_WINDOW_TITLE: str = "IntellicrackS13D04TestWindow"
_CHILD_LIFETIME_SEC: int = 30
_NEGATIVE_PROBE_ATTEMPTS: int = 5

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
        0, 0, 200, 200,
        None, None, None, None,
    )
    if not hwnd:
        sys.exit(1)

    # Measured directly against this repository's spawn_on_hidden_desktop: on
    # a desktop that has never been the input desktop, neither requesting
    # WS_VISIBLE in CreateWindowExW's own dwStyle nor a later ShowWindow(SW_
    # SHOWNORMAL) call reliably leaves the WS_VISIBLE bit set (ShowWindow was
    # observed to actively clear it back off on this desktop kind). Writing
    # the style bit directly with SetWindowLongPtrW - and never calling
    # ShowWindow afterwards - is what reliably sticks.
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


def _poll(probe: Callable[[], int | None]) -> int | None:
    """Poll ``probe`` until it returns a non-``None`` value or time runs out.

    Args:
        probe: Zero-argument callable returning a window handle or ``None``.

    Returns:
        int | None: The first non-``None`` result, or ``None`` if the poll
        window elapsed without one.
    """
    deadline = time.monotonic() + _POLL_TIMEOUT_SEC
    result: int | None = None
    while time.monotonic() < deadline:
        result = probe()
        if result is not None:
            return result
        time.sleep(_POLL_INTERVAL_SEC)
    return result


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
    script_path = tmp_path / "s13d04_window_helper.py"
    script_path.write_text(_HELPER_SCRIPT, encoding="utf-8")

    process = spawn_on_hidden_desktop(Path(sys.executable), [str(script_path)])
    try:
        yield process
    finally:
        process.terminate()
        process.close()


def test_desktop_scoped_finder_locates_window_plain_enum_windows_cannot(
    spawned_window_process: DesktopProcess,
) -> None:
    """The desktop-scoped finder must see a window that plain EnumWindows cannot.

    Asserts both halves of the real defect: ``find_window_by_pid_on_desktop``
    (fed the child's actual ``HDESK`` via ``get_desktop_handle_for_pid``)
    finds the real window, while the legacy ``find_window_by_pid`` -
    unmodified, still doing a plain ``EnumWindows`` against the test
    process's own current desktop - genuinely cannot, because the window
    lives on a different, hidden desktop. A regression that makes
    ``find_window_by_pid_on_desktop`` ignore its ``hdesk`` argument (and so
    behave like the legacy finder) fails the first assertion.

    Args:
        spawned_window_process: Real Win32-window-owning child process on its
            own hidden desktop, from the module fixture.
    """
    pid = spawned_window_process.pid

    hdesk = get_desktop_handle_for_pid(pid)
    assert hdesk is not None, "spawn_on_hidden_desktop must register the child's HDESK for embed lookup"

    hwnd = _poll(lambda: find_window_by_pid_on_desktop(hdesk, pid))
    assert hwnd is not None, "desktop-scoped finder failed to locate the real window on the hidden desktop"
    assert hwnd > 0

    assert find_window_by_pid(pid) is None, (
        "plain EnumWindows-based finder unexpectedly saw a window on a different desktop; "
        "the desktop-scoping fix is not actually being exercised by this test"
    )


def test_desktop_scoped_finder_returns_none_for_mismatched_pid(
    spawned_window_process: DesktopProcess,
) -> None:
    """The desktop-scoped finder must not match a window owned by a different PID.

    Guards against a regression that finds *any* top-level window on the
    target desktop rather than one actually owned by the requested PID - for
    example a finder that drops the ``GetWindowThreadProcessId`` filter.

    Args:
        spawned_window_process: Real Win32-window-owning child process on its
            own hidden desktop, from the module fixture.
    """
    pid = spawned_window_process.pid
    hdesk = get_desktop_handle_for_pid(pid)
    assert hdesk is not None

    real_hwnd = _poll(lambda: find_window_by_pid_on_desktop(hdesk, pid))
    assert real_hwnd is not None, "precondition failed: the real window must be locatable before the mismatch probe runs"

    for _ in range(_NEGATIVE_PROBE_ATTEMPTS):
        assert find_window_by_pid_on_desktop(hdesk, pid + 1) is None, (
            "finder matched a window on the desktop that does not belong to the requested PID"
        )


def test_resolve_debugger_window_hwnd_uses_registered_desktop(
    spawned_window_process: DesktopProcess,
) -> None:
    """The panel's production resolver must find the window via the pid->desktop registry.

    Exercises ``_resolve_debugger_window_hwnd``, the exact function
    ``_poll_embed_tick`` calls on every embed-poll tick, end to end: it must
    look up the child's registered hidden desktop and locate its window
    there, without needing the caller to pass a desktop handle explicitly.

    Args:
        spawned_window_process: Real Win32-window-owning child process on its
            own hidden desktop, from the module fixture.
    """
    pid = spawned_window_process.pid

    hwnd = _poll(lambda: _resolve_debugger_window_hwnd(pid))

    assert hwnd is not None, "the panel's production resolver failed to locate the debugger window on its hidden desktop"
    assert hwnd > 0


def test_get_desktop_handle_for_pid_cleared_after_close(
    spawned_window_process: DesktopProcess,
) -> None:
    """The pid->HDESK registry entry must be created on spawn and removed on close.

    A regression that never registers the handle breaks embedding outright
    (S13-D04 itself); a regression that never clears it on close leaks a
    stale desktop handle association across process lifetimes and could
    misdirect a later, unrelated PID's embed lookup.

    Args:
        spawned_window_process: Real Win32-window-owning child process on its
            own hidden desktop, from the module fixture.
    """
    pid = spawned_window_process.pid
    assert get_desktop_handle_for_pid(pid) is not None

    spawned_window_process.terminate()
    spawned_window_process.close()

    assert get_desktop_handle_for_pid(pid) is None
