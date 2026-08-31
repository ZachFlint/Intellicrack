# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Showing the editor in an embedded WebView2 window.

The external browser shell in :mod:`hexbench.shell` needs a Chromium browser
installed and, because it is started through ``ShellExecuteW``, tells this
process nothing about the window afterwards. An embedded window removes both
problems: it renders through the WebView2 runtime that ships with Windows, and
closing it returns control here, which is a definite end-of-session signal
rather than an inferred one.

Two facts govern how this is wired into the entry point. The toolkit's event
loop must own the main thread, so the HTTP server runs on a worker thread and
this call blocks until the window closes. And the window is created in private
mode, so the WebView2 runtime keeps no profile, cache or local storage on disk
between sessions -- an editor that opens arbitrary binaries should leave nothing
of them behind.

The toolkit is reached through :class:`Webview` rather than imported directly.
Its ``create_window`` is annotated ``url: str | callable | None``, naming the
builtin *function* ``callable`` where the ``Callable`` type was meant, so a type
checker cannot resolve the signature and every call site inherits the unknown.
Declaring the two functions this module actually uses fixes that at the boundary
instead of at each call, and states the dependency as a surface narrow enough to
verify: ``tests/test_window.py`` binds this declaration against the installed
toolkit, so a drift between them fails a gate rather than a window open.
"""

from __future__ import annotations

import ctypes
import importlib
from ctypes import wintypes
from typing import TYPE_CHECKING, Final, Protocol, cast


if TYPE_CHECKING:
    from collections.abc import Callable


__all__ = [
    "DEFAULT_HEIGHT",
    "DEFAULT_TITLE",
    "DEFAULT_WIDTH",
    "MINIMUM_HEIGHT",
    "MINIMUM_WIDTH",
    "TOOLKIT_MODULE",
    "Webview",
    "WebviewWindow",
    "desktop_size",
    "fit_to_desktop",
    "load_toolkit",
    "run_window",
]

TOOLKIT_MODULE: Final = "webview"

DEFAULT_TITLE: Final = "Hexbench"
DEFAULT_WIDTH: Final = 1700
DEFAULT_HEIGHT: Final = 1050

MINIMUM_WIDTH: Final = 960
MINIMUM_HEIGHT: Final = 600

_USER_LIBRARY: Final = "user32"
_SPI_GETWORKAREA: Final = 0x0030
_REFERENCE_DPI: Final = 96
_DESKTOP_MARGIN: Final = 40


class WebviewWindow(Protocol):
    """The part of a created window's surface this editor relies on."""

    def destroy(self) -> None:
        """Close this window, letting the toolkit's event loop return.

        Called from the shutdown route's thread rather than the thread running
        the event loop, because the request that asks the session to end is
        served on a worker while the main thread is blocked inside
        :meth:`Webview.start`.
        """
        ...


class Webview(Protocol):
    """The part of the toolkit's module surface this editor relies on."""

    def create_window(
        self,
        title: str,
        *,
        url: str,
        width: int,
        height: int,
        min_size: tuple[int, int],
        text_select: bool,
    ) -> WebviewWindow | None:
        """Describe a window to be opened once the event loop starts.

        Args:
            title: Text shown in the window's title bar.
            url: Address to load.
            width: Initial width of the window in pixels.
            height: Initial height of the window in pixels.
            min_size: Smallest width and height the window can be resized to.
            text_select: Whether text in the page can be selected with the mouse.

        Returns:
            WebviewWindow | None: The toolkit's handle on the window, which the
            entry point keeps so the session can be ended from the page as well
            as by closing the window, or ``None`` if the toolkit declined to
            describe one.
        """
        ...

    def start(self, *, private_mode: bool) -> None:
        """Run the event loop until every window has been closed.

        Args:
            private_mode: Whether the renderer should keep no profile, cache or
                local storage on disk.
        """
        ...


def load_toolkit() -> Webview:
    """Import the window toolkit.

    Importing here rather than at module scope keeps the modes that open no
    window -- printing the address, or handing the session to an external
    browser -- working on a machine where the toolkit is not installed.

    Returns:
        Webview: The imported module, seen through the narrow surface this
        editor uses.
    """
    return cast("Webview", importlib.import_module(TOOLKIT_MODULE))


def desktop_size() -> tuple[int, int] | None:
    """Measure the desktop area a window can occupy, in the toolkit's units.

    The toolkit sizes windows in device-independent pixels, which on a scaled
    display are not what the desktop measures: a 175% display reports a work
    area of 2560x1356 real pixels but will only seat a 1463x775 window. The
    division by the reported scale reconciles the two, and is correct however
    the process was started, because Windows answers both calls consistently --
    a process that has not declared itself scaling-aware is told 96 dots per
    inch and given a work area already reduced to match.

    Returns:
        tuple[int, int] | None: The usable width and height, or ``None`` if this
        is not Windows or the desktop declined to say.
    """
    try:
        user32 = ctypes.WinDLL(_USER_LIBRARY, use_last_error=True)
    except (OSError, AttributeError):
        return None
    area = wintypes.RECT()
    if not user32.SystemParametersInfoW(_SPI_GETWORKAREA, 0, ctypes.byref(area), 0):
        return None
    scale = user32.GetDpiForSystem() / _REFERENCE_DPI
    if scale <= 0:
        return None
    return int((area.right - area.left) / scale), int((area.bottom - area.top) / scale)


def fit_to_desktop(width: int, height: int, available: tuple[int, int] | None) -> tuple[int, int]:
    """Shrink a window size until it fits the desktop it has to open on.

    The preferred size suits a large display and overflows a small one, where a
    window taller than the desktop puts the status bar under the taskbar and one
    wider than it pushes the docked panels off the side. The minimum is the
    floor: below it the layout is broken anyway, so a desktop smaller than that
    gets a window it can scroll rather than one that is unusable.

    Args:
        width: Preferred width in device-independent pixels.
        height: Preferred height in device-independent pixels.
        available: Usable desktop size, or ``None`` if it could not be measured,
            in which case the preferred size is kept.

    Returns:
        tuple[int, int]: The width and height to open with.
    """
    if available is None:
        return width, height
    usable_width, usable_height = available
    fitted_width = min(width, max(usable_width - _DESKTOP_MARGIN, MINIMUM_WIDTH))
    fitted_height = min(height, max(usable_height - _DESKTOP_MARGIN, MINIMUM_HEIGHT))
    return fitted_width, fitted_height


def run_window(
    url: str,
    *,
    title: str = DEFAULT_TITLE,
    width: int = DEFAULT_WIDTH,
    height: int = DEFAULT_HEIGHT,
    on_ready: Callable[[WebviewWindow], None] | None = None,
) -> None:
    """Open the editor in an embedded window and block until it is closed.

    The minimum size is set because the editor's three-pane layout stops being
    usable below it: the offset gutter, hex pane and ASCII pane cannot all fit,
    and the docked panels collapse over the editor rather than beside it.

    Args:
        url: Address to open, including the session token.
        title: Text shown in the window's title bar.
        width: Preferred width of the window, reduced to fit the desktop.
        height: Preferred height of the window, reduced to fit the desktop.
        on_ready: Handed the created window before the event loop starts, so a
            caller can end the session from the page. Closing the window is the
            only other way out of this call, and a page that has asked the
            server to stop cannot close a window it did not itself open.
    """
    toolkit = load_toolkit()
    fitted_width, fitted_height = fit_to_desktop(width, height, desktop_size())
    window = toolkit.create_window(
        title,
        url=url,
        width=fitted_width,
        height=fitted_height,
        min_size=(MINIMUM_WIDTH, MINIMUM_HEIGHT),
        text_select=True,
    )
    if on_ready is not None and window is not None:
        on_ready(window)
    toolkit.start(private_mode=True)
