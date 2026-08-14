# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Checking the embedded window against the toolkit actually installed.

:mod:`hexbench.window` declares the two toolkit functions it calls instead of
importing their real signatures, because those signatures do not type-check.
That declaration is only worth anything if something proves it still describes
the installed toolkit, which is what these tests do: they take the parameters
out of the declaration and bind them to the real functions. A renamed keyword, a
removed one or a typo on either side fails here rather than at the moment a user
asks for a window.

Nothing here opens a window. Starting the event loop would block until a human
closed it, so the boundary is checked instead of crossed.
"""

from __future__ import annotations

import contextlib
import importlib
import inspect
import io
import unittest
import unittest.mock
from typing import TYPE_CHECKING, Final

from hexbench import window as window_module
from hexbench.__main__ import SHELL_BROWSER, SHELL_NONE, SHELL_WINDOW, ServerStop, build_argument_parser, resolve_shell
from hexbench.tests._support import Assertions
from hexbench.window import (
    DEFAULT_HEIGHT,
    DEFAULT_TITLE,
    DEFAULT_WIDTH,
    MINIMUM_HEIGHT,
    MINIMUM_WIDTH,
    TOOLKIT_MODULE,
    Webview,
    WebviewWindow,
    desktop_size,
    fit_to_desktop,
    load_toolkit,
    run_window,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_SELF: Final = "self"
_TITLE: Final = "title"
_USAGE_ERROR: Final = 2

_ROOMY_DESKTOP: Final = (2000, 1400)
_CRAMPED_DESKTOP: Final = (1463, 775)
_TINY_DESKTOP: Final = (320, 240)
_PLACEHOLDERS: Final[dict[str, object]] = {
    _TITLE: "hexbench",
    "url": "http://127.0.0.1:1/#token",
    "width": 1280,
    "height": 800,
    "min_size": (640, 480),
    "text_select": True,
    "private_mode": True,
}


def _declared_arguments(declaration: Callable[..., object]) -> dict[str, object]:
    """Build a call for every parameter the facade declares.

    The parameter names are read out of the declaration rather than written
    here, so this cannot silently keep testing a keyword the facade has dropped.

    Args:
        declaration: A method of :class:`hexbench.window.Webview`.

    Returns:
        dict[str, object]: A value for each declared parameter, keyed by name.
    """
    return {name: _PLACEHOLDERS[name] for name in inspect.signature(declaration).parameters if name != _SELF}


def _resolve(argv: list[str]) -> str:
    """Resolve the shell mode the way :func:`main` does.

    Args:
        argv: Command line arguments to parse.

    Returns:
        str: The resolved mode.
    """
    parser = build_argument_parser()
    arguments = parser.parse_args(argv)
    browser: Path | None = arguments.browser
    return resolve_shell(parser, arguments.shell, browser)


def _refusal(argv: list[str]) -> tuple[object, str]:
    """Resolve a command line that should be refused, and report the refusal.

    ``argparse`` refuses by raising :class:`SystemExit`, which is not an
    :class:`Exception` and so cannot go through the suite's ``raises`` helper.
    The complaint is captured too, because an exit status alone would not say
    whether the parser refused for the reason under test.

    Args:
        argv: Command line arguments to parse.

    Returns:
        tuple[object, str]: The exit status, and what was written to stderr; the
        status is ``None`` if the command line was accepted after all.
    """
    complaint = io.StringIO()
    status: object = None
    with contextlib.redirect_stderr(complaint):
        try:
            _resolve(argv)
        except SystemExit as exit_request:
            status = exit_request.code
    return status, complaint.getvalue()


class ToolkitFacadeTests(Assertions, unittest.TestCase):
    """The declared toolkit surface matches the installed toolkit."""

    def test_toolkit_imports(self) -> None:
        """The named module is importable and is the module it claims to be."""
        toolkit = load_toolkit()
        self.equal(getattr(toolkit, "__name__", None), TOOLKIT_MODULE, "the imported toolkit")

    def test_declares_something_to_check(self) -> None:
        """Both calls carry parameters, so the binding checks below can fail."""
        for declaration in (Webview.create_window, Webview.start):
            with self.subTest(call=declaration.__name__):
                self.require(
                    _declared_arguments(declaration),
                    f"{declaration.__name__} declares no parameters, so binding it against the toolkit proves nothing",
                )

    def test_create_window_accepts_the_declared_call(self) -> None:
        """Every parameter the facade declares is one the toolkit accepts."""
        arguments = _declared_arguments(Webview.create_window)
        title = arguments.pop(_TITLE)
        signature = inspect.signature(load_toolkit().create_window)
        bound = signature.bind(title, **arguments)
        self.equal(bound.arguments[_TITLE], title, "the title the toolkit would receive")

    def test_start_accepts_the_declared_call(self) -> None:
        """Private mode is still how the toolkit is told to persist nothing."""
        arguments = _declared_arguments(Webview.start)
        bound = inspect.signature(load_toolkit().start).bind(**arguments)
        self.require_same(dict(bound.arguments), arguments, "the arguments the toolkit would receive from start")

    def test_declared_names_are_keywords_on_the_toolkit(self) -> None:
        """The facade passes by keyword, so the toolkit must accept keywords.

        Binding alone would still pass if the toolkit had made a parameter
        positional-only, because the facade supplies them in declaration order.
        """
        declared = set(_declared_arguments(Webview.create_window)) - {_TITLE}
        parameters = inspect.signature(load_toolkit().create_window).parameters
        positional = sorted(name for name in declared if parameters[name].kind == inspect.Parameter.POSITIONAL_ONLY)
        self.require_same(positional, [], "these parameters became positional-only, so the facade cannot name them")

    def test_window_defaults_clear_the_minimum(self) -> None:
        """The window opens larger than the size the layout stops working at."""
        signature = inspect.signature(run_window)
        self.equal(signature.parameters[_TITLE].default, DEFAULT_TITLE, "the default window title")
        self.equal(signature.parameters["width"].default, DEFAULT_WIDTH, "the default window width")
        self.equal(signature.parameters["height"].default, DEFAULT_HEIGHT, "the default window height")
        minimum = inspect.getsource(run_window)
        self.require("min_size" in minimum, "run_window no longer gives the window a minimum size")
        self.exceeds(DEFAULT_WIDTH, DEFAULT_HEIGHT, "the window opens wider than it is tall, as the layout needs")


class DesktopFitTests(Assertions, unittest.TestCase):
    """The window is reduced to a size the desktop can actually seat."""

    def test_the_desktop_can_be_measured(self) -> None:
        """This machine reports a usable desktop, so the fitting has an input."""
        measured = desktop_size()
        self.unequal(measured, None, "the measured desktop size on this machine")
        if measured is not None:
            width, height = measured
            self.exceeds(width, MINIMUM_WIDTH - 1, "the measured desktop width")
            self.exceeds(height, 0, "the measured desktop height")

    def test_a_size_that_fits_is_left_alone(self) -> None:
        """A window smaller than the desktop is not shrunk for no reason."""
        self.require_same(fit_to_desktop(1000, 700, _ROOMY_DESKTOP), (1000, 700), "a window that already fits")

    def test_an_oversized_window_is_brought_within_the_desktop(self) -> None:
        """Both dimensions are reduced below a desktop smaller than the request.

        The desktop used here is the one this machine actually reports, which is
        what the preferred size overflowed before the fitting existed.
        """
        usable_width, usable_height = _CRAMPED_DESKTOP
        width, height = fit_to_desktop(DEFAULT_WIDTH, DEFAULT_HEIGHT, _CRAMPED_DESKTOP)
        self.require(width < DEFAULT_WIDTH, f"width {width} was not reduced for a {usable_width} point desktop")
        self.require(height < DEFAULT_HEIGHT, f"height {height} was not reduced for a {usable_height} point desktop")
        self.require(width <= usable_width, f"width {width} still overflows a {usable_width} point desktop")
        self.require(height <= usable_height, f"height {height} still overflows a {usable_height} point desktop")

    def test_the_layout_floor_is_never_breached(self) -> None:
        """A desktop below the usable minimum still gets a usable window."""
        width, height = fit_to_desktop(DEFAULT_WIDTH, DEFAULT_HEIGHT, _TINY_DESKTOP)
        self.equal(width, MINIMUM_WIDTH, "the width on a desktop below the layout floor")
        self.equal(height, MINIMUM_HEIGHT, "the height on a desktop below the layout floor")

    def test_an_unmeasurable_desktop_keeps_the_preference(self) -> None:
        """A desktop that cannot be measured is not treated as a tiny one."""
        self.require_same(fit_to_desktop(DEFAULT_WIDTH, DEFAULT_HEIGHT, None), (DEFAULT_WIDTH, DEFAULT_HEIGHT), "an unmeasurable desktop")

    def test_the_default_fits_this_machine(self) -> None:
        """What this machine would actually open sits inside its own desktop."""
        measured = desktop_size()
        self.unequal(measured, None, "the desktop this gate has to measure against")
        usable_width, usable_height = measured if measured is not None else _TINY_DESKTOP
        width, height = fit_to_desktop(DEFAULT_WIDTH, DEFAULT_HEIGHT, (usable_width, usable_height))
        self.require(width <= usable_width, f"the window would open {width} wide on a {usable_width} point desktop")
        self.require(height <= usable_height, f"the window would open {height} tall on a {usable_height} point desktop")


class ShellSelectionTests(Assertions, unittest.TestCase):
    """The command line picks the way the session is shown."""

    def test_embedded_window_is_the_default(self) -> None:
        """An unqualified session opens the embedded window."""
        self.equal(_resolve([]), SHELL_WINDOW, "the mode an unqualified session runs in")

    def test_each_mode_can_be_asked_for(self) -> None:
        """Every mode the parser offers resolves to itself."""
        for mode in (SHELL_WINDOW, SHELL_BROWSER, SHELL_NONE):
            with self.subTest(mode=mode):
                self.equal(_resolve(["--shell", mode]), mode, f"the mode --shell {mode} selects")

    def test_naming_a_browser_selects_the_browser(self) -> None:
        """Naming an executable is enough to ask for an external browser."""
        self.equal(_resolve(["--browser", "C:/brave.exe"]), SHELL_BROWSER, "the mode a browser path selects")

    def test_naming_a_browser_for_another_mode_is_refused(self) -> None:
        """A browser path that cannot be used is reported, not ignored."""
        for mode in (SHELL_WINDOW, SHELL_NONE):
            with self.subTest(mode=mode):
                status, complaint = _refusal(["--shell", mode, "--browser", "C:/brave.exe"])
                self.equal(status, _USAGE_ERROR, f"the exit status for --browser with --shell {mode}")
                self.contains("--browser", complaint, "the complaint about an unusable browser path")

    def test_an_unknown_mode_is_refused(self) -> None:
        """The parser rejects a mode the entry point cannot act on."""
        status, complaint = _refusal(["--shell", "kiosk"])
        self.equal(status, _USAGE_ERROR, "the exit status for an unsupported --shell value")
        self.contains("--shell", complaint, "the complaint about an unsupported mode")


class _RecordingWindow:
    """A stand-in for the toolkit's window that records whether it was closed."""

    def __init__(self) -> None:
        """Create a window that has not been closed yet."""
        self.destroyed = False

    def destroy(self) -> None:
        """Record that the window was asked to close."""
        self.destroyed = True


class _RecordingToolkit:
    """A stand-in for the toolkit module that records the order of its calls."""

    def __init__(self, window: WebviewWindow | None) -> None:
        """Create a toolkit that hands out one window.

        Args:
            window: The window ``create_window`` should return, or ``None`` to
                model a toolkit that declines to describe one.
        """
        self.window = window
        self.events: list[str] = []

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
        """Record the call and hand back the configured window.

        Args:
            title: Ignored; recorded only as part of the call.
            url: Ignored; recorded only as part of the call.
            width: Ignored; recorded only as part of the call.
            height: Ignored; recorded only as part of the call.
            min_size: Ignored; recorded only as part of the call.
            text_select: Ignored; recorded only as part of the call.

        Returns:
            WebviewWindow | None: The window this toolkit was built with.
        """
        del title, url, width, height, min_size, text_select
        self.events.append("create")
        return self.window

    def start(self, *, private_mode: bool) -> None:
        """Record that the event loop was entered.

        Args:
            private_mode: Ignored; recorded only as part of the call.
        """
        del private_mode
        self.events.append("start")


class WindowCloseTests(Assertions, unittest.TestCase):
    """Ending the session from the page must close the window, not just the server."""

    def test_the_declared_close_binds_to_the_installed_window(self) -> None:
        """The facade's ``destroy`` must still describe the installed toolkit's window."""
        window_type = importlib.import_module(TOOLKIT_MODULE).Window
        declared = set(_declared_arguments(WebviewWindow.destroy))
        parameters = inspect.signature(window_type.destroy).parameters
        required = {
            name
            for name, parameter in parameters.items()
            if name != _SELF
            and parameter.default is inspect.Parameter.empty
            and parameter.kind not in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
        }
        self.require_same(required, declared, "arguments the installed window's destroy requires")

    def test_run_window_hands_the_window_over_before_the_loop_starts(self) -> None:
        """The window must reach the caller while the loop can still be interrupted."""
        window = _RecordingWindow()
        toolkit = _RecordingToolkit(window)
        seen: list[WebviewWindow] = []

        def _remember(handed: WebviewWindow) -> None:
            toolkit.events.append("handover")
            seen.append(handed)

        with unittest.mock.patch.object(window_module, "load_toolkit", return_value=toolkit):
            run_window("http://127.0.0.1:1/#token", on_ready=_remember)

        self.require_same(toolkit.events, ["create", "handover", "start"], "the order run_window did its work in")
        self.equal(len(seen), 1, "the number of windows handed to the caller")
        self.require(seen[0] is window, "the caller was handed the window the toolkit created")

    def test_a_toolkit_that_describes_no_window_is_survived(self) -> None:
        """A toolkit that returns no window must still start, without a crash."""
        toolkit = _RecordingToolkit(None)
        handed: list[WebviewWindow] = []

        with unittest.mock.patch.object(window_module, "load_toolkit", return_value=toolkit):
            run_window("http://127.0.0.1:1/#token", on_ready=handed.append)

        self.require_same(toolkit.events, ["create", "start"], "the order run_window did its work in")
        self.equal(len(handed), 0, "the number of windows handed over when the toolkit described none")

    def test_ending_the_session_closes_the_attached_window(self) -> None:
        """A stopper that owns a window must close it, or the window outlives its backend."""
        window = _RecordingWindow()
        stopper = ServerStop()
        stopper.attach_window(window)

        self.falsy(window.destroyed, "the window before the session was ended")
        stopper()
        self.truthy(window.destroyed, "the window after the session was ended from the page")

    def test_a_session_with_no_window_still_stops_cleanly(self) -> None:
        """The browser and address-only shells attach no window and must not fail."""
        stopper = ServerStop()
        stopper()

        window = _RecordingWindow()
        stopper.attach_window(window)
        stopper()
        self.truthy(window.destroyed, "a window attached after an earlier windowless stop")


if __name__ == "__main__":
    unittest.main()
