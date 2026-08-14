# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Opening the editor in a chromeless browser window.

A Chromium browser started with ``--app`` gives a window with no tab strip, no
address bar and no browser menu, which is the difference between hexbench
looking like a program and looking like a web page. It is launched through
``ShellExecuteW`` rather than as a child process, which keeps this package free
of process-spawning machinery at the cost of learning nothing about the window
afterwards; that is why the entry point watches for silence instead of waiting
on a process handle.

The profile lives under the temporary directory and never inside the package.
Chromium writes tens of megabytes of cache and databases into a profile, and it
also keeps a lock there, so putting one inside an installed package would both
soil the installation and make two sessions fight over it.
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import Final


__all__ = ["announce", "find_browser", "install_roots", "launch_window", "open_shell", "profile_directory"]

_PROFILE_NAME: Final = "hexbench-browser-profile"
_DEFAULT_WIDTH: Final = 1700
_DEFAULT_HEIGHT: Final = 1050

_SHELL_SUCCESS_FLOOR: Final = 32
_SHOW_NORMAL: Final = 1
_OPEN_VERB: Final = "open"
_SHELL_LIBRARY: Final = "shell32"

_PROGRAM_FILES: Final = "ProgramFiles"
_PROGRAM_FILES_X86: Final = "ProgramFiles(x86)"
_LOCAL_APPDATA: Final = "LOCALAPPDATA"
_PER_USER_PROGRAMS: Final = "Programs"

_FALLBACK_ROOTS: Final[tuple[str, ...]] = ("C:\\Program Files", "C:\\Program Files (x86)")

_BROWSERS: Final[tuple[tuple[str, ...], ...]] = (
    ("BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
    ("Google", "Chrome", "Application", "chrome.exe"),
    ("Vivaldi", "Application", "vivaldi.exe"),
    ("Opera", "launcher.exe"),
    ("Opera", "opera.exe"),
    ("Microsoft", "Edge", "Application", "msedge.exe"),
)


def install_roots() -> tuple[Path, ...]:
    """List the directories browsers are installed under, most likely first.

    Opera's consumer installer, unlike every other browser this looks for,
    places itself under a per-user ``Programs`` directory rather than directly
    under ``LOCALAPPDATA``, so that directory is listed as its own root rather
    than folded into one of the relative paths in :data:`_BROWSERS`.

    Returns:
        tuple[Path, ...]: Existing candidate roots, without duplicates.
    """
    local_appdata = os.environ.get(_LOCAL_APPDATA)
    named: tuple[str | Path | None, ...] = (
        os.environ.get(_PROGRAM_FILES),
        os.environ.get(_PROGRAM_FILES_X86),
        local_appdata,
        Path(local_appdata) / _PER_USER_PROGRAMS if local_appdata else None,
    )
    roots: list[Path] = []
    for value in (*named, *_FALLBACK_ROOTS):
        if not value:
            continue
        candidate = Path(value)
        if candidate not in roots:
            roots.append(candidate)
    return tuple(roots)


def find_browser(override: Path | None = None) -> Path | None:
    """Locate the browser to open the editor in.

    Brave is preferred, then Chrome, Vivaldi and Opera, with Edge considered
    last. Each is looked for under both program directories and under the
    per-user application data directory, since every one of these browsers can
    be installed either machine-wide or for a single user.

    Args:
        override: An explicitly chosen browser executable. When given and
            present it is used unconditionally; when given and absent no
            substitute is chosen, so an explicit choice is never silently
            ignored.

    Returns:
        Path | None: The browser executable, or ``None`` when none was found.
    """
    if override is not None:
        return override if override.is_file() else None
    roots = install_roots()
    for relative in _BROWSERS:
        for root in roots:
            candidate = root.joinpath(*relative)
            if candidate.is_file():
                return candidate
    return None


def profile_directory() -> Path:
    """Locate the browser profile this application uses.

    Returns:
        Path: A directory under the system temporary directory, kept separate
        from the user's own browser profile so the window carries no extensions,
        sessions or sign-in state.
    """
    return Path(tempfile.gettempdir()) / _PROFILE_NAME


def _shell_execute(target: Path, parameters: str) -> int:
    """Ask the shell to start a program.

    Args:
        target: Executable to start.
        parameters: Command line for the executable, excluding its own path.

    Returns:
        int: The value ``ShellExecuteW`` returned, which is greater than 32 on
        success and is an error code otherwise; zero if the shell library could
        not be loaded at all.
    """
    try:
        shell32 = ctypes.WinDLL(_SHELL_LIBRARY, use_last_error=True)
    except OSError:
        return 0
    execute = shell32.ShellExecuteW
    execute.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int]
    execute.restype = ctypes.c_ssize_t
    outcome: int = execute(None, _OPEN_VERB, str(target), parameters, None, _SHOW_NORMAL)
    return outcome


def launch_window(url: str, *, browser: Path, width: int = _DEFAULT_WIDTH, height: int = _DEFAULT_HEIGHT) -> bool:
    """Open one chromeless browser window on the given address.

    Args:
        url: Address to open, including the session token.
        browser: Browser executable to start.
        width: Width of the window in pixels.
        height: Height of the window in pixels.

    Returns:
        bool: Whether the shell accepted the request. Success only means the
        window was started; the browser reports nothing back afterwards.
    """
    profile = profile_directory()
    try:
        profile.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    parameters = f'--app="{url}" --user-data-dir="{profile}" --window-size={width},{height} --no-first-run --no-default-browser-check'
    return _shell_execute(browser, parameters) > _SHELL_SUCCESS_FLOOR


def announce(url: str) -> None:
    """State the address for a user who has to open it themselves.

    Args:
        url: Address the server is listening on, including the session token.
    """
    sys.stdout.write(f"hexbench is serving at {url}\n")
    sys.stdout.flush()


def open_shell(url: str, *, override: Path | None = None) -> bool:
    """Show the editor, in a browser window if one can be opened.

    Args:
        url: Address to open, including the session token.
        override: An explicitly chosen browser executable.

    Returns:
        bool: Whether a window was opened. When no window could be opened the
        address is written to standard output instead, so the session is still
        reachable.
    """
    browser = find_browser(override)
    if browser is not None and launch_window(url, browser=browser):
        return True
    if override is not None:
        sys.stderr.write(f"hexbench: could not open the requested browser {override}; showing the address instead\n")
        sys.stderr.flush()
    announce(url)
    return False
