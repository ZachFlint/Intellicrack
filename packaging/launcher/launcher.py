# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frozen launcher for the installed Intellicrack platform.

This module is compiled into ``Intellicrack.exe`` and installed at the root of
the install directory. It resolves the bundled Python runtime, tool
directories, and application source that were laid down beside it, assembles an
ephemeral child environment (never touching the machine or user environment),
and spawns the PyQt6 application as ``runtime/pythonw.exe -m intellicrack``
without opening a console window.

The installed layout the launcher targets is::

    <installdir>/Intellicrack.exe        (this launcher, frozen)
    <installdir>/runtime/                (bundled Python 3.13 environment)
    <installdir>/app/src/intellicrack/   (application source)
    <installdir>/app/tools/...           (optional installed tool components)
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path


_PATH_SEGMENTS: tuple[tuple[str, ...], ...] = (
    ("runtime",),
    ("runtime", "Library", "bin"),
    ("runtime", "Library", "mingw-w64", "bin"),
    ("runtime", "Library", "usr", "bin"),
    ("runtime", "DLLs"),
    ("app", "tools", "cutter"),
    ("app", "tools", "radare2", "bin"),
)

_PYTHONW_SEGMENTS: tuple[str, ...] = ("runtime", "pythonw.exe")
_APP_SEGMENT: str = "app"
_APP_SRC_SEGMENTS: tuple[str, ...] = ("app", "src")
_GHIDRA_GLOB: str = "tools/ghidra/jdk-21*"
_STATE_DIR_NAME: str = "Intellicrack"

_ERROR_TITLE: str = "Intellicrack"
_USER_LIBRARY: str = "user32"
_MB_OK: int = 0x00000000
_MB_ICONERROR: int = 0x00000010


def resolve_install_dir() -> Path:
    """Resolve the install directory that contains the launcher.

    When running as a frozen executable the install directory is the directory
    that holds ``sys.executable`` (the launcher sits at the install root). In a
    development checkout the launcher lives at ``packaging/launcher`` inside the
    repository, so the repository root is returned as a sensible fallback that
    keeps the module runnable for a smoke test.

    Returns:
        Path: The absolute path to the resolved install directory.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]


def find_java_home(app_dir: Path) -> Path | None:
    """Locate the bundled Ghidra JDK if the Ghidra component is installed.

    Searches ``app/tools/ghidra`` for a single ``jdk-21*`` directory that
    contains a ``bin`` subdirectory. When the Ghidra component was not installed
    no such directory exists and no JDK is reported.

    Args:
        app_dir: The application directory (``<installdir>/app``).

    Returns:
        Path | None: The absolute path to the bundled JDK, or ``None`` when it is absent.
    """
    for candidate in sorted(app_dir.glob(_GHIDRA_GLOB)):
        if candidate.is_dir() and (candidate / "bin").is_dir():
            return candidate.resolve()
    return None


def build_child_env(install_dir: Path) -> dict[str, str]:
    """Build an ephemeral environment block for the spawned application.

    The returned mapping is a copy of the current process environment with the
    bundled runtime and tool directories prepended to ``PATH``, ``PYTHONPATH``
    pointed at the application source, ``JAVA_HOME`` set to the bundled JDK when
    present, and ``INTELLICRACK_STATE_DIR`` pointed at a per-user writable state
    directory under ``%LOCALAPPDATA%`` so credentials, config, logs, and data are
    never written under the read-only, world-readable install directory. Only
    directories that actually exist are added, so tool components the user did
    not install do not shadow their own configuration. The current process
    environment is never modified.

    Creating the state directory is the one step here that touches the disk, so
    it is the one that can fail -- a locked-down profile, or a file already
    occupying that name, raises :class:`OSError`. It is deliberately left to
    propagate: :func:`launch` turns it into the same reported failure a refused
    spawn produces, rather than silently dropping the variable and letting the
    application fall back to writing under the read-only install directory.

    The full parent environment is inherited deliberately, not filtered. The
    child is the first-party Intellicrack application the user explicitly
    launched -- the same trust position a shortcut launched from Explorer gives
    it, which also passes the entire user environment. Inheritance is required
    for correct operation: the application authenticates AI providers from an
    open-ended set of environment credentials (``ANTHROPIC_API_KEY``,
    ``GEMINI_API_KEY``, ``OPENAI_API_KEY``, ``GROK_*``, ``OPENROUTER_API_KEY``,
    ``HF_TOKEN``/``HUGGINGFACE_HUB_TOKEN`` and user-defined variants), and the
    external tools it spawns (Ghidra, x64dbg, QEMU, radare2) rely on inherited
    ``JAVA_HOME``/``PATH``/tool configuration. An allowlist would silently drop
    credentials the user adds; a secret-pattern denylist would strip exactly the
    ``*_API_KEY``/``*_TOKEN`` values the application needs. The launcher itself
    introduces no new secret -- it adds only the non-sensitive path and
    state-directory variables above.

    Args:
        install_dir: The resolved install directory.

    Returns:
        dict[str, str]: A new environment mapping suitable for passing to :class:`subprocess.Popen`.
    """
    env: dict[str, str] = dict(os.environ)

    prepend: list[str] = []
    for segments in _PATH_SEGMENTS:
        directory = install_dir.joinpath(*segments)
        if directory.is_dir():
            prepend.append(str(directory))

    existing_path = env.get("PATH", "")
    path_parts = prepend + ([existing_path] if existing_path else [])
    if path_parts:
        env["PATH"] = os.pathsep.join(path_parts)

    app_src = str(install_dir.joinpath(*_APP_SRC_SEGMENTS))
    existing_pythonpath = env.get("PYTHONPATH", "")
    if existing_pythonpath:
        env["PYTHONPATH"] = os.pathsep.join((app_src, existing_pythonpath))
    else:
        env["PYTHONPATH"] = app_src

    java_home = find_java_home(install_dir / _APP_SEGMENT)
    if java_home is not None:
        env["JAVA_HOME"] = str(java_home)

    local_app_data = env.get("LOCALAPPDATA")
    if local_app_data:
        state_dir = Path(local_app_data) / _STATE_DIR_NAME
        state_dir.mkdir(parents=True, exist_ok=True)
        env["INTELLICRACK_STATE_DIR"] = str(state_dir)

    return env


def report_error(message: str) -> None:
    """Report a fatal startup failure to whoever can see it.

    A session started from a terminal has a usable ``sys.stderr`` and gets the
    message there. The frozen launcher is windowed, so a session started from the
    Start menu or a shortcut has no stream to read: there the message is shown in
    a dialog instead, because a shortcut that fails silently is indistinguishable
    from one that did nothing at all.

    Args:
        message: The failure to report.
    """
    stream = sys.stderr
    if stream is not None:
        stream.write(f"{message}\n")
        stream.flush()

    user32 = ctypes.WinDLL(_USER_LIBRARY)
    message_box = user32.MessageBoxW
    message_box.argtypes = (wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT)
    message_box.restype = ctypes.c_int
    message_box(None, message, _ERROR_TITLE, _MB_OK | _MB_ICONERROR)


def creation_flags() -> int:
    """Compute the process creation flags for a detached, windowless child.

    Returns:
        int: The Windows creation flags that detach the child and suppress its console window.
    """
    return subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP


def launch(argv: list[str]) -> int:
    """Spawn the Intellicrack application with the bundled runtime.

    Assembles the ephemeral child environment, verifies the bundled
    ``pythonw.exe`` is present, and launches ``pythonw.exe -m intellicrack``
    with the pass-through arguments in the application directory, without a
    console window. The launcher does not wait for the child.

    Every failure on this path is reported through :func:`report_error` so a
    session started from a shortcut gets a dialog naming the cause, instead of
    the raw traceback the bootloader would otherwise put on screen.

    Args:
        argv: Extra arguments to forward to the ``intellicrack`` module.

    Returns:
        int: ``0`` on a successful spawn, or ``1`` when the bundled runtime is missing, the
        environment could not be prepared, or the child could not be started.
    """
    install_dir = resolve_install_dir()
    pythonw = install_dir.joinpath(*_PYTHONW_SEGMENTS)
    app_dir = install_dir / _APP_SEGMENT

    if not pythonw.is_file():
        report_error(f"Intellicrack runtime not found: {pythonw}")
        return 1

    try:
        env = build_child_env(install_dir)
    except OSError as error:
        report_error(f"Failed to prepare the Intellicrack environment: {error}")
        return 1

    command = [str(pythonw), "-m", "intellicrack", *argv]

    try:
        subprocess.Popen(
            command,
            cwd=str(app_dir),
            env=env,
            creationflags=creation_flags(),
            close_fds=True,
        )
    except OSError as error:
        report_error(f"Failed to start Intellicrack: {error}")
        return 1

    return 0


def main() -> int:
    """Entry point for the frozen launcher.

    Returns:
        int: The process exit code produced by :func:`launch`.
    """
    return launch(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
