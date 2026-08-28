# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Frozen launcher for the installed Hexbench hex editor.

This module is compiled into ``Hexbench.exe`` and installed at the root of the
install directory beside ``Intellicrack.exe``. It resolves the bundled Python
runtime and the staged ``hexbench`` package that the installer laid down next to
it, assembles an ephemeral child environment (never touching the machine or user
environment), and spawns ``runtime/python.exe -m hexbench``.

The installed layout the launcher targets is::

    <installdir>/Hexbench.exe            (this launcher, frozen)
    <installdir>/runtime/                (bundled Python 3.13 environment)
    <installdir>/hexbench/               (the hexbench package source)

Two choices here are deliberate and are what make the shortcut work.

The child is started from ``python.exe`` under ``CREATE_NO_WINDOW`` rather than
from ``pythonw.exe`` or under ``DETACHED_PROCESS``. Hexbench writes diagnostics
to ``sys.stderr`` unconditionally, and both of those alternatives leave the
child's standard handles as ``None``, which turns the first such diagnostic into
an ``AttributeError`` instead of a message. ``CREATE_NO_WINDOW`` allocates a
real console the user never sees, so the handles stay valid and nothing is
displayed.

The package is run as ``-m hexbench`` with the install directory on
``PYTHONPATH`` rather than by pointing the interpreter at a file inside it. The
editor locates its ``static`` tree relative to its own ``__file__``, so it has
to be imported as a module of the package rather than as a top-level script.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path


_RUNTIME_PATH_SEGMENTS: tuple[tuple[str, ...], ...] = (
    ("runtime",),
    ("runtime", "Library", "bin"),
    ("runtime", "Library", "mingw-w64", "bin"),
    ("runtime", "Library", "usr", "bin"),
    ("runtime", "DLLs"),
)

_PYTHON_SEGMENTS: tuple[str, ...] = ("runtime", "python.exe")
_PACKAGE_NAME: str = "hexbench"
_PACKAGE_MARKER: str = "__init__.py"

_ERROR_TITLE: str = "Hexbench"
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


def package_root(install_dir: Path) -> Path:
    """Resolve the directory that must be importable for ``-m hexbench``.

    The installer stages the package itself as ``<installdir>/hexbench``, so the
    directory that has to be on ``PYTHONPATH`` is its parent -- the install
    directory. In a development checkout the package lives under ``src``
    instead, which is that same relationship one level down.

    Args:
        install_dir: The resolved install directory.

    Returns:
        Path: The directory to place on ``PYTHONPATH`` so ``hexbench`` imports.
    """
    if (install_dir / _PACKAGE_NAME / _PACKAGE_MARKER).is_file():
        return install_dir
    return install_dir / "src"


def build_child_env(install_dir: Path) -> dict[str, str]:
    """Build an ephemeral environment block for the spawned editor.

    The returned mapping is a copy of the current process environment with the
    bundled runtime directories prepended to ``PATH`` and the directory holding
    the ``hexbench`` package prepended to ``PYTHONPATH``. Only directories that
    actually exist are added. No tool directories are contributed: the editor
    drives the hexcore extension out of the runtime and needs none of them. The
    current process environment is never modified.

    Args:
        install_dir: The resolved install directory.

    Returns:
        dict[str, str]: A new environment mapping suitable for passing to :class:`subprocess.Popen`.
    """
    env: dict[str, str] = dict(os.environ)

    prepend: list[str] = []
    for segments in _RUNTIME_PATH_SEGMENTS:
        directory = install_dir.joinpath(*segments)
        if directory.is_dir():
            prepend.append(str(directory))

    existing_path = env.get("PATH", "")
    path_parts = prepend + ([existing_path] if existing_path else [])
    if path_parts:
        env["PATH"] = os.pathsep.join(path_parts)

    roots = str(package_root(install_dir))
    existing_pythonpath = env.get("PYTHONPATH", "")
    if existing_pythonpath:
        env["PYTHONPATH"] = os.pathsep.join((roots, existing_pythonpath))
    else:
        env["PYTHONPATH"] = roots

    return env


def report_error(message: str) -> None:
    """Report a fatal startup failure to whoever can see it.

    A session started from a terminal has a usable ``sys.stderr`` and gets the
    message there. The frozen launcher is windowed, so a session started from
    the Start menu or a shortcut has no stream to read: there the message is
    shown in a dialog instead, because a shortcut that fails silently is
    indistinguishable from one that did nothing at all.

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
    """Compute the process creation flags for a windowless child with live streams.

    ``CREATE_NO_WINDOW`` is chosen over ``DETACHED_PROCESS`` because the latter
    leaves the child without standard handles, and the editor writes diagnostics
    to ``sys.stderr`` unconditionally.

    Returns:
        int: The Windows creation flag that suppresses the console window.
    """
    return subprocess.CREATE_NO_WINDOW


def launch(argv: list[str]) -> int:
    """Spawn the Hexbench editor with the bundled runtime.

    Assembles the ephemeral child environment, verifies both the bundled
    ``python.exe`` and the staged ``hexbench`` package are present, and launches
    ``python.exe -m hexbench`` with the pass-through arguments, without a console
    window. The launcher does not wait for the child.

    Args:
        argv: Extra arguments to forward to the ``hexbench`` module.

    Returns:
        int: ``0`` on a successful spawn, or ``1`` when the bundled runtime or the
        package is missing, or the child could not be started.
    """
    install_dir = resolve_install_dir()
    python = install_dir.joinpath(*_PYTHON_SEGMENTS)

    if not python.is_file():
        report_error(f"Hexbench runtime not found: {python}")
        return 1

    roots = package_root(install_dir)
    package = roots / _PACKAGE_NAME / _PACKAGE_MARKER
    if not package.is_file():
        report_error(f"Hexbench package not found: {package}")
        return 1

    env = build_child_env(install_dir)
    command = [str(python), "-m", _PACKAGE_NAME, *argv]

    try:
        subprocess.Popen(
            command,
            cwd=str(install_dir),
            env=env,
            creationflags=creation_flags(),
            close_fds=True,
        )
    except OSError as error:
        report_error(f"Failed to start Hexbench: {error}")
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
