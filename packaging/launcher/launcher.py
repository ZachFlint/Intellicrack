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

import os
import subprocess
import sys
from pathlib import Path


_PATH_SEGMENTS: tuple[tuple[str, ...], ...] = (
    ("runtime",),
    ("runtime", "Library", "bin"),
    ("runtime", "Library", "mingw-w64", "bin"),
    ("runtime", "Library", "usr", "bin"),
    ("runtime", "Scripts"),
    ("runtime", "DLLs"),
    ("app", "tools", "cutter"),
    ("app", "tools", "radare2", "bin"),
)

_PYTHONW_SEGMENTS: tuple[str, ...] = ("runtime", "pythonw.exe")
_APP_SEGMENT: str = "app"
_APP_SRC_SEGMENTS: tuple[str, ...] = ("app", "src")
_GHIDRA_GLOB: str = "tools/ghidra/jdk-21*"


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
    pointed at the application source, and ``JAVA_HOME`` set to the bundled JDK
    when present. Only directories that actually exist are added, so tool
    components the user did not install do not shadow their own configuration.
    The current process environment is never modified.

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

    return env


def _creation_flags() -> int:
    """Compute the process creation flags for a detached, windowless child.

    Returns:
        int: The Windows creation flags that detach the child and suppress a console window, or ``0``
        on platforms without those flags.
    """
    if sys.platform == "win32":
        return subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    return 0


def launch(argv: list[str]) -> int:
    """Spawn the Intellicrack application with the bundled runtime.

    Assembles the ephemeral child environment, verifies the bundled
    ``pythonw.exe`` is present, and launches ``pythonw.exe -m intellicrack``
    with the pass-through arguments in the application directory, without a
    console window. The launcher does not wait for the child.

    Args:
        argv: Extra arguments to forward to the ``intellicrack`` module.

    Returns:
        int: ``0`` on a successful spawn, or ``1`` when the bundled runtime is missing or the child
        could not be started.
    """
    install_dir = resolve_install_dir()
    pythonw = install_dir.joinpath(*_PYTHONW_SEGMENTS)
    app_dir = install_dir / _APP_SEGMENT

    if not pythonw.is_file():
        sys.stderr.write(f"Intellicrack runtime not found: {pythonw}\n")
        return 1

    env = build_child_env(install_dir)
    command = [str(pythonw), "-m", "intellicrack", *argv]

    try:
        subprocess.Popen(
            command,
            cwd=str(app_dir),
            env=env,
            creationflags=_creation_flags(),
            close_fds=True,
        )
    except OSError as error:
        sys.stderr.write(f"Failed to start Intellicrack: {error}\n")
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
