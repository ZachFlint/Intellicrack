# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Fixtures shared by the MCP gates that run a real server confined at Low integrity."""

from __future__ import annotations

import csv
import os
import subprocess
from pathlib import Path
from typing import Final

import pytest


_ICACLS_TIMEOUT_S: Final[float] = 60.0
_WINDOWS_ROOT: Final[str] = r"C:\Windows"


def _system_tool(name: str) -> str:
    """Locate a program in the Windows system directory.

    Args:
        name: The program's name without its suffix.

    Returns:
        str: Its full path.
    """
    return str(Path(os.environ.get("SYSTEMROOT", _WINDOWS_ROOT), "System32", f"{name}.exe"))


def _account_sid() -> str:
    """Read the security identifier of the account the tests run as.

    Returns:
        str: The SID, such as ``S-1-5-21-...``.
    """
    completed = subprocess.run(
        [_system_tool("whoami"), "/user", "/fo", "csv", "/nh"],
        capture_output=True,
        text=True,
        check=True,
        timeout=_ICACLS_TIMEOUT_S,
    )
    [row] = list(csv.reader(completed.stdout.splitlines()))
    return row[1]


def _grant(path: Path, permission: str) -> None:
    """Add one access entry to a directory with ``icacls``.

    Args:
        path: The directory.
        permission: The ``icacls`` grant, such as ``*S-1-5-21-...:(OI)(CI)F``.
    """
    _ = subprocess.run(
        [_system_tool("icacls"), str(path), "/grant", permission],
        capture_output=True,
        text=True,
        check=True,
        timeout=_ICACLS_TIMEOUT_S,
    )


@pytest.fixture
def account_reachable_tmp_path(tmp_path: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Give the test's directory the access a directory the operator owns has: the operator's own account can use it.

    pytest creates its temporary directories with mode ``0o700``, which Python on Windows turns into a protected access list granting only
    SYSTEM, Administrators and the directory's owner. Under an elevated runner the owner is the Administrators group, which the sandbox
    token holds deny-only, so the account a confined server runs as could not even open its own working directory, unlike any directory
    the operator really owns. The account is granted full access below the test's directory and listing on the directories above it that
    pytest locked the same way.

    Args:
        tmp_path: Per-test directory.
        tmp_path_factory: Locates the session's base temporary directory.

    Returns:
        Path: The test's directory.
    """
    sid = _account_sid()
    basetemp = tmp_path_factory.getbasetemp()
    _grant(tmp_path, f"*{sid}:(OI)(CI)F")
    for ancestor in tmp_path.parents:
        if ancestor == basetemp.parent or ancestor.is_relative_to(basetemp):
            _grant(ancestor, f"*{sid}:(RX)")
    return tmp_path
