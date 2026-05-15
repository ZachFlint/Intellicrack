# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Host-side emulation of the QEMU Windows guest agent ``Test-AllowedCommand``.

The Windows guest agent bootstrap script (see
``QEMUSandbox._WINDOWS_GUEST_AGENT_SCRIPT`` body around line 1887 of
``src/intellicrack/sandbox/qemu.py``) gates every dispatched executable with a
PowerShell ``Test-AllowedCommand`` helper that accepts an entry when either:

* The lowercased value matches a name in ``$allowedNames``
  (``powershell``, ``powershell.exe``, ``cmd``, ``cmd.exe``), or
* The value ends with ``.exe`` and its lowercased form begins with one of the
  System32, SysWOW64 or ``Z:\`` roots.

This module replicates that decision so tests can assert that a host-side
dispatch would have been accepted in-guest without spinning up a real VM. It
is shared between audit-regression tests that exercise different agent code
paths (anti-evasion, dropped-file extraction, and any future test that drives
``GuestAgentClient.send_command`` with allowlist-sensitive commands).
"""

from __future__ import annotations


ALLOWED_GUEST_AGENT_NAMES: frozenset[str] = frozenset({"powershell", "powershell.exe", "cmd", "cmd.exe"})
"""Bare-name entries the in-guest allowlist accepts without a path prefix."""

ALLOWED_GUEST_AGENT_ROOTS_WINDOWS: tuple[str, ...] = (
    "z:\\",
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)
"""Lowercased absolute path prefixes the in-guest allowlist accepts for ``.exe`` files."""


def is_windows_allowlisted(command: str) -> bool:
    """Return whether the in-guest agent would accept ``command``.

    Mirrors the PowerShell ``Test-AllowedCommand`` helper installed by the
    Windows guest agent bootstrap script: a value is accepted when either
    its lowercased form is in :data:`ALLOWED_GUEST_AGENT_NAMES`, or it ends
    in ``.exe`` and starts with one of the roots in
    :data:`ALLOWED_GUEST_AGENT_ROOTS_WINDOWS`.

    Args:
        command: Command name or absolute path the sandbox would dispatch.

    Returns:
        bool: ``True`` when the in-guest agent's allowlist would accept the
        command, ``False`` otherwise.
    """
    if not command:
        return False
    lowered = command.lower()
    if lowered in ALLOWED_GUEST_AGENT_NAMES:
        return True
    if not lowered.endswith(".exe"):
        return False
    return any(lowered.startswith(root) for root in ALLOWED_GUEST_AGENT_ROOTS_WINDOWS)
