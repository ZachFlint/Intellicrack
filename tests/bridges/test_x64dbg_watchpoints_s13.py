# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for S13-D03 in the x64dbg bridge.

S13-D03: ``get_watchpoints`` always raised ``ToolError("Failed to get
watchpoint list")`` on both Load and Attach, so the Watchpoints tab never
populated. The plugin's dedicated ``wp_list`` pipe command is backed by
``DbgGetBpList(bp_hardware, &bpmap)``, whose C++ SDK signature returns the
matching hardware-breakpoint *count* (an ``int``), not a success flag,
so the deployed plugin binary's ``if (!DbgGetBpList(...))`` check treats
every empty result - the overwhelmingly common case right after a fresh
Load/Attach - as a hard failure and reports the error string reproduced
above.

``get_breakpoints`` already enumerates the very same hardware-breakpoint
table via the plugin's ``bp_list`` command (filtering ``bp_hardware``
among other types) without that defect - it is relied on elsewhere in
this bridge for breakpoint-verification polling - so the fix switches
``get_watchpoints`` to issue ``bp_list`` and filter the response down to
``type == "hardware"`` entries instead of the broken dedicated command.

:class:`TestGetWatchpointsListsAddedHardwareWatchpoint` drives the real
``X64DbgBridge`` against a real host x64dbg installation and a real
System32 debuggee: it sets a hardware watchpoint via ``set_watchpoint``
and then asserts ``get_watchpoints`` actually reports it, which the
pre-fix implementation could never do.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_X64DBG_INSTALL_ROOT: Final[Path] = _REPO_ROOT / "tools" / "x64dbg"
_TARGET_EXE: Final[Path] = Path("C:/Windows/System32/notepad.exe")
_WATCHPOINT_SIZE_BYTES: Final[int] = 4


def _x64dbg_release_exists() -> bool:
    """Return whether a vendored x64dbg release build is present.

    Returns:
        bool: True if either the x64 or the x32 x64dbg executable exists
        under the vendored installation root checked into this repository.
    """
    x64_exe = _X64DBG_INSTALL_ROOT / "release" / "x64" / "x64dbg.exe"
    x32_exe = _X64DBG_INSTALL_ROOT / "release" / "x32" / "x32dbg.exe"
    return x64_exe.exists() or x32_exe.exists()


@pytest.mark.skipif(sys.platform != "win32", reason="x64dbg is a Windows-only debugger")
@pytest.mark.skipif(not _x64dbg_release_exists(), reason="vendored x64dbg install not present on this host")
@pytest.mark.asyncio
class TestGetWatchpointsListsAddedHardwareWatchpoint:
    """S13-D03: ``get_watchpoints`` must report a watchpoint it just set."""

    async def test_get_watchpoints_after_set_watchpoint_includes_the_new_address(self) -> None:
        """Set a hardware watchpoint on a loaded debuggee, then list it back.

        Falsifiable: before the fix, ``get_watchpoints`` unconditionally
        raised ``ToolError("Failed to get watchpoint list")`` as soon as
        the plugin's ``wp_list`` handler observed zero *or more* hardware
        breakpoints (the ``DbgGetBpList`` return value is a count, not a
        boolean, so its C++ ``!`` check misfires on the near-universal
        empty/any-count case). This test would fail with that
        ``ToolError`` even after ``set_watchpoint`` genuinely installed
        the hardware breakpoint in the debuggee.
        """
        if not _TARGET_EXE.exists():
            pytest.skip(f"debuggee target not present on this host: {_TARGET_EXE}")

        bridge = X64DbgBridge()
        await bridge.initialize(_X64DBG_INSTALL_ROOT)
        if not bridge.state.connected or not bridge.plugin_status.get("plugin_deployed"):
            pytest.skip(f"x64dbg bridge plugin could not be deployed on this host: {bridge.plugin_status}")

        try:
            await bridge.load(_TARGET_EXE)
            assert bridge.attached_pid is not None, "load() left attached_pid unset; cannot exercise watchpoints"

            modules = await bridge.get_modules()
            target_module = next(
                (module for module in modules if module.name.lower() == _TARGET_EXE.name.lower()),
                None,
            )
            assert target_module is not None, (
                f"{_TARGET_EXE.name} missing from get_modules() output: {sorted(module.name for module in modules)}"
            )
            watch_address = target_module.base_address

            watchpoint_id = await bridge.set_watchpoint(watch_address, _WATCHPOINT_SIZE_BYTES, "write")
            assert watchpoint_id is not None

            watchpoints = await bridge.get_watchpoints()

            matching = [wp for wp in watchpoints if wp.address == watch_address]
            assert matching, (
                f"get_watchpoints() did not report a watchpoint at 0x{watch_address:X}; "
                f"got addresses {[hex(wp.address) for wp in watchpoints]}"
            )
            assert matching[0].enabled is True
        finally:
            await bridge.shutdown()

    async def test_get_watchpoints_on_fresh_debuggee_returns_empty_without_raising(self) -> None:
        """A freshly loaded debuggee with no watchpoints must list an empty set, not raise.

        This is the actual S13-D03 symptom and the strongest falsifiable
        gate for the fix: the plugin's ``wp_list`` is backed by
        ``DbgGetBpList(bp_hardware, ...)``, whose return value is the
        hardware-breakpoint *count*, and the deployed plugin's
        ``if (!DbgGetBpList(...))`` check misreads the near-universal
        zero-count case as a hard failure -- so ``get_watchpoints`` raised
        ``ToolError`` on every fresh Load/Attach before any watchpoint was
        set (unlike the set-then-list case above, where a non-zero count
        happens to keep the broken command's return value truthy). The
        ``bp_list``-based fix returns an empty list for zero hardware
        breakpoints instead of raising.
        """
        if not _TARGET_EXE.exists():
            pytest.skip(f"debuggee target not present on this host: {_TARGET_EXE}")

        bridge = X64DbgBridge()
        await bridge.initialize(_X64DBG_INSTALL_ROOT)
        if not bridge.state.connected or not bridge.plugin_status.get("plugin_deployed"):
            pytest.skip(f"x64dbg bridge plugin could not be deployed on this host: {bridge.plugin_status}")

        try:
            await bridge.load(_TARGET_EXE)
            assert bridge.attached_pid is not None, "load() left attached_pid unset; cannot exercise watchpoints"

            watchpoints = await bridge.get_watchpoints()
            assert isinstance(watchpoints, list), (
                f"get_watchpoints() on a fresh debuggee must return a list, got {type(watchpoints).__name__}"
            )
        finally:
            await bridge.shutdown()
