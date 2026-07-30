# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for S13-D02 and S13-D06 in the x64dbg bridge.

S13-D02: ``load()`` previously never registered ``self._attached_pid`` in
practice - it queried ``$pid`` exactly once, immediately after issuing
``InitDebug``, which races the debug loop's process-creation event and
commonly observes ``0``. Every process-inspection command
(``read_memory``, ``get_memory_regions``, ``get_modules``, ``get_threads``,
``get_process_info``) gates purely on ``self._attached_pid is None`` and
therefore raised "not attached" even though the debuggee was loaded and
running. :class:`TestLoadRegistersAttachedProcess` drives the real
``X64DbgBridge`` against a real host x64dbg installation and a real
System32 debuggee to prove the Load path now registers attach state the
same way the Attach path always did.

S13-D06: ``scan_memory`` must raise a clear ``ToolError`` for patterns
shorter than ``MIN_PATTERN_LENGTH`` bytes instead of silently returning an
empty result list. :class:`TestScanMemoryRejectsShortPatterns` exercises
that guard directly; it requires no host x64dbg installation because the
length check runs before any process or memory access.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

import pytest

from intellicrack.bridges.x64dbg import MIN_PATTERN_LENGTH, X64DbgBridge
from intellicrack.core.types import ToolError


_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
_X64DBG_INSTALL_ROOT: Final[Path] = _REPO_ROOT / "tools" / "x64dbg"
_TARGET_EXE: Final[Path] = Path("C:/Windows/System32/notepad.exe")
_MODULE_BASE_READ_SIZE: Final[int] = 2


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
class TestLoadRegistersAttachedProcess:
    """S13-D02: ``load()`` must register attach state like ``attach()`` does."""

    async def test_load_then_run_makes_inspection_commands_see_the_attached_process(self) -> None:
        """Load a real debuggee and confirm process-inspection RPCs succeed.

        Falsifiable: before the fix, ``self._attached_pid`` stayed ``None``
        after ``load()`` in real usage because the single, unretried
        ``reg_get $pid`` immediately after ``InitDebug`` raced the debug
        loop's process-creation event. ``get_modules``, ``read_memory``, and
        ``get_threads`` would then each raise ``ToolError`` ("not attached")
        instead of returning the real, non-empty results asserted below.
        """
        if not _TARGET_EXE.exists():
            pytest.skip(f"debuggee target not present on this host: {_TARGET_EXE}")

        bridge = X64DbgBridge()
        await bridge.initialize(_X64DBG_INSTALL_ROOT)
        if not bridge.state.connected or not bridge.plugin_status.get("plugin_deployed"):
            pytest.skip(f"x64dbg bridge plugin could not be deployed on this host: {bridge.plugin_status}")

        try:
            await bridge.load(_TARGET_EXE)

            assert bridge.attached_pid is not None, (
                "load() left attached_pid unset after InitDebug; process-inspection commands would incorrectly report 'not attached'"
            )

            modules = await bridge.get_modules()
            assert modules, "get_modules() returned no modules for a freshly loaded debuggee"

            target_module = next(
                (module for module in modules if module.name.lower() == _TARGET_EXE.name.lower()),
                None,
            )
            assert target_module is not None, (
                f"{_TARGET_EXE.name} missing from get_modules() output: {sorted(module.name for module in modules)}"
            )

            header = await bridge.read_memory(target_module.base_address, _MODULE_BASE_READ_SIZE)
            assert header == b"MZ", f"expected the real 'MZ' PE header at the module base, got {header!r}"

            threads = await bridge.get_threads()
            assert threads, "get_threads() returned no threads for a freshly loaded, running debuggee"
        finally:
            await bridge.shutdown()


class TestScanMemoryRejectsShortPatterns:
    """S13-D06: ``scan_memory`` must reject sub-minimum-length patterns loudly."""

    @pytest.mark.asyncio
    async def test_hex_string_pattern_shorter_than_minimum_raises_tool_error(self) -> None:
        """A hex-string pattern under ``MIN_PATTERN_LENGTH`` bytes raises ``ToolError``.

        Falsifiable: before the fix (or under a regression that removes the
        length guard), a short pattern would silently produce an empty
        match list instead of surfacing the requirement to the caller/UI.
        """
        bridge = X64DbgBridge()
        short_pattern = "48 8B 05 90"

        with pytest.raises(ToolError, match=rf"at least {MIN_PATTERN_LENGTH}"):
            await bridge.scan_memory(short_pattern)

    @pytest.mark.asyncio
    async def test_raw_bytes_pattern_shorter_than_minimum_raises_tool_error(self) -> None:
        """A raw ``bytes`` pattern under ``MIN_PATTERN_LENGTH`` bytes raises ``ToolError``.

        Falsifiable: mirrors the hex-string case for the ``bytes`` branch of
        ``scan_memory``'s ``pattern: str | bytes`` parameter so both input
        forms are covered by the same length guard.
        """
        bridge = X64DbgBridge()
        short_pattern = bytes.fromhex("488B0590")

        with pytest.raises(ToolError, match=rf"at least {MIN_PATTERN_LENGTH}"):
            await bridge.scan_memory(short_pattern)

    @pytest.mark.skipif(sys.platform != "win32", reason="scan_memory's post-guard path requires Windows APIs")
    @pytest.mark.asyncio
    async def test_pattern_at_minimum_length_is_not_rejected_by_the_length_guard(self) -> None:
        """A pattern exactly ``MIN_PATTERN_LENGTH`` bytes long clears the length guard.

        Falsifiable: an off-by-one in the guard (``<=`` instead of ``<``)
        would reject this pattern with the same "too short" ``ToolError``
        that the short-pattern tests assert on; asserting a *different*
        failure mode here (no attached process) proves the length check
        itself passed.
        """
        bridge = X64DbgBridge()
        exact_length_pattern = bytes(MIN_PATTERN_LENGTH)

        with pytest.raises(ToolError, match=r"[Nn]o process attached|not attached"):
            await bridge.scan_memory(exact_length_pattern)
