# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for S14-D02 (PID filtering) and S14-D05 (raw system query sizing).

Exercises ``ProcessBridge`` against the real Windows process snapshot and
``NtQuerySystemInformation`` APIs. No mocks: every assertion is derived from
live process enumeration or a live kernel query, so a regression in either
defect fix causes a genuine test failure.
"""

from __future__ import annotations

import ctypes
import os
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_SYSTEM_BASIC_INFORMATION_CLASS = 0
_SYSTEM_PROCESS_INFORMATION_CLASS = 5
_EXPECTED_PAGE_SIZE = 4096
_BOGUS_PID_FILTER = "999999999999"
_ATTR_PROCESS_MATCHES_FILTER = "_process_matches_filter"


def _invoke_process_matches_filter(pid: int, name: str, filter_name: str | None) -> bool:
    """Invoke ``ProcessBridge._process_matches_filter`` via getattr, bypassing reportPrivateUsage.

    Args:
        pid: Candidate process ID.
        name: Candidate process executable name.
        filter_name: Filter string under test.

    Returns:
        bool: Whether the candidate matches the filter.

    Raises:
        TypeError: If the resolved attribute is not callable or does not return bool.
    """
    fn: object = getattr(ProcessBridge, _ATTR_PROCESS_MATCHES_FILTER)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_PROCESS_MATCHES_FILTER} is not callable"
        raise TypeError(msg)
    result: object = fn(pid, name, filter_name)
    if not isinstance(result, bool):
        msg = f"ProcessBridge.{_ATTR_PROCESS_MATCHES_FILTER} expected bool return, got {type(result).__name__}"
        raise TypeError(msg)
    return result


class _SystemBasicInformation(ctypes.Structure):
    """Layout of ``SYSTEM_BASIC_INFORMATION`` for ``NtQuerySystemInformation`` class 0."""

    _fields_ = (
        ("Reserved", wintypes.ULONG),
        ("TimerResolution", wintypes.ULONG),
        ("PageSize", wintypes.ULONG),
        ("NumberOfPhysicalPages", wintypes.ULONG),
        ("LowestPhysicalPageNumber", wintypes.ULONG),
        ("HighestPhysicalPageNumber", wintypes.ULONG),
        ("AllocationGranularity", wintypes.ULONG),
        ("MinimumUserModeAddress", ctypes.c_size_t),
        ("MaximumUserModeAddress", ctypes.c_size_t),
        ("ActiveProcessorsAffinityMask", ctypes.c_size_t),
        ("NumberOfProcessors", ctypes.c_byte),
    )


@pytest_asyncio.fixture(scope="module")
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Create, initialize, and shut down a ``ProcessBridge`` for the module.

    Yields:
        ProcessBridge: Initialized bridge that will be shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    yield bridge
    await bridge.shutdown()


class TestS14D02PidFilter:
    """S14-D02: the process list filter must match by PID as well as by name."""

    async def test_numeric_filter_matches_real_pid(self, process_bridge: ProcessBridge) -> None:
        """Filtering by the current process's PID must return that process's row.

        Args:
            process_bridge: Module-scoped, initialized ``ProcessBridge``.
        """
        pid = os.getpid()
        unfiltered = await process_bridge.list_processes_detailed(None)
        assert any(entry.get("pid") == pid for entry in unfiltered), "sanity: current process must be enumerable"

        filtered = await process_bridge.list_processes_detailed(str(pid))
        assert any(entry.get("pid") == pid for entry in filtered)

    async def test_numeric_filter_rejects_bogus_pid(self, process_bridge: ProcessBridge) -> None:
        """Filtering by a PID string no real process's PID contains returns no rows.

        Args:
            process_bridge: Module-scoped, initialized ``ProcessBridge``.
        """
        filtered = await process_bridge.list_processes_detailed(_BOGUS_PID_FILTER)
        assert filtered == []

    async def test_name_filter_still_matches_by_name(self, process_bridge: ProcessBridge) -> None:
        """Non-numeric filters must still match case-insensitively by process name.

        Args:
            process_bridge: Module-scoped, initialized ``ProcessBridge``.
        """
        pid = os.getpid()
        exe_stem = Path(sys.executable).stem
        filtered = await process_bridge.list_processes_detailed(exe_stem)
        assert any(entry.get("pid") == pid for entry in filtered)

    @pytest.mark.parametrize(
        ("pid", "name", "filter_name", "expected"),
        [
            (512, "target.exe", "12", True),
            (512, "target.exe", "999", False),
            (512, "target.exe", None, True),
            (512, "TARGET.exe", "target", True),
            (512, "notepad.exe", "512", True),
        ],
    )
    def test_process_matches_filter_unit(
        self,
        *,
        pid: int,
        name: str,
        filter_name: str | None,
        expected: bool,
    ) -> None:
        """Verify the shared filter predicate's numeric-vs-name branching directly.

        Args:
            pid: Candidate process ID.
            name: Candidate process executable name.
            filter_name: Filter string under test.
            expected: Expected match result.
        """
        assert _invoke_process_matches_filter(pid, name, filter_name) is expected


class TestS14D05RawQuerySizing:
    """S14-D05: ``query_system_info`` must size retries from the kernel's return_length hint."""

    async def test_fixed_size_class_zero_returns_valid_basic_information(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """``SystemBasicInformation`` (class 0) must succeed with the default oversized buffer.

        The default 65536-byte initial buffer is far larger than the fixed
        ``SYSTEM_BASIC_INFORMATION`` structure. Windows rejects an oversized
        buffer for this exact-size class with ``STATUS_INFO_LENGTH_MISMATCH``,
        so this only succeeds if the retry loop shrinks to the kernel's
        reported ``ReturnLength`` instead of doubling toward the 1 GB cap.

        Args:
            process_bridge: Module-scoped, initialized ``ProcessBridge``.
        """
        result = await process_bridge.query_system_info(_SYSTEM_BASIC_INFORMATION_CLASS)
        raw = bytes.fromhex(result)
        assert len(raw) >= ctypes.sizeof(_SystemBasicInformation)

        info = _SystemBasicInformation.from_buffer_copy(raw[: ctypes.sizeof(_SystemBasicInformation)])
        assert info.PageSize == _EXPECTED_PAGE_SIZE
        assert info.NumberOfProcessors > 0

    async def test_variable_size_class_still_succeeds(self, process_bridge: ProcessBridge) -> None:
        """``SystemProcessInformation`` (class 5) must still auto-grow correctly.

        Args:
            process_bridge: Module-scoped, initialized ``ProcessBridge``.
        """
        result = await process_bridge.query_system_info(_SYSTEM_PROCESS_INFORMATION_CLASS)
        assert isinstance(result, str)
        assert len(result) > 0
        assert all(c in "0123456789abcdef" for c in result)
        assert len(result) % 2 == 0
