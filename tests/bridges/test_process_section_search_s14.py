# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for S14-D12 (section unmap teardown) and S14-D13 (pattern search scoping/cancel/progress).

Exercises ``ProcessBridge`` against real Win32 section objects and the
current process's own memory through live ``CreateFileMappingW`` /
``MapViewOfFile`` / ``UnmapViewOfFile`` and ``ReadProcessMemory`` calls. No
mocks: every assertion is derived from live kernel state (residual-mapping
queries via ``VirtualQuery``) or from wall-clock timing and byte counts of a
live memory scan, so a regression in either defect fix causes a genuine test
failure.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import threading
import time
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio
import structlog.testing

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import MEM_COMMIT, MEM_FREE, MEMORY_BASIC_INFORMATION
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_SECTION_SIZE = 4096
_SCRATCH_REGION_SIZE = 4 * 1024 * 1024
_PATTERN_BYTES = bytes.fromhex("DEADBEEFCAFEBABE")
_PATTERN_HEX = " ".join(f"{b:02X}" for b in _PATTERN_BYTES)
_MEM_COMMIT_RESERVE = 0x1000 | 0x2000
_PAGE_READWRITE = 0x04
_MEM_RELEASE = 0x8000
_CANCEL_BOUND_SECONDS = 15.0
_SCOPED_SCAN_BOUND_SECONDS = 3.0
_SCOPED_BYTES_CEILING = 1_000_000


def _query_state(address: int) -> int:
    """Query the live memory state of ``address`` via ``VirtualQuery``.

    Args:
        address: Virtual address to query.

    Returns:
        int: The ``State`` field (e.g. ``MEM_FREE``, ``MEM_COMMIT``) that
            ``VirtualQuery`` reports for the region containing ``address``.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.VirtualQuery.restype = ctypes.c_size_t
    mbi = MEMORY_BASIC_INFORMATION()
    result = kernel32.VirtualQuery(ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
    assert result != 0, "VirtualQuery failed against a live address"
    return int(mbi.State)


def _alloc_scratch_region(size: int) -> int:
    """Commit a private read/write scratch region in the current process.

    Args:
        size: Number of bytes to commit.

    Returns:
        int: Base address of the committed region.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    address = kernel32.VirtualAlloc(None, size, _MEM_COMMIT_RESERVE, _PAGE_READWRITE)
    assert address, "VirtualAlloc failed to commit the scratch region"
    return int(address)


def _free_scratch_region(address: int) -> None:
    """Release a scratch region previously committed by :func:`_alloc_scratch_region`.

    Args:
        address: Base address returned by :func:`_alloc_scratch_region`.
    """
    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
    kernel32.VirtualFree.restype = ctypes.c_int
    kernel32.VirtualFree(ctypes.c_void_p(address), 0, _MEM_RELEASE)


@pytest_asyncio.fixture
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Create, initialize, self-attach, and shut down a ``ProcessBridge``.

    Yields:
        ProcessBridge: Initialized bridge attached to the current process;
            shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    await bridge.open_process(os.getpid())
    yield bridge
    await bridge.shutdown()


class TestS14D12SectionUnmap:
    """S14-D12: section create -> map -> unmap must round-trip cleanly."""

    async def test_create_map_unmap_round_trip_succeeds(self, process_bridge: ProcessBridge) -> None:
        """A mapped section view must unmap successfully with no residual mapping.

        Args:
            process_bridge: Function-scoped, self-attached ``ProcessBridge``.
        """
        handle = await process_bridge.create_section(_SECTION_SIZE)
        base = await process_bridge.map_section(handle, _SECTION_SIZE)

        assert base > 0xFFFF, f"mapped base looks truncated/invalid: {hex(base)}"
        assert base in process_bridge.section_views
        assert _query_state(base) == MEM_COMMIT

        with structlog.testing.capture_logs() as captured:
            result = await process_bridge.unmap_section(base)

        assert result is True
        failures = [c for c in captured if c.get("event") == "section_unmap_failed"]
        assert not failures, f"unmap_section took the failure path: {failures}"

        assert base not in process_bridge.section_views
        assert handle not in process_bridge.section_handles
        assert _query_state(base) == MEM_FREE, "residual mapping remains after unmap"

        with pytest.raises(ToolError) as exc_info:
            await process_bridge.unmap_section(base)
        assert exc_info.value.details.get("code") == "SECTION_NOT_MAPPED"

    async def test_shutdown_unmaps_mapped_section_without_failure_log(self) -> None:
        """``shutdown`` must unmap a tracked section cleanly with no failure log.

        Uses a dedicated bridge instance rather than the shared fixture
        because ``shutdown`` tears down the bridge's cached DLL handles.
        """
        bridge = ProcessBridge()
        await bridge.initialize()
        handle = await bridge.create_section(_SECTION_SIZE)
        base = await bridge.map_section(handle, _SECTION_SIZE)
        assert _query_state(base) == MEM_COMMIT

        with structlog.testing.capture_logs() as captured:
            await bridge.shutdown()

        failures = [c for c in captured if c.get("event") in {"section_unmap_failed", "shutdown_unmap_section_failed"}]
        assert not failures, f"shutdown took the section-unmap failure path: {failures}"
        assert _query_state(base) == MEM_FREE, "residual mapping remains after shutdown"


class TestS14D13PatternSearchScopingCancelProgress:
    """S14-D13: pattern search must support address scoping, cancellation, and progress."""

    async def test_scoped_scan_finds_pattern_and_scans_far_fewer_bytes(self, process_bridge: ProcessBridge) -> None:
        """A tightly-scoped scan must find a known pattern while scanning a small fraction of the process.

        Args:
            process_bridge: Function-scoped, self-attached ``ProcessBridge``.
        """
        region = _alloc_scratch_region(_SCRATCH_REGION_SIZE)
        try:
            target_offset = _SCRATCH_REGION_SIZE // 2
            target_address = region + target_offset
            ctypes.memmove(target_address, _PATTERN_BYTES, len(_PATTERN_BYTES))

            regions = await process_bridge.get_memory_map()
            total_readable_bytes = sum(r.size for r in regions if "r" in r.protection)

            progress_calls: list[tuple[int, int]] = []

            def on_progress(scanned: int, total: int) -> None:
                """Record a cumulative-progress update for later assertions.

                Args:
                    scanned: Cumulative bytes scanned so far.
                    total: Total bytes selected for the whole scoped scan.
                """
                progress_calls.append((scanned, total))

            start = time.monotonic()
            matches = await process_bridge.search_pattern(
                _PATTERN_HEX,
                start_address=target_address - 4096,
                end_address=target_address + len(_PATTERN_BYTES) + 4096,
                progress_callback=on_progress,
            )
            elapsed = time.monotonic() - start

            assert target_address in matches
            assert elapsed < _SCOPED_SCAN_BOUND_SECONDS, f"scoped scan took too long: {elapsed}s"
            assert progress_calls, "progress_callback was never invoked"
            final_scanned, final_total = progress_calls[-1]
            assert final_scanned == final_total
            assert final_total < _SCOPED_BYTES_CEILING, f"scoped scan covered {final_total} bytes, expected a bounded region"
            assert final_total < total_readable_bytes, "scoped scan did not scan fewer bytes than the full process"
        finally:
            _free_scratch_region(region)

    async def test_cancel_stops_full_scan_promptly_with_partial_progress(self, process_bridge: ProcessBridge) -> None:
        """Setting ``cancel_event`` during an unscoped scan must stop it well before completion.

        Args:
            process_bridge: Function-scoped, self-attached ``ProcessBridge``.
        """
        cancel_event = threading.Event()
        progress_calls: list[tuple[int, int]] = []

        def on_progress(scanned: int, total: int) -> None:
            """Record a cumulative-progress update and trip cancellation once observed.

            Args:
                scanned: Cumulative bytes scanned so far.
                total: Total bytes selected for the whole scan.
            """
            progress_calls.append((scanned, total))

        async def trip_cancel_shortly() -> None:
            """Set the cancellation flag shortly after the scan begins."""
            await asyncio.sleep(0.05)
            cancel_event.set()

        canceller = asyncio.create_task(trip_cancel_shortly())
        start = time.monotonic()
        matches = await process_bridge.search_pattern(
            _PATTERN_HEX,
            cancel_event=cancel_event,
            progress_callback=on_progress,
        )
        elapsed = time.monotonic() - start
        await canceller

        assert cancel_event.is_set()
        assert elapsed < _CANCEL_BOUND_SECONDS, f"cancellation did not stop the scan promptly: {elapsed}s"
        assert isinstance(matches, list)
        assert progress_calls, "progress_callback was never invoked before cancellation"
        final_scanned, final_total = progress_calls[-1]
        assert final_scanned < final_total, "scan reported complete despite cancellation; cancel_event was ignored"
