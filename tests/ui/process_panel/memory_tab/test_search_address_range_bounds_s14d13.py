# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for A5 (S14-D13, Low): pattern-search range bounding must reach the UI.

Before the fix, ``MemoryTab._build_search_tab`` exposed only a pattern field
and a Search button; ``_on_search`` always called
``ProcessBridge.search_pattern`` without ``start_address``/``end_address``,
so the backend's already-implemented address-range clipping was unreachable
from the panel. The fix adds Start/End ``QLineEdit`` fields and threads their
parsed values through to the bridge call.

``TestBoundedSearchConfinesResultsToRange`` drives the real
``MemoryTab._on_search`` entry point against a real ``ProcessBridge``
self-attached to the live test process (``os.getpid()``), with a known
sentinel byte pattern written into a real ``VirtualAlloc``-backed scratch
region at two addresses far apart. A narrow bound around only the first
address must find that address and must NOT find the second (proving results
are confined to the requested range); widening the bound to cover the whole
scratch region must then surface the second address too, proving the earlier
exclusion was the bound doing real filtering rather than a vacuous absence of
any out-of-range match. No mocking is involved in that scan: the bridge, the
scratch memory, and the Qt async dispatch are all real.

``TestInvalidAddressRangeRejected`` and
``TestEmptyBoundsDispatchUnboundedSearch`` cover the fast, mock-backed
wiring paths: invalid start/end text must block dispatch with an inline
error, ``start >= end`` must be rejected, and empty fields must still reach
the bridge as ``start_address=None, end_address=None`` (today's unbounded
behavior, preserved).
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import time
from typing import TYPE_CHECKING, Final
from unittest.mock import MagicMock

import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.ui.panels.process_panel import memory_tab as _memory_tab_mod
from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator

    from PyQt6.QtWidgets import QApplication

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")

_REGION_SIZE: Final[int] = 0x100000
_NEAR_OFFSET: Final[int] = 0x10000
_FAR_OFFSET: Final[int] = _REGION_SIZE - 0x10000
_SENTINEL: Final[bytes] = bytes.fromhex("A514D13FCAFEBABE")
_SENTINEL_HEX: Final[str] = " ".join(f"{b:02X}" for b in _SENTINEL)
_NARROW_MARGIN: Final[int] = 0x1000
_MEM_COMMIT_RESERVE: Final[int] = 0x1000 | 0x2000
_PAGE_READWRITE: Final[int] = 0x04
_MEM_RELEASE: Final[int] = 0x8000
_MAX_WAIT_S: Final[float] = 15.0
_POLL_INTERVAL_S: Final[float] = 0.02


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


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Drive an async bridge coroutine to completion on a private event loop.

    Args:
        coro: The awaitable coroutine to execute.

    Returns:
        T: The resolved result of the coroutine.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _pump_until(qapp: QApplication, predicate: Callable[[], bool], timeout_s: float = _MAX_WAIT_S) -> bool:
    """Pump the Qt event loop until ``predicate`` is satisfied or ``timeout_s`` elapses.

    Args:
        qapp: The QApplication instance whose event loop is pumped.
        predicate: Zero-argument callable polled after each pump.
        timeout_s: Maximum wall-clock seconds to keep pumping.

    Returns:
        bool: True if ``predicate`` became truthy before the deadline.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        qapp.processEvents()
        time.sleep(_POLL_INTERVAL_S)
    return bool(predicate())


def _collect_result_addresses(tab: MemoryTab) -> list[int]:
    """Read every address currently listed in the search-results table.

    Args:
        tab: MemoryTab whose ``_search_results`` table is read.

    Returns:
        list[int]: Parsed integer addresses, one per table row.
    """
    table = tab._search_results
    addresses: list[int] = []
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        assert item is not None, f"search-results row {row} has no address item"
        addresses.append(int(item.text(), 16))
    return addresses


@pytest.fixture
def bridge() -> Generator[ProcessBridge]:
    """Create, initialize, and self-attach a real ``ProcessBridge``.

    Yields:
        ProcessBridge: Bridge attached to the current test process; shut
            down on teardown.
    """
    b = ProcessBridge()
    _run(b.initialize())
    _run(b.open_process(os.getpid()))
    yield b
    _run(b.shutdown())


@pytest.fixture
def tab(qapp: QApplication, bridge: ProcessBridge) -> MemoryTab:
    """Create a ``MemoryTab`` wired to the real, self-attached bridge.

    Args:
        qapp: Session QApplication fixture from ``tests/ui/conftest.py``.
        bridge: Real ``ProcessBridge`` fixture attached to the current process.

    Returns:
        MemoryTab: Tab with the bridge set and ``os.getpid()`` marked attached.
    """
    assert qapp is not None
    t = MemoryTab()
    t.set_bridge(bridge)
    t.set_attached_pid(os.getpid())
    return t


@pytest.fixture
def scratch_region() -> Generator[int]:
    """Commit and later release a 1 MiB scratch region in the current process.

    Yields:
        int: Base address of the committed scratch region.
    """
    region = _alloc_scratch_region(_REGION_SIZE)
    try:
        yield region
    finally:
        _free_scratch_region(region)


@pytest.fixture
def sentinel_region(scratch_region: int) -> tuple[int, int, int]:
    """Write the sentinel pattern into a scratch region at two far-apart offsets.

    Args:
        scratch_region: Base address of the committed scratch region.

    Returns:
        tuple[int, int, int]: ``(region_base, near_address, far_address)``.
    """
    near_address = scratch_region + _NEAR_OFFSET
    far_address = scratch_region + _FAR_OFFSET
    ctypes.memmove(near_address, _SENTINEL, len(_SENTINEL))
    ctypes.memmove(far_address, _SENTINEL, len(_SENTINEL))
    return scratch_region, near_address, far_address


class TestBoundedSearchConfinesResultsToRange:
    """A5/S14-D13: a bounded search must be confined to its address range."""

    def test_narrow_bound_excludes_far_match_and_wide_bound_reveals_it(
        self,
        tab: MemoryTab,
        qapp: QApplication,
        sentinel_region: tuple[int, int, int],
    ) -> None:
        """Narrow bound finds only the near sentinel; widening the bound reveals the far one too.

        Args:
            tab: MemoryTab fixture wired to a real, self-attached bridge.
            qapp: Session QApplication fixture, pumped to drive the off-thread scan.
            sentinel_region: ``(region_base, near_address, far_address)`` fixture.
        """
        region_base, near_address, far_address = sentinel_region

        tab._search_pattern.setText(_SENTINEL_HEX)
        tab._search_start_addr.setText(f"0x{near_address - _NARROW_MARGIN:X}")
        tab._search_end_addr.setText(f"0x{near_address + len(_SENTINEL) + _NARROW_MARGIN:X}")
        tab._on_search()

        completed = _pump_until(qapp, lambda: not tab._search_cancel_btn.isEnabled())
        assert completed, "narrow-bound search never completed"

        narrow_addresses = _collect_result_addresses(tab)
        assert near_address in narrow_addresses, (
            f"narrow-bound search must find the in-range sentinel at {hex(near_address)}; got {[hex(a) for a in narrow_addresses]}"
        )
        assert far_address not in narrow_addresses, (
            f"narrow-bound search must exclude the out-of-range sentinel at {hex(far_address)}; got "
            f"{[hex(a) for a in narrow_addresses]} -- the range bound is not filtering"
        )

        tab._search_start_addr.setText(f"0x{region_base:X}")
        tab._search_end_addr.setText(f"0x{region_base + _REGION_SIZE:X}")
        tab._on_search()

        completed = _pump_until(qapp, lambda: not tab._search_cancel_btn.isEnabled())
        assert completed, "wide-bound search never completed"

        wide_addresses = _collect_result_addresses(tab)
        assert near_address in wide_addresses
        assert far_address in wide_addresses, (
            f"widening the bound to cover the whole scratch region must reveal the far sentinel at "
            f"{hex(far_address)} that the narrow bound excluded -- otherwise the narrow result was "
            f"vacuous rather than a real range filter; got {[hex(a) for a in wide_addresses]}"
        )


def _fail_if_dispatched(*args: object, **kwargs: object) -> None:
    """Record that a dispatch happened; used to prove invalid input blocks it.

    Args:
        *args: Positional arguments passed by the caller (unused).
        **kwargs: Keyword arguments passed by the caller (unused).
    """
    del args, kwargs
    pytest.fail("run_bridge_coroutine_logged must not be called for invalid input")


class TestInvalidAddressRangeRejected:
    """Invalid start/end text, and start >= end, must block dispatch with an inline error."""

    def test_invalid_start_address_blocks_dispatch_and_shows_inline_error(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unparseable Start field must not dispatch and must show an inline error.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        assert qapp is not None
        t = MemoryTab()
        t.set_bridge(MagicMock())
        t.set_attached_pid(1234)
        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        t._search_pattern.setText("90 90")
        t._search_start_addr.setText("not_a_hex_address")
        t._on_search()

        assert "not_a_hex_address" in t._search_status.text(), (
            f"expected the bad start-address text in the inline error; got {t._search_status.text()!r}"
        )
        assert t._search_status.text() != "Searching...", "an invalid start address must not start a scan"

    def test_invalid_end_address_blocks_dispatch_and_shows_inline_error(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An unparseable End field must not dispatch and must show an inline error.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        assert qapp is not None
        t = MemoryTab()
        t.set_bridge(MagicMock())
        t.set_attached_pid(1234)
        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        t._search_pattern.setText("90 90")
        t._search_start_addr.setText("0x1000")
        t._search_end_addr.setText("ZZZNOTANADDR")
        t._on_search()

        assert "ZZZNOTANADDR" in t._search_status.text(), (
            f"expected the bad end-address text in the inline error; got {t._search_status.text()!r}"
        )
        assert t._search_status.text() != "Searching...", "an invalid end address must not start a scan"

    def test_start_greater_than_end_blocks_dispatch_with_clear_message(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``start > end`` (both valid hex) must not dispatch and must explain the rejection.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        assert qapp is not None
        t = MemoryTab()
        t.set_bridge(MagicMock())
        t.set_attached_pid(1234)
        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        t._search_pattern.setText("90 90")
        t._search_start_addr.setText("0x2000")
        t._search_end_addr.setText("0x1000")
        t._on_search()

        message = t._search_status.text()
        lowered = message.lower()
        assert "start" in lowered, f"expected a start/end range message; got {message!r}"
        assert "end" in lowered, f"expected a start/end range message; got {message!r}"
        assert message != "Searching...", "start > end must not start a scan"

    def test_start_equal_to_end_blocks_dispatch(
        self,
        qapp: QApplication,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``start == end`` (both valid hex) must not dispatch a zero-width range.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        assert qapp is not None
        t = MemoryTab()
        t.set_bridge(MagicMock())
        t.set_attached_pid(1234)
        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", _fail_if_dispatched)

        t._search_pattern.setText("90 90")
        t._search_start_addr.setText("0x1000")
        t._search_end_addr.setText("0x1000")
        t._on_search()

        assert t._search_status.text() != "Searching...", "start == end must not start a scan"


class TestEmptyBoundsDispatchUnboundedSearch:
    """Leaving both address fields empty must preserve today's unbounded behavior."""

    def test_empty_bounds_reach_bridge_as_none(self, qapp: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
        """With Start/End left empty, ``search_pattern`` must be called with both bounds ``None``.

        Args:
            qapp: Session QApplication fixture.
            monkeypatch: pytest monkeypatch fixture.
        """
        assert qapp is not None
        monkeypatch.setattr(_memory_tab_mod, "run_bridge_coroutine_logged", lambda *_a, **_k: None)

        t = MemoryTab()
        mock_bridge = MagicMock()
        t.set_bridge(mock_bridge)
        t.set_attached_pid(1234)

        t._search_pattern.setText("90 90")
        t._search_start_addr.setText("")
        t._search_end_addr.setText("")
        t._on_search()

        mock_bridge.search_pattern.assert_called_once()
        call_kwargs = mock_bridge.search_pattern.call_args.kwargs
        assert "start_address" in call_kwargs, "start_address must be passed through explicitly, even when empty"
        assert "end_address" in call_kwargs, "end_address must be passed through explicitly, even when empty"
        assert call_kwargs["start_address"] is None
        assert call_kwargs["end_address"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
