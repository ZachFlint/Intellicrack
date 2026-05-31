# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``process_panel.memory_tab``.

Audit shard 14 flagged the existing memory-tab tests for invoking
``MemoryTab._format_memory`` with hand-crafted byte blobs and never reading
real process memory. These tests attach a real :class:`ProcessBridge` to the
running interpreter, read the genuine bytes at a real loaded-module image base
(which always begins with the ``MZ`` PE signature), and verify
``_format_memory`` renders those real bytes. They also drive
``MemoryTab._refresh_regions`` so the region table is populated from the real
``get_memory_map`` enumeration of this process's address space.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.panels.process_panel.memory_tab import MemoryTab
from tests._helpers.realcov_process_panel import (
    RealProcessBridgeProbe,
    close_real_bridge,
    make_real_bridge_attached_to_self,
    pump_until,
    require_windows,
    run_bridge_sync,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

_MZ_SIGNATURE = b"MZ"


@pytest.fixture
def qapp() -> Iterator[QApplication]:
    """Provide a live QApplication for widget construction.

    Yields:
        QApplication: The running application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


@pytest.fixture
def real_bridge() -> Iterator[RealProcessBridgeProbe]:
    """Provide a real ProcessBridge attached to the current process.

    Yields:
        RealProcessBridgeProbe: Bridge initialized and attached to this process.
    """
    require_windows()
    bridge = make_real_bridge_attached_to_self()
    try:
        yield bridge
    finally:
        close_real_bridge(bridge)


class _MemoryTabProbe(MemoryTab):
    """Test subclass exposing typed accessors to protected tab members."""

    def refresh_regions(self) -> None:
        """Drive the real memory-region refresh."""
        self._refresh_regions()

    def format_memory(self, data: bytes, base_addr: int, fmt: str) -> str:
        """Render real memory bytes through the production formatter.

        Args:
            data: Real bytes read from process memory.
            base_addr: Base address for offset display.
            fmt: Display format ('Hex', 'ASCII', or 'Both').

        Returns:
            str: The formatted memory string.
        """
        return self._format_memory(data, base_addr, fmt)

    def region_count(self) -> int:
        """Return the number of rows in the region table.

        Returns:
            int: Region-table row count.
        """
        return self._region_table.rowCount()

    def region_cell(self, row: int, column: int) -> str | None:
        """Return a region-table cell text.

        Args:
            row: Zero-based row index.
            column: Zero-based column index.

        Returns:
            str | None: The cell text, or None if absent.
        """
        item = self._region_table.item(row, column)
        return None if item is None else item.text()

    def region_count_label(self) -> str:
        """Return the region-count label text.

        Returns:
            str: The label text such as ``"123 regions"``.
        """
        return self._region_count.text()


@pytest.fixture
def tab(qapp: QApplication, real_bridge: RealProcessBridgeProbe) -> _MemoryTabProbe:
    """Create a MemoryTab probe wired to the real bridge and attached PID.

    Args:
        qapp: QApplication fixture (ensures Qt initialised).
        real_bridge: Real ProcessBridge attached to this process.

    Returns:
        _MemoryTabProbe: A probe driving the real bridge against this process.
    """
    del qapp
    widget = _MemoryTabProbe()
    widget.set_bridge(real_bridge)
    widget.set_attached_pid(os.getpid())
    return widget


def _ntdll_base(bridge: RealProcessBridgeProbe) -> int:
    """Resolve the real loaded base address of ntdll.dll in this process.

    Args:
        bridge: Real bridge attached to this process.

    Returns:
        int: The genuine image base of ntdll.dll.
    """
    modules = run_bridge_sync(bridge.get_modules(os.getpid()))
    for mod in modules:
        if mod.name.lower() == "ntdll.dll":
            return mod.base_address
    pytest.fail("ntdll.dll not present in real module enumeration")


def test_format_memory_renders_real_pe_header(real_bridge: RealProcessBridgeProbe, tab: _MemoryTabProbe) -> None:
    """``_format_memory`` must faithfully render bytes read from real memory.

    Reads the first 32 bytes at the genuine ntdll image base (a real PE that
    starts with ``MZ``) and verifies the formatted hex/ASCII output contains
    the real signature bytes and the real base address, proving the formatter
    operates on real process memory rather than a synthetic blob.

    Args:
        real_bridge: Real bridge attached to this process.
        tab: MemoryTab probe bound to the real bridge.
    """
    base = _ntdll_base(real_bridge)

    raw = real_bridge.read_bytes(base, 32)
    assert raw[:2] == _MZ_SIGNATURE, "real ntdll image did not start with MZ"

    rendered = tab.format_memory(raw, base, "Both")
    assert f"{base:016X}" in rendered
    assert "4D 5A" in rendered, "MZ signature bytes missing from formatted hex"
    assert "MZ" in rendered, "MZ signature missing from formatted ASCII column"


def test_format_memory_hex_matches_real_bytes(real_bridge: RealProcessBridgeProbe, tab: _MemoryTabProbe) -> None:
    """Every real byte read must appear as its two-digit hex in the output.

    Args:
        real_bridge: Real bridge attached to this process.
        tab: MemoryTab probe bound to the real bridge.
    """
    base = _ntdll_base(real_bridge)
    raw = real_bridge.read_bytes(base, 16)

    rendered = tab.format_memory(raw, base, "Hex")
    expected_hex = " ".join(f"{b:02X}" for b in raw)
    assert expected_hex in rendered


def test_region_map_populated_from_real_memory_map(qapp: QApplication, tab: _MemoryTabProbe) -> None:
    """Refresh must fill the region table from the real ``get_memory_map``.

    The current process's address space always contains committed image
    regions; the rendered region table must hold rows whose base/size columns
    parse as valid hex, and the count label must match the rendered rows.

    Args:
        qapp: Qt application driving the event loop.
        tab: MemoryTab probe bound to the real bridge.
    """
    tab.refresh_regions()
    populated = pump_until(qapp, lambda: tab.region_count() > 0)
    assert populated, "region table never populated from real get_memory_map()"

    rows = tab.region_count()
    assert rows >= 1

    first_base = tab.region_cell(0, 0)
    first_size = tab.region_cell(0, 1)
    assert first_base is not None
    assert first_size is not None
    assert int(first_base, 16) >= 0
    assert int(first_size, 16) > 0
    assert tab.region_count_label() == f"{rows} regions"


def test_region_map_contains_real_module_region(
    qapp: QApplication,
    real_bridge: RealProcessBridgeProbe,
    tab: _MemoryTabProbe,
) -> None:
    """A real loaded module's base must fall inside an enumerated region.

    The ntdll image base reported by ``get_modules`` must be covered by one of
    the real memory regions returned by ``get_memory_map``, cross-validating
    that two independent real Win32 enumerations agree.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge attached to this process.
        tab: MemoryTab probe bound to the real bridge.
    """
    ntdll_base = _ntdll_base(real_bridge)

    tab.refresh_regions()
    populated = pump_until(qapp, lambda: tab.region_count() > 0)
    assert populated

    covered = False
    for row in range(tab.region_count()):
        base_text = tab.region_cell(row, 0)
        size_text = tab.region_cell(row, 1)
        if base_text is None or size_text is None:
            continue
        base = int(base_text, 16)
        size = int(size_text, 16)
        if base <= ntdll_base < base + size:
            covered = True
            break
    assert covered, "real ntdll base not covered by any enumerated memory region"
