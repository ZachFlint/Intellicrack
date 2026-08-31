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


def _module_base(bridge: RealProcessBridgeProbe, module_name: str) -> tuple[int, int]:
    """Resolve a real loaded module's base address and image size.

    Args:
        bridge: Real bridge attached to this process.
        module_name: Lower-case module file name (e.g. ``"kernel32.dll"``).

    Returns:
        tuple[int, int]: ``(base_address, image_size)`` from the real
        ``get_modules`` enumeration.
    """
    modules = run_bridge_sync(bridge.get_modules(os.getpid()))
    for mod in modules:
        if mod.name.lower() == module_name:
            return mod.base_address, mod.size
    pytest.fail(f"{module_name} not present in real module enumeration")


def _rendered_region_bases(tab: _MemoryTabProbe) -> dict[int, tuple[int, str, str, str | None]]:
    """Index the rendered region table by base address.

    Args:
        tab: MemoryTab probe whose region table has been populated.

    Returns:
        dict[int, tuple[int, str, str, str | None]]: Map from region base
        address to ``(size, protection, type, module_name)`` as rendered.
    """
    rendered: dict[int, tuple[int, str, str, str | None]] = {}
    for row in range(tab.region_count()):
        base_text = tab.region_cell(row, 0)
        size_text = tab.region_cell(row, 1)
        if base_text is None or size_text is None:
            continue
        rendered[int(base_text, 16)] = (
            int(size_text, 16),
            tab.region_cell(row, 2) or "",
            tab.region_cell(row, 4) or "",
            tab.region_cell(row, 5),
        )
    return rendered


def test_region_map_rows_round_trip_real_image_regions(
    qapp: QApplication,
    real_bridge: RealProcessBridgeProbe,
    tab: _MemoryTabProbe,
) -> None:
    """Rendered image rows must exactly reproduce the real ``MemoryRegion`` records.

    An independent ``get_memory_map`` enumeration is the oracle. The comparison
    is scoped to ``MEM_IMAGE`` regions (loaded DLL sections), which are mapped
    copy-on-write and therefore stable across two near-instant reads, unlike
    dynamic stack/heap regions that can resize between calls. Every rendered
    image row's base, size, protection, state, type, and module name must match
    the corresponding real field exactly, catching any swap, truncation, or
    hex-formatting regression that a bare ``rows >= 1`` check would miss.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge supplying the independent oracle enumeration.
        tab: MemoryTab probe bound to the real bridge.
    """
    oracle = run_bridge_sync(real_bridge.get_memory_map(resolve_names=True))
    image_oracle = {region.base_address: region for region in oracle if region.type == "image"}
    assert len(image_oracle) > 100, f"expected many real image regions in this process, got {len(image_oracle)}"

    tab.refresh_regions()
    populated = pump_until(qapp, lambda: tab.region_count() > 0)
    assert populated, "region table never populated from real get_memory_map()"

    rows = tab.region_count()
    assert tab.region_count_label() == f"{rows} regions"

    matched = 0
    for row in range(rows):
        base_text = tab.region_cell(row, 0)
        assert base_text is not None
        region = image_oracle.get(int(base_text, 16))
        if region is None:
            continue
        matched += 1
        base = region.base_address
        assert tab.region_cell(row, 1) == f"0x{region.size:X}", f"size mismatch at base 0x{base:X}"
        assert tab.region_cell(row, 2) == region.protection, f"protection mismatch at base 0x{base:X}"
        assert tab.region_cell(row, 3) == region.state, f"state mismatch at base 0x{base:X}"
        assert tab.region_cell(row, 4) == region.type, f"type mismatch at base 0x{base:X}"
        assert tab.region_cell(row, 5) == (region.module_name or ""), f"module mismatch at base 0x{base:X}"

    assert matched >= len(image_oracle) - 8, f"only {matched}/{len(image_oracle)} real image regions matched in the rendered table"


def test_region_map_pins_real_module_header_region(
    qapp: QApplication,
    real_bridge: RealProcessBridgeProbe,
    tab: _MemoryTabProbe,
) -> None:
    """Each real module's image base must render as an exact image region.

    For both ntdll.dll and kernel32.dll, the base reported by the independent
    ``get_modules`` enumeration must appear verbatim as a region base in the
    table; that region must be typed ``image``, name the real module, be
    readable, and the module's full ``[base, base + size)`` image span must be
    covered by contiguous rendered image regions. Because these are loaded code
    modules, the span must additionally contain at least one executable image
    region (the ``.text`` section, rendered ``r-x``). A base off by a page, a
    halved size, a dropped image flag, or a lost execute bit fails this gate.

    Args:
        qapp: Qt application driving the event loop.
        real_bridge: Real bridge supplying the independent module oracle.
        tab: MemoryTab probe bound to the real bridge.
    """
    tab.refresh_regions()
    populated = pump_until(qapp, lambda: tab.region_count() > 0)
    assert populated, "region table never populated from real get_memory_map()"

    rendered = _rendered_region_bases(tab)

    for module_name in ("ntdll.dll", "kernel32.dll"):
        base, image_size = _module_base(real_bridge, module_name)
        assert base in rendered, f"{module_name} image base 0x{base:X} absent from rendered region bases"

        size, protection, region_type, region_module = rendered[base]
        assert region_type == "image", f"{module_name} base region must be MEM_IMAGE, got {region_type!r}"
        assert "r" in protection, f"{module_name} header region must be readable, got {protection!r}"
        assert region_module is not None, f"{module_name} region must carry a resolved module name, got None"
        assert module_name in region_module.lower(), f"{module_name} region must name the real module, got {region_module!r}"
        assert size > 0, f"{module_name} header region size must be positive, got 0x{size:X}"
        assert size <= image_size, f"{module_name} header region size 0x{size:X} exceeds image span 0x{image_size:X}"

        module_end = base + image_size
        executable_image_seen = False
        cursor = base
        while cursor < module_end and cursor in rendered:
            seg_size, seg_protection, seg_type, _ = rendered[cursor]
            if seg_type == "image" and "x" in seg_protection:
                executable_image_seen = True
            cursor += seg_size
        assert cursor >= module_end, (
            f"{module_name} image span [0x{base:X}, 0x{module_end:X}) not fully covered by contiguous regions; "
            f"coverage stopped at 0x{cursor:X}"
        )
        assert executable_image_seen, (
            f"{module_name} is a loaded code module but no executable image region was rendered within its span "
            f"[0x{base:X}, 0x{module_end:X})"
        )
