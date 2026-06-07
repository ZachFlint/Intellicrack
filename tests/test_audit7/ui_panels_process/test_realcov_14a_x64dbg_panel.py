# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""FIX UNIT 14a real-data coverage for ``x64dbg_panel``.

Audit shard 14 marked ``x64dbg_panel.py`` as a CRITICAL coverage gap: no
dedicated panel test existed, so the disassembly, register, module, section,
export, and memory-dump rendering paths were never validated against real
data. The live x64dbg debugger backend is not present in the test container,
so these tests cannot drive the bridge end-to-end; that integration path is
documented as a skip. Instead they feed the panel's *render* methods data
produced from REAL binaries by the SAME engines the bridge uses in production:

* ``_apply_disassembly`` is fed real ``DisassemblyLine`` objects decoded by
  Capstone (the bridge's own disassembler) from the real ``.text`` section of
  ``C:/Windows/System32/kernel32.dll``; the rendered view must contain the
  real instruction mnemonics and addresses Capstone produced.
* ``_apply_modules`` is fed real ``ModuleInfo`` built from real System32 DLLs.
* ``_apply_module_sections`` / ``_apply_module_exports`` are fed real PE
  section and export records parsed from a real DLL (e.g. ``LoadLibraryA``).
* ``_on_mem_read_success`` is fed the real MZ-prefixed bytes of a real PE.

This proves the panel renders genuine tool data correctly, which is the audit
mandate, without requiring a live debugger.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.base import DisassemblyLine
from intellicrack.core.types import ModuleInfo
from intellicrack.ui.panels.x64dbg_panel import X64DbgPanel


if TYPE_CHECKING:
    from collections.abc import Iterator
    from types import ModuleType

    from PyQt6.QtWidgets import QApplication, QTableWidget


def _capstone() -> ModuleType:
    """Import the Capstone disassembler module.

    Imported via :func:`importlib.import_module` so the untyped third-party
    surface is treated as a plain module, mirroring how the production
    ``X64DbgBridge`` consumes Capstone.

    Returns:
        ModuleType: The imported capstone module.
    """
    return importlib.import_module("capstone")


def _lief() -> ModuleType:
    """Import the LIEF binary-parsing module.

    Returns:
        ModuleType: The imported lief module.
    """
    return importlib.import_module("lief")


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="x64dbg panel real-data rendering uses real System32 PE binaries",
)

_KERNEL32 = "C:/Windows/System32/kernel32.dll"


def _column_texts(table: QTableWidget, column: int) -> set[str]:
    """Collect the text of every non-empty cell in a table column.

    Args:
        table: The table widget to read.
        column: Zero-based column index.

    Returns:
        set[str]: The text of each populated cell in the column.
    """
    texts: set[str] = set()
    for row in range(table.rowCount()):
        item = table.item(row, column)
        if item is not None:
            texts.add(item.text())
    return texts


class _X64DbgPanelProbe(X64DbgPanel):
    """Test subclass exposing typed accessors to protected render members.

    Accessing the panel's protected render methods and widgets from a derived
    class keeps the tests fully type-correct (protected members are accessible
    in subclasses) while still driving the real production rendering code.
    """

    def render_disassembly(self, lines: list[DisassemblyLine]) -> str:
        """Render real disassembly lines and return the resulting view text.

        Args:
            lines: Real ``DisassemblyLine`` records to render.

        Returns:
            str: The plain text of the disassembly view after rendering.
        """
        self._apply_disassembly(lines)
        return self._disasm_view.toPlainText()

    def render_modules(self, modules: list[ModuleInfo]) -> None:
        """Render real module records into the module table.

        Args:
            modules: Real ``ModuleInfo`` records to render.
        """
        self._apply_modules(modules)

    def module_names(self) -> set[str]:
        """Return the module names rendered in the module table.

        Returns:
            set[str]: Names rendered in the first module-table column.
        """
        return _column_texts(self._module_table, 0)

    def module_size_hex(self, row: int) -> str | None:
        """Return the rendered size cell text for a module row.

        Args:
            row: Zero-based module-table row index.

        Returns:
            str | None: The size column text, or None if absent.
        """
        item = self._module_table.item(row, 2)
        return None if item is None else item.text()

    def render_sections(self, sections: list[dict[str, object]]) -> None:
        """Render real PE section records into the detail table.

        Args:
            sections: Real section dicts to render.
        """
        self._apply_module_sections(sections)

    def render_exports(self, exports: list[dict[str, object]]) -> None:
        """Render real PE export records into the detail table.

        Args:
            exports: Real export dicts to render.
        """
        self._apply_module_exports(exports)

    def detail_names(self) -> set[str]:
        """Return the names rendered in the module-detail table.

        Returns:
            set[str]: Names rendered in the first detail-table column.
        """
        return _column_texts(self._mod_detail_table, 0)

    def detail_row_count(self) -> int:
        """Return the number of rows in the module-detail table.

        Returns:
            int: Row count of the detail table.
        """
        return self._mod_detail_table.rowCount()

    def module_row_count(self) -> int:
        """Return the number of rows in the module table.

        Returns:
            int: Row count of the module table.
        """
        return self._module_table.rowCount()

    def detail_cell(self, row: int, column: int) -> str | None:
        """Return the text of a specific cell in the module-detail table.

        Args:
            row: Zero-based row index.
            column: Zero-based column index.

        Returns:
            str | None: The cell text, or ``None`` if the cell is absent.
        """
        item = self._mod_detail_table.item(row, column)
        return None if item is None else item.text()

    def render_memory(self, address: int, data: bytes) -> str:
        """Render a real memory read and return the hex-dump text.

        Args:
            address: Base address used for the dump.
            data: Real bytes to render.

        Returns:
            str: The plain text of the memory dump after rendering.
        """
        self._on_mem_read_success(address, data)
        return self._mem_dump.toPlainText()


@pytest.fixture
def panel(qapp: QApplication) -> Iterator[_X64DbgPanelProbe]:
    """Create an X64DbgPanel probe for rendering tests.

    Args:
        qapp: Session QApplication fixture (ensures Qt initialised).

    Yields:
        _X64DbgPanelProbe: A freshly constructed panel probe.
    """
    del qapp
    widget = _X64DbgPanelProbe()
    yield widget
    widget.deleteLater()


def _resolve_kernel32() -> Path:
    """Resolve the real kernel32.dll path, skipping if absent.

    Returns:
        Path: Validated path to the real kernel32 PE.
    """
    path = Path(_KERNEL32)
    if not path.is_file():
        pytest.skip(f"Real PE {path} not present")
    return path


def _real_disassembly_lines(count: int) -> tuple[list[DisassemblyLine], int]:
    """Decode real instructions from kernel32's ``.text`` section via Capstone.

    Builds ``DisassemblyLine`` objects exactly as
    ``X64DbgBridge._capstone_disassemble`` does, so the panel renders genuine
    machine-code mnemonics from a real binary.

    Args:
        count: Maximum number of instructions to decode.

    Returns:
        tuple[list[DisassemblyLine], int]: The decoded lines and the virtual
            start address used for the first instruction.
    """
    lief = _lief()
    capstone = _capstone()

    path = _resolve_kernel32()
    binary = lief.parse(str(path))
    if binary is None:
        pytest.skip("lief could not parse real kernel32.dll")
    text = next((s for s in binary.sections if s.name == ".text"), None)
    if text is None:
        pytest.skip("kernel32.dll has no .text section")

    start_va = int(binary.optional_header.imagebase) + int(text.virtual_address)
    data = bytes(text.content)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    lines: list[DisassemblyLine] = []
    for instr in md.disasm(data, start_va):
        lines.append(
            DisassemblyLine(
                address=int(instr.address),
                bytes_str=" ".join(f"{b:02x}" for b in bytes(instr.bytes)),
                mnemonic=str(instr.mnemonic),
                operands=str(instr.op_str),
                comment=None,
            ),
        )
        if len(lines) >= count:
            break
    if not lines:
        pytest.skip("Capstone produced no instructions from real .text")
    return lines, start_va


def test_apply_disassembly_renders_real_mnemonics(panel: _X64DbgPanelProbe) -> None:
    """The disassembly view must render real Capstone-decoded instructions.

    Every decoded instruction's address and mnemonic from the real kernel32
    ``.text`` section must appear in the rendered view text, proving the panel
    correctly displays genuine disassembly.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    lines, _start = _real_disassembly_lines(20)
    rendered = panel.render_disassembly(lines)
    assert rendered, "disassembly view empty after applying real lines"

    for dl in lines:
        assert f"0x{dl.address:016X}" in rendered, f"address {dl.address:#x} not rendered"
        assert dl.mnemonic in rendered, f"mnemonic {dl.mnemonic!r} not rendered"

    rendered_first_line = rendered.splitlines()[0]
    assert lines[0].mnemonic in rendered_first_line
    assert lines[0].bytes_str in rendered_first_line


def test_apply_disassembly_line_count_matches_real(panel: _X64DbgPanelProbe) -> None:
    """The number of rendered lines must equal the decoded instruction count.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    lines, _start = _real_disassembly_lines(15)
    rendered = panel.render_disassembly(lines)
    rendered_lines = [ln for ln in rendered.splitlines() if ln.strip()]
    assert len(rendered_lines) == len(lines)


def test_apply_modules_renders_real_system_dlls(panel: _X64DbgPanelProbe) -> None:
    """The module table must render real System32 module records.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    candidates = ["kernel32.dll", "ntdll.dll", "user32.dll"]
    modules: list[ModuleInfo] = []
    for idx, name in enumerate(candidates):
        path = Path("C:/Windows/System32") / name
        if not path.is_file():
            continue
        size = path.stat().st_size
        modules.append(
            ModuleInfo(
                name=name,
                path=path,
                base_address=0x180000000 + idx * 0x10000000,
                size=size,
                entry_point=0,
            ),
        )
    if not modules:
        pytest.skip("No real System32 DLLs present")

    panel.render_modules(modules)

    assert panel.module_row_count() == len(modules)
    assert {m.name for m in modules} <= panel.module_names()
    first_size = panel.module_size_hex(0)
    assert first_size is not None
    assert int(first_size, 16) == modules[0].size


def _real_pe_sections() -> list[dict[str, object]]:
    """Parse real PE sections from kernel32.dll into bridge-shaped dicts.

    Returns:
        list[dict[str, object]]: Section records keyed name/address/size/
            characteristics as the bridge's ``get_module_sections`` emits.
    """
    lief = _lief()
    path = _resolve_kernel32()
    binary = lief.parse(str(path))
    if binary is None:
        pytest.skip("lief could not parse real kernel32.dll")
    image_base = int(binary.optional_header.imagebase)
    return [
        {
            "name": str(sec.name),
            "address": hex(image_base + int(sec.virtual_address)),
            "size": hex(int(sec.virtual_size)),
            "characteristics": hex(int(sec.characteristics)),
        }
        for sec in binary.sections
    ]


def test_apply_module_sections_renders_real_pe_sections(panel: _X64DbgPanelProbe) -> None:
    """Section detail table must render real PE section names.

    A real Windows DLL always carries a ``.text`` code section and an
    ``.rdata`` read-only data section; both must appear in the rendered table.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    sections = _real_pe_sections()
    panel.render_sections(sections)

    assert panel.detail_row_count() == len(sections)
    rendered = panel.detail_names()
    assert ".text" in rendered
    assert ".rdata" in rendered


def _real_pe_exports() -> list[dict[str, object]]:
    """Parse real PE exports from kernel32.dll into bridge-shaped dicts.

    Returns:
        list[dict[str, object]]: Export records keyed name/ordinal/address.
    """
    lief = _lief()
    path = _resolve_kernel32()
    binary = lief.parse(str(path))
    if binary is None:
        pytest.skip("lief could not parse real kernel32.dll")
    export = binary.get_export()
    if export is None:
        pytest.skip("kernel32.dll exposes no export table")
    return [
        {
            "name": str(entry.name),
            "ordinal": int(entry.ordinal),
            "address": hex(int(entry.address)),
        }
        for entry in export.entries
    ]


def test_apply_module_exports_renders_real_exports(panel: _X64DbgPanelProbe) -> None:
    """Export detail table must render real exported function names.

    ``kernel32.dll`` always exports ``LoadLibraryA``; the rendered export table
    must contain it, proving real export data flows through the panel.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    exports = _real_pe_exports()
    panel.render_exports(exports)

    assert panel.detail_row_count() == len(exports)
    assert "LoadLibraryA" in panel.detail_names()


def test_apply_module_exports_renders_exact_cell_values(panel: _X64DbgPanelProbe) -> None:
    """Each export row must render name (col 0), ordinal (col 1), and address (col 2).

    The test locates the ``LoadLibraryA`` row by scanning column 0, then
    verifies that column 1 carries its ordinal as a non-empty string and
    column 2 carries a hex address beginning with ``0x``.  This catches a
    regression where only column 0 is populated (the existing test) but
    columns 1 and 2 silently lose their values.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    exports = _real_pe_exports()
    panel.render_exports(exports)

    load_library_row: int | None = None
    for row in range(panel.detail_row_count()):
        name_cell = panel.detail_cell(row, 0)
        if name_cell == "LoadLibraryA":
            load_library_row = row
            break

    assert load_library_row is not None, "LoadLibraryA row not found in rendered export table"

    ordinal_cell = panel.detail_cell(load_library_row, 1)
    assert ordinal_cell is not None, "LoadLibraryA ordinal cell (col 1) is None"
    assert ordinal_cell.strip(), "LoadLibraryA ordinal cell is empty string"
    int(ordinal_cell)

    address_cell = panel.detail_cell(load_library_row, 2)
    assert address_cell is not None, "LoadLibraryA address cell (col 2) is None"
    assert address_cell.startswith("0x"), f"LoadLibraryA address cell expected hex string starting with '0x', got {address_cell!r}"


def test_on_mem_read_success_renders_real_pe_header(panel: _X64DbgPanelProbe) -> None:
    """The memory dump must render the real bytes of a real PE header.

    Reads the first 64 bytes of the real kernel32.dll file (which begin with
    the ``MZ`` signature) and verifies the hex dump output reflects them.

    Args:
        panel: The X64DbgPanel probe under test.
    """
    path = _resolve_kernel32()
    raw = path.read_bytes()[:64]
    assert raw[:2] == b"MZ", "real PE did not start with MZ"

    address = 0x140000000
    rendered = panel.render_memory(address, raw)
    assert rendered, "memory dump empty after applying real bytes"
    assert "4D 5A" in rendered, "MZ signature bytes missing from hex dump"
    assert "MZ" in rendered, "MZ signature missing from hex dump ASCII column"
