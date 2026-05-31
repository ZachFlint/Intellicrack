# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.ui.panels.analysis_panel`.

The audit (shard 14) flagged ``analysis_panel.py`` as having **no test file**
and demanded that the panel be proven to render *real* parsed binary data:
real section names (``.text``), real import/export symbols, real entropy, and
real navigation addresses.

These tests parse a genuine Windows System32 PE with :mod:`pefile`, build a
real :class:`~intellicrack.core.types.BridgeAnalysisSummary` from the parsed
sections / imports / exports, push it through
:meth:`BridgeAnalysisPanel.set_analysis`, and assert the panel's Qt tables hold
the verbatim values that came out of the real binary. No mocks or synthetic
byte blobs are used; the data originates entirely from the on-disk PE.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import TYPE_CHECKING

import pefile
import pytest

from intellicrack.core.types import (
    BridgeAnalysisSummary,
    ExportInfo,
    ImportInfo,
    SectionInfo,
    StringInfo,
)
from intellicrack.ui.panels.analysis_panel import BridgeAnalysisPanel


if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication


def _shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte buffer.

    Args:
        data: Raw bytes to measure.

    Returns:
        float: Entropy in bits per byte (0.0 for an empty buffer).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _sections_from_pe(pe: pefile.PE) -> list[SectionInfo]:
    """Extract real :class:`SectionInfo` records from a parsed PE.

    Args:
        pe: A fully parsed :class:`pefile.PE`.

    Returns:
        list[SectionInfo]: One record per PE section with real name, RVA,
        sizes, characteristics, and computed entropy.
    """
    sections: list[SectionInfo] = []
    for section in pe.sections:
        raw = section.get_data()
        sections.append(
            SectionInfo(
                name=section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_size=int(section.SizeOfRawData),
                characteristics=int(section.Characteristics),
                entropy=_shannon_entropy(raw),
            ),
        )
    return sections


def _imports_from_pe(pe: pefile.PE, limit: int = 40) -> list[ImportInfo]:
    """Extract real named imports from a parsed PE.

    Args:
        pe: A fully parsed :class:`pefile.PE`.
        limit: Maximum number of import entries to collect.

    Returns:
        list[ImportInfo]: Real import-table entries with DLL, function name,
        ordinal, and thunk address.
    """
    imports: list[ImportInfo] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("ascii", errors="replace")
        for imp in entry.imports:
            if imp.name is None:
                continue
            imports.append(
                ImportInfo(
                    dll=dll,
                    function=imp.name.decode("ascii", errors="replace"),
                    ordinal=int(imp.ordinal) if imp.ordinal is not None else None,
                    address=int(imp.address) if imp.address is not None else 0,
                ),
            )
            if len(imports) >= limit:
                return imports
    return imports


def _exports_from_pe(pe: pefile.PE, limit: int = 40) -> list[ExportInfo]:
    """Extract real named exports from a parsed PE.

    Args:
        pe: A fully parsed :class:`pefile.PE`.
        limit: Maximum number of export entries to collect.

    Returns:
        list[ExportInfo]: Real export-table entries with name, ordinal, and
        virtual address.
    """
    exports: list[ExportInfo] = []
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is None:
        return exports
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    for symbol in export_dir.symbols:
        if symbol.name is None:
            continue
        exports.append(
            ExportInfo(
                name=symbol.name.decode("ascii", errors="replace"),
                ordinal=int(symbol.ordinal),
                address=image_base + int(symbol.address),
            ),
        )
        if len(exports) >= limit:
            break
    return exports


def _summary_from_binary(path: Path) -> BridgeAnalysisSummary:
    """Build a real :class:`BridgeAnalysisSummary` from a real PE file.

    Args:
        path: Path to a real PE binary on disk.

    Returns:
        BridgeAnalysisSummary: Summary populated from the genuinely parsed
        sections, imports, and exports of ``path``.
    """
    pe = pefile.PE(str(path), fast_load=False)
    try:
        sections = _sections_from_pe(pe)
        imports = _imports_from_pe(pe)
        exports = _exports_from_pe(pe)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        is_64 = int(pe.OPTIONAL_HEADER.Magic) == 0x20B
    finally:
        pe.close()

    first_section = sections[0]
    strings = [
        StringInfo(
            address=image_base + first_section.virtual_address,
            value=first_section.name,
            encoding="ascii",
            section=first_section.name,
        ),
    ]

    return BridgeAnalysisSummary(
        binary_name=path.name,
        strings=strings,
        imports=imports,
        exports=exports,
        sections=sections,
        functions=[],
        format_info="PE32+" if is_64 else "PE32",
        architecture="x86_64" if is_64 else "x86",
        source_bridges=["pefile"],
        analysis_notes=[f"Parsed {len(sections)} sections from {path.name}"],
        complete=True,
    )


@pytest.fixture
def dll_summary(real_pe_dll: Path) -> BridgeAnalysisSummary:
    """Provide a real summary parsed from the System32 DLL fixture.

    Args:
        real_pe_dll: Session-scoped real PE DLL fixture (kernel32.dll).

    Returns:
        BridgeAnalysisSummary: Real summary built from the DLL.
    """
    return _summary_from_binary(real_pe_dll)


@pytest.fixture
def exe_summary(real_pe_exe: Path) -> BridgeAnalysisSummary:
    """Provide a real summary parsed from the System32 EXE fixture.

    Args:
        real_pe_exe: Session-scoped real PE executable fixture.

    Returns:
        BridgeAnalysisSummary: Real summary built from the executable.
    """
    return _summary_from_binary(real_pe_exe)


@pytest.mark.usefixtures("qapp")
class TestAnalysisPanelRendersRealSections:
    """The sections table must show the verbatim real PE section layout."""

    @staticmethod
    def test_section_count_matches_real_pe(dll_summary: BridgeAnalysisSummary) -> None:
        """The table row count must equal the number of real PE sections.

        Args:
            dll_summary: Real summary parsed from kernel32.dll.
        """
        panel = BridgeAnalysisPanel()
        panel.set_analysis(dll_summary)

        sections_table = panel._sections_table
        assert sections_table.rowCount() == len(dll_summary.sections)
        assert len(dll_summary.sections) > 0

    @staticmethod
    def test_text_section_present_with_real_values(dll_summary: BridgeAnalysisSummary) -> None:
        """A real ``.text`` section must render with its real VA and entropy.

        Args:
            dll_summary: Real summary parsed from kernel32.dll.
        """
        panel = BridgeAnalysisPanel()
        panel.set_analysis(dll_summary)
        table = panel._sections_table

        names = {
            (item.text() if (item := table.item(row, 0)) is not None else "")
            for row in range(table.rowCount())
        }
        assert ".text" in names, f"expected a real .text section, got {sorted(names)}"

        text_section = next(s for s in dll_summary.sections if s.name == ".text")
        text_row = next(
            row
            for row in range(table.rowCount())
            if (cell := table.item(row, 0)) is not None and cell.text() == ".text"
        )
        va_cell = table.item(text_row, 1)
        entropy_cell = table.item(text_row, 5)
        assert va_cell is not None
        assert entropy_cell is not None
        assert va_cell.text() == f"0x{text_section.virtual_address:08X}"
        assert entropy_cell.text() == f"{text_section.entropy:.2f}"
        assert text_section.entropy > 4.0, "real .text code section should not be near-zero entropy"

    @staticmethod
    def test_header_reflects_real_format(dll_summary: BridgeAnalysisSummary) -> None:
        """The header labels must reflect the real binary name and architecture.

        Args:
            dll_summary: Real summary parsed from kernel32.dll.
        """
        panel = BridgeAnalysisPanel()
        panel.set_analysis(dll_summary)

        assert panel._binary_label.text() == dll_summary.binary_name
        assert dll_summary.architecture in panel._arch_label.text()
        assert dll_summary.format_info in panel._format_label.text()
        assert "pefile" in panel._bridges_label.text()


@pytest.mark.usefixtures("qapp")
class TestAnalysisPanelRendersRealImportsExports:
    """Import / export tables must carry real symbol names from the PE."""

    @staticmethod
    def test_imports_table_contains_real_symbols(exe_summary: BridgeAnalysisSummary) -> None:
        """The imports table must list real imported function names.

        Args:
            exe_summary: Real summary parsed from a System32 executable.
        """
        if not exe_summary.imports:
            pytest.skip("the resolved PE executable exposes no named imports")

        panel = BridgeAnalysisPanel()
        panel.set_analysis(exe_summary)
        table = panel._imports_table
        assert table.rowCount() == len(exe_summary.imports)

        rendered = {
            (item.text() if (item := table.item(row, 1)) is not None else "")
            for row in range(table.rowCount())
        }
        expected = {imp.function for imp in exe_summary.imports}
        assert rendered == expected
        assert all(name for name in rendered), "real imports must have non-empty names"

    @staticmethod
    def test_exports_table_contains_real_kernel32_symbols(
        dll_summary: BridgeAnalysisSummary,
    ) -> None:
        """The exports table must list real kernel32 export names.

        Args:
            dll_summary: Real summary parsed from kernel32.dll.
        """
        if not dll_summary.exports:
            pytest.skip("the resolved PE DLL exposes no named exports")

        panel = BridgeAnalysisPanel()
        panel.set_analysis(dll_summary)
        table = panel._exports_table
        assert table.rowCount() == len(dll_summary.exports)

        rendered = {
            (item.text() if (item := table.item(row, 0)) is not None else "")
            for row in range(table.rowCount())
        }
        expected = {exp.name for exp in dll_summary.exports}
        assert rendered == expected
        assert all(name for name in rendered)


@pytest.mark.usefixtures("qapp")
class TestAnalysisPanelNavigation:
    """Double-clicking an address cell must emit the real parsed address."""

    @staticmethod
    def test_section_address_navigation_emits_real_va(
        dll_summary: BridgeAnalysisSummary,
        qapp: QApplication,
    ) -> None:
        """Double-clicking a section VA cell emits the real virtual address.

        Args:
            dll_summary: Real summary parsed from kernel32.dll.
            qapp: QApplication fixture driving signal delivery.
        """
        del qapp
        panel = BridgeAnalysisPanel()
        panel.set_analysis(dll_summary)

        captured: list[int] = []
        panel.address_navigate.connect(captured.append)

        text_section = next(s for s in dll_summary.sections if s.name == ".text")
        text_row = next(
            row
            for row in range(panel._sections_table.rowCount())
            if (cell := panel._sections_table.item(row, 0)) is not None and cell.text() == ".text"
        )
        panel._sections_table.cellDoubleClicked.emit(text_row, 1)

        assert captured == [text_section.virtual_address]

    @staticmethod
    def test_clear_resets_real_state(dll_summary: BridgeAnalysisSummary) -> None:
        """Clearing the panel must drop the real analysis and empty the tables.

        Args:
            dll_summary: Real summary parsed from kernel32.dll.
        """
        panel = BridgeAnalysisPanel()
        panel.set_analysis(dll_summary)
        assert panel.get_current_analysis() is dll_summary
        assert panel._sections_table.rowCount() > 0

        panel.clear()

        assert panel.get_current_analysis() is None
        assert panel._sections_table.rowCount() == 0
        assert panel._imports_table.rowCount() == 0
        assert panel._exports_table.rowCount() == 0
        assert panel._binary_label.text() == "No binary loaded"
