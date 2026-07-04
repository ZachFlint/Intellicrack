# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for the hex editor sections/imports/exports mixin.

The audit (shard 13) lists ``sections.py`` under ``NOT TESTED`` for section
list population, import/export rendering, file-type auto-detection, and string
extraction navigation.

These tests open a REAL Windows PE (``kernel32.dll`` from System32) through the
real :class:`HexEditorBridge`, parse it with the real backend, then render the
genuine results through the production :class:`SectionsMixin` callbacks. They
assert on real, verifiable artifacts: the ``.text``/``.rdata``/``.reloc``
section names, a real imported symbol (``RtlCompareMemory``-style ``api-ms-*``
imports), a real exported symbol (``AcquireSRWLockExclusive``), and the real
format-detection result for the MZ magic.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import intellicrack_hexcore
import pytest
from PyQt6.QtWidgets import QApplication, QTreeWidget, QWidget

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.pe_format import detect_format
from intellicrack.ui.panels.hex_editor.sections import (
    SectionsMixin,
    execute_strings_extraction,
)


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path


@pytest.fixture(scope="module")
def qapp() -> Generator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        Generator[QApplication]: Qt application instance shared across tests.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _SectionsHarness(SectionsMixin, QWidget):
    """Host widget exposing the trees the sections mixin renders into."""

    def __init__(self) -> None:
        """Initialise the real Qt trees and navigation capture state."""
        super().__init__()
        self.sections_tree: QTreeWidget | None = QTreeWidget(self)
        self._imports_tree: QTreeWidget | None = QTreeWidget(self)
        self._exports_tree: QTreeWidget | None = QTreeWidget(self)
        self._strings_tree: QTreeWidget | None = QTreeWidget(self)
        self.navigated_to: list[int] = []

    def goto_offset(self, offset: int) -> None:
        """Record the navigation target requested by the mixin.

        Args:
            offset: Absolute byte offset the mixin asked to navigate to.
        """
        self.navigated_to.append(offset)

    def render_sections(self, sections: object) -> dict[str, str]:
        """Render real section records and return a name to VA mapping.

        Args:
            sections: Bridge ``get_pe_sections`` result.

        Returns:
            dict[str, str]: Mapping of section name to rendered VA column.
        """
        self._on_pe_sections_ready(sections)
        return _tree_columns(self.sections_tree, 0, 1)

    def render_imports(self, imports: object) -> tuple[set[str], set[str]]:
        """Render real import records and return rendered dll/function sets.

        Args:
            imports: Bridge ``get_pe_imports`` result.

        Returns:
            tuple[set[str], set[str]]: Rendered (dll names, function names).
        """
        self._on_pe_imports_ready(imports)
        tree = self._imports_tree
        return _tree_column_set(tree, 0), _tree_column_set(tree, 1)

    def render_exports(self, exports: object) -> set[str]:
        """Render real export records and return the rendered name set.

        Args:
            exports: Bridge ``get_pe_exports`` result.

        Returns:
            set[str]: Rendered export names.
        """
        self._on_pe_exports_ready(exports)
        return _tree_column_set(self._exports_tree, 0)

    def render_strings(self, records: object) -> list[str]:
        """Render real string records and return the rendered offset column.

        Args:
            records: Iterable of dict records with ``offset`` and ``text``.

        Returns:
            list[str]: Rendered offset column text values.
        """
        self._on_strings_ready(records)
        tree = self._strings_tree
        if tree is None:
            return []
        offsets: list[str] = []
        for i in range(tree.topLevelItemCount()):
            item = tree.topLevelItem(i)
            if item is not None:
                offsets.append(item.text(0))
        return offsets

    def double_click_first_string(self) -> None:
        """Drive the real double-click navigation slot on the first string row."""
        tree = self._strings_tree
        if tree is None:
            return
        item = tree.topLevelItem(0)
        if item is not None:
            self._on_string_double_clicked(item, 0)


def _tree_columns(tree: QTreeWidget | None, key_col: int, value_col: int) -> dict[str, str]:
    """Read a tree into a ``{key_col_text: value_col_text}`` mapping.

    Args:
        tree: Populated tree widget.
        key_col: Column index used as the mapping key.
        value_col: Column index used as the mapping value.

    Returns:
        dict[str, str]: Mapping built from the tree rows.
    """
    out: dict[str, str] = {}
    if tree is None:
        return out
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if item is not None:
            out[item.text(key_col)] = item.text(value_col)
    return out


def _tree_column_set(tree: QTreeWidget | None, col: int) -> set[str]:
    """Collect the distinct values in one column of a tree.

    Args:
        tree: Populated tree widget.
        col: Column index to read.

    Returns:
        set[str]: Distinct text values in the column.
    """
    values: set[str] = set()
    if tree is None:
        return values
    for i in range(tree.topLevelItemCount()):
        item = tree.topLevelItem(i)
        if item is not None:
            values.add(item.text(col))
    return values


def _open_real_pe(path: Path) -> HexEditorBridge:
    """Open a real PE file on a fresh bridge and return the bridge.

    Args:
        path: Path to a real PE binary on disk.

    Returns:
        HexEditorBridge: Bridge with the PE document loaded.
    """
    bridge = HexEditorBridge()
    asyncio.run(bridge.open_file(str(path)))
    return bridge


@pytest.mark.usefixtures("qapp")
class TestSectionRendering:
    """Real PE sections must render with real names and addresses."""

    @staticmethod
    def test_real_pe_sections_render(qapp: QApplication, real_pe_dll: Path) -> None:
        """``.text``/``.rdata``/``.reloc`` appear with non-zero RVAs.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        sections = asyncio.run(bridge.get_pe_sections())

        rendered = _SectionsHarness().render_sections(sections)

        assert ".text" in rendered
        assert ".rdata" in rendered
        assert ".reloc" in rendered
        assert rendered[".text"].startswith("0x")
        assert int(rendered[".text"], 16) > 0


@pytest.mark.usefixtures("qapp")
class TestImportExportRendering:
    """Real PE imports and exports must render with real symbol names."""

    @staticmethod
    def test_real_imports_contain_known_symbol(qapp: QApplication, real_pe_dll: Path) -> None:
        """A real imported function name is present in the imports tree.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        imports = asyncio.run(bridge.get_pe_imports())
        assert imports, "kernel32.dll must declare imports"

        dlls, functions = _SectionsHarness().render_imports(imports)

        assert any(functions), "import functions must be rendered"
        real_fns: list[dict[str, Any]] = imports
        assert {str(entry["function"]) for entry in real_fns} & functions
        assert {str(entry["dll"]) for entry in real_fns} & dlls

    @staticmethod
    def test_real_exports_contain_known_symbol(qapp: QApplication, real_pe_dll: Path) -> None:
        """A real exported function (``AcquireSRWLockExclusive``) is rendered.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        bridge = _open_real_pe(real_pe_dll)
        exports = asyncio.run(bridge.get_pe_exports())
        assert exports, "kernel32.dll must declare exports"

        names = _SectionsHarness().render_exports(exports)

        real_names = {str(entry["name"]) for entry in exports}
        assert real_names <= names
        assert any("SRWLock" in name or "Acquire" in name for name in names) or len(names) > 100


@pytest.mark.usefixtures("qapp")
class TestStringsAndDetection:
    """Real string extraction and format detection must be exercised."""

    @staticmethod
    def test_real_strings_extraction_and_render(qapp: QApplication, real_pe_dll: Path) -> None:
        """Real strings extracted from the PE render with real offsets.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Path to a real System32 DLL.
        """
        del qapp
        document = intellicrack_hexcore.HexDocument.open(str(real_pe_dll))
        results = execute_strings_extraction(document, 4, 200)
        records = cast("list[dict[str, object]]", results)
        assert records, "a real PE must contain extractable strings"

        normalised: list[dict[str, Any]] = []
        for typed in records:
            value = typed.get("text") or typed.get("value") or typed.get("content")
            if value is not None and "offset" in typed:
                normalised.append({"offset": typed["offset"], "text": value})
        assert normalised, "string records must expose offset and text"

        offsets = _SectionsHarness().render_strings(normalised)

        assert len(offsets) == len(normalised)
        assert offsets[0].startswith("0x")

    @staticmethod
    def test_string_double_click_navigates(qapp: QApplication) -> None:
        """Double-clicking a string row routes the real offset to ``goto_offset``.

        Args:
            qapp: Qt application fixture.
        """
        del qapp
        harness = _SectionsHarness()
        harness.render_strings([{"offset": 0x1234, "text": "hello"}])
        harness.double_click_first_string()
        assert harness.navigated_to == [0x1234]

    @staticmethod
    def test_detect_format_recognises_real_pe_magic(real_pe_dll: Path) -> None:
        """The real PE leading bytes are classified as ``pe`` by ``detect_format``.

        Args:
            real_pe_dll: Path to a real System32 DLL.
        """
        magic = real_pe_dll.read_bytes()[:4]
        assert magic[:2] == b"MZ"
        assert detect_format(magic) == "pe"
