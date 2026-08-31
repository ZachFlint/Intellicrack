# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.ui.panels.cutter_tabs`.

The audit flagged the Cutter analysis tabs as having **no dedicated test**: the
panel that renders symbols, headers, sections, and hexdumps from real binary
analysis was never exercised against real data.

A live Cutter/Rizin server is genuine external infrastructure and is absent in
the container, so these tests do not stand up a server. Instead they build the
exact domain objects a real :class:`CutterBridge` query returns
(:class:`SymbolInfo`, :class:`HeaderInfo`, :class:`SectionInfo`,
:class:`StringInfo`) from a **real** Windows System32 PE parsed with
:mod:`pefile`, then drive each tab's real ``_apply_data`` rendering path and
assert the Qt tables hold the verbatim real values (real export symbol names,
real section names, real virtual addresses). The hexdump tab is fed a real
hexdump string rendered from real ``.text`` bytes. The rendering logic under
test is the production code; only the network round trip to the server is
elided, exactly as the audit's "protocol-correct real data" guidance permits.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pefile
import pytest

from intellicrack.core.types import (
    HeaderInfo,
    SectionInfo,
    StringInfo,
    SymbolInfo,
)
from intellicrack.ui.panels.cutter_tabs import (
    AllStringsTab,
    HeadersTab,
    HexdumpTab,
    SymbolsTab,
)


if TYPE_CHECKING:
    from pathlib import Path

    from intellicrack.bridges.cutter import CutterBridge


class _RecordingHexBridge:
    """Cutter bridge stub recording hexdump calls for the invalid-input guard.

    The hexdump tab parses the address input *before* dispatching to the
    bridge, so this stub exists only to confirm the guard short-circuits and
    never reaches the bridge on malformed input.

    Attributes:
        calls: Recorded ``(address, length)`` hexdump invocations.
    """

    calls: list[tuple[int, int]]

    def __init__(self) -> None:
        """Initialise an empty call log."""
        self.calls = []

    def hexdump(self, address: int, length: int) -> str:
        """Record an invocation; reaching this is a guard failure.

        Args:
            address: Requested dump address.
            length: Requested dump length.

        Returns:
            str: An empty string (never expected to be produced in the test).
        """
        self.calls.append((address, length))
        return ""


def _real_symbols(path: Path, limit: int = 20) -> list[SymbolInfo]:
    """Build real :class:`SymbolInfo` records from a PE export table.

    Args:
        path: Path to a real PE binary.
        limit: Maximum number of symbols to collect.

    Returns:
        list[SymbolInfo]: Real export symbols with real names and addresses.
    """
    pe = pefile.PE(str(path), fast_load=False)
    try:
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        raw = [] if export_dir is None else list(export_dir.symbols)
    finally:
        pe.close()

    symbols: list[SymbolInfo] = []
    module = path.name
    for symbol in raw:
        if symbol.name is None:
            continue
        symbols.append(
            SymbolInfo(
                name=symbol.name.decode("ascii", errors="replace"),
                address=image_base + int(symbol.address),
                module_name=module,
                file_name=None,
                line_number=None,
            ),
        )
        if len(symbols) >= limit:
            break
    return symbols


def _real_headers(path: Path) -> list[HeaderInfo]:
    """Build real :class:`HeaderInfo` records from PE optional-header fields.

    Args:
        path: Path to a real PE binary.

    Returns:
        list[HeaderInfo]: Real header field name/value pairs.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        opt = pe.OPTIONAL_HEADER
        return [
            HeaderInfo(name="Magic", value=hex(int(opt.Magic)), address=0),
            HeaderInfo(name="ImageBase", value=hex(int(opt.ImageBase)), address=0),
            HeaderInfo(
                name="AddressOfEntryPoint",
                value=hex(int(opt.AddressOfEntryPoint)),
                address=int(opt.ImageBase) + int(opt.AddressOfEntryPoint),
            ),
            HeaderInfo(name="Subsystem", value=str(int(opt.Subsystem)), address=0),
        ]
    finally:
        pe.close()


def _real_sections(path: Path) -> list[SectionInfo]:
    """Build real :class:`SectionInfo` records from a PE section table.

    Args:
        path: Path to a real PE binary.

    Returns:
        list[SectionInfo]: Real section records.
    """
    pe = pefile.PE(str(path), fast_load=True)
    try:
        return [
            SectionInfo(
                name=section.Name.rstrip(b"\x00").decode("ascii", errors="replace"),
                virtual_address=int(section.VirtualAddress),
                virtual_size=int(section.Misc_VirtualSize),
                raw_size=int(section.SizeOfRawData),
                characteristics=int(section.Characteristics),
                entropy=0.0,
            )
            for section in pe.sections
        ]
    finally:
        pe.close()


@pytest.mark.usefixtures("qapp")
class TestSymbolsTabRealData:
    """The symbols tab must render real export symbols from a real PE."""

    @staticmethod
    def test_apply_real_export_symbols(real_pe_dll: Path) -> None:
        """Real kernel32 export names and addresses must populate the table.

        Args:
            real_pe_dll: Real System32 PE DLL fixture (kernel32.dll).
        """
        symbols = _real_symbols(real_pe_dll)
        if not symbols:
            pytest.skip("resolved PE DLL exposes no named exports")

        tab = SymbolsTab()
        tab._apply_data(symbols)

        assert tab._table.rowCount() == len(symbols)
        rendered_names = {(item.text() if (item := tab._table.item(row, 0)) is not None else "") for row in range(tab._table.rowCount())}
        assert rendered_names == {s.name for s in symbols}

        first = symbols[0]
        addr_item = tab._table.item(0, 1)
        module_item = tab._table.item(0, 2)
        assert addr_item is not None
        assert module_item is not None
        assert addr_item.text() == f"0x{first.address:X}"
        assert module_item.text() == real_pe_dll.name


@pytest.mark.usefixtures("qapp")
class TestHeadersTabRealData:
    """The headers tab must render real optional-header field values."""

    @staticmethod
    def test_apply_real_headers(real_pe_dll: Path) -> None:
        """Real PE header field values must populate the table verbatim.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        headers = _real_headers(real_pe_dll)
        tab = HeadersTab()
        tab._apply_data(headers)

        assert tab._table.rowCount() == len(headers)
        magic_row = next(
            row for row in range(tab._table.rowCount()) if (cell := tab._table.item(row, 0)) is not None and cell.text() == "Magic"
        )
        value_item = tab._table.item(magic_row, 1)
        assert value_item is not None
        magic_header = next(h for h in headers if h.name == "Magic")
        assert value_item.text() == magic_header.value
        assert value_item.text() in {"0x10b", "0x20b"}


@pytest.mark.usefixtures("qapp")
class TestAllStringsTabRealData:
    """The strings tab must render real string records with real sections."""

    @staticmethod
    def test_apply_real_string_records(real_pe_dll: Path) -> None:
        """Real section-derived string records must populate the table.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        sections = _real_sections(real_pe_dll)
        pe = pefile.PE(str(real_pe_dll), fast_load=True)
        try:
            image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        finally:
            pe.close()
        strings = [
            StringInfo(
                address=image_base + sec.virtual_address,
                value=sec.name,
                encoding="ascii",
                section=sec.name,
            )
            for sec in sections
        ]

        tab = AllStringsTab()
        tab._apply_data(strings)

        assert tab._table.rowCount() == len(strings)
        section_names = {(item.text() if (item := tab._table.item(row, 2)) is not None else "") for row in range(tab._table.rowCount())}
        assert ".text" in section_names

        text_row = next(
            row for row in range(tab._table.rowCount()) if (cell := tab._table.item(row, 2)) is not None and cell.text() == ".text"
        )
        addr_item = tab._table.item(text_row, 0)
        text_string = next(s for s in strings if s.section == ".text")
        assert addr_item is not None
        assert addr_item.text() == f"0x{text_string.address:X}"


@pytest.mark.usefixtures("qapp")
class TestHexdumpTabRealData:
    """The hexdump tab must render real bytes and parse real input."""

    @staticmethod
    def test_apply_real_hexdump_text(real_pe_dll: Path) -> None:
        """A real hexdump string of real ``.text`` bytes must render verbatim.

        Args:
            real_pe_dll: Real System32 PE DLL fixture.
        """
        pe = pefile.PE(str(real_pe_dll), fast_load=True)
        try:
            text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
            base = int(pe.OPTIONAL_HEADER.ImageBase) + int(text.VirtualAddress)
            raw = text.get_data()[:32]
        finally:
            pe.close()

        dump_line = f"0x{base:08X}  " + " ".join(f"{b:02x}" for b in raw)

        tab = HexdumpTab()
        tab._apply_data(dump_line)

        rendered = tab._output.toPlainText()
        assert rendered == dump_line
        assert f"0x{base:08X}" in rendered
        assert f"{raw[0]:02x}" in rendered

    @staticmethod
    def test_invalid_address_input_surfaces_error() -> None:
        """A non-hex address must produce a real parse error without a bridge call."""
        tab = HexdumpTab()
        recorder = _RecordingHexBridge()
        tab._bridge = cast("CutterBridge", recorder)

        tab._addr_input.setText("not-a-real-address")
        tab._on_dump()

        assert tab._output.toPlainText() == "[error] Invalid address or length"
        assert recorder.calls == []
