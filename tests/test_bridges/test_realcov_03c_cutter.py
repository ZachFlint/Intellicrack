# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data integration tests for :class:`CutterBridge`.

These tests drive the bridge against a genuine rizin/radare2 backend and
real, on-disk PE and ELF binaries. Unlike the command-recorder unit tests in
``test_cutter.py`` (which validate command construction with a Python double),
every assertion here is anchored to a value computed by the real Rizin engine:
real section names (``.text``), real exported symbols
(``AcquireSRWLockExclusive``), real disassembled mnemonics, real hash-stable
byte round-trips through ``write_bytes``/``read_bytes``, real assembled machine
code from ``assemble_at`` (``nop`` -> ``90``), and real cross-format header
fields parsed from a committed ELF binary.

The backend spawns an external rizin process for every loaded binary, so each
test carries the ``spawns_process`` marker and runs only inside the Docker
sandbox (which ships radare2 5.9.8) or when host-process tests are explicitly
allowed. When no rizin/radare2 binary is discoverable the module-level fixtures
issue a precise :func:`pytest.skip` rather than fabricating a pass.
"""

from __future__ import annotations

import asyncio
import os
import shutil
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.bridges.cutter import CutterBridge


if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

pytestmark = [pytest.mark.spawns_process, pytest.mark.asyncio]


async def _make_bridge_or_skip() -> CutterBridge:
    """Build a bridge whose backend is available, or skip the test.

    Returns:
        CutterBridge: A fresh bridge with a confirmed rizin/radare2 backend.
    """
    bridge = CutterBridge()
    if not await bridge.is_available():
        pytest.skip("rizin/radare2 backend not discoverable on PATH")
    return bridge


async def test_backend_available_or_explicit_skip() -> None:
    """Backend availability smoke test: fails loud in enforced-backend CI runs.

    When the environment variable ``EXPECT_RIZIN_BACKEND`` is set to any
    non-empty value, a missing rizin/radare2 binary is treated as a hard
    failure rather than a skip. This distinguishes "backend genuinely
    absent on this host" from "backend missing because the container was
    mis-configured". Without the variable the test skips as normal.

    The check also verifies that when the backend IS available, the bridge
    reports ``is_available() == True`` rather than silently returning a
    fabricated result.
    """
    bridge = CutterBridge()
    available = await bridge.is_available()
    if not available:
        enforce = os.environ.get("EXPECT_RIZIN_BACKEND", "")
        if enforce:
            pytest.fail(
                "rizin/radare2 backend not found on PATH but EXPECT_RIZIN_BACKEND is set; "
                "the container or host environment must supply rizin or radare2.",
            )
        pytest.skip("rizin/radare2 backend not discoverable on PATH (set EXPECT_RIZIN_BACKEND to enforce)")
    assert available is True, "is_available() must return exactly True when backend is present"


@pytest_asyncio.fixture
async def pe_bridge(real_pe_dll: Path) -> AsyncIterator[CutterBridge]:
    """Load and quick-analyze a real System32 PE DLL with the real backend.

    Args:
        real_pe_dll: Session fixture resolving ``kernel32.dll`` from System32.

    Yields:
        CutterBridge: Bridge with ``kernel32.dll`` loaded and analyzed.
    """
    bridge = await _make_bridge_or_skip()
    try:
        await bridge.load_binary(real_pe_dll)
        await bridge.analyze("quick")
        yield bridge
    finally:
        await bridge.shutdown()


@pytest_asyncio.fixture
async def elf_bridge(real_elf_binary: Path) -> AsyncIterator[CutterBridge]:
    """Load and quick-analyze the committed real ELF fixture.

    Args:
        real_elf_binary: Session fixture resolving the committed ELF binary.

    Yields:
        CutterBridge: Bridge with the ELF fixture loaded and analyzed.
    """
    bridge = await _make_bridge_or_skip()
    try:
        await bridge.load_binary(real_elf_binary)
        await bridge.analyze("quick")
        yield bridge
    finally:
        await bridge.shutdown()


async def _first_real_text_function(bridge: CutterBridge) -> tuple[int, int, str]:
    """Return ``(address, size, name)`` of a sized function from the analysis.

    Args:
        bridge: Analyzed bridge.

    Returns:
        tuple[int, int, str]: Address, byte size, and rizin name of the first
        analyzed function whose size exceeds eight bytes.
    """
    funcs = await bridge.get_functions()
    for func in funcs:
        if func.size > 8:
            return func.address, func.size, func.name
    pytest.skip("analysis produced no sized functions to operate on")


class TestRealLoadBinaryPe:
    """Validate ``load_binary`` extracts real PE metadata from kernel32.dll."""

    async def test_pe_metadata_is_real(self, pe_bridge: CutterBridge, real_pe_dll: Path) -> None:
        """Loaded PE reports real 64-bit PE32+ metadata and matching size.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
            real_pe_dll: Path to the on-disk DLL for size comparison.
        """
        info = await pe_bridge.load_binary(real_pe_dll)
        disk_size = (await asyncio.to_thread(real_pe_dll.stat)).st_size
        assert info.name == "kernel32.dll"
        assert info.file_type == "pe32+"
        assert info.is_64bit is True
        assert info.size == disk_size
        assert info.architecture.lower().startswith("x86")

    async def test_pe_has_text_section(self, pe_bridge: CutterBridge) -> None:
        """Real PE sections include the ``.text`` code section with a nonzero VA.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        sections = await pe_bridge.get_sections()
        names = {section.name for section in sections}
        assert ".text" in names
        assert ".rdata" in names
        text = next(section for section in sections if section.name == ".text")
        assert text.virtual_address > 0
        assert text.virtual_size > 0

    async def test_pe_exports_real_symbols(self, pe_bridge: CutterBridge) -> None:
        """kernel32 exports include well-known Win32 API names with addresses.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        exports = await pe_bridge.get_exports()
        names = {export.name for export in exports}
        assert "CreateFileW" in names
        assert "LoadLibraryA" in names
        create_file = next(export for export in exports if export.name == "CreateFileW")
        assert create_file.address > 0

    async def test_pe_imports_real_functions(self, pe_bridge: CutterBridge) -> None:
        """kernel32 imports resolve real ntdll runtime functions.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        imports = await pe_bridge.get_imports()
        functions = {imp.function for imp in imports}
        assert imports
        assert any(name.startswith(("Rtl", "Nt", "Zw")) for name in functions)


class TestRealAnalysisFunctions:
    """Validate function discovery against real analyzed code."""

    async def test_get_functions_discovers_code(self, pe_bridge: CutterBridge) -> None:
        """Analysis discovers many real functions inside ``.text``.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        funcs = await pe_bridge.get_functions()
        assert len(funcs) > 50
        assert all(func.address > 0 for func in funcs)
        assert any(func.size > 0 for func in funcs)

    async def test_get_function_returns_real_function(self, pe_bridge: CutterBridge) -> None:
        """``get_function`` at a discovered address echoes the same metadata.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address, size, name = await _first_real_text_function(pe_bridge)
        func = await pe_bridge.get_function(address)
        assert func is not None
        assert func.address == address
        assert func.size == size
        assert func.name == name

    async def test_get_functions_filter_pattern(self, pe_bridge: CutterBridge) -> None:
        """The regex filter narrows the function list to matching names only.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        all_funcs = await pe_bridge.get_functions()
        sample = next(func for func in all_funcs if len(func.name) > 4)
        token = sample.name[-4:]
        filtered = await pe_bridge.get_functions(filter_pattern=token)
        assert filtered
        assert all(token in func.name for func in filtered)
        assert len(filtered) <= len(all_funcs)


class TestRealDisassembly:
    """Validate disassembly produces real mnemonics from real .text bytes."""

    async def test_disassemble_real_instructions(self, pe_bridge: CutterBridge) -> None:
        """Disassembling a real function yields real x86 mnemonics and bytes.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address, _size, _name = await _first_real_text_function(pe_bridge)
        lines = await pe_bridge.disassemble(address, 6)
        assert lines
        assert lines[0].address == address
        for line in lines:
            assert line.mnemonic
            assert all(char in "0123456789abcdef" for char in line.bytes_str.lower())

    async def test_disassemble_function_text(self, pe_bridge: CutterBridge) -> None:
        """Whole-function disassembly returns a multi-line textual listing.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address, _size, _name = await _first_real_text_function(pe_bridge)
        text = await pe_bridge.disassemble_function(address)
        assert text.strip()
        assert len(text.splitlines()) >= 1

    async def test_basic_blocks_real(self, pe_bridge: CutterBridge) -> None:
        """A real function exposes at least one basic block with a size.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address, _size, _name = await _first_real_text_function(pe_bridge)
        blocks = await pe_bridge.get_basic_blocks(address)
        assert blocks
        assert blocks[0].size > 0


class TestRealByteIo:
    """Validate raw byte read and hex dump against real binary content."""

    async def test_read_bytes_matches_disassembly(self, pe_bridge: CutterBridge) -> None:
        """Bytes read at the text section start match the first disassembled op.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        sections = await pe_bridge.get_sections()
        text = next(section for section in sections if section.name == ".text")
        data = await pe_bridge.read_bytes(text.virtual_address, 16)
        assert len(data) == 16
        lines = await pe_bridge.disassemble(text.virtual_address, 1)
        first_bytes = bytes.fromhex(lines[0].bytes_str)
        assert data.startswith(first_bytes)

    async def test_hexdump_real(self, pe_bridge: CutterBridge) -> None:
        """A hex dump of a real section yields formatted, non-empty output.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        sections = await pe_bridge.get_sections()
        text = next(section for section in sections if section.name == ".text")
        dump = await pe_bridge.hexdump(text.virtual_address, 32)
        assert dump.strip()
        words = await pe_bridge.hexdump_words(text.virtual_address, 32)
        assert words.strip()


class TestRealPatching:
    """Validate write/assemble operations against a writable PE copy."""

    @pytest_asyncio.fixture
    async def patch_bridge(self, real_pe_dll: Path, tmp_path: Path) -> AsyncIterator[CutterBridge]:
        """Load an analyzed, write-cached copy of kernel32.dll for patching.

        Args:
            real_pe_dll: Session fixture resolving ``kernel32.dll``.
            tmp_path: Per-test temporary directory.

        Yields:
            CutterBridge: Bridge on a private DLL copy with the patch cache on.
        """
        work = tmp_path / "kernel32_copy.dll"
        await asyncio.to_thread(shutil.copy, real_pe_dll, work)
        bridge = await _make_bridge_or_skip()
        try:
            await bridge.load_binary(work)
            await bridge.analyze("quick")
            yield bridge
        finally:
            await bridge.shutdown()

    async def test_write_bytes_round_trip(self, patch_bridge: CutterBridge) -> None:
        """``write_bytes`` overwrites real bytes verifiable through ``read_bytes``.

        Args:
            patch_bridge: Writable kernel32.dll copy bridge.
        """
        address, _size, _name = await _first_real_text_function(patch_bridge)
        original = await patch_bridge.read_bytes(address, 4)
        assert original != b"\x90\x90\x90\x90"
        result = await patch_bridge.write_bytes(address, "90909090")
        assert result is True
        patched = await patch_bridge.read_bytes(address, 4)
        assert patched == b"\x90\x90\x90\x90"

    async def test_assemble_at_produces_machine_code(self, patch_bridge: CutterBridge) -> None:
        """``assemble_at`` encodes ``nop`` to the real 0x90 opcode and commits it.

        Args:
            patch_bridge: Writable kernel32.dll copy bridge.
        """
        address, _size, _name = await _first_real_text_function(patch_bridge)
        encoded = await patch_bridge.assemble_at(address, "nop")
        assert encoded == b"\x90"
        committed = await patch_bridge.read_bytes(address, 1)
        assert committed == b"\x90"

    async def test_assemble_real_mov(self, patch_bridge: CutterBridge) -> None:
        """Assembling ``xor eax, eax`` yields the real two-byte encoding 0x31C0.

        Args:
            patch_bridge: Writable kernel32.dll copy bridge.
        """
        address, _size, _name = await _first_real_text_function(patch_bridge)
        encoded = await patch_bridge.assemble_at(address, "xor eax, eax")
        assert encoded == bytes.fromhex("31c0")

    async def test_write_value_round_trip(self, patch_bridge: CutterBridge) -> None:
        """``write_value`` writes a little-endian dword observable via ``read_bytes``.

        Args:
            patch_bridge: Writable kernel32.dll copy bridge.
        """
        address, _size, _name = await _first_real_text_function(patch_bridge)
        assert await patch_bridge.write_value(address, 0xDEADBEEF, size=4) is True
        data = await patch_bridge.read_bytes(address, 4)
        assert data == (0xDEADBEEF).to_bytes(4, "little")

    async def test_write_xor_is_reversible(self, patch_bridge: CutterBridge) -> None:
        """``write_xor`` mutates real bytes and reapplying the key restores them.

        XOR is its own inverse, so two identical ``write_xor`` passes over the
        same range must return the bytes to their original values. This proves
        the transform genuinely executed against the loaded image rather than
        merely dispatching a command.

        Args:
            patch_bridge: Writable kernel32.dll copy bridge.
        """
        address, _size, _name = await _first_real_text_function(patch_bridge)
        original = await patch_bridge.read_bytes(address, 4)
        assert await patch_bridge.write_xor(address, 4, 0x5A) is True
        transformed = await patch_bridge.read_bytes(address, 4)
        assert transformed != original
        assert await patch_bridge.write_xor(address, 4, 0x5A) is True
        restored = await patch_bridge.read_bytes(address, 4)
        assert restored == original


class TestRealStringSearch:
    """Validate string extraction and search against real binary content."""

    async def test_search_strings_finds_known(self, pe_bridge: CutterBridge) -> None:
        """Searching for ``Microsoft`` returns matching real data-section strings.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        matches = await pe_bridge.search_strings("Microsoft")
        assert matches
        assert all("microsoft" in match.value.lower() for match in matches)
        assert all(match.address > 0 for match in matches)

    async def test_get_all_strings_real(self, pe_bridge: CutterBridge) -> None:
        """``get_all_strings`` returns real, addressed strings from the binary.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        strings = await pe_bridge.get_all_strings()
        assert len(strings) > 10
        assert any(string.value for string in strings)

    async def test_search_string_live_locates_bytes(self, pe_bridge: CutterBridge) -> None:
        """A literal string present in the binary is found; absent text is not.

        The presence of a known substring yields a non-empty real match set
        while a string that cannot occur yields none, proving the byte search
        genuinely scans the loaded image rather than echoing a constant.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        matches = await pe_bridge.search_strings("Microsoft")
        needle = next(match.value for match in matches if "Microsoft" in match.value)
        token = needle[: needle.index("Microsoft") + len("Microsoft")][-8:]
        hits = await pe_bridge.search_string_live(token)
        assert hits
        absent = await pe_bridge.search_string_live("zZqXrWv_not_present_4242")
        assert absent == []

    async def test_search_bytes_finds_real_sequence(self, pe_bridge: CutterBridge) -> None:
        """A real instruction byte sequence is located; impossible bytes are not.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        address, _size, _name = await _first_real_text_function(pe_bridge)
        prologue = await pe_bridge.read_bytes(address, 6)
        hits = await pe_bridge.search_bytes(prologue)
        assert hits
        missing = await pe_bridge.search_bytes(b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x13\x37")
        assert missing == []


class TestRealMetadata:
    """Validate symbol/library/header/relocation enumeration on real PEs."""

    async def test_symbols_real(self, pe_bridge: CutterBridge) -> None:
        """``get_symbols`` returns many real, addressed symbols.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        symbols = await pe_bridge.get_symbols()
        assert len(symbols) > 50
        assert any(symbol.name for symbol in symbols)

    async def test_libraries_real(self, pe_bridge: CutterBridge) -> None:
        """kernel32 links real API-set/ntdll libraries surfaced by ``get_libraries``.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        libraries = await pe_bridge.get_libraries()
        assert libraries
        names = {library.name.lower() for library in libraries}
        assert any(name.endswith(".dll") for name in names)

    async def test_headers_real(self, pe_bridge: CutterBridge) -> None:
        """``get_headers`` returns real named PE header fields.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        headers = await pe_bridge.get_headers()
        assert headers
        assert any(header.name for header in headers)

    async def test_relocations_real(self, pe_bridge: CutterBridge) -> None:
        """``get_relocations`` returns a list parsed from the real reloc table.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        relocations = await pe_bridge.get_relocations()
        assert isinstance(relocations, list)


class TestRealXrefs:
    """Validate cross-reference extraction against real analyzed code."""

    async def test_xrefs_to_real_callee(self, pe_bridge: CutterBridge) -> None:
        """At least one analyzed function has real inbound cross-references.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        funcs = await pe_bridge.get_functions()
        for func in funcs[:400]:
            xrefs = await pe_bridge.get_xrefs_to(func.address)
            if xrefs:
                assert all(xref.to_address == func.address for xref in xrefs)
                assert all(xref.from_address > 0 for xref in xrefs)
                return
        pytest.skip("no inbound cross-references found in the first 400 functions")


class TestRealEsil:
    """Validate the ESIL evaluator computes real arithmetic over the session."""

    async def test_esil_eval_arithmetic(self, pe_bridge: CutterBridge) -> None:
        """``ae`` evaluates a real ESIL expression to its computed value.

        Args:
            pe_bridge: Analyzed kernel32.dll bridge.
        """
        result = await pe_bridge.esil_eval("1,1,+")
        assert "0x2" in result or result.strip() == "2"


class TestRealCrossFormatElf:
    """Validate the bridge parses a genuinely different binary format (ELF)."""

    async def test_elf_header_fields(self, elf_bridge: CutterBridge, real_elf_binary: Path) -> None:
        """The committed ELF reports real ELF64 metadata distinct from a PE.

        Args:
            elf_bridge: Analyzed ELF fixture bridge.
            real_elf_binary: Path to the committed ELF fixture.
        """
        info = await elf_bridge.load_binary(real_elf_binary)
        assert "elf" in info.file_type
        assert info.is_64bit is True
        section_names = {section.name for section in info.sections}
        assert ".text" in section_names

    async def test_elf_functions_discovered(self, elf_bridge: CutterBridge) -> None:
        """Analysis of the ELF discovers real functions with code addresses.

        Args:
            elf_bridge: Analyzed ELF fixture bridge.
        """
        funcs = await elf_bridge.get_functions()
        assert funcs
        assert all(func.address > 0 for func in funcs)

    async def test_elf_symbols_real(self, elf_bridge: CutterBridge) -> None:
        """The ELF exposes real symbol-table entries.

        Args:
            elf_bridge: Analyzed ELF fixture bridge.
        """
        symbols = await elf_bridge.get_symbols()
        assert symbols
        assert any(symbol.name for symbol in symbols)
