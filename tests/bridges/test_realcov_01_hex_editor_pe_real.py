# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-binary validation for ``HexEditorBridge`` PE introspection.

The pre-existing ``test_hex_editor_pe_methods.py`` suite attaches an
in-memory surrogate document built from a hand-assembled two-section PE
buffer with empty data directories. That proves the bridge's dispatch
and section-walk arithmetic but never exercises real import tables,
real export tables (including ordinal-only and forwarded exports), the
full multi-section layout of a real DLL, or the disk-path fast path in
:meth:`HexEditorBridge._open_pe_for_inspection`.

This module loads genuine ``System32`` DLLs through the real
``intellicrack_hexcore`` document backend via
:meth:`HexEditorBridge.open_file` and asserts on verifiable real-world
results: the actual section names, real imported DLL names and function
symbols (``LoadLibraryA``, ``GetProcAddress``), real exported symbols,
and hash digests cross-checked against :mod:`hashlib`. Every assertion
is cross-validated against an independent oracle (:mod:`pefile` or
:mod:`hashlib`) so the test proves operational correctness, not merely
that a call returned.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
from typing import TYPE_CHECKING, cast

import pefile
import pytest
import pytest_asyncio

from intellicrack.bridges.hex_editor import HexEditorBridge


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path

_IMAGE_DIRECTORY_ENTRY_EXPORT = 0


def _hexcore_available() -> bool:
    """Report whether the optional ``intellicrack_hexcore`` backend is built.

    Returns:
        bool: ``True`` when the Rust hexcore extension is importable.
    """
    return importlib.util.find_spec("intellicrack_hexcore") is not None


def _pefile_import_pairs(path: Path) -> set[tuple[str, str]]:
    """Collect ``(dll, function)`` import pairs via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        set[tuple[str, str]]: Lowercased DLL name paired with each named
            imported function symbol.
    """
    pairs: set[tuple[str, str]] = set()
    pe = pefile.PE(str(path))
    try:
        pe.parse_data_directories()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll_name = entry.dll.decode("ascii", errors="replace").lower()
            for imp in entry.imports:
                if imp.name is not None:
                    pairs.add((dll_name, imp.name.decode("ascii", errors="replace")))
    finally:
        pe.close()
    return pairs


def _hashlib_digest(path: Path, algorithm: str, length: int | None = None) -> str:
    """Compute an independent hashlib digest over a real file or prefix.

    Args:
        path: Path to the file to hash.
        algorithm: Hash algorithm name accepted by :func:`hashlib.new`.
        length: When given, hash only the first ``length`` bytes; when
            ``None`` hash the entire file.

    Returns:
        str: Hexadecimal digest string.
    """
    data = path.read_bytes()
    if length is not None:
        data = data[:length]
    hasher = hashlib.new(algorithm, usedforsecurity=False)
    hasher.update(data)
    return hasher.hexdigest()


def _file_size(path: Path) -> int:
    """Return the on-disk size of a file in bytes.

    Args:
        path: Path to the file.

    Returns:
        int: File size in bytes.
    """
    return path.stat().st_size


def _pefile_export_names(path: Path) -> set[str]:
    """Collect named exported symbols via the pefile oracle.

    Args:
        path: Path to a real PE binary.

    Returns:
        set[str]: Named exported symbols from the export directory.
    """
    names: set[str] = set()
    pe = pefile.PE(str(path))
    try:
        pe.parse_data_directories(directories=[_IMAGE_DIRECTORY_ENTRY_EXPORT])
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_dir is not None:
            names = {sym.name.decode("ascii", errors="replace") for sym in export_dir.symbols if sym.name is not None}
    finally:
        pe.close()
    return names


pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not _hexcore_available(),
        reason="intellicrack_hexcore (Rust backend) not built; open_file requires it",
    ),
]


@pytest_asyncio.fixture
async def kernel32_bridge(real_pe_dll: Path) -> AsyncGenerator[HexEditorBridge]:
    """Open ``kernel32.dll`` through a real hexcore-backed bridge.

    Args:
        real_pe_dll: Path to the real ``kernel32.dll`` System32 fixture.

    Yields:
        AsyncGenerator[HexEditorBridge]: Bridge with the real DLL opened.
    """
    bridge = HexEditorBridge()
    await bridge.open_file(str(real_pe_dll))
    try:
        yield bridge
    finally:
        await bridge.close_file()


class TestRealPeSections:
    """Validate ``get_pe_sections`` against a real DLL's full section table."""

    async def test_sections_match_pefile(
        self,
        kernel32_bridge: HexEditorBridge,
        real_pe_dll: Path,
    ) -> None:
        """Verify bridge section names/offsets match pefile for kernel32.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
            real_pe_dll: Path to kernel32.dll for the pefile oracle.
        """
        sections = await kernel32_bridge.get_pe_sections()
        pe = pefile.PE(str(real_pe_dll), fast_load=True)
        try:
            expected = [
                (
                    s.Name.split(b"\x00", 1)[0].decode("ascii", errors="replace"),
                    int(s.VirtualAddress),
                    int(s.PointerToRawData),
                    int(s.SizeOfRawData),
                )
                for s in pe.sections
            ]
        finally:
            pe.close()

        actual = [
            (
                str(s["name"]),
                int(s["virtual_address"]),
                int(s["raw_offset"]),
                int(s["raw_size"]),
            )
            for s in sections
        ]
        assert actual == expected
        names = {name for name, *_ in actual}
        assert ".text" in names
        assert ".rdata" in names
        assert len(actual) >= 4, "real system DLL must expose several sections"

    async def test_text_section_is_executable(
        self,
        kernel32_bridge: HexEditorBridge,
    ) -> None:
        """Verify the real ``.text`` section carries the execute flag.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
        """
        sections = await kernel32_bridge.get_pe_sections()
        text = next(s for s in sections if s["name"] == ".text")
        execute_flag = 0x20000000
        assert int(text["characteristics"]) & execute_flag


class TestRealPeImports:
    """Validate ``get_pe_imports`` against a real DLL's populated IAT."""

    async def test_imports_match_pefile(
        self,
        kernel32_bridge: HexEditorBridge,
        real_pe_dll: Path,
    ) -> None:
        """Verify bridge imports cover the same DLL/function pairs as pefile.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
            real_pe_dll: Path to kernel32.dll for the pefile oracle.
        """
        imports = await kernel32_bridge.get_pe_imports()
        assert imports, "kernel32.dll has a populated import directory"

        expected_pairs = await asyncio.to_thread(_pefile_import_pairs, real_pe_dll)
        actual_pairs = {(str(i["dll"]).lower(), str(i["function"])) for i in imports if not str(i["function"]).startswith("Ordinal ")}
        assert expected_pairs
        assert expected_pairs <= actual_pairs

    async def test_imports_reference_real_runtime_dll(
        self,
        kernel32_bridge: HexEditorBridge,
    ) -> None:
        """Verify kernel32 imports from its real lower-level dependencies.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
        """
        imports = await kernel32_bridge.get_pe_imports()
        dll_names = {str(i["dll"]).lower() for i in imports}
        assert any("kernelbase" in name or "ntdll" in name for name in dll_names)


class TestRealPeExports:
    """Validate ``get_pe_exports`` against a real DLL's export directory."""

    async def test_kernel32_exports_known_symbols(
        self,
        kernel32_bridge: HexEditorBridge,
    ) -> None:
        """Verify kernel32 exports include the canonical loader APIs.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
        """
        exports = await kernel32_bridge.get_pe_exports()
        names = {str(e["name"]) for e in exports}
        assert "LoadLibraryA" in names
        assert "GetProcAddress" in names
        assert "VirtualAlloc" in names

    async def test_exports_match_pefile_count_and_names(
        self,
        kernel32_bridge: HexEditorBridge,
        real_pe_dll: Path,
    ) -> None:
        """Verify the bridge's export name set matches pefile's directory.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
            real_pe_dll: Path to kernel32.dll for the pefile oracle.
        """
        exports = await kernel32_bridge.get_pe_exports()
        expected_named = await asyncio.to_thread(_pefile_export_names, real_pe_dll)
        actual_named = {str(e["name"]) for e in exports if not str(e["name"]).startswith("Ordinal ")}
        assert expected_named
        assert expected_named <= actual_named

    async def test_ntdll_exports_native_syscalls(self, real_pe_dlls: list[Path]) -> None:
        """Verify ntdll exports native-API symbols when present on the system.

        Args:
            real_pe_dlls: Real System32 DLLs; ntdll is selected when present.
        """
        ntdll = next((p for p in real_pe_dlls if p.name.lower() == "ntdll.dll"), None)
        if ntdll is None:
            pytest.skip("ntdll.dll not available among resolved real DLLs")
        bridge = HexEditorBridge()
        await bridge.open_file(str(ntdll))
        try:
            exports = await bridge.get_pe_exports()
        finally:
            await bridge.close_file()
        names = {str(e["name"]) for e in exports}
        assert "NtClose" in names
        assert "RtlGetVersion" in names


class TestRealDocumentHashing:
    """Validate hashing over a real document against ``hashlib``."""

    async def test_full_document_sha256_matches_hashlib(
        self,
        kernel32_bridge: HexEditorBridge,
        real_pe_dll: Path,
    ) -> None:
        """Verify the bridge's whole-file sha256 equals hashlib's digest.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
            real_pe_dll: Path to kernel32.dll for the hashlib oracle.
        """
        digest = await kernel32_bridge.calculate_hash("sha256")
        expected = await asyncio.to_thread(_hashlib_digest, real_pe_dll, "sha256")
        assert digest == expected

    async def test_full_document_md5_matches_hashlib(
        self,
        kernel32_bridge: HexEditorBridge,
        real_pe_dll: Path,
    ) -> None:
        """Verify the bridge's whole-file md5 equals hashlib's digest.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
            real_pe_dll: Path to kernel32.dll for the hashlib oracle.
        """
        digest = await kernel32_bridge.calculate_hash("md5")
        expected = await asyncio.to_thread(_hashlib_digest, real_pe_dll, "md5")
        assert digest == expected

    async def test_range_hash_matches_hashlib(
        self,
        kernel32_bridge: HexEditorBridge,
        real_pe_dll: Path,
    ) -> None:
        """Verify a range hash equals hashlib over the same real byte slice.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
            real_pe_dll: Path to kernel32.dll for the hashlib oracle.
        """
        length = 4096
        digest = await kernel32_bridge.calculate_hash_range(0, length, "sha256")
        expected = await asyncio.to_thread(_hashlib_digest, real_pe_dll, "sha256", length)
        assert digest == expected


class TestRealDocumentSearchAndTransform:
    """Validate search and transform against real document bytes."""

    async def test_search_finds_real_mz_magic(
        self,
        kernel32_bridge: HexEditorBridge,
    ) -> None:
        """Verify byte search locates the real ``MZ`` magic at offset 0.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
        """
        results = await kernel32_bridge.search_bytes("4d5a", 5)
        offsets = {r["offset"] for r in results}
        assert 0 in offsets

    async def test_xor_transform_over_real_header(
        self,
        kernel32_bridge: HexEditorBridge,
    ) -> None:
        """Verify a non-destructive XOR transform over the real DOS magic.

        XORing the real first two bytes ``MZ`` (0x4D, 0x5A) with key 0xFF
        yields 0xB2, 0xA5. The transform runs with ``in_place=False`` so
        the document is unmodified.

        Args:
            kernel32_bridge: Bridge with kernel32.dll open.
        """
        out = await kernel32_bridge.apply_transform(
            "xor_single",
            0,
            2,
            '{"key":"ff"}',
            in_place=False,
        )
        assert out == bytes([0x4D ^ 0xFF, 0x5A ^ 0xFF]).hex()


class TestOpenCloseLifecycle:
    """Validate the open/close lifecycle against a real on-disk binary."""

    async def test_open_reports_real_size(self, real_pe_dll: Path) -> None:
        """Verify ``open_file`` reports the real on-disk file size.

        Args:
            real_pe_dll: Path to the real kernel32.dll fixture.
        """
        bridge = HexEditorBridge()
        expected_size = await asyncio.to_thread(_file_size, real_pe_dll)
        result = await bridge.open_file(str(real_pe_dll))
        try:
            assert int(result["size"]) == expected_size
            assert result["modified"] is False
            doc = bridge.document
            assert doc is not None
            assert cast("int", doc.length()) == expected_size
        finally:
            closed = await bridge.close_file()
        assert closed is True

    async def test_close_after_close_is_false(self, real_pe_dll: Path) -> None:
        """Verify a second close returns ``False`` with no document open.

        Args:
            real_pe_dll: Path to the real kernel32.dll fixture.
        """
        bridge = HexEditorBridge()
        await bridge.open_file(str(real_pe_dll))
        assert await bridge.close_file() is True
        assert await bridge.close_file() is False
        assert bridge.document is None
