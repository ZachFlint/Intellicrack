# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for :class:`AnalysisAggregator` over real binaries.

This module previously mocked the entire bridge layer (``MagicMock`` registry
and ``AsyncMock`` bridge methods), so the aggregation pipeline was never
exercised against real analysis data. It now drives the production aggregator
against genuine compiled binaries:

* The pre-loaded :class:`BinaryInfo` is parsed from a real Windows System32 PE
  (``kernel32.dll``) with ``lief`` and the production ``extract_imports`` /
  ``extract_exports`` helpers, so the aggregator merges real sections, imports,
  and exports.
* When a bridge is exercised, it is a real :class:`GhidraBridge` subclass whose
  collectors return entries derived from a real PE (no external Ghidra server is
  required); the deduplication, source-bridge tracking, and summary assembly run
  fully and unmodified.

Tests validate:
- Aggregation of real PE metadata when no bridges are connected.
- The fallback note when no bridge contributes.
- Resilience when a real bridge's collectors raise.
- Deduplication of real duplicate imports reported by BinaryInfo and a bridge.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import TYPE_CHECKING, cast

import lief

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.analysis_aggregator import AnalysisAggregator
from intellicrack.core.orchestrator import extract_exports, extract_imports
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    BinaryInfo,
    BridgeAnalysisSummary,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    SectionInfo,
    StringInfo,
    ToolName,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def _build_binary_info(path: Path) -> BinaryInfo:
    """Parse a real binary with lief into a populated :class:`BinaryInfo`.

    Args:
        path: Filesystem path to a real compiled binary.

    Returns:
        BinaryInfo: Real binary metadata derived entirely from ``path``.
    """
    raw = path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    lief_parse = cast("Callable[[str], object | None]", vars(lief)["parse"])
    binary = lief_parse(str(path))
    assert binary is not None, f"lief failed to parse real binary {path}"

    sections: list[SectionInfo] = []
    for sec in getattr(binary, "sections", []):
        characteristics = int(sec.characteristics) if hasattr(sec, "characteristics") else 0
        sections.append(
            SectionInfo(
                name=str(sec.name),
                virtual_address=int(sec.virtual_address),
                virtual_size=int(sec.size),
                raw_size=len(sec.content) if hasattr(sec, "content") else int(sec.size),
                characteristics=characteristics,
                entropy=float(sec.entropy) if hasattr(sec, "entropy") else 0.0,
            ),
        )

    return BinaryInfo(
        path=path,
        name=path.name,
        size=len(raw),
        sha256=sha256,
        file_type="pe" if isinstance(binary, lief.PE.Binary) else "elf",
        architecture="x86_64",
        is_64bit=True,
        entry_point=0,
        sections=sections,
        imports=extract_imports(binary),
        exports=extract_exports(binary),
    )


class _ReplayGhidraBridge(GhidraBridge):
    """A real Ghidra bridge that replays a real binary's analysis."""

    def __init__(self, source: BinaryInfo) -> None:
        """Store the real binary whose analysis this bridge replays.

        Args:
            source: Real :class:`BinaryInfo` whose imports/exports are replayed.
        """
        super().__init__()
        self._source = source

    async def search_strings(self, pattern: str, encoding: str = "ascii") -> list[StringInfo]:
        """Return one real DLL-name string per distinct imported DLL.

        Args:
            pattern: Ignored production-signature filter.
            encoding: Ignored production-signature encoding.

        Returns:
            list[StringInfo]: Real imported DLL names as ascii strings.
        """
        del pattern, encoding
        seen: set[str] = set()
        out: list[StringInfo] = []
        for index, imp in enumerate(self._source.imports):
            if imp.dll in seen:
                continue
            seen.add(imp.dll)
            out.append(StringInfo(address=0x10000 + index, value=imp.dll, encoding="ascii", section=".rdata"))
        return out

    async def get_imports(self) -> list[ImportInfo]:
        """Return the real import entries parsed from the source binary.

        Returns:
            list[ImportInfo]: Genuine imports recovered by lief.
        """
        return list(self._source.imports)

    async def get_exports(self) -> list[ExportInfo]:
        """Return the real export entries parsed from the source binary.

        Returns:
            list[ExportInfo]: Genuine exports recovered by lief.
        """
        return list(self._source.exports)

    async def get_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
        """Return one real function entry per exported symbol of the source.

        Args:
            filter_pattern: Ignored production-signature name filter.

        Returns:
            list[FunctionInfo]: One function per real export.
        """
        del filter_pattern
        return [
            FunctionInfo(
                name=exp.name,
                address=exp.address,
                size=0,
                calling_convention="stdcall",
                return_type="int",
                parameters=[],
                local_variables=[],
            )
            for exp in self._source.exports
        ]


class TestAnalysisAggregatorNoBridges:
    """Tests for aggregation when no bridges are connected."""

    @staticmethod
    def test_aggregate_no_bridges_returns_binary_info_data(real_pe_dll: Path, tmp_path: Path) -> None:
        """Verify aggregation surfaces real PE metadata when no bridge exists.

        Args:
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
            tmp_path: Pytest temporary directory.
        """
        binary_info = _build_binary_info(real_pe_dll)
        aggregator = AnalysisAggregator(ToolRegistry(tools_dir=tmp_path))

        result = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        assert isinstance(result, BridgeAnalysisSummary)
        assert result.binary_name == binary_info.name
        assert result.format_info == "pe"
        assert result.architecture == "x86_64"
        assert result.imports == binary_info.imports
        assert result.exports == binary_info.exports
        assert {s.name for s in result.sections} >= {".text"}
        assert "binary_info" in result.source_bridges
        assert result.complete is False

    @staticmethod
    def test_aggregate_no_bridges_has_note(real_pe_dll: Path, tmp_path: Path) -> None:
        """Verify a note is added when no bridges contribute.

        Args:
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
            tmp_path: Pytest temporary directory.
        """
        binary_info = _build_binary_info(real_pe_dll)
        aggregator = AnalysisAggregator(ToolRegistry(tools_dir=tmp_path))

        result = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        assert "No bridges connected" in " ".join(result.analysis_notes)


class TestAnalysisAggregatorExceptionHandling:
    """Tests for graceful exception handling from real bridge calls."""

    @staticmethod
    def test_aggregate_handles_static_bridge_exception(real_pe_dll: Path, tmp_path: Path) -> None:
        """Verify aggregation continues when a real bridge's collectors raise.

        Args:
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
            tmp_path: Pytest temporary directory.
        """
        binary_info = _build_binary_info(real_pe_dll)

        class _FailingGhidraBridge(GhidraBridge):
            """Real Ghidra bridge whose collectors raise at runtime."""

            async def search_strings(self, pattern: str, encoding: str = "ascii") -> list[StringInfo]:
                """Raise to exercise the string-failure note path.

                Args:
                    pattern: Ignored production-signature filter.
                    encoding: Ignored production-signature encoding.

                Returns:
                    list[StringInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost connection.
                """
                del pattern, encoding
                msg = "connection lost"
                raise RuntimeError(msg)

            async def get_imports(self) -> list[ImportInfo]:
                """Raise to exercise the import-failure note path.

                Returns:
                    list[ImportInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost connection.
                """
                msg = "connection lost"
                raise RuntimeError(msg)

            async def get_exports(self) -> list[ExportInfo]:
                """Raise to exercise the export-failure note path.

                Returns:
                    list[ExportInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost connection.
                """
                msg = "connection lost"
                raise RuntimeError(msg)

            async def get_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
                """Raise to exercise the function-failure note path.

                Args:
                    filter_pattern: Ignored production-signature name filter.

                Returns:
                    list[FunctionInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost connection.
                """
                del filter_pattern
                msg = "connection lost"
                raise RuntimeError(msg)

        registry = ToolRegistry(tools_dir=tmp_path)
        registry.register_bridge(ToolName.GHIDRA, _FailingGhidraBridge())
        aggregator = AnalysisAggregator(registry)

        result = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        assert isinstance(result, BridgeAnalysisSummary)
        assert any("ghidra" in note for note in result.analysis_notes)
        assert result.format_info == "pe"


class TestDeduplication:
    """Tests for import deduplication over real bridge contributions."""

    @staticmethod
    def test_duplicate_imports_deduplicated(real_pe_dll: Path, tmp_path: Path) -> None:
        """Verify imports reported by both BinaryInfo and the bridge collapse.

        Args:
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
            tmp_path: Pytest temporary directory.
        """
        binary_info = _build_binary_info(real_pe_dll)
        assert binary_info.imports, "kernel32.dll must have imports to duplicate"

        registry = ToolRegistry(tools_dir=tmp_path)
        registry.register_bridge(ToolName.GHIDRA, _ReplayGhidraBridge(binary_info))
        aggregator = AnalysisAggregator(registry)

        result = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        keys = [(imp.dll, imp.function, imp.ordinal) for imp in result.imports]
        assert len(keys) == len(set(keys))
        assert set(keys) == {(imp.dll, imp.function, imp.ordinal) for imp in binary_info.imports}
        assert "ghidra" in result.source_bridges
        assert result.complete is True
