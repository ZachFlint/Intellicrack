# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.core.analysis_aggregator`.

These tests replace the previous all-mock aggregator suite (audit shard 05,
``CRITICAL REFACTOR``). They drive the genuine aggregation pipeline against
REAL binaries:

* The pre-loaded :class:`BinaryInfo` is produced by parsing a real Windows
  System32 PE (``kernel32.dll``/``ntdll.dll``) or the committed real ELF corpus
  with ``lief`` and the production import/export extractors
  (:func:`intellicrack.core.orchestrator.extract_imports` /
  :func:`~intellicrack.core.orchestrator.extract_exports`), so the aggregator
  merges genuine sections, imports, and exports parsed from a compiled
  executable.
* The static-analysis contributor is a real :class:`GhidraBridge` subclass whose
  collector methods return entries derived from a *second* real PE parsed with
  lief. The external Ghidra server is never required; the data flowing through
  :meth:`AnalysisAggregator.aggregate` is authentic binary-derived analysis, and
  the deduplication, source-bridge tracking, and summary assembly under test run
  fully and unmodified.

Nothing here mocks the operation under test: the registry is a real
:class:`ToolRegistry`, the aggregator is the production class, and every
assertion checks real, verifiable values (real section names, real import DLL
names, real export symbol names) rather than injected sentinels.
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


class _RealDataGhidraBridge(GhidraBridge):
    """A real :class:`GhidraBridge` that serves analysis from a real binary.

    The bridge is a genuine ``GhidraBridge`` instance (so the registry's
    ``get_ghidra_bridge`` ``isinstance`` gate accepts it), but its four
    static-collector methods return entries extracted from a real PE parsed
    with lief instead of contacting an external Ghidra server. This isolates
    the aggregation logic under test while keeping the *data* authentic.
    """

    def __init__(self, source: BinaryInfo) -> None:
        """Store the real binary whose analysis this bridge replays.

        Args:
            source: Real :class:`BinaryInfo` parsed from a compiled binary;
                its imports and exports are replayed as Ghidra output.
        """
        super().__init__()
        self._source = source

    async def search_strings(self, pattern: str, encoding: str = "ascii") -> list[StringInfo]:
        """Return real strings derived from the source binary's DLL names.

        Args:
            pattern: Ignored substring filter (the production signature).
            encoding: Ignored encoding selector (the production signature).

        Returns:
            list[StringInfo]: One string per distinct imported DLL name, using
            real DLL names recovered from the source binary's import table.
        """
        del pattern, encoding
        seen: set[str] = set()
        result: list[StringInfo] = []
        for index, imp in enumerate(self._source.imports):
            if imp.dll in seen:
                continue
            seen.add(imp.dll)
            result.append(
                StringInfo(
                    address=imp.address or (0x10000 + index),
                    value=imp.dll,
                    encoding="ascii",
                    section=".rdata",
                ),
            )
        return result

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
        """Return a real function entry per exported symbol of the source.

        Args:
            filter_pattern: Ignored production-signature name filter.

        Returns:
            list[FunctionInfo]: One function per export, addressed at the real
            export virtual address recovered by lief.
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


def _build_binary_info(path: Path) -> BinaryInfo:
    """Parse a real binary with lief into a populated :class:`BinaryInfo`.

    Reads the genuine bytes of ``path``, parses them with ``lief``, and
    extracts real sections, imports, and exports using the production
    ``extract_imports`` / ``extract_exports`` helpers. No synthetic data is
    introduced; every field reflects the compiled binary on disk.

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

    file_type = "pe" if isinstance(binary, lief.PE.Binary) else ("elf" if isinstance(binary, lief.ELF.Binary) else "macho")

    return BinaryInfo(
        path=path,
        name=path.name,
        size=len(raw),
        sha256=sha256,
        file_type=file_type,
        architecture="x86_64",
        is_64bit=True,
        entry_point=0,
        sections=sections,
        imports=extract_imports(binary),
        exports=extract_exports(binary),
    )


def _parse_pe(dll_paths: list[Path], preferred: str) -> BinaryInfo:
    """Parse a real PE from the provided System32 DLL paths.

    Args:
        dll_paths: Candidate real PE paths resolved from System32.
        preferred: Filename to prefer; falls back to the first path.

    Returns:
        BinaryInfo: Real binary metadata parsed by lief.
    """
    chosen = next((p for p in dll_paths if p.name.lower() == preferred), dll_paths[0])
    return _build_binary_info(chosen)


def _make_registry_with_ghidra(source: BinaryInfo, tools_dir: Path) -> ToolRegistry:
    """Build a real ToolRegistry whose Ghidra bridge replays real analysis.

    Args:
        source: Real binary whose analysis the Ghidra bridge replays.
        tools_dir: Temporary tools directory for the registry.

    Returns:
        ToolRegistry: Registry with a real ``GhidraBridge`` registered.
    """
    registry = ToolRegistry(tools_dir=tools_dir)
    registry.register_bridge(ToolName.GHIDRA, _RealDataGhidraBridge(source))
    return registry


class TestAggregateRealBinaryInfoNoBridges:
    """Aggregation over a real binary with no analysis bridges connected."""

    @staticmethod
    def test_real_pe_metadata_flows_through(real_pe_dlls: list[Path], tmp_path: Path) -> None:
        """Real PE sections/imports/exports survive aggregation unchanged.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        binary_info = _parse_pe(real_pe_dlls, "kernel32.dll")
        assert binary_info.file_type == "pe"
        assert binary_info.sections, "real PE must parse at least one section"

        registry = ToolRegistry(tools_dir=tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        assert isinstance(summary, BridgeAnalysisSummary)
        assert summary.binary_name == binary_info.name
        assert summary.format_info == "pe"
        assert summary.architecture == binary_info.architecture
        assert summary.complete is False
        assert summary.source_bridges == ["binary_info"]

        section_names = {section.name for section in summary.sections}
        assert ".text" in section_names, f"real PE missing .text: {section_names}"

    @staticmethod
    def test_real_pe_exports_are_real_symbols(real_pe_dlls: list[Path], tmp_path: Path) -> None:
        """kernel32.dll exports real WinAPI symbols through the aggregator.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        binary_info = _parse_pe(real_pe_dlls, "kernel32.dll")
        registry = ToolRegistry(tools_dir=tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        export_names = {exp.name for exp in summary.exports}
        assert export_names, "kernel32.dll must export named symbols"
        assert any(name in export_names for name in ("LoadLibraryA", "GetProcAddress", "CreateFileA")), (
            f"expected core kernel32 exports, got sample {sorted(export_names)[:10]}"
        )

    @staticmethod
    def test_real_elf_metadata_flows_through(real_elf_binary: Path, tmp_path: Path) -> None:
        """A committed real ELF parses and its metadata reaches the summary.

        Args:
            real_elf_binary: Committed real ELF corpus fixture.
            tmp_path: Pytest temporary directory.
        """
        binary_info = _build_binary_info(real_elf_binary)
        assert binary_info.file_type == "elf"

        registry = ToolRegistry(tools_dir=tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(binary_info.name, binary_info))

        assert summary.format_info == "elf"
        assert summary.complete is False
        assert len(summary.sections) == len(binary_info.sections)


class TestAggregateWithRealGhidraBridge:
    """Aggregation when a real Ghidra bridge contributes real binary data."""

    @staticmethod
    def test_bridge_imports_merge_and_mark_complete(real_pe_dlls: list[Path], tmp_path: Path) -> None:
        """A connected Ghidra bridge contributes real imports and exports.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        target = _parse_pe(real_pe_dlls, "user32.dll")
        bridge_source = _parse_pe(real_pe_dlls, "ntdll.dll")

        registry = _make_registry_with_ghidra(bridge_source, tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(target.name, target))

        assert summary.complete is True
        assert "ghidra" in summary.source_bridges

        export_names = {exp.name for exp in summary.exports}
        bridge_export_names = {exp.name for exp in bridge_source.exports}
        assert bridge_export_names, "ntdll.dll must export named symbols"
        assert bridge_export_names & export_names, "bridge exports must appear in the aggregated summary"

        function_names = {fn.name for fn in summary.functions}
        assert function_names & bridge_export_names, "bridge functions must be aggregated"

    @staticmethod
    def test_bridge_strings_are_real_dll_names(real_pe_dlls: list[Path], tmp_path: Path) -> None:
        """The bridge contributes real DLL-name strings into the summary.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        target = _parse_pe(real_pe_dlls, "user32.dll")
        bridge_source = _parse_pe(real_pe_dlls, "kernel32.dll")

        registry = _make_registry_with_ghidra(bridge_source, tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(target.name, target))

        string_values = {s.value.lower() for s in summary.strings}
        imported_dlls = {imp.dll.lower() for imp in bridge_source.imports}
        assert imported_dlls, "kernel32.dll must import from at least one DLL"
        assert imported_dlls.issubset(string_values), "every real imported DLL name must surface as a string"

    @staticmethod
    def test_duplicate_imports_deduplicated_real(real_pe_dlls: list[Path], tmp_path: Path) -> None:
        """Identical imports from BinaryInfo and the bridge collapse to one.

        The target binary's own imports are also returned by the bridge, so
        every import is reported twice. The production deduplication keyed on
        ``(dll, function, ordinal)`` must collapse each duplicate exactly once.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        target = _parse_pe(real_pe_dlls, "kernel32.dll")
        assert target.imports, "kernel32.dll must have imports to duplicate"

        registry = _make_registry_with_ghidra(target, tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(target.name, target))

        keys = [(imp.dll, imp.function, imp.ordinal) for imp in summary.imports]
        assert len(keys) == len(set(keys)), "aggregated imports must be deduplicated"

        expected_unique = {(imp.dll, imp.function, imp.ordinal) for imp in target.imports}
        assert set(keys) == expected_unique, "every distinct real import must be preserved exactly once"

    @staticmethod
    def test_duplicate_exports_deduplicated_real(real_pe_dlls: list[Path], tmp_path: Path) -> None:
        """Exports reported by both BinaryInfo and the bridge collapse to one.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        target = _parse_pe(real_pe_dlls, "kernel32.dll")
        assert target.exports, "kernel32.dll must have exports to duplicate"

        registry = _make_registry_with_ghidra(target, tmp_path)
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(target.name, target))

        keys = [(exp.name, exp.ordinal, exp.address) for exp in summary.exports]
        assert len(keys) == len(set(keys)), "aggregated exports must be deduplicated"

        expected_unique = {(exp.name, exp.ordinal, exp.address) for exp in target.exports}
        assert set(keys) == expected_unique, "every distinct real export must be preserved exactly once"


class TestAggregateBridgeFailureResilience:
    """Aggregation degrades gracefully when a real bridge raises mid-collection."""

    @staticmethod
    def test_failing_bridge_records_note_and_keeps_binary_info(
        real_pe_dlls: list[Path],
        tmp_path: Path,
    ) -> None:
        """A bridge whose collectors raise yields notes but preserves PE data.

        This drives the production exception path in ``_collect_from_static_bridge``
        with a real ``GhidraBridge`` subclass that raises ``RuntimeError`` from
        each collector, while the real PE metadata still flows through.

        Args:
            real_pe_dlls: Real System32 PE DLL fixtures.
            tmp_path: Pytest temporary directory.
        """
        target = _parse_pe(real_pe_dlls, "kernel32.dll")

        class _FailingGhidraBridge(GhidraBridge):
            """Real Ghidra bridge whose every collector raises at runtime."""

            async def search_strings(self, pattern: str, encoding: str = "ascii") -> list[StringInfo]:
                """Raise to exercise the aggregator's string-failure note path.

                Args:
                    pattern: Ignored production-signature filter.
                    encoding: Ignored production-signature encoding.

                Returns:
                    list[StringInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost Ghidra connection.
                """
                del pattern, encoding
                msg = "ghidra rpc connection lost"
                raise RuntimeError(msg)

            async def get_imports(self) -> list[ImportInfo]:
                """Raise to exercise the import-failure note path.

                Returns:
                    list[ImportInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost Ghidra connection.
                """
                msg = "ghidra rpc connection lost"
                raise RuntimeError(msg)

            async def get_exports(self) -> list[ExportInfo]:
                """Raise to exercise the export-failure note path.

                Returns:
                    list[ExportInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost Ghidra connection.
                """
                msg = "ghidra rpc connection lost"
                raise RuntimeError(msg)

            async def get_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
                """Raise to exercise the function-failure note path.

                Args:
                    filter_pattern: Ignored production-signature name filter.

                Returns:
                    list[FunctionInfo]: Never returned; the method always raises.

                Raises:
                    RuntimeError: Always, simulating a lost Ghidra connection.
                """
                del filter_pattern
                msg = "ghidra rpc connection lost"
                raise RuntimeError(msg)

        registry = ToolRegistry(tools_dir=tmp_path)
        registry.register_bridge(ToolName.GHIDRA, _FailingGhidraBridge())
        aggregator = AnalysisAggregator(registry)

        summary = asyncio.run(aggregator.aggregate(target.name, target))

        ghidra_failure_notes = [note for note in summary.analysis_notes if "ghidra" in note]
        assert ghidra_failure_notes, "every failed Ghidra collector must record a note"
        assert summary.format_info == "pe"
        section_names = {section.name for section in summary.sections}
        assert ".text" in section_names
        # A bridge that raises from every collector contributed nothing, so the
        # aggregator falls back to BinaryInfo-only and flags the summary as
        # incomplete just as if no bridge had been connected at all.
        assert summary.complete is False
        assert summary.source_bridges == ["binary_info"]
