# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for AnalysisAggregator.

Tests validate:
- Aggregation with mocked ToolRegistry
- Graceful handling when no bridges connected
- BinaryInfo data propagation
- Exception handling from failed bridge calls
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from intellicrack.core.analysis_aggregator import AnalysisAggregator
from intellicrack.core.types import (
    BinaryInfo,
    BridgeAnalysisSummary,
    ExportInfo,
    ImportInfo,
    SectionInfo,
    ToolError,
)


ADDR_BASE = 0x401000
ADDR_IMPORT = 0x402000
ADDR_EXPORT = 0x403000


def _make_binary_info() -> BinaryInfo:
    """Create a test BinaryInfo instance.

    Returns:
        BinaryInfo: BinaryInfo with minimal test data.
    """
    return BinaryInfo(
        path=Path("/test/binary.exe"),
        name="binary.exe",
        size=65536,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_type="pe",
        architecture="x86_64",
        is_64bit=True,
        entry_point=ADDR_BASE,
        sections=[
            SectionInfo(
                name=".text",
                virtual_address=0x1000,
                virtual_size=0x5000,
                raw_size=0x4800,
                characteristics=0x60000020,
                entropy=6.5,
            ),
        ],
        imports=[
            ImportInfo(
                dll="kernel32.dll",
                function="CreateFileA",
                ordinal=None,
                address=ADDR_IMPORT,
            ),
        ],
        exports=[
            ExportInfo(
                name="DllMain",
                ordinal=1,
                address=ADDR_EXPORT,
            ),
        ],
    )


def _make_tool_registry_no_bridges() -> MagicMock:
    """Create a mock ToolRegistry where all bridge getters raise ToolError.

    Returns:
        MagicMock: MagicMock configured to raise ToolError on bridge access.
    """
    registry = MagicMock()
    registry.get_ghidra_bridge.side_effect = ToolError("not available")
    registry.get_cutter_bridge.side_effect = ToolError("not available")
    return registry


class TestAnalysisAggregatorNoBridges:
    """Tests for aggregation when no bridges are connected."""

    @staticmethod
    def test_aggregate_no_bridges_returns_binary_info_data() -> None:
        """Verify aggregation uses BinaryInfo data when no bridges available."""
        registry = _make_tool_registry_no_bridges()
        aggregator = AnalysisAggregator(registry)
        binary_info = _make_binary_info()

        result = asyncio.get_event_loop().run_until_complete(aggregator.aggregate("binary.exe", binary_info))

        assert isinstance(result, BridgeAnalysisSummary)
        assert result.binary_name == "binary.exe"
        assert result.format_info == "pe"
        assert result.architecture == "x86_64"
        assert len(result.imports) == 1
        assert len(result.exports) == 1
        assert len(result.sections) == 1
        assert "binary_info" in result.source_bridges

    @staticmethod
    def test_aggregate_no_bridges_has_note() -> None:
        """Verify a note is added when no bridges contribute."""
        registry = _make_tool_registry_no_bridges()
        aggregator = AnalysisAggregator(registry)
        binary_info = _make_binary_info()

        result = asyncio.get_event_loop().run_until_complete(aggregator.aggregate("binary.exe", binary_info))

        notes_text = " ".join(result.analysis_notes)
        assert "No bridges connected" in notes_text


class TestAnalysisAggregatorExceptionHandling:
    """Tests for graceful exception handling from bridge calls."""

    @staticmethod
    def test_aggregate_handles_static_bridge_exception() -> None:
        """Verify aggregation continues when static bridge methods raise."""
        registry = MagicMock()

        ghidra = MagicMock()
        ghidra.search_strings = AsyncMock(side_effect=RuntimeError("connection lost"))
        ghidra.get_imports = AsyncMock(side_effect=RuntimeError("connection lost"))
        ghidra.get_exports = AsyncMock(side_effect=RuntimeError("connection lost"))
        ghidra.get_functions = AsyncMock(side_effect=RuntimeError("connection lost"))
        registry.get_ghidra_bridge.return_value = ghidra
        registry.get_cutter_bridge.side_effect = ToolError("not available")

        aggregator = AnalysisAggregator(registry)
        binary_info = _make_binary_info()

        result = asyncio.get_event_loop().run_until_complete(aggregator.aggregate("binary.exe", binary_info))

        assert isinstance(result, BridgeAnalysisSummary)
        assert any("ghidra" in note for note in result.analysis_notes)


class TestDeduplication:
    """Tests for import/export deduplication."""

    @staticmethod
    def test_duplicate_imports_deduplicated() -> None:
        """Verify duplicate imports by address are removed."""
        registry = MagicMock()

        ghidra = MagicMock()
        ghidra.search_strings = AsyncMock(return_value=[])
        ghidra.get_imports = AsyncMock(
            return_value=[
                ImportInfo(dll="kernel32.dll", function="CreateFileA", ordinal=None, address=ADDR_IMPORT),
            ],
        )
        ghidra.get_exports = AsyncMock(return_value=[])
        ghidra.get_functions = AsyncMock(return_value=[])
        registry.get_ghidra_bridge.return_value = ghidra
        registry.get_cutter_bridge.side_effect = ToolError("not available")

        binary_info = _make_binary_info()
        aggregator = AnalysisAggregator(registry)

        result = asyncio.get_event_loop().run_until_complete(aggregator.aggregate("binary.exe", binary_info))

        import_addrs = [imp.address for imp in result.imports]
        assert import_addrs.count(ADDR_IMPORT) == 1
