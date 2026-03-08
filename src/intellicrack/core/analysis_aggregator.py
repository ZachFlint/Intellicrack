# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Bridge analysis aggregator for Intellicrack.

Queries connected bridges and aggregates their output into a unified
BridgeAnalysisSummary. Replaces the standalone license_analyzer module
by delegating all actual analysis to the bridge layer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .logging import get_logger
from .types import (
    BridgeAnalysisSummary,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    SectionInfo,
    StringInfo,
    ToolError,
)


if TYPE_CHECKING:
    from .tools import ToolRegistry
    from .types import BinaryInfo

_logger = get_logger("core.analysis_aggregator")


class AnalysisAggregator:
    """Aggregates analysis data from connected bridges.

    Queries BinaryBridge, GhidraBridge, and Radare2Bridge for strings,
    imports, exports, functions, and sections, then packages everything
    into a single BridgeAnalysisSummary.

    Attributes:
        _tools: Reference to the shared ToolRegistry.
    """

    def __init__(self, tools: ToolRegistry) -> None:
        """Initialize the aggregator with a tool registry.

        Args:
            tools: ToolRegistry providing access to bridge instances.
        """
        self._tools = tools

    async def aggregate(
        self,
        binary_name: str,
        binary_info: BinaryInfo,
    ) -> BridgeAnalysisSummary:
        """Aggregate analysis data from all connected bridges.

        Starts with data already present in BinaryInfo (sections, imports,
        exports, file_type, architecture), then queries connected bridges
        for additional data (strings, functions).

        Args:
            binary_name: Display name of the binary being analyzed.
            binary_info: Pre-loaded binary metadata from the binary bridge.

        Returns:
            BridgeAnalysisSummary with data from all contributing bridges.
        """
        strings: list[StringInfo] = []
        imports: list[ImportInfo] = list(binary_info.imports)
        exports: list[ExportInfo] = list(binary_info.exports)
        sections: list[SectionInfo] = list(binary_info.sections)
        functions: list[FunctionInfo] = []
        source_bridges: list[str] = []
        notes: list[str] = []

        await self._collect_from_binary_bridge(strings, source_bridges, notes)

        await self._collect_from_static_bridge(
            "ghidra",
            strings,
            imports,
            exports,
            functions,
            source_bridges,
            notes,
        )
        await self._collect_from_static_bridge(
            "radare2",
            strings,
            imports,
            exports,
            functions,
            source_bridges,
            notes,
        )

        imports = _deduplicate_imports(imports)
        exports = _deduplicate_exports(exports)

        if not source_bridges:
            source_bridges.append("binary_info")
            notes.append("No bridges connected; using BinaryInfo metadata only")

        return BridgeAnalysisSummary(
            binary_name=binary_name,
            strings=strings,
            imports=imports,
            exports=exports,
            sections=sections,
            functions=functions,
            format_info=binary_info.file_type,
            architecture=binary_info.architecture,
            source_bridges=source_bridges,
            analysis_notes=notes,
        )

    async def _collect_from_binary_bridge(
        self,
        strings: list[StringInfo],
        source_bridges: list[str],
        notes: list[str],
    ) -> None:
        """Collect string data from the BinaryBridge.

        Args:
            strings: Accumulator list for discovered strings.
            source_bridges: Accumulator list for contributing bridge names.
            notes: Accumulator list for analysis notes.
        """
        try:
            binary_bridge = self._tools.get_binary_bridge()
        except ToolError:
            notes.append("BinaryBridge not available")
            return

        try:
            raw_strings = await binary_bridge.get_strings()
            for addr, value in raw_strings:
                strings.append(
                    StringInfo(
                        address=addr,
                        value=value,
                        encoding="utf-8",
                        section="",
                    )
                )
            source_bridges.append("binary")
        except Exception as exc:
            _logger.warning(
                "binary_bridge_strings_failed",
                extra={"error": str(exc)},
            )
            notes.append(f"BinaryBridge string extraction failed: {exc}")

    async def _collect_from_static_bridge(
        self,
        bridge_name: str,
        strings: list[StringInfo],
        imports: list[ImportInfo],
        exports: list[ExportInfo],
        functions: list[FunctionInfo],
        source_bridges: list[str],
        notes: list[str],
    ) -> None:
        """Collect data from a static analysis bridge (Ghidra or radare2).

        Args:
            bridge_name: Name of the bridge ("ghidra" or "radare2").
            strings: Accumulator list for discovered strings.
            imports: Accumulator list for import entries.
            exports: Accumulator list for export entries.
            functions: Accumulator list for analyzed functions.
            source_bridges: Accumulator list for contributing bridge names.
            notes: Accumulator list for analysis notes.
        """
        try:
            bridge = self._tools.get_ghidra_bridge() if bridge_name == "ghidra" else self._tools.get_radare2_bridge()
        except ToolError:
            return

        contributed = False

        try:
            bridge_strings = await bridge.search_strings("")
            strings.extend(bridge_strings)
            contributed = True
        except Exception as exc:
            _logger.warning(
                "static_bridge_strings_failed",
                extra={"bridge": bridge_name, "error": str(exc)},
            )
            notes.append(f"{bridge_name} string search failed: {exc}")

        try:
            bridge_imports = await bridge.get_imports()
            imports.extend(bridge_imports)
            contributed = True
        except Exception as exc:
            _logger.warning(
                "static_bridge_imports_failed",
                extra={"bridge": bridge_name, "error": str(exc)},
            )
            notes.append(f"{bridge_name} import enumeration failed: {exc}")

        try:
            bridge_exports = await bridge.get_exports()
            exports.extend(bridge_exports)
            contributed = True
        except Exception as exc:
            _logger.warning(
                "static_bridge_exports_failed",
                extra={"bridge": bridge_name, "error": str(exc)},
            )
            notes.append(f"{bridge_name} export enumeration failed: {exc}")

        try:
            bridge_functions = await bridge.get_functions()
            functions.extend(bridge_functions)
            contributed = True
        except Exception as exc:
            _logger.warning(
                "static_bridge_functions_failed",
                extra={"bridge": bridge_name, "error": str(exc)},
            )
            notes.append(f"{bridge_name} function enumeration failed: {exc}")

        if contributed:
            source_bridges.append(bridge_name)


def _deduplicate_imports(imports: list[ImportInfo]) -> list[ImportInfo]:
    """Remove duplicate imports by address.

    Args:
        imports: List of import entries possibly containing duplicates.

    Returns:
        Deduplicated list preserving first-seen order.
    """
    seen: set[int] = set()
    result: list[ImportInfo] = []
    for imp in imports:
        if imp.address not in seen:
            seen.add(imp.address)
            result.append(imp)
    return result


def _deduplicate_exports(exports: list[ExportInfo]) -> list[ExportInfo]:
    """Remove duplicate exports by address.

    Args:
        exports: List of export entries possibly containing duplicates.

    Returns:
        Deduplicated list preserving first-seen order.
    """
    seen: set[int] = set()
    result: list[ExportInfo] = []
    for exp in exports:
        if exp.address not in seen:
            seen.add(exp.address)
            result.append(exp)
    return result
