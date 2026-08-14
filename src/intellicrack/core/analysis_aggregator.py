# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Bridge analysis aggregator for Intellicrack.

Queries connected bridges and aggregates their output into a unified BridgeAnalysisSummary by delegating all actual analysis to the bridge
layer.
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

_logger = get_logger(__name__)


class AnalysisAggregator:
    """Aggregates analysis data from connected bridges.

    Queries GhidraBridge and CutterBridge for strings, imports, exports, functions, and sections, then packages everything into a single
    BridgeAnalysisSummary.
    """

    def __init__(self, tools: ToolRegistry) -> None:
        """Initialize the AnalysisAggregator with a tool registry.

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
        for additional data (strings, functions). The returned summary's
        ``complete`` flag is True only when at least one real analysis
        bridge contributed data; consumers (notably AI report generation)
        must check ``complete`` before treating the summary as
        authoritative.

        Args:
            binary_name: Display name of the binary being analyzed.
            binary_info: Pre-loaded binary metadata from the binary bridge.

        Returns:
            BridgeAnalysisSummary: Aggregated data from all contributing bridges.
        """
        _logger.info("aggregation_starting", binary_name=binary_name)
        strings: list[StringInfo] = []
        imports: list[ImportInfo] = list(binary_info.imports)
        exports: list[ExportInfo] = list(binary_info.exports)
        sections: list[SectionInfo] = list(binary_info.sections)
        functions: list[FunctionInfo] = []
        source_bridges: list[str] = []
        notes: list[str] = []

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
            "cutter",
            strings,
            imports,
            exports,
            functions,
            source_bridges,
            notes,
        )

        imports = _deduplicate_imports(imports)
        exports = _deduplicate_exports(exports)

        complete = bool(source_bridges)
        if not complete:
            source_bridges.append("binary_info")
            notes.append("No bridges connected; using BinaryInfo metadata only")

        _logger.info(
            "aggregation_completed",
            binary_name=binary_name,
            source_bridges=source_bridges,
            strings_count=len(strings),
            functions_count=len(functions),
            complete=complete,
        )
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
            complete=complete,
        )

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
        """Collect data from a static analysis bridge (Ghidra or Cutter).

        Args:
            bridge_name: Name of the bridge ("ghidra" or "cutter").
            strings: Accumulator list for discovered strings.
            imports: Accumulator list for import entries.
            exports: Accumulator list for export entries.
            functions: Accumulator list for analyzed functions.
            source_bridges: Accumulator list for contributing bridge names.
            notes: Accumulator list for analysis notes.
        """
        try:
            bridge = self._tools.get_ghidra_bridge() if bridge_name == "ghidra" else self._tools.get_cutter_bridge()
        except ToolError:
            _logger.exception("static_bridge_unavailable", bridge=bridge_name)
            return

        contributed = False

        try:
            bridge_strings = await bridge.search_strings("")
            strings.extend(bridge_strings)
            contributed = True
        except (OSError, RuntimeError, ToolError) as exc:
            _logger.warning(
                "static_bridge_strings_failed",
                bridge=bridge_name,
                error=str(exc),
            )
            notes.append(f"{bridge_name} string search failed: {exc}")

        try:
            bridge_imports = await bridge.get_imports()
            imports.extend(bridge_imports)
            contributed = True
        except (OSError, RuntimeError, ToolError) as exc:
            _logger.warning(
                "static_bridge_imports_failed",
                bridge=bridge_name,
                error=str(exc),
            )
            notes.append(f"{bridge_name} import enumeration failed: {exc}")

        try:
            bridge_exports = await bridge.get_exports()
            exports.extend(bridge_exports)
            contributed = True
        except (OSError, RuntimeError, ToolError) as exc:
            _logger.warning(
                "static_bridge_exports_failed",
                bridge=bridge_name,
                error=str(exc),
            )
            notes.append(f"{bridge_name} export enumeration failed: {exc}")

        try:
            bridge_functions = await bridge.get_functions()
            functions.extend(bridge_functions)
            contributed = True
        except (OSError, RuntimeError, ToolError) as exc:
            _logger.warning(
                "static_bridge_functions_failed",
                bridge=bridge_name,
                error=str(exc),
            )
            notes.append(f"{bridge_name} function enumeration failed: {exc}")

        if contributed:
            source_bridges.append(bridge_name)


def _deduplicate_imports(imports: list[ImportInfo]) -> list[ImportInfo]:
    """Remove duplicate imports by ``(dll, function, ordinal)``.

    Address alone is not a stable identity for an import: unbound or
    by-ordinal entries frequently share ``address == 0``, and even bound
    entries can share an address across DLLs in pathological PE layouts.
    Keying on ``(dll, function, ordinal)`` preserves every distinct
    import while still collapsing exact duplicates.

    Args:
        imports: List of import entries possibly containing duplicates.

    Returns:
        list[ImportInfo]: Deduplicated list preserving first-seen order.
    """
    seen: set[tuple[str, str, int | None]] = set()
    result: list[ImportInfo] = []
    for imp in imports:
        key = (imp.dll, imp.function, imp.ordinal)
        if key not in seen:
            seen.add(key)
            result.append(imp)
    return result


def _deduplicate_exports(exports: list[ExportInfo]) -> list[ExportInfo]:
    """Remove duplicate exports by ``(name, ordinal, address)``.

    Forwarder exports legitimately share a single trampoline address
    while exposing distinct names/ordinals. Keying on the natural identity
    triple keeps every unique export entry while still removing exact
    duplicates introduced when multiple bridges report the same symbol.

    Args:
        exports: List of export entries possibly containing duplicates.

    Returns:
        list[ExportInfo]: Deduplicated list preserving first-seen order.
    """
    seen: set[tuple[str, int, int]] = set()
    result: list[ExportInfo] = []
    for exp in exports:
        key = (exp.name, exp.ordinal, exp.address)
        if key not in seen:
            seen.add(key)
            result.append(exp)
    return result
