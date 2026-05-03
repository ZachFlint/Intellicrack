# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 U9 tests for AnalysisAggregator and BridgeAnalysisSummary.

Covers:
- F-0005: deduplication of imports/exports keys on
  ``(dll, function, ordinal)`` (imports) and ``(name, ordinal, address)``
  (exports), so unbound by-ordinal entries with ``address == 0`` are not
  collapsed across distinct ``(dll, function)`` pairs. The pre-fix
  implementation keyed solely on ``address`` and would erase distinct
  imports.
- F-0015: ``BridgeAnalysisSummary.complete`` defaults to ``False`` when
  no real analysis bridge contributed data; consumers must surface the
  "no bridges" condition rather than emitting an authoritative empty
  report.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

from intellicrack.core.analysis_aggregator import AnalysisAggregator
from intellicrack.core.types import (
    BinaryInfo,
    BridgeAnalysisSummary,
    ExportInfo,
    ImportInfo,
    ToolError,
)


_ADDR_TEXT_BASE: int = 0x0040_1000
_IMPORT_BOUND_ADDR_A: int = 0x0040_2000
_EXPORT_TRAMPOLINE_ADDR: int = 0x0040_3000


def _empty_binary_info(
    *,
    imports: list[ImportInfo] | None = None,
    exports: list[ExportInfo] | None = None,
) -> BinaryInfo:
    """Create a BinaryInfo populated with the given imports and exports.

    Args:
        imports: Optional import entries seeded into the binary.
        exports: Optional export entries seeded into the binary.

    Returns:
        BinaryInfo: Minimal but type-complete BinaryInfo for aggregator
            unit tests.
    """
    return BinaryInfo(
        path=Path("/test/binary.exe"),
        name="binary.exe",
        size=4096,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_type="pe",
        architecture="x86_64",
        is_64bit=True,
        entry_point=_ADDR_TEXT_BASE,
        sections=[],
        imports=list(imports or []),
        exports=list(exports or []),
    )


def _registry_no_bridges() -> MagicMock:
    """Build a ToolRegistry mock where every bridge getter raises ToolError.

    Returns:
        MagicMock: Registry whose ``get_*_bridge`` methods raise
            :class:`ToolError`, simulating the "no bridges connected" case.
    """
    registry = MagicMock()
    registry.get_ghidra_bridge.side_effect = ToolError("ghidra unavailable")
    registry.get_cutter_bridge.side_effect = ToolError("cutter unavailable")
    return registry


# ---------------------------------------------------------------------------
# F-0005: imports/exports dedup must not collapse distinct entries that
# happen to share an address. The aggregator's public entry point is
# ``aggregate``; the dedup helpers run as part of that pipeline so we
# exercise their behaviour through the public interface only.
# ---------------------------------------------------------------------------


def _aggregate_with_seeded_data(
    *,
    imports: list[ImportInfo] | None = None,
    exports: list[ExportInfo] | None = None,
) -> BridgeAnalysisSummary:
    """Run ``AnalysisAggregator.aggregate`` with the given seeded imports/exports.

    Args:
        imports: Optional import entries seeded into BinaryInfo.
        exports: Optional export entries seeded into BinaryInfo.

    Returns:
        BridgeAnalysisSummary: The aggregated summary produced when no
            bridges contribute data.
    """
    binary_info = _empty_binary_info(imports=imports, exports=exports)
    aggregator = AnalysisAggregator(_registry_no_bridges())
    return asyncio.run(aggregator.aggregate("binary.exe", binary_info))


def test_f0005_imports_dedup_preserves_distinct_unbound_by_ordinal_entries() -> None:
    """Pre-fix code keyed on address; distinct unbound imports collapsed.

    Two by-ordinal imports from different DLLs frequently both report
    ``address == 0`` (they are not yet bound to a thunk). Keying solely
    on ``address`` collapsed both into one entry and dropped a real,
    distinct import. Keying on ``(dll, function, ordinal)`` preserves
    them, and the aggregator must surface both through its public
    output.
    """
    summary = _aggregate_with_seeded_data(
        imports=[
            ImportInfo(dll="kernel32.dll", function="", ordinal=10, address=0),
            ImportInfo(dll="user32.dll", function="", ordinal=20, address=0),
        ],
    )
    assert len(summary.imports) == 2, "address-keyed dedup would collapse both unbound imports to one entry; expected 2 distinct imports"
    dlls = {imp.dll for imp in summary.imports}
    assert dlls == {"kernel32.dll", "user32.dll"}


def test_f0005_imports_dedup_preserves_distinct_named_imports_at_address_zero() -> None:
    """Distinct named imports sharing ``address == 0`` must not collapse.

    Two named-by-name imports can both be unbound (address 0) when a
    static-analysis bridge has not yet resolved their thunk addresses.
    The pre-fix implementation collapsed both into one entry; the fix
    preserves both because their (dll, function, ordinal) keys differ.
    """
    summary = _aggregate_with_seeded_data(
        imports=[
            ImportInfo(dll="kernel32.dll", function="CreateFileA", ordinal=None, address=0),
            ImportInfo(dll="kernel32.dll", function="ReadFile", ordinal=None, address=0),
        ],
    )
    assert len(summary.imports) == 2
    functions = {imp.function for imp in summary.imports}
    assert functions == {"CreateFileA", "ReadFile"}


def test_f0005_imports_dedup_collapses_exact_duplicates() -> None:
    """Exact duplicates of the same import must still be collapsed.

    The dedup is required precisely to remove duplicates introduced
    when multiple bridges report the same import.
    """
    summary = _aggregate_with_seeded_data(
        imports=[
            ImportInfo(dll="kernel32.dll", function="CreateFileA", ordinal=None, address=_IMPORT_BOUND_ADDR_A),
            ImportInfo(dll="kernel32.dll", function="CreateFileA", ordinal=None, address=_IMPORT_BOUND_ADDR_A),
        ],
    )
    assert len(summary.imports) == 1


def test_f0005_imports_dedup_distinguishes_same_name_different_dll() -> None:
    """Same function name in different DLLs are distinct imports.

    ``CreateFileA`` exists in both ``kernel32.dll`` (modern path) and
    historically ``kernelbase.dll``. Both must be retained even when
    their thunk addresses happen to match.
    """
    summary = _aggregate_with_seeded_data(
        imports=[
            ImportInfo(dll="kernel32.dll", function="CreateFileA", ordinal=None, address=_IMPORT_BOUND_ADDR_A),
            ImportInfo(dll="kernelbase.dll", function="CreateFileA", ordinal=None, address=_IMPORT_BOUND_ADDR_A),
        ],
    )
    assert len(summary.imports) == 2
    dlls = {imp.dll for imp in summary.imports}
    assert dlls == {"kernel32.dll", "kernelbase.dll"}


def test_f0005_exports_dedup_preserves_forwarder_entries_sharing_address() -> None:
    """Forwarder exports legitimately share an address but differ in name.

    PE forwarders route multiple symbols through one trampoline. The
    pre-fix address-only dedup discarded all but the first; the fix
    keys on ``(name, ordinal, address)`` so forwarder symbols survive.
    """
    summary = _aggregate_with_seeded_data(
        exports=[
            ExportInfo(name="ForwardedA", ordinal=1, address=_EXPORT_TRAMPOLINE_ADDR),
            ExportInfo(name="ForwardedB", ordinal=2, address=_EXPORT_TRAMPOLINE_ADDR),
        ],
    )
    assert len(summary.exports) == 2
    names = {exp.name for exp in summary.exports}
    assert names == {"ForwardedA", "ForwardedB"}


def test_f0005_exports_dedup_collapses_exact_duplicates() -> None:
    """Identical export entries must still collapse to one.

    Confirms the dedup still removes genuine duplicates produced when
    multiple bridges enumerate the same export table.
    """
    summary = _aggregate_with_seeded_data(
        exports=[
            ExportInfo(name="DllMain", ordinal=1, address=_EXPORT_TRAMPOLINE_ADDR),
            ExportInfo(name="DllMain", ordinal=1, address=_EXPORT_TRAMPOLINE_ADDR),
        ],
    )
    assert len(summary.exports) == 1


# ---------------------------------------------------------------------------
# F-0015: BridgeAnalysisSummary.complete defaults False when no real bridge.
# ---------------------------------------------------------------------------


def test_f0015_summary_complete_defaults_false_without_source_bridges() -> None:
    """A summary with empty ``source_bridges`` must report ``complete=False``.

    Pre-fix code defaulted ``complete=True`` regardless of contributors.
    The fix makes ``complete`` default to ``False`` so consumers must
    treat any summary lacking a real bridge contribution as
    non-authoritative.
    """
    summary = BridgeAnalysisSummary(
        binary_name="binary.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=[],
        analysis_notes=[],
    )
    assert summary.complete is False


def test_f0015_summary_complete_explicit_true_overrides_default() -> None:
    """The ``complete`` flag is settable to True when bridges contributed.

    Verifies the default-False behaviour does not prevent legitimate
    aggregations (where a real bridge supplied data) from being marked
    complete.
    """
    summary = BridgeAnalysisSummary(
        binary_name="binary.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=["ghidra"],
        analysis_notes=[],
        complete=True,
    )
    assert summary.complete is True


def test_f0015_aggregate_with_no_bridges_marks_summary_incomplete() -> None:
    """End-to-end: aggregation without bridges yields ``complete=False``.

    When every bridge getter raises :class:`ToolError`, the aggregator
    falls back to BinaryInfo-only metadata and must report the summary
    as incomplete. This is the integration-level guarantee that
    consumers can trust ``summary.complete`` to gate authoritative
    consumption.
    """
    binary_info = _empty_binary_info()
    aggregator = AnalysisAggregator(_registry_no_bridges())

    summary = asyncio.run(aggregator.aggregate("binary.exe", binary_info))

    assert summary.complete is False
    assert summary.source_bridges == ["binary_info"]
    assert any("No bridges connected" in note for note in summary.analysis_notes)
