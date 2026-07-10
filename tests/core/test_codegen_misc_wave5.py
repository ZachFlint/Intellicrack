# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-gate tests for ScriptManager, TemplateManager, and AnalysisAggregator (Group 06 Wave 5).

Covers:
  S8-20 — ``ScriptManager.build_execute_command`` for ``ScriptLanguage.R2_COMMANDS``
           returns ``["r2", "-q", "-i", <path ending in .r2>]`` exactly.
  S8-21 — ``TemplateBootstrapError`` is raised when ``export_template_json``
           raises ``RuntimeError``; ``failed_templates`` is non-empty.
  S7-11 — ``AnalysisAggregator`` with only a Cutter bridge contributing data
           yields ``"cutter"`` in ``summary.source_bridges`` and
           ``summary.complete is True``.
  S7-12 — ``AnalysisAggregator`` with both Ghidra and Cutter bridges contributing
           yields both names in ``summary.source_bridges``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import override

import pytest

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.analysis_aggregator import AnalysisAggregator
from intellicrack.core.script_gen import Script, ScriptLanguage, ScriptManager
from intellicrack.core.template_manager import TemplateBootstrapError, TemplateManager
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import (
    BinaryInfo,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    StringInfo,
    ToolName,
)


class _FailingExportDocument:
    """Fake HexDocumentFull implementation whose export_template_json always raises.

    Satisfies the ``HexDocumentFull`` structural protocol without holding any
    real hex document state.  All non-critical methods return safe empty values.
    The ``export_template_json`` method always raises ``RuntimeError`` to
    exercise the ``_bootstrap_single_template`` error-accumulation path.
    """

    def read(self, offset: int, length: int) -> list[int]:
        """Return zeros for any read request.

        Args:
            offset: Byte offset (unused).
            length: Number of bytes to read.

        Returns:
            list[int]: Zero-filled list of ``length`` bytes.
        """
        del offset
        return [0] * length

    def length(self) -> int:
        """Return a nominal document length.

        Returns:
            int: 4096.
        """
        return 4096

    def write(self, offset: int, data: bytes) -> None:
        """Accept write requests silently.

        Args:
            offset: Byte offset (unused).
            data: Data to write (unused).
        """
        del offset, data

    def list_templates(self) -> list[tuple[str, str]]:
        """Return one template name/description pair.

        Returns:
            list[tuple[str, str]]: Single-element list with template name and desc.
        """
        return [("pe_header", "PE Header")]

    def list_templates_detailed(self) -> list[object]:
        """Return one full-detail template entry that will fail on export.

        Returns:
            list[object]: List of (name, description, category, field_count) tuples.
        """
        return [("pe_header", "PE Header", "pe", 10)]

    def register_json_template(self, name: str, json_str: str) -> None:
        """Accept template registration silently.

        Args:
            name: Template name (unused).
            json_str: JSON template string (unused).
        """
        del name, json_str

    def remove_template(self, name: str) -> None:
        """Accept template removal silently.

        Args:
            name: Template name to remove (unused).
        """
        del name

    def export_template_json(self, name: str) -> str:
        """Always raise RuntimeError to trigger bootstrap failure tracking.

        Args:
            name: Template name (unused; error is unconditional).

        Returns:
            str: Never returns; always raises.

        Raises:
            RuntimeError: Always raised to simulate an export failure.
        """
        del name
        raise RuntimeError

    def inspect_at(self, offset: int) -> dict[str, object]:
        """Return an empty inspection result.

        Args:
            offset: Byte offset to inspect (unused).

        Returns:
            dict[str, object]: Empty dict.
        """
        del offset
        return {}


class _AggStubCutterBridge(CutterBridge):
    """Stub CutterBridge that returns minimal valid data without starting Cutter.

    Overrides all network-bound methods so the aggregator receives a non-empty
    ``search_strings`` result (which sets ``contributed = True``) without any
    real Cutter/Rizin process.
    """

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initialize; does not start Cutter.

        Args:
            tool_path: Ignored tool path.
        """

    @override
    async def shutdown(self) -> None:
        """No-op shutdown."""

    @override
    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: True.
        """
        return True

    @override
    async def search_strings(self, pattern: str) -> list[StringInfo]:
        """Return one string entry so ``contributed = True`` in the aggregator.

        Args:
            pattern: Ignored pattern.

        Returns:
            list[StringInfo]: Single string entry at address 0x1000.
        """
        del pattern
        return [StringInfo(address=0x1000, value="cutter_stub_string", encoding="ascii", section=".data")]

    @override
    async def get_imports(self) -> list[ImportInfo]:
        """Return an empty import list.

        Returns:
            list[ImportInfo]: Empty list.
        """
        return []

    @override
    async def get_exports(self) -> list[ExportInfo]:
        """Return an empty export list.

        Returns:
            list[ExportInfo]: Empty list.
        """
        return []

    @override
    async def get_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
        """Return an empty function list.

        Args:
            filter_pattern: Ignored filter.

        Returns:
            list[FunctionInfo]: Empty list.
        """
        del filter_pattern
        return []


class _AggStubGhidraBridge(GhidraBridge):
    """Stub GhidraBridge that returns minimal valid data without starting Ghidra.

    Overrides all network-bound methods so the aggregator receives a non-empty
    ``search_strings`` result (which sets ``contributed = True``) without any
    real Ghidra server process.
    """

    @override
    async def initialize(self, tool_path: Path | None = None) -> None:
        """No-op initialize; does not start Ghidra.

        Args:
            tool_path: Ignored tool path.
        """

    @override
    async def shutdown(self) -> None:
        """No-op shutdown."""

    @override
    async def is_available(self) -> bool:
        """Always available.

        Returns:
            bool: True.
        """
        return True

    @override
    async def search_strings(self, pattern: str, encoding: str = "ascii") -> list[StringInfo]:
        """Return one string entry so ``contributed = True`` in the aggregator.

        Args:
            pattern: Ignored pattern.
            encoding: Ignored encoding filter.

        Returns:
            list[StringInfo]: Single string entry at address 0x2000.
        """
        del pattern, encoding
        return [StringInfo(address=0x2000, value="ghidra_stub_string", encoding="ascii", section=".rdata")]

    @override
    async def get_imports(self) -> list[ImportInfo]:
        """Return an empty import list.

        Returns:
            list[ImportInfo]: Empty list.
        """
        return []

    @override
    async def get_exports(self) -> list[ExportInfo]:
        """Return an empty export list.

        Returns:
            list[ExportInfo]: Empty list.
        """
        return []

    @override
    async def get_functions(self, filter_pattern: str | None = None) -> list[FunctionInfo]:
        """Return an empty function list.

        Args:
            filter_pattern: Ignored filter.

        Returns:
            list[FunctionInfo]: Empty list.
        """
        del filter_pattern
        return []


def _make_binary_info(tmp_path: Path) -> BinaryInfo:
    """Create a minimal BinaryInfo for aggregator tests.

    Args:
        tmp_path: Pytest temporary directory (used as the binary path).

    Returns:
        BinaryInfo: Minimal binary metadata with no sections, imports, or exports.
    """
    return BinaryInfo(
        path=tmp_path / "target.exe",
        name="target.exe",
        size=4096,
        sha256="a" * 64,
        file_type="PE",
        architecture="x86_64",
        is_64bit=True,
        entry_point=0x1000,
        sections=[],
        imports=[],
        exports=[],
    )


class TestScriptManagerR2Command:
    """Gate for S8-20: ScriptManager.build_execute_command for R2_COMMANDS."""

    def test_r2_commands_returns_r2_argv(self, tmp_path: Path) -> None:
        """build_execute_command(R2_COMMANDS script) returns ['r2', '-q', '-i', <path.r2>].

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: ``script_gen.py`` line 1033-1034 —
        ``return ["r2", "-q", "-i", path_str, *extra]`` for ``ScriptLanguage.R2_COMMANDS``.
        Mutation: returning ``["r2pipe", path_str]`` or omitting ``"-q"`` / ``"-i"``
        would fail the element-by-element assertion.
        """
        mgr = ScriptManager(scripts_dir=tmp_path / "scripts")
        script = Script(
            name="probe_sections",
            script_type="cutter",
            language=ScriptLanguage.R2_COMMANDS,
            content="iz\nfl",
            description="List strings and flags",
        )

        cmd = mgr.build_execute_command(script, args=None)

        assert len(cmd) == 4, f"Expected 4-element command list; got {cmd!r}"
        assert cmd[0] == "r2", f"cmd[0] must be 'r2'; got {cmd[0]!r}"
        assert cmd[1] == "-q", f"cmd[1] must be '-q'; got {cmd[1]!r}"
        assert cmd[2] == "-i", f"cmd[2] must be '-i'; got {cmd[2]!r}"
        assert cmd[3].endswith(".r2"), f"cmd[3] must end with '.r2'; got {cmd[3]!r}"

    def test_r2_commands_with_extra_args_appended(self, tmp_path: Path) -> None:
        """Extra args are appended after the script path in R2_COMMANDS invocation.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: ``*extra`` splatted after ``path_str`` at line 1034.
        Mutation: inserting extra before path_str swaps the argv order, making
        the path end up at a wrong index.
        """
        mgr = ScriptManager(scripts_dir=tmp_path / "scripts")
        script = Script(
            name="xrefs_probe",
            script_type="cutter",
            language=ScriptLanguage.R2_COMMANDS,
            content="axt",
            description="Cross-reference probe",
        )

        cmd = mgr.build_execute_command(script, args=["target.bin"])

        assert len(cmd) == 5, f"Expected 5 elements with one extra arg; got {cmd!r}"
        assert cmd[0] == "r2"
        assert cmd[1] == "-q"
        assert cmd[2] == "-i"
        assert cmd[3].endswith(".r2"), f"Script path at cmd[3] must end with .r2; got {cmd[3]!r}"
        assert cmd[4] == "target.bin", f"Extra arg must be last; got {cmd[4]!r}"

    def test_r2_commands_script_path_is_absolute(self, tmp_path: Path) -> None:
        """The materialized script path in the command is an absolute filesystem path.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: ``_materialise_script_path`` writes to ``tempfile.NamedTemporaryFile``
        whose ``name`` attribute is always absolute.  Mutation: using a relative path
        would cause r2 to fail when invoked from a different working directory.
        """
        mgr = ScriptManager(scripts_dir=tmp_path / "scripts")
        script = Script(
            name="sections_probe",
            script_type="cutter",
            language=ScriptLanguage.R2_COMMANDS,
            content="iS",
            description="Section list probe",
        )

        cmd = mgr.build_execute_command(script, args=None)
        script_path = Path(cmd[3])

        assert script_path.is_absolute(), f"Materialized script path must be absolute; got {cmd[3]!r}"


class TestTemplateBootstrapError:
    """Gate for S8-21: TemplateBootstrapError raised when export_template_json fails."""

    def test_bootstrap_raises_on_failing_export(self, tmp_path: Path) -> None:
        """bootstrap_builtins raises TemplateBootstrapError when export raises RuntimeError.

        Args:
            tmp_path: Pytest temporary directory used as config_dir.

        Oracle: ``template_manager.py`` line 186-187 —
        ``if self.failed_templates: raise TemplateBootstrapError(message, self.failed_templates)``.
        Mutation: swallowing the per-template exception in ``_bootstrap_single_template``
        means no failure is recorded, ``failed_templates`` stays empty, and the
        ``TemplateBootstrapError`` is never raised.
        """
        manager = TemplateManager(config_dir=tmp_path)
        document = _FailingExportDocument()

        with pytest.raises(TemplateBootstrapError) as exc_info:
            manager.bootstrap_builtins(document)

        err = exc_info.value
        assert len(err.failed_templates) > 0, f"failed_templates must be non-empty after export failure; got {err.failed_templates!r}"

    def test_bootstrap_error_message_contains_failure_count(self, tmp_path: Path) -> None:
        """TemplateBootstrapError message contains the failure count.

        Args:
            tmp_path: Pytest temporary directory used as config_dir.

        Oracle: message format at line 186 —
        ``f"bootstrap encountered {len(self.failed_templates)} template failure(s)"``.
        Mutation: changing the format string breaks the ``in str(err)`` assertion.
        """
        manager = TemplateManager(config_dir=tmp_path)
        document = _FailingExportDocument()

        with pytest.raises(TemplateBootstrapError) as exc_info:
            manager.bootstrap_builtins(document)

        err = exc_info.value
        msg = str(err)
        assert "bootstrap encountered" in msg, f"Expected 'bootstrap encountered' in error message; got {msg!r}"
        assert "template failure" in msg, f"Expected 'template failure' in error message; got {msg!r}"

    def test_bootstrap_error_failed_templates_are_path_string_pairs(self, tmp_path: Path) -> None:
        """Each failed_template entry is a (Path, str) pair.

        Args:
            tmp_path: Pytest temporary directory used as config_dir.

        Oracle: ``_bootstrap_single_template`` appends
        ``(target_path, str(exc))`` to ``self.failed_templates``.
        Mutation: appending only the error string (not a tuple) causes the
        ``isinstance(entry, tuple)`` assertion to fail.
        """
        manager = TemplateManager(config_dir=tmp_path)
        document = _FailingExportDocument()

        with pytest.raises(TemplateBootstrapError) as exc_info:
            manager.bootstrap_builtins(document)

        for entry in exc_info.value.failed_templates:
            assert isinstance(entry, tuple), f"Each failed_template entry must be a tuple; got {type(entry)!r}: {entry!r}"
            assert len(entry) == 2, f"Each entry must be a 2-tuple; got {entry!r}"
            path_part, msg_part = entry
            assert isinstance(path_part, Path), f"First element must be a Path; got {type(path_part)!r}"
            assert isinstance(msg_part, str), f"Second element must be a str; got {type(msg_part)!r}"

    def test_bootstrap_is_runtime_error_subclass(self) -> None:
        """TemplateBootstrapError is a RuntimeError subclass.

        Oracle: class definition ``class TemplateBootstrapError(RuntimeError):``.
        Mutation: changing the base class to ``Exception`` fails this assertion.
        """
        err = TemplateBootstrapError("msg", [])
        assert isinstance(err, RuntimeError), f"TemplateBootstrapError must subclass RuntimeError; got {type(err).__mro__!r}"


class TestAnalysisAggregatorCutterOnly:
    """Gate for S7-11: AnalysisAggregator with Cutter bridge contributes 'cutter' to summary."""

    def test_cutter_stub_appears_in_source_bridges(self, tmp_path: Path) -> None:
        """Aggregation with a CutterBridge stub yields 'cutter' in source_bridges.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: ``analysis_aggregator.py`` line 206-207 —
        ``if contributed: source_bridges.append(bridge_name)`` where
        ``contributed = True`` when any bridge call succeeds.  ``_AggStubCutterBridge``
        returns a non-empty list from ``search_strings``, so ``contributed`` is True.

        Mutation: removing the ``source_bridges.append(bridge_name)`` line means
        the bridge never appears in the summary even when it contributed data.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        cutter_stub = _AggStubCutterBridge()
        registry.register_bridge(ToolName.CUTTER, cutter_stub)

        aggregator = AnalysisAggregator(tools=registry)
        binary_info = _make_binary_info(tmp_path)

        async def _run() -> None:
            summary = await aggregator.aggregate("target.exe", binary_info)

            assert "cutter" in summary.source_bridges, f"'cutter' must appear in source_bridges; got {summary.source_bridges!r}"
            assert summary.complete is True, f"summary.complete must be True when cutter contributed; got {summary.complete!r}"
            found_stub_string = any(s.value == "cutter_stub_string" for s in summary.strings)
            assert found_stub_string, (
                f"Stub string 'cutter_stub_string' must appear in summary.strings; got {[s.value for s in summary.strings]!r}"
            )

        asyncio.run(_run())

    def test_ghidra_absent_means_only_cutter_in_source_bridges(self, tmp_path: Path) -> None:
        """With only a Cutter stub registered, 'ghidra' must NOT appear in source_bridges.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: the aggregator tries get_ghidra_bridge() first; since GHIDRA is
        not registered, it catches ``ToolError`` and continues without adding
        'ghidra'.  Only 'cutter' appears.  Mutation: adding 'ghidra' unconditionally
        would fail the ``not in`` assertion.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        registry.register_bridge(ToolName.CUTTER, _AggStubCutterBridge())

        aggregator = AnalysisAggregator(tools=registry)
        binary_info = _make_binary_info(tmp_path)

        async def _run() -> None:
            summary = await aggregator.aggregate("target.exe", binary_info)
            assert "ghidra" not in summary.source_bridges, (
                f"'ghidra' must NOT appear when only cutter is registered; got {summary.source_bridges!r}"
            )
            assert "cutter" in summary.source_bridges

        asyncio.run(_run())


class TestAnalysisAggregatorBothBridges:
    """Gate for S7-12: AnalysisAggregator with both Ghidra and Cutter yields both in source_bridges."""

    def test_both_bridge_names_appear_when_both_registered(self, tmp_path: Path) -> None:
        """Aggregation with both stubs yields both 'ghidra' and 'cutter' in source_bridges.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: the aggregator calls ``_collect_from_static_bridge`` twice (once for
        'ghidra', once for 'cutter'); when both succeed, both names are appended.
        ``summary.complete is True`` because at least one bridge contributed.

        Mutation: iterating only over one bridge, or not calling the second one,
        means one name is absent, failing the set-equality assertion.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        registry.register_bridge(ToolName.GHIDRA, _AggStubGhidraBridge())
        registry.register_bridge(ToolName.CUTTER, _AggStubCutterBridge())

        aggregator = AnalysisAggregator(tools=registry)
        binary_info = _make_binary_info(tmp_path)

        async def _run() -> None:
            summary = await aggregator.aggregate("target.exe", binary_info)

            assert "ghidra" in summary.source_bridges, f"'ghidra' must be in source_bridges; got {summary.source_bridges!r}"
            assert "cutter" in summary.source_bridges, f"'cutter' must be in source_bridges; got {summary.source_bridges!r}"
            assert summary.complete is True, f"complete must be True when both bridges contributed; got {summary.complete!r}"

        asyncio.run(_run())

    def test_strings_from_both_bridges_present_in_summary(self, tmp_path: Path) -> None:
        """Strings from both bridge stubs appear in summary.strings after aggregation.

        Args:
            tmp_path: Pytest temporary directory.

        Oracle: ``_collect_from_static_bridge`` calls ``strings.extend(bridge_strings)``
        for each bridge; with both stubs returning one string each, the summary
        must contain both values.  Mutation: overwriting ``strings`` instead of
        extending would retain only the last bridge's strings.
        """
        registry = ToolRegistry(tools_dir=tmp_path / "tools")
        registry.register_bridge(ToolName.GHIDRA, _AggStubGhidraBridge())
        registry.register_bridge(ToolName.CUTTER, _AggStubCutterBridge())

        aggregator = AnalysisAggregator(tools=registry)
        binary_info = _make_binary_info(tmp_path)

        async def _run() -> None:
            summary = await aggregator.aggregate("target.exe", binary_info)
            values = {s.value for s in summary.strings}
            assert "ghidra_stub_string" in values, f"Ghidra stub string must appear in summary.strings; values={values!r}"
            assert "cutter_stub_string" in values, f"Cutter stub string must appear in summary.strings; values={values!r}"

        asyncio.run(_run())
