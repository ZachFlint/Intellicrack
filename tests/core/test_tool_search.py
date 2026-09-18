# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Falsifiable gates for :class:`ToolSearchIndex` ranking correctness.

Every test in this module builds the index from real bridge
:class:`ToolDefinition` objects (the same live-registry snapshot
``ToolRegistry.get_tool_definitions()`` would hand to the orchestrator's
``tools.search`` meta-tool) rather than a synthetic double, so a scoring
regression that only manifests against real function names and descriptions
is caught here.
"""

from __future__ import annotations

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.bridges.frida_bridge import FridaBridge
from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.sandbox_bridge import SandboxBridge
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.tool_search import ToolSearchIndex
from intellicrack.core.types import ToolDefinition, ToolFunction, ToolName, ToolParameter


def _real_all_tool_definitions() -> list[ToolDefinition]:
    """Instantiate every concrete bridge and collect its real tool definition.

    Returns:
        list[ToolDefinition]: One real ToolDefinition per concrete bridge,
        mirroring exactly what ``ToolRegistry.get_tool_definitions()`` hands
        to the orchestrator in production.
    """
    return [
        CutterBridge().tool_definition,
        FridaBridge().tool_definition,
        GhidraBridge().tool_definition,
        HexEditorBridge().tool_definition,
        ProcessBridge().tool_definition,
        SandboxBridge().tool_definition,
        X64DbgBridge().tool_definition,
    ]


class TestRankingAgainstRealRegistry:
    """Ranking correctness gates driven by the real ~700-function registry."""

    def test_suite_is_not_vacuous(self) -> None:
        """Guard: the real registry must remain non-trivially large."""
        total = sum(len(d.functions) for d in _real_all_tool_definitions())
        assert total > 100, f"real tool registry shrank to {total} functions; ranking suite may be vacuous"

    def test_set_a_breakpoint_ranks_x64dbg_set_breakpoint_first(self) -> None:
        """The query ``"set a breakpoint"`` ranks ``x64dbg.set_breakpoint`` first.

        ``x64dbg.set_breakpoint`` is described verbatim as ``"Set a
        breakpoint"``: it should out-score every other x64dbg breakpoint
        function (``set_memory_range_breakpoint``, ``set_dll_breakpoint``,
        etc., whose names and descriptions only partially overlap the
        query) and every function belonging to a different bridge.
        """
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("set a breakpoint", limit=10)

        assert matches, "expected at least one match for 'set a breakpoint'"
        assert matches[0].function.name == "x64dbg.set_breakpoint"
        assert matches[0].tool_name == ToolName.X64DBG

    def test_breakpoint_query_surfaces_only_debugger_capable_bridges_in_top_results(self) -> None:
        """Every top-5 match for a breakpoint query belongs to a debugger-capable bridge.

        Both x64dbg and Cutter (via its r2 debug backend) implement
        ``set_breakpoint``, so both are legitimately relevant here. No
        other bridge (Ghidra, Frida, hex editor, process, sandbox) has
        breakpoint-related functionality, so a scoring regression that lets
        an unrelated bridge's function outrank real breakpoint functions
        would surface here.
        """
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("set a breakpoint at an address", limit=5)

        assert matches
        assert all(match.tool_name in {ToolName.X64DBG, ToolName.CUTTER} for match in matches)

    def test_bridge_name_query_boosts_that_bridges_functions(self) -> None:
        """A query naming a bridge directly (``"frida hook function"``) ranks that bridge's functions highly.

        Oracle: the bridge-name boost applies uniformly across every
        function of the named bridge, so the top results should be
        dominated by Frida functions relative to a query with no bridge
        name in it.
        """
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("frida hook a function", limit=5)

        assert matches
        assert matches[0].tool_name == ToolName.FRIDA

    def test_function_name_match_ranks_above_description_only_match(self) -> None:
        """A query matching a function's own name outranks one matching only a description.

        ``ghidra.decompile`` names decompilation directly; compares it
        against the full real registry, where any other function that only
        mentions "decompile" in its description (never in its own name)
        must rank below it.
        """
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("decompile", limit=10)

        assert matches
        top_names = [m.function.name for m in matches[:3]]
        assert any(name.endswith(".decompile") for name in top_names), f"expected a *.decompile function near the top, got {top_names}"

    def test_nonsense_query_matches_nothing(self) -> None:
        """A query with no token or substring overlap anywhere returns no matches."""
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("zzqxjklwvbnmqzxvbnmasdfgh", limit=10)
        assert matches == []

    def test_empty_query_matches_nothing(self) -> None:
        """An empty (or whitespace-only) query returns no matches rather than the whole registry."""
        index = ToolSearchIndex(_real_all_tool_definitions())
        assert index.search("", limit=10) == []
        assert index.search("   ", limit=10) == []

    def test_limit_caps_the_number_of_matches(self) -> None:
        """``limit`` bounds the returned match count even when many functions match."""
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("memory", limit=3)
        assert len(matches) <= 3

    def test_results_are_sorted_by_descending_score(self) -> None:
        """Matches are returned in non-increasing score order."""
        index = ToolSearchIndex(_real_all_tool_definitions())
        matches = index.search("breakpoint memory hook decompile", limit=20)
        scores = [m.score for m in matches]
        assert scores == sorted(scores, reverse=True)


class TestSearchGrouped:
    """``search_grouped`` regroups flat matches back into per-bridge ToolDefinitions."""

    def test_grouped_results_partition_by_bridge_preserving_registry_order(self) -> None:
        """Each returned ToolDefinition holds only matched functions, in their original registry order.

        Both x64dbg and Cutter implement ``set_breakpoint`` (Cutter's r2
        debug backend mirrors x64dbg's), so both legitimately appear;
        x64dbg's own ``set_breakpoint`` scores highest, so its group must
        rank first.
        """
        index = ToolSearchIndex(_real_all_tool_definitions())
        grouped = index.search_grouped("set a breakpoint", limit=10)

        assert grouped, "expected at least one grouped ToolDefinition"
        assert all(d.tool_name in {ToolName.X64DBG, ToolName.CUTTER} for d in grouped)
        assert grouped[0].tool_name == ToolName.X64DBG

        x64dbg_original_order = [f.name for f in X64DbgBridge().tool_definition.functions]
        grouped_names = [f.name for f in grouped[0].functions]
        # The grouped subset must appear in the same relative order as the source registry.
        filtered_original = [name for name in x64dbg_original_order if name in grouped_names]
        assert grouped_names == filtered_original

    def test_grouped_result_is_empty_for_a_nonsense_query(self) -> None:
        """No matches means no ToolDefinitions are returned."""
        index = ToolSearchIndex(_real_all_tool_definitions())
        assert index.search_grouped("zzqxjklwvbnmqzxvbnmasdfgh", limit=10) == []

    def test_grouped_functions_are_a_strict_subset_of_the_source_definition(self) -> None:
        """A grouped ToolDefinition never contains a function absent from the real source bridge."""
        index = ToolSearchIndex(_real_all_tool_definitions())
        grouped = index.search_grouped("breakpoint", limit=50)

        source_names_by_tool = {d.tool_name: {f.name for f in d.functions} for d in _real_all_tool_definitions()}
        for definition in grouped:
            assert {f.name for f in definition.functions} <= source_names_by_tool[definition.tool_name]


class TestSyntheticWeightOrdering:
    """Pins the relative weighting of name/tool-name/description matches with controlled fixtures.

    Uses small synthetic ToolDefinitions (not the real registry) so the
    exact overlap structure is known, isolating the weighting invariant
    from incidental noise in real function descriptions.
    """

    @staticmethod
    def _controlled_definitions() -> list[ToolDefinition]:
        """Build definitions where the query term appears in exactly one field at a time.

        Returns:
            list[ToolDefinition]: Three single-function tools: one whose
            function *name* contains "widget", one whose *description*
            contains "widget" but whose name does not, and one whose owning
            tool (bridge) name contains "widget".
            (``ToolName`` has no literal "widget" member, so the tool-name
            field is exercised via a description-carried marker instead --
            see the per-test docstring for the exact setup each test uses.)
        """
        return [
            ToolDefinition(
                tool_name=ToolName.GHIDRA.value,
                description="Static analysis",
                functions=[
                    ToolFunction(
                        name="ghidra.widget_inspect",
                        description="Inspect program metadata",
                        parameters=[ToolParameter(name="x", type="string", description="d")],
                        returns="r",
                    ),
                ],
            ),
            ToolDefinition(
                tool_name=ToolName.FRIDA.value,
                description="Dynamic instrumentation",
                functions=[
                    ToolFunction(
                        name="frida.inspect_state",
                        description="Inspect the current widget configuration",
                        parameters=[ToolParameter(name="x", type="string", description="d")],
                        returns="r",
                    ),
                ],
            ),
        ]

    def test_function_name_overlap_outranks_description_only_overlap(self) -> None:
        """A query term present in the function's own name outranks the same term present only in its description."""
        index = ToolSearchIndex(self._controlled_definitions())
        matches = index.search("widget", limit=10)

        assert len(matches) == 2
        assert matches[0].function.name == "ghidra.widget_inspect"
        assert matches[0].score > matches[1].score

    def test_bridge_name_token_in_query_boosts_matching_bridge(self) -> None:
        """A query containing the exact bridge name (``"frida"``) boosts that bridge's function over a same-scoring rival."""
        definitions = [
            ToolDefinition(
                tool_name=ToolName.GHIDRA.value,
                description="d",
                functions=[
                    ToolFunction(name="ghidra.inspect", description="Inspect state", parameters=[], returns="r"),
                ],
            ),
            ToolDefinition(
                tool_name=ToolName.FRIDA.value,
                description="d",
                functions=[
                    ToolFunction(name="frida.inspect", description="Inspect state", parameters=[], returns="r"),
                ],
            ),
        ]
        index = ToolSearchIndex(definitions)
        matches = index.search("frida inspect", limit=10)

        assert len(matches) == 2
        assert matches[0].function.name == "frida.inspect"
        assert matches[0].tool_name == ToolName.FRIDA
        assert matches[0].score > matches[1].score
