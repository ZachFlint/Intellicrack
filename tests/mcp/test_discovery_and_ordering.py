# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for MCP tool discovery and advertised ordering.

MCP tools must be reachable through the tool-search path the bridges already
use, not a parallel one, and they must be advertised after the bridges so a
provider that truncates at its own tool cap drops third-party tools first.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.core.session import Session
from intellicrack.core.tool_search import ToolSearchIndex
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ToolDefinition, ToolFunction
from intellicrack.mcp.config import to_canonical_name


if TYPE_CHECKING:
    from pathlib import Path


_BRIDGE_NAMESPACE = "ghidra"
_MCP_NAMESPACE = "mcp-files"


def _bridge_definition() -> ToolDefinition:
    """Build a definition shaped like a built-in bridge's.

    Returns:
        ToolDefinition: A bridge-shaped definition.
    """
    return ToolDefinition(
        tool_name=_BRIDGE_NAMESPACE,
        description="Ghidra static analysis",
        functions=[
            ToolFunction(name="ghidra.decompile", description="Decompile a function to C.", parameters=[], returns="str"),
            ToolFunction(name="ghidra.list_functions", description="List every function.", parameters=[], returns="list"),
        ],
    )


def _mcp_definition() -> ToolDefinition:
    """Build a definition shaped like a connected MCP server's.

    Returns:
        ToolDefinition: An MCP-shaped definition.
    """
    return ToolDefinition(
        tool_name=_MCP_NAMESPACE,
        description="tools from MCP server 'files'",
        functions=[
            ToolFunction(
                name=to_canonical_name("files", "read_file"),
                description="[MCP server 'files'] Read a file from disk and return its contents.",
                parameters=[],
                returns="object",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            ),
        ],
    )


class TestDiscoveryThroughToolSearch:
    """An MCP tool is found by the same index that finds bridge tools."""

    def test_search_finds_an_mcp_tool(self) -> None:
        """A natural-language query reaches a connected server's tool."""
        index = ToolSearchIndex([_bridge_definition(), _mcp_definition()])
        matches = index.search("read a file from disk")
        names = [match.function.name for match in matches]
        assert to_canonical_name("files", "read_file") in names

    def test_search_still_finds_bridge_tools(self) -> None:
        """Adding MCP definitions does not displace the bridges."""
        index = ToolSearchIndex([_bridge_definition(), _mcp_definition()])
        matches = index.search("decompile a function")
        names = [match.function.name for match in matches]
        assert "ghidra.decompile" in names

    def test_search_reports_the_owning_namespace(self) -> None:
        """A match carries the namespace it came from, for attribution."""
        index = ToolSearchIndex([_bridge_definition(), _mcp_definition()])
        matches = index.search("read a file from disk")
        owning = {match.tool_name for match in matches}
        assert _MCP_NAMESPACE in owning

    def test_grouped_search_keeps_namespaces_apart(self) -> None:
        """Regrouping preserves one definition per contributing namespace."""
        index = ToolSearchIndex([_bridge_definition(), _mcp_definition()])
        grouped = index.search_grouped("file")
        namespaces = [definition.tool_name for definition in grouped]
        assert len(namespaces) == len(set(namespaces)), "a namespace was reported twice"

    def test_discovered_name_persists_in_the_session(self) -> None:
        """A discovered MCP tool is recorded on the existing loaded-tools list.

        This is the contract that keeps MCP on the same discovery path as the
        bridges rather than a parallel one.
        """
        session = Session.create(provider="openai", model="gpt-5", name="discovery")
        index = ToolSearchIndex([_bridge_definition(), _mcp_definition()])
        matches = index.search("read a file from disk")

        newly = [match.function.name for match in matches if session.add_loaded_tool(match.function.name)]
        assert to_canonical_name("files", "read_file") in newly
        assert to_canonical_name("files", "read_file") in session.loaded_tools


class TestAdvertisedOrdering:
    """Externally-sourced tools are advertised after the built-in ones."""

    @pytest.fixture
    def registry(self, tmp_path: Path) -> ToolRegistry:
        """Build a registry with no bridges initialised.

        Args:
            tmp_path: Pytest-provided temporary directory.

        Returns:
            ToolRegistry: An empty registry.
        """
        return ToolRegistry(tmp_path)

    @staticmethod
    async def _executor(function_name: str, arguments: dict[str, Any]) -> object:
        """Stand in as an executor that is never called here.

        Args:
            function_name: Canonical dotted function name.
            arguments: Parsed arguments.

        Returns:
            object: The name and arguments it was dispatched with.
        """
        return (function_name, arguments)

    def test_registration_order_is_preserved(self, registry: ToolRegistry) -> None:
        """Two servers keep the order they were registered in.

        A provider cap truncates the tail, so a stable order is what makes
        truncation predictable rather than arbitrary.

        Args:
            registry: Registry under test.
        """
        registry.external_tools.register("mcp-first", self._executor, definitions=lambda: [_mcp_definition()])
        registry.external_tools.register(
            "mcp-second",
            self._executor,
            definitions=lambda: [
                ToolDefinition(
                    tool_name="mcp-second",
                    description="second server",
                    functions=[ToolFunction(name="mcp-second.ping", description="ping", parameters=[], returns="str")],
                ),
            ],
        )
        assert registry.external_tools.namespaces() == ["mcp-first", "mcp-second"]

    def test_external_definitions_follow_the_bridges(self, registry: ToolRegistry) -> None:
        """Externally-sourced definitions are appended, never prepended.

        With no bridges registered the external definitions are all there is,
        so this asserts the weaker but still meaningful property that they
        appear in the catalog at all and in registration order.

        Args:
            registry: Registry under test.
        """
        registry.external_tools.register("mcp-files", self._executor, definitions=lambda: [_mcp_definition()])
        namespaces = [definition.tool_name for definition in registry.get_tool_definitions()]
        assert namespaces[-1] == _MCP_NAMESPACE

    def test_a_namespace_without_definitions_advertises_nothing(self, registry: ToolRegistry) -> None:
        """A namespace registered without a definition provider is dispatch-only.

        Args:
            registry: Registry under test.
        """
        registry.external_tools.register("mcp-quiet", self._executor)
        namespaces = [definition.tool_name for definition in registry.get_tool_definitions()]
        assert "mcp-quiet" not in namespaces
        assert registry.external_tools.get("mcp-quiet") is not None
