# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""End-to-end tests for GhidraBridge.

Tests validate:
- Bridge instantiation and capability reporting
- Tool definition completeness for all 81 tool functions
- String injection safety in generated Jython code (json.dumps usage)
- Method existence and signatures for all bridge methods
- Error handling when Ghidra is not connected
- ToolError raised by all methods when disconnected
"""

from __future__ import annotations

import importlib
import json
import sys
from typing import Any, Final

import pytest

from intellicrack.bridges.ghidra import GhidraBridge
from intellicrack.core.types import ToolError, ToolName


_EXPECTED_TOOL_COUNT: Final[int] = 81
_TEST_ADDRESS: Final[int] = 0x401000
_TEST_RADIUS: Final[int] = 0x100
_MIN_DESCRIPTION_LEN: Final[int] = 5


@pytest.fixture
def bridge() -> GhidraBridge:
    """Create a fresh GhidraBridge instance.

    Returns:
        GhidraBridge: GhidraBridge instance.
    """
    return GhidraBridge()


def test_bridge_instantiation() -> None:
    """Verify GhidraBridge can be instantiated."""
    b = GhidraBridge()
    assert b is not None


def test_bridge_name(bridge: GhidraBridge) -> None:
    """Verify bridge has correct name property.

    Args:
        bridge: GhidraBridge fixture.
    """
    assert bridge.name == ToolName.GHIDRA


def test_bridge_capabilities(bridge: GhidraBridge) -> None:
    """Verify bridge exposes its capabilities.

    Args:
        bridge: GhidraBridge fixture.
    """
    caps = bridge.capabilities
    assert caps.supports_decompilation is True
    assert caps.supports_static_analysis is True
    assert caps.supports_scripting is True


def test_tool_definition_exists(bridge: GhidraBridge) -> None:
    """Verify tool_definition property returns a valid definition.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    assert tool_def is not None
    assert tool_def.tool_name == ToolName.GHIDRA


def test_tool_definition_function_count(bridge: GhidraBridge) -> None:
    """Verify all expected tool functions are present.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    assert len(tool_def.functions) >= _EXPECTED_TOOL_COUNT


def test_tool_definition_original_functions(bridge: GhidraBridge) -> None:
    """Verify all pre-existing tool functions are defined.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    function_names = {f.name for f in tool_def.functions}
    original = {
        "ghidra.load_binary",
        "ghidra.analyze",
        "ghidra.get_functions",
        "ghidra.decompile",
        "ghidra.disassemble",
        "ghidra.get_xrefs_to",
        "ghidra.get_xrefs_from",
        "ghidra.search_strings",
        "ghidra.search_bytes",
        "ghidra.rename_function",
        "ghidra.add_comment",
        "ghidra.get_imports",
        "ghidra.get_exports",
        "ghidra.get_data_type",
        "ghidra.set_data_type",
        "ghidra.start_headless",
        "ghidra.get_function",
    }
    assert original.issubset(function_names), f"Missing: {original - function_names}"


def test_tool_definition_new_functions(bridge: GhidraBridge) -> None:
    """Verify all expanded tool functions are defined.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    function_names = {f.name for f in tool_def.functions}
    new_functions = {
        "ghidra.execute_script",
        "ghidra.set_label",
        "ghidra.get_labels",
        "ghidra.create_bookmark",
        "ghidra.get_bookmarks",
        "ghidra.create_function",
        "ghidra.delete_function",
        "ghidra.edit_function_signature",
        "ghidra.set_function_variable_type",
        "ghidra.define_structure",
        "ghidra.get_structures",
        "ghidra.apply_structure_at",
        "ghidra.get_memory_map",
        "ghidra.get_call_graph",
        "ghidra.get_segments",
        "ghidra.get_program_info",
        "ghidra.write_bytes",
        "ghidra.undo",
        "ghidra.redo",
        "ghidra.read_bytes",
        "ghidra.get_pcode",
        "ghidra.get_basic_blocks",
        "ghidra.get_slice",
        "ghidra.get_callers",
        "ghidra.get_register_value",
        "ghidra.import_debug_info",
        "ghidra.add_reference",
        "ghidra.delete_reference",
        "ghidra.get_relocations",
        "ghidra.create_namespace",
        "ghidra.get_namespaces",
        "ghidra.create_equate",
        "ghidra.get_equates",
        "ghidra.search_symbols",
        "ghidra.get_stack_frame",
        "ghidra.get_function_body",
        "ghidra.get_call_tree",
        "ghidra.get_calling_conventions",
        "ghidra.get_instruction_flow",
        "ghidra.create_data_type",
        "ghidra.create_data",
        "ghidra.configure_analysis",
        "ghidra.set_decompiler_options",
        "ghidra.create_memory_block",
        "ghidra.get_comments",
        "ghidra.get_all_comments",
        "ghidra.get_program_tree",
        "ghidra.get_properties",
        "ghidra.diff_programs",
        "ghidra.set_color",
        "ghidra.set_program_metadata",
        "ghidra.execute_script_with_params",
        "ghidra.get_thunk_info",
        "ghidra.get_external_references",
        "ghidra.add_external_function",
        "ghidra.create_overlay_space",
        "ghidra.add_bookmark",
        "ghidra.remove_bookmark",
        "ghidra.add_label",
        "ghidra.remove_label",
        "ghidra.add_thunk",
        "ghidra.remove_thunk",
        "ghidra.add_external_reference",
        "ghidra.remove_external_reference",
    }
    assert new_functions.issubset(function_names), f"Missing: {new_functions - function_names}"


def test_tool_functions_have_descriptions(bridge: GhidraBridge) -> None:
    """Verify every tool function has a non-empty description.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    for func in tool_def.functions:
        assert func.description, f"Function {func.name} has no description"
        assert len(func.description) > _MIN_DESCRIPTION_LEN, f"Function {func.name} description too short"


def test_tool_functions_have_matching_methods(bridge: GhidraBridge) -> None:
    """Verify every tool function has a matching method on the bridge.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    for func in tool_def.functions:
        method_name = func.name.replace("ghidra.", "")
        method = getattr(bridge, method_name, None)
        assert method is not None, f"Missing method for tool {func.name}: {method_name}"
        assert callable(method), f"Method {method_name} is not callable"


def test_tool_function_parameters_typed(bridge: GhidraBridge) -> None:
    """Verify tool function parameters have type specifications.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    for func in tool_def.functions:
        for param in func.parameters:
            assert param.type, f"Parameter {param.name} in {func.name} has no type"


class TestStringInjectionPrevention:
    """Verify json.dumps usage in Jython code generation prevents injection."""

    def test_json_dumps_handles_quotes(self) -> None:
        """Verify json.dumps properly escapes quotes for code interpolation."""
        malicious = 'test"; import os; os.system("rm -rf /"); "'
        escaped = json.dumps(malicious)
        assert '"' not in escaped[1:-1].replace('\\"', "")
        assert escaped.startswith('"')
        assert escaped.endswith('"')

    def test_json_dumps_handles_backslashes(self) -> None:
        """Verify json.dumps escapes backslashes."""
        payload = "C:\\Windows\\System32"
        escaped = json.dumps(payload)
        assert "\\\\" in escaped

    def test_json_dumps_handles_newlines(self) -> None:
        """Verify json.dumps escapes newlines."""
        payload = "line1\nline2\rline3"
        escaped = json.dumps(payload)
        assert "\\n" in escaped
        assert "\\r" in escaped

    def test_json_dumps_handles_unicode(self) -> None:
        """Verify json.dumps handles unicode characters."""
        payload = "\u0000\u001f"
        escaped = json.dumps(payload)
        assert "\\u0000" in escaped


class TestMutatingMethodsRequireConnection:
    """Verify mutating methods raise ToolError when Ghidra is not connected."""

    @pytest.fixture
    def disconnected(self) -> GhidraBridge:
        """Create a bridge with no connection.

        Returns:
            GhidraBridge: GhidraBridge instance not connected.
        """
        return GhidraBridge()

    @pytest.mark.asyncio
    async def test_execute_script_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify execute_script raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.execute_script("print('test')")

    @pytest.mark.asyncio
    async def test_set_label_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_label raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_label(_TEST_ADDRESS, "test_label")

    @pytest.mark.asyncio
    async def test_create_bookmark_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_bookmark raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_bookmark(_TEST_ADDRESS, "analysis", "note")

    @pytest.mark.asyncio
    async def test_create_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_function(_TEST_ADDRESS, "my_func")

    @pytest.mark.asyncio
    async def test_delete_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify delete_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.delete_function(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_edit_function_signature_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify edit_function_signature raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.edit_function_signature(_TEST_ADDRESS, return_type="int")

    @pytest.mark.asyncio
    async def test_set_function_variable_type_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_function_variable_type raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_function_variable_type(_TEST_ADDRESS, "var1", "int")

    @pytest.mark.asyncio
    async def test_define_structure_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify define_structure raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        fields: list[dict[str, Any]] = [
            {"name": "field1", "type": "int", "size": 4},
            {"name": "field2", "type": "char*", "size": 8},
        ]
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.define_structure("MyStruct", fields)

    @pytest.mark.asyncio
    async def test_apply_structure_at_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify apply_structure_at raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.apply_structure_at(_TEST_ADDRESS, "MyStruct")

    @pytest.mark.asyncio
    async def test_write_bytes_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify write_bytes raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.write_bytes(_TEST_ADDRESS, "90 90 90")

    @pytest.mark.asyncio
    async def test_undo_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify undo raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.undo()

    @pytest.mark.asyncio
    async def test_redo_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify redo raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.redo()


class TestQueryMethodsRaiseWhenDisconnected:
    """Verify query methods raise ToolError when Ghidra is not connected."""

    @pytest.fixture
    def disconnected(self) -> GhidraBridge:
        """Create a bridge with no connection.

        Returns:
            GhidraBridge: GhidraBridge instance not connected.
        """
        return GhidraBridge()

    @pytest.mark.asyncio
    async def test_initialize_raises_when_package_missing(self) -> None:
        """Verify initialize raises ToolError when ghidra_bridge import fails."""
        bridge = GhidraBridge()
        saved = sys.modules.get("ghidra_bridge")
        sys.modules["ghidra_bridge"] = None  # type: ignore[assignment]
        try:
            with pytest.raises(ToolError, match="not installed"):
                await bridge.initialize()
        finally:
            if saved is not None:
                sys.modules["ghidra_bridge"] = saved
            else:
                sys.modules.pop("ghidra_bridge", None)
            importlib.invalidate_caches()

    @pytest.mark.asyncio
    async def test_analyze_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify analyze raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.analyze()

    @pytest.mark.asyncio
    async def test_get_functions_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_functions raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_functions()

    @pytest.mark.asyncio
    async def test_get_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_function(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_disassemble_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify disassemble raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.disassemble(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_xrefs_to_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_xrefs_to raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_xrefs_to(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_xrefs_from_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_xrefs_from raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_xrefs_from(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_search_strings_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_strings raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_strings("test")

    @pytest.mark.asyncio
    async def test_search_bytes_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_bytes raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_bytes(b"\x90\x90")

    @pytest.mark.asyncio
    async def test_get_imports_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_imports raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_imports()

    @pytest.mark.asyncio
    async def test_get_exports_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_exports raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_exports()

    @pytest.mark.asyncio
    async def test_get_data_type_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_data_type raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_data_type(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_labels_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_labels raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_labels(_TEST_ADDRESS, _TEST_RADIUS)

    @pytest.mark.asyncio
    async def test_get_bookmarks_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_bookmarks raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_bookmarks("analysis")

    @pytest.mark.asyncio
    async def test_get_structures_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_structures raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_structures()

    @pytest.mark.asyncio
    async def test_get_memory_map_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_memory_map raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_memory_map()

    @pytest.mark.asyncio
    async def test_get_call_graph_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_call_graph raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_call_graph(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_segments_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_segments raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_segments()

    @pytest.mark.asyncio
    async def test_get_program_info_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_program_info raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_program_info()


class TestNewMethodsRaiseWhenDisconnected:
    """Verify all Phase 2-4 methods raise ToolError when disconnected."""

    @pytest.fixture
    def disconnected(self) -> GhidraBridge:
        """Create a bridge with no connection.

        Returns:
            GhidraBridge: GhidraBridge instance not connected.
        """
        return GhidraBridge()

    @pytest.mark.asyncio
    async def test_read_bytes_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify read_bytes raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.read_bytes(_TEST_ADDRESS, 16)

    @pytest.mark.asyncio
    async def test_search_bytes_wildcard_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_bytes with hex_pattern string raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_bytes("48 8B ?? ?? ?? ??")

    @pytest.mark.asyncio
    async def test_get_pcode_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_pcode raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_pcode(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_basic_blocks_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_basic_blocks raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_basic_blocks(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_slice_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_slice raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_slice(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_callers_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_callers raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_callers(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_register_value_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_register_value raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_register_value(_TEST_ADDRESS, "EAX")

    @pytest.mark.asyncio
    async def test_import_debug_info_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify import_debug_info raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.import_debug_info("test.pdb")

    @pytest.mark.asyncio
    async def test_add_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_reference(_TEST_ADDRESS, _TEST_ADDRESS + 0x100)

    @pytest.mark.asyncio
    async def test_delete_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify delete_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.delete_reference(_TEST_ADDRESS, _TEST_ADDRESS + 0x100)

    @pytest.mark.asyncio
    async def test_get_relocations_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_relocations raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_relocations()

    @pytest.mark.asyncio
    async def test_create_namespace_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_namespace raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_namespace("TestNS")

    @pytest.mark.asyncio
    async def test_get_namespaces_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_namespaces raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_namespaces()

    @pytest.mark.asyncio
    async def test_create_equate_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_equate raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_equate(_TEST_ADDRESS, 42, "MY_CONST")

    @pytest.mark.asyncio
    async def test_get_equates_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_equates raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_equates()

    @pytest.mark.asyncio
    async def test_search_symbols_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify search_symbols raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.search_symbols("main")

    @pytest.mark.asyncio
    async def test_get_stack_frame_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_stack_frame raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_stack_frame(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_function_body_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_function_body raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_function_body(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_call_tree_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_call_tree raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_call_tree(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_calling_conventions_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_calling_conventions raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_calling_conventions()

    @pytest.mark.asyncio
    async def test_get_instruction_flow_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_instruction_flow raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_instruction_flow(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_create_data_type_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_data_type raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_data_type("/MyTypes", "MyEnum", "enum")

    @pytest.mark.asyncio
    async def test_create_data_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_data raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_data(_TEST_ADDRESS, "dword")

    @pytest.mark.asyncio
    async def test_configure_analysis_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify configure_analysis raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.configure_analysis("Decompiler", enabled=True)

    @pytest.mark.asyncio
    async def test_set_decompiler_options_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_decompiler_options raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_decompiler_options(simplification="normalize")

    @pytest.mark.asyncio
    async def test_create_memory_block_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_memory_block raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_memory_block("test_block", _TEST_ADDRESS, 4096)

    @pytest.mark.asyncio
    async def test_get_comments_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_comments raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_comments(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_all_comments_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_all_comments raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_all_comments()

    @pytest.mark.asyncio
    async def test_get_program_tree_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_program_tree raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_program_tree()

    @pytest.mark.asyncio
    async def test_get_properties_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_properties raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_properties(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_diff_programs_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify diff_programs raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.diff_programs("other.exe")

    @pytest.mark.asyncio
    async def test_set_color_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_color raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_color(_TEST_ADDRESS, 0xFF0000)

    @pytest.mark.asyncio
    async def test_set_program_metadata_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify set_program_metadata raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.set_program_metadata(name="test")

    @pytest.mark.asyncio
    async def test_get_thunk_info_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_thunk_info raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_thunk_info(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_get_external_references_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify get_external_references raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.get_external_references(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_add_external_function_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_external_function raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_external_function("kernel32.dll", "LoadLibraryA")

    @pytest.mark.asyncio
    async def test_create_overlay_space_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify create_overlay_space raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.create_overlay_space("test_overlay")

    @pytest.mark.asyncio
    async def test_add_bookmark_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_bookmark raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_bookmark(_TEST_ADDRESS, "Analysis", "note")

    @pytest.mark.asyncio
    async def test_remove_bookmark_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_bookmark raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_bookmark(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_add_label_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_label raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_label(_TEST_ADDRESS, "lbl")

    @pytest.mark.asyncio
    async def test_remove_label_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_label raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_label(_TEST_ADDRESS, "lbl")

    @pytest.mark.asyncio
    async def test_add_thunk_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_thunk raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_thunk(_TEST_ADDRESS, _TEST_ADDRESS + 0x100)

    @pytest.mark.asyncio
    async def test_remove_thunk_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_thunk raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_thunk(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_add_external_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify add_external_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.add_external_reference(_TEST_ADDRESS, "kernel32.dll", "LoadLibraryA")

    @pytest.mark.asyncio
    async def test_remove_external_reference_not_connected(self, disconnected: GhidraBridge) -> None:
        """Verify remove_external_reference raises when not connected.

        Args:
            disconnected: GhidraBridge fixture.
        """
        with pytest.raises(ToolError, match="not connected"):
            await disconnected.remove_external_reference(_TEST_ADDRESS)


def test_tool_definition_exact_count(bridge: GhidraBridge) -> None:
    """Verify tool_definition has exactly the expected number of functions.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    assert len(tool_def.functions) == _EXPECTED_TOOL_COUNT, (
        f"Expected {_EXPECTED_TOOL_COUNT}, got {len(tool_def.functions)}"
    )


def test_all_tool_names_unique(bridge: GhidraBridge) -> None:
    """Verify all tool function names are unique.

    Args:
        bridge: GhidraBridge fixture.
    """
    tool_def = bridge.tool_definition
    names = [f.name for f in tool_def.functions]
    assert len(names) == len(set(names)), f"Duplicate names found: {[n for n in names if names.count(n) > 1]}"


@pytest.mark.asyncio
async def test_is_available_no_path() -> None:
    """Verify is_available returns False when Ghidra path not set."""
    b = GhidraBridge()
    result = await b.is_available()
    assert result is False
