# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real-data coverage for :mod:`intellicrack.core.tools`.

Audit shard 05 flagged ``ToolRegistry.execute_tool_call`` as exercised only
through error cases (unknown tool, unknown function, not callable) and
``get_tool_definitions`` / ``set_session`` as effectively untested on the happy
path. These tests close those gaps by driving the production registry end to
end:

* ``execute_tool_call`` dispatches to the real :class:`HexEditorBridge` against
  a real Windows System32 PE, opening the file through the Rust hexcore and
  reading back the genuine ``MZ`` magic bytes. The result is the actual bridge
  return value, not an injected sentinel.
* The capability gate is exercised with a real method the bridge genuinely
  lacks the capability for (``run_python_script`` requires scripting; the hex
  editor disables it), proving the gate raises a real :class:`ToolError`.
* ``get_tool_definitions`` is validated against each bridge's own
  ``tool_definition`` so the schema returned to the LLM is the real one.
* ``set_session`` propagation is verified by confirming the real bridge
  publishes its live :class:`ToolState` into the session after a real dispatch.

The registry and bridges are the production classes; only genuinely absent
external tools cause a documented skip.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest
import pytest_asyncio

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.session import Session
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import BreakpointInfo, ProviderName, ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator
    from pathlib import Path


_BRIDGE_COUNT_ALL: Final[int] = 7
_MZ_MAGIC_HEX: Final[str] = "4D 5A"
_PE_HEADER_READ_LEN: Final[int] = 2


def _file_size(path: Path) -> int:
    """Return the on-disk size of ``path`` from a synchronous context.

    Args:
        path: File whose size to read.

    Returns:
        int: Size of the file in bytes.
    """
    return path.stat().st_size


@pytest_asyncio.fixture
async def initialized_registry(tmp_path: Path) -> AsyncGenerator[ToolRegistry]:
    """Provide a fully initialized real ToolRegistry and shut it down after.

    Args:
        tmp_path: Pytest temporary directory used as the tools directory.

    Yields:
        ToolRegistry: A registry whose bridges have been
        instantiated and the locally-initializable ones (including the hex
        editor) initialized.
    """
    registry = ToolRegistry(tools_dir=tmp_path)
    await registry.initialize()
    try:
        yield registry
    finally:
        await registry.shutdown()


class TestExecuteToolCallRealDispatch:
    """Real dispatch of ``execute_tool_call`` to a live bridge method."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_hex_editor_open_real_pe_returns_real_size(
        initialized_registry: ToolRegistry,
        real_pe_dll: Path,
    ) -> None:
        """Opening a real PE through the registry returns its real size.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
        """
        bridge = initialized_registry.get_hex_editor_bridge()
        if not await bridge.is_available():
            pytest.skip("hex editor Rust core (intellicrack_hexcore) is not available")

        opened = await initialized_registry.execute_tool_call(
            "hex_editor",
            "open_file",
            {"path": str(real_pe_dll)},
        )
        assert isinstance(opened, dict)
        assert opened["size"] == _file_size(real_pe_dll)
        assert opened["modified"] is False

    @staticmethod
    @pytest.mark.asyncio
    async def test_hex_editor_reads_real_mz_magic(
        initialized_registry: ToolRegistry,
        real_pe_dll: Path,
    ) -> None:
        """Reading offset 0 of a real PE through the registry yields ``MZ``.

        This proves the tool call actually reached the real binary's bytes:
        every PE begins with the literal ``MZ`` (``4D 5A``) DOS signature.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
        """
        bridge = initialized_registry.get_hex_editor_bridge()
        if not await bridge.is_available():
            pytest.skip("hex editor Rust core (intellicrack_hexcore) is not available")

        await initialized_registry.execute_tool_call(
            "hex_editor",
            "open_file",
            {"path": str(real_pe_dll)},
        )
        magic = await initialized_registry.execute_tool_call(
            "hex_editor",
            "read_bytes",
            {"offset": 0, "length": _PE_HEADER_READ_LEN},
        )
        assert magic == _MZ_MAGIC_HEX

    @staticmethod
    @pytest.mark.asyncio
    async def test_dotted_function_name_routes_to_method(
        initialized_registry: ToolRegistry,
        real_pe_dll: Path,
    ) -> None:
        """A dotted ``tool.function`` name resolves to the bare method.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
        """
        bridge = initialized_registry.get_hex_editor_bridge()
        if not await bridge.is_available():
            pytest.skip("hex editor Rust core (intellicrack_hexcore) is not available")

        opened = await initialized_registry.execute_tool_call(
            "hex_editor",
            "hex_editor.open_file",
            {"path": str(real_pe_dll)},
        )
        assert isinstance(opened, dict)
        assert opened["size"] == _file_size(real_pe_dll)

    @staticmethod
    @pytest.mark.asyncio
    async def test_tool_name_is_case_insensitive(
        initialized_registry: ToolRegistry,
    ) -> None:
        """Uppercase and lowercase tool names both route to the same bridge.

        The registry lower-cases the caller-supplied name before resolving it
        to a ``ToolName`` enum value, so ``"X64DBG"`` must reach the same
        ``X64DbgBridge`` instance as ``"x64dbg"``.  Falsifiability oracle:
        call the bridge directly and assert both dispatch results equal it.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
        """
        bridge = initialized_registry.get_x64dbg_bridge()
        oracle: list[BreakpointInfo] = await bridge.get_breakpoints()

        result_upper: object = await initialized_registry.execute_tool_call("X64DBG", "get_breakpoints", {})
        result_lower: object = await initialized_registry.execute_tool_call("x64dbg", "get_breakpoints", {})

        assert result_upper == oracle, f"'X64DBG' dispatch returned {result_upper!r}, expected oracle {oracle!r}"
        assert result_lower == oracle, f"'x64dbg' dispatch returned {result_lower!r}, expected oracle {oracle!r}"


class TestExecuteToolCallCapabilityGate:
    """The real capability gate rejects methods the bridge cannot perform."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_scripting_disabled_bridge_is_gated(
        initialized_registry: ToolRegistry,
    ) -> None:
        """``run_python_script`` is rejected because scripting is disabled.

        The hex editor exposes ``run_python_script`` (mapped to the
        ``scripting`` capability) but constructs with ``supports_scripting=False``,
        so the registry's capability gate must raise a real ``ToolError``
        before the method runs.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
        """
        bridge = initialized_registry.get_hex_editor_bridge()
        assert bridge.capabilities.has_capability("scripting") is False
        assert hasattr(bridge, "run_python_script")

        with pytest.raises(ToolError, match="missing capability"):
            await initialized_registry.execute_tool_call(
                "hex_editor",
                "run_python_script",
                {"source": "print(1)"},
            )


class TestToolDefinitionsRealSchema:
    """``get_tool_definitions`` returns each bridge's real LLM schema."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_definitions_match_bridge_definitions(
        initialized_registry: ToolRegistry,
    ) -> None:
        """Every returned definition equals the owning bridge's own schema.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
        """
        definitions = initialized_registry.get_tool_definitions()
        assert len(definitions) == _BRIDGE_COUNT_ALL

        by_name = {d.tool_name: d for d in definitions}
        for tool_name in initialized_registry.get_available_tools():
            bridge = initialized_registry.get(tool_name)
            assert bridge is not None
            assert by_name[tool_name].description == bridge.tool_definition.description
            func_names = {fn.name for fn in by_name[tool_name].functions}
            assert func_names == {fn.name for fn in bridge.tool_definition.functions}
            assert func_names, f"{tool_name.value} exposes no functions"

    @staticmethod
    @pytest.mark.asyncio
    async def test_hex_editor_advertises_open_file(
        initialized_registry: ToolRegistry,
    ) -> None:
        """The hex editor schema advertises its real ``open_file`` function.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
        """
        definitions = initialized_registry.get_tool_definitions()
        hex_def = next(d for d in definitions if d.tool_name == ToolName.HEX_EDITOR)
        advertised = {fn.name for fn in hex_def.functions}
        assert any(name.endswith("open_file") for name in advertised), f"hex editor must advertise open_file, got {sorted(advertised)}"


class TestSetSessionPropagation:
    """``set_session`` wires the session into bridges for real dispatches."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_session_receives_tool_state_after_open(
        initialized_registry: ToolRegistry,
        real_pe_dll: Path,
    ) -> None:
        """Opening a real PE publishes the bridge's live state into the session.

        Args:
            initialized_registry: Fully initialized real ToolRegistry.
            real_pe_dll: Real System32 PE DLL fixture (``kernel32.dll``).
        """
        bridge = initialized_registry.get_hex_editor_bridge()
        if not await bridge.is_available():
            pytest.skip("hex editor Rust core (intellicrack_hexcore) is not available")

        session = Session.create(provider=ProviderName.OLLAMA, model="test-model")
        initialized_registry.set_session(session)

        await initialized_registry.execute_tool_call(
            "hex_editor",
            "open_file",
            {"path": str(real_pe_dll)},
        )
        assert ToolName.HEX_EDITOR in session.tool_states
        published = session.tool_states[ToolName.HEX_EDITOR]
        assert published.tool == ToolName.HEX_EDITOR
        assert published.target_path is not None
        assert published.target_path.name.lower() == real_pe_dll.name.lower()


_ALIGNMENT_GRID_SIZE: Final[int] = 512


class TestRegisterBridgeRealInstance:
    """``register_bridge`` swaps in a real bridge and routes to it."""

    @staticmethod
    @pytest.mark.asyncio
    async def test_registered_bridge_is_returned_and_dispatched(
        tmp_path: Path,
    ) -> None:
        """A freshly registered real bridge is reached by the full dispatch path.

        After registering a real ``HexEditorBridge``, the test drives
        ``execute_tool_call`` end-to-end (tool-name normalisation, bridge
        lookup, capability check, attribute resolution, coroutine dispatch).
        The independent oracle is calling ``bridge.get_alignment_grid()``
        directly on the same instance: if the registry routes to the wrong
        bridge, or fails to resolve the method, the oracle stays at ``0``
        while the dispatch result is ``512``, or vice-versa.

        Args:
            tmp_path: Pytest temporary directory used as the tools directory.
        """
        registry = ToolRegistry(tools_dir=tmp_path)
        bridge = HexEditorBridge()
        registry.register_bridge(ToolName.HEX_EDITOR, bridge)

        assert registry.get(ToolName.HEX_EDITOR) is bridge
        assert registry.get_hex_editor_bridge() is bridge
        assert ToolName.HEX_EDITOR in registry.get_available_tools()

        set_result = await registry.execute_tool_call(
            "hex_editor",
            "set_alignment_grid",
            {"size": _ALIGNMENT_GRID_SIZE},
        )
        assert set_result is True, f"set_alignment_grid dispatch returned {set_result!r}, expected True"

        oracle_grid: int = await bridge.get_alignment_grid()
        assert oracle_grid == _ALIGNMENT_GRID_SIZE, (
            f"direct bridge oracle returned {oracle_grid}, expected {_ALIGNMENT_GRID_SIZE} after dispatch"
        )

        get_result = await registry.execute_tool_call(
            "hex_editor",
            "get_alignment_grid",
            {},
        )
        assert get_result == _ALIGNMENT_GRID_SIZE, (
            f"get_alignment_grid dispatch returned {get_result!r}, expected oracle {_ALIGNMENT_GRID_SIZE}"
        )

        await registry.shutdown()
