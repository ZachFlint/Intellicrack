# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for the CutterBridge Cutter/Rizin integration.

Tests validate:
- Bridge instantiation and capability flags
- Tool definition completeness (80 functions, all resolve to methods)
- Tool definition parameter names match method signatures
- initialize() verifies Rizin availability and raises ToolError when absent
- initialize() stores tool_path and prepends to PATH
- load_binary() coerces string paths to Path objects
- search_bytes() accepts both bytes and str inputs
- write_bytes() accepts hex string and returns True
- assemble_at() uses r2pipe pa command instead of standalone rasm2
- add_comment() maps comment_type to correct Rizin commands
- _close_existing_r2() handles quit() failures gracefully
- Methods raise ToolError when no binary is loaded or not analyzed
- Section permission integer to rwx string conversion
- Bug fixes: entry point double-baddr, save_binary wtf command
- New methods: get_symbols, get_libraries, read_bytes, get_flags, etc.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path
from typing import Final, cast
from unittest.mock import patch

import pytest
import r2pipe

from intellicrack.bridges.cutter import CutterBridge
from intellicrack.core.types import ToolError, ToolName
from intellicrack.ui.panels.cutter_panel import perm_to_rwx


_EXPECTED_TOOL_FUNC_COUNT: Final[int] = 80
_TEST_ADDRESS: Final[int] = 0x401000
_MIN_DESC_LEN: Final[int] = 5


class _CommandRecorder:
    """r2pipe stand-in that records commands and returns configurable JSON.

    Captures every command sent through ``cmd()`` so tests can verify the
    exact Rizin commands the bridge constructs.

    Attributes:
        commands: Running list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to response string used by
            ``cmd()`` to select a canned reply.

    Attributes:
        commands: Running list of every command string passed to ``cmd()``.
        responses: Mapping of command prefix to response string used by
            ``cmd()`` to select a canned reply.

    Args:
        responses: Mapping of command prefix to response string.  If a
            command starts with a key, the corresponding value is returned.
            Falls back to empty string.
    """

    commands: list[str]
    responses: dict[str, str]

    def __init__(self, responses: dict[str, str] | None = None) -> None:
        self.commands = []
        self.responses = responses or {}

    def cmd(self, command: str) -> str:
        """Record ``command`` and return the configured response.

        Args:
            command: The r2 command string issued by the bridge.

        Returns:
            str: Configured response for the longest matching prefix, or
            an empty string when no configured prefix matches.
        """
        self.commands.append(command)
        for prefix, response in self.responses.items():
            if command.startswith(prefix):
                return response
        return ""

    def quit(self) -> None:
        """No-op ``quit`` for test cleanup."""


class _FailingQuitR2:
    """r2pipe stand-in whose ``quit()`` raises ``RuntimeError``."""

    def cmd(self, _command: str) -> str:
        """Return an empty response regardless of the command.

        Args:
            _command: Ignored command string.

        Returns:
            str: Empty string.
        """
        return ""

    def quit(self) -> None:
        """Raise ``RuntimeError`` to simulate a dead session.

        Raises:
            RuntimeError: Always.
        """
        msg = "broken pipe"
        raise RuntimeError(msg)


def _as_r2pipe(double: _CommandRecorder | _FailingQuitR2) -> r2pipe.open:
    """Cast a test double to the ``r2pipe.open`` type.

    Runtime invariant: ``_CommandRecorder`` and ``_FailingQuitR2`` implement
    the exact subset of the ``r2pipe.open`` interface that ``CutterBridge``
    consumes -- ``cmd(str) -> str`` and ``quit() -> None``.  The bridge
    never accesses any other r2pipe member in production, so these test
    doubles are duck-type equivalents for assignment to ``bridge.r2``.
    Centralising the cast here keeps the invariant documented in one
    place rather than scattered across every call site.

    Args:
        double: Test double that duck-types the ``r2pipe.open`` interface.

    Returns:
        r2pipe.open: The same instance, typed as ``r2pipe.open`` for the
        bridge's setter signature.
    """
    return cast(r2pipe.open, double)


@pytest.fixture
def bridge() -> CutterBridge:
    """Create a fresh CutterBridge instance.

    Returns:
        CutterBridge: Unconnected CutterBridge.
    """
    return CutterBridge()


@pytest.fixture
def recorder() -> _CommandRecorder:
    """Create a default CommandRecorder with common responses.

    Returns:
        _CommandRecorder: Recorder with analysis/metadata stubs.
    """
    return _CommandRecorder({
        "e asm.arch": "x86",
        "e asm.bits": "64",
        "/xj": "[]",
        "aflj": "[]",
        "izj": "[]",
        "iSj": "[]",
        "iij": "[]",
        "iEj": "[]",
        "axtj": "[]",
        "axfj": "[]",
        "pdj": "[]",
        "afij": "[]",
        "itj": "[]",
        "ij": '[{"bin":{"class":"PE","arch":"x86","bits":64,"baddr":0,"entry":0}}]',
        "agj": "[]",
    })


@pytest.fixture
def loaded_bridge(recorder: _CommandRecorder) -> CutterBridge:
    """Create a bridge with an r2 session and analyzed state.

    Uses the public ``r2`` property setter and ``analyze()`` method
    to avoid accessing protected members.

    Args:
        recorder: Command recorder fixture.

    Returns:
        CutterBridge: Bridge ready for method calls.
    """
    b = CutterBridge()
    b.r2 = _as_r2pipe(recorder)
    asyncio.get_event_loop().run_until_complete(b.analyze())
    recorder.commands.clear()
    return b


class TestBridgeInstantiation:
    """Verify CutterBridge basic properties after construction."""

    def test_instantiation(self) -> None:
        """Verify CutterBridge can be created."""
        b = CutterBridge()
        assert b is not None

    def test_name(self, bridge: CutterBridge) -> None:
        """Verify bridge reports ToolName.CUTTER.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.name == ToolName.CUTTER

    def test_r2_is_none_initially(self, bridge: CutterBridge) -> None:
        """Verify r2 connection is None before initialization.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.r2 is None

    def test_r2_property_settable(self) -> None:
        """Verify the public r2 property setter works."""
        bridge = CutterBridge()
        typed_rec = _as_r2pipe(_CommandRecorder())
        bridge.r2 = typed_rec
        assert bridge.r2 is typed_rec


class TestCapabilities:
    """Verify capability flags match actual bridge functionality."""

    def test_supports_static_analysis(self, bridge: CutterBridge) -> None:
        """Verify static analysis is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_static_analysis is True

    def test_does_not_support_dynamic_analysis(self, bridge: CutterBridge) -> None:
        """Verify dynamic analysis is not claimed.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_dynamic_analysis is False

    def test_supports_decompilation(self, bridge: CutterBridge) -> None:
        """Verify decompilation is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_decompilation is True

    def test_does_not_support_debugging(self, bridge: CutterBridge) -> None:
        """Verify debugging is not claimed.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_debugging is False

    def test_supports_patching(self, bridge: CutterBridge) -> None:
        """Verify patching is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_patching is True

    def test_supports_scripting(self, bridge: CutterBridge) -> None:
        """Verify scripting is supported.

        Args:
            bridge: CutterBridge fixture.
        """
        assert bridge.capabilities.supports_scripting is True


class TestToolDefinition:
    """Verify tool_definition completeness and method alignment."""

    def test_tool_definition_exists(self, bridge: CutterBridge) -> None:
        """Verify tool_definition property returns a valid definition.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        assert td is not None
        assert td.tool_name == ToolName.CUTTER

    def test_expected_function_count(self, bridge: CutterBridge) -> None:
        """Verify all 21 tool functions are present.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        assert len(td.functions) == _EXPECTED_TOOL_FUNC_COUNT

    def test_all_expected_functions_present(self, bridge: CutterBridge) -> None:
        """Verify every expected function name is in the definition.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = {f.name for f in td.functions}
        assert len(names) == _EXPECTED_TOOL_FUNC_COUNT
        core_funcs = {
            "cutter.load_binary",
            "cutter.analyze",
            "cutter.get_functions",
            "cutter.decompile",
            "cutter.disassemble",
            "cutter.get_xrefs_to",
            "cutter.get_xrefs_from",
            "cutter.search_strings",
            "cutter.search_bytes",
            "cutter.get_imports",
            "cutter.get_exports",
            "cutter.get_sections",
            "cutter.rename_function",
            "cutter.add_comment",
            "cutter.write_bytes",
            "cutter.execute_command",
            "cutter.get_function",
            "cutter.search_bytes_wildcard",
            "cutter.assemble_at",
            "cutter.seek",
            "cutter.get_function_address",
            "cutter.get_function_graph",
            "cutter.get_all_strings",
            "cutter.get_symbols",
            "cutter.get_libraries",
            "cutter.get_headers",
            "cutter.get_debug_info",
            "cutter.get_classes",
            "cutter.get_relocations",
            "cutter.get_resources",
            "cutter.search_rop_gadgets",
            "cutter.get_callgraph",
            "cutter.get_vtables",
            "cutter.get_syscalls",
            "cutter.read_bytes",
            "cutter.save_binary",
            "cutter.get_comments",
            "cutter.get_flags",
            "cutter.add_flag",
            "cutter.resolve_flag",
        }
        assert core_funcs.issubset(names), f"Missing: {core_funcs - names}"

    def test_no_duplicate_cutter_assemble(self, bridge: CutterBridge) -> None:
        """Verify cutter.assemble (duplicate of assemble_at) was removed.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = [f.name for f in td.functions]
        assert "cutter.assemble" not in names

    def test_execute_command_not_execute(self, bridge: CutterBridge) -> None:
        """Verify the tool function is named execute_command, not execute.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        names = {f.name for f in td.functions}
        assert "cutter.execute" not in names
        assert "cutter.execute_command" in names

    def test_all_functions_have_descriptions(self, bridge: CutterBridge) -> None:
        """Verify every tool function has a non-trivial description.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            assert len(func.description) > _MIN_DESC_LEN, f"{func.name} description too short"

    def test_all_functions_resolve_to_methods(self, bridge: CutterBridge) -> None:
        """Verify every tool_def function name maps to a callable method.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            method_name = func.name.replace("cutter.", "")
            method = getattr(bridge, method_name, None)
            assert method is not None, f"Missing method: {method_name}"
            assert callable(method), f"Not callable: {method_name}"

    def test_all_function_parameters_have_types(self, bridge: CutterBridge) -> None:
        """Verify tool function parameters have type specifications.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            for param in func.parameters:
                assert param.type, f"Param {param.name} in {func.name} has no type"

    def test_parameter_names_match_method_signatures(self, bridge: CutterBridge) -> None:
        """Verify tool_def parameter names match the Python method parameters.

        This is critical: execute_tool_call passes arguments as **kwargs,
        so the LLM parameter names MUST match the method parameter names.

        Args:
            bridge: CutterBridge fixture.
        """
        td = bridge.tool_definition
        for func in td.functions:
            method_name = func.name.replace("cutter.", "")
            method = getattr(bridge, method_name)
            sig = inspect.signature(method)
            method_params = [
                p.name for p in sig.parameters.values() if p.name != "self"
            ]
            tooldef_params = [p.name for p in func.parameters]
            assert tooldef_params == method_params[: len(tooldef_params)], (
                f"{func.name}: tool_def={tooldef_params} != method={method_params}"
            )


class TestInitialize:
    """Verify initialize() validates Rizin availability."""

    @pytest.mark.asyncio
    async def test_raises_when_rizin_not_available(self) -> None:
        """Verify initialize raises ToolError when Rizin is not found."""
        bridge = CutterBridge()
        with (
            patch("shutil.which", return_value=None),
            pytest.raises(ToolError, match="cutter not available"),
        ):
            await bridge.initialize()

    @pytest.mark.asyncio
    async def test_stores_tool_path_modifies_env(self, tmp_path: Path) -> None:
        """Verify initialize with tool_path modifies PATH environment.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        tool_dir = tmp_path / "rizin"
        tool_dir.mkdir()
        original_path = os.environ.get("PATH", "")
        try:
            with (
                patch("shutil.which", return_value=None),
                pytest.raises(ToolError),
            ):
                await bridge.initialize(tool_path=tool_dir)
            assert str(tool_dir) in os.environ.get("PATH", "")
        finally:
            os.environ["PATH"] = original_path

    @pytest.mark.asyncio
    async def test_prepends_tool_dir_to_path(self, tmp_path: Path) -> None:
        """Verify initialize prepends the tool directory to os PATH.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        tool_dir = tmp_path / "rizin"
        tool_dir.mkdir()
        original_path = os.environ.get("PATH", "")
        try:
            with (
                patch("shutil.which", return_value=None),
                pytest.raises(ToolError),
            ):
                await bridge.initialize(tool_path=tool_dir)
            assert str(tool_dir) in os.environ.get("PATH", "")
        finally:
            os.environ["PATH"] = original_path

    @pytest.mark.asyncio
    async def test_does_not_duplicate_path_entry(self, tmp_path: Path) -> None:
        """Verify initialize does not add the same directory twice to PATH.

        Args:
            tmp_path: Temporary directory from pytest.
        """
        bridge = CutterBridge()
        tool_dir = tmp_path / "rizin"
        tool_dir.mkdir()
        tool_dir_str = str(tool_dir)
        os.environ["PATH"] = tool_dir_str + os.pathsep + os.environ.get("PATH", "")
        original_path = os.environ["PATH"]
        try:
            with (
                patch("shutil.which", return_value=None),
                pytest.raises(ToolError),
            ):
                await bridge.initialize(tool_path=tool_dir)
            count = os.environ["PATH"].count(tool_dir_str)
            assert count == 1
        finally:
            os.environ["PATH"] = original_path


class TestLoadBinary:
    """Verify load_binary handles string and Path inputs."""

    @pytest.mark.asyncio
    async def test_string_path_coerced_to_path(self, bridge: CutterBridge, tmp_path: Path) -> None:
        """Verify load_binary accepts a string path without TypeError.

        Args:
            bridge: CutterBridge fixture.
            tmp_path: Temporary directory from pytest.
        """
        fake_binary = tmp_path / "test.exe"
        fake_binary.write_bytes(b"\x00" * 64)
        with pytest.raises(ToolError, match="cutter not available"):
            await bridge.load_binary(str(fake_binary))

    @pytest.mark.asyncio
    async def test_path_object_accepted(self, bridge: CutterBridge, tmp_path: Path) -> None:
        """Verify load_binary accepts a Path object.

        Args:
            bridge: CutterBridge fixture.
            tmp_path: Temporary directory from pytest.
        """
        fake_binary = tmp_path / "test.exe"
        fake_binary.write_bytes(b"\x00" * 64)
        with pytest.raises(ToolError, match="cutter not available"):
            await bridge.load_binary(fake_binary)

    @pytest.mark.asyncio
    async def test_nonexistent_path_raises(self, bridge: CutterBridge) -> None:
        """Verify load_binary raises ToolError for missing files.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="file not found"):
            await bridge.load_binary("/nonexistent/path/to/binary.exe")

    @pytest.mark.asyncio
    async def test_nonexistent_path_string_raises(self, bridge: CutterBridge) -> None:
        """Verify load_binary string path raises ToolError for missing files.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="file not found"):
            await bridge.load_binary(Path("/nonexistent/path/to/binary.exe"))


class TestSearchBytes:
    """Verify search_bytes handles both bytes and str input types."""

    @pytest.mark.asyncio
    async def test_string_hex_pattern(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify search_bytes sends stripped hex when given a string.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.search_bytes("48 8B 05")
        r2_cmds = [c for c in recorder.commands if c.startswith("/xj")]
        assert len(r2_cmds) == 1
        assert r2_cmds[0] == "/xj 488B05"

    @pytest.mark.asyncio
    async def test_bytes_pattern(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify search_bytes hex-encodes bytes input.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.search_bytes(b"\x48\x8b\x05")
        r2_cmds = [c for c in recorder.commands if c.startswith("/xj")]
        assert len(r2_cmds) == 1
        assert r2_cmds[0] == "/xj 488b05"

    @pytest.mark.asyncio
    async def test_no_binary_raises(self, bridge: CutterBridge) -> None:
        """Verify search_bytes raises ToolError when no binary loaded.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.search_bytes("90 90")


class TestWriteBytes:
    """Verify write_bytes accepts hex string and returns True."""

    @pytest.mark.asyncio
    async def test_returns_true(
        self,
        loaded_bridge: CutterBridge,
    ) -> None:
        """Verify write_bytes returns True on success.

        Args:
            loaded_bridge: Bridge with r2 session.
        """
        result = await loaded_bridge.write_bytes(_TEST_ADDRESS, "90909090")
        assert result is True

    @pytest.mark.asyncio
    async def test_strips_spaces_from_hex(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify write_bytes strips spaces from hex data before sending.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.write_bytes(_TEST_ADDRESS, "90 90 90 90")
        wx_cmds = [c for c in recorder.commands if c.startswith("wx")]
        assert len(wx_cmds) == 1
        assert "90909090" in wx_cmds[0]

    @pytest.mark.asyncio
    async def test_sends_correct_address(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify write_bytes includes the target address in the command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.write_bytes(0xDEAD, "CC")
        wx_cmds = [c for c in recorder.commands if c.startswith("wx")]
        assert f"@ {0xDEAD}" in wx_cmds[0]

    @pytest.mark.asyncio
    async def test_no_binary_raises(self, bridge: CutterBridge) -> None:
        """Verify write_bytes raises ToolError when no binary loaded.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.write_bytes(_TEST_ADDRESS, "90")


class TestAssembleAt:
    """Verify assemble_at uses pa command instead of standalone rasm2."""

    @pytest.mark.asyncio
    async def test_writes_at_address(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at sends wa command with correct address.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "90"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        await b.assemble_at(0x401000, "nop")
        wa_cmds = [c for c in recorder.commands if c.startswith("wa")]
        assert len(wa_cmds) == 1
        assert "nop" in wa_cmds[0]
        assert f"@ {0x401000}" in wa_cmds[0]

    @pytest.mark.asyncio
    async def test_uses_pa_not_rasm2(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at uses r2pipe pa command, not standalone rasm2.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "90"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        await b.assemble_at(0x1000, "nop")
        pa_cmds = [c for c in recorder.commands if c.startswith("pa")]
        rasm2_cmds = [c for c in recorder.commands if c.startswith("rasm2")]
        assert len(pa_cmds) == 1
        assert len(rasm2_cmds) == 0
        assert "nop" in pa_cmds[0]

    @pytest.mark.asyncio
    async def test_returns_assembled_bytes(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at returns the assembled bytes.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "9090"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        result = await b.assemble_at(0x1000, "nop; nop")
        assert result == b"\x90\x90"

    @pytest.mark.asyncio
    async def test_raises_on_failure(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify assemble_at raises ToolError when assembly fails.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["pa"] = "Cannot assemble"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        with pytest.raises(ToolError, match="failed to assemble"):
            await b.assemble_at(0x1000, "invalid_instruction")


class TestAddComment:
    """Verify add_comment maps comment_type to Rizin commands."""

    @pytest.mark.asyncio
    async def test_eol_comment(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify EOL type uses CC command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "test comment", "EOL")
        cc_cmds = [c for c in recorder.commands if "test comment" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CC ")

    @pytest.mark.asyncio
    async def test_function_comment(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify function type uses CCf command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "func note", "function")
        cc_cmds = [c for c in recorder.commands if "func note" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CCf ")

    @pytest.mark.asyncio
    async def test_unique_comment(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify unique type uses CCu command.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "unique note", "unique")
        cc_cmds = [c for c in recorder.commands if "unique note" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CCu ")

    @pytest.mark.asyncio
    async def test_default_comment_type(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify default comment type falls back to CC.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, "default")
        cc_cmds = [c for c in recorder.commands if "default" in c]
        assert len(cc_cmds) == 1
        assert cc_cmds[0].startswith("CC ")

    @pytest.mark.asyncio
    async def test_returns_true(self, loaded_bridge: CutterBridge) -> None:
        """Verify add_comment returns True on success.

        Args:
            loaded_bridge: Bridge with r2 session.
        """
        result = await loaded_bridge.add_comment(_TEST_ADDRESS, "test")
        assert result is True

    @pytest.mark.asyncio
    async def test_escapes_quotes(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify add_comment escapes double quotes in comment text.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.add_comment(_TEST_ADDRESS, 'say "hello"')
        cc_cmds = [c for c in recorder.commands if "hello" in c]
        assert len(cc_cmds) == 1
        assert '\\"hello\\"' in cc_cmds[0]


class TestShutdownCleanup:
    """Verify shutdown() handles r2 quit errors gracefully."""

    @pytest.mark.asyncio
    async def test_nulls_r2_on_success(self) -> None:
        """Verify r2 is None after successful shutdown."""
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(_CommandRecorder())
        await bridge.shutdown()
        assert bridge.r2 is None

    @pytest.mark.asyncio
    async def test_nulls_r2_on_quit_failure(self) -> None:
        """Verify r2 is None even when quit() raises during shutdown."""
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(_FailingQuitR2())
        await bridge.shutdown()
        assert bridge.r2 is None

    @pytest.mark.asyncio
    async def test_does_not_propagate_quit_error(self) -> None:
        """Verify quit() RuntimeError is caught by shutdown, not propagated."""
        bridge = CutterBridge()
        bridge.r2 = _as_r2pipe(_FailingQuitR2())
        await bridge.shutdown()

    @pytest.mark.asyncio
    async def test_noop_when_r2_is_none(self) -> None:
        """Verify shutdown is safe when r2 is already None."""
        bridge = CutterBridge()
        assert bridge.r2 is None
        await bridge.shutdown()
        assert bridge.r2 is None


class TestMethodsRequireBinaryLoaded:
    """Verify methods raise ToolError when no binary is loaded."""

    @pytest.mark.asyncio
    async def test_search_bytes_no_binary(self, bridge: CutterBridge) -> None:
        """Verify search_bytes raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.search_bytes("90")

    @pytest.mark.asyncio
    async def test_write_bytes_no_binary(self, bridge: CutterBridge) -> None:
        """Verify write_bytes raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.write_bytes(0, "90")

    @pytest.mark.asyncio
    async def test_execute_command_no_binary(self, bridge: CutterBridge) -> None:
        """Verify execute_command raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.execute_command("?V")

    @pytest.mark.asyncio
    async def test_decompile_no_binary(self, bridge: CutterBridge) -> None:
        """Verify decompile raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.decompile(_TEST_ADDRESS)


class TestMethodsRequireAnalysis:
    """Verify analysis-dependent methods raise ToolError when not analyzed."""

    @pytest.fixture
    def unanalyzed(self, recorder: _CommandRecorder) -> CutterBridge:
        """Create bridge with r2 session but not yet analyzed.

        Sets r2 via the public property setter; does NOT call analyze()
        so the bridge remains in the unanalyzed state.

        Args:
            recorder: Command recorder fixture.

        Returns:
            CutterBridge: Bridge with binary loaded but not analyzed.
        """
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        return b

    @pytest.mark.asyncio
    async def test_get_functions_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify get_functions raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.get_functions()

    @pytest.mark.asyncio
    async def test_disassemble_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify disassemble raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.disassemble(_TEST_ADDRESS)

    @pytest.mark.asyncio
    async def test_search_bytes_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify search_bytes raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.search_bytes("90")

    @pytest.mark.asyncio
    async def test_assemble_at_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify assemble_at raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.assemble_at(_TEST_ADDRESS, "nop")

    @pytest.mark.asyncio
    async def test_add_comment_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify add_comment raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.add_comment(_TEST_ADDRESS, "test")

    @pytest.mark.asyncio
    async def test_get_xrefs_to_not_analyzed(self, unanalyzed: CutterBridge) -> None:
        """Verify get_xrefs_to raises when not analyzed.

        Args:
            unanalyzed: Unanalyzed bridge fixture.
        """
        with pytest.raises(ToolError, match="not analyzed"):
            await unanalyzed.get_xrefs_to(_TEST_ADDRESS)


class TestGetExportsOrdinal:
    """Verify get_exports uses Rizin ordinal with index fallback."""

    @pytest.mark.asyncio
    async def test_uses_rizin_ordinal_when_present(self) -> None:
        """Verify ordinal from Rizin data is preferred over enumerate index."""
        rec = _CommandRecorder({
            "iEj": '[{"name":"Export1","vaddr":4096,"ordinal":42}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        await b.analyze()
        exports = await b.get_exports()
        assert len(exports) == 1
        assert exports[0].ordinal == 42

    @pytest.mark.asyncio
    async def test_falls_back_to_index_when_no_ordinal(self) -> None:
        """Verify enumerate index is used when Rizin has no ordinal field."""
        rec = _CommandRecorder({
            "iEj": '[{"name":"Export1","vaddr":4096}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        await b.analyze()
        exports = await b.get_exports()
        assert len(exports) == 1
        assert exports[0].ordinal == 0


class TestPermToRwx:
    """Verify perm_to_rwx converts permission integers to rwx strings."""

    def test_all_permissions(self) -> None:
        """Verify rwx for all-permissions (7)."""
        assert perm_to_rwx(7) == "rwx"

    def test_read_execute(self) -> None:
        """Verify r-x for read+execute (5)."""
        assert perm_to_rwx(5) == "r-x"

    def test_no_permissions(self) -> None:
        """Verify --- for no permissions (0)."""
        assert perm_to_rwx(0) == "---"

    def test_read_only(self) -> None:
        """Verify r-- for read-only (4)."""
        assert perm_to_rwx(4) == "r--"

    def test_write_only(self) -> None:
        """Verify -w- for write-only (2)."""
        assert perm_to_rwx(2) == "-w-"

    def test_execute_only(self) -> None:
        """Verify --x for execute-only (1)."""
        assert perm_to_rwx(1) == "--x"

    def test_read_write(self) -> None:
        """Verify rw- for read+write (6)."""
        assert perm_to_rwx(6) == "rw-"

    def test_write_execute(self) -> None:
        """Verify -wx for write+execute (3)."""
        assert perm_to_rwx(3) == "-wx"


class TestExecuteCommand:
    """Verify execute_command passes commands to r2."""

    @pytest.mark.asyncio
    async def test_passes_command_through(
        self,
        loaded_bridge: CutterBridge,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify execute_command forwards the exact command string.

        Args:
            loaded_bridge: Bridge with r2 session.
            recorder: Command recorder fixture.
        """
        await loaded_bridge.execute_command("pd 10")
        assert "pd 10" in recorder.commands

    @pytest.mark.asyncio
    async def test_returns_command_output(self, recorder: _CommandRecorder) -> None:
        """Verify execute_command returns the r2 output.

        Args:
            recorder: Command recorder fixture.
        """
        recorder.responses["?V"] = "5.9.4"
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        result = await b.execute_command("?V")
        assert result == "5.9.4"


class _MetadataProbeBridge(CutterBridge):
    """Testing subclass exposing protected metadata extraction.

    Subclasses may access protected members of their parent, so this
    wrapper lets tests exercise ``_extract_binary_metadata`` without
    accessing a protected method from outside the class hierarchy.
    """

    async def extract_metadata(self) -> tuple[str, str, int, int]:
        """Expose the protected metadata extractor for tests.

        Returns:
            tuple[str, str, int, int]: Tuple of (file_type, arch, bits, entry_point).
        """
        return await self._extract_binary_metadata()


class TestEntryPointBug:
    """Verify entry point is not double-added with baddr (Bug 2 fix)."""

    @pytest.mark.asyncio
    async def test_entry_point_not_double_baddr(self) -> None:
        """Verify _extract_binary_metadata returns bin.entry directly."""
        rec = _CommandRecorder({
            "ij": '[{"bin":{"class":"PE","arch":"x86","bits":64,"baddr":4194304,"entry":4198400}}]',
            "itj": "[]",
            "iSj": "[]",
            "iij": "[]",
            "iEj": "[]",
        })
        b = _MetadataProbeBridge()
        b.r2 = _as_r2pipe(rec)
        _, _, _, entry = await b.extract_metadata()
        assert entry == 4198400


class TestSaveBinary:
    """Verify save_binary sends wtf command (Bug 3 fix)."""

    @pytest.mark.asyncio
    async def test_sends_wtf_command(
        self,
        recorder: _CommandRecorder,
    ) -> None:
        """Verify save_binary sends wtf with the given path.

        Args:
            recorder: Command recorder fixture.
        """
        b = CutterBridge()
        b.r2 = _as_r2pipe(recorder)
        await b.analyze()
        recorder.commands.clear()
        result = await b.save_binary("/tmp/output.exe")
        assert result is True
        wtf_cmds = [c for c in recorder.commands if c.startswith("wtf")]
        assert len(wtf_cmds) == 1
        assert "/tmp/output.exe" in wtf_cmds[0]


class TestGetSymbols:
    """Verify get_symbols returns SymbolInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_symbol_info(self) -> None:
        """Verify get_symbols parses isj output correctly."""
        rec = _CommandRecorder({
            "isj": '[{"name":"main","vaddr":4096,"libname":""}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        symbols = await b.get_symbols()
        assert len(symbols) == 1
        assert symbols[0].name == "main"
        assert symbols[0].address == 4096

    @pytest.mark.asyncio
    async def test_no_binary_raises(self, bridge: CutterBridge) -> None:
        """Verify get_symbols raises when no binary.

        Args:
            bridge: CutterBridge fixture.
        """
        with pytest.raises(ToolError, match="no binary loaded"):
            await bridge.get_symbols()


class TestReadBytes:
    """Verify read_bytes returns raw bytes."""

    @pytest.mark.asyncio
    async def test_returns_bytes(self) -> None:
        """Verify read_bytes parses p8 output correctly."""
        rec = _CommandRecorder({
            "p8": "48 8b 05",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.read_bytes(0x1000, 3)
        assert isinstance(result, bytes)

    @pytest.mark.asyncio
    async def test_sends_p8_command(self) -> None:
        """Verify read_bytes sends p8 command with count and address."""
        rec = _CommandRecorder({
            "p8": "90",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        await b.read_bytes(0x1000, 1)
        p8_cmds = [c for c in rec.commands if c.startswith("p8")]
        assert len(p8_cmds) == 1
        assert "1" in p8_cmds[0]
        assert f"@ {0x1000}" in p8_cmds[0]


class TestGetFlags:
    """Verify get_flags returns FlagInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_flag_info(self) -> None:
        """Verify get_flags parses fj output correctly."""
        rec = _CommandRecorder({
            "fj": '[{"name":"entry0","offset":4096,"size":1}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        flags = await b.get_flags()
        assert len(flags) == 1
        assert flags[0].name == "entry0"
        assert flags[0].address == 4096
        assert flags[0].size == 1


class TestAddFlag:
    """Verify add_flag sends f command."""

    @pytest.mark.asyncio
    async def test_sends_f_command(self) -> None:
        """Verify add_flag sends the correct Rizin command."""
        rec = _CommandRecorder()
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.add_flag("test_flag", 4, 0x1000)
        assert result is True
        f_cmds = [c for c in rec.commands if c.startswith("f ")]
        assert len(f_cmds) == 1
        assert "test_flag" in f_cmds[0]
        assert f"@ {0x1000}" in f_cmds[0]


class TestGetComments:
    """Verify get_comments returns CommentInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_comment_info(self) -> None:
        """Verify get_comments parses CCj output correctly."""
        rec = _CommandRecorder({
            "CCj": '[{"offset":4096,"name":"test comment","type":"inline"}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        comments = await b.get_comments()
        assert len(comments) == 1
        assert comments[0].address == 4096
        assert comments[0].text == "test comment"


class TestHexdump:
    """Verify hexdump returns string output."""

    @pytest.mark.asyncio
    async def test_sends_px_command(self) -> None:
        """Verify hexdump sends px command with correct parameters."""
        rec = _CommandRecorder({
            "px": "- offset -   0 1  2 3\n0x00001000  9090 9090",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.hexdump(0x1000, 128)
        assert isinstance(result, str)
        px_cmds = [c for c in rec.commands if c.startswith("px")]
        assert len(px_cmds) == 1
        assert "128" in px_cmds[0]


class TestGetBasicBlocks:
    """Verify get_basic_blocks returns BlockInfo objects."""

    @pytest.mark.asyncio
    async def test_returns_block_info(self) -> None:
        """Verify get_basic_blocks parses afbj output correctly."""
        rec = _CommandRecorder({
            "afbj": '[{"addr":4096,"size":20,"jump":4116,"fail":null,"ops":[]}]',
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        blocks = await b.get_basic_blocks(0x1000)
        assert len(blocks) == 1
        assert blocks[0].address == 4096
        assert blocks[0].size == 20
        assert blocks[0].jump == 4116


class TestEsilOps:
    """Verify ESIL emulation operations."""

    @pytest.mark.asyncio
    async def test_esil_eval(self) -> None:
        """Verify esil_eval sends ae command."""
        rec = _CommandRecorder({
            "ae": "0x42",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.esil_eval("1,1,+")
        assert isinstance(result, str)
        ae_cmds = [c for c in rec.commands if c.startswith("ae ")]
        assert len(ae_cmds) == 1

    @pytest.mark.asyncio
    async def test_esil_init_memory(self) -> None:
        """Verify esil_init_memory sends aeim command."""
        rec = _CommandRecorder()
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.esil_init_memory()
        assert result is True
        assert "aeim" in rec.commands


class TestGetConfig:
    """Verify configuration get/set operations."""

    @pytest.mark.asyncio
    async def test_get_config(self) -> None:
        """Verify get_config reads a configuration value."""
        rec = _CommandRecorder({
            "e asm.arch": "x86",
        })
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.get_config("asm.arch")
        assert result == "x86"

    @pytest.mark.asyncio
    async def test_set_config(self) -> None:
        """Verify set_config sends e key=value command."""
        rec = _CommandRecorder()
        b = CutterBridge()
        b.r2 = _as_r2pipe(rec)
        result = await b.set_config("asm.arch", "arm")
        assert result is True
        e_cmds = [c for c in rec.commands if "asm.arch=arm" in c]
        assert len(e_cmds) == 1
