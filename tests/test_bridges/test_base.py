# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tests for bridges.base module.

Covers DisassemblyLine, MemorySearchResult, StackFrame, WatchpointInfo,
BridgeCapabilities, BridgeState, and ToolBridgeBase integration with
Session and ToolRegistry capability enforcement.
"""

from __future__ import annotations

import asyncio
import dataclasses
import pathlib
import tempfile
from typing import Final, cast

import pytest

from intellicrack.bridges.base import (
    TOOL_CAPABILITY_MAP,
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    MemorySearchResult,
    StackFrame,
    ToolBridgeBase,
    WatchpointInfo,
)
from intellicrack.core.session import Session
from intellicrack.core.tools import ToolRegistry
from intellicrack.core.types import ProviderName, ToolDefinition, ToolError, ToolName


_ADDR: Final[int] = 0x00401000
_ADDR2: Final[int] = 0x00401010


class _MinimalBridge(ToolBridgeBase):
    """Minimal concrete ToolBridgeBase subclass for integration tests."""

    def __init__(self, tool_name: ToolName = ToolName.CUTTER, caps: BridgeCapabilities | None = None) -> None:
        """Initialize with an optional ToolName and BridgeCapabilities.

        Args:
            tool_name: ToolName to report as this bridge's identity.
            caps: Optional BridgeCapabilities to install; defaults to all-False if None.
        """
        super().__init__()
        self._tool_name = tool_name
        if caps is not None:
            self._capabilities = caps

    @property
    def name(self) -> ToolName:
        """Get the tool name.

        Returns:
            ToolName: The tool name enum value.
        """
        return self._tool_name

    @property
    def tool_definition(self) -> ToolDefinition:
        """Get a minimal tool definition for unit tests.

        Returns:
            ToolDefinition: Minimal ToolDefinition with no functions.
        """
        return ToolDefinition(tool_name=self._tool_name, description="test bridge", functions=[])

    async def initialize(self, tool_path: pathlib.Path | None = None) -> None:
        """No-op initialize.

        Args:
            tool_path: Unused tool path.
        """

    async def shutdown(self) -> None:
        """Delegate to base shutdown."""
        await super().shutdown()

    async def is_available(self) -> bool:
        """Always reports available.

        Returns:
            bool: Always True.
        """
        return True

    async def disassemble(self, address: int, count: int = 20) -> list[DisassemblyLine]:
        """Return a stub disassembly result.

        Args:
            address: Start address.
            count: Number of instructions (unused in stub).

        Returns:
            list[DisassemblyLine]: One stub DisassemblyLine.
        """
        _ = count
        return [DisassemblyLine(address=address, bytes_str="90", mnemonic="nop", operands="")]

    async def execute_script(self, script: str) -> str:
        """Return the script unchanged as a stub.

        Args:
            script: Script text.

        Returns:
            str: The script echoed back.
        """
        return script

    async def set_watchpoint(self, address: int, size: int = 4, watch_type: str = "write") -> int:
        """Stub watchpoint setter.

        Args:
            address: Watch address (unused in stub).
            size: Region size (unused in stub).
            watch_type: Type of watchpoint (unused in stub).

        Returns:
            int: Stub watchpoint ID 1.
        """
        _ = address, size, watch_type
        return 1

    async def write_memory(self, address: int, data: bytes) -> int:
        """Stub memory writer.

        Args:
            address: Target address (unused in stub).
            data: Bytes to write.

        Returns:
            int: Number of bytes written.
        """
        _ = address
        return len(data)

    async def patch_instruction(self, address: int, instruction: str) -> bool:
        """Stub instruction patcher.

        Args:
            address: Address to patch (unused in stub).
            instruction: New instruction (unused in stub).

        Returns:
            bool: Always True.
        """
        _ = address, instruction
        return True

    async def decompile(self, address: int) -> str:
        """Stub decompiler.

        Args:
            address: Function address.

        Returns:
            str: Stub decompiled text.
        """
        return f"void func_{address:#x}(void) {{}}"

    def set_last_error(self, message: str) -> None:
        """Set the last_error on the internal bridge state and republish.

        Args:
            message: Error message to record in bridge state.
        """
        current = BridgeState(
            connected=self.state.connected,
            tool_running=self.state.tool_running,
            binary_loaded=self.state.binary_loaded,
            process_attached=self.state.process_attached,
            target_path=self.state.target_path,
            target_pid=self.state.target_pid,
            last_error=message,
        )
        self.state = current


def _make_registry(tool_name: ToolName = ToolName.CUTTER, caps: BridgeCapabilities | None = None) -> ToolRegistry:
    """Create a ToolRegistry populated with a single _MinimalBridge.

    Args:
        tool_name: ToolName to register.
        caps: BridgeCapabilities for the bridge.

    Returns:
        ToolRegistry: Registry with the bridge registered.
    """
    reg = ToolRegistry(pathlib.Path(tempfile.mkdtemp()))
    bridge = _MinimalBridge(tool_name=tool_name, caps=caps)
    reg.register_bridge(tool_name, bridge)
    return reg


class TestDisassemblyLineFields:
    """Verify DisassemblyLine field schema and downstream serialization."""

    def test_field_names_match_expected_schema(self) -> None:
        """DisassemblyLine must expose exactly five named fields in declaration order.

        The ordered field list is the contract that bridge parsers and AI context
        serializers depend on; reordering or renaming a field breaks that contract.
        """
        names = [f.name for f in dataclasses.fields(DisassemblyLine)]
        assert names == ["address", "bytes_str", "mnemonic", "operands", "comment"]

    def test_asdict_round_trip_preserves_all_values(self) -> None:
        """asdict() must reproduce every field value without lossy conversion.

        This is the serialization contract used by AI context builders that
        convert DisassemblyLine objects into JSON-serializable dicts.
        """
        line = DisassemblyLine(
            address=_ADDR,
            bytes_str="48 89 C3",
            mnemonic="mov",
            operands="rbx, rax",
            comment="save rax",
        )
        d = dataclasses.asdict(line)
        assert d == {
            "address": 0x00401000,
            "bytes_str": "48 89 C3",
            "mnemonic": "mov",
            "operands": "rbx, rax",
            "comment": "save rax",
        }

    def test_comment_field_defaults_to_none(self) -> None:
        """Omitting comment must yield None so downstream None-checks are reliable.

        Bridges that emit lines without comments rely on comment=None as the
        sentinel; if the default were changed to '' the comment-filter logic
        in the AI context builder would break silently.
        """
        line = DisassemblyLine(address=_ADDR, bytes_str="90", mnemonic="nop", operands="")
        assert line.comment is None

    def test_comment_filter_discriminates_annotated_from_plain_lines(self) -> None:
        """Downstream code that filters commented lines must work correctly.

        Simulates bridge output iteration: lines with comments are collected
        for annotation display; plain lines are left unannotated.
        """
        lines: list[DisassemblyLine] = [
            DisassemblyLine(address=_ADDR, bytes_str="90", mnemonic="nop", operands=""),
            DisassemblyLine(address=_ADDR2, bytes_str="C3", mnemonic="ret", operands="", comment="end of func"),
        ]
        commented = [ln for ln in lines if ln.comment is not None]
        plain = [ln for ln in lines if ln.comment is None]
        assert len(commented) == 1
        assert commented[0].comment == "end of func"
        assert len(plain) == 1
        assert plain[0].address == _ADDR


class TestMemorySearchResultFields:
    """Verify MemorySearchResult field schema and sorting behavior."""

    def test_field_names_match_expected_schema(self) -> None:
        """MemorySearchResult must expose exactly four named fields in order.

        Bridge scan functions return lists of these; the caller iterates them
        by field position in structured display code.
        """
        names = [f.name for f in dataclasses.fields(MemorySearchResult)]
        assert names == ["address", "matched_bytes", "context_before", "context_after"]

    def test_asdict_preserves_hex_string_fields(self) -> None:
        """asdict() must preserve hex-string fields exactly as set.

        The context strings are passed verbatim into the AI context window;
        any truncation or re-encoding would corrupt the hex representation.
        """
        result = MemorySearchResult(
            address=_ADDR,
            matched_bytes="90 90",
            context_before="CC CC",
            context_after="C3 C3",
        )
        d = dataclasses.asdict(result)
        assert d == {
            "address": 0x00401000,
            "matched_bytes": "90 90",
            "context_before": "CC CC",
            "context_after": "C3 C3",
        }

    def test_sort_by_address_gives_ascending_order(self) -> None:
        """Sorted results must be ordered low-to-high by virtual address.

        The hex editor bridge displays scan results in address order; if sort
        by ``address`` key is broken the display ordering is undefined.
        """
        results: list[MemorySearchResult] = [
            MemorySearchResult(address=0x00401010, matched_bytes="FF E0", context_before="00", context_after="90"),
            MemorySearchResult(address=0x00401000, matched_bytes="90 90", context_before="CC", context_after="C3"),
        ]
        ordered = sorted(results, key=lambda r: r.address)
        assert ordered[0].address == 0x00401000
        assert ordered[0].matched_bytes == "90 90"
        assert ordered[1].address == 0x00401010
        assert ordered[1].matched_bytes == "FF E0"


class TestStackFrameFields:
    """Verify StackFrame field schema, None-safety, and struct unpacking."""

    def test_field_names_match_expected_schema(self) -> None:
        """StackFrame must expose exactly seven named fields in declaration order.

        Debugger UI widgets unpack these fields positionally; reordering breaks
        column alignment in the call-stack table view.
        """
        names = [f.name for f in dataclasses.fields(StackFrame)]
        assert names == [
            "index",
            "address",
            "return_address",
            "frame_pointer",
            "stack_pointer",
            "function_name",
            "module_name",
        ]

    def test_asdict_with_resolved_symbols(self) -> None:
        """asdict() must include resolved function and module name verbatim.

        The session context serializer converts stack frames to dicts for the AI
        provider; symbol names must survive the round-trip without modification.
        """
        frame = StackFrame(
            index=0,
            address=_ADDR,
            return_address=_ADDR2,
            frame_pointer=0x0028FF00,
            stack_pointer=0x0028FEF0,
            function_name="main",
            module_name="test.exe",
        )
        d = dataclasses.asdict(frame)
        assert d["index"] == 0
        assert d["address"] == 0x00401000
        assert d["return_address"] == 0x00401010
        assert d["frame_pointer"] == 0x0028FF00
        assert d["stack_pointer"] == 0x0028FEF0
        assert d["function_name"] == "main"
        assert d["module_name"] == "test.exe"

    def test_none_symbol_fields_preserved_through_asdict(self) -> None:
        """None function_name and module_name must survive asdict without coercion.

        Bridge code that handles unresolved symbols checks ``if frame.function_name
        is None``; if asdict coerced None to an empty string that guard would fail.
        """
        frame = StackFrame(
            index=3,
            address=_ADDR,
            return_address=_ADDR2,
            frame_pointer=0,
            stack_pointer=0,
            function_name=None,
            module_name=None,
        )
        d = dataclasses.asdict(frame)
        assert d["function_name"] is None
        assert d["module_name"] is None

    def test_none_name_guard_works_in_display_logic(self) -> None:
        """Code that substitutes a placeholder for unresolved names must work.

        Debugger UI code uses ``frame.function_name or '<unknown>'``; this test
        drives that exact expression to ensure None resolves to the placeholder
        and a real name is returned unchanged.
        """
        resolved = StackFrame(
            index=0,
            address=_ADDR,
            return_address=_ADDR2,
            frame_pointer=0,
            stack_pointer=0,
            function_name="WinMain",
            module_name="target.exe",
        )
        unresolved = StackFrame(
            index=1,
            address=_ADDR2,
            return_address=_ADDR,
            frame_pointer=0,
            stack_pointer=0,
            function_name=None,
            module_name=None,
        )
        assert (resolved.function_name or "<unknown>") == "WinMain"
        assert (unresolved.function_name or "<unknown>") == "<unknown>"
        assert (resolved.module_name or "<unknown>") == "target.exe"
        assert (unresolved.module_name or "<unknown>") == "<unknown>"


class TestWatchpointInfoFields:
    """Verify WatchpointInfo field schema and mutable state transitions."""

    def test_field_names_match_expected_schema(self) -> None:
        """WatchpointInfo must expose exactly six named fields in declaration order.

        Debugger bridge methods iterate these positionally for display and
        serialization; any schema change breaks the watchpoint panel.
        """
        names = [f.name for f in dataclasses.fields(WatchpointInfo)]
        assert names == ["id", "address", "size", "watch_type", "enabled", "hit_count"]

    def test_hit_count_increments_and_enable_toggle_work(self) -> None:
        """hit_count mutation and enabled toggle must reflect independently.

        Debugger bridge code increments hit_count each time the watchpoint
        fires and sets enabled=False when the user disables it; these are
        separate fields and must not interfere.
        """
        wp = WatchpointInfo(id=7, address=_ADDR, size=4, watch_type="write", enabled=True, hit_count=0)
        wp.hit_count += 1
        wp.hit_count += 1
        wp.enabled = False
        assert wp.hit_count == 2
        assert wp.enabled is False
        assert wp.id == 7
        assert wp.address == _ADDR
        assert wp.size == 4
        assert wp.watch_type == "write"

    def test_asdict_captures_mutated_state(self) -> None:
        """asdict() after mutation must reflect the current field values.

        The session-persistence layer serializes watchpoints via asdict; if
        post-mutation state were not captured the saved session would contain
        stale watchpoint data.
        """
        wp = WatchpointInfo(id=1, address=_ADDR, size=8, watch_type="read", enabled=True, hit_count=0)
        wp.hit_count = 5
        wp.enabled = False
        d = dataclasses.asdict(wp)
        assert d == {
            "id": 1,
            "address": 0x00401000,
            "size": 8,
            "watch_type": "read",
            "enabled": False,
            "hit_count": 5,
        }


class TestBridgeCapabilitiesEnforcement:
    """Verify BridgeCapabilities gates ToolRegistry.execute_tool_call correctly."""

    def test_execute_tool_call_raises_on_missing_static_analysis(self) -> None:
        """execute_tool_call must raise ToolError when bridge lacks static_analysis.

        If capability enforcement were removed or the capability check
        were bypassed, this test would fail because the stub bridge has no
        ``supports_static_analysis`` but the ``disassemble`` function is in
        TOOL_CAPABILITY_MAP under static_analysis.
        """
        reg = _make_registry(ToolName.CUTTER, caps=BridgeCapabilities())
        with pytest.raises(ToolError, match="missing capability"):
            asyncio.run(reg.execute_tool_call("cutter", "disassemble", {"address": _ADDR}))

    def test_execute_tool_call_succeeds_when_static_analysis_declared(self) -> None:
        """execute_tool_call must not raise when bridge declares static_analysis.

        Paired with the failing-case test above; together they prove that the
        capability check is the deciding factor, not an unconditional error.
        """
        reg = _make_registry(
            ToolName.CUTTER,
            caps=BridgeCapabilities(supports_static_analysis=True),
        )
        result = asyncio.run(reg.execute_tool_call("cutter", "disassemble", {"address": _ADDR}))
        assert isinstance(result, list)
        disasm_lines = cast(list[DisassemblyLine], result)
        assert len(disasm_lines) == 1
        line = disasm_lines[0]
        assert isinstance(line, DisassemblyLine)
        assert line.address == _ADDR
        assert line.mnemonic == "nop"

    def test_execute_tool_call_raises_on_missing_scripting(self) -> None:
        """execute_tool_call must raise ToolError when bridge lacks scripting.

        TOOL_CAPABILITY_MAP maps ``execute_script`` -> ``scripting``; a bridge
        without ``supports_scripting=True`` must be rejected.
        """
        reg = _make_registry(ToolName.FRIDA, caps=BridgeCapabilities())
        with pytest.raises(ToolError, match="missing capability"):
            asyncio.run(reg.execute_tool_call("frida", "execute_script", {"script": "1"}))

    def test_execute_tool_call_succeeds_for_scripting_with_capability(self) -> None:
        """execute_tool_call returns bridge result when scripting cap is set.

        Confirms that the capability gating does not unconditionally block
        calls; it passes through when the bridge declares the required cap.
        """
        reg = _make_registry(
            ToolName.FRIDA,
            caps=BridgeCapabilities(supports_scripting=True),
        )
        result = asyncio.run(reg.execute_tool_call("frida", "execute_script", {"script": "echo"}))
        assert result == "echo"

    def test_execute_tool_call_raises_on_missing_debugging(self) -> None:
        """execute_tool_call must raise ToolError when bridge lacks debugging.

        ``set_watchpoint`` maps to ``debugging`` in TOOL_CAPABILITY_MAP; a
        bridge without ``supports_debugging=True`` must be rejected.
        """
        reg = _make_registry(ToolName.CUTTER, caps=BridgeCapabilities())
        with pytest.raises(ToolError, match="missing capability"):
            asyncio.run(
                reg.execute_tool_call(
                    "cutter",
                    "set_watchpoint",
                    {"address": _ADDR, "size": 4, "watch_type": "write"},
                ),
            )

    def test_execute_tool_call_raises_on_missing_memory_access(self) -> None:
        """execute_tool_call must raise ToolError when bridge lacks memory_access.

        ``write_memory`` maps to ``memory_access``; missing cap must surface as
        ToolError, not silently succeed or raise a different error type.
        """
        reg = _make_registry(ToolName.CUTTER, caps=BridgeCapabilities())
        with pytest.raises(ToolError, match="missing capability"):
            asyncio.run(
                reg.execute_tool_call(
                    "cutter",
                    "write_memory",
                    {"address": _ADDR, "data": b"\x90"},
                ),
            )

    def test_execute_tool_call_raises_on_missing_patching(self) -> None:
        """execute_tool_call must raise ToolError when bridge lacks patching.

        ``patch_instruction`` maps to ``patching``; missing cap must raise.
        """
        reg = _make_registry(ToolName.CUTTER, caps=BridgeCapabilities())
        with pytest.raises(ToolError, match="missing capability"):
            asyncio.run(
                reg.execute_tool_call(
                    "cutter",
                    "patch_instruction",
                    {"address": _ADDR, "instruction": "nop"},
                ),
            )

    def test_execute_tool_call_raises_on_missing_decompilation(self) -> None:
        """execute_tool_call must raise ToolError when bridge lacks decompilation.

        ``decompile`` maps to ``decompilation`` in TOOL_CAPABILITY_MAP; a
        bridge that only declares static_analysis must still be blocked for
        decompilation calls.
        """
        reg = _make_registry(
            ToolName.CUTTER,
            caps=BridgeCapabilities(supports_static_analysis=True),
        )
        with pytest.raises(ToolError, match="missing capability"):
            asyncio.run(
                reg.execute_tool_call(
                    "cutter",
                    "decompile",
                    {"address": _ADDR},
                ),
            )

    def test_has_capability_returns_correct_boolean_for_each_field(self) -> None:
        """has_capability must return True only for capabilities explicitly set.

        This verifies that the attribute-lookup logic (``getattr(self,
        f'supports_{cap}', False)``) does not silently return True for
        unset or misspelled capability names.
        """
        caps = BridgeCapabilities(
            supports_static_analysis=True,
            supports_scripting=True,
        )
        assert caps.has_capability("static_analysis") is True
        assert caps.has_capability("scripting") is True
        assert caps.has_capability("debugging") is False
        assert caps.has_capability("decompilation") is False
        assert caps.has_capability("memory_access") is False
        assert caps.has_capability("patching") is False
        assert caps.has_capability("nonexistent_cap") is False

    def test_supports_arch_and_supports_format_are_disjoint_checks(self) -> None:
        """supports_arch and supports_format must each query only their own list.

        If the implementation accidentally swapped the lists the arch and format
        checks would succeed for wrong values and fail for correct ones.
        """
        caps = BridgeCapabilities(
            supported_architectures=["x86", "x86_64"],
            supported_formats=["pe", "elf"],
        )
        assert caps.supports_arch("x86") is True
        assert caps.supports_arch("x86_64") is True
        assert caps.supports_arch("arm") is False
        assert caps.supports_arch("pe") is False

        assert caps.supports_format("pe") is True
        assert caps.supports_format("elf") is True
        assert caps.supports_format("macho") is False
        assert caps.supports_format("x86") is False


class TestBridgeStateSessionIntegration:
    """Verify BridgeState transitions are faithfully published to Session."""

    def test_set_session_immediately_publishes_current_state(self) -> None:
        """Attaching a session must push the bridge's current state into tool_states.

        If this publish were skipped the session would have stale data until the
        next state change; the orchestrator's view of tool connectivity would be
        wrong at session-attach time.
        """
        bridge = _MinimalBridge(ToolName.CUTTER)
        sess = Session.create(provider=ProviderName.ANTHROPIC, model="test")
        assert ToolName.CUTTER not in sess.tool_states
        bridge.set_session(sess)
        assert ToolName.CUTTER in sess.tool_states

    def test_state_setter_publishes_connected_true_to_session(self) -> None:
        """Setting bridge.state with connected=True must reach the session.

        The session's tool_states entry for the bridge must reflect the new
        connected flag immediately after the assignment, not lazily.
        """
        bridge = _MinimalBridge(ToolName.CUTTER)
        sess = Session.create(provider=ProviderName.ANTHROPIC, model="test")
        bridge.set_session(sess)

        new_state = BridgeState(connected=True, tool_running=True)
        bridge.state = new_state

        assert sess.tool_states[ToolName.CUTTER].connected is True

    def test_state_setter_publishes_last_error_to_session(self) -> None:
        """An error in bridge state must appear verbatim in the session record.

        The orchestrator reads ``session.tool_states[tool].last_error`` to show
        error status in the UI; if the error string were truncated or lost the
        user would see no error message.
        """
        bridge = _MinimalBridge(ToolName.CUTTER)
        sess = Session.create(provider=ProviderName.ANTHROPIC, model="test")
        bridge.set_session(sess)

        bridge.set_last_error("rizin crashed: exit code 139")

        assert sess.tool_states[ToolName.CUTTER].last_error == "rizin crashed: exit code 139"

    def test_is_ready_requires_both_connected_and_tool_running(self) -> None:
        """is_ready must return False unless both connected and tool_running are True.

        Bridge guard code calls ``if not state.is_ready(): raise ToolError``; if
        is_ready were changed to check only one flag some methods would operate on
        a disconnected or not-yet-started tool.
        """
        state = BridgeState()
        assert state.is_ready() is False

        state.connected = True
        assert state.is_ready() is False

        state.tool_running = True
        assert state.is_ready() is True

        state.connected = False
        assert state.is_ready() is False

    def test_clear_error_resets_last_error_and_is_idempotent(self) -> None:
        """clear_error must set last_error to None, including when already None.

        Bridge error-recovery sequences call clear_error before a retry; if it
        did not reset the field the previous error would persist through the retry.
        Calling it on an already-None field must not raise.
        """
        state = BridgeState(last_error="tool not responding")
        assert state.last_error == "tool not responding"
        state.clear_error()
        assert state.last_error is None

        state.clear_error()
        assert state.last_error is None

    def test_shutdown_removes_bridge_entry_from_session_tool_states(self) -> None:
        """Shutdown must clear the bridge's entry from session.tool_states.

        After shutdown the orchestrator must not see a stale connected/attached
        state for the bridge; clear_tool_state must be called so the session
        reflects reality.
        """
        bridge = _MinimalBridge(ToolName.CUTTER)
        sess = Session.create(provider=ProviderName.ANTHROPIC, model="test")
        bridge.set_session(sess)

        new_state = BridgeState(connected=True, tool_running=True)
        bridge.state = new_state
        assert ToolName.CUTTER in sess.tool_states

        asyncio.run(bridge.shutdown())
        assert ToolName.CUTTER not in sess.tool_states


class TestToolCapabilityMapCompleteness:
    """Verify TOOL_CAPABILITY_MAP covers all expected operation families."""

    def test_static_analysis_family_entries_present(self) -> None:
        """Core static-analysis operations must map to 'static_analysis'.

        If any of these entries were removed from the map, bridges that declare
        ``supports_static_analysis=True`` would bypass the capability check for
        those operations, silently allowing calls on non-static bridges.
        """
        static_ops: list[str] = ["disassemble", "disassemble_at", "get_xrefs_to", "get_xrefs_from"]
        for op in static_ops:
            assert TOOL_CAPABILITY_MAP.get(op) == "static_analysis", f"{op!r} must map to 'static_analysis'"

    def test_debugging_family_entries_present(self) -> None:
        """Core debugging operations must map to 'debugging'.

        Debugger bridges must be gated on ``supports_debugging``; if any entry
        were missing the registry would allow non-debugger bridges to respond to
        breakpoint requests.
        """
        debug_ops: list[str] = ["attach", "detach", "set_breakpoint", "remove_breakpoint", "set_watchpoint"]
        for op in debug_ops:
            assert TOOL_CAPABILITY_MAP.get(op) == "debugging", f"{op!r} must map to 'debugging'"

    def test_patching_family_entries_present(self) -> None:
        """Core patching operations must map to 'patching'."""
        patch_ops: list[str] = ["patch_instruction", "write_bytes", "apply_patch", "revert_patch"]
        for op in patch_ops:
            assert TOOL_CAPABILITY_MAP.get(op) == "patching", f"{op!r} must map to 'patching'"

    def test_memory_access_family_entries_present(self) -> None:
        """Core memory-access operations must map to 'memory_access'."""
        mem_ops: list[str] = ["read_memory", "write_memory", "allocate_memory", "get_memory_regions"]
        for op in mem_ops:
            assert TOOL_CAPABILITY_MAP.get(op) == "memory_access", f"{op!r} must map to 'memory_access'"
