"""Tests for bridges.base module - dataclasses, BridgeState, and BridgeCapabilities."""

from __future__ import annotations

from typing import Final

from intellicrack.bridges.base import (
    BridgeCapabilities,
    BridgeState,
    DisassemblyLine,
    MemorySearchResult,
    StackFrame,
    WatchpointInfo,
)


_ADDR: Final[int] = 0x00401000
_ADDR2: Final[int] = 0x00401010
_SIZE: Final[int] = 4


def test_disassembly_line_construction() -> None:
    """Verify DisassemblyLine dataclass fields."""
    line = DisassemblyLine(
        address=_ADDR,
        bytes_str="90",
        mnemonic="nop",
        operands="",
    )
    assert line.address == _ADDR
    assert line.bytes_str == "90"
    assert line.mnemonic == "nop"
    assert not line.operands
    assert line.comment is None


def test_disassembly_line_with_comment() -> None:
    """Verify DisassemblyLine with optional comment."""
    line = DisassemblyLine(
        address=_ADDR,
        bytes_str="CC",
        mnemonic="int3",
        operands="",
        comment="breakpoint",
    )
    assert line.comment == "breakpoint"


def test_memory_search_result_construction() -> None:
    """Verify MemorySearchResult dataclass fields."""
    result = MemorySearchResult(
        address=_ADDR,
        matched_bytes="90 90",
        context_before="CC",
        context_after="C3",
    )
    assert result.address == _ADDR
    assert result.matched_bytes == "90 90"
    assert result.context_before == "CC"
    assert result.context_after == "C3"


def test_stack_frame_construction() -> None:
    """Verify StackFrame dataclass fields."""
    frame = StackFrame(
        index=0,
        address=_ADDR,
        return_address=_ADDR2,
        frame_pointer=0x0028FF00,
        stack_pointer=0x0028FEF0,
        function_name="main",
        module_name="test.exe",
    )
    assert frame.index == 0
    assert frame.address == _ADDR
    assert frame.function_name == "main"
    assert frame.module_name == "test.exe"


def test_stack_frame_none_names() -> None:
    """Verify StackFrame with unknown function/module."""
    frame = StackFrame(
        index=1,
        address=_ADDR,
        return_address=_ADDR2,
        frame_pointer=0,
        stack_pointer=0,
        function_name=None,
        module_name=None,
    )
    assert frame.function_name is None
    assert frame.module_name is None


def test_watchpoint_info_construction() -> None:
    """Verify WatchpointInfo dataclass fields."""
    wp = WatchpointInfo(
        id=1,
        address=_ADDR,
        size=_SIZE,
        watch_type="write",
        enabled=True,
        hit_count=0,
    )
    assert wp.id == 1
    assert wp.size == _SIZE
    assert wp.watch_type == "write"
    assert wp.enabled is True
    assert wp.hit_count == 0


def test_bridge_capabilities_defaults() -> None:
    """Verify BridgeCapabilities defaults to all False."""
    caps = BridgeCapabilities()
    assert caps.supports_static_analysis is False
    assert caps.supports_dynamic_analysis is False
    assert caps.supports_decompilation is False
    assert caps.supports_debugging is False
    assert caps.supports_patching is False
    assert caps.supports_scripting is False
    assert caps.supports_memory_access is False
    assert caps.supported_architectures == []
    assert caps.supported_formats == []


def test_bridge_capabilities_has_capability() -> None:
    """Verify has_capability() checks supports_ attribute."""
    caps = BridgeCapabilities(supports_static_analysis=True)
    assert caps.has_capability("static_analysis") is True
    assert caps.has_capability("debugging") is False
    assert caps.has_capability("nonexistent") is False


def test_bridge_capabilities_supports_arch() -> None:
    """Verify supports_arch() checks architecture list."""
    caps = BridgeCapabilities(supported_architectures=["x86", "x86_64"])
    assert caps.supports_arch("x86") is True
    assert caps.supports_arch("arm") is False


def test_bridge_capabilities_supports_format() -> None:
    """Verify supports_format() checks format list."""
    caps = BridgeCapabilities(supported_formats=["pe", "elf"])
    assert caps.supports_format("pe") is True
    assert caps.supports_format("macho") is False


def test_bridge_state_defaults() -> None:
    """Verify BridgeState defaults."""
    state = BridgeState()
    assert state.connected is False
    assert state.tool_running is False
    assert state.binary_loaded is False
    assert state.process_attached is False
    assert state.target_path is None
    assert state.target_pid is None
    assert state.last_error is None


def test_bridge_state_is_ready() -> None:
    """Verify is_ready() requires both connected and tool_running."""
    state = BridgeState()
    assert state.is_ready() is False
    state.connected = True
    assert state.is_ready() is False
    state.tool_running = True
    assert state.is_ready() is True


def test_bridge_state_clear_error() -> None:
    """Verify clear_error() resets last_error."""
    state = BridgeState(last_error="something broke")
    assert state.last_error == "something broke"
    state.clear_error()
    assert state.last_error is None
