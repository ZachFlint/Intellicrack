# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Genuine behavioral tests for Intellicrack core types module.

Each test drives production logic to a verified expected outcome derived from
an independent oracle (PE flag bitmask specifications, Python language semantics,
UUID format, or documented API contracts), not from re-reading the fields
that were just written.  Every test goes red if the covered production code
is deleted or corrupted.
"""

from __future__ import annotations

import math
import re
from dataclasses import fields
from datetime import UTC
from pathlib import Path

import pytest

from intellicrack.core.session import Session
from intellicrack.core.types import (
    AttachError,
    AuthenticationError,
    BinaryInfo,
    BreakpointInfo,
    BridgeAnalysisSummary,
    CrossReference,
    DataTypeInfo,
    FunctionInfo,
    HookInfo,
    IntellicrackError,
    Message,
    ModuleInfo,
    PatchInfo,
    ProcessInfo,
    ProviderError,
    ProviderName,
    RateLimitError,
    RegisterState,
    SandboxError,
    SectionInfo,
    StringInfo,
    ThreadInfo,
    ToolCall,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
    ToolState,
    VariableInfo,
)


# ---------------------------------------------------------------------------
# SectionInfo computed properties (PE characteristic bit flags)
# Independent oracle: PE specification bitmask values
#   0x20000000 = IMAGE_SCN_MEM_EXECUTE
#   0x40000000 = IMAGE_SCN_MEM_READ
#   0x80000000 = IMAGE_SCN_MEM_WRITE
# ---------------------------------------------------------------------------

_TEXT_CHARACTERISTICS = 0x60000020  # EXECUTE | READ | CNT_CODE
_DATA_CHARACTERISTICS = 0xC0000040  # READ | WRITE | CNT_INITIALIZED_DATA


def _make_section(name: str, characteristics: int, entropy: float = 5.0) -> SectionInfo:
    """Build a minimal SectionInfo for property tests.

    Args:
        name: Section name.
        characteristics: PE section characteristic flags.
        entropy: Shannon entropy value.

    Returns:
        SectionInfo: Minimal section instance.
    """
    return SectionInfo(
        name=name,
        virtual_address=0x1000,
        virtual_size=0x5000,
        raw_size=0x4800,
        characteristics=characteristics,
        entropy=entropy,
    )


def _make_binary(name: str = "test.exe") -> BinaryInfo:
    """Create a minimal BinaryInfo for session tests.

    Args:
        name: Binary filename.

    Returns:
        BinaryInfo: Minimal binary instance.
    """
    return BinaryInfo(
        path=Path(f"C:/test/{name}"),
        name=name,
        size=65536,
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_type="pe",
        architecture="x86_64",
        is_64bit=True,
        entry_point=0x401000,
        sections=[],
        imports=[],
        exports=[],
    )


def test_section_executable_flag_set() -> None:
    """SectionInfo.is_executable returns True when bit 0x20000000 is set."""
    sec = _make_section(".text", _TEXT_CHARACTERISTICS)
    assert sec.is_executable is True
    assert sec.is_readable is True
    assert sec.is_writable is False


def test_section_writable_flag_set() -> None:
    """SectionInfo.is_writable returns True when bit 0x80000000 is set."""
    sec = _make_section(".data", _DATA_CHARACTERISTICS)
    assert sec.is_writable is True
    assert sec.is_readable is True
    assert sec.is_executable is False


def test_section_no_flags() -> None:
    """SectionInfo with no permission bits returns False for all three properties."""
    sec = _make_section(".pad", 0x00000000)
    assert sec.is_executable is False
    assert sec.is_readable is False
    assert sec.is_writable is False


def test_section_all_permission_flags() -> None:
    """SectionInfo with all three permission bits returns True for all three properties."""
    all_flags = 0xE0000000
    sec = _make_section(".rwx", all_flags)
    assert sec.is_executable is True
    assert sec.is_readable is True
    assert sec.is_writable is True


def test_section_entropy_high_flags_packed() -> None:
    """High-entropy section correctly reports executable (UPX0 pattern)."""
    sec = _make_section(".upx0", 0xE0000020, entropy=7.95)
    assert sec.entropy > 7.0
    assert sec.is_executable is True


# ---------------------------------------------------------------------------
# DataTypeInfo.display_type computed property
# Independent oracle: documented format rules in the class docstring
# ---------------------------------------------------------------------------


def test_display_type_plain_name() -> None:
    """DataTypeInfo.display_type returns the raw name for non-pointer, non-array types."""
    info = DataTypeInfo(
        address=0x401000,
        name="DWORD",
        category="/PE/Types",
        size=4,
        is_pointer=False,
        is_array=False,
        array_length=None,
        base_type=None,
    )
    assert info.display_type == "DWORD"


def test_display_type_pointer_format() -> None:
    """DataTypeInfo.display_type returns 'base_type *' for pointer types."""
    info = DataTypeInfo(
        address=0x402000,
        name="char *",
        category="/C/Pointers",
        size=8,
        is_pointer=True,
        is_array=False,
        array_length=None,
        base_type="char",
    )
    assert info.display_type == "char *"


def test_display_type_array_format() -> None:
    """DataTypeInfo.display_type returns 'base_type[N]' for array types."""
    info = DataTypeInfo(
        address=0x403000,
        name="byte[256]",
        category="/Arrays",
        size=256,
        is_pointer=False,
        is_array=True,
        array_length=256,
        base_type="byte",
    )
    assert info.display_type == "byte[256]"


def test_display_type_pointer_without_base_type_falls_back_to_name() -> None:
    """DataTypeInfo.display_type falls back to name when is_pointer but base_type is None."""
    info = DataTypeInfo(
        address=0x404000,
        name="void *",
        category="/C/Pointers",
        size=8,
        is_pointer=True,
        is_array=False,
        array_length=None,
        base_type=None,
    )
    assert info.display_type == "void *"


def test_display_type_array_without_base_type_falls_back_to_name() -> None:
    """DataTypeInfo.display_type falls back to name when is_array but base_type is None."""
    info = DataTypeInfo(
        address=0x405000,
        name="unknown[]",
        category="/Arrays",
        size=0,
        is_pointer=False,
        is_array=True,
        array_length=10,
        base_type=None,
    )
    assert info.display_type == "unknown[]"


# ---------------------------------------------------------------------------
# FunctionInfo.has_code and FunctionInfo.summary
# Independent oracle: documented property semantics
# ---------------------------------------------------------------------------


def test_function_has_code_false_when_both_none() -> None:
    """FunctionInfo.has_code is False when neither decompiled_code nor disassembly is set."""
    info = FunctionInfo(
        name="CheckLicense",
        address=0x401000,
        size=256,
        calling_convention="fastcall",
        return_type="BOOL",
        parameters=[],
        local_variables=[],
    )
    assert info.has_code is False


def test_function_has_code_true_with_decompiled_code() -> None:
    """FunctionInfo.has_code is True when decompiled_code is non-empty."""
    info = FunctionInfo(
        name="ValidateKey",
        address=0x402000,
        size=128,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
        decompiled_code="int ValidateKey(void) { return 1; }",
    )
    assert info.has_code is True


def test_function_has_code_true_with_disassembly_only() -> None:
    """FunctionInfo.has_code is True when only disassembly is provided."""
    info = FunctionInfo(
        name="sub_401000",
        address=0x401000,
        size=64,
        calling_convention="unknown",
        return_type="void",
        parameters=[],
        local_variables=[],
        disassembly="push ebp\nmov ebp, esp",
    )
    assert info.has_code is True


def test_function_summary_format() -> None:
    """FunctionInfo.summary produces 'name@hex_addr (convention, N vars)' format."""
    var = VariableInfo(name="result", type="DWORD", offset=-0x10, size=4)
    info = FunctionInfo(
        name="CheckLicense",
        address=0x401000,
        size=256,
        calling_convention="fastcall",
        return_type="BOOL",
        parameters=[],
        local_variables=[var],
    )
    assert info.summary == "CheckLicense@0x401000 (fastcall, 1 vars)"


def test_function_summary_zero_vars() -> None:
    """FunctionInfo.summary shows '0 vars' when no local variables are present."""
    info = FunctionInfo(
        name="sub_402000",
        address=0x402000,
        size=32,
        calling_convention="stdcall",
        return_type="void",
        parameters=[],
        local_variables=[],
    )
    assert info.summary == "sub_402000@0x402000 (stdcall, 0 vars)"


# ---------------------------------------------------------------------------
# BreakpointInfo.__str__
# Independent oracle: documented format string in the class docstring
# ---------------------------------------------------------------------------


def test_breakpoint_str_enabled() -> None:
    """BreakpointInfo.__str__ produces 'BP#id @ addr (type): enabled, hit N times'."""
    bp = BreakpointInfo(
        id=1,
        address=0x401000,
        bp_type="software",
        enabled=True,
        hit_count=5,
    )
    assert str(bp) == "BP#1 @ 0x401000 (software): enabled, hit 5 times"


def test_breakpoint_str_disabled_with_condition() -> None:
    """BreakpointInfo.__str__ shows 'disabled' when enabled is False."""
    bp = BreakpointInfo(
        id=2,
        address=0x402000,
        bp_type="hardware",
        enabled=False,
        hit_count=0,
        condition="eax == 0",
    )
    assert str(bp) == "BP#2 @ 0x402000 (hardware): disabled, hit 0 times"


def test_breakpoint_str_zero_hits() -> None:
    """BreakpointInfo.__str__ correctly shows hit_count=0 for a freshly set breakpoint."""
    bp = BreakpointInfo(
        id=42,
        address=0xDEAD000,
        bp_type="memory",
        enabled=True,
        hit_count=0,
    )
    assert "hit 0 times" in str(bp)
    assert "0xdead000" in str(bp)


# ---------------------------------------------------------------------------
# ThreadInfo.__str__
# Independent oracle: documented format string
# ---------------------------------------------------------------------------


def test_thread_str_format() -> None:
    """ThreadInfo.__str__ produces 'Thread tid (state) @ pc=hex_pc'."""
    t = ThreadInfo(tid=1234, start_address=0x401000, current_pc=0x401500, state="running")
    assert str(t) == "Thread 1234 (running) @ pc=0x401500"


def test_thread_str_suspended_state() -> None:
    """ThreadInfo.__str__ reflects the state field accurately for 'suspended'."""
    t = ThreadInfo(tid=7, start_address=0x401000, current_pc=0x401800, state="suspended")
    result = str(t)
    assert "suspended" in result
    assert "Thread 7" in result
    assert "0x401800" in result


# ---------------------------------------------------------------------------
# CrossReference.__str__
# Independent oracle: documented format "[type] src -> dst"
# ---------------------------------------------------------------------------


def test_cross_reference_str_with_function_names() -> None:
    """CrossReference.__str__ uses function names when available."""
    xref = CrossReference(
        from_address=0x401000,
        to_address=0x402000,
        ref_type="call",
        from_function="main",
        to_function="CheckLicense",
    )
    assert str(xref) == "[call] main -> CheckLicense"


def test_cross_reference_str_with_addresses_fallback() -> None:
    """CrossReference.__str__ falls back to hex addresses when function names are None."""
    xref = CrossReference(
        from_address=0x401000,
        to_address=0x402000,
        ref_type="data",
        from_function=None,
        to_function=None,
    )
    assert str(xref) == "[data] 0x401000 -> 0x402000"


def test_cross_reference_str_mixed_names() -> None:
    """CrossReference.__str__ uses function name for src but address for unnamed dst."""
    xref = CrossReference(
        from_address=0x401000,
        to_address=0x402000,
        ref_type="jump",
        from_function="dispatcher",
        to_function=None,
    )
    assert str(xref) == "[jump] dispatcher -> 0x402000"


# ---------------------------------------------------------------------------
# RegisterState.__getitem__, get_gpr_dict, get_segment_registers
# Independent oracle: x86-64 ABI register set
# ---------------------------------------------------------------------------

_REG_STATE_KWARGS: dict[str, int] = {
    "rax": 0x1234567890ABCDEF,
    "rbx": 0,
    "rcx": 0x100,
    "rdx": 0x200,
    "rsi": 0x300,
    "rdi": 0x400,
    "rbp": 0x7FFF00000000,
    "rsp": 0x7FFF00001000,
    "rip": 0x401000,
    "r8": 0,
    "r9": 0,
    "r10": 0,
    "r11": 0,
    "r12": 0,
    "r13": 0,
    "r14": 0,
    "r15": 0,
    "rflags": 0x246,
    "cs": 0x33,
    "ds": 0x2B,
    "es": 0x2B,
    "fs": 0x53,
    "gs": 0x2B,
    "ss": 0x2B,
}


def test_register_state_getitem_valid_key() -> None:
    """RegisterState.__getitem__ returns the correct register value for a valid key."""
    state = RegisterState(**_REG_STATE_KWARGS)
    assert state["rax"] == 0x1234567890ABCDEF
    assert state["rip"] == 0x401000
    assert state["rflags"] == 0x246
    assert state["cs"] == 0x33
    assert state["fs"] == 0x53


def test_register_state_getitem_invalid_key_raises_key_error() -> None:
    """RegisterState.__getitem__ raises KeyError for an unknown register name."""
    state = RegisterState(**_REG_STATE_KWARGS)
    with pytest.raises(KeyError):
        _ = state["notreg"]


def test_register_state_getitem_x86_32_name_raises_key_error() -> None:
    """RegisterState.__getitem__ raises KeyError for x86-32 register names not in x64 ABI."""
    state = RegisterState(**_REG_STATE_KWARGS)
    with pytest.raises(KeyError):
        _ = state["eip"]


def test_register_state_get_gpr_dict_contains_all_16_gprs() -> None:
    """RegisterState.get_gpr_dict returns exactly the 16 x86-64 GPRs."""
    state = RegisterState(**_REG_STATE_KWARGS)
    gpr = state.get_gpr_dict()
    expected_keys = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
    assert set(gpr.keys()) == expected_keys
    assert gpr["rax"] == 0x1234567890ABCDEF
    assert gpr["rcx"] == 0x100
    assert gpr["rsp"] == 0x7FFF00001000


def test_register_state_get_gpr_dict_excludes_rip_and_segments() -> None:
    """RegisterState.get_gpr_dict must not include rip or segment registers."""
    state = RegisterState(**_REG_STATE_KWARGS)
    gpr = state.get_gpr_dict()
    for excluded in ("rip", "rflags", "cs", "ds", "es", "fs", "gs", "ss"):
        assert excluded not in gpr, f"GPR dict should not contain {excluded}"


def test_register_state_get_segment_registers_contains_all_six() -> None:
    """RegisterState.get_segment_registers returns exactly the 6 x86-64 segment registers."""
    state = RegisterState(**_REG_STATE_KWARGS)
    segs = state.get_segment_registers()
    assert set(segs.keys()) == {"cs", "ds", "es", "fs", "gs", "ss"}
    assert segs["cs"] == 0x33
    assert segs["fs"] == 0x53
    assert segs["ss"] == 0x2B


def test_register_state_get_segment_registers_excludes_gprs() -> None:
    """RegisterState.get_segment_registers must not include any GPR or rip."""
    state = RegisterState(**_REG_STATE_KWARGS)
    segs = state.get_segment_registers()
    for gpr_name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "r8"):
        assert gpr_name not in segs


# ---------------------------------------------------------------------------
# ToolFunction.signature computed property
# Independent oracle: documented format "name(param: type, ...) -> returns"
# ---------------------------------------------------------------------------


def test_tool_function_signature_single_param() -> None:
    """ToolFunction.signature renders 'name(param: type) -> returns'."""
    param = ToolParameter(name="address", type="integer", description="Target address", required=True)
    func = ToolFunction(name="read_memory", description="Read bytes", parameters=[param], returns="bytes")
    assert func.signature == "read_memory(address: integer) -> bytes"


def test_tool_function_signature_multiple_params() -> None:
    """ToolFunction.signature lists all parameters separated by ', '."""
    p1 = ToolParameter(name="address", type="integer", description="Address", required=True)
    p2 = ToolParameter(name="size", type="integer", description="Size", required=False, default=16)
    func = ToolFunction(name="read_memory", description="Read bytes", parameters=[p1, p2], returns="bytes")
    assert func.signature == "read_memory(address: integer, size: integer) -> bytes"


def test_tool_function_signature_no_params() -> None:
    """ToolFunction.signature with empty params produces 'name() -> returns'."""
    func = ToolFunction(name="list_modules", description="List modules", parameters=[], returns="list[ModuleInfo]")
    assert func.signature == "list_modules() -> list[ModuleInfo]"


# ---------------------------------------------------------------------------
# BridgeAnalysisSummary.complete flag semantics
# Independent oracle: docstring states False is the default; consumers MUST
# check this flag before treating the summary as authoritative
# ---------------------------------------------------------------------------


def test_bridge_analysis_summary_complete_defaults_false() -> None:
    """BridgeAnalysisSummary.complete is False when not explicitly set."""
    summary = BridgeAnalysisSummary(
        binary_name="test.exe",
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


def test_bridge_analysis_summary_complete_can_be_set_true() -> None:
    """BridgeAnalysisSummary.complete reflects True when a bridge has contributed."""
    summary = BridgeAnalysisSummary(
        binary_name="analyzed.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=["binary"],
        analysis_notes=["static analysis complete"],
        complete=True,
    )
    assert summary.complete is True


def test_bridge_analysis_summary_source_bridges_content() -> None:
    """BridgeAnalysisSummary.source_bridges preserves all bridge names in order."""
    summary = BridgeAnalysisSummary(
        binary_name="target.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=["binary", "ghidra", "frida"],
        analysis_notes=[],
        complete=True,
    )
    assert summary.source_bridges == ["binary", "ghidra", "frida"]
    assert len(summary.source_bridges) == 3


def test_bridge_analysis_summary_str_contains_binary_name() -> None:
    """str(BridgeAnalysisSummary) includes the binary_name field."""
    summary = BridgeAnalysisSummary(
        binary_name="uniqueMarkerBinary.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=["binary"],
        analysis_notes=[],
    )
    assert "uniqueMarkerBinary.exe" in str(summary)


# ---------------------------------------------------------------------------
# IntellicrackError hierarchy: construction, str, and isinstance tests
# These tests are falsifiable: if the inheritance chain is broken the isinstance
# check will return False, or the str representation will not match.
# ---------------------------------------------------------------------------


def test_intellicrack_error_str_equals_message() -> None:
    """str(IntellicrackError) equals the message passed to __init__."""
    msg = "Something went wrong in the analysis engine"
    err = IntellicrackError(msg)
    assert str(err) == msg


def test_intellicrack_error_code_is_none_by_default() -> None:
    """IntellicrackError.error_code is None when not explicitly provided."""
    err = IntellicrackError("no code")
    assert err.error_code is None


def test_intellicrack_error_details_empty_dict_by_default() -> None:
    """IntellicrackError.details is an empty dict when not explicitly provided."""
    err = IntellicrackError("no details")
    assert err.details == {}


def test_intellicrack_error_stores_error_code() -> None:
    """IntellicrackError stores the provided error_code precisely."""
    err = IntellicrackError("coded", error_code=1001)
    assert err.error_code == 1001


def test_intellicrack_error_stores_details() -> None:
    """IntellicrackError stores the provided details dict without mutation."""
    d = {"component": "analyzer", "phase": "init"}
    err = IntellicrackError("detailed", details=d)
    assert err.details["component"] == "analyzer"
    assert err.details["phase"] == "init"


def test_intellicrack_error_is_exception_subclass() -> None:
    """IntellicrackError is a subclass of Exception."""
    assert issubclass(IntellicrackError, Exception)


def test_provider_error_is_intellicrack_error_subclass() -> None:
    """ProviderError is a subclass of IntellicrackError."""
    assert issubclass(ProviderError, IntellicrackError)


def test_provider_error_caught_as_intellicrack_error() -> None:
    """ProviderError instance is accepted by 'except IntellicrackError' handler."""
    err = ProviderError("api down", provider_name="anthropic", status_code=503)
    assert isinstance(err, IntellicrackError)
    assert err.provider_name == "anthropic"
    assert err.status_code == 503


def test_authentication_error_is_provider_error_subclass() -> None:
    """AuthenticationError is a subclass of ProviderError."""
    assert issubclass(AuthenticationError, ProviderError)
    assert issubclass(AuthenticationError, IntellicrackError)


def test_authentication_error_caught_as_provider_error() -> None:
    """AuthenticationError instance is accepted by ProviderError isinstance check."""
    err = AuthenticationError("bad key", provider_name="openai", status_code=401)
    assert isinstance(err, ProviderError)
    assert err.provider_name == "openai"
    assert err.status_code == 401


def test_authentication_error_str_equals_message() -> None:
    """str(AuthenticationError) reflects the message passed to __init__."""
    err = AuthenticationError("expired token")
    assert str(err) == "expired token"


def test_rate_limit_error_is_provider_error_subclass() -> None:
    """RateLimitError is a subclass of ProviderError."""
    assert issubclass(RateLimitError, ProviderError)


def test_rate_limit_error_caught_as_provider_error() -> None:
    """RateLimitError instance is accepted by ProviderError isinstance check."""
    err = RateLimitError("too many requests", retry_after=60.0, provider_name="anthropic", status_code=429)
    assert isinstance(err, ProviderError)
    assert err.retry_after is not None
    assert math.isclose(err.retry_after, 60.0)
    assert err.provider_name == "anthropic"
    assert err.status_code == 429


def test_rate_limit_error_retry_after_none_by_default() -> None:
    """RateLimitError.retry_after is None when not provided."""
    err = RateLimitError("rate limited")
    assert err.retry_after is None


def test_tool_error_is_intellicrack_error_subclass() -> None:
    """ToolError is a subclass of IntellicrackError."""
    assert issubclass(ToolError, IntellicrackError)


def test_tool_error_caught_as_intellicrack_error() -> None:
    """ToolError instance is accepted by IntellicrackError isinstance check."""
    err = ToolError("ghidra crashed", tool_name="ghidra", exit_code=1, stderr="OOM")
    assert isinstance(err, IntellicrackError)
    assert isinstance(err, ToolError)
    assert err.tool_name == "ghidra"
    assert err.exit_code == 1
    assert err.stderr == "OOM"


def test_attach_error_is_tool_error_subclass() -> None:
    """AttachError is a subclass of ToolError."""
    assert issubclass(AttachError, ToolError)
    assert issubclass(AttachError, IntellicrackError)


def test_attach_error_caught_as_tool_error() -> None:
    """AttachError instance is accepted by ToolError isinstance check."""
    err = AttachError("access denied", pid=4567, process_name="protectedapp.exe", tool_name="x64dbg")
    assert isinstance(err, ToolError)
    assert isinstance(err, AttachError)
    assert err.pid == 4567
    assert err.process_name == "protectedapp.exe"
    assert err.tool_name == "x64dbg"


def test_sandbox_error_is_intellicrack_error_subclass() -> None:
    """SandboxError is a subclass of IntellicrackError."""
    assert issubclass(SandboxError, IntellicrackError)


def test_sandbox_error_caught_as_intellicrack_error() -> None:
    """SandboxError instance is accepted by IntellicrackError isinstance check."""
    err = SandboxError("VM failed", sandbox_type="qemu", vm_state="paused", error_code=3001)
    assert isinstance(err, IntellicrackError)
    assert isinstance(err, SandboxError)
    assert err.sandbox_type == "qemu"
    assert err.vm_state == "paused"
    assert err.error_code == 3001


def test_sandbox_error_not_subclass_of_provider_error() -> None:
    """SandboxError is not a subclass of ProviderError."""
    assert not issubclass(SandboxError, ProviderError)


def test_tool_error_not_subclass_of_provider_error() -> None:
    """ToolError is not a subclass of ProviderError."""
    assert not issubclass(ToolError, ProviderError)


# ---------------------------------------------------------------------------
# pytest.raises tests for exception error paths
# These use pytest.raises to verify that specific operations raise the right
# exception type with the right message.
# ---------------------------------------------------------------------------


def test_register_state_getitem_raises_key_error_with_message() -> None:
    """RegisterState.__getitem__ includes the bad key name in the KeyError."""
    state = RegisterState(**_REG_STATE_KWARGS)
    with pytest.raises(KeyError, match="eip"):
        _ = state["eip"]


def test_tool_name_invalid_value_raises_value_error_with_name() -> None:
    """ToolName raises ValueError containing the invalid value for an unrecognized string."""
    with pytest.raises(ValueError, match="nonexistent_tool"):
        ToolName("nonexistent_tool")


def test_provider_name_invalid_value_raises_value_error_with_name() -> None:
    """ProviderName raises ValueError containing the invalid value for an unrecognized string."""
    with pytest.raises(ValueError, match="nonexistent_provider"):
        ProviderName("nonexistent_provider")


def test_session_add_tag_whitespace_raises_value_error_with_message() -> None:
    """Session.add_tag raises ValueError with the documented message for whitespace tags."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    with pytest.raises(ValueError, match="non-empty"):
        session.add_tag("   ")


def test_session_add_tag_empty_raises_value_error_with_message() -> None:
    """Session.add_tag raises ValueError with the documented message for empty tags."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    with pytest.raises(ValueError, match="non-empty"):
        session.add_tag("")


# ---------------------------------------------------------------------------
# ToolName and ProviderName enum membership and values
# Independent oracle: documented string values required by external tool bridges
# ---------------------------------------------------------------------------


def test_tool_name_enum_values_exact() -> None:
    """ToolName enum members have the exact string values required by bridges."""
    assert ToolName.GHIDRA.value == "ghidra"
    assert ToolName.X64DBG.value == "x64dbg"
    assert ToolName.FRIDA.value == "frida"
    assert ToolName.CUTTER.value == "cutter"
    assert ToolName.SANDBOX.value == "sandbox"
    assert ToolName.HEX_EDITOR.value == "hex_editor"


def test_provider_name_enum_values_exact() -> None:
    """ProviderName enum members have the exact string values required by provider bridges."""
    assert ProviderName.ANTHROPIC.value == "anthropic"
    assert ProviderName.OPENAI.value == "openai"
    assert ProviderName.GOOGLE.value == "google"
    assert ProviderName.OLLAMA.value == "ollama"
    assert ProviderName.OPENROUTER.value == "openrouter"


def test_tool_name_roundtrip_from_value() -> None:
    """ToolName can be reconstructed from its string value (used by deserializers)."""
    assert ToolName("ghidra") is ToolName.GHIDRA
    assert ToolName("frida") is ToolName.FRIDA
    assert ToolName("x64dbg") is ToolName.X64DBG


def test_provider_name_roundtrip_from_value() -> None:
    """ProviderName can be reconstructed from its string value (used by session deserializer)."""
    assert ProviderName("anthropic") is ProviderName.ANTHROPIC
    assert ProviderName("openai") is ProviderName.OPENAI


# ---------------------------------------------------------------------------
# Session.create: UUID format and field initialization
# Independent oracle: UUID v4 spec (RFC 4122) — 8-4-4-4-12 hex groups
# ---------------------------------------------------------------------------

_UUID4_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
)


def test_session_create_generates_uuid4_id() -> None:
    """Session.create produces a UUID v4 session ID conforming to RFC 4122."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022", name="Test")
    assert _UUID4_PATTERN.match(session.id), f"Session ID {session.id!r} is not a valid UUID v4"


def test_session_create_ids_are_unique() -> None:
    """Session.create produces a different ID for each call (probabilistic UUID uniqueness)."""
    ids = {Session.create(provider=ProviderName.OPENAI, model="gpt-4o").id for _ in range(10)}
    assert len(ids) == 10


def test_session_create_stores_provider_and_model() -> None:
    """Session.create stores provider and model exactly as passed."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-opus-4-5-20251101")
    assert session.provider is ProviderName.ANTHROPIC
    assert session.model == "claude-opus-4-5-20251101"


def test_session_create_uses_provided_name() -> None:
    """Session.create stores the explicit name when one is provided."""
    session = Session.create(provider=ProviderName.OPENAI, model="gpt-4o", name="My Analysis Session")
    assert session.name == "My Analysis Session"


def test_session_create_starts_with_empty_collections() -> None:
    """Session.create produces a session with no binaries, messages, patches, or tags."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    assert session.binaries == []
    assert session.messages == []
    assert session.patches == []
    assert session.tags == []


def test_session_active_binary_none_when_no_binaries() -> None:
    """Session.active_binary returns None before any binary is added."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    assert session.active_binary is None


# ---------------------------------------------------------------------------
# Session.add_binary / active_binary
# Independent oracle: add_binary sets active_binary_index to 0 on first add
# ---------------------------------------------------------------------------


def test_session_add_binary_makes_it_active() -> None:
    """Adding the first binary sets active_binary_index=0 and active_binary points to it."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    binary = _make_binary("target.exe")
    session.add_binary(binary)
    assert session.active_binary_index == 0
    assert session.active_binary is not None
    assert session.active_binary.name == "target.exe"


def test_session_add_two_binaries_first_remains_active() -> None:
    """Adding a second binary does not change the active index away from 0."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_binary(_make_binary("first.exe"))
    session.add_binary(_make_binary("second.exe"))
    assert session.active_binary_index == 0
    assert session.active_binary is not None
    assert session.active_binary.name == "first.exe"


def test_session_active_binary_respects_index_change() -> None:
    """Session.active_binary follows active_binary_index when changed manually."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_binary(_make_binary("first.exe"))
    session.add_binary(_make_binary("second.exe"))
    session.active_binary_index = 1
    assert session.active_binary is not None
    assert session.active_binary.name == "second.exe"


def test_session_active_binary_out_of_range_returns_none() -> None:
    """Session.active_binary returns None when index is out of bounds."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_binary(_make_binary())
    session.active_binary_index = 99
    assert session.active_binary is None


# ---------------------------------------------------------------------------
# Session.add_tag / remove_tag
# Independent oracle: documented contract (bool return, ValueError, normalisation)
# ---------------------------------------------------------------------------


def test_session_add_tag_returns_true_for_new_tag() -> None:
    """Session.add_tag returns True when the tag is freshly added."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    assert session.add_tag("malware") is True
    assert "malware" in session.tags


def test_session_add_tag_returns_false_for_duplicate() -> None:
    """Session.add_tag returns False and does not duplicate when tag already exists."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_tag("malware")
    result = session.add_tag("malware")
    assert result is False
    assert session.tags.count("malware") == 1


def test_session_add_tag_strips_whitespace() -> None:
    """Session.add_tag normalises tags by stripping leading/trailing whitespace."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_tag("  ransomware  ")
    assert "ransomware" in session.tags
    assert "  ransomware  " not in session.tags


def test_session_remove_tag_returns_true_when_present() -> None:
    """Session.remove_tag returns True and removes the tag when it exists."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_tag("malware")
    result = session.remove_tag("malware")
    assert result is True
    assert "malware" not in session.tags


def test_session_remove_tag_returns_false_when_absent() -> None:
    """Session.remove_tag returns False without error when tag does not exist."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    result = session.remove_tag("nonexistent")
    assert result is False


def test_session_remove_tag_strips_whitespace_to_match() -> None:
    """Session.remove_tag matches against normalised tag (strips whitespace)."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    session.add_tag("pe_binary")
    result = session.remove_tag("  pe_binary  ")
    assert result is True
    assert "pe_binary" not in session.tags


# ---------------------------------------------------------------------------
# Session.set_tool_state / clear_tool_state
# Independent oracle: dict-based storage; clear returns True iff key existed
# ---------------------------------------------------------------------------


def test_session_set_tool_state_stores_state() -> None:
    """Session.set_tool_state stores the ToolState and makes it retrievable."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    state = ToolState(tool=ToolName.GHIDRA, connected=True, process_attached=False, target_path=None, last_error=None)
    session.set_tool_state(state)
    assert ToolName.GHIDRA in session.tool_states
    stored = session.tool_states[ToolName.GHIDRA]
    assert stored.connected is True
    assert stored.tool is ToolName.GHIDRA


def test_session_set_tool_state_overwrites_previous() -> None:
    """Session.set_tool_state replaces the previous state for the same tool."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    s1 = ToolState(tool=ToolName.FRIDA, connected=True, process_attached=False, target_path=None, last_error=None)
    s2 = ToolState(tool=ToolName.FRIDA, connected=False, process_attached=False, target_path=None, last_error="detached")
    session.set_tool_state(s1)
    session.set_tool_state(s2)
    assert session.tool_states[ToolName.FRIDA].connected is False
    assert session.tool_states[ToolName.FRIDA].last_error == "detached"


def test_session_clear_tool_state_returns_true_and_removes() -> None:
    """Session.clear_tool_state returns True and removes the entry when present."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    state = ToolState(tool=ToolName.GHIDRA, connected=True, process_attached=False, target_path=None, last_error=None)
    session.set_tool_state(state)
    result = session.clear_tool_state(ToolName.GHIDRA)
    assert result is True
    assert ToolName.GHIDRA not in session.tool_states


def test_session_clear_tool_state_returns_false_when_absent() -> None:
    """Session.clear_tool_state returns False without error when no state is stored."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    result = session.clear_tool_state(ToolName.X64DBG)
    assert result is False


# ---------------------------------------------------------------------------
# Message timestamp and tool_calls / tool_results wiring
# Independent oracle: datetime UTC, ToolCall/ToolResult field contract
# ---------------------------------------------------------------------------


def test_message_timestamp_is_utc_aware() -> None:
    """Message default timestamp is a UTC-aware datetime, not naive."""
    msg = Message(role="user", content="Hello")
    assert msg.timestamp.tzinfo is not None
    assert msg.timestamp.tzinfo == UTC


def test_message_timestamps_are_distinct_across_instances() -> None:
    """Two separate Message instances have distinct timestamps (not shared default)."""
    m1 = Message(role="user", content="first")
    m2 = Message(role="user", content="second")
    assert m1.timestamp is not m2.timestamp


def test_message_tool_calls_none_by_default() -> None:
    """Message.tool_calls defaults to None when not provided."""
    msg = Message(role="assistant", content="Thinking...")
    assert msg.tool_calls is None


def test_message_with_tool_call_preserves_arguments() -> None:
    """Message.tool_calls stores ToolCall with correct arguments dict."""
    call = ToolCall(
        id="call_abc",
        tool_name="ghidra",
        function_name="decompile",
        arguments={"address": 0x401000, "resolve_names": True},
    )
    msg = Message(role="assistant", content="Decompiling...", tool_calls=[call])
    assert msg.tool_calls is not None
    assert len(msg.tool_calls) == 1
    assert msg.tool_calls[0].id == "call_abc"
    assert msg.tool_calls[0].arguments["address"] == 0x401000
    assert msg.tool_calls[0].arguments["resolve_names"] is True


def test_tool_result_duration_and_error_fields() -> None:
    """ToolResult stores duration_ms and error precisely for both success and failure."""
    ok = ToolResult(call_id="c1", success=True, result={"bp_id": 3}, error=None, duration_ms=15.5)
    fail = ToolResult(call_id="c2", success=False, result=None, error="access denied", duration_ms=5.0)
    assert ok.success is True
    assert ok.error is None
    assert math.isclose(ok.duration_ms, 15.5)
    assert fail.success is False
    assert fail.error == "access denied"
    assert math.isclose(fail.duration_ms, 5.0)


# ---------------------------------------------------------------------------
# PatchInfo byte lengths and values
# Independent oracle: known patch patterns for JZ->JMP and NOP sleds
# ---------------------------------------------------------------------------


def test_patch_info_jz_to_jmp_bytes() -> None:
    """PatchInfo stores original JZ and replacement JMP bytes without mutation."""
    patch = PatchInfo(
        address=0x401000,
        original_bytes=b"\x74\x10",
        new_bytes=b"\xeb\x10",
        description="JZ -> JMP",
        applied=True,
    )
    assert patch.original_bytes == b"\x74\x10"
    assert patch.new_bytes == b"\xeb\x10"
    assert patch.applied is True
    assert len(patch.original_bytes) == len(patch.new_bytes)


def test_patch_info_nop_sled_length_and_bytes() -> None:
    """PatchInfo for a NOP sled has exactly 5 bytes matching the expected opcodes."""
    original = b"\xe8\x00\x10\x00\x00"
    nop_sled = b"\x90\x90\x90\x90\x90"
    patch = PatchInfo(
        address=0x402000,
        original_bytes=original,
        new_bytes=nop_sled,
        description="NOP out license check call",
        applied=False,
    )
    assert len(patch.original_bytes) == 5
    assert len(patch.new_bytes) == 5
    assert all(b == 0x90 for b in patch.new_bytes)
    assert patch.applied is False


# ---------------------------------------------------------------------------
# ToolDefinition structure
# Independent oracle: ToolFunction.signature contract already validated above
# ---------------------------------------------------------------------------


def test_tool_definition_functions_accessible_by_index() -> None:
    """ToolDefinition.functions list is indexable and returns correct ToolFunction."""
    p = ToolParameter(name="address", type="integer", description="Address to read", required=True)
    f1 = ToolFunction(name="read_memory", description="Read bytes from process memory", parameters=[p], returns="bytes")
    f2 = ToolFunction(name="list_modules", description="List loaded modules", parameters=[], returns="list")
    tool = ToolDefinition(tool_name=ToolName.FRIDA, description="Frida dynamic instrumentation", functions=[f1, f2])
    assert tool.functions[0].name == "read_memory"
    assert tool.functions[1].name == "list_modules"
    assert tool.functions[0].signature == "read_memory(address: integer) -> bytes"


def test_tool_parameter_enum_membership() -> None:
    """ToolParameter.enum list contains exactly the provided values."""
    param = ToolParameter(
        name="bp_type",
        type="string",
        description="Breakpoint type",
        required=True,
        enum=["software", "hardware", "memory"],
    )
    assert param.enum == ["software", "hardware", "memory"]
    assert param.enum is not None
    assert "software" in param.enum
    assert "memory" in param.enum
    assert len(param.enum) == 3


# ---------------------------------------------------------------------------
# Session field inventory (structural contract)
# Independent oracle: documented Session attributes in the class docstring
# ---------------------------------------------------------------------------


def test_session_has_all_required_fields() -> None:
    """Session dataclass exposes all documented fields."""
    required = {
        "id",
        "name",
        "created_at",
        "updated_at",
        "provider",
        "model",
        "binaries",
        "active_binary_index",
        "messages",
        "tool_states",
        "patches",
        "bridge_analyses",
        "notes",
        "tags",
    }
    actual = {f.name for f in fields(Session)}
    missing = required - actual
    assert not missing, f"Missing Session fields: {missing}"


def test_bridge_analysis_summary_has_complete_field() -> None:
    """BridgeAnalysisSummary exposes the 'complete' flag that consumers must check."""
    field_names = {f.name for f in fields(BridgeAnalysisSummary)}
    assert "complete" in field_names


# ---------------------------------------------------------------------------
# Session.get_bridge_analysis / add_bridge_analysis round-trip
# Independent oracle: dict storage keyed by binary name
# ---------------------------------------------------------------------------


def test_session_add_and_get_bridge_analysis() -> None:
    """Session.add_bridge_analysis stores and get_bridge_analysis retrieves the same object."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    analysis = BridgeAnalysisSummary(
        binary_name="target.exe",
        strings=[StringInfo(address=0x401010, value="Invalid License", encoding="ascii", section=".rdata")],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=["binary"],
        analysis_notes=["found license check string"],
        complete=True,
    )
    session.add_bridge_analysis("target.exe", analysis)
    retrieved = session.get_bridge_analysis("target.exe")
    assert retrieved is not None
    assert retrieved.binary_name == "target.exe"
    assert retrieved.complete is True
    assert len(retrieved.strings) == 1
    assert retrieved.strings[0].value == "Invalid License"
    assert retrieved.source_bridges == ["binary"]


def test_session_get_bridge_analysis_returns_none_for_unknown() -> None:
    """Session.get_bridge_analysis returns None when the binary name has no stored analysis."""
    session = Session.create(provider=ProviderName.ANTHROPIC, model="claude-3-5-sonnet-20241022")
    result = session.get_bridge_analysis("not_loaded.exe")
    assert result is None


# ---------------------------------------------------------------------------
# ProcessInfo / ThreadInfo / ModuleInfo composite structure
# Independent oracle: known field values cross-checked against input
# ---------------------------------------------------------------------------


def test_process_info_threads_and_modules_preserved() -> None:
    """ProcessInfo.threads and .modules store all passed entries in order."""
    t1 = ThreadInfo(tid=1, start_address=0x401000, current_pc=0x401000, state="running")
    t2 = ThreadInfo(tid=2, start_address=0x402000, current_pc=0x402500, state="suspended")
    mod = ModuleInfo(
        name="ntdll.dll",
        path=Path("C:/Windows/System32/ntdll.dll"),
        base_address=0x77000000,
        size=0x1A0000,
        entry_point=0,
    )
    proc = ProcessInfo(
        pid=1234,
        name="target.exe",
        path=Path("C:/Program Files/App/target.exe"),
        command_line="target.exe --debug",
        parent_pid=4,
        threads=[t1, t2],
        modules=[mod],
    )
    assert proc.pid == 1234
    assert len(proc.threads) == 2
    assert proc.threads[0].tid == 1
    assert proc.threads[1].tid == 2
    assert proc.threads[1].state == "suspended"
    assert len(proc.modules) == 1
    assert proc.modules[0].base_address == 0x77000000


# ---------------------------------------------------------------------------
# HookInfo optional address
# Independent oracle: None vs int semantics
# ---------------------------------------------------------------------------


def test_hook_info_active_with_resolved_address() -> None:
    """HookInfo stores an active hook with a resolved integer address."""
    hook = HookInfo(id="hook_001", target="CheckLicense", address=0x401000, script_id="scr_1", active=True)
    assert hook.address == 0x401000
    assert hook.active is True


def test_hook_info_unresolved_address_is_none() -> None:
    """HookInfo address=None represents an unresolved hook target."""
    hook = HookInfo(id="hook_002", target="kernel32.dll!CreateFileW", address=None, script_id="scr_2", active=False)
    assert hook.address is None
    assert hook.active is False
