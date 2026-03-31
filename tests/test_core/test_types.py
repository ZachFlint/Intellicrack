# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Comprehensive tests for Intellicrack core types module.

Tests validate:
- Dataclass field assignments and type correctness
- BridgeAnalysisSummary aggregation type
- DataTypeInfo for Ghidra integration
- Session and state management types
"""

from __future__ import annotations

from dataclasses import fields
from pathlib import Path

from intellicrack.core.types import (
    AttachError,
    AuthenticationError,
    BinaryInfo,
    BreakpointInfo,
    BridgeAnalysisSummary,
    DataTypeInfo,
    ExportInfo,
    FunctionInfo,
    HookInfo,
    ImportInfo,
    IntellicrackError,
    Message,
    ModuleInfo,
    ParameterInfo,
    PatchInfo,
    ProcessInfo,
    ProviderError,
    ProviderName,
    RateLimitError,
    RegisterState,
    SandboxError,
    SectionInfo,
    Session,
    StringInfo,
    ThreadInfo,
    ToolCall,
    ToolDefinition,
    ToolError,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
    VariableInfo,
)


# Test constants for memory addresses
ADDR_BASE = 0x401000
ADDR_SECONDARY = 0x402000
ADDR_TERTIARY = 0x403000
ADDR_POINTER = 0x402000
ADDR_ARRAY = 0x403000
ADDR_ENTRY_POINT = 0x401000
ADDR_IMPORT = 0x402000
ADDR_SECTION_VIRTUAL = 0x1000
ADDR_SECTION_UPX_VIRTUAL = 0x1000
ADDR_FUNCTION = 0x401000
ADDR_FUNCTION_ALT = 0x402000
ADDR_BREAKPOINT = 0x401000
ADDR_BREAKPOINT_HW = 0x402000
ADDR_THREAD_START = 0x401000
ADDR_MODULE_BASE = 0x77000000
ADDR_HOOK = 0x401000
ADDR_PATCH = 0x401000
ADDR_PATCH_NOP = 0x402000
ADDR_STACK_POINTER = 0x7FFF00001000
ADDR_BASE_POINTER = 0x7FFF00000000
ADDR_REGISTER_RIP = 0x401000
ADDR_REGISTER_RAX = 0x1234567890ABCDEF

# Test constants for sizes
SIZE_DWORD = 4
SIZE_POINTER_64 = 8
SIZE_ARRAY_256 = 256
SIZE_BINARY = 65536
SIZE_FUNCTION = 256
SIZE_FUNCTION_SMALL = 128
SIZE_SECTION_VIRTUAL = 0x5000
SIZE_SECTION_RAW = 0x4800
SIZE_SECTION_UPX_VIRTUAL = 0x10000
SIZE_SECTION_UPX_RAW = 0x200
SIZE_MODULE = 0x1A0000
SIZE_PATCH_BYTES = 5
SIZE_DEFAULT_READ = 16

# Test constants for PIDs and thread IDs
TEST_PID = 1234
TEST_PID_PROTECTED = 4567
TEST_PARENT_PID = 4
TEST_TID = 1234
TEST_TID_INITIAL = 1
TEST_THREAD_PRIORITY = 8
TEST_THREAD_PRIORITY_HIGH = 10

# Test constants for characteristics and flags
SECTION_CHARACTERISTICS = 0x60000020
SECTION_CHARACTERISTICS_UPX = 0xE0000020
ENTROPY_NORMAL = 6.5
ENTROPY_PACKED = 7.95
ENTROPY_PACKED_THRESHOLD = 7.0

# Test constants for register values
REGISTER_ZERO = 0
REGISTER_RCX = 0x100
REGISTER_RDX = 0x200
REGISTER_RSI = 0x300
REGISTER_RDI = 0x400
REGISTER_RFLAGS = 0x246
REGISTER_CS = 0x33
REGISTER_DS = 0x2B
REGISTER_ES = 0x2B
REGISTER_FS = 0x53
REGISTER_GS = 0x2B
REGISTER_SS = 0x2B

DURATION_MS = 15.5
DURATION_MS_SHORT = 5.0

# Test constants for HTTP status codes
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_RATE_LIMITED = 429
HTTP_INTERNAL_ERROR = 500

# Test constants for error codes
ERROR_CODE_BASE = 1001
ERROR_CODE_CRITICAL = 9999
ERROR_CODE_PROVIDER = 5001
ERROR_CODE_TOOL = 2001
ERROR_CODE_SANDBOX = 3001

# Test constants for retry and exit codes
RETRY_AFTER_SECONDS = 60.0
RETRY_AFTER_SECONDS_SHORT = 30.5
EXIT_CODE_CRASH = 139
EXIT_CODE_ERROR = 1

# Test constants for breakpoints and hooks
BREAKPOINT_ID_1 = 1
BREAKPOINT_ID_2 = 2
BREAKPOINT_HIT_COUNT = 5
BREAKPOINT_HIT_COUNT_ZERO = 0
EXPORT_ORDINAL = 1
VARIABLE_OFFSET = -0x10
NO_ENTRY_POINT = 0


# DataTypeInfo dataclass tests


def test_datatype_info_creation() -> None:
    """Verify DataTypeInfo can be instantiated with all fields."""
    info = DataTypeInfo(
        address=ADDR_BASE,
        name="DWORD",
        category="/PE/Types",
        size=SIZE_DWORD,
        is_pointer=False,
        is_array=False,
        array_length=None,
        base_type=None,
    )
    assert info.address == ADDR_BASE
    assert info.name == "DWORD"
    assert info.category == "/PE/Types"
    assert info.size == SIZE_DWORD
    assert info.is_pointer is False
    assert info.is_array is False


def test_datatype_info_pointer() -> None:
    """Verify pointer data type representation."""
    info = DataTypeInfo(
        address=ADDR_POINTER,
        name="char *",
        category="/C/Pointers",
        size=SIZE_POINTER_64,
        is_pointer=True,
        is_array=False,
        array_length=None,
        base_type="char",
    )
    assert info.is_pointer is True
    assert info.base_type == "char"
    assert info.size == SIZE_POINTER_64


def test_datatype_info_array() -> None:
    """Verify array data type representation."""
    info = DataTypeInfo(
        address=ADDR_ARRAY,
        name="byte[256]",
        category="/Arrays",
        size=SIZE_ARRAY_256,
        is_pointer=False,
        is_array=True,
        array_length=SIZE_ARRAY_256,
        base_type="byte",
    )
    assert info.is_array is True
    assert info.array_length == SIZE_ARRAY_256
    assert info.base_type == "byte"


def test_datatype_info_has_required_fields() -> None:
    """Verify all required fields are present."""
    field_names = {f.name for f in fields(DataTypeInfo)}
    required = {"address", "name", "category", "size", "is_pointer", "is_array"}
    assert required.issubset(field_names)


# BridgeAnalysisSummary dataclass tests


def test_bridge_analysis_summary_creation() -> None:
    """Verify BridgeAnalysisSummary can be constructed with all fields."""
    string = StringInfo(
        address=ADDR_BASE,
        value="test string",
        encoding="ascii",
        section=".rdata",
    )
    imp = ImportInfo(
        dll="kernel32.dll",
        function="CreateFileA",
        ordinal=None,
        address=ADDR_SECONDARY,
    )
    exp = ExportInfo(
        name="DllMain",
        ordinal=1,
        address=ADDR_BASE,
    )
    section = SectionInfo(
        name=".text",
        virtual_address=ADDR_SECTION_VIRTUAL,
        virtual_size=SIZE_SECTION_VIRTUAL,
        raw_size=SIZE_SECTION_RAW,
        characteristics=SECTION_CHARACTERISTICS,
        entropy=ENTROPY_NORMAL,
    )

    summary = BridgeAnalysisSummary(
        binary_name="test.exe",
        strings=[string],
        imports=[imp],
        exports=[exp],
        sections=[section],
        functions=[],
        format_info="pe",
        architecture="x86_64",
        source_bridges=["binary", "ghidra"],
        analysis_notes=["Analysis complete"],
    )

    assert summary.binary_name == "test.exe"
    assert len(summary.strings) == 1
    assert len(summary.imports) == 1
    assert len(summary.exports) == 1
    assert len(summary.sections) == 1
    assert len(summary.functions) == 0
    assert summary.format_info == "pe"
    assert summary.architecture == "x86_64"
    assert "binary" in summary.source_bridges
    assert "ghidra" in summary.source_bridges
    assert summary.analysis_notes == ["Analysis complete"]


def test_bridge_analysis_summary_empty_lists() -> None:
    """Verify BridgeAnalysisSummary works with all empty lists."""
    summary = BridgeAnalysisSummary(
        binary_name="empty.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="unknown",
        architecture="unknown",
        source_bridges=[],
        analysis_notes=[],
    )
    assert summary.binary_name == "empty.exe"
    assert len(summary.strings) == 0
    assert len(summary.imports) == 0
    assert len(summary.exports) == 0
    assert len(summary.sections) == 0
    assert len(summary.functions) == 0
    assert len(summary.source_bridges) == 0
    assert len(summary.analysis_notes) == 0


def test_bridge_analysis_summary_has_all_fields() -> None:
    """Verify all required fields exist in BridgeAnalysisSummary."""
    field_names = {f.name for f in fields(BridgeAnalysisSummary)}
    required = {
        "binary_name",
        "strings",
        "imports",
        "exports",
        "sections",
        "functions",
        "format_info",
        "architecture",
        "source_bridges",
        "analysis_notes",
    }
    assert required.issubset(field_names)


def test_bridge_analysis_summary_str() -> None:
    """Verify BridgeAnalysisSummary has a meaningful string representation."""
    summary = BridgeAnalysisSummary(
        binary_name="repr.exe",
        strings=[],
        imports=[],
        exports=[],
        sections=[],
        functions=[],
        format_info="pe",
        architecture="x86",
        source_bridges=["binary"],
        analysis_notes=[],
    )
    text = str(summary)
    assert "repr.exe" in text


# StringInfo dataclass tests


def test_string_info_ascii() -> None:
    """Verify ASCII string representation."""
    info = StringInfo(
        address=ADDR_BASE,
        value="Invalid License Key",
        encoding="ascii",
        section=".rdata",
    )
    assert info.address == ADDR_BASE
    assert info.value == "Invalid License Key"
    assert info.encoding == "ascii"
    assert info.section == ".rdata"


def test_string_info_unicode() -> None:
    """Verify Unicode string representation."""
    info = StringInfo(
        address=ADDR_SECONDARY,
        value="Registration Required",
        encoding="utf-16le",
        section=".data",
    )
    assert info.encoding == "utf-16le"


# BinaryInfo dataclass tests


def test_binary_info_pe() -> None:
    """Verify PE binary info representation."""
    section = SectionInfo(
        name=".text",
        virtual_address=ADDR_SECTION_VIRTUAL,
        virtual_size=SIZE_SECTION_VIRTUAL,
        raw_size=SIZE_SECTION_RAW,
        characteristics=SECTION_CHARACTERISTICS,
        entropy=ENTROPY_NORMAL,
    )
    import_info = ImportInfo(
        dll="kernel32.dll",
        function="GetProcAddress",
        ordinal=None,
        address=ADDR_IMPORT,
    )
    export_info = ExportInfo(
        name="DllMain",
        ordinal=EXPORT_ORDINAL,
        address=ADDR_ENTRY_POINT,
    )

    info = BinaryInfo(
        path=Path("/path/to/binary.dll"),
        name="binary.dll",
        size=SIZE_BINARY,
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        file_type="pe",
        architecture="x86_64",
        is_64bit=True,
        entry_point=ADDR_ENTRY_POINT,
        sections=[section],
        imports=[import_info],
        exports=[export_info],
    )

    assert info.file_type == "pe"
    assert info.architecture == "x86_64"
    assert info.is_64bit is True
    assert info.entry_point == ADDR_ENTRY_POINT
    assert len(info.sections) == 1
    assert len(info.imports) == 1
    assert len(info.exports) == 1
    assert info.name == "binary.dll"
    assert info.md5 == "d41d8cd98f00b204e9800998ecf8427e"


def test_section_info_has_entropy() -> None:
    """Verify SectionInfo includes entropy field for packed detection."""
    section = SectionInfo(
        name=".upx0",
        virtual_address=ADDR_SECTION_UPX_VIRTUAL,
        virtual_size=SIZE_SECTION_UPX_VIRTUAL,
        raw_size=SIZE_SECTION_UPX_RAW,
        characteristics=SECTION_CHARACTERISTICS_UPX,
        entropy=ENTROPY_PACKED,
    )
    assert section.entropy == ENTROPY_PACKED
    assert section.entropy > ENTROPY_PACKED_THRESHOLD


# FunctionInfo dataclass tests


def test_function_info_creation() -> None:
    """Verify FunctionInfo instantiation."""
    param = ParameterInfo(
        name="lpBuffer",
        type="LPVOID",
        size=SIZE_POINTER_64,
        location="rcx",
    )
    var = VariableInfo(
        name="result",
        type="DWORD",
        offset=VARIABLE_OFFSET,
        size=SIZE_DWORD,
    )

    info = FunctionInfo(
        name="CheckLicense",
        address=ADDR_FUNCTION,
        size=SIZE_FUNCTION,
        calling_convention="fastcall",
        return_type="BOOL",
        parameters=[param],
        local_variables=[var],
    )

    assert info.address == ADDR_FUNCTION
    assert info.name == "CheckLicense"
    assert info.return_type == "BOOL"
    assert info.size == SIZE_FUNCTION
    assert info.calling_convention == "fastcall"
    assert len(info.parameters) == 1
    assert len(info.local_variables) == 1


def test_function_info_with_decompiled_code() -> None:
    """Verify FunctionInfo with optional decompiled code."""
    info = FunctionInfo(
        name="ValidateKey",
        address=ADDR_FUNCTION_ALT,
        size=SIZE_FUNCTION_SMALL,
        calling_convention="cdecl",
        return_type="int",
        parameters=[],
        local_variables=[],
        decompiled_code="int ValidateKey(void) { return 1; }",
        disassembly="push ebp\nmov ebp, esp",
    )
    assert info.decompiled_code is not None
    assert info.disassembly is not None


# BreakpointInfo dataclass tests


def test_breakpoint_info_software() -> None:
    """Verify software breakpoint representation."""
    bp = BreakpointInfo(
        id=BREAKPOINT_ID_1,
        address=ADDR_BREAKPOINT,
        bp_type="software",
        enabled=True,
        hit_count=BREAKPOINT_HIT_COUNT_ZERO,
        condition=None,
    )
    assert bp.id == BREAKPOINT_ID_1
    assert bp.bp_type == "software"
    assert bp.enabled is True


def test_breakpoint_info_hardware() -> None:
    """Verify hardware breakpoint representation."""
    bp = BreakpointInfo(
        id=BREAKPOINT_ID_2,
        address=ADDR_BREAKPOINT_HW,
        bp_type="hardware",
        enabled=True,
        hit_count=BREAKPOINT_HIT_COUNT,
        condition="eax == 0",
    )
    assert bp.bp_type == "hardware"
    assert bp.condition == "eax == 0"


# RegisterState dataclass tests


def test_register_state_x64() -> None:
    """Verify x64 register state representation including segment registers."""
    state = RegisterState(
        rax=ADDR_REGISTER_RAX,
        rbx=REGISTER_ZERO,
        rcx=REGISTER_RCX,
        rdx=REGISTER_RDX,
        rsi=REGISTER_RSI,
        rdi=REGISTER_RDI,
        rbp=ADDR_BASE_POINTER,
        rsp=ADDR_STACK_POINTER,
        rip=ADDR_REGISTER_RIP,
        r8=REGISTER_ZERO,
        r9=REGISTER_ZERO,
        r10=REGISTER_ZERO,
        r11=REGISTER_ZERO,
        r12=REGISTER_ZERO,
        r13=REGISTER_ZERO,
        r14=REGISTER_ZERO,
        r15=REGISTER_ZERO,
        rflags=REGISTER_RFLAGS,
        cs=REGISTER_CS,
        ds=REGISTER_DS,
        es=REGISTER_ES,
        fs=REGISTER_FS,
        gs=REGISTER_GS,
        ss=REGISTER_SS,
    )
    assert state.rax == ADDR_REGISTER_RAX
    assert state.rip == ADDR_REGISTER_RIP
    assert state.rflags == REGISTER_RFLAGS
    assert state.cs == REGISTER_CS
    assert state.fs == REGISTER_FS


def test_register_state_has_segment_registers() -> None:
    """Verify all segment registers are present."""
    field_names = {f.name for f in fields(RegisterState)}
    segment_regs = {"cs", "ds", "es", "fs", "gs", "ss"}
    assert segment_regs.issubset(field_names)


# ProcessInfo dataclass tests


def test_process_info_creation() -> None:
    """Verify ProcessInfo instantiation."""
    thread = ThreadInfo(
        tid=TEST_TID_INITIAL,
        start_address=ADDR_THREAD_START,
        state="running",
        priority=TEST_THREAD_PRIORITY,
    )
    module = ModuleInfo(
        name="ntdll.dll",
        path=Path("C:/Windows/System32/ntdll.dll"),
        base_address=ADDR_MODULE_BASE,
        size=SIZE_MODULE,
        entry_point=NO_ENTRY_POINT,
    )

    info = ProcessInfo(
        pid=TEST_PID,
        name="target.exe",
        path=Path("C:/Program Files/App/target.exe"),
        command_line="target.exe --option",
        parent_pid=TEST_PARENT_PID,
        threads=[thread],
        modules=[module],
    )

    assert info.pid == TEST_PID
    assert info.name == "target.exe"
    assert info.parent_pid == TEST_PARENT_PID
    assert len(info.threads) == 1
    assert len(info.modules) == 1


def test_thread_info_uses_tid() -> None:
    """Verify ThreadInfo uses 'tid' field not 'id'."""
    thread = ThreadInfo(
        tid=TEST_TID,
        start_address=ADDR_THREAD_START,
        state="suspended",
        priority=TEST_THREAD_PRIORITY_HIGH,
    )
    assert thread.tid == TEST_TID


# HookInfo dataclass tests


def test_hook_info_creation() -> None:
    """Verify HookInfo instantiation with correct fields."""
    hook = HookInfo(
        id="hook_001",
        target="CheckLicense",
        address=ADDR_HOOK,
        script_id="script_001",
        active=True,
    )
    assert hook.id == "hook_001"
    assert hook.target == "CheckLicense"
    assert hook.address == ADDR_HOOK
    assert hook.script_id == "script_001"
    assert hook.active is True


def test_hook_info_without_address() -> None:
    """Verify HookInfo with None address (unresolved)."""
    hook = HookInfo(
        id="hook_002",
        target="kernel32.dll!CreateFileW",
        address=None,
        script_id="script_002",
        active=False,
    )
    assert hook.address is None
    assert hook.active is False


# PatchInfo dataclass tests


def test_patch_info_creation() -> None:
    """Verify PatchInfo instantiation with correct field names."""
    patch = PatchInfo(
        address=ADDR_PATCH,
        original_bytes=b"\x74\x10",
        new_bytes=b"\xeb\x10",
        description="JZ -> JMP",
        applied=True,
    )
    assert patch.address == ADDR_PATCH
    assert patch.original_bytes == b"\x74\x10"
    assert patch.new_bytes == b"\xeb\x10"
    assert patch.applied is True


def test_patch_info_nop_sled() -> None:
    """Verify PatchInfo for NOP sled patches."""
    patch = PatchInfo(
        address=ADDR_PATCH_NOP,
        original_bytes=b"\xe8\x00\x10\x00\x00",
        new_bytes=b"\x90\x90\x90\x90\x90",
        description="NOP out license check call",
        applied=False,
    )
    assert len(patch.original_bytes) == SIZE_PATCH_BYTES
    assert len(patch.new_bytes) == SIZE_PATCH_BYTES


# ToolDefinition dataclass tests


def test_tool_definition_creation() -> None:
    """Verify ToolDefinition instantiation with correct fields."""
    param = ToolParameter(
        name="address",
        type="integer",
        description="Memory address to read",
        required=True,
    )
    func = ToolFunction(
        name="read_memory",
        description="Read bytes from memory",
        parameters=[param],
        returns="Bytes at the specified address",
    )
    tool = ToolDefinition(
        tool_name=ToolName.GHIDRA,
        description="Ghidra reverse engineering tool",
        functions=[func],
    )
    assert tool.tool_name == ToolName.GHIDRA
    assert tool.description == "Ghidra reverse engineering tool"
    assert len(tool.functions) == 1
    assert tool.functions[0].name == "read_memory"


def test_tool_parameter_with_enum() -> None:
    """Verify ToolParameter with enum constraint."""
    param = ToolParameter(
        name="bp_type",
        type="string",
        description="Breakpoint type",
        required=True,
        enum=["software", "hardware", "memory"],
    )
    assert param.enum is not None
    assert "software" in param.enum


def test_tool_parameter_with_default() -> None:
    """Verify ToolParameter with default value."""
    param = ToolParameter(
        name="size",
        type="integer",
        description="Number of bytes to read",
        required=False,
        default=SIZE_DEFAULT_READ,
    )
    assert param.required is False
    assert param.default == SIZE_DEFAULT_READ


# IntellicrackError exception tests


def test_intellicrack_error_is_base() -> None:
    """Verify IntellicrackError is the base exception."""
    error = IntellicrackError("Test error")
    assert isinstance(error, Exception)


def test_provider_error_inheritance() -> None:
    """Verify ProviderError inherits from IntellicrackError."""
    error = ProviderError("Provider failed")
    assert isinstance(error, IntellicrackError)


def test_authentication_error_inheritance() -> None:
    """Verify AuthenticationError inherits from ProviderError."""
    error = AuthenticationError("Auth failed")
    assert isinstance(error, ProviderError)
    assert isinstance(error, IntellicrackError)


def test_rate_limit_error_inheritance() -> None:
    """Verify RateLimitError inherits from ProviderError."""
    error = RateLimitError("Rate limited")
    assert isinstance(error, ProviderError)


def test_tool_error_inheritance() -> None:
    """Verify ToolError inherits from IntellicrackError."""
    error = ToolError("Tool failed")
    assert isinstance(error, IntellicrackError)


def test_attach_error_inheritance() -> None:
    """Verify AttachError inherits from IntellicrackError."""
    error = AttachError("Attach failed")
    assert isinstance(error, IntellicrackError)


def test_sandbox_error_inheritance() -> None:
    """Verify SandboxError inherits from IntellicrackError."""
    error = SandboxError("Sandbox failed")
    assert isinstance(error, IntellicrackError)


# ToolName and ProviderName enum tests


def test_tool_name_has_ghidra() -> None:
    """Verify Ghidra tool is defined."""
    assert ToolName.GHIDRA.value == "ghidra"


def test_tool_name_has_cutter() -> None:
    """Verify Cutter tool is defined."""
    assert ToolName.CUTTER.value == "cutter"


def test_tool_name_has_frida() -> None:
    """Verify Frida tool is defined."""
    assert ToolName.FRIDA.value == "frida"


def test_tool_name_has_x64dbg() -> None:
    """Verify x64dbg tool is defined."""
    assert ToolName.X64DBG.value == "x64dbg"


def test_provider_name_has_anthropic() -> None:
    """Verify Anthropic provider is defined."""
    assert ProviderName.ANTHROPIC.value == "anthropic"


def test_provider_name_has_openai() -> None:
    """Verify OpenAI provider is defined."""
    assert ProviderName.OPENAI.value == "openai"


# Session dataclass tests


def test_session_has_id() -> None:
    """Verify Session has id field."""
    field_names = {f.name for f in fields(Session)}
    assert "id" in field_names


def test_session_has_messages() -> None:
    """Verify Session has messages field."""
    field_names = {f.name for f in fields(Session)}
    assert "messages" in field_names


def test_session_has_tool_states() -> None:
    """Verify Session has tool_states field."""
    field_names = {f.name for f in fields(Session)}
    assert "tool_states" in field_names


# ToolCall and ToolResult tests


def test_tool_call_creation() -> None:
    """Verify ToolCall instantiation with correct fields."""
    call = ToolCall(
        id="call_123",
        tool_name="ghidra",
        function_name="set_breakpoint",
        arguments={"address": ADDR_BASE, "type": "software"},
    )
    assert call.id == "call_123"
    assert call.tool_name == "ghidra"
    assert call.function_name == "set_breakpoint"
    assert call.arguments["address"] == ADDR_BASE


def test_tool_result_success() -> None:
    """Verify successful ToolResult."""
    result = ToolResult(
        call_id="call_123",
        success=True,
        result={"breakpoint_id": 1},
        error=None,
        duration_ms=DURATION_MS,
    )
    assert result.call_id == "call_123"
    assert result.success is True
    assert result.error is None
    assert result.duration_ms == DURATION_MS


def test_tool_result_error() -> None:
    """Verify error ToolResult."""
    result = ToolResult(
        call_id="call_456",
        success=False,
        result=None,
        error="Failed to set breakpoint: access denied",
        duration_ms=DURATION_MS_SHORT,
    )
    assert result.success is False
    assert result.error == "Failed to set breakpoint: access denied"


# Message dataclass tests


def test_message_user() -> None:
    """Verify user message creation."""
    msg = Message(
        role="user",
        content="Analyze this binary",
    )
    assert msg.role == "user"
    assert msg.content == "Analyze this binary"


def test_message_assistant() -> None:
    """Verify assistant message creation."""
    msg = Message(
        role="assistant",
        content="I'll analyze the binary now.",
    )
    assert msg.role == "assistant"


def test_message_with_tool_calls() -> None:
    """Verify message with tool calls."""
    call = ToolCall(
        id="call_001",
        tool_name="ghidra",
        function_name="read_memory",
        arguments={"address": ADDR_BASE, "size": SIZE_DEFAULT_READ},
    )
    msg = Message(
        role="assistant",
        content="Reading memory...",
        tool_calls=[call],
    )
    assert msg.tool_calls is not None
    assert len(msg.tool_calls) == 1


def test_message_has_timestamp() -> None:
    """Verify Message has timestamp field with default factory."""
    field_names = {f.name for f in fields(Message)}
    assert "timestamp" in field_names


# IntellicrackError structured context tests


def test_base_error_message_only() -> None:
    """Verify error with message only."""
    error = IntellicrackError("Something went wrong")
    assert str(error) == "Something went wrong"
    assert error.error_code is None
    assert error.details == {}


def test_base_error_with_error_code() -> None:
    """Verify error with error code."""
    error = IntellicrackError("Failed operation", error_code=ERROR_CODE_BASE)
    assert error.error_code == ERROR_CODE_BASE


def test_base_error_with_details() -> None:
    """Verify error with details dictionary."""
    details = {"component": "analyzer", "phase": "initialization"}
    error = IntellicrackError("Initialization failed", details=details)
    assert error.details == details
    assert error.details["component"] == "analyzer"


def test_base_error_full_context() -> None:
    """Verify error with all context fields."""
    error = IntellicrackError(
        "Critical failure",
        error_code=ERROR_CODE_CRITICAL,
        details={"severity": "critical", "recoverable": False},
    )
    assert error.error_code == ERROR_CODE_CRITICAL
    assert error.details["severity"] == "critical"
    assert error.details["recoverable"] is False


# ProviderError structured context tests


def test_provider_error_basic() -> None:
    """Verify basic ProviderError."""
    error = ProviderError("API call failed")
    assert str(error) == "API call failed"
    assert error.provider_name is None


def test_provider_error_with_provider_name() -> None:
    """Verify ProviderError with provider name."""
    error = ProviderError("Rate limited", provider_name="anthropic")
    assert error.provider_name == "anthropic"


def test_provider_error_with_status_code() -> None:
    """Verify ProviderError with HTTP status code."""
    error = ProviderError("Unauthorized", status_code=HTTP_UNAUTHORIZED)
    assert error.status_code == HTTP_UNAUTHORIZED


def test_provider_error_with_response_body() -> None:
    """Verify ProviderError with response body."""
    body = '{"error": "invalid_api_key"}'
    error = ProviderError("Authentication failed", response_body=body)
    assert error.response_body == body


def test_provider_error_full_context() -> None:
    """Verify ProviderError with all context."""
    error = ProviderError(
        "Request failed",
        provider_name="openai",
        status_code=HTTP_INTERNAL_ERROR,
        response_body='{"error": "internal"}',
        error_code=ERROR_CODE_PROVIDER,
        details={"endpoint": "/v1/chat/completions"},
    )
    assert error.provider_name == "openai"
    assert error.status_code == HTTP_INTERNAL_ERROR
    assert error.response_body == '{"error": "internal"}'
    assert error.error_code == ERROR_CODE_PROVIDER
    assert error.details["endpoint"] == "/v1/chat/completions"


# AuthenticationError structured context tests


def test_auth_error_inherits_provider_error() -> None:
    """Verify AuthenticationError inherits from ProviderError."""
    error = AuthenticationError("Invalid credentials")
    assert isinstance(error, ProviderError)
    assert isinstance(error, IntellicrackError)


def test_auth_error_with_provider_context() -> None:
    """Verify AuthenticationError with provider context."""
    error = AuthenticationError(
        "API key rejected",
        provider_name="google",
        status_code=HTTP_FORBIDDEN,
    )
    assert error.provider_name == "google"
    assert error.status_code == HTTP_FORBIDDEN


# RateLimitError structured context tests


def test_rate_limit_basic() -> None:
    """Verify basic RateLimitError."""
    error = RateLimitError("Too many requests")
    assert str(error) == "Too many requests"
    assert error.retry_after is None


def test_rate_limit_with_retry_after() -> None:
    """Verify RateLimitError with retry_after."""
    error = RateLimitError("Rate limited", retry_after=RETRY_AFTER_SECONDS)
    assert error.retry_after == RETRY_AFTER_SECONDS


def test_rate_limit_full_context() -> None:
    """Verify RateLimitError with full context."""
    error = RateLimitError(
        "Rate limit exceeded",
        retry_after=RETRY_AFTER_SECONDS_SHORT,
        provider_name="anthropic",
        status_code=HTTP_RATE_LIMITED,
    )
    assert error.retry_after == RETRY_AFTER_SECONDS_SHORT
    assert error.provider_name == "anthropic"
    assert error.status_code == HTTP_RATE_LIMITED


# ToolError structured context tests


def test_tool_error_basic_structured() -> None:
    """Verify basic ToolError."""
    error = ToolError("Tool failed")
    assert str(error) == "Tool failed"
    assert error.tool_name is None


def test_tool_error_with_tool_name_structured() -> None:
    """Verify ToolError with tool name."""
    error = ToolError("Ghidra script failed", tool_name="ghidra")
    assert error.tool_name == "ghidra"


def test_tool_error_with_exit_code() -> None:
    """Verify ToolError with process exit code."""
    error = ToolError("Process crashed", exit_code=EXIT_CODE_CRASH)
    assert error.exit_code == EXIT_CODE_CRASH


def test_tool_error_with_stderr() -> None:
    """Verify ToolError with stderr output."""
    stderr = "Error: Invalid address 0xDEADBEEF"
    error = ToolError("Memory read failed", stderr=stderr)
    assert error.stderr == stderr


TEST_PID_DETAILS = 12345


def test_tool_error_full_context_structured() -> None:
    """Verify ToolError with all context."""
    error = ToolError(
        "Frida injection failed",
        tool_name="frida",
        exit_code=EXIT_CODE_ERROR,
        stderr="Failed to attach to process",
        error_code=ERROR_CODE_TOOL,
        details={"pid": TEST_PID_DETAILS, "target": "notepad.exe"},
    )
    assert error.tool_name == "frida"
    assert error.exit_code == EXIT_CODE_ERROR
    assert error.stderr == "Failed to attach to process"
    assert error.error_code == ERROR_CODE_TOOL
    assert error.details["pid"] == TEST_PID_DETAILS


# AttachError structured context tests


def test_attach_error_basic_structured() -> None:
    """Verify basic AttachError."""
    error = AttachError("Failed to attach")
    assert isinstance(error, ToolError)


def test_attach_error_with_pid_structured() -> None:
    """Verify AttachError with process ID."""
    error = AttachError("Access denied", pid=TEST_PID)
    assert error.pid == TEST_PID


def test_attach_error_with_process_name() -> None:
    """Verify AttachError with process name."""
    error = AttachError("Process not found", process_name="target.exe")
    assert error.process_name == "target.exe"


def test_attach_error_full_context_structured() -> None:
    """Verify AttachError with all context."""
    error = AttachError(
        "Cannot attach to protected process",
        pid=TEST_PID_PROTECTED,
        process_name="protectedapp.exe",
        tool_name="x64dbg",
    )
    assert error.pid == TEST_PID_PROTECTED
    assert error.process_name == "protectedapp.exe"
    assert error.tool_name == "x64dbg"


# SandboxError structured context tests


def test_sandbox_error_basic_structured() -> None:
    """Verify basic SandboxError."""
    error = SandboxError("VM failed to start")
    assert isinstance(error, IntellicrackError)


def test_sandbox_error_with_type() -> None:
    """Verify SandboxError with sandbox type."""
    error = SandboxError("Image not found", sandbox_type="qemu")
    assert error.sandbox_type == "qemu"


def test_sandbox_error_with_vm_state() -> None:
    """Verify SandboxError with VM state."""
    error = SandboxError("Snapshot failed", vm_state="running")
    assert error.vm_state == "running"


def test_sandbox_error_full_context() -> None:
    """Verify SandboxError with all context."""
    error = SandboxError(
        "VM crashed during analysis",
        sandbox_type="qemu",
        vm_state="paused",
        error_code=ERROR_CODE_SANDBOX,
        details={"exit_reason": "triple_fault"},
    )
    assert error.sandbox_type == "qemu"
    assert error.vm_state == "paused"
    assert error.error_code == ERROR_CODE_SANDBOX
    assert error.details["exit_reason"] == "triple_fault"


# Exception inheritance chain tests


def test_all_errors_inherit_from_base() -> None:
    """Verify all custom errors inherit from IntellicrackError."""
    errors = [
        ProviderError("test"),
        AuthenticationError("test"),
        RateLimitError("test"),
        ToolError("test"),
        AttachError("test"),
        SandboxError("test"),
    ]
    for error in errors:
        assert isinstance(error, IntellicrackError)
        assert isinstance(error, Exception)


def test_provider_errors_have_provider_attributes() -> None:
    """Verify provider-related errors have provider_name attribute."""
    errors = [
        ProviderError("test"),
        AuthenticationError("test"),
        RateLimitError("test"),
    ]
    for error in errors:
        assert hasattr(error, "provider_name")


def test_tool_errors_have_tool_attributes() -> None:
    """Verify tool-related errors have tool_name attribute."""
    errors = [
        ToolError("test"),
        AttachError("test"),
    ]
    for error in errors:
        assert hasattr(error, "tool_name")
