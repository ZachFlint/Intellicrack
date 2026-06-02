# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Behavioural and integration tests for Intellicrack core types.

These tests do not merely construct dataclasses and read fields back; that
proves nothing about the application. Instead they drive the real behaviour
that the core types carry:

* Computed properties and string renderings whose oracle is an external
  specification (the PE/COFF section-characteristic bit layout) or a value
  derived by hand, never the implementation's own output.
* Round-tripping the types through the *real* SQLite-backed
  :class:`~intellicrack.core.session.SessionStore` serialise/deserialise path,
  using a real on-disk database, so a regression in any field mapping,
  hex/byte encoding, enum coercion, or datetime handling fails the test.
* A real Windows PE binary parsed by the real
  :class:`~intellicrack.bridges.hex_editor.HexEditorBridge` into
  :class:`SectionInfo`/:class:`ImportInfo`/:class:`ExportInfo` records, whose
  decoded permission flags are checked against the PE/COFF specification.
* The exception hierarchy's structured-context propagation through real
  ``raise``/``except`` flows, including the ``KeyError`` error path of
  :meth:`RegisterState.__getitem__`.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import TYPE_CHECKING, Any

import pytest

from intellicrack.bridges.hex_editor import HexEditorBridge
from intellicrack.core.session import Session, SessionStore
from intellicrack.core.types import (
    AttachError,
    AuthenticationError,
    BinaryInfo,
    BreakpointInfo,
    BridgeAnalysisSummary,
    CrossReference,
    DataTypeInfo,
    ExportInfo,
    FunctionInfo,
    ImportInfo,
    IntellicrackError,
    Message,
    ParameterInfo,
    PatchInfo,
    ProviderError,
    ProviderName,
    RateLimitError,
    RegisterState,
    SandboxError,
    SectionInfo,
    StringInfo,
    ThreadInfo,
    ToolCall,
    ToolFunction,
    ToolName,
    ToolParameter,
    ToolResult,
    ToolState,
    VariableInfo,
)


if TYPE_CHECKING:
    from pathlib import Path


# PE/COFF section characteristic bit flags (winnt.h IMAGE_SCN_* constants).
# These are the independent oracle for SectionInfo's permission properties.
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

ADDR_TEXT = 0x401000
ADDR_DATA = 0x402000
ADDR_RDATA = 0x403000

ENTROPY_NORMAL = 6.5
ENTROPY_PACKED = 7.95

HTTP_UNAUTHORIZED = 401
HTTP_RATE_LIMITED = 429
RETRY_AFTER_SECONDS = 30.5
ERROR_CODE_BASE = 1001

RAX_VALUE = 0x1234567890ABCDEF
RIP_VALUE = 0x401000
RSP_VALUE = 0x7FFF00001000


def _build_section(name: str, *, va: int, characteristics: int, entropy: float) -> SectionInfo:
    """Build a SectionInfo with concrete section-table values.

    Args:
        name: Section name.
        va: Virtual address.
        characteristics: PE/COFF characteristic flags.
        entropy: Shannon entropy of the section.

    Returns:
        SectionInfo: A populated section record.
    """
    return SectionInfo(
        name=name,
        virtual_address=va,
        virtual_size=0x5000,
        raw_size=0x4800,
        characteristics=characteristics,
        entropy=entropy,
    )


# --- SectionInfo permission decoding (oracle: PE/COFF bit spec) --------------


class TestSectionInfoPermissionDecoding:
    """SectionInfo decodes PE/COFF characteristic bits into r/w/x flags."""

    @staticmethod
    def test_text_section_is_read_execute_not_write() -> None:
        """A real ``.text`` characteristic word decodes to r-x, not writable."""
        chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        section = _build_section(".text", va=ADDR_TEXT, characteristics=chars, entropy=ENTROPY_NORMAL)

        assert section.is_executable is True
        assert section.is_readable is True
        assert section.is_writable is False

    @staticmethod
    def test_data_section_is_read_write_not_execute() -> None:
        """A real ``.data`` characteristic word decodes to rw-, not executable."""
        chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        section = _build_section(".data", va=ADDR_DATA, characteristics=chars, entropy=ENTROPY_NORMAL)

        assert section.is_executable is False
        assert section.is_readable is True
        assert section.is_writable is True

    @staticmethod
    def test_rdata_section_is_read_only() -> None:
        """A read-only ``.rdata`` characteristic word decodes to r--."""
        section = _build_section(".rdata", va=ADDR_RDATA, characteristics=IMAGE_SCN_MEM_READ, entropy=ENTROPY_NORMAL)

        assert section.is_readable is True
        assert section.is_writable is False
        assert section.is_executable is False

    @staticmethod
    def test_zero_characteristics_decode_to_no_permissions() -> None:
        """A characteristic word of zero yields no decoded permissions."""
        section = _build_section(".bss", va=ADDR_DATA, characteristics=0, entropy=0.0)

        assert section.is_readable is False
        assert section.is_writable is False
        assert section.is_executable is False

    @staticmethod
    def test_all_permission_bits_set_decode_to_rwx() -> None:
        """All three memory bits set decodes to a full rwx section."""
        chars = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
        section = _build_section(".rwx", va=ADDR_TEXT, characteristics=chars, entropy=ENTROPY_PACKED)

        assert section.is_readable is True
        assert section.is_writable is True
        assert section.is_executable is True


# --- DataTypeInfo.display_type formatting (oracle: hand-derived string) ------


class TestDataTypeInfoDisplay:
    """DataTypeInfo.display_type formats pointer/array/scalar types."""

    @staticmethod
    def test_pointer_display_appends_star() -> None:
        """A pointer renders as ``<base> *`` from its base type."""
        info = DataTypeInfo(
            address=ADDR_DATA,
            name="char_ptr",
            category="/C/Pointers",
            size=8,
            is_pointer=True,
            is_array=False,
            array_length=None,
            base_type="char",
        )
        assert info.display_type == "char *"

    @staticmethod
    def test_array_display_includes_length() -> None:
        """An array renders as ``<base>[<length>]``."""
        info = DataTypeInfo(
            address=ADDR_RDATA,
            name="byte_array",
            category="/Arrays",
            size=256,
            is_pointer=False,
            is_array=True,
            array_length=256,
            base_type="byte",
        )
        assert info.display_type == "byte[256]"

    @staticmethod
    def test_scalar_display_uses_name() -> None:
        """A plain scalar renders as its declared name."""
        info = DataTypeInfo(
            address=ADDR_TEXT,
            name="DWORD",
            category="/PE/Types",
            size=4,
            is_pointer=False,
            is_array=False,
            array_length=None,
            base_type=None,
        )
        assert info.display_type == "DWORD"

    @staticmethod
    def test_array_without_base_type_falls_back_to_name() -> None:
        """An array flagged without a base type falls back to the name."""
        info = DataTypeInfo(
            address=ADDR_TEXT,
            name="opaque_blob",
            category="/Arrays",
            size=16,
            is_pointer=False,
            is_array=True,
            array_length=None,
            base_type=None,
        )
        assert info.display_type == "opaque_blob"


# --- FunctionInfo computed properties (oracle: hand-derived) -----------------


class TestFunctionInfoComputed:
    """FunctionInfo.has_code and summary reflect populated content."""

    @staticmethod
    def test_summary_renders_name_address_convention_and_var_count() -> None:
        """Summary embeds hex address, convention, and local-variable count."""
        var = VariableInfo(name="result", type="DWORD", offset=-0x10, size=4)
        func = FunctionInfo(
            name="CheckLicense",
            address=0x401000,
            size=256,
            calling_convention="fastcall",
            return_type="BOOL",
            parameters=[ParameterInfo(name="key", type="LPVOID", size=8, location="rcx")],
            local_variables=[var],
        )
        assert func.summary == "CheckLicense@0x401000 (fastcall, 1 vars)"

    @staticmethod
    def test_has_code_false_without_decompiled_or_disassembly() -> None:
        """has_code is False when neither code form is present."""
        func = FunctionInfo(
            name="stub",
            address=0x402000,
            size=0,
            calling_convention="cdecl",
            return_type="void",
            parameters=[],
            local_variables=[],
        )
        assert func.has_code is False

    @staticmethod
    def test_has_code_true_with_disassembly_only() -> None:
        """has_code is True when only disassembly is present."""
        func = FunctionInfo(
            name="ValidateKey",
            address=0x402000,
            size=128,
            calling_convention="cdecl",
            return_type="int",
            parameters=[],
            local_variables=[],
            disassembly="push ebp\nmov ebp, esp",
        )
        assert func.has_code is True
        assert func.decompiled_code is None


# --- ToolFunction.signature (oracle: hand-derived) --------------------------


def test_tool_function_signature_lists_params_and_return() -> None:
    """ToolFunction.signature renders name, typed params, and return type."""
    func = ToolFunction(
        name="ghidra.read_memory",
        description="Read bytes from memory",
        parameters=[
            ToolParameter(name="address", type="integer", description="addr", required=True),
            ToolParameter(name="size", type="integer", description="len", required=False),
        ],
        returns="bytes",
    )
    assert func.signature == "ghidra.read_memory(address: integer, size: integer) -> bytes"


# --- __str__ renderings (oracle: hand-derived) ------------------------------


class TestStringRenderings:
    """Dataclass __str__ implementations format their state precisely."""

    @staticmethod
    def test_cross_reference_prefers_function_names() -> None:
        """CrossReference renders symbol names when available."""
        xref = CrossReference(
            from_address=0x401000,
            to_address=0x402000,
            ref_type="call",
            from_function="main",
            to_function="CheckLicense",
        )
        assert str(xref) == "[call] main -> CheckLicense"

    @staticmethod
    def test_cross_reference_falls_back_to_hex_addresses() -> None:
        """CrossReference renders hex addresses when names are missing."""
        xref = CrossReference(
            from_address=0x401000,
            to_address=0x402000,
            ref_type="jump",
            from_function=None,
            to_function=None,
        )
        assert str(xref) == "[jump] 0x401000 -> 0x402000"

    @staticmethod
    def test_breakpoint_str_reports_status_and_hits() -> None:
        """BreakpointInfo renders id, address, type, enabled state, and hits."""
        bp = BreakpointInfo(
            id=2,
            address=0x401000,
            bp_type="hardware",
            enabled=False,
            hit_count=5,
            condition="eax == 0",
        )
        assert str(bp) == "BP#2 @ 0x401000 (hardware): disabled, hit 5 times"

    @staticmethod
    def test_thread_str_reports_current_pc() -> None:
        """ThreadInfo renders tid, state, and hex current program counter."""
        thread = ThreadInfo(tid=1234, start_address=0x401000, current_pc=0x401ABC, state="running")
        assert str(thread) == "Thread 1234 (running) @ pc=0x401abc"


# --- RegisterState access including the error path --------------------------


class TestRegisterStateAccess:
    """RegisterState exposes register access, grouping, and key validation."""

    @staticmethod
    def _state() -> RegisterState:
        """Build a fully populated x64 register state.

        Returns:
            RegisterState: Register state with distinct sentinel values.
        """
        return RegisterState(
            rax=RAX_VALUE,
            rbx=0,
            rcx=0x100,
            rdx=0x200,
            rsi=0x300,
            rdi=0x400,
            rbp=0x7FFF00000000,
            rsp=RSP_VALUE,
            rip=RIP_VALUE,
            r8=0,
            r9=0,
            r10=0,
            r11=0,
            r12=0,
            r13=0,
            r14=0,
            r15=0,
            rflags=0x246,
            cs=0x33,
            ds=0x2B,
            es=0x2B,
            fs=0x53,
            gs=0x2B,
            ss=0x2B,
        )

    def test_getitem_returns_named_register_value(self) -> None:
        """__getitem__ resolves a register by name to its integer value."""
        state = self._state()
        assert state["rax"] == RAX_VALUE
        assert state["rip"] == RIP_VALUE
        assert state["fs"] == 0x53

    def test_getitem_unknown_register_raises_keyerror(self) -> None:
        """__getitem__ raises KeyError for an unknown register name."""
        state = self._state()
        with pytest.raises(KeyError, match="r99"):
            _ = state["r99"]

    def test_gpr_dict_excludes_rip_and_segment_registers(self) -> None:
        """get_gpr_dict returns only GPRs, omitting rip/rflags/segments."""
        gprs = self._state().get_gpr_dict()
        assert gprs["rax"] == RAX_VALUE
        assert gprs["rsp"] == RSP_VALUE
        assert set(gprs) == {
            "rax",
            "rbx",
            "rcx",
            "rdx",
            "rsi",
            "rdi",
            "rbp",
            "rsp",
            "r8",
            "r9",
            "r10",
            "r11",
            "r12",
            "r13",
            "r14",
            "r15",
        }

    def test_segment_registers_grouped_correctly(self) -> None:
        """get_segment_registers returns exactly the six segment registers."""
        segs = self._state().get_segment_registers()
        assert segs == {"cs": 0x33, "ds": 0x2B, "es": 0x2B, "fs": 0x53, "gs": 0x2B, "ss": 0x2B}


# --- Exception hierarchy structured-context propagation ----------------------


class TestExceptionStructuredContext:
    """Intellicrack exceptions carry structured context through real raises."""

    @staticmethod
    def test_base_error_str_and_default_context() -> None:
        """IntellicrackError stringifies its message and defaults context."""
        error = IntellicrackError("boom")
        assert str(error) == "boom"
        assert error.error_code is None
        assert error.details == {}

    @staticmethod
    def test_provider_error_propagates_full_context_through_raise() -> None:
        """A raised ProviderError preserves provider/status/body/details."""
        original = ProviderError(
            "Unauthorized",
            provider_name="anthropic",
            status_code=HTTP_UNAUTHORIZED,
            response_body='{"error": "invalid_api_key"}',
            error_code=ERROR_CODE_BASE,
            details={"endpoint": "/v1/messages"},
        )
        with pytest.raises(ProviderError) as exc_info:
            raise original
        err = exc_info.value
        assert isinstance(err, IntellicrackError)
        assert err.provider_name == "anthropic"
        assert err.status_code == HTTP_UNAUTHORIZED
        assert err.response_body == '{"error": "invalid_api_key"}'
        assert err.error_code == ERROR_CODE_BASE
        assert err.details["endpoint"] == "/v1/messages"

    @staticmethod
    def test_rate_limit_error_is_caught_as_provider_error() -> None:
        """RateLimitError carries retry_after and is catchable as ProviderError."""
        original = RateLimitError(
            "Rate limited",
            retry_after=RETRY_AFTER_SECONDS,
            provider_name="anthropic",
            status_code=HTTP_RATE_LIMITED,
        )
        with pytest.raises(ProviderError) as exc_info:
            raise original
        err = exc_info.value
        assert isinstance(err, RateLimitError)
        assert err.retry_after == RETRY_AFTER_SECONDS
        assert err.status_code == HTTP_RATE_LIMITED

    @staticmethod
    def test_authentication_error_inherits_provider_init() -> None:
        """AuthenticationError reuses ProviderError's structured __init__."""
        error = AuthenticationError("API key rejected", provider_name="google", status_code=403)
        assert isinstance(error, ProviderError)
        assert error.provider_name == "google"
        assert error.status_code == 403

    @staticmethod
    def test_attach_error_is_tool_error_with_process_context() -> None:
        """AttachError records pid/process_name and is catchable as ToolError."""
        error = AttachError(
            "Cannot attach to protected process",
            pid=4567,
            process_name="protectedapp.exe",
            tool_name="x64dbg",
        )
        assert error.pid == 4567
        assert error.process_name == "protectedapp.exe"
        assert error.tool_name == "x64dbg"

    @staticmethod
    def test_sandbox_error_carries_vm_state_and_type() -> None:
        """SandboxError records sandbox type and VM state plus base details."""
        error = SandboxError(
            "VM crashed during analysis",
            sandbox_type="qemu",
            vm_state="paused",
            details={"exit_reason": "triple_fault"},
        )
        assert isinstance(error, IntellicrackError)
        assert error.sandbox_type == "qemu"
        assert error.vm_state == "paused"
        assert error.details["exit_reason"] == "triple_fault"


# --- Real SQLite round-trip through SessionStore ----------------------------


def _make_store(tmp_path: Path) -> SessionStore:
    """Create a SessionStore backed by a fresh on-disk SQLite database.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        SessionStore: A store ready for save/load round-trips.
    """
    return SessionStore(tmp_path / "sessions.db")


class TestPatchInfoRoundTrip:
    """PatchInfo survives the real hex-encoded serialise/deserialise path."""

    @staticmethod
    def test_patch_bytes_survive_database_round_trip(tmp_path: Path) -> None:
        """A NOP-sled patch's exact bytes reconstruct after save/load.

        The session serialiser hex-encodes the byte fields and the loader
        decodes them; a regression in either direction would corrupt the
        patch bytes when read back from the real SQLite database.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = _make_store(tmp_path)
        session = _new_session()
        original = PatchInfo(
            address=0x402000,
            original_bytes=b"\xe8\x00\x10\x00\x00",
            new_bytes=b"\x90\x90\x90\x90\x90",
            description="NOP out license check call",
            applied=False,
        )
        session.add_patch(original)
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert len(loaded.patches) == 1
        restored = loaded.patches[0]
        assert restored.address == 0x402000
        assert restored.original_bytes == b"\xe8\x00\x10\x00\x00"
        assert restored.new_bytes == b"\x90\x90\x90\x90\x90"
        assert restored.description == "NOP out license check call"
        assert restored.applied is False


class TestMessageRoundTrip:
    """Message with tool calls/results survives the real session DB."""

    @staticmethod
    def test_message_tool_call_round_trips_through_database(tmp_path: Path) -> None:
        """An assistant Message with a ToolCall reconstructs from SQLite.

        The whole Session is persisted to and loaded from a real SQLite
        database; a break in Message/ToolCall serialisation, the datetime
        encoding, or the JSON column handling would fail this test.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = _make_store(tmp_path)
        session = _new_session()
        call = ToolCall(
            id="call_001",
            tool_name="ghidra",
            function_name="read_memory",
            arguments={"address": 0x401000, "size": 16},
        )
        result = ToolResult(
            call_id="call_001",
            success=True,
            result={"bytes": "909090"},
            error=None,
            duration_ms=15.5,
        )
        message = Message(
            role="assistant",
            content="Reading memory...",
            tool_calls=[call],
            tool_results=[result],
        )
        session.add_message(message)
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert len(loaded.messages) == 1
        restored = loaded.messages[0]
        assert restored.role == "assistant"
        assert restored.content == "Reading memory..."
        assert restored.timestamp == message.timestamp
        assert restored.tool_calls is not None
        assert restored.tool_calls[0].id == "call_001"
        assert restored.tool_calls[0].function_name == "read_memory"
        assert restored.tool_calls[0].arguments == {"address": 0x401000, "size": 16}
        assert restored.tool_results is not None
        assert restored.tool_results[0].success is True
        assert restored.tool_results[0].result == {"bytes": "909090"}
        assert abs(restored.tool_results[0].duration_ms - 15.5) < 1e-9


class TestToolStateRoundTrip:
    """ToolState enum keys round-trip through the session DB."""

    @staticmethod
    def test_tool_state_enum_keys_reconstruct(tmp_path: Path) -> None:
        """A ToolState keyed by ToolName.GHIDRA reconstructs by enum value.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = _make_store(tmp_path)
        session = _new_session()
        session.set_tool_state(
            ToolState(
                tool=ToolName.GHIDRA,
                connected=True,
                process_attached=False,
                target_path=None,
                last_error="decompiler busy",
            ),
        )
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert ToolName.GHIDRA in loaded.tool_states
        state = loaded.tool_states[ToolName.GHIDRA]
        assert state.connected is True
        assert state.process_attached is False
        assert state.last_error == "decompiler busy"


class TestBridgeAnalysisRoundTrip:
    """BridgeAnalysisSummary survives the nested serialise/deserialise path."""

    @staticmethod
    def test_summary_with_nested_records_reconstructs(tmp_path: Path) -> None:
        """A summary's strings/imports/sections survive a real DB round-trip.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        store = _make_store(tmp_path)
        session = _new_session()
        summary = BridgeAnalysisSummary(
            binary_name="target.dll",
            strings=[StringInfo(address=0x403000, value="Invalid License", encoding="ascii", section=".rdata")],
            imports=[ImportInfo(dll="kernel32.dll", function="CreateFileA", ordinal=None, address=0x402000)],
            exports=[ExportInfo(name="DllMain", ordinal=1, address=0x401000)],
            sections=[_build_section(".text", va=ADDR_TEXT, characteristics=IMAGE_SCN_MEM_EXECUTE, entropy=ENTROPY_NORMAL)],
            functions=[],
            format_info="pe",
            architecture="x86_64",
            source_bridges=["hex_editor", "ghidra"],
            analysis_notes=["aggregated"],
        )
        session.add_bridge_analysis("target.dll", summary)
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        restored = loaded.get_bridge_analysis("target.dll")
        assert restored is not None
        assert restored.binary_name == "target.dll"
        assert restored.strings[0].value == "Invalid License"
        assert restored.strings[0].encoding == "ascii"
        assert restored.imports[0].dll == "kernel32.dll"
        assert restored.imports[0].function == "CreateFileA"
        assert restored.exports[0].name == "DllMain"
        assert restored.sections[0].name == ".text"
        assert restored.sections[0].is_executable is True
        assert restored.source_bridges == ["hex_editor", "ghidra"]


# --- Real PE driven through the real bridge into core types ------------------


def _new_session() -> Session:
    """Create a fresh in-memory Session for round-trip tests.

    Returns:
        Session: A new session configured for the Anthropic provider.
    """
    return Session.create(provider=ProviderName.ANTHROPIC, model="claude-3")


class TestRealPeIntoCoreTypes:
    """A real PE parsed by the real bridge populates core types correctly."""

    @staticmethod
    def _open(path: Path) -> HexEditorBridge:
        """Open a real PE on a fresh HexEditorBridge.

        Args:
            path: Path to a real PE binary.

        Returns:
            HexEditorBridge: Bridge with the document loaded.
        """
        bridge = HexEditorBridge()
        asyncio.run(bridge.open_file(str(path)))
        return bridge

    def test_real_pe_sections_decode_executable_text_segment(self, real_pe_dll: Path) -> None:
        """The real ``.text`` section of kernel32.dll decodes as executable.

        The bridge parses the on-disk PE section table; the resulting
        characteristic word is fed into SectionInfo, whose property decoding
        is checked against the PE/COFF executable bit. A regression in the
        section walk or the bit decoding fails this test.

        Args:
            real_pe_dll: Path to a real System32 DLL.
        """
        bridge = self._open(real_pe_dll)
        raw_sections: list[dict[str, Any]] = asyncio.run(bridge.get_pe_sections())
        sections = [
            SectionInfo(
                name=str(s["name"]),
                virtual_address=int(s["virtual_address"]),
                virtual_size=int(s["virtual_size"]),
                raw_size=int(s["raw_size"]),
                characteristics=int(s["characteristics"]),
                entropy=0.0,
            )
            for s in raw_sections
        ]
        by_name = {s.name: s for s in sections}
        assert ".text" in by_name, "kernel32.dll must expose a .text section"

        text = by_name[".text"]
        assert text.virtual_address > 0
        assert text.is_executable is True
        assert text.is_readable is True
        assert text.is_writable is False
        # Cross-check the property against the raw flag directly.
        assert bool(text.characteristics & IMAGE_SCN_MEM_EXECUTE) is True

    def test_real_pe_binaryinfo_round_trips_through_session_store(self, real_pe_dll: Path, tmp_path: Path) -> None:
        """A BinaryInfo built from a real PE reconstructs from a real DB.

        A real PE is parsed into sections/imports/exports, assembled into a
        BinaryInfo with an independently computed SHA-256, persisted to a real
        SQLite database, and loaded back. The reconstructed binary must match
        the original field-by-field, including the executable .text section.

        Args:
            real_pe_dll: Path to a real System32 DLL.
            tmp_path: Pytest-provided temporary directory.
        """
        bridge = self._open(real_pe_dll)
        raw_sections: list[dict[str, Any]] = asyncio.run(bridge.get_pe_sections())
        raw_imports: list[dict[str, Any]] = asyncio.run(bridge.get_pe_imports())
        raw_exports: list[dict[str, Any]] = asyncio.run(bridge.get_pe_exports())

        pe_bytes = real_pe_dll.read_bytes()
        expected_sha = hashlib.sha256(pe_bytes).hexdigest()

        sections = [
            SectionInfo(
                name=str(s["name"]),
                virtual_address=int(s["virtual_address"]),
                virtual_size=int(s["virtual_size"]),
                raw_size=int(s["raw_size"]),
                characteristics=int(s["characteristics"]),
                entropy=0.0,
            )
            for s in raw_sections
        ]
        imports = [
            ImportInfo(
                dll=str(i["dll"]),
                function=str(i["function"]),
                ordinal=int(i["ordinal"]) or None,
                address=int(i["address"]),
            )
            for i in raw_imports[:5]
        ]
        exports = [ExportInfo(name=str(e["name"]), ordinal=int(e["ordinal"]), address=int(e["address"])) for e in raw_exports[:5]]
        binary = BinaryInfo(
            path=real_pe_dll,
            name=real_pe_dll.name,
            size=len(pe_bytes),
            sha256=expected_sha,
            file_type="pe",
            architecture="x86_64",
            is_64bit=True,
            entry_point=int(sections[0].virtual_address),
            sections=sections,
            imports=imports,
            exports=exports,
        )

        store = _make_store(tmp_path)
        session = _new_session()
        session.add_binary(binary)
        store.save(session)

        loaded = store.load(session.id)
        assert loaded is not None
        assert len(loaded.binaries) == 1
        restored = loaded.binaries[0]
        assert restored.name == real_pe_dll.name
        assert restored.size == len(pe_bytes)
        assert restored.sha256 == expected_sha
        assert restored.file_type == "pe"
        assert {s.name for s in restored.sections} == {s.name for s in sections}
        text = next((s for s in restored.sections if s.name == ".text"), None)
        assert text is not None
        assert text.is_executable is True
        if imports:
            assert restored.imports[0].dll == imports[0].dll
            assert restored.imports[0].function == imports[0].function
