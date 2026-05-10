# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 X64DBG-B regression tests.

Covers four production-blocker findings:

* F-0003 - ``patch_anti_debug`` PEB-base plumbing and broader patch
  coverage; ``read_peb`` tool definition advertises the ``address``
  field.
* F-0024 - ``_extract_command_line_from_peb`` rejects odd
  ``UNICODE_STRING.Length`` values and lengths exceeding
  ``MaximumLength`` instead of silently coercing them.
* F-0025 - ``WIN_NO_INHERIT_HANDLE`` constant is removed from
  ``intellicrack.bridges.x64dbg``; ``OpenProcess`` calls inline the
  literal ``False``.
* F-0027 - ``get_process_info`` raises ``ToolError`` when no process is
  attached instead of returning ``None``.
"""

from __future__ import annotations

import ctypes
import inspect
import os
import sys
from pathlib import Path
from typing import Any, Final


if sys.platform == "win32":
    from ctypes import wintypes

import pytest

from intellicrack.bridges import x64dbg as x64dbg_module
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError, ToolName


_PEB_BASE: Final[int] = 0x7FFE_0000_0000
_HEAP_BASE: Final[int] = 0x4000_0000
_TARGET_PID: Final[int] = 4242
_PROCESS_VM_READ: Final[int] = 0x0010


def _read_unicode_string(handle: int, params_addr: int, ptr_size: int) -> str | None:
    """Look up the module-private UNICODE_STRING reader via :func:`getattr`.

    Args:
        handle: Process handle with VM_READ access.
        params_addr: Address of the synthetic ``RTL_USER_PROCESS_PARAMETERS``.
        ptr_size: Pointer size in bytes (4 or 8).

    Returns:
        str | None: Result of the bridge's UNICODE_STRING reader.

    Raises:
        TypeError: If the bridge function returns a non-string,
            non-``None`` value (the public contract is ``str | None``).
    """
    fn: Any = getattr(x64dbg_module, "_read_unicode_string_from_params")
    result: Any = fn(handle, params_addr, ptr_size)
    if result is None:
        return None
    if isinstance(result, str):
        return result
    msg = f"unexpected return type from _read_unicode_string_from_params: {type(result)!r}"
    raise TypeError(msg)


def _build_params_buffer(
    cmd_line: str,
    length_override: int | None = None,
    maximum_length_override: int | None = None,
) -> tuple[ctypes.Array[ctypes.c_char], ctypes.Array[ctypes.c_char], int]:
    """Build a synthetic RTL_USER_PROCESS_PARAMETERS for UNICODE_STRING tests.

    The returned tuple keeps both buffers alive for the caller's
    lifetime; the buffer pointer in the ``UNICODE_STRING`` references
    the command-line buffer's address so a real ``ReadProcessMemory``
    on the synthetic params address resolves correctly.

    Args:
        cmd_line: Command-line string to encode in UTF-16-LE and place
            behind the ``UNICODE_STRING.Buffer`` pointer.
        length_override: Optional override for the ``Length`` field.
            When ``None``, defaults to ``len(encoded)`` so the
            UNICODE_STRING is well-formed.
        maximum_length_override: Optional override for the
            ``MaximumLength`` field. When ``None``, defaults to
            ``len(encoded) + 2`` so the structure satisfies the
            ``Length <= MaximumLength`` invariant.

    Returns:
        tuple[ctypes.Array[ctypes.c_char], ctypes.Array[ctypes.c_char], int]:
        Tuple of ``(params_buffer, cmd_buffer, params_addr)``. Hold a
        reference to both buffers for the duration of the test so the
        backing memory is not freed.
    """
    encoded = cmd_line.encode("utf-16-le")
    cmd_offset = 0x70
    ustr_size = x64dbg_module.UNICODE_STRING_SIZE_64

    cmd_buffer = ctypes.create_string_buffer(encoded, len(encoded))
    cmd_buffer_addr = ctypes.addressof(cmd_buffer)

    length = length_override if length_override is not None else len(encoded)
    maximum_length = maximum_length_override if maximum_length_override is not None else len(encoded) + 2

    ustr_bytes = bytearray(ustr_size)
    ustr_bytes[0:2] = length.to_bytes(2, "little")
    ustr_bytes[2:4] = maximum_length.to_bytes(2, "little")
    ustr_bytes[8:16] = cmd_buffer_addr.to_bytes(8, "little")

    params_buffer = ctypes.create_string_buffer(cmd_offset + ustr_size)
    ctypes.memmove(
        ctypes.addressof(params_buffer) + cmd_offset,
        bytes(ustr_bytes),
        ustr_size,
    )
    return params_buffer, cmd_buffer, ctypes.addressof(params_buffer)


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.fixture
def attached_bridge() -> X64DbgBridge:
    """Construct a bridge attached to the current process.

    Returns:
        X64DbgBridge: A bridge with ``attached_pid = os.getpid()``.
    """
    b = X64DbgBridge()
    b.attached_pid = os.getpid()
    return b


# ---------------------------------------------------------------------------
# F-0025: WIN_NO_INHERIT_HANDLE constant removed
# ---------------------------------------------------------------------------


class TestWinNoInheritHandleRemoved:
    """Verify the ``WIN_NO_INHERIT_HANDLE`` constant is gone."""

    def test_constant_not_exposed(self) -> None:
        """Verify the bridge module does not export ``WIN_NO_INHERIT_HANDLE``."""
        assert not hasattr(x64dbg_module, "WIN_NO_INHERIT_HANDLE"), (
            "WIN_NO_INHERIT_HANDLE constant must be deleted; the bridge inlines False in OpenProcess calls."
        )

    def test_source_inlines_false_for_inherit_handle(self) -> None:
        """Verify the source no longer references the constant by name."""
        path = x64dbg_module.__file__
        assert path is not None
        text = Path(path).read_text(encoding="utf-8")
        assert "WIN_NO_INHERIT_HANDLE" not in text, "WIN_NO_INHERIT_HANDLE must not appear in source after audit6 X64DBG-B."

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    async def test_read_memory_still_opens_process(
        self,
        attached_bridge: X64DbgBridge,
    ) -> None:
        """Verify ``read_memory`` (which used the constant) still works.

        Args:
            attached_bridge: Bridge attached to current process.
        """
        marker = b"AUDIT6_F0025_MARKER"
        buf = ctypes.create_string_buffer(marker)
        addr = ctypes.addressof(buf)
        result = await attached_bridge.read_memory(addr, len(marker))
        assert result == marker


# ---------------------------------------------------------------------------
# F-0024: UNICODE_STRING odd-length and bounds rejection
# ---------------------------------------------------------------------------


class TestUnicodeStringRejection:
    """Verify ``_read_unicode_string_from_params`` rejects malformed input."""

    @staticmethod
    def _read_through_self_handle(params_addr: int) -> str | None:
        """Open the current process and read the synthetic UNICODE_STRING.

        Args:
            params_addr: Address of the synthetic
                ``RTL_USER_PROCESS_PARAMETERS`` block.

        Returns:
            str | None: Bridge's parsed result.
        """
        kernel32 = ctypes.windll.kernel32
        inherit = wintypes.BOOL(0)
        handle = kernel32.OpenProcess(_PROCESS_VM_READ, inherit, os.getpid())
        assert handle, "OpenProcess(self) must succeed"
        try:
            return _read_unicode_string(handle, params_addr, x64dbg_module.POINTER_SIZE_64)
        finally:
            kernel32.CloseHandle(handle)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_well_formed_returns_string(self) -> None:
        """Verify a valid UNICODE_STRING yields the decoded command line."""
        cmd_line = "C:\\Program Files\\App.exe --flag"
        params_buffer, cmd_buffer, params_addr = _build_params_buffer(cmd_line)
        result = self._read_through_self_handle(params_addr)
        assert ctypes.sizeof(params_buffer) > 0
        assert ctypes.sizeof(cmd_buffer) > 0
        assert result == cmd_line

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_odd_length_returns_none(self) -> None:
        """Verify an odd ``Length`` is rejected with ``None``."""
        encoded_length = len("abc".encode("utf-16-le"))
        params_buffer, cmd_buffer, params_addr = _build_params_buffer(
            "abc",
            length_override=encoded_length + 1,
            maximum_length_override=encoded_length + 4,
        )
        result = self._read_through_self_handle(params_addr)
        assert ctypes.sizeof(params_buffer) > 0
        assert ctypes.sizeof(cmd_buffer) > 0
        assert result is None, "Odd UNICODE_STRING.Length must be rejected, not silently trimmed."

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_length_exceeds_maximum_returns_none(self) -> None:
        """Verify ``Length > MaximumLength`` is rejected with ``None``."""
        encoded_length = len("abcd".encode("utf-16-le"))
        params_buffer, cmd_buffer, params_addr = _build_params_buffer(
            "abcd",
            length_override=encoded_length,
            maximum_length_override=encoded_length - 2,
        )
        result = self._read_through_self_handle(params_addr)
        assert ctypes.sizeof(params_buffer) > 0
        assert ctypes.sizeof(cmd_buffer) > 0
        assert result is None, "Length > MaximumLength must be rejected, not silently passed."


# ---------------------------------------------------------------------------
# F-0027: get_process_info raises when not attached
# ---------------------------------------------------------------------------


class TestGetProcessInfoRaisesWhenDetached:
    """Verify ``get_process_info`` no longer returns ``None``."""

    @pytest.mark.asyncio
    async def test_raises_when_not_attached(self, bridge: X64DbgBridge) -> None:
        """Verify ToolError is raised instead of returning None.

        Args:
            bridge: Unattached bridge fixture.
        """
        with pytest.raises(ToolError) as excinfo:
            await bridge.get_process_info()
        assert "not attached" in str(excinfo.value).lower()
        assert excinfo.value.tool_name == "x64dbg"

    def test_return_annotation_is_processinfo(self) -> None:
        """Verify ``get_process_info`` is annotated as ``ProcessInfo`` (no Optional)."""
        sig = inspect.signature(X64DbgBridge.get_process_info)
        ret = sig.return_annotation
        ret_str = str(ret)
        assert "None" not in ret_str, f"get_process_info return annotation must drop None; got {ret_str!r}"
        assert "ProcessInfo" in ret_str


# ---------------------------------------------------------------------------
# F-0003: patch_anti_debug PEB plumbing + expanded check set
# ---------------------------------------------------------------------------


class _StubBridgeBase(X64DbgBridge):
    """Test double that replaces RPC and memory-write primitives."""

    def __init__(self) -> None:
        """Initialise the test double with empty trace state."""
        super().__init__()
        self.stub_peb: dict[str, Any] = {}
        self.stub_writes: list[tuple[int, bytes]] = []
        self.stub_reads: dict[int, bytes] = {}
        self.stub_peb_error: ToolError | None = None
        self.stub_write_error: ToolError | None = None

    async def read_peb(self) -> dict[str, Any]:
        """Return the canned PEB dictionary or raise a canned error.

        Returns:
            dict[str, Any]: Canned PEB response.

        Raises:
            stub_peb_error: When set, propagates the scripted ``ToolError``
                so callers can exercise the failure path.
        """
        stub_peb_error: ToolError | None = self.stub_peb_error
        if stub_peb_error is not None:
            raise stub_peb_error
        return dict(self.stub_peb)

    async def write_memory(self, address: int, data: bytes) -> int:
        """Record the write and return its byte count.

        Args:
            address: Target address.
            data: Bytes to write.

        Returns:
            int: Number of bytes "written".

        Raises:
            stub_write_error: When set, propagates the scripted ``ToolError``
                so callers can exercise the failure path.
        """
        stub_write_error: ToolError | None = self.stub_write_error
        if stub_write_error is not None:
            raise stub_write_error
        self.stub_writes.append((address, bytes(data)))
        return len(data)

    async def read_memory(self, address: int, size: int) -> bytes:
        """Return the canned read for the given address.

        Args:
            address: Address to read.
            size: Read size (must match the canned bytes' length).

        Returns:
            bytes: Canned bytes.

        Raises:
            ToolError: When the address has no canned response.
        """
        if address in self.stub_reads:
            return self.stub_reads[address][:size]
        msg = f"unexpected read at {hex(address)}"
        raise ToolError(msg, tool_name="x64dbg")


class TestReadPebToolDefinitionAdvertisesAddress:
    """Verify the tool definition lists the ``address`` field."""

    def test_returns_field_lists_address(self, bridge: X64DbgBridge) -> None:
        """Confirm ``returns`` mentions ``address`` for ``x64dbg.read_peb``.

        Args:
            bridge: Bridge fixture.
        """
        tool_def = bridge.tool_definition
        assert tool_def.tool_name == ToolName.X64DBG
        peb_tool = next(
            (f for f in tool_def.functions if f.name == "x64dbg.read_peb"),
            None,
        )
        assert peb_tool is not None, "x64dbg.read_peb tool definition missing"
        assert "address" in peb_tool.returns, f"read_peb tool definition must advertise the address field (got {peb_tool.returns!r})"
        assert "processParameters" in peb_tool.returns


@pytest.mark.asyncio
class TestPatchAntiDebugCorePatches:
    """Verify the original supported checks still apply when PEB is plumbed."""

    async def test_default_checks_apply_being_debugged_and_nt_global(self) -> None:
        """Default checks patch BeingDebugged, NtGlobalFlag, and heap flags."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.is_64bit = True
        b.stub_peb = {"address": hex(_PEB_BASE), "beingDebugged": 1, "ntGlobalFlag": 0x70}
        process_heap_offset = 0x30
        b.stub_reads[_PEB_BASE + process_heap_offset] = _HEAP_BASE.to_bytes(8, "little")

        result = await b.patch_anti_debug()

        assert result["success"] is True, result
        assert result["status"]["being_debugged"] is True
        assert result["status"]["nt_global_flag"] is True
        assert result["status"]["heap_flags"] is True
        assert "errors" not in result
        assert "supported" in result
        addresses = dict(b.stub_writes)
        assert addresses.get(_PEB_BASE + 2) == b"\x00", "BeingDebugged not patched"
        assert addresses.get(_PEB_BASE + 0xBC) == b"\x00\x00\x00\x00", "NtGlobalFlag not patched"
        assert addresses.get(_HEAP_BASE + 0x70) == b"\x00\x00\x00\x00", "HeapFlags not patched"
        assert addresses.get(_HEAP_BASE + 0x74) == b"\x00\x00\x00\x00", "ForceFlags not patched"

    async def test_32bit_uses_correct_offsets(self) -> None:
        """Verify 32-bit code path uses 0x68 / 0x18 / 0x40 / 0x44 offsets."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.is_64bit = False
        b.stub_peb = {"address": hex(_PEB_BASE)}
        process_heap_offset_32 = 0x18
        b.stub_reads[_PEB_BASE + process_heap_offset_32] = _HEAP_BASE.to_bytes(4, "little")

        result = await b.patch_anti_debug(["being_debugged", "nt_global_flag", "heap_flags"])
        assert result["success"] is True, result
        addresses = dict(b.stub_writes)
        assert _PEB_BASE + 0x68 in addresses, "32-bit NtGlobalFlag offset wrong"
        assert _HEAP_BASE + 0x40 in addresses, "32-bit HeapFlags offset wrong"
        assert _HEAP_BASE + 0x44 in addresses, "32-bit ForceFlags offset wrong"


@pytest.mark.asyncio
class TestPatchAntiDebugPebPlumbing:
    """Verify PEB-base plumbing detects missing/malformed values cleanly."""

    async def test_missing_address_records_per_check_error(self) -> None:
        """When ``read_peb`` omits ``address``, every actionable check errors."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.stub_peb = {"beingDebugged": 1}

        result = await b.patch_anti_debug(["being_debugged"])
        assert result["success"] is False
        assert result["status"]["being_debugged"] is False
        assert "errors" in result
        assert "PEB base address" in result["errors"]["being_debugged"]
        assert b.stub_writes == []

    async def test_malformed_address_records_per_check_error(self) -> None:
        """A non-parseable ``address`` value triggers a per-check error."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.stub_peb = {"address": "not_hex"}

        result = await b.patch_anti_debug(["being_debugged"])
        assert result["success"] is False
        assert "PEB base address" in result["errors"]["being_debugged"]

    async def test_read_peb_failure_records_per_check_error(self) -> None:
        """Plumbing surfaces ``read_peb`` errors per check rather than raising."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.stub_peb_error = ToolError("plugin offline", tool_name="x64dbg")

        result = await b.patch_anti_debug(["being_debugged"])
        assert result["success"] is False
        assert "read_peb failed" in result["errors"]["being_debugged"]


@pytest.mark.asyncio
class TestPatchAntiDebugUnsupportedCheckRejection:
    """Verify unsupported check names are rejected explicitly."""

    async def test_unknown_check_recorded_as_error(self) -> None:
        """An unsupported check name appears in ``errors`` with a clear message."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.stub_peb = {"address": hex(_PEB_BASE)}

        result = await b.patch_anti_debug(["process_debug_flags"])
        assert result["success"] is False
        assert "errors" in result
        assert "process_debug_flags" in result["errors"]
        assert "unsupported anti-debug check" in result["errors"]["process_debug_flags"]
        assert "supported" in result
        assert "being_debugged" in result["supported"]

    async def test_mixed_known_and_unknown_partial_success(self) -> None:
        """A known check still applies even when an unknown one is requested."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.is_64bit = True
        b.stub_peb = {"address": hex(_PEB_BASE)}

        result = await b.patch_anti_debug(["being_debugged", "kd_debugger_not_present"])
        assert result["status"]["being_debugged"] is True
        assert "kd_debugger_not_present" in result["errors"]
        assert result["success"] is False, "any error must drop success to False"


class TestPatchAntiDebugClassConstant:
    """Verify ``SUPPORTED_ANTI_DEBUG_PATCHES`` documents the contract."""

    def test_constant_has_expected_entries(self) -> None:
        """Verify the supported patch tuple contains the documented checks."""
        supported = X64DbgBridge.SUPPORTED_ANTI_DEBUG_PATCHES
        assert "being_debugged" in supported
        assert "nt_global_flag" in supported
        assert "heap_flags" in supported

    @pytest.mark.asyncio
    async def test_default_param_matches_documented_default(self) -> None:
        """Default ``checks=None`` expands to a stable, documented set."""
        b = _StubBridgeBase()
        b.attached_pid = _TARGET_PID
        b.is_64bit = True
        b.stub_peb = {"address": hex(_PEB_BASE)}
        b.stub_reads[_PEB_BASE + 0x30] = _HEAP_BASE.to_bytes(8, "little")

        result = await b.patch_anti_debug(None)
        assert set(result["status"].keys()) == {"being_debugged", "nt_global_flag", "heap_flags"}
