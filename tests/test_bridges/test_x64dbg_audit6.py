# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit6 regression tests for ``intellicrack.bridges.x64dbg``.

Combines the X64DBG-A, X64DBG-B, X64DBG-C, X64DBG-D, and X64DBG-E audit6
work units into a single test module so their helpers and fixtures are
shared.

X64DBG-A production-blocker findings:

* F-0004 - step coroutines wait on the plugin's paused event with a
  bounded timeout instead of a fixed sleep.
* F-0011 - shutdown completes process termination, state clearing, and
  super-shutdown even when an earlier cleanup phase raises.
* F-0013 - `_start_debugger` refuses to launch when the C++ plugin is
  not deployed.
* F-0015 - `Popen` invocation routes stdout/stderr/stdin to `DEVNULL`
  so the GUI cannot deadlock on a full pipe.
* F-0017 - `_wait_for_pipe_ready` raises on non-Windows instead of
  sleeping and returning.
* F-0018 - `_detect_process_arch` returns `None` and `attach`
  raises rather than guessing 64-bit on error.
* F-0023 - `_detect_architecture` rejects unsupported / corrupt PE
  inputs instead of silently returning 64-bit / 32-bit.

The X64DBG-A tests exercise the actual defect surface: real PE bytes
feed into the architecture detector, real `Popen` kwargs are
inspected via a recording wrapper installed at the bridge's `Popen`
import binding, and step waiting uses real `asyncio.Future`
resolution scheduled through the bridge's threadsafe event handler.
X64DBG-B production-blocker findings:

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

X64DBG-C production-blocker findings:

* F-0001 - post-condition verification on ``set_breakpoint``,
  ``patch_instruction``, ``nop_range``, and ``run_to``.
* F-0008 - structured plugin error codes replacing substring matching
  in ``_is_recoverable_pipe_error``.
* F-0014 - ``evaluate_expression`` raises ``ToolError`` on non-int /
  non-string responses instead of returning ``0``.
* F-0016 - INFO-level "command_set" log lines downgraded to DEBUG
  ``x64dbg_command_queued`` wording where no verification gates them.
* F-0028 - fallback in ``save_database``/``load_database`` etc. only
  triggers on ``unknown_command`` codes; pipe-disconnected errors must
  propagate.
* F-0029 - ``get_status`` raises ``ToolError`` instead of returning a
  fake-default status dict when the plugin response is not a dict.

The X64DBG-C tests substitute the bridge's ``_pipe_client`` with an
in-process fake that records sent commands and replays scripted
responses; this is the smallest viable boundary because launching real
x64dbg from CI is not feasible.

X64DBG-D production-blocker findings:

* F-0002 - ``set_breakpoint`` round-trips the native breakpoint id and
  verifies the debugger actually applied the breakpoint via ``bp_list``.
* F-0006 - ``get_threads`` populates ``start_address``, ``current_pc``,
  and ``state`` from real Win32 thread queries.
* F-0007 - ``_read_module_entry_point`` validates the optional-header
  layout (PE32 vs PE32+) and ``SizeOfOptionalHeader`` instead of blindly
  trusting a 256-byte read.
* F-0009 - ``except Exception`` swallow paths in ``disassemble_at``,
  ``_get_threads``, ``_get_modules``, and ``_get_parent_pid`` are
  narrowed to typed-failure handlers.
* F-0010 - per-handle process-handle cache is populated on first
  memory access and released on detach/shutdown.
* F-0012 - ``_breakpoints``/``_watchpoints`` dictionaries are guarded
  against concurrent mutation from coroutines and ``_handle_event``.
* F-0026 - ``set_breakpoint`` issues ``bpcond`` after ``bp_set`` when a
  conditional expression is supplied.

The X64DBG-D tests also use a deterministic in-process pipe-client
substitute that records every command/params pair without spawning
x64dbg, so the failure modes above can be reproduced on a developer
workstation.

X64DBG-E production-blocker findings:

* F-0005 - ``find_pattern`` with wildcards must stream regions in
  chunks with rolling overlap so wildcard matches that fall outside the
  first ``MAX_MEMORY_READ_SIZE`` window are still found.
* F-0019 - ``get_resources`` must walk the resource tree recursively
  and emit one dict per leaf with size and rva populated.
* F-0020 - ``_build_export_entries`` must enumerate every export
  reported by the PE export directory; no silent truncation.
* F-0021 - ``analyze_entropy`` must read in chunks so a single
  unreadable page does not abort the whole scan.
* F-0022 - ``set_breakpoint_on_api`` must resolve the API VA via the
  expression evaluator and place the breakpoint at the resolved VA.

The X64DBG-E tests inject deterministic in-memory data through
``monkeypatch`` of ``read_memory`` / ``get_memory_regions`` /
``_send_pipe_command`` / ``set_breakpoint`` so the production code
paths execute exactly as in production but without requiring a live
x64dbg.exe.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import inspect
import os
import struct
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast


if sys.platform == "win32":
    from ctypes import wintypes

import pytest

from intellicrack.bridges import x64dbg as x64dbg_module
from intellicrack.bridges._pe_format import (
    PE32_OPTIONAL_HEADER_SIZE,
    PE32PLUS_OPTIONAL_HEADER_SIZE,
    PE_OPTIONAL_HEADER_MAGIC_PE32,
    PE_OPTIONAL_HEADER_OFFSET,
    PE_SIGNATURE,
)
from intellicrack.bridges._win32_types import NT_HEADERS_OPTIONAL_OFFSET
from intellicrack.bridges.x64dbg import (
    MAX_MEMORY_READ_SIZE,
    PE32_MACHINE,
    PE64_MACHINE,
    PE_EXPORT_MAX,
    X64DbgBridge,
)
from intellicrack.core.types import BreakpointInfo, MemoryRegion, ToolError, ToolName


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine, Generator


_bridge_module = x64dbg_module


_PEB_BASE: Final[int] = 0x7FFE_0000_0000
_HEAP_BASE: Final[int] = 0x4000_0000
_TARGET_PID: Final[int] = 4242
_PROCESS_VM_READ: Final[int] = 0x0010

_BP_ADDR: Final[int] = 0x401000
_PATCH_ADDR: Final[int] = 0x402000
_RUNTO_ADDR: Final[int] = 0x403000
_FILL_SIZE: Final[int] = 4


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


class _FakePipeClient:
    """In-process replacement for ``NamedPipeClient`` used by tests.

    Exposes the methods that ``X64DbgBridge._send_pipe_command``
    actually invokes (``is_connected`` property, ``send_command``).
    Each test scripts the ``responses`` callable to return a different
    pipe response per command.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialize the fake pipe client.

        Args:
            responder: Callable that maps ``(command, params)`` to the
                response dict the named-pipe layer would have returned.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Always report connected.

        Returns:
            bool: True - the fake is permanently "connected".
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the request and return the scripted response.

        Args:
            command: RPC command name.
            params: Optional parameters dict.

        Returns:
            dict[str, Any]: The response dict produced by ``responder``.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class _PlaceholderProcess:
    """Sentinel stand-in used to satisfy ``self._process is not None`` checks.

    Several wrappers in :class:`X64DbgBridge` short-circuit with a
    ``ToolError`` when ``self._process is None`` (e.g.
    :meth:`X64DbgBridge._send_command`). The tests do not actually
    spawn x64dbg.exe; this sentinel exists only so those guards see a
    non-``None`` value while the real I/O still flows through the
    fake pipe client.
    """


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipeClient:
    """Attach a fake pipe client to ``bridge`` and mark the plugin deployed.

    Also installs a sentinel ``_process`` value so wrappers that gate
    on ``self._process is not None`` (e.g. ``_send_command``) do not
    early-out before reaching the pipe.

    Args:
        bridge: Bridge instance under test.
        responder: Per-command response generator.

    Returns:
        _FakePipeClient: The installed fake, useful for assertions on
        the ``sent`` list.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


_SEND_PIPE_ATTR = "_send_pipe_command"
_IS_RECOVERABLE_ATTR = "_is_recoverable_pipe_error"


async def _call_send_pipe(
    bridge: X64DbgBridge,
    command: str,
    params: dict[str, Any] | None = None,
) -> object:
    """Invoke the bridge's protected ``_send_pipe_command`` method.

    Resolved via ``getattr`` with a string constant so basedpyright's
    ``reportPrivateUsage`` rule is satisfied.

    Args:
        bridge: Bridge instance under test.
        command: RPC command name.
        params: Optional parameters dict.

    Returns:
        object: The pipe-command result. Typed as ``object`` because
        the underlying ``PipeCommandResult`` union spans every
        JSON-serialisable shape and the test never inspects the value.
    """
    method = cast("Callable[..., Awaitable[object]]", getattr(bridge, _SEND_PIPE_ATTR))
    return await method(command, params)


def _classify(bridge: X64DbgBridge, exc: ToolError) -> bool:
    """Invoke the bridge's protected ``_is_recoverable_pipe_error``.

    Resolved via ``getattr`` with a string constant so basedpyright's
    ``reportPrivateUsage`` rule is satisfied.

    Args:
        bridge: Bridge instance under test.
        exc: ToolError to classify.

    Returns:
        bool: True if the error is recoverable via the script-fallback
        path.
    """
    classifier = cast("Callable[[ToolError], bool]", getattr(bridge, _IS_RECOVERABLE_ATTR))
    return classifier(exc)


class _LoggerEventRecorder:
    """Capture structlog event-name + level + kwargs from the bridge logger.

    The bridge instantiates its logger via ``get_logger`` from
    :mod:`intellicrack.core.logging`, which returns a
    ``structlog.stdlib.BoundLogger``. Pytest's ``caplog`` fixture only
    sees stdlib-handler output, which depends on whether the structlog
    config has been initialised in the running test session. To avoid
    coupling the F-0016 regression tests to that config, this recorder
    patches the bound logger's ``debug`` / ``info`` / ``warning``
    methods on entry and restores them on exit.
    """

    def __init__(self) -> None:
        """Initialise the empty record list and originals slot."""
        self.records: list[tuple[str, str, dict[str, object]]] = []
        self._originals: dict[str, Callable[..., None]] = {}

    @contextlib.contextmanager
    def recording(self) -> Generator[None]:
        """Patch the bridge logger for the duration of the ``with`` block.

        Yields:
            None: Control returns to the caller while the patches are
            active; on exit the original methods are restored.
        """
        bound_logger = getattr(_bridge_module, "_logger")
        for level in ("debug", "info", "warning", "error"):
            self._originals[level] = cast(
                "Callable[..., None]",
                getattr(bound_logger, level),
            )

        def _make_recorder(level_name: str) -> Callable[..., None]:
            def _recorder(event: str, **kwargs: object) -> None:
                self.records.append((event, level_name, dict(kwargs)))

            return _recorder

        for level in ("debug", "info", "warning", "error"):
            setattr(bound_logger, level, _make_recorder(level))
        try:
            yield
        finally:
            for level, original in self._originals.items():
                setattr(bound_logger, level, original)


def _capture_logger_events() -> _LoggerEventRecorder:
    """Construct a fresh ``_LoggerEventRecorder``.

    Returns:
        _LoggerEventRecorder: A recorder whose ``recording()`` context
        manager swaps the bridge logger's level methods for the
        duration of the block.
    """
    return _LoggerEventRecorder()


_REGION_BASE: Final[int] = 0x10000000
_MODULE_BASE: Final[int] = 0x40000000
_RSRC_RVA: Final[int] = 0x1000


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


# F-0008 - structured plugin error codes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestStructuredErrorCodes:
    """F-0008: ``_is_recoverable_pipe_error`` uses structured codes."""

    async def test_pipe_disconnected_is_not_recoverable(self, bridge: X64DbgBridge) -> None:
        """Pipe-disconnect failures must not classify as recoverable.

        A pipe-disconnected error means the script-fallback path would
        travel the same broken pipe (audit6.md F-0008/F-0028) - the
        bridge must propagate the failure instead of swallowing it.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": False, "error": "Pipe not connected"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "anything")
        assert _classify(bridge, exc_info.value) is False

    async def test_unknown_command_is_recoverable(self, bridge: X64DbgBridge) -> None:
        """Unknown-RPC failures classify as recoverable.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": False, "error": "Unknown command 'foo'"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "foo")
        assert _classify(bridge, exc_info.value) is True

    async def test_real_remote_error_propagates(self, bridge: X64DbgBridge) -> None:
        """A real plugin error (e.g. invalid address) is not recoverable.

        Old marker matching swept up "address not found" because of the
        word "found"; the structured code path keeps that text as
        ``remote_error`` and lets it propagate.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": False, "error": "Address not found in symbol table"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "eval", {"expression": "@bogus"})
        assert _classify(bridge, exc_info.value) is False

    async def test_structured_code_field_overrides_legacy_text(self, bridge: X64DbgBridge) -> None:
        """A plugin-supplied ``code`` field is preferred over text matching.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "id": 1,
                "success": False,
                "error": "anything goes here",
                "code": "unknown_command",
            }

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "foo")
        assert _classify(bridge, exc_info.value) is True


# ---------------------------------------------------------------------------
# F-0014 - evaluate_expression must raise on protocol violations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEvaluateExpression:
    """F-0014: failure to evaluate must not collapse to ``0``."""

    async def test_string_value_is_parsed(self, bridge: X64DbgBridge) -> None:
        """Hex-string responses parse to ints.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": "0xDEADBEEF"}

        _install_fake_pipe(bridge, responder)
        assert await bridge.evaluate_expression("foo") == 0xDEADBEEF

    async def test_int_value_returns_unchanged(self, bridge: X64DbgBridge) -> None:
        """Integer responses are returned verbatim.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": 42}

        _install_fake_pipe(bridge, responder)
        assert await bridge.evaluate_expression("foo") == 42

    async def test_unparseable_string_raises(self, bridge: X64DbgBridge) -> None:
        """A non-numeric string raises ``ToolError`` instead of yielding 0.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": "not-a-number"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="evaluate_expression"):
            await bridge.evaluate_expression("foo")

    async def test_none_result_raises(self, bridge: X64DbgBridge) -> None:
        """A ``None`` result raises rather than collapsing to 0.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": None}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="evaluate_expression"):
            await bridge.evaluate_expression("foo")

    async def test_bool_result_raises(self, bridge: X64DbgBridge) -> None:
        """``True``/``False`` cannot be silently coerced to 1/0.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": True}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="evaluate_expression"):
            await bridge.evaluate_expression("foo")


# ---------------------------------------------------------------------------
# F-0029 - get_status must not return a fake-default dict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestGetStatus:
    """F-0029: invalid status payload must raise."""

    async def test_dict_payload_is_returned(self, bridge: X64DbgBridge) -> None:
        """Real status dict is returned verbatim.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "id": 1,
                "success": True,
                "result": {"debugging": True, "paused": False, "initialized": True},
            }

        _install_fake_pipe(bridge, responder)
        status = await bridge.get_status()
        assert status["debugging"] is True
        assert status["initialized"] is True

    async def test_list_payload_raises(self, bridge: X64DbgBridge) -> None:
        """A list payload raises ``ToolError`` (not all-False fallback).

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": ["debugging", "paused"]}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="get_status"):
            await bridge.get_status()


# ---------------------------------------------------------------------------
# F-0001 - post-condition verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetBreakpointVerification:
    """F-0001: ``set_breakpoint`` queries ``bp_list`` to confirm the bp."""

    async def test_breakpoint_present_in_bp_list(self, bridge: X64DbgBridge) -> None:
        """When ``bp_list`` reports the address, the bridge succeeds.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": _BP_ADDR, "type": "software", "enabled": True}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        bp_id = await bridge.set_breakpoint(_BP_ADDR)
        assert bp_id == _BP_ADDR
        assert ("bp_set", {"address": _BP_ADDR, "type": "software", "condition": None}) in fake.sent
        assert ("bp_list", None) in fake.sent

    async def test_breakpoint_absent_raises(self, bridge: X64DbgBridge) -> None:
        """When ``bp_list`` does not include the address, raise.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {"id": 1, "success": True, "result": []}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="no software breakpoint exists"):
            await bridge.set_breakpoint(_BP_ADDR)
        assert _BP_ADDR not in bridge.breakpoints

    async def test_breakpoint_skipped_when_bp_list_unknown(self, bridge: X64DbgBridge) -> None:
        """Older plugins lacking ``bp_list`` skip verification gracefully.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {"id": 1, "success": False, "error": "Unknown command 'bp_list'"}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bp_id = await bridge.set_breakpoint(_BP_ADDR)
        assert bp_id == _BP_ADDR
        assert _BP_ADDR in bridge.breakpoints

    async def test_breakpoint_protocol_violation_raises(self, bridge: X64DbgBridge) -> None:
        """``bp_list`` returning a non-list payload raises.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "bp_set":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {"id": 1, "success": True, "result": "not-a-list"}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="bp_list returned"):
            await bridge.set_breakpoint(_BP_ADDR)


@pytest.mark.asyncio
class TestRunToVerification:
    """F-0001: ``run_to`` polls ``reg_get rip`` to confirm arrival."""

    async def test_run_to_reaches_target(self, bridge: X64DbgBridge) -> None:
        """When the IP reaches the target, succeed.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "reg_get":
                assert params is not None
                assert params.get("name") == "rip"
                return {"id": 1, "success": True, "result": _RUNTO_ADDR}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bridge.RUN_TO_TIMEOUT = 1.0
        result = await bridge.run_to(_RUNTO_ADDR)
        assert result["success"] is True
        assert result["verified"] is True
        assert result["current_ip"] == hex(_RUNTO_ADDR)

    async def test_run_to_times_out_when_ip_misses_target(self, bridge: X64DbgBridge) -> None:
        """When the IP never matches target, raise.

        Args:
            bridge: Fixture bridge instance.
        """
        wrong_ip = _RUNTO_ADDR - 0x10

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "reg_get":
                return {"id": 1, "success": True, "result": wrong_ip}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bridge.RUN_TO_TIMEOUT = 0.05
        bridge.RUN_TO_POLL_INTERVAL = 0.005
        with pytest.raises(ToolError, match="run_to verification failed"):
            await bridge.run_to(_RUNTO_ADDR)

    async def test_run_to_skipped_when_reg_get_unknown(self, bridge: X64DbgBridge) -> None:
        """Older plugins without ``reg_get`` succeed with verified=False.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "reg_get":
                return {"id": 1, "success": False, "error": "Unknown command 'reg_get'"}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        bridge.RUN_TO_TIMEOUT = 1.0
        result = await bridge.run_to(_RUNTO_ADDR)
        assert result["verified"] is False
        assert result["current_ip"] is None


@pytest.mark.asyncio
class TestNopRangeAndPatchVerification:
    """F-0001: ``patch_instruction`` and ``nop_range`` verify the write.

    These helpers do not require Win32 because the bridge skips the
    verifying read when ``_attached_pid is None`` and surfaces
    ``verified=False`` instead of synthesising success.
    """

    async def test_nop_range_returns_unverified_when_not_attached(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """No attached PID -> verified=False, no fake success bytes.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.nop_range(_PATCH_ADDR, _FILL_SIZE)
        assert result["verified"] is False
        assert result["address"] == hex(_PATCH_ADDR)
        assert result["size"] == _FILL_SIZE

    async def test_patch_instruction_returns_unverified_when_not_attached(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """No attached PID -> verified=False, no fake patched bytes.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "assemble":
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.patch_instruction(_PATCH_ADDR, "nop")
        assert result["verified"] is False
        assert result["patched_bytes"] is None
        assert result["address"] == hex(_PATCH_ADDR)


# ---------------------------------------------------------------------------
# F-0028 - fallback only triggers on unknown_command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestFallbackBehaviour:
    """F-0028: ``save_database`` falls back only for unknown_command."""

    async def test_save_database_falls_back_on_unknown_rpc(self, bridge: X64DbgBridge) -> None:
        """When ``db_save`` is unknown, the script command path is used.

        Args:
            bridge: Fixture bridge instance.
        """
        sent_commands: list[str] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            sent_commands.append(command)
            if command == "db_save":
                return {"id": 1, "success": False, "error": "Unknown command 'db_save'"}
            if command == "exec":
                assert params is not None
                assert params.get("command") == "dbsave"
                return {"id": 1, "success": True, "result": None}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.save_database()
        assert result["success"] is True
        assert "db_save" in sent_commands
        assert "exec" in sent_commands

    async def test_save_database_propagates_pipe_disconnect(self, bridge: X64DbgBridge) -> None:
        """Pipe-disconnected errors must propagate (not fall back).

        The previous behaviour swallowed any error that contained the
        word "pipe" and routed through a script command on the same
        broken pipe (audit6.md F-0028). The fix raises so the operator
        sees the real failure.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": False, "error": "Pipe not connected"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="Pipe not connected"):
            await bridge.save_database()


# ---------------------------------------------------------------------------
# F-0016 - logging downgrade
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestLoggingDowngrade:
    """F-0016: fire-and-forget exec wrappers emit DEBUG ``x64dbg_command_queued``.

    INFO logs must not advertise success when the bridge has only
    queued a console command. The post-fix behaviour emits a DEBUG log
    explicitly tagged ``x64dbg_command_queued`` so log readers can tell
    queued events apart from verified ones.
    """

    async def test_thread_suspend_logs_at_debug_with_queued_wording(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Calling ``suspend_thread`` emits debug "x64dbg_command_queued".

        Replaces the bridge's ``_logger.debug`` with a recorder so the
        test can inspect the structured event name independently of
        whatever stdlib/structlog handler chain is attached at the
        time pytest runs.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": None}

        _install_fake_pipe(bridge, responder)
        events = _capture_logger_events()
        with events.recording():
            await bridge.suspend_thread(0x123)
        assert any(name == "x64dbg_command_queued" for name, _level, _ in events.records)
        assert not any(name == "thread_suspending" for name, _level, _ in events.records)

    async def test_script_load_logs_at_debug(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Calling ``script_load`` emits debug "x64dbg_command_queued".

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": True, "result": None}

        _install_fake_pipe(bridge, responder)
        events = _capture_logger_events()
        with events.recording():
            await bridge.script_load("foo.txt")
        assert any(name == "x64dbg_command_queued" for name, level, _ in events.records if level == "debug")
        assert not any(name == "script_loading" for name, _level, _ in events.records)


# ---------------------------------------------------------------------------
# F-0008 - error_code propagated as structured detail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestErrorCodeDetails:
    """F-0008: every ``ToolError`` from ``_send_pipe_command`` carries a code."""

    async def test_pipe_disconnected_attaches_code(self, bridge: X64DbgBridge) -> None:
        """A pipe-disconnect surfaces the ``pipe_disconnected`` code.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"id": 1, "success": False, "error": "Pipe not connected"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "anything")
        assert exc_info.value.details.get("x64dbg_error_code") == "pipe_disconnected"

    async def test_timeout_attaches_code(self, bridge: X64DbgBridge) -> None:
        """An asyncio timeout surfaces the ``timeout`` code.

        Args:
            bridge: Fixture bridge instance.
        """

        class _SlowFakePipe:
            """Pipe client whose ``send_command`` never returns."""

            @property
            def is_connected(self) -> bool:
                """Always report connected.

                Returns:
                    bool: True.
                """
                return True

            async def send_command(
                self,
                _command: str,
                _params: dict[str, Any] | None = None,
            ) -> dict[str, Any]:
                """Sleep longer than the bridge's command timeout.

                Args:
                    _command: Ignored.
                    _params: Ignored.

                Returns:
                    dict[str, Any]: Never returns.
                """
                await asyncio.sleep(60.0)
                return {"id": 1, "success": True, "result": None}

        setattr(bridge, "_pipe_client", _SlowFakePipe())
        setattr(bridge, "_plugin_deployed", True)
        bridge.COMMAND_TIMEOUT = 0.05
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "anything")
        assert exc_info.value.details.get("x64dbg_error_code") == "timeout"

    async def test_plugin_unavailable_attaches_code(self, bridge: X64DbgBridge) -> None:
        """When the plugin is undeployed, the ``plugin_unavailable`` code is emitted.

        Args:
            bridge: Fixture bridge instance.
        """
        setattr(bridge, "_plugin_deployed", False)
        with pytest.raises(ToolError) as exc_info:
            await _call_send_pipe(bridge, "anything")
        assert exc_info.value.details.get("x64dbg_error_code") == "plugin_unavailable"


_HANDLE_EVENT_ATTR = "_handle_event"
_PIPE_CLIENT_ATTR = "_pipe_client"
_PLUGIN_DEPLOYED_ATTR = "_plugin_deployed"
_STATE_LOCK_ATTR = "_state_lock"
_PROCESS_HANDLES_ATTR = "_process_handles"
_RELEASE_HANDLES_ATTR = "_release_process_handles"
_GET_CACHED_HANDLE_ATTR = "_get_cached_process_handle"
_READ_PE_HEADER_ATTR = "_read_pe_header"
_READ_MODULE_ENTRY_POINT_ATTR = "_read_module_entry_point"
_READ_MEMORY_ATTR = "read_memory"
_GET_PARENT_PID_ATTR = "_get_parent_pid"

_BP_ADDR_PRIMARY = 0x401000
_BP_ADDR_SECONDARY = 0x402000
_BP_ADDR_TERTIARY = 0x403000
_PE_ENTRY_RVA = 0x12345
_TEST_BASE_ADDRESS = 0x140000000
_PROCESS_VM_OPERATION = 0x0008


def _dispatch_event(bridge: X64DbgBridge, message: dict[str, Any]) -> None:
    """Invoke the bridge's protected event dispatcher.

    Args:
        bridge: Bridge under test.
        message: Event payload.
    """
    raw_handler: object = getattr(bridge, _HANDLE_EVENT_ATTR)
    handler = cast("Callable[[dict[str, Any]], None]", raw_handler)
    handler(message)


class _FakePipeClientD:
    """In-process substitute for ``NamedPipeClient`` that records traffic.

    Each ``send_command`` invocation appends a ``(command, params)``
    tuple to ``calls`` and returns the response queued by the test via
    ``queue_response``. ``send_command`` raises ``ToolError`` when no
    response has been queued so a missing test setup is loud rather
    than silent.
    """

    def __init__(self) -> None:
        """Initialize the fake pipe client."""
        self.calls: list[tuple[str, dict[str, Any] | None]] = []
        self._responses: dict[str, list[dict[str, Any]]] = {}
        self._default_responses: dict[str, dict[str, Any]] = {}
        self.is_connected: bool = True

    def queue_response(self, command: str, response: dict[str, Any]) -> None:
        """Queue a single response for a given command name.

        Args:
            command: Command name.
            response: Response dict to return for the next call.
        """
        self._responses.setdefault(command, []).append(response)

    def set_default_response(self, command: str, response: dict[str, Any]) -> None:
        """Set a default response for a command when the queue is empty.

        Args:
            command: Command name.
            response: Response dict.
        """
        self._default_responses[command] = response

    def set_event_handler(self, handler: Callable[[dict[str, Any]], None] | None) -> None:
        """No-op event handler setter to satisfy the bridge contract.

        Args:
            handler: Ignored.
        """
        del handler

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the call and return the queued response.

        Args:
            command: Command name.
            params: Command parameters.

        Returns:
            dict[str, Any]: Queued response.

        Raises:
            ToolError: If no response is queued for ``command``.
        """
        self.calls.append((command, params))
        queue = self._responses.get(command, [])
        if queue:
            return queue.pop(0)
        if command in self._default_responses:
            return self._default_responses[command]
        msg = f"_FakePipeClientD: no response queued for command={command!r}"
        raise ToolError(msg)

    async def connect(self) -> None:
        """No-op connect for compatibility."""

    async def close(self) -> None:
        """Mark the fake client disconnected to mirror the real client."""
        self.is_connected = False


def _attach_fake_pipe_d(bridge: X64DbgBridge) -> _FakePipeClientD:
    """Wire a fake pipe client and mark the plugin deployed.

    Uses ``setattr`` with string-constant attribute names so the test
    does not access the bridge's protected private slots through
    direct attribute syntax (which basedpyright would flag as
    ``reportPrivateUsage``).

    Args:
        bridge: Bridge under test.

    Returns:
        _FakePipeClientD: The freshly attached fake client.
    """
    fake = _FakePipeClientD()
    setattr(bridge, _PIPE_CLIENT_ATTR, fake)
    setattr(bridge, _PLUGIN_DEPLOYED_ATTR, True)
    return fake


def _fake_of_d(bridge: X64DbgBridge) -> _FakePipeClientD:
    """Return the fake pipe client previously attached to ``bridge``.

    Args:
        bridge: Bridge whose pipe client to return.

    Returns:
        _FakePipeClientD: The previously attached fake.
    """
    raw: object = getattr(bridge, _PIPE_CLIENT_ATTR)
    return cast("_FakePipeClientD", raw)


@pytest.fixture
def bridge_d() -> X64DbgBridge:
    """Provide a fresh bridge instance with the fake plugin wired.

    Returns:
        X64DbgBridge: Bridge with ``_pipe_client`` set to a fake.
    """
    b = X64DbgBridge()
    _attach_fake_pipe_d(b)
    return b


@pytest.mark.asyncio
async def test_set_breakpoint_returns_native_address_after_verification(bridge_d: X64DbgBridge) -> None:
    """F-0002: native breakpoint id is the address; verified by ``bp_list``.

    Args:
        bridge_d: Pre-wired bridge fixture.
    """
    fake = _fake_of_d(bridge_d)
    fake.queue_response("bp_set", {"success": True, "result": hex(_BP_ADDR_PRIMARY)})
    fake.queue_response(
        "bp_list",
        {
            "success": True,
            "result": [
                {
                    "address": hex(_BP_ADDR_PRIMARY),
                    "type": "normal",
                    "enabled": True,
                    "hitCount": 0,
                    "breakCondition": "",
                },
            ],
        },
    )

    bp_id = await bridge_d.set_breakpoint(_BP_ADDR_PRIMARY, "software")

    assert bp_id == _BP_ADDR_PRIMARY
    stored = bridge_d.breakpoints[_BP_ADDR_PRIMARY]
    assert stored.id == _BP_ADDR_PRIMARY
    assert stored.address == _BP_ADDR_PRIMARY


@pytest.mark.asyncio
async def test_set_breakpoint_rejects_unverifiable_breakpoint(bridge_d: X64DbgBridge) -> None:
    """F-0002: ``bp_set`` parse-success without ``bp_list`` confirmation raises.

    Args:
        bridge_d: Pre-wired bridge fixture.
    """
    fake = _fake_of_d(bridge_d)
    fake.queue_response("bp_set", {"success": True, "result": hex(_BP_ADDR_PRIMARY)})
    fake.queue_response("bp_list", {"success": True, "result": []})

    with pytest.raises(ToolError, match="no software breakpoint exists"):
        await bridge_d.set_breakpoint(_BP_ADDR_PRIMARY, "software")
    assert _BP_ADDR_PRIMARY not in bridge_d.breakpoints


@pytest.mark.asyncio
async def test_set_breakpoint_with_condition_issues_bpcond(bridge_d: X64DbgBridge) -> None:
    """F-0026: conditional bp issues a ``bpcond`` script command after ``bp_set``.

    Args:
        bridge_d: Pre-wired bridge fixture.
    """
    fake = _fake_of_d(bridge_d)
    fake.queue_response("bp_set", {"success": True, "result": hex(_BP_ADDR_PRIMARY)})
    fake.queue_response(
        "bp_list",
        {
            "success": True,
            "result": [
                {
                    "address": hex(_BP_ADDR_PRIMARY),
                    "type": "normal",
                    "enabled": True,
                    "hitCount": 0,
                    "breakCondition": "",
                },
            ],
        },
    )
    fake.queue_response("exec", {"success": True, "result": "ok"})

    await bridge_d.set_breakpoint(_BP_ADDR_PRIMARY, "software", "rax==0")

    exec_calls = [c for c in fake.calls if c[0] == "exec"]
    assert len(exec_calls) == 1
    params = exec_calls[0][1]
    assert params is not None
    cmd = params.get("command", "")
    assert isinstance(cmd, str)
    assert cmd.startswith("bpcond ")
    assert hex(_BP_ADDR_PRIMARY) in cmd
    assert '"rax==0"' in cmd


@pytest.mark.asyncio
async def test_remove_breakpoint_uses_address_keyed_native_id(bridge_d: X64DbgBridge) -> None:
    """F-0002: removal is keyed by native id (address) and clears local registry.

    Args:
        bridge_d: Pre-wired bridge fixture.
    """
    fake = _fake_of_d(bridge_d)
    fake.queue_response("bp_set", {"success": True, "result": hex(_BP_ADDR_PRIMARY)})
    fake.queue_response(
        "bp_list",
        {
            "success": True,
            "result": [
                {
                    "address": hex(_BP_ADDR_PRIMARY),
                    "type": "normal",
                    "enabled": True,
                    "hitCount": 0,
                    "breakCondition": "",
                },
            ],
        },
    )
    fake.queue_response("bp_remove", {"success": True, "result": True})

    bp_id = await bridge_d.set_breakpoint(_BP_ADDR_PRIMARY, "software")
    assert bp_id == _BP_ADDR_PRIMARY

    removed = await bridge_d.remove_breakpoint(bp_id)
    assert removed is True
    assert _BP_ADDR_PRIMARY not in bridge_d.breakpoints


@pytest.mark.asyncio
async def test_concurrent_set_breakpoint_calls_serialise_state(bridge_d: X64DbgBridge) -> None:
    """F-0012: parallel ``set_breakpoint`` does not corrupt the registry.

    Args:
        bridge_d: Pre-wired bridge fixture.
    """
    fake = _fake_of_d(bridge_d)
    addresses = [_BP_ADDR_PRIMARY, _BP_ADDR_SECONDARY, _BP_ADDR_TERTIARY]
    bp_list_payload: list[dict[str, Any]] = []
    for addr in addresses:
        fake.queue_response("bp_set", {"success": True, "result": hex(addr)})
        bp_list_payload.append(
            {
                "address": hex(addr),
                "type": "normal",
                "enabled": True,
                "hitCount": 0,
                "breakCondition": "",
            },
        )
        fake.queue_response("bp_list", {"success": True, "result": list(bp_list_payload)})

    coroutines: list[Awaitable[int]] = [bridge_d.set_breakpoint(addr, "software") for addr in addresses]
    results: list[int] = await asyncio.gather(*coroutines)

    assert sorted(results) == sorted(addresses)
    assert set(bridge_d.breakpoints.keys()) == set(addresses)


def test_handle_event_breakpoint_hit_counts_under_concurrent_mutation() -> None:
    """F-0012: ``_handle_event`` and coroutine mutation cannot race.

    Spawns many threads that simultaneously dispatch breakpoint events
    and mutate ``_breakpoints`` so a missing lock would surface as a
    ``RuntimeError`` ("dictionary changed size during iteration") or a
    lost ``hit_count`` increment.
    """
    bridge = X64DbgBridge()
    iterations = 200
    addresses = [0x401000 + i * 0x10 for i in range(8)]
    for addr in addresses:
        bridge.breakpoints[addr] = BreakpointInfo(
            id=addr,
            address=addr,
            bp_type="software",
            enabled=True,
            hit_count=0,
        )

    state_lock_obj: object = getattr(bridge, _STATE_LOCK_ATTR)
    state_lock = cast("threading.Lock", state_lock_obj)

    def event_thread(addr: int) -> None:
        """Repeatedly dispatch breakpoint events for one address.

        Args:
            addr: Address to fire breakpoints against.
        """
        for _ in range(iterations):
            _dispatch_event(bridge, {"event": "breakpoint", "address": addr})

    def mutator_thread(addr: int) -> None:
        """Add and remove a parallel breakpoint while events fire.

        Args:
            addr: Base address used for the mutator state.
        """
        for i in range(iterations):
            ephemeral_addr = addr + 0x100 + i
            with state_lock:
                bridge.breakpoints[ephemeral_addr] = BreakpointInfo(
                    id=ephemeral_addr,
                    address=ephemeral_addr,
                    bp_type="software",
                    enabled=True,
                    hit_count=0,
                )
            with state_lock:
                bridge.breakpoints.pop(ephemeral_addr, None)

    threads = [threading.Thread(target=event_thread, args=(addr,)) for addr in addresses]
    threads.extend(threading.Thread(target=mutator_thread, args=(addr,)) for addr in addresses)
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    for addr in addresses:
        assert bridge.breakpoints[addr].hit_count == iterations


@pytest.mark.asyncio
async def test_get_threads_populates_start_address_and_pc() -> None:
    """F-0006: live threads expose non-zero start_address and a real state.

    Verifies the audit's core complaint that the bridge advertised
    ``start_address``/``current_pc`` but always returned 0. With the
    fix in place, at least one thread reports a non-zero start address
    produced by ``NtQueryInformationThread`` and at least one reports
    a real running/suspended state.
    """
    if sys.platform != "win32":
        pytest.skip("Windows only")

    import os  # noqa: PLC0415

    bridge = X64DbgBridge()
    bridge.attached_pid = os.getpid()

    threads = await bridge.get_threads()
    assert threads, "expected at least one thread for the current process"
    states = {t.state for t in threads}
    assert states & {"running", "suspended", "terminated"}, f"expected at least one thread with a real state, got {states!r}"
    assert any(t.start_address != 0 for t in threads), "no thread carried a non-zero start address"


def _build_pe_header(*, magic: int, optional_header_size: int) -> bytes:
    """Construct a buffer mimicking ``ReadProcessMemory`` of a PE NT-headers region.

    Args:
        magic: Optional-header ``Magic`` value (PE32, PE32+, or other).
        optional_header_size: ``SizeOfOptionalHeader`` to embed in the COFF header.

    Returns:
        bytes: Buffer starting at the PE signature (i.e. what the bridge sees
        after ``read_dos_e_lfanew``).
    """
    buf = bytearray(NT_HEADERS_OPTIONAL_OFFSET + max(optional_header_size, PE32PLUS_OPTIONAL_HEADER_SIZE) + 0x100)
    buf[0:4] = PE_SIGNATURE
    struct.pack_into("<H", buf, 4, 0x8664)
    struct.pack_into("<H", buf, 6, 1)
    struct.pack_into("<I", buf, 8, 0)
    struct.pack_into("<I", buf, 12, 0)
    struct.pack_into("<I", buf, 16, 0)
    struct.pack_into("<H", buf, 20, optional_header_size)
    struct.pack_into("<H", buf, 22, 0)
    struct.pack_into("<H", buf, NT_HEADERS_OPTIONAL_OFFSET, magic)
    entry_offset = NT_HEADERS_OPTIONAL_OFFSET + 0x28
    struct.pack_into("<I", buf, entry_offset, _PE_ENTRY_RVA)
    assert NT_HEADERS_OPTIONAL_OFFSET == PE_OPTIONAL_HEADER_OFFSET
    assert PE32PLUS_OPTIONAL_HEADER_SIZE > PE32_OPTIONAL_HEADER_SIZE
    return bytes(buf)


def _patch_read_pe_header(bridge: X64DbgBridge, payload: bytes) -> None:
    """Replace ``_read_pe_header`` on ``bridge`` so ``_read_module_entry_point`` sees ``payload``.

    Args:
        bridge: Bridge under test.
        payload: Synthetic PE header payload to return.
    """

    async def fake_read_pe_header(base_address: int, module_name: str, size: int = 256) -> tuple[int, bytes]:
        """Return the synthesised PE header.

        Yields back to the loop once so the coroutine is a genuine
        async function (the real implementation awaits ``read_memory``).

        Args:
            base_address: Ignored.
            module_name: Ignored.
            size: Ignored.

        Returns:
            tuple[int, bytes]: ``(0, payload)``.
        """
        del base_address, module_name, size
        await asyncio.sleep(0)
        return 0, payload

    setattr(bridge, _READ_PE_HEADER_ATTR, fake_read_pe_header)


def test_read_module_entry_point_validates_pe32_magic() -> None:
    """F-0007: PE32 (32-bit) magic is honoured by entry-point parsing."""
    bridge = X64DbgBridge()
    pe_header = _build_pe_header(magic=PE_OPTIONAL_HEADER_MAGIC_PE32, optional_header_size=PE32_OPTIONAL_HEADER_SIZE)
    _patch_read_pe_header(bridge, pe_header)

    raw_method: object = getattr(bridge, _READ_MODULE_ENTRY_POINT_ATTR)
    method = cast("Callable[[int, str], Coroutine[Any, Any, int]]", raw_method)
    result = asyncio.run(method(_TEST_BASE_ADDRESS, "test32.dll"))
    assert result == _TEST_BASE_ADDRESS + _PE_ENTRY_RVA


def test_read_module_entry_point_rejects_unknown_magic() -> None:
    """F-0007: unknown optional-header magic returns 0 instead of garbage."""
    bridge = X64DbgBridge()
    pe_header = _build_pe_header(magic=0x107, optional_header_size=PE32_OPTIONAL_HEADER_SIZE)
    _patch_read_pe_header(bridge, pe_header)

    raw_method: object = getattr(bridge, _READ_MODULE_ENTRY_POINT_ATTR)
    method = cast("Callable[[int, str], Coroutine[Any, Any, int]]", raw_method)
    assert asyncio.run(method(_TEST_BASE_ADDRESS, "rom-image.dll")) == 0


def test_read_module_entry_point_rejects_undersized_optional_header() -> None:
    """F-0007: ``SizeOfOptionalHeader`` below PE32 minimum returns 0."""
    bridge = X64DbgBridge()
    pe_header = _build_pe_header(magic=PE_OPTIONAL_HEADER_MAGIC_PE32, optional_header_size=PE32_OPTIONAL_HEADER_SIZE - 16)
    _patch_read_pe_header(bridge, pe_header)

    raw_method: object = getattr(bridge, _READ_MODULE_ENTRY_POINT_ATTR)
    method = cast("Callable[[int, str], Coroutine[Any, Any, int]]", raw_method)
    assert asyncio.run(method(_TEST_BASE_ADDRESS, "shrunken.dll")) == 0


@pytest.mark.asyncio
async def test_disassemble_failure_raises_instead_of_swallowing(bridge_d: X64DbgBridge) -> None:
    """F-0009: ``disassemble_at`` no longer silently returns ``[]`` on errors.

    Uses a controlled ``read_memory`` failure to drive the previously
    bare-``Exception`` branch in ``disassemble_at`` and asserts that
    the error now propagates as a ``ToolError`` with the actual cause.

    Args:
        bridge_d: Pre-wired bridge fixture.
    """
    pytest.importorskip("capstone")

    fake = _fake_of_d(bridge_d)
    fake.set_default_response(
        "disasm",
        {"success": False, "error": "pipe disconnected", "code": "pipe_disconnected"},
    )

    async def failing_read_memory(address: int, size: int) -> bytes:
        """Always raise to simulate a memory failure inside the cap-disasm path.

        The body yields once so the coroutine matches the real async
        ``read_memory`` shape before the controlled failure.

        Args:
            address: Ignored.
            size: Ignored.

        Returns:
            bytes: never returns.

        Raises:
            ToolError: Always.
        """
        del address, size
        await asyncio.sleep(0)
        msg = "ReadProcessMemory failed at 0x401000"
        raise ToolError(msg)

    setattr(bridge_d, _READ_MEMORY_ATTR, failing_read_memory)

    with pytest.raises(ToolError, match="Disassembly failed"):
        await bridge_d.disassemble_at(_BP_ADDR_PRIMARY, count=1)


def test_get_parent_pid_narrow_exception_does_not_swallow_typeerror() -> None:
    """F-0009: ``_get_parent_pid`` no longer swallows non-OS errors.

    A plain ``TypeError`` from a programming bug must surface to the
    caller instead of being converted to a generic ``ToolError`` by
    the previous bare-``except Exception`` clause.
    """
    if sys.platform != "win32":
        pytest.skip("Windows only")

    import ctypes  # noqa: PLC0415
    import os  # noqa: PLC0415

    saved = ctypes.windll.kernel32.Process32FirstW
    failure_message = "simulated programmer error"

    def boom(*_args: object, **_kwargs: object) -> int:
        """Replacement for ``Process32FirstW`` that raises ``TypeError``.

        Args:
            *_args: Forwarded positional arguments (ignored).
            **_kwargs: Forwarded keyword arguments (ignored).

        Returns:
            int: Never returns.

        Raises:
            TypeError: Always raised so the test can verify the
                bare-Exception swallow path is gone.
        """
        raise TypeError(failure_message)

    setattr(ctypes.windll.kernel32, "Process32FirstW", boom)
    raw_get_parent_pid: object = getattr(X64DbgBridge, _GET_PARENT_PID_ATTR)
    get_parent_pid = cast("Callable[[int], int]", raw_get_parent_pid)
    try:
        with pytest.raises(TypeError, match=failure_message):
            get_parent_pid(os.getpid())
    finally:
        setattr(ctypes.windll.kernel32, "Process32FirstW", saved)


@pytest.mark.asyncio
async def test_process_handle_cache_reused_across_reads() -> None:
    """F-0010: repeated ``read_memory`` calls reuse one open handle.

    Verifies the bridge no longer pays an ``OpenProcess`` /
    ``CloseHandle`` cost on every memory access.
    """
    if sys.platform != "win32":
        pytest.skip("Windows only")

    import ctypes  # noqa: PLC0415
    import os  # noqa: PLC0415

    bridge = X64DbgBridge()
    bridge.attached_pid = os.getpid()

    test_data = b"AUDIT6_HANDLE_CACHE_PROBE_VALUE"
    buffer = ctypes.create_string_buffer(test_data)
    addr = ctypes.addressof(buffer)

    open_count = 0
    saved_open = ctypes.windll.kernel32.OpenProcess

    def counting_open(*args: object, **kwargs: object) -> int:
        """Wrap ``OpenProcess`` to count invocations during the test.

        Args:
            *args: Forwarded positional arguments.
            **kwargs: Forwarded keyword arguments.

        Returns:
            int: The handle returned by the real ``OpenProcess``.
        """
        nonlocal open_count
        open_count += 1
        return cast("int", saved_open(*args, **kwargs))

    setattr(ctypes.windll.kernel32, "OpenProcess", counting_open)
    try:
        first = await bridge.read_memory(addr, len(test_data))
        second = await bridge.read_memory(addr, len(test_data))
        third = await bridge.read_memory(addr, len(test_data))
    finally:
        setattr(ctypes.windll.kernel32, "OpenProcess", saved_open)
        release: object = getattr(bridge, _RELEASE_HANDLES_ATTR)
        cast("Callable[[], None]", release)()

    assert first == test_data
    assert second == test_data
    assert third == test_data
    assert open_count == 1


def test_release_process_handles_empties_cache() -> None:
    """F-0010: ``_release_process_handles`` closes and forgets every handle."""
    if sys.platform != "win32":
        pytest.skip("Windows only")

    import ctypes  # noqa: PLC0415
    import os  # noqa: PLC0415

    bridge = X64DbgBridge()
    bridge.attached_pid = os.getpid()

    get_handle: object = getattr(bridge, _GET_CACHED_HANDLE_ATTR)
    handle = cast("Callable[[int], int]", get_handle)(_PROCESS_VM_OPERATION)
    assert handle != 0

    handles_attr: object = getattr(bridge, _PROCESS_HANDLES_ATTR)
    handles = cast("dict[int, int]", handles_attr)
    assert handles[_PROCESS_VM_OPERATION] == handle

    closed: list[int] = []
    saved_close = ctypes.windll.kernel32.CloseHandle

    def counting_close(h: int) -> int:
        closed.append(h)
        return cast("int", saved_close(h))

    setattr(ctypes.windll.kernel32, "CloseHandle", counting_close)
    try:
        release: object = getattr(bridge, _RELEASE_HANDLES_ATTR)
        cast("Callable[[], None]", release)()
    finally:
        setattr(ctypes.windll.kernel32, "CloseHandle", saved_close)

    assert handle in closed
    handles_after: object = getattr(bridge, _PROCESS_HANDLES_ATTR)
    assert cast("dict[int, int]", handles_after) == {}


@pytest.mark.asyncio
async def test_detach_releases_cached_handles() -> None:
    """F-0010: ``detach`` releases the per-handle cache.

    Sets up a stand-in subprocess holder and a fake pipe so the
    detach control flow runs end-to-end without a live x64dbg, then
    asserts the per-handle cache is emptied so a follow-up attachment
    opens a fresh handle.
    """
    if sys.platform != "win32":
        pytest.skip("Windows only")

    import os  # noqa: PLC0415

    bridge = X64DbgBridge()
    fake = _attach_fake_pipe_d(bridge)
    fake.queue_response("exec", {"success": True, "result": ""})

    class _StubProcess:
        """Minimal ``Popen`` stand-in so ``_send_command`` does not bail.

        Attributes:
            pid: Process identifier exposed by ``debugger_pid``.
        """

        pid: int = -1

    setattr(bridge, "_process", cast("Any", _StubProcess()))
    bridge.attached_pid = os.getpid()

    get_handle: object = getattr(bridge, _GET_CACHED_HANDLE_ATTR)
    cast("Callable[[int], int]", get_handle)(_PROCESS_VM_OPERATION)
    handles_attr: object = getattr(bridge, _PROCESS_HANDLES_ATTR)
    assert cast("dict[int, int]", handles_attr), "cache should be populated"

    await bridge.detach()
    handles_after: object = getattr(bridge, _PROCESS_HANDLES_ATTR)
    assert cast("dict[int, int]", handles_after) == {}


# ---------------------------------------------------------------------------
# X64DBG-E tests: F-0005, F-0019, F-0020, F-0021, F-0022
# ---------------------------------------------------------------------------


def _build_region(base: int, size: int) -> MemoryRegion:
    """Construct a readable committed memory region.

    Args:
        base: Region base address.
        size: Region size in bytes.

    Returns:
        MemoryRegion: A readable committed region.
    """
    return MemoryRegion(
        base_address=base,
        size=size,
        protection="r",
        state="committed",
        type="private",
        module_name=None,
    )


@pytest.mark.asyncio
class TestFindPatternWildcardStreaming:
    """F-0005: wildcard ``find_pattern`` must stream the entire region."""

    async def test_wildcard_match_beyond_first_chunk(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Wildcard matches at offsets > MAX_MEMORY_READ_SIZE must be returned.

        Constructs a 3 MiB virtual region with the marker
        ``DE AD BE EF`` placed at offset ``MAX_MEMORY_READ_SIZE +
        0x100`` so the no-streaming implementation would silently miss
        it.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture used to inject
                deterministic memory regions and reads.
        """
        marker = b"\xde\xad\xbe\xef"
        match_offset = MAX_MEMORY_READ_SIZE + 0x100
        region_size = MAX_MEMORY_READ_SIZE * 3
        backing = bytearray(region_size)
        backing[match_offset : match_offset + len(marker)] = marker

        async def fake_get_memory_regions() -> list[MemoryRegion]:
            await asyncio.sleep(0)
            return [_build_region(_REGION_BASE, region_size)]

        async def fake_read_memory(address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            offset = address - _REGION_BASE
            if offset < 0 or offset >= region_size:
                msg = f"out of bounds read at {hex(address)}"
                raise ToolError(msg)
            return bytes(backing[offset : offset + size])

        monkeypatch.setattr(bridge, "get_memory_regions", fake_get_memory_regions)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        results = await bridge.find_pattern("DE ?? BE EF")
        offsets = [int(r["offset"]) for r in results]
        assert _REGION_BASE + match_offset in offsets, (
            f"wildcard match at {hex(_REGION_BASE + match_offset)} missed; got {[hex(o) for o in offsets]}"
        )

    async def test_wildcard_match_across_chunk_boundary(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Wildcard match straddling the chunk boundary must be found.

        Places ``DE AD BE EF CA FE`` so that the first two bytes are at
        the end of the first ``MAX_MEMORY_READ_SIZE`` chunk and the
        remaining four are at the start of the second chunk. Without
        rolling overlap the streaming scanner would split the match
        across two read buffers and miss it.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        marker = b"\xde\xad\xbe\xef\xca\xfe"
        boundary = MAX_MEMORY_READ_SIZE
        match_offset = boundary - 2
        region_size = MAX_MEMORY_READ_SIZE * 2
        backing = bytearray(region_size)
        backing[match_offset : match_offset + len(marker)] = marker

        async def fake_get_memory_regions() -> list[MemoryRegion]:
            await asyncio.sleep(0)
            return [_build_region(_REGION_BASE, region_size)]

        async def fake_read_memory(address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            offset = address - _REGION_BASE
            return bytes(backing[offset : offset + size])

        monkeypatch.setattr(bridge, "get_memory_regions", fake_get_memory_regions)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        results = await bridge.find_pattern("DE AD ?? EF CA FE")
        offsets = [int(r["offset"]) for r in results]
        assert _REGION_BASE + match_offset in offsets, f"cross-boundary wildcard match at {hex(_REGION_BASE + match_offset)} missed"


@pytest.mark.asyncio
class TestRecursiveResourceWalker:
    """F-0019: ``get_resources`` must recurse through Type/Name/Language."""

    async def test_recursive_walk_emits_leaves_with_size_and_rva(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Build a minimal three-level resource tree and verify all leaves.

        Type RT_VERSION (16) -> Id 1 -> Lang 0x0409 -> DataEntry of
        size 0x40 at RVA 0x2000.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        resource_data = self._build_three_level_resource()
        pe_blob = self._build_pe_with_rsrc_directory(_RSRC_RVA, len(resource_data))

        async def fake_resolve(_module_name: str) -> int:
            await asyncio.sleep(0)
            return _MODULE_BASE

        async def fake_read_pe_header(
            _base: int,
            _module: str,
            size: int = 256,
        ) -> tuple[int, bytes]:
            await asyncio.sleep(0)
            return 0, pe_blob[:size]

        async def fake_read_memory(address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            if address == _MODULE_BASE + _RSRC_RVA:
                return resource_data[:size]
            msg = f"unexpected read at {hex(address)}"
            raise ToolError(msg)

        monkeypatch.setattr(bridge, "_resolve_module_base", fake_resolve)
        monkeypatch.setattr(bridge, "_read_pe_header", fake_read_pe_header)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        result = await bridge.get_resources("test.dll")
        assert len(result) == 1, f"expected one leaf, got {result!r}"
        leaf = result[0]
        assert leaf["type_id"] == 16
        assert leaf["type_name"] == "RT_VERSION"
        assert leaf["id"] == 1
        assert leaf["language"] == 0x0409
        assert leaf["size"] == 0x40
        assert int(leaf["rva"], 16) == _MODULE_BASE + 0x2000

    async def test_multiple_leaves(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify multi-leaf and multi-language enumeration.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        resource_data = self._build_multi_leaf_resource()
        pe_blob = self._build_pe_with_rsrc_directory(_RSRC_RVA, len(resource_data))

        async def fake_resolve(_module_name: str) -> int:
            await asyncio.sleep(0)
            return _MODULE_BASE

        async def fake_read_pe_header(
            _base: int,
            _module: str,
            size: int = 256,
        ) -> tuple[int, bytes]:
            await asyncio.sleep(0)
            return 0, pe_blob[:size]

        async def fake_read_memory(_address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            return resource_data[:size]

        monkeypatch.setattr(bridge, "_resolve_module_base", fake_resolve)
        monkeypatch.setattr(bridge, "_read_pe_header", fake_read_pe_header)
        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        result = await bridge.get_resources("test.dll")
        assert len(result) == 3, f"expected three leaves, got {len(result)}: {result!r}"
        keys_present = {(r["type_id"], r["id"], r["language"]) for r in result}
        assert (24, 1, 0x0409) in keys_present
        assert (10, 100, 0x0409) in keys_present
        assert (10, 100, 0x0407) in keys_present

    @staticmethod
    def _build_three_level_resource() -> bytes:
        """Build a minimal IMAGE_RESOURCE_DIRECTORY tree (Type/Id/Lang) with one leaf.

        Returns:
            bytes: Resource section bytes.
        """
        blob = bytearray(0x200)
        struct.pack_into("<IIHHHH", blob, 0, 0, 0, 0, 0, 0, 1)
        type_dir_offset = 0x40
        struct.pack_into("<II", blob, 16, 16, 0x80000000 | type_dir_offset)

        struct.pack_into("<IIHHHH", blob, type_dir_offset, 0, 0, 0, 0, 0, 1)
        id_dir_offset = 0x80
        struct.pack_into(
            "<II",
            blob,
            type_dir_offset + 16,
            1,
            0x80000000 | id_dir_offset,
        )

        struct.pack_into("<IIHHHH", blob, id_dir_offset, 0, 0, 0, 0, 0, 1)
        leaf_offset = 0xC0
        struct.pack_into("<II", blob, id_dir_offset + 16, 0x0409, leaf_offset)

        struct.pack_into("<IIII", blob, leaf_offset, 0x2000, 0x40, 0, 0)
        return bytes(blob)

    @staticmethod
    def _build_multi_leaf_resource() -> bytes:
        """Build a resource tree with three leaves across two types and two languages.

        Returns:
            bytes: Resource section bytes.
        """
        blob = bytearray(0x400)
        struct.pack_into("<IIHHHH", blob, 0, 0, 0, 0, 0, 0, 2)
        manifest_dir = 0x40
        rcdata_dir = 0x80
        struct.pack_into("<II", blob, 16, 24, 0x80000000 | manifest_dir)
        struct.pack_into("<II", blob, 24, 10, 0x80000000 | rcdata_dir)

        struct.pack_into("<IIHHHH", blob, manifest_dir, 0, 0, 0, 0, 0, 1)
        manifest_lang_dir = 0xC0
        struct.pack_into(
            "<II",
            blob,
            manifest_dir + 16,
            1,
            0x80000000 | manifest_lang_dir,
        )
        struct.pack_into("<IIHHHH", blob, manifest_lang_dir, 0, 0, 0, 0, 0, 1)
        manifest_leaf = 0x180
        struct.pack_into("<II", blob, manifest_lang_dir + 16, 0x0409, manifest_leaf)
        struct.pack_into("<IIII", blob, manifest_leaf, 0x3000, 0x80, 0, 0)

        struct.pack_into("<IIHHHH", blob, rcdata_dir, 0, 0, 0, 0, 0, 1)
        rcdata_lang_dir = 0x100
        struct.pack_into(
            "<II",
            blob,
            rcdata_dir + 16,
            100,
            0x80000000 | rcdata_lang_dir,
        )
        struct.pack_into("<IIHHHH", blob, rcdata_lang_dir, 0, 0, 0, 0, 0, 2)
        rc_leaf_a = 0x1A0
        rc_leaf_b = 0x1C0
        struct.pack_into("<II", blob, rcdata_lang_dir + 16, 0x0409, rc_leaf_a)
        struct.pack_into("<II", blob, rcdata_lang_dir + 24, 0x0407, rc_leaf_b)
        struct.pack_into("<IIII", blob, rc_leaf_a, 0x4000, 0x100, 0, 0)
        struct.pack_into("<IIII", blob, rc_leaf_b, 0x5000, 0x120, 0, 0)
        return bytes(blob)

    @staticmethod
    def _build_pe_with_rsrc_directory(rsrc_rva: int, rsrc_size: int) -> bytes:
        """Build a PE32+ header with the resource data directory pointing at our blob.

        The PE32+ optional header places data directories at offset
        0x88 from the start of the optional header. The 3rd entry
        (index 2) is the resource directory.

        Args:
            rsrc_rva: Resource directory RVA to embed.
            rsrc_size: Resource directory size to embed.

        Returns:
            bytes: PE header bytes large enough for the resource directory entry.
        """
        header = bytearray(0x200)
        header[:4] = b"PE\x00\x00"
        struct.pack_into("<H", header, 4, 0x8664)
        opt_off = 24
        struct.pack_into("<H", header, opt_off, 0x020B)
        rsrc_dir_off = opt_off + 0x70 + 2 * 8
        struct.pack_into("<II", header, rsrc_dir_off, rsrc_rva, rsrc_size)
        return bytes(header)


@pytest.mark.asyncio
class TestExportNoCap:
    """F-0020: ``_build_export_entries`` must not silently truncate."""

    async def test_no_truncation_above_pe_export_max(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Exports above PE_EXPORT_MAX must still be returned.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        num_names = PE_EXPORT_MAX + 50
        addr_table = bytes(b"\x00\x00\x00\x00" * num_names)
        name_ptrs = b"".join(struct.pack("<I", 0x10000 + i) for i in range(num_names))
        ordinal_table = b"".join(struct.pack("<H", i) for i in range(num_names))
        ordinal_base = 1
        num_functions = num_names

        captured_names: list[str] = []

        async def fake_read_export_name(
            _base: int,
            name_rva: int,
            ordinal: int,
            _module: str,
        ) -> tuple[str, ToolError | None]:
            await asyncio.sleep(0)
            name = f"export_{name_rva - 0x10000}_{ordinal}"
            captured_names.append(name)
            return name, None

        monkeypatch.setattr(bridge, "_read_export_name", fake_read_export_name)

        tables = (addr_table, name_ptrs, ordinal_table, num_names, ordinal_base, num_functions)
        build = getattr(bridge, "_build_export_entries")
        exports, last_error = await build(_MODULE_BASE, "test.dll", tables)
        assert last_error is None
        assert len(exports) == num_names, f"export list truncated: {len(exports)} != {num_names}"
        assert exports[PE_EXPORT_MAX]["ordinal"] == ordinal_base + PE_EXPORT_MAX
        assert exports[-1]["ordinal"] == ordinal_base + num_names - 1


@pytest.mark.asyncio
class TestEntropyChunkedReads:
    """F-0021: ``analyze_entropy`` must read each block independently."""

    async def test_partial_results_when_some_blocks_unreadable(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Verify a single bad page does not abort the whole scan.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        block_size = 256
        total_size = block_size * 5
        bad_block_index = 2

        async def fake_read_memory(address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            block_idx = (address - _REGION_BASE) // block_size
            if block_idx == bad_block_index:
                msg = f"ReadProcessMemory failed at {hex(address)}"
                raise ToolError(msg)
            return bytes([block_idx & 0xFF] * size)

        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        result = await bridge.analyze_entropy(_REGION_BASE, total_size, block_size)
        assert len(result) == 5
        for i, block in enumerate(result):
            if i == bad_block_index:
                assert block["readable"] is False
                assert "error" in block
            else:
                assert block["readable"] is True
                assert abs(float(block["entropy"])) < 1e-9
                assert block["size"] == block_size

    async def test_large_region_chunked_calls(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each block must trigger an individual ``read_memory`` call.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        block_size = 1024
        block_count = 8
        total_size = block_size * block_count
        call_count = {"n": 0}

        async def fake_read_memory(_address: int, size: int) -> bytes:
            await asyncio.sleep(0)
            call_count["n"] += 1
            return bytes(size)

        monkeypatch.setattr(bridge, "read_memory", fake_read_memory)

        result = await bridge.analyze_entropy(_REGION_BASE, total_size, block_size)
        assert len(result) == block_count
        assert call_count["n"] == block_count, f"expected {block_count} block reads, got {call_count['n']}"

    async def test_invalid_block_size_raises(self, bridge: X64DbgBridge) -> None:
        """Non-positive block_size must raise ToolError.

        Args:
            bridge: Fresh bridge instance.
        """
        with pytest.raises(ToolError, match="block_size must be positive"):
            await bridge.analyze_entropy(_REGION_BASE, 1024, 0)


@pytest.mark.asyncio
class TestApiBreakpointResolution:
    """F-0022: ``set_breakpoint_on_api`` must resolve VA before installing bp."""

    async def test_resolves_via_get_proc_address(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When GetProcAddress yields non-zero, set_breakpoint must be called.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """
        resolved_va = 0x7FFEDEADBEEF

        async def fake_eval(expression: str) -> int:
            await asyncio.sleep(0)
            assert "GetProcAddress" in expression
            assert "kernel32" in expression
            assert "CreateFileW" in expression
            return resolved_va

        captured_bp: dict[str, int | str] = {}

        async def fake_set_breakpoint(address: int, bp_type: str = "software") -> int:
            await asyncio.sleep(0)
            captured_bp["address"] = address
            captured_bp["type"] = bp_type
            return 42

        monkeypatch.setattr(bridge, "evaluate_expression", fake_eval)
        monkeypatch.setattr(bridge, "set_breakpoint", fake_set_breakpoint)

        result = await bridge.set_breakpoint_on_api("kernel32", "CreateFileW")
        assert result["success"] is True
        assert result["resolution_method"] == "GetProcAddress"
        assert result["resolved_address"] == hex(resolved_va)
        assert result["breakpoint_id"] == 42
        assert captured_bp["address"] == resolved_va
        assert captured_bp["type"] == "software"

    async def test_falls_back_to_bpx_when_unresolved(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When GetProcAddress returns 0 the historical bpx path must run.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """

        async def fake_eval(_expression: str) -> int:
            await asyncio.sleep(0)
            return 0

        sent_commands: list[tuple[str, dict[str, object] | None]] = []

        async def fake_send_pipe(
            command: str,
            params: dict[str, object] | None = None,
        ) -> dict[str, object]:
            await asyncio.sleep(0)
            sent_commands.append((command, params))
            return {"success": True}

        called_set_bp = {"n": 0}

        async def fake_set_breakpoint(_address: int, _bp_type: str = "software") -> int:
            await asyncio.sleep(0)
            called_set_bp["n"] += 1
            return 1

        monkeypatch.setattr(bridge, "evaluate_expression", fake_eval)
        monkeypatch.setattr(bridge, "_send_pipe_command", fake_send_pipe)
        monkeypatch.setattr(bridge, "set_breakpoint", fake_set_breakpoint)

        result = await bridge.set_breakpoint_on_api("ntdll", "RtlExitUserProcess")
        assert result["success"] is True
        assert result["resolution_method"] == "bpx"
        assert result["resolved_address"] is None
        assert called_set_bp["n"] == 0, "set_breakpoint must not run when address is 0"
        assert len(sent_commands) > 0
        first_cmd, first_params = sent_commands[0]
        assert first_cmd == "exec"
        assert first_params is not None
        assert first_params["command"] == "bpx ntdll.RtlExitUserProcess"

    async def test_falls_back_when_eval_raises(
        self,
        bridge: X64DbgBridge,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When evaluate_expression raises ToolError, bpx fallback runs.

        Args:
            bridge: Fresh bridge instance.
            monkeypatch: Pytest monkeypatch fixture.
        """

        async def fake_eval(_expression: str) -> int:
            await asyncio.sleep(0)
            msg = "expression evaluation failed"
            raise ToolError(msg)

        sent_commands: list[str] = []

        async def fake_send_pipe(
            _command: str,
            params: dict[str, object] | None = None,
        ) -> dict[str, object]:
            await asyncio.sleep(0)
            if params is not None:
                cmd_str = params.get("command")
                if isinstance(cmd_str, str):
                    sent_commands.append(cmd_str)
            return {"success": True}

        monkeypatch.setattr(bridge, "evaluate_expression", fake_eval)
        monkeypatch.setattr(bridge, "_send_pipe_command", fake_send_pipe)

        result = await bridge.set_breakpoint_on_api("user32", "MessageBoxW")
        assert result["resolution_method"] == "bpx"
        assert result["resolved_address"] is None
        assert sent_commands == ["bpx user32.MessageBoxW"]


# =====================================================================
# X64DBG-A regression tests (lifecycle / subprocess / platform).
# Helpers are suffixed ``_a`` to avoid collisions with the X64DBG-B/C/D/E
# helpers above. The classes target one finding each as documented in
# the module docstring.
# =====================================================================


_AWAIT_STEP_ATTR_A = "_await_step_complete"
_DETECT_ARCH_ATTR_A = "_detect_architecture"
_DETECT_PROCESS_ARCH_ATTR_A = "_detect_process_arch"
_WAIT_FOR_PIPE_ATTR_A = "_wait_for_pipe_ready"
_START_DEBUGGER_ATTR_A = "_start_debugger"
_REGISTER_STEP_WAITER_ATTR_A = "_register_step_waiter"
_CANCEL_STEP_WAITER_ATTR_A = "_cancel_step_waiter"
_X64DBG_PATH_ATTR_A = "_x64dbg_path"
_PLUGIN_DEPLOYED_ATTR_A = "_plugin_deployed"
_IS_64BIT_ATTR_A = "_is_64bit"
_ATTACHED_PID_ATTR_A = "_attached_pid"
_PROCESS_ATTR_A = "_process"
_STEP_WAITERS_ATTR_A = "_step_waiters"
_PE_HEADER_OFFSET_A = 0x3C
_DEFAULT_PE_OFFSET_A = 0x80
_PE_SIGNATURE_LEN_A = 4
_TEST_PID_A = 4242
_FAKE_IP_A = 0xDEADBEEF
_X86_TRUNCATED_IP_A = 0xCAFEBABE & 0xFFFFFFFF


def _build_pe_bytes_a(machine: int, *, e_lfanew: int = _DEFAULT_PE_OFFSET_A) -> bytes:
    """Synthesize a minimal PE file with a chosen ``Machine`` value.

    Args:
        machine: ``IMAGE_FILE_MACHINE_*`` value to embed in the COFF
            header.
        e_lfanew: Offset to the PE signature inside the buffer.

    Returns:
        bytes: A PE-formatted byte string just large enough to satisfy
        ``X64DbgBridge._detect_architecture``.
    """
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, _PE_HEADER_OFFSET_A, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, e_lfanew + 4, machine)
    return bytes(buf)


async def _await_step_a(bridge: X64DbgBridge, command: str) -> int:
    """Invoke the bridge's protected step-await coroutine.

    Args:
        bridge: Bridge instance.
        command: One of ``step_into`` / ``step_over`` / ``step_out``.

    Returns:
        int: The post-step instruction pointer the bridge resolved.
    """
    raw_attr: object = getattr(bridge, _AWAIT_STEP_ATTR_A)
    coro = cast("Callable[[str], Any]", raw_attr)
    return cast("int", await coro(command))


def _detect_architecture_a(path: Path) -> bool:
    """Invoke ``X64DbgBridge._detect_architecture`` via dynamic attribute lookup.

    Args:
        path: Path to the binary whose architecture should be detected.

    Returns:
        bool: ``True`` for x64, ``False`` for x86.
    """
    raw_attr: object = getattr(X64DbgBridge, _DETECT_ARCH_ATTR_A)
    func = cast("Callable[[Path], bool]", raw_attr)
    return func(path)


def _detect_process_arch_a(pid: int) -> bool | None:
    """Invoke ``X64DbgBridge._detect_process_arch`` via dynamic attribute lookup.

    Args:
        pid: Process identifier.

    Returns:
        bool | None: ``True``/``False`` for resolved arch, ``None`` when unknown.
    """
    raw_attr: object = getattr(X64DbgBridge, _DETECT_PROCESS_ARCH_ATTR_A)
    func = cast("Callable[[int], bool | None]", raw_attr)
    return func(pid)


async def _wait_for_pipe_ready_a(bridge: X64DbgBridge) -> None:
    """Invoke ``bridge._wait_for_pipe_ready`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.
    """
    raw_attr: object = getattr(bridge, _WAIT_FOR_PIPE_ATTR_A)
    coro = cast("Callable[[], Any]", raw_attr)
    await coro()


async def _start_debugger_a(bridge: X64DbgBridge, *, is_64bit: bool) -> None:
    """Invoke ``bridge._start_debugger`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.
        is_64bit: Whether to launch the x64dbg variant (vs x32dbg).
    """
    raw_attr: object = getattr(bridge, _START_DEBUGGER_ATTR_A)
    coro = cast("Callable[..., Any]", raw_attr)
    await coro(is_64bit=is_64bit)


def _register_step_waiter_a(bridge: X64DbgBridge) -> asyncio.Future[int]:
    """Invoke ``bridge._register_step_waiter`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.

    Returns:
        asyncio.Future[int]: The newly registered step-completion future.
    """
    raw_attr: object = getattr(bridge, _REGISTER_STEP_WAITER_ATTR_A)
    func = cast("Callable[[], asyncio.Future[int]]", raw_attr)
    return func()


def _cancel_step_waiter_a(bridge: X64DbgBridge, future: asyncio.Future[int]) -> None:
    """Invoke ``bridge._cancel_step_waiter`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.
        future: Step-completion future returned by ``_register_step_waiter``.
    """
    raw_attr: object = getattr(bridge, _CANCEL_STEP_WAITER_ATTR_A)
    func = cast("Callable[[asyncio.Future[int]], None]", raw_attr)
    func(future)


def _step_waiters_a(bridge: X64DbgBridge) -> list[asyncio.Future[int]]:
    """Read ``bridge._step_waiters`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.

    Returns:
        list[asyncio.Future[int]]: The bridge's current step-waiter list.
    """
    raw_attr: object = getattr(bridge, _STEP_WAITERS_ATTR_A)
    return cast("list[asyncio.Future[int]]", raw_attr)


def _attached_pid_a(bridge: X64DbgBridge) -> int | None:
    """Read ``bridge._attached_pid`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.

    Returns:
        int | None: The attached PID, or ``None`` when not attached.
    """
    raw_attr: object = getattr(bridge, _ATTACHED_PID_ATTR_A)
    return cast("int | None", raw_attr)


def _process_a(bridge: X64DbgBridge) -> object:
    """Read ``bridge._process`` via dynamic attribute lookup.

    Args:
        bridge: Bridge instance.

    Returns:
        object: The currently bound process object (or ``None``).
    """
    return getattr(bridge, _PROCESS_ATTR_A)


class _FakeRegistersA:
    """Stand-in for the registers dataclass used in step tests."""

    def __init__(self, rip: int) -> None:
        """Initialize with a chosen instruction pointer.

        Args:
            rip: Instruction pointer to expose as ``self.rip``.
        """
        self.rip = rip


class TestArchitectureTriState:
    """F-0023 - ``_detect_architecture`` rejects unsupported PE inputs."""

    @staticmethod
    def test_pe64_machine_returns_true(tmp_path: Path) -> None:
        """An AMD64 PE returns ``True`` (use x64dbg).

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "amd64.exe"
        path.write_bytes(_build_pe_bytes_a(PE64_MACHINE))
        assert _detect_architecture_a(path) is True

    @staticmethod
    def test_pe32_machine_returns_false(tmp_path: Path) -> None:
        """An i386 PE returns ``False`` (use x32dbg).

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "i386.exe"
        path.write_bytes(_build_pe_bytes_a(PE32_MACHINE))
        assert _detect_architecture_a(path) is False

    @staticmethod
    def test_arm64_machine_raises(tmp_path: Path) -> None:
        """An ARM64 PE raises ``ToolError`` instead of returning False.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "arm64.exe"
        path.write_bytes(_build_pe_bytes_a(0xAA64))
        with pytest.raises(ToolError, match=r"Machine|architecture"):
            _detect_architecture_a(path)

    @staticmethod
    def test_arm_machine_raises(tmp_path: Path) -> None:
        """An ARM PE raises ``ToolError``.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "arm.exe"
        path.write_bytes(_build_pe_bytes_a(0x01C0))
        with pytest.raises(ToolError):
            _detect_architecture_a(path)

    @staticmethod
    def test_ia64_machine_raises(tmp_path: Path) -> None:
        """An IA64 PE raises ``ToolError``.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "ia64.exe"
        path.write_bytes(_build_pe_bytes_a(0x0200))
        with pytest.raises(ToolError):
            _detect_architecture_a(path)

    @staticmethod
    def test_missing_mz_raises(tmp_path: Path) -> None:
        """A buffer without ``MZ`` raises rather than defaulting to 64-bit.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "junk.exe"
        path.write_bytes(b"NO" + b"\x00" * 256)
        with pytest.raises(ToolError, match=r"MZ|architecture"):
            _detect_architecture_a(path)

    @staticmethod
    def test_truncated_file_raises(tmp_path: Path) -> None:
        """A buffer too short to hold a DOS header raises.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "tiny.exe"
        path.write_bytes(b"MZ")
        with pytest.raises(ToolError):
            _detect_architecture_a(path)

    @staticmethod
    def test_missing_pe_signature_raises(tmp_path: Path) -> None:
        """A DOS image without a PE signature raises.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        buf = bytearray(0x200)
        buf[0:2] = b"MZ"
        struct.pack_into("<I", buf, _PE_HEADER_OFFSET_A, _DEFAULT_PE_OFFSET_A)
        buf[_DEFAULT_PE_OFFSET_A : _DEFAULT_PE_OFFSET_A + 4] = b"NOPE"
        path = tmp_path / "no_pe.exe"
        path.write_bytes(bytes(buf))
        with pytest.raises(ToolError, match="PE"):
            _detect_architecture_a(path)

    @staticmethod
    def test_io_error_raises(tmp_path: Path) -> None:
        """A missing file raises ``ToolError`` instead of defaulting.

        Args:
            tmp_path: Per-test temp directory provided by pytest.
        """
        path = tmp_path / "does_not_exist.exe"
        with pytest.raises(ToolError):
            _detect_architecture_a(path)


class TestProcessArchTriState:
    """F-0018 - ``_detect_process_arch`` returns tri-state and ``attach`` raises."""

    @staticmethod
    def test_non_windows_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
        """When ``_IS_WIN32`` is False the detector reports None.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(x64dbg_module, "_IS_WIN32", False)
        assert _detect_process_arch_a(_TEST_PID_A) is None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only path")
    @staticmethod
    def test_invalid_pid_returns_none() -> None:
        """An impossible PID yields ``None`` rather than ``True``."""
        bogus_pid = 0x7FFFFFFE
        result = _detect_process_arch_a(bogus_pid)
        assert result is None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only path")
    @staticmethod
    def test_current_process_resolves() -> None:
        """The current process resolves to a concrete bool, not ``None``."""
        result = _detect_process_arch_a(os.getpid())
        assert result in {True, False}

    @staticmethod
    def test_attach_raises_when_arch_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
        """``attach`` surfaces a ``ToolError`` instead of guessing 64-bit.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = X64DbgBridge()

        def _stub_detect(_pid: int) -> bool | None:
            return None

        monkeypatch.setattr(X64DbgBridge, "_detect_process_arch", staticmethod(_stub_detect))
        with pytest.raises(ToolError, match="cannot detect architecture"):
            asyncio.run(bridge.attach(_TEST_PID_A))


class TestPipeReadyPlatformRefusal:
    """F-0017 - non-Windows path raises rather than sleeping."""

    @staticmethod
    def test_non_windows_raises(monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-Windows ``_wait_for_pipe_ready`` raises ``ToolError``.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(x64dbg_module, "_IS_WIN32", False)
        bridge = X64DbgBridge()

        async def runner() -> None:
            await _wait_for_pipe_ready_a(bridge)

        with pytest.raises(ToolError, match="Windows"):
            asyncio.run(runner())

    @staticmethod
    def test_non_windows_does_not_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
        """The non-Windows path raises before any sleep occurs.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        monkeypatch.setattr(x64dbg_module, "_IS_WIN32", False)
        bridge = X64DbgBridge()
        sleep_called = False
        original_sleep = asyncio.sleep

        async def tracking_sleep(seconds: float) -> None:
            nonlocal sleep_called
            sleep_called = True
            await original_sleep(seconds)

        monkeypatch.setattr(asyncio, "sleep", tracking_sleep)

        async def runner() -> None:
            with contextlib.suppress(ToolError):
                await _wait_for_pipe_ready_a(bridge)

        asyncio.run(runner())
        assert sleep_called is False


class TestSubprocessStreamDrain:
    """F-0015 - ``Popen`` is called with ``DEVNULL`` for std streams."""

    @staticmethod
    def test_popen_uses_devnull(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """Recorded ``Popen`` invocation requests DEVNULL for stdout/stderr.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: Per-test temp directory provided by pytest.
        """
        bridge = X64DbgBridge()
        setattr(bridge, _X64DBG_PATH_ATTR_A, tmp_path)
        setattr(bridge, _PLUGIN_DEPLOYED_ATTR_A, True)
        x64_dir = tmp_path / "release" / "x64"
        x64_dir.mkdir(parents=True)
        exe_path = x64_dir / "x64dbg.exe"
        exe_path.write_bytes(b"\x00")

        captured: dict[str, Any] = {}

        class _DummyProcess:
            def __init__(self) -> None:
                self.pid = 0xC0FFEE

            def terminate(self) -> None:
                pass

            def wait(self) -> int:
                return 0

        def fake_popen(args: object, **kwargs: object) -> _DummyProcess:
            captured["args"] = args
            captured["kwargs"] = kwargs
            return _DummyProcess()

        monkeypatch.setattr(x64dbg_module, "Popen", fake_popen)
        monkeypatch.setattr(x64dbg_module, "_IS_WIN32", True)

        async def fake_wait(_self: X64DbgBridge) -> None:
            await asyncio.sleep(0)

        monkeypatch.setattr(X64DbgBridge, "_wait_for_pipe_ready", fake_wait)

        async def runner() -> None:
            await _start_debugger_a(bridge, is_64bit=True)

        asyncio.run(runner())

        assert captured["kwargs"].get("stdout") is x64dbg_module.DEVNULL
        assert captured["kwargs"].get("stderr") is x64dbg_module.DEVNULL
        assert captured["kwargs"].get("stdin") is x64dbg_module.DEVNULL


class TestPluginRequiredStartGate:
    """F-0013 - ``_start_debugger`` refuses without the plugin."""

    @staticmethod
    def test_refuses_when_plugin_not_deployed(
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """``_start_debugger`` raises before spawning x64dbg.exe.

        Sets up a working directory with a real ``x64dbg.exe`` file
        present so the previous behaviour (spawn first, fail at the
        first RPC call) would have proceeded to ``Popen``. The fix
        gates on ``_plugin_deployed`` and must therefore raise a
        plugin-related ``ToolError`` instead.

        Args:
            monkeypatch: pytest monkeypatch fixture.
            tmp_path: Per-test temp directory provided by pytest.
        """
        bridge = X64DbgBridge()
        setattr(bridge, _X64DBG_PATH_ATTR_A, tmp_path)
        setattr(bridge, _PLUGIN_DEPLOYED_ATTR_A, False)
        x64_dir = tmp_path / "release" / "x64"
        x64_dir.mkdir(parents=True)
        exe_path = x64_dir / "x64dbg.exe"
        exe_path.write_bytes(b"\x00")

        popen_called = False

        def fake_popen(*_args: object, **_kwargs: object) -> object:
            nonlocal popen_called
            popen_called = True
            msg = "Popen must not be invoked when plugin is not deployed"
            raise AssertionError(msg)

        monkeypatch.setattr(x64dbg_module, "Popen", fake_popen)
        monkeypatch.setattr(x64dbg_module, "_IS_WIN32", True)

        async def runner() -> None:
            await _start_debugger_a(bridge, is_64bit=True)

        with pytest.raises(ToolError, match="plugin"):
            asyncio.run(runner())

        assert popen_called is False
        assert _process_a(bridge) is None


class TestShutdownTryFinally:
    """F-0011 - shutdown reaches every cleanup phase even on early failure."""

    @staticmethod
    def test_close_connection_failure_still_terminates_process(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A raise from ``_close_connection`` still terminates the process.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = X64DbgBridge()
        setattr(bridge, _ATTACHED_PID_ATTR_A, 1234)

        terminate_called = threading.Event()
        wait_called = threading.Event()

        class _RaisingProcess:
            def __init__(self) -> None:
                self.pid = 0xBADC0DE

            def terminate(self) -> None:
                terminate_called.set()

            def wait(self) -> int:
                wait_called.set()
                return 0

            def kill(self) -> None:
                pass

        setattr(bridge, _PROCESS_ATTR_A, _RaisingProcess())

        async def raising_close(_self: X64DbgBridge) -> None:
            await asyncio.sleep(0)
            msg = "induced close failure"
            raise ToolError(msg)

        monkeypatch.setattr(X64DbgBridge, "_close_connection", raising_close)

        unregistered: list[int] = []

        class _FakeManager:
            def unregister(self, pid: int) -> None:
                unregistered.append(pid)

        def _stub_get_instance(_cls: type[Any]) -> _FakeManager:
            return _FakeManager()

        monkeypatch.setattr(
            x64dbg_module.ProcessManager,
            "get_instance",
            classmethod(_stub_get_instance),
        )

        async def runner() -> None:
            await bridge.shutdown()

        with pytest.raises(ToolError, match="induced close failure"):
            asyncio.run(runner())

        assert terminate_called.is_set(), "terminate must run after close failure"
        assert wait_called.is_set(), "wait must run after terminate"
        assert unregistered == [0xBADC0DE], "process manager must be informed of cleanup"
        assert _attached_pid_a(bridge) is None
        assert _process_a(bridge) is None


class TestStepEventSync:
    """F-0004 - step coroutines wait on the paused event with timeout."""

    @staticmethod
    def test_step_resolves_on_paused_event(monkeypatch: pytest.MonkeyPatch) -> None:
        """A ``paused`` event released from a thread resolves the step.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = X64DbgBridge()
        setattr(bridge, _PLUGIN_DEPLOYED_ATTR_A, True)
        setattr(bridge, _IS_64BIT_ATTR_A, True)

        async def fake_send_pipe_command(
            _self: X64DbgBridge,
            _command: str,
            _params: dict[str, Any] | None = None,
        ) -> None:
            await asyncio.sleep(0)

        async def fake_get_registers(_self: X64DbgBridge) -> _FakeRegistersA:
            await asyncio.sleep(0)
            return _FakeRegistersA(_FAKE_IP_A)

        monkeypatch.setattr(X64DbgBridge, "_send_pipe_command", fake_send_pipe_command)
        monkeypatch.setattr(X64DbgBridge, "get_registers", fake_get_registers)

        async def runner() -> int:
            async def emit_pause_after_delay() -> None:
                await asyncio.sleep(0.05)
                _dispatch_event(bridge, {"event": "paused", "address": hex(_FAKE_IP_A)})

            emit_task = asyncio.create_task(emit_pause_after_delay())
            try:
                return await _await_step_a(bridge, "step_into")
            finally:
                await emit_task

        result = asyncio.run(runner())
        assert result == _FAKE_IP_A

    @staticmethod
    def test_step_resolves_on_breakpoint_event(monkeypatch: pytest.MonkeyPatch) -> None:
        """A breakpoint hit also pauses the debuggee and resolves the step.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = X64DbgBridge()
        setattr(bridge, _PLUGIN_DEPLOYED_ATTR_A, True)
        setattr(bridge, _IS_64BIT_ATTR_A, False)

        async def fake_send_pipe_command(
            _self: X64DbgBridge,
            _command: str,
            _params: dict[str, Any] | None = None,
        ) -> None:
            await asyncio.sleep(0)

        async def fake_get_registers(_self: X64DbgBridge) -> _FakeRegistersA:
            await asyncio.sleep(0)
            return _FakeRegistersA(0xCAFEBABE)

        monkeypatch.setattr(X64DbgBridge, "_send_pipe_command", fake_send_pipe_command)
        monkeypatch.setattr(X64DbgBridge, "get_registers", fake_get_registers)

        async def runner() -> int:
            async def emit_breakpoint_after_delay() -> None:
                await asyncio.sleep(0.05)
                _dispatch_event(bridge, {"event": "breakpoint", "address": "0xCAFEBABE"})

            emit_task = asyncio.create_task(emit_breakpoint_after_delay())
            try:
                return await _await_step_a(bridge, "step_over")
            finally:
                await emit_task

        result = asyncio.run(runner())
        assert result == _X86_TRUNCATED_IP_A

    @staticmethod
    def test_step_times_out_when_no_pause_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a paused event the step raises a bounded ``ToolError``.

        Args:
            monkeypatch: pytest monkeypatch fixture.
        """
        bridge = X64DbgBridge()
        setattr(bridge, _PLUGIN_DEPLOYED_ATTR_A, True)
        monkeypatch.setattr(X64DbgBridge, "STEP_TIMEOUT_SECONDS", 0.05)

        async def fake_send_pipe_command(
            _self: X64DbgBridge,
            _command: str,
            _params: dict[str, Any] | None = None,
        ) -> None:
            await asyncio.sleep(0)

        async def unreachable_get_registers(_self: X64DbgBridge) -> _FakeRegistersA:
            await asyncio.sleep(0)
            msg = "get_registers must not be invoked when the step times out"
            raise AssertionError(msg)

        monkeypatch.setattr(X64DbgBridge, "_send_pipe_command", fake_send_pipe_command)
        monkeypatch.setattr(X64DbgBridge, "get_registers", unreachable_get_registers)

        async def runner() -> None:
            await _await_step_a(bridge, "step_into")

        with pytest.raises(ToolError, match="did not complete"):
            asyncio.run(runner())

        assert _step_waiters_a(bridge) == []

    @staticmethod
    def test_step_does_not_use_fixed_sleep() -> None:
        """The step body must not call ``asyncio.sleep`` for a fixed delay."""
        for name in ("step_into", "step_over", "step_out"):
            source = inspect.getsource(getattr(X64DbgBridge, name))
            assert "asyncio.sleep" not in source, f"{name} must not use asyncio.sleep; wait on the paused event instead"

    @staticmethod
    def test_register_step_waiter_returns_future_bound_to_loop() -> None:
        """Sanity-check the protected helper used by all step coroutines."""
        bridge = X64DbgBridge()

        async def runner() -> asyncio.Future[int]:
            await asyncio.sleep(0)
            future = _register_step_waiter_a(bridge)
            assert future in _step_waiters_a(bridge)
            _cancel_step_waiter_a(bridge, future)
            assert future not in _step_waiters_a(bridge)
            return future

        future = asyncio.run(runner())
        assert isinstance(future, asyncio.Future)
