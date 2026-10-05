# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Second-pass coverage tests for the x64dbg bridge: list-shaped plugin replies and failure paths.

x64dbg is not installed where these tests run. Plugin replies the echo pipe server cannot produce
(``bp_list`` lists, ``reg_all`` values, ``unknown_command`` errors, ``status`` payloads) come from
:class:`ScriptedBridge`, a subclass of the real ``X64DbgBridge`` that replaces only the transport seams
(``_send_pipe_command``, ``_send_command`` and the scripted ``read_memory`` addresses). Expectations are
derived independently: the PE specification layouts (packed with ``struct``), the Shannon entropy of 256
equiprobable byte values (8 bits), ``VirtualProtect`` / ``VirtualQuery`` ground truth on a real page,
``LookupPrivilegeValueW`` as the inverse of ``LookupPrivilegeNameW``, ``Toolhelp`` snapshot errors read
back from the operating system, and a real suspended child process.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import os
import struct
import subprocess
import sys
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest

from intellicrack.bridges import x64dbg as x64dbg_mod
from intellicrack.bridges.base import BridgeState, WatchpointInfo
from intellicrack.bridges.win32_types import (
    MEM_COMMIT,
    MEM_RELEASE,
    MEM_RESERVE,
    PAGE_READONLY,
    PAGE_READWRITE,
)
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.session import Session
from intellicrack.core.types import BreakpointInfo, ToolError, ToolName
from intellicrack.core.win32_desktop_process import DesktopProcess, spawn_on_hidden_desktop
from intellicrack.mcp.sandbox_launch import CREATE_SUSPENDED


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Iterator

    from intellicrack.bridges.x64dbg import PipeCommandResult
    from intellicrack.core.types import ModuleInfo


type Reply = PipeCommandResult | ToolError

_SLEEP_CODE = "import time; time.sleep(300)"
_PAGE_SIZE = 0x1000
_WAIT_S = 30.0
_BP_ADDRESS = 0x401000
_PE_OFFSET = 0x80
_PE32PLUS_MAGIC = 0x20B
_PE32PLUS_OPTIONAL_SIZE = 240
_PE32PLUS_DATA_DIRECTORY_START = 24 + 112
_TLS_DIRECTORY_INDEX = 9
_TLS_RVA = 0x3000
_TLS_ARRAY_RVA = 0x4000
_TLS_CALLBACK_RVA = 0x5000
_TLS_DIRECTORY64_SIZE = 40
_MAX_TLS_CALLBACKS = 64
_ENTROPY_BLOCK = 256
_MARKER = b"CRITCOV_R1_MARKER"
_UNNAMED_LUID_LOW = 0x7FFFFFF0
_HELD_PRIVILEGE = "SeChangeNotifyPrivilege"
_SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
_SE_PRIVILEGE_ENABLED = 0x2


class ScriptedBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose pipe and scripted memory reads are answered from data.

    ``pipe_script`` maps a pipe command name to a queue of replies; each call pops the first reply while
    more than one remains and repeats the last one afterwards. A reply that is a ``ToolError`` is raised.
    ``memory_script`` does the same for ``read_memory`` calls at an exact address; unscripted addresses use
    the real ``ReadProcessMemory`` path. Console commands are recorded in ``sent_commands``.
    """

    VERIFY_TIMEOUT = 0.3
    VERIFY_POLL_INTERVAL = 0.02

    def __init__(self) -> None:
        """Create the bridge with empty scripts."""
        super().__init__()
        self.pipe_script: dict[str, list[Reply]] = {}
        self.memory_script: dict[int, list[bytes | ToolError]] = {}
        self.sent_commands: list[str] = []

    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Answer a plugin pipe command from ``pipe_script``.

        Args:
            command: Pipe command name.
            params: Parameters the bridge attached to the command (unused).

        Returns:
            PipeCommandResult: The scripted reply.

        Raises:
            LookupError: If the command has no scripted reply.
            ToolError: If the scripted reply is an error.
        """
        await asyncio.sleep(0)
        queue = self.pipe_script.get(command)
        if queue is None:
            msg = f"unscripted pipe command {command!r} {params!r}"
            raise LookupError(msg)
        reply = queue[0] if len(queue) == 1 else queue.pop(0)
        if isinstance(reply, ToolError):
            raise ToolError(reply.message, tool_name=reply.tool_name, details=dict(reply.details)) from reply
        return reply

    async def _send_command(self, command: str) -> str:
        """Record the console command text instead of sending it.

        Args:
            command: Console command text built by the production code.

        Returns:
            str: Always an empty command output.
        """
        await asyncio.sleep(0)
        self.sent_commands.append(command)
        return ""

    async def read_memory(self, address: int, size: int) -> bytes:
        """Serve a scripted read or fall back to the real process read.

        Args:
            address: Address being read.
            size: Number of bytes requested.

        Returns:
            bytes: Scripted bytes (truncated to ``size``) or the real read result.

        Raises:
            ToolError: If the scripted reply is an error.
        """
        queue = self.memory_script.get(address)
        if queue is None:
            return await super().read_memory(address, size)
        reply = queue[0] if len(queue) == 1 else queue.pop(0)
        if isinstance(reply, ToolError):
            raise ToolError(reply.message, tool_name=reply.tool_name, details=dict(reply.details)) from reply
        return reply[:size]


class DisconnectedBridge(X64DbgBridge):
    """Real bridge whose pipe connect returns while no pipe client exists (the pipe dropped meanwhile)."""

    async def _wait_for_pipe_ready(self) -> None:
        """Report the pipe as ready without waiting."""
        await asyncio.sleep(0)

    async def _connect(self) -> None:
        """Return without establishing a pipe client."""
        await asyncio.sleep(0)


class NoModulesBridge(ScriptedBridge):
    """Scripted bridge whose Toolhelp module enumeration finds no module."""

    async def _get_modules(self) -> list[ModuleInfo]:
        """Report an empty module list.

        Returns:
            list[ModuleInfo]: Always empty.
        """
        await asyncio.sleep(0)
        return []


class TlsFeedBridge(ScriptedBridge):
    """Scripted bridge that reports a fixed list of TLS callbacks to ``break_on_tls_callbacks``."""

    def __init__(self, callbacks: list[dict[str, Any]]) -> None:
        """Create the bridge with the callbacks it will report.

        Args:
            callbacks: TLS callback dicts returned by ``get_tls_callbacks``.
        """
        super().__init__()
        self.callbacks = callbacks
        self.requested_modules: list[str] = []

    async def get_tls_callbacks(self, module_name: str) -> list[dict[str, Any]]:
        """Return the configured callbacks and remember the requested module.

        Args:
            module_name: Module name requested by the caller.

        Returns:
            list[dict[str, Any]]: The configured TLS callback dicts.
        """
        await asyncio.sleep(0)
        self.requested_modules.append(module_name)
        return [dict(callback) for callback in self.callbacks]


class StubbornProcess(DesktopProcess):
    """Real hidden-desktop process whose ``terminate`` is ignored and whose ``kill`` can be made to fail.

    It adopts the state of a genuinely spawned :class:`DesktopProcess`, so every handle, wait and exit-code
    query is the real implementation; only ``terminate`` is a no-op until :meth:`end` is called.
    """

    kill_error: OSError | None

    @classmethod
    def adopt(cls, real: DesktopProcess, kill_error: OSError | None) -> StubbornProcess:
        """Wrap a real process.

        Args:
            real: Freshly spawned process whose state is adopted.
            kill_error: Error ``kill`` raises, or ``None`` to kill for real.

        Returns:
            StubbornProcess: The wrapper sharing the real handles.
        """
        stub = cls.__new__(cls)
        stub.__dict__.update(vars(real))
        stub.kill_error = kill_error
        return stub

    def terminate(self) -> None:
        """Ignore the termination request."""

    def kill(self) -> None:
        """Kill for real, or raise the configured error.

        Raises:
            OSError: When a kill error is configured.
        """
        if self.kill_error is not None:
            raise OSError(*self.kill_error.args) from self.kill_error
        self.end()

    def end(self) -> None:
        """Terminate the process through the real implementation."""
        DesktopProcess.terminate(self)


class ProtectingBridge(ScriptedBridge):
    """Scripted bridge whose ``setpagerights`` console command really re-protects one page of this process."""

    target_page: int = 0
    new_protection: int = PAGE_READONLY

    async def _send_command(self, command: str) -> str:
        """Record the command and apply ``setpagerights`` with the real ``VirtualProtect``.

        Args:
            command: Console command text built by the production code.

        Returns:
            str: Always an empty command output.

        Raises:
            OSError: If ``VirtualProtect`` fails.
        """
        output = await super()._send_command(command)
        if command.startswith("setpagerights"):
            old = wintypes.DWORD(0)
            if not _k32().VirtualProtect(self.target_page, _PAGE_SIZE, self.new_protection, ctypes.byref(old)):
                msg = "VirtualProtect failed"
                raise OSError(ctypes.get_last_error(), msg)
        return output


class _Luid(ctypes.Structure):
    """Windows ``LUID`` layout."""

    _fields_: ClassVar = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


@dataclass
class FaultySession(Session):
    """Real session whose tool-state removal fails the way a corrupted registry would."""

    def clear_tool_state(self, tool: ToolName) -> bool:
        """Fail the removal.

        Args:
            tool: Tool whose state would be cleared (unused).

        Returns:
            bool: Never returns.

        Raises:
            RuntimeError: Always.
        """
        msg = f"session registry corrupted for {tool.value}"
        raise RuntimeError(msg)


def _k32() -> ctypes.WinDLL:
    """Create a ``kernel32`` binding with the entry points used here typed.

    Returns:
        ctypes.WinDLL: Binding with last-error tracking.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.VirtualFree.restype = wintypes.BOOL
    k32.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
    k32.VirtualProtect.restype = wintypes.BOOL
    k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.GetModuleHandleW.restype = wintypes.HMODULE
    k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    return k32


def _method(obj: object, name: str) -> Callable[..., Any]:
    """Fetch a (private) callable attribute by name.

    Args:
        obj: Object or class that carries the member.
        name: Member name.

    Returns:
        Callable[..., Any]: The member typed as a callable.
    """
    return cast("Callable[..., Any]", getattr(obj, name))


def _async_method(obj: object, name: str) -> Callable[..., Awaitable[Any]]:
    """Fetch a (private) coroutine function by name.

    Args:
        obj: Object or class that carries the member.
        name: Member name.

    Returns:
        Callable[..., Awaitable[Any]]: The member typed as an async callable.
    """
    return cast("Callable[..., Awaitable[Any]]", getattr(obj, name))


@contextlib.contextmanager
def _optional_modules_missing(*slots: str) -> Generator[None]:
    """Mark optional third-party modules as not installed for the duration of a block.

    The slots are the bridge module's availability flags (``None`` means the package could not be
    imported); each is restored afterwards.

    Args:
        *slots: Names of the module-level availability slots to clear.

    Yields:
        None: Control while the slots are cleared.
    """
    saved = {slot: getattr(x64dbg_mod, slot) for slot in slots}
    for slot in slots:
        setattr(x64dbg_mod, slot, None)
    try:
        yield
    finally:
        for slot, value in saved.items():
            setattr(x64dbg_mod, slot, value)


@contextlib.contextmanager
def _committed_page(protect: int) -> Generator[int]:
    """Commit one real page with the given protection in this process.

    Args:
        protect: ``PAGE_*`` protection constant for the new page.

    Yields:
        int: Base address of the committed page.
    """
    address = _k32().VirtualAlloc(None, _PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, protect)
    assert address, f"VirtualAlloc failed with error {ctypes.get_last_error()}"
    try:
        yield int(address)
    finally:
        _k32().VirtualFree(address, 0, MEM_RELEASE)


def _unknown_command() -> ToolError:
    """Build the error an older plugin returns for an RPC it does not implement.

    Returns:
        ToolError: Error coded ``unknown_command``.
    """
    return ToolError("unknown command", tool_name="x64dbg", details={"x64dbg_error_code": "unknown_command"})


def _spawn_hidden() -> DesktopProcess:
    """Run a sleeping Python child on a hidden desktop.

    Returns:
        DesktopProcess: The live child.
    """
    return spawn_on_hidden_desktop(Path(sys.executable), ["-c", _SLEEP_CODE])


def _reap_hidden(proc: DesktopProcess) -> None:
    """Terminate, wait for and close a hidden-desktop child.

    Args:
        proc: Process to clean up.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=_WAIT_S)
    finally:
        proc.close()


def _dos_header() -> bytes:
    """Build a 64-byte DOS header whose ``e_lfanew`` is ``_PE_OFFSET``.

    Returns:
        bytes: The DOS header.
    """
    header = bytearray(64)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, _PE_OFFSET)
    return bytes(header)


def _pe64_nt_header(directories: dict[int, tuple[int, int]] | None = None, size: int = 0x200) -> bytes:
    """Build PE32+ NT headers following the PE specification offsets.

    The optional header starts at offset 24 (signature plus 20-byte COFF header), is 112 bytes long
    for PE32+, and is followed by 8-byte ``IMAGE_DATA_DIRECTORY`` entries.

    Args:
        directories: Data directory entries as ``{index: (rva, size)}``.
        size: Total length of the returned buffer.

    Returns:
        bytes: The NT headers padded with zeros to ``size``.
    """
    header = bytearray(size)
    header[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", header, 4, 0x8664, 0, 0, 0, 0, _PE32PLUS_OPTIONAL_SIZE, 0x2022)
    struct.pack_into("<H", header, 24, _PE32PLUS_MAGIC)
    for index, (rva, entry_size) in (directories or {}).items():
        struct.pack_into("<II", header, _PE32PLUS_DATA_DIRECTORY_START + 8 * index, rva, entry_size)
    return bytes(header)


def _kernel32_base() -> int:
    """Resolve the live base address of ``kernel32.dll`` in this process.

    Returns:
        int: Base address reported by ``GetModuleHandleW``.
    """
    handle = _k32().GetModuleHandleW("kernel32.dll")
    assert handle, "kernel32.dll is not loaded in this process"
    return int(handle)


def _module_headers(base: int, nt_header: bytes) -> dict[int, list[bytes | ToolError]]:
    """Script the two header reads the bridge issues for a module at ``base``.

    Args:
        base: Module base address.
        nt_header: Bytes served for the NT headers.

    Returns:
        dict[int, list[bytes | ToolError]]: Memory script for the DOS header and NT headers.
    """
    return {base: [_dos_header()], base + _PE_OFFSET: [nt_header]}


@pytest.fixture
def scripted_bridge() -> Iterator[ScriptedBridge]:
    """Provide a fresh scripted bridge and release cached process handles afterwards.

    Yields:
        ScriptedBridge: Bridge with empty scripts and no attached process.
    """
    bridge = ScriptedBridge()
    try:
        yield bridge
    finally:
        _method(bridge, "_release_process_handles")()


@pytest.fixture
def kernel_bridge(scripted_bridge: ScriptedBridge) -> ScriptedBridge:
    """Attach the scripted bridge to this process so ``kernel32.dll`` resolves to its real base.

    Args:
        scripted_bridge: Fresh scripted bridge.

    Returns:
        ScriptedBridge: The same bridge attached to the current process.
    """
    scripted_bridge.attached_pid = os.getpid()
    return scripted_bridge


@pytest.fixture
def hidden_sleeper() -> Iterator[DesktopProcess]:
    """Provide a live Python child sleeping on a hidden desktop.

    Yields:
        DesktopProcess: The running child; terminated and closed on teardown.
    """
    proc = _spawn_hidden()
    try:
        yield proc
    finally:
        _reap_hidden(proc)


@pytest.fixture
def suspended_child() -> Iterator[subprocess.Popen[bytes]]:
    """Provide a real child process that was created suspended (no module list yet).

    Yields:
        subprocess.Popen[bytes]: The suspended child; killed on teardown.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        creationflags=CREATE_SUSPENDED,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield child
    finally:
        child.kill()
        child.wait(timeout=_WAIT_S)


@pytest.mark.asyncio
async def test_initialize_without_optional_disassemblers_resets_the_state() -> None:
    """With capstone and keystone missing, ``initialize`` still hands back a fresh idle state.

    The two optional-dependency warnings are executed here but only logged, so no assertion depends on them.
    """
    bridge = X64DbgBridge()
    bridge.state.connected = True
    bridge.state.tool_running = True
    with _optional_modules_missing("_capstone", "_keystone"):
        await bridge.initialize(None)
    assert bridge.state == BridgeState(connected=False, tool_running=False)
    assert bridge.x64dbg_path is None


@pytest.mark.asyncio
async def test_disassemble_without_capstone_names_the_plugin_error() -> None:
    """With no plugin and no capstone the error says how to install capstone and why the plugin failed."""
    bridge = X64DbgBridge()
    with _optional_modules_missing("_capstone"), pytest.raises(ToolError) as caught:
        await bridge.disassemble_at(0x1000, 1)
    assert caught.value.message == (
        "Capstone disassembler not available. Install with: pixi add capstone-engine "
        "(plugin error: x64dbg bridge plugin not available: x64dbg installation not configured)"
    )


@pytest.mark.asyncio
async def test_disassemble_without_capstone_omits_the_plugin_error_after_a_non_list_reply(
    scripted_bridge: ScriptedBridge,
) -> None:
    """A non-list ``disasm`` reply is not an error, so the missing-capstone message has no plugin detail.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["disasm"] = [{"unexpected": "shape"}]
    with _optional_modules_missing("_capstone"), pytest.raises(ToolError) as caught:
        await scripted_bridge.disassemble_at(0x1000, 1)
    assert caught.value.message == "Capstone disassembler not available. Install with: pixi add capstone-engine"


@pytest.mark.asyncio
async def test_assemble_reports_a_missing_keystone_and_an_empty_encoding() -> None:
    """Without keystone assembling is refused; with keystone an instruction-less string yields no encoding."""
    bridge = X64DbgBridge()
    assert await bridge.assemble_at(_BP_ADDRESS, "nop") == b"\x90"
    with pytest.raises(ToolError) as empty:
        await bridge.assemble_at(_BP_ADDRESS, "")
    assert empty.value.message == "Failed to assemble: "
    with _optional_modules_missing("_keystone"), pytest.raises(ToolError) as missing:
        await bridge.assemble_at(_BP_ADDRESS, "nop")
    assert missing.value.message.startswith("Keystone assembler not available.")


@pytest.mark.asyncio
async def test_yara_scan_reports_a_missing_yara_module() -> None:
    """A valid inline rule still cannot run when yara-python is not installed."""
    bridge = X64DbgBridge()
    with _optional_modules_missing("_yara"), pytest.raises(ToolError) as caught:
        await bridge.yara_scan(rule_text="rule r1 { condition: true }")
    assert caught.value.message.startswith("yara-python is not installed.")


@pytest.mark.asyncio
async def test_yara_scan_runs_a_rule_file_over_an_explicit_window(kernel_bridge: ScriptedBridge, tmp_path: Path) -> None:
    """A rule file with content compiles and reports the match at the address of the marker.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
        tmp_path: Per-test temporary directory.
    """
    rule = tmp_path / "marker.yar"
    rule.write_text(f'rule critcov_r1 {{ strings: $m = "{_MARKER.decode("ascii")}" condition: $m }}', encoding="ascii")
    blob = b"\x00" * 24 + _MARKER + b"\x01" * 24
    buffer = ctypes.create_string_buffer(blob, len(blob))
    start = ctypes.addressof(buffer)
    matches = await kernel_bridge.yara_scan(rule_path=str(rule), address=start, size=len(blob))
    assert matches == [{"rule": "critcov_r1", "address": hex(start + 24), "matched_bytes": _MARKER.hex()}]


@pytest.mark.asyncio
async def test_analyze_entropy_flags_an_empty_read_and_scores_a_uniform_block(scripted_bridge: ScriptedBridge) -> None:
    """An empty read is unreadable (not zero entropy); all 256 byte values equally often is 8 bits.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = {0x10000: [b""], 0x10100: [bytes(range(_ENTROPY_BLOCK))]}
    results = await scripted_bridge.analyze_entropy(0x10000, 2 * _ENTROPY_BLOCK, _ENTROPY_BLOCK)
    assert results == [
        {"address": "0x10000", "entropy": 0.0, "size": 0, "readable": False, "error": "empty read"},
        {"address": "0x10100", "entropy": 8.0, "size": _ENTROPY_BLOCK, "readable": True},
    ]


@pytest.mark.asyncio
async def test_patch_process_heap_flags_rejects_a_truncated_heap_pointer(scripted_bridge: ScriptedBridge) -> None:
    """A ``PEB.ProcessHeap`` read shorter than a pointer is reported instead of being decoded.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    peb = 0x7000_0000
    scripted_bridge.memory_script = {peb + 0x30: [b"\x01\x02"]}
    result = await _async_method(scripted_bridge, "_patch_process_heap_flags")(peb)
    assert result == (False, "PEB.ProcessHeap read returned truncated data")


def test_append_token_privilege_skips_an_unknown_luid_and_names_a_known_one() -> None:
    """``LookupPrivilegeNameW`` fails for an unassigned LUID (nothing appended) and names a real one."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    append = _method(X64DbgBridge, "_append_token_privilege")
    unknown: list[dict[str, Any]] = []
    append(advapi32, struct.pack("<III", _UNNAMED_LUID_LOW, 0, 3), 0, unknown)
    assert unknown == []
    luid = _Luid()
    assert advapi32.LookupPrivilegeValueW(None, _HELD_PRIVILEGE, ctypes.byref(luid))
    attributes = _SE_PRIVILEGE_ENABLED | _SE_PRIVILEGE_ENABLED_BY_DEFAULT
    known: list[dict[str, Any]] = []
    append(advapi32, struct.pack("<III", luid.LowPart, luid.HighPart & 0xFFFFFFFF, attributes), 0, known)
    assert known == [{"name": _HELD_PRIVILEGE, "enabled": True, "enabled_by_default": True}]


@pytest.mark.asyncio
async def test_get_entry_point_needs_at_least_one_module() -> None:
    """With no module name, no binary path and no loaded module there is nothing to read an entry point from."""
    bridge = NoModulesBridge()
    with pytest.raises(ToolError) as caught:
        await bridge.get_entry_point()
    assert caught.value.message == "No modules loaded; cannot determine entry point"
    assert caught.value.tool_name == "x64dbg"


@pytest.mark.asyncio
async def test_load_library_rejects_a_result_register_that_is_neither_text_nor_number(
    scripted_bridge: ScriptedBridge,
) -> None:
    """A ``$result`` payload of another type cannot be a base address, so the load is reported as failed.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["reg_get"] = [None]
    with pytest.raises(ToolError) as caught:
        await scripted_bridge.load_library("sample.dll")
    assert caught.value.details == {"x64dbg_error_code": "remote_error", "path": "sample.dll"}
    assert "$result is None" in caught.value.message
    assert scripted_bridge.sent_commands == ['loadlib "sample.dll"']


@pytest.mark.asyncio
async def test_wait_for_running_state_ignores_a_status_without_a_paused_flag(scripted_bridge: ScriptedBridge) -> None:
    """A status object with no boolean ``paused`` gives no observation, though the RPC answered.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["status"] = [{"debugging": True}]
    result = await _async_method(scripted_bridge, "_wait_for_running_state")(expected=True)
    assert result == (None, True)


@pytest.mark.asyncio
async def test_get_registers_reads_unparseable_and_foreign_values_as_zero(scripted_bridge: ScriptedBridge) -> None:
    """Hex text and integers parse; unparseable text and non-scalar payloads read as 0.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["reg_all"] = [{"rax": "0x10", "rbx": "bogus", "rcx": None, "rdx": 5, "rsi": [1]}]
    regs = await scripted_bridge.get_registers()
    assert (regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi) == (16, 0, 0, 5, 0)


@pytest.mark.asyncio
async def test_get_breakpoints_falls_back_to_the_local_registry_without_bp_list(scripted_bridge: ScriptedBridge) -> None:
    """An older plugin without ``bp_list`` leaves only the locally tracked breakpoints.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    local = BreakpointInfo(id=0x1000, address=0x1000, bp_type="software", enabled=True, hit_count=0, condition=None)
    scripted_bridge.breakpoints[0x1000] = local
    scripted_bridge.pipe_script["bp_list"] = [_unknown_command()]
    assert await scripted_bridge.get_breakpoints() == [local]


@pytest.mark.asyncio
async def test_get_breakpoints_merges_gui_breakpoints_from_the_plugin_list(scripted_bridge: ScriptedBridge) -> None:
    """GUI-created entries are merged with their reported type, state, hits and condition.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    local = BreakpointInfo(id=0x1000, address=0x1000, bp_type="software", enabled=True, hit_count=0, condition=None)
    scripted_bridge.breakpoints[0x1000] = local
    entries: list[object] = [
        "junk",
        {"address": "0x2000", "type": "memory", "enabled": False, "hitCount": 3, "breakCondition": "eax == 1"},
        {"address": "0x1000", "type": "hardware"},
        {"address": "0x3000", "type": "unheard-of", "hit_count": 2},
    ]
    scripted_bridge.pipe_script["bp_list"] = [entries]
    assert await scripted_bridge.get_breakpoints() == [
        local,
        BreakpointInfo(id=0x2000, address=0x2000, bp_type="memory", enabled=False, hit_count=3, condition="eax == 1"),
        BreakpointInfo(id=0x3000, address=0x3000, bp_type="software", enabled=True, hit_count=2, condition=None),
    ]


@pytest.mark.asyncio
async def test_get_watchpoints_falls_back_to_the_local_registry_without_bp_list(scripted_bridge: ScriptedBridge) -> None:
    """An older plugin without ``bp_list`` leaves only the locally tracked watchpoints.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    local = WatchpointInfo(id=1, address=0x2000, size=4, watch_type="write", enabled=True, hit_count=0)
    scripted_bridge.watchpoints[1] = local
    scripted_bridge.pipe_script["bp_list"] = [_unknown_command()]
    assert await scripted_bridge.get_watchpoints() == [local]


@pytest.mark.asyncio
async def test_get_watchpoints_merges_hardware_entries_the_registry_does_not_know(
    scripted_bridge: ScriptedBridge,
) -> None:
    """Only hardware entries at unknown addresses are added, numbered after the local ones.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    local = WatchpointInfo(id=1, address=0x2000, size=4, watch_type="write", enabled=True, hit_count=0)
    scripted_bridge.watchpoints[1] = local
    scripted_bridge.next_wp_id = 2
    entries: list[object] = [
        "junk",
        {"type": "software", "address": "0x9000"},
        {"type": "hardware", "address": "0x2000"},
        {"type": "hardware", "address": "0x3000", "size": 8, "access": "r", "enabled": False, "hitCount": 3},
        {"type": "hardware", "address": "0x4000", "hit_count": 4},
    ]
    scripted_bridge.pipe_script["bp_list"] = [entries]
    assert await scripted_bridge.get_watchpoints() == [
        local,
        WatchpointInfo(id=2, address=0x3000, size=8, watch_type="r", enabled=False, hit_count=3),
        WatchpointInfo(id=3, address=0x4000, size=1, watch_type="write", enabled=True, hit_count=4),
    ]


@pytest.mark.asyncio
async def test_breakpoint_presence_honours_the_requested_type(scripted_bridge: ScriptedBridge) -> None:
    """A ``bp_list`` entry at the right address but of another type does not count; ``normal`` means software.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    present = _async_method(scripted_bridge, "_verify_breakpoint_present")
    other: list[object] = ["junk", {"address": "0x1", "type": "software"}, {"address": "0x401000", "type": "hardware"}]
    scripted_bridge.pipe_script["bp_list"] = [other]
    assert await present(_BP_ADDRESS, "software") is False
    matching: list[object] = [*other, {"address": _BP_ADDRESS, "type": "normal"}]
    scripted_bridge.pipe_script["bp_list"] = [matching]
    assert await present(_BP_ADDRESS, "software") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "entries",
    [
        ["junk", {"address": "zz"}, {"address": 0x1}, {"address": None}, {"address": "0x401000"}],
        [{"address": _BP_ADDRESS}],
    ],
)
async def test_breakpoint_applied_accepts_an_entry_at_the_address(
    scripted_bridge: ScriptedBridge,
    entries: list[object],
) -> None:
    """The address may be an integer or a numeric string; junk, unparseable and other entries are skipped.

    Args:
        scripted_bridge: Fresh scripted bridge.
        entries: ``bp_list`` payload containing the breakpoint.
    """
    scripted_bridge.pipe_script["bp_list"] = [entries]
    assert await _async_method(scripted_bridge, "_verify_breakpoint_applied")(_BP_ADDRESS) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("entries", [[], [{"address": 0x1}, {"address": "0x2"}]])
async def test_breakpoint_applied_rejects_a_list_without_the_address(
    scripted_bridge: ScriptedBridge,
    entries: list[object],
) -> None:
    """A ``bp_list`` that does not contain the address fails the verification with a remote-error code.

    Args:
        scripted_bridge: Fresh scripted bridge.
        entries: ``bp_list`` payload lacking the breakpoint.
    """
    scripted_bridge.pipe_script["bp_list"] = [entries]
    with pytest.raises(ToolError) as caught:
        await _async_method(scripted_bridge, "_verify_breakpoint_applied")(_BP_ADDRESS)
    assert caught.value.message == "set_breakpoint verification failed: address 0x401000 not present in bp_list after bp_set"
    assert caught.value.details == {"x64dbg_error_code": "remote_error", "address": "0x401000"}


@pytest.mark.asyncio
async def test_breakpoint_verification_is_skipped_when_bp_list_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """An older plugin without ``bp_list`` cannot verify, so both applied and condition checks pass silently.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["bp_list"] = [_unknown_command()]
    assert await _async_method(scripted_bridge, "_verify_breakpoint_applied")(_BP_ADDRESS) is None
    assert await _async_method(scripted_bridge, "_verify_breakpoint_condition")(_BP_ADDRESS, "software", "eax == 1") is None


@pytest.mark.asyncio
async def test_breakpoint_condition_rejects_a_list_without_the_address(scripted_bridge: ScriptedBridge) -> None:
    """Junk entries and entries at other addresses are skipped; absence fails with the type in the details.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    entries: list[object] = ["junk", {"address": "0x1", "breakCondition": "eax == 1"}]
    scripted_bridge.pipe_script["bp_list"] = [entries]
    with pytest.raises(ToolError) as caught:
        await _async_method(scripted_bridge, "_verify_breakpoint_condition")(_BP_ADDRESS, "software", "eax == 1")
    assert caught.value.message == (
        "set_breakpoint condition verification failed: address 0x401000 not present in bp_list after condition set"
    )
    assert caught.value.details == {"x64dbg_error_code": "remote_error", "address": "0x401000", "bp_type": "software"}


@pytest.mark.asyncio
async def test_memory_range_breakpoint_missing_from_bp_list_is_rejected(scripted_bridge: ScriptedBridge) -> None:
    """When ``bp_list`` shows no memory breakpoint after ``SetMemoryRangeBPX`` nothing is recorded.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["bp_list"] = [[]]
    with pytest.raises(ToolError) as caught:
        await scripted_bridge.set_memory_range_breakpoint(_BP_ADDRESS, 0x10)
    assert caught.value.message == "x64dbg accepted SetMemoryRangeBPX but no memory breakpoint exists at 0x401000"
    assert scripted_bridge.breakpoints == {}


@pytest.mark.asyncio
async def test_await_debuggee_pid_retries_after_a_missing_rpc(scripted_bridge: ScriptedBridge) -> None:
    """``unknown_command`` from ``reg_get`` is retried until the plugin reports a pid.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script["reg_get"] = [_unknown_command(), "0x2a"]
    assert await _async_method(scripted_bridge, "_await_debuggee_pid")() == 42


@pytest.mark.asyncio
async def test_break_on_tls_callbacks_sets_one_breakpoint_per_callback() -> None:
    """Every reported callback address gets a software breakpoint."""
    bridge = TlsFeedBridge([{"index": 0, "address": "0x401000"}, {"index": 1, "address": "0x402000"}])
    bridge.pipe_script["bp_set"] = [None]
    bridge.pipe_script["bp_list"] = [
        [{"address": "0x401000", "type": "software"}, {"address": "0x402000", "type": "software"}],
    ]
    result = await bridge.break_on_tls_callbacks("sample.exe")
    assert result == {"success": True, "breakpoints_set": 2}
    assert sorted(bridge.breakpoints) == [0x401000, 0x402000]
    assert bridge.requested_modules == ["sample.exe"]


@pytest.mark.asyncio
async def test_tls_callbacks_are_empty_when_the_headers_end_before_the_tls_directory(kernel_bridge: ScriptedBridge) -> None:
    """A header read too short to contain the TLS data directory entry yields no callbacks.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
    """
    kernel_bridge.memory_script = _module_headers(_kernel32_base(), _pe64_nt_header()[:64])
    assert await kernel_bridge.get_tls_callbacks("kernel32.dll") == []


@pytest.mark.asyncio
async def test_tls_callbacks_are_empty_when_the_callback_array_pointer_is_null(kernel_bridge: ScriptedBridge) -> None:
    """A TLS directory whose ``AddressOfCallBacks`` is zero lists no callbacks.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
    """
    base = _kernel32_base()
    headers = _module_headers(base, _pe64_nt_header({_TLS_DIRECTORY_INDEX: (_TLS_RVA, _TLS_DIRECTORY64_SIZE)}))
    kernel_bridge.memory_script = {**headers, base + _TLS_RVA: [bytes(_TLS_DIRECTORY64_SIZE)]}
    assert await kernel_bridge.get_tls_callbacks("kernel32.dll") == []


def _tls_scenario(base: int, callback_vas: list[int]) -> dict[int, list[bytes | ToolError]]:
    """Script a PE32+ module whose TLS directory follows the specification layout.

    ``IMAGE_TLS_DIRECTORY64`` is ``StartAddressOfRawData`` (offset 0), ``EndAddressOfRawData`` (8),
    ``AddressOfIndex`` (16), ``AddressOfCallBacks`` (24), ``SizeOfZeroFill`` (32), ``Characteristics`` (36);
    the callback array is a list of 8-byte virtual addresses ended by a null entry (when shorter than the limit).

    Args:
        base: Module base address.
        callback_vas: Callback addresses in array order.

    Returns:
        dict[int, list[bytes | ToolError]]: Memory script for headers, directory and callback array.
    """
    headers = _module_headers(base, _pe64_nt_header({_TLS_DIRECTORY_INDEX: (_TLS_RVA, _TLS_DIRECTORY64_SIZE)}))
    directory = bytearray(_TLS_DIRECTORY64_SIZE)
    struct.pack_into("<QQQQ", directory, 0, base + 0x6000, base + 0x6100, base + 0x6200, base + _TLS_ARRAY_RVA)
    script: dict[int, list[bytes | ToolError]] = {**headers, base + _TLS_RVA: [bytes(directory)]}
    for slot, address in enumerate(callback_vas):
        script[base + _TLS_ARRAY_RVA + 8 * slot] = [struct.pack("<Q", address)]
    if len(callback_vas) < _MAX_TLS_CALLBACKS:
        script[base + _TLS_ARRAY_RVA + 8 * len(callback_vas)] = [struct.pack("<Q", 0)]
    return script


@pytest.mark.asyncio
async def test_tls_callbacks_follow_address_of_callbacks_at_directory_offset_24(kernel_bridge: ScriptedBridge) -> None:
    """The callbacks are found through ``AddressOfCallBacks`` (offset 24 of ``IMAGE_TLS_DIRECTORY64``).

    The bridge reads the array pointer at ``12 + pointer size`` = 20, which straddles ``AddressOfIndex`` and
    ``AddressOfCallBacks``, so it follows a bogus address and fails.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
    """
    base = _kernel32_base()
    first, second = base + _TLS_CALLBACK_RVA, base + _TLS_CALLBACK_RVA + 0x10
    kernel_bridge.memory_script = _tls_scenario(base, [first, second])
    result = await kernel_bridge.get_tls_callbacks("kernel32.dll")
    assert result == [{"index": 0, "address": hex(first)}, {"index": 1, "address": hex(second)}]


@pytest.mark.asyncio
async def test_tls_callbacks_stop_after_sixty_four_entries_without_a_terminator(kernel_bridge: ScriptedBridge) -> None:
    """A callback array without a null terminator is cut at 64 entries, in array order.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
    """
    base = _kernel32_base()
    callback_vas = [base + _TLS_CALLBACK_RVA + 0x10 * slot for slot in range(_MAX_TLS_CALLBACKS)]
    kernel_bridge.memory_script = _tls_scenario(base, callback_vas)
    result = await kernel_bridge.get_tls_callbacks("kernel32.dll")
    assert result == [{"index": slot, "address": hex(address)} for slot, address in enumerate(callback_vas)]


@pytest.mark.asyncio
async def test_resources_are_empty_when_the_headers_end_before_the_resource_directory(kernel_bridge: ScriptedBridge) -> None:
    """A header read too short to contain the resource data directory entry yields no resources.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
    """
    kernel_bridge.memory_script = _module_headers(_kernel32_base(), _pe64_nt_header()[:64])
    assert await kernel_bridge.get_resources("kernel32.dll") == []


@pytest.mark.asyncio
async def test_resources_are_empty_when_the_resource_directory_is_unused(kernel_bridge: ScriptedBridge) -> None:
    """A zero RVA and size in the resource data directory means the image has no resources.

    Args:
        kernel_bridge: Scripted bridge attached to this process.
    """
    kernel_bridge.memory_script = _module_headers(_kernel32_base(), _pe64_nt_header())
    assert await kernel_bridge.get_resources("kernel32.dll") == []


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_load_fails_when_the_pipe_is_not_connected_after_initdebug(
    scripted_bridge: ScriptedBridge,
    hidden_sleeper: DesktopProcess,
    real_pe_dll: Path,
) -> None:
    """With the debugger alive but no pipe client, ``load`` raises instead of reporting success.

    Args:
        scripted_bridge: Fresh scripted bridge.
        hidden_sleeper: Live child standing in as the debugger process.
        real_pe_dll: Real System32 DLL used as the binary.
    """
    scripted_bridge.pipe_script["reg_get"] = ["0x1234"]
    setattr(scripted_bridge, "_process", hidden_sleeper)
    try:
        with pytest.raises(ToolError) as caught:
            await scripted_bridge.load(real_pe_dll)
    finally:
        setattr(scripted_bridge, "_process", None)
    assert caught.value.message == (
        "x64dbg session lost during load(): the bridge pipe is not connected after InitDebug. x64dbg installation not configured"
    )
    assert caught.value.details == {"x64dbg_error_code": "pipe_disconnected", "command": "InitDebug"}
    assert scripted_bridge.state.binary_loaded is False


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_attach_fails_when_the_pipe_is_not_connected_after_the_attach_command(
    scripted_bridge: ScriptedBridge,
    hidden_sleeper: DesktopProcess,
) -> None:
    """With the debugger alive but no pipe client, ``attach`` raises and records no attached process.

    Args:
        scripted_bridge: Fresh scripted bridge.
        hidden_sleeper: Live child standing in as the debugger process.
    """
    pid = os.getpid()
    setattr(scripted_bridge, "_process", hidden_sleeper)
    try:
        with pytest.raises(ToolError) as caught:
            await scripted_bridge.attach(pid)
    finally:
        setattr(scripted_bridge, "_process", None)
    assert caught.value.message == (
        f"x64dbg session lost during attach(): the bridge pipe is not connected after issuing attach {pid}. "
        "x64dbg installation not configured"
    )
    assert caught.value.details == {"x64dbg_error_code": "pipe_disconnected", "command": "attach"}
    assert scripted_bridge.attached_pid is None
    assert scripted_bridge.sent_commands == [f"attach {pid}"]


@pytest.mark.asyncio
async def test_send_pipe_command_reports_a_pipe_client_that_vanished_during_connect() -> None:
    """If connecting returns while no pipe client exists, the command fails with a disconnect code."""
    bridge = DisconnectedBridge()
    setattr(bridge, "_plugin_deployed", True)
    with pytest.raises(ToolError) as caught:
        await _async_method(bridge, "_send_pipe_command")("ping")
    assert caught.value.message == "Named pipe client not available"
    assert caught.value.details == {"x64dbg_error_code": "pipe_disconnected", "command": "ping"}
    assert caught.value.tool_name == "x64dbg"


@pytest.mark.asyncio
async def test_establish_bridge_connection_rejects_a_pipe_that_reports_disconnected() -> None:
    """A connect that returns without a connected pipe fails with the remediation text and no cause suffix."""
    bridge = DisconnectedBridge()
    with pytest.raises(ToolError) as caught:
        await _async_method(bridge, "_establish_bridge_connection")()
    assert caught.value.message.startswith("x64dbg started but the Intellicrack bridge plugin never opened its named pipe")
    assert "Underlying error" not in caught.value.message
    assert caught.value.details == {"x64dbg_error_code": "pipe_disconnected"}
    assert caught.value.tool_name == "x64dbg"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_terminate_falls_back_to_kill_when_the_process_ignores_terminate() -> None:
    """A debugger that survives ``terminate`` for five seconds is killed and then waited for."""
    stub = StubbornProcess.adopt(_spawn_hidden(), None)
    errors: list[BaseException] = []
    try:
        await _async_method(X64DbgBridge, "_terminate_process_with_timeout")(stub, stub.pid, errors)
        assert errors == []
        assert stub.poll() == 1
    finally:
        stub.end()
        await asyncio.get_running_loop().shutdown_default_executor()
        stub.close()


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_terminate_records_a_kill_failure_after_the_timeout() -> None:
    """When the fallback ``kill`` itself fails the error is collected and the process is left running."""
    refusal = OSError(5, "kill refused")
    stub = StubbornProcess.adopt(_spawn_hidden(), refusal)
    errors: list[BaseException] = []
    try:
        await _async_method(X64DbgBridge, "_terminate_process_with_timeout")(stub, stub.pid, errors)
        assert [type(error) for error in errors] == [OSError]
        assert [error.args for error in errors] == [refusal.args]
        assert stub.poll() is None
    finally:
        stub.end()
        stub.wait(timeout=_WAIT_S)
        await asyncio.get_running_loop().shutdown_default_executor()
        stub.close()


@pytest.mark.asyncio
async def test_shutdown_collects_a_failure_of_the_base_class_teardown() -> None:
    """A session that cannot clear the bridge's tool state fails the base shutdown; it is re-raised at the end."""
    now = datetime.now(tz=UTC)
    session = FaultySession(id="r1", name="r1", created_at=now, updated_at=now, provider="none", model="none")
    bridge = X64DbgBridge()
    bridge.set_session(session)
    bridge.attached_pid = 4242
    with pytest.raises(RuntimeError, match="session registry corrupted for") as caught:
        await bridge.shutdown()
    assert isinstance(caught.value.__cause__, RuntimeError)
    assert bridge.attached_pid is None


@pytest.mark.asyncio
async def test_set_memory_protection_verifies_a_copy_right_by_observed_change() -> None:
    """``write_copy`` has no rwx string, so a page whose real protection changed is reported as verified.

    The scripted ``setpagerights`` really re-protects the page (read-write to read-only) with ``VirtualProtect``.
    """
    bridge = ProtectingBridge()
    bridge.attached_pid = os.getpid()
    try:
        with _committed_page(PAGE_READWRITE) as page:
            bridge.target_page = page
            result = await bridge.set_memory_protection(page + 0x10, "write_copy")
    finally:
        _method(bridge, "_release_process_handles")()
    assert result == {
        "success": True,
        "address": hex(page + 0x10),
        "rights": "write_copy",
        "guard": False,
        "verified": True,
    }
    assert bridge.sent_commands[0].startswith(f"setpagerights {hex(page + 0x10)}, ")


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_memory_regions_are_still_listed_when_the_module_list_is_unavailable(
    scripted_bridge: ScriptedBridge,
    suspended_child: subprocess.Popen[bytes],
) -> None:
    """A process whose modules cannot be listed yet still has its regions, with no module name on images.

    Today the module snapshot failure goes unnoticed (PD-052), so this passes through the empty-list path; once
    PD-052 is fixed the same assertions hold through the ``ToolError`` handler.

    Args:
        scripted_bridge: Fresh scripted bridge.
        suspended_child: Real child created suspended.
    """
    scripted_bridge.attached_pid = suspended_child.pid
    regions = await scripted_bridge.get_memory_regions()
    images = [region for region in regions if region.type == "image"]
    assert images
    assert all(region.module_name is None for region in images)
