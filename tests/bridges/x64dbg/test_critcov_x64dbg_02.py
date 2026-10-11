# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Coverage-gap tests for ``X64DbgBridge`` (stack walking, Win32 enumeration, PE readers, verified wrappers).

x64dbg is not installed where these tests run, so everything that normally travels the plugin pipe is
answered by :class:`ScriptedBridge`, a subclass of the real bridge that replaces only the two transport
seams (``_send_pipe_command`` and ``read_memory`` for scripted addresses). All bridge logic above those
seams is the production code. Expectations come from independent sources: the PE specification layouts
(built with ``struct``), ``pefile`` on the same System32 DLL, ``CommandLineToArgvW`` as the Windows
command-line parser, ``subprocess.list2cmdline``, the documented Toolhelp snapshot semantics, and
hand-computed frame-pointer chains.
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pefile
import pytest

from intellicrack.bridges.base import StackFrame
from intellicrack.bridges.win32_types import (
    INVALID_HANDLE_VALUE,
    TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD,
)
from intellicrack.bridges.x64dbg import MAX_MEMORY_READ_SIZE, X64DbgBridge
from intellicrack.core.types import MemoryRegion, ToolError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator

    from intellicrack.bridges.base import MemorySearchResult
    from intellicrack.bridges.x64dbg import PipeCommandResult
    from intellicrack.core.types import ThreadInfo


_BASE = 0x180000000
_PE_OFFSET = 0x80
_PE32PLUS_MAGIC = 0x20B
_PE32PLUS_OPTIONAL_SIZE = 240
_EXPORT_RVA = 0x2000
_FUNCTION_RVA = 0x1000
_CHAIN_BASE = 0x10000
_MISSING_PID = 0x7FFFFFFC
_MISSING_TID = 0xFFFFFFFC
_TARGET_ADDRESS = 0x401000

_REGS_64: dict[str, object] = {"rsp": "0x7000", "rbp": "0x1000", "rip": "0x401000"}
_REGS_32: dict[str, object] = {"esp": "0x7000", "ebp": "0x1000", "eip": "0x401000"}


class ScriptedBridge(X64DbgBridge):
    """Real ``X64DbgBridge`` whose plugin pipe and scripted memory reads are answered from data.

    ``pipe_script`` maps a pipe command name to a queue of replies; each call pops the first reply
    while more than one remains and repeats the last one afterwards. A reply that is a ``ToolError``
    is raised, anything else is returned. ``memory_script`` does the same for ``read_memory`` calls at
    an exact address; unscripted addresses use the real ``ReadProcessMemory`` path. The verification
    windows are shortened so timeout paths finish quickly.
    """

    VERIFY_TIMEOUT = 0.3
    VERIFY_POLL_INTERVAL = 0.02
    RUN_TO_POLL_INTERVAL = 0.02

    def __init__(self) -> None:
        """Create the bridge with empty scripts."""
        super().__init__()
        self.pipe_script: dict[str, list[PipeCommandResult | ToolError]] = {}
        self.memory_script: dict[int, list[bytes | ToolError]] = {}
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    async def _send_pipe_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> PipeCommandResult:
        """Answer a plugin pipe command from ``pipe_script``.

        Args:
            command: Pipe command name.
            params: Parameters the bridge attached to the command.

        Returns:
            PipeCommandResult: The scripted reply.

        Raises:
            LookupError: If the command has no scripted reply.
            ToolError: If the scripted reply is an error.
        """
        self.sent.append((command, params))
        queue = self.pipe_script.get(command)
        if queue is None:
            msg = f"unscripted pipe command {command!r}"
            raise LookupError(msg)
        reply = queue[0] if len(queue) == 1 else queue.pop(0)
        if isinstance(reply, ToolError):
            raise ToolError(
                reply.message,
                tool_name=reply.tool_name,
                exit_code=reply.exit_code,
                stderr=reply.stderr,
                details=reply.details,
            ) from reply
        return reply

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
            raise ToolError(
                reply.message,
                tool_name=reply.tool_name,
                exit_code=reply.exit_code,
                stderr=reply.stderr,
                details=reply.details,
            ) from reply
        return reply[:size]


class _ThreadEntry32(ctypes.Structure):
    """Layout of the Win32 ``THREADENTRY32`` snapshot record."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class _ProcessEntry32W(ctypes.Structure):
    """Layout of the Win32 ``PROCESSENTRY32W`` snapshot record."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _async_method(owner: object, name: str) -> Callable[..., Awaitable[Any]]:
    """Fetch a coroutine function by name.

    Args:
        owner: Object or class that carries the member.
        name: Member name.

    Returns:
        Callable[..., Awaitable[Any]]: The member, typed as an async callable.
    """
    return cast("Callable[..., Awaitable[Any]]", getattr(owner, name))


def _sync_method(owner: object, name: str) -> Callable[..., Any]:
    """Fetch a plain function by name.

    Args:
        owner: Object or class that carries the member.
        name: Member name.

    Returns:
        Callable[..., Any]: The member, typed as a callable.
    """
    return cast("Callable[..., Any]", getattr(owner, name))


def _plugin_error(code: str, message: str = "scripted plugin failure") -> ToolError:
    """Build the ``ToolError`` the bridge raises for a plugin failure.

    Args:
        code: Value for ``details["x64dbg_error_code"]``.
        message: Error text.

    Returns:
        ToolError: Error carrying the structured code.
    """
    return ToolError(message, tool_name="x64dbg", details={"x64dbg_error_code": code})


def _unknown_command() -> ToolError:
    """Build the error an older plugin returns for an RPC it does not implement.

    Returns:
        ToolError: Error coded ``unknown_command``.
    """
    return _plugin_error("unknown_command", "unknown command")


def _code(exc: ToolError) -> object:
    """Read the structured x64dbg error code from an error.

    Args:
        exc: Error raised by the bridge.

    Returns:
        object: The ``x64dbg_error_code`` detail, or ``None``.
    """
    return exc.details.get("x64dbg_error_code")


def _dos_header(pe_offset: int = _PE_OFFSET) -> bytes:
    """Build a 64-byte DOS header whose ``e_lfanew`` is ``pe_offset``.

    Args:
        pe_offset: Offset of the NT headers.

    Returns:
        bytes: The DOS header.
    """
    header = bytearray(64)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, pe_offset)
    return bytes(header)


def _nt_header(
    *,
    magic: int = _PE32PLUS_MAGIC,
    optional_size: int = _PE32PLUS_OPTIONAL_SIZE,
    sections: int = 0,
    entry_rva: int = 0,
    export: tuple[int, int] = (0, 0),
    size: int = 0x200,
) -> bytes:
    """Build PE NT headers following the PE specification offsets.

    The optional header starts at offset 24 (4-byte signature plus 20-byte COFF header);
    ``AddressOfEntryPoint`` is at optional offset 16, the Major/Minor operating-system versions are
    at optional offset 40, and the PE32+ data directories start after the 112-byte optional header.

    Args:
        magic: Optional header magic.
        optional_size: COFF ``SizeOfOptionalHeader``.
        sections: COFF ``NumberOfSections``.
        entry_rva: ``AddressOfEntryPoint``.
        export: Export data directory ``(rva, size)``.
        size: Total length of the returned buffer.

    Returns:
        bytes: The NT headers padded with zeros to ``size``.
    """
    header = bytearray(size)
    header[0:4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", header, 4, 0x8664, sections, 0, 0, 0, optional_size, 0x2022)
    struct.pack_into("<H", header, 24, magic)
    struct.pack_into("<I", header, 24 + 16, entry_rva)
    struct.pack_into("<HH", header, 24 + 40, 6, 1)
    struct.pack_into("<II", header, 24 + 112, *export)
    return bytes(header)


def _module_memory(base: int, nt_header: bytes) -> dict[int, list[bytes | ToolError]]:
    """Script the two header reads the bridge issues for a module at ``base``.

    Args:
        base: Module base address.
        nt_header: Bytes served for the NT headers.

    Returns:
        dict[int, list[bytes | ToolError]]: Memory script for the DOS header and NT headers.
    """
    return {base: [_dos_header()], base + _PE_OFFSET: [nt_header]}


def _export_memory(base: int, name_read: bytes | ToolError) -> dict[int, list[bytes | ToolError]]:
    """Script a module with exactly one named export whose name read is ``name_read``.

    Args:
        base: Module base address.
        name_read: Reply for the export-name read.

    Returns:
        dict[int, list[bytes | ToolError]]: Memory script covering headers and export tables.
    """
    export_dir = bytearray(40)
    struct.pack_into("<I", export_dir, 16, 1)
    struct.pack_into("<I", export_dir, 20, 1)
    struct.pack_into("<I", export_dir, 24, 1)
    struct.pack_into("<I", export_dir, 28, 0x2100)
    struct.pack_into("<I", export_dir, 32, 0x2110)
    struct.pack_into("<I", export_dir, 36, 0x2120)
    memory = _module_memory(base, _nt_header(export=(_EXPORT_RVA, 0x28)))
    memory[base + _EXPORT_RVA] = [bytes(export_dir)]
    memory[base + 0x2100] = [struct.pack("<I", _FUNCTION_RVA)]
    memory[base + 0x2110] = [struct.pack("<I", 0x2200)]
    memory[base + 0x2120] = [struct.pack("<H", 0)]
    memory[base + 0x2200] = [name_read]
    return memory


def _top_frame() -> StackFrame:
    """Build the frame the fallback walker always reports first (from the register file).

    Returns:
        StackFrame: Frame 0 for ``rip=0x401000``, ``rbp=0x1000``, ``rsp=0x7000``.
    """
    return StackFrame(
        index=0,
        address=0x401000,
        return_address=0,
        frame_pointer=0x1000,
        stack_pointer=0x7000,
        function_name=None,
        module_name=None,
    )


def _loaded_module_base(name: str) -> int:
    """Resolve the live base address of a module loaded in this process via the OS loader.

    Args:
        name: Module file name, for example ``kernel32.dll``.

    Returns:
        int: Base address reported by ``GetModuleHandleW``.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    handle = kernel32.GetModuleHandleW(name)
    assert handle, f"{name} is not loaded in this process"
    return int(handle)


def _address_of_entry_point(dll_name: str) -> int:
    """Read ``AddressOfEntryPoint`` of a System32 DLL with ``pefile``.

    Args:
        dll_name: File name inside the Windows System32 directory.

    Returns:
        int: The optional header's ``AddressOfEntryPoint``.
    """
    path = Path(os.environ["SYSTEMROOT"]) / "System32" / dll_name
    return pefile.PE(data=path.read_bytes(), fast_load=True).OPTIONAL_HEADER.AddressOfEntryPoint


def _typed_kernel32() -> ctypes.WinDLL:
    """Create a private ``kernel32`` binding with the Toolhelp entry points typed.

    Returns:
        ctypes.WinDLL: Binding with last-error tracking and explicit ``restype``/``argtypes``.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.Thread32First.restype = wintypes.BOOL
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    return kernel32


def _parse_command_line(command_line: str) -> list[str]:
    """Split a command line with the Windows ``CommandLineToArgvW`` parser.

    Args:
        command_line: Full command line, program name first.

    Returns:
        list[str]: The argv list the Windows C runtime rules produce.

    Raises:
        OSError: If ``CommandLineToArgvW`` fails.
    """
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    shell32.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    shell32.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.restype = wintypes.HLOCAL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    count = ctypes.c_int(0)
    argv = shell32.CommandLineToArgvW(command_line, ctypes.byref(count))
    if not argv:
        msg = "CommandLineToArgvW failed"
        raise OSError(msg)
    try:
        return [str(argv[index]) for index in range(count.value)]
    finally:
        kernel32.LocalFree(argv)


def _write_stale_file(path: Path, size: int) -> None:
    """Create ``path`` with ``size`` bytes so it already exists before an export.

    Args:
        path: File to create.
        size: Number of bytes to write.
    """
    path.write_bytes(b"\x00" * size)


@pytest.fixture
def scripted_bridge() -> Iterator[ScriptedBridge]:
    """Provide a fresh scripted bridge and release any cached process handles afterwards.

    Yields:
        ScriptedBridge: Bridge with empty scripts and no attached process.
    """
    bridge = ScriptedBridge()
    try:
        yield bridge
    finally:
        _sync_method(bridge, "_release_process_handles")()


@pytest.fixture
def attached_bridge(scripted_bridge: ScriptedBridge) -> ScriptedBridge:
    """Attach the scripted bridge to the current process so Toolhelp and memory reads are real.

    Args:
        scripted_bridge: Fresh scripted bridge.

    Returns:
        ScriptedBridge: The same bridge with ``attached_pid`` set to this process.
    """
    scripted_bridge.attached_pid = os.getpid()
    return scripted_bridge


@pytest.fixture
def idle_process() -> Iterator[subprocess.Popen[bytes]]:
    """Start a real child process that idles until it is killed.

    Yields:
        subprocess.Popen[bytes]: The running child.
    """
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield process
    finally:
        process.kill()
        process.wait(timeout=10)
        if process.stdin is not None:
            process.stdin.close()


@pytest.fixture
def running_bridge(scripted_bridge: ScriptedBridge, idle_process: subprocess.Popen[bytes]) -> ScriptedBridge:
    """Give the scripted bridge a live process so console-command paths (``_send_command``) run.

    Args:
        scripted_bridge: Fresh scripted bridge.
        idle_process: Real child process standing in for the debugger process handle.

    Returns:
        ScriptedBridge: The bridge with its process attribute set.
    """
    setattr(scripted_bridge, "_process", idle_process)
    return scripted_bridge


@pytest.mark.asyncio
async def test_stack_trace_walks_frame_pointer_chain_when_rpc_missing(scripted_bridge: ScriptedBridge) -> None:
    """A missing ``stack_trace`` RPC falls back to walking ``[rbp]`` / ``[rbp+8]`` pairs.

    Each x64 frame stores the caller's frame pointer at ``[rbp]`` and the return address at
    ``[rbp+8]``; the caller's stack pointer after the return is ``rbp + 16``.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"stack_trace": [_unknown_command()], "reg_all": [_REGS_64]}
    scripted_bridge.memory_script = {
        0x1000: [struct.pack("<QQ", 0x2000, 0x401100)],
        0x2000: [struct.pack("<QQ", 0x3000, 0x401200)],
        0x3000: [struct.pack("<QQ", 0, 0x401300)],
    }

    frames = await scripted_bridge.get_stack_trace()

    assert frames == [
        _top_frame(),
        StackFrame(
            index=1,
            address=0x401100,
            return_address=0x401100,
            frame_pointer=0x2000,
            stack_pointer=0x1010,
            function_name=None,
            module_name=None,
        ),
        StackFrame(
            index=2,
            address=0x401200,
            return_address=0x401200,
            frame_pointer=0x3000,
            stack_pointer=0x2010,
            function_name=None,
            module_name=None,
        ),
    ]


@pytest.mark.asyncio
async def test_stack_trace_walk_uses_32_bit_slots_for_32_bit_targets(scripted_bridge: ScriptedBridge) -> None:
    """For a 32-bit target the saved ebp and return address are 4-byte slots and a frame spans 8 bytes.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.is_64bit = False
    scripted_bridge.pipe_script = {"stack_trace": [_unknown_command()], "reg_all": [_REGS_32]}
    scripted_bridge.memory_script = {
        0x1000: [struct.pack("<II", 0x2000, 0x401100) + b"\x00" * 8],
        0x2000: [struct.pack("<II", 0, 0x401200) + b"\x00" * 8],
    }

    frames = await scripted_bridge.get_stack_trace()

    assert frames == [
        _top_frame(),
        StackFrame(
            index=1,
            address=0x401100,
            return_address=0x401100,
            frame_pointer=0x2000,
            stack_pointer=0x1008,
            function_name=None,
            module_name=None,
        ),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("saved_rbp", "return_address"),
    [(0, 0x401100), (0x2000, 0)],
    ids=["zero-saved-frame-pointer", "zero-return-address"],
)
async def test_stack_trace_walk_stops_at_a_null_link(scripted_bridge: ScriptedBridge, saved_rbp: int, return_address: int) -> None:
    """A frame whose saved frame pointer or return address is zero ends the chain without being reported.

    Args:
        scripted_bridge: Fresh scripted bridge.
        saved_rbp: Saved frame pointer stored in the first frame.
        return_address: Return address stored in the first frame.
    """
    scripted_bridge.pipe_script = {"stack_trace": [_unknown_command()], "reg_all": [_REGS_64]}
    scripted_bridge.memory_script = {0x1000: [struct.pack("<QQ", saved_rbp, return_address)]}

    frames = await scripted_bridge.get_stack_trace()

    assert frames == [_top_frame()]


@pytest.mark.asyncio
async def test_stack_trace_walk_stops_on_short_frame_read(scripted_bridge: ScriptedBridge) -> None:
    """Fewer than 16 bytes of frame data cannot hold a frame, so the walk ends with only the top frame.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"stack_trace": [_unknown_command()], "reg_all": [_REGS_64]}
    scripted_bridge.memory_script = {0x1000: [b"\x01\x02\x03"]}

    frames = await scripted_bridge.get_stack_trace()

    assert frames == [_top_frame()]


@pytest.mark.asyncio
async def test_stack_trace_walk_keeps_frames_found_before_a_failed_read(scripted_bridge: ScriptedBridge) -> None:
    """A memory read failure mid-walk stops the walk but keeps the frames already collected.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"stack_trace": [_unknown_command()], "reg_all": [_REGS_64]}
    scripted_bridge.memory_script = {
        0x1000: [struct.pack("<QQ", 0x2000, 0x401100)],
        0x2000: [ToolError("ReadProcessMemory failed at 0x2000")],
    }

    frames = await scripted_bridge.get_stack_trace()

    assert [frame.address for frame in frames] == [0x401000, 0x401100]


@pytest.mark.asyncio
async def test_stack_trace_walk_is_bounded_to_thirty_one_frames(scripted_bridge: ScriptedBridge) -> None:
    """A chain that never terminates yields the top frame plus 31 walked frames and then stops.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {
        "stack_trace": [_unknown_command()],
        "reg_all": [{"rsp": "0x7000", "rbp": hex(_CHAIN_BASE), "rip": "0x401000"}],
    }
    scripted_bridge.memory_script = {
        _CHAIN_BASE + 0x10 * k: [struct.pack("<QQ", _CHAIN_BASE + 0x10 * (k + 1), 0x500000 + k)] for k in range(31)
    }

    frames = await scripted_bridge.get_stack_trace()

    assert len(frames) == 32
    assert frames[31] == StackFrame(
        index=31,
        address=0x500000 + 30,
        return_address=0x500000 + 30,
        frame_pointer=_CHAIN_BASE + 0x10 * 31,
        stack_pointer=_CHAIN_BASE + 0x10 * 31,
        function_name=None,
        module_name=None,
    )


@pytest.mark.parametrize(
    ("entry", "function_name", "module_name"),
    [
        ({"index": 3, "address": "0x401000", "from": "0x401005", "to": "0x7ff0", "comment": "main"}, "main", None),
        (
            {"index": 4, "address": "0x401000", "from": "0x401005", "to": "0x7ff0", "comment": "kernel32.CreateFileW"},
            "CreateFileW",
            "kernel32",
        ),
        ({"index": 5, "address": "0x401000", "from": "0x401005", "to": "0x7ff0", "comment": ""}, None, None),
    ],
    ids=["bare-symbol", "module-dot-symbol", "no-comment"],
)
def test_parse_stack_frame_entry_splits_the_comment_into_module_and_function(
    entry: dict[str, object],
    function_name: str | None,
    module_name: str | None,
) -> None:
    """The plugin's free-text comment is ``module.function`` or a bare symbol name.

    Args:
        entry: Plugin stack-frame record.
        function_name: Expected resolved function name.
        module_name: Expected resolved module name.
    """
    frame = _sync_method(X64DbgBridge, "_parse_stack_frame_entry")(entry)

    assert frame == StackFrame(
        index=cast("int", entry["index"]),
        address=0x401000,
        return_address=0x401005,
        frame_pointer=0x7FF0,
        stack_pointer=0,
        function_name=function_name,
        module_name=module_name,
    )


@pytest.mark.asyncio
async def test_scan_region_chunks_stops_scanning_after_an_empty_read(scripted_bridge: ScriptedBridge) -> None:
    """An empty chunk ends the region scan, so data in later chunks is never searched.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    pattern = b"\xde\xad\xbe\xef"
    scripted_bridge.memory_script = {_CHAIN_BASE: [b""], _CHAIN_BASE + MAX_MEMORY_READ_SIZE: [pattern]}
    region = MemoryRegion(
        base_address=_CHAIN_BASE,
        size=MAX_MEMORY_READ_SIZE + 0x10,
        protection="r--",
        state="committed",
        type="private",
        module_name=None,
    )
    matches: list[MemorySearchResult] = []

    await _async_method(scripted_bridge, "_scan_region_chunks")(region, pattern, matches)

    assert matches == []


@pytest.mark.asyncio
async def test_wildcard_scan_stops_scanning_after_an_empty_read(scripted_bridge: ScriptedBridge) -> None:
    """The wildcard scanner also ends the region at the first empty chunk.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = {_CHAIN_BASE: [b""], _CHAIN_BASE + MAX_MEMORY_READ_SIZE: [b"\xaa\x11\xbb"]}
    region = MemoryRegion(
        base_address=_CHAIN_BASE,
        size=MAX_MEMORY_READ_SIZE + 0x10,
        protection="r--",
        state="committed",
        type="private",
        module_name=None,
    )
    matches: list[dict[str, Any]] = []

    await _async_method(scripted_bridge, "_scan_region_chunks_wildcard")(region, [0xAA, None, 0xBB], 1, matches)

    assert matches == []


@pytest.mark.asyncio
async def test_wildcard_scan_ignores_an_empty_pattern(scripted_bridge: ScriptedBridge) -> None:
    """An empty wildcard pattern matches nothing instead of matching at every offset.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = {_CHAIN_BASE: [b"\x00\x01\x02\x03"]}
    region = MemoryRegion(
        base_address=_CHAIN_BASE,
        size=4,
        protection="r--",
        state="committed",
        type="private",
        module_name=None,
    )
    matches: list[dict[str, Any]] = []

    await _async_method(scripted_bridge, "_scan_region_chunks_wildcard")(region, [], 1, matches)

    assert matches == []


@pytest.mark.asyncio
async def test_wildcard_scan_skips_an_unreadable_chunk_and_resumes_at_the_next(scripted_bridge: ScriptedBridge) -> None:
    """A failed chunk read is skipped; matches in the following chunk are reported at their true addresses.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    second_chunk = _CHAIN_BASE + MAX_MEMORY_READ_SIZE
    scripted_bridge.memory_script = {
        _CHAIN_BASE: [ToolError("ReadProcessMemory failed")],
        second_chunk: [b"\x00\xaa\x11\xbb" + b"\x00" * 12],
    }
    region = MemoryRegion(
        base_address=_CHAIN_BASE,
        size=MAX_MEMORY_READ_SIZE + 0x10,
        protection="r--",
        state="committed",
        type="private",
        module_name=None,
    )
    matches: list[dict[str, Any]] = []

    await _async_method(scripted_bridge, "_scan_region_chunks_wildcard")(region, [0xAA, None, 0xBB], 1, matches)

    assert matches == [{"address": hex(second_chunk + 1), "offset": second_chunk + 1}]


def test_extend_wildcard_matches_ignores_buffers_shorter_than_the_pattern() -> None:
    """A buffer shorter than the pattern cannot contain a match."""
    compiled = _sync_method(X64DbgBridge, "_compile_wildcard_regex")([0x41, 0x41])
    matches: list[dict[str, Any]] = []

    _sync_method(X64DbgBridge, "_extend_wildcard_matches")(b"A", 0x1000, compiled, 2, 1, matches)

    assert matches == []


def test_extend_wildcard_matches_reports_overlapping_matches_up_to_the_buffer_end() -> None:
    """Overlapping occurrences are all reported and the scan stops when too few bytes remain."""
    compiled = _sync_method(X64DbgBridge, "_compile_wildcard_regex")([0x41, 0x41])
    matches: list[dict[str, Any]] = []

    _sync_method(X64DbgBridge, "_extend_wildcard_matches")(b"AAA", 0x1000, compiled, 2, 1, matches)

    assert matches == [
        {"address": "0x1000", "offset": 0x1000},
        {"address": "0x1001", "offset": 0x1001},
    ]


def test_extend_wildcard_matches_keeps_only_aligned_addresses() -> None:
    """With alignment 2 only matches at even virtual addresses are reported."""
    compiled = _sync_method(X64DbgBridge, "_compile_wildcard_regex")([0x41])
    matches: list[dict[str, Any]] = []

    _sync_method(X64DbgBridge, "_extend_wildcard_matches")(b"AAAA", 0x1001, compiled, 1, 2, matches)

    assert matches == [
        {"address": "0x1002", "offset": 0x1002},
        {"address": "0x1004", "offset": 0x1004},
    ]


@pytest.mark.parametrize(
    "arg",
    [
        "has space",
        'say "hi" now',
        "C:\\Program Files\\App\\",
        "a\\b c",
        'q\\"z y',
        "tab\there",
        'quote"only',
        "x y\\\\",
    ],
)
def test_build_cmdline_round_trips_through_the_windows_argument_parser(arg: str) -> None:
    """Whatever the bridge quotes must be split back into the original arguments by Windows itself.

    Args:
        arg: Argument containing whitespace, quotes or backslashes.
    """
    command_line = _sync_method(X64DbgBridge, "_build_cmdline")([arg, "tail"])

    assert _parse_command_line(f"prog {command_line}") == ["prog", arg, "tail"]


@pytest.mark.parametrize(
    "args",
    [
        ["has space"],
        ["a\\b c"],
        ["C:\\Program Files\\App\\"],
        ['say "hi" now'],
        ['q\\"z y'],
        ["x y\\\\"],
        ["tab\there"],
        ["", "z"],
        ["plain", "also-plain"],
    ],
)
def test_build_cmdline_matches_the_standard_library_quoting(args: list[str]) -> None:
    """For arguments both quoters wrap identically the bridge output equals ``subprocess.list2cmdline``.

    Args:
        args: Argument list to quote.
    """
    assert _sync_method(X64DbgBridge, "_build_cmdline")(args) == subprocess.list2cmdline(args)


def test_thread_start_address_is_zero_for_a_thread_that_cannot_be_opened() -> None:
    """``OpenThread`` fails for a thread id that does not exist, so the start address is reported as 0."""
    query = _sync_method(X64DbgBridge, "_query_thread_start_address")

    assert query(_MISSING_TID) == 0


def test_thread_start_address_query_reports_zero_for_an_invalid_handle() -> None:
    """``NtQueryInformationThread`` returns a negative NTSTATUS for a NULL handle, which maps to 0."""
    ntdll = ctypes.WinDLL("ntdll")

    result = _sync_method(X64DbgBridge, "_query_thread_start_address_with_handle")(ntdll, 0, _MISSING_TID)

    assert result == 0


def test_thread_start_address_query_swallows_argument_conversion_errors() -> None:
    """If ctypes rejects the call arguments the start address is reported as 0 instead of raising."""
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtQueryInformationThread.argtypes = [
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]

    result = _sync_method(X64DbgBridge, "_query_thread_start_address_with_handle")(ntdll, 1234, _MISSING_TID)

    assert result == 0


def test_thread_pc_and_state_is_unknown_for_a_thread_that_cannot_be_opened(scripted_bridge: ScriptedBridge) -> None:
    """A thread id that cannot be opened yields ``(0, "unknown")`` rather than aborting enumeration.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    assert _sync_method(scripted_bridge, "_query_thread_pc_and_state")(_MISSING_TID) == (0, "unknown")


def test_thread_pc_read_with_an_invalid_handle_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """``SuspendThread`` on an invalid handle returns -1; the state and program counter are then unknown.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    kernel32 = ctypes.WinDLL("kernel32")

    result = _sync_method(scripted_bridge, "_read_thread_pc_and_state_with_handle")(kernel32, 0, _MISSING_TID)

    assert result == (0, "unknown")


def test_thread_pc_read_swallows_argument_conversion_errors(scripted_bridge: ScriptedBridge) -> None:
    """If ctypes rejects the ``SuspendThread`` argument the result is ``(0, "unknown")`` instead of an exception.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.SuspendThread.argtypes = [ctypes.POINTER(ctypes.c_int)]

    result = _sync_method(scripted_bridge, "_read_thread_pc_and_state_with_handle")(kernel32, 1234, _MISSING_TID)

    assert result == (0, "unknown")


def test_program_counter_read_is_zero_when_the_64_bit_context_call_fails(scripted_bridge: ScriptedBridge) -> None:
    """``GetThreadContext`` fails for a NULL handle, so the 64-bit program counter reads as 0.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    assert _sync_method(scripted_bridge, "_read_thread_program_counter")(0) == 0


def test_program_counter_read_is_zero_when_the_wow64_context_call_fails(scripted_bridge: ScriptedBridge) -> None:
    """``Wow64GetThreadContext`` fails for a NULL handle, so a 32-bit target's program counter reads as 0.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.is_64bit = False

    assert _sync_method(scripted_bridge, "_read_thread_program_counter")(0) == 0


def test_thread_enumeration_yields_nothing_for_a_snapshot_without_thread_data(scripted_bridge: ScriptedBridge) -> None:
    """A process-only snapshot holds no thread information, so ``Thread32First`` fails and nothing is listed.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    kernel32 = _typed_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    assert snapshot != INVALID_HANDLE_VALUE
    threads: list[ThreadInfo] = []
    try:
        _sync_method(scripted_bridge, "_enumerate_attached_threads")(kernel32, snapshot, _ThreadEntry32, threads)
    finally:
        kernel32.CloseHandle(snapshot)

    assert threads == []


def test_parent_pid_lookup_returns_zero_for_a_snapshot_without_process_data() -> None:
    """A thread-only snapshot holds no process information, so ``Process32FirstW`` fails and the parent is 0."""
    kernel32 = _typed_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    assert snapshot != INVALID_HANDLE_VALUE
    try:
        result = _sync_method(X64DbgBridge, "_find_parent_pid_in_snapshot")(kernel32, snapshot, _ProcessEntry32W, os.getpid())
    finally:
        kernel32.CloseHandle(snapshot)

    assert result == 0


@pytest.mark.asyncio
async def test_module_snapshot_failure_reports_the_operating_system_error() -> None:
    """A snapshot that fails for a reason other than a transient length error raises with the OS error code."""
    kernel32 = _typed_kernel32()
    probe = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, _MISSING_PID)
    assert probe == INVALID_HANDLE_VALUE
    expected_code = ctypes.get_last_error()

    with pytest.raises(ToolError, match=rf"failed to create snapshot for modules PID {_MISSING_PID}") as info:
        await _async_method(X64DbgBridge, "_create_module_snapshot_with_retry")(kernel32, _MISSING_PID)

    assert info.value.exit_code == expected_code


@pytest.mark.asyncio
async def test_get_modules_raises_when_the_module_snapshot_cannot_be_created(scripted_bridge: ScriptedBridge) -> None:
    """Listing modules of a process id that does not exist must raise, as its docstring promises.

    ``CreateToolhelp32Snapshot`` returns ``INVALID_HANDLE_VALUE`` for such a pid. ``_get_modules`` calls
    it through a ``kernel32`` binding that has no ``restype``, so the result is a signed ``-1`` that
    never matches the unsigned sentinels and the failure goes unnoticed (an empty list is returned after
    the verification window instead of a ``ToolError``).

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.attached_pid = _MISSING_PID

    with pytest.raises(ToolError, match="failed to create snapshot for modules"):
        await scripted_bridge.get_modules()


@pytest.mark.asyncio
async def test_read_pe_header_rejects_a_missing_dos_signature(scripted_bridge: ScriptedBridge) -> None:
    """Memory that does not start with ``MZ`` is not a PE image.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = {_BASE: [b"\x00" * 64]}

    with pytest.raises(ToolError, match=re.escape("Invalid DOS header in synthetic.dll")):
        await _async_method(scripted_bridge, "_read_pe_header")(_BASE, "synthetic.dll")


@pytest.mark.asyncio
async def test_read_pe_header_rejects_a_missing_nt_signature(scripted_bridge: ScriptedBridge) -> None:
    """A DOS header whose ``e_lfanew`` does not point at the NT signature is rejected.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = _module_memory(_BASE, b"XXXX" + b"\x00" * 60)

    with pytest.raises(ToolError, match=re.escape("Invalid PE signature in synthetic.dll")):
        await _async_method(scripted_bridge, "_read_pe_header")(_BASE, "synthetic.dll")


@pytest.mark.asyncio
async def test_read_module_entry_point_is_zero_when_the_header_cannot_be_read(scripted_bridge: ScriptedBridge) -> None:
    """An unreadable PE header leaves the entry point at 0 instead of failing module enumeration.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = {_BASE: [ToolError("ReadProcessMemory failed")]}

    assert await _async_method(scripted_bridge, "_read_module_entry_point")(_BASE, "synthetic.dll") == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "nt_header",
    [
        _nt_header()[:14],
        _nt_header()[:24],
        _nt_header(optional_size=0),
        _nt_header()[:40],
    ],
    ids=["truncated-coff-header", "truncated-before-optional-magic", "empty-optional-header", "header-too-short-for-entry-point"],
)
async def test_read_module_entry_point_is_zero_for_a_damaged_header(scripted_bridge: ScriptedBridge, nt_header: bytes) -> None:
    """Truncated or empty NT headers cannot carry an entry point, so it is reported as 0.

    Args:
        scripted_bridge: Fresh scripted bridge.
        nt_header: NT header bytes served to the bridge.
    """
    scripted_bridge.memory_script = _module_memory(_BASE, nt_header)

    assert await _async_method(scripted_bridge, "_read_module_entry_point")(_BASE, "synthetic.dll") == 0


@pytest.mark.asyncio
async def test_read_module_entry_point_returns_base_plus_address_of_entry_point(scripted_bridge: ScriptedBridge) -> None:
    """The entry point is ``base + AddressOfEntryPoint`` (optional header offset 16 per the PE specification).

    The synthetic header places ``AddressOfEntryPoint = 0x1234`` at optional-header offset 16 and
    operating-system version fields at offset 40, so reading the wrong field gives a different value.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = _module_memory(_BASE, _nt_header(entry_rva=0x1234))

    entry_point = await _async_method(scripted_bridge, "_read_module_entry_point")(_BASE, "synthetic.dll")

    assert entry_point == _BASE + 0x1234


@pytest.mark.asyncio
async def test_get_entry_point_reports_the_pe_address_of_entry_point(attached_bridge: ScriptedBridge) -> None:
    """``get_entry_point`` on the real kernel32 must equal ``pefile``'s ``AddressOfEntryPoint`` for the same file.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    expected_rva = _address_of_entry_point("kernel32.dll")

    result = await attached_bridge.get_entry_point("kernel32.dll")

    assert int(result["entry_point_rva"], 16) == expected_rva
    assert int(result["entry_point_va"], 16) == _loaded_module_base("kernel32.dll") + expected_rva


@pytest.mark.asyncio
async def test_get_modules_entry_point_is_base_plus_address_of_entry_point(attached_bridge: ScriptedBridge) -> None:
    """The entry point ``get_modules`` records for kernel32 must be its load base plus ``AddressOfEntryPoint``.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    expected_rva = _address_of_entry_point("kernel32.dll")

    modules = await attached_bridge.get_modules()

    kernel32 = next(module for module in modules if module.name.lower() == "kernel32.dll")
    assert kernel32.entry_point == _loaded_module_base("kernel32.dll") + expected_rva


@pytest.mark.asyncio
async def test_get_entry_point_defaults_to_the_attached_binary_name(attached_bridge: ScriptedBridge) -> None:
    """Without a module name the entry-point lookup targets the file name of the loaded binary.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    attached_bridge.binary_path = Path(os.environ["SYSTEMROOT"]) / "System32" / "kernel32.dll"

    result = await attached_bridge.get_entry_point()

    assert result["module"] == "kernel32.dll"
    assert int(result["base_address"], 16) == _loaded_module_base("kernel32.dll")


@pytest.mark.asyncio
async def test_get_entry_point_falls_back_to_the_first_loaded_module(attached_bridge: ScriptedBridge) -> None:
    """With neither a module name nor a binary path the first enumerated module is used.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    modules = await attached_bridge.get_modules()

    result = await attached_bridge.get_entry_point()

    assert result["module"] == modules[0].name
    assert int(result["base_address"], 16) == modules[0].base_address


@pytest.mark.asyncio
async def test_get_entry_point_rejects_headers_too_short_for_the_entry_point(attached_bridge: ScriptedBridge) -> None:
    """A header too short to hold the optional header's entry-point field raises a clear error.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    attached_bridge.memory_script = _module_memory(_loaded_module_base("kernel32.dll"), _nt_header()[:32])

    with pytest.raises(ToolError, match=re.escape("PE header too small to read entry point in kernel32.dll")):
        await attached_bridge.get_entry_point("kernel32.dll")


@pytest.mark.asyncio
async def test_get_module_sections_reads_a_section_table_that_fits_the_header(attached_bridge: ScriptedBridge) -> None:
    """A section table inside the first header read is parsed per the IMAGE_SECTION_HEADER layout.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    base = _loaded_module_base("kernel32.dll")
    section = struct.pack("<8sIIIIIIHHI", b".text", 0x500, 0x1000, 0x600, 0x400, 0, 0, 0, 0, 0x60000020)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0x2022)
    attached_bridge.memory_script = _module_memory(base, b"PE\x00\x00" + coff + section)

    sections = await attached_bridge.get_module_sections("kernel32.dll")

    assert sections == [
        {
            "name": ".text",
            "virtual_address": hex(base + 0x1000),
            "virtual_size": 0x500,
            "raw_size": 0x600,
            "characteristics": "0x60000020",
            "readable": True,
            "writable": False,
            "executable": True,
        },
    ]


@pytest.mark.asyncio
async def test_read_export_tables_rejects_headers_too_small_for_the_export_directory(scripted_bridge: ScriptedBridge) -> None:
    """A header that ends before the export data directory entry cannot describe exports.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    with pytest.raises(ToolError, match="PE header too small for export directory"):
        await _async_method(scripted_bridge, "_read_export_tables")(_BASE, _nt_header()[:100])


@pytest.mark.asyncio
async def test_read_export_tables_rejects_a_module_without_an_export_directory(scripted_bridge: ScriptedBridge) -> None:
    """A zero export RVA/size means the module exports nothing.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    with pytest.raises(ToolError, match="No export directory"):
        await _async_method(scripted_bridge, "_read_export_tables")(_BASE, _nt_header())


@pytest.mark.asyncio
async def test_read_export_name_reraises_errors_that_are_not_a_missing_rpc(scripted_bridge: ScriptedBridge) -> None:
    """A real read failure (not an unknown-command downgrade) must reach the caller.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.memory_script = {_BASE + 0x2200: [_plugin_error("remote_error", "remote read failed")]}

    with pytest.raises(ToolError, match="remote read failed"):
        await _async_method(scripted_bridge, "_read_export_name")(_BASE, 0x2200, 7, "synthetic.dll")


@pytest.mark.asyncio
async def test_read_export_name_substitutes_an_ordinal_name_for_a_recoverable_failure(scripted_bridge: ScriptedBridge) -> None:
    """A recoverable read failure yields the synthetic ``ordinal_<n>`` name and returns the error.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    failure = _unknown_command()
    scripted_bridge.memory_script = {_BASE + 0x2200: [failure]}

    name, error = await _async_method(scripted_bridge, "_read_export_name")(_BASE, 0x2200, 7, "synthetic.dll")

    assert name == "ordinal_7"
    assert isinstance(error, ToolError)
    assert str(error) == str(failure)
    assert _code(error) == "unknown_command"


@pytest.mark.asyncio
async def test_build_export_entries_returns_the_last_recoverable_read_error(scripted_bridge: ScriptedBridge) -> None:
    """Export entries keep going after a recoverable name-read failure and report that failure.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    failure = _unknown_command()
    scripted_bridge.memory_script = {_BASE + 0x2200: [failure]}
    tables = (struct.pack("<I", _FUNCTION_RVA), struct.pack("<I", 0x2200), struct.pack("<H", 0), 1, 1, 1)

    entries, last_error = await _async_method(scripted_bridge, "_build_export_entries")(_BASE, "synthetic.dll", tables)

    assert entries == [{"ordinal": 1, "name": "ordinal_1", "address": hex(_BASE + _FUNCTION_RVA), "truncated": False}]
    assert isinstance(last_error, ToolError)
    assert str(last_error) == str(failure)


@pytest.mark.asyncio
async def test_get_module_exports_returns_nothing_for_a_module_without_exports(attached_bridge: ScriptedBridge) -> None:
    """A module whose export tables cannot be read yields an empty export list.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    attached_bridge.memory_script = _module_memory(_loaded_module_base("kernel32.dll"), _nt_header())

    assert await attached_bridge.get_module_exports("kernel32.dll") == []


@pytest.mark.asyncio
async def test_get_module_exports_tolerates_a_recoverable_name_read_failure(attached_bridge: ScriptedBridge) -> None:
    """An export whose name cannot be read is still listed, named by its ordinal.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    base = _loaded_module_base("kernel32.dll")
    attached_bridge.memory_script = _export_memory(base, _unknown_command())

    exports = await attached_bridge.get_module_exports("kernel32.dll")

    assert exports == [{"ordinal": 1, "name": "ordinal_1", "address": hex(base + _FUNCTION_RVA), "truncated": False}]


@pytest.mark.asyncio
async def test_get_debug_registers_accepts_integer_register_values(scripted_bridge: ScriptedBridge) -> None:
    """Debug registers returned as integers are kept as integers, in DR0-DR3, DR6, DR7 order.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"reg_get": [1, 2, 3, 4, 5, 6]}

    registers = await scripted_bridge.get_debug_registers()

    assert registers == {"dr0": 1, "dr1": 2, "dr2": 3, "dr3": 4, "dr6": 5, "dr7": 6}


@pytest.mark.asyncio
async def test_get_extended_registers_rejects_a_non_object_response(scripted_bridge: ScriptedBridge) -> None:
    """The extended register file must be a JSON object; any other payload is a remote error.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"reg_extended": [["not", "an", "object"]]}

    with pytest.raises(ToolError, match="reg_extended returned a non-object response") as info:
        await scripted_bridge.get_extended_registers()

    assert _code(info.value) == "remote_error"


@pytest.mark.asyncio
async def test_wait_for_instruction_pointer_reraises_a_non_unknown_command_failure(scripted_bridge: ScriptedBridge) -> None:
    """Only ``unknown_command`` means "cannot poll"; any other ``reg_get`` failure propagates.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"reg_get": [_plugin_error("timeout", "reg_get timed out")]}

    with pytest.raises(ToolError, match="reg_get timed out") as info:
        await _async_method(scripted_bridge, "_wait_for_instruction_pointer")(_TARGET_ADDRESS, timeout_s=0.1)

    assert _code(info.value) == "timeout"


@pytest.mark.asyncio
async def test_wait_for_instruction_pointer_returns_none_when_the_value_is_not_numeric(scripted_bridge: ScriptedBridge) -> None:
    """A ``reg_get`` payload that is neither an integer nor a string never yields an observed instruction pointer.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"reg_get": [None]}

    observed = await _async_method(scripted_bridge, "_wait_for_instruction_pointer")(_TARGET_ADDRESS, timeout_s=0.1)

    assert observed is None


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "fragment"),
    [
        ("run_to_user_code", (), "run_to_user_code verification failed"),
        ("run_to_party", (1,), "run_to_party verification failed"),
        ("step_into_user_code", (), "step_into_user_code verification failed"),
        ("step_into_system_code", (), "step_into_system_code verification failed"),
        ("step_extended", (), "step_extended verification failed"),
    ],
)
async def test_run_and_step_wrappers_fail_when_the_debugger_never_starts_running(
    running_bridge: ScriptedBridge,
    method: str,
    args: tuple[int, ...],
    fragment: str,
) -> None:
    """If ``status`` keeps reporting a paused debugger the run/step wrapper raises a timeout error.

    Args:
        running_bridge: Scripted bridge with a live process.
        method: Bridge method under test.
        args: Positional arguments for the method.
        fragment: Text the error message must contain.
    """
    running_bridge.pipe_script = {"exec": [""], "status": [{"paused": True, "debugging": True}]}

    with pytest.raises(ToolError, match=re.escape(fragment)) as info:
        await _async_method(running_bridge, method)(*args)

    assert _code(info.value) == "timeout"


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "expected"),
    [
        ("run_to_user_code", (), {"success": True, "verified": False}),
        ("run_to_party", (1,), {"success": True, "party": 1, "verified": False}),
    ],
)
async def test_run_wrappers_report_unverified_success_when_status_is_unavailable(
    running_bridge: ScriptedBridge,
    method: str,
    args: tuple[int, ...],
    expected: dict[str, object],
) -> None:
    """A plugin without the ``status`` RPC cannot verify the run, so success is reported as unverified.

    Args:
        running_bridge: Scripted bridge with a live process.
        method: Bridge method under test.
        args: Positional arguments for the method.
        expected: Expected result dictionary.
    """
    running_bridge.pipe_script = {"exec": [""], "status": [_unknown_command()]}

    assert await _async_method(running_bridge, method)(*args) == expected


@pytest.mark.asyncio
async def test_wait_for_running_state_gives_up_when_status_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """A plugin that never knows ``status`` yields ``(None, False)`` once the window elapses.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"status": [_unknown_command()]}

    result = await _async_method(scripted_bridge, "_wait_for_running_state")(expected=True)

    assert result == (None, False)


@pytest.mark.asyncio
async def test_wait_for_running_state_reraises_other_status_failures(scripted_bridge: ScriptedBridge) -> None:
    """A ``status`` failure other than an unknown command is surfaced.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"status": [_plugin_error("pipe_disconnected", "pipe disconnected")]}

    with pytest.raises(ToolError, match="pipe disconnected") as info:
        await _async_method(scripted_bridge, "_wait_for_running_state")(expected=True)

    assert _code(info.value) == "pipe_disconnected"


@pytest.mark.asyncio
async def test_wait_for_running_state_reports_no_observation_for_a_non_object_status(scripted_bridge: ScriptedBridge) -> None:
    """A ``status`` payload that is not an object carries no running flag, so nothing is observed.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"status": ["running"]}

    result = await _async_method(scripted_bridge, "_wait_for_running_state")(expected=True)

    assert result == (None, True)


@pytest.mark.asyncio
async def test_wait_for_running_state_derives_running_from_the_paused_flag_alone(scripted_bridge: ScriptedBridge) -> None:
    """Without a ``debugging`` flag, ``paused=False`` means the debugger is running.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"status": [{"paused": False}]}

    result = await _async_method(scripted_bridge, "_wait_for_running_state")(expected=True)

    assert result == (True, True)


@pytest.mark.asyncio
async def test_query_script_error_is_none_when_eval_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """A plugin without the ``eval`` RPC cannot report the script error flag.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"eval": [_unknown_command()]}

    assert await _async_method(scripted_bridge, "_query_script_error")() is None


@pytest.mark.asyncio
async def test_query_script_error_reraises_other_eval_failures(scripted_bridge: ScriptedBridge) -> None:
    """Any ``eval`` failure other than an unknown command propagates.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"eval": [_plugin_error("timeout", "eval timed out")]}

    with pytest.raises(ToolError, match="eval timed out"):
        await _async_method(scripted_bridge, "_query_script_error")()


@pytest.mark.asyncio
async def test_query_plugin_present_reraises_plugin_list_failures(scripted_bridge: ScriptedBridge) -> None:
    """A ``plugin_list`` failure other than an unknown command propagates.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"plugin_list": [_plugin_error("timeout", "plugin_list timed out")]}

    with pytest.raises(ToolError, match="plugin_list timed out"):
        await _async_method(scripted_bridge, "_query_plugin_present")("MyPlugin")


@pytest.mark.asyncio
async def test_query_plugin_present_matches_names_case_insensitively_across_key_variants(scripted_bridge: ScriptedBridge) -> None:
    """Non-object entries and other plugins are skipped; ``plugName`` is accepted as the name key.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"plugin_list": [["junk", {"name": "other"}, {"plugName": "MyPlugin"}]]}

    assert await _async_method(scripted_bridge, "_query_plugin_present")("myplugin") is True


@pytest.mark.asyncio
async def test_query_plugin_present_is_false_when_no_listed_plugin_matches(scripted_bridge: ScriptedBridge) -> None:
    """A plugin list that does not contain the name means the plugin is absent.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"plugin_list": [["junk", {"name": "other"}]]}

    assert await _async_method(scripted_bridge, "_query_plugin_present")("MyPlugin") is False


@pytest.mark.asyncio
async def test_query_plugin_present_is_none_when_neither_rpc_exists(scripted_bridge: ScriptedBridge) -> None:
    """With neither ``plugin_list`` nor ``eval`` available presence cannot be determined.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"plugin_list": [_unknown_command()], "eval": [_unknown_command()]}

    assert await _async_method(scripted_bridge, "_query_plugin_present")("MyPlugin") is None


@pytest.mark.asyncio
async def test_query_plugin_present_reraises_plugin_find_failures(scripted_bridge: ScriptedBridge) -> None:
    """The ``plugin.find`` fallback also propagates failures other than an unknown command.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"plugin_list": [_unknown_command()], "eval": [_plugin_error("timeout", "eval timed out")]}

    with pytest.raises(ToolError, match="eval timed out"):
        await _async_method(scripted_bridge, "_query_plugin_present")("MyPlugin")


@pytest.mark.asyncio
async def test_lookup_label_text_reraises_failures_other_than_unknown_command(scripted_bridge: ScriptedBridge) -> None:
    """Reading a label back can only be skipped for a missing RPC; real failures propagate.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"lbl_list": [_plugin_error("pipe_disconnected", "pipe disconnected")]}

    with pytest.raises(ToolError, match="pipe disconnected"):
        await _async_method(scripted_bridge, "_lookup_label_text")(_TARGET_ADDRESS)


@pytest.mark.asyncio
async def test_lookup_label_text_is_empty_for_a_non_list_response(scripted_bridge: ScriptedBridge) -> None:
    """A non-list ``lbl_list`` payload is treated as "no label here".

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"lbl_list": [{"unexpected": "object"}]}

    text = await _async_method(scripted_bridge, "_lookup_label_text")(_TARGET_ADDRESS)

    assert isinstance(text, str)
    assert not text


@pytest.mark.asyncio
async def test_lookup_label_text_selects_the_entry_for_the_requested_address(scripted_bridge: ScriptedBridge) -> None:
    """Non-object entries, entries without a parseable address and other addresses are skipped.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {
        "lbl_list": [
            [
                "junk",
                {"address": "bogus", "text": "nope"},
                {"address": "0x1", "text": "other"},
                {"address": "0x401000", "text": "main"},
            ],
        ],
    }

    assert await _async_method(scripted_bridge, "_lookup_label_text")(_TARGET_ADDRESS) == "main"


@pytest.mark.parametrize(
    ("method", "rpc"),
    [("_query_bp_list", "bp_list"), ("_query_thread_details", "thread_detail")],
)
@pytest.mark.asyncio
async def test_list_queries_are_none_when_the_rpc_is_unknown(scripted_bridge: ScriptedBridge, method: str, rpc: str) -> None:
    """A plugin that lacks the list RPC reports ``None`` so callers can mark verification unavailable.

    Args:
        scripted_bridge: Fresh scripted bridge.
        method: Query helper under test.
        rpc: Pipe command the helper issues.
    """
    scripted_bridge.pipe_script = {rpc: [_unknown_command()]}

    assert await _async_method(scripted_bridge, method)() is None


@pytest.mark.parametrize(
    ("method", "rpc"),
    [("_query_bp_list", "bp_list"), ("_query_thread_details", "thread_detail")],
)
@pytest.mark.asyncio
async def test_list_queries_reraise_other_failures(scripted_bridge: ScriptedBridge, method: str, rpc: str) -> None:
    """A list RPC failure other than an unknown command propagates to the caller.

    Args:
        scripted_bridge: Fresh scripted bridge.
        method: Query helper under test.
        rpc: Pipe command the helper issues.
    """
    scripted_bridge.pipe_script = {rpc: [_plugin_error("timeout", f"{rpc} timed out")]}

    with pytest.raises(ToolError, match=f"{rpc} timed out"):
        await _async_method(scripted_bridge, method)()


@pytest.mark.asyncio
async def test_query_thread_details_is_empty_for_a_non_list_response(scripted_bridge: ScriptedBridge) -> None:
    """A ``thread_detail`` payload that is not a list means no threads were reported.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"thread_detail": [{"unexpected": "object"}]}

    assert await _async_method(scripted_bridge, "_query_thread_details")() == []


def test_find_bp_enabled_skips_non_objects_and_other_addresses() -> None:
    """Only the entry for the requested address supplies the enabled flag."""
    entries: list[object] = [
        "junk",
        {"address": "0x1", "enabled": True},
        {"address": "0x2", "enabled": False},
    ]

    assert _sync_method(X64DbgBridge, "_find_bp_enabled")(entries, 2) is False


def test_find_thread_record_ignores_entries_whose_id_is_not_the_integer_requested() -> None:
    """A string thread id never matches, and the first integer-id match is returned."""
    entries: list[dict[str, object]] = [
        {"threadId": "7", "name": "string-id"},
        {"threadId": 8, "name": "other"},
        {"threadId": 7, "name": "match"},
    ]

    assert _sync_method(X64DbgBridge, "_find_thread_record")(entries, 7) == {"threadId": 7, "name": "match"}


@pytest.mark.asyncio
async def test_wait_for_breakpoint_state_reports_unavailable_when_bp_list_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """A plugin without ``bp_list`` yields ``(None, False)`` once the window elapses.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"bp_list": [_unknown_command()]}

    result = await _async_method(scripted_bridge, "_wait_for_breakpoint_enabled_state")(_TARGET_ADDRESS, expected=True)

    assert result == (None, False)


@pytest.mark.asyncio
async def test_disable_breakpoint_fails_when_bp_list_never_shows_the_breakpoint(scripted_bridge: ScriptedBridge) -> None:
    """If ``bp_list`` answers but never lists the breakpoint, disabling cannot be verified and raises.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"exec": [""], "bp_list": [[]]}

    with pytest.raises(
        ToolError,
        match=re.escape("disable_breakpoint verification failed: bp_list returned no entry for 0x401000"),
    ) as info:
        await scripted_bridge.disable_breakpoint(_TARGET_ADDRESS)

    assert _code(info.value) == "timeout"
    assert ("exec", {"command": "bd 0x401000"}) in scripted_bridge.sent


@pytest.mark.asyncio
async def test_skip_instruction_fails_when_nothing_disassembles_at_the_instruction_pointer(scripted_bridge: ScriptedBridge) -> None:
    """An empty disassembly at the current instruction pointer is an error, not a zero-length skip.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"reg_all": [{"rip": "0x401000"}], "disasm": [[]]}

    with pytest.raises(ToolError, match=re.escape("Cannot disassemble instruction at 0x401000")):
        await scripted_bridge.skip_instruction()


@pytest.mark.asyncio
async def test_get_labels_is_empty_for_a_non_list_response(scripted_bridge: ScriptedBridge) -> None:
    """A non-list ``lbl_list`` payload yields no labels.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"lbl_list": [{"unexpected": "object"}]}

    assert await scripted_bridge.get_labels(0, 0x100) == []


@pytest.mark.asyncio
async def test_get_labels_keeps_only_parseable_in_range_entries(scripted_bridge: ScriptedBridge) -> None:
    """Non-object entries, unparseable addresses and out-of-range addresses are dropped.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {
        "lbl_list": [
            [
                "junk",
                {"address": "bogus", "text": "bad"},
                {"address": "0x10", "text": "inside"},
                {"address": "0x99999", "text": "outside"},
            ],
        ],
    }

    assert await scripted_bridge.get_labels(0, 0x100) == [{"address": "0x10", "text": "inside"}]


@pytest.mark.asyncio
async def test_get_comments_is_empty_for_a_non_list_response(scripted_bridge: ScriptedBridge) -> None:
    """A non-list ``cmt_list`` payload yields no comments.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"cmt_list": [{"unexpected": "object"}]}

    assert await scripted_bridge.get_comments(0, 0x100) == []


@pytest.mark.asyncio
async def test_get_comments_keeps_only_parseable_in_range_entries(scripted_bridge: ScriptedBridge) -> None:
    """Non-object entries, unparseable addresses and out-of-range addresses are dropped.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {
        "cmt_list": [
            [
                "junk",
                {"address": "bogus", "text": "bad"},
                {"address": "0x10", "text": "inside"},
                {"address": "0x99999", "text": "outside"},
            ],
        ],
    }

    assert await scripted_bridge.get_comments(0, 0x100) == [{"address": "0x10", "text": "inside"}]


@pytest.mark.asyncio
async def test_delete_label_is_unverified_when_lbl_list_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """Without ``lbl_list`` the deletion is reported as successful but unverified.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"exec": [""], "lbl_list": [_unknown_command()]}

    result = await scripted_bridge.delete_label(_TARGET_ADDRESS)

    assert result == {"address": "0x401000", "success": True, "verified": False}
    assert ("exec", {"command": "labeldel 0x401000"}) in scripted_bridge.sent


@pytest.mark.asyncio
async def test_set_comment_is_unverified_when_cmt_list_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """Without ``cmt_list`` the comment is reported as set but unverified, with its text quoted in the command.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"exec": [""], "cmt_list": [_unknown_command()]}

    result = await scripted_bridge.set_comment(_TARGET_ADDRESS, "loop body")

    assert result == {"address": "0x401000", "text": "loop body", "success": True, "verified": False}
    assert ("exec", {"command": 'cmtset 0x401000, "loop body"'}) in scripted_bridge.sent


@pytest.mark.asyncio
async def test_delete_comment_is_unverified_when_cmt_list_is_unknown(scripted_bridge: ScriptedBridge) -> None:
    """Without ``cmt_list`` the deletion is reported as successful but unverified.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"exec": [""], "cmt_list": [_unknown_command()]}

    result = await scripted_bridge.delete_comment(_TARGET_ADDRESS)

    assert result == {"address": "0x401000", "success": True, "verified": False}
    assert ("exec", {"command": "commentdel 0x401000"}) in scripted_bridge.sent


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_load_library_accepts_an_integer_result_register(running_bridge: ScriptedBridge) -> None:
    """``$result`` returned as an integer is the loaded module's base address.

    Args:
        running_bridge: Scripted bridge with a live process.
    """
    running_bridge.pipe_script = {"exec": [""], "reg_get": [0x7FFA0000]}

    result = await running_bridge.load_library("helper.dll")

    assert result == {"success": True, "path": "helper.dll", "base_address": "0x7ffa0000"}
    assert ("exec", {"command": 'loadlib "helper.dll"'}) in running_bridge.sent


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "expected"),
    [
        ("suspend_thread", (7,), {"success": True, "tid": 7, "verified": False}),
        ("resume_thread", (7,), {"success": True, "tid": 7, "verified": False}),
        ("switch_thread", (7,), {"success": True, "tid": 7, "verified": False}),
        ("set_thread_name", (7, "worker"), {"success": True, "tid": 7, "name": "worker", "verified": False}),
    ],
)
async def test_thread_wrappers_are_unverified_when_thread_detail_is_unknown(
    running_bridge: ScriptedBridge,
    method: str,
    args: tuple[object, ...],
    expected: dict[str, object],
) -> None:
    """A plugin without ``thread_detail`` cannot confirm a thread change, so success is reported as unverified.

    Args:
        running_bridge: Scripted bridge with a live process.
        method: Bridge method under test.
        args: Positional arguments for the method.
        expected: Expected result dictionary.
    """
    running_bridge.pipe_script = {"exec": [""], "thread_detail": [_unknown_command()]}

    assert await _async_method(running_bridge, method)(*args) == expected


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "fragment"),
    [
        ("suspend_thread", (7,), "suspend_thread verification failed: thread_detail returned no entry for tid=7"),
        ("resume_thread", (7,), "resume_thread verification failed: thread_detail returned no entry for tid=7"),
        ("set_thread_name", (7, "worker"), "set_thread_name verification failed: thread_detail returned no entry for tid=7"),
    ],
)
async def test_thread_wrappers_fail_when_thread_detail_never_lists_the_thread(
    running_bridge: ScriptedBridge,
    method: str,
    args: tuple[object, ...],
    fragment: str,
) -> None:
    """If ``thread_detail`` answers but never lists the thread, the change cannot be verified and raises.

    Args:
        running_bridge: Scripted bridge with a live process.
        method: Bridge method under test.
        args: Positional arguments for the method.
        fragment: Text the error message must contain.
    """
    running_bridge.pipe_script = {"exec": [""], "thread_detail": [[]]}

    with pytest.raises(ToolError, match=re.escape(fragment)) as info:
        await _async_method(running_bridge, method)(*args)

    assert _code(info.value) == "timeout"


@pytest.mark.asyncio
async def test_memory_verification_read_returns_none_for_unreadable_memory(attached_bridge: ScriptedBridge) -> None:
    """A verification read that fails (here: the unmapped first page) yields ``None`` instead of raising.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    result = await _async_method(attached_bridge, "_read_memory_for_verification")(0x10, 4)

    assert result is None


@pytest.mark.asyncio
async def test_await_memory_change_returns_the_last_good_read_when_a_later_read_fails(attached_bridge: ScriptedBridge) -> None:
    """When memory is unchanged and then becomes unreadable, the last successful read is returned.

    Args:
        attached_bridge: Bridge attached to this process.
    """
    attached_bridge.memory_script = {_TARGET_ADDRESS: [b"\x90", ToolError("ReadProcessMemory failed")]}

    result = await _async_method(attached_bridge, "_await_memory_change")(_TARGET_ADDRESS, 1, b"\x90")

    assert result == b"\x90"


@pytest.mark.asyncio
async def test_get_function_cfg_returns_an_empty_graph_for_a_non_object_response(scripted_bridge: ScriptedBridge) -> None:
    """A ``cfg`` payload that is not an object degrades to an empty graph for the requested entry.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"cfg": [["not", "an", "object"]]}

    assert await scripted_bridge.get_function_cfg(_TARGET_ADDRESS) == {"entry": "0x401000", "blocks": [], "edges": []}


@pytest.mark.spawns_process
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "rpc", "fallback"),
    [
        ("load_database", (), "db_load", "dbload"),
        ("clear_database", (), "db_clear", "dbclear"),
        ("add_watch", ("rax+4",), "watch_add", 'AddWatch "rax+4"'),
        ("remove_watch", (2,), "watch_remove", "DelWatch 2"),
    ],
)
async def test_database_and_watch_wrappers_fall_back_to_console_commands(
    running_bridge: ScriptedBridge,
    method: str,
    args: tuple[object, ...],
    rpc: str,
    fallback: str,
) -> None:
    """When the plugin lacks the RPC the wrapper issues the equivalent x64dbg console command.

    Args:
        running_bridge: Scripted bridge with a live process.
        method: Bridge method under test.
        args: Positional arguments for the method.
        rpc: Pipe command tried first.
        fallback: Console command expected afterwards.
    """
    running_bridge.pipe_script = {rpc: [_unknown_command()], "exec": [""]}

    result = await _async_method(running_bridge, method)(*args)

    assert result["success"] is True
    assert running_bridge.sent[-1] == ("exec", {"command": fallback})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "args", "rpc"),
    [
        ("load_database", (), "db_load"),
        ("clear_database", (), "db_clear"),
        ("get_patches", (), "patch_list"),
        ("get_seh_chain", (), "seh_chain"),
        ("read_teb", (), "teb_read"),
        ("get_pe_directories", ("kernel32.dll",), "pe_directories"),
        ("add_watch", ("rax",), "watch_add"),
        ("remove_watch", (1,), "watch_remove"),
    ],
)
async def test_wrappers_reraise_plugin_errors_that_are_not_a_missing_rpc(
    scripted_bridge: ScriptedBridge,
    method: str,
    args: tuple[object, ...],
    rpc: str,
) -> None:
    """Only an unknown RPC may be downgraded; a real plugin failure must reach the caller unchanged.

    Args:
        scripted_bridge: Fresh scripted bridge.
        method: Bridge method under test.
        args: Positional arguments for the method.
        rpc: Pipe command the method issues first.
    """
    scripted_bridge.pipe_script = {rpc: [_plugin_error("remote_error", f"{rpc} failed remotely")]}

    with pytest.raises(ToolError, match=f"{rpc} failed remotely") as info:
        await _async_method(scripted_bridge, method)(*args)

    assert _code(info.value) == "remote_error"


@pytest.mark.asyncio
async def test_get_patches_is_empty_when_the_rpc_is_missing(scripted_bridge: ScriptedBridge) -> None:
    """A plugin without ``patch_list`` reports no patches rather than failing.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"patch_list": [_unknown_command()]}

    assert await scripted_bridge.get_patches() == []


@pytest.mark.asyncio
async def test_get_pe_directories_is_empty_for_a_non_list_response(scripted_bridge: ScriptedBridge) -> None:
    """A ``pe_directories`` payload that is not a list yields no directory entries.

    Args:
        scripted_bridge: Fresh scripted bridge.
    """
    scripted_bridge.pipe_script = {"pe_directories": [{"unexpected": "object"}]}

    assert await scripted_bridge.get_pe_directories("kernel32.dll") == []


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_export_patches_rejects_a_stale_file_that_already_has_the_expected_size(
    running_bridge: ScriptedBridge,
    tmp_path: Path,
) -> None:
    """A pre-existing file of the right size that was not rewritten is not evidence of a successful export.

    Two patched bytes at 0x1000 and 0x1003 span 4 bytes, so ``savedata`` must dump 0x1000..0x1003. The
    output file already exists with exactly 4 bytes and is never touched, so the bridge must refuse to
    report success.

    Args:
        running_bridge: Scripted bridge with a live process.
        tmp_path: Per-test temporary directory.
    """
    output = tmp_path / "patches.bin"
    _write_stale_file(output, 4)
    running_bridge.pipe_script = {"patch_list": [[{"address": "0x1000"}, {"address": "0x1003"}]], "exec": [""]}

    with pytest.raises(ToolError, match="export_patches verification failed") as info:
        await running_bridge.export_patches(str(output))

    assert info.value.details["expected_size"] == 4
    assert ("exec", {"command": f'savedata "{output}", 0x1000, 0x4'}) in running_bridge.sent
