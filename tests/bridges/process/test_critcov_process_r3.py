# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Third-pass critical-coverage tests for the process bridge: 32-bit targets, stack depth and registry value size.

Every test that touches another process drives the real Win32 APIs against a child the test starts itself: a 32-bit
``cmd.exe`` from the ``SysWOW64`` directory blocked in ``pause`` on an open stdin pipe, or a Python interpreter blocked
in a native read below fifty nested callbacks. All queries are read-only. The expectations come from queries made with the
test's own prototyped Win32 calls (independent module list, thread list, start addresses, x86 ``TEB``/``PEB`` layout,
``VirtualQueryEx`` stack allocation), never from the bridge. The registry tests write a uniquely named scratch value under
``HKEY_CURRENT_USER\Software`` and delete the key in a ``finally``.

The 32-bit environment-block, ``TEB``, SEH-chain and TLS tests marked as defect gates fail until the bridge reads the 32-bit
blocks of a WOW64 target instead of the 64-bit ones and until the ``PEB32`` parser's minimum length matches its structure.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import functools
import itertools
import os
import sys
import threading
import time
import uuid
import winreg
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    IMAGE_FILE_MACHINE_I386,
    INVALID_HANDLE_VALUE,
    MEMORY_BASIC_INFORMATION,
    PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
    TH32CS_SNAPTHREAD,
    THREAD_BASIC_INFORMATION,
    THREAD_QUERY_INFORMATION,
    THREADENTRY32,
    ProcessWow64Information,
    ThreadBasicInformation,
    ThreadQuerySetWin32StartAddress,
)
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 120.0
_PROMPT_WAIT_S: Final[float] = 15.0
_POLL_S: Final[float] = 0.05
_READY: Final[str] = "ready"
_LIST_MODULES_ALL: Final[int] = 3
_MODULE_CAP: Final[int] = 1024
_MAX_PATH_CHARS: Final[int] = 1024
_MIN_LOADED_MODULES: Final[int] = 4
_PEB32_BEING_DEBUGGED_OFFSET: Final[int] = 2
_WOW64_TEB_DELTA: Final[int] = 0x2000
_TEB32_EXCEPTION_LIST_OFFSET: Final[int] = 0x00
_TEB32_STACK_BASE_OFFSET: Final[int] = 0x04
_TEB32_SELF_OFFSET: Final[int] = 0x18
_TEB32_PEB_OFFSET: Final[int] = 0x30
_TEB32_TLS_SLOTS_OFFSET: Final[int] = 0xE10
_ADDRESS_SPACE_32: Final[int] = 1 << 32
_SEH_CHAIN_END: Final[int] = 0xFFFFFFFF
_WOW64_CODE_SEGMENT: Final[int] = 0x23
_WOW64_STACK_SEGMENT: Final[int] = 0x2B
_X86_REGISTERS: Final[frozenset[str]] = frozenset({
    "eax",
    "ebx",
    "ecx",
    "edx",
    "esi",
    "edi",
    "ebp",
    "esp",
    "eip",
    "eflags",
    "cs",
    "ds",
    "es",
    "fs",
    "gs",
    "ss",
    "dr0",
    "dr1",
    "dr2",
    "dr3",
    "dr6",
    "dr7",
})
_REGISTRY_CAP: Final[int] = 16 * 1024 * 1024
_REGISTRY_VALUE: Final[str] = "blob"
_REGISTRY_FILL: Final[bytes] = b"\xab"
_STACK_FRAME_CAP: Final[int] = 256
_DEEP_CALLBACK_DEPTH: Final[str] = "50"

_DEEP_SOURCE: Final[str] = (
    "import ctypes, sys\n"
    "k = ctypes.WinDLL('kernel32')\n"
    "cb_type = ctypes.CFUNCTYPE(None, ctypes.c_int)\n"
    "def f(n):\n"
    "    if n > 0:\n"
    "        cb(n - 1)\n"
    "    else:\n"
    "        sys.stdout.write('ready %d\\n' % k.GetCurrentThreadId())\n"
    "        sys.stdout.flush()\n"
    "        sys.stdin.read()\n"
    "cb = cb_type(f)\n"
    "f(int(sys.argv[1]))\n"
)


class _ModuleInfo(ctypes.Structure):
    """``MODULEINFO`` as filled in by ``GetModuleInformation``."""

    _fields_ = (
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    )


def _run[T](coro: Coroutine[object, object, T]) -> T:
    """Run a coroutine to completion on a private event loop and join its executor threads.

    Args:
        coro: Coroutine to execute.

    Returns:
        T: The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_default_executor())
        finally:
            loop.close()


def sync_method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) synchronous method by name.

    Args:
        obj: Object that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def _as_int(value: object) -> int:
    """Narrow a dictionary value that must be an integer.

    Args:
        value: Value to narrow.

    Returns:
        int: The same value, typed as an integer.
    """
    assert isinstance(value, int)
    return value


@functools.cache
def _k32() -> ctypes.WinDLL:
    """Load a private ``kernel32`` handle with explicit prototypes for the test's own calls.

    Returns:
        ctypes.WinDLL: A ``kernel32`` handle whose function pointers are independent of the bridge's own.
    """
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenProcess.restype = wintypes.HANDLE
    dll.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenThread.restype = wintypes.HANDLE
    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL
    dll.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    dll.ReadProcessMemory.restype = wintypes.BOOL
    dll.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    dll.VirtualQueryEx.restype = ctypes.c_size_t
    dll.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    dll.IsWow64Process2.restype = wintypes.BOOL
    dll.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    dll.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    dll.Thread32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    dll.Thread32First.restype = wintypes.BOOL
    dll.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    dll.Thread32Next.restype = wintypes.BOOL
    return dll


@functools.cache
def _psapi() -> ctypes.WinDLL:
    """Load a private ``psapi`` handle with explicit module-enumeration prototypes.

    Returns:
        ctypes.WinDLL: A ``psapi`` handle whose function pointers are independent of the bridge's own.
    """
    dll = ctypes.WinDLL("psapi", use_last_error=True)
    dll.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    dll.EnumProcessModulesEx.restype = wintypes.BOOL
    dll.GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(_ModuleInfo), wintypes.DWORD]
    dll.GetModuleInformation.restype = wintypes.BOOL
    dll.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.LPWSTR, wintypes.DWORD]
    dll.GetModuleFileNameExW.restype = wintypes.DWORD
    return dll


@functools.cache
def _ntdll() -> ctypes.WinDLL:
    """Load a private ``ntdll`` handle with explicit information-query prototypes.

    Returns:
        ctypes.WinDLL: An ``ntdll`` handle whose function pointers are independent of the bridge's own.
    """
    dll = ctypes.WinDLL("ntdll")
    dll.NtQueryInformationProcess.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    dll.NtQueryInformationProcess.restype = ctypes.c_long
    dll.NtQueryInformationThread.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    dll.NtQueryInformationThread.restype = ctypes.c_long
    return dll


@contextlib.contextmanager
def _process_handle(pid: int, access: int) -> Generator[int]:
    """Open a process handle with exactly ``access`` rights and close it afterwards.

    Args:
        pid: Identifier of the process to open.
        access: Win32 process access mask.

    Yields:
        int: The open process handle.
    """
    inherit_handle = False
    handle: int | None = _k32().OpenProcess(access, inherit_handle, pid)
    assert handle
    try:
        yield handle
    finally:
        _k32().CloseHandle(handle)


@contextlib.contextmanager
def _thread_handle(tid: int, access: int) -> Generator[int]:
    """Open a thread handle with exactly ``access`` rights and close it afterwards.

    Args:
        tid: Identifier of the thread to open.
        access: Win32 thread access mask.

    Yields:
        int: The open thread handle.
    """
    inherit_handle = False
    handle: int | None = _k32().OpenThread(access, inherit_handle, tid)
    assert handle
    try:
        yield handle
    finally:
        _k32().CloseHandle(handle)


def _process_machine(pid: int) -> int:
    """Ask the operating system which machine type a process image targets.

    Args:
        pid: Identifier of the process to query.

    Returns:
        int: The ``IMAGE_FILE_MACHINE_*`` value reported by ``IsWow64Process2`` for the process itself.
    """
    with _process_handle(pid, PROCESS_QUERY_LIMITED_INFORMATION) as handle:
        process_machine = wintypes.USHORT(0)
        native_machine = wintypes.USHORT(0)
        queried: int = _k32().IsWow64Process2(handle, ctypes.byref(process_machine), ctypes.byref(native_machine))
        assert queried
        return process_machine.value


def _read_remote(handle: int, address: int, size: int) -> bytes | None:
    """Read bytes from another process through the test's own ``kernel32``.

    Args:
        handle: Process handle with ``PROCESS_VM_READ`` access.
        address: Address inside the target process.
        size: Number of bytes to read.

    Returns:
        bytes | None: The bytes that were read, or ``None`` when the read is refused.
    """
    buffer = ctypes.create_string_buffer(size)
    count = ctypes.c_size_t(0)
    read_ok: int = _k32().ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(count))
    if not read_ok or count.value != size:
        return None
    return buffer.raw[: count.value]


def _u32(handle: int, address: int) -> int:
    """Read one little-endian 32-bit value from another process.

    Args:
        handle: Process handle with ``PROCESS_VM_READ`` access.
        address: Address inside the target process.

    Returns:
        int: The value stored at ``address``.
    """
    data = _read_remote(handle, address, 4)
    assert data is not None
    return int.from_bytes(data, "little")


def _is_readable(handle: int, address: int) -> bool:
    """Report whether four bytes at an address of another process can be read.

    Args:
        handle: Process handle with ``PROCESS_VM_READ`` access.
        address: Address inside the target process.

    Returns:
        bool: ``True`` when the read succeeds.
    """
    return _read_remote(handle, address, 4) is not None


def _allocation_base(handle: int, address: int) -> int:
    """Return the base of the virtual-memory allocation that holds an address.

    Args:
        handle: Process handle with ``PROCESS_QUERY_INFORMATION`` access.
        address: Address inside the target process.

    Returns:
        int: ``AllocationBase`` from ``VirtualQueryEx``, or 0 when the query fails.
    """
    info = MEMORY_BASIC_INFORMATION()
    written: int = _k32().VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info))
    return int(info.AllocationBase or 0) if written else 0


def _module_ranges(handle: int) -> list[tuple[str, int, int]]:
    """List the modules of a process, 32-bit and 64-bit, with their name and address range.

    Args:
        handle: Process handle with query and read access.

    Returns:
        list[tuple[str, int, int]]: ``(file name, base, end)`` per module; empty when the enumeration is refused.
    """
    array = (ctypes.c_void_p * _MODULE_CAP)()
    needed = wintypes.DWORD(0)
    listed: int = _psapi().EnumProcessModulesEx(handle, array, ctypes.sizeof(array), ctypes.byref(needed), _LIST_MODULES_ALL)
    if not listed:
        return []
    ranges: list[tuple[str, int, int]] = []
    for index in range(min(needed.value // ctypes.sizeof(ctypes.c_void_p), _MODULE_CAP)):
        base = array[index] or 0
        info = _ModuleInfo()
        described: int = _psapi().GetModuleInformation(handle, ctypes.c_void_p(base), ctypes.byref(info), ctypes.sizeof(info))
        if not described:
            continue
        name_buffer = ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
        length: int = _psapi().GetModuleFileNameExW(handle, ctypes.c_void_p(base), name_buffer, _MAX_PATH_CHARS)
        ranges.append((Path(name_buffer.value[:length]).name.lower(), base, base + int(info.SizeOfImage)))
    return ranges


def _in_modules(address: int, ranges: list[tuple[str, int, int]]) -> bool:
    """Report whether an address lies inside any listed module.

    Args:
        address: Address to classify.
        ranges: Module ranges from :func:`_module_ranges`.

    Returns:
        bool: ``True`` when some module covers the address.
    """
    return any(base <= address < end for _name, base, end in ranges)


def _main_module(handle: int, exe_name: str) -> tuple[int, int]:
    """Find the address range of a named module of a process.

    Args:
        handle: Process handle with query and read access.
        exe_name: Lower-case file name of the module.

    Returns:
        tuple[int, int]: ``(base, end)`` of the module.
    """
    matches = [(base, end) for name, base, end in _module_ranges(handle) if name == exe_name]
    assert len(matches) == 1
    return matches[0]


def _thread_ids(pid: int) -> list[int]:
    """List the thread identifiers of a process through a Toolhelp snapshot made by the test.

    Args:
        pid: Owner process identifier.

    Returns:
        list[int]: Thread identifiers owned by ``pid``.
    """
    snapshot: int | None = _k32().CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    assert snapshot is not None
    assert snapshot != INVALID_HANDLE_VALUE
    found: list[int] = []
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(entry)
        more: int = _k32().Thread32First(snapshot, ctypes.byref(entry))
        while more:
            if entry.th32OwnerProcessID == pid:
                found.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            more = _k32().Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        _k32().CloseHandle(snapshot)
    return found


def _start_address(tid: int) -> int:
    """Query the Win32 start address of a thread through the test's own ``ntdll`` prototype.

    Args:
        tid: Thread identifier.

    Returns:
        int: The start address reported for the thread.
    """
    with _thread_handle(tid, THREAD_QUERY_INFORMATION) as handle:
        value = ctypes.c_void_p(0)
        query = _ntdll().NtQueryInformationThread
        status: int = query(handle, ThreadQuerySetWin32StartAddress, ctypes.byref(value), ctypes.sizeof(value), None)
        assert status >= 0
        return value.value or 0


def _teb64_address(tid: int) -> int:
    """Query the base of the native (64-bit) thread environment block of a thread.

    Args:
        tid: Thread identifier.

    Returns:
        int: ``TebBaseAddress`` reported by ``ThreadBasicInformation``.
    """
    with _thread_handle(tid, THREAD_QUERY_INFORMATION) as handle:
        info = THREAD_BASIC_INFORMATION()
        status: int = _ntdll().NtQueryInformationThread(handle, ThreadBasicInformation, ctypes.byref(info), ctypes.sizeof(info), None)
        assert status >= 0
        return int(info.TebBaseAddress or 0)


def _wow64_peb_address(handle: int) -> int:
    """Query the address of the 32-bit process environment block of a WOW64 process.

    Args:
        handle: Process handle with ``PROCESS_QUERY_INFORMATION`` access.

    Returns:
        int: The address reported by ``ProcessWow64Information``.
    """
    value = ctypes.c_void_p(0)
    returned = wintypes.ULONG(0)
    query = _ntdll().NtQueryInformationProcess
    status: int = query(handle, ProcessWow64Information, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(returned))
    assert status >= 0
    return value.value or 0


def _teb32_address(handle: int, tid: int) -> int:
    """Locate the 32-bit thread environment block of a WOW64 thread and verify it against the x86 layout.

    The block sits 0x2000 bytes above the native one. Its ``NT_TIB.Self`` field must point back at it and its
    ``ProcessEnvironmentBlock`` field must equal the address that ``ProcessWow64Information`` reports.

    Args:
        handle: Process handle with query and read access.
        tid: Thread identifier.

    Returns:
        int: Address of the 32-bit thread environment block.
    """
    teb = _teb64_address(tid) + _WOW64_TEB_DELTA
    assert _u32(handle, teb + _TEB32_SELF_OFFSET) == teb
    assert _u32(handle, teb + _TEB32_PEB_OFFSET) == _wow64_peb_address(handle)
    return teb


def _main_thread_id(pid: int, main_range: tuple[int, int]) -> int:
    """Pick the thread whose start address lies inside the main executable.

    Args:
        pid: Process identifier.
        main_range: ``(base, end)`` of the main executable image.

    Returns:
        int: The identifier of the single thread that starts inside the image.
    """
    candidates = [tid for tid in _thread_ids(pid) if main_range[0] <= _start_address(tid) < main_range[1]]
    assert len(candidates) == 1
    return candidates[0]


def _wait_for_modules(pid: int) -> None:
    """Wait until the loader of a child has mapped at least the executable and its first libraries.

    Args:
        pid: Process identifier of the child.

    Raises:
        AssertionError: If the child never reaches that state within the time limit.
    """
    deadline = time.monotonic() + _WAIT_S
    while time.monotonic() < deadline:
        with _process_handle(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
            if len(_module_ranges(handle)) >= _MIN_LOADED_MODULES:
                return
        time.sleep(_POLL_S)
    msg = "the child never finished loading"
    raise AssertionError(msg)


def _first_output_byte(proc: Popen[bytes]) -> None:
    """Block until the child writes its first byte of output or closes its stdout.

    Args:
        proc: The child whose stdout is read.
    """
    stdout = proc.stdout
    if stdout is not None:
        stdout.read(1)


def _stop_child(proc: Popen[bytes], reader: threading.Thread | None = None) -> None:
    """Terminate a child process, wait for it, join its reader thread and close its pipes.

    Args:
        proc: The child process to stop.
        reader: Optional thread that is blocked reading the child's stdout.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=_WAIT_S)
    finally:
        try:
            if reader is not None and reader.is_alive():
                reader.join(_WAIT_S)
        finally:
            for stream in (proc.stdin, proc.stdout):
                if stream is not None:
                    stream.close()


@contextlib.contextmanager
def _running_child(source: str, *args: str) -> Generator[tuple[Popen[bytes], list[str]]]:
    """Start a Python child that reports readiness on stdout and then blocks on stdin; stop it afterwards.

    Args:
        source: Program text the child runs.
        *args: Extra command-line arguments, visible to the program from ``sys.argv[1:]``.

    Yields:
        tuple[Popen[bytes], list[str]]: The ready child and the tokens that followed ``ready`` on its first line.
    """
    proc = Popen([sys.executable, "-c", source, *args], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    try:
        stdout = proc.stdout
        assert stdout is not None
        tokens = stdout.readline().decode("ascii", errors="replace").split()
        assert tokens
        assert tokens[0] == _READY
        yield proc, tokens[1:]
    finally:
        _stop_child(proc)


@contextlib.contextmanager
def _scratch_value(size: int) -> Generator[str]:
    r"""Create a uniquely named scratch key under ``HKEY_CURRENT_USER\Software`` holding one binary value, and delete it afterwards.

    Args:
        size: Length of the binary value in bytes; every byte equals :data:`_REGISTRY_FILL`.

    Yields:
        str: Key path below ``HKEY_CURRENT_USER``.
    """
    path = "Software\\IntellicrackCritcovR3_" + uuid.uuid4().hex
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(key, _REGISTRY_VALUE, 0, winreg.REG_BINARY, _REGISTRY_FILL * size)
        yield path
    finally:
        key.Close()
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)


@pytest.fixture
def process_bridge() -> Generator[ProcessBridge]:
    """Initialize a bridge against the real DLLs and shut it down afterwards.

    Yields:
        ProcessBridge: An initialized bridge with no process attached.
    """
    instance = ProcessBridge()
    _run(instance.initialize())
    try:
        yield instance
    finally:
        _run(instance.shutdown())


@pytest.fixture
def wow64_child() -> Generator[Popen[bytes]]:
    """Start a 32-bit ``cmd.exe`` from ``SysWOW64`` that waits in ``pause`` on its open stdin pipe, and stop it afterwards.

    The fixture asserts that the child is a 32-bit process according to the operating system and that its loader has
    finished, then gives the program a bounded time to print its prompt, which it does just before blocking on the pipe.

    Yields:
        Popen[bytes]: The running 32-bit child.
    """
    exe = Path(os.environ["SYSTEMROOT"]) / "SysWOW64" / "cmd.exe"
    assert exe.is_file()
    proc = Popen([str(exe), "/c", "pause"], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    prompt = threading.Thread(target=_first_output_byte, args=(proc,), daemon=True)
    try:
        assert _process_machine(proc.pid) == IMAGE_FILE_MACHINE_I386
        _wait_for_modules(proc.pid)
        prompt.start()
        prompt.join(_PROMPT_WAIT_S)
        yield proc
    finally:
        _stop_child(proc, prompt)


@pytest.fixture
def wow64_main_tid(wow64_child: Popen[bytes]) -> int:
    """Identify the main thread of the 32-bit child from the thread list and start addresses the test queries itself.

    Args:
        wow64_child: The running 32-bit child.

    Returns:
        int: Identifier of the thread that starts inside ``cmd.exe``.
    """
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        return _main_thread_id(wow64_child.pid, _main_module(handle, "cmd.exe"))


@pytest.fixture
def wow64_bridge(process_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> ProcessBridge:
    """Attach the initialized bridge to the 32-bit child with full access.

    Args:
        process_bridge: Initialized bridge.
        wow64_child: The running 32-bit child.

    Returns:
        ProcessBridge: The bridge, attached to the 32-bit child.
    """
    assert _run(process_bridge.open_process(wow64_child.pid, "all"))
    return process_bridge


def _attached_handle(bridge: ProcessBridge) -> int:
    """Return the process handle of an attached bridge.

    Args:
        bridge: Bridge attached to a process.

    Returns:
        int: The bridge's process handle.
    """
    handle = bridge.process_handle
    assert handle is not None
    return handle


def test_registry_value_one_byte_over_the_cap_is_refused(process_bridge: ProcessBridge) -> None:
    """A binary registry value one byte above 16 MiB is refused instead of being read.

    Args:
        process_bridge: Initialized bridge.

    Mutation: changing ``_REG_MAX_BUF_SIZE`` at process.py:227 from 16 MiB to 32 MiB makes the read succeed.
    """
    with _scratch_value(_REGISTRY_CAP + 1) as path, pytest.raises(ToolError, match="registry value exceeds maximum supported size"):
        _run(process_bridge.reg_read_value("HKCU\\" + path, _REGISTRY_VALUE))


def test_registry_value_exactly_at_the_cap_is_read_completely(process_bridge: ProcessBridge) -> None:
    """A binary registry value of exactly 16 MiB is read in full as raw type 3 with every byte intact.

    Args:
        process_bridge: Initialized bridge.

    Mutation: changing ``required > _REG_MAX_BUF_SIZE`` at process.py:2038 to ``>=`` makes the exact-cap value fail.
    """
    with _scratch_value(_REGISTRY_CAP) as path:
        result = _run(process_bridge.reg_read_value("HKCU\\" + path, _REGISTRY_VALUE))
    assert result == {"type": "raw(3)", "data": _REGISTRY_FILL.hex() * _REGISTRY_CAP}


def test_detect_architecture_reports_x86_for_a_32_bit_child(process_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> None:
    """A child the operating system reports as an i386 image is detected as ``x86`` on a 64-bit host.

    Args:
        process_bridge: Initialized bridge.
        wow64_child: The running 32-bit child.

    Mutation: changing ``return self._machine_to_arch_string(process_machine)`` at process.py:2453 to return the native machine's name.
    """
    assert _run(process_bridge.detect_architecture(wow64_child.pid)) == "x86"


def test_legacy_wow64_detector_reports_x86_for_a_32_bit_handle(wow64_bridge: ProcessBridge) -> None:
    """The ``IsWow64Process`` fallback answers ``x86`` for a WOW64 target although the host pointer size is 64 bits.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.

    Mutation: changing ``return "x86"`` at process.py:2591 to ``return "x86_64"``.
    """
    assert sys.maxsize > 2**32
    detector = sync_method(wow64_bridge, "_detect_arch_via_iswow64process")
    assert detector(_attached_handle(wow64_bridge)) == "x86"


def test_target_is_64bit_is_false_for_a_32_bit_child(wow64_bridge: ProcessBridge) -> None:
    """A process whose image machine is i386 is not a 64-bit target.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.

    Mutation: changing ``return False`` at process.py:5344 to ``return True``.
    """
    assert sync_method(wow64_bridge, "_target_is_64bit")(_attached_handle(wow64_bridge)) is False


def test_read_peb_exposes_the_wow64_peb_of_a_32_bit_child(wow64_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> None:
    """The PEB read of a 32-bit child names the 32-bit PEB reported by ``ProcessWow64Information`` and its debug flag.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.

    Mutation: changing ``result["wow64_peb_address"] = wow64_info[0]`` at process.py:5309 to store ``wow64_info[0] + 1``.
    """
    peb = _run(wow64_bridge.read_peb())
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        expected = _wow64_peb_address(handle)
        being_debugged = _read_remote(handle, expected + _PEB32_BEING_DEBUGGED_OFFSET, 1)
    assert expected != 0
    assert being_debugged is not None
    assert peb["wow64_peb_address"] == expected
    nested = cast("dict[str, object]", peb["wow64_peb"])
    assert nested["peb_address"] == expected
    assert nested["being_debugged"] == being_debugged[0]


def test_read_peb_of_a_32_bit_child_reports_the_image_base_of_the_child(wow64_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> None:
    """The top-level PEB fields of a 32-bit child describe that child: its executable base and readable loader and parameter blocks.

    Defect gate: the bridge parses the 64-bit PEB that ``ProcessBasicInformation`` returns for a WOW64 target with the 32-bit
    layout and reports ``0xffffffff`` as the image base.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.

    Mutation: none; this test fails today and passes once the 32-bit PEB is read with the 32-bit layout.
    """
    peb = _run(wow64_bridge.read_peb())
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        main_base, _main_end = _main_module(handle, "cmd.exe")
        ldr = _as_int(peb["ldr_address"])
        parameters = _as_int(peb["process_parameters_address"])
        assert peb["image_base_address"] == main_base
        assert 0 < ldr < _ADDRESS_SPACE_32
        assert _is_readable(handle, ldr)
        assert 0 < parameters < _ADDRESS_SPACE_32
        assert _is_readable(handle, parameters)


def test_read_wow64_peb_reports_image_base_loader_and_parameters(wow64_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> None:
    """The 32-bit PEB read of a 32-bit child reports its executable base and readable loader and parameter blocks.

    Defect gate: ``_PEB32_MIN_PARSE_LENGTH`` (0x18) is larger than ``ctypes.sizeof(PEB32)`` (0x14), so the parser always
    takes its short-buffer branch and reports the image base, loader and parameter addresses as 0.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.

    Mutation: none; this test fails today and passes once the minimum length is 0x14 or less.
    """
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        expected_address = _wow64_peb_address(handle)
        main_base, _main_end = _main_module(handle, "cmd.exe")
        result = cast("tuple[int, dict[str, object]] | None", sync_method(wow64_bridge, "_read_wow64_peb")(_attached_handle(wow64_bridge)))
        assert result is not None
        address, fields = result
        ldr = _as_int(fields["ldr_address"])
        parameters = _as_int(fields["process_parameters_address"])
        assert address == expected_address
        assert fields["peb_address"] == expected_address
        assert fields["image_base_address"] == main_base
        assert 0 < ldr < _ADDRESS_SPACE_32
        assert _is_readable(handle, ldr)
        assert 0 < parameters < _ADDRESS_SPACE_32
        assert _is_readable(handle, parameters)


def test_read_wow64_peb_is_none_for_a_handle_without_read_access(wow64_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> None:
    """A handle that may query but not read memory yields no 32-bit PEB, while a full handle yields one at the reported address.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.

    Mutation: dropping the ``not`` in ``if not self._kernel32.ReadProcessMemory(`` at process.py:5401 makes the full handle return ``None``.
    """
    reader = sync_method(wow64_bridge, "_read_wow64_peb")
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as full:
        expected = _wow64_peb_address(full)
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION) as query_only:
        assert _read_remote(query_only, expected, 4) is None
        refused = reader(query_only)
    granted = cast("tuple[int, dict[str, object]] | None", reader(_attached_handle(wow64_bridge)))
    assert refused is None
    assert granted is not None
    assert granted[0] == expected


def test_get_threads_lists_every_thread_of_a_32_bit_child(process_bridge: ProcessBridge, wow64_child: Popen[bytes]) -> None:
    """The thread list of a 32-bit child matches an independent snapshot, with real start addresses, module-resident PCs and running state.

    Args:
        process_bridge: Initialized bridge.
        wow64_child: The running 32-bit child.

    Mutation: changing ``return int(ctx32.Eip)`` at process.py:3975 to ``return int(ctx32.Esp)`` puts the PCs on the stack, outside every module.
    """
    threads = _run(process_bridge.get_threads(wow64_child.pid))
    expected_tids = sorted(_thread_ids(wow64_child.pid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        ranges = _module_ranges(handle)
    assert sorted(thread.tid for thread in threads) == expected_tids
    for thread in threads:
        assert thread.start_address == _start_address(thread.tid)
        assert _in_modules(thread.current_pc, ranges)
        assert thread.state == "running"


def test_pc_and_state_probe_reads_a_32_bit_eip(wow64_bridge: ProcessBridge, wow64_child: Popen[bytes], wow64_main_tid: int) -> None:
    """The combined PC and state probe of a blocked 32-bit thread reports its ``Eip`` and the running state.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: changing ``return int(ctx32.Eip) if wow64_get_ctx(handle, ctypes.byref(ctx32)) else 0`` at process.py:3812 to read ``Esp``.
    """
    pc, state = cast("tuple[int, str]", sync_method(wow64_bridge, "_query_thread_pc_and_state")(wow64_main_tid))
    context = _run(wow64_bridge.get_thread_context(wow64_main_tid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        ranges = _module_ranges(handle)
    assert state == "running"
    assert _in_modules(pc, ranges)
    assert pc == context["eip"]


def test_thread_context_of_a_32_bit_thread_has_x86_registers_in_range(
    wow64_bridge: ProcessBridge,
    wow64_child: Popen[bytes],
    wow64_main_tid: int,
) -> None:
    """The context of a blocked 32-bit thread carries the x86 register set, WOW64 segments, a module-resident ``Eip`` and a stack-resident ``Esp``.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: changing ``"eip": ctx32.Eip`` at process.py:5867 to ``"eip": ctx32.Esp`` puts ``eip`` on the stack.
    """
    context = _run(wow64_bridge.get_thread_context(wow64_main_tid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        ranges = _module_ranges(handle)
        stack_top = _u32(handle, _teb32_address(handle, wow64_main_tid) + _TEB32_STACK_BASE_OFFSET)
        stack_allocation = _allocation_base(handle, stack_top - 4)
        esp_allocation = _allocation_base(handle, context["esp"])
    assert set(context) == _X86_REGISTERS
    assert context["cs"] == _WOW64_CODE_SEGMENT
    assert context["ss"] == _WOW64_STACK_SEGMENT
    assert _in_modules(context["eip"], ranges)
    assert context["esp"] < stack_top
    assert esp_allocation == stack_allocation


def test_stack_walk_of_a_32_bit_thread_starts_at_eip_and_stays_in_modules(
    wow64_bridge: ProcessBridge,
    wow64_child: Popen[bytes],
    wow64_main_tid: int,
) -> None:
    """The stack walk of a blocked 32-bit thread starts at the thread's ``Eip``, numbers its frames and visits the main executable.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: changing ``frame.AddrPC.Offset = ctx32.Eip`` at process.py:6310 to ``ctx32.Esp`` makes the first frame lie on the stack.
    """
    frames = _run(wow64_bridge.stack_walk(wow64_main_tid))
    context = _run(wow64_bridge.get_thread_context(wow64_main_tid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        ranges = _module_ranges(handle)
        main_base, main_end = _main_module(handle, "cmd.exe")
    addresses = [_as_int(frame["address"]) for frame in frames]
    assert len(frames) >= 3
    assert addresses[0] == context["eip"]
    assert [frame["index"] for frame in frames] == list(range(len(frames)))
    assert all(_in_modules(address, ranges) for address in addresses)
    assert any(main_base <= address < main_end for address in addresses)


def test_seh_chain_of_a_32_bit_thread_is_linked_and_terminated(wow64_bridge: ProcessBridge, wow64_main_tid: int) -> None:
    """The exception-handler chain of a 32-bit thread has several records, each linking to the next, and ends with ``0xFFFFFFFF``.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: swapping the unpacked names in ``next_ptr, handler = struct.unpack("<II", record_data)`` at process.py:6527 breaks the terminator.
    """
    chain = _run(wow64_bridge.get_seh_chain(wow64_main_tid))
    assert len(chain) >= 2
    for record, following in itertools.pairwise(chain):
        assert record["next"] == following["address"]
    assert chain[-1]["next"] == _SEH_CHAIN_END


def test_seh_chain_of_a_32_bit_thread_lies_on_its_stack_and_names_module_handlers(
    wow64_bridge: ProcessBridge,
    wow64_child: Popen[bytes],
    wow64_main_tid: int,
) -> None:
    """The first record of a 32-bit thread's chain is the ``ExceptionList`` of its 32-bit TEB, and every record sits on its stack with a module-resident handler.

    Defect gate: for a WOW64 thread the bridge reads the 64-bit TEB with the 32-bit layout, so the chain starts at the
    address of the 32-bit TEB itself, which is neither on the stack nor a registration record.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.
        wow64_child: The running 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: none; this test fails today and passes once the bridge reads the 32-bit TEB of a WOW64 thread.
    """
    chain = _run(wow64_bridge.get_seh_chain(wow64_main_tid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        teb32 = _teb32_address(handle, wow64_main_tid)
        head = _u32(handle, teb32 + _TEB32_EXCEPTION_LIST_OFFSET)
        stack_top = _u32(handle, teb32 + _TEB32_STACK_BASE_OFFSET)
        stack_allocation = _allocation_base(handle, stack_top - 4)
        ranges = _module_ranges(handle)
        addresses = [_as_int(record["address"]) for record in chain]
        handlers = [_as_int(record["handler_address"]) for record in chain]
        on_stack = [address < stack_top and _allocation_base(handle, address) == stack_allocation for address in addresses]
    assert chain
    assert addresses[0] == head
    assert all(on_stack)
    assert all(_in_modules(handler, ranges) for handler in handlers)


def test_read_teb_of_a_32_bit_thread_reports_its_environment_block_and_stack(
    process_bridge: ProcessBridge,
    wow64_child: Popen[bytes],
    wow64_main_tid: int,
) -> None:
    """The TEB read of a 32-bit thread reports the 32-bit PEB address and the thread's 32-bit stack bounds.

    Defect gate: for a WOW64 thread the bridge reads the 64-bit TEB with the 32-bit layout, so ``peb_address`` is the
    native TEB's own address and the stack base is 0.

    Args:
        process_bridge: Initialized bridge.
        wow64_child: The running 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: none; this test fails today and passes once the bridge reads the 32-bit TEB of a WOW64 thread.
    """
    teb = _run(process_bridge.read_teb(wow64_main_tid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        expected_peb = _wow64_peb_address(handle)
        expected_base = _u32(handle, _teb32_address(handle, wow64_main_tid) + _TEB32_STACK_BASE_OFFSET)
    stack_limit = _as_int(teb["stack_limit"])
    assert teb["peb_address"] == expected_peb
    assert teb["stack_base"] == expected_base
    assert 0 < stack_limit < expected_base


def test_read_teb_of_a_32_bit_thread_places_the_tls_array_in_its_own_block(
    process_bridge: ProcessBridge,
    wow64_child: Popen[bytes],
    wow64_main_tid: int,
) -> None:
    """The TLS array base reported for a 32-bit thread is the ``TlsSlots`` offset inside that thread's 32-bit TEB.

    Defect gate: the TLS slot reader starts from this base, which is derived from the native TEB address for a WOW64 thread.

    Args:
        process_bridge: Initialized bridge.
        wow64_child: The running 32-bit child.
        wow64_main_tid: Identifier of the child's main thread.

    Mutation: none; this test fails today and passes once the bridge reads the 32-bit TEB of a WOW64 thread.
    """
    teb = _run(process_bridge.read_teb(wow64_main_tid))
    with _process_handle(wow64_child.pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as handle:
        expected = _teb32_address(handle, wow64_main_tid) + _TEB32_TLS_SLOTS_OFFSET
    assert teb["tls_array_base"] == expected


def test_stack_walk_stops_at_the_frame_cap(process_bridge: ProcessBridge) -> None:
    """A thread blocked below fifty nested native callbacks is walked to exactly 256 frames, numbered 0 to 255.

    Args:
        process_bridge: Initialized bridge.

    Mutation: changing ``max_frames = 256`` at process.py:6349 to ``128`` shortens the walk to 128 frames.
    """
    with _running_child(_DEEP_SOURCE, _DEEP_CALLBACK_DEPTH) as (proc, tokens):
        tid = int(tokens[0])
        assert tid in _thread_ids(proc.pid)
        assert _run(process_bridge.open_process(proc.pid, "all"))
        frames = _run(process_bridge.stack_walk(tid))
    assert len(frames) == _STACK_FRAME_CAP
    assert [frame["index"] for frame in frames] == list(range(_STACK_FRAME_CAP))
