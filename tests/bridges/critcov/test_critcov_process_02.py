# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the ProcessBridge privilege, handle, PEB/TEB, context, SEH and enumeration paths.

Every test drives the real Win32 APIs through a real ``ProcessBridge``. Processes are touched only
when they are children the test itself starts (a Python interpreter or ``cmd.exe`` blocked on stdin),
never the pytest process. The tests cover the error and edge paths of the privilege adjuster, the
handle and service enumerators, the PEB/TEB readers and parsers, the thread-context accessors, the
DbgHelp stack walker, the x64 exception-directory reader (driven with module images planted in the
child's own memory), the mitigation queries, the heap and process walkers, the token helpers, the
typed registry reader and the environment-block reader.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import functools
import os
import re
import struct
import sys
import threading
import time
import winreg
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, cast

import psutil
import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    ENUM_SERVICE_STATUS_PROCESSW,
    HEAPLIST32,
    PROCESS_MITIGATION_ASLR_POLICY,
    PROCESS_MITIGATION_DEP_POLICY,
    PROCESSENTRY32,
    STACKFRAME64,
    TOKEN_PRIVILEGES,
)
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ModuleInfo, ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Iterable


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_ABSENT_PID: Final[int] = 999_999_999
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_CMD_EXE: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "cmd.exe"
_CMD_SCRIPT: Final[str] = "echo critcov-ready& set /p critcov_wait="
_INVALID_HANDLE: Final[int] = (1 << 64) - 1

_PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
_THREAD_SUSPEND_RESUME: Final[int] = 0x0002
_THREAD_GET_CONTEXT: Final[int] = 0x0008
_TH32CS_SNAPHEAPLIST: Final[int] = 0x00000001
_MACHINE_AMD64: Final[int] = 0x8664
_ERROR_NO_MORE_FILES: Final[int] = 18
_WAIT_ABANDONED: Final[int] = 0x80
_STATE_ALL: Final[int] = 0x3

_ERR_KERNEL32: Final[str] = "kernel32 not available"
_ERR_NTDLL: Final[str] = "ntdll not available"
_ERR_ADVAPI32: Final[str] = "advapi32 not available"
_ERR_USER32: Final[str] = "user32 not available"
_ERR_DBGHELP: Final[str] = "dbghelp not available"
_ERR_NO_PROCESS: Final[str] = "no process specified"
_ERR_NOT_ATTACHED: Final[str] = "no process attached"
_ERR_OPEN: Final[str] = "process open failed"
_ERR_THREAD_OPEN: Final[str] = "thread open failed"
_ERR_CONTEXT_GET: Final[str] = "GetThreadContext failed"
_ERR_CONTEXT_SET: Final[str] = "SetThreadContext failed"
_ERR_TOKEN_OPEN: Final[str] = "token open failed"
_ERR_SNAPSHOT: Final[str] = "snapshot creation failed"
_ERR_WIN32_STATUS: Final[str] = r"failed: 0xC[0-9A-F]{7}$"

_MISSING_KEY: Final[str] = f"Software\\IntellicrackCritcovProcess02Missing{os.getpid()}"
_BINARY_PAYLOAD: Final[bytes] = b"\x01\x02\xfe\xff\x00\x7f"
_DWORD_VALUE: Final[int] = 0x12345678
_QWORD_VALUE: Final[int] = 0x1122334455667788

_NT_OFFSET: Final[int] = 0x80
_NT_HEADER_READ_SIZE: Final[int] = 168
_NT_EXCEPTION_DIRECTORY_OFFSET: Final[int] = 24 + 112 + 3 * 8
_PE32_PLUS_MAGIC: Final[int] = 0x20B
_PE32_MAGIC: Final[int] = 0x10B
_PAGE: Final[int] = 0x1000
_PARAMS_ENV_POINTER_OFFSET_X64: Final[int] = 0x80
_PARAMS_READ_SIZE_X64: Final[int] = 0x400
_ENV_CEILING: Final[int] = 2 * 1024 * 1024


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


def priv[T](obj: object, name: str, typ: type[T]) -> T:
    """Read a private attribute with a known static type.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        typ: Static type of the attribute, used only for typing.

    Returns:
        T: The attribute value.
    """
    del typ
    value: T = getattr(obj, name)
    return value


def sync_method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) synchronous method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method or plain function.
    """
    return cast("Callable[..., object]", getattr(obj, name))


def async_method(obj: object, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method.
    """
    return cast("Callable[..., Coroutine[object, object, object]]", getattr(obj, name))


@contextlib.contextmanager
def _slot(obj: object, name: str, value: object) -> Generator[None]:
    """Temporarily replace a private data attribute of a real object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        value: Value installed for the duration of the context.

    Yields:
        None: Control while the attribute holds ``value``.
    """
    original: object = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, original)


@functools.cache
def _k32() -> ctypes.WinDLL:
    """Load a private kernel32 handle with prototypes configured for the test helpers.

    Returns:
        ctypes.WinDLL: A kernel32 handle that is separate from the bridge's own.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.SuspendThread.restype = wintypes.DWORD
    kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
    kernel32.ResumeThread.restype = wintypes.DWORD
    kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.GetProcessMitigationPolicy.restype = wintypes.BOOL
    kernel32.GetProcessMitigationPolicy.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Heap32ListFirst.restype = wintypes.BOOL
    kernel32.Heap32ListFirst.argtypes = [wintypes.HANDLE, ctypes.POINTER(_OracleHeapList)]
    kernel32.Heap32ListNext.restype = wintypes.BOOL
    kernel32.Heap32ListNext.argtypes = [wintypes.HANDLE, ctypes.POINTER(_OracleHeapList)]
    return kernel32


@contextlib.contextmanager
def _opened_process(pid: int, access: int) -> Generator[int]:
    """Open a process handle with exactly the requested access and close it afterwards.

    Args:
        pid: Identifier of the process to open.
        access: Access mask requested from ``OpenProcess``.

    Yields:
        int: The open process handle.
    """
    kernel32 = _k32()
    inherit = False
    handle: int | None = kernel32.OpenProcess(access, inherit, pid)
    assert handle
    try:
        yield handle
    finally:
        kernel32.CloseHandle(handle)


@contextlib.contextmanager
def _opened_thread(tid: int, access: int) -> Generator[int]:
    """Open a thread handle with exactly the requested access and close it afterwards.

    Args:
        tid: Identifier of the thread to open.
        access: Access mask requested from ``OpenThread``.

    Yields:
        int: The open thread handle.
    """
    kernel32 = _k32()
    inherit = False
    handle: int | None = kernel32.OpenThread(access, inherit, tid)
    assert handle
    try:
        yield handle
    finally:
        kernel32.CloseHandle(handle)


def _primary_bit(handle: int, policy_class: int) -> bool:
    """Independently decode bit 0 of a one-DWORD process mitigation policy.

    Args:
        handle: Process handle with query access.
        policy_class: ``PROCESS_MITIGATION_POLICY`` enumeration value.

    Returns:
        bool: ``True`` when the query succeeds and bit 0 of the flags is set.
    """
    flags = ctypes.c_ulong(0)
    if not _k32().GetProcessMitigationPolicy(handle, policy_class, ctypes.byref(flags), ctypes.sizeof(flags)):
        return False
    return bool(flags.value & 1)


class _OracleHeapList(ctypes.Structure):
    """Test-local definition of the documented Win32 ``HEAPLIST32`` structure."""

    _fields_: ClassVar = [
        ("dwSize", ctypes.c_size_t),
        ("th32ProcessID", wintypes.DWORD),
        ("th32HeapID", ctypes.c_size_t),
        ("dwFlags", wintypes.DWORD),
    ]


def _toolhelp_heap_list(pid: int) -> list[tuple[int, int]]:
    """List the heaps of a process through an independent Toolhelp32 walk, in enumeration order.

    Args:
        pid: Identifier of the process to inspect.

    Returns:
        list[tuple[int, int]]: ``(heap_id, flags)`` per entry returned by ``Heap32ListFirst`` and ``Heap32ListNext``.
    """
    kernel32 = _k32()
    snapshot: int | None = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPHEAPLIST, pid)
    assert snapshot is not None
    assert snapshot != _INVALID_HANDLE
    heaps: list[tuple[int, int]] = []
    try:
        entry = _OracleHeapList()
        entry.dwSize = ctypes.sizeof(_OracleHeapList)
        more = bool(kernel32.Heap32ListFirst(snapshot, ctypes.byref(entry)))
        while more:
            heaps.append((int(entry.th32HeapID), int(entry.dwFlags)))
            entry.dwSize = ctypes.sizeof(_OracleHeapList)
            more = bool(kernel32.Heap32ListNext(snapshot, ctypes.byref(entry)))
    finally:
        kernel32.CloseHandle(snapshot)
    return heaps


def _stop_target(proc: Popen[bytes]) -> None:
    """Terminate a child process, wait for it and close its pipes.

    Args:
        proc: The child process to stop.
    """
    try:
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=_WAIT_S)
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


def _start_ready_child(argv: list[str]) -> Popen[bytes]:
    """Start a child that prints a ready marker on stdout and then blocks on stdin.

    Args:
        argv: Command line of the child.

    Returns:
        Popen[bytes]: The ready child process.
    """
    proc = Popen(argv, stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    ready = b""
    try:
        stdout = proc.stdout
        assert stdout is not None
        ready = stdout.readline().strip()
    finally:
        if ready != _TARGET_READY:
            _stop_target(proc)
    assert ready == _TARGET_READY
    return proc


def _child_tid(proc: Popen[bytes]) -> int:
    """Return the identifier of the first thread of a child process.

    Args:
        proc: The running child process.

    Returns:
        int: A thread identifier owned by the child.
    """
    threads = psutil.Process(proc.pid).threads()
    assert threads
    return int(threads[0].id)


def _plant(bridge: ProcessBridge, image: bytes, size: int) -> int:
    """Allocate committed read-write memory in the attached child and fill it with ``image``.

    Args:
        bridge: Bridge attached to the child.
        image: Bytes written at the start of the new region.
        size: Size of the region to allocate.

    Returns:
        int: Base address of the new region inside the child.
    """
    address = _run(bridge.allocate(size, "rw"))
    written = _run(bridge.write_memory(address, image))
    assert written == len(image)
    return address


def _module_image(
    size: int,
    *,
    dos_signature: bytes = b"MZ",
    e_lfanew: int = _NT_OFFSET,
    nt_signature: bytes = b"PE\x00\x00",
    magic: int = _PE32_PLUS_MAGIC,
    directory: tuple[int, int] = (0x400, 12),
) -> bytearray:
    """Build a PE32+ module image with one handler-carrying RUNTIME_FUNCTION.

    The image follows the PE format: ``MZ`` at offset 0, ``e_lfanew`` at 0x3C, the NT signature,
    the optional-header magic at NT+24 and the exception data directory (index 3) at NT+24+112+3*8.
    A one-entry table sits at 0x400 and its UNWIND_INFO, carrying an exception handler at RVA 0x700,
    sits at 0x600.

    Args:
        size: Total image size in bytes.
        dos_signature: The two bytes written at offset 0.
        e_lfanew: Offset of the NT headers.
        nt_signature: The four bytes written at the NT headers.
        magic: Optional-header magic value.
        directory: ``(rva, size)`` stored in the exception data directory.

    Returns:
        bytearray: The assembled image.
    """
    image = bytearray(size)
    image[0:2] = dos_signature
    struct.pack_into("<I", image, 0x3C, e_lfanew)
    if e_lfanew >= 0x40 and e_lfanew + _NT_HEADER_READ_SIZE <= size:
        image[e_lfanew : e_lfanew + 4] = nt_signature
        struct.pack_into("<H", image, e_lfanew + 24, magic)
        struct.pack_into("<II", image, e_lfanew + _NT_EXCEPTION_DIRECTORY_OFFSET, *directory)
    struct.pack_into("<III", image, 0x400, 0x10, 0x20, 0x600)
    unwind = _unwind_info(1, 0, 0x700)
    image[0x600 : 0x600 + len(unwind)] = unwind
    return image


def _unwind_info(flags: int, code_slots: int, handler_rva: int) -> bytes:
    """Build an x64 UNWIND_INFO record that carries an exception-handler RVA.

    The layout is the documented one: version and flags, prolog size, count of codes, frame
    register, the unwind-code array padded to an even count, then the handler RVA.

    Args:
        flags: ``UNW_FLAG_*`` bits (1 for EHANDLER, 2 for UHANDLER).
        code_slots: Value stored in ``CountOfCodes``.
        handler_rva: Exception-handler RVA stored after the code array.

    Returns:
        bytes: The encoded record.
    """
    header = bytes([1 | (flags << 3), 0, code_slots, 0])
    codes = bytes(((code_slots + 1) & ~1) * 2)
    return header + codes + struct.pack("<I", handler_rva)


def _runtime_functions(entries: Iterable[tuple[int, int, int]]) -> bytes:
    """Encode RUNTIME_FUNCTION entries (BeginAddress, EndAddress, UnwindInfoAddress).

    Args:
        entries: One ``(begin_rva, end_rva, unwind_rva)`` tuple per function.

    Returns:
        bytes: The packed table.
    """
    return b"".join(struct.pack("<III", *entry) for entry in entries)


def _module_info(name: str, base: int, size: int) -> ModuleInfo:
    """Describe a planted module the way the module enumerator would.

    Args:
        name: Module name.
        base: Base address inside the child.
        size: Image size in bytes.

    Returns:
        ModuleInfo: The module description.
    """
    return ModuleInfo(name=name, path=Path(name), base_address=base, size=size, entry_point=0)


@pytest.fixture
def target_process() -> Generator[Popen[bytes]]:
    """Start a Python child for the bridge to inspect and stop it afterwards.

    Yields:
        Popen[bytes]: The running child process.
    """
    proc = _start_ready_child([sys.executable, "-c", _TARGET_SOURCE])
    try:
        yield proc
    finally:
        _stop_target(proc)


@pytest.fixture
def cmd_process() -> Generator[Popen[bytes]]:
    """Start a small ``cmd.exe`` child that blocks reading stdin and stop it afterwards.

    Yields:
        Popen[bytes]: The running child process.
    """
    proc = _start_ready_child([str(_CMD_EXE), "/d", "/c", _CMD_SCRIPT])
    try:
        yield proc
    finally:
        _stop_target(proc)


@pytest.fixture
def bare_bridge() -> ProcessBridge:
    """Create a bridge that was never initialized, so every DLL slot is empty.

    Returns:
        ProcessBridge: A bridge with no loaded DLLs and no attached process.
    """
    return ProcessBridge()


@pytest.fixture
def bridge() -> Generator[ProcessBridge]:
    """Create an initialized bridge and shut it down afterwards.

    Yields:
        ProcessBridge: A bridge with every DLL loaded and no attached process.
    """
    instance = ProcessBridge()
    _run(instance.initialize())
    assert instance.kernel32 is not None
    try:
        yield instance
    finally:
        _run(instance.shutdown())


@pytest.fixture
def attached_bridge(bridge: ProcessBridge, target_process: Popen[bytes]) -> ProcessBridge:
    """Attach the initialized bridge to the Python child with full access.

    Args:
        bridge: Initialized bridge without a session.
        target_process: The running child process.

    Returns:
        ProcessBridge: The same bridge, holding a handle on the child.
    """
    assert _run(bridge.open_process(target_process.pid, "all")) is True
    return bridge


@pytest.fixture
def registry_key() -> Generator[str]:
    """Create a scratch HKCU key holding a DWORD, a QWORD and a binary value, and delete it afterwards.

    Yields:
        str: Path of the key below HKEY_CURRENT_USER.
    """
    sub_key = f"Software\\IntellicrackCritcovProcess02{os.getpid()}"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, sub_key, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "dword_value", 0, winreg.REG_DWORD, _DWORD_VALUE)
        winreg.SetValueEx(key, "qword_value", 0, winreg.REG_QWORD, _QWORD_VALUE)
        winreg.SetValueEx(key, "binary_value", 0, winreg.REG_BINARY, _BINARY_PAYLOAD)
    try:
        yield sub_key
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub_key)


@pytest.fixture
def scm_enum_function(bridge: ProcessBridge) -> Callable[..., int]:
    """Return ``EnumServicesStatusExW`` with the bridge's prototypes configured.

    Args:
        bridge: Initialized bridge.

    Returns:
        Callable[..., int]: The configured enumeration function.
    """
    prototypes = cast(
        "tuple[Callable[..., int], Callable[..., int], Callable[..., int]]",
        sync_method(bridge, "_configure_scm_prototypes")(),
    )
    return prototypes[1]


_BARE_ASYNC_GUARDS: Final[tuple[tuple[str, tuple[object, ...], str], ...]] = (
    ("get_handles", (), _ERR_NO_PROCESS),
    ("enum_handles", (), _ERR_NTDLL),
    ("get_windows", (), _ERR_USER32),
    ("list_services", (), _ERR_ADVAPI32),
    ("read_peb", (), _ERR_NTDLL),
    ("read_teb", (1,), _ERR_NTDLL),
    ("get_heaps", (), _ERR_KERNEL32),
    ("get_thread_context", (1,), _ERR_KERNEL32),
    ("set_thread_context", (1, {"rax": 0}), _ERR_KERNEL32),
    ("stack_walk", (1,), _ERR_KERNEL32),
    ("get_mitigation_policies", (), _ERR_KERNEL32),
    ("enumerate_system_processes", (), _ERR_KERNEL32),
    ("enumerate_handles", (), _ERR_NTDLL),
    ("enumerate_heaps", (), _ERR_KERNEL32),
    ("enumerate_services", (), _ERR_ADVAPI32),
    ("time_thread_wait", (1, 0), _ERR_KERNEL32),
    ("duplicate_token", (1,), _ERR_KERNEL32),
    ("remove_privilege", (1, "SeShutdownPrivilege"), _ERR_KERNEL32),
    ("decommit_memory", (1, 0x10000, _PAGE), _ERR_KERNEL32),
    ("read_registry", ("HKCU", "Software", "value"), _ERR_ADVAPI32),
    ("detect_kernel_debugger", (1,), _ERR_KERNEL32),
    ("get_mitigation_policy", (), _ERR_KERNEL32),
    ("get_extension_policy", (), _ERR_KERNEL32),
    ("get_environment", (), _ERR_KERNEL32),
)

_INITIALIZED_ASYNC_FAILURES: Final[tuple[tuple[str, tuple[object, ...], str], ...]] = (
    ("get_handles", (), _ERR_NO_PROCESS),
    ("get_windows", (), _ERR_NO_PROCESS),
    ("get_heaps", (), _ERR_NO_PROCESS),
    ("get_heaps", (_ABSENT_PID,), _ERR_SNAPSHOT),
    ("enumerate_heaps", (), _ERR_NO_PROCESS),
    ("read_peb", (), _ERR_NOT_ATTACHED),
    ("read_peb", (_ABSENT_PID,), _ERR_OPEN),
    ("read_teb", (0,), _ERR_THREAD_OPEN),
    ("get_mitigation_policies", (_ABSENT_PID,), _ERR_OPEN),
    ("get_extension_policy", (_ABSENT_PID,), _ERR_OPEN),
    ("decommit_memory", (_ABSENT_PID, 0x10000, _PAGE), _ERR_OPEN),
    ("remove_privilege", (_ABSENT_PID, "SeShutdownPrivilege"), _ERR_OPEN),
    ("read_registry", ("HKCU", _MISSING_KEY, "value"), "registry key open failed: HKCU\\" + _MISSING_KEY),
)

_CLEARED_SLOT_ASYNC_GUARDS: Final[tuple[tuple[str, tuple[object, ...], str, str], ...]] = (
    ("read_peb", (), "_kernel32", _ERR_KERNEL32),
    ("read_teb", (1,), "_kernel32", _ERR_KERNEL32),
    ("duplicate_token", (1,), "_advapi32", _ERR_ADVAPI32),
    ("remove_privilege", (1, "SeShutdownPrivilege"), "_advapi32", _ERR_ADVAPI32),
    ("detect_kernel_debugger", (1,), "_ntdll", _ERR_NTDLL),
    ("get_environment", (), "_ntdll", _ERR_NTDLL),
    ("get_windows", (), "_kernel32", _ERR_KERNEL32),
    ("stack_walk", (1,), "_dbghelp", _ERR_DBGHELP),
)

_BARE_SYNC_GUARDS: Final[tuple[tuple[str, Callable[[], tuple[object, ...]], dict[str, object], str], ...]] = (
    ("_apply_token_privilege", lambda: (wintypes.HANDLE(), "SeDebugPrivilege"), {"enable": True}, _ERR_ADVAPI32),
    ("_call_adjust_token_privileges", lambda: (wintypes.HANDLE(), TOKEN_PRIVILEGES()), {"disable_all": False}, _ERR_ADVAPI32),
    ("_query_extended_handles_buffer", lambda: (), {}, _ERR_NTDLL),
    ("_sync_iterate_handles_for_pid", lambda: (1,), {}, _ERR_NTDLL),
    ("_sync_enum_handles", lambda: (None,), {}, _ERR_NTDLL),
    ("_configure_scm_prototypes", lambda: (), {}, _ERR_ADVAPI32),
    ("_read_peb_from_handle", lambda: (0,), {}, _ERR_NTDLL),
    ("_read_teb_with_thread_handle", lambda: (1, 0, [None]), {}, _ERR_KERNEL32),
    ("_read_and_parse_teb", lambda: (0, 0), {"exit_status": 0}, _ERR_KERNEL32),
    ("_capture_thread_context", lambda: (0, 1), {}, _ERR_CONTEXT_GET),
    ("_capture_wow64_context", lambda: (0,), {}, _ERR_CONTEXT_GET),
    ("_capture_native_context", lambda: (0,), {}, _ERR_CONTEXT_GET),
    ("_apply_thread_context", lambda: (0, 1, {}), {}, _ERR_CONTEXT_SET),
    ("_apply_wow64_context", lambda: (0, {}), {}, _ERR_CONTEXT_SET),
    ("_apply_native_context", lambda: (0, {}), {}, _ERR_CONTEXT_SET),
    ("_stack_walk_with_thread_handle", lambda: (0,), {}, _ERR_KERNEL32),
    ("_stack_walk_with_dbghelp", lambda: (0,), {}, _ERR_DBGHELP),
    ("_walk_stack_native", lambda: (0,), {}, _ERR_NOT_ATTACHED),
    ("_walk_stack_wow64", lambda: (0,), {}, _ERR_NOT_ATTACHED),
    (
        "_enumerate_services_by_state",
        lambda: (0, ctypes.WinDLL("advapi32").EnumServicesStatusExW, _STATE_ALL),
        {},
        _ERR_ADVAPI32,
    ),
    ("_duplicate_token_for_handle", lambda: (0, 1), {}, _ERR_TOKEN_OPEN),
    ("_duplicate_token_impl", lambda: (wintypes.HANDLE(), 1), {}, _ERR_ADVAPI32),
    ("_remove_privilege_for_handle", lambda: (0, 1, "SeShutdownPrivilege"), {}, _ERR_TOKEN_OPEN),
    ("_query_kernel_debugger_port", lambda: (0, 1), {}, _ERR_NTDLL),
    ("_read_env_block", lambda: (0, 0), {}, _ERR_KERNEL32),
    ("_read_env_bytes", lambda: (0, 0), {}, _ERR_KERNEL32),
)

_CLEARED_SLOT_SYNC_GUARDS: Final[tuple[tuple[str, Callable[[], tuple[object, ...]], dict[str, object], str, str], ...]] = (
    ("_apply_token_privilege", lambda: (wintypes.HANDLE(), "SeDebugPrivilege"), {"enable": True}, "_kernel32", _ERR_KERNEL32),
    ("_call_adjust_token_privileges", lambda: (wintypes.HANDLE(), TOKEN_PRIVILEGES()), {"disable_all": False}, "_kernel32", _ERR_KERNEL32),
    ("_read_peb_from_handle", lambda: (0,), {}, "_kernel32", _ERR_KERNEL32),
)

_NEUTRAL_RETURNS: Final[tuple[tuple[str, Callable[[], tuple[object, ...]], object], ...]] = (
    ("_read_wow64_peb", lambda: (0,), None),
    ("_collect_mitigation_policies", lambda: (0,), {"error": "kernel32 not available"}),
    ("_query_extension_point_disable", lambda: (0, None), False),
    ("_resolve_symbol", lambda: (1,), ("", 0)),
    ("_resolve_module", lambda: (1,), ""),
    ("_iterate_stack_frames", lambda: (_MACHINE_AMD64, 0, STACKFRAME64(), None), []),
    ("_remove_privilege_impl", lambda: (wintypes.HANDLE(), 1, "SeShutdownPrivilege"), False),
    ("_time_wait_on_handle", lambda: (0, 1, 0), {"result": "failed", "elapsed_us": 0}),
)

_FAILING_HANDLE_CALLS: Final[tuple[tuple[str, tuple[object, ...], str], ...]] = (
    ("_stack_walk_with_thread_handle", (0,), _ERR_THREAD_OPEN),
    ("_walk_stack_native", (0,), _ERR_CONTEXT_GET),
    ("_walk_stack_wow64", (0,), _ERR_CONTEXT_GET),
    ("_capture_wow64_context", (0,), _ERR_CONTEXT_GET),
    ("_capture_native_context", (0,), _ERR_CONTEXT_GET),
    ("_apply_wow64_context", (0, {"eax": 1}), _ERR_CONTEXT_GET),
    ("_apply_native_context", (0, {"rax": 1}), _ERR_CONTEXT_GET),
    ("_apply_thread_context", (0, 1, {"rax": 1}), _ERR_CONTEXT_SET),
)

_MISSING_EXPORT_CALLS: Final[tuple[tuple[str, tuple[object, ...], str], ...]] = (
    ("_capture_wow64_context", (0,), _ERR_CONTEXT_GET),
    ("_apply_wow64_context", (0, {"eax": 1}), _ERR_CONTEXT_SET),
)

_REJECTED_IMAGES: Final[tuple[tuple[str, Callable[[], bytearray]], ...]] = (
    ("dos_signature", lambda: _module_image(_PAGE, dos_signature=b"ZM")),
    ("e_lfanew_zero", lambda: _module_image(_PAGE, e_lfanew=0)),
    ("nt_signature", lambda: _module_image(_PAGE, nt_signature=b"PX\x00\x00")),
    ("pe32_magic", lambda: _module_image(_PAGE, magic=_PE32_MAGIC)),
    ("directory_below_one_entry", lambda: _module_image(_PAGE, directory=(0x400, 11))),
    ("table_beyond_committed_memory", lambda: _module_image(_PAGE, directory=(0xFF8, 24))),
    ("nt_headers_beyond_committed_memory", lambda: _module_image(_PAGE, e_lfanew=0xFF0)),
)

_DECODE_CASES: Final[tuple[tuple[str, int, int, int, int, bytes, str], ...]] = (
    ("zero_length", 256, 0, 0, 8, b"", ""),
    ("length_above_maximum_length", 256, 0, 10, 8, b"", ""),
    ("length_above_name_cap", 1024, 0, 514, 600, b"", ""),
    ("string_beyond_buffer", 120, 0, 20, 20, b"", ""),
    ("well_formed_name", 256, 0, 10, 12, "Event".encode("utf-16-le"), "Event"),
)


@pytest.mark.parametrize(("method", "args", "message"), _BARE_ASYNC_GUARDS, ids=[case[0] for case in _BARE_ASYNC_GUARDS])
def test_uninitialized_bridge_reports_the_first_missing_requirement(
    bare_bridge: ProcessBridge,
    method: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """A bridge with no DLLs and no process refuses each public entry point with the matching message.

    Mutation: any guard at the top of these methods that tests the wrong DLL slot (for example the
    ``self._ntdll is None`` check in ``read_peb`` at process.py:5217 testing ``self._advapi32``)
    raises a different message and this test fails.

    Args:
        bare_bridge: Bridge that was never initialized.
        method: Public method to call.
        args: Positional arguments for the call.
        message: Expected error text.
    """
    with pytest.raises(ToolError, match=re.escape(message)):
        _run(async_method(bare_bridge, method)(*args))


@pytest.mark.parametrize(
    ("method", "args", "message"),
    _INITIALIZED_ASYNC_FAILURES,
    ids=[f"{case[0]}-{index}" for index, case in enumerate(_INITIALIZED_ASYNC_FAILURES)],
)
def test_initialized_bridge_reports_missing_target_or_unopenable_object(
    bridge: ProcessBridge,
    method: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """An initialized bridge without an attached process rejects calls that need a target or name a missing object.

    Mutation: replacing the ``raise ToolError(_ERR_OPEN_FAILED)`` after a failed ``OpenProcess`` (for
    example process.py:5242) with ``pass`` lets the call proceed on a null handle and this test fails.

    Args:
        bridge: Initialized bridge with no attached process.
        method: Public method to call.
        args: Positional arguments for the call.
        message: Expected error text.
    """
    with pytest.raises(ToolError, match=re.escape(message)):
        _run(async_method(bridge, method)(*args))


@pytest.mark.parametrize(
    ("method", "args", "slot", "message"),
    _CLEARED_SLOT_ASYNC_GUARDS,
    ids=[f"{case[0]}-{case[2]}" for case in _CLEARED_SLOT_ASYNC_GUARDS],
)
def test_cleared_dll_slot_reports_the_missing_dll(
    bridge: ProcessBridge,
    method: str,
    args: tuple[object, ...],
    slot: str,
    message: str,
) -> None:
    """Clearing one DLL slot of an initialized bridge makes the entry point name exactly that DLL.

    Mutation: deleting the second guard of ``read_peb`` (process.py:5220-5222) makes the call go on
    to ``OpenProcess`` on ``None`` and this test fails with an AttributeError.

    Args:
        bridge: Initialized bridge.
        method: Public method to call.
        args: Positional arguments for the call.
        slot: Private DLL attribute cleared for the call.
        message: Expected error text.
    """
    with _slot(bridge, slot, None), pytest.raises(ToolError, match=re.escape(message)):
        _run(async_method(bridge, method)(*args))


@pytest.mark.parametrize(
    ("method", "make_args", "kwargs", "message"),
    _BARE_SYNC_GUARDS,
    ids=[case[0] for case in _BARE_SYNC_GUARDS],
)
def test_uninitialized_bridge_helpers_refuse_to_run(
    bare_bridge: ProcessBridge,
    method: str,
    make_args: Callable[[], tuple[object, ...]],
    kwargs: dict[str, object],
    message: str,
) -> None:
    """Private helpers raise the documented error instead of touching a missing DLL.

    Mutation: removing the ``if self._advapi32 is None`` guard of ``_apply_token_privilege``
    (process.py:4447-4448) makes the helper call ``None.LookupPrivilegeValueW`` and this test fails.

    Args:
        bare_bridge: Bridge that was never initialized.
        method: Private method to call.
        make_args: Factory for the positional arguments.
        kwargs: Keyword arguments for the call.
        message: Expected error text.
    """
    helper = sync_method(bare_bridge, method)
    args = make_args()
    with pytest.raises(ToolError, match=re.escape(message)):
        helper(*args, **kwargs)


@pytest.mark.parametrize(
    ("method", "make_args", "kwargs", "slot", "message"),
    _CLEARED_SLOT_SYNC_GUARDS,
    ids=[f"{case[0]}-{case[3]}" for case in _CLEARED_SLOT_SYNC_GUARDS],
)
def test_cleared_kernel_slot_makes_helpers_refuse_to_run(
    bridge: ProcessBridge,
    method: str,
    make_args: Callable[[], tuple[object, ...]],
    kwargs: dict[str, object],
    slot: str,
    message: str,
) -> None:
    """With the other DLLs present, clearing the kernel32 slot is what each helper reports.

    Mutation: removing the ``if self._kernel32 is None`` guard at process.py:4449-4450 lets
    ``_apply_token_privilege`` go on to ``LookupPrivilegeValueW`` and this test fails.

    Args:
        bridge: Initialized bridge.
        method: Private method to call.
        make_args: Factory for the positional arguments.
        kwargs: Keyword arguments for the call.
        slot: Private DLL attribute cleared for the call.
        message: Expected error text.
    """
    helper = sync_method(bridge, method)
    args = make_args()
    with _slot(bridge, slot, None), pytest.raises(ToolError, match=re.escape(message)):
        helper(*args, **kwargs)


@pytest.mark.parametrize(("method", "make_args", "expected"), _NEUTRAL_RETURNS, ids=[case[0] for case in _NEUTRAL_RETURNS])
def test_uninitialized_bridge_helpers_return_neutral_values(
    bare_bridge: ProcessBridge,
    method: str,
    make_args: Callable[[], tuple[object, ...]],
    expected: object,
) -> None:
    """Helpers that cannot fail loudly return their documented empty value on a bridge with no DLLs.

    Mutation: changing the ``return ""`` of ``_resolve_module`` at process.py:6438 to ``return "?"``
    makes the matching case fail.

    Args:
        bare_bridge: Bridge that was never initialized.
        method: Private method to call.
        make_args: Factory for the positional arguments.
        expected: The value the helper must return.
    """
    helper = sync_method(bare_bridge, method)
    args = make_args()
    assert helper(*args) == expected


def test_remove_privilege_impl_returns_false_when_kernel32_is_missing(bridge: ProcessBridge) -> None:
    """The privilege remover reports failure, not an exception, when only kernel32 is gone.

    Mutation: changing ``return False`` at process.py:7604 to ``return True`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    helper = sync_method(bridge, "_remove_privilege_impl")
    with _slot(bridge, "_kernel32", None):
        assert helper(wintypes.HANDLE(), 1, "SeShutdownPrivilege") is False


def test_handle_type_map_without_ntdll_keeps_the_cached_map(bare_bridge: ProcessBridge) -> None:
    """Without ntdll the object-type map is returned unchanged from the cache.

    Mutation: changing ``return self._handle_type_cache`` at process.py:4781 to ``return {}`` fails.

    Args:
        bare_bridge: Bridge that was never initialized.
    """
    seeded = {7: "Event", 9: "Section"}
    with _slot(bare_bridge, "_handle_type_cache", seeded):
        assert sync_method(bare_bridge, "_build_handle_type_map")() == {7: "Event", 9: "Section"}


def test_collection_helpers_do_nothing_without_kernel32(bare_bridge: ProcessBridge) -> None:
    """Snapshot walkers return without appending anything when kernel32 is missing.

    Mutation: replacing the ``return`` at process.py:7001 with a call that appends a placeholder
    entry makes the empty-list assertions fail.

    Args:
        bare_bridge: Bridge that was never initialized.
    """
    processes: list[dict[str, object]] = []
    list_heaps: list[dict[str, object]] = []
    walked_heaps: list[dict[str, object]] = []
    process_entry = PROCESSENTRY32()
    heap_entry = HEAPLIST32()
    sync_method(bare_bridge, "_collect_system_process_entries")(0, process_entry, processes)
    sync_method(bare_bridge, "_collect_heap_list_entries")(0, heap_entry, list_heaps)
    sync_method(bare_bridge, "_collect_heap_entries")(0, heap_entry, walked_heaps, 1, None, None, time.monotonic() + _WAIT_S)
    assert processes == []
    assert list_heaps == []
    assert walked_heaps == []


@pytest.mark.parametrize(
    ("name", "size", "offset", "length", "max_length", "payload", "expected"),
    _DECODE_CASES,
    ids=[case[0] for case in _DECODE_CASES],
)
def test_object_type_name_decoder_rejects_inconsistent_unicode_strings(
    name: str,
    size: int,
    offset: int,
    length: int,
    max_length: int,
    payload: bytes,
    expected: str,
) -> None:
    """The UNICODE_STRING decoder returns an empty name for every inconsistent header and the name for a good one.

    Mutation: dropping ``or length > max_length`` from process.py:4717 makes the
    ``length_above_maximum_length`` case decode garbage instead of returning an empty string.

    Args:
        name: Case identifier, unused except for the test id.
        size: Size of the buffer holding the string.
        offset: Offset of the UNICODE_STRING header.
        length: ``Length`` field in bytes.
        max_length: ``MaximumLength`` field in bytes.
        payload: Name bytes written 104 bytes after the header.
        expected: Name the decoder must return.
    """
    del name
    buffer = ctypes.create_string_buffer(size)
    struct.pack_into("<HH", buffer, offset, length, max_length)
    if payload:
        struct.pack_into(f"<{len(payload)}s", buffer, offset + 104, payload)
    decoder = sync_method(ProcessBridge, "_decode_object_type_name")
    assert decoder(buffer, offset, offset + 104) == expected


def test_object_type_name_reader_survives_a_null_header_pointer() -> None:
    """A header address that resolves to NULL yields an empty name and no exception.

    The offset is chosen so that the buffer address plus the offset is zero, which makes the
    ``.contents`` access inside the decoder raise the ``ValueError`` the reader is meant to absorb.

    Mutation: removing the ``except (ValueError, OSError, ctypes.ArgumentError)`` clause at
    process.py:4686 lets the ValueError escape and this test fails.
    """
    buffer = ctypes.create_string_buffer(64)
    reader = sync_method(ProcessBridge, "_read_object_type_name")
    name = reader(buffer, -ctypes.addressof(buffer), 8)
    assert isinstance(name, str)
    assert not name


def test_type_info_parser_skips_unnamed_entries_but_keeps_counting(bare_bridge: ProcessBridge) -> None:
    """An entry with an empty name leaves no map entry but still consumes one type index.

    Entries start 8 bytes in; each is 104 header bytes plus ``MaximumLength`` bytes, rounded up to
    a multiple of 8. The first entry has no name, the second is ``Event``, so the map is ``{3: "Event"}``.

    Mutation: changing ``if name:`` at process.py:4760 to ``if True:`` adds ``2: ""`` and fails.

    Args:
        bare_bridge: Bridge that was never initialized.
    """
    buffer = ctypes.create_string_buffer(256)
    struct.pack_into("<I", buffer, 0, 2)
    struct.pack_into("<HH", buffer, 8, 0, 8)
    struct.pack_into("<HH", buffer, 120, 10, 12)
    struct.pack_into("<10s", buffer, 120 + 104, "Event".encode("utf-16-le"))
    assert sync_method(bare_bridge, "_parse_type_info_buffer")(buffer, 256) == {3: "Event"}


def test_type_info_parser_stops_at_the_usable_buffer_size(bare_bridge: ProcessBridge) -> None:
    """Entries that start beyond the usable size are not parsed even if the memory holds a valid one.

    Mutation: deleting the ``break`` guard at process.py:4752-4753 parses the ``Event`` entry
    that lies beyond ``buf_size`` and the map gains ``3: "Event"``.

    Args:
        bare_bridge: Bridge that was never initialized.
    """
    buffer = ctypes.create_string_buffer(256)
    struct.pack_into("<I", buffer, 0, 3)
    struct.pack_into("<HH", buffer, 8, 8, 8)
    struct.pack_into("<8s", buffer, 8 + 104, "File".encode("utf-16-le"))
    struct.pack_into("<HH", buffer, 120, 10, 12)
    struct.pack_into("<10s", buffer, 120 + 104, "Event".encode("utf-16-le"))
    assert sync_method(bare_bridge, "_parse_type_info_buffer")(buffer, 160) == {2: "File"}


def _service_buffer(entries: tuple[tuple[int, int, int], ...]) -> ctypes.Array[ctypes.c_char]:
    """Build a buffer of ENUM_SERVICE_STATUS_PROCESSW records with null name pointers.

    Args:
        entries: One ``(process_id, current_state, service_type)`` per record.

    Returns:
        ctypes.Array[ctypes.c_char]: A buffer holding exactly ``len(entries)`` records.
    """
    entry_size = ctypes.sizeof(ENUM_SERVICE_STATUS_PROCESSW)
    buffer = ctypes.create_string_buffer(entry_size * len(entries))
    for index, (pid, state, service_type) in enumerate(entries):
        record = ctypes.cast(ctypes.byref(buffer, index * entry_size), ctypes.POINTER(ENUM_SERVICE_STATUS_PROCESSW)).contents
        record.ServiceStatusProcess.dwProcessId = pid
        record.ServiceStatusProcess.dwCurrentState = state
        record.ServiceStatusProcess.dwServiceType = service_type
    return buffer


def test_service_parser_stops_when_the_count_exceeds_the_buffer() -> None:
    """A count larger than the buffer holds yields only the records that fit, with decoded states.

    Mutation: deleting the bounds check at process.py:5148-5150 reads past the buffer and the
    result no longer equals the three expected records.
    """
    buffer = _service_buffer(((100, 4, 0x10), (200, 1, 0x20), (300, 99, 0x10)))
    parser = sync_method(ProcessBridge, "_parse_service_entries")
    assert parser(buffer, 5, None) == [
        {"name": "", "display_name": "", "state": "running", "pid": 100, "service_type": 0x10},
        {"name": "", "display_name": "", "state": "stopped", "pid": 200, "service_type": 0x20},
        {"name": "", "display_name": "", "state": "unknown", "pid": 300, "service_type": 0x10},
    ]


def test_service_parser_filters_by_owning_process() -> None:
    """Only records whose process id equals the filter are returned.

    Mutation: changing ``svc_pid != filter_pid`` at process.py:5163 to ``svc_pid == filter_pid``
    returns the other two records and fails.
    """
    buffer = _service_buffer(((100, 4, 0x10), (200, 1, 0x20), (300, 4, 0x10)))
    parser = sync_method(ProcessBridge, "_parse_service_entries")
    assert parser(buffer, 3, 200) == [
        {"name": "", "display_name": "", "state": "stopped", "pid": 200, "service_type": 0x20},
    ]


def test_peb_parser_uses_the_i386_layout_for_32_bit_targets() -> None:
    """The 32-bit PEB layout puts ImageBaseAddress at 0x08, Ldr at 0x0C and ProcessParameters at 0x10.

    Mutation: changing the ``0x0C`` offset at process.py:5444 to ``0x10`` swaps the Ldr and
    ProcessParameters values and fails.
    """
    raw = bytearray(0x30)
    raw[0] = 1
    raw[2] = 1
    struct.pack_into("<III", raw, 0x08, 0x00400000, 0x77001000, 0x00123450)
    parser = sync_method(ProcessBridge, "_parse_peb_fields")
    assert parser(bytes(raw), 0x7FFDF000, target_is_64bit=False) == {
        "peb_address": 0x7FFDF000,
        "image_base_address": 0x00400000,
        "ldr_address": 0x77001000,
        "process_parameters_address": 0x00123450,
        "being_debugged": 1,
        "inherited_address_space": 1,
    }


def test_peb32_parser_reads_a_full_buffer() -> None:
    """A PEB32 buffer of at least 0x18 bytes is parsed field by field.

    Mutation: changing the ``0x08`` offset at process.py:5479 to ``0x0C`` reports the Ldr address
    as the image base and fails.
    """
    raw = bytearray(0x18)
    raw[0] = 1
    raw[2] = 1
    struct.pack_into("<III", raw, 0x08, 0x00400000, 0x77001000, 0x00123450)
    parser = sync_method(ProcessBridge, "_parse_peb32_fields")
    assert parser(bytes(raw), 0x7FFDE000) == {
        "peb_address": 0x7FFDE000,
        "image_base_address": 0x00400000,
        "ldr_address": 0x77001000,
        "process_parameters_address": 0x00123450,
        "being_debugged": 1,
        "inherited_address_space": 1,
    }


@pytest.mark.parametrize(
    ("raw", "being_debugged", "inherited"),
    [
        pytest.param(b"\x01\x00\x01\x00", 1, 1, id="four_bytes"),
        pytest.param(b"\x05\x00", 0, 5, id="two_bytes"),
        pytest.param(b"", 0, 0, id="empty"),
    ],
)
def test_peb32_parser_reports_zero_fields_for_short_buffers(raw: bytes, being_debugged: int, inherited: int) -> None:
    """A PEB32 buffer shorter than 0x18 bytes yields zero addresses and only the bytes that exist.

    Mutation: changing ``_PEB32_MIN_PARSE_LENGTH`` handling at process.py:5469 to ``< 0`` makes the
    parser raise ``struct.error`` on these buffers and fails.

    Args:
        raw: The truncated PEB bytes.
        being_debugged: Expected ``being_debugged`` value.
        inherited: Expected ``inherited_address_space`` value.
    """
    parser = sync_method(ProcessBridge, "_parse_peb32_fields")
    assert parser(raw, 0x7FFDE000) == {
        "peb_address": 0x7FFDE000,
        "image_base_address": 0,
        "ldr_address": 0,
        "process_parameters_address": 0,
        "being_debugged": being_debugged,
        "inherited_address_space": inherited,
    }


def test_teb_parser_uses_the_i386_layout_for_32_bit_targets() -> None:
    """The 32-bit TEB layout and its TLS slot array at TEB+0xE10 are decoded from the documented offsets.

    NT_TIB fields come first (exception list 0x00, stack base 0x04, stack limit 0x08, fiber data
    0x10), then the TLS pointer at 0x2C, the PEB pointer at 0x30, the last error at 0x34 and the
    SameTebFlags word at 0xFCA, whose bit 2 means a fiber is present.

    Mutation: changing ``0x30`` at process.py:5673 to ``0x34`` reports the last error as the PEB
    address and fails.
    """
    raw = bytearray(0xFCC)
    struct.pack_into("<I", raw, 0x00, 0x0019FF70)
    struct.pack_into("<I", raw, 0x04, 0x001A0000)
    struct.pack_into("<I", raw, 0x08, 0x0019E000)
    struct.pack_into("<I", raw, 0x10, 0x00001E00)
    struct.pack_into("<I", raw, 0x2C, 0x00B10000)
    struct.pack_into("<I", raw, 0x30, 0x7FFDE000)
    struct.pack_into("<I", raw, 0x34, 5)
    struct.pack_into("<H", raw, 0xFCA, 0x000C)
    parser = sync_method(ProcessBridge, "_parse_teb_fields")
    assert parser(bytes(raw), 0x7FFDF000, target_is_64bit=False) == {
        "teb_address": 0x7FFDF000,
        "seh_frame": 0x0019FF70,
        "stack_base": 0x001A0000,
        "stack_limit": 0x0019E000,
        "fiber_data": 0x00001E00,
        "thread_local_storage_pointer": 0x00B10000,
        "peb_address": 0x7FFDE000,
        "last_error_value": 5,
        "same_teb_flags": 0x000C,
        "has_fiber_data": True,
        "tls_array_base": 0x7FFDF000 + 0xE10,
    }


def test_mitigation_decoder_reports_reserved_bits_and_the_dep_permanent_flag() -> None:
    """Bits beyond the documented DEP flags land in ``reserved`` and ``Permanent`` comes from the structure.

    Mutation: changing ``flags_val & ~consumed_mask`` at process.py:6924 to ``flags_val & consumed_mask``
    reports ``reserved`` as 3 instead of 4 and fails.
    """
    policy = PROCESS_MITIGATION_DEP_POLICY(Flags=7, Permanent=1)
    decoder = sync_method(ProcessBridge, "_decode_mitigation_flags")
    assert decoder("DEP", 7, policy) == {
        "flags": 7,
        "flags_hex": "0x00000007",
        "Enable": True,
        "DisableAtlThunkEmulation": True,
        "reserved": 4,
        "enabled": True,
        "Permanent": True,
    }


@pytest.mark.parametrize(
    ("flags", "expected"),
    [
        pytest.param(5, {"flags": 5, "flags_hex": "0x00000005", "reserved": 5, "enabled": True}, id="bits_set"),
        pytest.param(0, {"flags": 0, "flags_hex": "0x00000000", "enabled": False}, id="no_bits"),
    ],
)
def test_mitigation_decoder_without_named_bits_derives_enabled_from_the_raw_flags(flags: int, expected: dict[str, object]) -> None:
    """A policy with no documented bit names is enabled exactly when any flag bit is set.

    Mutation: changing ``bool(flags_val)`` at process.py:6931 to ``True`` makes the ``no_bits`` case fail.

    Args:
        flags: Raw flags value.
        expected: The decoded dictionary.
    """
    decoder = sync_method(ProcessBridge, "_decode_mitigation_flags")
    assert decoder("Unlisted", flags, PROCESS_MITIGATION_ASLR_POLICY(Flags=flags)) == expected


def test_adjusting_a_privilege_the_token_never_held_reports_not_held(bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """Enabling SeCreateTokenPrivilege, which no ordinary account token holds, is reported as not held.

    ``AdjustTokenPrivileges`` succeeds but sets ``ERROR_NOT_ALL_ASSIGNED`` when the token lacks the
    privilege; the child shares the pytest user's token, which never contains the privilege that is
    granted only to the security subsystem.

    Mutation: changing ``last_error == ERROR_NOT_ALL_ASSIGNED`` at process.py:4462 to ``!=`` makes
    the call return True and this test fail.

    Args:
        bridge: Initialized bridge.
        target_process: The running child process.
    """
    with pytest.raises(ToolError, match=re.escape("privilege not held: SeCreateTokenPrivilege")):
        _run(bridge.adjust_token_privilege("SeCreateTokenPrivilege", enable=True, pid=target_process.pid))


@pytest.mark.parametrize(
    ("method", "last_argument"),
    [
        pytest.param("_enumerate_services", None, id="enumerate_services"),
        pytest.param("_enumerate_services_by_state", _STATE_ALL, id="enumerate_services_by_state"),
    ],
)
def test_service_enumeration_with_an_invalid_manager_handle_returns_nothing(
    bridge: ProcessBridge,
    scm_enum_function: Callable[..., int],
    method: str,
    last_argument: int | None,
) -> None:
    """Both service enumerators return an empty list when the size probe reports no bytes needed.

    A NULL service-manager handle makes ``EnumServicesStatusExW`` fail without reporting a size.

    Mutation: changing ``if buf_size == 0`` at process.py:5096 (or 7322) to ``if buf_size < 0`` makes
    the enumerator allocate a zero-length buffer, call the API again and raise.

    Args:
        bridge: Initialized bridge.
        scm_enum_function: Configured ``EnumServicesStatusExW``.
        method: Private enumerator to call.
        last_argument: The PID filter or service-state filter, depending on the enumerator.
    """
    assert sync_method(bridge, method)(0, scm_enum_function, last_argument) == []


def test_read_peb_from_an_invalid_handle_reports_the_ntstatus(bridge: ProcessBridge) -> None:
    """A NULL process handle makes NtQueryInformationProcess fail and the NTSTATUS appears in the error.

    Mutation: changing ``status < 0`` at process.py:5286 to ``status > 0`` lets the invalid handle
    through to ``ReadProcessMemory`` and the message check fails.

    Args:
        bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="NtQueryInformationProcess " + _ERR_WIN32_STATUS):
        sync_method(bridge, "_read_peb_from_handle")(0)


def test_read_peb_without_read_access_reports_a_read_failure(bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """A query-only handle lets the PEB address be found but not read, and the failure is reported.

    Mutation: changing ``if not self._kernel32.ReadProcessMemory(`` at process.py:5295 to
    ``if self._kernel32.ReadProcessMemory(`` makes this test fail because the error is not raised.

    Args:
        bridge: Initialized bridge.
        target_process: The running child process.
    """
    with (
        _opened_process(target_process.pid, _PROCESS_QUERY_INFORMATION) as handle,
        pytest.raises(ToolError, match=re.escape("PEB read failed")),
    ):
        sync_method(bridge, "_read_peb_from_handle")(handle)


def test_wow64_peb_query_with_an_invalid_handle_returns_nothing(bridge: ProcessBridge) -> None:
    """A failing ProcessWow64Information query is treated as 'no 32-bit PEB'.

    Mutation: changing ``return None`` at process.py:5392 to ``return (0, {})`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    assert sync_method(bridge, "_read_wow64_peb")(0) is None


def test_read_teb_from_an_invalid_thread_handle_reports_the_ntstatus(bridge: ProcessBridge) -> None:
    """A NULL thread handle makes NtQueryInformationThread fail and the NTSTATUS appears in the error.

    Mutation: changing ``status < 0`` at process.py:5571 to ``status > 0`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="NtQueryInformationThread " + _ERR_WIN32_STATUS):
        sync_method(bridge, "_read_teb_with_thread_handle")(1, 0, [None])


def test_teb_read_without_read_access_reports_a_read_failure(bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """A query-only process handle cannot read the TEB and the failure is reported.

    Mutation: changing ``if not self._kernel32.ReadProcessMemory(`` at process.py:5622 to
    ``if self._kernel32.ReadProcessMemory(`` fails this test.

    Args:
        bridge: Initialized bridge.
        target_process: The running child process.
    """
    with (
        _opened_process(target_process.pid, _PROCESS_QUERY_INFORMATION) as handle,
        pytest.raises(ToolError, match=re.escape("TEB read failed")),
    ):
        sync_method(bridge, "_read_and_parse_teb")(handle, _PAGE, exit_status=0)


def test_heap_walkers_return_nothing_for_an_unusable_snapshot(bridge: ProcessBridge) -> None:
    """The heap-list walkers return without results when the first heap cannot be fetched.

    Mutation: changing ``return`` at process.py:5753 to ``heaps.append({})`` (or at 7154) leaves a
    bogus entry and fails this test.

    Args:
        bridge: Initialized bridge.
    """
    list_heaps: list[dict[str, object]] = []
    walked_heaps: list[dict[str, object]] = []
    heap_entry = HEAPLIST32()
    heap_entry.dwSize = ctypes.sizeof(HEAPLIST32)
    sync_method(bridge, "_collect_heap_list_entries")(0, heap_entry, list_heaps)
    sync_method(bridge, "_collect_heap_entries")(0, heap_entry, walked_heaps, 1, None, None, time.monotonic() + _WAIT_S)
    assert list_heaps == []
    assert walked_heaps == []


def test_heap_block_walker_returns_nothing_without_the_block_apis() -> None:
    """Without Heap32First/Heap32Next there are no blocks to report.

    Mutation: changing ``or`` to ``and`` at process.py:7214 makes the walker dereference ``None`` and fail.
    """
    walker = sync_method(ProcessBridge, "_collect_heap_blocks")
    assert walker(1, 0, None, None, time.monotonic() + _WAIT_S) == []


def test_heap_block_walker_returns_nothing_for_an_unknown_process(bridge: ProcessBridge) -> None:
    """Heap32First fails for a process that does not exist and the walker reports no blocks.

    Mutation: changing ``return blocks`` at process.py:7219 to ``raise ToolError("x")`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    kernel32 = priv(bridge, "_kernel32", ctypes.WinDLL)
    heap32first = cast("Callable[..., int]", getattr(kernel32, "Heap32First"))
    heap32next = cast("Callable[..., int]", getattr(kernel32, "Heap32Next"))
    walker = sync_method(ProcessBridge, "_collect_heap_blocks")
    assert walker(_ABSENT_PID, 0, heap32first, heap32next, time.monotonic() + _WAIT_S) == []


def test_heap_walk_of_a_small_process_reports_every_heap_and_ends_cleanly(bridge: ProcessBridge, cmd_process: Popen[bytes]) -> None:
    """The block walk visits the whole heap list of a small child and finishes each heap through ``Heap32Next``.

    The expected heap ids and flags, in order and with multiplicity, come from an independent
    Toolhelp32 heap-list walk of the same child (own kernel32 handle, own ``HEAPLIST32`` definition,
    own snapshot).

    Mutation: inserting a ``break`` right after the ``heaps.append`` at process.py:7157 stops the
    walk after the first heap and the id list no longer equals the oracle's.

    Args:
        bridge: Initialized bridge.
        cmd_process: The running ``cmd.exe`` child.
    """
    heaps = _run(bridge.enumerate_heaps(cmd_process.pid))
    expected = _toolhelp_heap_list(cmd_process.pid)
    assert [cast("int", heap["id"]) for heap in heaps] == [heap_id for heap_id, _ in expected]
    assert [cast("int", heap["flags"]) for heap in heaps] == [flags for _, flags in expected]
    for heap in heaps:
        for block in cast("list[dict[str, object]]", heap["blocks"]):
            assert set(block) == {"address", "size", "flags"}
            assert cast("int", block["address"]) > 0


def test_process_snapshot_failure_reports_the_last_error(bridge: ProcessBridge) -> None:
    """A failing Process32First that is not ERROR_NO_MORE_FILES raises with the captured error code.

    The thread's ctypes error slot is set to 0 beforehand, so the reported code is 0.

    Mutation: changing ``error_code != _ERROR_NO_MORE_FILES`` at process.py:7004 to ``==`` makes the
    call return quietly and this test fail.

    Args:
        bridge: Initialized bridge.
    """
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    ctypes.set_last_error(0)
    with pytest.raises(ToolError, match=re.escape("snapshot creation failed (Process32First: 0)")):
        sync_method(bridge, "_collect_system_process_entries")(0, entry, [])


def test_process_snapshot_with_no_more_files_is_not_an_error(bridge: ProcessBridge) -> None:
    """Process32First reporting ERROR_NO_MORE_FILES (18) ends the walk without an exception or entries.

    Mutation: changing ``return`` at process.py:7007 to ``raise ToolError("x")`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    results: list[dict[str, object]] = []
    ctypes.set_last_error(_ERROR_NO_MORE_FILES)
    sync_method(bridge, "_collect_system_process_entries")(0, entry, results)
    assert results == []


def test_time_wait_on_an_invalid_handle_reports_failure(bridge: ProcessBridge) -> None:
    """Waiting on a NULL handle returns WAIT_FAILED, which the bridge reports as ``failed``.

    Mutation: changing ``result_str = "failed"`` at process.py:7406 to ``"signaled"`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    result = cast("dict[str, object]", sync_method(bridge, "_time_wait_on_handle")(0, 1, 0))
    assert result["result"] == "failed"
    assert isinstance(result["elapsed_us"], int)


def test_time_wait_on_an_abandoned_mutex_reports_the_raw_code(bridge: ProcessBridge) -> None:
    """A mutex whose owner thread exited gives WAIT_ABANDONED (0x80), reported as ``other_128``.

    Mutation: changing the ``f"other_{wait_result}"`` at process.py:7408 to ``"other"`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    kernel32 = _k32()
    initial_owner = False
    mutex: int | None = kernel32.CreateMutexW(None, initial_owner, None)
    assert mutex

    def _acquire_and_exit() -> None:
        """Take ownership of the mutex and return without releasing it."""
        kernel32.WaitForSingleObject(mutex, 5000)

    worker = threading.Thread(target=_acquire_and_exit)
    worker.start()
    try:
        worker.join(timeout=_WAIT_S)
        assert not worker.is_alive()
        result = cast("dict[str, object]", sync_method(bridge, "_time_wait_on_handle")(mutex, 1, 1000))
    finally:
        worker.join(timeout=_WAIT_S)
        kernel32.CloseHandle(mutex)
    assert result["result"] == f"other_{_WAIT_ABANDONED}"
    assert isinstance(result["elapsed_us"], int)


def test_token_duplication_helpers_fail_on_invalid_handles(bridge: ProcessBridge) -> None:
    """A NULL process handle cannot yield a token, and a NULL token cannot be duplicated.

    Mutation: changing ``if not self._advapi32.DuplicateTokenEx(`` at process.py:7497 to
    ``if self._advapi32.DuplicateTokenEx(`` makes the second call return a value and fail.

    Args:
        bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match=re.escape(_ERR_TOKEN_OPEN)):
        sync_method(bridge, "_duplicate_token_for_handle")(0, 1)
    with pytest.raises(ToolError, match=re.escape("DuplicateTokenEx failed")):
        sync_method(bridge, "_duplicate_token_impl")(wintypes.HANDLE(0), 1)


def test_privilege_removal_fails_to_open_the_token_of_an_invalid_handle(bridge: ProcessBridge) -> None:
    """Removing a privilege through a NULL process handle reports that the token cannot be opened.

    Mutation: changing ``if not self._advapi32.OpenProcessToken(`` at process.py:7570 to
    ``if self._advapi32.OpenProcessToken(`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match=re.escape(_ERR_TOKEN_OPEN)):
        sync_method(bridge, "_remove_privilege_for_handle")(0, 1, "SeShutdownPrivilege")


def test_decommit_of_an_unallocated_address_reports_failure(bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """Decommitting memory that was never allocated in a child opened by pid returns False.

    The bridge is not attached, so the pid path opens its own handle with ``PROCESS_VM_OPERATION``
    and closes it again.

    Mutation: changing ``return result`` at process.py:7676 to ``return True`` fails this test.

    Args:
        bridge: Initialized bridge without an attached process.
        target_process: The running child process.
    """
    assert _run(bridge.decommit_memory(target_process.pid, 0x10, _PAGE)) is False


@pytest.mark.parametrize(
    ("value_name", "expected"),
    [
        pytest.param("dword_value", {"type": "REG_DWORD", "data": _DWORD_VALUE}, id="dword"),
        pytest.param("qword_value", {"type": "REG_QWORD", "data": _QWORD_VALUE}, id="qword"),
        pytest.param("binary_value", {"type": "REG_BINARY", "data": _BINARY_PAYLOAD.hex()}, id="binary"),
    ],
)
def test_registry_values_are_decoded_by_type(
    bridge: ProcessBridge,
    registry_key: str,
    value_name: str,
    expected: dict[str, object],
) -> None:
    """DWORD and QWORD values decode to integers and other types come back as hexadecimal bytes.

    Mutation: changing ``struct.unpack_from("<Q", raw)`` at process.py:7752 to ``"<I"`` truncates
    the QWORD and fails the ``qword`` case.

    Args:
        bridge: Initialized bridge.
        registry_key: Scratch key holding the typed values.
        value_name: Value to read.
        expected: Expected result dictionary.
    """
    assert _run(bridge.read_registry("HKCU", registry_key, value_name)) == expected


def test_kernel_debugger_query_on_an_invalid_handle_reports_the_ntstatus(bridge: ProcessBridge) -> None:
    """A NULL process handle makes the debug-port query fail with an NTSTATUS in the message.

    Mutation: changing ``status < 0`` at process.py:7814 to ``status > 0`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="NtQueryInformationProcess " + _ERR_WIN32_STATUS):
        sync_method(bridge, "_query_kernel_debugger_port")(0, 1)


def test_mitigation_query_with_an_invalid_handle_reports_query_failure(bridge: ProcessBridge) -> None:
    """A failing GetProcessMitigationPolicy yields the 'query failed' entry rather than flags.

    Mutation: changing ``if ok:`` at process.py:6879 to ``if not ok:`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    kernel32 = priv(bridge, "_kernel32", ctypes.WinDLL)
    get_policy = cast("Callable[..., int]", getattr(kernel32, "GetProcessMitigationPolicy"))
    result = sync_method(bridge, "_query_single_mitigation_policy")(get_policy, 0, "DEP", 0, PROCESS_MITIGATION_DEP_POLICY)
    assert result == {"enabled": False, "error": "query failed"}


def test_extension_point_query_with_an_invalid_handle_is_not_enabled(bridge: ProcessBridge) -> None:
    """A failing extension-point policy query is reported as not disabled.

    Mutation: changing the final ``return False`` at process.py:7963 to ``return True`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    assert sync_method(bridge, "_query_extension_point_disable")(0, None) is False


def test_mitigation_collection_without_the_policy_export_reports_unavailable(bridge: ProcessBridge) -> None:
    """A kernel library without GetProcessMitigationPolicy yields a single error entry.

    The kernel slot is temporarily filled with the real advapi32 handle, which does not export
    the function, the way an older Windows kernel32 would not.

    Mutation: changing ``if get_policy is None`` at process.py:6830 to ``if get_policy is not None``
    fails this test.

    Args:
        bridge: Initialized bridge.
    """
    with _slot(bridge, "_kernel32", ctypes.WinDLL("advapi32")):
        result = sync_method(bridge, "_collect_mitigation_policies")(0)
    assert result == {"error": "GetProcessMitigationPolicy not available"}


def test_extension_point_query_without_the_policy_export_is_not_enabled(bridge: ProcessBridge) -> None:
    """A kernel library without GetProcessMitigationPolicy cannot report the extension-point policy.

    Mutation: changing ``return False`` at process.py:7948 to ``return True`` fails this test.

    Args:
        bridge: Initialized bridge.
    """
    with _slot(bridge, "_kernel32", ctypes.WinDLL("advapi32")):
        assert sync_method(bridge, "_query_extension_point_disable")(0, None) is False


@pytest.mark.parametrize(("method", "args", "message"), _MISSING_EXPORT_CALLS, ids=[case[0] for case in _MISSING_EXPORT_CALLS])
def test_wow64_context_helpers_without_the_wow64_exports_refuse(
    bridge: ProcessBridge,
    method: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """A kernel library without Wow64GetThreadContext makes the WOW64 context helpers raise.

    The kernel slot is temporarily filled with the real advapi32 handle, which lacks the export.

    Mutation: changing ``if wow64_get_ctx is None`` at process.py:5850 to ``is not None`` fails this test.

    Args:
        bridge: Initialized bridge.
        method: Private helper to call.
        args: Positional arguments for the call.
        message: Expected error text.
    """
    helper = sync_method(bridge, method)
    with _slot(bridge, "_kernel32", ctypes.WinDLL("advapi32")), pytest.raises(ToolError, match=re.escape(message)):
        helper(*args)


def test_wow64_stack_walk_without_the_wow64_export_refuses(attached_bridge: ProcessBridge) -> None:
    """The WOW64 stack walker raises when the kernel library lacks Wow64GetThreadContext.

    Mutation: changing ``if wow64_get_ctx is None`` at process.py:6297 to ``is not None`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    walker = sync_method(attached_bridge, "_walk_stack_wow64")
    with _slot(attached_bridge, "_kernel32", ctypes.WinDLL("advapi32")), pytest.raises(ToolError, match=re.escape(_ERR_CONTEXT_GET)):
        walker(0)


@pytest.mark.parametrize(("method", "args", "message"), _FAILING_HANDLE_CALLS, ids=[case[0] for case in _FAILING_HANDLE_CALLS])
def test_context_and_stack_helpers_report_failure_for_a_null_thread_handle(
    attached_bridge: ProcessBridge,
    method: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """Context and stack helpers raise the documented error when the Win32 call rejects a NULL thread handle.

    Mutation: changing ``if not self._kernel32.GetThreadContext(`` at process.py:6255 to
    ``if self._kernel32.GetThreadContext(`` fails the ``_walk_stack_native`` case.

    Args:
        attached_bridge: Bridge attached to the child.
        method: Private helper to call.
        args: Positional arguments for the call.
        message: Expected error text.
    """
    helper = sync_method(attached_bridge, method)
    with pytest.raises(ToolError, match=re.escape(message)):
        helper(*args)


def test_stack_walk_of_an_unknown_thread_reports_that_it_cannot_be_opened(attached_bridge: ProcessBridge) -> None:
    """Walking the stack of thread id 0 fails at OpenThread.

    Mutation: deleting the ``raise ToolError(_ERR_THREAD_OPEN_FAILED)`` at process.py:6168 fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    with pytest.raises(ToolError, match=re.escape(_ERR_THREAD_OPEN)):
        _run(attached_bridge.stack_walk(0))


def test_stack_walk_reports_a_symbol_handler_that_is_already_initialized(attached_bridge: ProcessBridge) -> None:
    """DbgHelp refuses a second SymInitialize for the same process handle and the walker reports it.

    Mutation: changing ``if not self._dbghelp.SymInitialize(`` at process.py:6228 to
    ``if self._dbghelp.SymInitialize(`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    dbghelp = priv(attached_bridge, "_dbghelp", ctypes.WinDLL)
    handle = attached_bridge.process_handle
    assert handle is not None
    invade = False
    assert dbghelp.SymInitialize(handle, None, invade)
    try:
        with pytest.raises(ToolError, match=re.escape(_ERR_DBGHELP)):
            sync_method(attached_bridge, "_stack_walk_with_dbghelp")(0)
    finally:
        dbghelp.SymCleanup(handle)


def test_native_context_update_without_set_access_reports_failure(attached_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """A thread handle that may read but not set the context fails at SetThreadContext after unknown names are skipped.

    The child's thread is suspended around the call so its context is valid.

    Mutation: changing ``if not self._kernel32.SetThreadContext(`` at process.py:6123 to
    ``if self._kernel32.SetThreadContext(`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
        target_process: The running child process.
    """
    kernel32 = _k32()
    helper = sync_method(attached_bridge, "_apply_native_context")
    with _opened_thread(_child_tid(target_process), _THREAD_GET_CONTEXT | _THREAD_SUSPEND_RESUME) as thread:
        assert kernel32.SuspendThread(thread) != 0xFFFFFFFF
        try:
            with pytest.raises(ToolError, match=re.escape(_ERR_CONTEXT_SET)):
                helper(thread, {"unknown_register": 1, "rax": 0x1234})
        finally:
            kernel32.ResumeThread(thread)


def test_symbol_and_module_resolution_fail_for_an_address_with_no_module(attached_bridge: ProcessBridge) -> None:
    """DbgHelp resolves nothing for address 1, so both resolvers return their empty values.

    Mutation: changing ``return "", 0`` at process.py:6426 to ``return "?", 0`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    assert sync_method(attached_bridge, "_resolve_symbol")(1) == ("", 0)
    module_name = sync_method(attached_bridge, "_resolve_module")(1)
    assert isinstance(module_name, str)
    assert not module_name


def test_mitigation_summary_of_the_attached_child_matches_the_win32_oracle(attached_bridge: ProcessBridge) -> None:
    """The attached-process path reports ASLR and CFG exactly as an independent policy query does.

    Mutation: swapping the ``aslr`` and ``cfg`` keys at process.py:7885-7886 fails this test whenever
    the two policies differ.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    handle = attached_bridge.process_handle
    assert handle is not None
    result = _run(attached_bridge.get_mitigation_policy())
    assert set(result) == {"dep", "aslr", "cfg", "sehop_via_options_mask"}
    assert result["aslr"] is _primary_bit(handle, 1)
    assert result["cfg"] is _primary_bit(handle, 7)
    assert isinstance(result["dep"], bool)
    assert isinstance(result["sehop_via_options_mask"], int)


def test_extension_policy_of_the_attached_child_matches_the_win32_oracle(attached_bridge: ProcessBridge) -> None:
    """The attached-process path reports the extension-point policy exactly as an independent query does.

    Mutation: changing ``policy_buf.value & 1`` at process.py:7956 to ``policy_buf.value & 2`` fails
    whenever the policy bit is set.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    handle = attached_bridge.process_handle
    assert handle is not None
    assert _run(attached_bridge.get_extension_policy()) == {"disable_extension_points": _primary_bit(handle, 6)}


def test_environment_block_with_a_null_pointer_is_empty(attached_bridge: ProcessBridge) -> None:
    """A process-parameters block whose Environment pointer is NULL yields no variables.

    The block is a zero-filled page planted in the child; Environment lives at offset 0x80 of
    RTL_USER_PROCESS_PARAMETERS on x64.

    Mutation: changing ``if env_ptr == 0`` at process.py:8069 to ``if env_ptr != 0`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    handle = attached_bridge.process_handle
    assert handle is not None
    params = _plant(attached_bridge, b"\x00" * _PARAMS_READ_SIZE_X64, _PAGE)
    assert sync_method(attached_bridge, "_read_env_block")(handle, params) == {}


def test_environment_block_without_read_access_is_empty(attached_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """A handle without ``PROCESS_VM_READ`` cannot read the parameter block, so no variables are reported.

    The parameter block is a valid planted page; only the access rights of the handle differ.

    Mutation: changing ``return {}`` at process.py:8065 to ``raise ToolError("x")`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child, used to plant the block.
        target_process: The running child process.
    """
    params = _plant(attached_bridge, b"\x00" * _PARAMS_READ_SIZE_X64, _PAGE)
    with _opened_process(target_process.pid, _PROCESS_QUERY_INFORMATION) as handle:
        assert sync_method(attached_bridge, "_read_env_block")(handle, params) == {}


def test_environment_block_with_an_unreadable_pointer_is_empty(attached_bridge: ProcessBridge) -> None:
    """An Environment pointer into unmapped memory yields no variables instead of an error.

    Mutation: changing ``if not env_bytes`` at process.py:8073 to ``if env_bytes`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    handle = attached_bridge.process_handle
    assert handle is not None
    image = bytearray(_PARAMS_READ_SIZE_X64)
    struct.pack_into("<Q", image, _PARAMS_ENV_POINTER_OFFSET_X64, 0x10)
    params = _plant(attached_bridge, bytes(image), _PAGE)
    assert sync_method(attached_bridge, "_read_env_block")(handle, params) == {}


def test_environment_read_stops_at_the_size_ceiling(attached_bridge: ProcessBridge) -> None:
    """A block without a terminator is read up to exactly the 2 MiB ceiling and no further.

    Mutation: raising ``_ENV_READ_MAX`` at process.py:399 above 0x200000 makes the walk continue
    into the zero bytes after the block and fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    handle = attached_bridge.process_handle
    assert handle is not None
    block = _plant(attached_bridge, b"A" * _ENV_CEILING, _ENV_CEILING + 0x10000)
    assert sync_method(attached_bridge, "_read_env_bytes")(handle, block) == b"A" * _ENV_CEILING


def test_environment_read_keeps_the_prefix_of_a_chunk_that_hits_unmapped_memory(attached_bridge: ProcessBridge) -> None:
    """When a chunk runs off the end of the committed page, the readable prefix is returned.

    One committed page of unterminated bytes is planted; the chunk read of 0x2000 bytes copies the
    first 0x1000 and fails on the rest.

    Mutation: deleting the ``if not ok: break`` at process.py:8131-8132 makes the walk read the
    next chunk, get nothing and still return the prefix, so a variant that discards it
    (``collected.clear()``) fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    handle = attached_bridge.process_handle
    assert handle is not None
    block = _plant(attached_bridge, b"A" * _PAGE, _PAGE)
    assert sync_method(attached_bridge, "_read_env_bytes")(handle, block) == b"A" * _PAGE


def test_handler_enumeration_of_a_well_formed_module_reports_its_handler(attached_bridge: ProcessBridge) -> None:
    """A planted PE32+ image with one handler-carrying function yields exactly that handler.

    This is the positive control for the rejected-image cases below.

    Mutation: changing ``base + handler_rva`` at process.py:6705 to ``handler_rva`` fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    base = _plant(attached_bridge, bytes(_module_image(_PAGE)), _PAGE)
    module = _module_info("planted.dll", base, _PAGE)
    handlers = sync_method(attached_bridge, "_enumerate_module_exception_handlers")(module)
    assert handlers == [
        {
            "module": "planted.dll",
            "address": base + 0x10,
            "end_address": base + 0x20,
            "handler_address": base + 0x700,
            "flags": "EHANDLER",
        },
    ]


@pytest.mark.parametrize(("name", "make_image"), _REJECTED_IMAGES, ids=[case[0] for case in _REJECTED_IMAGES])
def test_handler_enumeration_skips_images_with_a_single_defect(
    attached_bridge: ProcessBridge,
    name: str,
    make_image: Callable[[], bytearray],
) -> None:
    """An image that would otherwise yield a handler yields nothing when one header field is wrong.

    Mutation: deleting the ``dos[:2] != PE_DOS_SIGNATURE`` test at process.py:6652 (or the matching
    check for each case) lets the planted handler through and fails the corresponding case.

    Args:
        attached_bridge: Bridge attached to the child.
        name: Case identifier, unused except for the test id.
        make_image: Factory for an otherwise valid image with one defective header field.
    """
    del name
    base = _plant(attached_bridge, bytes(make_image()), _PAGE)
    module = _module_info("defective.dll", base, _PAGE)
    assert sync_method(attached_bridge, "_enumerate_module_exception_handlers")(module) == []


@pytest.mark.parametrize("base", [pytest.param(0, id="null_base"), pytest.param(0x10, id="unreadable_base")])
def test_handler_enumeration_skips_modules_without_a_readable_header(attached_bridge: ProcessBridge, base: int) -> None:
    """A module at a NULL or unmapped base yields no handlers and no exception.

    Mutation: changing ``if base == 0`` at process.py:6608 to ``if base != 0`` fails the ``null_base``
    case, and changing the ``except ToolError`` at 6649 to ``except KeyError`` fails ``unreadable_base``.

    Args:
        attached_bridge: Bridge attached to the child.
        base: Base address given to the module description.
    """
    module = _module_info("nowhere.dll", base, _PAGE)
    assert sync_method(attached_bridge, "_enumerate_module_exception_handlers")(module) == []


def test_handler_enumeration_stops_at_the_per_module_cap(attached_bridge: ProcessBridge) -> None:
    """A module whose table holds 2049 handler-carrying functions reports only the first 2048.

    Mutation: changing ``>=`` at process.py:6627 to ``>`` returns 2049 handlers and fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    count = 2049
    size = 0x10000
    table = _runtime_functions((0x2000 + index * 0x10, 0x2008 + index * 0x10, 0x8000) for index in range(count))
    image = _module_image(size, directory=(0x1000, len(table)))
    image[0x1000 : 0x1000 + len(table)] = table
    unwind = _unwind_info(1, 0, 0x5000)
    image[0x8000 : 0x8000 + len(unwind)] = unwind
    base = _plant(attached_bridge, bytes(image), size)
    module = _module_info("capped.dll", base, size)
    handlers = cast("list[dict[str, object]]", sync_method(attached_bridge, "_enumerate_module_exception_handlers")(module))
    assert len(handlers) == 2048
    assert handlers[0] == {
        "module": "capped.dll",
        "address": base + 0x2000,
        "end_address": base + 0x2008,
        "handler_address": base + 0x5000,
        "flags": "EHANDLER",
    }
    assert handlers[-1]["address"] == base + 0x2000 + 2047 * 0x10


def test_handler_enumeration_skips_unusable_unwind_records(attached_bridge: ProcessBridge) -> None:
    """Unwind records that cannot be read, or carry a zero handler RVA, are skipped; the good one is reported.

    Four functions are planted: one whose UNWIND_INFO starts just past the committed page, one whose
    header is readable but whose handler RVA lies past the page, one whose handler RVA is zero, and a
    good one.

    Mutation: deleting the ``if handler_rva == 0: return None`` at process.py:6751-6752 adds the
    zero-handler function to the result and fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    table = _runtime_functions([(0x10, 0x20, 0x1000), (0x30, 0x40, 0xFFC), (0x50, 0x60, 0x800), (0x70, 0x80, 0x900)])
    image = _module_image(_PAGE, directory=(0x200, len(table)))
    image[0x200 : 0x200 + len(table)] = table
    zero_handler = _unwind_info(1, 0, 0)
    image[0x800 : 0x800 + len(zero_handler)] = zero_handler
    good = _unwind_info(1, 0, 0x700)
    image[0x900 : 0x900 + len(good)] = good
    image[0xFFC:_PAGE] = bytes([0x09, 0x00, 0x00, 0x00])
    base = _plant(attached_bridge, bytes(image), _PAGE)
    module = _module_info("unwind.dll", base, _PAGE)
    assert sync_method(attached_bridge, "_enumerate_module_exception_handlers")(module) == [
        {
            "module": "unwind.dll",
            "address": base + 0x70,
            "end_address": base + 0x80,
            "handler_address": base + 0x700,
            "flags": "EHANDLER",
        },
    ]


def test_handler_enumeration_aligns_the_handler_after_the_unwind_codes(attached_bridge: ProcessBridge) -> None:
    """With an odd unwind-code count the handler RVA follows the padded code array, and both flags are named.

    A function without UNWIND_INFO is skipped. The second has one unwind code (padded to two), both
    handler flags and a handler RVA of 0x7F0 stored eight bytes after the header.

    Mutation: changing ``((count_of_codes + 1) & ~1)`` at process.py:6743 to ``count_of_codes`` reads
    the handler two bytes early and fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    table = _runtime_functions([(0x10, 0x20, 0), (0x30, 0x40, 0x600)])
    image = _module_image(_PAGE, directory=(0x400, len(table)))
    image[0x400 : 0x400 + len(table)] = table
    unwind = _unwind_info(3, 1, 0x7F0)
    image[0x600 : 0x600 + len(unwind)] = unwind
    base = _plant(attached_bridge, bytes(image), _PAGE)
    module = _module_info("aligned.dll", base, _PAGE)
    assert sync_method(attached_bridge, "_enumerate_module_exception_handlers")(module) == [
        {
            "module": "aligned.dll",
            "address": base + 0x30,
            "end_address": base + 0x40,
            "handler_address": base + 0x7F0,
            "flags": "EHANDLER|UHANDLER",
        },
    ]


def test_x64_handler_enumeration_survives_a_failing_module_listing(bare_bridge: ProcessBridge) -> None:
    """When the module listing raises, the x64 handler enumeration returns an empty list.

    Mutation: changing ``return handlers`` at process.py:6564 to ``raise`` fails this test.

    Args:
        bare_bridge: Bridge that was never initialized, so the module listing raises.
    """
    assert _run(async_method(bare_bridge, "_enumerate_x64_exception_handlers")()) == []


def test_x64_handler_enumeration_of_an_exited_process_is_empty(attached_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """An attached child that has exited has no modules to inspect, so the result is empty and not truncated.

    Mutation: changing ``for module in modules`` at process.py:6567 to iterate a placeholder module
    list makes the call report handlers or raise, and fails this test.

    Args:
        attached_bridge: Bridge attached to the child.
        target_process: The running child process.
    """
    target_process.kill()
    target_process.wait(timeout=_WAIT_S)
    assert _run(async_method(attached_bridge, "_enumerate_x64_exception_handlers")()) == []
