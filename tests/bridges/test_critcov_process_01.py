# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the process bridge's guards, failure paths and thread probes.

Every test that touches a live process drives the real Win32 APIs against a child
process that the test itself starts (a Python interpreter blocked on stdin), never
against the pytest process. The tests cover the "dependency not loaded" guards, the
failure branches of memory, token and snapshot operations, the PE-header architecture
fallback, the suspend/resume and thread-probe paths, and the remote-thread wait logic.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import functools
import inspect
import struct
import sys
import threading
import winreg
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import psutil
import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    LUID,
    LUID_AND_ATTRIBUTES,
    MODULEENTRY32,
    PROCESSENTRY32,
    THREADENTRY32,
    TOKEN_PRIVILEGES,
)
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 20.0
_WAIT_MS: Final[int] = 20000
_ABSENT_PID: Final[int] = 0x7FFFFFFE
_TARGET_READY: Final[bytes] = b"critcov-ready"
_TARGET_SOURCE: Final[str] = "import sys\nsys.stdout.write('critcov-ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_WORKER_READY: Final[bytes] = b"critcov-worker"
_WORKER_GONE: Final[bytes] = b"critcov-worker-gone"
_WORKER_SOURCE: Final[str] = (
    "import ctypes\n"
    "import sys\n"
    "import threading\n"
    "started = threading.Event()\n"
    "release = threading.Event()\n"
    "tids = []\n"
    "def worker():\n"
    "    tids.append(ctypes.windll.kernel32.GetCurrentThreadId())\n"
    "    started.set()\n"
    "    release.wait()\n"
    "thread = threading.Thread(target=worker)\n"
    "thread.start()\n"
    "started.wait()\n"
    "sys.stdout.write('critcov-worker %d\\n' % tids[0])\n"
    "sys.stdout.flush()\n"
    "sys.stdin.readline()\n"
    "release.set()\n"
    "thread.join()\n"
    "sys.stdout.write('critcov-worker-gone\\n')\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)

_PROCESS_TERMINATE: Final[int] = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION: Final[int] = 0x1000
_SYNCHRONIZE: Final[int] = 0x00100000
_THREAD_SUSPEND_RESUME: Final[int] = 0x0002
_THREAD_GET_CONTEXT: Final[int] = 0x0008
_THREAD_QUERY_INFORMATION: Final[int] = 0x0040
_TOKEN_DUPLICATE: Final[int] = 0x0002
_TOKEN_QUERY: Final[int] = 0x0008
_TOKEN_ALL_ACCESS: Final[int] = 0xF01FF
_SE_PRIVILEGE_REMOVED: Final[int] = 0x00000004
_SECURITY_IMPERSONATION: Final[int] = 2
_TOKEN_PRIMARY: Final[int] = 1
_PAGE_READWRITE: Final[int] = 0x04
_FILE_MAP_WRITE: Final[int] = 0x0002
_INVALID_HANDLE_VALUE: Final[int] = 0xFFFFFFFFFFFFFFFF
_WAIT_OBJECT_0: Final[int] = 0
_MAX_SUSPEND_COUNT: Final[int] = 127
_SUSPEND_FAILED: Final[int] = 0xFFFFFFFF
_NATIVE_MACHINES: Final[frozenset[int]] = frozenset({0x8664, 0xAA64})
_PE_ARCH_BY_MACHINE: Final[dict[int, str]] = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}
_UNMAPPED_BASE: Final[int] = 0x10
_FAKE_SECTION_HANDLE: Final[int] = 0x77
_FAKE_PROCESS_HANDLE: Final[int] = 1
_UNKNOWN_PRIVILEGE_LOW_PART: Final[int] = 0x7FFFFFF0
_UNKNOWN_PRIVILEGE_HIGH_PART: Final[int] = 0x1234
_PATTERN_BYTE: Final[int] = 0x41
_ONE_CHUNK: Final[int] = 0x100000

_NEUTRAL_WITHOUT_KERNEL32: Final[tuple[tuple[str, tuple[object, ...], object], ...]] = (
    ("_elevate_debug_privilege", (), None),
    ("_elevate_debug_privilege_impl", (), None),
    ("_configure_current_process_token_prototypes", (), None),
    ("_call_iswow64process2", (0,), None),
    ("_pid_is_wow64", (1,), False),
    ("_detect_arch_via_pe_header", (1,), None),
    ("_read_pe_arch_from_handle", (0,), None),
    ("_detect_arch_via_iswow64process", (0,), "Unknown"),
    ("_region_still_committed", (0x1000,), False),
    ("_query_thread_start_address", (1,), 0),
    ("_query_thread_state", (1,), "unknown"),
    ("_probe_thread_state", (0, 1), "unknown"),
    ("_probe_thread_state_inner", (0,), "unknown"),
    ("_query_thread_pc_and_state", (1,), (0, "unknown")),
    ("_probe_thread_pc_and_state", (0, 1), (0, "unknown")),
    ("_probe_thread_pc_and_state_inner", (0,), (0, "unknown")),
    ("_read_thread_pc", (0,), 0),
    ("_query_thread_current_pc", (1,), 0),
    ("_read_thread_current_pc", (0, None, 1), 0),
    ("_suspend_and_read_pc", (0, None), 0),
    ("_read_pc_via_context", (0, None), 0),
    ("_query_module_entry_point", (0, 0), 0),
    ("get_process_memory_mb", (1,), 0.0),
)

_RAISES_WITHOUT_KERNEL32: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("list_processes", ()),
    ("list_processes_detailed", ()),
    ("open_process", (1,)),
    ("terminate", ()),
    ("get_token_privileges", ()),
    ("unmap_section", (0x1000,)),
    ("_inject_dll_with_remote_mem", (0x1000, b"")),
    ("_await_remote_loadlibrary", (0,)),
)

_RAISES_WITH_HANDLE_WITHOUT_KERNEL32: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("read_memory", (0x1000, 4)),
    ("write_memory", (0x1000, b"a")),
    ("allocate", (16,)),
    ("free", (0x1000,)),
    ("protect", (0x1000, 16, "rw")),
    ("get_memory_map", ()),
    ("inject_dll", ("x.dll",)),
    ("_sync_read_memory", (0x1000, 4)),
)

_RAISES_WITHOUT_PROCESS: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("allocate", (16,)),
    ("free", (0x1000,)),
    ("protect", (0x1000, 16, "rw")),
    ("get_memory_map", ()),
    ("_sync_read_memory", (0x1000, 4)),
)

_RAISES_WITHOUT_ADVAPI32: Final[tuple[tuple[str, tuple[object, ...]], ...]] = (
    ("_reg_query_value_grow", (0, "value")),
    ("_read_token_privileges", (wintypes.HANDLE(0),)),
    ("_privilege_entry_to_dict", (LUID_AND_ATTRIBUTES(),)),
)

_REMOTE_MEMORY_FAILURES: Final[tuple[tuple[str, tuple[object, ...], str], ...]] = (
    ("write_memory", (0x10, b"x"), "memory write failed"),
    ("allocate", (1 << 46, "rw"), "memory allocation failed"),
    ("free", (0x10,), "memory free failed"),
    ("protect", (0x10, 0x1000, "rw"), "memory protection change failed"),
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


def set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a real object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        value: New value for the attribute.
    """
    setattr(obj, name, value)


def sync_method(obj: object, name: str) -> Callable[..., object]:
    """Look up a (possibly private) synchronous method by name.

    Args:
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method or plain function.
    """
    return cast("Callable[..., object]", getattr(obj, name))


async def _await_value(awaitable: Awaitable[object]) -> object:
    """Await ``awaitable`` and return its result.

    Args:
        awaitable: Awaitable to resolve.

    Returns:
        object: The awaited result.
    """
    return await awaitable


def _invoke(obj: object, name: str, args: tuple[object, ...]) -> object:
    """Call a (possibly private, possibly coroutine) method and return its result.

    Args:
        obj: Object that owns the method.
        name: Method name.
        args: Positional arguments for the call.

    Returns:
        object: The method's return value, with coroutines awaited to completion.
    """
    result: object = getattr(obj, name)(*args)
    if inspect.isawaitable(result):
        return _run(_await_value(result))
    return result


@functools.cache
def _k32() -> ctypes.WinDLL:
    """Load a private ``kernel32`` handle with explicit prototypes and last-error capture.

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
    dll.SuspendThread.argtypes = [wintypes.HANDLE]
    dll.SuspendThread.restype = wintypes.DWORD
    dll.ResumeThread.argtypes = [wintypes.HANDLE]
    dll.ResumeThread.restype = wintypes.DWORD
    dll.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    dll.WaitForSingleObject.restype = wintypes.DWORD
    dll.GetProcessId.argtypes = [wintypes.HANDLE]
    dll.GetProcessId.restype = wintypes.DWORD
    dll.Process32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    dll.Process32First.restype = wintypes.BOOL
    dll.CreateFileMappingW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    dll.CreateFileMappingW.restype = wintypes.HANDLE
    dll.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    dll.MapViewOfFile.restype = ctypes.c_void_p
    dll.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    dll.UnmapViewOfFile.restype = wintypes.BOOL
    return dll


@functools.cache
def _advapi32() -> ctypes.WinDLL:
    """Load a private ``advapi32`` handle with explicit prototypes.

    Returns:
        ctypes.WinDLL: An ``advapi32`` handle whose function pointers are independent of the bridge's own.
    """
    dll = ctypes.WinDLL("advapi32", use_last_error=True)
    dll.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    dll.OpenProcessToken.restype = wintypes.BOOL
    dll.DuplicateTokenEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    dll.DuplicateTokenEx.restype = wintypes.BOOL
    dll.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
    dll.LookupPrivilegeValueW.restype = wintypes.BOOL
    dll.AdjustTokenPrivileges.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    dll.AdjustTokenPrivileges.restype = wintypes.BOOL
    return dll


def _close(handle: int) -> bool:
    """Close a kernel handle through the test's own ``kernel32``.

    Args:
        handle: Handle value to close.

    Returns:
        bool: ``True`` when the handle was open and is now closed.
    """
    closed: int = _k32().CloseHandle(handle)
    return bool(closed)


def _suspend(handle: int) -> int:
    """Suspend a thread and return its previous suspend count.

    Args:
        handle: Thread handle with ``THREAD_SUSPEND_RESUME`` access.

    Returns:
        int: Previous suspend count, or ``0xFFFFFFFF`` when the call failed.
    """
    previous: int = _k32().SuspendThread(handle)
    return previous


def _resume(handle: int) -> int:
    """Resume a thread and return its previous suspend count.

    Args:
        handle: Thread handle with ``THREAD_SUSPEND_RESUME`` access.

    Returns:
        int: Previous suspend count, or ``0xFFFFFFFF`` when the call failed.
    """
    previous: int = _k32().ResumeThread(handle)
    return previous


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
        _close(handle)


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
        _close(handle)


@contextlib.contextmanager
def _without_dll(bridge: ProcessBridge, attribute: str) -> Generator[None]:
    """Temporarily clear one loaded-DLL attribute of a real bridge.

    Args:
        bridge: Bridge whose attribute is cleared.
        attribute: Private attribute name such as ``_psapi``.

    Yields:
        None: Control while the attribute is ``None``.
    """
    original = priv(bridge, attribute, object)
    set_priv(bridge, attribute, None)
    try:
        yield
    finally:
        set_priv(bridge, attribute, original)


@contextlib.contextmanager
def _debug_privilege_stripped_token(pid: int) -> Generator[int]:
    """Duplicate a process token and remove ``SeDebugPrivilege`` from the duplicate.

    Args:
        pid: Identifier of the process whose token is duplicated.

    Yields:
        int: Handle to the duplicated primary token that no longer holds ``SeDebugPrivilege``.
    """
    advapi32 = _advapi32()
    source = wintypes.HANDLE()
    duplicate = wintypes.HANDLE()
    with _process_handle(pid, _PROCESS_QUERY_LIMITED_INFORMATION) as process:
        opened: int = advapi32.OpenProcessToken(process, _TOKEN_DUPLICATE | _TOKEN_QUERY, ctypes.byref(source))
        assert opened
        duplicated: int = advapi32.DuplicateTokenEx(
            source,
            _TOKEN_ALL_ACCESS,
            None,
            _SECURITY_IMPERSONATION,
            _TOKEN_PRIMARY,
            ctypes.byref(duplicate),
        )
        assert _close(source.value or 0)
        assert duplicated
    luid = LUID()
    found: int = advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
    assert found
    request = TOKEN_PRIVILEGES()
    request.PrivilegeCount = 1
    request.Privileges[0].Luid = luid
    request.Privileges[0].Attributes = _SE_PRIVILEGE_REMOVED
    disable_all = wintypes.BOOL(0)
    advapi32.AdjustTokenPrivileges(
        duplicate,
        disable_all,
        ctypes.byref(request),
        ctypes.sizeof(request),
        None,
        None,
    )
    try:
        yield duplicate.value or 0
    finally:
        _close(duplicate.value or 0)


def _create_section(size: int) -> int:
    """Create an anonymous page-file-backed section.

    Args:
        size: Section size in bytes.

    Returns:
        int: Handle to the new section.
    """
    handle: int | None = _k32().CreateFileMappingW(_INVALID_HANDLE_VALUE, None, _PAGE_READWRITE, 0, size, None)
    assert handle
    return handle


def _map_view(section: int) -> int:
    """Map a writable view of a section into the calling process.

    Args:
        section: Section handle.

    Returns:
        int: Base address of the mapped view.
    """
    base: int | None = _k32().MapViewOfFile(section, _FILE_MAP_WRITE, 0, 0, 0)
    assert base
    return base


def _thread_ids(pid: int) -> list[int]:
    """List the native thread identifiers of a process.

    Args:
        pid: Identifier of the process.

    Returns:
        list[int]: Thread identifiers reported by the operating system.
    """
    return [thread.id for thread in psutil.Process(pid).threads()]


def _suspend_count(tid: int) -> int:
    """Read a thread's suspend count by suspending and immediately resuming it.

    Args:
        tid: Identifier of the thread.

    Returns:
        int: The suspend count the thread had before the probe.
    """
    with _thread_handle(tid, _THREAD_SUSPEND_RESUME) as handle:
        previous = _suspend(handle)
        _resume(handle)
    return previous


def _image_arch(pid: int) -> str:
    """Derive a process's architecture from the COFF machine field of its image file.

    Args:
        pid: Identifier of the process.

    Returns:
        str: ``'x86'``, ``'x86_64'`` or ``'arm64'`` according to the image's ``IMAGE_FILE_HEADER.Machine``.
    """
    data = Path(psutil.Process(pid).exe()).read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    return _PE_ARCH_BY_MACHINE[machine]


def _stop_child(proc: Popen[bytes]) -> None:
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


def _start_child(source: str, ready_prefix: bytes) -> tuple[Popen[bytes], bytes]:
    """Start a Python child that reports readiness on stdout and then blocks on stdin.

    Args:
        source: Program text the child runs.
        ready_prefix: Prefix of the readiness line the child prints.

    Returns:
        tuple[Popen[bytes], bytes]: The ready child process and its readiness line.
    """
    proc = Popen([sys.executable, "-c", source], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    ready = b""
    try:
        stdout = proc.stdout
        assert stdout is not None
        ready = stdout.readline().strip()
    finally:
        if not ready.startswith(ready_prefix):
            _stop_child(proc)
    assert ready.startswith(ready_prefix)
    return proc, ready


def _release_worker(proc: Popen[bytes]) -> None:
    """Tell the worker child to let its extra thread exit and wait for the confirmation line.

    Args:
        proc: Child started from the worker program.
    """
    stdin = proc.stdin
    stdout = proc.stdout
    assert stdin is not None
    assert stdout is not None
    stdin.write(b"go\n")
    stdin.flush()
    assert stdout.readline().strip() == _WORKER_GONE


def _wait_signaled(handle: int) -> None:
    """Block until a kernel object becomes signaled.

    Args:
        handle: Handle with ``SYNCHRONIZE`` access.
    """
    waited: int = _k32().WaitForSingleObject(handle, _WAIT_MS)
    assert waited == _WAIT_OBJECT_0


def _wait_exit(proc: Popen[bytes]) -> int:
    """Wait for a child process to exit.

    Args:
        proc: The child process.

    Returns:
        int: The child's exit code.
    """
    return proc.wait(timeout=_WAIT_S)


@contextlib.contextmanager
def _child_allocation(bridge: ProcessBridge, size: int) -> Generator[int]:
    """Allocate read/write memory in the attached child and free it afterwards.

    Args:
        bridge: Bridge attached to the child.
        size: Allocation size in bytes.

    Yields:
        int: Address of the allocation inside the child.
    """
    address = _run(bridge.allocate(size, "rw"))
    try:
        yield address
    finally:
        with contextlib.suppress(ToolError):
            _run(bridge.free(address))


@pytest.fixture
def idle_bridge() -> ProcessBridge:
    """Create a bridge that was never initialized, so no DLL is loaded and nothing is attached.

    Returns:
        ProcessBridge: A fresh bridge.
    """
    return ProcessBridge()


@pytest.fixture
def bridge_with_handle() -> Generator[ProcessBridge]:
    """Create an uninitialized bridge whose attached-process slot is occupied by a placeholder value.

    The placeholder is never passed to Win32 because every call under test stops at the missing ``kernel32`` first.

    Yields:
        ProcessBridge: A bridge with a process handle but no ``kernel32``.
    """
    instance = ProcessBridge()
    set_priv(instance, "_process_handle", _FAKE_PROCESS_HANDLE)
    try:
        yield instance
    finally:
        set_priv(instance, "_process_handle", None)


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
def target_process() -> Generator[Popen[bytes]]:
    """Start a child process for the bridge to operate on and stop it afterwards.

    Yields:
        Popen[bytes]: The running child process.
    """
    proc, _ready = _start_child(_TARGET_SOURCE, _TARGET_READY)
    try:
        yield proc
    finally:
        _stop_child(proc)


@pytest.fixture
def worker_process() -> Generator[tuple[Popen[bytes], int]]:
    """Start a child that owns an extra thread it can be told to end, and stop it afterwards.

    Yields:
        tuple[Popen[bytes], int]: The running child and the native identifier of its extra thread.
    """
    proc, ready = _start_child(_WORKER_SOURCE, _WORKER_READY)
    try:
        yield proc, int(ready.split()[1])
    finally:
        _stop_child(proc)


@pytest.fixture
def attached_bridge(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> ProcessBridge:
    """Attach the initialized bridge to the child with full access.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.

    Returns:
        ProcessBridge: The bridge, attached to the child.
    """
    assert _run(process_bridge.open_process(target_process.pid, "all"))
    return process_bridge


@pytest.fixture
def max_suspended_thread(target_process: Popen[bytes]) -> Generator[int]:
    """Push one thread of the child to the maximum suspend count and release it afterwards.

    Args:
        target_process: The running child process.

    Yields:
        int: Identifier of the thread whose suspend count is at the documented maximum.
    """
    victim = _thread_ids(target_process.pid)[0]
    with _thread_handle(victim, _THREAD_SUSPEND_RESUME) as handle:
        for expected in range(_MAX_SUSPEND_COUNT):
            assert _suspend(handle) == expected
        assert _suspend(handle) == _SUSPEND_FAILED
        try:
            yield victim
        finally:
            for _ in range(_MAX_SUSPEND_COUNT):
                _resume(handle)


def test_dll_properties_return_the_dll_loaded_under_their_own_name(process_bridge: ProcessBridge) -> None:
    """Each DLL property exposes the library that carries its own name.

    Args:
        process_bridge: Initialized bridge.
    """
    loaded = {
        "kernel32": process_bridge.kernel32,
        "psapi": process_bridge.psapi,
        "ntdll": process_bridge.ntdll,
        "advapi32": process_bridge.advapi32,
        "user32": process_bridge.user32,
        "dbghelp": process_bridge.dbghelp,
    }
    names = {key: priv(dll, "_name", str) for key, dll in loaded.items()}
    assert names == {key: key for key in loaded}


def test_state_properties_report_defaults_on_a_new_bridge(idle_bridge: ProcessBridge) -> None:
    """A bridge that has attached to nothing reports empty state through its properties.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    assert idle_bridge.debug_privilege_enabled is False
    assert idle_bridge.attached_pid is None
    assert idle_bridge.process_handle is None
    assert idle_bridge.pipe_handles == {}
    assert idle_bridge.device_handles == {}


def test_state_properties_reflect_only_their_own_field(idle_bridge: ProcessBridge) -> None:
    """Each state property returns the value of its own field and no other.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    privilege_flag = True
    set_priv(idle_bridge, "_debug_privilege_enabled", privilege_flag)
    set_priv(idle_bridge, "_attached_pid", 1234)
    set_priv(idle_bridge, "_process_handle", 99)
    set_priv(idle_bridge, "_pipe_handles", {5: "pipe"})
    set_priv(idle_bridge, "_device_handles", {6: "device"})
    assert idle_bridge.debug_privilege_enabled is True
    assert idle_bridge.attached_pid == 1234
    assert idle_bridge.process_handle == 99
    assert idle_bridge.pipe_handles == {5: "pipe"}
    assert idle_bridge.device_handles == {6: "device"}


@pytest.mark.parametrize(("name", "args", "expected"), _NEUTRAL_WITHOUT_KERNEL32, ids=[row[0] for row in _NEUTRAL_WITHOUT_KERNEL32])
def test_helper_without_kernel32_returns_its_neutral_value(
    idle_bridge: ProcessBridge,
    name: str,
    args: tuple[object, ...],
    expected: object,
) -> None:
    """Without a loaded ``kernel32`` every helper answers with its documented neutral value.

    Args:
        idle_bridge: Bridge that was never initialized.
        name: Helper under test.
        args: Positional arguments for the call.
        expected: Neutral value the helper must report.
    """
    assert _invoke(idle_bridge, name, args) == expected


@pytest.mark.parametrize(("name", "args"), _RAISES_WITHOUT_KERNEL32, ids=[row[0] for row in _RAISES_WITHOUT_KERNEL32])
def test_call_without_kernel32_raises(idle_bridge: ProcessBridge, name: str, args: tuple[object, ...]) -> None:
    """Without a loaded ``kernel32`` the operation refuses with a ToolError.

    Args:
        idle_bridge: Bridge that was never initialized.
        name: Operation under test.
        args: Positional arguments for the call.
    """
    with pytest.raises(ToolError, match="kernel32 not available"):
        _invoke(idle_bridge, name, args)


@pytest.mark.parametrize(
    ("name", "args"),
    _RAISES_WITH_HANDLE_WITHOUT_KERNEL32,
    ids=[row[0] for row in _RAISES_WITH_HANDLE_WITHOUT_KERNEL32],
)
def test_call_with_an_attached_handle_but_without_kernel32_raises(
    bridge_with_handle: ProcessBridge,
    name: str,
    args: tuple[object, ...],
) -> None:
    """A recorded process handle does not help when ``kernel32`` is missing.

    Args:
        bridge_with_handle: Bridge with a process handle and no ``kernel32``.
        name: Operation under test.
        args: Positional arguments for the call.
    """
    with pytest.raises(ToolError, match="kernel32 not available"):
        _invoke(bridge_with_handle, name, args)


@pytest.mark.parametrize(("name", "args"), _RAISES_WITHOUT_PROCESS, ids=[row[0] for row in _RAISES_WITHOUT_PROCESS])
def test_call_without_an_attached_process_raises(idle_bridge: ProcessBridge, name: str, args: tuple[object, ...]) -> None:
    """Memory operations refuse to run when no process is attached.

    Args:
        idle_bridge: Bridge that was never initialized.
        name: Operation under test.
        args: Positional arguments for the call.
    """
    with pytest.raises(ToolError, match="no process attached"):
        _invoke(idle_bridge, name, args)


@pytest.mark.parametrize(("name", "args"), _RAISES_WITHOUT_ADVAPI32, ids=[row[0] for row in _RAISES_WITHOUT_ADVAPI32])
def test_call_without_advapi32_raises(idle_bridge: ProcessBridge, name: str, args: tuple[object, ...]) -> None:
    """Without a loaded ``advapi32`` the token and registry helpers refuse with a ToolError.

    Args:
        idle_bridge: Bridge that was never initialized.
        name: Helper under test.
        args: Positional arguments for the call.
    """
    with pytest.raises(ToolError, match="advapi32 not available"):
        _invoke(idle_bridge, name, args)


def test_token_handle_helpers_without_dlls_report_a_token_open_failure(idle_bridge: ProcessBridge) -> None:
    """Both token-handle helpers refuse with the token-open error when the DLLs are missing.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    with pytest.raises(ToolError, match="token open failed"):
        sync_method(idle_bridge, "_get_token_privileges_for_handle")(0, None)
    with pytest.raises(ToolError, match="token open failed"):
        sync_method(idle_bridge, "_adjust_token_privilege_with_handle")(0, "SeDebugPrivilege", enable=True)


def test_adjust_token_privilege_without_kernel32_raises(idle_bridge: ProcessBridge) -> None:
    """Adjusting a privilege needs ``kernel32`` before anything else.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    with pytest.raises(ToolError, match="kernel32 not available"):
        _run(idle_bridge.adjust_token_privilege("SeDebugPrivilege", enable=True))


def test_token_operations_without_advapi32_raise(process_bridge: ProcessBridge) -> None:
    """Reading or adjusting token privileges refuses once ``advapi32`` is missing.

    Args:
        process_bridge: Initialized bridge.
    """
    with _without_dll(process_bridge, "_advapi32"):
        with pytest.raises(ToolError, match="advapi32 not available"):
            _run(process_bridge.get_token_privileges())
        with pytest.raises(ToolError, match="advapi32 not available"):
            _run(process_bridge.adjust_token_privilege("SeDebugPrivilege", enable=True))


def test_read_token_privileges_without_kernel32_raises(process_bridge: ProcessBridge) -> None:
    """The token reader needs ``kernel32`` even when ``advapi32`` is present.

    Args:
        process_bridge: Initialized bridge.
    """
    with _without_dll(process_bridge, "_kernel32"), pytest.raises(ToolError, match="kernel32 not available"):
        sync_method(process_bridge, "_read_token_privileges")(wintypes.HANDLE(0))


def test_snapshot_collectors_without_kernel32_leave_their_output_empty(idle_bridge: ProcessBridge) -> None:
    """The snapshot walkers return quietly and add nothing when ``kernel32`` is missing.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    processes: list[object] = []
    modules: list[object] = []
    threads: list[object] = []
    results: list[object] = []
    assert sync_method(idle_bridge, "_iterate_process_snapshot")(0, PROCESSENTRY32(), processes, None) is None
    assert sync_method(idle_bridge, "_collect_module_entries")(0, MODULEENTRY32(), modules, None) is None
    assert sync_method(idle_bridge, "_collect_thread_entries")(0, THREADENTRY32(), threads, 1) is None
    assert _invoke(idle_bridge, "_iterate_process_snapshot_detailed", (0, PROCESSENTRY32(), results, None)) is None
    assert processes == []
    assert modules == []
    assert threads == []
    assert results == []


def test_get_process_memory_mb_reports_zero_without_psapi(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """Without ``psapi`` the memory probe reports 0.0 even for a live process.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    assert _run(process_bridge.get_process_memory_mb(target_process.pid)) > 0.0
    with _without_dll(process_bridge, "_psapi"):
        assert _run(process_bridge.get_process_memory_mb(target_process.pid)) == pytest.approx(0.0)


def test_adjust_se_debug_privilege_raises_when_the_token_does_not_hold_it(
    idle_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """Enabling ``SeDebugPrivilege`` on a token that lacks it raises and leaves the flag clear.

    Args:
        idle_bridge: Bridge that was never initialized.
        target_process: The running child process whose token is duplicated and stripped.
    """
    advapi32_le = cast("ctypes.WinDLL", sync_method(ProcessBridge, "_prepare_privilege_advapi32")())
    with (
        _debug_privilege_stripped_token(target_process.pid) as token,
        pytest.raises(ToolError, match="SeDebugPrivilege not granted"),
    ):
        sync_method(idle_bridge, "_adjust_se_debug_privilege")(advapi32_le, wintypes.HANDLE(token))
    assert idle_bridge.debug_privilege_enabled is False


def test_adding_the_same_privilege_callback_twice_registers_it_once(idle_bridge: ProcessBridge) -> None:
    """A callback added twice is invoked once per notification.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    calls: list[str] = []

    def callback() -> None:
        """Record that the registry invoked this callback."""
        calls.append("called")

    idle_bridge.add_privileges_changed_callback(callback)
    idle_bridge.add_privileges_changed_callback(callback)
    sync_method(idle_bridge, "_notify_privileges_changed")()
    assert calls == ["called"]


def test_removing_an_unregistered_privilege_callback_is_ignored(idle_bridge: ProcessBridge) -> None:
    """Removing a callback that was never added neither raises nor disturbs the registered ones.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    calls: list[str] = []

    def registered() -> None:
        """Record that the registered callback ran."""
        calls.append("registered")

    def stranger() -> None:
        """Do nothing; this callback is never registered."""

    idle_bridge.add_privileges_changed_callback(registered)
    idle_bridge.remove_privileges_changed_callback(stranger)
    sync_method(idle_bridge, "_notify_privileges_changed")()
    assert calls == ["registered"]


def test_a_failing_privilege_callback_does_not_stop_the_others(idle_bridge: ProcessBridge) -> None:
    """An exception from one observer is contained and later observers still run.

    Args:
        idle_bridge: Bridge that was never initialized.
    """
    calls: list[str] = []

    def failing() -> None:
        """Fail the way a misbehaving observer would.

        Raises:
            RuntimeError: Always.
        """
        msg = "observer failed"
        raise RuntimeError(msg)

    def following() -> None:
        """Record that the observer after the failing one ran."""
        calls.append("following")

    idle_bridge.add_privileges_changed_callback(failing)
    idle_bridge.add_privileges_changed_callback(following)
    sync_method(idle_bridge, "_notify_privileges_changed")()
    assert calls == ["following"]


def test_get_token_privileges_without_a_pid_reads_the_calling_process_token(process_bridge: ProcessBridge) -> None:
    """With no pid and nothing attached the bridge reads its own process token.

    Args:
        process_bridge: Initialized bridge with nothing attached.
    """
    privileges = _run(process_bridge.get_token_privileges())
    names = {str(entry["name"]) for entry in privileges}
    assert "SeChangeNotifyPrivilege" in names
    assert all(isinstance(entry["enabled"], bool) for entry in privileges)


def test_token_operations_for_an_absent_pid_report_an_open_failure(process_bridge: ProcessBridge) -> None:
    """Reading or adjusting the token of a process that does not exist fails at the process open.

    Args:
        process_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="process open failed"):
        _run(process_bridge.get_token_privileges(_ABSENT_PID))
    with pytest.raises(ToolError, match="process open failed"):
        _run(process_bridge.adjust_token_privilege("SeDebugPrivilege", enable=True, pid=_ABSENT_PID))


def test_get_token_privileges_for_handle_reports_a_token_open_failure(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """A process handle without query rights cannot yield a token.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    with _process_handle(target_process.pid, _PROCESS_TERMINATE) as handle, pytest.raises(ToolError, match="token open failed"):
        sync_method(process_bridge, "_get_token_privileges_for_handle")(handle, target_process.pid)


def test_adjust_token_privilege_with_handle_reports_a_token_open_failure(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """A process handle without query rights cannot yield an adjustable token.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    with _process_handle(target_process.pid, _PROCESS_TERMINATE) as handle, pytest.raises(ToolError, match="token open failed"):
        sync_method(process_bridge, "_adjust_token_privilege_with_handle")(handle, "SeDebugPrivilege", enable=True)


def test_read_token_privileges_rejects_an_invalid_token_handle(process_bridge: ProcessBridge) -> None:
    """A null token handle makes the size query and the data query fail with a ToolError.

    Args:
        process_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="GetTokenInformation failed"):
        sync_method(process_bridge, "_read_token_privileges")(wintypes.HANDLE(0))


def test_privilege_entry_with_an_unresolvable_luid_is_named_unknown(process_bridge: ProcessBridge) -> None:
    """A LUID that no privilege owns is reported as ``Unknown`` with its raw fields intact.

    Args:
        process_bridge: Initialized bridge.
    """
    entry = LUID_AND_ATTRIBUTES()
    entry.Luid.LowPart = _UNKNOWN_PRIVILEGE_LOW_PART
    entry.Luid.HighPart = _UNKNOWN_PRIVILEGE_HIGH_PART
    entry.Attributes = 3
    assert sync_method(process_bridge, "_privilege_entry_to_dict")(entry) == {
        "name": "Unknown",
        "luid_low": _UNKNOWN_PRIVILEGE_LOW_PART,
        "luid_high": _UNKNOWN_PRIVILEGE_HIGH_PART,
        "enabled": True,
        "attributes": 3,
    }


def test_unmap_section_leaves_an_untracked_section_handle_open(process_bridge: ProcessBridge) -> None:
    """Unmapping a view whose section the bridge does not own drops the view but keeps the handle.

    Args:
        process_bridge: Initialized bridge.
    """
    views = cast("dict[int, int]", priv(process_bridge, "_section_views", object))
    owned = cast("dict[int, str]", priv(process_bridge, "_section_handles", object))
    section = _create_section(0x1000)
    base = _map_view(section)
    views[base] = section
    try:
        result = _run(process_bridge.unmap_section(base))
        tracked_after = base in views
        still_mapped = bool(_k32().UnmapViewOfFile(base))
    finally:
        views.pop(base, None)
        handle_was_open = _close(section)
    assert result is True
    assert not tracked_after
    assert not still_mapped
    assert section not in owned
    assert handle_was_open


def test_unmap_section_failure_keeps_the_view_tracked(process_bridge: ProcessBridge) -> None:
    """A failed unmap raises with the unmap-failed code and leaves the tracking entry in place.

    Args:
        process_bridge: Initialized bridge.
    """
    views = cast("dict[int, int]", priv(process_bridge, "_section_views", object))
    views[_UNMAPPED_BASE] = _FAKE_SECTION_HANDLE
    try:
        with pytest.raises(ToolError) as excinfo:
            _run(process_bridge.unmap_section(_UNMAPPED_BASE))
        tracked_after = _UNMAPPED_BASE in views
    finally:
        views.pop(_UNMAPPED_BASE, None)
    assert excinfo.value.details.get("code") == "SECTION_UNMAP_FAILED"
    assert tracked_after


def test_call_iswow64process2_reports_none_for_a_handle_that_cannot_be_queried(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """``IsWow64Process2`` answers with a machine pair for a queryable handle and ``None`` otherwise.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    with _process_handle(target_process.pid, _PROCESS_QUERY_LIMITED_INFORMATION) as queryable:
        pair = cast("tuple[int, int] | None", sync_method(process_bridge, "_call_iswow64process2")(queryable))
    with _process_handle(target_process.pid, _PROCESS_TERMINATE) as blind:
        blind_pair = sync_method(process_bridge, "_call_iswow64process2")(blind)
    with _process_handle(target_process.pid, _SYNCHRONIZE) as wait_only:
        wait_only_pair = sync_method(process_bridge, "_call_iswow64process2")(wait_only)
    assert pair is not None
    assert pair[1] in _NATIVE_MACHINES
    assert blind_pair is None
    assert wait_only_pair is None


def test_target_is_wow64_needs_kernel32_and_an_attached_process(idle_bridge: ProcessBridge, process_bridge: ProcessBridge) -> None:
    """WOW64 detection refuses without ``kernel32`` and without an attached process.

    Args:
        idle_bridge: Bridge that was never initialized.
        process_bridge: Initialized bridge with nothing attached.
    """
    for candidate in (idle_bridge, process_bridge):
        with pytest.raises(ToolError, match="WOW64 detection unavailable"):
            sync_method(candidate, "_target_is_wow64")()


def test_target_is_wow64_falls_back_when_the_handle_cannot_be_queried(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """A handle without query access makes the new API fail and the legacy API answer ``False``.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    assert _run(process_bridge.open_process(target_process.pid, "terminate"))
    assert sync_method(process_bridge, "_target_is_wow64")() is False


def test_pid_is_wow64_is_false_for_an_absent_pid(process_bridge: ProcessBridge) -> None:
    """A pid that cannot be opened is reported as not running under WOW64.

    Args:
        process_bridge: Initialized bridge.
    """
    assert sync_method(process_bridge, "_pid_is_wow64")(_ABSENT_PID) is False


def test_detect_arch_via_pe_header_matches_the_image_machine(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """The PE-header fallback reports the machine stored in the child's image file.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    assert sync_method(process_bridge, "_detect_arch_via_pe_header")(target_process.pid) == _image_arch(target_process.pid)


def test_detect_arch_via_pe_header_is_none_for_an_absent_pid(process_bridge: ProcessBridge) -> None:
    """A process that cannot be opened has no readable PE header.

    Args:
        process_bridge: Initialized bridge.
    """
    assert sync_method(process_bridge, "_detect_arch_via_pe_header")(_ABSENT_PID) is None


def test_read_pe_arch_from_handle_is_none_without_read_access(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """A handle that cannot enumerate modules yields no architecture.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    with _process_handle(target_process.pid, _PROCESS_TERMINATE) as handle:
        assert sync_method(process_bridge, "_read_pe_arch_from_handle")(handle) is None


def test_detect_arch_via_iswow64process2_is_none_for_an_unqueryable_handle(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """When ``IsWow64Process2`` fails the helper reports that no answer is available.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process, opened without query rights.
    """
    with _process_handle(target_process.pid, _SYNCHRONIZE) as blind:
        assert sync_method(process_bridge, "_detect_arch_via_iswow64process2")(blind) is None


def test_detect_architecture_with_handle_falls_back_to_the_pe_header(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """When ``IsWow64Process2`` cannot answer, the cascade reads the child's PE header.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    with _process_handle(target_process.pid, _PROCESS_TERMINATE) as handle:
        arch = sync_method(process_bridge, "_detect_architecture_with_handle")(target_process.pid, handle)
    assert arch == _image_arch(target_process.pid)


def test_detect_architecture_with_handle_falls_back_to_the_pointer_size(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """With neither new API nor PE header available, the host pointer size decides the answer.

    The handle grants only ``SYNCHRONIZE``, so both ``IsWow64`` queries fail, and the pid is absent, so the PE header cannot be read.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process, opened without query rights.
    """
    expected = "x86_64" if sys.maxsize > 2**32 else "x86"
    with _process_handle(target_process.pid, _SYNCHRONIZE) as blind:
        assert sync_method(process_bridge, "_detect_architecture_with_handle")(_ABSENT_PID, blind) == expected


def test_detect_arch_via_iswow64process_reports_a_native_child(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """The legacy detector reports a native 64-bit child as the host architecture.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    with _process_handle(target_process.pid, _PROCESS_QUERY_LIMITED_INFORMATION) as handle:
        assert sync_method(process_bridge, "_detect_arch_via_iswow64process")(handle) == _image_arch(target_process.pid)


def test_reg_query_value_grow_reports_a_missing_value(process_bridge: ProcessBridge) -> None:
    """Reading a registry value that does not exist raises with the Win32 return code.

    Args:
        process_bridge: Initialized bridge.
    """
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft") as key:
        hkey = wintypes.HKEY(int(key))
        with pytest.raises(ToolError, match=r"registry value read failed: CritcovNoSuchValue \(rc=2\)"):
            sync_method(process_bridge, "_reg_query_value_grow")(hkey, "CritcovNoSuchValue")


def test_open_dispatch_attaches_to_the_requested_process(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """``open`` opens a handle on the requested pid and records the attachment.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    assert _run(process_bridge.open(target_process.pid, "query")) is True
    handle = process_bridge.process_handle
    assert handle is not None
    owner: int = _k32().GetProcessId(handle)
    assert owner == target_process.pid
    assert process_bridge.attached_pid == target_process.pid


def test_iterate_process_snapshot_raises_for_an_unusable_snapshot(process_bridge: ProcessBridge) -> None:
    """A snapshot handle that cannot be walked makes the process walker raise.

    Args:
        process_bridge: Initialized bridge.
    """
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    with pytest.raises(ToolError, match=r"snapshot creation failed \(Process32First: \d+\)"):
        sync_method(process_bridge, "_iterate_process_snapshot")(0, entry, [], None)


def test_iterate_process_snapshot_reports_the_real_win32_error(process_bridge: ProcessBridge) -> None:
    """The process walker reports the error code that ``Process32First`` actually failed with.

    Args:
        process_bridge: Initialized bridge.
    """
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    ctypes.set_last_error(0)
    with pytest.raises(ToolError) as excinfo:
        sync_method(process_bridge, "_iterate_process_snapshot")(0, entry, [], None)
    oracle_entry = PROCESSENTRY32()
    oracle_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    failed: int = _k32().Process32First(0, ctypes.byref(oracle_entry))
    real_error = ctypes.get_last_error()
    assert not failed
    assert real_error != 0
    assert f"Process32First: {real_error}" in excinfo.value.message


def test_iterate_process_snapshot_detailed_ignores_an_unusable_snapshot(process_bridge: ProcessBridge) -> None:
    """The detailed walker returns quietly with no results when the snapshot cannot be walked.

    Args:
        process_bridge: Initialized bridge.
    """
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    results: list[object] = []
    assert _invoke(process_bridge, "_iterate_process_snapshot_detailed", (0, entry, results, None)) is None
    assert results == []


def test_collect_thread_entries_ignores_an_unusable_snapshot(process_bridge: ProcessBridge) -> None:
    """The thread walker returns quietly with no threads when the snapshot cannot be walked.

    Args:
        process_bridge: Initialized bridge.
    """
    entry = THREADENTRY32()
    entry.dwSize = ctypes.sizeof(THREADENTRY32)
    threads: list[object] = []
    assert sync_method(process_bridge, "_collect_thread_entries")(0, entry, threads, 1) is None
    assert threads == []


def test_get_process_info_is_none_for_an_absent_pid(process_bridge: ProcessBridge) -> None:
    """Asking for a process that does not exist yields ``None``.

    Args:
        process_bridge: Initialized bridge.
    """
    assert _run(process_bridge.get_process_info(_ABSENT_PID)) is None


def test_terminate_with_a_pid_ends_that_process(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """Terminating by pid ends the child with the bridge's exit code.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    assert _run(process_bridge.terminate(target_process.pid)) is True
    assert _wait_exit(target_process) == 1


def test_terminate_without_a_pid_ends_the_attached_process_and_detaches(
    attached_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """Terminating with no pid ends the attached child and releases the attachment.

    Args:
        attached_bridge: Bridge attached to the child.
        target_process: The running child process.
    """
    assert _run(attached_bridge.terminate()) is True
    assert _wait_exit(target_process) == 1
    assert attached_bridge.process_handle is None
    assert attached_bridge.attached_pid is None


def test_terminate_for_an_absent_pid_reports_an_open_failure(process_bridge: ProcessBridge) -> None:
    """A pid that cannot be opened for termination raises.

    Args:
        process_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="process open failed"):
        _run(process_bridge.terminate(_ABSENT_PID))


@pytest.mark.parametrize("method", ["suspend", "resume"])
def test_suspend_and_resume_need_a_target(idle_bridge: ProcessBridge, method: str) -> None:
    """Suspending or resuming with no pid and nothing attached raises.

    Args:
        idle_bridge: Bridge that was never initialized.
        method: ``suspend`` or ``resume``.
    """
    with pytest.raises(ToolError, match="no process specified"):
        _invoke(idle_bridge, method, ())


def test_suspend_and_resume_change_the_suspend_count_of_every_thread(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """Suspending raises every thread's count to one and resuming brings it back to zero.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    tids = _thread_ids(target_process.pid)
    assert _run(process_bridge.suspend(target_process.pid)) is True
    suspended = [_suspend_count(tid) for tid in tids]
    assert _run(process_bridge.resume(target_process.pid)) is True
    resumed = [_suspend_count(tid) for tid in tids]
    assert suspended == [1] * len(tids)
    assert resumed == [0] * len(tids)


def test_suspend_raises_when_a_thread_cannot_be_suspended(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
    max_suspended_thread: int,
) -> None:
    """A thread whose suspend count is at the maximum cannot be suspended again, and the bridge says so.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
        max_suspended_thread: Thread whose suspend count is at the maximum.
    """
    with pytest.raises(ToolError, match=rf"suspend failed for thread IDs: .*{max_suspended_thread}"):
        _run(process_bridge.suspend(target_process.pid))


def test_get_threads_reports_unknown_for_a_thread_at_the_maximum_suspend_count(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
    max_suspended_thread: int,
) -> None:
    """The probes cannot suspend a thread at the maximum count, so its state and pc stay unknown.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
        max_suspended_thread: Thread whose suspend count is at the maximum.
    """
    matching = [thread for thread in _run(process_bridge.get_threads(target_process.pid)) if thread.tid == max_suspended_thread]
    assert len(matching) == 1
    assert matching[0].state == "unknown"
    assert matching[0].current_pc == 0


def test_get_threads_without_a_pid_raises_when_nothing_is_attached(process_bridge: ProcessBridge) -> None:
    """Thread enumeration needs a pid or an attached process.

    Args:
        process_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="no process specified"):
        _run(process_bridge.get_threads())


def test_get_modules_for_an_absent_pid_is_empty(process_bridge: ProcessBridge) -> None:
    """A pid with no module snapshot yields an empty module list.

    Args:
        process_bridge: Initialized bridge.
    """
    assert _run(process_bridge.get_modules(_ABSENT_PID)) == []


def test_get_modules_without_psapi_reports_zero_entry_points(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """Entry points come from ``psapi``; without it every module reports zero.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.
    """
    image_name = Path(psutil.Process(target_process.pid).exe()).name.lower()
    with_psapi = _run(process_bridge.get_modules(target_process.pid))
    with _without_dll(process_bridge, "_psapi"):
        without_psapi = _run(process_bridge.get_modules(target_process.pid))
    assert any(module.entry_point != 0 for module in with_psapi)
    assert image_name in {module.name.lower() for module in without_psapi}
    assert all(module.entry_point == 0 for module in without_psapi)


def test_query_module_entry_point_is_zero_for_an_unreadable_module(process_bridge: ProcessBridge) -> None:
    """A failed ``GetModuleInformation`` call yields entry point zero.

    Args:
        process_bridge: Initialized bridge.
    """
    assert sync_method(process_bridge, "_query_module_entry_point")(0, 0) == 0


def test_query_thread_pc_and_state_reports_a_pc_inside_executable_memory(
    attached_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """A blocked child thread is reported as running with a program counter in executable memory.

    Args:
        attached_bridge: Bridge attached to the child.
        target_process: The running child process.
    """
    tid = _thread_ids(target_process.pid)[0]
    pc, state = cast("tuple[int, str]", sync_method(attached_bridge, "_query_thread_pc_and_state")(tid))
    containing = [
        region for region in _run(attached_bridge.get_memory_map()) if region.base_address <= pc < region.base_address + region.size
    ]
    assert state == "running"
    assert pc != 0
    assert len(containing) == 1
    assert "x" in containing[0].protection


def test_query_thread_pc_and_state_for_the_calling_thread_and_an_absent_thread(attached_bridge: ProcessBridge) -> None:
    """The calling thread is reported as running without a probe and an absent thread as unknown.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    current_tid: int = ctypes.windll.kernel32.GetCurrentThreadId()
    assert sync_method(attached_bridge, "_query_thread_pc_and_state")(current_tid) == (0, "running")
    assert sync_method(attached_bridge, "_query_thread_pc_and_state")(_ABSENT_PID) == (0, "unknown")


def test_probes_report_a_thread_that_has_exited(process_bridge: ProcessBridge, worker_process: tuple[Popen[bytes], int]) -> None:
    """Once a thread has exited every probe reports it as terminated.

    Args:
        process_bridge: Initialized bridge.
        worker_process: The worker child and the identifier of its extra thread.
    """
    proc, tid = worker_process
    access = _THREAD_QUERY_INFORMATION | _THREAD_SUSPEND_RESUME | _THREAD_GET_CONTEXT | _SYNCHRONIZE
    with _thread_handle(tid, access) as handle:
        _release_worker(proc)
        _wait_signaled(handle)
        assert sync_method(process_bridge, "_probe_thread_state_inner")(handle) == "terminated"
        assert sync_method(process_bridge, "_probe_thread_state")(handle, tid) == "terminated"
        assert sync_method(process_bridge, "_probe_thread_pc_and_state_inner")(handle) == (0, "terminated")
        assert sync_method(process_bridge, "_probe_thread_pc_and_state")(handle, tid) == (0, "terminated")


def test_probes_report_unknown_for_an_invalid_thread_handle(process_bridge: ProcessBridge) -> None:
    """A null thread handle makes the state probe and the pc probe both answer unknown.

    Args:
        process_bridge: Initialized bridge.
    """
    assert sync_method(process_bridge, "_probe_thread_state_inner")(0) == "unknown"
    assert sync_method(process_bridge, "_probe_thread_pc_and_state_inner")(0) == (0, "unknown")


def test_read_thread_pc_is_zero_without_get_context_access(attached_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """A thread handle without ``THREAD_GET_CONTEXT`` cannot yield a program counter.

    Args:
        attached_bridge: Bridge attached to the child.
        target_process: The running child process.
    """
    tid = _thread_ids(target_process.pid)[0]
    with _thread_handle(tid, _THREAD_QUERY_INFORMATION) as handle:
        assert sync_method(attached_bridge, "_read_thread_pc")(handle) == 0
        assert sync_method(attached_bridge, "_read_pc_via_context")(handle, target_process.pid) == 0


def test_region_still_committed_follows_the_child_allocation(attached_bridge: ProcessBridge, idle_bridge: ProcessBridge) -> None:
    """An address is committed while its allocation exists and not once it is freed.

    Args:
        attached_bridge: Bridge attached to the child.
        idle_bridge: Bridge that was never initialized.
    """
    address = _run(attached_bridge.allocate(0x1000, "rw"))
    committed = sync_method(attached_bridge, "_region_still_committed")(address)
    assert _run(attached_bridge.free(address)) is True
    released = sync_method(attached_bridge, "_region_still_committed")(address)
    assert committed is True
    assert released is False
    assert sync_method(idle_bridge, "_region_still_committed")(address) is False


def test_region_still_committed_is_false_without_an_attached_process(process_bridge: ProcessBridge) -> None:
    """Without an attached process no address counts as committed.

    Args:
        process_bridge: Initialized bridge with nothing attached.
    """
    assert sync_method(process_bridge, "_region_still_committed")(0x1000) is False


@pytest.mark.parametrize(
    ("name", "args", "message"),
    _REMOTE_MEMORY_FAILURES,
    ids=[row[0] for row in _REMOTE_MEMORY_FAILURES],
)
def test_remote_memory_operation_failure_is_reported(
    attached_bridge: ProcessBridge,
    name: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """Memory operations that the child's address space rejects raise their own error.

    Args:
        attached_bridge: Bridge attached to the child.
        name: Operation under test.
        args: Positional arguments for the call.
        message: Error text the operation must raise with.
    """
    with pytest.raises(ToolError, match=message):
        _invoke(attached_bridge, name, args)


@pytest.mark.parametrize("pattern", ["", "   "])
def test_search_pattern_with_no_bytes_finds_nothing(idle_bridge: ProcessBridge, pattern: str) -> None:
    """A pattern without any byte tokens returns no matches without touching a process.

    Args:
        idle_bridge: Bridge that was never initialized.
        pattern: Pattern text with no tokens.
    """
    assert _run(idle_bridge.search_pattern(pattern)) == []


@pytest.mark.parametrize("pattern", ["41 ?? 43", "41 ? 43"])
def test_search_pattern_wildcards_match_any_byte(attached_bridge: ProcessBridge, pattern: str) -> None:
    """Both wildcard spellings match whatever byte sits in their position.

    Args:
        attached_bridge: Bridge attached to the child.
        pattern: Pattern with a wildcard in the middle.
    """
    with _child_allocation(attached_bridge, 0x1000) as address:
        assert _run(attached_bridge.write_memory(address + 0x100, b"ABC")) == 3
        matches = _run(attached_bridge.search_pattern(pattern, start_address=address, end_address=address + 0x1000))
    assert matches == [address + 0x100]


def test_scan_region_pattern_stops_when_cancelled(attached_bridge: ProcessBridge) -> None:
    """A set cancel event stops the chunk scan before any byte is read.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    scan = sync_method(attached_bridge, "_scan_region_pattern")
    with _child_allocation(attached_bridge, 0x1000) as address:
        assert _run(attached_bridge.write_memory(address, bytes([_PATTERN_BYTE]))) == 1
        free_run: list[int] = []
        cancelled_run: list[int] = []
        cancel = threading.Event()
        scanned_free = scan(address, 0x1000, [_PATTERN_BYTE], 0, free_run, cancel, None)
        cancel.set()
        scanned_cancelled = scan(address, 0x1000, [_PATTERN_BYTE], 0, cancelled_run, cancel, None)
    assert scanned_free == 0x1000
    assert free_run == [address]
    assert scanned_cancelled == 0
    assert cancelled_run == []


@pytest.mark.parametrize("expected_progress", [[0x3000], []], ids=["with-callback", "without-callback"])
def test_scan_region_pattern_skips_a_chunk_that_cannot_be_read(attached_bridge: ProcessBridge, expected_progress: list[int]) -> None:
    """A chunk that reaches past the committed pages is skipped and the scan still finishes.

    Args:
        attached_bridge: Bridge attached to the child.
        expected_progress: Progress values the scan must report; empty when no callback is supplied.
    """
    progress: list[int] = []
    matches: list[int] = []
    callback = progress.append if expected_progress else None
    with _child_allocation(attached_bridge, 0x1000) as address:
        assert _run(attached_bridge.write_memory(address, bytes([_PATTERN_BYTE]))) == 1
        scanned = sync_method(attached_bridge, "_scan_region_pattern")(address, 0x3000, [_PATTERN_BYTE], 0, matches, None, callback)
    assert scanned == 0x3000
    assert matches == []
    assert progress == expected_progress


def test_scan_region_pattern_aborts_when_the_region_was_freed(attached_bridge: ProcessBridge) -> None:
    """A failed read inside a region that is no longer committed ends the scan immediately.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    address = _run(attached_bridge.allocate(0x1000, "rw"))
    assert _run(attached_bridge.free(address)) is True
    progress: list[int] = []
    matches: list[int] = []
    scanned = sync_method(attached_bridge, "_scan_region_pattern")(address, 0x1000, [_PATTERN_BYTE], 0, matches, None, progress.append)
    assert scanned == 0
    assert matches == []
    assert progress == []


def test_scan_region_pattern_finishes_a_region_that_is_exactly_one_chunk(attached_bridge: ProcessBridge) -> None:
    """A single-byte pattern over exactly one chunk finds its match and ends the loop by exhaustion.

    Args:
        attached_bridge: Bridge attached to the child.
    """
    progress: list[int] = []
    matches: list[int] = []
    marker = bytes([0xA5])
    with _child_allocation(attached_bridge, _ONE_CHUNK) as address:
        assert _run(attached_bridge.write_memory(address + 0x80000, marker)) == 1
        scanned = sync_method(attached_bridge, "_scan_region_pattern")(address, _ONE_CHUNK, [0xA5], 0, matches, None, progress.append)
    assert scanned == _ONE_CHUNK
    assert matches == [address + 0x80000]
    assert progress == [_ONE_CHUNK]


def test_await_remote_loadlibrary_rejects_an_invalid_handle(process_bridge: ProcessBridge) -> None:
    """Waiting on a null handle fails and is reported as a wait failure.

    Args:
        process_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError, match="WaitForSingleObject failed on remote thread"):
        sync_method(process_bridge, "_await_remote_loadlibrary")(0)


def test_await_remote_loadlibrary_times_out_on_a_handle_that_never_signals(
    process_bridge: ProcessBridge,
    target_process: Popen[bytes],
) -> None:
    """A handle that stays unsignaled for the whole wait makes the helper report a timeout.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process, whose handle signals only when it exits.
    """
    with _process_handle(target_process.pid, _SYNCHRONIZE) as handle, pytest.raises(ToolError, match="remote thread timed out"):
        sync_method(process_bridge, "_await_remote_loadlibrary")(handle)


def test_await_remote_loadlibrary_reports_an_exit_code_query_failure(
    process_bridge: ProcessBridge,
    worker_process: tuple[Popen[bytes], int],
) -> None:
    """A signaled thread handle that may not be queried makes the exit-code lookup fail.

    Args:
        process_bridge: Initialized bridge.
        worker_process: The worker child and the identifier of its extra thread.
    """
    proc, tid = worker_process
    with _thread_handle(tid, _SYNCHRONIZE) as handle:
        _release_worker(proc)
        _wait_signaled(handle)
        with pytest.raises(ToolError, match=r"GetExitCodeThread failed: \d+"):
            sync_method(process_bridge, "_await_remote_loadlibrary")(handle)
