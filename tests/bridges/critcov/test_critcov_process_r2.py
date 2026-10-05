# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass critical-coverage tests for the process bridge's remaining reachable failure paths.

Every test that modifies or probes a live process drives the real Win32 APIs against a child process that the
test itself starts (a Python interpreter blocked on stdin). The only queries made against the pytest process
are the read-only "no pid, nothing attached" arms of the mitigation, extension-policy, job and GUI-resource
readers, which describe the calling process through the current-process pseudo handle; those tests compare the
bridge's answer with an independent query made through the test's own prototyped Win32 handles. The tests cover
the architecture reader on damaged or unreadable PE headers, the remote-thread and wait failures of DLL
injection, the out-of-range handle guards of the thread probes and mitigation queries, the exported-function
guards, the section unmapper, the job, .NET and environment readers on unusual targets, the TLS
expansion-table readers and the start-up path of a process whose token holds no debug privilege.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import functools
import os
import shutil
import struct
import sys
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

import intellicrack.bridges.process as process_module
from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    GR_GDIOBJECTS,
    GR_USEROBJECTS,
    PAGE_NOACCESS,
    PAGE_READWRITE,
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_OPERATION,
    PROCESS_VM_READ,
    PROCESS_VM_WRITE,
    SE_PRIVILEGE_REMOVED,
    SYNCHRONIZE,
    ProcessASLRPolicy,
    ProcessControlFlowGuardPolicy,
    ProcessExtensionPointDisablePolicy,
)
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 120.0
_READY: Final[str] = "ready"
_OUT_OF_RANGE_HANDLE: Final[int] = 1 << 80
_PAGE: Final[int] = 0x1000
_E_LFANEW_OFFSET: Final[int] = 0x3C
_PEB_PROCESS_PARAMETERS_OFFSET: Final[int] = 0x20
_IMAGE_ACCESS: Final[int] = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
_PE_ARCH_BY_MACHINE: Final[dict[int, str]] = {0x014C: "x86", 0x8664: "x86_64", 0xAA64: "arm64"}
_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
_POLICY_NAMES: Final[tuple[str, ...]] = (
    "DEP",
    "ASLR",
    "DynamicCode",
    "StrictHandleCheck",
    "SystemCallDisable",
    "CFG",
    "BinarySignature",
    "FontDisable",
    "ImageLoad",
)

_BLOCKER_SOURCE: Final[str] = "import sys\nsys.stdout.write('ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_IMAGE_SOURCE: Final[str] = (
    "import ctypes\n"
    "import sys\n"
    "k = ctypes.WinDLL('kernel32')\n"
    "k.GetModuleHandleW.restype = ctypes.c_void_p\n"
    "k.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]\n"
    "sys.stdout.write('ready %d\\n' % k.GetModuleHandleW(None))\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)
_DLL_LOADER_SOURCE: Final[str] = (
    "import ctypes\n"
    "import sys\n"
    "for path in sys.argv[1:]:\n"
    "    ctypes.WinDLL(path)\n"
    "sys.stdout.write('ready\\n')\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)
_NO_DEBUG_PRIVILEGE_SOURCE: Final[str] = (
    "import asyncio\n"
    "import ctypes\n"
    "from ctypes import wintypes\n"
    "from intellicrack.bridges.process import ProcessBridge\n"
    "from intellicrack.bridges.win32_types import LUID, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY\n"
    "k = ctypes.WinDLL('kernel32', use_last_error=True)\n"
    "a = ctypes.WinDLL('advapi32', use_last_error=True)\n"
    "k.GetCurrentProcess.restype = wintypes.HANDLE\n"
    "a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]\n"
    "a.OpenProcessToken.restype = wintypes.BOOL\n"
    "a.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]\n"
    "a.LookupPrivilegeValueW.restype = wintypes.BOOL\n"
    "a.AdjustTokenPrivileges.argtypes = [\n"
    "    wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p\n"
    "]\n"
    "a.AdjustTokenPrivileges.restype = wintypes.BOOL\n"
    "token = wintypes.HANDLE()\n"
    "assert a.OpenProcessToken(k.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token))\n"
    "luid = LUID()\n"
    "assert a.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(luid))\n"
    "request = TOKEN_PRIVILEGES()\n"
    "request.PrivilegeCount = 1\n"
    "request.Privileges[0].Luid = luid\n"
    f"request.Privileges[0].Attributes = {SE_PRIVILEGE_REMOVED}\n"
    "a.AdjustTokenPrivileges(token, wintypes.BOOL(0), ctypes.byref(request), ctypes.sizeof(request), None, None)\n"
    "bridge = ProcessBridge()\n"
    "asyncio.run(bridge.initialize())\n"
    "print('critcov-result', bridge.debug_privilege_enabled, bridge.state.connected, flush=True)\n"
    "asyncio.run(bridge.shutdown())\n"
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


def async_method(obj: object, name: str) -> Callable[..., Coroutine[object, object, object]]:
    """Look up a (possibly private) coroutine method by name.

    Args:
        obj: Object that owns the method.
        name: Method name.

    Returns:
        Callable[..., Coroutine[object, object, object]]: The bound coroutine method.
    """
    return cast("Callable[..., Coroutine[object, object, object]]", getattr(obj, name))


@functools.cache
def _k32() -> ctypes.WinDLL:
    """Load a private ``kernel32`` handle with explicit prototypes for the test's own calls.

    Returns:
        ctypes.WinDLL: A ``kernel32`` handle whose function pointers are independent of the bridge's own.
    """
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    dll.OpenProcess.restype = wintypes.HANDLE
    dll.CloseHandle.argtypes = [wintypes.HANDLE]
    dll.CloseHandle.restype = wintypes.BOOL
    dll.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    dll.VirtualProtectEx.restype = wintypes.BOOL
    dll.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    dll.ReadProcessMemory.restype = wintypes.BOOL
    dll.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    dll.WriteProcessMemory.restype = wintypes.BOOL
    dll.GetCurrentProcess.argtypes = []
    dll.GetCurrentProcess.restype = wintypes.HANDLE
    dll.GetProcessMitigationPolicy.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    dll.GetProcessMitigationPolicy.restype = wintypes.BOOL
    dll.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    dll.IsProcessInJob.restype = wintypes.BOOL
    dll.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    dll.UnmapViewOfFile.restype = wintypes.BOOL
    return dll


@functools.cache
def _user32() -> ctypes.WinDLL:
    """Load a private ``user32`` handle with an explicit ``GetGuiResources`` prototype.

    Returns:
        ctypes.WinDLL: A ``user32`` handle whose function pointers are independent of the bridge's own.
    """
    dll = ctypes.WinDLL("user32", use_last_error=True)
    dll.GetGuiResources.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    dll.GetGuiResources.restype = wintypes.DWORD
    return dll


def _policy_primary_bit(handle: int, policy_class: int) -> bool:
    """Independently decode bit 0 of a one-DWORD process mitigation policy.

    Args:
        handle: Process handle or pseudo handle with query access.
        policy_class: ``PROCESS_MITIGATION_POLICY`` enumeration value.

    Returns:
        bool: ``True`` when the query succeeds and bit 0 of the flags is set.
    """
    flags = ctypes.c_ulong(0)
    queried: int = _k32().GetProcessMitigationPolicy(handle, policy_class, ctypes.byref(flags), ctypes.sizeof(flags))
    return bool(queried) and bool(flags.value & 1)


def _gui_count(handle: int, flag: int) -> int:
    """Count GDI or USER objects of a process through the test's own ``user32``.

    Args:
        handle: Process handle or pseudo handle with query access.
        flag: ``GR_GDIOBJECTS`` or ``GR_USEROBJECTS``.

    Returns:
        int: The object count reported by ``GetGuiResources``.
    """
    count: int = _user32().GetGuiResources(handle, flag)
    return count


@contextlib.contextmanager
def _remote_handle(pid: int, access: int) -> Generator[int]:
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


def _read_remote(handle: int, address: int, size: int) -> bytes:
    """Read bytes from another process through the test's own ``kernel32``.

    Args:
        handle: Process handle with ``PROCESS_VM_READ`` access.
        address: Address inside the target process.
        size: Number of bytes to read.

    Returns:
        bytes: The bytes that were read.
    """
    buffer = ctypes.create_string_buffer(size)
    count = ctypes.c_size_t(0)
    read_ok: int = _k32().ReadProcessMemory(handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(count))
    assert read_ok
    return buffer.raw[: count.value]


def _write_remote(handle: int, address: int, data: bytes) -> None:
    """Write bytes into another process through the test's own ``kernel32``.

    Args:
        handle: Process handle with ``PROCESS_VM_WRITE`` and ``PROCESS_VM_OPERATION`` access.
        address: Address inside the target process.
        data: Bytes to write.
    """
    buffer = ctypes.create_string_buffer(data, len(data))
    count = ctypes.c_size_t(0)
    write_ok: int = _k32().WriteProcessMemory(handle, ctypes.c_void_p(address), buffer, len(data), ctypes.byref(count))
    assert write_ok
    assert count.value == len(data)


@contextlib.contextmanager
def _remote_protection(handle: int, address: int, size: int, protection: int) -> Generator[None]:
    """Change the protection of a region of another process and restore it afterwards.

    Args:
        handle: Process handle with ``PROCESS_VM_OPERATION`` access.
        address: Start of the region.
        size: Size of the region in bytes.
        protection: ``PAGE_*`` protection applied for the duration of the context.

    Yields:
        None: Control while the new protection is in force.
    """
    previous = wintypes.DWORD(0)
    changed: int = _k32().VirtualProtectEx(handle, ctypes.c_void_p(address), size, protection, ctypes.byref(previous))
    assert changed
    try:
        yield
    finally:
        scratch = wintypes.DWORD(0)
        _k32().VirtualProtectEx(handle, ctypes.c_void_p(address), size, previous.value, ctypes.byref(scratch))


@contextlib.contextmanager
def _patched_remote(handle: int, address: int, data: bytes) -> Generator[None]:
    """Overwrite bytes in another process and put the original bytes back afterwards.

    Args:
        handle: Process handle with read, write and operation access.
        address: Start of the bytes to overwrite.
        data: Replacement bytes.

    Yields:
        None: Control while the replacement bytes are in place.
    """
    original = _read_remote(handle, address, len(data))
    with _remote_protection(handle, address, len(data), PAGE_READWRITE):
        _write_remote(handle, address, data)
        try:
            yield
        finally:
            _write_remote(handle, address, original)


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
    tokens: list[str] = []
    try:
        stdout = proc.stdout
        assert stdout is not None
        tokens = stdout.readline().decode("ascii", errors="replace").split()
        assert tokens
        assert tokens[0] == _READY
        yield proc, tokens[1:]
    finally:
        _stop_child(proc)


def _image_arch() -> str:
    """Derive the architecture of the interpreter image from the COFF machine field of its file.

    Returns:
        str: ``'x86'``, ``'x86_64'`` or ``'arm64'`` according to the file's ``IMAGE_FILE_HEADER.Machine``.
    """
    data = Path(sys.executable).read_bytes()
    pe_offset = struct.unpack_from("<I", data, _E_LFANEW_OFFSET)[0]
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    return _PE_ARCH_BY_MACHINE[machine]


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


@pytest.fixture
def idle_bridge() -> ProcessBridge:
    """Create a bridge that was never initialized, so no DLL is loaded and nothing is attached.

    Returns:
        ProcessBridge: A fresh bridge.
    """
    return ProcessBridge()


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
    with _running_child(_BLOCKER_SOURCE) as (proc, _tokens):
        yield proc


@pytest.fixture
def image_child() -> Generator[tuple[Popen[bytes], int]]:
    """Start a child that reports the base address of its own executable image and stop it afterwards.

    Yields:
        tuple[Popen[bytes], int]: The running child and the base address of its main image.
    """
    with _running_child(_IMAGE_SOURCE) as (proc, tokens):
        yield proc, int(tokens[0])


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
def foreign_library() -> ctypes.WinDLL:
    """Load a real system library that exports none of the Win32 process-API names the bridge probes for.

    Returns:
        ctypes.WinDLL: The ``ntdll`` library, which exports native ``Nt``/``Rtl`` entry points only.
    """
    return ctypes.WinDLL("ntdll")


def test_missing_debug_privilege_is_tolerated_at_initialization() -> None:
    """A process whose token holds no ``SeDebugPrivilege`` still initializes, with the privilege flag clear.

    The check runs in a child interpreter that removes the privilege from its own token first, so the
    pytest process's token is never touched.

    Mutation: removing ``except ToolError`` at process.py:1502 lets the privilege failure escape
    ``initialize`` and the child exits with a traceback.
    """
    env = dict(os.environ)
    source_root = str(Path(process_module.__file__).resolve().parents[2])
    env["PYTHONPATH"] = source_root + os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else source_root
    proc = Popen([sys.executable, "-c", _NO_DEBUG_PRIVILEGE_SOURCE], stdout=PIPE, stderr=PIPE, env=env)
    stdout, stderr = proc.communicate(timeout=_WAIT_S)
    lines = [line for line in stdout.decode("utf-8", errors="replace").splitlines() if line.startswith("critcov-result")]
    assert proc.returncode == 0, stderr.decode("utf-8", errors="replace")
    assert lines == ["critcov-result False True"]


def test_call_iswow64process2_is_none_when_the_library_lacks_the_export(idle_bridge: ProcessBridge, foreign_library: ctypes.WinDLL) -> None:
    """A kernel library without ``IsWow64Process2`` makes the helper report that no answer is available.

    Args:
        idle_bridge: Bridge that was never initialized.
        foreign_library: Real library that exports no ``IsWow64Process2``.

    Mutation: changing ``return None`` at process.py:1852 to ``return (0, 0)`` makes the helper report a pair.
    """
    with _slot(idle_bridge, "_kernel32", foreign_library):
        assert sync_method(idle_bridge, "_call_iswow64process2")(0) is None


def test_target_is_wow64_refuses_when_neither_wow64_export_exists(idle_bridge: ProcessBridge, foreign_library: ctypes.WinDLL) -> None:
    """With neither ``IsWow64Process2`` nor ``IsWow64Process`` available the detection refuses instead of guessing.

    Args:
        idle_bridge: Bridge that was never initialized.
        foreign_library: Real library that exports neither WOW64 query.

    Mutation: replacing the ``raise`` at process.py:1902 with ``return False`` makes the call return quietly.
    """
    with (
        _slot(idle_bridge, "_kernel32", foreign_library),
        _slot(idle_bridge, "_process_handle", 1),
        pytest.raises(ToolError, match="WOW64 detection unavailable"),
    ):
        sync_method(idle_bridge, "_target_is_wow64")()


def test_legacy_architecture_detector_uses_the_pointer_size_without_the_export(
    idle_bridge: ProcessBridge,
    foreign_library: ctypes.WinDLL,
) -> None:
    """Without ``IsWow64Process`` the legacy detector answers with the architecture of the host pointer size.

    Args:
        idle_bridge: Bridge that was never initialized.
        foreign_library: Real library that exports no ``IsWow64Process``.

    Mutation: changing ``"x86_64" if pointer_bits == _POINTER_BITS_64`` at process.py:2594 to always return ``"x86"``.
    """
    expected = "x86_64" if sys.maxsize > 2**32 else "x86"
    with _slot(idle_bridge, "_kernel32", foreign_library):
        assert sync_method(idle_bridge, "_detect_arch_via_iswow64process")(0) == expected


def test_module_entry_point_is_zero_when_the_library_lacks_get_module_information(
    idle_bridge: ProcessBridge,
    foreign_library: ctypes.WinDLL,
) -> None:
    """A process-status library without ``GetModuleInformation`` makes the entry-point query report 0.

    Args:
        idle_bridge: Bridge that was never initialized.
        foreign_library: Real library that exports no ``GetModuleInformation``.

    Mutation: replacing ``return 0`` at process.py:3834 with ``raise ToolError("x")``.
    """
    with _slot(idle_bridge, "_psapi", foreign_library):
        assert sync_method(idle_bridge, "_query_module_entry_point")(0, 0) == 0


def test_read_pe_arch_is_none_when_the_image_header_page_is_unreadable(
    process_bridge: ProcessBridge,
    image_child: tuple[Popen[bytes], int],
) -> None:
    """With the first page of the child's image made inaccessible the DOS header cannot be read.

    Once the protection is restored the same call reports the architecture stored in the image file.

    Args:
        process_bridge: Initialized bridge.
        image_child: The running child and the base of its main image.

    Mutation: changing ``if not self._kernel32.ReadProcessMemory(`` at process.py:2537 to drop the ``not``.
    """
    proc, base = image_child
    reader = sync_method(process_bridge, "_read_pe_arch_from_handle")
    with _remote_handle(proc.pid, _IMAGE_ACCESS) as handle:
        with _remote_protection(handle, base, _PAGE, PAGE_NOACCESS):
            blocked = reader(handle)
        restored = reader(handle)
    assert blocked is None
    assert restored == _image_arch()


def test_read_pe_arch_is_none_when_the_dos_signature_is_damaged(
    process_bridge: ProcessBridge,
    image_child: tuple[Popen[bytes], int],
) -> None:
    """A module whose header does not start with ``MZ`` yields no architecture.

    Args:
        process_bridge: Initialized bridge.
        image_child: The running child and the base of its main image.

    Mutation: changing ``!= "pe"`` at process.py:2546 to ``== "pe"``.
    """
    proc, base = image_child
    with _remote_handle(proc.pid, _IMAGE_ACCESS) as handle:
        with _patched_remote(handle, base, b"ZZ"):
            damaged = sync_method(process_bridge, "_read_pe_arch_from_handle")(handle)
        restored = sync_method(process_bridge, "_read_pe_arch_from_handle")(handle)
    assert damaged is None
    assert restored == _image_arch()


def test_read_pe_arch_is_none_when_the_nt_signature_is_damaged(
    process_bridge: ProcessBridge,
    image_child: tuple[Popen[bytes], int],
) -> None:
    """A module whose NT headers do not start with the ``PE`` signature yields no architecture.

    Args:
        process_bridge: Initialized bridge.
        image_child: The running child and the base of its main image.

    Mutation: changing ``!= PE_SIGNATURE`` at process.py:2561 to ``== PE_SIGNATURE``.
    """
    proc, base = image_child
    with _remote_handle(proc.pid, _IMAGE_ACCESS) as handle:
        nt_offset = struct.unpack("<I", _read_remote(handle, base + _E_LFANEW_OFFSET, 4))[0]
        with _patched_remote(handle, base + nt_offset, b"XXXX"):
            damaged = sync_method(process_bridge, "_read_pe_arch_from_handle")(handle)
        restored = sync_method(process_bridge, "_read_pe_arch_from_handle")(handle)
    assert damaged is None
    assert restored == _image_arch()


def test_read_pe_arch_is_none_when_the_nt_headers_are_unreadable(
    process_bridge: ProcessBridge,
    image_child: tuple[Popen[bytes], int],
) -> None:
    """A header whose ``e_lfanew`` points into inaccessible memory yields no architecture.

    The field is pointed at the second page of the image, which is made inaccessible, while the DOS
    header page stays readable.

    Args:
        process_bridge: Initialized bridge.
        image_child: The running child and the base of its main image.

    Mutation: changing ``if not self._kernel32.ReadProcessMemory(`` at process.py:2552 to drop the ``not``.
    """
    proc, base = image_child
    with _remote_handle(proc.pid, _IMAGE_ACCESS) as handle:
        with (
            _remote_protection(handle, base + _PAGE, _PAGE, PAGE_NOACCESS),
            _patched_remote(handle, base + _E_LFANEW_OFFSET, struct.pack("<I", _PAGE)),
        ):
            damaged = sync_method(process_bridge, "_read_pe_arch_from_handle")(handle)
        restored = sync_method(process_bridge, "_read_pe_arch_from_handle")(handle)
    assert damaged is None
    assert restored == _image_arch()


def test_terminate_of_an_exited_process_reports_a_terminate_failure(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """Terminating a process that already exited, while its object is still alive, fails with the terminate error.

    A second handle keeps the exited process object alive so that it can still be opened by pid.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.

    Mutation: replacing ``raise ToolError(_ERR_TERMINATE_FAILED)`` at process.py:2678 with ``return False``.
    """
    with _remote_handle(target_process.pid, SYNCHRONIZE):
        target_process.terminate()
        target_process.wait(timeout=_WAIT_S)
        with pytest.raises(ToolError, match="terminate failed"):
            _run(process_bridge.terminate(target_process.pid))


def test_wait_failure_is_reported_once_the_wait_result_is_unsigned(process_bridge: ProcessBridge) -> None:
    """With ``WaitForSingleObject`` returning an unsigned value a null handle is reported as a wait failure.

    The bridge's own ``_time_wait_on_handle`` declares an unsigned return type on the shared function
    object; the original return type is restored afterwards.

    Args:
        process_bridge: Initialized bridge.

    Mutation: changing the message raised at process.py:4096 to a different text.
    """
    kernel32 = priv(process_bridge, "_kernel32", ctypes.WinDLL)
    original = kernel32.WaitForSingleObject.restype
    try:
        timed = cast("dict[str, object]", sync_method(process_bridge, "_time_wait_on_handle")(0, 1, 0))
        assert timed["result"] == "failed"
        with pytest.raises(ToolError, match="WaitForSingleObject failed on remote thread"):
            sync_method(process_bridge, "_await_remote_loadlibrary")(0)
    finally:
        kernel32.WaitForSingleObject.restype = original


@pytest.mark.parametrize(
    ("name", "args", "expected"),
    [
        ("_probe_thread_state", (_OUT_OF_RANGE_HANDLE, 1), "unknown"),
        ("_probe_thread_pc_and_state", (_OUT_OF_RANGE_HANDLE, 1), (0, "unknown")),
        ("_read_thread_current_pc", (_OUT_OF_RANGE_HANDLE, None, 1), 0),
    ],
    ids=["state", "pc_and_state", "current_pc"],
)
def test_thread_probes_absorb_a_handle_that_cannot_be_marshalled(
    process_bridge: ProcessBridge,
    name: str,
    args: tuple[object, ...],
    expected: object,
) -> None:
    """A handle value that does not fit a pointer makes ctypes refuse the call and the probe reports the neutral result.

    Args:
        process_bridge: Initialized bridge.
        name: Probe under test.
        args: Positional arguments for the call.
        expected: Neutral value the probe must report.

    Mutation: removing ``ctypes.ArgumentError`` from the ``except`` clause of the probe lets the exception escape.
    """
    assert sync_method(process_bridge, name)(*args) == expected


@contextlib.contextmanager
def _attached_handle_value(bridge: ProcessBridge, value: int) -> Generator[None]:
    """Record a process-handle value on a bridge without any Win32 call and clear it afterwards.

    Args:
        bridge: Bridge whose attached-process slot is set.
        value: Handle value to record.

    Yields:
        None: Control while the slot holds ``value``.
    """
    set_priv(bridge, "_process_handle", value)
    try:
        yield
    finally:
        set_priv(bridge, "_process_handle", None)


def test_mitigation_policies_report_every_policy_unsupported_for_an_unmarshallable_handle(process_bridge: ProcessBridge) -> None:
    """Every policy query is reported as unsupported when ctypes cannot pass the recorded handle.

    Args:
        process_bridge: Initialized bridge.

    Mutation: removing ``ctypes.ArgumentError`` from the ``except`` clause at process.py:6871 lets the exception escape.
    """
    with _attached_handle_value(process_bridge, _OUT_OF_RANGE_HANDLE):
        policies = _run(process_bridge.get_mitigation_policies())
    assert policies == {name: {"enabled": False, "error": "not supported"} for name in _POLICY_NAMES}


def test_flat_mitigation_summary_is_all_clear_for_an_unmarshallable_handle(process_bridge: ProcessBridge) -> None:
    """The flat summary reports every flag clear and a zero options mask when no query can be made.

    Args:
        process_bridge: Initialized bridge.

    Mutation: removing ``ctypes.ArgumentError`` from the ``except`` clause at process.py:7873 lets the exception escape.
    """
    with _attached_handle_value(process_bridge, _OUT_OF_RANGE_HANDLE):
        summary = _run(process_bridge.get_mitigation_policy())
    assert summary == {"dep": False, "aslr": False, "cfg": False, "sehop_via_options_mask": 0}


def test_mitigation_policies_without_a_target_describe_the_calling_process(process_bridge: ProcessBridge) -> None:
    """With no pid and nothing attached, the per-policy report matches independent queries on the calling process.

    The queries are read-only and use the current-process pseudo handle. The bridge declares
    ``GetCurrentProcess`` as returning a pointer-sized handle, so the pseudo handle reaches the policy query
    as a Python integer that ctypes cannot pass to a function without prototypes; the bridge then reports
    every policy as unsupported although the operating system answers for the calling process.

    Suspected defect (new, gated by this test and the three other no-target tests): process.py:6789 hands the
    pseudo handle to ``GetProcessMitigationPolicy`` without declared argument types.

    Args:
        process_bridge: Initialized bridge.

    Mutation: replacing ``GetCurrentProcess()`` at process.py:6789 with ``0`` makes the call raise.
    """
    policies = _run(process_bridge.get_mitigation_policies())
    current = _k32().GetCurrentProcess()
    aslr = cast("dict[str, object]", policies["ASLR"])
    cfg = cast("dict[str, object]", policies["CFG"])
    assert "error" not in aslr
    assert aslr["enabled"] is _policy_primary_bit(current, ProcessASLRPolicy)
    assert cfg["enabled"] is _policy_primary_bit(current, ProcessControlFlowGuardPolicy)


def test_flat_mitigation_summary_without_a_target_describes_the_calling_process(process_bridge: ProcessBridge) -> None:
    """With no pid and nothing attached, the summary matches independent policy queries on the calling process.

    The queries are read-only and use the current-process pseudo handle. Suspected defect (new): the
    pseudo handle reaches ``GetProcessMitigationPolicy`` as an integer that ctypes cannot marshal, so the
    bridge reports every flag clear while the operating system reports address-space randomization on.

    Args:
        process_bridge: Initialized bridge.

    Mutation: replacing ``GetCurrentProcess()`` at process.py:7859 with ``0`` makes the call raise.
    """
    summary = _run(process_bridge.get_mitigation_policy())
    current = _k32().GetCurrentProcess()
    assert set(summary) == {"dep", "aslr", "cfg", "sehop_via_options_mask"}
    assert summary["aslr"] is _policy_primary_bit(current, ProcessASLRPolicy)
    assert summary["cfg"] is _policy_primary_bit(current, ProcessControlFlowGuardPolicy)
    assert isinstance(summary["dep"], bool)
    assert isinstance(summary["sehop_via_options_mask"], int)


def test_extension_policy_without_a_target_describes_the_calling_process(process_bridge: ProcessBridge) -> None:
    """With no pid and nothing attached, the extension-point policy matches an independent query on the calling process.

    Executed, not discriminating: a failed query also reports ``False``, so while the policy is clear for
    the calling process this test cannot tell a correct query from a failed one.

    Args:
        process_bridge: Initialized bridge.

    Mutation: replacing ``GetCurrentProcess()`` at process.py:7917 with ``0`` makes the call raise.
    """
    current = _k32().GetCurrentProcess()
    expected = _policy_primary_bit(current, ProcessExtensionPointDisablePolicy)
    assert _run(process_bridge.get_extension_policy()) == {"disable_extension_points": expected}


def test_job_info_without_a_target_describes_the_calling_process(process_bridge: ProcessBridge) -> None:
    """With no pid and nothing attached, the job membership matches an independent ``IsProcessInJob`` on the calling process.

    Suspected defect (new): the pseudo handle reaches ``IsProcessInJob`` as an integer that ctypes cannot
    marshal, so the call raises ``ctypes.ArgumentError`` instead of answering.

    Args:
        process_bridge: Initialized bridge.

    Mutation: replacing ``GetCurrentProcess()`` at process.py:9051 with ``0`` makes the call raise.
    """
    answer = wintypes.BOOL(0)
    queried: int = _k32().IsProcessInJob(_k32().GetCurrentProcess(), None, ctypes.byref(answer))
    assert queried
    result = _run(process_bridge.get_job_info())
    assert result["in_job"] is bool(answer.value)


def test_gui_resources_without_a_target_match_independent_counts_for_the_calling_process(process_bridge: ProcessBridge) -> None:
    """With no pid and nothing attached, the GDI and USER counts lie between two independent ``GetGuiResources`` readings.

    Suspected defect (new): the pseudo handle reaches ``GetGuiResources`` as an integer that ctypes cannot
    marshal, so the call raises ``ctypes.ArgumentError`` instead of answering.

    Args:
        process_bridge: Initialized bridge.

    Mutation: replacing ``GetCurrentProcess()`` at process.py:9477 with ``0`` makes the call raise.
    """
    current = _k32().GetCurrentProcess()
    before = (_gui_count(current, GR_GDIOBJECTS), _gui_count(current, GR_USEROBJECTS))
    result = _run(process_bridge.get_gui_resources())
    after = (_gui_count(current, GR_GDIOBJECTS), _gui_count(current, GR_USEROBJECTS))
    assert min(before[0], after[0]) <= result["gdi_objects"] <= max(before[0], after[0])
    assert min(before[1], after[1]) <= result["user_objects"] <= max(before[1], after[1])


def test_extension_policy_is_clear_for_an_unmarshallable_handle(process_bridge: ProcessBridge) -> None:
    """The extension-point query reports ``False`` when ctypes cannot pass the recorded handle.

    Args:
        process_bridge: Initialized bridge.

    Mutation: removing ``ctypes.ArgumentError`` from the ``except`` clause at process.py:7957 lets the exception escape.
    """
    with _attached_handle_value(process_bridge, _OUT_OF_RANGE_HANDLE):
        assert _run(process_bridge.get_extension_policy()) == {"disable_extension_points": False}


def test_job_info_for_a_handle_without_query_rights_reports_no_job(process_bridge: ProcessBridge, target_process: Popen[bytes]) -> None:
    """When ``IsProcessInJob`` cannot answer, the process is reported as not being in a job.

    Args:
        process_bridge: Initialized bridge.
        target_process: The running child process.

    Mutation: changing ``if is_in_job.value:`` at process.py:9080 to ``if True:`` makes the call add job details.
    """
    with _remote_handle(target_process.pid, SYNCHRONIZE) as handle:
        answer = wintypes.BOOL(0)
        queried: int = ctypes.WinDLL("kernel32", use_last_error=True).IsProcessInJob(handle, None, ctypes.byref(answer))
        assert not queried
        result = sync_method(process_bridge, "_collect_job_info")(handle, target_process.pid)
    assert result == {"in_job": False}


def test_unmap_section_uses_unmapviewoffile2_when_the_kernel_library_exports_it(process_bridge: ProcessBridge) -> None:
    """A tracked view is released through a library that exports ``UnmapViewOfFile2`` and its section handle is dropped.

    The view and its section are created with the bridge's own ``kernel32``; only the unmap runs against
    ``kernelbase``, the library that hosts the memory-API exports the ``kernel32`` of a Server Core image may
    not forward. The outcome is checked independently: the address is no longer a mapped view.

    Args:
        process_bridge: Initialized bridge.

    Mutation: replacing ``ctypes.c_void_p(base_address)`` at process.py:1779 with ``ctypes.c_void_p(0)``
    makes the unmap fail whenever the library exports ``UnmapViewOfFile2``.
    """
    section = _run(process_bridge.create_section(_PAGE))
    base = _run(process_bridge.map_section(section, _PAGE))
    assert base in process_bridge.section_views
    with _slot(process_bridge, "_kernel32", ctypes.WinDLL("kernelbase")):
        released = _run(process_bridge.unmap_section(base))
    still_mapped: int = _k32().UnmapViewOfFile(ctypes.c_void_p(base))
    assert released is True
    assert base not in process_bridge.section_views
    assert section not in process_bridge.section_handles
    assert not still_mapped


def test_detect_dotnet_reports_a_runtime_dll_that_names_no_framework(
    process_bridge: ProcessBridge,
    tmp_path: Path,
) -> None:
    """A child holding only a module named ``clrjit.dll`` is managed but its version stays unknown.

    No module has a COM descriptor and ``clrjit.dll`` is not one of the names the heuristic maps to a version.

    Args:
        process_bridge: Initialized bridge.
        tmp_path: Directory that receives the decoy DLL copy.

    Mutation: adding ``"clrjit.dll"`` to the ``clr.dll`` branch at process.py:8589 makes the version a string.
    """
    decoy = tmp_path / "clrjit.dll"
    shutil.copyfile(_SYSTEM32 / "version.dll", decoy)
    with _running_child(_DLL_LOADER_SOURCE, str(decoy)) as (proc, _tokens):
        result = _run(process_bridge.detect_dotnet(proc.pid))
    assert result == {
        "managed": True,
        "version": None,
        "clr_loaded": True,
        "clr_version": None,
        "runtime_dlls": ["clrjit.dll"],
    }


def test_tls_expansion_pointer_read_failure_leaves_the_slots_untouched(attached_bridge: ProcessBridge) -> None:
    """An expansion-pointer slot at an unmapped address is logged and no slot is added.

    Args:
        attached_bridge: Bridge attached to the child.

    Mutation: removing ``except ToolError`` at process.py:9908 lets the read failure escape.
    """
    slots: list[dict[str, object]] = []
    _run(async_method(attached_bridge, "_append_tls_expansion_slots")(slots, 0x10, 128, 1, "<Q", 8))
    assert slots == []


def test_tls_expansion_table_read_failure_leaves_the_slots_untouched(attached_bridge: ProcessBridge) -> None:
    """An expansion pointer that leads to unmapped memory is logged and no slot is added.

    Args:
        attached_bridge: Bridge attached to the child.

    Mutation: removing ``except ToolError`` at process.py:9948 lets the read failure escape.
    """
    slots: list[dict[str, object]] = []
    address = _run(attached_bridge.allocate(_PAGE, "rw"))
    try:
        assert _run(attached_bridge.write_memory(address, struct.pack("<Q", 0x10))) == 8
        sync_method(attached_bridge, "_read_tls_expansion_table")(slots, address, 128, 1, "<Q", 8)
    finally:
        assert _run(attached_bridge.free(address))
    assert slots == []


def test_environment_of_a_process_without_a_parameters_block_is_empty(
    process_bridge: ProcessBridge,
    image_child: tuple[Popen[bytes], int],
) -> None:
    """A PEB whose ``ProcessParameters`` pointer is zero has no environment to read.

    The pointer is zeroed inside the child's own PEB and put back afterwards; once restored the
    environment contains ``SYSTEMROOT``, which the child inherited.

    Args:
        process_bridge: Initialized bridge.
        image_child: The running child and the base of its main image.

    Mutation: changing ``or params_addr == 0`` at process.py:8000 to ``or params_addr == 1`` makes the read go on.
    """
    proc, _base = image_child
    peb_address = cast("int", _run(process_bridge.read_peb(proc.pid))["peb_address"])
    with _remote_handle(proc.pid, _IMAGE_ACCESS) as handle:
        with _patched_remote(handle, peb_address + _PEB_PROCESS_PARAMETERS_OFFSET, bytes(8)):
            emptied = _run(process_bridge.get_environment(proc.pid))
        restored = _run(process_bridge.get_environment(proc.pid))
    assert emptied == {}
    assert "SYSTEMROOT" in {key.upper() for key in restored}
