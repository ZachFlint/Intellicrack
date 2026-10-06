# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the ProcessBridge I/O mixin, job queries and runtime helpers.

The tests drive the real Win32 APIs. Anything that needs a live process uses a child
that the test starts itself (a Python interpreter, or Windows PowerShell for the managed
runtime check) and never the pytest process. The covered surface is: missing-DLL guards,
named pipe and device failures, the .NET detection helpers (PE COM descriptor parsing,
metadata version reading and CLR DLL name heuristics), job object queries, GUI object
counts, typed registry reads, section failures, TLS expansion slots, the raw
``NtQuerySystemInformation`` bridge and shutdown.
"""

from __future__ import annotations

import asyncio
import ctypes
import msvcrt
import os
import re
import shutil
import stat
import struct
import sys
import uuid
import winreg
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    IO_COUNTERS,
    JOBOBJECT_BASIC_LIMIT_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX,
)
from intellicrack.core.subprocess_compat import PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator, Sequence


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 60.0
_ABSENT_PID: Final[int] = 0x7FFFFFFE
_BOGUS_HANDLE: Final[int] = 0xDEAD0000
_UNOWNED_HANDLE_VALUE: Final[int] = 0x7FF0
_ERROR_INVALID_HANDLE: Final[int] = 6
_PROCESS_QUERY_INFORMATION: Final[int] = 0x0400
_SYSTEM32: Final[Path] = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
_POWERSHELL: Final[Path] = _SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
_POWERSHELL_SCRIPT: Final[str] = "[Console]::Out.WriteLine('ready'); [Console]::Out.Flush(); [void][Console]::In.ReadLine()"
_NO_KERNEL32: Final[str] = "kernel32 not available"
_NO_ADVAPI32: Final[str] = "advapi32 not available"
_NO_NTDLL: Final[str] = "ntdll not available"

_FSCTL_SET_SPARSE: Final[int] = 0x000900C4

_IMAGE_SIZE: Final[int] = 0x400
_NT_OFFSET: Final[int] = 0x80
_OPTIONAL_HEADER_SIZE: Final[int] = 240
_COM_DIRECTORY_OFFSET: Final[int] = 0x178
_SECTION_TABLE_OFFSET: Final[int] = 0x188
_SECTION_HEADER_SIZE: Final[int] = 40
_PE32_PLUS_MAGIC: Final[int] = 0x20B
_MACHINE_AMD64: Final[int] = 0x8664
_METADATA_SIGNATURE: Final[int] = 0x424A5342
_METADATA_BUFFER_SIZE: Final[int] = 276
_CLR4_VERSION: Final[bytes] = b"v4.0.30319\x00\x00"
_PAGE_SIZE: Final[int] = 0x1000
_STATIC_TLS_SLOTS: Final[int] = 64

_JOB_FLAGS: Final[int] = 0x308
_JOB_ACTIVE_PROCESS_LIMIT: Final[int] = 7
_JOB_PROCESS_MEMORY_LIMIT: Final[int] = 1 << 30
_JOB_MEMORY_LIMIT: Final[int] = 1 << 31

_BLOCKER_SOURCE: Final[str] = "import sys\nsys.stdout.write('ready\\n')\nsys.stdout.flush()\nsys.stdin.read()\n"
_DLL_LOADER_SOURCE: Final[str] = (
    "import ctypes\n"
    "import sys\n"
    "for path in sys.argv[1:]:\n"
    "    ctypes.WinDLL(path)\n"
    "sys.stdout.write('ready\\n')\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)
_IMAGE_HOST_SOURCE: Final[str] = (
    "import ctypes\n"
    "import sys\n"
    "from ctypes import wintypes\n"
    "k = ctypes.WinDLL('kernel32')\n"
    "k.VirtualAlloc.restype = ctypes.c_void_p\n"
    "k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]\n"
    "k.VirtualProtect.restype = wintypes.BOOL\n"
    "k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]\n"
    "base = k.VirtualAlloc(None, 0x2000, 0x3000, 0x04)\n"
    "data = bytes.fromhex(sys.argv[1])\n"
    "ctypes.memmove(base, data, len(data))\n"
    "old = wintypes.DWORD(0)\n"
    "assert k.VirtualProtect(base + 0x1000, 0x1000, 0x01, ctypes.byref(old))\n"
    "sys.stdout.write('ready %d\\n' % base)\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)
_JOB_SOURCE: Final[str] = (
    "import ctypes\n"
    "import struct\n"
    "import sys\n"
    "from ctypes import wintypes\n"
    "k = ctypes.WinDLL('kernel32')\n"
    "k.CreateJobObjectW.restype = wintypes.HANDLE\n"
    "k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]\n"
    "k.SetInformationJobObject.restype = wintypes.BOOL\n"
    "k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]\n"
    "k.AssignProcessToJobObject.restype = wintypes.BOOL\n"
    "k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]\n"
    "k.GetCurrentProcess.restype = wintypes.HANDLE\n"
    "job = k.CreateJobObjectW(None, None)\n"
    "assert job\n"
    "info = ctypes.create_string_buffer(144)\n"
    f"struct.pack_into('<I', info, 16, {_JOB_FLAGS})\n"
    f"struct.pack_into('<I', info, 40, {_JOB_ACTIVE_PROCESS_LIMIT})\n"
    f"struct.pack_into('<Q', info, 112, {_JOB_PROCESS_MEMORY_LIMIT})\n"
    f"struct.pack_into('<Q', info, 120, {_JOB_MEMORY_LIMIT})\n"
    "assert k.SetInformationJobObject(job, 9, info, 144)\n"
    "assert k.AssignProcessToJobObject(job, k.GetCurrentProcess())\n"
    "sys.stdout.write('ready %d\\n' % job)\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
)
_TLS_SOURCE: Final[str] = (
    "import ctypes\n"
    "import sys\n"
    "from ctypes import wintypes\n"
    "k = ctypes.WinDLL('kernel32')\n"
    "k.TlsAlloc.restype = wintypes.DWORD\n"
    "k.TlsAlloc.argtypes = []\n"
    "k.TlsSetValue.restype = wintypes.BOOL\n"
    "k.TlsSetValue.argtypes = [wintypes.DWORD, ctypes.c_void_p]\n"
    "k.GetCurrentThreadId.restype = wintypes.DWORD\n"
    "pairs = []\n"
    "for i in range(80):\n"
    "    index = k.TlsAlloc()\n"
    "    assert index != 0xFFFFFFFF\n"
    "    value = 0x1000 + 16 * i\n"
    "    assert k.TlsSetValue(index, value)\n"
    "    pairs.append('%d:%d' % (index, value))\n"
    "sys.stdout.write('ready %d %s\\n' % (k.GetCurrentThreadId(), ','.join(pairs)))\n"
    "sys.stdout.flush()\n"
    "sys.stdin.read()\n"
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


def method(obj: object, name: str) -> Callable[..., object]:
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


def set_priv(obj: object, name: str, value: object) -> None:
    """Set a private data attribute on a real object to put it in an otherwise unreachable state.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name, including its leading underscore.
        value: New attribute value.
    """
    setattr(obj, name, value)


def _kernel32_oracle() -> ctypes.WinDLL:
    """Load a private ``kernel32`` with explicit full-width signatures, independent of the bridge's own handle.

    Returns:
        ctypes.WinDLL: A ``kernel32`` whose entry points used by this module are fully typed.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    k32.UnmapViewOfFile.restype = wintypes.BOOL
    k32.DuplicateHandle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    k32.DuplicateHandle.restype = wintypes.BOOL
    return k32


def _oracle_gui_counts(pid: int) -> tuple[int, int]:
    """Count GDI and USER objects of a process through a separate, fully typed ``user32``.

    Args:
        pid: Identifier of the process to inspect.

    Returns:
        tuple[int, int]: ``(gdi_objects, user_objects)`` as reported by ``GetGuiResources`` flags 0 and 1.
    """
    k32 = _kernel32_oracle()
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetGuiResources.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    user32.GetGuiResources.restype = wintypes.DWORD
    handle = int(k32.OpenProcess(_PROCESS_QUERY_INFORMATION, 0, pid) or 0)
    assert handle, "oracle OpenProcess failed"
    try:
        return int(user32.GetGuiResources(handle, 0)), int(user32.GetGuiResources(handle, 1))
    finally:
        k32.CloseHandle(handle)


def _pe_headers(
    *,
    com_rva: int,
    com_size: int,
    sections: Sequence[tuple[int, int, int, int]] = (),
    total: int = _IMAGE_SIZE,
) -> bytearray:
    """Build the headers of a PE32+ image with the COM descriptor directory and section table filled in.

    Args:
        com_rva: Relative virtual address stored in data directory entry 14.
        com_size: Size stored in data directory entry 14.
        sections: ``(virtual_size, virtual_address, raw_size, raw_offset)`` tuples, one per section header.
        total: Length of the returned buffer in bytes.

    Returns:
        bytearray: Zero-padded image buffer holding the DOS header, NT headers and section table.
    """
    data = bytearray(total)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, _NT_OFFSET)
    data[_NT_OFFSET : _NT_OFFSET + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, _NT_OFFSET + 4, _MACHINE_AMD64, len(sections), 0, 0, 0, _OPTIONAL_HEADER_SIZE, 0x2022)
    struct.pack_into("<H", data, _NT_OFFSET + 24, _PE32_PLUS_MAGIC)
    struct.pack_into("<II", data, _COM_DIRECTORY_OFFSET, com_rva, com_size)
    for index, (virtual_size, virtual_address, raw_size, raw_offset) in enumerate(sections):
        entry = _SECTION_TABLE_OFFSET + index * _SECTION_HEADER_SIZE
        data[entry : entry + 8] = b".text\x00\x00\x00"
        struct.pack_into("<IIII", data, entry + 8, virtual_size, virtual_address, raw_size, raw_offset)
    return data


def _put_cor20(data: bytearray, offset: int, meta_rva: int) -> None:
    """Write an IMAGE_COR20_HEADER whose MetaData directory points at ``meta_rva``.

    Args:
        data: Image buffer to modify.
        offset: Buffer offset of the header.
        meta_rva: RVA stored in the header's MetaData directory entry.
    """
    struct.pack_into("<IHHII", data, offset, 72, 2, 5, meta_rva, 0x100)


def _put_metadata(data: bytearray, offset: int, version: bytes) -> None:
    """Write an ECMA-335 metadata root carrying ``version`` as its version string.

    Args:
        data: Image buffer to modify.
        offset: Buffer offset of the metadata root.
        version: Version string bytes, already padded to the declared length.
    """
    struct.pack_into("<IHHII", data, offset, _METADATA_SIGNATURE, 1, 1, 0, len(version))
    data[offset + 16 : offset + 16 + len(version)] = version


def _managed_image(
    *,
    sections: Sequence[tuple[int, int, int, int]] = (),
    com_rva: int = 0x200,
    meta_rva: int = 0x300,
    version: bytes = _CLR4_VERSION,
) -> bytes:
    """Build a PE image with a COR20 header at ``0x200`` and a metadata root at ``0x300``.

    Args:
        sections: Section headers as accepted by :func:`_pe_headers`.
        com_rva: RVA recorded in the COM descriptor data directory.
        meta_rva: RVA recorded in the COR20 header's MetaData entry.
        version: Metadata version string bytes.

    Returns:
        bytes: The image bytes.
    """
    data = _pe_headers(com_rva=com_rva, com_size=72, sections=sections)
    _put_cor20(data, 0x200, meta_rva)
    _put_metadata(data, 0x300, version)
    return bytes(data)


def _metadata_root(*, signature: int, version: bytes, declared_length: int) -> bytes:
    """Build a metadata root buffer the size ``_read_metadata_version`` reads.

    Args:
        signature: Value for the ``Signature`` field.
        version: Version string bytes stored at offset 16.
        declared_length: Value for the ``Length`` field at offset 12.

    Returns:
        bytes: Zero-padded metadata root bytes.
    """
    data = bytearray(_METADATA_BUFFER_SIZE)
    struct.pack_into("<IHHII", data, 0, signature, 1, 1, 0, declared_length)
    data[16 : 16 + len(version)] = version
    return bytes(data)


def _dos_only(e_lfanew: int) -> bytes:
    """Build a buffer holding only a DOS header with the given ``e_lfanew``.

    Args:
        e_lfanew: Value stored at the DOS header's NT-header pointer.

    Returns:
        bytes: A 0x100-byte buffer.
    """
    data = bytearray(0x100)
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    return bytes(data)


def _stage_decoy_dll(directory: Path, name: str) -> str:
    """Copy a small system DLL under ``name`` so a child can load it as a module of that name.

    Args:
        directory: Directory that receives the copy.
        name: File name of the copy.

    Returns:
        str: Path of the staged copy.
    """
    target = directory / name
    shutil.copyfile(_SYSTEM32 / "version.dll", target)
    return str(target)


class ChildHost:
    """Starts child processes that report readiness on stdout and stops all of them afterwards."""

    def __init__(self) -> None:
        """Create a host that has not started any child."""
        self._children: list[Popen[bytes]] = []

    def start_command(self, command: Sequence[str]) -> tuple[Popen[bytes], list[str]]:
        """Start ``command`` and wait for its first output line, which must begin with ``ready``.

        Args:
            command: Program and arguments to launch.

        Returns:
            tuple[Popen[bytes], list[str]]: The running child and the tokens that followed ``ready`` on its first line.
        """
        proc = Popen(list(command), stdin=PIPE, stdout=PIPE, stderr=PIPE)
        self._children.append(proc)
        stdout = proc.stdout
        assert stdout is not None
        tokens = stdout.readline().decode("ascii", errors="replace").split()
        if not tokens or tokens[0] != "ready":
            proc.terminate()
            proc.wait(timeout=_WAIT_S)
            stderr = proc.stderr
            detail = stderr.read().decode("utf-8", errors="replace") if stderr is not None else ""
            pytest.fail(f"child {command[0]!r} never reported readiness (first line {tokens!r}, stderr {detail!r})")
        return proc, tokens[1:]

    def start(self, source: str, *args: str) -> tuple[Popen[bytes], list[str]]:
        """Start a Python interpreter running ``source``.

        Args:
            source: Program text passed to ``python -c``.
            *args: Extra command-line arguments, visible to the program from ``sys.argv[1:]``.

        Returns:
            tuple[Popen[bytes], list[str]]: The running child and the tokens that followed ``ready``.
        """
        return self.start_command([sys.executable, "-c", source, *args])

    def start_image(self, image: bytes) -> tuple[Popen[bytes], int]:
        """Start a child that holds ``image`` in its own memory followed by one inaccessible page.

        Args:
            image: Bytes copied to the start of a freshly allocated two-page region.

        Returns:
            tuple[Popen[bytes], int]: The running child and the base address of the region inside it.
        """
        proc, tokens = self.start(_IMAGE_HOST_SOURCE, image.hex())
        return proc, int(tokens[0])

    def close(self) -> None:
        """Terminate every started child, wait for it and close its pipes."""
        for proc in self._children:
            try:
                if proc.poll() is None:
                    proc.terminate()
                proc.wait(timeout=_WAIT_S)
            finally:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
        self._children.clear()


@pytest.fixture
def child_host() -> Generator[ChildHost]:
    """Provide a :class:`ChildHost` and stop every child it started afterwards.

    Yields:
        ChildHost: The host used to start children.
    """
    host = ChildHost()
    try:
        yield host
    finally:
        host.close()


@pytest.fixture
def idle_bridge() -> ProcessBridge:
    """Provide a bridge that was never initialized, so every DLL reference is ``None``.

    Returns:
        ProcessBridge: A bridge without loaded DLLs.
    """
    return ProcessBridge()


@pytest.fixture
def live_bridge() -> Generator[ProcessBridge]:
    """Provide an initialized bridge and shut it down afterwards.

    Yields:
        ProcessBridge: A bridge with every DLL loaded and no attached process.
    """
    bridge = ProcessBridge()
    _run(bridge.initialize())
    try:
        yield bridge
    finally:
        _run(bridge.shutdown())


@pytest.fixture
def registry_key() -> Generator[str]:
    """Create a throwaway HKCU key holding a DWORD and a QWORD value and delete it afterwards.

    Yields:
        str: The key path, prefixed with the ``HKCU`` root name, in the form the bridge accepts.
    """
    path = rf"Software\IntellicrackCritcovProcess03_{uuid.uuid4().hex}"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as key:
        winreg.SetValueEx(key, "dword_value", 0, winreg.REG_DWORD, 0xDEADBEEF)
        winreg.SetValueEx(key, "qword_value", 0, winreg.REG_QWORD, 0x0123456789ABCDEF)
    try:
        yield "HKCU\\" + path
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)


_ASYNC_GUARDS: Final[list[tuple[str, tuple[object, ...], str]]] = [
    ("pipe_connect", (r"\\.\pipe\critcov_guard", 10), _NO_KERNEL32),
    ("pipe_read", (1, 1), _NO_KERNEL32),
    ("pipe_write", (1, b"a"), _NO_KERNEL32),
    ("device_open", (r"\\.\critcov_guard",), _NO_KERNEL32),
    ("device_ioctl", (1, 1), _NO_KERNEL32),
    ("get_job_info", (), _NO_KERNEL32),
    ("get_gui_resources", (), _NO_KERNEL32),
    ("create_section", (16,), _NO_KERNEL32),
    ("map_section", (1, 16), _NO_KERNEL32),
    ("reg_read_value", ("HKCU\\Software", "value"), _NO_ADVAPI32),
    ("reg_enum_keys", ("HKCU\\Software",), _NO_ADVAPI32),
    ("reg_enum_values", ("HKCU\\Software",), _NO_ADVAPI32),
    ("query_system_info", (0,), _NO_NTDLL),
]

_SYNC_GUARDS: Final[list[tuple[str, tuple[object, ...]]]] = [
    ("_enumerate_com_servers_sync", ({},)),
    ("_scan_clsid_entries", (wintypes.HKEY(), {})),
    ("_check_inproc_server", (wintypes.HKEY(), "{00000000-0000-0000-0000-000000000000}")),
]

_IDLE_DEFAULTS: Final[list[tuple[str, tuple[object, ...], object]]] = [
    ("_open_process_for_vm_read", (1234,), (None, False)),
    ("_read_cor20_version", (1, 0x1000), None),
    ("_read_metadata_version", (1, 0x1000, 0x2000, []), None),
    ("_collect_job_info", (1, None), {"in_job": False}),
    ("_query_job_details", (1,), {}),
    ("_acquire_queryable_job_handle", (1,), None),
    ("_get_target_pid_for_handle", (1,), 0),
    ("_lookup_job_type_indices", (), set()),
    ("_duplicate_job_handle_from_target", (1, {1}), None),
    ("_read_job_information", (1,), {}),
    ("_reg_enum_subkeys", (wintypes.HKEY(),), []),
    ("_reg_enum_value_names", (wintypes.HKEY(),), []),
]

_DOTNET_HEURISTICS: Final[list[tuple[tuple[str, ...], str]]] = [
    (("coreclr.dll",), ".NET Core/5+"),
    (("system.private.corelib.dll",), ".NET Core/5+"),
    (("clr.dll",), ".NET Framework 4.x"),
    (("mscorwks.dll",), ".NET Framework 2.x/3.x"),
    (("mscoree.dll",), ".NET Framework"),
    (("mscoree.dll", "clr.dll"), ".NET Framework 4.x"),
    (("clr.dll", "coreclr.dll"), ".NET Core/5+"),
]

_METADATA_VERSION_CASES: Final[list[tuple[int, bytes, int, str | None]]] = [
    (_METADATA_SIGNATURE, _CLR4_VERSION, 12, "v4.0.30319"),
    (_METADATA_SIGNATURE, b"v4.0.30319" + b"\x00" * 246, 256, "v4.0.30319"),
    (0x00905A4D, _CLR4_VERSION, 12, None),
    (_METADATA_SIGNATURE, _CLR4_VERSION, 0, None),
    (_METADATA_SIGNATURE, _CLR4_VERSION, 257, None),
    (_METADATA_SIGNATURE, b"v4.0 \x00\x00\x00", 8, "v4.0"),
    (_METADATA_SIGNATURE, b"v4\xff\x00", 4, "v4\ufffd"),
    (_METADATA_SIGNATURE, b"\x00\x00\x00\x00", 4, ""),
]


@pytest.mark.parametrize(("name", "args", "message"), _ASYNC_GUARDS, ids=[entry[0] for entry in _ASYNC_GUARDS])
def test_operation_without_required_dll_raises_tool_error(
    idle_bridge: ProcessBridge,
    name: str,
    args: tuple[object, ...],
    message: str,
) -> None:
    """Every operation that needs a Win32 DLL refuses to run on a bridge that never loaded it.

    Args:
        idle_bridge: Bridge whose DLL references are all ``None``.
        name: Name of the coroutine under test.
        args: Positional arguments for the call.
        message: Exact message of the expected error.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(idle_bridge, name)(*args))
    assert excinfo.value.message == message


@pytest.mark.parametrize(("name", "args"), _SYNC_GUARDS, ids=[entry[0] for entry in _SYNC_GUARDS])
def test_registry_walk_helpers_without_advapi32_raise(idle_bridge: ProcessBridge, name: str, args: tuple[object, ...]) -> None:
    """The COM registry walkers refuse to run when advapi32 was never loaded.

    Args:
        idle_bridge: Bridge whose DLL references are all ``None``.
        name: Name of the helper under test.
        args: Positional arguments for the call.
    """
    with pytest.raises(ToolError) as excinfo:
        method(idle_bridge, name)(*args)
    assert excinfo.value.message == _NO_ADVAPI32


@pytest.mark.parametrize(("name", "args", "expected"), _IDLE_DEFAULTS, ids=[entry[0] for entry in _IDLE_DEFAULTS])
def test_helpers_without_dlls_return_their_empty_result(
    idle_bridge: ProcessBridge,
    name: str,
    args: tuple[object, ...],
    expected: object,
) -> None:
    """Low-level helpers return their documented empty result when the DLL they need is missing.

    Args:
        idle_bridge: Bridge whose DLL references are all ``None``.
        name: Name of the helper under test.
        args: Positional arguments for the call.
        expected: The empty value the helper must return.
    """
    assert method(idle_bridge, name)(*args) == expected


def test_scan_handles_without_kernel32_returns_none(idle_bridge: ProcessBridge) -> None:
    """Scanning a handle table for a job handle to duplicate does nothing without kernel32.

    Args:
        idle_bridge: Bridge whose DLL references are all ``None``.
    """
    buffer = ctypes.create_string_buffer(64)
    duplicate = _kernel32_oracle().DuplicateHandle
    assert method(idle_bridge, "_scan_handles_for_duplicate")(buffer, 0, 0, 1, {1}, 1, duplicate) is None


def test_get_gui_resources_without_user32_raises(live_bridge: ProcessBridge) -> None:
    """GUI object counting reports a missing user32 even when kernel32 is loaded.

    Args:
        live_bridge: Initialized bridge.
    """
    set_priv(live_bridge, "_user32", None)
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.get_gui_resources())
    assert excinfo.value.message == "user32 not available"


def test_open_process_for_vm_read_without_any_target_returns_none(live_bridge: ProcessBridge) -> None:
    """With no pid argument and no attached process there is nothing to open.

    Args:
        live_bridge: Initialized bridge that is not attached.
    """
    assert method(live_bridge, "_open_process_for_vm_read")(None) == (None, False)


def test_open_process_for_vm_read_unopenable_pid_returns_none(live_bridge: ProcessBridge) -> None:
    """A pid that cannot be opened yields no handle and no ownership.

    Args:
        live_bridge: Initialized bridge that is not attached.
    """
    assert method(live_bridge, "_open_process_for_vm_read")(_ABSENT_PID) == (None, False)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (5, "Device open failed (Win32 error 5): access is denied. Retry from an elevated (Administrator) process."),
        (2, "Device open failed (Win32 error 2)"),
    ],
    ids=["access_denied_adds_elevation_hint", "other_code_has_no_hint"],
)
def test_describe_win32_device_error_names_code_and_hints_only_for_access_denied(code: int, expected: str) -> None:
    """The device error text always names the Win32 code and adds the elevation hint only for code 5.

    Args:
        code: Win32 error code to describe.
        expected: Exact message the bridge must build.
    """
    describe = cast("Callable[[str, int], str]", getattr(ProcessBridge, "_describe_win32_device_error"))
    assert describe("Device open failed", code) == expected


def test_pipe_connect_to_absent_pipe_raises(live_bridge: ProcessBridge) -> None:
    """Connecting to a pipe nobody created fails and leaves no tracked handle.

    Args:
        live_bridge: Initialized bridge.
    """
    name = rf"\\.\pipe\critcov_process_03_absent_{uuid.uuid4().hex}"
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.pipe_connect(name, 50))
    assert excinfo.value.message == "pipe connect failed"
    assert live_bridge.pipe_handles == {}


def test_pipe_read_on_write_only_handle_raises(live_bridge: ProcessBridge, tmp_path: Path) -> None:
    """Reading through a handle that was opened write-only is reported as a failed read.

    Args:
        live_bridge: Initialized bridge.
        tmp_path: Directory that receives the scratch file.
    """
    fd = os.open(tmp_path / "write_only.bin", os.O_WRONLY | os.O_CREAT | os.O_BINARY)
    try:
        handle = msvcrt.get_osfhandle(fd)
        with pytest.raises(ToolError) as excinfo:
            _run(live_bridge.pipe_read(handle, 16))
    finally:
        os.close(fd)
    assert excinfo.value.message == "memory read failed"


def test_pipe_write_on_read_only_handle_raises(live_bridge: ProcessBridge, tmp_path: Path) -> None:
    """Writing through a handle that was opened read-only is reported as a failed write.

    Args:
        live_bridge: Initialized bridge.
        tmp_path: Directory that receives the scratch file.
    """
    target = tmp_path / "read_only.bin"
    target.write_bytes(b"x")
    fd = os.open(target, os.O_RDONLY | os.O_BINARY)
    try:
        handle = msvcrt.get_osfhandle(fd)
        with pytest.raises(ToolError) as excinfo:
            _run(live_bridge.pipe_write(handle, b"abcd"))
    finally:
        os.close(fd)
    assert excinfo.value.message == "memory write failed"
    assert target.read_bytes() == b"x"


@pytest.mark.parametrize("input_data", [None, ""], ids=["no_input_buffer", "empty_hex_input"])
def test_device_ioctl_marks_an_opened_file_sparse(live_bridge: ProcessBridge, tmp_path: Path, input_data: str | None) -> None:
    """FSCTL_SET_SPARSE sent through an opened file handle makes the file sparse and returns no output bytes.

    The expectation comes from the file attributes the operating system reports afterwards, read through
    ``os.stat`` after the handle was closed.

    Args:
        live_bridge: Initialized bridge.
        tmp_path: Directory that receives the scratch file.
        input_data: Hex input passed to the call.
    """
    target = tmp_path / "sparse_target.bin"
    target.write_bytes(b"x")
    assert target.stat().st_file_attributes & stat.FILE_ATTRIBUTE_SPARSE_FILE == 0
    handle = _run(live_bridge.device_open(str(target)))
    try:
        output = _run(live_bridge.device_ioctl(handle, _FSCTL_SET_SPARSE, input_data, 0))
    finally:
        _run(live_bridge.device_close(handle))
    assert len(output) == 0
    assert target.stat().st_file_attributes & stat.FILE_ATTRIBUTE_SPARSE_FILE == stat.FILE_ATTRIBUTE_SPARSE_FILE


def test_device_ioctl_on_invalid_handle_reports_the_win32_error(live_bridge: ProcessBridge) -> None:
    """A failing DeviceIoControl carries the real Win32 error in both the code and the message.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.device_ioctl(_BOGUS_HANDLE, _FSCTL_SET_SPARSE, None, 16))
    assert excinfo.value.error_code == _ERROR_INVALID_HANDLE
    assert excinfo.value.message == "DeviceIoControl failed (Win32 error 6)"


def test_detect_dotnet_absent_pid_reports_native_process(live_bridge: ProcessBridge) -> None:
    """A pid with no modules and no openable process is reported as native with no runtime DLLs.

    Args:
        live_bridge: Initialized bridge.
    """
    result = _run(live_bridge.detect_dotnet(_ABSENT_PID))
    assert result == {
        "managed": False,
        "version": None,
        "clr_loaded": False,
        "clr_version": None,
        "runtime_dlls": [],
    }


@pytest.mark.parametrize(("names", "expected"), _DOTNET_HEURISTICS, ids=["+".join(entry[0]) for entry in _DOTNET_HEURISTICS])
def test_detect_dotnet_names_runtime_from_loaded_clr_dlls(
    live_bridge: ProcessBridge,
    child_host: ChildHost,
    tmp_path: Path,
    names: tuple[str, ...],
    expected: str,
) -> None:
    """Native modules named like CLR runtime DLLs make the bridge fall back to the DLL-name heuristic.

    The child loads copies of a small system DLL under the CLR names, so the module list contains those names while
    no module has a COM descriptor.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child that loads the decoy DLLs.
        tmp_path: Directory that receives the decoy DLL copies.
        names: File names the decoy DLLs are staged under.
        expected: Version string the heuristic must report.
    """
    paths = [_stage_decoy_dll(tmp_path, name) for name in names]
    child, _ = child_host.start(_DLL_LOADER_SOURCE, *paths)
    result = _run(live_bridge.detect_dotnet(child.pid))
    assert result["managed"] is True
    assert result["clr_loaded"] is True
    assert result["version"] == expected
    assert result["clr_version"] == expected
    assert sorted(cast("list[str]", result["runtime_dlls"])) == sorted(names)


def test_detect_dotnet_reads_metadata_version_of_real_managed_process(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A running Windows PowerShell host is reported with the CLR 4 metadata version string.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the PowerShell child.
    """
    child, _ = child_host.start_command([str(_POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", _POWERSHELL_SCRIPT])
    result = _run(live_bridge.detect_dotnet(child.pid))
    assert result["managed"] is True
    assert result["version"] == "v4.0.30319"


@pytest.mark.parametrize(
    "data",
    [bytes(0x100), _dos_only(0xFFFF)],
    ids=["zero_e_lfanew", "e_lfanew_beyond_buffer"],
)
def test_parse_pe_com_descriptor_rejects_unusable_nt_offset(data: bytes) -> None:
    """A DOS header whose NT-header pointer is zero or outside the buffer has no COM descriptor.

    Args:
        data: Image bytes to parse.
    """
    parse = cast("Callable[[bytes], object]", getattr(ProcessBridge, "_parse_pe_com_descriptor"))
    assert parse(data) is None


def test_parse_pe_com_descriptor_rejects_wrong_signature() -> None:
    """Bytes at the NT offset that are not the PE signature mean the image has no COM descriptor."""
    data = _pe_headers(com_rva=0x200, com_size=72)
    data[_NT_OFFSET : _NT_OFFSET + 4] = b"NE\x00\x00"
    parse = cast("Callable[[bytes], object]", getattr(ProcessBridge, "_parse_pe_com_descriptor"))
    assert parse(bytes(data)) is None


def test_parse_pe_com_descriptor_rejects_buffer_that_ends_before_the_directory() -> None:
    """A buffer too short to hold data directory entry 14 has no COM descriptor."""
    data = _pe_headers(com_rva=0x200, com_size=72)
    parse = cast("Callable[[bytes], object]", getattr(ProcessBridge, "_parse_pe_com_descriptor"))
    assert parse(bytes(data[:0x100])) is None


@pytest.mark.parametrize(("com_rva", "com_size"), [(0, 72), (0x200, 0)], ids=["zero_rva", "zero_size"])
def test_parse_pe_com_descriptor_rejects_empty_directory_entry(com_rva: int, com_size: int) -> None:
    """A COM descriptor entry with a zero RVA or a zero size marks a native image.

    Args:
        com_rva: RVA stored in the directory entry.
        com_size: Size stored in the directory entry.
    """
    data = _pe_headers(com_rva=com_rva, com_size=com_size)
    parse = cast("Callable[[bytes], object]", getattr(ProcessBridge, "_parse_pe_com_descriptor"))
    assert parse(bytes(data)) is None


def test_parse_pe_com_descriptor_returns_rva_and_section_table() -> None:
    """A managed image yields its COM descriptor RVA and every section header in table order."""
    sections = ((0x300, 0x1000, 0x200, 0x400), (0x100, 0x2000, 0x100, 0x600))
    data = _pe_headers(com_rva=0x1234, com_size=72, sections=sections)
    parse = cast("Callable[[bytes], tuple[int, list[dict[str, int | str]]] | None]", getattr(ProcessBridge, "_parse_pe_com_descriptor"))
    parsed = parse(bytes(data))
    assert parsed is not None
    com_rva, parsed_sections = parsed
    assert com_rva == 0x1234
    assert [
        (entry["name"], entry["virtual_size"], entry["virtual_address"], entry["raw_size"], entry["raw_offset"])
        for entry in parsed_sections
    ] == [
        (".text", 0x300, 0x1000, 0x200, 0x400),
        (".text", 0x100, 0x2000, 0x100, 0x600),
    ]


@pytest.mark.parametrize(
    ("signature", "version", "declared_length", "expected"),
    _METADATA_VERSION_CASES,
    ids=[
        "valid",
        "longest_allowed_length",
        "bad_signature",
        "zero_length",
        "length_over_limit",
        "trailing_space_stripped",
        "non_ascii_replaced",
        "all_nul_is_empty",
    ],
)
def test_parse_dotnet_metadata_version_string(signature: int, version: bytes, declared_length: int, expected: str | None) -> None:
    """The metadata root parser validates the signature and length and decodes the NUL-terminated version.

    Args:
        signature: ``Signature`` field of the metadata root.
        version: Bytes stored at offset 16.
        declared_length: ``Length`` field of the metadata root.
        expected: Version string the parser must return, or ``None`` when the root is rejected.
    """
    parse = cast("Callable[[bytes], str | None]", getattr(ProcessBridge, "_parse_dotnet_metadata_version_string"))
    assert parse(_metadata_root(signature=signature, version=version, declared_length=declared_length)) == expected


def _read_cor20(bridge: ProcessBridge, child_host: ChildHost, image: bytes, *, offset: int = 0) -> str | None:
    """Place ``image`` in a child's memory and run ``_read_cor20_version`` against it through a real process handle.

    Args:
        bridge: Initialized bridge that opens the child.
        child_host: Starts the child holding the image.
        image: PE image bytes copied to the start of the child's region.
        offset: Offset added to the region base before reading.

    Returns:
        str | None: Whatever ``_read_cor20_version`` returned.
    """
    child, base = child_host.start_image(image)
    _run(bridge.open_process(child.pid, "read"))
    try:
        handle = bridge.process_handle
        assert handle is not None
        return cast("str | None", method(bridge, "_read_cor20_version")(handle, base + offset))
    finally:
        _run(bridge.close())


def test_read_cor20_version_resolves_metadata_without_a_section_table(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """The metadata version of an image in another process is read when the section table does not cover the metadata RVA.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    assert _read_cor20(live_bridge, child_host, _managed_image()) == "v4.0.30319"


def test_read_cor20_version_resolves_metadata_covered_by_an_identity_section(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A section whose virtual address equals its raw offset gives the same metadata location either way.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    image = _managed_image(sections=((0x200, 0x200, 0x200, 0x200),))
    assert _read_cor20(live_bridge, child_host, image) == "v4.0.30319"


def test_read_cor20_version_reads_metadata_at_its_rva_in_a_loader_mapped_image(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A loaded image keeps its metadata at ``base + RVA`` even when the section's raw offset differs.

    The bytes of a process are the loader-mapped image, where every RVA is a plain offset from the base.
    The section header places the metadata RVA 0x300 at raw offset 0x200, which must not move the read.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    image = _managed_image(sections=((0x100, 0x300, 0x100, 0x200),))
    assert _read_cor20(live_bridge, child_host, image) == "v4.0.30319"


def test_read_cor20_version_reports_unreadable_headers(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A module base whose memory cannot be read has no version.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    assert _read_cor20(live_bridge, child_host, _managed_image(), offset=_PAGE_SIZE) is None


def test_read_cor20_version_reports_unreadable_cor20_header(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A COR20 header that runs into inaccessible memory gives no version.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    assert _read_cor20(live_bridge, child_host, _managed_image(com_rva=_PAGE_SIZE - 8)) is None


def test_read_cor20_version_reports_zero_metadata_rva(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A COR20 header without a MetaData directory gives no version.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    assert _read_cor20(live_bridge, child_host, _managed_image(meta_rva=0)) is None


def test_read_cor20_version_reports_unreadable_metadata(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A MetaData directory that points into inaccessible memory gives no version.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    assert _read_cor20(live_bridge, child_host, _managed_image(meta_rva=_PAGE_SIZE)) is None


def test_read_cor20_version_treats_an_empty_version_string_as_missing(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A metadata root whose version string is all NUL bytes gives no version.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child holding the image.
    """
    assert _read_cor20(live_bridge, child_host, _managed_image(version=b"\x00\x00\x00\x00")) is None


def test_get_job_info_reports_limits_of_the_childs_job(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """A process that owns a job handle exposes that job's limits through the duplicated handle.

    The child creates a job with an active-process limit and process and job memory limits, assigns itself to it
    and holds the handle; the expected values are the ones the child wrote through raw bytes.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child that owns the job.
    """
    child, _ = child_host.start(_JOB_SOURCE)
    result = _run(live_bridge.get_job_info(child.pid))
    assert result["in_job"] is True
    basic = cast("dict[str, int]", result["basic_limits"])
    assert basic["active_process_limit"] == _JOB_ACTIVE_PROCESS_LIMIT
    assert basic["limit_flags"] & _JOB_FLAGS == _JOB_FLAGS
    extended = cast("dict[str, object]", result["extended_limits"])
    assert extended["process_memory_limit"] == _JOB_PROCESS_MEMORY_LIMIT
    assert extended["job_memory_limit"] == _JOB_MEMORY_LIMIT
    assert cast("dict[str, int]", extended["basic_limits"])["active_process_limit"] == _JOB_ACTIVE_PROCESS_LIMIT
    counters = cast("dict[str, int]", result["io_counters"])
    assert set(counters) == {
        "read_operation_count",
        "write_operation_count",
        "other_operation_count",
        "read_transfer_count",
        "write_transfer_count",
        "other_transfer_count",
    }
    assert all(value >= 0 for value in counters.values())


def test_get_job_info_for_absent_pid_raises(live_bridge: ProcessBridge) -> None:
    """Querying a pid that cannot be opened is reported as an open failure.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.get_job_info(_ABSENT_PID))
    assert excinfo.value.message == "process open failed"


def test_read_job_information_with_invalid_job_handle_returns_empty(live_bridge: ProcessBridge) -> None:
    """Both limit queries failing leaves the result empty instead of raising.

    Args:
        live_bridge: Initialized bridge.
    """
    assert method(live_bridge, "_read_job_information")(_BOGUS_HANDLE) == {}


def test_read_job_information_without_query_export_returns_empty() -> None:
    """A kernel32 reference that does not export QueryInformationJobObject yields an empty result."""
    bridge = ProcessBridge()
    set_priv(bridge, "_kernel32", ctypes.WinDLL("version"))
    assert method(bridge, "_read_job_information")(1) == {}


def test_job_helpers_without_their_kernel32_exports_return_defaults() -> None:
    """A kernel32 reference missing GetProcessId, OpenProcess and friends yields the documented defaults."""
    bridge = ProcessBridge()
    set_priv(bridge, "_kernel32", ctypes.WinDLL("version"))
    assert method(bridge, "_get_target_pid_for_handle")(1) == 0
    assert method(bridge, "_duplicate_job_handle_from_target")(1, {1}) is None


def test_acquire_job_handle_for_invalid_process_handle_returns_none(live_bridge: ProcessBridge) -> None:
    """A process handle that GetProcessId rejects has no job handle to acquire.

    Args:
        live_bridge: Initialized bridge.
    """
    assert method(live_bridge, "_get_target_pid_for_handle")(_BOGUS_HANDLE) == 0
    assert method(live_bridge, "_acquire_queryable_job_handle")(_BOGUS_HANDLE) is None


def test_acquire_job_handle_without_a_job_object_type_returns_none(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """When the object-type map names no ``Job`` type there is no handle to duplicate.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child whose process handle is queried.
    """
    child, _ = child_host.start(_BLOCKER_SOURCE)
    _run(live_bridge.open_process(child.pid, "query"))
    try:
        handle = live_bridge.process_handle
        assert handle is not None
        assert method(live_bridge, "_get_target_pid_for_handle")(handle) == child.pid
        set_priv(live_bridge, "_handle_type_cache", {2: "File", 3: "Event"})
        assert method(live_bridge, "_acquire_queryable_job_handle")(handle) is None
    finally:
        _run(live_bridge.close())


def test_duplicate_job_handle_without_ntdll_returns_none(live_bridge: ProcessBridge) -> None:
    """A failing system handle query is logged and reported as no handle.

    Args:
        live_bridge: Initialized bridge.
    """
    set_priv(live_bridge, "_ntdll", None)
    assert method(live_bridge, "_duplicate_job_handle_from_target")(1, {1}) is None


def test_duplicate_job_handle_from_unopenable_process_returns_none(live_bridge: ProcessBridge) -> None:
    """A target process that cannot be opened for handle duplication yields no handle.

    Args:
        live_bridge: Initialized bridge.
    """
    assert method(live_bridge, "_duplicate_job_handle_from_target")(_ABSENT_PID, {1}) is None


def test_scan_handles_ignores_foreign_untyped_and_unduplicable_entries(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """Only entries of the target pid, with a job type index and a usable handle value, are duplicated.

    Every entry would duplicate successfully if it were not filtered out, except the last, which names a handle the
    child does not own, so the scan must return ``None``.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child that owns a real job handle.
    """
    child, tokens = child_host.start(_JOB_SOURCE)
    job_handle = int(tokens[0])
    job_type = 7
    entries = [
        (child.pid + 4, job_type, job_handle),
        (child.pid, job_type + 1, job_handle),
        (child.pid, job_type, 0),
        (child.pid, job_type, _UNOWNED_HANDLE_VALUE),
    ]
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    header_size = 2 * ctypes.sizeof(ctypes.c_void_p)
    buffer = ctypes.create_string_buffer(header_size + len(entries) * entry_size)
    for index, (pid, type_index, value) in enumerate(entries):
        entry = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.from_buffer(buffer, header_size + index * entry_size)
        entry.UniqueProcessId = pid
        entry.ObjectTypeIndex = type_index
        entry.HandleValue = value
    oracle = _kernel32_oracle()
    _run(live_bridge.open_process(child.pid, "all"))
    try:
        process_handle = live_bridge.process_handle
        assert process_handle is not None
        scan = method(live_bridge, "_scan_handles_for_duplicate")
        result = scan(buffer, len(entries), entry_size, child.pid, {job_type}, process_handle, oracle.DuplicateHandle)
    finally:
        _run(live_bridge.close())
    if isinstance(result, int):
        oracle.CloseHandle(result)
    assert result is None


def test_job_limit_converters_copy_every_field() -> None:
    """The structure-to-dict converters map each native field to its own key."""
    basic = JOBOBJECT_BASIC_LIMIT_INFORMATION()
    basic.PerProcessUserTimeLimit = 11
    basic.PerJobUserTimeLimit = 12
    basic.LimitFlags = 13
    basic.MinimumWorkingSetSize = 14
    basic.MaximumWorkingSetSize = 15
    basic.ActiveProcessLimit = 16
    basic.Affinity = 17
    basic.PriorityClass = 18
    basic.SchedulingClass = 19
    expected_basic = {
        "per_process_user_time_limit": 11,
        "per_job_user_time_limit": 12,
        "limit_flags": 13,
        "minimum_working_set_size": 14,
        "maximum_working_set_size": 15,
        "active_process_limit": 16,
        "affinity": 17,
        "priority_class": 18,
        "scheduling_class": 19,
    }
    extended = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    extended.BasicLimitInformation = basic
    extended.ProcessMemoryLimit = 21
    extended.JobMemoryLimit = 22
    extended.PeakProcessMemoryUsed = 23
    extended.PeakJobMemoryUsed = 24
    counters = IO_COUNTERS()
    counters.ReadOperationCount = 31
    counters.WriteOperationCount = 32
    counters.OtherOperationCount = 33
    counters.ReadTransferCount = 34
    counters.WriteTransferCount = 35
    counters.OtherTransferCount = 36
    assert method(ProcessBridge, "_basic_limit_to_dict")(basic) == expected_basic
    assert method(ProcessBridge, "_extended_limit_to_dict")(extended) == {
        "basic_limits": expected_basic,
        "process_memory_limit": 21,
        "job_memory_limit": 22,
        "peak_process_memory_used": 23,
        "peak_job_memory_used": 24,
    }
    assert method(ProcessBridge, "_io_counters_to_dict")(counters) == {
        "read_operation_count": 31,
        "write_operation_count": 32,
        "other_operation_count": 33,
        "read_transfer_count": 34,
        "write_transfer_count": 35,
        "other_transfer_count": 36,
    }


def test_get_gui_resources_for_child_matches_independent_user32_counts(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """The GDI and USER counts of a child equal what a separate ``GetGuiResources`` reports for it.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child that is inspected.
    """
    child, _ = child_host.start(_BLOCKER_SOURCE)
    gdi_objects, user_objects = _oracle_gui_counts(child.pid)
    assert _run(live_bridge.get_gui_resources(child.pid)) == {"gdi_objects": gdi_objects, "user_objects": user_objects}


def test_get_gui_resources_for_absent_pid_raises(live_bridge: ProcessBridge) -> None:
    """Counting GUI objects of a pid that cannot be opened is reported as an open failure.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.get_gui_resources(_ABSENT_PID))
    assert excinfo.value.message == "process open failed"


def test_reg_read_value_decodes_dword_and_qword(live_bridge: ProcessBridge, registry_key: str) -> None:
    """DWORD and QWORD registry values are returned as unsigned integers of the value that was written.

    Args:
        live_bridge: Initialized bridge.
        registry_key: Path of a key holding both values.
    """
    assert _run(live_bridge.reg_read_value(registry_key, "dword_value")) == {"type": "dword", "data": 0xDEADBEEF}
    assert _run(live_bridge.reg_read_value(registry_key, "qword_value")) == {"type": "qword", "data": 0x0123456789ABCDEF}


@pytest.mark.parametrize("operation", ["reg_enum_keys", "reg_enum_values"])
def test_reg_enumeration_of_absent_key_raises(live_bridge: ProcessBridge, registry_key: str, operation: str) -> None:
    """Enumerating a key that does not exist names the key in the error.

    Args:
        live_bridge: Initialized bridge.
        registry_key: Path of an existing key, used to derive an absent sibling.
        operation: Name of the enumeration coroutine under test.
    """
    absent = registry_key + "_absent"
    with pytest.raises(ToolError) as excinfo:
        _run(async_method(live_bridge, operation)(absent))
    assert excinfo.value.message == "registry key open failed: " + absent


def test_create_section_with_zero_size_reports_creation_failure(live_bridge: ProcessBridge) -> None:
    """A pagefile-backed mapping needs a non-zero size, so a zero-size request fails and is not tracked.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.create_section(0))
    error = excinfo.value
    assert error.message == "section creation failed"
    assert error.details["code"] == "SECTION_CREATE_FAILED"
    assert error.error_code is not None
    assert error.error_code > 0
    assert error.details["last_error"] == error.error_code
    assert live_bridge.section_handles == {}


def test_map_section_of_invalid_handle_reports_mapping_failure(live_bridge: ProcessBridge) -> None:
    """Mapping a handle that is not a section fails and tracks no view.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.map_section(_BOGUS_HANDLE, _PAGE_SIZE))
    assert excinfo.value.message == "section mapping failed"
    assert live_bridge.section_views == {}


def test_get_tls_values_without_attached_process_returns_empty(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """When the TLS array cannot be read because nothing is attached, the result is an empty list.

    Args:
        live_bridge: Initialized bridge that is not attached.
        child_host: Starts the child whose thread is inspected.
    """
    _, tokens = child_host.start(_TLS_SOURCE)
    assert _run(live_bridge.get_tls_values(int(tokens[0]))) == []


def test_get_tls_values_follows_the_expansion_array_for_high_indexes(live_bridge: ProcessBridge, child_host: ChildHost) -> None:
    """TLS indexes beyond the 64 static slots are read through the TEB expansion pointer.

    The child allocates 80 TLS indexes and stores a distinct value in each; the expected index/value pairs are the
    ones it printed.

    Args:
        live_bridge: Initialized bridge.
        child_host: Starts the child that owns the TLS slots.
    """
    child, tokens = child_host.start(_TLS_SOURCE)
    expected = {int(index): int(value) for index, value in (pair.split(":") for pair in tokens[1].split(","))}
    expected_expansion = {index: value for index, value in expected.items() if index >= _STATIC_TLS_SLOTS}
    assert expected_expansion
    _run(live_bridge.open_process(child.pid, "read"))
    try:
        slots = _run(live_bridge.get_tls_values(int(tokens[0])))
    finally:
        _run(live_bridge.close())
    actual = {cast("int", slot["index"]): cast("int", slot["value"]) for slot in slots}
    assert {index: value for index, value in actual.items() if index >= _STATIC_TLS_SLOTS} == expected_expansion
    assert all(actual[index] == value for index, value in expected.items() if index < _STATIC_TLS_SLOTS)


def test_query_system_info_rejects_initial_buffer_over_the_limit(live_bridge: ProcessBridge) -> None:
    """An initial buffer above the maximum is refused before any allocation.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.query_system_info(0, 0x40000001))
    assert excinfo.value.message == "NtQuerySystemInformation buffer exceeded maximum size"


def test_query_system_info_reports_the_ntstatus_of_an_invalid_class(live_bridge: ProcessBridge) -> None:
    """An information class the kernel does not know fails with the error NTSTATUS in the message.

    Args:
        live_bridge: Initialized bridge.
    """
    with pytest.raises(ToolError) as excinfo:
        _run(live_bridge.query_system_info(0x7FFF, 64))
    assert re.fullmatch(r"NtQuerySystemInformation failed: 0xC[0-9A-F]{7}", excinfo.value.message)


def test_shutdown_survives_a_view_that_can_no_longer_be_unmapped(live_bridge: ProcessBridge) -> None:
    """A tracked view that was unmapped behind the bridge's back does not abort shutdown.

    Args:
        live_bridge: Initialized bridge.
    """
    handle = _run(live_bridge.create_section(_PAGE_SIZE))
    address = _run(live_bridge.map_section(handle, _PAGE_SIZE))
    assert _kernel32_oracle().UnmapViewOfFile(ctypes.c_void_p(address))
    _run(live_bridge.shutdown())
    assert live_bridge.section_views == {}
    assert live_bridge.section_handles == {}
    assert live_bridge.kernel32 is None


def test_shutdown_without_close_handle_export_still_clears_tracking() -> None:
    """A kernel32 reference that cannot close handles does not stop shutdown from clearing its tracking tables."""
    bridge = ProcessBridge()
    set_priv(bridge, "_kernel32", ctypes.WinDLL("version"))
    bridge.pipe_handles[0x1234] = r"\\.\pipe\critcov_unused"
    bridge.device_handles[0x5678] = r"\\.\critcov_unused"
    _run(bridge.shutdown())
    assert bridge.pipe_handles == {}
    assert bridge.device_handles == {}
    assert bridge.kernel32 is None
