# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Third-pass critical-coverage tests for the x64dbg bridge, built on facts measured in the test container.

Every expectation rests on a measurement or on an independent oracle:

* A 32-bit child from ``SysWOW64`` is a real WOW64 process: ``IsWow64Process2`` reports machine ``0x14C`` for it, so the bridge's
  pointer-size helper must answer 4, and a 64-bit child must answer 8.
* ``Thread32First`` and ``Process32FirstW`` return FALSE (error 6) for ``INVALID_HANDLE_VALUE`` and (error 24) for a structure whose size
  is not the documented one; the bridge must then report no threads and parent 0.
* A child that keeps loading and unloading DLLs makes a module snapshot fail with ``ERROR_BAD_LENGTH`` (24) in about 15 percent of the
  snapshots, so the bridge's retry loop runs for real.
* A region the bridge listed can be made unreadable by the child itself on a signal from the test, which makes the scan's chunk-failure
  handler deterministic.
* The optional disassembler, assembler and YARA imports are checked in real child interpreters in which the packages are made
  unimportable with ``sys.modules[name] = None``.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

import pytest

from intellicrack.bridges import x64dbg as x64dbg_module
from intellicrack.bridges.win32_types import (
    IMAGE_FILE_MACHINE_I386,
    INVALID_HANDLE_VALUE,
    PROCESS_QUERY_LIMITED_INFORMATION,
    TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD,
)
from intellicrack.bridges.x64dbg import X64DbgBridge
from tests._helpers.child_python import run_child_json


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator

    from intellicrack.bridges.base import MemorySearchResult


pytestmark = pytest.mark.spawns_process

_CHILD_TIMEOUT_SECONDS: Final[float] = 120.0
_REGION_SIZE: Final[int] = 0x400000
_STRADDLING_MARKER_OFFSET: Final[int] = 0x0FFFF8
_SECOND_MARKER_OFFSET: Final[int] = 0x200010
_MARKER: Final[bytes] = bytes(range(0xA0, 0xB0))
_MAX_RETRY_PROBES: Final[int] = 400

_STALE_REGION_CHILD: Final[str] = r"""
import ctypes, sys
from ctypes import wintypes
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.VirtualAlloc.restype = ctypes.c_void_p
k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k.VirtualProtect.restype = wintypes.BOOL
k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k.VirtualFree.restype = wintypes.BOOL
k.VirtualFree.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]
SIZE = 0x400000
addr = k.VirtualAlloc(None, SIZE, 0x3000, 0x04)
marker = bytes(range(0xA0, 0xB0))
ctypes.memmove(addr + 0x0FFFF8, marker, 16)
ctypes.memmove(addr + 0x200010, marker, 16)
print("ADDR", hex(addr), flush=True)
for line in sys.stdin:
    parts = line.split()
    if not parts:
        continue
    cmd = parts[0]
    ok = True
    if cmd == "protect_mid":
        old = wintypes.DWORD()
        ok = k.VirtualProtect(addr + 0x100000, 0x100000, 0x01, ctypes.byref(old))
    elif cmd == "protect_all":
        old = wintypes.DWORD()
        ok = k.VirtualProtect(addr, SIZE, 0x01, ctypes.byref(old))
    elif cmd == "free":
        ok = k.VirtualFree(addr, 0, 0x8000)
    elif cmd == "quit":
        break
    print("DONE", cmd, bool(ok), ctypes.get_last_error(), flush=True)
"""

_CHURN_CHILD: Final[str] = """
import ctypes, time
k = ctypes.WinDLL("kernel32", use_last_error=True)
k.LoadLibraryW.restype = ctypes.c_void_p
k.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
k.FreeLibrary.argtypes = [ctypes.c_void_p]
print("READY", flush=True)
names = ["winmm.dll", "wininet.dll", "dbghelp.dll", "wsock32.dll", "version.dll", "winspool.drv"]
end = time.time() + 120
while time.time() < end:
    for n in names:
        h = k.LoadLibraryW(n)
        if h:
            k.FreeLibrary(h)
"""

_IMPORT_CHILD: Final[str] = """
import json
import sys

for name in __BLOCKED__:
    sys.modules[name] = None

refused = {}
for name in ("capstone", "keystone", "yara"):
    try:
        __import__(name)
        refused[name] = False
    except ImportError:
        refused[name] = True

from intellicrack.bridges import x64dbg as module

print(json.dumps({
    "refused": refused,
    "capstone_is_none": module._capstone is None,
    "keystone_is_none": module._keystone is None,
    "yara_is_none": module._yara is None,
    "get_capstone_is_none": module.get_capstone() is None,
    "get_keystone_is_none": module.get_keystone() is None,
    "get_yara_is_none": module._get_yara() is None,
}))
"""


class _ThreadEntry32(ctypes.Structure):
    """Layout of the Win32 ``THREADENTRY32`` snapshot record (28 bytes)."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class _ShortThreadEntry(ctypes.Structure):
    """``THREADENTRY32`` cut after the owner process id (16 bytes), which ``Thread32First`` rejects with error 24."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
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


class _ShortProcessEntry(ctypes.Structure):
    """``PROCESSENTRY32W`` cut after the parent process id (40 bytes), which ``Process32FirstW`` rejects with error 24."""

    _fields_: ClassVar = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
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


def _typed_kernel32() -> ctypes.WinDLL:
    """Create a private ``kernel32`` binding with the entry points these tests use typed.

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
    kernel32.Thread32Next.restype = wintypes.BOOL
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.IsWow64Process2.restype = wintypes.BOOL
    kernel32.IsWow64Process2.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.USHORT),
        ctypes.POINTER(wintypes.USHORT),
    ]
    return kernel32


def _coverage_env() -> dict[str, str]:
    """Collect the coverage variables a child interpreter needs for its lines to be counted.

    Returns:
        dict[str, str]: Every environment variable whose name starts with ``COV``.
    """
    return {name: value for name, value in os.environ.items() if name.startswith("COV")}


def _command(child: subprocess.Popen[str], name: str) -> str:
    """Send one command to the region child and read its single reply line.

    Args:
        child: The running region child.
        name: Command word.

    Returns:
        str: The reply line without its newline.
    """
    assert child.stdin is not None
    assert child.stdout is not None
    child.stdin.write(f"{name}\n")
    child.stdin.flush()
    return child.stdout.readline().strip()


def _open_query_handle(kernel32: ctypes.WinDLL, pid: int) -> int:
    """Open a process with the limited-query right.

    Args:
        kernel32: Typed ``kernel32`` binding.
        pid: Process id to open.

    Returns:
        int: A non-zero process handle.
    """
    inherit_handle = False
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, inherit_handle, pid)
    assert handle
    return int(handle)


@pytest.fixture
def stale_region_child() -> Iterator[tuple[subprocess.Popen[str], int]]:
    """Start a 64-bit child that owns a 4 MB read-write region and changes it on command.

    Yields:
        tuple[subprocess.Popen[str], int]: The child and the base address of its region.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", _STALE_REGION_CHILD],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert child.stdout is not None
        banner = child.stdout.readline().split()
        assert banner[0] == "ADDR"
        yield child, int(banner[1], 16)
    finally:
        child.kill()
        child.wait(timeout=10)
        if child.stdin is not None:
            child.stdin.close()
        if child.stdout is not None:
            child.stdout.close()


@pytest.fixture
def churning_child() -> Iterator[subprocess.Popen[str]]:
    """Start a child that keeps loading and unloading DLLs so its module list keeps changing.

    Yields:
        subprocess.Popen[str]: The running child.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", _CHURN_CHILD],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "READY"
        yield child
    finally:
        child.kill()
        child.wait(timeout=10)
        if child.stdout is not None:
            child.stdout.close()


@pytest.fixture
def idle_process() -> Iterator[subprocess.Popen[bytes]]:
    """Start a real 64-bit child process that idles until it is killed.

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
def wow64_child() -> Iterator[subprocess.Popen[bytes]]:
    """Start a 32-bit child from ``SysWOW64`` that runs for about half a minute.

    Yields:
        subprocess.Popen[bytes]: The running 32-bit child.
    """
    ping = Path(os.environ["SYSTEMROOT"]) / "SysWOW64" / "ping.exe"
    process = subprocess.Popen(
        [str(ping), "-n", "30", "127.0.0.1"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield process
    finally:
        process.kill()
        process.wait(timeout=10)


@pytest.fixture(scope="module")
def all_blocked_state() -> dict[str, Any]:
    """Import the bridge module in a child where capstone, keystone and yara cannot be imported.

    Returns:
        dict[str, Any]: The JSON state the child printed.
    """
    code = _IMPORT_CHILD.replace("__BLOCKED__", repr(["capstone", "keystone", "yara"]))
    return run_child_json(code, timeout_s=_CHILD_TIMEOUT_SECONDS, extra_env=_coverage_env())


@pytest.fixture(scope="module")
def yara_blocked_state() -> dict[str, Any]:
    """Import the bridge module in a child where only yara cannot be imported.

    Returns:
        dict[str, Any]: The JSON state the child printed.
    """
    code = _IMPORT_CHILD.replace("__BLOCKED__", repr(["yara"]))
    return run_child_json(code, timeout_s=_CHILD_TIMEOUT_SECONDS, extra_env=_coverage_env())


def test_pointer_size_is_four_for_a_32_bit_child_and_eight_for_a_64_bit_child(
    wow64_child: subprocess.Popen[bytes],
    idle_process: subprocess.Popen[bytes],
) -> None:
    """A WOW64 target has 4-byte pointers; a native 64-bit target has 8-byte pointers.

    The oracle is ``IsWow64Process2``, which reports the 32-bit child's machine as ``IMAGE_FILE_MACHINE_I386``.

    Probe key: ``wow64_run_ping.exe`` (``IsWow64Process2`` machine ``0x14c``, ``product_pointer_size`` 4).

    One-line change that fails it: change ``return POINTER_SIZE_32`` to ``return POINTER_SIZE_64`` at x64dbg.py:819.

    Args:
        wow64_child: Running 32-bit child.
        idle_process: Running 64-bit child.
    """
    assert wow64_child.poll() is None
    kernel32 = _typed_kernel32()
    pointer_size = _sync_method(x64dbg_module, "_get_process_pointer_size")
    wow_handle = _open_query_handle(kernel32, wow64_child.pid)
    native_handle = _open_query_handle(kernel32, idle_process.pid)
    try:
        process_machine = wintypes.USHORT()
        native_machine = wintypes.USHORT()
        assert kernel32.IsWow64Process2(wow_handle, ctypes.byref(process_machine), ctypes.byref(native_machine))
        assert process_machine.value == IMAGE_FILE_MACHINE_I386

        assert pointer_size(wow_handle) == 4
        assert pointer_size(native_handle) == ctypes.sizeof(ctypes.c_void_p)
    finally:
        kernel32.CloseHandle(wow_handle)
        kernel32.CloseHandle(native_handle)


def test_thread_enumeration_lists_nothing_for_an_invalid_snapshot_handle() -> None:
    """``Thread32First`` fails for ``INVALID_HANDLE_VALUE``, so no thread is listed.

    The bridge is attached to pid 0 on purpose: a zeroed entry has owner pid 0, so an enumeration that ignored the failed first call would
    list one phantom thread.

    Probe key: ``th_first_invalid_handle_value`` (``ret`` false, ``last_error`` 6) and ``product_thread_enum_closed_snapshot``.

    One-line change that fails it: replace the ``return`` at x64dbg.py:5898 with ``pass``.
    """
    bridge = X64DbgBridge()
    bridge.attached_pid = 0
    threads: list[Any] = []

    _sync_method(bridge, "_enumerate_attached_threads")(_typed_kernel32(), INVALID_HANDLE_VALUE, _ThreadEntry32, threads)

    assert threads == []


def test_thread_enumeration_lists_nothing_when_the_entry_structure_has_the_wrong_size() -> None:
    """``Thread32First`` rejects an entry whose ``dwSize`` is not the documented one (error 24), so no thread is listed.

    The same snapshot is first walked directly with the documented structure size: ``Thread32First`` succeeds and the walk finds this
    test's own native thread id under this process id, which shows the snapshot is good and only the structure size differs.

    Probe key: ``th_first_valid_struct_ThreadEntryShort`` (``ret`` false, ``last_error`` 24) and ``product_thread_enum_short_struct``.

    One-line change that fails it: replace the ``return`` at x64dbg.py:5898 with ``pass``.
    """
    kernel32 = _typed_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPPROCESS, 0)
    assert snapshot != INVALID_HANDLE_VALUE
    try:
        full = _ThreadEntry32()
        full.dwSize = ctypes.sizeof(_ThreadEntry32)
        assert kernel32.Thread32First(snapshot, ctypes.byref(full))
        own_thread_seen = False
        while True:
            if full.th32OwnerProcessID == os.getpid() and full.th32ThreadID == threading.get_native_id():
                own_thread_seen = True
                break
            if not kernel32.Thread32Next(snapshot, ctypes.byref(full)):
                break
        assert own_thread_seen

        bridge = X64DbgBridge()
        bridge.attached_pid = 0
        threads: list[Any] = []
        _sync_method(bridge, "_enumerate_attached_threads")(kernel32, snapshot, _ShortThreadEntry, threads)
    finally:
        kernel32.CloseHandle(snapshot)

    assert threads == []


def test_parent_pid_lookup_is_zero_for_an_invalid_snapshot_handle() -> None:
    """``Process32FirstW`` fails for ``INVALID_HANDLE_VALUE``, so the lookup answers 0 instead of the real parent.

    The same call on a valid snapshot returns ``os.getppid()``, which shows the 0 is the failure answer and not the true value.

    Probe key: ``ps_first_invalid_handle_value`` (``ret`` false, ``last_error`` 6), ``product_parent_lookup_closed_snapshot`` (0) and
    ``product_parent_lookup_valid_control``.

    One-line change that fails it: change ``return 0`` to ``return -1`` at x64dbg.py:6504.
    """
    kernel32 = _typed_kernel32()
    lookup = _sync_method(X64DbgBridge, "_find_parent_pid_in_snapshot")
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    assert snapshot != INVALID_HANDLE_VALUE
    try:
        assert lookup(kernel32, snapshot, _ProcessEntry32W, os.getpid()) == os.getppid()
    finally:
        kernel32.CloseHandle(snapshot)

    assert lookup(kernel32, INVALID_HANDLE_VALUE, _ProcessEntry32W, os.getpid()) == 0


def test_parent_pid_lookup_is_zero_when_the_entry_structure_has_the_wrong_size() -> None:
    """``Process32FirstW`` rejects an entry whose ``dwSize`` is not the documented one (error 24), so the lookup answers 0.

    Probe key: ``ps_first_valid_struct_ProcEntryShort`` (``ret`` false, ``last_error`` 24) and ``product_parent_lookup_short_struct`` (0).

    One-line change that fails it: change ``return 0`` to ``return -1`` at x64dbg.py:6504.
    """
    kernel32 = _typed_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    assert snapshot != INVALID_HANDLE_VALUE
    try:
        result = _sync_method(X64DbgBridge, "_find_parent_pid_in_snapshot")(kernel32, snapshot, _ShortProcessEntry, os.getpid())
    finally:
        kernel32.CloseHandle(snapshot)

    assert result == 0


@pytest.mark.asyncio
async def test_module_snapshot_is_retried_while_the_target_changes_its_module_list(churning_child: subprocess.Popen[str]) -> None:
    """A module snapshot that fails with ``ERROR_BAD_LENGTH`` is retried after a delay and then succeeds.

    The child loads and unloads DLLs without pause, which made 92 of 600 snapshots fail with error 24 in the probe. The product call is
    repeated until one call has waited out at least half the retry delay; every call must still return a valid snapshot, because a
    transient failure is retried. The chance that 400 consecutive calls see no failure is below 1e-27 at the measured rate.

    Probe key: ``modsnap_dll_churn_child`` (histogram ``{"24": 92, "ok": 508}``).

    One-line change that fails it: change ``error_code != _ERROR_BAD_LENGTH`` to ``True`` at x64dbg.py:6157 (error 24 then raises at once).

    Args:
        churning_child: Child whose module list keeps changing.
    """
    kernel32 = _typed_kernel32()
    create_snapshot = _async_method(X64DbgBridge, "_create_module_snapshot_with_retry")
    delay = float(getattr(x64dbg_module, "_TOOLHELP_MODULE_SNAPSHOT_RETRY_DELAY"))
    retried = False
    for _ in range(_MAX_RETRY_PROBES):
        started = time.perf_counter()
        snapshot = await create_snapshot(kernel32, churning_child.pid)
        elapsed = time.perf_counter() - started
        assert snapshot
        assert snapshot != INVALID_HANDLE_VALUE
        kernel32.CloseHandle(snapshot)
        if elapsed >= delay / 2:
            retried = True
            break

    assert retried


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("action", "surviving_offsets"),
    [
        ("protect_mid", [_SECOND_MARKER_OFFSET]),
        ("protect_all", []),
        ("free", []),
    ],
)
async def test_scan_skips_chunks_of_a_region_that_became_unreadable_after_it_was_listed(
    stale_region_child: tuple[subprocess.Popen[str], int],
    action: str,
    surviving_offsets: list[int],
) -> None:
    """A chunk that cannot be read is skipped, the carried tail is dropped, and later chunks are still scanned at the right addresses.

    The child owns a 4 MB read-write region (four 1 MB chunks) with a 16-byte marker straddling the first chunk boundary and another in
    the third chunk. The bridge lists the region, the child then makes part or all of it unreadable on a signal from the test, and the
    scan runs on the stale region record. Before the change both markers are found at the offsets the child wrote; afterwards the
    straddling marker is lost (its second half is in the unreadable chunk) and a marker in a still-readable chunk is reported at its
    true address, not shifted by the dropped tail.

    Probe key: ``scan_stale_protect_mid``, ``scan_stale_protect_all``, ``scan_stale_free``.

    One-line change that fails it: delete ``carry = b""`` at x64dbg.py:5697 (the third chunk's marker is then reported 15 bytes off).

    Args:
        stale_region_child: The child and the base address of its region.
        action: Command that makes the region unreadable.
        surviving_offsets: Offsets (from the region base) of the markers that must still be found.
    """
    child, base = stale_region_child
    bridge = X64DbgBridge()
    bridge.attached_pid = child.pid
    scan = _async_method(bridge, "_scan_region_chunks")
    try:
        regions = await bridge.get_memory_regions()
        region = next(r for r in regions if r.base_address == base)
        assert region.size == _REGION_SIZE
        assert region.protection == "rw-"

        before: list[MemorySearchResult] = []
        await scan(region, _MARKER, before)
        assert [m.address for m in before] == [base + _STRADDLING_MARKER_OFFSET, base + _SECOND_MARKER_OFFSET]

        assert _command(child, action) == f"DONE {action} True 0"

        after: list[MemorySearchResult] = []
        await scan(region, _MARKER, after)
        assert [m.address for m in after] == [base + offset for offset in surviving_offsets]
    finally:
        _sync_method(bridge, "_release_process_handles")()


def test_module_import_leaves_all_three_optional_packages_unset_when_none_can_be_imported(all_blocked_state: dict[str, Any]) -> None:
    """With capstone, keystone and yara unimportable the module still imports and every handle is ``None``.

    Probe key: ``imports_child_all_three_blocked``.

    One-line change that fails it: change ``except ImportError:`` to ``except KeyError:`` at x64dbg.py:140 (the import then fails in the child).

    Args:
        all_blocked_state: State reported by the child interpreter.
    """
    assert all_blocked_state["refused"] == {"capstone": True, "keystone": True, "yara": True}
    assert all_blocked_state["capstone_is_none"] is True
    assert all_blocked_state["keystone_is_none"] is True
    assert all_blocked_state["yara_is_none"] is True
    assert all_blocked_state["get_capstone_is_none"] is True
    assert all_blocked_state["get_keystone_is_none"] is True
    assert all_blocked_state["get_yara_is_none"] is True


def test_module_import_keeps_capstone_and_keystone_when_only_yara_is_missing(yara_blocked_state: dict[str, Any]) -> None:
    """The three import guards are independent: a missing yara does not disable capstone or keystone.

    Probe key: ``imports_child_only_yara_blocked``.

    One-line change that fails it: set ``_capstone = None`` inside the yara ``except ImportError`` block at x64dbg.py:155.

    Args:
        yara_blocked_state: State reported by the child interpreter.
    """
    assert yara_blocked_state["refused"] == {"capstone": False, "keystone": False, "yara": True}
    assert yara_blocked_state["capstone_is_none"] is False
    assert yara_blocked_state["keystone_is_none"] is False
    assert yara_blocked_state["yara_is_none"] is True
    assert yara_blocked_state["get_capstone_is_none"] is False
    assert yara_blocked_state["get_keystone_is_none"] is False
    assert yara_blocked_state["get_yara_is_none"] is True
