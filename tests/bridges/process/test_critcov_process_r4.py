# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
r"""Fourth-pass critical-coverage tests for the process bridge: an empty process snapshot and a 32-bit target's unreadable TEB pointer.

The expectations rest on measurements in the test container, each confirmed again inside the test by the test's own Win32 call:

* A Toolhelp snapshot made with no class flags (``0``) is valid but holds no process records: ``Process32First`` returns FALSE and the
  operating system reports ``ERROR_NO_MORE_FILES`` (18). Probe key: ``first_0x0_Process32First``.
* A 32-bit ``cmd.exe`` from ``SysWOW64`` is a WOW64 process, and a read of its address 0x10 (inside the never-mapped null region) is refused
  by ``ReadProcessMemory``. Probe keys: ``syswow64_cmd_exists``, ``teb_null_page_exc``.
"""

from __future__ import annotations

import asyncio
import ctypes
import functools
import os
import re
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    IMAGE_FILE_MACHINE_I386,
    INVALID_HANDLE_VALUE,
    PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESSENTRY32,
)
from intellicrack.core.subprocess_compat import DEVNULL, PIPE, Popen
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine, Generator


pytestmark = pytest.mark.spawns_process

_WAIT_S: Final[float] = 120.0
_ERROR_NO_MORE_FILES: Final[int] = 18
_NO_CLASS_FLAGS: Final[int] = 0
_NULL_REGION_ADDRESS: Final[int] = 0x10
_POINTER_SIZE_32_BIT_TARGET: Final[int] = 8


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
        obj: Object or class that owns the method.
        name: Method name.

    Returns:
        Callable[..., object]: The bound method.
    """
    return cast("Callable[..., object]", getattr(obj, name))


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
    dll.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    dll.ReadProcessMemory.restype = wintypes.BOOL
    dll.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    dll.IsWow64Process2.restype = wintypes.BOOL
    dll.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    dll.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    dll.Process32First.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    dll.Process32First.restype = wintypes.BOOL
    return dll


def _process_machine(pid: int) -> int:
    """Ask the operating system which machine type a process image targets.

    Args:
        pid: Identifier of the process to query.

    Returns:
        int: The ``IMAGE_FILE_MACHINE_*`` value reported by ``IsWow64Process2`` for the process itself.
    """
    inherit_handle = False
    handle: int | None = _k32().OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, inherit_handle, pid)
    assert handle
    try:
        process_machine = wintypes.USHORT(0)
        native_machine = wintypes.USHORT(0)
        queried: int = _k32().IsWow64Process2(handle, ctypes.byref(process_machine), ctypes.byref(native_machine))
        assert queried
        return process_machine.value
    finally:
        _k32().CloseHandle(handle)


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


def _snapshot_without_classes() -> int:
    """Create a valid Toolhelp snapshot that holds no records of any class.

    Returns:
        int: The snapshot handle; the caller closes it.
    """
    snapshot: int | None = _k32().CreateToolhelp32Snapshot(_NO_CLASS_FLAGS, 0)
    assert snapshot is not None
    assert snapshot != INVALID_HANDLE_VALUE
    return snapshot


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

    The fixture asserts that the operating system reports the child as an i386 image before yielding it.

    Yields:
        Popen[bytes]: The running 32-bit child.
    """
    exe = Path(os.environ["SYSTEMROOT"]) / "SysWOW64" / "cmd.exe"
    assert exe.is_file()
    proc = Popen([str(exe), "/c", "pause"], stdin=PIPE, stdout=PIPE, stderr=DEVNULL)
    try:
        assert _process_machine(proc.pid) == IMAGE_FILE_MACHINE_I386
        yield proc
    finally:
        _stop_child(proc)


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


def test_iterate_process_snapshot_ends_quietly_for_a_snapshot_without_process_records(process_bridge: ProcessBridge) -> None:
    """A snapshot with no process records makes ``Process32First`` fail with ``ERROR_NO_MORE_FILES``, which is not an error.

    The test proves the premise with its own call on a second identical snapshot, then requires the walker to return without raising and
    without collecting anything. A walker that treated the code as a failure would raise ``ToolError``; one that carried on past the failed
    first call would collect the unfilled entry.

    Args:
        process_bridge: Initialized bridge.

    Mutation: changing ``!=`` to ``==`` in the comparison at process.py:2277 makes the walker raise ``ToolError`` here; deleting the
    ``return`` at process.py:2280 makes it append an entry for process id 0.
    """
    oracle_snapshot = _snapshot_without_classes()
    snapshot = _snapshot_without_classes()
    try:
        oracle_entry = PROCESSENTRY32()
        oracle_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        ctypes.set_last_error(0)
        failed: int = _k32().Process32First(oracle_snapshot, ctypes.byref(oracle_entry))
        assert not failed
        assert ctypes.get_last_error() == _ERROR_NO_MORE_FILES

        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        processes: list[object] = []
        walked = sync_method(process_bridge, "_iterate_process_snapshot")(snapshot, entry, processes, None)
    finally:
        _k32().CloseHandle(snapshot)
        _k32().CloseHandle(oracle_snapshot)

    assert walked is None
    assert processes == []


def test_read_and_parse_teb_refuses_an_unreadable_wow64_teb_pointer(wow64_bridge: ProcessBridge) -> None:
    """For a 32-bit target the first read fetches the 32-bit TEB address; when that read is refused the bridge reports a TEB read failure.

    The address handed in lies in the null region of the 32-bit child, which no process maps. The test confirms with its own
    ``ReadProcessMemory`` call, made with the same handle and the same eight-byte size the bridge uses for the pointer, that the read is
    refused, and then requires ``ToolError("TEB read failed")``.

    Args:
        wow64_bridge: Bridge attached to the 32-bit child.

    Mutation: changing the message raised at process.py:5690 (``_ERR_TEB_READ``) to any other text, or returning a dictionary there, makes
    the match fail. Deleting that ``raise`` outright is an equivalent change: the read at process.py:5694 then fails at the zero
    address the unfilled pointer leaves behind and raises the same message.
    """
    handle = wow64_bridge.process_handle
    assert handle is not None
    buffer = ctypes.create_string_buffer(_POINTER_SIZE_32_BIT_TARGET)
    count = ctypes.c_size_t(0)
    read_ok: int = _k32().ReadProcessMemory(
        handle,
        ctypes.c_void_p(_NULL_REGION_ADDRESS),
        buffer,
        _POINTER_SIZE_32_BIT_TARGET,
        ctypes.byref(count),
    )
    assert not read_ok

    with pytest.raises(ToolError, match=re.escape("TEB read failed")):
        sync_method(wow64_bridge, "_read_and_parse_teb")(handle, _NULL_REGION_ADDRESS, exit_status=0)
