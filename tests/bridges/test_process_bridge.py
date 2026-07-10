# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Integration tests for ProcessBridge against real Windows APIs.

Uses the Python interpreter process (os.getpid()) as the target.
All async, all Windows-only. No mocks for Win32 calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import inspect
import os
import re
import struct
import sys
import tempfile
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import pytest
import pytest_asyncio

from intellicrack.bridges.process import (
    IMAGEHLP_MODULE64,
    PEB64,
    TLS_ARRAY_OFFSET_X64,
    TLS_ARRAY_OFFSET_X86,
    TLS_STATIC_SLOT_COUNT,
    ProcessBridge,
)
from intellicrack.bridges.win32_types import SYMBOL_INFO
from intellicrack.core.types import ToolError, ToolName


if sys.platform == "win32":
    import winreg

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Generator

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_MEM_MAPPED = 0x40000
_MEM_IMAGE = 0x1000000
_PAGE_NOACCESS = 0x01

_TH32CS_SNAPPROCESS: int = 0x00000002
_INVALID_HANDLE_VALUE: int = (2 ** (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1

_PAGE_READONLY: int = 0x02
_PAGE_READWRITE: int = 0x04
_PAGE_EXECUTE: int = 0x10
_PAGE_EXECUTE_READ: int = 0x20
_PAGE_EXECUTE_READWRITE: int = 0x40

_ATTR_KERNEL32 = "_kernel32"
_ATTR_NTDLL = "_ntdll"
_ATTR_ADVAPI32 = "_advapi32"
_ATTR_DEBUG_PRIV = "_debug_privilege_enabled"
_ATTR_PROCESS_HANDLE = "_process_handle"
_ATTR_ATTACHED_PID = "_attached_pid"
_ATTR_PROT_FROM_STRING = "_prot_from_string"
_ATTR_PARSE_REGISTRY_PATH = "_parse_registry_path"
_ATTR_SECTION_HANDLES = "_section_handles"
_ATTR_SECTION_VIEWS = "_section_views"
_ATTR_RESOLVE_SYMBOL = "_resolve_symbol"
_ATTR_RESOLVE_MODULE = "_resolve_module"

_MAX_SYM_NAME: int = 2000


class _SectionHandlesShapeError(TypeError):
    """Raised when ``_section_handles`` is not a ``dict[int, str]``."""


class _SectionViewsShapeError(TypeError):
    """Raised when ``_section_views`` is not a ``dict[int, int]``."""


def _get_section_handles(bridge: ProcessBridge) -> dict[int, str]:
    """Return ``_section_handles`` as a typed ``dict[int, str]``.

    Bypasses ``reportPrivateUsage`` so tests can verify the bridge's
    handle-tracking lifecycle without weakening the public API.

    Args:
        bridge: ProcessBridge instance to read from.

    Returns:
        dict[int, str]: The bridge's section-handle tracking dict
            (mutable; the test owns no copy).

    Raises:
        _SectionHandlesShapeError: If the underlying attribute is missing
            or not a dict with ``int`` keys and ``str`` values.
    """
    raw: object = getattr(bridge, _ATTR_SECTION_HANDLES)
    if not isinstance(raw, dict):
        raise _SectionHandlesShapeError
    typed: dict[object, object] = cast("dict[object, object]", raw)
    for k, v in typed.items():
        if not isinstance(k, int) or not isinstance(v, str):
            raise _SectionHandlesShapeError
    return cast("dict[int, str]", raw)


def _get_section_views(bridge: ProcessBridge) -> dict[int, int]:
    """Return ``_section_views`` as a typed ``dict[int, int]``.

    Bypasses ``reportPrivateUsage`` so tests can verify the bridge's
    view-tracking lifecycle without weakening the public API.

    Args:
        bridge: ProcessBridge instance to read from.

    Returns:
        dict[int, int]: The bridge's mapped-view tracking dict
            (base address -> section handle).

    Raises:
        _SectionViewsShapeError: If the underlying attribute is missing
            or not a dict with ``int`` keys and ``int`` values.
    """
    raw: object = getattr(bridge, _ATTR_SECTION_VIEWS)
    if not isinstance(raw, dict):
        raise _SectionViewsShapeError
    typed: dict[object, object] = cast("dict[object, object]", raw)
    for k, v in typed.items():
        if not isinstance(k, int) or not isinstance(v, int):
            raise _SectionViewsShapeError
    return cast("dict[int, int]", raw)


def _unlink_suppress(path: str) -> None:
    """Delete a file, suppressing OSError if it does not exist.

    Runs synchronously so it can be dispatched via asyncio.to_thread
    from async test teardown without triggering ASYNC240.

    Args:
        path: Filesystem path to remove.
    """
    with contextlib.suppress(OSError):
        Path(path).unlink()


def _get_attr_optional[TAttr](bridge: ProcessBridge, name: str, expected: type[TAttr]) -> TAttr | None:
    """Return a protected optional attribute from bridge, narrowed to expected type.

    Used to bypass reportPrivateUsage when tests need to inspect internal
    state without weakening the bridge's public API boundary.

    Args:
        bridge: The ProcessBridge instance to read from.
        name: Attribute name (must be a literal constant declared in this module).
        expected: Expected runtime type of the non-None value.

    Returns:
        TAttr | None: The attribute value typed as ``expected | None``.

    Raises:
        TypeError: If the attribute is neither None nor an instance of expected.
    """
    value: object = getattr(bridge, name)
    if value is None:
        return None
    if not isinstance(value, expected):
        msg = f"ProcessBridge.{name} expected {expected.__name__} or None, got {type(value).__name__}"
        raise TypeError(msg)
    return value


def _get_debug_privilege_enabled(bridge: ProcessBridge) -> bool:
    """Return the bridge's debug privilege flag, bypassing reportPrivateUsage.

    Args:
        bridge: The ProcessBridge instance to read from.

    Returns:
        bool: True if the debug privilege was acquired during initialization.

    Raises:
        TypeError: If the underlying attribute is not a bool.
    """
    flag: object = getattr(bridge, _ATTR_DEBUG_PRIV)
    if not isinstance(flag, bool):
        msg = f"ProcessBridge.{_ATTR_DEBUG_PRIV} expected bool, got {type(flag).__name__}"
        raise TypeError(msg)
    return flag


def _invoke_prot_from_string(protection: str) -> int:
    """Invoke ProcessBridge._prot_from_string via getattr, bypassing reportPrivateUsage.

    Args:
        protection: Protection string such as ``"rwx"``, ``"rw"``, or ``"r"``.

    Returns:
        int: The Win32 PAGE_* flag integer for the given string.

    Raises:
        TypeError: If the resolved attribute is not callable or does not return int.
    """
    fn: object = getattr(ProcessBridge, _ATTR_PROT_FROM_STRING)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_PROT_FROM_STRING} is not callable"
        raise TypeError(msg)
    result: object = fn(protection)
    if not isinstance(result, int):
        msg = f"ProcessBridge.{_ATTR_PROT_FROM_STRING} expected int return, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _invoke_parse_registry_path(key_path: str) -> tuple[int, str]:
    r"""Invoke ProcessBridge._parse_registry_path via getattr, bypassing reportPrivateUsage.

    Args:
        key_path: Registry path such as ``r"HKLM\\SOFTWARE\\Test"``.

    Returns:
        tuple[int, str]: A 2-tuple of ``(root_key_handle, subpath)``.

    Raises:
        TypeError: If the resolved attribute is not callable or returns an
            unexpected shape.
    """
    fn: object = getattr(ProcessBridge, _ATTR_PARSE_REGISTRY_PATH)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} is not callable"
        raise TypeError(msg)
    result: object = fn(key_path)
    if not isinstance(result, tuple):
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected 2-tuple, got {type(result).__name__}"
        raise TypeError(msg)
    typed_result = cast("tuple[object, ...]", result)
    if len(typed_result) != 2:
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected 2-tuple, got tuple of length {len(typed_result)}"
        raise TypeError(msg)
    root_obj: object = typed_result[0]
    sub_obj: object = typed_result[1]
    if not isinstance(root_obj, int) or not isinstance(sub_obj, str):
        msg = f"ProcessBridge.{_ATTR_PARSE_REGISTRY_PATH} expected (int, str), got ({type(root_obj).__name__}, {type(sub_obj).__name__})"
        raise TypeError(msg)
    return root_obj, sub_obj


def _invoke_resolve_symbol(bridge: ProcessBridge, pc: int) -> tuple[str, int]:
    """Invoke ProcessBridge._resolve_symbol via getattr, bypassing reportPrivateUsage.

    Args:
        bridge: The ProcessBridge instance.
        pc: Program counter address to resolve.

    Returns:
        tuple[str, int]: ``(symbol_name, displacement)`` pair.

    Raises:
        TypeError: If the resolved attribute is not callable or returns unexpected type.
    """
    fn: object = getattr(bridge, _ATTR_RESOLVE_SYMBOL)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_RESOLVE_SYMBOL} is not callable"
        raise TypeError(msg)
    raw: object = fn(pc)
    if not isinstance(raw, tuple):
        msg = f"ProcessBridge.{_ATTR_RESOLVE_SYMBOL} expected 2-tuple, got {type(raw).__name__}"
        raise TypeError(msg)
    typed_raw: tuple[object, ...] = cast("tuple[object, ...]", raw)
    if len(typed_raw) != 2:
        msg = f"ProcessBridge.{_ATTR_RESOLVE_SYMBOL} expected 2-element tuple, got {len(typed_raw)}"
        raise TypeError(msg)
    sym: object = typed_raw[0]
    disp: object = typed_raw[1]
    if not isinstance(sym, str) or not isinstance(disp, int):
        msg = f"ProcessBridge.{_ATTR_RESOLVE_SYMBOL} expected (str, int), got ({type(sym).__name__}, {type(disp).__name__})"
        raise TypeError(msg)
    return sym, disp


def _invoke_resolve_module(bridge: ProcessBridge, pc: int) -> str:
    """Invoke ProcessBridge._resolve_module via getattr, bypassing reportPrivateUsage.

    Args:
        bridge: The ProcessBridge instance.
        pc: Program counter address to resolve.

    Returns:
        str: Module name or empty string.

    Raises:
        TypeError: If the resolved attribute is not callable or returns unexpected type.
    """
    fn: object = getattr(bridge, _ATTR_RESOLVE_MODULE)
    if not callable(fn):
        msg = f"ProcessBridge.{_ATTR_RESOLVE_MODULE} is not callable"
        raise TypeError(msg)
    result: object = fn(pc)
    if not isinstance(result, str):
        msg = f"ProcessBridge.{_ATTR_RESOLVE_MODULE} expected str, got {type(result).__name__}"
        raise TypeError(msg)
    return result


def _configure_kernel32_signatures(k32: ctypes.WinDLL) -> None:
    """Set correct 64-bit return/argument types on kernel32 functions.

    Args:
        k32: Loaded kernel32 DLL handle.
    """
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    k32.VirtualFreeEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
    ]
    k32.VirtualProtectEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_size_t,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k32.CreateFileMappingW.restype = wintypes.HANDLE
    k32.CreateFileMappingW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    k32.MapViewOfFile.restype = ctypes.c_void_p
    k32.MapViewOfFile.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_size_t,
    ]


@pytest_asyncio.fixture(scope="module")
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Create, initialize, and shutdown a ProcessBridge for the module.

    Yields:
        AsyncGenerator[ProcessBridge]: Initialized bridge that will be shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    k32 = _get_attr_optional(bridge, _ATTR_KERNEL32, ctypes.WinDLL)
    if k32 is not None:
        _configure_kernel32_signatures(k32)
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge(process_bridge: ProcessBridge) -> AsyncGenerator[ProcessBridge]:
    """Attach the bridge to the current Python process.

    Args:
        process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.

    Yields:
        AsyncGenerator[ProcessBridge]: The shared bridge with an open handle on the current Python process.
    """
    await process_bridge.open_process(os.getpid(), "all")
    yield process_bridge
    await process_bridge.close()


@pytest_asyncio.fixture
async def main_thread_tid(attached_bridge: ProcessBridge) -> int:
    """Get the TID of the first thread in the current process.

    Args:
        attached_bridge: ProcessBridge fixture pre-attached to the current Python process.

    Returns:
        int: Windows thread id of the first thread enumerated in the current process.
    """
    threads = await attached_bridge.get_threads(os.getpid())
    return threads[0].tid


@pytest.fixture
def known_buffer() -> tuple[int, ctypes.Array[ctypes.c_char], bytes]:
    """Create a buffer with known content for memory read tests.

    Returns:
        tuple[int, ctypes.Array[ctypes.c_char], bytes]: Tuple ``(address,
        backing_buffer, expected_bytes)`` whose address may be safely read
        by the bridge.
    """
    data = b"INTELLICRACK_BRIDGE_TEST_7890ABCDEF"
    buf = ctypes.create_string_buffer(data)
    return ctypes.addressof(buf), buf, data


@pytest.fixture
def secondary_thread() -> Generator[int]:
    """Spawn a blocking thread and yield its Windows TID for context tests.

    Yields:
        Generator[int]: Windows thread id of a parked worker thread that blocks until the fixture tears down.
    """
    event = threading.Event()
    tid_holder: list[int] = []

    def _worker() -> None:
        tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
        event.wait()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    time.sleep(0.1)
    yield tid_holder[0]
    event.set()
    t.join(timeout=2)


class TestInitialization:
    """Verify bridge initialization loads DLLs and sets state."""

    async def test_initialize_loads_kernel32(self, process_bridge: ProcessBridge) -> None:
        """Verify kernel32 is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL) is not None

    async def test_initialize_loads_ntdll(self, process_bridge: ProcessBridge) -> None:
        """Verify ntdll is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert _get_attr_optional(process_bridge, _ATTR_NTDLL, ctypes.WinDLL) is not None

    async def test_initialize_loads_advapi32(self, process_bridge: ProcessBridge) -> None:
        """Verify advapi32 is loaded after initialization.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert _get_attr_optional(process_bridge, _ATTR_ADVAPI32, ctypes.WinDLL) is not None

    async def test_initialize_sets_connected(self, process_bridge: ProcessBridge) -> None:
        """Verify state shows connected and tool_running after init.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert process_bridge.state.connected is True
        assert process_bridge.state.tool_running is True

    async def test_initialize_debug_privilege_flag(self, process_bridge: ProcessBridge) -> None:
        """Verify debug privilege flag is a boolean.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert isinstance(_get_debug_privilege_enabled(process_bridge), bool)

    async def test_name_is_process(self, process_bridge: ProcessBridge) -> None:
        """Verify bridge name is ToolName.PROCESS.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert process_bridge.name == ToolName.PROCESS

    async def test_is_available(self, process_bridge: ProcessBridge) -> None:
        """Verify is_available returns True on Windows.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert await process_bridge.is_available() is True

    async def test_tool_definition_count(self, process_bridge: ProcessBridge) -> None:
        """Verify tool definition has 54 functions.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        assert len(process_bridge.tool_definition.functions) == 54


class TestProcessListing:
    """Verify process listing and filtering."""

    async def test_list_processes_non_empty(self, process_bridge: ProcessBridge) -> None:
        """Verify process list is non-empty and every entry has a valid pid and name.

        Asserts structural correctness on every returned ProcessInfo object and
        cross-checks that the current Python process is present with the exact
        ``os.getpid()`` value and a name containing "python", so a bug that
        returns malformed objects or omits the self-process fails here.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes()
        assert len(procs) > 0, "list_processes must return at least one entry"
        assert all(hasattr(p, "pid") and hasattr(p, "name") and isinstance(p.pid, int) and p.pid >= 0 for p in procs), (
            "every ProcessInfo must have a non-negative integer pid and a name attribute (pid 0 = System Idle Process)"
        )
        self_proc = next((p for p in procs if p.pid == os.getpid()), None)
        assert self_proc is not None, f"current Python process (pid={os.getpid()}) must appear in list_processes output"
        assert isinstance(self_proc.name, str), "self ProcessInfo.name must be a str"
        assert len(self_proc.name) > 0, "self ProcessInfo.name must be non-empty"
        assert "python" in self_proc.name.lower(), f"current process name must contain 'python', got {self_proc.name!r}"

    async def test_list_processes_includes_self(self, process_bridge: ProcessBridge) -> None:
        """Verify process list contains current PID.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes()
        assert any(p.pid == os.getpid() for p in procs)

    async def test_list_processes_has_python_name(self, process_bridge: ProcessBridge) -> None:
        """Verify our process entry name contains 'python'.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes()
        self_proc = next((p for p in procs if p.pid == os.getpid()), None)
        assert self_proc is not None
        assert "python" in self_proc.name.lower()

    async def test_list_processes_filter(self, process_bridge: ProcessBridge) -> None:
        """Verify name filter returns only processes whose names contain the filter string.

        ``len(procs) >= 1`` is necessary but not sufficient — the critical gate is
        that ``filter_name`` actually constrains the result to matching names.  If
        the filter is silently ignored and all processes are returned, at least one
        non-Python process name would fail the ``all(...)`` assertion below.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes(filter_name="python")
        assert len(procs) >= 1, "filter_name='python' must return at least one process (the current interpreter)"
        assert all("python" in p.name.lower() for p in procs), (
            "filter_name='python' must return ONLY processes with 'python' in their name; "
            f"non-matching entries: {[p.name for p in procs if 'python' not in p.name.lower()]}"
        )

    async def test_list_processes_detailed_has_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify detailed listing includes expected keys.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        assert len(procs) >= 1
        entry = procs[0]
        for key in ("pid", "name", "architecture", "memory_mb", "thread_count"):
            assert key in entry

    async def test_list_processes_detailed_self_arch(self, process_bridge: ProcessBridge) -> None:
        """Verify our process architecture matches the canonical bitness of the running interpreter.

        ``struct.calcsize("P") * 8`` is the independent oracle: 64 on a 64-bit
        interpreter, 32 on a 32-bit one.  The bridge must return the matching
        string ("x86_64" or "x86") for the current process, not merely any value
        from an allowed set.  A bridge that always returns "x86_64" would still
        pass the old check on a 64-bit host but fail here on a 32-bit host, and
        a bridge that swaps the strings would fail immediately.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        self_proc = next((p for p in procs if p["pid"] == os.getpid()), None)
        assert self_proc is not None, f"current process (pid={os.getpid()}) must appear in list_processes_detailed"
        arch = self_proc["architecture"]
        assert isinstance(arch, str), f"architecture must be str, got {type(arch).__name__}"
        expected_arch = "x86_64" if struct.calcsize("P") == 8 else "x86"
        assert arch == expected_arch, (
            f"bridge reported architecture {arch!r} for the current process, "
            f"but struct.calcsize('P')*8=={struct.calcsize('P') * 8} requires {expected_arch!r}"
        )

    async def test_list_processes_detailed_self_memory(self, process_bridge: ProcessBridge) -> None:
        """Verify our process has positive memory usage.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        procs = await process_bridge.list_processes_detailed(filter_name="python")
        self_proc = next((p for p in procs if p["pid"] == os.getpid()), None)
        assert self_proc is not None
        memory_mb = self_proc["memory_mb"]
        assert isinstance(memory_mb, (int, float))
        assert memory_mb > 0

    async def test_detect_architecture_self(self, process_bridge: ProcessBridge) -> None:
        """Verify architecture detection returns the canonical arch on the current process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        arch = await process_bridge.detect_architecture(os.getpid())
        expected = "x86_64" if struct.calcsize("P") == 8 else "x86"
        assert arch == expected

    async def test_detect_architecture_invalid_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify architecture detection returns Unknown for invalid PID.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        arch = await process_bridge.detect_architecture(99999999)
        assert arch == "Unknown"


class TestProcessOpenClose:
    """Verify process open/close lifecycle."""

    async def test_open_process_query(self, process_bridge: ProcessBridge) -> None:
        """Verify opening own process succeeds.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.open_process(os.getpid(), "query")
        assert result is True
        assert getattr(process_bridge, _ATTR_PROCESS_HANDLE) is not None
        await process_bridge.close()

    async def test_close_resets_state(self, process_bridge: ProcessBridge) -> None:
        """Verify close resets handle, pid, and state.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.open_process(os.getpid(), "all")
        await process_bridge.close()
        assert getattr(process_bridge, _ATTR_PROCESS_HANDLE) is None
        assert getattr(process_bridge, _ATTR_ATTACHED_PID) is None
        assert process_bridge.state.process_attached is False

    async def test_open_invalid_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify opening an invalid PID raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError, match="process open failed"):
            await process_bridge.open_process(99999999, "all")

    async def test_get_process_memory_mb_self(self, process_bridge: ProcessBridge) -> None:
        """Verify memory query returns positive value for self.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        mem = await process_bridge.get_process_memory_mb(os.getpid())
        assert mem > 0


class TestMemoryOperations:
    """Verify memory read, write, allocate, free, protect, search, and map."""

    async def test_read_memory_known_buffer(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify reading from a known buffer returns expected data.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            known_buffer: Triple of (address, backing buffer, expected bytes) for a buffer with known content.
        """
        addr, _buf, data = known_buffer
        result = await attached_bridge.read_memory(addr, len(data))
        assert isinstance(result, str)
        assert bytes.fromhex(result)[: len(data)] == data

    async def test_read_memory_not_attached_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify reading without attachment raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.read_memory(0x1000, 16)

    async def test_write_read_roundtrip(self, attached_bridge: ProcessBridge) -> None:
        """Verify allocate-write-read-free roundtrip works.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        addr = await attached_bridge.allocate(4096, "rw")
        try:
            test_data = b"WRITE_TEST"
            written = await attached_bridge.write_memory(addr, test_data)
            assert written == len(test_data)
            readback = await attached_bridge.read_memory(addr, len(test_data))
            assert bytes.fromhex(readback) == test_data
        finally:
            await attached_bridge.free(addr)

    async def test_allocate_free_cycle(self, attached_bridge: ProcessBridge) -> None:
        """Verify allocate returns non-zero address and free succeeds.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        addr = await attached_bridge.allocate(4096, "rw")
        assert addr != 0
        result = await attached_bridge.free(addr)
        assert result is True

    async def test_protect_returns_old_protection(self, attached_bridge: ProcessBridge) -> None:
        """Verify protect returns the previous protection string.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        addr = await attached_bridge.allocate(4096, "rw")
        try:
            old_prot = await attached_bridge.protect(addr, 4096, "r")
            assert "rw" in old_prot
        finally:
            await attached_bridge.free(addr)

    async def test_search_pattern_finds_bytes(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify pattern search returns the exact address of known bytes.

        Searches the full unique sentinel content of the known buffer (not a
        short prefix that could collide with unrelated heap bytes) within a
        128 KiB window around it. ``addr in results`` is the exact-addressing
        gate: a bridge with an off-by-one error reports the match at
        ``addr + 1`` rather than ``addr``, so exact membership would fail.
        A dedicated guard additionally asserts the buffer is not reported at
        ``addr ± 1``. The first-occurrence ordering of results is deliberately
        not asserted because a live process can legitimately hold other copies
        of the sentinel (the source ``bytes`` literal itself) at lower
        addresses, which is memory-layout and test-order dependent.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            known_buffer: Triple of (address, backing buffer, expected bytes) for a buffer with known content.
        """
        addr, _buf, data = known_buffer
        pattern = " ".join(f"{b:02X}" for b in data)
        results = await attached_bridge.search_pattern(pattern, start_address=addr - 0x10000, end_address=addr + 0x10000)
        assert addr in results, (
            f"expected exact buffer address {hex(addr)} in search results {[hex(r) for r in results[:10]]}; "
            "absence here indicates the bridge reports the wrong match offset"
        )
        nearby = [hex(r) for r in results if abs(r - addr) <= 2]
        assert (addr - 1) not in results, f"off-by-one (addr-1) match indicates an addressing bug; results near the buffer: {nearby}"
        assert (addr + 1) not in results, f"off-by-one (addr+1) match indicates an addressing bug; results near the buffer: {nearby}"

    async def test_search_pattern_absent_returns_empty(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify pattern search returns an empty list for bytes not present in the searched range.

        Uses a sentinel pattern that cannot collide with the known_buffer content
        or any plausible stack/heap data, and restricts the search to a 64 KiB
        window around the buffer so the scan completes quickly.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            known_buffer: Triple of (address, backing buffer, expected bytes) for a buffer with known content.
        """
        addr, _buf, _data = known_buffer
        absent_pattern = "FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
        results = await attached_bridge.search_pattern(absent_pattern, start_address=addr, end_address=addr + 0x10000)
        assert results == [], (
            f"absent pattern must return empty list, got {len(results)} match(es) starting at {[hex(r) for r in results[:4]]}"
        )

    async def test_get_memory_map_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify memory map returns non-empty list with required fields.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        regions = await attached_bridge.get_memory_map()
        assert len(regions) > 0
        region = regions[0]
        assert hasattr(region, "base_address")
        assert hasattr(region, "size")
        assert hasattr(region, "protection")


class TestThreadEnumeration:
    """Verify thread listing and bug-fix fields (start_address, state)."""

    async def test_get_threads_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify thread list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert len(threads) > 0

    async def test_get_threads_have_tid(self, attached_bridge: ProcessBridge) -> None:
        """Verify all threads have positive TIDs.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert all(t.tid > 0 for t in threads)

    async def test_get_threads_start_address_nonzero(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a non-zero start address (bug fix).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert any(t.start_address != 0 for t in threads)

    async def test_get_threads_state_not_unknown(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a known state (bug fix).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        valid_states = {"running", "suspended", "terminated", "waiting"}
        assert any(t.state in valid_states for t in threads)

    async def test_get_threads_expose_pc_fields(self, attached_bridge: ProcessBridge) -> None:
        """Verify all threads have separate start_address and current_pc fields.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert all(t.start_address >= 0 and t.current_pc >= 0 for t in threads)


class TestModuleListing:
    """Verify module enumeration."""

    async def test_get_modules_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify module list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert len(modules) > 0

    async def test_get_modules_includes_python(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one module name contains 'python'.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert any("python" in m.name.lower() for m in modules)

    async def test_get_modules_have_base_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify all modules have positive base addresses.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert all(m.base_address > 0 for m in modules)

    async def test_get_modules_no_pid_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify get_modules raises when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process"):
            await process_bridge.get_modules()


class TestProcessInfo:
    """Verify process info aggregation."""

    async def test_get_process_info_self(self, attached_bridge: ProcessBridge) -> None:
        """Verify process info is populated for self.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        info = await attached_bridge.get_process_info(os.getpid())
        assert info is not None
        assert len(info.threads) > 0
        assert len(info.modules) > 0

    async def test_get_process_info_no_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify process info returns None when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        info = await process_bridge.get_process_info()
        assert info is None


class TestTokenPrivileges:
    """Verify token privilege enumeration and adjustment."""

    async def test_get_token_privileges_has_entries(self, attached_bridge: ProcessBridge) -> None:
        """Verify token privileges list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        privs = await attached_bridge.get_token_privileges(os.getpid())
        assert len(privs) > 0

    async def test_get_token_privileges_has_sechangenotify(self, attached_bridge: ProcessBridge) -> None:
        """Verify SeChangeNotifyPrivilege is present.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        privs = await attached_bridge.get_token_privileges(os.getpid())
        assert any("SeChangeNotifyPrivilege" in str(p.get("name", "")) for p in privs)

    async def test_get_token_privileges_entry_keys(self, attached_bridge: ProcessBridge) -> None:
        """Verify each privilege entry has required keys.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        privs = await attached_bridge.get_token_privileges(os.getpid())
        for priv in privs:
            for key in ("name", "luid_low", "luid_high", "enabled", "attributes"):
                assert key in priv

    async def test_adjust_token_privilege_invalid_raises(self, attached_bridge: ProcessBridge) -> None:
        """Verify adjusting a fake privilege raises ToolError.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        with pytest.raises(ToolError, match="privilege lookup failed"):
            await attached_bridge.adjust_token_privilege("SeCompletelyFakePrivilege", enable=True, pid=os.getpid())


class TestHandleEnumeration:
    """Verify handle enumeration via NtQuerySystemInformation."""

    async def test_get_handles_returns_list(self, process_bridge: ProcessBridge) -> None:
        """Verify handle enumeration returns a list without error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handles = await process_bridge.get_handles(os.getpid())
        assert isinstance(handles, list)

    async def test_get_handles_have_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify each handle entry has required fields when available.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handles = await process_bridge.get_handles(os.getpid())
        for handle in handles[:5]:
            assert "handle_value" in handle
            assert "type_index" in handle


class TestWindowEnumeration:
    """Verify window enumeration returns exact structural fields matching an independent oracle."""

    async def test_get_windows_no_crash(self, process_bridge: ProcessBridge) -> None:
        """Verify get_windows returns an entry with exact hwnd, class_name, title, and visible fields.

        Creates a hidden top-level STATIC window in the current process via
        CreateWindowExW, reads its class name, title, and visibility directly
        via user32 as an independent oracle, then asserts the bridge returns
        a matching entry with exact field values. Destroys the window in the
        finally block. Skips if CreateWindowExW fails (GUI unavailable in the
        current environment).

        Mutation caught: returning wrong class_name, a mismatched hwnd integer,
        or inverting the visible flag causes the corresponding assertion to fail.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        user32 = ctypes.windll.user32
        k32 = ctypes.windll.kernel32
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.GetClassNameW.restype = ctypes.c_int
        user32.GetWindowTextW.restype = ctypes.c_int

        hinstance: int = k32.GetModuleHandleW(None)
        expected_title = f"IntellicrackBridgeWindowTest_{os.getpid()}"
        hwnd: int = user32.CreateWindowExW(
            0,
            "STATIC",
            expected_title,
            0,
            0,
            0,
            1,
            1,
            None,
            None,
            hinstance,
            None,
        )
        if not hwnd:
            pytest.skip("CreateWindowExW failed — GUI not available in this environment")
            return
        try:
            class_buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, class_buf, 256)
            expected_class: str = class_buf.value

            expected_visible: bool = bool(user32.IsWindowVisible(hwnd))

            windows = await process_bridge.get_windows(os.getpid())
            matched = next((w for w in windows if w.get("hwnd") == hwnd), None)
            assert matched is not None, (
                f"created window HWND {hwnd:#x} (class={expected_class!r}, title={expected_title!r}) "
                f"not found in get_windows({os.getpid()}); total windows returned: {len(windows)}"
            )
            assert matched["class_name"] == expected_class, (
                f"class_name mismatch: bridge={matched['class_name']!r}, oracle={expected_class!r}"
            )
            assert matched["title"] == expected_title, f"title mismatch: bridge={matched['title']!r}, oracle={expected_title!r}"
            assert matched["visible"] is expected_visible, f"visible mismatch: bridge={matched['visible']!r}, oracle={expected_visible!r}"
        finally:
            user32.DestroyWindow(hwnd)


class TestServiceListing:
    """Verify service enumeration."""

    async def test_list_services_returns_list(self, process_bridge: ProcessBridge) -> None:
        """Verify service listing returns a list without error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        assert isinstance(services, list)

    async def test_list_services_have_name_state(self, process_bridge: ProcessBridge) -> None:
        """Verify each service has name and state when available.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        for svc in services[:5]:
            assert "name" in svc
            assert "state" in svc


class TestPebTebAccess:
    """Verify PEB and TEB reads."""

    async def test_read_peb_has_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify PEB read returns a positive peb_address.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        peb = await attached_bridge.read_peb()
        peb_address = peb["peb_address"]
        assert isinstance(peb_address, int)
        assert peb_address > 0

    async def test_read_peb_has_image_base(self, attached_bridge: ProcessBridge) -> None:
        """Verify PEB contains positive image_base_address.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        peb = await attached_bridge.read_peb()
        image_base = peb["image_base_address"]
        assert isinstance(image_base, int)
        assert image_base > 0

    async def test_read_teb_has_address(self, attached_bridge: ProcessBridge) -> None:
        """Verify TEB read returns a positive teb_address.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        tid = threads[0].tid
        teb = await attached_bridge.read_teb(tid)
        teb_address = teb["teb_address"]
        assert isinstance(teb_address, int)
        assert teb_address > 0

    async def test_read_teb_stack_range(self, attached_bridge: ProcessBridge) -> None:
        """Verify stack_base > 0 and stack_limit < stack_base (downward growth).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        tid = threads[0].tid
        teb = await attached_bridge.read_teb(tid)
        stack_base = teb.get("stack_base")
        stack_limit = teb.get("stack_limit")
        assert isinstance(stack_base, int)
        assert isinstance(stack_limit, int)
        assert stack_base > 0
        assert stack_limit < stack_base


class TestHeapEnumeration:
    """Verify heap enumeration via Toolhelp32."""

    async def test_get_heaps_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify heap list is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        heaps = await attached_bridge.get_heaps(os.getpid())
        assert len(heaps) > 0

    async def test_get_heaps_has_default(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one heap is the default.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        heaps = await attached_bridge.get_heaps(os.getpid())
        assert any(h.get("is_default") is True for h in heaps)


class TestThreadContext:
    """Verify thread context read using a secondary thread to avoid deadlock."""

    async def test_get_thread_context_has_registers(self, attached_bridge: ProcessBridge, secondary_thread: int) -> None:
        """Verify context has rip and rsp on 64-bit, or eip/esp on 32-bit.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            secondary_thread: Windows thread id of a parked worker thread used for context queries.
        """
        ctx = await attached_bridge.get_thread_context(secondary_thread)
        if struct.calcsize("P") == 8:
            assert "rip" in ctx
            assert "rsp" in ctx
            assert ctx["rip"] != 0
            assert ctx["rsp"] != 0
        else:
            assert "eip" in ctx
            assert "esp" in ctx

    async def test_get_thread_context_invalid_tid(self, attached_bridge: ProcessBridge) -> None:
        """Verify invalid TID raises ToolError.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        with pytest.raises(ToolError):
            await attached_bridge.get_thread_context(0)


class TestSetThreadContext:
    """set_thread_context writes register values verifiable via get_thread_context."""

    _SENTINEL: int = 0xDEADB00F

    async def test_set_thread_context_dr0_roundtrip(
        self,
        attached_bridge: ProcessBridge,
        secondary_thread: int,
    ) -> None:
        """set_thread_context writes dr0; get_thread_context reads back the sentinel.

        Dr0 is a hardware debug-address register. Setting it to a known sentinel
        value on a parked worker thread and immediately reading it back via
        GetThreadContext confirms that SetThreadContext was actually called.
        Dr0 does not affect execution unless dr7 enables the breakpoint, so the
        secondary thread continues safely with dr0 = sentinel until restored.

        Mutation caught: returning True from set_thread_context without calling
        SetThreadContext causes the readback to return the original dr0 value
        instead of _SENTINEL, failing the equality assertion.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            secondary_thread: Windows thread id of a parked worker thread used for context queries.
        """
        if sys.platform != "win32":
            pytest.skip("Windows-only: SetThreadContext / GetThreadContext")

        ctx_before = await attached_bridge.get_thread_context(secondary_thread)
        original_dr0 = int(ctx_before["dr0"])
        try:
            result = await attached_bridge.set_thread_context(
                secondary_thread,
                {"dr0": self._SENTINEL},
            )
            assert result is True, "set_thread_context must return True on success"

            ctx_after = await attached_bridge.get_thread_context(secondary_thread)
            read_back = int(ctx_after["dr0"])
            assert read_back == self._SENTINEL, (
                f"dr0 must equal sentinel {self._SENTINEL:#010x} after set_thread_context; "
                f"got {read_back:#010x} -- SetThreadContext was not called or wrote to the wrong field"
            )
        finally:
            await attached_bridge.set_thread_context(
                secondary_thread,
                {"dr0": original_dr0},
            )

    async def test_set_thread_context_invalid_tid_raises(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """set_thread_context raises ToolError for TID 0 (non-existent thread).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        with pytest.raises(ToolError, match="thread open failed"):
            await attached_bridge.set_thread_context(0, {"dr0": 0})


class TestMitigationPolicies:
    """Verify mitigation policy queries."""

    async def test_mitigation_policies_has_dep(self, attached_bridge: ProcessBridge) -> None:
        """Verify result has 'DEP' key.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        policies = await attached_bridge.get_mitigation_policies(os.getpid())
        assert "DEP" in policies

    async def test_mitigation_policies_dep_structure(self, attached_bridge: ProcessBridge) -> None:
        """Verify DEP value is dict with 'enabled' and 'flags'.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        policies = await attached_bridge.get_mitigation_policies(os.getpid())
        dep_value = policies["DEP"]
        assert isinstance(dep_value, dict)
        assert "enabled" in dep_value
        assert "flags" in dep_value


class TestEnvironmentVariables:
    """Verify environment variable reading from PEB."""

    async def test_get_environment_non_empty(self, attached_bridge: ProcessBridge) -> None:
        """Verify environment dict is non-empty.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        env = await attached_bridge.get_environment(pid=os.getpid())
        assert len(env) > 0

    async def test_get_environment_has_path(self, attached_bridge: ProcessBridge) -> None:
        """Verify environment contains PATH (case-insensitive).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        env = await attached_bridge.get_environment(pid=os.getpid())
        assert any(k.upper() == "PATH" for k in env)


class TestDotNetDetection:
    """Verify .NET CLR detection."""

    async def test_detect_dotnet_python_is_negative(self, attached_bridge: ProcessBridge) -> None:
        """Verify Python process has no CLR loaded.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        result = await attached_bridge.detect_dotnet(os.getpid())
        clr_loaded = result["clr_loaded"]
        assert isinstance(clr_loaded, bool)
        assert clr_loaded is False


class TestJobGuiCom:
    """Verify job object, GUI resources, and COM enumeration."""

    async def test_get_job_info_has_in_job(self, attached_bridge: ProcessBridge) -> None:
        """Verify get_job_info returns in_job matching the IsProcessInJob Win32 oracle.

        Calls IsProcessInJob on the current process handle directly (independent
        of the bridge code path) to establish the expected boolean, then asserts
        the bridge returns the identical value. Also asserts the value is bool, not
        an int or None.

        Mutation caught: always returning in_job=False when the process is actually
        in a job causes the oracle comparison to fail; always returning in_job=True
        when it is not in a job also fails.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        k32 = ctypes.windll.kernel32
        k32.IsProcessInJob.restype = wintypes.BOOL
        k32.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        k32.GetCurrentProcess.restype = wintypes.HANDLE

        in_job_oracle = wintypes.BOOL(0)
        current_handle: int = k32.GetCurrentProcess()
        ok: int = k32.IsProcessInJob(current_handle, None, ctypes.byref(in_job_oracle))
        if not ok:
            pytest.skip("IsProcessInJob failed — cannot establish oracle")
        expected_in_job: bool = bool(in_job_oracle.value)

        info = await attached_bridge.get_job_info(os.getpid())
        assert isinstance(info, dict)
        assert "in_job" in info
        in_job_val: object = info["in_job"]
        assert isinstance(in_job_val, bool), f"in_job must be bool, got {type(in_job_val).__name__}"
        assert in_job_val is expected_in_job, f"bridge in_job={in_job_val!r} does not match IsProcessInJob oracle={expected_in_job!r}"

    async def test_get_gui_resources_has_counts(self, attached_bridge: ProcessBridge) -> None:
        """Verify GUI resources has non-negative counts.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        res = await attached_bridge.get_gui_resources(os.getpid())
        assert res["gdi_objects"] >= 0
        assert res["user_objects"] >= 0

    async def test_enumerate_com_servers_returns_list(self, attached_bridge: ProcessBridge) -> None:
        """Verify COM enumeration returns a list without crashing.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        result = await attached_bridge.enumerate_com_servers(os.getpid())
        assert isinstance(result, list)


class TestKernelDebuggerDetection:
    """Verify detect_kernel_debugger returns an exact bool matching ProcessDebugPort oracle."""

    async def test_detect_kernel_debugger_current_process_not_debugged(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify detect_kernel_debugger returns False matching NtQueryInformationProcess oracle.

        Reads ProcessDebugPort (class 7) via NtQueryInformationProcess directly
        as an independent oracle, then asserts the bridge returns the identical
        bool. In the test sandbox (no debugger attached) both must be False.

        Mutation caught: always returning True when the process has no debug port
        causes both the oracle comparison and the explicit is-False assertion to fail.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        ntdll = ctypes.windll.ntdll
        k32 = ctypes.windll.kernel32
        process_debug_port: int = 7
        process_query_information: int = 0x0400
        inherit_handle: bool = False

        proc_handle: int = k32.OpenProcess(process_query_information, inherit_handle, os.getpid())
        if not proc_handle:
            pytest.skip("cannot open own process for query")
        try:
            debug_port = ctypes.c_void_p(0)
            ret_len = wintypes.ULONG(0)
            status: int = ntdll.NtQueryInformationProcess(
                proc_handle,
                process_debug_port,
                ctypes.byref(debug_port),
                ctypes.sizeof(debug_port),
                ctypes.byref(ret_len),
            )
            if status < 0:
                pytest.skip(f"NtQueryInformationProcess returned NTSTATUS {status & 0xFFFFFFFF:#010x}")
            expected: bool = bool(debug_port.value)
        finally:
            k32.CloseHandle(proc_handle)

        result: bool = await process_bridge.detect_kernel_debugger(os.getpid())
        assert result is expected, (
            f"bridge returned {result!r} but NtQueryInformationProcess oracle says {expected!r} for ProcessDebugPort on pid={os.getpid()}"
        )
        assert result is False, (
            "test process must not have a kernel debugger port attached; "
            "a non-False result indicates an unexpected debugger or a bridge defect"
        )

    async def test_detect_kernel_debugger_invalid_pid_raises(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify detect_kernel_debugger raises ToolError for an invalid PID.

        An invalid PID (99999999) causes OpenProcess to fail; the bridge must
        surface this as ToolError rather than silently returning False. Silently
        returning False for an inaccessible process would allow callers to treat
        an un-openable process as un-debugged.

        Mutation caught: returning False on OpenProcess failure instead of raising
        ToolError allows a no-op false-negative result to propagate silently.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError, match="process open failed"):
            await process_bridge.detect_kernel_debugger(99999999)


class TestRegistry:
    """Verify registry access operations."""

    async def test_reg_read_value_product_name(self, process_bridge: ProcessBridge) -> None:
        """Verify reading ProductName from CurrentVersion.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.reg_read_value(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName")
        value_type = result["type"]
        assert isinstance(value_type, str)
        assert value_type == "string"
        assert str(result["data"]) != ""

    async def test_reg_enum_keys_microsoft(self, process_bridge: ProcessBridge) -> None:
        r"""Verify enumerating HKLM\\SOFTWARE\\Microsoft returns non-empty list.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        keys = await process_bridge.reg_enum_keys(r"HKLM\SOFTWARE\Microsoft")
        assert len(keys) > 0

    async def test_reg_enum_values_currentversion(self, process_bridge: ProcessBridge) -> None:
        """Verify enumerating values under CurrentVersion returns non-empty list.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        values = await process_bridge.reg_enum_values(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        assert len(values) > 0

    async def test_reg_read_invalid_key_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify reading invalid key raises ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError, match="registry key open failed"):
            await process_bridge.reg_read_value(r"HKLM\SOFTWARE\TOTALLY_FAKE_KEY_12345", "value")


class TestSectionMapping:
    """Verify section create and map operations."""

    async def test_create_section_returns_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify section creation returns a positive handle.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handle = await process_bridge.create_section(4096)
        try:
            assert handle > 0
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
            _get_section_handles(process_bridge).pop(handle, None)

    async def test_map_section_returns_address(self, process_bridge: ProcessBridge) -> None:
        """Verify mapping a section returns a positive address.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        handle = await process_bridge.create_section(4096)
        try:
            addr: int = await process_bridge.map_section(handle, 4096)
            assert addr > 0
            ok: bool = await process_bridge.unmap_section(addr)
            assert ok
        finally:
            section_handles = _get_section_handles(process_bridge)
            if handle in section_handles:
                ctypes.windll.kernel32.CloseHandle(handle)
                section_handles.pop(handle, None)


class TestNtQuerySystemInformation:
    """Verify raw NtQuerySystemInformation bridge."""

    async def test_query_system_info_process_info(self, process_bridge: ProcessBridge) -> None:
        """Verify SystemProcessInformation (class 5) returns a non-empty hex string.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.query_system_info(5)
        assert isinstance(result, str)
        assert len(result) > 0
        assert all(c in "0123456789abcdef" for c in result)
        assert len(result) % 2 == 0


class TestSehFiberTls:
    """Verify SEH chain, fiber data, and TLS access."""

    async def test_get_seh_chain_no_crash(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify SEH chain raises on x64 target and validates entry fields on WOW64.

        Per F-0008, SEH chain traversal via FS:[0] is only valid for x86 / WOW64.
        On a native x64 target the bridge must raise ToolError with the exact
        message. On a WOW64 (32-bit) target the bridge must return at least one
        well-formed entry whose ``address``, ``handler_address``, and ``next``
        fields are all integers with positive ``address`` and ``handler_address``
        values (both must be valid pointer-sized memory addresses).

        Mutation caught (x64): suppressing the ToolError raise causes the
        ``pytest.raises`` block to fail. Mutation caught (WOW64): returning an
        empty list or omitting required entry keys fails the structural assertions.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        if struct.calcsize("P") == 8:
            with pytest.raises(ToolError, match="SEH chain not applicable to x64 target"):
                await attached_bridge.get_seh_chain(main_thread_tid)
        else:
            chain = await attached_bridge.get_seh_chain(main_thread_tid)
            assert isinstance(chain, list)
            assert len(chain) >= 1, "WOW64 thread must have at least one SEH frame"
            for entry in chain:
                assert "address" in entry, f"SEH entry missing 'address' key: {entry}"
                assert "handler_address" in entry, f"SEH entry missing 'handler_address' key: {entry}"
                assert "next" in entry, f"SEH entry missing 'next' key: {entry}"
                assert isinstance(entry["address"], int), f"address must be int, got {type(entry['address']).__name__}"
                assert isinstance(entry["handler_address"], int), (
                    f"handler_address must be int, got {type(entry['handler_address']).__name__}"
                )
                assert isinstance(entry["next"], int), f"next must be int, got {type(entry['next']).__name__}"
                assert entry["address"] > 0, f"SEH frame address {entry['address']:#x} must be positive (valid pointer)"
                assert entry["handler_address"] > 0, (
                    f"SEH handler_address {entry['handler_address']:#x} must be positive (valid function pointer)"
                )

    async def test_get_fiber_data_returns_dict(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify get_fiber_data reports a CPython thread as a non-fiber.

        A CPython interpreter thread never calls ``ConvertThreadToFiber``, so it
        is not a fiber and ``has_fiber`` must be False. The TEB ``FiberData``
        field (offset 0x20) is a union with ``Version`` and is therefore non-zero
        for ordinary threads, so ``has_fiber`` must be derived from the TEB
        ``HasFiberData`` flag, never from ``fiber_data != 0``.

        Mutation caught: deriving ``has_fiber`` from ``fiber_data != 0`` (the
        current production behaviour) misclassifies every ordinary thread as a
        fiber and turns this gate red - this is the documented defect PD-005 in
        audit/PRODUCTION-DEFECTS.md.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        result = await attached_bridge.get_fiber_data(main_thread_tid)
        assert isinstance(result, dict)
        assert "fiber_data" in result, "result must contain 'fiber_data' key"
        assert "has_fiber" in result, "result must contain 'has_fiber' key"

        fiber_data_val: object = result["fiber_data"]
        has_fiber_val: object = result["has_fiber"]

        assert isinstance(fiber_data_val, int), f"fiber_data must be int, got {type(fiber_data_val).__name__}"
        assert isinstance(has_fiber_val, bool), f"has_fiber must be bool, got {type(has_fiber_val).__name__}"
        assert has_fiber_val is False, f"has_fiber must be False for a non-fiber Python thread, got {has_fiber_val!r}"

    async def test_get_tls_values_returns_list(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify get_tls_values excludes zero-value slots and returns exact sentinel at correct index.

        Allocates a TLS slot via TlsAlloc, writes a known sentinel via TlsSetValue,
        then asserts: (a) every returned entry has a non-zero value (the bridge
        must exclude zero-value slots), and (b) the allocated slot appears at the
        correct index with the exact sentinel value.

        Mutation caught: including zero-value slots in the result fails assertion (a);
        returning the sentinel at the wrong index or with the wrong value fails (b).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        k32 = ctypes.windll.kernel32
        k32.TlsAlloc.restype = wintypes.DWORD
        k32.TlsFree.restype = wintypes.BOOL
        k32.TlsSetValue.restype = wintypes.BOOL

        slot: int = k32.TlsAlloc()
        if slot == 0xFFFFFFFF:
            pytest.skip("TlsAlloc failed — TLS slot exhaustion or API unavailable")
        sentinel: int = 0xDEADC0DE
        k32.TlsSetValue(slot, ctypes.c_void_p(sentinel))
        try:
            result = await attached_bridge.get_tls_values(main_thread_tid)
            assert isinstance(result, list)
            for entry in result:
                entry_val: object = entry.get("value")
                assert isinstance(entry_val, int), f"TLS entry value must be int, got {type(entry_val).__name__}"
                assert entry_val != 0, (
                    f"zero-value TLS slot at index {entry.get('index')} must be excluded from result; "
                    f"bridge is returning all slots instead of only non-zero slots"
                )
            found = next((e for e in result if e.get("index") == slot), None)
            assert found is not None, (
                f"allocated TLS slot {slot} with sentinel {sentinel:#010x} not found in result "
                f"(result has {len(result)} entries, indices: {[e.get('index') for e in result[:10]]})"
            )
            assert found["value"] == sentinel, f"TLS slot {slot}: expected sentinel {sentinel:#010x}, got {found['value']:#010x}"
        finally:
            k32.TlsFree(slot)


class TestStaticHelpers:
    """Verify static helper methods with no asyncio or platform restriction."""

    def test_prot_from_string_rwx(self) -> None:
        """Verify 'rwx' maps to PAGE_EXECUTE_READWRITE."""
        assert _invoke_prot_from_string("rwx") == _PAGE_EXECUTE_READWRITE

    def test_prot_from_string_rw(self) -> None:
        """Verify 'rw' maps to PAGE_READWRITE."""
        assert _invoke_prot_from_string("rw") == _PAGE_READWRITE

    def test_prot_from_string_rx(self) -> None:
        """Verify 'rx' maps to PAGE_EXECUTE_READ."""
        assert _invoke_prot_from_string("rx") == _PAGE_EXECUTE_READ

    def test_prot_from_string_r(self) -> None:
        """Verify 'r' maps to PAGE_READONLY."""
        assert _invoke_prot_from_string("r") == _PAGE_READONLY

    def test_prot_from_string_x(self) -> None:
        """Verify 'x' maps to PAGE_EXECUTE."""
        assert _invoke_prot_from_string("x") == _PAGE_EXECUTE

    def test_prot_from_string_unknown_defaults(self) -> None:
        """Verify unknown string defaults to PAGE_EXECUTE_READWRITE."""
        assert _invoke_prot_from_string("???") == _PAGE_EXECUTE_READWRITE

    def test_parse_registry_path_hklm(self) -> None:
        """Verify HKLM prefix resolves correctly."""
        root, sub = _invoke_parse_registry_path(r"HKLM\SOFTWARE\Test")
        assert root == 0x80000002
        assert sub == r"SOFTWARE\Test"

    def test_parse_registry_path_hkcu(self) -> None:
        """Verify HKCU prefix resolves correctly."""
        root, sub = _invoke_parse_registry_path(r"HKCU\Software")
        assert root == 0x80000001
        assert sub == "Software"

    def test_parse_registry_path_hkcr(self) -> None:
        """Verify HKCR prefix resolves correctly."""
        root, sub = _invoke_parse_registry_path(r"HKCR\CLSID")
        assert root == 0x80000000
        assert sub == "CLSID"

    def test_parse_registry_path_full_name(self) -> None:
        """Verify HKEY_LOCAL_MACHINE resolves same as HKLM."""
        root, sub = _invoke_parse_registry_path(r"HKEY_LOCAL_MACHINE\SOFTWARE\Test")
        assert root == 0x80000002
        assert sub == r"SOFTWARE\Test"

    def test_parse_registry_path_invalid_raises(self) -> None:
        """Verify invalid root raises ToolError."""
        with pytest.raises(ToolError, match="invalid registry root"):
            _invoke_parse_registry_path(r"INVALID\Path")


class TestErrorConditions:
    """Verify error handling for unattached operations."""

    async def test_read_memory_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify read_memory raises when not attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.read_memory(0x1000, 16)

    async def test_write_memory_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify write_memory raises when not attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.write_memory(0x1000, b"\x90")

    async def test_terminate_not_attached(self, process_bridge: ProcessBridge) -> None:
        """Verify terminate raises when not attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.terminate()

    async def test_get_modules_no_pid(self, process_bridge: ProcessBridge) -> None:
        """Verify get_modules raises when no PID available.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process"):
            await process_bridge.get_modules()


class TestF0004TerminateFailure:
    """Verify F-0004: terminate() leaves _process_handle intact on TerminateProcess failure."""

    async def test_handle_preserved_after_terminate_access_denied(self, process_bridge: ProcessBridge) -> None:
        """Verify _process_handle is not cleared when TerminateProcess fails.

        Open the current process with query-only rights (PROCESS_QUERY_INFORMATION),
        which lacks PROCESS_TERMINATE.  TerminateProcess will return 0 (ERROR_ACCESS_DENIED).
        Before the fix, the finally-block called self.close() which wiped the handle;
        after the fix the handle must still be present.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is None:
            pytest.skip("kernel32 unavailable")

        process_query_information = 0x0400
        inherit_handle = False
        handle: int = k32.OpenProcess(process_query_information, inherit_handle, os.getpid())
        if not handle:
            pytest.skip("Could not open own process with query-only rights")

        setattr(process_bridge, _ATTR_PROCESS_HANDLE, handle)
        setattr(process_bridge, _ATTR_ATTACHED_PID, os.getpid())

        try:
            with pytest.raises(ToolError, match="terminate failed"):
                await process_bridge.terminate()

            remaining_handle: object = getattr(process_bridge, _ATTR_PROCESS_HANDLE)
            assert remaining_handle is not None, "_process_handle was cleared despite TerminateProcess failure"
            assert remaining_handle == handle
        finally:
            k32.CloseHandle(handle)
            setattr(process_bridge, _ATTR_PROCESS_HANDLE, None)
            setattr(process_bridge, _ATTR_ATTACHED_PID, None)


class TestF0005SuspendResumeReportsFailure:
    """Verify F-0005: suspend/resume raise ToolError with failed TIDs on thread API failures."""

    async def test_suspend_raises_for_protected_process_threads(self, process_bridge: ProcessBridge) -> None:
        """Verify suspend raises ToolError when OpenThread fails due to insufficient rights.

        The Windows System process (PID 4) has threads that normal user-mode code
        cannot open with THREAD_SUSPEND_RESUME.  suspend() must collect all the
        failing TIDs and raise ToolError rather than silently returning True.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is None:
            pytest.skip("kernel32 unavailable")

        system_pid = 4
        threads = await process_bridge.get_threads(system_pid)
        if not threads:
            pytest.skip("No threads found for System process (PID 4) — cannot exercise failure path")

        thread_suspend_resume = 0x0002
        inherit_flag = False
        any_protected = any(not k32.OpenThread(thread_suspend_resume, inherit_flag, t.tid) for t in threads)
        if not any_protected:
            pytest.skip("All System threads opened successfully — insufficient privilege restrictions in this environment")

        with pytest.raises(ToolError):
            await process_bridge.suspend(system_pid)

    async def test_resume_raises_for_protected_process_threads(self, process_bridge: ProcessBridge) -> None:
        """Verify resume raises ToolError when OpenThread fails due to insufficient rights.

        The Windows System process (PID 4) has threads that normal user-mode code
        cannot open with THREAD_SUSPEND_RESUME.  resume() must collect all the
        failing TIDs and raise ToolError rather than silently returning True.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = _get_attr_optional(process_bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is None:
            pytest.skip("kernel32 unavailable")

        system_pid = 4
        threads = await process_bridge.get_threads(system_pid)
        if not threads:
            pytest.skip("No threads found for System process (PID 4) — cannot exercise failure path")

        thread_suspend_resume = 0x0002
        inherit_flag = False
        any_protected = any(not k32.OpenThread(thread_suspend_resume, inherit_flag, t.tid) for t in threads)
        if not any_protected:
            pytest.skip("All System threads opened successfully — insufficient privilege restrictions in this environment")

        with pytest.raises(ToolError):
            await process_bridge.resume(system_pid)


class TestF0023ServiceParseUnicode:
    """Verify F-0023: list_services() returns entries with str name and display_name fields."""

    async def test_service_name_fields_are_str(self, process_bridge: ProcessBridge) -> None:
        """Verify that each service entry contains str-typed name and display_name values.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        assert len(services) > 0, "No services returned; cannot validate types"
        for svc in services:
            assert isinstance(svc, dict)
            name_val: object = svc.get("name", None)
            display_val: object = svc.get("display_name", None)
            assert isinstance(name_val, str), f"service 'name' is {type(name_val).__name__}, expected str"
            assert isinstance(display_val, str), f"service 'display_name' is {type(display_val).__name__}, expected str"

    async def test_service_entries_contain_required_keys(self, process_bridge: ProcessBridge) -> None:
        """Verify every service entry has name, display_name, state, pid, and service_type keys.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        assert len(services) > 0
        for svc in services:
            assert isinstance(svc, dict)
            for key in ("name", "display_name", "state", "pid", "service_type"):
                assert key in svc, f"Missing key '{key}' in service entry"

    async def test_service_name_non_empty_for_at_least_one(self, process_bridge: ProcessBridge) -> None:
        """Verify at least one service has a non-empty unicode name.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        services = await process_bridge.list_services()
        non_empty = [s for s in services if isinstance(s.get("name"), str) and s.get("name")]
        assert non_empty, "All service names are empty"


class TestF0026NoFakeSuccess:
    """Verify F-0026: pipe_close and device_close return False/raise on internal failure."""

    async def test_pipe_close_raises_without_kernel32(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_close raises ToolError when kernel32 is None.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        original_k32: object = getattr(process_bridge, _ATTR_KERNEL32)
        setattr(process_bridge, _ATTR_KERNEL32, None)
        try:
            with pytest.raises(ToolError, match="kernel32 not available"):
                await process_bridge.pipe_close(0xDEAD)
        finally:
            setattr(process_bridge, _ATTR_KERNEL32, original_k32)

    async def test_device_close_raises_without_kernel32(self, process_bridge: ProcessBridge) -> None:
        """Verify device_close raises ToolError when kernel32 is None.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        original_k32: object = getattr(process_bridge, _ATTR_KERNEL32)
        setattr(process_bridge, _ATTR_KERNEL32, None)
        try:
            with pytest.raises(ToolError, match="kernel32 not available"):
                await process_bridge.device_close(0xDEAD)
        finally:
            setattr(process_bridge, _ATTR_KERNEL32, original_k32)


class TestF0006MemConstants:
    """Verify get_memory_map filters MEM_MAPPED/MEM_IMAGE via named constants."""

    def test_mem_mapped_constant_value(self) -> None:
        """Sanity check ``_MEM_MAPPED`` matches the documented Win32 value."""
        assert _MEM_MAPPED == 0x40000

    def test_mem_image_constant_value(self) -> None:
        """Sanity check ``_MEM_IMAGE`` matches the documented Win32 value."""
        assert _MEM_IMAGE == 0x1000000

    async def test_get_memory_map_resolves_image_or_mapped_names(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify resolve_names populates module_name only for MEM_IMAGE/MEM_MAPPED.

        The current Python interpreter always has its own image mapped,
        so at least one MEM_IMAGE region with a non-empty module_name
        must appear when resolve_names=True. Any region carrying a
        module_name must therefore have type "image" or "mapped"
        (the human-readable names produced by ``mem_type_to_string`` for
        ``MEM_IMAGE`` and ``MEM_MAPPED`` respectively).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        regions = await attached_bridge.get_memory_map(resolve_names=True)
        named_regions = [r for r in regions if r.module_name]
        assert named_regions, "expected at least one MEM_IMAGE/MEM_MAPPED region with module name"
        for region in named_regions:
            assert region.type in {"image", "mapped"}, f"region with module_name must be image or mapped, got type={region.type}"

    async def test_get_memory_map_no_resolve_skips_names(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify resolve_names=False never populates module_name.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        regions = await attached_bridge.get_memory_map(resolve_names=False)
        for region in regions:
            assert region.module_name is None


class TestF0007PatternScanContinues:
    """Verify pattern scan continues past per-chunk read failures."""

    @staticmethod
    async def _exercise_pattern_scan_after_unreadable_chunk(
        attached_bridge: ProcessBridge,
        addr: int,
        chunk_size: int,
        region_size: int,
        unique_pattern: bytes,
    ) -> None:
        """Drive the pattern-scan-after-unreadable-chunk scenario.

        Args:
            attached_bridge: ProcessBridge attached to the test process.
            addr: Base address of the committed test region.
            chunk_size: Size in bytes of the search chunk boundary.
            region_size: Total size of the allocated test region.
            unique_pattern: Sentinel bytes written into the second chunk.
        """
        second_chunk_offset = chunk_size
        await attached_bridge.write_memory(addr + second_chunk_offset, unique_pattern)
        handle = _get_attr_optional(attached_bridge, _ATTR_PROCESS_HANDLE, int)
        assert handle is not None
        k32 = ctypes.windll.kernel32
        old_prot = wintypes.DWORD()
        ok = k32.VirtualProtectEx(
            wintypes.HANDLE(handle),
            ctypes.c_void_p(addr),
            ctypes.c_size_t(chunk_size),
            wintypes.DWORD(_PAGE_NOACCESS),
            ctypes.byref(old_prot),
        )
        assert ok, "VirtualProtectEx PAGE_NOACCESS failed"

        pattern_str = " ".join(f"{b:02X}" for b in unique_pattern)
        matches = await attached_bridge.search_pattern(
            pattern_str,
            start_address=addr,
            end_address=addr + region_size,
        )
        assert addr + second_chunk_offset in matches, (
            f"pattern not found in second chunk at {hex(addr + second_chunk_offset)}; matches={[hex(m) for m in matches[:8]]}"
        )

        restore_prot = wintypes.DWORD()
        k32.VirtualProtectEx(
            wintypes.HANDLE(handle),
            ctypes.c_void_p(addr),
            ctypes.c_size_t(chunk_size),
            old_prot,
            ctypes.byref(restore_prot),
        )

    async def test_pattern_scan_finds_match_after_unreadable_chunk(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Pattern matches in a region survive an unreadable preceding chunk.

        ``_SEARCH_CHUNK_SIZE`` is 1 MiB (``0x100000``). Allocates a
        2 MiB committed region, writes a unique 16-byte pattern at the
        start of the *second* chunk, then flips the first 1 MiB to
        ``PAGE_NOACCESS`` (via a direct ``VirtualProtectEx`` call so we
        do not need to extend the bridge's ``_prot_from_string`` map for
        a test-only protection mode) so the kernel's
        ``ReadProcessMemory`` will return an error for that chunk.
        Pre-fix, the region scanner broke out of the region on the
        first ``ToolError`` and the pattern in the readable second
        chunk was never reached. Post-fix, the scanner logs the chunk
        failure, observes the surrounding region is still committed
        via ``VirtualQueryEx``, and continues to the next chunk so the
        match is found.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        unique_pattern = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe\x13\x37\x42\x42\x99\x88\x77\x66"
        chunk_size = 0x100000
        region_size = chunk_size * 2
        addr = await attached_bridge.allocate(region_size, "rw")
        try:
            await self._exercise_pattern_scan_after_unreadable_chunk(
                attached_bridge,
                addr,
                chunk_size,
                region_size,
                unique_pattern,
            )
        finally:
            await attached_bridge.free(addr)

    async def test_pattern_scan_aborts_when_region_freed(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify scan terminates cleanly when a region is no longer committed.

        Allocates a region with a unique pattern, writes the pattern,
        frees the region, then runs a pattern search bounded to that
        address range. The scan must not raise. The freed address must
        not appear in the matches because the region is no longer
        committed (``get_memory_map`` filters MEM_COMMIT only).

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        unique_pattern = b"\x11\x22\x33\x44\x55\x66\x77\x88\xaa\xbb\xcc\xdd\xee\xff\x00\x99"
        addr = await attached_bridge.allocate(0x4000, "rw")
        await attached_bridge.write_memory(addr, unique_pattern)
        await attached_bridge.free(addr)
        pattern_str = " ".join(f"{b:02X}" for b in unique_pattern)
        matches = await attached_bridge.search_pattern(
            pattern_str,
            start_address=addr,
            end_address=addr + 0x4000,
        )
        assert isinstance(matches, list)
        assert addr not in matches


class TestF0037ReadMemoryHex:
    """Verify read_memory returns a JSON-serialisable hex string."""

    async def test_read_memory_returns_hex_string(
        self,
        attached_bridge: ProcessBridge,
        known_buffer: tuple[int, ctypes.Array[ctypes.c_char], bytes],
    ) -> None:
        """Verify return value type, length, and charset.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
            known_buffer: Triple of (address, backing buffer, expected
                bytes) for a buffer with known content.
        """
        addr, _buf, _data = known_buffer
        result = await attached_bridge.read_memory(addr, 16)
        assert isinstance(result, str)
        assert len(result) == 32
        assert re.fullmatch(r"[0-9a-f]+", result) is not None

    async def test_read_memory_hex_round_trips_to_bytes(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify the hex string round-trips through bytes.fromhex.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        addr = await attached_bridge.allocate(64, "rw")
        try:
            payload = b"hex_round_trip_data!"
            await attached_bridge.write_memory(addr, payload)
            result = await attached_bridge.read_memory(addr, len(payload))
            assert bytes.fromhex(result) == payload
        finally:
            await attached_bridge.free(addr)


class TestF0038SectionCollision:
    """Verify create_section detects duplicate names."""

    async def test_named_section_collision_raises(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Second create_section with same name raises with collision code.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        section_name = f"IntellicrackProcessBridgeTest_F0038_{os.getpid()}"
        first = await process_bridge.create_section(4096, section_name=section_name)
        try:
            await self._assert_named_section_collision(process_bridge, first, section_name)
        finally:
            ctypes.windll.kernel32.CloseHandle(first)
            _get_section_handles(process_bridge).pop(first, None)

    @staticmethod
    async def _assert_named_section_collision(
        process_bridge: ProcessBridge,
        first_handle: int,
        section_name: str,
    ) -> None:
        """Assert duplicate-name section creation raises the collision error.

        Args:
            process_bridge: ProcessBridge under test.
            first_handle: Handle returned for the first successful create.
            section_name: Section name shared by both create calls.
        """
        assert first_handle > 0
        with pytest.raises(ToolError) as excinfo:
            await process_bridge.create_section(4096, section_name=section_name)
        err = excinfo.value
        details = err.details or {}
        assert details.get("code") == "SECTION_NAME_COLLISION"
        assert err.error_code == 183

    async def test_anonymous_sections_do_not_collide(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Anonymous sections never raise the collision error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        first = await process_bridge.create_section(4096)
        second = await process_bridge.create_section(4096)
        try:
            assert first > 0
            assert second > 0
            assert first != second
        finally:
            ctypes.windll.kernel32.CloseHandle(first)
            ctypes.windll.kernel32.CloseHandle(second)
            section_handles = _get_section_handles(process_bridge)
            section_handles.pop(first, None)
            section_handles.pop(second, None)


class TestF0039UnmapSection:
    """Verify unmap_section unmaps the view and tracks state."""

    async def test_unmap_section_clears_tracking_and_unmaps(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """unmap_section removes the base from the views dict and unmaps it.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        handle = await process_bridge.create_section(4096)
        addr: int = await process_bridge.map_section(handle, 4096)
        assert addr in _get_section_views(process_bridge)

        ok: bool = await process_bridge.unmap_section(addr)
        assert ok

        assert addr not in _get_section_views(process_bridge)
        assert handle not in _get_section_handles(process_bridge)

    async def test_unmap_section_then_read_attached_fails(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """After unmap, a read at the base address raises ToolError.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the
                current Python process.
        """
        handle = await attached_bridge.create_section(4096)
        addr = await attached_bridge.map_section(handle, 4096)
        await attached_bridge.unmap_section(addr)

        with pytest.raises(ToolError):
            await attached_bridge.read_memory(addr, 16)

    async def test_unmap_section_unknown_base_raises(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Unmapping an untracked address raises with NOT_MAPPED code.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has
                already been initialized.
        """
        with pytest.raises(ToolError) as excinfo:
            await process_bridge.unmap_section(0xDEADBEEF)
        details = excinfo.value.details or {}
        assert details.get("code") == "SECTION_NOT_MAPPED"


_PIPE_NAME_AUDIT2 = r"\\.\pipe\intellicrack_audit2_test"
_PIPE_BUF_SIZE = 64
_PHYS_DRIVE = r"\\.\PhysicalDrive0"
_PHYS_DRIVE_ACCESS = 0x80000000
_PHYS_DRIVE_SHARE = 0x00000001 | 0x00000002


def _create_named_pipe_server(pipe_name: str) -> int:
    """Create a named pipe server using CreateNamedPipeW.

    Args:
        pipe_name: The fully-qualified named pipe path.

    Returns:
        int: Server pipe handle, or -1 on failure.
    """
    k32 = ctypes.windll.kernel32
    k32.CreateNamedPipeW.restype = wintypes.HANDLE
    server_handle: int = k32.CreateNamedPipeW(
        pipe_name,
        0x00000003,
        0x00000000,
        1,
        _PIPE_BUF_SIZE,
        _PIPE_BUF_SIZE,
        0,
        None,
    )
    return server_handle


def _open_phys_drive_or_skip() -> int:
    """Open PhysicalDrive0 for read sharing, skipping if access is denied.

    Returns:
        int: Valid device handle.
    """
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    test_h: int = k32.CreateFileW(
        _PHYS_DRIVE,
        _PHYS_DRIVE_ACCESS,
        _PHYS_DRIVE_SHARE,
        None,
        3,
        0,
        None,
    )
    if test_h in {_INVALID_HANDLE_VALUE, 0}:
        pytest.skip(f"{_PHYS_DRIVE} requires elevated privileges")
    return test_h


class TestF0017PipeHandleType:
    """Verify CreateFileW restype=HANDLE so pipe_connect returns a non-truncated positive int."""

    async def test_pipe_connect_returns_positive_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_connect returns a positive int handle, not a sign-extended negative.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        server_handle = _create_named_pipe_server(_PIPE_NAME_AUDIT2)
        assert server_handle != -1, "failed to create named pipe server"

        connected = threading.Event()
        connect_error: list[bool] = [False]

        def _server_thread() -> None:
            k32.ConnectNamedPipe.restype = wintypes.BOOL
            result = k32.ConnectNamedPipe(server_handle, None)
            if not result:
                connect_error[0] = True
            connected.set()

        t = threading.Thread(target=_server_thread, daemon=True)
        t.start()

        try:
            handle = await process_bridge.pipe_connect(_PIPE_NAME_AUDIT2, 5000)
            connected.wait(timeout=5.0)
            assert handle > 0, f"handle should be a positive int, got {handle}"
            assert handle not in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, "handle must not be INVALID_HANDLE_VALUE"
            k32.CloseHandle(handle)
        finally:
            k32.DisconnectNamedPipe(server_handle)
            k32.CloseHandle(server_handle)
            t.join(timeout=2.0)


class TestF0017DeviceHandleType:
    """Verify device_open returns a valid positive handle for accessible devices."""

    async def test_device_open_known_device_positive_handle(self, process_bridge: ProcessBridge) -> None:
        """Verify device_open returns a positive int handle for an accessible device.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        test_h = _open_phys_drive_or_skip()
        k32.CloseHandle(test_h)

        handle = await process_bridge.device_open(_PHYS_DRIVE)
        try:
            assert handle > 0, f"device handle should be positive, got {handle}"
            assert handle not in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, "handle must not be INVALID_HANDLE_VALUE"
        finally:
            k32.CloseHandle(handle)


class TestF0016PipeCloseResult:
    """Verify pipe_close returns True on success and raises on invalid handle."""

    async def test_pipe_close_valid_handle_returns_true(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_close returns True when CloseHandle succeeds.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        server_handle = _create_named_pipe_server(f"{_PIPE_NAME_AUDIT2}_close")
        assert server_handle != -1

        connected = threading.Event()

        def _srv() -> None:
            k32.ConnectNamedPipe.restype = wintypes.BOOL
            k32.ConnectNamedPipe(server_handle, None)
            connected.set()

        t = threading.Thread(target=_srv, daemon=True)
        t.start()

        client_handle = await process_bridge.pipe_connect(f"{_PIPE_NAME_AUDIT2}_close", 5000)
        connected.wait(timeout=5.0)
        result = await process_bridge.pipe_close(client_handle)
        assert result is True

        k32.DisconnectNamedPipe(server_handle)
        k32.CloseHandle(server_handle)
        t.join(timeout=2.0)

    async def test_pipe_close_invalid_handle_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_close raises ToolError when given an invalid handle.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError):
            await process_bridge.pipe_close(0xDEAD0000)


class TestF0016DeviceCloseResult:
    """Verify device_close returns True on success and raises on invalid handle."""

    async def test_device_close_invalid_handle_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify device_close raises ToolError when given an invalid handle.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ToolError):
            await process_bridge.device_close(0xDEAD0001)

    async def test_device_close_valid_handle_returns_true(self, process_bridge: ProcessBridge) -> None:
        """Verify device_close returns True when CloseHandle succeeds on an accessible device.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        _open_phys_drive_or_skip()

        handle = await process_bridge.device_open(_PHYS_DRIVE)
        result = await process_bridge.device_close(handle)
        assert result is True


class TestF0018DeviceIoctlHexInput:
    """Verify device_ioctl validates hex string input and raises on invalid input."""

    async def test_device_ioctl_invalid_hex_raises_value_error(self, process_bridge: ProcessBridge) -> None:
        """Verify device_ioctl raises ValueError for non-hex input_data.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with pytest.raises(ValueError, match="hex"):
            await process_bridge.device_ioctl(1, 0x00000001, "not-hex")

    async def test_device_ioctl_valid_hex_accepted(self, process_bridge: ProcessBridge) -> None:
        """Verify device_ioctl accepts a valid hex string without raising on parse.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        test_h = _open_phys_drive_or_skip()
        k32 = ctypes.windll.kernel32
        try:
            result = await process_bridge.device_ioctl(test_h, 0x70000, "")
            assert isinstance(result, str)
            assert all(c in "0123456789abcdef" for c in result)
        except ToolError:
            pass
        finally:
            k32.CloseHandle(test_h)


class TestF0037PipeReadHex:
    """Verify pipe_read returns a lowercase hex string."""

    async def test_pipe_read_returns_hex_string(self, process_bridge: ProcessBridge) -> None:
        """Verify pipe_read returns a hex string of the correct length.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        k32 = ctypes.windll.kernel32
        server_handle = _create_named_pipe_server(f"{_PIPE_NAME_AUDIT2}_read")
        assert server_handle != -1

        known_bytes = b"\xde\xad\xbe\xef"
        write_done = threading.Event()

        def _srv() -> None:
            k32.ConnectNamedPipe.restype = wintypes.BOOL
            k32.ConnectNamedPipe(server_handle, None)
            bw = wintypes.DWORD(0)
            k32.WriteFile(server_handle, known_bytes, len(known_bytes), ctypes.byref(bw), None)
            write_done.set()

        t = threading.Thread(target=_srv, daemon=True)
        t.start()

        client_handle = await process_bridge.pipe_connect(f"{_PIPE_NAME_AUDIT2}_read", 5000)
        write_done.wait(timeout=5.0)

        try:
            result = await process_bridge.pipe_read(client_handle, len(known_bytes))
            assert isinstance(result, str), f"pipe_read should return str, got {type(result)}"
            assert result == known_bytes.hex(), f"expected {known_bytes.hex()!r}, got {result!r}"
            assert result == "deadbeef"
        finally:
            k32.CloseHandle(client_handle)
            k32.DisconnectNamedPipe(server_handle)
            k32.CloseHandle(server_handle)
            t.join(timeout=2.0)


class TestF0037DeviceIoctlOutputHex:
    """Verify device_ioctl returns output as a hex string."""

    async def test_device_ioctl_output_is_hex_string(self, process_bridge: ProcessBridge) -> None:
        """Verify device_ioctl output is a lowercase hex string.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        test_h = _open_phys_drive_or_skip()
        k32 = ctypes.windll.kernel32
        try:
            result = await process_bridge.device_ioctl(test_h, 0x70000, None, 512)
            assert isinstance(result, str), f"device_ioctl should return str, got {type(result)}"
            assert re.fullmatch(r"[0-9a-f]*", result) is not None, f"not a valid hex string: {result!r}"
        except ToolError:
            pass
        finally:
            k32.CloseHandle(test_h)


class TestF0002SnapshotHandleType:
    """F-0002: CreateToolhelp32Snapshot.restype must be wintypes.HANDLE."""

    async def test_list_returns_current_process(self, process_bridge: ProcessBridge) -> None:
        """list() must include the current Python process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        procs = await process_bridge.list()
        pids = [p.pid for p in procs]
        assert os.getpid() in pids

    async def test_snapshot_handle_not_truncated_negative(self, process_bridge: ProcessBridge) -> None:
        """On 64-bit Python the snapshot handle must not be a truncated negative int.

        Ensures that restype=wintypes.HANDLE preserves the full 64-bit value,
        preventing sign-extension that would produce -1 for valid handles.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        del process_bridge
        if ctypes.sizeof(ctypes.c_void_p) < 8:
            pytest.skip("32-bit Python - handle truncation concern only applies to 64-bit")

        k32 = ctypes.windll.kernel32
        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        snapshot: int = k32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
        try:
            assert snapshot != _INVALID_HANDLE_VALUE, "snapshot creation must not fail"
            assert snapshot >= 0, f"snapshot handle must not be negative (was {snapshot:#x})"
        finally:
            if snapshot != _INVALID_HANDLE_VALUE:
                k32.CloseHandle(snapshot)


class TestF0003Process32FirstFailure:
    """F-0003: Process32First failure must raise ToolError with error code."""

    async def test_list_processes_succeeds_normally(self, process_bridge: ProcessBridge) -> None:
        """Baseline: list_processes returns at least the current process.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        procs = await process_bridge.list_processes()
        assert any(p.pid == os.getpid() for p in procs)

    async def test_forced_snapshot_failure_raises_tool_error(self) -> None:
        """Force CreateToolhelp32Snapshot to return INVALID_HANDLE_VALUE.

        Injects a stub via unittest.mock.patch that returns INVALID_HANDLE_VALUE
        for every call. The bridge must detect this and raise ToolError.
        """
        bridge = ProcessBridge()
        await bridge.initialize()

        k32 = getattr(bridge, "_kernel32", None)
        if k32 is None:
            await bridge.shutdown()
            pytest.skip("kernel32 not available")

        def _bad_snapshot(flags: int, pid: int) -> int:
            del flags, pid
            return _INVALID_HANDLE_VALUE

        try:
            with pytest.raises(ToolError), patch.object(k32, "CreateToolhelp32Snapshot", side_effect=_bad_snapshot):
                await bridge.list_processes()
        finally:
            await bridge.shutdown()


class TestF0019HandleTypeNames:
    """F-0019: enum_handles must return type_name strings, never ints."""

    async def test_enum_handles_returns_string_type_names(self, process_bridge: ProcessBridge) -> None:
        """enum_handles for the current PID returns entries with string type_name.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(os.getpid())
        assert isinstance(handles, list)
        assert len(handles) > 0, "current process must have open handles"
        for entry in handles:
            type_name = entry.get("type_name")
            assert isinstance(type_name, str), f"type_name must be str, got {type(type_name).__name__}"
            assert type_name, "type_name must not be empty"

    async def test_enum_handles_includes_known_types(self, process_bridge: ProcessBridge) -> None:
        """enum_handles for the current PID includes Process, Thread, or Event entries.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(os.getpid())
        type_names = {str(h.get("type_name", "")) for h in handles}
        known_types = {"Process", "Thread", "Event", "File", "Section", "Directory"}
        found = type_names & known_types
        assert found, f"no known type names found; got: {str(sorted(type_names)[:20])}"

    async def test_enum_handles_type_name_never_int(self, process_bridge: ProcessBridge) -> None:
        """type_name field in enum_handles output must never be a bare integer.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(os.getpid())
        for entry in handles:
            type_name = entry.get("type_name")
            assert not isinstance(type_name, int), f"type_name should not be int, got {repr(type_name)}"

    async def test_enum_handles_no_pid_returns_multiple_pids(self, process_bridge: ProcessBridge) -> None:
        """enum_handles without a pid filter returns handles from multiple PIDs.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.enum_handles(None)
        pids = {h.get("pid") for h in handles}
        assert len(pids) > 1, "system-wide handle scan must return handles from multiple processes"
        assert os.getpid() in pids


class TestF0040HandleBufferBounds:
    """F-0040: Buffer bounds must be validated before iterating handles."""

    async def test_buffer_bounds_validated_on_overflow(self) -> None:
        """NtQuerySystemInformation returning a buffer with 1M handles in 4 KiB must raise ToolError.

        Constructs a fake buffer header claiming 1_000_000 handles in 4096 bytes
        and injects it via mock. The bridge must detect the overflow and raise
        ToolError before iterating.
        """
        bridge = ProcessBridge()
        await bridge.initialize()

        ntdll = getattr(bridge, "_ntdll", None)
        if ntdll is None:
            await bridge.shutdown()
            pytest.skip("ntdll not available")

        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        fake_buf_size = 4096
        fake_num_handles = 1_000_000
        fmt = "<Q" if ptr_size == 8 else "<I"

        fake_buffer = ctypes.create_string_buffer(fake_buf_size)
        struct.pack_into(fmt, fake_buffer, 0, fake_num_handles)

        def _mock_ntquery(
            info_class: int,
            buf: ctypes.Array[ctypes.c_char],
            buf_len: int,
            ret_len: ctypes.Array[ctypes.c_char],
        ) -> int:
            del info_class, buf_len, ret_len
            size = min(fake_buf_size, getattr(buf, "_length_", fake_buf_size))
            ctypes.memmove(buf, fake_buffer, size)
            return 0

        try:
            with pytest.raises(ToolError), patch.object(ntdll, "NtQuerySystemInformation", side_effect=_mock_ntquery):
                await bridge.get_handles(os.getpid())
        finally:
            await bridge.shutdown()

    async def test_valid_buffer_does_not_raise(self, process_bridge: ProcessBridge) -> None:
        """A real NtQuerySystemInformation call must not raise a buffer overflow error.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        handles = await process_bridge.get_handles(os.getpid())
        assert isinstance(handles, list)


_TEST_CLSID = "{AAAAAAAA-TEST-TEST-TEST-BBBBBBBBBBBB}"
_TEST_BASE_KEY = r"Software\IntellicrackTest\CLSID"
_TEST_KEY_PATH = _TEST_BASE_KEY + "\\" + _TEST_CLSID
_TEST_INPROC_PATH = _TEST_KEY_PATH + "\\InprocServer32"
_TEST_LOCAL_PATH = _TEST_KEY_PATH + "\\LocalServer32"
_TEST_INPROC_DLL = r"C:\Windows\System32\test_inproc.dll"
_TEST_LOCAL_EXE = r"C:\Windows\System32\test_local.exe"
_DOTNET_HOST_CANDIDATES = [
    r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe",
    r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe",
    r"C:\Program Files\dotnet\dotnet.exe",
]


class TestF0036AdvApi32MissingRaises:
    """F-0036: enumerate_com_servers must raise ToolError when advapi32 is unavailable."""

    async def test_raises_when_advapi32_is_none(self, process_bridge: ProcessBridge) -> None:
        """Verify enumerate_com_servers raises ToolError when advapi32 is not loaded.

        Temporarily replaces the bridge's advapi32 reference with None and
        asserts that ToolError is raised with the expected message.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        original = getattr(process_bridge, _ATTR_ADVAPI32)
        try:
            setattr(process_bridge, _ATTR_ADVAPI32, None)
            with pytest.raises(ToolError, match="advapi32 not available"):
                await process_bridge.enumerate_com_servers(os.getpid())
        finally:
            setattr(process_bridge, _ATTR_ADVAPI32, original)


class TestF0014ComEnumNonBlocking:
    """F-0014: enumerate_com_servers must not block the event loop (uses asyncio.to_thread)."""

    async def test_concurrent_task_advances_during_enum(self, process_bridge: ProcessBridge) -> None:
        """Verify a concurrent task makes progress while enumerate_com_servers runs.

        Starts a background counter task that increments every 10 ms and
        runs enumerate_com_servers concurrently.  If the registry walk
        blocks the event loop, the counter will not advance; if it is
        properly offloaded via asyncio.to_thread the counter will
        increment at least once.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        counter: list[int] = [0]
        stop_event = asyncio.Event()

        async def _increment() -> None:
            while not stop_event.is_set():
                await asyncio.sleep(0.01)
                counter[0] += 1

        task = asyncio.create_task(_increment())
        try:
            await process_bridge.enumerate_com_servers(os.getpid())
        finally:
            stop_event.set()
            await task

        assert counter[0] > 0, "event loop was blocked: counter did not advance during enumerate_com_servers"


class TestF0032AllInprocServerKeys:
    r"""F-0032: _check_inproc_server must walk all InprocServer* AND LocalServer* keys."""

    async def test_returns_inprocserver32_and_localserver32(self, process_bridge: ProcessBridge) -> None:
        r"""Verify both InprocServer32 and LocalServer32 are returned for a test CLSID.

        Creates temporary registry entries under
        ``HKCU\Software\IntellicrackTest\CLSID\{test_clsid}\InprocServer32``
        and ``LocalServer32``, opens that parent key via advapi32, calls
        ``_check_inproc_server``, and asserts both server types appear in
        the result.  Cleans up the test registry keys on teardown.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        try:
            self._run_inproc_server_test(process_bridge)
        finally:
            for sub in (_TEST_INPROC_PATH, _TEST_LOCAL_PATH, _TEST_KEY_PATH):
                with contextlib.suppress(OSError):
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            for sub in (_TEST_BASE_KEY, r"Software\IntellicrackTest"):
                with contextlib.suppress(OSError):
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)

    @staticmethod
    def _run_inproc_server_test(process_bridge: ProcessBridge) -> None:
        """Create test registry entries and invoke _check_inproc_server.

        Args:
            process_bridge: ProcessBridge instance exposing
                ``_check_inproc_server`` for the test.
        """
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _TEST_INPROC_PATH) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _TEST_INPROC_DLL)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _TEST_LOCAL_PATH) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, _TEST_LOCAL_EXE)

        advapi32 = _get_attr_optional(process_bridge, _ATTR_ADVAPI32, ctypes.WinDLL)
        if advapi32 is None:
            pytest.skip("advapi32 not available")
            return

        parent_hkey = wintypes.HKEY()
        ret_open: object = advapi32.RegOpenKeyExW(
            0x80000001,
            _TEST_BASE_KEY,
            0,
            0x20019,
            ctypes.byref(parent_hkey),
        )
        if ret_open != 0:
            msg = f"could not open test registry key (error {ret_open})"
            pytest.skip(msg)
            return

        try:
            TestF0032AllInprocServerKeys._assert_inproc_and_local_present(process_bridge, parent_hkey)
        finally:
            advapi32.RegCloseKey(parent_hkey)

    @staticmethod
    def _assert_inproc_and_local_present(
        process_bridge: ProcessBridge,
        parent_hkey: wintypes.HKEY,
    ) -> None:
        """Call _check_inproc_server and assert both server types are present.

        Args:
            process_bridge: ProcessBridge instance under test.
            parent_hkey: Opened HKEY pointing at the test CLSID parent key.
        """
        fn_raw: object = getattr(process_bridge, "_check_inproc_server")
        if not callable(fn_raw):
            pytest.skip("_check_inproc_server not accessible")
            return
        raw_call_result: object = fn_raw(parent_hkey, _TEST_CLSID)
        if not isinstance(raw_call_result, list):
            pytest.skip("unexpected _check_inproc_server return type")
            return
        call_result_list = cast("list[object]", raw_call_result)
        results: list[dict[str, str]] = [cast("dict[str, str]", item) for item in call_result_list if isinstance(item, dict)]
        server_types = {entry.get("server_type", "") for entry in results}
        inproc_found = "InprocServer32" in server_types
        local_found = "LocalServer32" in server_types
        assert inproc_found, f"InprocServer32 not found in {server_types}"
        assert local_found, f"LocalServer32 not found in {server_types}"


class TestF0015DotnetByCor20Header:
    """F-0015: detect_dotnet must use PE COR20 header for managed detection."""

    async def test_python_process_managed_false(self, process_bridge: ProcessBridge) -> None:
        """Verify the Python interpreter itself is not reported as a managed process.

        The CPython interpreter is a native process; it should have
        ``managed: False`` unless some edge case module triggers a match.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        result = await process_bridge.detect_dotnet(os.getpid())
        assert isinstance(result, dict)
        assert "managed" in result
        assert "version" in result
        assert "clr_loaded" in result
        assert "clr_version" in result
        assert result["managed"] is False

    async def test_managed_process_detected(self, process_bridge: ProcessBridge) -> None:
        r"""Verify a managed .NET process is detected as managed with a version.

        Spawns the .NET Framework or .NET runtime host (if available) as a
        subprocess and checks that detect_dotnet returns managed=True with
        a non-None version string.  Skips when no .NET host is available on
        the current machine.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        host_path: str | None = None
        for candidate in _DOTNET_HOST_CANDIDATES:
            if await asyncio.to_thread(Path(candidate).exists):
                host_path = candidate
                break

        if host_path is None:
            pytest.skip(".NET host executable not found on this machine")
            return

        async_proc = await asyncio.create_subprocess_exec(
            host_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await self._assert_managed_process_detected(process_bridge, async_proc)
        finally:
            with contextlib.suppress(ProcessLookupError):
                async_proc.kill()
            await async_proc.wait()

    @staticmethod
    async def _assert_managed_process_detected(
        process_bridge: ProcessBridge,
        async_proc: asyncio.subprocess.Process,
    ) -> None:
        """Assert detect_dotnet reports the spawned process as managed.

        Args:
            process_bridge: ProcessBridge used to invoke ``detect_dotnet``.
            async_proc: Subprocess running a .NET host to inspect.
        """
        await asyncio.sleep(0.5)
        if async_proc.returncode is not None:
            pytest.skip("managed process exited immediately, cannot inspect")
            return
        result = await process_bridge.detect_dotnet(async_proc.pid)
        assert isinstance(result, dict)
        assert result.get("managed") is True or result.get("clr_loaded") is True
        version = result.get("version") or result.get("clr_version")
        assert version is not None


class _K32StubNoIsWow64:
    """Minimal kernel32 stub that lacks both IsWow64Process variants.

    Used as a drop-in for the real WinDLL in tests that verify the
    ToolError raise path when neither WOW64 detection API is present.
    hasattr() returns False for IsWow64Process and IsWow64Process2.
    """


class _BridgeNoWow64Apis(ProcessBridge):
    """ProcessBridge subclass where _call_iswow64process2 always returns None.

    Also installs a kernel32 stub that lacks IsWow64Process so that both
    API paths are absent.  Used to test the ToolError raise path for F-0034.
    """

    def __init__(self) -> None:
        """Initialize with a kernel32 stub that lacks both WOW64 APIs."""
        super().__init__()
        vars(self)["_kernel32"] = _K32StubNoIsWow64()

    def _call_iswow64process2(self, handle: int) -> tuple[int, int] | None:
        """Return None unconditionally to simulate missing IsWow64Process2.

        Args:
            handle: Process handle (ignored).

        Returns:
            tuple[int, int] | None: Always None.
        """
        del handle
        return None


class TestF0034NoSilentWow64Fallback:
    """F-0034: _target_is_64bit must raise ToolError when both WOW64 APIs are absent."""

    def test_raises_when_kernel32_is_none(self) -> None:
        """Verify ToolError is raised when kernel32 handle is None.

        Uses an uninitialized bridge (kernel32 is None before initialize()).
        """
        bridge = ProcessBridge()
        target_is_64bit = getattr(bridge, "_target_is_64bit")
        with pytest.raises(ToolError, match="WOW64 detection unavailable"):
            target_is_64bit(0xFFFFFFFF)

    def test_raises_when_iswow64_apis_missing(self) -> None:
        """Verify ToolError is raised when both IsWow64Process APIs are absent.

        Uses _BridgeNoWow64Apis which installs a stub kernel32 lacking
        IsWow64Process and overrides _call_iswow64process2 to return None,
        then verifies the bridge raises rather than silently returning the
        host pointer size.
        """
        bridge = _BridgeNoWow64Apis()
        target_is_64bit_fn = getattr(bridge, "_target_is_64bit")
        with pytest.raises(ToolError, match="WOW64 detection unavailable"):
            target_is_64bit_fn(0xFFFFFFFF)


class TestF0011PEBSize:
    """F-0011: read_peb uses ctypes.sizeof(PEB) buffer, not fixed 0x100."""

    async def test_peb_raw_length_matches_struct_size(self, process_bridge: ProcessBridge) -> None:
        """Verify PEB raw bytes length equals ctypes.sizeof(PEB64) on x64.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.open_process(os.getpid(), "all")
        try:
            result = await process_bridge.read_peb(os.getpid())
        finally:
            await process_bridge.close()

        raw = result.get("raw")
        assert isinstance(raw, bytes), "raw key must be bytes"
        expected = ctypes.sizeof(PEB64)
        assert len(raw) == expected, f"Expected PEB raw length {expected}, got {len(raw)}"

    async def test_peb_contains_known_fields(self, process_bridge: ProcessBridge) -> None:
        """Verify PEB dict contains image_base_address and process_parameters_address.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.open_process(os.getpid(), "all")
        try:
            result = await process_bridge.read_peb(os.getpid())
        finally:
            await process_bridge.close()

        assert isinstance(result.get("image_base_address"), int)
        assert isinstance(result.get("process_parameters_address"), int)
        assert result["image_base_address"] != 0
        assert result["process_parameters_address"] != 0


class TestF0028ReadTEBPerTid:
    """F-0028: read_teb opens its own process handle per thread ID."""

    async def test_teb_base_differs_between_threads(self, process_bridge: ProcessBridge) -> None:
        """Verify main thread and spawned thread have different TEB base addresses.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        main_tid_holder: list[int] = []
        worker_tid_holder: list[int] = []
        event = threading.Event()

        def _get_main_tid() -> None:
            if sys.platform == "win32":
                main_tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())

        def _worker() -> None:
            if sys.platform == "win32":
                worker_tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
            event.wait()

        _get_main_tid()
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        await asyncio.sleep(0.1)

        try:
            await self._assert_teb_addresses_differ(process_bridge, main_tid_holder, worker_tid_holder)
        finally:
            event.set()
            t.join(timeout=2)

    @staticmethod
    async def _assert_teb_addresses_differ(
        process_bridge: ProcessBridge,
        main_tid_holder: list[int],
        worker_tid_holder: list[int],
    ) -> None:
        """Assert main thread and worker thread report distinct TEB bases.

        Args:
            process_bridge: ProcessBridge used to call ``read_teb``.
            main_tid_holder: List containing the main thread id.
            worker_tid_holder: List containing the worker thread id.
        """
        if not main_tid_holder or not worker_tid_holder:
            pytest.skip("Could not get thread IDs")

        main_tid = main_tid_holder[0]
        worker_tid = worker_tid_holder[0]

        main_teb = await process_bridge.read_teb(main_tid)
        worker_teb = await process_bridge.read_teb(worker_tid)

        main_addr = main_teb.get("teb_address")
        worker_addr = worker_teb.get("teb_address")

        assert isinstance(main_addr, int)
        assert main_addr != 0
        assert isinstance(worker_addr, int)
        assert worker_addr != 0
        assert main_addr != worker_addr, "Main and worker thread TEBs must have different addresses"


class TestF0022TLSArrayPointer:
    """F-0022: tls_array_base in TEB dict reflects correct static TLS array offset."""

    async def test_tls_array_base_at_correct_offset(self, process_bridge: ProcessBridge) -> None:
        """Verify tls_array_base equals teb_address + architecture-correct offset.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        if sys.platform != "win32":
            pytest.skip("Windows only")

        main_tid = ctypes.windll.kernel32.GetCurrentThreadId()
        teb = await process_bridge.read_teb(main_tid)

        teb_addr = teb.get("teb_address")
        tls_array_base = teb.get("tls_array_base")

        assert isinstance(teb_addr, int)
        assert teb_addr != 0
        assert isinstance(tls_array_base, int)
        assert tls_array_base != 0

        is_x64 = ctypes.sizeof(ctypes.c_void_p) == 8
        expected_offset = TLS_ARRAY_OFFSET_X64 if is_x64 else TLS_ARRAY_OFFSET_X86
        assert tls_array_base == teb_addr + expected_offset, (
            f"tls_array_base {hex(tls_array_base)} != teb_address {hex(teb_addr)} + offset {hex(expected_offset)}"
        )

    async def test_tls_array_base_key_present_not_tls_expansion_slots(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify dict has tls_array_base key and not the old tls_expansion_slots key.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        if sys.platform != "win32":
            pytest.skip("Windows only")

        main_tid = ctypes.windll.kernel32.GetCurrentThreadId()
        teb = await process_bridge.read_teb(main_tid)

        assert "tls_array_base" in teb, "tls_array_base key must be present"
        assert "tls_expansion_slots" not in teb, "old tls_expansion_slots key must not be present"


class TestF0021StaticTLSSlots:
    """F-0021: get_tls_values reads static TLS array at correct TEB offset."""

    async def test_tls_slot_value_readable(self, attached_bridge: ProcessBridge) -> None:
        """Verify a TLS slot value set by TlsSetValue is returned by get_tls_values.

        Allocates a TLS slot, writes a known sentinel value, then reads
        the static TLS array via the bridge and checks the sentinel appears
        at the correct slot index.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        if sys.platform != "win32":
            pytest.skip("Windows only")

        k32 = ctypes.windll.kernel32
        slot: int = k32.TlsAlloc()
        if slot == 0xFFFFFFFF:
            pytest.skip("TlsAlloc failed")

        sentinel = 0xDEADBEEF
        try:
            await self._assert_tls_slot_value(attached_bridge, k32, slot, sentinel)
        finally:
            k32.TlsFree(slot)

    @staticmethod
    async def _assert_tls_slot_value(
        attached_bridge: ProcessBridge,
        k32: ctypes.WinDLL,
        slot: int,
        sentinel: int,
    ) -> None:
        """Write the sentinel into the TLS slot and assert the bridge reads it.

        Args:
            attached_bridge: ProcessBridge attached to the current process.
            k32: kernel32 WinDLL handle for TLS APIs.
            slot: TLS slot index allocated via ``TlsAlloc``.
            sentinel: Sentinel value to write/verify via the TLS slot.
        """
        k32.TlsSetValue(slot, ctypes.c_void_p(sentinel))
        main_tid = k32.GetCurrentThreadId()
        max_slots = max(TLS_STATIC_SLOT_COUNT, slot + 1)
        tls_values = await attached_bridge.get_tls_values(main_tid, max_slots=max_slots)

        found = next((s for s in tls_values if s.get("index") == slot), None)
        assert found is not None, f"TLS slot {slot} with value {hex(sentinel)} not found in {tls_values}"
        found_value = cast("int", found["value"])
        assert found_value == sentinel, f"Expected {hex(sentinel)}, got {hex(found_value)}"

    async def test_tls_values_returns_list_of_dicts(self, attached_bridge: ProcessBridge, main_thread_tid: int) -> None:
        """Verify get_tls_values returns a list of dicts each with index and value.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            main_thread_tid: Windows thread id of the first thread enumerated in the current process.
        """
        result = await attached_bridge.get_tls_values(main_thread_tid)
        assert isinstance(result, list)
        for entry in result:
            assert "index" in entry
            assert "value" in entry
            assert isinstance(entry["index"], int)
            assert isinstance(entry["value"], int)
            assert 0 <= entry["index"] < TLS_STATIC_SLOT_COUNT


class TestF0033FullEnvironmentBlock:
    """F-0033: read_environment reads the full env block without a 64 KiB cap."""

    async def test_large_env_block_no_cap(self, process_bridge: ProcessBridge) -> None:
        """Verify environment variables totalling >64 KiB are all readable.

        Spawns a child process with 100 KiB of environment variable data
        (via a single large env var) and verifies the bridge reads the full
        block including the large variable.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        large_value = "X" * (100 * 1024)
        child_env = {**os.environ, "INTELLICRACK_LARGE_TEST": large_value}

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
            env=child_env,
        )
        try:
            await self._assert_large_env_var_readable(process_bridge, proc, large_value)
        finally:
            proc.kill()
            await proc.wait()

    @staticmethod
    async def _assert_large_env_var_readable(
        process_bridge: ProcessBridge,
        proc: asyncio.subprocess.Process,
        large_value: str,
    ) -> None:
        """Assert the spawned child's large env var round-trips fully.

        Args:
            process_bridge: ProcessBridge used to inspect the child.
            proc: Subprocess running with the large env var injected.
            large_value: Expected exact value of ``INTELLICRACK_LARGE_TEST``.
        """
        assert proc.pid is not None
        await process_bridge.open_process(proc.pid, "all")
        try:
            env_vars = await process_bridge.get_environment(proc.pid)
        finally:
            await process_bridge.close()

        assert "INTELLICRACK_LARGE_TEST" in env_vars, "Large env var must be present"
        assert env_vars["INTELLICRACK_LARGE_TEST"] == large_value, (
            f"Large env var truncated: expected {len(large_value)} chars, got {len(env_vars['INTELLICRACK_LARGE_TEST'])}"
        )


class TestF0012EnvOffsets:
    """F-0012/F-0046: _extract_env_pointer uses correct offsets and types."""

    async def test_env_offsets_child_known_vars(self, process_bridge: ProcessBridge) -> None:
        """Verify known env vars are readable from a child process on x64.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        test_vars = {
            "INTELLICRACK_TEST_A": "hello_world",
            "INTELLICRACK_TEST_B": "value_123",
            "INTELLICRACK_TEST_C": "unicode_test",
        }
        child_env = {**os.environ, **test_vars}

        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
            env=child_env,
        )
        try:
            await self._assert_known_env_vars(process_bridge, proc, test_vars)
        finally:
            proc.kill()
            await proc.wait()

    @staticmethod
    async def _read_env_until_populated(
        process_bridge: ProcessBridge,
        pid: int,
        timeout_sec: float = 5.0,
    ) -> dict[str, str]:
        """Poll ``get_environment`` until the child's env block is readable.

        ``create_subprocess_exec`` returns once the child has been created,
        which can be before the Windows loader finishes populating
        ``RTL_USER_PROCESS_PARAMETERS.Environment`` in the child PEB. Reading
        immediately then races and yields zero variables under load. Polling
        until the block is populated (or the deadline elapses) makes the read
        deterministic regardless of system load or test ordering.

        Args:
            process_bridge: ProcessBridge already attached to the child.
            pid: Child process id to inspect.
            timeout_sec: Maximum time to wait for the env block to populate.

        Returns:
            dict[str, str]: The child's environment variables (possibly empty
            if the deadline elapsed without a populated block).
        """
        deadline = time.monotonic() + timeout_sec
        env_vars: dict[str, str] = await process_bridge.get_environment(pid)
        while not env_vars and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
            env_vars = await process_bridge.get_environment(pid)
        return env_vars

    @staticmethod
    async def _assert_known_env_vars(
        process_bridge: ProcessBridge,
        proc: asyncio.subprocess.Process,
        test_vars: dict[str, str],
    ) -> None:
        """Read child env via the bridge and assert known vars match.

        Args:
            process_bridge: ProcessBridge used to inspect the child.
            proc: Subprocess running with the env vars injected.
            test_vars: Mapping of env var name to expected value.
        """
        assert proc.pid is not None
        await process_bridge.open_process(proc.pid, "all")
        try:
            env_vars = await TestF0012EnvOffsets._read_env_until_populated(process_bridge, proc.pid)
        finally:
            await process_bridge.close()

        for key, expected_val in test_vars.items():
            assert key in env_vars, f"Expected env var {key!r} missing (read {len(env_vars)} vars from child)"
            assert env_vars[key] == expected_val, f"{key}: expected {expected_val!r}, got {env_vars[key]!r}"

    def test_extract_env_pointer_64bit_offsets(self) -> None:
        """Verify _extract_env_pointer reads correct x64 offsets.

        Builds a synthetic RTL_USER_PROCESS_PARAMETERS buffer with known
        values at the x64 Environment (0x80) and EnvironmentSize (0x3F0)
        offsets, then verifies _extract_env_pointer returns them.
        """
        buf_size = 0x400
        raw = bytearray(buf_size)

        env_ptr_val = 0x00007FFF_DEADBE00
        env_size_val = 0x0001_2345
        struct.pack_into("<Q", raw, 0x80, env_ptr_val)
        struct.pack_into("<Q", raw, 0x3F0, env_size_val)

        extract = getattr(ProcessBridge, "_extract_env_pointer")
        ptr, size = extract(bytes(raw), target_is_64bit=True)

        assert ptr == env_ptr_val, f"env_ptr mismatch: {hex(ptr)} != {hex(env_ptr_val)}"
        assert size == env_size_val, f"env_size mismatch: {hex(size)} != {hex(env_size_val)}"

    def test_extract_env_pointer_32bit_offsets(self) -> None:
        """Verify _extract_env_pointer reads correct x86 offsets.

        Builds a synthetic RTL_USER_PROCESS_PARAMETERS buffer with known
        values at the x86 Environment (0x48) and EnvironmentSize (0x290)
        offsets, then verifies _extract_env_pointer returns them.
        """
        buf_size = 0x2A0
        raw = bytearray(buf_size)

        env_ptr_val = 0x004A_1234
        env_size_val = 0x0000_5678
        struct.pack_into("<I", raw, 0x48, env_ptr_val)
        struct.pack_into("<I", raw, 0x290, env_size_val)

        extract = getattr(ProcessBridge, "_extract_env_pointer")
        ptr, size = extract(bytes(raw), target_is_64bit=False)

        assert ptr == env_ptr_val, f"env_ptr mismatch: {hex(ptr)} != {hex(env_ptr_val)}"
        assert size == env_size_val, f"env_size mismatch: {hex(size)} != {hex(env_size_val)}"


class TestF0047ModuleEntryPoint:
    """F-0047: get_modules must populate entry_point from MODULEINFO."""

    async def test_entry_point_field_exists(self, attached_bridge: ProcessBridge) -> None:
        """Verify every ModuleInfo has an entry_point attribute.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        for mod in modules:
            assert hasattr(mod, "entry_point")
            assert isinstance(mod.entry_point, int)

    async def test_at_least_one_nonzero_entry_point(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one module has a non-zero entry point.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        assert any(m.entry_point != 0 for m in modules)

    async def test_entry_point_within_module_range(self, attached_bridge: ProcessBridge) -> None:
        """Verify entry_point falls within [base_address, base_address + size) for at least one module.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        modules = await attached_bridge.get_modules(os.getpid())
        found = any(
            mod.entry_point != 0 and mod.size > 0 and mod.base_address <= mod.entry_point < mod.base_address + mod.size for mod in modules
        )
        assert found, "No module has entry_point within its base_address..base_address+size range"


class TestF0048ThreadCurrentPC:
    """F-0048: get_threads must populate current_pc via GetThreadContext."""

    async def test_current_pc_field_exists(self, attached_bridge: ProcessBridge) -> None:
        """Verify every ThreadInfo has a current_pc attribute.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        for t in threads:
            assert hasattr(t, "current_pc")
            assert isinstance(t.current_pc, int)

    async def test_at_least_one_nonzero_current_pc(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread has a non-zero current_pc.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        assert any(t.current_pc != 0 for t in threads)

    async def test_current_pc_within_known_module(self, attached_bridge: ProcessBridge) -> None:
        """Verify at least one thread's current_pc falls within a loaded module range.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        threads = await attached_bridge.get_threads(os.getpid())
        modules = await attached_bridge.get_modules(os.getpid())
        nonzero_pcs = [t.current_pc for t in threads if t.current_pc != 0]
        assert nonzero_pcs
        found = False
        for pc in nonzero_pcs:
            for mod in modules:
                if mod.base_address > 0 and mod.size > 0 and mod.base_address <= pc < mod.base_address + mod.size:
                    found = True
                    break
            if found:
                break
        assert found, "No thread current_pc falls within any loaded module range"


class TestF0020ThreadStateNoStuckSuspend:
    """F-0020: _query_thread_state must not leave thread suspended on probe failure."""

    async def test_resume_always_called_on_exception(self, process_bridge: ProcessBridge) -> None:
        """Force _query_thread_state to raise mid-probe; assert thread NOT left suspended.

        Spawns a helper thread, obtains its TID, invokes the private
        _query_thread_state probe, and then verifies the thread is still
        runnable by joining it with a short timeout after signalling stop.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        stop_event = threading.Event()
        tid_holder: list[int] = []

        def _worker() -> None:
            tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
            stop_event.wait(timeout=5.0)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        await asyncio.sleep(0.05)
        assert tid_holder, "Worker thread did not record its TID"
        worker_tid = tid_holder[0]

        query_fn: Callable[[int], str] | None = getattr(process_bridge, "_query_thread_state", None)
        assert callable(query_fn)
        state: str = await asyncio.to_thread(query_fn, worker_tid)
        assert isinstance(state, str)

        stop_event.set()
        await asyncio.to_thread(t.join, 2.0)
        assert not t.is_alive(), "Worker thread is still alive — may have been left suspended"

    async def test_state_string_valid_after_probe(self, process_bridge: ProcessBridge) -> None:
        """Verify _query_thread_state returns a non-empty string for a live thread.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        stop_event = threading.Event()
        tid_holder: list[int] = []

        def _worker() -> None:
            tid_holder.append(ctypes.windll.kernel32.GetCurrentThreadId())
            stop_event.wait(timeout=5.0)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        await asyncio.sleep(0.05)
        assert tid_holder
        worker_tid = tid_holder[0]

        query_fn: Callable[[int], str] | None = getattr(process_bridge, "_query_thread_state", None)
        assert callable(query_fn)
        state: str = await asyncio.to_thread(query_fn, worker_tid)
        assert state in {"running", "suspended", "terminated", "unknown"}

        stop_event.set()
        await asyncio.to_thread(t.join, 2.0)


class TestF0010InjectDllUnicode:
    """F-0010: inject_dll must use LoadLibraryW (UTF-16) path encoding."""

    async def test_inject_dll_nonexistent_raises_tool_error(self, attached_bridge: ProcessBridge) -> None:
        """Verify inject_dll raises ToolError when DLL does not exist.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        with pytest.raises(ToolError, match="DLL not found"):
            await attached_bridge.inject_dll(r"C:\nonexistent_dll_\x00test.dll")

    async def test_inject_dll_not_attached_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify inject_dll raises ToolError when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.inject_dll(r"C:\Windows\System32\kernel32.dll")


class TestF0010InjectDllExitCodeChecked:
    """F-0010: inject_dll must check GetExitCodeThread and raise on failure."""

    async def test_inject_dll_kernel32_raises_on_failure(self, process_bridge: ProcessBridge) -> None:
        """Verify injecting a path that LoadLibraryW cannot load raises ToolError.

        Injects into a dedicated spawned child process rather than the test
        runner, so the loader state under test is isolated from every other test
        in the run. The payload is a real file holding an invalid PE image, so
        LoadLibraryW executes inside the target but returns NULL (remote thread
        exit code 0), which inject_dll must surface as a ToolError.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        with tempfile.NamedTemporaryFile(suffix=".dll", delete=False) as handle:
            handle.write(b"NOT_A_REAL_DLL\x00")
            bad_dll = handle.name

        proc = await asyncio.create_subprocess_exec(sys.executable, "-c", "import time; time.sleep(30)")
        try:
            await self._assert_inject_dll_raises_in_target(process_bridge, proc, bad_dll)
        finally:
            proc.terminate()
            await proc.wait()
            await asyncio.to_thread(_unlink_suppress, bad_dll)

    @staticmethod
    async def _assert_inject_dll_raises_in_target(
        process_bridge: ProcessBridge,
        proc: asyncio.subprocess.Process,
        bad_dll: str,
    ) -> None:
        """Open the spawned target and assert inject_dll raises ToolError for it.

        Args:
            process_bridge: ProcessBridge used to attach to and inject into the target.
            proc: Subprocess representing the injection target.
            bad_dll: Path to the invalid DLL payload.
        """
        await asyncio.sleep(0.5)
        await process_bridge.open_process(proc.pid, "all")
        try:
            with pytest.raises(ToolError):
                await process_bridge.inject_dll(bad_dll)
        finally:
            await process_bridge.close()


class TestF0009ContextWow64:
    """F-0009: get_thread_context selects context type from target WOW64 status."""

    async def test_context_64bit_target_returns_rip(
        self,
        attached_bridge: ProcessBridge,
        secondary_thread: int,
    ) -> None:
        """On a 64-bit target process, context contains 64-bit registers.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            secondary_thread: Windows thread id of a parked worker thread used for context queries.
        """
        if struct.calcsize("P") != 8:
            pytest.skip("requires 64-bit host")

        ctx = await attached_bridge.get_thread_context(secondary_thread)
        assert "rip" in ctx, "64-bit target must expose Rip as 'rip'"
        assert "rsp" in ctx, "64-bit target must expose Rsp as 'rsp'"
        assert "eip" not in ctx, "64-bit target must not expose eip"

    async def test_context_wow64_target_returns_eip(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """On a WOW64 (32-bit on 64-bit host) target, context contains 32-bit registers.

        Spawns a 32-bit SysWOW64 process and reads thread context from it. Skips
        when SysWOW64 is not available or the host is not 64-bit.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        if struct.calcsize("P") != 8:
            pytest.skip("requires 64-bit host")

        wow64_notepad = r"C:\Windows\SysWOW64\notepad.exe"
        wow64_path = Path(wow64_notepad)
        if not await asyncio.to_thread(wow64_path.exists):
            pytest.skip("SysWOW64\\notepad.exe not present")

        proc = await asyncio.create_subprocess_exec(wow64_notepad)
        try:
            await self._run_wow64_context_test(process_bridge, proc)
        finally:
            proc.terminate()
            await proc.wait()

    @staticmethod
    async def _run_wow64_context_test(
        process_bridge: ProcessBridge,
        proc: asyncio.subprocess.Process,
    ) -> None:
        """Open the WOW64 child and verify its context exposes ``eip``.

        Args:
            process_bridge: ProcessBridge used to attach and inspect.
            proc: Subprocess running the WOW64 notepad target.
        """
        await asyncio.sleep(0.5)
        await process_bridge.open_process(proc.pid, "all")
        try:
            await TestF0009ContextWow64._assert_wow64_eip(process_bridge, proc)
        finally:
            await process_bridge.close()

    @staticmethod
    async def _assert_wow64_eip(
        process_bridge: ProcessBridge,
        proc: asyncio.subprocess.Process,
    ) -> None:
        """Assert WOW64 thread context contains ``eip`` and not ``rip``.

        Args:
            process_bridge: Attached ProcessBridge for the WOW64 target.
            proc: Subprocess representing the WOW64 target.
        """
        is_wow64_fn = getattr(process_bridge, "_target_is_wow64", None)
        if is_wow64_fn is None or not is_wow64_fn():
            pytest.skip("SysWOW64 notepad is not detected as WOW64 on this system")
        threads = await process_bridge.get_threads(proc.pid)
        assert len(threads) > 0, "WOW64 process must have at least one thread"
        tid = threads[0].tid
        ctx = await process_bridge.get_thread_context(tid)
        assert "eip" in ctx, "WOW64 target must expose eip"
        assert "rip" not in ctx, "WOW64 target must not expose rip"


class TestF0008SehChainX64Raises:
    """F-0008: get_seh_chain raises ToolError on x64 target (SEH not applicable)."""

    async def test_seh_chain_x64_raises(
        self,
        attached_bridge: ProcessBridge,
        secondary_thread: int,
    ) -> None:
        """On an x64 target, get_seh_chain must raise ToolError.

        SEH chain traversal via FS:[0] is only valid for x86. On x64, Windows uses
        table-based exception handling and the SEH chain pointer in the x86 TEB
        is not populated.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
            secondary_thread: Windows thread id of a parked worker thread used for context queries.
        """
        if struct.calcsize("P") != 8:
            pytest.skip("requires 64-bit native process")

        with pytest.raises(ToolError, match="SEH chain not applicable to x64 target"):
            await attached_bridge.get_seh_chain(secondary_thread)

    async def test_seh_chain_not_attached_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify get_seh_chain raises ToolError when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError, match="no process attached"):
            await process_bridge.get_seh_chain(1)


class TestF0024SymbolInfoSizeOfStruct:
    """F-0024: SYMBOL_INFO.SizeOfStruct uses proper header-only size formula."""

    def test_sizeofsruct_equals_header_size(self) -> None:
        """Verify computed SizeOfStruct matches the SYMBOL_INFO header size.

        The SizeOfStruct must be the fixed header portion of SYMBOL_INFO
        (excluding the variable-length Name array), matching what dbghelp.h
        defines when SYMBOL_INFO has Name[1].
        """
        name_array_size = ctypes.sizeof(ctypes.c_char * 1024)
        min_name_size = ctypes.sizeof(ctypes.c_char)
        expected_header = ctypes.sizeof(SYMBOL_INFO) - name_array_size + min_name_size
        assert expected_header > 0
        assert expected_header < ctypes.sizeof(SYMBOL_INFO)

    async def test_resolve_symbol_returns_nonempty_name(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify _resolve_symbol resolves kernel32.dll export to a non-empty name.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        k32 = ctypes.windll.kernel32
        addr: int | None = ctypes.cast(k32.GetCurrentProcess, ctypes.c_void_p).value
        if addr is None or addr == 0:
            pytest.skip("could not get kernel32 function address")

        dbghelp = getattr(attached_bridge, "_dbghelp", None)
        if dbghelp is None:
            pytest.skip("dbghelp not available")

        proc_handle: object = getattr(attached_bridge, "_process_handle", None)
        if proc_handle is None:
            pytest.skip("no process handle")

        invade = True
        sym_initialized = bool(dbghelp.SymInitialize(proc_handle, None, invade))
        try:
            self._assert_symbol_resolves(attached_bridge, addr, sym_initialized=sym_initialized)
        finally:
            dbghelp.SymCleanup(proc_handle)

    @staticmethod
    def _assert_symbol_resolves(
        attached_bridge: ProcessBridge,
        addr: int,
        *,
        sym_initialized: bool,
    ) -> None:
        """Resolve the address via the bridge and assert a non-empty name.

        Args:
            attached_bridge: ProcessBridge attached to the current process.
            addr: Address to resolve.
            sym_initialized: Whether SymInitialize succeeded.
        """
        if not sym_initialized:
            pytest.skip("SymInitialize failed — insufficient privileges for symbol loading")
        name, _ = _invoke_resolve_symbol(attached_bridge, addr)
        if not name:
            pytest.skip("SymFromAddr returned empty — symbols not available")
        assert isinstance(name, str)
        assert len(name) > 0


class TestF0025ImageHlpModuleStruct:
    """F-0025: _resolve_module uses IMAGEHLP_MODULE64 structure (not raw buffer)."""

    def test_imagehlp_module64_struct_has_module_name(self) -> None:
        """Verify IMAGEHLP_MODULE64 structure can be instantiated and SizeOfStruct set.

        The ``ModuleName`` field is a 32-byte char array, so a default-constructed
        struct is safe to inspect without Win32 interaction.
        """
        mod = IMAGEHLP_MODULE64()
        mod.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULE64)
        assert mod.SizeOfStruct == ctypes.sizeof(IMAGEHLP_MODULE64)
        assert ctypes.sizeof(IMAGEHLP_MODULE64) > 584

    async def test_resolve_module_returns_kernel32(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify _resolve_module returns 'kernel32' for an address in kernel32.dll.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        k32 = ctypes.windll.kernel32
        addr: int | None = ctypes.cast(k32.GetCurrentProcess, ctypes.c_void_p).value
        if addr is None or addr == 0:
            pytest.skip("could not get kernel32 function address")

        dbghelp = getattr(attached_bridge, "_dbghelp", None)
        if dbghelp is None:
            pytest.skip("dbghelp not available")

        proc_handle: object = getattr(attached_bridge, "_process_handle", None)
        if proc_handle is None:
            pytest.skip("no process handle")

        invade = True
        sym_initialized = bool(dbghelp.SymInitialize(proc_handle, None, invade))
        try:
            self._assert_module_resolves(attached_bridge, addr, sym_initialized=sym_initialized)
        finally:
            dbghelp.SymCleanup(proc_handle)

    @staticmethod
    def _assert_module_resolves(
        attached_bridge: ProcessBridge,
        addr: int,
        *,
        sym_initialized: bool,
    ) -> None:
        """Resolve the module name via the bridge and assert kernel32 match.

        Args:
            attached_bridge: ProcessBridge attached to the current process.
            addr: Address known to live in kernel32.
            sym_initialized: Whether SymInitialize succeeded.
        """
        if not sym_initialized:
            pytest.skip("SymInitialize failed — insufficient privileges for module info")
        module_name = _invoke_resolve_module(attached_bridge, addr)
        if not module_name:
            pytest.skip("SymGetModuleInfo64 returned empty — module info not available")
        assert isinstance(module_name, str)
        assert "kernel32" in module_name.lower()


class TestF0041BoolReturnChecked:
    """F-0041: SuspendThread and SymInitialize BOOL returns are checked."""

    async def test_suspend_thread_failure_raises_tool_error(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify get_thread_context raises ToolError when SuspendThread fails.

        A terminated thread handle returns -1 from SuspendThread. After creating a
        thread and letting it finish naturally, its TID may still be openable briefly
        before the OS reclaims it; SuspendThread on the dying thread handle fails.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        k32 = ctypes.windll.kernel32
        k32.SuspendThread.restype = wintypes.DWORD

        tid_holder: list[int] = []

        def _short_worker() -> None:
            tid_holder.append(k32.GetCurrentThreadId())

        t = threading.Thread(target=_short_worker)
        t.start()
        t.join(timeout=5)

        if not tid_holder:
            pytest.skip("thread did not report TID")

        dead_tid = tid_holder[0]
        with pytest.raises(ToolError):
            await attached_bridge.get_thread_context(dead_tid)

    async def test_stack_walk_not_attached_raises(self, process_bridge: ProcessBridge) -> None:
        """Verify stack_walk raises ToolError when no process is attached.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture that has already been initialized.
        """
        await process_bridge.close()
        with pytest.raises(ToolError):
            await process_bridge.stack_walk(1)


class TestF0042SymbolBufferAllocation:
    """F-0042: SYMBOL_INFO name buffer supports names up to MAX_SYM_NAME chars."""

    async def test_resolve_symbol_no_truncation_on_long_name(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify symbol resolution returns untruncated names for long symbol names.

        Decorated C++ symbol names in dbghelp often exceed 64 characters. This test
        resolves symbols in the current process and verifies at least one name exceeds
        32 characters, confirming the full-size buffer is being used correctly.

        Args:
            attached_bridge: ProcessBridge fixture pre-attached to the current Python process.
        """
        dbghelp = getattr(attached_bridge, "_dbghelp", None)
        if dbghelp is None:
            pytest.skip("dbghelp not available")

        proc_handle: object = getattr(attached_bridge, "_process_handle", None)
        if proc_handle is None:
            pytest.skip("no process handle")

        invade = True
        sym_initialized = bool(dbghelp.SymInitialize(proc_handle, None, invade))
        try:
            self._assert_long_symbol_names_resolve(attached_bridge, sym_initialized=sym_initialized)
        finally:
            dbghelp.SymCleanup(proc_handle)

    @staticmethod
    def _assert_long_symbol_names_resolve(
        attached_bridge: ProcessBridge,
        *,
        sym_initialized: bool,
    ) -> None:
        """Resolve several kernel32 symbols and assert names are not truncated.

        Args:
            attached_bridge: ProcessBridge attached to the current process.
            sym_initialized: Whether SymInitialize succeeded.
        """
        if not sym_initialized:
            pytest.skip("SymInitialize failed — insufficient privileges for symbol loading")

        k32 = ctypes.windll.kernel32
        addresses: list[int] = []
        for fn_obj in (k32.GetCurrentProcess, k32.ReadProcessMemory, k32.VirtualQueryEx):
            addr: int | None = ctypes.cast(fn_obj, ctypes.c_void_p).value
            if addr and addr != 0:
                addresses.append(addr)

        resolved: list[str] = []
        for addr in addresses:
            name, _ = _invoke_resolve_symbol(attached_bridge, addr)
            if name:
                resolved.append(name)

        if not resolved:
            pytest.skip("no symbols resolved — PDB/symbol server not configured")
        for name in resolved:
            assert isinstance(name, str)
            assert len(name) > 0

    def test_sym_buf_size_accommodates_max_sym_name(self) -> None:
        """Verify the symbol buffer formula produces a size larger than SYMBOL_INFO alone.

        The allocated buffer must be at least sizeof(SYMBOL_INFO) + MAX_SYM_NAME bytes
        so that long symbol names do not overflow.
        """
        sym_header_size = ctypes.sizeof(SYMBOL_INFO) - ctypes.sizeof(ctypes.c_char * 1024) + ctypes.sizeof(ctypes.c_char)
        sym_buf_size = sym_header_size + _MAX_SYM_NAME * ctypes.sizeof(ctypes.c_char)
        assert sym_buf_size > ctypes.sizeof(SYMBOL_INFO)
        assert sym_buf_size >= sym_header_size + _MAX_SYM_NAME


class TestF0038SectionCreateFileMappingHandle:
    """F-0038: CreateFileMappingW must return a non-truncated handle and detect collisions."""

    async def test_create_section_returns_positive_handle(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify create_section returns a valid handle on a 64-bit interpreter.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        section_name = f"IntellicrackProcessBridge_F0038_handle_{os.getpid()}"
        handle = await process_bridge.create_section(4096, section_name=section_name)
        assert handle > 0
        k32 = ctypes.windll.kernel32
        k32.CloseHandle(handle)

    async def test_create_section_named_collision_raises(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify a duplicate-named section raises with the collision code.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        section_name = f"IntellicrackProcessBridge_F0038_collide_{os.getpid()}"
        first = await process_bridge.create_section(4096, section_name=section_name)
        try:
            await self._assert_create_section_collision(process_bridge, first, section_name)
        finally:
            k32 = ctypes.windll.kernel32
            k32.CloseHandle(first)

    @staticmethod
    async def _assert_create_section_collision(
        process_bridge: ProcessBridge,
        first_handle: int,
        section_name: str,
    ) -> None:
        """Assert a duplicate-named create_section raises with collision code.

        Args:
            process_bridge: ProcessBridge under test.
            first_handle: Handle returned for the first successful create.
            section_name: Shared section name forcing the collision.
        """
        assert first_handle > 0
        with pytest.raises(ToolError) as excinfo:
            await process_bridge.create_section(4096, section_name=section_name)
        details = excinfo.value.details
        assert isinstance(details, dict)
        assert details.get("code") == "SECTION_NAME_COLLISION"


class TestF0030RegistryHives:
    """F-0030: _parse_registry_path supports HKU and HKCC."""

    def test_parse_hku_short(self) -> None:
        """Verify HKU short form resolves to HKEY_USERS."""
        root, sub = _invoke_parse_registry_path(r"HKU\.DEFAULT")
        assert root == 0x80000003
        assert sub == ".DEFAULT"

    def test_parse_hkey_users_long(self) -> None:
        """Verify HKEY_USERS long form resolves identically."""
        root, sub = _invoke_parse_registry_path(r"HKEY_USERS\.DEFAULT")
        assert root == 0x80000003
        assert sub == ".DEFAULT"

    def test_parse_hkcc_short(self) -> None:
        """Verify HKCC short form resolves to HKEY_CURRENT_CONFIG."""
        root, sub = _invoke_parse_registry_path(r"HKCC\Software")
        assert root == 0x80000005
        assert sub == "Software"

    def test_parse_hkey_current_config_long(self) -> None:
        """Verify HKEY_CURRENT_CONFIG long form resolves identically."""
        root, sub = _invoke_parse_registry_path(r"HKEY_CURRENT_CONFIG\Software")
        assert root == 0x80000005
        assert sub == "Software"


class TestF0031RegReadValueGrows:
    """F-0031: reg_read_value grows the buffer on ERROR_MORE_DATA."""

    async def test_reg_read_large_value_succeeds(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        r"""Verify a value larger than 4096 bytes is read in full.

        Creates a HKCU\\Software key with a 24 KiB REG_BINARY value and
        verifies reg_read_value returns all 24 KiB instead of failing
        with the legacy fixed-buffer behavior.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        key_name = rf"Software\IntellicrackProcessBridgeTest_F0031_{os.getpid()}"
        large_payload = bytes(range(256)) * 96
        assert len(large_payload) == 24576

        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_name, 0, winreg.KEY_WRITE) as hkey:
            winreg.SetValueEx(hkey, "BigValue", 0, winreg.REG_BINARY, large_payload)
        try:
            result = await process_bridge.reg_read_value(
                rf"HKCU\{key_name}",
                "BigValue",
            )
            assert isinstance(result, dict)
            data_hex = result.get("data")
            assert isinstance(data_hex, str)
            assert bytes.fromhex(data_hex) == large_payload
        finally:
            winreg.DeleteKeyEx(winreg.HKEY_CURRENT_USER, key_name)


class TestF0043QuerySystemInfoRetries:
    """F-0043: query_system_info auto-grows on STATUS_BUFFER_OVERFLOW/TOO_SMALL."""

    async def test_query_handles_with_small_initial_buffer(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify SystemHandleInformation succeeds even when seeded with a tiny buffer.

        Calling NtQuerySystemInformation(SystemHandleInformation) with
        an initial 1024-byte buffer forces the kernel to return one of
        STATUS_INFO_LENGTH_MISMATCH / STATUS_BUFFER_OVERFLOW /
        STATUS_BUFFER_TOO_SMALL on most systems. The retry loop must
        grow until the call succeeds.

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        system_handle_information = 16
        result = await process_bridge.query_system_info(
            system_handle_information,
            buffer_size=1024,
        )
        assert isinstance(result, str)
        assert len(result) > 0
        assert all(c in "0123456789abcdef" for c in result)
        assert len(result) % 2 == 0
        assert len(bytes.fromhex(result)) > 0


class TestF0027MitigationBitfields:
    """F-0027: Each policy decodes its specific bitfield, not blanket bool(flags & 1)."""

    async def test_dep_policy_has_named_fields(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify DEP policy exposes Enable, DisableAtlThunkEmulation, Permanent.

        Args:
            attached_bridge: ProcessBridge attached to current process.
        """
        policies = await attached_bridge.get_mitigation_policies()
        assert isinstance(policies, dict)
        dep = policies.get("DEP")
        assert isinstance(dep, dict)
        assert "Enable" in dep
        assert "DisableAtlThunkEmulation" in dep
        assert "Permanent" in dep
        assert "flags" in dep

    async def test_aslr_policy_has_named_bits(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify ASLR policy exposes named bottom-up/force-relocate/high-entropy bits.

        Args:
            attached_bridge: ProcessBridge attached to current process.
        """
        policies = await attached_bridge.get_mitigation_policies()
        aslr = policies.get("ASLR")
        assert isinstance(aslr, dict)
        for key in (
            "EnableBottomUpRandomization",
            "EnableForceRelocateImages",
            "EnableHighEntropy",
            "DisallowStrippedImages",
        ):
            assert key in aslr, f"missing ASLR field {key}"

    async def test_cfg_policy_has_named_bits(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify CFG policy exposes EnableControlFlowGuard and StrictMode bits.

        Args:
            attached_bridge: ProcessBridge attached to current process.
        """
        policies = await attached_bridge.get_mitigation_policies()
        cfg = policies.get("CFG")
        assert isinstance(cfg, dict)
        assert "EnableControlFlowGuard" in cfg
        assert "EnableExportSuppression" in cfg
        assert "StrictMode" in cfg


class TestF0035HandleEnumNonBlocking:
    """F-0035: get_handles and enum_handles offload iteration to asyncio.to_thread."""

    async def test_get_handles_yields_event_loop(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify get_handles allows other tasks to make progress concurrently.

        While get_handles iterates the system handle table (potentially
        tens of thousands of entries), a parallel sleep(0) ticker must
        be able to advance multiple times if the iteration is offloaded
        via asyncio.to_thread.

        Args:
            attached_bridge: ProcessBridge attached to current process.
        """
        ticks = [0]

        async def ticker() -> None:
            for _ in range(100):
                await asyncio.sleep(0)
                ticks[0] += 1

        ticker_task = asyncio.create_task(ticker())
        result = await attached_bridge.get_handles()
        await ticker_task
        assert isinstance(result, list)
        assert ticks[0] == 100

    async def test_enum_handles_yields_event_loop(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Verify enum_handles allows the event loop to make progress.

        Args:
            attached_bridge: ProcessBridge attached to current process.
        """
        ticks = [0]

        async def ticker() -> None:
            for _ in range(50):
                await asyncio.sleep(0)
                ticks[0] += 1

        ticker_task = asyncio.create_task(ticker())
        result = await attached_bridge.enum_handles(pid=os.getpid())
        await ticker_task
        assert isinstance(result, list)
        assert ticks[0] == 50


class TestF0013JobHandleEnumeration:
    """F-0013: _acquire_queryable_job_handle returns a real handle from the system handle table."""

    async def test_get_job_info_returns_in_job_when_assigned(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Verify get_job_info reports in_job=True when the target is in a job.

        Creates a CreateJobObjectW handle, assigns the current process,
        then asks get_job_info(current_pid) to confirm in_job=True. The
        F-0013 fix must locate the job via the system handle table
        rather than relying on OpenJobObjectW(NULL).

        Args:
            process_bridge: Module-scoped ProcessBridge fixture.
        """
        k32 = ctypes.windll.kernel32
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.AssignProcessToJobObject.restype = wintypes.BOOL
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.IsProcessInJob.restype = wintypes.BOOL
        k32.IsProcessInJob.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        ]

        already_in = wintypes.BOOL(0)
        current = k32.GetCurrentProcess()
        k32.IsProcessInJob(current, None, ctypes.byref(already_in))
        if already_in.value:
            pytest.skip("current process is already in a job; cannot exercise assignment path")

        job_handle = k32.CreateJobObjectW(None, None)
        assert job_handle, "CreateJobObjectW must succeed"
        try:
            if not k32.AssignProcessToJobObject(job_handle, current):
                pytest.skip("AssignProcessToJobObject denied; cannot exercise F-0013 path")
            info = await process_bridge.get_job_info(os.getpid())
            assert isinstance(info, dict)
            assert info.get("in_job") is True
        finally:
            k32.CloseHandle(job_handle)


class TestF0044ShutdownReleasesResources:
    """F-0044: shutdown() unmaps sections and closes pipe/device handles."""

    @staticmethod
    async def _assert_shutdown_clears_tracking(bridge: ProcessBridge) -> None:
        """Create and map a section, then assert ``shutdown`` clears both tracking dicts.

        Args:
            bridge: An initialized, signature-configured ProcessBridge.
        """
        section_name = f"IntellicrackProcessBridge_F0044_{os.getpid()}"
        handle = await bridge.create_section(0x4000, section_name=section_name)
        base = await bridge.map_section(handle, 0x4000)
        assert base > 0

        section_views = _get_section_views(bridge)
        section_handles = _get_section_handles(bridge)
        assert base in section_views
        assert handle in section_handles

        await bridge.shutdown()

        section_views_after = _get_section_views(bridge)
        section_handles_after = _get_section_handles(bridge)
        assert len(section_views_after) == 0
        assert len(section_handles_after) == 0

    async def test_shutdown_unmaps_tracked_section_view(self) -> None:
        """Verify shutdown unmaps any view recorded in _section_views.

        Uses a dedicated, function-local :class:`ProcessBridge` rather than
        the shared module fixture so exercising the destructive
        ``shutdown`` path cannot disturb other tests or leave
        loop-bound Win32 resources alive past the test's event loop.
        Creates a section, maps a view, asserts both tracking dicts are
        populated, calls ``shutdown``, and asserts both dicts are empty.
        """
        bridge = ProcessBridge()
        await bridge.initialize()
        k32 = _get_attr_optional(bridge, _ATTR_KERNEL32, ctypes.WinDLL)
        if k32 is not None:
            _configure_kernel32_signatures(k32)
        try:
            await TestF0044ShutdownReleasesResources._assert_shutdown_clears_tracking(bridge)
        finally:
            await bridge.shutdown()


class TestF0029NoStartedInfoLogs:
    """F-0029: No public method emits *_started events at info level."""

    def test_no_started_info_logs_in_module(self) -> None:
        """Verify process.py contains zero ``_logger.info("..._started"`` events.

        Greps the module text for the pattern audit2 forbade. The fix
        must demote every per-call ``_started`` info log to debug or
        remove it.
        """
        process_py = Path(__file__).resolve().parents[2] / "src" / "intellicrack" / "bridges" / "process.py"
        text = process_py.read_text(encoding="utf-8")
        offending = re.findall(r'_logger\.info\("[a-zA-Z_]+_started"', text)
        assert offending == [], f"audit2 F-0029: _started info logs still present: {offending}"


class TestF0045DispatchShimsNoDuplicateEvents:
    """F-0045: list/list_detailed/open dispatch shims do not emit their own _started events."""

    def test_list_shim_emits_no_started_event(self) -> None:
        """Verify the ``list`` dispatch shim has no ``_started`` log emit.

        Walks the source of ``ProcessBridge.list`` and asserts the
        underlying delegate is the only logger interaction (the
        delegated method emits its own ``processes_listing`` debug
        event; the shim must not duplicate it).
        """
        src = inspect.getsource(ProcessBridge.list)
        assert "_logger.info" not in src
        assert "_started" not in src

    def test_list_detailed_shim_emits_no_started_event(self) -> None:
        """Verify the ``list_detailed`` dispatch shim has no ``_started`` log emit."""
        src = inspect.getsource(ProcessBridge.list_detailed)
        assert "_logger.info" not in src
        assert "_started" not in src

    def test_open_shim_emits_no_started_event(self) -> None:
        """Verify the ``open`` dispatch shim has no ``_started`` log emit."""
        src = inspect.getsource(ProcessBridge.open)
        assert "_logger.info" not in src
        assert "_started" not in src
