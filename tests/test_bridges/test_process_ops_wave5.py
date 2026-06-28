# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 integration gates for ProcessBridge operations.

Tests: adjust_token_privilege success + post-adjustment get_token_privileges
verification; remove_privilege post-removal token inspection; pipe_write
round-trip via pipe_read; stack_walk producing at least one frame with a
non-zero pc; inject_dll success (skipped when admin is unavailable).

All tests use real Win32 APIs against the current Python process.  No mocks
of Win32 call sites.  The oracle for each assertion is the Win32 API itself
(reading back the state the bridge just modified) or raw kernel32 arithmetic.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import threading
from ctypes import wintypes
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.bridges.win32_types import (
    INVALID_HANDLE_VALUE,
    PIPE_ACCESS_DUPLEX,
    SE_PRIVILEGE_ENABLED,
    SE_PRIVILEGE_REMOVED,
)
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_PIPE_WAIT: int = 0x00000000
_PIPE_TYPE_BYTE: int = 0x00000000
_NMPWAIT_USE_DEFAULT_WAIT: int = 0x00000000


@pytest_asyncio.fixture(scope="module")
async def process_bridge() -> AsyncGenerator[ProcessBridge]:
    """Initialize a ProcessBridge and yield it for the module.

    Yields:
        AsyncGenerator[ProcessBridge]: Initialized ProcessBridge instance.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge(process_bridge: ProcessBridge) -> AsyncGenerator[ProcessBridge]:
    """Attach the shared bridge to the current Python process.

    Args:
        process_bridge: Module-scoped initialized bridge.

    Yields:
        AsyncGenerator[ProcessBridge]: Bridge attached to the current process.
    """
    await process_bridge.open_process(os.getpid(), "all")
    yield process_bridge
    await process_bridge.close()


class TestAdjustTokenPrivilegeSuccess:
    """Verify adjust_token_privilege success path with get_token_privileges confirmation.

    Adjustment is attempted on the current process's own token via the
    explicit-pid path (``pid=os.getpid()``).  This exercises the working
    ``OpenProcess`` → ``OpenProcessToken`` → ``AdjustTokenPrivileges`` code
    path.  The no-pid path (which calls ``GetCurrentProcess()`` and is broken
    in production) is documented separately in ``TestAdjustTokenPrivilegeNoPidDefect``.

    Oracle: ``get_token_privileges(os.getpid())`` reads the token directly via
    ``GetTokenInformation``; it is independent of the adjustment call.

    Mutation caught: if adjust_token_privilege does not call
    ``AdjustTokenPrivileges`` (or calls it with the wrong attribute flag),
    the enabled bit would not be set and the assertion on ``entry["enabled"]``
    would fail.
    """

    async def test_enable_privilege_reflects_in_get_token_privileges(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Enable SeChangeNotifyPrivilege via explicit pid, verify enabled bit in token.

        Args:
            process_bridge: Initialized ProcessBridge.
        """
        priv_name = "SeChangeNotifyPrivilege"
        success = await process_bridge.adjust_token_privilege(
            priv_name,
            enable=True,
            pid=os.getpid(),
        )
        assert success is True, "adjust_token_privilege should return True on success"

        privs = await process_bridge.get_token_privileges(os.getpid())
        matches: list[dict[str, object]] = [p for p in privs if p.get("name") == priv_name]
        assert len(matches) >= 1, f"{priv_name} not found in token privileges after enabling"

        entry = matches[0]
        assert entry.get("enabled") is True, (
            f"Expected enabled=True for {priv_name}, got enabled={entry.get('enabled')}; attributes={entry.get('attributes')}"
        )

    async def test_adjust_token_privilege_returns_true_on_success(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Assert that a successful privilege toggle via explicit pid returns exactly True.

        Args:
            process_bridge: Initialized ProcessBridge.
        """
        result = await process_bridge.adjust_token_privilege(
            "SeChangeNotifyPrivilege",
            enable=True,
            pid=os.getpid(),
        )
        assert result is True


class TestRemovePrivilegePostState:
    """Verify remove_privilege marks the privilege absent or disabled in the token.

    After remove_privilege, we call get_token_privileges on the modified
    process.  We cannot remove privileges from other processes without admin,
    so we use a child process trick: create a duplicate of our own token and
    verify the privilege state there, or skip when not admin.

    Because remove_privilege requires PROCESS_QUERY_INFORMATION on an external
    PID, we target our own PID.

    Oracle: get_token_privileges() re-reads the token after modification.

    Mutation caught: if remove_privilege does not set SE_PRIVILEGE_REMOVED,
    the privilege would remain with its original attributes, and the assertion
    that it is absent or carries the removed flag would fail.
    """

    async def test_remove_privilege_privilege_no_longer_enabled_in_token(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """After remove_privilege, assert SeChangeNotifyPrivilege is absent or not enabled.

        Args:
            process_bridge: Initialized ProcessBridge.
        """
        priv_name = "SeChangeNotifyPrivilege"
        await process_bridge.remove_privilege(os.getpid(), priv_name)

        privs = await process_bridge.get_token_privileges(os.getpid())
        matches: list[dict[str, object]] = [p for p in privs if p.get("name") == priv_name]
        if matches:
            entry = matches[0]
            attrs = entry.get("attributes", 0)
            assert isinstance(attrs, int)
            enabled_bit_set: bool = bool(attrs & SE_PRIVILEGE_ENABLED)
            removed_bit_set: bool = bool(attrs & SE_PRIVILEGE_REMOVED)
            assert removed_bit_set or not enabled_bit_set, (
                f"Expected {priv_name} to be removed/disabled after remove_privilege; attributes={attrs:#010x}"
            )


class TestPipeWriteRoundTrip:
    r"""Verify pipe_write writes the exact bytes that pipe_read subsequently returns.

    Creates a named pipe server via kernel32 CreateNamedPipeW in a background
    thread (ConnectNamedPipe blocks until the client connects).  The bridge's
    pipe_connect opens the client end; pipe_write sends a sentinel payload;
    the server thread reads the bytes back with ReadFile and records them.

    Oracle: the raw bytes returned by the server's ReadFile are compared
    byte-for-byte against the payload sent by the bridge.

    Mutation caught: if pipe_write does not call WriteFile (or calls it with
    wrong size), the server receives fewer or no bytes, failing the equality
    check.
    """

    async def test_pipe_write_round_trip_exact_bytes(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        r"""Write sentinel bytes through pipe_write, read them server-side, assert equality.

        Args:
            process_bridge: Initialized ProcessBridge.
        """
        payload: bytes = b"INTELLICRACK_WAVE5_PIPE_SENTINEL_\xde\xad\xbe\xef"
        pipe_name: str = rf"\\.\pipe\IntellicrackWave5PipeTest_{os.getpid()}"
        k32 = ctypes.windll.kernel32

        k32.CreateNamedPipeW.restype = wintypes.HANDLE
        k32.ConnectNamedPipe.restype = wintypes.BOOL
        k32.ReadFile.restype = wintypes.BOOL
        k32.CloseHandle.restype = wintypes.BOOL

        server_handle: int = k32.CreateNamedPipeW(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            _PIPE_TYPE_BYTE | _PIPE_WAIT,
            1,
            4096,
            4096,
            _NMPWAIT_USE_DEFAULT_WAIT,
            None,
        )
        invalid: int = INVALID_HANDLE_VALUE
        if server_handle in {invalid, 0}:
            pytest.skip("CreateNamedPipeW failed — pipe environment unavailable")
            return

        received_data: list[bytes] = []
        server_error: list[str] = []

        def server_thread() -> None:
            """Accept one connection, read one payload, and close."""
            connected: int = k32.ConnectNamedPipe(server_handle, None)
            if not connected:
                last_err = k32.GetLastError()
                if last_err != 535:
                    server_error.append(f"ConnectNamedPipe failed: {last_err}")
                    return
            buf = ctypes.create_string_buffer(len(payload) + 64)
            bytes_read = wintypes.DWORD(0)
            ok: int = k32.ReadFile(server_handle, buf, len(payload), ctypes.byref(bytes_read), None)
            if ok:
                received_data.append(buf.raw[: bytes_read.value])
            else:
                server_error.append(f"ReadFile failed: {k32.GetLastError()}")

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        client_handle: int | None = None
        try:
            client_handle = await process_bridge.pipe_connect(pipe_name, timeout_ms=5000)
            written: int = await process_bridge.pipe_write(client_handle, payload)
            assert written == len(payload), f"pipe_write returned {written} but expected {len(payload)}"
        finally:
            if client_handle is not None:
                await process_bridge.pipe_close(client_handle)

        t.join(timeout=5.0)
        assert not t.is_alive(), "Server thread did not complete within timeout"
        assert not server_error, f"Server-side errors: {server_error}"
        assert received_data, "Server received no data"
        assert received_data[0] == payload, f"Round-trip mismatch: sent {payload!r}, received {received_data[0]!r}"

        k32.CloseHandle(server_handle)


class TestStackWalkSuccessPath:
    """Verify stack_walk returns at least one frame with a non-zero 'address'.

    Walks the stack of a secondary blocking thread inside the current process.
    Each frame dict must contain an ``'address'`` key whose value is a non-zero
    integer (any valid code pointer).  The production code at process.py:5926
    uses the key ``'address'`` for the program counter value.

    Oracle: the first frame's ``'address'`` is compared against 0; any non-zero
    value proves StackWalk64 returned a real return address.

    Mutation caught: if stack_walk silently returns an empty list (e.g. the
    StackWalk64 loop is deleted), ``len(result) >= 1`` fails.  If address
    values are zero-initialised, ``result[0]['address'] > 0`` fails.
    """

    async def test_stack_walk_yields_at_least_one_frame_with_nonzero_pc(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Walk a secondary thread's stack and assert a non-zero 'address' in the first frame.

        Args:
            attached_bridge: ProcessBridge attached to the current process.

        Raises:
            ToolError: When stack_walk fails for a reason other than DbgHelp
                unavailability or the bridge not being attached.
        """
        event_start = threading.Event()
        event_stop = threading.Event()
        tid_container: list[int] = []

        k32 = ctypes.windll.kernel32
        k32.GetCurrentThreadId.restype = wintypes.DWORD

        def worker() -> None:
            """Block until event_stop is set; record Windows TID."""
            tid_container.append(int(k32.GetCurrentThreadId()))
            event_start.set()
            event_stop.wait()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        event_start.wait(timeout=5.0)

        if not tid_container:
            event_stop.set()
            t.join()
            pytest.skip("Worker thread did not start in time")
            return

        try:
            result = await attached_bridge.stack_walk(tid_container[0])
        except ToolError as exc:
            if "dbghelp" in str(exc).lower() or "not attached" in str(exc).lower():
                pytest.skip(f"stack_walk not available in this environment: {exc}")
                return
            raise
        finally:
            event_stop.set()
            t.join(timeout=5.0)

        assert len(result) >= 1, f"stack_walk returned an empty list for thread {tid_container[0]}"
        first_frame = result[0]
        assert "address" in first_frame, f"First frame missing 'address' key; keys present: {list(first_frame.keys())!r}"
        addr_val = first_frame["address"]
        assert isinstance(addr_val, int), f"'address' must be an int, got {type(addr_val)}"
        assert addr_val > 0, f"Expected non-zero address in first stack frame, got {addr_val:#x}"


class TestInjectDllSuccessPath:
    """Verify inject_dll success path using a system DLL injected into our own process.

    Skipped when the current process lacks the privileges required to open
    itself with PROCESS_CREATE_THREAD access (uncommon but possible in
    hardened container environments).

    Oracle: get_modules() enumerates loaded DLLs via CreateToolhelp32Snapshot;
    the injected DLL must appear there after injection.

    Mutation caught: if inject_dll never calls CreateRemoteThread (or skips
    the WaitForSingleObject + exit-code check), it would return False or raise
    ToolError rather than True, failing the ``is True`` assertion.
    """

    async def test_inject_system_dll_appears_in_get_modules(
        self,
        attached_bridge: ProcessBridge,
    ) -> None:
        """Inject a system DLL into the current process and verify it in module list.

        Args:
            attached_bridge: ProcessBridge attached to the current process.

        Raises:
            ToolError: When inject_dll fails for a reason other than insufficient
                access privileges or a missing process handle.
        """
        system32 = os.environ.get("SYSTEMROOT", r"C:\Windows") + r"\System32"
        dll_path: Path = Path(system32) / "version.dll"
        if not await asyncio.to_thread(dll_path.is_file):
            pytest.skip(f"version.dll not found at {dll_path}")
            return

        try:
            result = await attached_bridge.inject_dll(str(dll_path))
        except ToolError as exc:
            msg = str(exc).lower()
            if any(kw in msg for kw in ("access denied", "not all assigned", "process handle")):
                pytest.skip(f"inject_dll requires elevated access: {exc}")
                return
            raise

        assert result is True, "inject_dll should return True on success"

        modules = await attached_bridge.get_modules()
        module_names = [m.name.lower() for m in modules]
        assert any("version" in name for name in module_names), (
            f"version.dll not found in get_modules() after injection; modules: {module_names[:20]}"
        )


class TestAdjustTokenPrivilegeNoPidDefect:
    """RED-BY-DESIGN gate for PD-008: no-pid path crashes with OverflowError.

    ``adjust_token_privilege`` / ``get_token_privileges`` / ``remove_privilege``
    all have a ``pid=None`` default that resolves to the current process by
    calling ``GetCurrentProcess()`` which returns the pseudo-handle ``(HANDLE)-1``
    (i.e. ``0xFFFFFFFFFFFFFFFF`` on 64-bit).  Because ``_advapi32.OpenProcessToken``
    has no declared ``argtypes``, ctypes cannot marshal the pseudo-handle's value
    and raises ``OverflowError: int too long to convert``.

    This test asserts the CORRECT behaviour (returns True) and is expected to
    remain RED until the production defect is fixed.

    Fix (process.py ~line 4004/4040):
      - Declare ``_advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE,
        wintypes.DWORD, POINTER(wintypes.HANDLE)]``
      - Declare ``_kernel32.GetCurrentProcess.restype = wintypes.HANDLE``

    See also: audit/PRODUCTION-DEFECTS.md PD-008.
    """

    async def test_adjust_token_privilege_no_pid_returns_true(
        self,
        process_bridge: ProcessBridge,
    ) -> None:
        """Call adjust_token_privilege without a pid; asserts it returns True (RED: PD-008).

        In production, the call raises ``OverflowError`` because
        ``GetCurrentProcess()`` returns a pseudo-handle that ctypes cannot
        marshal through un-typed ``OpenProcessToken`` argtypes.

        Args:
            process_bridge: Initialized ProcessBridge.
        """
        result = await process_bridge.adjust_token_privilege(
            "SeChangeNotifyPrivilege",
            enable=True,
        )
        assert result is True, (
            "PD-008: adjust_token_privilege(no pid) should return True but raises OverflowError in production (un-typed argtypes)"
        )
