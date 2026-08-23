# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 process bridge findings (Unit 2).

Covers:

* F-0008 - ``get_seh_chain`` must use a 4-byte pointer when the target
  is WOW64, regardless of the host interpreter's pointer width.
* F-0019 - ``get_handles`` must resolve ``ObjectTypeIndex`` to a
  human-readable ``type_name`` string while preserving the raw
  ``type_index`` as a sibling field. The tool definition's ``returns``
  text must describe the new schema.
* F-0035 - ``search_pattern`` must not block the asyncio event loop
  while scanning many regions; each region's scan must be dispatched
  via ``asyncio.to_thread`` and yield to the loop.
* F-0037 - ``query_system_info`` must return a hex ``str`` rather than
  raw ``bytes`` so the tool-def contract is honoured and JSON tool
  responses are serialisable. The function's return annotation must be
  ``str``.
* F-0044 - ``pipe_connect`` and ``device_open`` must register their
  handles in :attr:`ProcessBridge._pipe_handles` and
  :attr:`ProcessBridge._device_handles` so ``shutdown`` can release
  them; the corresponding ``*_close`` methods must remove the entry on
  success.
"""

from __future__ import annotations

import asyncio
import ctypes
import inspect
import os
import struct
import sys
from typing import TYPE_CHECKING, cast
from unittest.mock import patch

import pytest
import pytest_asyncio

from intellicrack.bridges.process import ProcessBridge
from intellicrack.core.types import ToolName


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Windows only"),
    pytest.mark.asyncio,
]

_ATTR_PIPE_HANDLES = "_pipe_handles"
_ATTR_DEVICE_HANDLES = "_device_handles"
_ATTR_TARGET_IS_WOW64 = "_target_is_wow64"


class _BridgeShapeError(TypeError):
    """Raised when an internal bridge attribute has an unexpected shape."""


def _get_kernel32(bridge: ProcessBridge) -> ctypes.WinDLL:
    """Return the bridge's loaded kernel32 ``WinDLL`` handle.

    Args:
        bridge: ProcessBridge instance.

    Returns:
        ctypes.WinDLL: The kernel32 handle bound to the bridge.

    Raises:
        _BridgeShapeError: If kernel32 is not loaded or has unexpected
            type.
    """
    raw = bridge.kernel32
    if not isinstance(raw, ctypes.WinDLL):
        raise _BridgeShapeError
    return raw


def _get_pipe_handles(bridge: ProcessBridge) -> dict[int, str]:
    """Return ``_pipe_handles`` typed as ``dict[int, str]``.

    Args:
        bridge: ProcessBridge instance.

    Returns:
        dict[int, str]: The bridge's pipe-handle tracking dict.

    Raises:
        _BridgeShapeError: If the attribute is missing or mis-typed.
    """
    raw: object = getattr(bridge, _ATTR_PIPE_HANDLES)
    if not isinstance(raw, dict):
        raise _BridgeShapeError
    typed: dict[object, object] = cast("dict[object, object]", raw)
    for k, v in typed.items():
        if not isinstance(k, int) or not isinstance(v, str):
            raise _BridgeShapeError
    return cast("dict[int, str]", raw)


def _get_device_handles(bridge: ProcessBridge) -> dict[int, str]:
    """Return ``_device_handles`` typed as ``dict[int, str]``.

    Args:
        bridge: ProcessBridge instance.

    Returns:
        dict[int, str]: The bridge's device-handle tracking dict.

    Raises:
        _BridgeShapeError: If the attribute is missing or mis-typed.
    """
    raw: object = getattr(bridge, _ATTR_DEVICE_HANDLES)
    if not isinstance(raw, dict):
        raise _BridgeShapeError
    typed: dict[object, object] = cast("dict[object, object]", raw)
    for k, v in typed.items():
        if not isinstance(k, int) or not isinstance(v, str):
            raise _BridgeShapeError
    return cast("dict[int, str]", raw)


_TEST_HANDLE_PIPE = 0x12340001
_TEST_HANDLE_DEVICE = 0x12340002


@pytest_asyncio.fixture
async def bridge_audit7() -> AsyncGenerator[ProcessBridge]:
    """Create and initialize a fresh ProcessBridge for each test.

    Yields:
        ProcessBridge: Initialized bridge that will be
        shut down on teardown.
    """
    bridge = ProcessBridge()
    await bridge.initialize()
    yield bridge
    await bridge.shutdown()


@pytest_asyncio.fixture
async def attached_bridge_audit7(
    bridge_audit7: ProcessBridge,
) -> AsyncGenerator[ProcessBridge]:
    """Attach the bridge to the current Python process for audit7 tests.

    Args:
        bridge_audit7: Fresh initialized ProcessBridge fixture.

    Yields:
        ProcessBridge: Bridge with an open handle on the
        current Python process.
    """
    await bridge_audit7.open_process(os.getpid(), "all")
    yield bridge_audit7
    await bridge_audit7.close()


# ---------------------------------------------------------------------
# F-0008: WOW64 SEH pointer width
# ---------------------------------------------------------------------


class TestF0008SehWow64PointerSize:
    """F-0008: SEH chain must use 4-byte pointers for WOW64 targets."""

    async def test_get_seh_chain_uses_four_byte_pointer_for_wow64_target(
        self,
        attached_bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify SEH chain unpacks 8-byte records with ``<II`` when WOW64.

        Forces ``_target_is_wow64`` to return ``True`` and intercepts
        ``_sync_read_memory`` to verify the read size is 8 bytes
        (two 32-bit pointers) regardless of the host interpreter's
        pointer width. A fabricated SEH record terminates the chain so
        the function returns cleanly without iterating into invalid
        memory.

        Args:
            attached_bridge_audit7: ProcessBridge attached to the test
                Python process.
        """
        bridge = attached_bridge_audit7
        read_sizes: list[int] = []
        seh_frame_addr = 0x0000_1000
        wow64_terminal = 0xFFFFFFFF

        def _fake_read_memory(address: int, size: int) -> bytes:
            del address
            read_sizes.append(size)
            return struct.pack("<II", wow64_terminal, 0xDEADBEEF)

        async def _fake_read_teb(tid: int) -> dict[str, object]:
            del tid
            await asyncio.sleep(0)
            return {"seh_frame": seh_frame_addr}

        with (
            patch.object(bridge, _ATTR_TARGET_IS_WOW64, return_value=True),
            patch.object(bridge, "_sync_read_memory", side_effect=_fake_read_memory),
            patch.object(bridge, "read_teb", side_effect=_fake_read_teb),
        ):
            chain = await bridge.get_seh_chain(tid=0)

        assert isinstance(chain, list)
        assert read_sizes, "expected at least one ReadProcessMemory call"
        for size in read_sizes:
            assert size == 8, f"WOW64 SEH record must be 8 bytes, got {size}"
        assert chain
        first = chain[0]
        assert first["handler_address"] == 0xDEADBEEF
        assert first["next"] == wow64_terminal


# ---------------------------------------------------------------------
# F-0019: get_handles resolves type names
# ---------------------------------------------------------------------


class TestF0019GetHandlesResolvesTypeNames:
    """F-0019: ``get_handles`` must surface resolved ``type_name`` strings."""

    async def test_get_handles_entries_include_type_name_string(
        self,
        attached_bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify each handle dict carries a ``type_name`` string field.

        Args:
            attached_bridge_audit7: ProcessBridge attached to the
                current Python process.
        """
        handles = await attached_bridge_audit7.get_handles(os.getpid())
        assert isinstance(handles, list)
        assert handles, "expected at least one handle for the current PID"

        for entry in handles[:50]:
            assert "type_name" in entry, "handle entry missing type_name"
            type_name = entry["type_name"]
            assert isinstance(type_name, str), f"type_name must be str, got {type(type_name).__name__}"
            assert type_name, "type_name must not be empty"

    async def test_get_handles_preserves_type_index_sibling_field(
        self,
        attached_bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify ``type_index`` is retained alongside ``type_name``.

        Args:
            attached_bridge_audit7: ProcessBridge attached to the
                current Python process.
        """
        handles = await attached_bridge_audit7.get_handles(os.getpid())
        assert handles
        for entry in handles[:50]:
            assert "type_index" in entry, "type_index sibling field missing"
            type_index = entry["type_index"]
            assert isinstance(type_index, int), f"type_index must be int, got {type(type_index).__name__}"

    async def test_get_handles_yields_known_kernel_type_names(
        self,
        attached_bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify at least one well-known Windows type name appears.

        The current Python process always holds at least one ``Process``
        handle, plus typically ``Thread``, ``File``, ``Event``, etc.

        Args:
            attached_bridge_audit7: ProcessBridge attached to the
                current Python process.
        """
        handles = await attached_bridge_audit7.get_handles(os.getpid())
        type_names = {str(h.get("type_name", "")) for h in handles}
        known_types = {"Process", "Thread", "File", "Event", "Mutant", "Key"}
        found = type_names & known_types
        assert found, f"expected at least one known kernel object type; got sample {sorted(type_names)[:20]}"

    def test_tool_definition_returns_text_mentions_type_name(self) -> None:
        """Verify the registered tool-def ``returns`` text reflects new schema."""
        bridge = ProcessBridge()
        tool_def = bridge.tool_definition
        assert tool_def.tool_name == ToolName.PROCESS
        get_handles_func = next(
            (f for f in tool_def.functions if f.name == "process.get_handles"),
            None,
        )
        assert get_handles_func is not None, "process.get_handles missing from tool_definition"
        returns_text = get_handles_func.returns
        assert "type_name" in returns_text, f"tool-def returns text must mention type_name, got: {returns_text}"


# ---------------------------------------------------------------------
# F-0035: search_pattern non-blocking
# ---------------------------------------------------------------------


class TestF0035SearchPatternNonBlocking:
    """F-0035: ``search_pattern`` must yield to the asyncio event loop."""

    async def test_search_pattern_returns_correct_match_addresses_via_real_scan(
        self,
        attached_bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify ``_scan_region_pattern`` locates a sentinel at its exact address.

        Allocates a ctypes buffer containing an 8-byte sentinel value at
        position zero and restricts the scan to the buffer's exact virtual-
        address range so no bytes outside the sentinel are read. The returned
        address list must contain ``ctypes.addressof(marker)`` computed before
        the call, an oracle entirely independent of the production scanning
        code. The real ``asyncio.to_thread`` machinery executes the real
        ``_scan_region_pattern`` worker against the real process-memory range;
        no mocking is involved.

        Args:
            attached_bridge_audit7: ProcessBridge attached to the test
                Python process.
        """
        sentinel = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"
        marker = ctypes.create_string_buffer(sentinel, len(sentinel))
        expected_addr = ctypes.addressof(marker)

        matches = await attached_bridge_audit7.search_pattern(
            "de ad be ef de ad be ef",
            start_address=expected_addr,
            end_address=expected_addr + len(sentinel),
        )

        assert expected_addr in matches, (
            f"search_pattern must locate sentinel at {hex(expected_addr)}; returned: {[hex(m) for m in matches]}"
        )

    def test_search_pattern_source_uses_to_thread(self) -> None:
        """Confirm ``search_pattern`` source contains ``asyncio.to_thread``.

        Static safeguard so the offload cannot regress to a synchronous
        call without the test catching it.
        """
        source = inspect.getsource(ProcessBridge.search_pattern)
        assert "asyncio.to_thread" in source, "search_pattern must dispatch region scans via asyncio.to_thread"


# ---------------------------------------------------------------------
# F-0037: query_system_info returns hex str
# ---------------------------------------------------------------------


class TestF0037QuerySystemInfoHexString:
    """F-0037: ``query_system_info`` returns a hex string, not raw bytes."""

    async def test_query_system_info_returns_hex_string(
        self,
        bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify ``query_system_info`` returns a hex-encoded ``str``.

        Args:
            bridge_audit7: Fresh ProcessBridge fixture.
        """
        system_process_information = 5
        result = await bridge_audit7.query_system_info(system_process_information)
        assert isinstance(result, str), f"query_system_info must return str, got {type(result).__name__}"
        assert result
        assert len(result) % 2 == 0
        assert all(c in "0123456789abcdef" for c in result)
        assert len(bytes.fromhex(result)) > 0

    def test_query_system_info_return_annotation_is_str(self) -> None:
        """Verify the function's return annotation is ``str``."""
        sig = inspect.signature(ProcessBridge.query_system_info)
        ret = sig.return_annotation
        assert ret in {str, "str"}, f"query_system_info return annotation must be str, got {ret!r}"


# ---------------------------------------------------------------------
# F-0044: pipe_connect / device_open populate tracking dicts
# ---------------------------------------------------------------------


class TestF0044HandleTrackingDicts:
    """F-0044: pipe_connect / device_open populate the tracking dicts."""

    async def test_pipe_connect_registers_handle_in_pipe_handles(
        self,
        bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify successful ``pipe_connect`` populates ``_pipe_handles``.

        Patches the kernel32 ``CreateFileW`` / ``WaitNamedPipeW`` /
        ``CloseHandle`` symbols on the bridge's loaded kernel32 to
        synthesise a successful open without touching the real Win32
        named-pipe namespace. Verifies the post-success state and that
        ``pipe_close`` removes the entry.

        Args:
            bridge_audit7: Fresh ProcessBridge fixture.
        """
        bridge = bridge_audit7
        k32 = _get_kernel32(bridge)

        pipe_name = r"\\.\pipe\IntellicrackAudit7TestPipe"
        original_create: object = getattr(k32, "CreateFileW")
        original_wait: object = getattr(k32, "WaitNamedPipeW")
        original_close: object = getattr(k32, "CloseHandle")

        def _fake_create_file_w(*args: object, **kwargs: object) -> int:
            del args, kwargs
            return _TEST_HANDLE_PIPE

        def _fake_wait_named_pipe_w(*args: object, **kwargs: object) -> int:
            del args, kwargs
            return 1

        def _fake_close_handle(*args: object, **kwargs: object) -> int:
            del args, kwargs
            return 1

        setattr(k32, "CreateFileW", _fake_create_file_w)
        setattr(k32, "WaitNamedPipeW", _fake_wait_named_pipe_w)
        setattr(k32, "CloseHandle", _fake_close_handle)
        try:
            await self._assert_pipe_register_and_close(bridge, pipe_name)
        finally:
            setattr(k32, "CreateFileW", original_create)
            setattr(k32, "WaitNamedPipeW", original_wait)
            setattr(k32, "CloseHandle", original_close)

    @staticmethod
    async def _assert_pipe_register_and_close(bridge: ProcessBridge, pipe_name: str) -> None:
        """Connect to a pipe and assert registration/close round-trips state.

        Args:
            bridge: ProcessBridge under test.
            pipe_name: Named pipe path supplied to ``pipe_connect``.
        """
        handle = await bridge.pipe_connect(pipe_name)
        pipe_handles = _get_pipe_handles(bridge)
        assert handle == _TEST_HANDLE_PIPE
        assert handle in pipe_handles, "pipe_connect must register handle in _pipe_handles"
        assert pipe_handles[handle] == pipe_name

        await bridge.pipe_close(handle)
        assert handle not in _get_pipe_handles(bridge), "pipe_close must remove the entry from _pipe_handles"

    async def test_device_open_registers_handle_in_device_handles(
        self,
        bridge_audit7: ProcessBridge,
    ) -> None:
        """Verify successful ``device_open`` populates ``_device_handles``.

        Patches the kernel32 ``CreateFileW`` / ``CloseHandle`` symbols
        on the bridge's loaded kernel32 to synthesise a successful open
        without touching real device-namespace drivers. Verifies the
        post-success state and that ``device_close`` removes the entry.

        Args:
            bridge_audit7: Fresh ProcessBridge fixture.
        """
        bridge = bridge_audit7
        k32 = _get_kernel32(bridge)

        device_path = r"\\.\IntellicrackAudit7TestDevice"
        original_create: object = getattr(k32, "CreateFileW")
        original_close: object = getattr(k32, "CloseHandle")

        def _fake_create_file_w(*args: object, **kwargs: object) -> int:
            del args, kwargs
            return _TEST_HANDLE_DEVICE

        def _fake_close_handle(*args: object, **kwargs: object) -> int:
            del args, kwargs
            return 1

        setattr(k32, "CreateFileW", _fake_create_file_w)
        setattr(k32, "CloseHandle", _fake_close_handle)
        try:
            await self._assert_device_register_and_close(bridge, device_path)
        finally:
            setattr(k32, "CreateFileW", original_create)
            setattr(k32, "CloseHandle", original_close)

    @staticmethod
    async def _assert_device_register_and_close(bridge: ProcessBridge, device_path: str) -> None:
        """Open a device and assert registration/close round-trips state.

        Args:
            bridge: ProcessBridge under test.
            device_path: Device namespace path supplied to ``device_open``.
        """
        handle = await bridge.device_open(device_path)
        device_handles = _get_device_handles(bridge)
        assert handle == _TEST_HANDLE_DEVICE
        assert handle in device_handles, "device_open must register handle in _device_handles"
        assert device_handles[handle] == device_path

        await bridge.device_close(handle)
        assert handle not in _get_device_handles(bridge), "device_close must remove the entry from _device_handles"
