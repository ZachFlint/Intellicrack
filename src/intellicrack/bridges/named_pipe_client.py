# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Named pipe client for x64dbg IPC."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import sys
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, ClassVar, cast

from intellicrack.core.logging import get_logger
from intellicrack.core.types import ToolError


_logger = get_logger("bridges.namedpipe")


_LENGTH_PREFIX_SIZE = 4
_CHUNK_SIZE = 65536

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


if sys.platform == "win32":
    kernel32: ctypes.WinDLL = ctypes.WinDLL("kernel32", use_last_error=True)

    kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]

    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]

    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]

    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    kernel32.CancelIoEx.restype = wintypes.BOOL
    kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID]


EventHandler = Callable[[dict[str, Any]], None]


@dataclass
class PipeConfig:
    """Configuration for named pipe client.

    Attributes:
        pipe_name: Named pipe path.
        connect_timeout: Timeout for connecting to the pipe.
        io_timeout: Timeout for read/write operations.
        max_message_size: Maximum payload size in bytes.
    """

    pipe_name: str = r"\\.\pipe\intellicrack_x64dbg"
    connect_timeout: float = 5.0
    io_timeout: float = 10.0
    max_message_size: int = 8 * 1024 * 1024


class NamedPipeClient:
    """Async named pipe client for x64dbg plugin IPC.

    Stores the provided pipe configuration (falling back to defaults when omitted), the optional event handler used for asynchronous plugin
    events, and sets up the pipe handle slot, the concurrency lock serialising I/O, and the request identifier counter.
    """

    def __init__(
        self,
        config: PipeConfig | None = None,
        event_handler: EventHandler | None = None,
    ) -> None:
        """Initialize the NamedPipeClient with the given configuration.

        Args:
            config: Pipe configuration, or None to use defaults.
            event_handler: Optional callback for pipe events.
        """
        self._config = config or PipeConfig()
        self._handle: int | None = None
        self._lock = asyncio.Lock()
        self._event_handler = event_handler
        self._next_id: int = 0

    @property
    def is_connected(self) -> bool:
        """Check connection status.

        Returns:
            bool: True if connected to the pipe.
        """
        return self._handle is not None

    def set_event_handler(self, handler: EventHandler | None) -> None:
        """Set the event handler callback.

        Args:
            handler: Event handler to set.
        """
        self._event_handler = handler

    async def connect(self) -> None:
        """Connect to the named pipe.

        Raises:
            ToolError: If connection fails.
        """
        if os.name != "nt":
            error_message = "Named pipes are only supported on Windows"
            raise ToolError(error_message)

        if self._handle is not None:
            return

        pipe_name = self._config.pipe_name
        _logger.info("pipe_connecting", pipe_name=pipe_name)

        try:
            self._handle = await asyncio.wait_for(
                asyncio.to_thread(self._open_handle),
                timeout=self._config.connect_timeout,
            )
            _logger.info("pipe_connected", pipe_name=pipe_name)
        except TimeoutError as exc:
            _logger.warning(
                "pipe_connection_failed",
                pipe_name=pipe_name,
                error="connection timeout",
            )
            error_message = "Timed out connecting to named pipe"
            raise ToolError(error_message) from exc

    async def close(self) -> None:
        """Close the pipe connection."""
        if self._handle is None:
            return
        pipe_name = self._config.pipe_name
        _logger.info("pipe_disconnecting", pipe_name=pipe_name)
        await asyncio.to_thread(self._close_handle)
        self._handle = None

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a command and wait for response.

        Args:
            command: Command name.
            params: Command parameters.

        Returns:
            dict[str, Any]: Response payload.
        """
        self._next_id += 1
        request_id = self._next_id
        request = {
            "id": request_id,
            "type": "command",
            "command": command,
            "params": params or {},
        }

        _logger.debug("pipe_command_sent", command=command)

        async with self._lock:
            await self._send_message(request)
            while True:
                message = await self._read_message()
                msg_type = str(message.get("type", ""))
                if msg_type == "event":
                    if self._event_handler is not None:
                        self._event_handler(message)
                    continue

                if message.get("id") == request_id:
                    return message

    async def _send_message(self, payload: dict[str, Any]) -> None:
        """Send a JSON message over the pipe.

        Args:
            payload: Message payload.

        Raises:
            ToolError: If sending fails.
        """
        data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(data) > self._config.max_message_size:
            error_message = "Message exceeds maximum size"
            raise ToolError(error_message)

        length_prefix = len(data).to_bytes(_LENGTH_PREFIX_SIZE, "little", signed=False)
        await self._write_bytes(length_prefix + data)

    async def _read_message(self) -> dict[str, Any]:
        """Read a JSON message from the pipe.

        Returns:
            dict[str, Any]: Parsed JSON payload.

        Raises:
            ToolError: If reading or parsing fails.
        """
        length_bytes = await self._read_exact(_LENGTH_PREFIX_SIZE)
        if len(length_bytes) != _LENGTH_PREFIX_SIZE:
            error_message = "Failed to read message length"
            raise ToolError(error_message)

        length = int.from_bytes(length_bytes, "little", signed=False)
        if length <= 0 or length > self._config.max_message_size:
            error_message = "Invalid message length"
            raise ToolError(error_message)

        data = await self._read_exact(length)
        try:
            payload: object = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            _logger.warning("pipe_invalid_json_payload", error=str(exc))
            error_message = f"Invalid JSON payload: {exc}"
            raise ToolError(error_message) from exc

        if not isinstance(payload, dict):
            error_message = "Unexpected message payload type"
            raise ToolError(error_message)
        return cast("dict[str, Any]", payload)

    async def _read_exact(self, size: int) -> bytes:
        """Read an exact number of bytes from the pipe.

        Args:
            size: Number of bytes to read.

        Returns:
            bytes: Bytes read.

        Raises:
            ToolError: If read fails.
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._read_exact_sync, size),
                timeout=self._config.io_timeout,
            )
        except TimeoutError as exc:
            self._cancel_io()
            _logger.warning(
                "pipe_error",
                operation="read",
                error="read timeout",
            )
            error_message = "Timed out reading from pipe"
            raise ToolError(error_message) from exc

    async def _write_bytes(self, data: bytes) -> None:
        """Write bytes to the pipe.

        Args:
            data: Bytes to write.

        Raises:
            ToolError: If write fails.
        """
        try:
            await asyncio.wait_for(
                asyncio.to_thread(self._write_sync, data),
                timeout=self._config.io_timeout,
            )
        except TimeoutError as exc:
            self._cancel_io()
            _logger.warning(
                "pipe_error",
                operation="write",
                error="write timeout",
            )
            error_message = "Timed out writing to pipe"
            raise ToolError(error_message) from exc

    _PIPE_ERROR_HINTS: ClassVar[dict[int, str]] = {
        2: ("The x64dbg bridge plugin is not running. Ensure x64dbg is open and the Intellicrack plugin is loaded"),
        5: "Access denied. Try running Intellicrack as administrator",
        231: ("All pipe instances are busy. Another client may already be connected"),
    }

    def _open_handle(self) -> int:
        """Open a handle to the configured named pipe on Windows.

        Waits up to the configured connect timeout for the pipe to become
        available and then opens it for duplex I/O. Maps common
        ``GetLastError`` codes to human-readable hints so orchestration
        code can surface actionable failures.

        Returns:
            int: Native handle value for the open pipe.

        Raises:
            ToolError: If called on a non-Windows platform, if
                ``WaitNamedPipeW`` fails, or if ``CreateFileW`` returns an
                invalid handle.
        """
        if sys.platform != "win32":
            error_message = "Named pipes are only supported on Windows"
            raise ToolError(error_message)

        pipe_name = self._config.pipe_name
        timeout_ms = int(self._config.connect_timeout * 1000)

        wait_ok = kernel32.WaitNamedPipeW(pipe_name, timeout_ms)
        if not wait_ok:
            error = ctypes.get_last_error()
            hint = self._PIPE_ERROR_HINTS.get(error, "")
            _logger.error(
                "pipe_connection_failed",
                pipe_name=pipe_name,
                error=f"pipe not available (code {error})",
                hint=hint,
            )
            error_message = f"Named pipe not available (error {error})"
            if hint:
                error_message = f"{error_message}. {hint}"
            raise ToolError(error_message)

        handle: int | None = kernel32.CreateFileW(
            pipe_name,
            _GENERIC_READ | _GENERIC_WRITE,
            0,
            None,
            _OPEN_EXISTING,
            0,
            None,
        )

        if handle is None or handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            hint = self._PIPE_ERROR_HINTS.get(error, "")
            _logger.error(
                "pipe_connection_failed",
                pipe_name=pipe_name,
                error=f"failed to open (code {error})",
                hint=hint,
            )
            error_message = f"Failed to open pipe (error {error})"
            if hint:
                error_message = f"{error_message}. {hint}"
            raise ToolError(error_message)

        return handle

    def _close_handle(self) -> None:
        """Close the underlying Windows pipe handle, if any.

        Calls ``CloseHandle`` on the stored handle so operating-system
        resources associated with the pipe are released. Does nothing if
        the client is not currently connected.
        """
        if self._handle is None:
            return
        if sys.platform != "win32":
            return
        kernel32.CloseHandle(self._handle)

    def _read_exact_sync(self, size: int) -> bytes:
        """Read exactly ``size`` bytes from the pipe synchronously.

        Performs blocking ``ReadFile`` calls in ``_CHUNK_SIZE`` increments
        until the requested number of bytes has been collected. Designed
        to be driven on a worker thread via ``asyncio.to_thread``.

        Args:
            size: Exact number of bytes that must be read.

        Returns:
            bytes: The full payload read from the pipe.

        Raises:
            ToolError: If the pipe is not connected, if ``ReadFile`` fails,
                or if the pipe closes before all bytes are received.
        """
        if self._handle is None:
            error_message = "Pipe not connected"
            raise ToolError(error_message)
        if sys.platform != "win32":
            error_message = "Named pipes are only supported on Windows"
            raise ToolError(error_message)

        data = bytearray()
        remaining = size
        _logger.debug("pipe_read_started", requested_bytes=size)

        while remaining > 0:
            chunk_size = min(_CHUNK_SIZE, remaining)
            buffer = ctypes.create_string_buffer(chunk_size)
            bytes_read = wintypes.DWORD(0)
            success = kernel32.ReadFile(
                self._handle,
                buffer,
                chunk_size,
                ctypes.byref(bytes_read),
                None,
            )
            if not success:
                error = ctypes.get_last_error()
                _logger.error(
                    "pipe_error",
                    operation="read",
                    error=f"read failed (code {error})",
                )
                error_message = f"Pipe read failed (error {error})"
                raise ToolError(error_message)
            if bytes_read.value == 0:
                _logger.error(
                    "pipe_error",
                    operation="read",
                    error="pipe closed unexpectedly",
                )
                error_message = "Pipe closed"
                raise ToolError(error_message)
            _logger.debug(
                "pipe_read_chunk",
                chunk_bytes=bytes_read.value,
                remaining=remaining - bytes_read.value,
            )
            data.extend(buffer.raw[: bytes_read.value])
            remaining -= bytes_read.value

        _logger.debug("pipe_read_complete", total_bytes=size)
        return bytes(data)

    def _write_sync(self, data: bytes) -> None:
        """Write ``data`` to the pipe synchronously.

        Performs blocking ``WriteFile`` calls in ``_CHUNK_SIZE`` increments
        until the entire buffer has been transmitted. Designed to be
        driven on a worker thread via ``asyncio.to_thread``.

        Args:
            data: Payload bytes to transmit.

        Raises:
            ToolError: If the pipe is not connected or if ``WriteFile``
                fails before the buffer has been fully written.
        """
        if self._handle is None:
            error_message = "Pipe not connected"
            raise ToolError(error_message)
        if sys.platform != "win32":
            error_message = "Named pipes are only supported on Windows"
            raise ToolError(error_message)

        total = len(data)
        offset = 0
        _logger.debug("pipe_write_started", total_bytes=total)

        while offset < total:
            chunk = data[offset : offset + _CHUNK_SIZE]
            bytes_written = wintypes.DWORD(0)
            success = kernel32.WriteFile(
                self._handle,
                chunk,
                len(chunk),
                ctypes.byref(bytes_written),
                None,
            )
            if not success:
                error = ctypes.get_last_error()
                _logger.error(
                    "pipe_error",
                    operation="write",
                    error=f"write failed (code {error})",
                )
                error_message = f"Pipe write failed (error {error})"
                raise ToolError(error_message)
            _logger.debug(
                "pipe_write_chunk",
                chunk_bytes=bytes_written.value,
                offset=offset + bytes_written.value,
            )
            offset += bytes_written.value

        _logger.debug("pipe_write_complete", total_bytes=total)

    def _cancel_io(self) -> None:
        """Cancel any in-flight pipe I/O on supported Windows builds.

        Invokes ``CancelIoEx`` against the current pipe handle when the
        Windows API is available so that a blocked ``ReadFile`` or
        ``WriteFile`` on another thread unblocks with a cancellation
        error. Does nothing if the client is not connected or if the
        API entry point is unavailable.
        """
        if self._handle is None:
            return
        if sys.platform != "win32":
            return
        _logger.debug("pipe_cancelling_io", handle=self._handle)
        kernel32.CancelIoEx(self._handle, None)
        _logger.debug("pipe_io_cancelled", handle=self._handle)
