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
from dataclasses import dataclass, field
from typing import Any, ClassVar, cast

from intellicrack.bridges._win32_types import (
    GENERIC_READ,
    GENERIC_WRITE,
    INVALID_HANDLE_VALUE,
    OPEN_EXISTING,
)
from intellicrack.core.error_logging import log_passthrough
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ToolError


_logger = get_logger(__name__)


_LENGTH_PREFIX_SIZE = 4
_CHUNK_SIZE = 65536
_REQUEST_ID_MAX = 0x7FFFFFFF

FILE_SHARE_READ: int = 0x00000001
FILE_SHARE_WRITE: int = 0x00000002


def _default_pipe_name() -> str:
    r"""Return the default Intellicrack x64dbg pipe name for the current process.

    The default pipe name is derived from the connector's own process id so
    that two Intellicrack instances on the same machine do not collide on a
    single hardcoded endpoint. Callers that need to target a specific x64dbg
    instance should override :attr:`PipeConfig.pipe_name` directly.

    Returns:
        str: ``\\.\pipe\intellicrack_x64dbg_<pid>``.
    """
    return rf"\\.\pipe\intellicrack_x64dbg_{os.getpid()}"


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
    r"""Configuration for named pipe client.

    Attributes:
        pipe_name: Named pipe path. Defaults to a per-process Intellicrack
            endpoint ``\\.\pipe\intellicrack_x64dbg_<pid>`` so multiple
            instances on the same host do not collide on a single hardcoded
            path.
        connect_timeout: Timeout for connecting to the pipe.
        io_timeout: Timeout for read/write operations.
        max_message_size: Maximum payload size in bytes.
    """

    pipe_name: str = field(default_factory=_default_pipe_name)
    connect_timeout: float = 5.0
    io_timeout: float = 10.0
    max_message_size: int = 8 * 1024 * 1024


class NamedPipeClient:
    """Async named pipe client for x64dbg plugin IPC.

    Stores the provided pipe configuration (falling back to defaults when
    omitted), the optional event handler used for asynchronous plugin events,
    and sets up the pipe handle slot, the per-write serialisation lock, the
    per-request response future map, and the request identifier counter
    (which is incremented under a dedicated request-id lock and wraps at
    ``2 ** 31 - 1``).
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
        self._write_lock = asyncio.Lock()
        self._id_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self._read_failure: Exception | None = None
        self._event_handler = event_handler
        self._next_id: int = 0
        _logger.info(
            "named_pipe_client_initialized",
            pipe_name=self._config.pipe_name,
            connect_timeout=self._config.connect_timeout,
            io_timeout=self._config.io_timeout,
        )

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

        Opens the configured pipe with shared read/write access so legitimate
        clients can reconnect without being blocked by a previous handle. If
        the awaiting coroutine is cancelled after the underlying ``CreateFileW``
        call has already returned a real handle, the handle is closed in the
        cancellation path so it does not leak into the operating system.

        Raises:
            ToolError: If called on a non-Windows platform, if the connect
                times out, or if the underlying Win32 calls fail.
            asyncio.CancelledError: Re-raised when the connect is cancelled
                so callers see normal asyncio cancellation semantics.
            Exception: Any other unexpected error from the underlying
                thread-pool open is re-raised after the leaked handle (if any)
                has been scheduled for closure.
        """
        if sys.platform != "win32":
            error_message = "Named pipes are only supported on Windows"
            raise ToolError(error_message)

        if self._handle is not None:
            return

        pipe_name = self._config.pipe_name
        _logger.info("pipe_connecting", pipe_name=pipe_name)

        open_task: asyncio.Task[int] = asyncio.create_task(
            asyncio.to_thread(self._open_handle),
        )
        try:
            self._handle = await asyncio.wait_for(
                asyncio.shield(open_task),
                timeout=self._config.connect_timeout,
            )
        except TimeoutError as exc:
            _logger.warning(
                "pipe_connection_failed",
                pipe_name=pipe_name,
                error="connection timeout",
            )
            self._reap_open_task(open_task)
            error_message = "Timed out connecting to named pipe"
            raise ToolError(error_message) from exc
        except asyncio.CancelledError:
            _logger.warning(
                "pipe_connection_cancelled",
                pipe_name=pipe_name,
            )
            self._reap_open_task(open_task)
            raise
        except Exception:
            self._reap_open_task(open_task)
            _logger.exception(
                "pipe_connect_unexpected_failure",
                pipe_name=pipe_name,
            )
            raise

        _logger.info("pipe_connected", pipe_name=pipe_name)
        self._read_failure = None
        loop = asyncio.get_running_loop()
        self._reader_task = loop.create_task(self._reader_loop())

    @staticmethod
    def _reap_open_task(open_task: asyncio.Task[int]) -> None:
        """Close any handle produced by ``open_task`` after cancellation/timeout.

        When ``connect`` aborts after ``CreateFileW`` has already returned a
        real handle, the handle would otherwise leak. This helper either
        closes the handle immediately if the open task already finished, or
        attaches a done-callback that closes it once the worker thread
        completes.

        Args:
            open_task: The task wrapping the synchronous handle-open call.
        """
        if open_task.done():
            if not open_task.cancelled() and open_task.exception() is None:
                leaked = open_task.result()
                NamedPipeClient._close_native_handle(leaked)
            return

        def _on_done(task: asyncio.Task[int]) -> None:
            """Close the handle once the deferred open completes.

            Args:
                task: The completed open task.
            """
            if task.cancelled():
                return
            if task.exception() is not None:
                return
            leaked_handle = task.result()
            NamedPipeClient._close_native_handle(leaked_handle)

        open_task.add_done_callback(_on_done)

    @staticmethod
    def _close_native_handle(handle: int) -> None:
        """Close a Windows pipe handle and log any failure.

        Used both for the in-flight cleanup path in :meth:`_reap_open_task`
        and for the connected handle in :meth:`_close_handle`. Returns
        silently on non-Windows platforms or for sentinel handle values.

        Args:
            handle: Native handle value returned by ``CreateFileW``.
        """
        if sys.platform != "win32":
            return
        if handle == INVALID_HANDLE_VALUE:
            return
        ok = kernel32.CloseHandle(handle)
        if not ok:
            error = ctypes.get_last_error()
            _logger.warning(
                "pipe_close_handle_failed",
                handle=handle,
                error_code=error,
                hint=NamedPipeClient._PIPE_ERROR_HINTS.get(error, ""),
            )

    async def close(self) -> None:
        """Close the pipe connection.

        Waits for any in-flight write to release the per-write lock, cancels the background reader task, fails any outstanding response
        futures with a ``ToolError`` so awaiting ``send_command`` callers do not hang, and then closes the underlying Windows handle on the
        asyncio thread pool via ``asyncio.to_thread``. Safe to call when the client is not connected.
        """
        async with self._close_lock:
            if self._handle is None:
                _logger.debug("pipe_close_noop_already_disconnected")
                return
            pipe_name = self._config.pipe_name
            _logger.info("pipe_disconnecting", pipe_name=pipe_name)

            self._cancel_io()

            reader = self._reader_task
            self._reader_task = None
            if reader is not None and not reader.done():
                reader.cancel()
                try:
                    await reader
                except asyncio.CancelledError as exc:
                    _logger.debug("pipe_reader_cancelled_on_close", error=str(exc))
                except (ToolError, OSError) as exc:
                    _logger.warning("pipe_reader_error_on_close", error=str(exc))
                except Exception:
                    _logger.exception("pipe_reader_close_unexpected_error")

            async with self._write_lock:
                pending = list(self._pending.items())
                self._pending.clear()
                for request_id, fut in pending:
                    if not fut.done():
                        fut.set_exception(
                            ToolError(f"Pipe closed before response for request {request_id}"),
                        )

                await asyncio.to_thread(self._close_handle)
                self._handle = None
                _logger.info("pipe_disconnected", pipe_name=pipe_name)

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a command and wait for its response.

        Allocates a monotonically-increasing request id under the id lock
        (wrapping at ``2 ** 31 - 1`` so long-running clients never overflow),
        registers a per-request future, serialises only the write portion of
        the exchange under the write lock, then awaits the matching response
        published by the background reader task.

        In addition to the directly raised exceptions listed below, the
        following exceptions can propagate from the underlying I/O layer
        and event loop and should be handled by callers:

        * ``TimeoutError`` - raised by :func:`asyncio.wait_for` when a write
          or per-chunk read exceeds :attr:`PipeConfig.io_timeout`.
        * ``asyncio.CancelledError`` - if the awaiting task is cancelled
          before the response arrives. The pending future is removed in the
          ``finally`` block so a subsequent reply for the same id is
          discarded cleanly.
        * ``OSError`` - if the underlying thread-pool I/O surface raises an
          OS-level failure that is not already wrapped in a ``ToolError``.
        * ``RuntimeError`` - if :func:`asyncio.get_running_loop` is invoked
          without a running event loop.

        Args:
            command: Command name.
            params: Command parameters.

        Returns:
            dict[str, Any]: Response payload.

        Raises:
            ToolError: If the pipe is not connected, if the message exceeds
                :attr:`PipeConfig.max_message_size`, if the underlying
                ``WriteFile`` call fails, if the background reader observes
                a fatal pipe error, or if the connection is closed while the
                request is in flight.
        """
        if self._handle is None:
            error_message = "Pipe not connected"
            raise ToolError(error_message)
        if self._read_failure is not None:
            error_message = f"Pipe reader failed: {self._read_failure}"
            raise ToolError(error_message) from self._read_failure

        request_id = await self._allocate_request_id()
        request = {
            "id": request_id,
            "type": "command",
            "command": command,
            "params": params or {},
        }
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[request_id] = future

        _logger.debug("pipe_command_sent", command=command, request_id=request_id)
        try:
            async with self._write_lock:
                await self._send_message(request)
            return await future
        finally:
            self._pending.pop(request_id, None)

    async def _allocate_request_id(self) -> int:
        """Allocate the next request id under the id lock.

        Wraps at ``2 ** 31 - 1`` so an extremely long-lived client cannot
        push the counter past Python's positive 32-bit signed range. The
        underlying lock guarantees that two concurrent ``send_command``
        callers receive monotonically increasing ids in a well-defined
        order.

        Returns:
            int: A positive request id in ``[1, 2 ** 31 - 1]``.
        """
        async with self._id_lock:
            self._next_id = (self._next_id % _REQUEST_ID_MAX) + 1
            return self._next_id

    async def _reader_loop(self) -> None:
        """Continuously read messages and dispatch them to events or futures.

        Runs as a background task started by :meth:`connect`. Events are
        forwarded to the user-supplied handler via
        ``loop.run_in_executor`` so a slow or blocking callback cannot stall
        the asyncio event loop or the request/response stream, and the I/O
        lock is never held across user code. Exceptions raised inside the
        handler are caught and logged so they cannot poison the request
        stream. Response messages are routed to the matching pending
        future. Exits cleanly on cancellation. On any other unhandled error
        the failure is recorded and propagated to all pending futures.

        Raises:
            asyncio.CancelledError: Re-raised when the background task is
                cancelled by :meth:`close`. All other read failures are
                captured, propagated to pending futures, and end the loop
                without re-raising.
        """
        loop = asyncio.get_running_loop()
        while True:
            try:
                message = await self._read_message()
            except asyncio.CancelledError as exc:
                log_passthrough(
                    _logger,
                    "pipe_reader_loop_cancelled_passthrough",
                    exc,
                )
                raise
            except (ToolError, OSError, RuntimeError, ValueError) as exc:
                self._read_failure = exc
                _logger.warning(
                    "pipe_reader_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                self._fail_pending(exc)
                return

            msg_type = str(message.get("type", ""))
            if msg_type == "event":
                handler = self._event_handler
                if handler is not None:
                    loop.run_in_executor(
                        None,
                        self._dispatch_event_safe,
                        handler,
                        message,
                    )
                continue

            request_id_obj = message.get("id")
            if not isinstance(request_id_obj, int):
                _logger.warning(
                    "pipe_response_missing_id",
                    msg_type=msg_type,
                )
                continue

            future = self._pending.pop(request_id_obj, None)
            if future is None:
                _logger.debug(
                    "pipe_response_no_waiter",
                    request_id=request_id_obj,
                )
                continue
            if not future.done():
                future.set_result(message)

    @staticmethod
    def _dispatch_event_safe(handler: EventHandler, message: dict[str, Any]) -> None:
        """Invoke ``handler`` with ``message`` and swallow any exception.

        Wrapping the user callback in try/except keeps a buggy event handler
        from corrupting the request/response stream. Failures are logged via
        ``_logger.exception`` so they remain debuggable.

        Args:
            handler: Event handler callback supplied by the user.
            message: Decoded event payload.
        """
        try:
            handler(message)
        except Exception:
            _logger.exception(
                "pipe_event_handler_error",
                msg_type=str(message.get("type", "")),
            )

    def _fail_pending(self, exc: Exception) -> None:
        """Resolve every pending response future with ``exc``.

        Args:
            exc: Exception to propagate to awaiting ``send_command`` callers.
        """
        pending = list(self._pending.items())
        self._pending.clear()
        for _, fut in pending:
            if not fut.done():
                fut.set_exception(exc)

    async def _send_message(self, payload: dict[str, Any]) -> None:
        """Send a JSON message over the pipe.

        Args:
            payload: Message payload.

        Raises:
            ToolError: If the message exceeds the configured maximum size or
                the underlying write fails.
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
            ToolError: If the read fails or times out.
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
            ToolError: If the write fails or times out.
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

    @classmethod
    def format_error_hint(cls, code: int) -> str | None:
        """Return the human-readable hint for a Win32 pipe error code.

        Provides public access to the curated mapping that the connect/read/
        write paths use to enrich error messages and logs. Callers (tests,
        diagnostics surfaces, AI orchestration code) can surface the same
        guidance the bridge itself emits without reaching into the private
        hint table.

        Args:
            code: ``GetLastError`` value returned from a failed Win32 pipe
                call (for example ``2`` for ``ERROR_FILE_NOT_FOUND`` or
                ``109`` for ``ERROR_BROKEN_PIPE``).

        Returns:
            str | None: The associated guidance string, or ``None`` when the
            code is not in the curated table.
        """
        return cls._PIPE_ERROR_HINTS.get(code)

    _PIPE_ERROR_HINTS: ClassVar[dict[int, str]] = {
        2: "The x64dbg bridge plugin is not running. Ensure x64dbg is open and the Intellicrack plugin is loaded",
        3: "Pipe path not found. Verify the configured pipe name matches the x64dbg plugin's named-pipe endpoint",
        5: "Access denied. Try running Intellicrack as administrator",
        6: "Invalid pipe handle. The pipe was closed or the handle is stale; reconnect before retrying",
        21: "The named pipe is not ready. Wait briefly and retry, or restart the x64dbg plugin",
        109: "The named pipe was closed by the remote end (broken pipe). Reconnect to recover",
        230: "Pipe is in an invalid state for the requested operation. Disconnect and reconnect to recover",
        231: "All pipe instances are busy. Another client may already be connected",
        232: "The named pipe is being closed (Windows is tearing it down). Wait for the server to recreate it",
        233: "No process is on the other end of the pipe. Ensure the x64dbg plugin is loaded and listening",
        535: "The pipe is already connected to a client. Disconnect the existing client before reconnecting",
        536: "The named pipe is listening for an inbound connection. Retry the open shortly",
    }

    def _open_handle(self) -> int:
        """Open a handle to the configured named pipe on Windows.

        Waits up to the configured connect timeout for the pipe to become
        available and then opens it for duplex I/O with shared read/write
        access (``FILE_SHARE_READ | FILE_SHARE_WRITE``) so legitimate
        reconnects from other Intellicrack components are not blocked by an
        exclusive lock. Maps common ``GetLastError`` codes to human-readable
        hints so orchestration code can surface actionable failures.

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
                error="pipe not available",
                error_code=error,
                hint=hint,
            )
            error_message = f"Named pipe not available (error {error})"
            if hint:
                error_message = f"{error_message}. {hint}"
            raise ToolError(error_message)

        handle: int | None = kernel32.CreateFileW(
            pipe_name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )

        if handle is None or handle == INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            hint = self._PIPE_ERROR_HINTS.get(error, "")
            _logger.error(
                "pipe_connection_failed",
                pipe_name=pipe_name,
                error="failed to open",
                error_code=error,
                hint=hint,
            )
            error_message = f"Failed to open pipe (error {error})"
            if hint:
                error_message = f"{error_message}. {hint}"
            raise ToolError(error_message)

        return handle

    def _close_handle(self) -> None:
        """Close the underlying Windows pipe handle, if any.

        Delegates to :meth:`_close_native_handle` which calls ``CloseHandle``, inspects the BOOL return value, and logs a warning with
        ``GetLastError`` if the close failed. Does nothing if the client is not currently connected or if the platform is not Windows.
        """
        if self._handle is None:
            return
        self._close_native_handle(self._handle)

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
                    error="read failed",
                    error_code=error,
                    hint=self._PIPE_ERROR_HINTS.get(error, ""),
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
                    error="write failed",
                    error_code=error,
                    hint=self._PIPE_ERROR_HINTS.get(error, ""),
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

        Invokes ``CancelIoEx`` against the current pipe handle when the Windows API is available so that a blocked ``ReadFile`` or
        ``WriteFile`` on another thread unblocks with a cancellation error. Does nothing if the client is not connected or if the API entry
        point is unavailable.
        """
        if self._handle is None:
            return
        if sys.platform != "win32":
            return
        _logger.debug("pipe_cancelling_io", handle=self._handle)
        kernel32.CancelIoEx(self._handle, None)
        _logger.debug("pipe_io_cancelled", handle=self._handle)
