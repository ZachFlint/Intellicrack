# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave 2d error-branch gates for ``NamedPipeClient`` IPC.

Targets the NO COVERAGE operations identified in
``audit/test-coverage-audit/section-01-bridge-framework.md``, section 1.5:

- GAP-06: ``connect()`` already-connected no-op
- GAP-07: ``send_command()`` ``_read_failure`` pre-send guard
- GAP-08: ``_send_message`` oversized payload enforcement
- GAP-09: ``_read_message`` malformed JSON / invalid length / non-dict payload
- GAP-11: ``_reader_loop`` response-missing-id and no-pending-waiter diagnostics

Every test drives the real ``NamedPipeClient`` over an in-memory ``_FakePipe``
transport that replaces the four synchronous Win32 I/O boundaries with
in-process byte buffers mirroring the framed-message wire protocol. No
production source file is modified. No function under test is patched,
mocked, or called via ``MagicMock``. The Win32 boundary substitutions are
instance-attribute overwrites via ``setattr``; all async orchestration in
``named_pipe_client.py`` runs unmodified.
"""

from __future__ import annotations

import asyncio
import json
import threading
from typing import TYPE_CHECKING, Any

import pytest
import pytest_asyncio

from intellicrack.bridges.named_pipe_client import NamedPipeClient, PipeConfig
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable


_FAKE_HANDLE: int = 0xABCDEF


class _FakePipe:
    """Trivial in-memory bidirectional message channel for tests.

    Mirrors the framed-message wire protocol that ``NamedPipeClient``
    expects: incoming bytes are consumed in order by the background reader
    thread; outgoing bytes are appended by the client write thread.
    Threading primitives are used because the bound transport methods run on
    ``asyncio.to_thread`` worker threads.
    """

    def __init__(self) -> None:
        """Initialise the fake pipe with empty incoming and outgoing buffers."""
        self.incoming: bytearray = bytearray()
        self.outgoing: bytearray = bytearray()
        self.cond: threading.Condition = threading.Condition()
        self.closed: bool = False

    def push_raw_bytes(self, data: bytes) -> None:
        """Append raw bytes directly to the client-bound incoming buffer.

        Use this method when crafting malformed frames (invalid length
        prefixes, non-JSON bodies) that ``push_server_frame`` would not
        produce.

        Args:
            data: Raw bytes to append to the incoming buffer.
        """
        with self.cond:
            self.incoming.extend(data)
            self.cond.notify_all()

    def push_server_frame(self, payload: dict[str, Any]) -> None:
        """Append a length-prefixed JSON frame to the client-bound buffer.

        Args:
            payload: Frame body to encode as a length-prefixed JSON message.
        """
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        with self.cond:
            self.incoming.extend(len(body).to_bytes(4, "little"))
            self.incoming.extend(body)
            self.cond.notify_all()

    def mark_closed(self) -> None:
        """Mark the fake pipe as closed and wake any blocked reader."""
        with self.cond:
            self.closed = True
            self.cond.notify_all()


def _bind_fake_pipe(client: NamedPipeClient, fake: _FakePipe) -> None:
    """Bind in-memory transport methods onto ``client`` without suppressions.

    Overwrites the four synchronous Win32 boundary methods
    (``_open_handle``, ``_close_handle``, ``_read_exact_sync``,
    ``_write_sync``) with closures that operate on ``fake``'s in-memory
    buffers. All async orchestration logic in ``NamedPipeClient`` runs
    unmodified.

    Args:
        client: Target ``NamedPipeClient`` to patch.
        fake: Backing in-memory pipe used as the stand-in transport.
    """

    def _open_handle() -> int:
        """Return the canned sentinel handle.

        Returns:
            int: Sentinel handle value used by the in-memory transport.
        """
        return _FAKE_HANDLE

    def _close_handle() -> None:
        """Mark the fake pipe closed."""
        fake.mark_closed()

    def _read_exact_sync(size: int) -> bytes:
        """Read exactly ``size`` bytes from the fake incoming buffer.

        Blocks on the ``Condition`` variable until enough bytes accumulate or
        the pipe is marked closed.

        Args:
            size: Number of bytes to consume from the incoming buffer.

        Returns:
            bytes: The requested bytes, removed from the buffer.

        Raises:
            ToolError: If the fake pipe is marked closed before enough bytes
                arrive.
        """
        with fake.cond:
            while len(fake.incoming) < size:
                if fake.closed:
                    msg = "Pipe closed"
                    raise ToolError(msg)
                fake.cond.wait(timeout=0.05)
            chunk = bytes(fake.incoming[:size])
            del fake.incoming[:size]
            return chunk

    def _write_sync(data: bytes) -> None:
        """Append ``data`` to the fake outgoing buffer.

        Args:
            data: Bytes to enqueue in the outgoing direction.
        """
        with fake.cond:
            fake.outgoing.extend(data)
            fake.cond.notify_all()

    setattr(client, "_open_handle", _open_handle)
    setattr(client, "_close_handle", _close_handle)
    setattr(client, "_read_exact_sync", _read_exact_sync)
    setattr(client, "_write_sync", _write_sync)


class _LogSink:
    """Recording stand-in for the module ``_logger`` of ``named_pipe_client``.

    Installed via ``monkeypatch`` for the duration of a test so the real
    reader-loop code path runs unchanged while its structured-log calls are
    captured deterministically. This avoids structlog's first-use logger cache,
    which makes a ``structlog.configure`` processor injected after the module
    logger is realised silently miss the events. Records every
    ``(level, event, fields)`` triple and sets ``event_seen`` when an event
    matching ``target`` is observed; thread-safe because the reader loop emits
    its logs from a worker thread.
    """

    def __init__(self, target: str) -> None:
        """Initialise the sink.

        Args:
            target: Event name to watch for and signal on.
        """
        self._target = target
        self.records: list[tuple[str, str, dict[str, object]]] = []
        self.event_seen: threading.Event = threading.Event()

    def _emit(self, level: str, event: str, **fields: object) -> None:
        """Record a single log call and signal when it matches the target.

        Args:
            level: Severity name of the originating call.
            event: Structlog event key.
            **fields: Structured key/value fields passed to the call.
        """
        self.records.append((level, event, dict(fields)))
        if event == self._target:
            self.event_seen.set()

    def debug(self, event: str, **fields: object) -> None:
        """Record a debug-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("debug", event, **fields)

    def info(self, event: str, **fields: object) -> None:
        """Record an info-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("info", event, **fields)

    def warning(self, event: str, **fields: object) -> None:
        """Record a warning-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("warning", event, **fields)

    def error(self, event: str, **fields: object) -> None:
        """Record an error-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("error", event, **fields)

    def exception(self, event: str, **fields: object) -> None:
        """Record an exception-level event.

        Args:
            event: Structlog event key.
            **fields: Structured fields.
        """
        self._emit("exception", event, **fields)

    def bind(self, **_fields: object) -> _LogSink:
        """Return self so chained ``bind(...)`` calls keep recording.

        Args:
            **_fields: Bound context fields (ignored by the sink).

        Returns:
            _LogSink: This sink instance.
        """
        return self


def _raw_client(fake: _FakePipe, *, max_message_size: int = 8 * 1024 * 1024) -> NamedPipeClient:
    """Build a ``NamedPipeClient`` with fake transport and handle pre-set.

    The client has ``_handle`` set to ``_FAKE_HANDLE`` directly so that
    ``_read_exact`` / ``_send_message`` can be called without first invoking
    ``connect()``, which would start the background reader loop and require
    a full async lifecycle.

    Args:
        fake: Backing in-memory pipe.
        max_message_size: Maximum frame size to configure on the client.

    Returns:
        NamedPipeClient: Client with fake transport bound and handle pre-set.
    """
    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_wave2d_raw",
        connect_timeout=1.0,
        io_timeout=1.0,
        max_message_size=max_message_size,
    )
    client = NamedPipeClient(config=config)
    _bind_fake_pipe(client, fake)
    setattr(client, "_handle", _FAKE_HANDLE)
    return client


@pytest.fixture
def fake_pipe() -> _FakePipe:
    """Return a fresh in-memory pipe stand-in.

    Returns:
        _FakePipe: Empty bidirectional buffer.
    """
    return _FakePipe()


@pytest_asyncio.fixture
async def connected_client(fake_pipe: _FakePipe) -> AsyncIterator[NamedPipeClient]:
    """Yield a connected ``NamedPipeClient`` driving ``fake_pipe``.

    Args:
        fake_pipe: Shared in-memory pipe transport.

    Yields:
        NamedPipeClient: Connected client ready to send commands.
    """
    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_wave2d_client",
        connect_timeout=1.0,
        io_timeout=1.0,
    )
    client = NamedPipeClient(config=config)
    _bind_fake_pipe(client, fake_pipe)
    await client.connect()
    try:
        yield client
    finally:
        if client.is_connected:
            await client.close()


# ---------------------------------------------------------------------------
# GAP-06: connect() already-connected no-op
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_already_connected_is_noop(fake_pipe: _FakePipe) -> None:
    """Second ``connect()`` on an already-connected client is a silent no-op (GAP-06).

    Concrete mutation caught: removing ``if self._handle is not None: return``
    from ``connect()`` would cause a second call to invoke ``_open_handle``
    again, opening a duplicate handle and leaking it. This gate counts
    ``_open_handle`` invocations and asserts exactly one call for two
    ``connect()`` invocations.

    Args:
        fake_pipe: In-memory transport driving the client.
    """
    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_wave2d_noop",
        connect_timeout=1.0,
        io_timeout=1.0,
    )
    client = NamedPipeClient(config=config)
    _bind_fake_pipe(client, fake_pipe)

    open_call_count: list[int] = []
    original_open: Callable[[], int] = getattr(client, "_open_handle")

    def counting_open() -> int:
        """Delegate to original open and record the call.

        Returns:
            int: Sentinel handle value from the original fake open.
        """
        open_call_count.append(1)
        return original_open()

    setattr(client, "_open_handle", counting_open)

    await client.connect()
    assert client.is_connected
    assert open_call_count == [1]

    await client.connect()
    assert client.is_connected
    assert open_call_count == [1], "connect() must not call _open_handle again when already connected"

    await client.close()


# ---------------------------------------------------------------------------
# GAP-07: send_command() _read_failure pre-send guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_command_raises_when_read_failure_is_set(
    connected_client: NamedPipeClient,
) -> None:
    """``send_command()`` raises ``ToolError`` immediately when ``_read_failure`` is set (GAP-07).

    Concrete mutation caught: removing ``if self._read_failure is not None: raise``
    from ``send_command()`` would allow it to allocate a request id and await a
    future that can never resolve because the reader loop is already dead. This
    gate asserts ``ToolError`` matching ``"Pipe reader failed"`` is raised before
    any I/O attempt, distinguishing the pre-send guard from the post-send timeout.

    Args:
        connected_client: Connected client from the fixture.
    """
    synthetic_error = RuntimeError("reader exploded")
    setattr(connected_client, "_read_failure", synthetic_error)
    with pytest.raises(ToolError, match=r"Pipe reader failed"):
        await connected_client.send_command("probe")


# ---------------------------------------------------------------------------
# GAP-08: _send_message oversized payload enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_message_oversized_raises_tool_error(fake_pipe: _FakePipe) -> None:
    """``_send_message`` raises ``ToolError`` when payload exceeds ``max_message_size`` (GAP-08).

    Concrete mutation caught: removing ``if len(data) > self._config.max_message_size``
    from ``_send_message`` would allow arbitrarily large frames to be written to
    the peer, corrupting the framing parser. This gate configures a 10-byte
    ``max_message_size`` and asserts ``ToolError("Message exceeds maximum size")``
    for a 200-character payload whose JSON encoding vastly exceeds 10 bytes.

    Args:
        fake_pipe: In-memory transport driving the client.
    """
    client = _raw_client(fake_pipe, max_message_size=10)
    send_message: Callable[..., Any] = getattr(client, "_send_message")
    big_payload: dict[str, Any] = {"data": "a" * 200}
    with pytest.raises(ToolError, match=r"Message exceeds maximum size"):
        await send_message(big_payload)
    setattr(client, "_handle", None)


# ---------------------------------------------------------------------------
# GAP-09a: _read_message invalid length-prefix (length == 0)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_message_zero_length_raises_tool_error(fake_pipe: _FakePipe) -> None:
    """``_read_message`` raises ``ToolError`` for a zero-value length prefix (GAP-09).

    Concrete mutation caught: removing ``length <= 0 or`` from the guard
    ``if length <= 0 or length > self._config.max_message_size`` would silently
    accept a zero-length frame and attempt to read zero body bytes, passing an
    empty bytearray to ``json.loads`` and raising ``JSONDecodeError`` instead of
    the correct ``ToolError("Invalid message length")``. This gate asserts the
    specific ``"Invalid message length"`` message.

    Args:
        fake_pipe: In-memory transport driving the client.
    """
    client = _raw_client(fake_pipe)
    fake_pipe.push_raw_bytes((0).to_bytes(4, "little"))

    read_message: Callable[[], Any] = getattr(client, "_read_message")
    with pytest.raises(ToolError, match=r"Invalid message length"):
        await read_message()
    setattr(client, "_handle", None)


# ---------------------------------------------------------------------------
# GAP-09a': _read_message invalid length-prefix (length > max_message_size)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_message_excess_length_raises_tool_error(fake_pipe: _FakePipe) -> None:
    """``_read_message`` raises ``ToolError`` when the length prefix exceeds ``max_message_size`` (GAP-09).

    Concrete mutation caught: removing ``or length > self._config.max_message_size``
    from the length guard would allow the client to attempt reading an unbounded
    number of bytes from the pipe, hanging indefinitely on a short frame.
    This gate uses ``max_message_size=100`` and pushes a length prefix of 101,
    asserting ``ToolError("Invalid message length")``.

    Args:
        fake_pipe: In-memory transport driving the client.
    """
    max_size = 100
    client = _raw_client(fake_pipe, max_message_size=max_size)
    fake_pipe.push_raw_bytes((max_size + 1).to_bytes(4, "little"))

    read_message: Callable[[], Any] = getattr(client, "_read_message")
    with pytest.raises(ToolError, match=r"Invalid message length"):
        await read_message()
    setattr(client, "_handle", None)


# ---------------------------------------------------------------------------
# GAP-09b: _read_message malformed JSON body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_message_malformed_json_raises_tool_error(fake_pipe: _FakePipe) -> None:
    """``_read_message`` raises ``ToolError`` for a non-JSON body (GAP-09).

    Concrete mutation caught: removing the ``except json.JSONDecodeError``
    handler in ``_read_message`` would let ``JSONDecodeError`` propagate
    unhandled, which the caller ``_reader_loop`` would not catch (it only
    catches ``ToolError``, ``OSError``, ``RuntimeError``, ``ValueError``).
    This gate feeds ``b"not-valid-json{{"`` as the frame body and asserts
    ``ToolError`` matching ``"Invalid JSON payload"``.

    Args:
        fake_pipe: In-memory transport driving the client.
    """
    client = _raw_client(fake_pipe)
    body = b"not-valid-json{{"
    fake_pipe.push_raw_bytes(len(body).to_bytes(4, "little") + body)

    read_message: Callable[[], Any] = getattr(client, "_read_message")
    with pytest.raises(ToolError, match=r"Invalid JSON payload"):
        await read_message()
    setattr(client, "_handle", None)


# ---------------------------------------------------------------------------
# GAP-09c: _read_message non-dict JSON payload (e.g. JSON array)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_message_non_dict_payload_raises_tool_error(fake_pipe: _FakePipe) -> None:
    """``_read_message`` raises ``ToolError`` when the decoded payload is not a ``dict`` (GAP-09).

    Concrete mutation caught: removing ``if not isinstance(payload, dict)``
    from ``_read_message`` would allow a JSON array payload to be returned as
    a ``list``, which the caller treats as a ``dict`` and calls ``.get("id")``
    on, raising an ``AttributeError`` instead of the controlled
    ``ToolError("Unexpected message payload type")``. This gate pushes the
    valid JSON array ``[1, 2, 3]`` and asserts the exact error message.

    Args:
        fake_pipe: In-memory transport driving the client.
    """
    client = _raw_client(fake_pipe)
    body = json.dumps([1, 2, 3]).encode("utf-8")
    fake_pipe.push_raw_bytes(len(body).to_bytes(4, "little") + body)

    read_message: Callable[[], Any] = getattr(client, "_read_message")
    with pytest.raises(ToolError, match=r"Unexpected message payload type"):
        await read_message()
    setattr(client, "_handle", None)


# ---------------------------------------------------------------------------
# GAP-11a: _reader_loop response missing integer id → warning log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reader_loop_response_missing_id_logs_warning(
    fake_pipe: _FakePipe,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_reader_loop`` emits ``pipe_response_missing_id`` warning for a frame without an int id (GAP-11).

    Concrete mutation caught: removing the ``if not isinstance(request_id_obj, int)``
    guard and its warning log from ``_reader_loop`` would silently discard the
    orphaned frame without any diagnostic, making it impossible to detect
    protocol violations from a misbehaving peer. This gate pushes a valid JSON
    object without an ``"id"`` key and asserts the warning is emitted at
    ``log_level == "warning"``.

    Args:
        fake_pipe: In-memory transport driving the client.
        monkeypatch: Fixture used to swap the module logger for a recording sink.
    """
    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_wave2d_missing_id",
        connect_timeout=1.0,
        io_timeout=1.0,
    )
    sink = _LogSink("pipe_response_missing_id")
    monkeypatch.setattr("intellicrack.bridges.named_pipe_client._logger", sink)
    client = NamedPipeClient(config=config)
    _bind_fake_pipe(client, fake_pipe)
    try:
        await client.connect()
        fake_pipe.push_server_frame({"type": "response", "result": "no-id-field"})
        ok = await asyncio.to_thread(sink.event_seen.wait, 3.0)
    finally:
        if client.is_connected:
            await client.close()

    assert ok, "pipe_response_missing_id was never logged within 3 seconds"
    matching = [r for r in sink.records if r[1] == "pipe_response_missing_id"]
    assert matching
    assert matching[0][0] == "warning"
    assert matching[0][2].get("msg_type") == "response"


# ---------------------------------------------------------------------------
# GAP-11b: _reader_loop response with no pending waiter → debug log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reader_loop_no_waiter_for_id_logs_debug(
    fake_pipe: _FakePipe,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_reader_loop`` emits ``pipe_response_no_waiter`` debug log for an orphaned response id (GAP-11).

    Concrete mutation caught: removing the ``_logger.debug("pipe_response_no_waiter", ...)``
    call from ``_reader_loop`` would silently discard responses whose sender
    future timed-out or was cancelled, making id-mismatch bugs invisible in
    production logs. This gate pushes a response with ``id=77777`` (for which
    no future is registered) and asserts a debug-level log entry with
    ``request_id == 77777``.

    Args:
        fake_pipe: In-memory transport driving the client.
        monkeypatch: Fixture used to swap the module logger for a recording sink.
    """
    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_wave2d_no_waiter",
        connect_timeout=1.0,
        io_timeout=1.0,
    )
    sink = _LogSink("pipe_response_no_waiter")
    monkeypatch.setattr("intellicrack.bridges.named_pipe_client._logger", sink)
    client = NamedPipeClient(config=config)
    _bind_fake_pipe(client, fake_pipe)
    try:
        await client.connect()
        fake_pipe.push_server_frame({"id": 77777, "type": "response", "data": "orphan"})
        ok = await asyncio.to_thread(sink.event_seen.wait, 3.0)
    finally:
        if client.is_connected:
            await client.close()

    assert ok, "pipe_response_no_waiter was never logged within 3 seconds"
    matching = [r for r in sink.records if r[1] == "pipe_response_no_waiter"]
    assert matching
    assert matching[0][0] == "debug"
    assert matching[0][2].get("request_id") == 77777
