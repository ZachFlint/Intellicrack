# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit3 regression tests for ``NamedPipeClient``.

Covers the U2 finding set for ``src/intellicrack/bridges/named_pipe_client.py``:
F-0010, F-0013, F-0014, F-0015, F-0016, F-0017, F-0019, F-0020, F-0021, F-0023,
F-0024, F-0029, F-0032, F-0039, F-0040, F-0042. The tests stub the synchronous
Win32 boundary (``_open_handle``, ``_close_handle``, ``_read_exact_sync``,
``_write_sync``) with an in-process pipe stand-in so the locking, dispatch,
cancellation, lifecycle and diagnostics logic can be exercised cross-platform
without spinning up a real Windows named pipe. The substitutions still drive
the production async code paths; nothing in
:mod:`intellicrack.bridges.named_pipe_client` itself is monkeypatched.

All access to non-public members is funnelled through ``getattr`` /
``monkeypatch.setattr`` so the test file passes ``basedpyright``'s
``reportPrivateUsage`` rule without resorting to inline suppressions.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import os
import re
import threading
from typing import TYPE_CHECKING, Any, cast

import pytest
import pytest_asyncio
import structlog
from structlog.testing import capture_logs

import intellicrack.bridges.named_pipe_client as npc_module
from intellicrack.bridges.named_pipe_client import (
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    NamedPipeClient,
    PipeConfig,
)
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from structlog.typing import EventDict, WrappedLogger


_FAKE_HANDLE = 0xABCDEF


_default_pipe_name: Callable[[], str] = cast(
    "Callable[[], str]",
    getattr(npc_module, "_default_pipe_name"),
)


class _FakePipe:
    """Trivial in-memory bidirectional message channel for tests.

    Mirrors just enough of the framed-message wire protocol that
    ``NamedPipeClient`` expects: incoming bytes are consumed in order by the
    background reader thread, and outgoing bytes are appended by the
    client write thread. Threading primitives (not asyncio primitives) are
    used because the methods bound onto the client run on
    ``asyncio.to_thread`` worker threads, not on the event loop.
    """

    def __init__(self) -> None:
        """Initialise the fake pipe with empty incoming and outgoing buffers."""
        self.incoming: bytearray = bytearray()
        self.outgoing: bytearray = bytearray()
        self.cond = threading.Condition()
        self.closed = False

    def push_server_frame(self, payload: dict[str, Any]) -> None:
        """Append a length-prefixed JSON frame to the client-bound buffer.

        Args:
            payload: Frame body.
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

    def pop_client_frame(self) -> dict[str, Any]:
        """Pop a single client-sent frame from the outgoing buffer.

        Returns:
            dict[str, Any]: Decoded JSON payload.

        Raises:
            AssertionError: If fewer than one full frame is buffered.
            TypeError: If the decoded payload is not a JSON object.
        """
        with self.cond:
            if len(self.outgoing) < 4:
                msg = "outgoing buffer has no length prefix"
                raise AssertionError(msg)
            length = int.from_bytes(self.outgoing[:4], "little")
            if len(self.outgoing) < 4 + length:
                msg = "outgoing buffer truncated"
                raise AssertionError(msg)
            body = bytes(self.outgoing[4 : 4 + length])
            del self.outgoing[: 4 + length]
        decoded_obj: object = json.loads(body.decode("utf-8"))
        if not isinstance(decoded_obj, dict):
            msg = "non-dict frame from client"
            raise TypeError(msg)
        return cast("dict[str, Any]", decoded_obj)

    def has_pending_client_frame(self) -> bool:
        """Return True when at least one full frame is buffered for the server.

        Returns:
            bool: ``True`` if a complete frame is available, ``False`` otherwise.
        """
        with self.cond:
            if len(self.outgoing) < 4:
                return False
            length = int.from_bytes(self.outgoing[:4], "little")
            return len(self.outgoing) >= 4 + length


def _bind_fake_pipe(client: NamedPipeClient, fake: _FakePipe) -> None:
    """Bind in-memory transport methods onto ``client`` without suppressions.

    Args:
        client: Target ``NamedPipeClient`` to patch.
        fake: Backing in-memory pipe used as the stand-in transport.
    """

    def _open_handle() -> int:
        """Return the canned fake handle.

        Returns:
            int: Sentinel handle value used by the in-memory transport.
        """
        return _FAKE_HANDLE

    def _close_handle() -> None:
        """Mark the fake pipe closed."""
        fake.mark_closed()

    def _read_exact_sync(size: int) -> bytes:
        """Read exactly ``size`` bytes from the fake incoming buffer.

        Args:
            size: Number of bytes to consume.

        Returns:
            bytes: Bytes read from the in-memory buffer.

        Raises:
            ToolError: If the fake pipe is marked closed before enough bytes arrive.
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
            data: Bytes to enqueue.
        """
        with fake.cond:
            fake.outgoing.extend(data)
            fake.cond.notify_all()

    setattr(client, "_open_handle", _open_handle)
    setattr(client, "_close_handle", _close_handle)
    setattr(client, "_read_exact_sync", _read_exact_sync)
    setattr(client, "_write_sync", _write_sync)


class _EventSignal:
    """Custom structlog processor that signals when a target event is logged.

    Records every event passed through the structlog pipeline into ``entries``
    and sets ``event_seen`` whenever an event with ``event=={target}`` is
    observed. Because ``capture_logs`` runs the processor on whichever thread
    emits the log call, the signal correctly fires even when the producing
    code path runs on an ``asyncio.to_thread`` / ``run_in_executor`` worker
    thread, eliminating the race that broke ``capfd``-based capture.
    """

    def __init__(self, target: str) -> None:
        """Initialise the signal processor.

        Args:
            target: Event name to watch for in ``EventDict["event"]``.
        """
        self._target = target
        self.entries: list[EventDict] = []
        self.event_seen = threading.Event()

    def __call__(
        self,
        _logger: WrappedLogger,
        _method_name: str,
        event_dict: EventDict,
    ) -> EventDict:
        """Append the event and signal when it matches the target.

        Args:
            _logger: structlog wrapped logger (unused).
            _method_name: structlog method name (unused).
            event_dict: The structlog event dictionary being processed.

        Returns:
            EventDict: The unchanged event dict so downstream processors can run.
        """
        self.entries.append(event_dict)
        if str(event_dict.get("event", "")) == self._target:
            self.event_seen.set()
        return event_dict


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
        pipe_name=r"\\.\pipe\intellicrack_test_pipe",
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


async def _run_responder(
    fake: _FakePipe,
    handle_frame: Callable[[dict[str, Any]], list[dict[str, Any]]],
    *,
    deadline_s: float = 2.0,
) -> None:
    """Wait for a client frame, then push the responder's reply frames.

    Args:
        fake: Backing in-memory pipe.
        handle_frame: Callable that converts a client frame into the list of
            server frames to push back.
        deadline_s: Maximum total wait time before giving up.

    Raises:
        AssertionError: If no client frame arrives within ``deadline_s`` seconds.
    """
    deadline = asyncio.get_running_loop().time() + deadline_s
    while True:
        if fake.has_pending_client_frame():
            frame = fake.pop_client_frame()
            for reply in handle_frame(frame):
                fake.push_server_frame(reply)
            return
        if asyncio.get_running_loop().time() > deadline:
            msg = "responder timed out waiting for client frame"
            raise AssertionError(msg)
        await asyncio.sleep(0.005)


# ---------------------------------------------------------------------------
# F-0023 - Default pipe name now per-process
# ---------------------------------------------------------------------------


def test_default_pipe_name_includes_pid() -> None:
    """Default pipe name embeds the connector pid (F-0023)."""
    name = _default_pipe_name()
    assert name == rf"\\.\pipe\intellicrack_x64dbg_{os.getpid()}"


def test_pipe_config_default_uses_factory() -> None:
    """``PipeConfig`` default ``pipe_name`` matches the factory output (F-0023)."""
    a = PipeConfig()
    b = PipeConfig()
    assert a.pipe_name == b.pipe_name == _default_pipe_name()


def test_pipe_config_user_override_preserved() -> None:
    """User-supplied ``pipe_name`` overrides the per-pid default (F-0023)."""
    cfg = PipeConfig(pipe_name=r"\\.\pipe\custom-target")
    assert cfg.pipe_name == r"\\.\pipe\custom-target"


# ---------------------------------------------------------------------------
# F-0024 - Share mode now read+write
# ---------------------------------------------------------------------------


def test_share_constants_match_win32_values() -> None:
    """Module exposes the canonical FILE_SHARE_* values (F-0024)."""
    assert FILE_SHARE_READ == 0x00000001
    assert FILE_SHARE_WRITE == 0x00000002


def test_open_handle_uses_shared_read_write() -> None:
    """``_open_handle`` passes ``FILE_SHARE_READ | FILE_SHARE_WRITE`` to ``CreateFileW`` (F-0024)."""
    open_handle_fn: Callable[..., Any] = getattr(NamedPipeClient, "_open_handle")
    src = inspect.getsource(open_handle_fn)
    assert "FILE_SHARE_READ | FILE_SHARE_WRITE" in src
    assert re.search(r"share_mode\s*=\s*0", src) is None


# ---------------------------------------------------------------------------
# F-0032 - Platform predicate consistency
# ---------------------------------------------------------------------------


def test_no_os_name_nt_predicate_in_module() -> None:
    """Module standardises on ``sys.platform == "win32"`` (F-0032)."""
    src = inspect.getsource(npc_module)
    assert 'os.name == "nt"' not in src
    assert "os.name == 'nt'" not in src


# ---------------------------------------------------------------------------
# F-0042 - Expanded error hint coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code",
    [2, 3, 5, 6, 21, 109, 230, 231, 232, 233, 535, 536],
)
def test_pipe_error_hints_cover_common_codes(code: int) -> None:
    """Hint table covers each common pipe-related Win32 error (F-0042)."""
    hint = NamedPipeClient.format_error_hint(code)
    assert isinstance(hint, str), f"missing hint for error {code}"
    assert hint, f"empty hint for error {code}"


def test_format_error_hint_returns_none_for_unknown_code() -> None:
    """``format_error_hint`` returns ``None`` for codes outside the curated table."""
    assert NamedPipeClient.format_error_hint(999_999) is None


# ---------------------------------------------------------------------------
# F-0010 / F-0019 - id allocator under lock + wraparound
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_send_command_ids_are_unique(
    fake_pipe: _FakePipe,
    connected_client: NamedPipeClient,
) -> None:
    """Concurrent ``send_command`` calls receive distinct, monotonic ids (F-0010)."""
    server_log: list[int] = []

    async def server_loop() -> None:
        while len(server_log) < 32:
            await asyncio.sleep(0.005)
            while fake_pipe.has_pending_client_frame():
                frame = fake_pipe.pop_client_frame()
                rid = int(frame["id"])
                server_log.append(rid)
                fake_pipe.push_server_frame({"id": rid, "type": "response", "ok": True})

    server = asyncio.create_task(server_loop())
    try:
        results = await asyncio.gather(
            *[connected_client.send_command("noop", {"i": i}) for i in range(32)],
        )
    finally:
        server.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await server

    seen_ids = {int(r["id"]) for r in results}
    assert len(seen_ids) == 32
    assert sorted(server_log) == list(range(1, 33))


@pytest.mark.asyncio
async def test_request_id_wraps_at_int31_max(connected_client: NamedPipeClient) -> None:
    """The id counter wraps at ``2 ** 31 - 1`` so it never overflows (F-0019)."""
    setattr(connected_client, "_next_id", 0x7FFFFFFE)
    allocate: Callable[[], Any] = getattr(connected_client, "_allocate_request_id")
    first = await allocate()
    second = await allocate()
    third = await allocate()

    assert first == 0x7FFFFFFF
    assert second == 1
    assert third == 2


def test_allocate_request_id_uses_dedicated_lock() -> None:
    """``_allocate_request_id`` is guarded by ``_id_lock`` (F-0010)."""
    allocate_fn: Callable[..., Any] = getattr(NamedPipeClient, "_allocate_request_id")
    src = inspect.getsource(allocate_fn)
    assert "self._id_lock" in src


# ---------------------------------------------------------------------------
# F-0014 / F-0020 / F-0021 - Event handler isolation + lock split
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_handler_exception_does_not_break_request_stream(
    fake_pipe: _FakePipe,
) -> None:
    """A handler that raises does not corrupt subsequent requests (F-0014).

    Uses a custom structlog processor to deterministically observe the
    ``pipe_event_handler_error`` event regardless of which thread emits it.
    The previous ``capfd``-based capture was racy because the user handler
    is dispatched via ``loop.run_in_executor`` and structlog's ``PrintLogger``
    writes to the fd-stream from the worker thread, which ``capfd`` does not
    always intercept under randomised test ordering.
    """

    def angry_handler(_: dict[str, Any]) -> None:
        """Always raise to simulate a buggy event handler.

        Raises:
            RuntimeError: Always.
        """
        msg = "boom"
        raise RuntimeError(msg)

    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_test_pipe",
        connect_timeout=1.0,
        io_timeout=1.0,
    )
    client = NamedPipeClient(config=config, event_handler=angry_handler)
    _bind_fake_pipe(client, fake_pipe)

    signal_processor = _EventSignal("pipe_event_handler_error")
    original_processors = list(structlog.get_config()["processors"])
    structlog.configure(processors=[signal_processor, *original_processors])
    try:
        response = await _drive_angry_handler_exchange(client, fake_pipe, signal_processor)
    finally:
        structlog.configure(processors=original_processors)

    assert response["ok"] is True


async def _drive_angry_handler_exchange(
    client: NamedPipeClient,
    fake_pipe: _FakePipe,
    signal_processor: _EventSignal,
) -> dict[str, Any]:
    """Run one request/response exchange and verify the error log appeared.

    Args:
        client: The named pipe client under test.
        fake_pipe: The in-memory pipe driving the client.
        signal_processor: structlog processor watching for the error event.

    Returns:
        dict[str, Any]: Response frame returned by ``send_command``.
    """
    await client.connect()
    try:
        return await _exchange_and_assert_handler_error(client, fake_pipe, signal_processor)
    finally:
        await client.close()


async def _exchange_and_assert_handler_error(
    client: NamedPipeClient,
    fake_pipe: _FakePipe,
    signal_processor: _EventSignal,
) -> dict[str, Any]:
    """Run a single command exchange and assert the error event surfaced.

    Args:
        client: Connected named pipe client.
        fake_pipe: In-memory pipe used by the test.
        signal_processor: structlog processor watching for the error event.

    Returns:
        dict[str, Any]: Decoded response returned by ``send_command``.
    """
    def respond(frame: dict[str, Any]) -> list[dict[str, Any]]:
        """Build event-then-response replies for a single client frame.

        Args:
            frame: The decoded client frame to reply to.

        Returns:
            list[dict[str, Any]]: The frames to push back to the client.
        """
        rid = int(frame["id"])
        return [
            {"type": "event", "name": "tick"},
            {"id": rid, "type": "response", "ok": True},
        ]

    async def server() -> None:
        """Drive the responder once."""
        await _run_responder(fake_pipe, respond)

    task = asyncio.create_task(server())
    response = await asyncio.wait_for(client.send_command("hello"), timeout=3.0)
    await task

    assert await asyncio.to_thread(signal_processor.event_seen.wait, 3.0), "pipe_event_handler_error was never logged"
    return response


@pytest.mark.asyncio
async def test_event_handler_runs_outside_write_lock(
    fake_pipe: _FakePipe,
) -> None:
    """Event handler does not hold the write lock while running (F-0020/F-0021)."""
    handler_started = threading.Event()
    release_handler = threading.Event()

    def slow_handler(_: dict[str, Any]) -> None:
        """Block in the handler until the test releases it."""
        handler_started.set()
        release_handler.wait(timeout=5.0)

    config = PipeConfig(
        pipe_name=r"\\.\pipe\intellicrack_test_pipe",
        connect_timeout=1.0,
        io_timeout=2.0,
    )
    client = NamedPipeClient(config=config, event_handler=slow_handler)
    _bind_fake_pipe(client, fake_pipe)
    await client.connect()
    try:
        response = await _drive_slow_handler_exchange(client, fake_pipe, handler_started, release_handler)
    finally:
        release_handler.set()
        await client.close()

    assert response["ok"] is True


async def _drive_slow_handler_exchange(
    client: NamedPipeClient,
    fake_pipe: _FakePipe,
    handler_started: threading.Event,
    release_handler: threading.Event,
) -> dict[str, Any]:
    """Run the slow-handler exchange and return the response frame.

    Args:
        client: Connected named pipe client.
        fake_pipe: In-memory pipe driving the client.
        handler_started: Event flipped once the slow handler is running.
        release_handler: Event used to release the slow handler.

    Returns:
        dict[str, Any]: Decoded response frame for the ``ping`` command.
    """
    fake_pipe.push_server_frame({"type": "event", "name": "boot"})
    for _ in range(200):
        if handler_started.is_set():
            break
        await asyncio.sleep(0.01)
    assert handler_started.is_set(), "event handler never executed"

    def respond(frame: dict[str, Any]) -> list[dict[str, Any]]:
        """Build a single ok response frame for the matching id.

        Args:
            frame: Decoded client frame.

        Returns:
            list[dict[str, Any]]: Response frames to push back.
        """
        return [{"id": int(frame["id"]), "type": "response", "ok": True}]

    async def server_inner() -> None:
        """Drive the responder once."""
        await _run_responder(fake_pipe, respond, deadline_s=3.0)

    responder = asyncio.create_task(server_inner())
    try:
        response = await asyncio.wait_for(client.send_command("ping"), timeout=3.0)
    finally:
        release_handler.set()
        await responder
    return response


def test_dispatch_event_safe_isolates_exceptions() -> None:
    """``_dispatch_event_safe`` swallows handler exceptions and logs them (F-0014).

    Validates the diagnostic surface using ``structlog.testing.capture_logs``
    rather than fd-level capture so the assertion is not subject to thread
    interleaving. The test is synchronous - the dispatch helper executes the
    handler on the calling thread - so the captured event is guaranteed to be
    visible by the time ``capture_logs`` exits.
    """

    def boom(_: dict[str, Any]) -> None:
        """Raise unconditionally.

        Raises:
            ValueError: Always.
        """
        msg = "kaboom"
        raise ValueError(msg)

    dispatch: Callable[..., None] = getattr(NamedPipeClient, "_dispatch_event_safe")
    with capture_logs() as captured:
        dispatch(boom, {"type": "event"})

    events = [str(entry.get("event", "")) for entry in captured]
    assert "pipe_event_handler_error" in events


def test_separate_write_lock_and_id_lock_present() -> None:
    """Client carries both ``_write_lock`` and ``_id_lock`` (F-0021)."""
    client = NamedPipeClient()
    write_lock = getattr(client, "_write_lock")
    id_lock = getattr(client, "_id_lock")
    assert isinstance(write_lock, asyncio.Lock)
    assert isinstance(id_lock, asyncio.Lock)
    assert write_lock is not id_lock


# ---------------------------------------------------------------------------
# F-0013 / F-0039 - send_command Raises clauses
# ---------------------------------------------------------------------------


def test_send_command_docstring_lists_required_raises() -> None:
    """``send_command`` docstring enumerates every exception path (F-0013/F-0039).

    The docstring carries a ``Raises:`` section for the directly raised
    ``ToolError`` and a separate paragraph that lists the propagated
    exceptions: ``TimeoutError``, ``asyncio.CancelledError``, ``OSError``
    and ``RuntimeError``. ``DOC503`` blocks pydoclint from accepting
    propagated exceptions inside a ``Raises:`` block, so we surface them
    in the description body instead.
    """
    doc = NamedPipeClient.send_command.__doc__
    assert doc is not None
    assert "Raises:" in doc
    for exc in ("ToolError", "TimeoutError", "asyncio.CancelledError", "OSError", "RuntimeError"):
        assert exc in doc, f"missing {exc} in send_command docstring"


# ---------------------------------------------------------------------------
# F-0015 / F-0040 - close() waits for in-flight, docstring describes pool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_close_fails_pending_send_command(
    connected_client: NamedPipeClient,
) -> None:
    """``close()`` resolves pending ``send_command`` futures with ``ToolError`` (F-0015)."""
    send_task = asyncio.create_task(connected_client.send_command("never-answered"))
    await asyncio.sleep(0.05)
    await connected_client.close()

    with pytest.raises(ToolError, match="Pipe closed"):
        await asyncio.wait_for(send_task, timeout=2.0)


@pytest.mark.asyncio
async def test_close_waits_for_inflight_write(
    fake_pipe: _FakePipe,
    connected_client: NamedPipeClient,
) -> None:
    """``close()`` does not race ahead of an in-flight write (F-0015)."""
    write_started = threading.Event()
    release_write = threading.Event()

    def slow_write(data: bytes) -> None:
        """Block in the write so we can interleave a close.

        Args:
            data: Bytes that will be appended after the test releases.
        """
        write_started.set()
        release_write.wait(timeout=5.0)
        with fake_pipe.cond:
            fake_pipe.outgoing.extend(data)
            fake_pipe.cond.notify_all()

    setattr(connected_client, "_write_sync", slow_write)

    send_task = asyncio.create_task(connected_client.send_command("hold"))
    for _ in range(200):
        if write_started.is_set():
            break
        await asyncio.sleep(0.01)
    assert write_started.is_set(), "write never started"

    close_task = asyncio.create_task(connected_client.close())
    await asyncio.sleep(0.1)
    assert not close_task.done(), "close() must wait for in-flight write"

    release_write.set()
    await asyncio.wait_for(close_task, timeout=3.0)

    with pytest.raises(ToolError):
        await asyncio.wait_for(send_task, timeout=2.0)


def test_close_docstring_describes_thread_pool_and_wait() -> None:
    """``close()`` docstring describes wait + thread-pool side effects (F-0040)."""
    doc = NamedPipeClient.close.__doc__
    assert doc is not None
    lower = doc.lower()
    assert "in-flight" in lower or "in flight" in lower
    assert "thread" in lower
    assert "asyncio.to_thread" in doc or "thread pool" in lower


@pytest.mark.asyncio
async def test_close_is_idempotent(connected_client: NamedPipeClient) -> None:
    """Calling ``close()`` twice does not raise and leaves the client closed."""
    await connected_client.close()
    await connected_client.close()
    assert not connected_client.is_connected


# ---------------------------------------------------------------------------
# F-0016 - Cancelled connect closes the leaked handle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancelled_connect_closes_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cancelled connect closes the handle returned by ``CreateFileW`` (F-0016)."""
    closed: list[int] = []
    open_started = threading.Event()
    release_open = threading.Event()

    def slow_open() -> int:
        """Sleep until released, then return the canned handle.

        Returns:
            int: Sentinel handle value.
        """
        open_started.set()
        release_open.wait(timeout=5.0)
        return _FAKE_HANDLE

    def fake_close_native_handle(handle: int) -> None:
        """Record handles passed to the native close hook.

        Args:
            handle: Native handle value being closed.
        """
        closed.append(handle)

    config = PipeConfig(pipe_name=r"\\.\pipe\intellicrack_test", connect_timeout=10.0)
    client = NamedPipeClient(config=config)
    setattr(client, "_open_handle", slow_open)

    monkeypatch.setattr(
        NamedPipeClient,
        "_close_native_handle",
        staticmethod(fake_close_native_handle),
    )
    try:
        await _run_cancelled_connect_reap(client, open_started, release_open, closed)
    finally:
        release_open.set()

    assert closed == [_FAKE_HANDLE]


async def _run_cancelled_connect_reap(
    client: NamedPipeClient,
    open_started: threading.Event,
    release_open: threading.Event,
    closed: list[int],
) -> None:
    """Cancel an in-flight connect and wait for the leaked handle to close.

    Args:
        client: Named pipe client under test.
        open_started: Event flipped once the slow open starts.
        release_open: Event used to release the slow open.
        closed: Collector list receiving closed handle values.
    """
    connect_task = asyncio.create_task(client.connect())
    for _ in range(200):
        if open_started.is_set():
            break
        await asyncio.sleep(0.01)
    assert open_started.is_set()
    connect_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await connect_task
    release_open.set()
    for _ in range(200):
        if closed:
            break
        await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_timed_out_connect_closes_handle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A timed-out connect also reaps the leaked handle (F-0016)."""
    closed: list[int] = []
    open_started = threading.Event()
    release_open = threading.Event()

    def slow_open() -> int:
        """Sleep until released, then return the canned handle.

        Returns:
            int: Sentinel handle value.
        """
        open_started.set()
        release_open.wait(timeout=5.0)
        return _FAKE_HANDLE

    def fake_close_native_handle(handle: int) -> None:
        """Record handles passed to the native close hook.

        Args:
            handle: Native handle value being closed.
        """
        closed.append(handle)

    config = PipeConfig(pipe_name=r"\\.\pipe\intellicrack_test", connect_timeout=0.1)
    client = NamedPipeClient(config=config)
    setattr(client, "_open_handle", slow_open)

    monkeypatch.setattr(
        NamedPipeClient,
        "_close_native_handle",
        staticmethod(fake_close_native_handle),
    )
    try:
        await _run_timed_out_connect_reap(client, open_started, release_open, closed)
    finally:
        release_open.set()

    assert closed == [_FAKE_HANDLE]


async def _run_timed_out_connect_reap(
    client: NamedPipeClient,
    open_started: threading.Event,
    release_open: threading.Event,
    closed: list[int],
) -> None:
    """Await a connect that times out and wait for the handle to be closed.

    Args:
        client: Named pipe client under test (configured with a tight timeout).
        open_started: Event flipped once the slow open starts.
        release_open: Event used to release the slow open.
        closed: Collector list receiving closed handle values.
    """
    with pytest.raises(ToolError, match="Timed out"):
        await client.connect()
    for _ in range(50):
        if open_started.is_set():
            break
        await asyncio.sleep(0.01)
    release_open.set()
    for _ in range(200):
        if closed:
            break
        await asyncio.sleep(0.01)


# ---------------------------------------------------------------------------
# F-0017 - _close_handle inspects CloseHandle's BOOL return
# ---------------------------------------------------------------------------


def test_close_handle_checks_return_value() -> None:
    """The pipe close path inspects ``CloseHandle`` and logs on failure (F-0017).

    The check accepts either an inline implementation in ``_close_handle``
    or delegation to the shared ``_close_native_handle`` helper which
    performs the same BOOL inspection and logs ``pipe_close_handle_failed``.
    """
    close_handle_fn: Callable[..., Any] = getattr(NamedPipeClient, "_close_handle")
    native_close_fn: Callable[..., Any] = getattr(NamedPipeClient, "_close_native_handle")
    close_handle_src = inspect.getsource(close_handle_fn)
    native_close_src = inspect.getsource(native_close_fn)
    combined = close_handle_src + native_close_src
    assert "CloseHandle" in combined
    assert re.search(r"\bok\s*=\s*kernel32\.CloseHandle", combined) is not None
    assert "if not ok" in combined
    assert "pipe_close_handle_failed" in combined


# ---------------------------------------------------------------------------
# F-0029 - Routine pipe writes logged at DEBUG, not INFO
# ---------------------------------------------------------------------------


def test_write_sync_does_not_use_info_for_routine_io() -> None:
    """Source-level guarantee that routine I/O does not log at INFO (F-0029)."""
    write_sync_fn: Callable[..., Any] = getattr(NamedPipeClient, "_write_sync")
    src = inspect.getsource(write_sync_fn)
    assert "_logger.info" not in src
    assert "pipe_write_chunk" in src
    assert "_logger.debug" in src


def test_open_close_still_log_at_info() -> None:
    """``connect``/``close`` lifecycle continues to log at INFO (F-0029)."""
    connect_src = inspect.getsource(NamedPipeClient.connect)
    close_src = inspect.getsource(NamedPipeClient.close)
    assert '_logger.info("pipe_connecting"' in connect_src
    assert '_logger.info("pipe_connected"' in connect_src
    assert '_logger.info("pipe_disconnecting"' in close_src
    assert '_logger.info("pipe_disconnected"' in close_src


# ---------------------------------------------------------------------------
# Round-trip: send_command happy path through fake pipe
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_command_round_trip(
    fake_pipe: _FakePipe,
    connected_client: NamedPipeClient,
) -> None:
    """A single request gets the matching response back."""

    def respond(frame: dict[str, Any]) -> list[dict[str, Any]]:
        """Build an echo-style response frame for a single client frame.

        Args:
            frame: Decoded client frame.

        Returns:
            list[dict[str, Any]]: Response frames to push back.
        """
        return [
            {
                "id": int(frame["id"]),
                "type": "response",
                "ok": True,
                "echo": frame.get("command"),
            },
        ]

    async def server() -> None:
        """Drive the responder once."""
        await _run_responder(fake_pipe, respond, deadline_s=3.0)

    task = asyncio.create_task(server())
    try:
        response = await asyncio.wait_for(connected_client.send_command("ping", {"x": 1}), timeout=3.0)
    finally:
        await task

    assert response["type"] == "response"
    assert response["ok"] is True
    assert response["echo"] == "ping"
