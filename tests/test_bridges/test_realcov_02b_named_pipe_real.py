# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Real Win32 named-pipe coverage for :class:`NamedPipeClient`.

The audit (``audit/test-audit-02-bridges-debugger-process.md``) flags that
``tests/test_audit3/bridges/test_named_pipe_client.py`` intentionally stubs the
four synchronous Win32 transport methods (``_open_handle``,
``_read_exact_sync``, ``_write_sync``, ``_close_handle``) with an in-memory
``_FakePipe``. That design exercises the async orchestration cross-platform but
never touches the real kernel pipe, so it cannot prove ``WaitNamedPipeW``,
``CreateFileW``, ``ReadFile``, ``WriteFile``, ``CloseHandle`` behaviour or real
``GetLastError`` propagation.

This module closes that gap. Every test here drives the *unmodified* production
``NamedPipeClient`` against a **real** Windows kernel named pipe served by a
separate operating-system process created with ``CreateNamedPipeW``. Nothing in
:mod:`intellicrack.bridges.named_pipe_client` is monkeypatched, faked, or
stubbed: the client's real ``_open_handle`` blocks on a real ``WaitNamedPipeW``,
its real ``_write_sync`` issues real ``WriteFile`` calls, its real
``_read_exact_sync`` issues real ``ReadFile`` calls, and its real
``_close_handle`` issues a real ``CloseHandle``. The server side is a genuine
duplex byte-stream named pipe, so the length-prefixed framed-message protocol
round-trips over the operating-system kernel exactly as it would against the
x64dbg plugin.

The server runs in a dedicated child process (rather than a thread) so the
blocking kernel I/O on the server side never contends with the client's asyncio
event loop for the GIL. Each scenario uses one request/response exchange per
connection (with the server free to multiplex an asynchronous event frame
ahead of a response), which is what the framed protocol guarantees over a real
synchronous duplex pipe. Because these tests spawn a real OS process, they
carry the ``spawns_process`` marker and run only inside the sandbox harness.
"""

from __future__ import annotations

import asyncio
import ctypes
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from typing import TYPE_CHECKING

import pytest

from intellicrack.bridges.named_pipe_client import NamedPipeClient, PipeConfig
from intellicrack.core.types import ToolError
from tests._helpers import realcov_pipe_server as srv


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="Named pipes are Windows-only"),
    pytest.mark.spawns_process,
]


_ERROR_FILE_NOT_FOUND = 2
_SERVER_MODULE = "tests._helpers.realcov_pipe_server"
_PIPE_READY_TIMEOUT_S = 20.0


def _unique_pipe_name() -> str:
    r"""Return a fresh, collision-free local named-pipe path.

    Returns:
        str: A ``\\.\pipe\intellicrack_realcov_<uuid>`` endpoint unique to the
        current test invocation.
    """
    return rf"\\.\pipe\intellicrack_realcov_{uuid.uuid4().hex}"


def _spawn_server(pipe_name: str, mode: str) -> subprocess.Popen[bytes]:
    """Start the standalone pipe-server process for ``pipe_name``.

    Launches ``tests._helpers.realcov_pipe_server`` as a separate OS process so
    its blocking kernel I/O runs without contending for this interpreter's GIL.
    The child hosts a single real named-pipe endpoint.

    Args:
        pipe_name: Fully-qualified named-pipe path the server will host.
        mode: Server behaviour selector.

    Returns:
        subprocess.Popen[bytes]: The started server process; the caller owns
        teardown via :func:`_terminate_server`.
    """
    return subprocess.Popen(
        [sys.executable, "-m", _SERVER_MODULE, pipe_name, mode],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _terminate_server(proc: subprocess.Popen[bytes]) -> None:
    """Terminate and reap the standalone pipe-server process.

    Args:
        proc: The server process to stop.
    """
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5.0)


def _wait_pipe_available(pipe_name: str, deadline_s: float) -> bool:
    """Block until the named pipe exists using real ``WaitNamedPipeW``.

    Polls the kernel for the endpoint while the child server starts up.

    Args:
        pipe_name: Endpoint to probe.
        deadline_s: Maximum total seconds to wait.

    Returns:
        bool: ``True`` once the pipe is available, ``False`` if it never
        appears before the deadline.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.WaitNamedPipeW.restype = wintypes.BOOL
    k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if k32.WaitNamedPipeW(pipe_name, 200):
            return True
        time.sleep(0.05)
    return False


def _run_with_server(
    pipe_name: str,
    mode: str,
    scenario: Callable[[NamedPipeClient], Awaitable[None]],
) -> None:
    """Spawn the real pipe server, run a client scenario, then tear down.

    Server spawning and the ``WaitNamedPipeW`` readiness probe are performed
    synchronously (outside any event loop). Only the client interaction runs
    under :func:`asyncio.run`, which manages the event loop and its thread-pool
    executor lifecycle that the production client relies on for its
    ``asyncio.to_thread`` Win32 I/O. The server child process is always reaped.

    Args:
        pipe_name: Endpoint the server hosts and the client connects to.
        mode: Server behaviour selector.
        scenario: Async callable that drives a connected client and asserts.
    """
    server = _spawn_server(pipe_name, mode)
    try:
        _require_pipe(pipe_name)
        asyncio.run(_drive_client(pipe_name, server, scenario))
    finally:
        _terminate_server(server)


def _require_pipe(pipe_name: str) -> None:
    """Block until the server pipe is available, failing if it never appears.

    Args:
        pipe_name: Endpoint the child server is expected to host.

    Raises:
        ToolError: If the pipe does not become available within the readiness
            deadline.
    """
    if not _wait_pipe_available(pipe_name, _PIPE_READY_TIMEOUT_S):
        error_message = f"Server pipe {pipe_name} never became available"
        raise ToolError(error_message)


async def _drive_client(
    pipe_name: str,
    server: subprocess.Popen[bytes],
    scenario: Callable[[NamedPipeClient], Awaitable[None]],
) -> None:
    """Connect a fresh client, run ``scenario``, then close cleanly.

    The server is terminated before the client closes so the client's blocking
    reader ``ReadFile`` fails with a broken-pipe error and the reader loop
    exits; the production ``close`` then runs its full teardown path against a
    quiescent handle rather than racing ``CancelIoEx`` against a freshly issued
    blocking read.

    Args:
        pipe_name: Endpoint to connect to.
        server: The running server process, terminated before client close.
        scenario: Async callable that drives the connected client and asserts.
    """
    config = PipeConfig(pipe_name=pipe_name, connect_timeout=8.0, io_timeout=8.0)
    client = NamedPipeClient(config=config)
    await client.connect()
    try:
        await scenario(client)
    finally:
        _terminate_server(server)
        await client.close()


async def _drive_connect_and_close(pipe_name: str, server: subprocess.Popen[bytes]) -> None:
    """Open the pipe, verify connection, then close and verify teardown.

    Args:
        pipe_name: Endpoint hosted by ``server``.
        server: The running server process, terminated before client close.
    """
    config = PipeConfig(pipe_name=pipe_name, connect_timeout=8.0, io_timeout=8.0)
    client = NamedPipeClient(config=config)
    await client.connect()
    assert client.is_connected is True
    _terminate_server(server)
    await client.close()
    assert client.is_connected is False


def test_real_connect_and_close_against_kernel_pipe() -> None:
    """Real ``connect``/``close`` open and shut a genuine kernel pipe handle.

    Drives the production ``_open_handle`` (``WaitNamedPipeW`` +
    ``CreateFileW``) and ``_close_handle`` (``CloseHandle``) against a real
    server endpoint and verifies the connection-state transitions.
    """
    pipe_name = _unique_pipe_name()
    server = _spawn_server(pipe_name, srv.MODE_ECHO)
    try:
        _require_pipe(pipe_name)
        asyncio.run(_drive_connect_and_close(pipe_name, server))
    finally:
        _terminate_server(server)


@pytest.mark.timeout(30)
def test_real_send_command_round_trip() -> None:
    """A command round-trips over the real kernel pipe and matches by id.

    Proves the full real path: real ``WriteFile`` of the request frame, the
    server's real ``ReadFile`` decode, the server's real ``WriteFile`` reply,
    and the client's real ``ReadFile`` plus future dispatch. The
    ``pytest.mark.timeout(30)`` guard ensures the test fails fast if the
    server process hangs or the pipe never becomes ready, rather than blocking
    indefinitely on ``_require_pipe`` or the async ``wait_for`` inner timeout.
    """
    pipe_name = _unique_pipe_name()

    async def scenario(client: NamedPipeClient) -> None:
        """Round-trip one command and assert the echoed payload.

        Args:
            client: Connected client under test.
        """
        response = await asyncio.wait_for(
            client.send_command("inspect", {"target": "kernel32", "n": 7}),
            timeout=8.0,
        )
        assert response["type"] == "response"
        assert response["ok"] is True
        assert response["echo_command"] == "inspect"
        assert response["echo_params"] == {"target": "kernel32", "n": 7}

    _run_with_server(pipe_name, srv.MODE_ECHO, scenario)


def test_real_command_id_matches_response() -> None:
    """A response is routed to the request future by its real wire id.

    The index-mode server echoes the request's ``params.index`` back under the
    same id, proving the production request-id allocation and future-routing
    logic over a real kernel-pipe round-trip.
    """
    pipe_name = _unique_pipe_name()

    async def scenario(client: NamedPipeClient) -> None:
        """Send one indexed command and assert the echoed index matches.

        Args:
            client: Connected client under test.
        """
        response = await asyncio.wait_for(
            client.send_command("ping", {"index": 7}),
            timeout=8.0,
        )
        assert response["ok"] is True
        assert int(response["index"]) == 7

    _run_with_server(pipe_name, srv.MODE_INDEX, scenario)


def test_real_async_event_delivered_to_handler() -> None:
    """An asynchronous server event reaches the registered handler over the pipe.

    The server replies to a request with an ``event`` frame followed by the
    matching ``response`` frame. The client's real reader loop must read both
    via ``ReadFile``, dispatch the event to the handler, and still resolve the
    request future with the response, proving event multiplexing on the real
    framed stream.
    """
    pipe_name = _unique_pipe_name()
    received: list[dict[str, object]] = []

    async def scenario(client: NamedPipeClient) -> None:
        """Send one command and assert both event and response are handled.

        Args:
            client: Connected client under test.
        """
        event_seen = asyncio.Event()
        loop = asyncio.get_running_loop()

        def handler(message: dict[str, object]) -> None:
            """Capture a delivered event frame and signal the waiter.

            Args:
                message: The decoded event payload.
            """
            received.append(message)
            loop.call_soon_threadsafe(event_seen.set)

        client.set_event_handler(handler)
        response = await asyncio.wait_for(client.send_command("status"), timeout=8.0)
        await asyncio.wait_for(event_seen.wait(), timeout=8.0)
        assert response["ok"] is True
        assert received[0]["name"] == srv.EVENT_NAME
        assert received[0]["address"] == srv.EVENT_ADDRESS

    _run_with_server(pipe_name, srv.MODE_EVENT_THEN_ECHO, scenario)


def test_real_large_payload_chunked_read() -> None:
    """A multi-chunk payload survives the real chunked ``ReadFile`` loop.

    The server returns a frame whose body far exceeds a single 64 KiB read
    chunk, forcing ``_read_exact_sync`` to iterate real ``ReadFile`` calls and
    reassemble the bytes exactly.
    """
    pipe_name = _unique_pipe_name()

    async def scenario(client: NamedPipeClient) -> None:
        """Round-trip the large blob and assert byte-exact reassembly.

        Args:
            client: Connected client under test.
        """
        response = await asyncio.wait_for(client.send_command("dump"), timeout=15.0)
        assert response["blob"] == srv.BLOB_PAYLOAD
        assert len(response["blob"]) == len(srv.BLOB_PAYLOAD)

    _run_with_server(pipe_name, srv.MODE_BLOB, scenario)


async def _attempt_missing_pipe_connect(
    pipe_name: str,
    connect_timeout_s: float,
) -> None:
    """Connect to a missing endpoint and assert the exact Win32 error code surfaces.

    ``WaitNamedPipeW`` returns immediately (does not spin for the full timeout
    period) when no pipe server exists, so the timeout only bounds the worst
    case on a loaded machine. The test asserts on the **integer** error code
    embedded in the message (``error 2``) and on the presence of the human-
    readable hint text from :meth:`NamedPipeClient.format_error_hint`, not just
    that some error occurred.

    Args:
        pipe_name: A pipe path with no server behind it.
        connect_timeout_s: Seconds to pass as ``connect_timeout`` in
            :class:`PipeConfig`, allowing callers to adjust for slow
            machines without changing the assertion contract.
    """
    config = PipeConfig(pipe_name=pipe_name, connect_timeout=connect_timeout_s, io_timeout=connect_timeout_s)
    client = NamedPipeClient(config=config)
    with pytest.raises(ToolError) as excinfo:
        await client.connect()

    message = str(excinfo.value)
    error_tag = f"error {_ERROR_FILE_NOT_FOUND}"
    assert error_tag in message, (
        f"Expected real Win32 ERROR_FILE_NOT_FOUND code ({_ERROR_FILE_NOT_FOUND}) in ToolError message; got: {message!r}"
    )

    hint = NamedPipeClient.format_error_hint(_ERROR_FILE_NOT_FOUND)
    assert hint is not None, f"format_error_hint({_ERROR_FILE_NOT_FOUND}) must return a non-None hint string"
    assert hint in message, f"Expected curated hint {hint!r} in ToolError message; got: {message!r}"

    assert client.is_connected is False, "is_connected must remain False after a failed connect"


@pytest.mark.timeout(15)
def test_real_connect_missing_pipe_raises_with_error_code() -> None:
    """Connecting to a nonexistent endpoint surfaces the real ``GetLastError``.

    No server is created, so the production ``_open_handle`` path runs
    ``WaitNamedPipeW`` against a missing pipe and must raise ``ToolError``
    carrying the real ``ERROR_FILE_NOT_FOUND`` (2) code plus the curated hint.
    The 15-second test-level timeout prevents indefinite hanging on pathological
    system states while allowing a generous per-attempt budget.
    """
    asyncio.run(_attempt_missing_pipe_connect(_unique_pipe_name(), connect_timeout_s=5.0))


async def _drain_until_broken(client: NamedPipeClient) -> None:
    """Issue commands until the broken pipe causes a ``ToolError``.

    The ``ToolError`` is raised by ``send_command`` itself once the reader
    loop observes the real ``ReadFile`` failure and fails the in-flight
    request; this helper simply propagates it so the caller can assert on it.

    Args:
        client: Connected client whose server endpoint has been torn down.
    """
    for _ in range(40):
        await asyncio.wait_for(client.send_command("after_break"), timeout=8.0)
        await asyncio.sleep(0.05)


def test_real_send_command_fails_after_server_disconnect() -> None:
    """A broken kernel pipe propagates a read failure to in-flight callers.

    After a successful connect, the server process is terminated. The client's
    real reader loop observes the real ``ReadFile`` failure and fails any
    subsequent ``send_command`` with a ``ToolError`` rather than hanging.
    """
    pipe_name = _unique_pipe_name()
    server = _spawn_server(pipe_name, srv.MODE_ECHO)
    try:
        _require_pipe(pipe_name)
        asyncio.run(_drive_disconnect(pipe_name, server))
    finally:
        _terminate_server(server)


async def _drive_disconnect(pipe_name: str, server: subprocess.Popen[bytes]) -> None:
    """Connect, warm up, kill the server, and assert the client fails cleanly.

    Args:
        pipe_name: Endpoint hosted by ``server``.
        server: The running server process to terminate mid-session.
    """
    config = PipeConfig(pipe_name=pipe_name, connect_timeout=8.0, io_timeout=8.0)
    client = NamedPipeClient(config=config)
    await client.connect()
    try:
        first = await asyncio.wait_for(client.send_command("warmup"), timeout=8.0)
        assert first["ok"] is True
        _terminate_server(server)
        with pytest.raises(ToolError):
            await _drain_until_broken(client)
    finally:
        await client.close()
