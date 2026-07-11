# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable recovery tests for the x64dbg named-pipe transport (F16 follow-up).

The F16 transport-recovery fix has several coupled halves, each gated here
against the genuine Win32 named-pipe kernel transport (a standalone server
child process hosts a real pipe; no transport call is mocked):

* ``NamedPipeClient.is_connected`` must report ``False`` once the background
  reader records a fatal failure - for example when the server drops the
  connection - even though the OS handle is still open, so callers
  re-establish the pipe instead of reusing a dead transport.
* ``X64DbgBridge._send_pipe_command`` must tear down a dead pipe client and
  reconnect on the next command rather than wedging on the stale client.
* ``NamedPipeClient.connect`` must serialise concurrent callers so two
  coroutines racing to open the same client never both drive
  ``CreateFileW`` against the plugin's single-instance pipe (the loser would
  otherwise collide with ``ERROR_PIPE_BUSY``).
* The background reader loop must wait indefinitely for the *next* frame to
  start rather than bounding that idle gap by the per-read I/O timeout, since
  a connected peer legitimately stays silent for an unbounded time between
  events (for example while a debuggee runs between breakpoints).
* ``X64DbgBridge._connect`` must serialise concurrent reconnect attempts so
  two commands that simultaneously discover a dead pipe do not both try to
  reopen the plugin's single-instance pipe.

Several tests exercise a real server drop: the ``drop_after_one`` server mode
replies to a single command and then closes its endpoint, so the client's
blocking ``ReadFile`` fails with a broken pipe and the production reader loop
records the failure - exactly the idle/interactive drop the fix targets.

Access to non-public members is funnelled through ``getattr`` / ``setattr`` so
the file satisfies ``basedpyright``'s ``reportPrivateUsage`` rule without inline
suppressions.
"""

from __future__ import annotations

import asyncio
import ctypes
import subprocess
import sys
import threading
import time
import uuid
from ctypes import wintypes
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.bridges.named_pipe_client import NamedPipeClient, PipeConfig
from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError
from tests._helpers import realcov_pipe_server as srv


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Real Windows named pipes are required to exercise the transport",
)

_SERVER_MODULE = "tests._helpers.realcov_pipe_server"
_PIPE_READY_TIMEOUT_S = 10.0
_DROP_DEADLINE_S = 6.0
_COMMAND_TIMEOUT_S = 8.0


def _unique_pipe_name() -> str:
    r"""Return a fresh, collision-free local named-pipe path.

    Returns:
        str: A ``\\.\pipe\intellicrack_x64dbg_recovery_<uuid>`` endpoint unique
        to the current test invocation.
    """
    return rf"\\.\pipe\intellicrack_x64dbg_recovery_{uuid.uuid4().hex}"


def _spawn_server(pipe_name: str, mode: str) -> subprocess.Popen[bytes]:
    """Start the standalone real-pipe server process for ``pipe_name``.

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


async def _await_client_reader_failure(client: NamedPipeClient) -> None:
    """Poll until the client reports itself disconnected after a reader failure.

    Args:
        client: Connected client whose server is expected to drop the pipe.
    """
    end = time.monotonic() + _DROP_DEADLINE_S
    while time.monotonic() < end:
        if not client.is_connected:
            return
        await asyncio.sleep(0.02)


async def _drive_client_disconnect_scenario(
    pipe_name: str,
    server: subprocess.Popen[bytes],
) -> None:
    """Round-trip one command, let the server drop, and assert the dead state.

    Args:
        pipe_name: Endpoint hosted by ``server``.
        server: The running drop-after-one server process.
    """
    config = PipeConfig(pipe_name=pipe_name, connect_timeout=8.0, io_timeout=8.0)
    client = NamedPipeClient(config=config)
    await client.connect()
    try:
        assert client.is_connected is True
        response = await asyncio.wait_for(client.send_command("ping"), timeout=_COMMAND_TIMEOUT_S)
        assert response.get("success") is True

        _terminate_server(server)
        await _await_client_reader_failure(client)

        assert client.is_connected is False, "reader failure must mark the client disconnected"

        with pytest.raises(ToolError, match="reader failed"):
            await client.send_command("after-drop")
    finally:
        await client.close()


def test_is_connected_false_after_server_drop() -> None:
    """``is_connected`` flips to ``False`` when the reader observes a server drop.

    Drives the real client over a genuine kernel pipe, terminates the server so
    the production reader loop records a fatal failure, and asserts the client
    reports itself disconnected while its OS handle is still open. Reverting the
    ``is_connected`` guard (back to ``self._handle is not None``) leaves the
    property ``True`` after the drop, so :func:`_await_client_reader_failure`
    never returns early and the ``is_connected is False`` assertion fails.
    """
    pipe_name = _unique_pipe_name()
    server = _spawn_server(pipe_name, srv.MODE_DROP_AFTER_ONE)
    try:
        _require_pipe(pipe_name)
        asyncio.run(_drive_client_disconnect_scenario(pipe_name, server))
    finally:
        _terminate_server(server)


async def _await_bridge_pipe_dead(bridge: X64DbgBridge) -> None:
    """Poll until the bridge's pipe client reports itself disconnected.

    Args:
        bridge: The x64dbg bridge whose pipe client should observe the drop.
    """
    end = time.monotonic() + _DROP_DEADLINE_S
    while time.monotonic() < end:
        client: Any = getattr(bridge, "_pipe_client")
        if client is None or not client.is_connected:
            return
        await asyncio.sleep(0.02)


async def _drive_bridge_reconnect(bridge: X64DbgBridge, pipe_name: str) -> None:
    """Send a command, let the server drop, then send again across a new server.

    Args:
        bridge: The x64dbg bridge under test.
        pipe_name: Endpoint both server generations host in turn.
    """
    send_pipe: Callable[[str], Awaitable[Any]] = getattr(bridge, "_send_pipe_command")

    server1 = _spawn_server(pipe_name, srv.MODE_DROP_AFTER_ONE)
    try:
        _require_pipe(pipe_name)
        raw1 = await asyncio.wait_for(send_pipe("first"), timeout=_COMMAND_TIMEOUT_S)
        assert isinstance(raw1, dict)
        result1 = cast("dict[str, Any]", raw1)
        assert result1.get("echo_command") == "first"
    finally:
        _terminate_server(server1)

    await _await_bridge_pipe_dead(bridge)

    server2 = _spawn_server(pipe_name, srv.MODE_DROP_AFTER_ONE)
    try:
        _require_pipe(pipe_name)
        raw2 = await asyncio.wait_for(send_pipe("second"), timeout=_COMMAND_TIMEOUT_S)
        assert isinstance(raw2, dict), "bridge must reconnect and return a real response"
        result2 = cast("dict[str, Any]", raw2)
        assert result2.get("echo_command") == "second"
    finally:
        _terminate_server(server2)


async def _close_bridge(bridge: X64DbgBridge) -> None:
    """Tear down the bridge's pipe client after the scenario.

    Args:
        bridge: The x64dbg bridge to clean up.
    """
    close_connection: Callable[[], Awaitable[None]] = getattr(bridge, "_close_connection")
    await close_connection()


def test_bridge_reconnects_after_server_drop() -> None:
    """``_send_pipe_command`` reconnects instead of wedging on a dropped pipe.

    The first command connects to a server that replies once and drops. After
    the reader records the failure, a second server is hosted on the same
    endpoint and a second command is issued. The fixed bridge tears down the
    dead client and reconnects, so the second command returns a real result.

    Falsifiability: reverting the ``_send_pipe_command`` teardown (so a
    non-``None`` dead client is reused) makes ``_connect`` a no-op on the stale
    handle, so the second command raises ``ToolError("Pipe reader failed: ...")``
    instead of returning ``{"echo_command": "second"}`` and this test fails.
    Likewise, reverting the ``is_connected`` change hides the drop and the
    second command reuses the dead client, failing the same way.
    """
    pipe_name = _unique_pipe_name()
    bridge = X64DbgBridge()
    setattr(bridge, "_PIPE_NAME", pipe_name)
    setattr(bridge, "_plugin_deployed", True)
    try:
        asyncio.run(_drive_bridge_reconnect(bridge, pipe_name))
    finally:
        asyncio.run(_close_bridge(bridge))


# ---------------------------------------------------------------------------
# Concurrent connect() serialises to a single real CreateFileW (F16)
# ---------------------------------------------------------------------------


async def _drive_concurrent_connect(pipe_name: str, open_calls: list[int]) -> None:
    """Race two ``connect()`` calls on one client against a real single-instance pipe.

    Args:
        pipe_name: Endpoint hosted by the standalone echo server.
        open_calls: Collector list; one entry is appended per real
            ``_open_handle`` invocation observed on the client.
    """
    config = PipeConfig(pipe_name=pipe_name, connect_timeout=8.0, io_timeout=8.0)
    client = NamedPipeClient(config=config)
    original_open_handle: Callable[[], int] = getattr(client, "_open_handle")

    def counting_open_handle() -> int:
        """Record an invocation and delegate to the real ``_open_handle``.

        Returns:
            int: The native handle returned by the real implementation.
        """
        open_calls.append(1)
        return original_open_handle()

    setattr(client, "_open_handle", counting_open_handle)
    try:
        await asyncio.gather(client.connect(), client.connect())
        assert client.is_connected is True

        response = await asyncio.wait_for(client.send_command("ping"), timeout=_COMMAND_TIMEOUT_S)
        assert response.get("ok") is True
    finally:
        await client.close()


def test_concurrent_connect_calls_open_handle_exactly_once() -> None:
    """Two concurrent ``connect()`` calls race to a single real handle-open (F16).

    Drives two overlapping ``connect()`` coroutines on the same
    ``NamedPipeClient`` against a genuine single-instance Win32 named pipe
    (``nMaxInstances=1``, hosted by the standalone echo server, exactly
    mirroring the x64dbg plugin's pipe). Without ``_connect_lock`` serialising
    the two callers, both would race real ``CreateFileW`` calls against the
    single-instance pipe; the kernel lets only one succeed and the other
    fails with ``ERROR_PIPE_BUSY`` (231), which ``connect()`` re-raises as a
    ``ToolError`` and ``asyncio.gather`` propagates - failing this test.

    Falsifiability: removing the ``async with self._connect_lock:`` guard
    from ``NamedPipeClient.connect`` (in
    ``src/intellicrack/bridges/named_pipe_client.py``) makes both concurrent
    calls invoke the real Win32 open path against the single-instance server
    pipe; one loses the kernel race with ``ERROR_PIPE_BUSY`` and
    ``asyncio.gather`` raises, failing this test before the
    ``open_calls`` assertion is even reached.
    """
    pipe_name = _unique_pipe_name()
    server = _spawn_server(pipe_name, srv.MODE_ECHO)
    open_calls: list[int] = []
    try:
        _require_pipe(pipe_name)
        asyncio.run(_drive_concurrent_connect(pipe_name, open_calls))
    finally:
        _terminate_server(server)

    assert len(open_calls) == 1, f"expected exactly one real _open_handle call, saw {len(open_calls)}"


# ---------------------------------------------------------------------------
# Reader loop survives an idle gap longer than io_timeout (F16)
# ---------------------------------------------------------------------------

_IDLE_IO_TIMEOUT_S = 0.5
_IDLE_GAP_DEADLINE_S = srv.IDLE_DELAY_SECONDS + 6.0


async def _drive_idle_gap_scenario(pipe_name: str) -> None:
    """Send one command, then wait out a server-side idle gap longer than io_timeout.

    Args:
        pipe_name: Endpoint hosted by the delayed-event server.

    Raises:
        AssertionError: If the delayed event never arrives within the
            polling deadline.
    """
    event_seen = threading.Event()
    received: list[dict[str, Any]] = []

    def on_event(message: dict[str, Any]) -> None:
        """Record the delayed event and signal the waiting test coroutine.

        Args:
            message: Decoded event payload delivered by the reader loop.
        """
        received.append(message)
        event_seen.set()

    config = PipeConfig(pipe_name=pipe_name, connect_timeout=8.0, io_timeout=_IDLE_IO_TIMEOUT_S)
    client = NamedPipeClient(config=config, event_handler=on_event)
    await client.connect()
    try:
        first = await asyncio.wait_for(client.send_command("ping"), timeout=_COMMAND_TIMEOUT_S)
        assert first.get("echo_command") == "ping"

        # The server stays silent for srv.IDLE_DELAY_SECONDS (4x io_timeout)
        # before pushing an unsolicited event. Poll through that gap and
        # assert the client never reports itself disconnected.
        deadline = time.monotonic() + _IDLE_GAP_DEADLINE_S
        while not event_seen.is_set():
            assert client.is_connected is True, "idle gap must not be treated as a fatal read timeout"
            if time.monotonic() > deadline:
                msg = "delayed event never arrived"
                raise AssertionError(msg)
            await asyncio.sleep(0.02)

        assert received
        assert received[0].get("name") == srv.EVENT_NAME
        assert client.is_connected is True

        second = await asyncio.wait_for(client.send_command("ping-again"), timeout=_COMMAND_TIMEOUT_S)
        assert second.get("echo_command") == "ping-again"
    finally:
        await client.close()


def test_reader_loop_survives_idle_gap_past_io_timeout() -> None:
    """Idle gaps longer than ``io_timeout`` do not kill the reader loop (F16).

    Configures a short ``io_timeout`` (0.5s) and drives a real server that
    replies once and then stays silent for four times that long before
    pushing an unsolicited event - reproducing the legitimate idle gap
    between debugger events (for example while a debuggee runs between
    breakpoints). The client must stay connected throughout the gap, receive
    the delayed event, and still service a subsequent command.

    Falsifiability: reverting ``_reader_loop`` (in
    ``src/intellicrack/bridges/named_pipe_client.py``) to call
    ``self._read_message(frame_timeout=self._config.io_timeout)`` instead of
    ``frame_timeout=None`` makes the length-prefix read for the next frame
    time out after 0.5s, well before the server's ~2s delayed event arrives;
    the reader loop then records a fatal failure, ``client.is_connected``
    flips to ``False`` during the poll loop, and the
    ``assert client.is_connected is True`` inside the loop fails this test.
    """
    pipe_name = _unique_pipe_name()
    server = _spawn_server(pipe_name, srv.MODE_DELAYED_EVENT)
    try:
        _require_pipe(pipe_name)
        asyncio.run(_drive_idle_gap_scenario(pipe_name))
    finally:
        _terminate_server(server)


# ---------------------------------------------------------------------------
# Bridge-level concurrent reconnect after a drop is serialised (F16)
# ---------------------------------------------------------------------------


async def _drive_concurrent_bridge_reconnect(bridge: X64DbgBridge, pipe_name: str) -> None:
    """Drop the pipe, then race two concurrent commands into the reconnect path.

    Args:
        bridge: The x64dbg bridge under test.
        pipe_name: Endpoint both server generations host in turn.
    """
    send_pipe: Callable[[str], Awaitable[Any]] = getattr(bridge, "_send_pipe_command")

    server1 = _spawn_server(pipe_name, srv.MODE_DROP_AFTER_ONE)
    try:
        _require_pipe(pipe_name)
        raw1 = await asyncio.wait_for(send_pipe("first"), timeout=_COMMAND_TIMEOUT_S)
        assert isinstance(raw1, dict)
        assert cast("dict[str, Any]", raw1).get("echo_command") == "first"
    finally:
        _terminate_server(server1)

    await _await_bridge_pipe_dead(bridge)

    server2 = _spawn_server(pipe_name, srv.MODE_ECHO_SUCCESS)
    try:
        _require_pipe(pipe_name)
        raw2, raw3 = await asyncio.gather(
            asyncio.wait_for(send_pipe("second"), timeout=_COMMAND_TIMEOUT_S),
            asyncio.wait_for(send_pipe("third"), timeout=_COMMAND_TIMEOUT_S),
        )
        result2 = cast("dict[str, Any]", raw2)
        result3 = cast("dict[str, Any]", raw3)
        assert {result2.get("echo_command"), result3.get("echo_command")} == {"second", "third"}
    finally:
        _terminate_server(server2)


def test_bridge_concurrent_reconnect_after_drop_serialises_to_one_connect() -> None:
    """Two commands racing a dead pipe both survive the reconnect (F16).

    After the first server drops the connection, two ``_send_pipe_command``
    calls are launched concurrently against a fresh single-instance server on
    the same endpoint. Both discover the dead client at essentially the same
    asyncio tick. Without ``_pipe_connect_lock`` serialising ``_connect``,
    both coroutines can race real ``CreateFileW`` calls against the plugin's
    single-instance pipe (or one can discard the other's freshly-connected
    client), which either fails one command outright with ``ERROR_PIPE_BUSY``
    (231) or leaves an orphaned live connection that starves the pipe for
    the other, surfacing as ``ERROR_SEM_TIMEOUT`` (121) on the next connect.

    Falsifiability: reverting ``X64DbgBridge._connect`` (in
    ``src/intellicrack/bridges/x64dbg.py``) to the unlocked
    create-if-``None``-then-connect form makes the two concurrent commands
    race the reconnect without serialisation; one of ``asyncio.gather``'s two
    awaited commands then raises ``ToolError`` (pipe busy or the reconnect
    timing out), failing this test before the ``echo_command`` assertion.
    """
    pipe_name = _unique_pipe_name()
    bridge = X64DbgBridge()
    setattr(bridge, "_PIPE_NAME", pipe_name)
    setattr(bridge, "_plugin_deployed", True)
    try:
        asyncio.run(_drive_concurrent_bridge_reconnect(bridge, pipe_name))
    finally:
        asyncio.run(_close_bridge(bridge))
