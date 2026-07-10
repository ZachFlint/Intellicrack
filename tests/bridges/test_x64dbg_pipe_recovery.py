# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Falsifiable recovery tests for the x64dbg named-pipe transport (F16 follow-up).

The F16 transport-recovery fix has two coupled halves, each gated here against
the genuine Win32 named-pipe kernel transport (a standalone server child
process hosts a real pipe; no transport call is mocked):

* ``NamedPipeClient.is_connected`` must report ``False`` once the background
  reader records a fatal failure - for example when the server drops the
  connection - even though the OS handle is still open, so callers
  re-establish the pipe instead of reusing a dead transport.
* ``X64DbgBridge._send_pipe_command`` must tear down a dead pipe client and
  reconnect on the next command rather than wedging on the stale client.

Both tests exercise a real server drop: the ``drop_after_one`` server mode
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
