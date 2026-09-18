# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the Streamable HTTP transport against a real remote server.

The fixture server is launched as a separate process listening on loopback and
spoken to over real HTTP. The credential gates drive a server that genuinely
answers ``401`` without its header, so the client's header plumbing is proved
against a real rejection rather than a simulated one.
"""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_server_main import DOTTED_TOOL_NAME, DOUBLE_UNDERSCORE_TOOL_NAME


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator


_SERVER_SCRIPT = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_server_main.py"
_GUARD_HEADER_NAME = "X-Fixture-Guard"
_GUARD_HEADER_VALUE = "fixture-guard-value"
_BOOT_TIMEOUT_S = 60.0
_CONNECT_TIMEOUT_S = 60.0
_TEARDOWN_GRACE_S = 15.0


def _free_port() -> int:
    """Reserve a loopback port the fixture server can bind.

    Returns:
        int: A port number that was free at the moment of asking.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _await_port(port: int, *, process: subprocess.Popen[bytes]) -> None:
    """Wait for the fixture server to accept connections.

    Args:
        port: Loopback port the server binds.
        process: The server process, watched so a crash fails fast.

    Raises:
        RuntimeError: If the server exits or never accepts in time.
    """
    deadline = time.monotonic() + _BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            message = f"the fixture HTTP server exited with {process.returncode} before accepting"
            raise RuntimeError(message)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    message = f"the fixture HTTP server never accepted on port {port}"
    raise RuntimeError(message)


@pytest.fixture
def guarded_server() -> Iterator[int]:
    """Run a real HTTP MCP server that requires an API-key header.

    Yields:
        int: The loopback port the server is listening on.
    """
    port = _free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            str(_SERVER_SCRIPT),
            "--mode",
            "well_behaved",
            "--transport",
            "http",
            "--port",
            str(port),
            "--require-header",
            f"{_GUARD_HEADER_NAME}: {_GUARD_HEADER_VALUE}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _await_port(port, process=process)
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _config(port: int, *, headers: dict[str, str], query: dict[str, str] | None = None) -> McpServerConfig:
    """Build an HTTP server configuration pointed at the fixture server.

    Args:
        port: Loopback port the server listens on.
        headers: Headers every request should carry.
        query: Query parameters appended to the endpoint URL.

    Returns:
        McpServerConfig: An enabled HTTP configuration.
    """
    spec = HttpServerSpec(url=f"http://127.0.0.1:{port}/mcp", headers=headers, query=query or {})
    return McpServerConfig(server_id="remote", kind=McpTransportKind.HTTP, http=spec, enabled=True, request_timeout_s=30.0)


def _connection(config: McpServerConfig) -> McpConnection:
    """Build a connection for an HTTP configuration.

    Args:
        config: The server to connect to.

    Returns:
        McpConnection: An unconnected connection.
    """
    return McpConnection(config, McpSecretResolver(CredentialStore()))


async def _with_connection[T](connection: McpConnection, body: Callable[[], Awaitable[T]]) -> T:
    """Connect, run a body, and always disconnect.

    Args:
        connection: The connection to drive.
        body: Awaitable-returning callable run while connected.

    Returns:
        T: Whatever ``body`` produced.
    """
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        return await body()
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_GRACE_S)


class TestStreamableHttpTransport:
    """A remote server is reachable over real Streamable HTTP."""

    def test_lists_tools_with_the_required_header(self, guarded_server: int) -> None:
        """A correctly credentialed connection sees the server's real catalog.

        Args:
            guarded_server: Port of the running fixture server.
        """
        connection = _connection(_config(guarded_server, headers={_GUARD_HEADER_NAME: _GUARD_HEADER_VALUE}))

        async def body() -> list[str]:
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            return [entry.name for entry in catalog.entries]

        names = asyncio.run(_with_connection(connection, body))
        assert "echo" in names
        assert DOUBLE_UNDERSCORE_TOOL_NAME in names
        assert DOTTED_TOOL_NAME in names

    def test_calls_a_tool_over_http(self, guarded_server: int) -> None:
        """A tool call round-trips over the HTTP transport.

        Args:
            guarded_server: Port of the running fixture server.
        """
        connection = _connection(_config(guarded_server, headers={_GUARD_HEADER_NAME: _GUARD_HEADER_VALUE}))

        async def body() -> list[str]:
            result = await connection.call_tool("echo", {"message": "over http"})
            return [getattr(block, "text", "") for block in result.content]

        texts = asyncio.run(_with_connection(connection, body))
        assert "over http" in texts

    def test_missing_credential_is_refused(self, guarded_server: int) -> None:
        """Connecting without the required header fails rather than succeeding.

        Args:
            guarded_server: Port of the running fixture server.
        """
        connection = _connection(_config(guarded_server, headers={}))

        with pytest.raises(McpConnectionError):
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S))

    def test_wrong_credential_is_refused(self, guarded_server: int) -> None:
        """A header with the wrong value is refused like a missing one.

        Args:
            guarded_server: Port of the running fixture server.
        """
        connection = _connection(_config(guarded_server, headers={_GUARD_HEADER_NAME: "wrong"}))

        with pytest.raises(McpConnectionError):
            asyncio.run(asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S))

    def test_api_key_carried_as_a_url_parameter(self, guarded_server: int) -> None:
        """Query parameters reach the endpoint alongside the headers.

        Some remote servers take their key in the URL and select optional tool
        sets the same way, so the query has to survive URL composition.

        Args:
            guarded_server: Port of the running fixture server.
        """
        connection = _connection(
            _config(guarded_server, headers={_GUARD_HEADER_NAME: _GUARD_HEADER_VALUE}, query={"toolset": "core", "key": "abc"}),
        )

        async def body() -> int:
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            return catalog.tool_count

        assert asyncio.run(_with_connection(connection, body)) > 0
