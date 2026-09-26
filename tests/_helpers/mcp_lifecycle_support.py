# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared plumbing for the gates that drive ``mcp_lifecycle_server.py``.

Everything here starts or configures a real server: a stdio child launched by
the connection under test, or a loopback HTTP or SSE server run as a separate
process. Nothing is simulated.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import HttpServerSpec, McpSandboxSpec, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Sequence


SERVER_SCRIPT = Path(__file__).resolve().parent / "mcp_lifecycle_server.py"
"""The steerable server every lifecycle gate talks to."""

BOOT_TIMEOUT_S = 60.0
"""Longest wait for a loopback server process to accept connections."""

REQUEST_TIMEOUT_S = 30.0
"""Per-call timeout configured on every lifecycle server."""


def free_port() -> int:
    """Reserve a loopback port a fixture server can bind.

    Returns:
        int: A port that was free at the moment of asking.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _await_port(port: int, process: subprocess.Popen[bytes]) -> None:
    """Wait for a fixture server to accept connections.

    Args:
        port: The port it binds.
        process: The server process.

    Raises:
        RuntimeError: If the server exits or never accepts in time.
    """
    deadline = time.monotonic() + BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        if process.poll() is not None:
            message = f"the lifecycle server exited with {process.returncode} before accepting"
            raise RuntimeError(message)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    message = f"the lifecycle server never accepted on port {port}"
    raise RuntimeError(message)


def start_network_server(transport: str, *, ttl_ms: int = 0) -> tuple[subprocess.Popen[bytes], int]:
    """Start the lifecycle server over HTTP or SSE and wait for it to accept.

    Args:
        transport: ``http`` or ``sse``.
        ttl_ms: Freshness hint for the tool listing, ``0`` for none.

    Returns:
        tuple[subprocess.Popen[bytes], int]: The process and its port.

    Raises:
        RuntimeError: If the server exits or never accepts in time; the
            process is stopped first.
    """
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT), "--transport", transport, "--port", str(port), "--ttl-ms", str(ttl_ms)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _await_port(port, process)
    except RuntimeError:
        stop_process(process)
        raise
    return process, port


def stop_process(process: subprocess.Popen[bytes]) -> None:
    """Stop a fixture server process.

    Args:
        process: The process.
    """
    if process.poll() is None:
        process.terminate()
    try:
        _ = process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        _ = process.wait(timeout=10)


@contextlib.contextmanager
def network_server(transport: str, *, ttl_ms: int = 0) -> Generator[tuple[subprocess.Popen[bytes], int]]:
    """Run the lifecycle server over HTTP or SSE for the duration of a block.

    Args:
        transport: ``http`` or ``sse``.
        ttl_ms: Freshness hint for the tool listing, ``0`` for none.

    Yields:
        tuple[subprocess.Popen[bytes], int]: The process and its port.
    """
    process, port = start_network_server(transport, ttl_ms=ttl_ms)
    try:
        yield process, port
    finally:
        stop_process(process)


def approving_gate(trust_path: Path, *, delay_s: float = 0.0) -> McpConsentGate:
    """Build a consent gate that approves every launch, optionally after a pause.

    Args:
        trust_path: File backing the trust store.
        delay_s: How long the prompt stays open before approving, standing in
            for an operator reading the dialog.

    Returns:
        McpConsentGate: The gate.
    """

    async def prompt(_config: McpServerConfig, _rendered: str, _findings: object) -> bool:
        """Approve after the configured pause.

        Args:
            _config: The server being launched.
            _rendered: The rendered launch description.
            _findings: Dangerous patterns found in the command.

        Returns:
            bool: Always ``True``.
        """
        await asyncio.sleep(delay_s)
        return True

    return McpConsentGate(TrustStore(trust_path), prompt)


def stdio_config(
    server_id: str,
    *,
    extra_args: Sequence[str] = (),
    command: str | None = None,
    args: Sequence[str] | None = None,
    sandbox: McpSandboxSpec | None = None,
) -> McpServerConfig:
    """Build a stdio configuration for the lifecycle server.

    Args:
        server_id: The server id.
        extra_args: Arguments appended after the script path.
        command: Launch command overriding the running interpreter.
        args: Arguments overriding the script path and ``extra_args``.
        sandbox: Confinement to apply, or ``None`` for none.

    Returns:
        McpServerConfig: An enabled stdio configuration.
    """
    spec = StdioServerSpec(
        command=command if command is not None else sys.executable,
        args=tuple(args) if args is not None else (str(SERVER_SCRIPT), *extra_args),
    )
    return McpServerConfig(
        server_id=server_id,
        kind=McpTransportKind.STDIO,
        stdio=spec,
        enabled=True,
        sandbox=sandbox if sandbox is not None else McpSandboxSpec(),
        request_timeout_s=REQUEST_TIMEOUT_S,
    )


def network_config(server_id: str, port: int, transport: McpTransportKind) -> McpServerConfig:
    """Build an HTTP or SSE configuration for the lifecycle server.

    Args:
        server_id: The server id.
        port: The loopback port the server listens on.
        transport: :attr:`McpTransportKind.HTTP` or :attr:`McpTransportKind.SSE`.

    Returns:
        McpServerConfig: An enabled remote configuration.
    """
    path = "/sse" if transport is McpTransportKind.SSE else "/mcp"
    return McpServerConfig(
        server_id=server_id,
        kind=transport,
        http=HttpServerSpec(url=f"http://127.0.0.1:{port}{path}"),
        enabled=True,
        request_timeout_s=REQUEST_TIMEOUT_S,
    )


def connection_for(config: McpServerConfig, gate: McpConsentGate | None = None) -> McpConnection:
    """Build an unconnected connection for a configuration.

    Args:
        config: The server to connect to.
        gate: Consent gate for a local server, or ``None``.

    Returns:
        McpConnection: The connection.
    """
    return McpConnection(config, McpSecretResolver(CredentialStore()), consent=gate)


async def _holds(predicate: Callable[[], bool | Awaitable[bool]]) -> bool:
    """Evaluate a condition that may be synchronous or asynchronous.

    Args:
        predicate: The condition.

    Returns:
        bool: Its value.
    """
    outcome = predicate()
    if inspect.isawaitable(outcome):
        return await outcome
    return outcome


async def wait_until(predicate: Callable[[], bool | Awaitable[bool]], *, timeout_s: float, interval_s: float = 0.1) -> bool:
    """Poll a condition until it holds or time runs out.

    Args:
        predicate: The condition, synchronous or asynchronous.
        timeout_s: Longest time to wait.
        interval_s: Delay between polls.

    Returns:
        bool: Whether the condition held before the deadline.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_s
    while loop.time() < deadline:
        if await _holds(predicate):
            return True
        await asyncio.sleep(interval_s)
    return await _holds(predicate)


async def call_text(connection: McpConnection, tool: str, arguments: dict[str, object] | None = None) -> str:
    """Call a tool and return the text of its first content part.

    Args:
        connection: A ready connection.
        tool: The tool to call.
        arguments: Its arguments.

    Returns:
        str: The first part's text, or an empty string when it has none.
    """
    result = await connection.call_tool(tool, dict(arguments or {}))
    for part in result.content:
        text = getattr(part, "text", None)
        if isinstance(text, str):
            return text
    return ""
