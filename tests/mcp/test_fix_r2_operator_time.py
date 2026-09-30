# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 8: the operator's time is kept out of every request deadline, on every protocol version.

A real ``MCPServer`` asks the operator for a name in the middle of ``tools/call``. The operator answers well after the server's
per-request timeout has passed, and the call must still succeed, both on a legacy 2025-11-25 server reached over HTTP+SSE, where the
question arrives as a server-to-client request inside the call, and on a 2026-07-28 server reached over Streamable HTTP. A server that
takes longer than its timeout on its own must still fail, so the deadline is shown to hold for the server's time.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest
from mcp_types import ElicitResult
from mcp_types.version import LATEST_MODERN_VERSION, MODERN_PROTOCOL_VERSIONS

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_http_process import running_server
from tests._helpers.mcp_interactive_server import ASK_TOOL_NAME, NAP_TOOL_NAME
from tests._helpers.mcp_lifecycle_support import call_text


if TYPE_CHECKING:
    from mcp.client.session import ClientRequestContext
    from mcp_types import ElicitRequestParams, ErrorData


_INTERACTIVE_SERVER: Final[Path] = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_interactive_server.py"
_REQUEST_TIMEOUT_S: Final[float] = 2.0
_OPERATOR_PAUSE_S: Final[float] = 6.0
_OUTER_TIMEOUT_S: Final[float] = 120.0
_TEARDOWN_TIMEOUT_S: Final[float] = 30.0
_LEGACY_VERSION: Final[str] = "2025-11-25"


class _SlowOperator:
    """Answers each question with a name, but only after a long pause.

    Attributes:
        asked: How many questions arrived.
    """

    asked: int

    def __init__(self) -> None:
        """Start with no questions asked."""
        self.asked = 0

    async def __call__(self, context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult | ErrorData:
        """Think for longer than the server's request timeout, then answer.

        Args:
            context: The SDK's request context.
            params: The question.

        Returns:
            ElicitResult | ErrorData: The accepted answer.
        """
        del context, params
        self.asked += 1
        await asyncio.sleep(_OPERATOR_PAUSE_S)
        return ElicitResult(action="accept", content={"name": "Ada"})


def _connection(tmp_path: Path, url: str, kind: McpTransportKind, operator: _SlowOperator) -> McpConnection:
    """Build a connection to a remote server with a short request timeout.

    Args:
        tmp_path: Per-test directory holding the test's own ``.env``.
        url: The server endpoint.
        kind: The transport it speaks.
        operator: The elicitation handler.

    Returns:
        McpConnection: The unconnected connection.
    """
    config = McpServerConfig(
        server_id="asker",
        kind=kind,
        http=HttpServerSpec(url=url),
        enabled=True,
        request_timeout_s=_REQUEST_TIMEOUT_S,
    )
    store = CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))
    return McpConnection(config, McpSecretResolver(store), elicitation_callback=operator)


async def _ask(connection: McpConnection) -> tuple[str, str | None]:
    """Connect, call the eliciting tool, and disconnect.

    Args:
        connection: The connection.

    Returns:
        tuple[str, str | None]: The tool's text and the negotiated protocol version.
    """
    await connection.connect()
    try:
        client = connection.client
        version = client.protocol_version if client is not None else None
        return await call_text(connection, ASK_TOOL_NAME), version
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


def test_legacy_server_waits_for_a_slow_answer(tmp_path: Path) -> None:
    """On a 2025-11-25 server over SSE, an answer given after the request timeout still completes the call.

    Args:
        tmp_path: Per-test directory.
    """
    operator = _SlowOperator()
    with running_server(_INTERACTIVE_SERVER, "--transport", "sse") as port:
        connection = _connection(tmp_path, f"http://127.0.0.1:{port}/sse", McpTransportKind.SSE, operator)
        text, version = asyncio.run(asyncio.wait_for(_ask(connection), timeout=_OUTER_TIMEOUT_S))

    assert version == _LEGACY_VERSION
    assert operator.asked == 1
    assert text == "hello Ada"


def test_modern_server_waits_for_a_slow_answer(tmp_path: Path) -> None:
    """On a 2026-07-28 server over Streamable HTTP, an answer given after the request timeout still completes the call.

    Args:
        tmp_path: Per-test directory.
    """
    operator = _SlowOperator()
    with running_server(_INTERACTIVE_SERVER, "--transport", "http") as port:
        connection = _connection(tmp_path, f"http://127.0.0.1:{port}/mcp", McpTransportKind.HTTP, operator)
        text, version = asyncio.run(asyncio.wait_for(_ask(connection), timeout=_OUTER_TIMEOUT_S))

    assert version in MODERN_PROTOCOL_VERSIONS
    assert version == LATEST_MODERN_VERSION
    assert operator.asked == 1
    assert text == "hello Ada"


@pytest.mark.parametrize("kind", [McpTransportKind.SSE, McpTransportKind.HTTP], ids=["legacy-sse", "modern-http"])
def test_a_slow_server_still_times_out(tmp_path: Path, kind: McpTransportKind) -> None:
    """A tool that takes longer than the request timeout on its own fails with the timeout, on either protocol version.

    Args:
        tmp_path: Per-test directory.
        kind: The transport, which selects the protocol version.
    """
    with running_server(_INTERACTIVE_SERVER, "--transport", kind.value, "--with-nap") as port:
        path = "/sse" if kind is McpTransportKind.SSE else "/mcp"
        connection = _connection(tmp_path, f"http://127.0.0.1:{port}{path}", kind, _SlowOperator())

        async def body() -> str:
            await connection.connect()
            try:
                with pytest.raises(McpConnectionError, match="exceeded") as caught:
                    _ = await connection.call_tool(NAP_TOOL_NAME, {"seconds": _OPERATOR_PAUSE_S})
                return str(caught.value)
            finally:
                await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

        message = asyncio.run(asyncio.wait_for(body(), timeout=_OUTER_TIMEOUT_S))

    assert f"{_REQUEST_TIMEOUT_S:.0f}s" in message
