# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates proving a server declared ``sse`` is spoken to over legacy HTTP+SSE.

The server is the SDK's own :class:`~mcp.server.mcpserver.MCPServer` served by
its ``sse_app`` on loopback, a real HTTP+SSE endpoint. Legacy SSE is a
different wire protocol from Streamable HTTP: the client opens a ``GET`` event
stream and posts messages to the endpoint that stream announces.
"""

from __future__ import annotations

import asyncio

from mcp import Client

from intellicrack.mcp.config import HttpServerSpec, McpTransportKind
from intellicrack.mcp.transport import open_http_transport
from tests._helpers.mcp_lifecycle_support import call_text, connection_for, network_config, network_server


_CONNECT_TIMEOUT_S = 90.0
_TEARDOWN_TIMEOUT_S = 30.0


class TestLegacySseServer:
    """A legacy SSE server connects, lists and calls through the connection."""

    def test_connection_lists_and_calls_over_sse(self) -> None:
        """The connection reaches an SSE server and negotiates a legacy version."""
        with network_server("sse") as (process, port):
            connection = connection_for(network_config("sse-srv", port, McpTransportKind.SSE))

            async def body() -> tuple[list[str], str, str | None]:
                await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
                try:
                    catalog = connection.catalog
                    names = [entry.name for entry in catalog.entries] if catalog is not None else []
                    client = connection.client
                    version = client.protocol_version if client is not None else None
                    return names, await call_text(connection, "whoami"), version
                finally:
                    await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

            names, pid, version = asyncio.run(body())
            assert pid == str(process.pid)
        assert {"whoami", "quit", "grow"} <= set(names)
        assert version == "2025-11-25"

    def test_transport_opens_the_sse_stream(self) -> None:
        """``open_http_transport`` with the SSE kind yields a working legacy pair."""
        with network_server("sse") as (_process, port):

            async def body() -> list[str]:
                spec = HttpServerSpec(url=f"http://127.0.0.1:{port}/sse")
                transport = open_http_transport(spec, headers={}, auth=None, timeout_s=30.0, kind=McpTransportKind.SSE)
                async with Client(transport, mode="legacy") as client:
                    listing = await client.list_tools()
                    return [tool.name for tool in listing.tools]

            names = asyncio.run(asyncio.wait_for(body(), timeout=_CONNECT_TIMEOUT_S))
        assert "whoami" in names
