# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for protocol-era negotiation, per-call timeouts, and listing limits.

Every gate drives a real server subprocess. The era gates pin the client to one
protocol generation at a time so both the modern and the handshake-era paths
are genuinely exercised rather than whichever one ``auto`` happens to pick.
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.catalog import MAX_TOOLS_PER_SERVER, fetch_catalog
from intellicrack.mcp.config import McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_server_main import DOTTED_TOOL_NAME, PAGINATING_TOOL_COUNT, SLOW_TOOL_SECONDS


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


_SERVER_SCRIPT = Path(__file__).resolve().parents[1] / "_helpers" / "mcp_server_main.py"
_CONNECT_TIMEOUT_S = 60.0
_TEARDOWN_GRACE_S = 15.0
_CALL_TIMEOUT_S = 3.0


def _parameters(mode: str) -> StdioServerParameters:
    """Build stdio launch parameters for the fixture server.

    Args:
        mode: Personality the fixture server should present.

    Returns:
        StdioServerParameters: Parameters the SDK spawns without a shell.
    """
    return StdioServerParameters(command=sys.executable, args=[str(_SERVER_SCRIPT), "--mode", mode])


def _config(mode: str, *, timeout_s: float) -> McpServerConfig:
    """Build a stdio server configuration for the fixture server.

    Args:
        mode: Personality the fixture server should present.
        timeout_s: Per-call timeout.

    Returns:
        McpServerConfig: An enabled stdio configuration.
    """
    spec = StdioServerSpec(command=sys.executable, args=(str(_SERVER_SCRIPT), "--mode", mode))
    return McpServerConfig(server_id="srv", kind=McpTransportKind.STDIO, stdio=spec, enabled=True, request_timeout_s=timeout_s)


def _gate(tmp_path: Path) -> McpConsentGate:
    """Build a consent gate that approves every launch.

    Args:
        tmp_path: Directory backing the trust store.

    Returns:
        McpConsentGate: An approving gate.
    """

    def prompt(_config: McpServerConfig, _rendered: str, _findings: object) -> bool:
        """Approve the launch.

        Args:
            _config: The server being launched.
            _rendered: The rendered launch description.
            _findings: Dangerous patterns found in the command.

        Returns:
            bool: Always ``True``.
        """
        return True

    return McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt)


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


class TestProtocolEraNegotiation:
    """The same server is reachable across both protocol generations."""

    def test_the_sdk_reports_both_eras(self) -> None:
        """The installed SDK really does span the two generations under test.

        Without this the era gates below could pass by testing one era twice.
        """
        assert MODERN_PROTOCOL_VERSIONS == ("2026-07-28",)
        assert "2025-11-25" in HANDSHAKE_PROTOCOL_VERSIONS

    @pytest.mark.parametrize("mode", ["2026-07-28", "legacy", "auto"])
    def test_tools_list_across_eras(self, mode: str) -> None:
        """A real server answers ``tools/list`` on each protocol generation.

        ``legacy`` drives the pre-2026 handshake path, ``2026-07-28`` the
        stateless one, and ``auto`` whichever the pair negotiates.

        Args:
            mode: Protocol generation to pin the client to.
        """

        async def body() -> list[str]:
            async with Client(stdio_client(_parameters("well_behaved")), mode=mode) as client:
                result = await client.list_tools()
                return [tool.name for tool in result.tools]

        names = asyncio.run(asyncio.wait_for(body(), timeout=_CONNECT_TIMEOUT_S))
        assert "echo" in names
        assert DOTTED_TOOL_NAME in names

    @pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
    def test_tool_call_across_eras(self, mode: str) -> None:
        """A tool call round-trips on each protocol generation.

        Args:
            mode: Protocol generation to pin the client to.
        """

        async def body() -> list[str]:
            async with Client(stdio_client(_parameters("well_behaved")), mode=mode) as client:
                result = await client.call_tool("echo", {"message": f"era {mode}"})
                return [getattr(block, "text", "") for block in result.content]

        texts = asyncio.run(asyncio.wait_for(body(), timeout=_CONNECT_TIMEOUT_S))
        assert f"era {mode}" in texts


class TestPerCallTimeout:
    """A server that never answers does not hang the client."""

    def test_a_stalling_tool_times_out(self, tmp_path: Path) -> None:
        """A call to a blocking tool gives up well before the tool would finish.

        The fixture's tool sleeps far longer than the timeout, so a client that
        waited for it would blow the test's own deadline rather than pass.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = McpConnection(
            _config("slow", timeout_s=_CALL_TIMEOUT_S),
            McpSecretResolver(CredentialStore()),
            consent=_gate(tmp_path),
        )
        started = time.monotonic()

        async def body() -> None:
            with pytest.raises(McpConnectionError) as caught:
                await connection.call_tool("stall", {})
            assert "exceeded" in str(caught.value), f"the call failed for some other reason: {caught.value}"

        asyncio.run(_with_connection(connection, body))
        elapsed = time.monotonic() - started
        assert elapsed < SLOW_TOOL_SECONDS, f"the call waited {elapsed:.1f}s for a {SLOW_TOOL_SECONDS}s tool"

    def test_teardown_is_clean_after_a_timeout(self, tmp_path: Path) -> None:
        """A timed-out call still leaves the connection able to shut down.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = McpConnection(
            _config("slow", timeout_s=_CALL_TIMEOUT_S),
            McpSecretResolver(CredentialStore()),
            consent=_gate(tmp_path),
        )

        async def body() -> None:
            with pytest.raises(McpConnectionError):
                await connection.call_tool("stall", {})

        asyncio.run(_with_connection(connection, body))
        assert connection.client is None


class TestListingLimits:
    """A large or hostile tool listing is retrieved fully and bounded."""

    def test_a_large_listing_is_retrieved_whole(self, tmp_path: Path) -> None:
        """Every page of a multi-page listing is followed.

        A client that stopped at the first page would report far fewer tools
        than the server publishes.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = McpConnection(
            _config("paginating", timeout_s=60.0),
            McpSecretResolver(CredentialStore()),
            consent=_gate(tmp_path),
        )

        async def body() -> int:
            await asyncio.sleep(0)
            catalog = connection.catalog
            assert catalog is not None
            return catalog.tool_count

        count = asyncio.run(_with_connection(connection, body))
        assert count == PAGINATING_TOOL_COUNT, f"expected {PAGINATING_TOOL_COUNT} tools, got {count}"
        assert count <= MAX_TOOLS_PER_SERVER

    def test_catalog_generation_is_stable_across_fetches(self, tmp_path: Path) -> None:
        """Re-listing an unchanged server yields the same generation.

        Approvals are keyed by this digest, so a generation that changed on
        every fetch would invalidate the operator's answers constantly.

        Args:
            tmp_path: Pytest-provided temporary directory.
        """
        connection = McpConnection(
            _config("well_behaved", timeout_s=30.0),
            McpSecretResolver(CredentialStore()),
            consent=_gate(tmp_path),
        )

        async def body() -> tuple[str, str]:
            first = connection.catalog
            assert first is not None
            client = connection.client
            assert client is not None
            second = await fetch_catalog(client, connection.server_id)
            return first.generation, second.generation

        first_generation, second_generation = asyncio.run(_with_connection(connection, body))
        assert first_generation == second_generation
