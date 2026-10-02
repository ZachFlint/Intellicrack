# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 36: Intellicrack declares exactly the client capabilities it implements, per protocol version, and reports both sides.

The gates connect Intellicrack's real connection to a real ``MCPServer`` whose tool reports the capabilities it received, on 2026-07-28
over stdio (capabilities ride every request's ``_meta``) and 2025-11-25 over SSE (sent once with ``initialize``). A capability is
declared only when the feature behind it is installed; ``roots`` carries ``listChanged`` only on 2025-11-25, where Intellicrack sends
that notification; and the connection's status names the negotiated version, what the server offers and what Intellicrack declared,
matching what actually went over the wire.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Final

import pytest
from mcp_types import ElicitResult, ListRootsResult, ServerCapabilities, TextContent

from intellicrack.mcp.client_hooks import McpClientHooks
from intellicrack.mcp.client_session import describe_capabilities
from tests._helpers.mcp_features_server import CAPABILITIES_TOOL
from tests._helpers.mcp_features_support import Era, features_connection


if TYPE_CHECKING:
    from pathlib import Path

    from mcp.client.session import ClientRequestContext
    from mcp_types import ElicitRequestParams

    from intellicrack.mcp.connection import McpConnection, McpServerStatus


_ERAS: Final[list[Era]] = [Era.MODERN, Era.LEGACY]
_TIMEOUT_S: Final[float] = 90.0


async def _no_roots(context: ClientRequestContext) -> ListRootsResult:
    """Answer ``roots/list`` with no roots.

    Args:
        context: The SDK's request context, unused.

    Returns:
        ListRootsResult: No roots.
    """
    del context
    await asyncio.sleep(0)
    return ListRootsResult(roots=[])


async def _decline(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
    """Decline every elicitation.

    Args:
        context: The SDK's request context, unused.
        params: The request, unused.

    Returns:
        ElicitResult: A decline.
    """
    del context, params
    await asyncio.sleep(0)
    return ElicitResult(action="decline")


async def _received(connection: McpConnection) -> object:
    """Ask the server which capabilities it received.

    Args:
        connection: The connection.

    Returns:
        object: The capabilities as they arrived, decoded from JSON.
    """
    result = await connection.call_tool(CAPABILITIES_TOOL, {})
    assert not result.is_error
    [block] = result.content
    assert isinstance(block, TextContent)
    return json.loads(block.text)


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_declared_capabilities_match_the_features_and_the_version(tmp_path: Path, era: Era) -> None:
    """Roots and elicitation are declared because they are installed, ``listChanged`` only on 2025-11-25, and nothing else.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> tuple[object, McpServerStatus]:
        """Connect with roots and elicitation installed.

        Returns:
            tuple[object, McpServerStatus]: What the server received, and the connection's status.
        """
        hooks = McpClientHooks(list_roots=_no_roots)
        async with features_connection(tmp_path, era, hooks=hooks, elicitation=_decline) as connection:
            return await _received(connection), connection.status

    received, status = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    roots: dict[str, object] = {"listChanged": True} if era is Era.LEGACY else {}
    assert received == {"elicitation": {"form": {}, "url": {}}, "roots": roots}
    assert status.protocol_version == era.value
    assert status.client_capabilities == ("elicitation (form, url)", "roots (listChanged)" if era is Era.LEGACY else "roots")


@pytest.mark.parametrize("era", _ERAS, ids=[era.name.lower() for era in _ERAS])
def test_nothing_is_declared_without_the_features(tmp_path: Path, era: Era) -> None:
    """A connection with no client-side features declares no capability at all.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
    """

    async def run() -> tuple[object, McpServerStatus]:
        """Connect with nothing installed.

        Returns:
            tuple[object, McpServerStatus]: What the server received, and the connection's status.
        """
        async with features_connection(tmp_path, era, hooks=McpClientHooks()) as connection:
            return await _received(connection), connection.status

    received, status = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert received == {}
    assert status.client_capabilities == ()


@pytest.mark.parametrize(
    ("era", "offered"),
    [
        (Era.MODERN, ("logging", "prompts (listChanged)", "resources (subscribe, listChanged)", "tools (listChanged)", "completions")),
        (Era.LEGACY, ("logging", "prompts", "resources (subscribe)", "tools", "completions")),
    ],
    ids=["modern", "legacy"],
)
def test_status_reports_what_the_server_offers(tmp_path: Path, era: Era, offered: tuple[str, ...]) -> None:
    """The status lists the server's own declaration for the negotiated version, and nothing once disconnected.

    Args:
        tmp_path: Per-test directory.
        era: The protocol generation.
        offered: What the fixture server declares on that generation.
    """

    async def run() -> tuple[McpServerStatus, McpServerStatus]:
        """Connect, then disconnect.

        Returns:
            tuple[McpServerStatus, McpServerStatus]: The status while connected and after.
        """
        async with features_connection(tmp_path, era, hooks=McpClientHooks()) as connection:
            live = connection.status
        return live, connection.status

    live, after = asyncio.run(asyncio.wait_for(run(), _TIMEOUT_S))
    assert live.server_capabilities == offered
    assert (after.protocol_version, after.server_capabilities, after.client_capabilities) == (None, (), ())


def test_capability_lines_leave_out_false_flags_and_name_extensions() -> None:
    """A flag declared false is not listed, and experimental or extension entries are named, cleaned of hidden characters."""
    declared = ServerCapabilities.model_validate({
        "tools": {"listChanged": False},
        "resources": {"subscribe": True, "listChanged": False},
        "experimental": {f"probe{chr(0x200B)}": {}},
    })
    assert describe_capabilities(declared) == ("experimental: probe", "resources (subscribe)", "tools")
