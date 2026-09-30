# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real MCP server that uses the client-side features: logging, sampling, roots and progress.

Built on the SDK's own :class:`~mcp.server.mcpserver.MCPServer`, run as a subprocess by the gates and spoken to over a real stdio pipe
(which negotiates 2026-07-28) or loopback legacy SSE (2025-11-25), or Streamable HTTP. Each tool exercises one client feature, so a gate
can drive that feature on both protocol generations through Intellicrack's real connection.

Run it as ``python mcp_features_server.py [--transport stdio|http|sse] [--port N]``.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING, Annotated, Any, Final

import anyio.lowlevel
import uvicorn
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.resolve import ListRoots, Resolve
from mcp_types import (
    LOG_LEVEL_META_KEY,
    EmptyResult,
    ListRootsResult,
    LoggingLevel,
    LoggingMessageNotification,
    LoggingMessageNotificationParams,
    NotificationParams,
    SetLevelRequestParams,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS


if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp.server import ServerRequestContext


CHATTER_TOOL: Final[str] = "chatter"
"""Logs one message at each of debug, info, warning and error, ``count`` times over."""

CHATTER_LOGGER: Final[str] = "fixture"
"""The logger name the chatter tool logs under."""

HIDDEN_MARK: Final[str] = chr(0x200B)
"""A zero-width space the chatter tool hides in every message, which a client must strip."""

LOG_LEVEL_SEEN_TOOL: Final[str] = "log_level_seen"
"""Reports the level the last ``logging/setLevel`` asked for, or ``none``."""

ROOTS_TOOL: Final[str] = "roots_seen"
"""Asks the client for its roots and reports them as a JSON list of ``{"uri", "name"}``."""

ROOTS_CHANGES_TOOL: Final[str] = "roots_changes"
"""Reports how many ``notifications/roots/list_changed`` the client has sent."""

CAPABILITIES_TOOL: Final[str] = "capabilities_seen"
"""Reports the capabilities the client declared for the request, as JSON."""


_LEVELS: Final[tuple[str, ...]] = ("debug", "info", "notice", "warning", "error", "critical", "alert", "emergency")


class _LegacyLogLevel:
    """What a 2025-11-25 client has told the server outside any request.

    Attributes:
        level: The level asked for with ``logging/setLevel``, or ``None`` before the client asked.
        roots_changes: How many ``notifications/roots/list_changed`` arrived.
    """

    level: str | None = None
    roots_changes: int = 0


_legacy = _LegacyLogLevel()


async def _set_level(_ctx: ServerRequestContext[Any, Any], params: SetLevelRequestParams) -> EmptyResult:
    """Record the level a 2025-11-25 client asked for.

    Args:
        _ctx: The request context.
        params: The request's parameters.

    Returns:
        EmptyResult: The empty acknowledgement.
    """
    _legacy.level = params.level
    await anyio.lowlevel.checkpoint()
    return EmptyResult()


async def _roots_changed(_ctx: ServerRequestContext[Any, Any], _params: NotificationParams) -> None:
    """Count a 2025-11-25 client's notice that its roots changed.

    Args:
        _ctx: The notification context.
        _params: The notification's parameters.
    """
    _legacy.roots_changes += 1
    await anyio.lowlevel.checkpoint()


class FeaturesServer(MCPServer):
    """The fixture server, which also serves ``logging/setLevel`` to 2025-11-25 clients."""

    def serve_log_level(self) -> None:
        """Register the ``logging/setLevel`` handler, which is also what advertises the ``logging`` capability."""
        self._lowlevel_server.add_request_handler("logging/setLevel", SetLevelRequestParams, _set_level)

    def count_roots_changes(self) -> None:
        """Register the ``notifications/roots/list_changed`` handler."""
        self._lowlevel_server.add_notification_handler("notifications/roots/list_changed", NotificationParams, _roots_changed)


def _requested(ctx: Context, level: LoggingLevel) -> bool:
    """Decide whether the client asked for messages at a level.

    On 2026-07-28 a client asks per request, with a ``logLevel`` in the request's ``_meta``, and asks for nothing without one; on
    2025-11-25 it asks with ``logging/setLevel``, and gets every message until it does.

    Args:
        ctx: The request context.
        level: The message's level.

    Returns:
        bool: ``True`` when the level is at or above the one asked for.
    """
    if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:
        wanted = (ctx.request_context.meta or {}).get(LOG_LEVEL_META_KEY)
        return isinstance(wanted, str) and wanted in _LEVELS and _LEVELS.index(level) >= _LEVELS.index(wanted)
    return _legacy.level is None or _LEVELS.index(level) >= _LEVELS.index(_legacy.level)


async def _log(ctx: Context, level: LoggingLevel, data: object, *, heed_level: bool) -> None:
    """Send one log message the way the SDK's own logging does, without its deprecated helpers.

    Args:
        ctx: The request context.
        level: The message's level.
        data: The message.
        heed_level: Whether to send it only when the client asked for its level; a careless server sends everything.
    """
    if heed_level and not _requested(ctx, level):
        return
    request = ctx.request_context
    notification = LoggingMessageNotification(params=LoggingMessageNotificationParams(level=level, data=data, logger=CHATTER_LOGGER))
    await request.session.send_notification(notification, related_request_id=request.request_id)


async def chatter(count: int, ctx: Context, *, heed_level: bool = True) -> str:
    """Log a message at each level, ``count`` times over.

    Args:
        count: How many rounds of messages to log.
        ctx: The request context.
        heed_level: Whether to honour the level the client asked for; a
            careless server logs everything.

    Returns:
        str: How many messages were logged.
    """
    for index in range(count):
        await _log(ctx, "debug", {"round": index, "text": f"debug {index}{HIDDEN_MARK}"}, heed_level=heed_level)
        await _log(ctx, "info", {"round": index, "text": f"info {index}{HIDDEN_MARK}"}, heed_level=heed_level)
        await _log(ctx, "warning", f"warning {index}{HIDDEN_MARK}", heed_level=heed_level)
        await _log(ctx, "error", f"error {index}{HIDDEN_MARK}", heed_level=heed_level)
    return f"logged {count * 4}"


def log_level_seen() -> str:
    """Report the level the last ``logging/setLevel`` asked for.

    Returns:
        str: The level, or ``none``.
    """
    return _legacy.level or "none"


def roots_changes() -> int:
    """Report how many roots-changed notices the client has sent.

    Returns:
        int: The count.
    """
    return _legacy.roots_changes


def _ask_for_roots() -> ListRoots:
    """Ask the client for its roots.

    Returns:
        ListRoots: The request marker.
    """
    return ListRoots()


def roots_seen(roots: Annotated[ListRootsResult, Resolve(_ask_for_roots)]) -> str:
    """Report the client's roots.

    Args:
        roots: The client's answer to ``roots/list``.

    Returns:
        str: The roots, as a JSON list of ``{"uri", "name"}``.
    """
    return json.dumps([{"uri": str(root.uri), "name": root.name} for root in roots.roots])


def capabilities_seen(ctx: Context) -> str:
    """Report the capabilities the client declared.

    Args:
        ctx: The request context.

    Returns:
        str: The capabilities as they arrived on the wire, or ``null``.
    """
    declared = ctx.client_capabilities
    return json.dumps(None if declared is None else declared.model_dump(mode="json", by_alias=True, exclude_none=True))


def build_server() -> MCPServer:
    """Build the server.

    Returns:
        MCPServer: The server, with every feature tool registered.
    """
    server = FeaturesServer(name="intellicrack-features-fixture")
    server.serve_log_level()
    server.count_roots_changes()
    server.add_tool(chatter, name=CHATTER_TOOL, description="Log messages at several levels.")
    server.add_tool(log_level_seen, name=LOG_LEVEL_SEEN_TOOL, description="Report the requested log level.")
    server.add_tool(roots_seen, name=ROOTS_TOOL, description="Report the client's roots.")
    server.add_tool(roots_changes, name=ROOTS_CHANGES_TOOL, description="Count the client's roots-changed notices.")
    server.add_tool(capabilities_seen, name=CAPABILITIES_TOOL, description="Report the client's declared capabilities.")
    return server


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the fixture over stdio, Streamable HTTP or legacy SSE.

    Args:
        argv: Command-line arguments, defaulting to ``sys.argv[1:]``.

    Returns:
        int: Process exit status.
    """
    parser = argparse.ArgumentParser(description="An MCP server that uses the client-side features.")
    parser.add_argument("--transport", choices=("stdio", "http", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=0)
    arguments = parser.parse_args(argv)
    server = build_server()
    if arguments.transport == "http":
        uvicorn.run(server.streamable_http_app(), host="127.0.0.1", port=arguments.port, log_level="error")
    elif arguments.transport == "sse":
        uvicorn.run(server.sse_app(), host="127.0.0.1", port=arguments.port, log_level="error")
    else:
        server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
