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
import base64
import json
import sys
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Annotated, Any, Final

import anyio.lowlevel
import uvicorn
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.resolve import ListRoots, Resolve
from mcp_types import (
    LOG_LEVEL_META_KEY,
    Completion,
    CompletionArgument,
    CompletionContext,
    EmptyResult,
    ListResourcesResult,
    ListRootsResult,
    LoggingLevel,
    LoggingMessageNotification,
    LoggingMessageNotificationParams,
    NotificationParams,
    PaginatedRequestParams,
    PromptListChangedNotification,
    PromptReference,
    ResourceListChangedNotification,
    ResourceTemplateReference,
    ResourceUpdatedNotification,
    ResourceUpdatedNotificationParams,
    SetLevelRequestParams,
    SubscribeRequestParams,
    UnsubscribeRequestParams,
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

SLOW_TOOL: Final[str] = "slow"
"""Reports progress ``steps`` times, ``delay`` seconds apart, then answers; with ``stuck`` its progress never advances."""

CANCELLATIONS_TOOL: Final[str] = "cancellations"
"""Reports how many slow calls were cancelled before they finished."""

SLOW_RESOURCE: Final[str] = "features://slow/report"
"""A resource whose read reports progress twice."""

SLOW_PROMPT: Final[str] = "slow_prompt"
"""A prompt whose fetch reports progress once."""

NOTES_RESOURCE: Final[str] = "features://notes/readme"
"""A text resource whose words carry a hidden character a client must strip."""

PIXEL_RESOURCE: Final[str] = "features://images/pixel.png"
"""A one-pixel PNG, served as a binary blob."""

PIXEL_PNG_BASE64: Final[str] = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg=="
"""The pixel's bytes."""

REPORT_TEMPLATE: Final[str] = "features://reports/{name}"
"""A resource template; its ``name`` completes to the report names."""

REPORT_NAMES: Final[tuple[str, ...]] = ("alpha", "alpine", "beta")
"""What ``name`` completes to."""

GREET_PROMPT: Final[str] = "greet"
"""A prompt taking a required ``person`` and an optional ``style``; ``person`` completes."""

RESOURCE_PAGE_SIZE: Final[int] = 1
"""How many resources each page of the listing holds, so a listing always spans pages."""

FORGET_SUBSCRIPTIONS_TOOL: Final[str] = "forget_subscriptions"
"""Makes the server forget every 2025-11-25 subscription, as a restarted server would."""

SUBSCRIBED_TOOL: Final[str] = "subscribed"
"""Reports the resources a 2025-11-25 client is subscribed to, as JSON."""

TOUCH_TOOL: Final[str] = "touch"
"""Adds :data:`ADDED_RESOURCE`, then tells subscribers that a resource changed and that the resource and prompt lists changed."""

ADDED_RESOURCE: Final[str] = "features://notes/added"
"""The resource the touch tool adds, so a client that lists again sees the list change."""


_LEVELS: Final[tuple[str, ...]] = ("debug", "info", "notice", "warning", "error", "critical", "alert", "emergency")


@dataclass
class _LegacyLogLevel:
    """What a 2025-11-25 client has told the server outside any request.

    Attributes:
        level: The level asked for with ``logging/setLevel``, or ``None`` before the client asked.
        roots_changes: How many ``notifications/roots/list_changed`` arrived.
        cancellations: How many slow calls were cancelled before they finished.
        subscribed: The resources a 2025-11-25 client subscribed to.
    """

    level: str | None = None
    roots_changes: int = 0
    cancellations: int = 0
    subscribed: set[str] = field(default_factory=set)


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


async def _subscribe(_ctx: ServerRequestContext[Any, Any], params: SubscribeRequestParams) -> EmptyResult:
    """Record a 2025-11-25 client's subscription.

    Args:
        _ctx: The request context.
        params: The request's parameters.

    Returns:
        EmptyResult: The empty acknowledgement.
    """
    _legacy.subscribed.add(str(params.uri))
    await anyio.lowlevel.checkpoint()
    return EmptyResult()


async def _unsubscribe(_ctx: ServerRequestContext[Any, Any], params: UnsubscribeRequestParams) -> EmptyResult:
    """Forget a 2025-11-25 client's subscription.

    Args:
        _ctx: The request context.
        params: The request's parameters.

    Returns:
        EmptyResult: The empty acknowledgement.
    """
    _legacy.subscribed.discard(str(params.uri))
    await anyio.lowlevel.checkpoint()
    return EmptyResult()


class FeaturesServer(MCPServer):
    """The fixture server, which also serves ``logging/setLevel`` to 2025-11-25 clients."""

    def serve_log_level(self) -> None:
        """Register the ``logging/setLevel`` handler, which is also what advertises the ``logging`` capability."""
        self._lowlevel_server.add_request_handler("logging/setLevel", SetLevelRequestParams, _set_level)

    def serve_subscriptions(self) -> None:
        """Register ``resources/subscribe`` and ``resources/unsubscribe``, which advertises subscriptions to 2025-11-25 clients."""
        self._lowlevel_server.add_request_handler("resources/subscribe", SubscribeRequestParams, _subscribe)
        self._lowlevel_server.add_request_handler("resources/unsubscribe", UnsubscribeRequestParams, _unsubscribe)

    def page_resources(self) -> None:
        """Serve ``resources/list`` a page of :data:`RESOURCE_PAGE_SIZE` at a time, with a cursor to the next."""
        self._lowlevel_server.add_request_handler("resources/list", PaginatedRequestParams, self._list_resource_page)

    async def _list_resource_page(self, _ctx: ServerRequestContext[Any, Any], params: PaginatedRequestParams) -> ListResourcesResult:
        """List one page of resources.

        Args:
            _ctx: The request context.
            params: The request's parameters, carrying the cursor.

        Returns:
            ListResourcesResult: The page.
        """
        resources = await self.list_resources()
        start = int(params.cursor or "0")
        end = start + RESOURCE_PAGE_SIZE
        return ListResourcesResult(resources=resources[start:end], next_cursor=str(end) if end < len(resources) else None)

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


async def slow(steps: int, delay: float, ctx: Context, *, stuck: bool = False) -> str:
    """Report progress step by step, pausing between steps; a call stopped before its last step is counted as cancelled.

    Args:
        steps: How many steps to report.
        delay: Seconds between steps.
        ctx: The request context.
        stuck: Whether to report the same progress every time.

    Returns:
        str: How many steps were taken.
    """
    finished = False
    try:
        for index in range(steps):
            await ctx.report_progress(0 if stuck else index + 1, steps, f"step {index + 1}{HIDDEN_MARK}")
            await anyio.sleep(delay)
        finished = True
    finally:
        if not finished:
            _legacy.cancellations += 1
    return f"took {steps} steps"


def cancellations() -> int:
    """Report how many slow calls were cancelled.

    Returns:
        int: The count.
    """
    return _legacy.cancellations


async def slow_report(name: str, ctx: Context) -> str:
    """Read a report, reporting progress as it goes.

    Args:
        name: The report's name.
        ctx: The request context.

    Returns:
        str: The report.
    """
    await ctx.report_progress(1, 2, "reading")
    await anyio.sleep(0.05)
    await ctx.report_progress(2, 2, "read")
    return f"report {name}"


async def slow_prompt(ctx: Context) -> str:
    """Build a prompt, reporting progress once.

    Args:
        ctx: The request context.

    Returns:
        str: The prompt text.
    """
    await ctx.report_progress(1, 1, "building")
    return "a slow prompt"


def notes() -> str:
    """Serve the notes.

    Returns:
        str: The notes.
    """
    return f"remember the target{HIDDEN_MARK}"


def pixel() -> bytes:
    """Serve the pixel.

    Returns:
        bytes: The PNG.
    """
    return base64.b64decode(PIXEL_PNG_BASE64)


def greet(person: str, style: str = "plain") -> str:
    """Build a greeting prompt.

    Args:
        person: Who to greet.
        style: How.

    Returns:
        str: The prompt text.
    """
    return f"Greet {person} in a {style} way."


async def complete(
    ref: PromptReference | ResourceTemplateReference,
    argument: CompletionArgument,
    context: CompletionContext | None,
) -> Completion | None:
    """Suggest values for the report template's ``name`` and the greeting's ``person``.

    Args:
        ref: What the argument belongs to.
        argument: The argument and what is typed so far.
        context: The other arguments' values, unused.

    Returns:
        Completion | None: The suggestions, or ``None`` for an argument that has none.
    """
    del context
    await anyio.lowlevel.checkpoint()
    if isinstance(ref, ResourceTemplateReference) and ref.uri == REPORT_TEMPLATE and argument.name == "name":
        values = [name for name in REPORT_NAMES if name.startswith(argument.value)]
        return Completion(values=values, total=len(values), has_more=False)
    if isinstance(ref, PromptReference) and ref.name == GREET_PROMPT and argument.name == "person":
        values = [name for name in ("ada", "alan", "grace") if name.startswith(argument.value)]
        return Completion(values=values, total=len(values), has_more=False)
    return None


def added() -> str:
    """Serve the added resource.

    Returns:
        str: Its text.
    """
    return "added later"


async def touch(uri: str, ctx: Context) -> str:
    """Add a resource, then tell clients that a resource changed and that the lists changed.

    On 2026-07-28 the events go to ``subscriptions/listen`` streams; on 2025-11-25 the resource update goes to a client that subscribed
    to it, and the list changes to every client.

    Args:
        uri: The resource that changed.
        ctx: The request context.

    Returns:
        str: What was sent.
    """
    _ = ctx.mcp_server.resource(ADDED_RESOURCE, mime_type="text/plain")(added)
    if ctx.protocol_version in MODERN_PROTOCOL_VERSIONS:
        await ctx.notify_resource_updated(uri)
        await ctx.notify_resources_changed()
        await ctx.notify_prompts_changed()
        return "published"
    session = ctx.request_context.session
    sent = "lists"
    if uri in _legacy.subscribed:
        await session.send_notification(ResourceUpdatedNotification(params=ResourceUpdatedNotificationParams(uri=uri)))
        sent = "update and lists"
    await session.send_notification(ResourceListChangedNotification())
    await session.send_notification(PromptListChangedNotification())
    return sent


def forget_subscriptions() -> str:
    """Forget every subscription.

    Returns:
        str: How many were forgotten.
    """
    count = len(_legacy.subscribed)
    _legacy.subscribed.clear()
    return str(count)


def subscribed() -> str:
    """Report the subscriptions.

    Returns:
        str: The subscribed URIs, sorted, as JSON.
    """
    return json.dumps(sorted(_legacy.subscribed))


def build_server() -> MCPServer:
    """Build the server.

    Returns:
        MCPServer: The server, with every feature tool registered.
    """
    server = FeaturesServer(name="intellicrack-features-fixture")
    server.serve_log_level()
    server.serve_subscriptions()
    server.page_resources()
    server.count_roots_changes()
    server.add_tool(chatter, name=CHATTER_TOOL, description="Log messages at several levels.")
    server.add_tool(log_level_seen, name=LOG_LEVEL_SEEN_TOOL, description="Report the requested log level.")
    server.add_tool(roots_seen, name=ROOTS_TOOL, description="Report the client's roots.")
    server.add_tool(roots_changes, name=ROOTS_CHANGES_TOOL, description="Count the client's roots-changed notices.")
    server.add_tool(capabilities_seen, name=CAPABILITIES_TOOL, description="Report the client's declared capabilities.")
    server.add_tool(slow, name=SLOW_TOOL, description="Report progress step by step.")
    server.add_tool(cancellations, name=CANCELLATIONS_TOOL, description="Count cancelled slow calls.")
    _ = server.resource("features://slow/{name}")(slow_report)
    _ = server.prompt(SLOW_PROMPT)(slow_prompt)
    _ = server.resource(NOTES_RESOURCE, mime_type="text/plain")(notes)
    _ = server.resource(PIXEL_RESOURCE, mime_type="image/png")(pixel)
    _ = server.resource(REPORT_TEMPLATE)(slow_report)
    _ = server.prompt(GREET_PROMPT)(greet)
    _ = server.completion()(complete)
    server.add_tool(touch, name=TOUCH_TOOL, description="Announce resource and list changes.")
    server.add_tool(forget_subscriptions, name=FORGET_SUBSCRIPTIONS_TOOL, description="Forget every subscription.")
    server.add_tool(subscribed, name=SUBSCRIBED_TOOL, description="Report the subscriptions.")
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
