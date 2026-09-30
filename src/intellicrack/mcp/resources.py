# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Resources and prompts published by connected MCP servers.

A server can offer more than tools. Resources are documents it will hand over
on request -- a file, a database row, an analysis report -- and prompts are
prepared message templates it suggests. Neither is a tool call: nothing here
runs on the operator's behalf, it only fetches what a server is already
offering.

Everything a server returns is still untrusted. Listings and resource text are
cleaned of invisible characters and forged fence markers as they arrive, and
bounded; whatever reaches the model as prose is fenced, exactly as tool output
is. A resource URI and a prompt name are kept exactly as the server wrote them
where the server needs them back to serve a read or a fetch.

Every request here goes through :meth:`~intellicrack.mcp.connection.McpConnection.request`,
which bounds it by the server's per-request timeout, not counting time spent
waiting on the operator, and re-raises a timeout or a transport failure as
:class:`~intellicrack.mcp.errors.McpConnectionError`.
:class:`asyncio.CancelledError` is deliberately not among them: it propagates
untouched, so cancelling a caller mid-request unwinds rather than being
recorded as a server fault.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    EmbeddedResourcePart,
    ImageResultPart,
    Message,
    TextResultPart,
    ToolResultPart,
)
from intellicrack.core.untrusted_text import clean_untrusted_label, sanitize_untrusted_text
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.progress import ProgressKind


if TYPE_CHECKING:
    from collections.abc import Mapping

    from mcp import Client
    from mcp_types import GetPromptResult, ReadResourceResult, RequestParamsMeta

    from intellicrack.mcp.connection import McpConnection
    from intellicrack.mcp.progress import ProgressFn


_logger = get_logger(__name__)


MAX_LIST_PAGES: Final[int] = 128
"""Hard cap on pagination rounds for a resource or prompt listing."""

MAX_ENTRIES: Final[int] = 2048
"""Hard cap on how many resources or prompts one server may contribute."""

MAX_PROMPT_TEXT_CHARS: Final[int] = 32768
"""Longest piece of prompt text kept from one message."""

MAX_RESOURCE_TEXT_CHARS: Final[int] = 128 * 1024
"""Longest piece of resource text kept from one read."""

_LABEL_CHARS: Final[int] = 256
"""Longest name, title or media type kept from a listing."""

_URI_CHARS: Final[int] = 2048
"""Longest URI kept from a listing."""

_DESCRIPTION_CHARS: Final[int] = 2048
"""Longest description kept from a listing."""


def _label(value: str | None, limit: int = _LABEL_CHARS) -> str | None:
    """Clean an optional server-supplied label.

    Args:
        value: The server's text, or ``None``.
        limit: Longest text kept.

    Returns:
        str | None: The cleaned text, or ``None`` when absent.
    """
    return None if value is None else clean_untrusted_label(value, limit=limit)


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    """One resource a server offers.

    Attributes:
        uri: The resource URI exactly as the server wrote it, which is what
            a read has to send back. Clean it before showing it.
        name: The server's own name for it, cleaned.
        title: The server's display title, or ``None``.
        description: The server's description, or ``None``.
        mime_type: The resource's media type, or ``None``.
        size: The resource's size in bytes, or ``None``.
    """

    uri: str
    name: str
    title: str | None = None
    description: str | None = None
    mime_type: str | None = None
    size: int | None = None


@dataclass(frozen=True, slots=True)
class PromptSummary:
    """One prompt template a server offers.

    Attributes:
        name: The server's own name for it exactly as written, which is what
            a fetch has to send back. Clean it before showing it.
        title: The server's display title, or ``None``.
        description: The server's description, or ``None``.
        arguments: Names of the arguments it accepts, in server order.
        required_arguments: Names of the arguments it requires.
    """

    name: str
    title: str | None = None
    description: str | None = None
    arguments: tuple[str, ...] = ()
    required_arguments: frozenset[str] = frozenset()


def _require_client(connection: McpConnection) -> Client:
    """Resolve a connection's entered client, or refuse.

    Args:
        connection: The connection to read from.

    Returns:
        Client: The entered client.

    Raises:
        McpConnectionError: If the server is not connected.
    """
    client = connection.client
    if client is None or not connection.is_ready:
        message = f"MCP server '{connection.server_id}' is not connected"
        raise McpConnectionError(message)
    return client


async def list_resources(connection: McpConnection) -> list[ResourceSummary]:
    """List every resource a server offers.

    A server that is not connected propagates
    :class:`~intellicrack.mcp.errors.McpConnectionError` from the connection
    check, and a request that times out or fails propagates the same from
    :meth:`~intellicrack.mcp.connection.McpConnection.request`.

    Args:
        connection: The connected server.

    Returns:
        list[ResourceSummary]: The resources, in server order, capped at
        :data:`MAX_ENTRIES`.
    """
    client = _require_client(connection)
    summaries: list[ResourceSummary] = []
    cursor: str | None = None
    for _ in range(MAX_LIST_PAGES):
        result = await connection.request("list resources", partial(client.list_resources, cursor=cursor))
        summaries.extend(
            ResourceSummary(
                uri=str(resource.uri),
                name=clean_untrusted_label(resource.name, limit=_LABEL_CHARS),
                title=_label(resource.title),
                description=_label(resource.description, _DESCRIPTION_CHARS),
                mime_type=_label(resource.mime_type),
                size=resource.size,
            )
            for resource in result.resources
        )
        cursor = result.next_cursor
        if cursor is None or len(summaries) >= MAX_ENTRIES:
            break
    _logger.debug("mcp_resources_listed", server_id=connection.server_id, count=len(summaries))
    return summaries[:MAX_ENTRIES]


async def read_resource(connection: McpConnection, uri: str, *, on_progress: ProgressFn | None = None) -> list[ToolResultPart]:
    """Fetch one resource's contents.

    The read asks the server to report its progress, which renews its
    deadline as a tool call's does. A server that is not connected
    propagates :class:`~intellicrack.mcp.errors.McpConnectionError` from the
    connection check, and a request that times out or fails propagates the
    same from
    :meth:`~intellicrack.mcp.connection.McpConnection.request_with_progress`.

    Args:
        connection: The connected server.
        uri: The resource URI, as the listing reported it.
        on_progress: Receives each progress notice, or ``None``.

    Returns:
        list[ToolResultPart]: One part per content block the server returned.
    """
    client = _require_client(connection)

    async def _read(meta: RequestParamsMeta | None) -> ReadResourceResult:
        """Read the resource.

        Args:
            meta: The ``_meta`` the request carries.

        Returns:
            ReadResourceResult: The server's answer.
        """
        return await client.read_resource(uri, meta=meta)

    result = await connection.request_with_progress(f"read {uri!r}", ProgressKind.RESOURCE, uri, _read, on_progress)

    parts: list[ToolResultPart] = []
    for contents in result.contents:
        text = getattr(contents, "text", None)
        blob = getattr(contents, "blob", None)
        parts.append(
            EmbeddedResourcePart(
                uri=clean_untrusted_label(str(contents.uri), limit=_URI_CHARS),
                text=clean_untrusted_label(text, limit=MAX_RESOURCE_TEXT_CHARS) if isinstance(text, str) else None,
                data="".join(blob.split()) if isinstance(blob, str) else None,
                mime_type=_label(contents.mime_type),
            ),
        )
    _logger.info("mcp_resource_read", server_id=connection.server_id, uri=uri, part_count=len(parts))
    return parts


async def list_prompts(connection: McpConnection) -> list[PromptSummary]:
    """List every prompt template a server offers.

    A server that is not connected propagates
    :class:`~intellicrack.mcp.errors.McpConnectionError` from the connection
    check, and a request that times out or fails propagates the same from
    :meth:`~intellicrack.mcp.connection.McpConnection.request`.

    Args:
        connection: The connected server.

    Returns:
        list[PromptSummary]: The prompts, in server order, capped at
        :data:`MAX_ENTRIES`.
    """
    client = _require_client(connection)
    summaries: list[PromptSummary] = []
    cursor: str | None = None
    for _ in range(MAX_LIST_PAGES):
        result = await connection.request("list prompts", partial(client.list_prompts, cursor=cursor))
        for prompt in result.prompts:
            arguments = tuple(argument.name for argument in prompt.arguments or ())
            required = frozenset(argument.name for argument in prompt.arguments or () if argument.required)
            summaries.append(
                PromptSummary(
                    name=prompt.name,
                    title=_label(prompt.title),
                    description=_label(prompt.description, _DESCRIPTION_CHARS),
                    arguments=arguments,
                    required_arguments=required,
                ),
            )
        cursor = result.next_cursor
        if cursor is None or len(summaries) >= MAX_ENTRIES:
            break
    _logger.debug("mcp_prompts_listed", server_id=connection.server_id, count=len(summaries))
    return summaries[:MAX_ENTRIES]


def _render_prompt_content(content: object) -> str:
    """Render one prompt message's content as text.

    A prompt message may carry an image, audio, or an embedded resource. A
    conversation :class:`~intellicrack.core.types.Message` holds text alone,
    so a non-text block becomes a short description of what it was rather
    than being dropped silently.

    Args:
        content: The content block the server returned.

    Returns:
        str: The block's text, or a description of what it carried.
    """
    kind = getattr(content, "type", None)
    if kind == "text":
        return str(getattr(content, "text", ""))
    if kind in {"image", "audio"}:
        mime_type = getattr(content, "mime_type", "application/octet-stream")
        return f"[{kind} attachment of type {mime_type}, not shown]"
    if kind == "resource":
        resource = getattr(content, "resource", None)
        text = getattr(resource, "text", None)
        if isinstance(text, str):
            return text
        return f"[embedded resource {getattr(resource, 'uri', 'unknown')}, not shown]"
    if kind == "resource_link":
        return f"[resource link {getattr(content, 'uri', 'unknown')}]"
    return "[unsupported prompt content]"


async def get_prompt(
    connection: McpConnection,
    name: str,
    arguments: Mapping[str, str],
    *,
    on_progress: ProgressFn | None = None,
) -> list[Message]:
    """Fetch one prompt template, filled in with the supplied arguments.

    The messages a server returns are its own words, not Intellicrack's, so
    each one is fenced before it can reach the model as conversation.

    The fetch asks the server to report its progress, which renews its
    deadline as a tool call's does. A server that is not connected
    propagates :class:`~intellicrack.mcp.errors.McpConnectionError` from the
    connection check, and a request that times out or fails propagates the
    same from
    :meth:`~intellicrack.mcp.connection.McpConnection.request_with_progress`.

    Args:
        connection: The connected server.
        name: The prompt name, as the listing reported it.
        arguments: Argument values to fill the template with.
        on_progress: Receives each progress notice, or ``None``.

    Returns:
        list[Message]: The rendered conversation messages.
    """
    client = _require_client(connection)
    values = dict(arguments)

    async def _get(meta: RequestParamsMeta | None) -> GetPromptResult:
        """Fetch the prompt.

        Args:
            meta: The ``_meta`` the request carries.

        Returns:
            GetPromptResult: The server's answer.
        """
        return await client.get_prompt(name, values, meta=meta)

    result = await connection.request_with_progress(f"fetch prompt {name!r}", ProgressKind.PROMPT, name, _get, on_progress)

    messages: list[Message] = []
    for entry in result.messages:
        rendered = _render_prompt_content(entry.content)
        messages.append(
            Message(
                role=entry.role,
                content=sanitize_untrusted_text(rendered, limit=MAX_PROMPT_TEXT_CHARS),
            ),
        )
    _logger.info("mcp_prompt_fetched", server_id=connection.server_id, prompt=name, message_count=len(messages))
    return messages


def _textual_content(part: ToolResultPart) -> str | None:
    """Extract the readable text of a result part, when it has any.

    Args:
        part: The part to read.

    Returns:
        str | None: The text, or ``None`` for a part that carries none.
    """
    if isinstance(part, TextResultPart):
        return part.text
    return part.text if isinstance(part, EmbeddedResourcePart) else None


def summarize_parts(parts: list[ToolResultPart]) -> str:
    """Render fetched resource contents as readable text.

    Args:
        parts: The parts a read produced.

    Returns:
        str: Fenced text for every textual part, and a short description of
        each part that carried something else.
    """
    rendered: list[str] = []
    for part in parts:
        text = _textual_content(part)
        if text is not None:
            rendered.append(sanitize_untrusted_text(text, limit=MAX_PROMPT_TEXT_CHARS))
        elif isinstance(part, ImageResultPart):
            rendered.append(f"[image of type {part.mime_type}, not shown]")
        else:
            rendered.append(f"[binary content of type {getattr(part, 'mime_type', None) or 'unknown'}, not shown]")
    return "\n\n".join(rendered)
