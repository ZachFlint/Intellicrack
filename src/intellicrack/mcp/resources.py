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

Everything a server returns is still untrusted, so text arrives bounded and
fenced, exactly as tool output does.

Every request here catches transport failures and re-raises them as
:class:`~intellicrack.mcp.errors.McpConnectionError`.
:class:`asyncio.CancelledError` is deliberately not among them: it propagates
untouched, so cancelling a caller mid-request unwinds rather than being
recorded as a server fault.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from intellicrack.core.logging import get_logger
from intellicrack.core.types import (
    EmbeddedResourcePart,
    ImageResultPart,
    Message,
    TextResultPart,
    ToolResultPart,
)
from intellicrack.mcp.connection import TRANSPORT_FAILURES, representative_failure
from intellicrack.mcp.errors import McpConnectionError
from intellicrack.mcp.tool_source import sanitize_untrusted_text


if TYPE_CHECKING:
    from collections.abc import Mapping

    from mcp import Client

    from intellicrack.mcp.connection import McpConnection


_logger = get_logger(__name__)


MAX_LIST_PAGES: Final[int] = 128
"""Hard cap on pagination rounds for a resource or prompt listing."""

MAX_ENTRIES: Final[int] = 2048
"""Hard cap on how many resources or prompts one server may contribute."""

MAX_PROMPT_TEXT_CHARS: Final[int] = 32768
"""Longest piece of prompt text kept from one message."""


@dataclass(frozen=True, slots=True)
class ResourceSummary:
    """One resource a server offers.

    Attributes:
        uri: The resource URI, used to read it.
        name: The server's own name for it.
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
        name: The server's own name for it, used to fetch it.
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

    Args:
        connection: The connected server.

    Returns:
        list[ResourceSummary]: The resources, in server order, capped at
        :data:`MAX_ENTRIES`.

    Raises:
        McpConnectionError: If the server is not connected, or the listing
            could not be retrieved.
    """
    client = _require_client(connection)
    summaries: list[ResourceSummary] = []
    cursor: str | None = None
    for _ in range(MAX_LIST_PAGES):
        try:
            result = await client.list_resources(cursor=cursor)
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{connection.server_id}': cannot list resources: {failure}"
            raise McpConnectionError(message) from failure
        summaries.extend(
            ResourceSummary(
                uri=str(resource.uri),
                name=resource.name,
                title=resource.title,
                description=resource.description,
                mime_type=resource.mime_type,
                size=resource.size,
            )
            for resource in result.resources
        )
        cursor = result.next_cursor
        if cursor is None or len(summaries) >= MAX_ENTRIES:
            break
    _logger.debug("mcp_resources_listed", server_id=connection.server_id, count=len(summaries))
    return summaries[:MAX_ENTRIES]


async def read_resource(connection: McpConnection, uri: str) -> list[ToolResultPart]:
    """Fetch one resource's contents.

    Args:
        connection: The connected server.
        uri: The resource URI, as the listing reported it.

    Returns:
        list[ToolResultPart]: One part per content block the server returned.

    Raises:
        McpConnectionError: If the server is not connected, or the read
            failed.
    """
    client = _require_client(connection)
    try:
        result = await client.read_resource(uri)
    except TRANSPORT_FAILURES as exc:
        failure = representative_failure(exc)
        message = f"server '{connection.server_id}': cannot read {uri!r}: {failure}"
        raise McpConnectionError(message) from failure

    parts: list[ToolResultPart] = []
    for contents in result.contents:
        text = getattr(contents, "text", None)
        blob = getattr(contents, "blob", None)
        parts.append(
            EmbeddedResourcePart(
                uri=str(contents.uri),
                text=text if isinstance(text, str) else None,
                data=blob if isinstance(blob, str) else None,
                mime_type=contents.mime_type,
            ),
        )
    _logger.info("mcp_resource_read", server_id=connection.server_id, uri=uri, part_count=len(parts))
    return parts


async def list_prompts(connection: McpConnection) -> list[PromptSummary]:
    """List every prompt template a server offers.

    Args:
        connection: The connected server.

    Returns:
        list[PromptSummary]: The prompts, in server order, capped at
        :data:`MAX_ENTRIES`.

    Raises:
        McpConnectionError: If the server is not connected, or the listing
            could not be retrieved.
    """
    client = _require_client(connection)
    summaries: list[PromptSummary] = []
    cursor: str | None = None
    for _ in range(MAX_LIST_PAGES):
        try:
            result = await client.list_prompts(cursor=cursor)
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{connection.server_id}': cannot list prompts: {failure}"
            raise McpConnectionError(message) from failure
        for prompt in result.prompts:
            arguments = tuple(argument.name for argument in prompt.arguments or ())
            required = frozenset(argument.name for argument in prompt.arguments or () if argument.required)
            summaries.append(
                PromptSummary(
                    name=prompt.name,
                    title=prompt.title,
                    description=prompt.description,
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


async def get_prompt(connection: McpConnection, name: str, arguments: Mapping[str, str]) -> list[Message]:
    """Fetch one prompt template, filled in with the supplied arguments.

    The messages a server returns are its own words, not Intellicrack's, so
    each one is fenced before it can reach the model as conversation.

    Args:
        connection: The connected server.
        name: The prompt name, as the listing reported it.
        arguments: Argument values to fill the template with.

    Returns:
        list[Message]: The rendered conversation messages.

    Raises:
        McpConnectionError: If the server is not connected, or the prompt
            could not be fetched.
    """
    client = _require_client(connection)
    try:
        result = await client.get_prompt(name, dict(arguments))
    except TRANSPORT_FAILURES as exc:
        failure = representative_failure(exc)
        message = f"server '{connection.server_id}': cannot fetch prompt {name!r}: {failure}"
        raise McpConnectionError(message) from failure

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
    if isinstance(part, EmbeddedResourcePart):
        return part.text
    return None


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
