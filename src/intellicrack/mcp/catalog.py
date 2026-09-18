# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The tool listing one Model Context Protocol server publishes.

A catalog is a snapshot: the tools a server advertised at one moment, the
freshness hints it attached, and a generation digest over the whole listing.
The digest is what makes a server's tool surface something the operator can
consent to. Approvals are keyed by it, so a server that quietly swaps the
body of a tool the operator already approved produces a different generation
and has to ask again.

Everything a server sends is untrusted. Descriptions are truncated, the tool
count is capped, an oversized input schema drops its tool rather than the
whole listing, and a malformed name is refused. What survives is stored
verbatim -- in particular the input schema, which reaches the provider
boundary byte-identical so a ``$ref``-bearing schema is not silently
flattened.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from intellicrack.core.logging import get_logger
from intellicrack.mcp.config import TOOL_NAME_PATTERN, to_canonical_name
from intellicrack.mcp.errors import McpProtocolError


if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp import Client
    from mcp_types import Tool, ToolAnnotations


_logger = get_logger(__name__)


MAX_TOOLS_PER_SERVER: Final[int] = 1024
"""Hard cap on the tools one server may contribute."""

MAX_LIST_PAGES: Final[int] = 256
"""Hard cap on pagination rounds, so a looping cursor cannot hang a connect."""

MAX_DESCRIPTION_CHARS: Final[int] = 2048
"""Longest tool description kept, past which it is truncated."""

MAX_SCHEMA_BYTES: Final[int] = 128 * 1024
"""Largest serialized input or output schema accepted for one tool."""

_GENERATION_DIGEST_BYTES: Final[int] = 16
"""Digest width of a generation identifier."""

_TRUNCATION_MARKER: Final[str] = "... [truncated by Intellicrack]"

_ERR_DUPLICATE_TOOL = "server published the same tool name twice"


@dataclass(frozen=True, slots=True)
class McpToolEntry:
    """One tool a server publishes.

    Attributes:
        name: The tool name as the server published it, verbatim.
        canonical_name: ``mcp-<serverId>.<name>``, the name Intellicrack
            routes, classifies, confirms and persists under.
        title: The server's display title, or ``None``.
        description: The server's description, truncated to
            :data:`MAX_DESCRIPTION_CHARS`.
        input_schema: Raw JSON Schema 2020-12 for the arguments, exactly as
            the server sent it.
        output_schema: Raw JSON Schema for structured output, or ``None``
            when the server publishes none.
        annotations: The server's behavioural hints, or ``None``. These are
            untrusted unless the server is trusted, which is why
            classification consults the trust store before reading them.
    """

    name: str
    canonical_name: str
    title: str | None
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    annotations: ToolAnnotations | None

    @property
    def display_name(self) -> str:
        """Human-facing label for this tool.

        Returns:
            str: The server's title when it published one, else its name.
        """
        return self.title or self.name

    @property
    def read_only_hint(self) -> bool:
        """The server's own claim that this tool does not mutate state.

        Returns:
            bool: ``True`` only when the server explicitly said so. Never
            consult this without first establishing the server is trusted.
        """
        return self.annotations is not None and self.annotations.read_only_hint is True

    @property
    def destructive_hint(self) -> bool:
        """The server's own claim that this tool performs destructive updates.

        Returns:
            bool: ``True`` when the server explicitly said so.
        """
        return self.annotations is not None and self.annotations.destructive_hint is True


@dataclass(frozen=True, slots=True)
class McpToolCatalog:
    """A server's tool listing at one point in time.

    Attributes:
        server_id: The server this listing came from.
        entries: The tools, in the order the server returned them.
        generation: Digest over the listing, stable across processes.
        fetched_at: When the listing was retrieved.
        ttl_ms: The server's freshness hint in milliseconds, or ``None``.
        cache_scope: The server's cache scope hint, or ``None``.
    """

    server_id: str
    entries: tuple[McpToolEntry, ...]
    generation: str
    fetched_at: datetime
    ttl_ms: int | None = None
    cache_scope: str | None = None

    def is_fresh(self, now: datetime) -> bool:
        """Report whether this listing may still be reused.

        A server that published no ``ttlMs`` gets no implied freshness: the
        listing is treated as stale so the next request re-lists.

        Args:
            now: The current time, timezone-aware.

        Returns:
            bool: ``True`` while the server's own freshness window holds.
        """
        if self.ttl_ms is None or self.ttl_ms <= 0:
            return False
        elapsed_ms = (now - self.fetched_at).total_seconds() * 1000.0
        return 0 <= elapsed_ms < self.ttl_ms

    def entry(self, canonical_name: str) -> McpToolEntry | None:
        """Look up one tool by its canonical name.

        Args:
            canonical_name: ``mcp-<serverId>.<toolName>``.

        Returns:
            McpToolEntry | None: The tool, or ``None`` when this server does
            not publish it.
        """
        return next((item for item in self.entries if item.canonical_name == canonical_name), None)

    def entry_by_name(self, tool_name: str) -> McpToolEntry | None:
        """Look up one tool by the name the server publishes it under.

        Args:
            tool_name: The server's own tool name.

        Returns:
            McpToolEntry | None: The tool, or ``None`` when absent.
        """
        return next((item for item in self.entries if item.name == tool_name), None)

    @property
    def tool_count(self) -> int:
        """Number of tools in this listing.

        Returns:
            int: The entry count.
        """
        return len(self.entries)


def truncate_description(description: str) -> str:
    """Bound a server-supplied description at the catalog boundary.

    Args:
        description: The server's description text.

    Returns:
        str: The description, truncated with an explicit marker when it
        exceeded :data:`MAX_DESCRIPTION_CHARS`.
    """
    if len(description) <= MAX_DESCRIPTION_CHARS:
        return description
    keep = MAX_DESCRIPTION_CHARS - len(_TRUNCATION_MARKER)
    return f"{description[:keep]}{_TRUNCATION_MARKER}"


def canonical_json(value: object) -> str:
    """Serialize a value to a stable JSON string.

    Keys are sorted and separators are fixed, so the same logical schema
    produces the same bytes in any process and on any platform.

    Args:
        value: The value to serialize.

    Returns:
        str: The canonical JSON encoding.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _annotations_fingerprint(annotations: ToolAnnotations | None) -> str:
    """Render a tool's annotations into the generation digest input.

    Args:
        annotations: The server's annotations, or ``None``.

    Returns:
        str: A canonical JSON encoding of the annotations.
    """
    if annotations is None:
        return "null"
    return canonical_json(annotations.model_dump(mode="json", exclude_none=True, by_alias=True))


def compute_generation(entries: Sequence[McpToolEntry]) -> str:
    """Digest a tool listing into a stable generation identifier.

    The digest covers every field the operator would be consenting to: the
    name, the description, the argument schema and the behavioural
    annotations. Entries are sorted by name first, so a server that merely
    reorders its listing keeps the same generation and does not re-prompt,
    while any change to what a tool claims to be produces a new one.

    Args:
        entries: The tools to digest, in any order.

    Returns:
        str: A hexadecimal digest, identical across processes and platforms.
    """
    digest = hashlib.blake2b(digest_size=_GENERATION_DIGEST_BYTES)
    for entry in sorted(entries, key=lambda item: item.name):
        parts = (
            entry.name,
            entry.description,
            canonical_json(entry.input_schema),
            canonical_json(entry.output_schema),
            _annotations_fingerprint(entry.annotations),
        )
        for part in parts:
            digest.update(part.encode("utf-8"))
            digest.update(b"\x1f")
        digest.update(b"\x1e")
    return digest.hexdigest()


def _schema_within_bounds(schema: dict[str, Any] | None, *, server_id: str, tool_name: str, field: str) -> bool:
    """Check that a server-supplied schema is small enough to keep.

    Args:
        schema: The schema to measure, or ``None``.
        server_id: Server the schema came from, for the log record.
        tool_name: Tool the schema belongs to, for the log record.
        field: Which schema is being measured, for the log record.

    Returns:
        bool: ``True`` when the schema is absent or within
        :data:`MAX_SCHEMA_BYTES`.
    """
    if schema is None:
        return True
    size = len(canonical_json(schema).encode("utf-8"))
    if size <= MAX_SCHEMA_BYTES:
        return True
    _logger.warning(
        "mcp_tool_schema_oversized",
        server_id=server_id,
        tool_name=tool_name,
        field=field,
        size_bytes=size,
        limit_bytes=MAX_SCHEMA_BYTES,
    )
    return False


def build_entry(tool: Tool, server_id: str) -> McpToolEntry | None:
    """Convert one SDK tool record into a catalog entry.

    Args:
        tool: The tool as the SDK parsed it.
        server_id: The server that published it.

    Returns:
        McpToolEntry | None: The entry, or ``None`` when the tool must be
        dropped because its name is malformed or a schema is oversized. A
        dropped tool never fails the whole listing: the remaining tools stay
        usable and the drop is logged.
    """
    if not TOOL_NAME_PATTERN.match(tool.name):
        _logger.warning("mcp_tool_name_rejected", server_id=server_id, tool_name=tool.name[:128])
        return None
    if not _schema_within_bounds(tool.input_schema, server_id=server_id, tool_name=tool.name, field="inputSchema"):
        return None
    if not _schema_within_bounds(tool.output_schema, server_id=server_id, tool_name=tool.name, field="outputSchema"):
        return None
    return McpToolEntry(
        name=tool.name,
        canonical_name=to_canonical_name(server_id, tool.name),
        title=tool.title,
        description=truncate_description(tool.description or ""),
        input_schema=dict(tool.input_schema),
        output_schema=dict(tool.output_schema) if tool.output_schema is not None else None,
        annotations=tool.annotations,
    )


def build_catalog(
    tools: Sequence[Tool],
    server_id: str,
    *,
    ttl_ms: int | None = None,
    cache_scope: str | None = None,
    fetched_at: datetime | None = None,
) -> McpToolCatalog:
    """Assemble a catalog from a server's tool records.

    Args:
        tools: The tools the server returned, in server order.
        server_id: The server that returned them.
        ttl_ms: The server's freshness hint, or ``None``.
        cache_scope: The server's cache scope hint, or ``None``.
        fetched_at: Retrieval time, defaulting to now.

    Returns:
        McpToolCatalog: The assembled listing, capped at
        :data:`MAX_TOOLS_PER_SERVER`.

    Raises:
        McpProtocolError: If the server published the same tool name twice,
            which would make routing ambiguous.
    """
    entries: list[McpToolEntry] = []
    seen: set[str] = set()
    for tool in tools:
        if len(entries) >= MAX_TOOLS_PER_SERVER:
            _logger.warning(
                "mcp_tool_listing_capped",
                server_id=server_id,
                kept=len(entries),
                limit=MAX_TOOLS_PER_SERVER,
            )
            break
        entry = build_entry(tool, server_id)
        if entry is None:
            continue
        if entry.name in seen:
            message = f"server '{server_id}': {_ERR_DUPLICATE_TOOL} ({entry.name!r})"
            raise McpProtocolError(message)
        seen.add(entry.name)
        entries.append(entry)

    frozen = tuple(entries)
    return McpToolCatalog(
        server_id=server_id,
        entries=frozen,
        generation=compute_generation(frozen),
        fetched_at=fetched_at if fetched_at is not None else datetime.now(tz=UTC),
        ttl_ms=ttl_ms,
        cache_scope=cache_scope,
    )


async def fetch_catalog(client: Client, server_id: str) -> McpToolCatalog:
    """Retrieve a server's complete tool listing.

    Pagination is followed to exhaustion, preserving the order the server
    returned tools in. The freshness hints are taken from the first page,
    which is the one a cached re-list would be served from.

    Args:
        client: A connected MCP client.
        server_id: The server's configured id.

    Returns:
        McpToolCatalog: The complete listing.

    Raises:
        McpProtocolError: If the server repeats a cursor, exceeds
            :data:`MAX_LIST_PAGES`, or publishes a duplicate tool name.
    """
    tools: list[Tool] = []
    cursor: str | None = None
    ttl_ms: int | None = None
    cache_scope: str | None = None
    seen_cursors: set[str] = set()

    for page in range(MAX_LIST_PAGES):
        result = await client.list_tools(cursor=cursor)
        if page == 0:
            ttl_ms = result.ttl_ms
            cache_scope = result.cache_scope
        tools.extend(result.tools)
        cursor = result.next_cursor
        if cursor is None:
            break
        if cursor in seen_cursors:
            message = f"server '{server_id}' repeated pagination cursor {cursor!r}; refusing to loop"
            raise McpProtocolError(message)
        seen_cursors.add(cursor)
    else:
        message = f"server '{server_id}' did not finish listing tools within {MAX_LIST_PAGES} pages"
        raise McpProtocolError(message)

    catalog = build_catalog(tools, server_id, ttl_ms=ttl_ms, cache_scope=cache_scope)
    _logger.info(
        "mcp_catalog_fetched",
        server_id=server_id,
        tool_count=catalog.tool_count,
        generation=catalog.generation,
        pages=len(seen_cursors) + 1,
        ttl_ms=ttl_ms,
    )
    return catalog
