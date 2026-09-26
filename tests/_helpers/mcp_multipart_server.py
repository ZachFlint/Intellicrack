# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real MCP server answering with multi-part, error and malformed results.

Built on the SDK's low-level :class:`~mcp.server.lowlevel.Server` rather than
``MCPServer``, because ``MCPServer`` validates a tool's structured output
before sending it and so cannot play a server that breaks its own
``outputSchema``. It is spoken to over a real stdio pipe.

Run it as ``python mcp_multipart_server.py``.
"""

from __future__ import annotations

import base64
import struct
import sys
import zlib
from typing import TYPE_CHECKING, Final

import anyio
import mcp_types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError


if TYPE_CHECKING:
    from mcp.server.context import ServerRequestContext


IMAGE_WIDTH: Final[int] = 640
"""Width of the PNG the ``snapshot`` tool returns."""

IMAGE_HEIGHT: Final[int] = 480
"""Height of the PNG the ``snapshot`` tool returns."""

ERROR_DETAIL: Final[str] = "disk quota exceeded while writing /var/data/export.bin " + "x" * 2000
"""Text the ``fail`` tool reports, deliberately longer than any old truncation."""

STRUCTURED_REPORT: Final[dict[str, object]] = {"count": 3, "labels": ["a", "b", "c"]}
"""Structured content the ``report`` tool returns, matching its schema."""

CONTROL_TEXT: Final[str] = "clean\x1b[31mred\x07bell\u202eevil"
"""Text carrying terminal escapes, a bell and a bidirectional override."""

BIG_TEXT_CHARS: Final[int] = 50_000
"""Length of the text the ``big`` tool returns, far past the context bound."""

STALL_SECONDS: Final[float] = 30.0
"""How long the ``stall`` tool blocks, longer than any gate's timeout."""

_COUNT_SCHEMA: Final[dict[str, object]] = {
    "type": "object",
    "properties": {"count": {"type": "integer"}, "labels": {"type": "array", "items": {"type": "string"}}},
    "required": ["count"],
}


def build_png(width: int, height: int) -> bytes:
    """Encode a solid grey PNG of the requested size.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.

    Returns:
        bytes: A valid PNG file.
    """

    def chunk(kind: bytes, payload: bytes) -> bytes:
        """Frame one PNG chunk with its length and CRC.

        Args:
            kind: Four-byte chunk type.
            payload: Chunk data.

        Returns:
            bytes: The framed chunk.
        """
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    rows = b"".join(b"\x00" + b"\x80" * width for _ in range(height))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b"")


def _tools() -> list[types.Tool]:
    """Describe every tool this server publishes.

    Returns:
        list[types.Tool]: The published tools.
    """
    empty: dict[str, object] = {"type": "object", "properties": {}}
    return [
        types.Tool(name="snapshot", description="Return a caption, an image and structured data.", input_schema=empty),
        types.Tool(name="fail", description="Report a tool-level failure.", input_schema=empty),
        types.Tool(name="fail_silently", description="Report failure with no content at all.", input_schema=empty),
        types.Tool(name="report", description="Structured output matching the schema.", input_schema=empty, output_schema=_COUNT_SCHEMA),
        types.Tool(name="lie", description="Structured output breaking the schema.", input_schema=empty, output_schema=_COUNT_SCHEMA),
        types.Tool(
            name="strict",
            description="Reject arguments at the protocol level.",
            input_schema={"type": "object", "properties": {"n": {"type": "integer"}}, "required": ["n"]},
        ),
        types.Tool(name="controls", description=f"Description with {CONTROL_TEXT}", input_schema=empty),
        types.Tool(name="stall", description="Block far longer than any client timeout.", input_schema=empty),
        types.Tool(name="big", description="Return a very long text result.", input_schema=empty),
    ]


async def _list_tools(_ctx: ServerRequestContext[object], _params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
    """Answer ``tools/list``.

    Args:
        _ctx: Request context.
        _params: Pagination parameters.

    Returns:
        types.ListToolsResult: Every tool.
    """
    await anyio.lowlevel.checkpoint()
    return types.ListToolsResult(tools=_tools())


async def _call_tool(_ctx: ServerRequestContext[object], params: types.CallToolRequestParams) -> types.CallToolResult:
    """Answer ``tools/call`` with the result the named tool is built to give.

    Args:
        _ctx: Request context.
        params: The call.

    Returns:
        types.CallToolResult: The tool's result.

    Raises:
        MCPError: For the ``strict`` tool when its argument is missing or not
            an integer, and for a tool this server does not publish, as a
            JSON-RPC invalid-params error.
    """
    name = params.name
    if name == "snapshot":
        image = base64.b64encode(build_png(IMAGE_WIDTH, IMAGE_HEIGHT)).decode("ascii")
        return types.CallToolResult(
            content=[
                types.TextContent(type="text", text="caption: grey frame"),
                types.ImageContent(type="image", data=image, mime_type="image/png"),
            ],
            structured_content={"frame": 1},
        )
    if name == "fail":
        return types.CallToolResult(content=[types.TextContent(type="text", text=ERROR_DETAIL)], is_error=True)
    if name == "fail_silently":
        return types.CallToolResult(content=[], is_error=True)
    if name == "report":
        return types.CallToolResult(content=[types.TextContent(type="text", text="3 labels")], structured_content=STRUCTURED_REPORT)
    if name == "lie":
        return types.CallToolResult(content=[types.TextContent(type="text", text="bad")], structured_content={"count": "three"})
    if name == "strict":
        value = (params.arguments or {}).get("n")
        if not isinstance(value, int):
            raise MCPError(code=types.INVALID_PARAMS, message="argument 'n' must be an integer")
        return types.CallToolResult(content=[types.TextContent(type="text", text=str(value * 2))])
    if name == "controls":
        return types.CallToolResult(content=[types.TextContent(type="text", text=CONTROL_TEXT)])
    if name == "big":
        return types.CallToolResult(content=[types.TextContent(type="text", text="z" * BIG_TEXT_CHARS)])
    if name == "stall":
        await anyio.sleep(STALL_SECONDS)
        return types.CallToolResult(content=[types.TextContent(type="text", text="finally")])
    raise MCPError(code=types.INVALID_PARAMS, message=f"unknown tool {name!r}")


async def _serve() -> None:
    """Serve the tools over stdio until the client disconnects."""
    server: Server[object] = Server("multipart", version="1.0.0", on_list_tools=_list_tools, on_call_tool=_call_tool)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> int:
    """Run the server.

    Returns:
        int: Process exit status.
    """
    anyio.run(_serve)
    return 0


if __name__ == "__main__":
    sys.exit(main())
