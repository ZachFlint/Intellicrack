# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real MCP server whose tool listing changes while the client is still reading it.

Built on the SDK's :class:`~mcp.server.mcpserver.MCPServer` and served over the legacy HTTP+SSE transport, so the client speaks
2025-11-25 and learns of listing changes only through ``notifications/tools/list_changed``. The first ``tools/list`` it answers is the
listing as it stood; before answering it adds a tool and sends that notice, so the notice reaches the client while its first listing is
still in flight. A client that drops a notice received during its handshake never learns of the added tool.

Run it as ``python mcp_racing_list_server.py --port N``.
"""

from __future__ import annotations

import argparse
import sys
from typing import TYPE_CHECKING, Final, override

import uvicorn
from mcp.server.mcpserver import MCPServer


if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp.server.context import ServerRequestContext
    from mcp_types import ListToolsResult, PaginatedRequestParams


FIRST_TOOL_NAME: Final[str] = "first"
"""The tool published from the start."""

LATE_TOOL_NAME: Final[str] = "late"
"""The tool added while the first listing is being answered."""


def first() -> str:
    """Answer from the first tool.

    Returns:
        str: A fixed marker.
    """
    return "first ok"


def late() -> str:
    """Answer from the late tool.

    Returns:
        str: A fixed marker.
    """
    return "late ok"


class RacingListServer(MCPServer):
    """Adds a tool and announces it while answering its first listing."""

    def __init__(self) -> None:
        """Publish the first tool only."""
        super().__init__(name="racing-list", version="1.0.0")
        self.add_tool(first, name=FIRST_TOOL_NAME, description="Published from the start.")
        self._grown = False

    @override
    async def _handle_list_tools(self, ctx: ServerRequestContext[object], params: PaginatedRequestParams | None) -> ListToolsResult:
        """Answer the listing as it stands, adding a tool and announcing it first on the first request.

        Args:
            ctx: The request context, used to send the change notice.
            params: The pagination parameters.

        Returns:
            ListToolsResult: The listing as it stood when the request arrived.
        """
        answer = await super()._handle_list_tools(ctx, params)
        if not self._grown:
            self._grown = True
            self.add_tool(late, name=LATE_TOOL_NAME, description="Added during the first listing.")
            await ctx.session.send_tool_list_changed()
        return answer


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the racing server over legacy SSE on loopback.

    Args:
        argv: Command-line arguments, defaulting to ``sys.argv[1:]``.

    Returns:
        int: Process exit status.
    """
    parser = argparse.ArgumentParser(description="An MCP server whose listing changes during the first tools/list.")
    parser.add_argument("--port", type=int, required=True)
    arguments = parser.parse_args(argv)
    uvicorn.run(RacingListServer().sse_app(), host="127.0.0.1", port=arguments.port, log_level="error")
    return 0


if __name__ == "__main__":
    sys.exit(main())
