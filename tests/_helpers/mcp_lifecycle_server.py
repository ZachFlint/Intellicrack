# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real MCP server whose lifecycle the connection gates can steer.

Built on the SDK's own :class:`~mcp.server.mcpserver.MCPServer` and served
over stdio, legacy SSE or Streamable HTTP, it exposes tools that make the
process exit cleanly, crash mid-call, report its own process id, and publish
a new tool together with a ``tools/list_changed`` notification. A
``--ttl-ms`` option attaches a freshness hint to its tool listing.

Run it as ``python mcp_lifecycle_server.py --transport <stdio|http|sse>``.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING

import uvicorn
from mcp.server import CacheHint
from mcp.server.mcpserver import Context, MCPServer


if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp.server.caching import CacheableMethod


CLEAN_EXIT_DELAY_S = 0.3
"""How long the ``quit`` tool waits before exiting, so its own reply is sent."""

CRASH_EXIT_CODE = 9
"""Exit status of the ``crash`` tool."""

GROWN_TOOL_PREFIX = "grown_"
"""Prefix of every tool the ``grow`` tool adds."""


def _spawn_sleeper() -> int:
    """Start a grandchild that sleeps far longer than any gate runs.

    Returns:
        int: The grandchild's process id.
    """
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(600)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return child.pid


def build_server(ttl_ms: int) -> MCPServer:
    """Build the steerable server.

    Args:
        ttl_ms: Freshness hint attached to ``tools/list``; ``0`` for none.

    Returns:
        MCPServer: The server.
    """
    hints: dict[CacheableMethod, CacheHint] = {}
    if ttl_ms > 0:
        hints["tools/list"] = CacheHint(ttl_ms=ttl_ms, scope="private")
    server = MCPServer(name="lifecycle", version="1.0.0", cache_hints=hints)
    grown: list[str] = []

    def whoami() -> str:
        """Report this server's process id.

        Returns:
            str: The process id as text.
        """
        return str(os.getpid())

    def quit_cleanly() -> str:
        """Exit with status zero shortly after replying.

        Returns:
            str: A fixed marker, sent before the process exits.
        """
        sys.stdout.flush()
        timer = threading.Timer(CLEAN_EXIT_DELAY_S, os._exit, args=(0,))
        timer.daemon = True
        timer.start()
        return "leaving"

    def crash() -> str:
        """Kill the process before any reply can be written.

        Returns:
            str: Never returns.
        """
        os._exit(CRASH_EXIT_CODE)

    async def grow(ctx: Context) -> str:
        """Publish one more tool and announce that the listing changed.

        Args:
            ctx: The request context, used to send the change notification.

        Returns:
            str: The new tool's name.
        """
        name = f"{GROWN_TOOL_PREFIX}{len(grown)}"
        grown.append(name)

        def grown_tool() -> str:
            """Report that a grown tool ran.

            Returns:
                str: A fixed marker.
            """
            return "grown ok"

        server.add_tool(grown_tool, name=name, description="A tool added at runtime.")
        await ctx.notify_tools_changed()
        await ctx.request_context.session.send_tool_list_changed()
        return name

    def env_keys() -> str:
        """Report the names of every environment variable this process received.

        Returns:
            str: The names, sorted and newline-separated.
        """
        return "\n".join(sorted(os.environ))

    def write_probe(path: str) -> str:
        """Try to create a file, reporting whether the write was allowed.

        Args:
            path: The file to create.

        Returns:
            str: ``written`` on success, else ``denied:`` and the error.
        """
        try:
            Path(path).write_text("probe", encoding="utf-8")
        except OSError as exc:
            return f"denied: {exc}"
        return "written"

    def spawn_child() -> str:
        """Start a long-lived grandchild process.

        Returns:
            str: The grandchild's process id.
        """
        return str(_spawn_sleeper())

    server.add_tool(whoami, name="whoami", description="Report the server process id.")
    server.add_tool(env_keys, name="env_keys", description="List environment variable names.")
    server.add_tool(write_probe, name="write_probe", description="Try to write a file.")
    server.add_tool(spawn_child, name="spawn_child", description="Spawn a long-lived grandchild.")
    server.add_tool(quit_cleanly, name="quit", description="Exit cleanly.")
    server.add_tool(crash, name="crash", description="Crash mid-call.")
    server.add_tool(grow, name="grow", description="Add a tool and announce it.")
    return server


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the steerable server over the requested transport.

    Args:
        argv: Command-line arguments, defaulting to ``sys.argv[1:]``.

    Returns:
        int: Process exit status.
    """
    parser = argparse.ArgumentParser(description="A steerable MCP server for the connection gates.")
    parser.add_argument("--transport", choices=("stdio", "http", "sse"), default="stdio")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--ttl-ms", type=int, default=0)
    parser.add_argument("--spawn-at-start", default=None, help="Spawn a grandchild before serving and write its pid here.")
    arguments = parser.parse_args(argv)

    if arguments.spawn_at_start is not None:
        Path(arguments.spawn_at_start).write_text(str(_spawn_sleeper()), encoding="utf-8")
    server = build_server(arguments.ttl_ms)
    if arguments.transport == "http":
        uvicorn.run(server.streamable_http_app(), host="127.0.0.1", port=arguments.port, log_level="error")
        return 0
    if arguments.transport == "sse":
        uvicorn.run(server.sse_app(), host="127.0.0.1", port=arguments.port, log_level="error")
        return 0
    server.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
