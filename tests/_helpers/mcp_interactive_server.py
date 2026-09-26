# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real MCP server that asks its client things, run as a subprocess by the gates.

Built on the SDK's own :class:`~mcp.server.mcpserver.MCPServer` and spoken to
over a real stdio pipe. Its tool pauses mid-call to elicit an answer from the
operator, and it publishes a prompt template with a required argument, which
together exercise every path by which a server reaches the operator rather
than the model.

Run it as ``python mcp_interactive_server.py``.
"""

from __future__ import annotations

import sys
from typing import Annotated

from mcp.server.mcpserver import Elicit, ElicitationResult, MCPServer, Resolve
from pydantic import BaseModel, Field


ASK_TOOL_NAME = "ask_name"
"""The tool that elicits a name from the operator before answering."""

GREETING_TOOL_NAME = "greet"
"""A tool that answers immediately."""

REVIEW_PROMPT_NAME = "review"
"""A prompt template taking one required and one optional argument."""


class NameAnswer(BaseModel):
    """The form the eliciting tool asks the operator to fill in.

    Attributes:
        name: The name to greet.
    """

    name: str = Field(description="Who to greet")


def ask() -> Elicit[NameAnswer]:
    """Request the name from the operator.

    Returns:
        Elicit[NameAnswer]: The elicitation the framework sends.
    """
    return Elicit("Who should be greeted?", NameAnswer)


def ask_name(answer: Annotated[ElicitationResult[NameAnswer], Resolve(ask)]) -> str:
    """Greet the name the operator gave.

    Args:
        answer: The operator's answer to the elicitation.

    Returns:
        str: The greeting, or what the operator answered instead.
    """
    if answer.action == "accept":
        return f"hello {answer.data.name}"
    return f"operator answered {answer.action}"


def build_server() -> MCPServer:
    """Build the interactive server.

    Returns:
        MCPServer: A server publishing an eliciting tool and a prompt.
    """
    server = MCPServer(name="interactive", version="1.0.0")

    def greet(name: str) -> str:
        """Greet someone.

        Args:
            name: Who to greet.

        Returns:
            str: The greeting.
        """
        return f"hello {name}"

    def review(target: str, focus: str = "everything") -> str:
        """Build a review request.

        Args:
            target: What to review.
            focus: What to pay attention to.

        Returns:
            str: The request text.
        """
        return f"Review {target}, paying attention to {focus}."

    server.add_tool(ask_name, name=ASK_TOOL_NAME, description="Ask the operator for a name.")
    server.add_tool(greet, name=GREETING_TOOL_NAME, description="Greet someone.")
    _ = server.prompt(name=REVIEW_PROMPT_NAME, title="Review", description="Ask for a review.")(review)
    return server


def main() -> int:
    """Serve the interactive server over stdio.

    Returns:
        int: Process exit status.
    """
    build_server().run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
