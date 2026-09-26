# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""What a server's tools cost, and which of them the operator has turned on.

Advertising a tool is not free: its name, description and argument schema all occupy the same context window the conversation does. A server
with three hundred tools would consume the budget before the first message. This module prices a tool so the settings dialog can show what
enabling it costs, and resolves which tools a server is actually allowed to contribute.

Token counting goes through :mod:`intellicrack.core.token_encoding`, which loads the encoding on a background thread with a bounded
download, so pricing a server's tools from the settings dialog never waits on the network. A caller that already has the active model's
own counter can inject it.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from intellicrack.core import token_encoding


if TYPE_CHECKING:
    from intellicrack.core.types import ToolFunction
    from intellicrack.mcp.catalog import McpToolCatalog, McpToolEntry
    from intellicrack.mcp.config import McpServerConfig


DEFAULT_ENCODING_NAME: Final[str] = token_encoding.DEFAULT_ENCODING_NAME
"""Encoding used when the caller supplies no model-specific counter."""

TokenCounter = Callable[[str], int]
"""Counts the tokens in a string."""


def _default_counter(text: str) -> int:
    """Count tokens with the default encoding, never waiting for it to load.

    The settings dialog prices tools on the GUI thread, so this never
    blocks: until the shared loader has the encoding, the count is the
    overestimate :func:`~intellicrack.core.token_encoding.estimate_tokens_without_encoder`
    gives, which errs toward warning the operator off rather than toward a
    prompt that silently overflows.

    Args:
        text: The text to count.

    Returns:
        int: The token count, exact once the encoding is loaded.
    """
    return token_encoding.count_tokens(text, DEFAULT_ENCODING_NAME, timeout=0.0)


@dataclass(frozen=True, slots=True)
class ToolCost:
    """What advertising one tool costs in context.

    Attributes:
        canonical_name: The tool this cost belongs to.
        schema_tokens: Tokens its argument schema occupies.
        description_tokens: Tokens its name and description occupy.
    """

    canonical_name: str
    schema_tokens: int
    description_tokens: int

    @property
    def total_tokens(self) -> int:
        """Total context this tool occupies when advertised.

        Returns:
            int: The sum of the schema and description costs.
        """
        return self.schema_tokens + self.description_tokens


def estimate_tool_cost(function: ToolFunction, counter: TokenCounter | None = None) -> ToolCost:
    """Price one tool definition against the context window.

    Args:
        function: The tool function as it would be advertised.
        counter: Token counter to use, defaulting to the shared encoding.

    Returns:
        ToolCost: The estimated cost of advertising ``function``.
    """
    count = counter if counter is not None else _default_counter
    schema = function.input_schema
    schema_text = json.dumps(schema, separators=(",", ":"), default=str) if schema else ""
    return ToolCost(
        canonical_name=function.name,
        schema_tokens=count(schema_text),
        description_tokens=count(f"{function.name}\n{function.description}\n{function.returns}"),
    )


def total_cost(costs: list[ToolCost]) -> int:
    """Sum the context cost of a set of tools.

    Args:
        costs: The per-tool costs.

    Returns:
        int: Total tokens the whole set occupies.
    """
    return sum(cost.total_tokens for cost in costs)


def enabled_entries(config: McpServerConfig, catalog: McpToolCatalog) -> tuple[McpToolEntry, ...]:
    """Resolve which of a server's tools may be advertised.

    A disabled server contributes nothing at all, which is the state every
    server starts in. An enabled server contributes every tool except those
    the operator has individually switched off.

    Args:
        config: The server's configuration.
        catalog: The server's current tool listing.

    Returns:
        tuple[McpToolEntry, ...]: The tools to advertise, in server order.
    """
    if not config.enabled:
        return ()
    if not config.disabled_tools:
        return catalog.entries
    return tuple(entry for entry in catalog.entries if entry.name not in config.disabled_tools)
