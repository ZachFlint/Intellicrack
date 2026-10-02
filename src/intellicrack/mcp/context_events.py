# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""What a server says has changed about its resources and prompts.

A server announces that its list of resources or of prompts changed, and that a resource a client subscribed to was updated. On
2025-11-25 these arrive as ``notifications/resources/list_changed``, ``notifications/prompts/list_changed`` and
``notifications/resources/updated``; on 2026-07-28 as events on the ``subscriptions/listen`` stream, which carries the client's
resource subscriptions in its filter. Either way a connection hands each one on as a :class:`McpContextEvent`.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass


class McpContextChange(enum.StrEnum):
    """What changed.

    Attributes:
        RESOURCES_LISTED: The server's list of resources changed.
        PROMPTS_LISTED: The server's list of prompts changed.
        RESOURCE_UPDATED: A resource the client subscribed to was updated.
    """

    RESOURCES_LISTED = "resources_listed"
    PROMPTS_LISTED = "prompts_listed"
    RESOURCE_UPDATED = "resource_updated"


@dataclass(frozen=True, slots=True)
class McpContextEvent:
    """One change a server announced.

    Attributes:
        server_id: The server.
        change: What changed.
        uri: The updated resource's URI exactly as the server sent it, for
            :attr:`McpContextChange.RESOURCE_UPDATED`; ``None`` otherwise.
    """

    server_id: str
    change: McpContextChange
    uri: str | None = None


type McpContextListener = Callable[[McpContextEvent], None]
"""Receives each change a server announces."""
