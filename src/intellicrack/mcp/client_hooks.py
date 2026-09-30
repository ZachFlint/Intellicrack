# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The client-side features one MCP connection offers its server.

Which callbacks a :class:`mcp.Client` is built with is what decides the capabilities it advertises: the SDK declares ``sampling`` only
when a sampling callback is installed, ``roots`` only with a roots callback, and so on, whichever protocol generation is negotiated.
A connection is therefore built from one :class:`McpClientHooks` per server, holding exactly the features Intellicrack implements and
has switched on for that server, and nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.client.session import ListRootsFnT, LoggingFnT, SamplingFnT
    from mcp_types import SamplingCapability

    from intellicrack.mcp.config import McpServerConfig


@dataclass(frozen=True, slots=True)
class McpClientHooks:
    """The callbacks one connection installs on its SDK client.

    Attributes:
        sampling: Answers ``sampling/createMessage``, or ``None`` when the
            server may not sample through Intellicrack, in which case the
            ``sampling`` capability is not advertised.
        sampling_capabilities: The sampling sub-capabilities advertised with
            ``sampling``, such as tool use.
        list_roots: Answers ``roots/list``, or ``None`` to advertise no roots.
        logging: Receives the server's ``notifications/message`` log records.
    """

    sampling: SamplingFnT | None = None
    sampling_capabilities: SamplingCapability | None = None
    list_roots: ListRootsFnT | None = None
    logging: LoggingFnT | None = None


type McpHooksFactory = Callable[[McpServerConfig], McpClientHooks]
"""Builds the hooks for one server from its configuration."""
