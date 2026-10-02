# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""The SDK client, declaring exactly the client capabilities Intellicrack implements on each protocol generation.

Which capabilities a client declares follows from the callbacks it is built with: ``sampling`` with a sampling callback, ``elicitation``
(form and URL, both of which Intellicrack answers) with an elicitation callback, ``roots`` with a roots callback. On 2025-11-25 they are
sent once, with ``initialize``; on 2026-07-28 they ride every request's ``_meta``.

The SDK's session declares ``roots`` as ``{"listChanged": true}`` on every generation. ``listChanged`` exists only through 2025-11-25:
2026-07-28 has no ``notifications/roots/list_changed``, because a server there asks for roots with each request that needs them, so
declaring it there promises a notification no client can send. :class:`McpClient` builds its session from
:class:`PreciseClientSession`, which declares ``roots`` as the empty object 2026-07-28 defines, and leaves every other declaration as the
SDK makes it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast, override

import anyio.lowlevel
from mcp import Client
from mcp.client.session import ClientSession
from mcp_types import ClientCapabilities, RootsCapability, ServerNotification
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from intellicrack.core.untrusted_text import clean_untrusted_label


if TYPE_CHECKING:
    from contextlib import AsyncExitStack

    from mcp.client.caching import ClientResponseCache
    from mcp.client.session import IncomingMessage, MessageHandlerFnT
    from pydantic import BaseModel


class PreciseClientSession(ClientSession):
    """A client session whose capability declaration matches the negotiated protocol generation."""

    @override
    def _build_capabilities(self, version: str) -> ClientCapabilities:
        """Build the capabilities declared on a wire speaking ``version``.

        Args:
            version: The protocol version being spoken.

        Returns:
            ClientCapabilities: The SDK's declaration, with ``roots`` reduced
            to the empty object on 2026-07-28.
        """
        declared = super()._build_capabilities(version)
        if declared.roots is not None and version in MODERN_PROTOCOL_VERSIONS:
            return declared.model_copy(update={"roots": RootsCapability()})
        return declared

    def declared_capabilities(self) -> ClientCapabilities | None:
        """Report the capabilities this session declares on the protocol it negotiated.

        Returns:
            ClientCapabilities | None: The declaration, or ``None`` before a
            protocol version was negotiated.
        """
        version = self.protocol_version
        return self._build_capabilities(version) if version is not None else None


class McpClient(Client):
    """The SDK client, speaking through a :class:`PreciseClientSession`."""

    @override
    async def _build_session(self, exit_stack: AsyncExitStack) -> ClientSession:
        """Enter the transport and build the session that will speak over it.

        Args:
            exit_stack: The stack the transport is entered on.

        The session is wired exactly as the SDK wires its own, including the
        response cache's eviction on the server's change notifications.

        Returns:
            ClientSession: The session, not yet entered.
        """
        dispatcher = await self._connect(exit_stack, self.mode, self.raise_exceptions)
        cache = self._response_cache
        message_handler = self.message_handler if cache is None else _evicting(cache, self.message_handler)
        return PreciseClientSession(
            dispatcher=dispatcher,
            read_timeout_seconds=self.read_timeout_seconds,
            sampling_callback=self.sampling_callback,
            sampling_capabilities=self.sampling_capabilities,
            list_roots_callback=self.list_roots_callback,
            logging_callback=self.logging_callback,
            log_level=self.log_level,
            message_handler=message_handler,
            client_info=self.client_info,
            elicitation_callback=self.elicitation_callback,
            extensions=self._folded_extensions.ad,
            result_claims=self._folded_extensions.claims,
            notification_bindings=self._folded_extensions.bindings,
        )


def _evicting(cache: ClientResponseCache, handler: MessageHandlerFnT | None) -> MessageHandlerFnT:
    """Evict the cached responses a server notification makes stale, then hand the message on.

    The cache is the SDK's in-memory store, which Intellicrack never
    replaces, so eviction is a dictionary update that has nothing to fail on.

    Args:
        cache: The client's response cache.
        handler: The connection's own message handler, or ``None``.

    Returns:
        MessageHandlerFnT: The wrapping handler.
    """

    async def _handle(message: IncomingMessage) -> None:
        """Evict what a notification makes stale, then deliver the message.

        Args:
            message: What the server sent.
        """
        if isinstance(message, ServerNotification):
            await cache.evict_for_notification(message)
        if handler is not None:
            await handler(message)
        else:
            await anyio.lowlevel.checkpoint()

    return _handle


def describe_capabilities(capabilities: BaseModel) -> tuple[str, ...]:
    """Render a capability declaration as one short line per capability.

    Args:
        capabilities: A client's or server's capability declaration.

    Returns:
        tuple[str, ...]: Each declared capability, followed by the flags and
        sub-capabilities it declares, such as ``resources (subscribe,
        listChanged)``; a flag declared false is left out.
    """
    declared: dict[str, object] = capabilities.model_dump(mode="json", by_alias=True, exclude_none=True)
    lines: list[str] = []
    for name, value in declared.items():
        if not isinstance(value, dict):
            continue
        details = cast("dict[str, object]", value)
        if name in {"experimental", "extensions"}:
            if details:
                lines.append(f"{name}: {', '.join(clean_untrusted_label(key) for key in details)}")
            continue
        features = [clean_untrusted_label(key) for key, flag in details.items() if flag is not False]
        lines.append(f"{name} ({', '.join(features)})" if features else name)
    return tuple(lines)
