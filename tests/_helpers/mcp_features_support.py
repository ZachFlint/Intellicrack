# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Connects Intellicrack's real MCP connection to the client-features fixture server on either protocol generation.

A stdio connection negotiates 2026-07-28, where server-to-client requests ride ``InputRequiredResult`` and logging is opted into per
request; an SSE connection runs the 2025-11-25 handshake, where the same features are standalone requests and ``logging/setLevel``. The
gates run each feature over both.
"""

from __future__ import annotations

import enum
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind, StdioServerSpec
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.consent import McpConsentGate, TrustStore
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_http_process import running_server


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from intellicrack.mcp.client_hooks import McpClientHooks
    from intellicrack.mcp.consent import DangerousPattern


FEATURES_SERVER_SCRIPT: Final[Path] = Path(__file__).resolve().parent / "mcp_features_server.py"
CONNECT_TIMEOUT_S: Final[float] = 60.0


class Era(enum.Enum):
    """A protocol generation, and the transport that reaches it.

    Attributes:
        MODERN: 2026-07-28, over stdio.
        LEGACY: 2025-11-25, over SSE.
    """

    MODERN = "2026-07-28"
    LEGACY = "2025-11-25"

    def accepts(self, version: str | None) -> bool:
        """Report whether a negotiated version belongs to this generation.

        Args:
            version: The negotiated protocol version.

        Returns:
            bool: ``True`` when it does.
        """
        versions = MODERN_PROTOCOL_VERSIONS if self is Era.MODERN else HANDSHAKE_PROTOCOL_VERSIONS
        return version in versions


def approve_every_launch(_config: McpServerConfig, _rendered: str, _findings: list[DangerousPattern]) -> bool:
    """Approve every launch.

    Args:
        _config: The server being launched.
        _rendered: The rendered launch description.
        _findings: Flagged patterns.

    Returns:
        bool: Always ``True``.
    """
    return True


def features_config(era: Era, *, server_id: str = "features", port: int | None = None, log_level: str | None = None) -> McpServerConfig:
    """Configure the fixture server for one protocol generation.

    Args:
        era: The generation.
        server_id: The configured id.
        port: The SSE port, for the legacy generation.
        log_level: The log level to ask for.

    Returns:
        McpServerConfig: The configuration.
    """
    if era is Era.MODERN:
        spec = StdioServerSpec(command=sys.executable, args=(str(FEATURES_SERVER_SCRIPT),))
        return McpServerConfig(
            server_id=server_id,
            kind=McpTransportKind.STDIO,
            stdio=spec,
            enabled=True,
            request_timeout_s=60.0,
            log_level=log_level,
        )
    http = HttpServerSpec(url=f"http://127.0.0.1:{port}/sse")
    return McpServerConfig(
        server_id=server_id,
        kind=McpTransportKind.SSE,
        http=http,
        enabled=True,
        request_timeout_s=60.0,
        log_level=log_level,
    )


def private_resolver(directory: Path) -> McpSecretResolver:
    """Build a secret resolver over a private ``.env``.

    Args:
        directory: Where the ``.env`` lives.

    Returns:
        McpSecretResolver: The resolver.
    """
    return McpSecretResolver(CredentialStore(fallback_loader=CredentialLoader(env_path=directory / ".env")))


@asynccontextmanager
async def features_connection(
    directory: Path,
    era: Era,
    *,
    hooks: McpClientHooks | None = None,
    log_level: str | None = None,
    server_id: str = "features",
) -> AsyncGenerator[McpConnection]:
    """Connect to the fixture server on one protocol generation, and disconnect afterwards.

    Args:
        directory: Per-test directory for the trust store and ``.env``.
        era: The protocol generation.
        hooks: The client-side features to offer.
        log_level: The log level to ask for.
        server_id: The configured id.

    Yields:
        McpConnection: The connected connection, on the requested generation.
    """
    async with AsyncExitStack() as stack:
        port = stack.enter_context(running_server(FEATURES_SERVER_SCRIPT, "--transport", "sse")) if era is Era.LEGACY else None
        config = features_config(era, server_id=server_id, port=port, log_level=log_level)
        connection = McpConnection(
            config,
            private_resolver(directory),
            consent=McpConsentGate(TrustStore(directory / "trust.json"), approve_every_launch),
            hooks=hooks,
        )
        await connection.connect()
        try:
            client = connection.client
            assert client is not None
            assert era.accepts(client.protocol_version), f"negotiated {client.protocol_version}, wanted {era.value}"
            yield connection
        finally:
            await connection.disconnect()
