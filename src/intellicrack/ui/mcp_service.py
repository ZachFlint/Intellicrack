# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Assembles the Model Context Protocol client for the running application.

Everything MCP needs in order to work inside Intellicrack is wired here once:
the configuration store, the keyring-backed secret resolver, the trust and
approval stores, the consent gate and its dialogs, the connection manager, and
the tool source that registers every connected server into the tool registry.

The point of a single assembly is that the wiring is checkable in one place.
A tool source that was never registered would leave third-party tools
invisible; a classifier that was never installed would leave their calls
classified as unknown; an approval store that was never installed would leave
"always" silently unhonoured. Each of those is a quiet failure, so they are
all done together or not at all.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from intellicrack.core.logging import get_logger
from intellicrack.core.session import McpServerState
from intellicrack.mcp.auth import KeyringTokenStorage, build_oauth_provider, issuer_for
from intellicrack.mcp.config import McpConfigStore, is_mcp_namespace
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore
from intellicrack.mcp.errors import McpError
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import McpToolSource, source_label
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_bridge import QtMcpPrompts
from intellicrack.ui.mcp_config import McpConfigDialog


if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.session import Session
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.core.types import ToolCall
    from intellicrack.credentials.store import CredentialStore
    from intellicrack.mcp.config import McpServerConfig


_logger = get_logger(__name__)


_AUTHORIZATION_HEADER = "authorization"


class McpService:
    """Owns the MCP client for the life of the application window."""

    def __init__(
        self,
        tool_registry: ToolRegistry,
        credential_store: CredentialStore,
        orchestrator: Orchestrator,
        parent: QWidget | None = None,
    ) -> None:
        """Assemble every part of the MCP client and wire it in.

        Args:
            tool_registry: Registry connected servers register their tools
                into.
            credential_store: Keyring-backed store holding input values and
                OAuth artefacts.
            orchestrator: Orchestrator the tool source is installed on, so
                MCP calls classify and advertise correctly.
            parent: Widget the consent and elicitation dialogs are parented
                to.
        """
        self._orchestrator = orchestrator
        self._parent = parent
        self._store = McpConfigStore()
        self._resolver = McpSecretResolver(credential_store)
        self._trust = TrustStore()
        self._approvals = ApprovalStore()
        self._prompts = QtMcpPrompts(self._trust, parent)
        self._gate = McpConsentGate(
            self._trust,
            self._prompts.request_launch_consent,
            self._on_generation_change,
        )
        self._manager = McpConnectionManager(
            self._store,
            self._resolver,
            self._gate,
            elicitation_factory=self._prompts.elicitation_for,
            auth_factory=self._build_auth,
        )
        self._source = McpToolSource(self._manager, tool_registry)
        self._manager.set_change_listener(self._on_server_changed)
        ToolConfirmationDialog.set_approval_store(self._approvals)
        orchestrator.set_mcp_tool_source(self._source)
        _logger.info("mcp_service_assembled")

    @property
    def manager(self) -> McpConnectionManager:
        """The connection manager owning every server.

        Returns:
            McpConnectionManager: The manager.
        """
        return self._manager

    @property
    def tool_source(self) -> McpToolSource:
        """The tool source registered into the tool registry.

        Returns:
            McpToolSource: The source.
        """
        return self._source

    @property
    def resolver(self) -> McpSecretResolver:
        """The resolver expanding ``${input:id}`` references.

        Returns:
            McpSecretResolver: The resolver.
        """
        return self._resolver

    @property
    def approvals(self) -> ApprovalStore:
        """The store holding persisted per-tool approvals.

        Returns:
            ApprovalStore: The store.
        """
        return self._approvals

    def _build_auth(self, config: McpServerConfig) -> Any:  # noqa: ANN401
        """Build the authentication handler for one HTTP server.

        OAuth is attached only when the server carries no ``Authorization``
        header of its own. A configured header is already the credential, and
        layering an OAuth flow over it would replace what the operator asked
        to send.

        Args:
            config: The server, with its headers already resolved.

        Returns:
            Any: An ``httpx2`` auth handler, or ``None`` when the server
            authenticates some other way or not at all.
        """
        spec = config.http
        if spec is None:
            return None
        if any(name.lower() == _AUTHORIZATION_HEADER for name in spec.headers):
            _logger.debug("mcp_oauth_skipped_static_header", server_id=config.server_id)
            return None
        issuer = issuer_for(spec)
        storage = KeyringTokenStorage(self._resolver.store, config.server_id, issuer)
        try:
            return build_oauth_provider(spec, storage)
        except McpError as exc:
            _logger.warning("mcp_oauth_provider_unavailable", server_id=config.server_id, error=str(exc))
            return None

    def _on_generation_change(self, server_id: str, generation: str) -> None:
        """Discard remembered approvals for a server whose tools changed.

        Args:
            server_id: The server whose tool listing moved.
            generation: The new generation digest.
        """
        namespace = self._manager.document.server(server_id)
        key = namespace.namespace if namespace is not None else f"mcp-{server_id}"
        self._approvals.invalidate_namespace(key)
        ToolConfirmationDialog.clear_decisions_for_source(key)
        _logger.warning("mcp_approvals_reset_after_change", server_id=server_id, generation=generation)

    def _on_server_changed(self, server_id: str) -> None:
        """Record a server's current state onto the active session.

        Args:
            server_id: The server whose state moved.
        """
        session = self._orchestrator.current_session
        if session is None:
            return
        status = next((entry for entry in self._manager.statuses() if entry.server_id == server_id), None)
        if status is None:
            return
        session.set_mcp_server_state(
            McpServerState(
                server_id=status.server_id,
                health=status.health.value,
                tool_count=status.tool_count,
                generation=status.generation,
                last_error=status.last_error,
            ),
        )

    def record_session_state(self, session: Session) -> None:
        """Write every server's current state onto one session.

        Args:
            session: The session to record onto.
        """
        for status in self._manager.statuses():
            session.set_mcp_server_state(
                McpServerState(
                    server_id=status.server_id,
                    health=status.health.value,
                    tool_count=status.tool_count,
                    generation=status.generation,
                    last_error=status.last_error,
                ),
            )

    def generation_for(self, call: ToolCall) -> str | None:
        """Read the tool-listing generation a call belongs to.

        Args:
            call: The tool call about to be confirmed.

        Returns:
            str | None: The generation, or ``None`` for a bridge tool.
        """
        if not is_mcp_namespace(call.tool_name.strip().lower()):
            return None
        return self._source.generation_for(call.function_name)

    @staticmethod
    def source_label_for(call: ToolCall) -> str | None:
        """Render where a call's tool came from, for the confirmation dialog.

        Args:
            call: The tool call about to be confirmed.

        Returns:
            str | None: A phrase naming the server, or ``None`` for a bridge
            tool.
        """
        if not is_mcp_namespace(call.tool_name.strip().lower()):
            return None
        return source_label(call.function_name)

    async def start(self) -> None:
        """Connect every enabled server and register their tools.

        A failure to start one server never stops the rest, and never stops
        the application: the tool source is registered either way, so a
        server that comes up later is reachable without a restart.
        """
        try:
            await self._manager.start()
        except McpError as exc:
            _logger.warning("mcp_service_start_incomplete", error=str(exc))
        self._source.register_all()
        _logger.info("mcp_service_started", servers=len(self._manager.document.servers))

    async def stop(self) -> None:
        """Disconnect every server and unregister their tools.

        Runs before the background loop is torn down, so no server process
        outlives the application and no worker is left awaiting a stopped
        loop.
        """
        self._source.unregister_all()
        self._orchestrator.set_mcp_tool_source(None)
        with contextlib.suppress(McpError):
            await self._manager.stop()
        ToolConfirmationDialog.set_approval_store(None)
        _logger.info("mcp_service_stopped")

    def open_settings(self, parent: QWidget | None = None) -> None:
        """Show the MCP settings dialog.

        Args:
            parent: Widget to parent the dialog to, defaulting to the
                service's own parent.
        """
        dialog = McpConfigDialog(self._manager, self._resolver, parent if parent is not None else self._parent)
        dialog.refresh_auth_state()
        _ = dialog.exec()
        self._source.register_all()
