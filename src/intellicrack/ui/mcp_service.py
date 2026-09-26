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

Two threads meet here. The connection manager runs on the background event
loop and reports changes from it; the session, the remembered approvals and
every widget belong to the GUI thread. Every report that touches GUI-thread
state is therefore carried across by a queued signal and applied there, and
the tool registry the loop iterates is only ever changed on the loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
from typing import TYPE_CHECKING, cast

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QMessageBox

from intellicrack.core.logging import get_logger
from intellicrack.core.session import McpServerState
from intellicrack.mcp.auth import KeyringTokenStorage, build_oauth_provider, issuer_for, open_authorization_page
from intellicrack.mcp.config import McpConfigStore, is_mcp_namespace
from intellicrack.mcp.connection import McpConnectionManager
from intellicrack.mcp.consent import ApprovalStore, McpConsentGate, TrustStore, deny_all_launches
from intellicrack.mcp.errors import McpError
from intellicrack.mcp.secrets import McpSecretResolver
from intellicrack.mcp.tool_source import McpToolSource, source_label
from intellicrack.ui.confirmation_dialog import ToolConfirmationDialog
from intellicrack.ui.mcp_bridge import QtMcpPrompts, elicitation_factory
from intellicrack.ui.mcp_config import McpConfigDialog
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    import httpx2
    from PyQt6.QtWidgets import QWidget

    from intellicrack.core.orchestrator import Orchestrator
    from intellicrack.core.session import Session
    from intellicrack.core.tools import ToolRegistry
    from intellicrack.core.types import ToolCall
    from intellicrack.credentials.store import CredentialStore
    from intellicrack.mcp.config import McpServerConfig
    from intellicrack.mcp.connection import McpServerStatus


_logger = get_logger(__name__)


_AUTHORIZATION_HEADER = "authorization"


def _state_of(status: McpServerStatus) -> McpServerState:
    """Snapshot a server's live status as the state a session records.

    Args:
        status: The server's current status.

    Returns:
        McpServerState: The session record.
    """
    return McpServerState(
        server_id=status.server_id,
        health=status.health.value,
        tool_count=status.tool_count,
        generation=status.generation,
        last_error=status.last_error,
    )


class _GuiThreadRelay(QObject):
    """Carries reports from the background loop onto the GUI thread.

    Created on the GUI thread, so a signal emitted from the loop's thread is
    queued and its slot runs on the GUI thread.
    """

    generation_changed = pyqtSignal(str, str)
    server_state_changed = pyqtSignal(object)
    sign_in_opened = pyqtSignal(str, str)


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
        self._relay = _GuiThreadRelay(parent)
        _ = self._relay.generation_changed.connect(self._apply_generation_change)
        _ = self._relay.server_state_changed.connect(self._apply_server_state)
        _ = self._relay.sign_in_opened.connect(self._show_sign_in_notice)
        self._prompts = QtMcpPrompts(parent)
        self._gate = McpConsentGate(
            self._trust,
            self._prompts.request_launch_consent,
            self._on_generation_change,
        )
        self._manager = McpConnectionManager(
            self._store,
            self._resolver,
            self._gate,
            elicitation_factory=elicitation_factory(self._prompts),
            auth_factory=self._build_auth,
        )
        self._gate.set_config_lookup(self._configured_server)
        self._source = McpToolSource(self._manager, tool_registry)
        self._manager.set_change_listener(self._on_server_changed)
        self._attachment_handler: Callable[[str], None] | None = None
        self._recorded_session: Session | None = None
        self._start_task: asyncio.Task[None] | None = None
        self._stopped = False
        self._sign_in_notices: list[QMessageBox] = []
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

    @property
    def prompts(self) -> QtMcpPrompts:
        """The bridge that asks the operator consent and elicitation questions.

        Returns:
            QtMcpPrompts: The prompt bridge.
        """
        return self._prompts

    def _configured_server(self, server_id: str) -> McpServerConfig | None:
        """Look up a server in the configuration currently in effect.

        Args:
            server_id: The server to find.

        Returns:
            McpServerConfig | None: The configuration, or ``None`` when no
            such server is configured.
        """
        return self._manager.document.server(server_id)

    def _build_auth(self, config: McpServerConfig) -> httpx2.Auth | None:
        """Build the authentication handler for one HTTP server.

        OAuth is attached only when the server carries no ``Authorization``
        header of its own. A configured header is already the credential, and
        layering an OAuth flow over it would replace what the operator asked
        to send.

        Args:
            config: The server, with its headers already resolved.

        Returns:
            httpx2.Auth | None: The handler to sign requests with, or
            ``None`` when the server authenticates some other way or not at
            all.
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
            return build_oauth_provider(spec, storage, redirect_handler=self.sign_in_redirect(config.server_id))
        except McpError as exc:
            _logger.warning("mcp_oauth_provider_unavailable", server_id=config.server_id, error=str(exc))
            return None

    def sign_in_redirect(self, server_id: str) -> Callable[[str], Awaitable[None]]:
        """Build the handler that sends the operator to one server's sign-in page.

        Opening a browser from the background is invisible from inside the
        application, and a sign-in the operator does not know about simply
        stalls until it times out. Once the page has been handed to the
        browser the operator is told, with the address, so they can finish
        signing in or open it themselves if no browser came up.

        Args:
            server_id: The server whose sign-in is starting.

        Returns:
            Callable[[str], Awaitable[None]]: The redirect handler for the
            server's OAuth flow.
        """

        async def _redirect(url: str) -> None:
            """Open the authorization page and tell the operator it was opened.

            Args:
                url: The authorization URL the SDK built.
            """
            await open_authorization_page(url)
            self._relay.sign_in_opened.emit(server_id, url)

        return _redirect

    def _show_sign_in_notice(self, server_id: str, url: str) -> None:
        """Tell the operator a browser window was opened to sign in.

        The notice does not block: the sign-in happens in the browser, and a
        modal box here would stop the operator using the application while
        it does.

        Args:
            server_id: The server being signed in to.
            url: The authorization address that was opened.
        """
        notice = QMessageBox(self._parent)
        notice.setObjectName("mcp_sign_in_notice")
        notice.setIcon(QMessageBox.Icon.Information)
        notice.setWindowTitle("MCP sign-in")
        notice.setText(
            f"A browser window was opened so you can sign in to the MCP server '{server_id}'. "
            "Finish signing in there; the server connects once you have.",
        )
        notice.setInformativeText(f"If no browser appeared, open this address yourself:\n{url}")
        notice.setStandardButtons(QMessageBox.StandardButton.Ok)
        notice.setModal(False)
        _ = notice.finished.connect(functools.partial(self._forget_notice, notice))
        self._sign_in_notices.append(notice)
        notice.show()
        _logger.info("mcp_sign_in_notice_shown", server_id=server_id)

    def _forget_notice(self, notice: QMessageBox, result: int) -> None:
        """Release a sign-in notice once the operator dismisses it.

        Args:
            notice: The notice that was closed.
            result: The button the notice was closed with, unused.
        """
        del result
        if notice in self._sign_in_notices:
            self._sign_in_notices.remove(notice)
        notice.deleteLater()

    @property
    def sign_in_notices(self) -> list[QMessageBox]:
        """The sign-in notices currently on screen.

        Returns:
            list[QMessageBox]: The open notices, oldest first.
        """
        return list(self._sign_in_notices)

    def _on_generation_change(self, server_id: str, generation: str) -> None:
        """Hand a server's changed tool listing to the GUI thread.

        Called on the background loop by the consent gate. The remembered
        answers it discards are read by the confirmation dialog on the GUI
        thread, so they are only ever changed there.

        Args:
            server_id: The server whose tool listing moved.
            generation: The new generation digest.
        """
        self._relay.generation_changed.emit(server_id, generation)

    def _apply_generation_change(self, server_id: str, generation: str) -> None:
        """Discard remembered approvals for a server whose tools changed.

        Runs on the GUI thread.

        Args:
            server_id: The server whose tool listing moved.
            generation: The new generation digest.
        """
        namespace = self._manager.document.server(server_id)
        key = namespace.namespace if namespace is not None else f"mcp-{server_id}"
        ToolConfirmationDialog.clear_decisions_for_source(key)
        _logger.warning("mcp_approvals_reset_after_change", server_id=server_id, generation=generation)

    def _on_server_changed(self, server_id: str) -> None:
        """Hand a server's new state to the GUI thread.

        Called on the background loop, where the connection's state is read
        consistently; the snapshot is recorded onto the session on the GUI
        thread.

        Args:
            server_id: The server whose state moved.
        """
        status = next((entry for entry in self._manager.statuses() if entry.server_id == server_id), None)
        if status is None:
            return
        self._relay.server_state_changed.emit(_state_of(status))

    def _apply_server_state(self, payload: object) -> None:
        """Record one server's state onto the active session.

        Runs on the GUI thread. A session that has not been brought up to
        date yet -- one just started or restored -- is given every server's
        state rather than only this one.

        Args:
            payload: The :class:`McpServerState` snapshot.
        """
        session = self._orchestrator.current_session
        if session is None:
            return
        if session is not self._recorded_session:
            self.record_session_state(session)
            return
        session.set_mcp_server_state(cast("McpServerState", payload))

    def record_session_state(self, session: Session) -> None:
        """Write every server's current state onto one session.

        Args:
            session: The session to record onto.
        """
        for status in self._manager.statuses():
            session.set_mcp_server_state(_state_of(status))
        self._recorded_session = session

    def sync_session_state(self) -> None:
        """Bring the active session's MCP record up to date if it is new to this service.

        Called on the GUI thread whenever the active session may have
        changed. A session started or restored since the last call is given
        every server's current state, replacing whatever a restored session
        carried from the run that saved it; the session already being kept
        up to date is left alone.
        """
        session = self._orchestrator.current_session
        if session is None or session is self._recorded_session:
            return
        self.record_session_state(session)
        _logger.debug("mcp_session_state_recorded", session_id=session.id)

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
        server that comes up later is reachable without a restart. A start
        still in progress when the service is stopped is abandoned: nothing
        it was waiting on is launched afterwards.

        Raises:
            asyncio.CancelledError: If the caller is cancelled while the
                servers are starting.
        """
        if self._stopped:
            _logger.info("mcp_service_start_skipped_after_stop")
            return
        task = asyncio.create_task(self._manager.start(), name="mcp-service-start")
        self._start_task = task
        try:
            await task
        except McpError as exc:
            _logger.warning("mcp_service_start_incomplete", error=str(exc))
        except asyncio.CancelledError:
            if not self._stopped:
                raise
            _logger.info("mcp_service_start_abandoned_on_stop")
            return
        finally:
            self._start_task = None
        if self._stopped:
            return
        self._source.register_all()
        _logger.info("mcp_service_started", servers=len(self._manager.document.servers))

    async def refresh_tool_registration(self) -> None:
        """Re-register every configured server's namespace.

        Runs on the background loop, the thread that iterates the tool
        registry while building tool definitions, so the registry is never
        changed underneath that iteration.
        """
        if self._stopped:
            return
        self._source.register_all()

    async def stop(self) -> None:
        """Disconnect every server and unregister their tools.

        Runs before the background loop is torn down, so no server process
        outlives the application and no worker is left awaiting a stopped
        loop. From here on no launch is asked about -- nobody is left to
        answer -- so every question still open is refused at once, and a
        start still in progress is cancelled before the servers are torn
        down.
        """
        self._stopped = True
        self._gate.set_prompt(deny_all_launches)
        self._prompts.refuse_all()
        task = self._start_task
        if task is not None and not task.done():
            _ = task.cancel()
            _ = await asyncio.wait({task})
        self._source.unregister_all()
        self._orchestrator.set_mcp_tool_source(None)
        with contextlib.suppress(McpError):
            await self._manager.stop()
        ToolConfirmationDialog.set_approval_store(None)
        _logger.info("mcp_service_stopped")

    def set_attachment_handler(self, handler: Callable[[str], None] | None) -> None:
        """Install what happens when the operator attaches a server resource or prompt.

        Args:
            handler: Called with the rendered text, or ``None`` to drop the
                current handler, in which case the Attach buttons do nothing
                beyond previewing.
        """
        self._attachment_handler = handler

    def open_settings(self, parent: QWidget | None = None) -> None:
        """Show the MCP settings dialog.

        The dialog is destroyed once it closes, rather than living on as a
        hidden child of its parent for the rest of the session, and the
        namespaces it may have added or removed are re-registered on the
        background loop.

        Args:
            parent: Widget to parent the dialog to, defaulting to the
                service's own parent.
        """
        dialog = McpConfigDialog(
            self._manager,
            self._resolver,
            parent if parent is not None else self._parent,
            approvals=self._approvals,
        )
        handler = self._attachment_handler
        if handler is not None:
            _ = dialog.resource_attached.connect(handler)
            _ = dialog.prompt_attached.connect(handler)
        try:
            dialog.refresh_auth_state()
            _ = dialog.exec()
        finally:
            dialog.deleteLater()
        run_bridge_coroutine_async(
            self.refresh_tool_registration(),
            on_error=lambda error: _logger.warning("mcp_tool_registration_refresh_failed", error=str(error)),
        )
