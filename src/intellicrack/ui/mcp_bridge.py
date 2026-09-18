# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Carries an MCP server's questions from the background loop to the operator.

The MCP client runs on the persistent background event loop and knows nothing
about Qt. Two of its decisions belong to a human, though: whether a local
program may be launched, and how to answer a server that asks for information
mid-call. This module is the only place the two worlds meet.

Each question is handed to the GUI thread through a queued signal and awaited
as a future on the loop that asked. Awaiting rather than blocking matters: a
consent dialog can sit open for as long as the operator takes to read a
command, and blocking the loop for that time would stall every other server's
heartbeat, every in-flight tool call, and any connection being established
alongside it.

When no answer arrives, the answer is no. A consent request that times out
refuses the launch and an elicitation that times out declines, because the
alternative -- proceeding as though the operator had agreed -- is the one
outcome that cannot be undone.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, Final, cast

from mcp_types import ElicitResult
from PyQt6.QtCore import QObject, pyqtSignal

from intellicrack.core.logging import get_logger
from intellicrack.mcp.consent import TrustState
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog


if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.client.session import ClientRequestContext, ElicitationFnT
    from mcp_types import ElicitRequestParams
    from PyQt6.QtWidgets import QWidget

    from intellicrack.mcp.config import McpServerConfig
    from intellicrack.mcp.consent import DangerousPattern, TrustStore


_logger = get_logger(__name__)


CONSENT_TIMEOUT_S: Final[float] = 900.0
"""How long a launch-consent dialog may stay open before the launch is refused."""

ELICITATION_TIMEOUT_S: Final[float] = 600.0
"""How long an elicitation dialog may stay open before it is declined."""


class QtMcpPrompts(QObject):
    """Presents MCP consent and elicitation questions on the GUI thread.

    One instance serves every server. Signals are emitted from the background
    loop and delivered on the GUI thread, which is what makes it safe to
    build a dialog in response to them.
    """

    consent_requested = pyqtSignal(object)
    elicitation_requested = pyqtSignal(object)

    def __init__(self, trust: TrustStore, parent: QWidget | None = None) -> None:
        """Initialize the prompt bridge.

        Args:
            trust: Trust store written when the operator ticks "trust this
                server" while approving a launch.
            parent: Widget the dialogs are parented to.
        """
        super().__init__(parent)
        self._trust = trust
        self._parent_widget = parent
        _ = self.consent_requested.connect(self._show_consent_dialog)
        _ = self.elicitation_requested.connect(self._show_elicitation_dialog)

    async def request_launch_consent(
        self,
        config: McpServerConfig,
        description: str,
        findings: list[DangerousPattern],
    ) -> bool:
        """Ask the operator whether a local server may be started.

        Args:
            config: The server about to be launched.
            description: The rendered launch description.
            findings: Patterns the consent scan flagged.

        Returns:
            bool: ``True`` only when the operator approved. A dialog that was
            never answered, or that could not be shown, refuses.

        Raises:
            asyncio.CancelledError: If the connection attempt is cancelled
                while the operator is still deciding.
        """
        loop = asyncio.get_running_loop()
        future: asyncio.Future[bool] = loop.create_future()
        self.consent_requested.emit((config, description, list(findings), future, loop))
        try:
            async with asyncio.timeout(CONSENT_TIMEOUT_S):
                return await future
        except TimeoutError:
            _logger.warning("mcp_consent_timeout", server_id=config.server_id, timeout_s=CONSENT_TIMEOUT_S)
            if not future.done():
                _ = future.cancel()
            return False
        except asyncio.CancelledError:
            if not future.done():
                _ = future.cancel()
            raise

    def _show_consent_dialog(self, payload: object) -> None:
        """Show the consent dialog and resolve the waiting future.

        Args:
            payload: Tuple of ``(config, description, findings, future,
                loop)`` emitted by :meth:`request_launch_consent`.
        """
        config, description, findings, future, loop = cast(
            "tuple[McpServerConfig, str, list[DangerousPattern], asyncio.Future[bool], asyncio.AbstractEventLoop]",
            payload,
        )
        approved = False
        try:
            dialog = McpServerConsentDialog(config, description, findings, self._parent_widget)
            _ = dialog.exec()
            approved = dialog.approved
            if approved and dialog.trusted:
                self._trust.set_state(config.server_id, TrustState.TRUSTED)
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("mcp_consent_dialog_failed", server_id=config.server_id, error=str(exc))
            approved = False
        _resolve_future(loop, future, approved)

    def elicitation_for(self, server_id: str) -> ElicitationFnT:
        """Build the elicitation handler for one server.

        Args:
            server_id: The server the handler answers for. The operator is
                told which server is asking, which the protocol callback
                itself does not carry.

        Returns:
            ElicitationFnT: The handler to hand to the SDK client.
        """

        async def _handle(context: ClientRequestContext, params: ElicitRequestParams) -> ElicitResult:
            """Ask the operator one server's question.

            Args:
                context: The SDK's request context, unused.
                params: The form or URL request the server sent.

            Returns:
                ElicitResult: The operator's answer, declining when no answer
                arrives.
            """
            del context
            return await self._request_elicitation(server_id, params)

        return _handle

    async def _request_elicitation(self, server_id: str, params: ElicitRequestParams) -> ElicitResult:
        """Ask the operator to answer one elicitation request.

        Args:
            server_id: The server asking.
            params: The form or URL request it sent.

        Returns:
            ElicitResult: The operator's answer, or a decline on timeout.

        Raises:
            asyncio.CancelledError: If the call is cancelled while the
                operator is still deciding.
        """
        loop = asyncio.get_running_loop()
        future: asyncio.Future[ElicitResult] = loop.create_future()
        self.elicitation_requested.emit((server_id, params, future, loop))
        try:
            async with asyncio.timeout(ELICITATION_TIMEOUT_S):
                return await future
        except TimeoutError:
            _logger.warning("mcp_elicitation_timeout", server_id=server_id, timeout_s=ELICITATION_TIMEOUT_S)
            if not future.done():
                _ = future.cancel()
            return ElicitResult(action="decline")
        except asyncio.CancelledError:
            if not future.done():
                _ = future.cancel()
            raise

    def _show_elicitation_dialog(self, payload: object) -> None:
        """Show the elicitation dialog and resolve the waiting future.

        Args:
            payload: Tuple of ``(server_id, params, future, loop)`` emitted
                by :meth:`_request_elicitation`.
        """
        server_id, params, future, loop = cast(
            "tuple[str, ElicitRequestParams, asyncio.Future[ElicitResult], asyncio.AbstractEventLoop]",
            payload,
        )
        result = ElicitResult(action="decline")
        try:
            dialog = McpElicitationDialog(server_id, params, self._parent_widget)
            _ = dialog.exec()
            result = dialog.to_result()
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("mcp_elicitation_dialog_failed", server_id=server_id, error=str(exc))
        _resolve_future(loop, future, result)


def _resolve_future(loop: asyncio.AbstractEventLoop, future: asyncio.Future[Any], value: object) -> None:
    """Deliver an answer back onto the loop that asked the question.

    Args:
        loop: The loop the future belongs to.
        future: The future awaiting the answer.
        value: The answer to deliver.
    """

    def _apply() -> None:
        """Set the future's result if it is still waiting for one."""
        if not future.done():
            future.set_result(value)

    try:
        loop.call_soon_threadsafe(_apply)
    except RuntimeError as exc:
        _logger.warning("mcp_prompt_future_unresolvable", error=str(exc))


def elicitation_factory(prompts: QtMcpPrompts) -> Callable[[str], ElicitationFnT]:
    """Adapt a prompt bridge into the factory the connection manager wants.

    Args:
        prompts: The prompt bridge serving every server.

    Returns:
        Callable[[str], ElicitationFnT]: A factory producing one handler per
        server id.
    """
    return prompts.elicitation_for
