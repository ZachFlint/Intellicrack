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
outcome that cannot be undone. A question that is given up on, by timing out
or because whoever asked it was cancelled, is also taken off the screen: a
dialog left open after nobody is waiting for it invites an answer that would
be thrown away.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, cast

from mcp_types import ElicitResult
from PyQt6.QtCore import QObject, pyqtSignal

from intellicrack.core.logging import get_logger
from intellicrack.mcp.consent import ConsentAnswer
from intellicrack.ui.mcp_consent_dialog import McpServerConsentDialog
from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog, build_declined_result, resolve_elicitation


if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.client.session import ClientRequestContext, ElicitationFnT
    from mcp_types import ElicitRequestParams
    from PyQt6.QtWidgets import QDialog, QWidget

    from intellicrack.mcp.config import McpServerConfig
    from intellicrack.mcp.consent import DangerousPattern


_logger = get_logger(__name__)


CONSENT_TIMEOUT_S: Final[float] = 900.0
"""How long a launch-consent dialog may stay open before the launch is refused."""

ELICITATION_TIMEOUT_S: Final[float] = 600.0
"""How long an elicitation dialog may stay open before it is declined."""


@dataclass(eq=False)
class PendingPrompt:
    """One question on its way to, or in front of, the operator.

    Attributes:
        loop: The loop the asker is waiting on.
        future: Resolved on ``loop`` with the operator's answer.
        refusal: The answer given on the operator's behalf when nobody is
            left to answer.
        withdrawn: Set from the loop's thread once nobody is waiting for the
            answer any more. Read on the GUI thread before and after the
            dialog is shown.
        dialog: The dialog currently showing the question. Touched only on
            the GUI thread.
    """

    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[Any]
    refusal: object
    withdrawn: threading.Event = field(default_factory=threading.Event)
    dialog: QDialog | None = None


class QtMcpPrompts(QObject):
    """Presents MCP consent and elicitation questions on the GUI thread.

    One instance serves every server. Signals are emitted from the background loop and delivered on the GUI thread, which is what makes it
    safe to build a dialog in response to them.
    """

    consent_requested = pyqtSignal(object)
    elicitation_requested = pyqtSignal(object)
    prompt_withdrawn = pyqtSignal(object)

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        consent_timeout_s: float = CONSENT_TIMEOUT_S,
        elicitation_timeout_s: float = ELICITATION_TIMEOUT_S,
    ) -> None:
        """Initialize the prompt bridge.

        Args:
            parent: Widget the dialogs are parented to.
            consent_timeout_s: How long a launch-consent question waits for
                an answer before the launch is refused.
            elicitation_timeout_s: How long an elicitation waits for an
                answer before it is declined.
        """
        super().__init__(parent)
        self._parent_widget = parent
        self._consent_timeout_s = consent_timeout_s
        self._elicitation_timeout_s = elicitation_timeout_s
        self._open: set[PendingPrompt] = set()
        _ = self.consent_requested.connect(self._show_consent_dialog)
        _ = self.elicitation_requested.connect(self._show_elicitation_dialog)
        _ = self.prompt_withdrawn.connect(self._close_withdrawn)

    async def request_launch_consent(
        self,
        config: McpServerConfig,
        description: str,
        findings: list[DangerousPattern],
    ) -> ConsentAnswer:
        """Ask the operator whether a local server may be started.

        Args:
            config: The server about to be launched.
            description: The rendered launch description.
            findings: Patterns the consent scan flagged.

        Returns:
            ConsentAnswer: The operator's answer. A dialog that was never
            answered, or that could not be shown, refuses this launch without
            marking the server denied.

        Raises:
            asyncio.CancelledError: If the connection attempt is cancelled
                while the operator is still deciding. The dialog is closed.
        """
        loop = asyncio.get_running_loop()
        pending = PendingPrompt(loop, loop.create_future(), ConsentAnswer(approved=False))
        self._open.add(pending)
        self.consent_requested.emit((pending, config, description, list(findings)))
        try:
            async with asyncio.timeout(self._consent_timeout_s):
                answer: object = await pending.future
        except TimeoutError:
            _logger.warning("mcp_consent_timeout", server_id=config.server_id, timeout_s=self._consent_timeout_s)
            self.withdraw(pending)
            return ConsentAnswer(approved=False)
        except asyncio.CancelledError:
            self.withdraw(pending)
            raise
        finally:
            self._open.discard(pending)
        return answer if isinstance(answer, ConsentAnswer) else ConsentAnswer(approved=False)

    def refuse_all(self) -> None:
        """Answer every open question with its refusal and take it off the screen.

        Called on the loop when nobody is left to answer, such as while MCP
        shuts down. Each asker receives the same answer an unanswered
        question gets -- a refused launch, a declined elicitation -- at once,
        rather than waiting out its timeout.
        """
        open_prompts = list(self._open)
        for pending in open_prompts:
            if not pending.future.done():
                pending.future.set_result(pending.refusal)
            pending.withdrawn.set()
            self.prompt_withdrawn.emit(pending)
        _logger.info("mcp_prompts_refused_all", count=len(open_prompts))

    def withdraw(self, pending: PendingPrompt) -> None:
        """Give up on a question and take it off the screen.

        Called on the loop that asked. The future is cancelled so a late
        answer finds nobody to deliver to, and the GUI thread is told to
        close the dialog if it is showing.

        Args:
            pending: The question to give up on.
        """
        pending.withdrawn.set()
        if not pending.future.done():
            _ = pending.future.cancel()
        self.prompt_withdrawn.emit(pending)

    @staticmethod
    def _close_withdrawn(payload: object) -> None:
        """Close the dialog of a question nobody is waiting for any more.

        Args:
            payload: The :class:`PendingPrompt` that was withdrawn.
        """
        pending = cast("PendingPrompt", payload)
        dialog = pending.dialog
        if dialog is not None:
            _logger.info("mcp_prompt_withdrawn_dialog_closed")
            dialog.reject()

    def _show_consent_dialog(self, payload: object) -> None:
        """Show the consent dialog and deliver the operator's answer.

        The answer is taken from the dialog's ``decision_made`` signal. A
        dialog closed any other way -- the window's close button, or being
        withdrawn -- produced no decision, and is delivered as a refusal
        unless nobody is waiting for it.

        Args:
            payload: Tuple of ``(pending, config, description, findings)``
                emitted by :meth:`request_launch_consent`.
        """
        pending, config, description, findings = cast(
            "tuple[PendingPrompt, McpServerConfig, str, list[DangerousPattern]]",
            payload,
        )
        if pending.withdrawn.is_set():
            _logger.info("mcp_consent_prompt_skipped_withdrawn", server_id=config.server_id)
            return
        decisions: list[ConsentAnswer] = []
        try:
            dialog = McpServerConsentDialog(config, description, findings, self._parent_widget)
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("mcp_consent_dialog_failed", server_id=config.server_id, error=str(exc))
            _resolve_future(pending, ConsentAnswer(approved=False))
            return

        def _record(approved: object, trusted: object, blocked: object) -> None:
            """Keep the decision the dialog reported.

            Args:
                approved: Whether the launch was approved.
                trusted: Whether the trust box was ticked.
                blocked: Whether the operator asked never to be asked again.
            """
            decisions.append(ConsentAnswer(approved=approved is True, trusted=trusted is True, blocked=blocked is True))

        _ = dialog.decision_made.connect(_record)
        self._run_dialog(pending, dialog)
        if pending.withdrawn.is_set():
            _logger.warning("mcp_consent_late_answer_discarded", server_id=config.server_id)
            return
        _resolve_future(pending, decisions[-1] if decisions else ConsentAnswer(approved=False))

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
        """
        loop = asyncio.get_running_loop()
        pending = PendingPrompt(loop, loop.create_future(), build_declined_result())
        self._open.add(pending)
        self.elicitation_requested.emit((pending, server_id, params))

        def _withdraw() -> None:
            """Take this server's question off the screen."""
            _logger.warning("mcp_elicitation_withdrawn", server_id=server_id)
            self.withdraw(pending)

        try:
            return await resolve_elicitation(pending.future, self._elicitation_timeout_s, on_abandon=_withdraw)
        finally:
            self._open.discard(pending)

    def _show_elicitation_dialog(self, payload: object) -> None:
        """Show the elicitation dialog and deliver the operator's answer.

        The answer is taken from the dialog's ``answered`` signal. A dialog
        closed without one is delivered as a cancellation unless nobody is
        waiting for it any more.

        Args:
            payload: Tuple of ``(pending, server_id, params)`` emitted by
                :meth:`_request_elicitation`.
        """
        pending, server_id, params = cast("tuple[PendingPrompt, str, ElicitRequestParams]", payload)
        if pending.withdrawn.is_set():
            _logger.info("mcp_elicitation_prompt_skipped_withdrawn", server_id=server_id)
            return
        results: list[ElicitResult] = []
        try:
            dialog = McpElicitationDialog(server_id, params, self._parent_widget)
        except (RuntimeError, OSError, ValueError) as exc:
            _logger.warning("mcp_elicitation_dialog_failed", server_id=server_id, error=str(exc))
            _resolve_future(pending, build_declined_result())
            return

        def _record(action: str) -> None:
            """Keep the answer the dialog reported.

            Args:
                action: ``accept``, ``decline`` or ``cancel``.
            """
            del action
            results.append(dialog.to_result())

        _ = dialog.answered.connect(_record)
        self._run_dialog(pending, dialog)
        if pending.withdrawn.is_set():
            _logger.warning("mcp_elicitation_late_answer_discarded", server_id=server_id)
            return
        _resolve_future(pending, results[-1] if results else ElicitResult(action="cancel"))

    @staticmethod
    def _run_dialog(pending: PendingPrompt, dialog: QDialog) -> None:
        """Show one question's dialog modally, tracking it so it can be withdrawn.

        Args:
            pending: The question being shown.
            dialog: The dialog showing it.
        """
        pending.dialog = dialog
        try:
            _ = dialog.exec()
        finally:
            pending.dialog = None
            dialog.deleteLater()


def _resolve_future(pending: PendingPrompt, value: object) -> None:
    """Deliver an answer back onto the loop that asked the question.

    An answer that arrives after the question was given up on is discarded
    on the loop itself, where the future's state is authoritative, so it can
    never take effect late.

    Args:
        pending: The question being answered.
        value: The answer to deliver.
    """
    future = pending.future

    def _apply() -> None:
        """Set the future's result if it is still waiting for one."""
        if future.done():
            _logger.warning("mcp_prompt_answer_after_withdrawal_discarded")
            return
        future.set_result(value)

    try:
        _ = pending.loop.call_soon_threadsafe(_apply)
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
