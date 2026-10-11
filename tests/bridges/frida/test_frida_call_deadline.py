# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The bounded call wrapper of the Frida bridge, driven with plain callables and a real ``frida.Cancellable``.

``_call_with_deadline`` runs any blocking callable on a worker thread inside a ``Cancellable`` scope and
gives up after a limit. None of that needs a Frida device, a session or a target process, so these tests
hand it ordinary Python callables that block on a ``threading.Event`` or on the token itself. The error
classes it raises are checked against messages written out here from the documented wording, and the
abandoned-outcome helper is checked against asyncio's own "never retrieved" report.
"""

from __future__ import annotations

import asyncio
import gc
import threading
import time
from typing import TYPE_CHECKING, Any, Final, cast

import frida
import pytest

from intellicrack.bridges import frida_bridge as frida_bridge_mod
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


_call_with_deadline: Callable[..., Awaitable[object]] = cast(
    "Callable[..., Awaitable[object]]",
    getattr(frida_bridge_mod, "_call_with_deadline"),
)
_discard_worker_outcome: Callable[[asyncio.Future[object]], None] = cast(
    "Callable[[asyncio.Future[object]], None]",
    getattr(frida_bridge_mod, "_discard_worker_outcome"),
)
_timeout_error: type[ToolError] = cast("type[ToolError]", getattr(frida_bridge_mod, "_FridaCallTimeoutError"))
_make_timeout_error: Callable[[str, float], ToolError] = cast(
    "Callable[[str, float], ToolError]",
    getattr(frida_bridge_mod, "_FridaCallTimeoutError"),
)
_make_unresponsive_error: Callable[[str, str], ToolError] = cast(
    "Callable[[str, str], ToolError]",
    getattr(frida_bridge_mod, "_AgentUnresponsiveError"),
)
_CANCEL_GRACE: Final[float] = float(getattr(frida_bridge_mod, "_FRIDA_CANCEL_GRACE"))

_SHORT_LIMIT: Final[float] = 0.2
_LONG_LIMIT: Final[float] = 60.0
_POLL_SECONDS: Final[float] = 0.01
_WAIT_SECONDS: Final[float] = 30.0
_CLOCK_TOLERANCE: Final[float] = 0.1


def _hold_until_cancelled(token: frida.Cancellable, gate: threading.Event, started: threading.Event, observed: list[str]) -> str:
    """Block the worker thread until the token is cancelled or the gate opens.

    Args:
        token: The cancellation token the call was scoped with.
        gate: Event the test sets to release the call whatever happens.
        started: Event this function sets as soon as it runs on the worker thread.
        observed: List that receives what ended the wait.

    Returns:
        str: ``"cancelled"`` when the token was cancelled, otherwise ``"released"``.
    """
    started.set()
    while not token.is_cancelled and not gate.is_set():
        _ = gate.wait(_POLL_SECONDS)
    outcome = "cancelled" if token.is_cancelled else "released"
    observed.append(outcome)
    return outcome


def _hold_until_released(gate: threading.Event) -> str:
    """Block the worker thread on an event and ignore any cancellation token.

    Args:
        gate: Event the test sets to release the call.

    Returns:
        str: ``"released"`` once the event is set or the safety wait ends.
    """
    _ = gate.wait(_WAIT_SECONDS)
    return "released"


def _multiply(left: int, right: int, *, scale: int) -> int:
    """Multiply two numbers and scale the product.

    Args:
        left: First factor.
        right: Second factor.
        scale: Multiplier applied to the product.

    Returns:
        int: ``left * right * scale``.
    """
    return left * right * scale


def _current_token() -> frida.Cancellable | None:
    """Report the cancellation token that is current on the calling thread.

    Returns:
        frida.Cancellable | None: The innermost active ``Cancellable`` scope, if any.
    """
    return frida.Cancellable.get_current()


async def _drain_executor() -> None:
    """Wait for the worker threads of the running loop's default executor to finish and stop."""
    await asyncio.get_running_loop().shutdown_default_executor()


class TestCallReturnsInTime:
    """A call that finishes inside its limit hands back its own outcome."""

    @pytest.mark.asyncio
    async def test_value_arguments_and_token_scope(self) -> None:
        """The value comes back, the arguments arrive, the call runs inside the given token and nothing is cancelled."""
        token = frida.Cancellable()
        seen: list[frida.Cancellable | None] = []

        def probe() -> int:
            """Record the token that is current on the worker thread.

            Returns:
                int: A fixed marker value.
            """
            seen.append(_current_token())
            return 7

        try:
            product = await _call_with_deadline(
                _multiply,
                (6, 7),
                {"scale": 10},
                limit=_LONG_LIMIT,
                cancellable=token,
                operation="multiply",
            )
            marker = await _call_with_deadline(probe, (), {}, limit=_LONG_LIMIT, cancellable=token, operation="probe")
        finally:
            await _drain_executor()
        assert product == 420
        assert marker == 7
        assert seen == [token]
        assert token.is_cancelled is False

    @pytest.mark.asyncio
    async def test_missing_token_gives_the_call_a_private_uncancelled_one(self) -> None:
        """With no token passed, the call still runs inside a real ``Cancellable`` scope that nobody cancelled."""
        try:
            current = await _call_with_deadline(_current_token, (), {}, limit=_LONG_LIMIT, cancellable=None, operation="current")
        finally:
            await _drain_executor()
        assert isinstance(current, frida.Cancellable)
        assert current.is_cancelled is False

    @pytest.mark.asyncio
    async def test_exception_from_the_call_propagates_unchanged(self) -> None:
        """A ``KeyError`` raised inside the call reaches the caller as that same type with the same arguments."""
        token = frida.Cancellable()
        empty: dict[str, int] = {}
        try:
            with pytest.raises(KeyError) as excinfo:
                await _call_with_deadline(empty.pop, ("missing",), {}, limit=_LONG_LIMIT, cancellable=token, operation="pop")
        finally:
            await _drain_executor()
        assert excinfo.value.args == ("missing",)
        assert not isinstance(excinfo.value, ToolError)
        assert token.is_cancelled is False


class TestCallOutlastsItsLimit:
    """A call that does not finish inside its limit is cancelled and reported."""

    @pytest.mark.asyncio
    async def test_timeout_names_the_operation_and_cancels_the_token(self) -> None:
        """The error carries the operation and limit, the message follows the documented wording, and the token is cancelled."""
        token = frida.Cancellable()
        gate = threading.Event()
        started = threading.Event()
        observed: list[str] = []
        try:
            with pytest.raises(_timeout_error) as excinfo:
                await _call_with_deadline(
                    _hold_until_cancelled,
                    (token, gate, started, observed),
                    {},
                    limit=_SHORT_LIMIT,
                    cancellable=token,
                    operation="attach",
                )
        finally:
            gate.set()
            await _drain_executor()
        assert str(excinfo.value) == "Frida call timed out: attach did not return within 0.2s; the agent or device did not answer"
        assert excinfo.value.details == {"operation": "attach", "timeout_seconds": 0.2}
        assert token.is_cancelled is True
        assert started.is_set()
        assert observed == ["cancelled"]

    @pytest.mark.asyncio
    async def test_call_that_ignores_the_token_is_abandoned_after_the_grace_period(self) -> None:
        """A call that never looks at the token is waited for through the grace period, then abandoned with the same error."""
        token = frida.Cancellable()
        gate = threading.Event()
        began = time.monotonic()
        try:
            with pytest.raises(_timeout_error) as excinfo:
                await _call_with_deadline(_hold_until_released, (gate,), {}, limit=_SHORT_LIMIT, cancellable=token, operation="rpc")
            elapsed = time.monotonic() - began
        finally:
            gate.set()
            await _drain_executor()
        assert excinfo.value.details == {"operation": "rpc", "timeout_seconds": 0.2}
        assert token.is_cancelled is True
        assert elapsed >= _SHORT_LIMIT + _CANCEL_GRACE - _CLOCK_TOLERANCE


class TestAwaitingTaskIsCancelled:
    """Cancelling the task that awaits the call cancels the call too."""

    @pytest.mark.asyncio
    async def test_cancelling_the_task_cancels_the_token_and_reraises(self) -> None:
        """The task ends cancelled, the token is cancelled and the blocked call sees the cancellation."""
        token = frida.Cancellable()
        gate = threading.Event()
        started = threading.Event()
        observed: list[str] = []
        task = asyncio.ensure_future(
            _call_with_deadline(
                _hold_until_cancelled,
                (token, gate, started, observed),
                {},
                limit=_LONG_LIMIT,
                cancellable=token,
                operation="attach",
            ),
        )
        try:
            assert await asyncio.to_thread(started.wait, _WAIT_SECONDS)
            assert token.is_cancelled is False
            _ = task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            gate.set()
            await _drain_executor()
        assert task.cancelled()
        assert token.is_cancelled is True
        assert observed == ["cancelled"]


class TestDiscardWorkerOutcome:
    """An abandoned worker's outcome is marked as seen so asyncio stays quiet about it."""

    @pytest.mark.asyncio
    async def test_unseen_exception_is_reported_and_a_discarded_one_is_not(self) -> None:
        """Dropping a failed future reports it to the loop unless the helper has looked at it first."""
        loop = asyncio.get_running_loop()
        reports: list[dict[str, Any]] = []

        def collect(_loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
            """Remember what the loop was asked to report.

            Args:
                _loop: The loop reporting the problem.
                context: The report asyncio built.
            """
            reports.append(context)

        loop.set_exception_handler(collect)
        try:
            discarded: asyncio.Future[object] = loop.create_future()
            discarded.set_exception(ValueError("discarded"))
            _discard_worker_outcome(discarded)
            del discarded
            _ = gc.collect()
            assert reports == []
            abandoned: asyncio.Future[object] = loop.create_future()
            abandoned.set_exception(ValueError("abandoned"))
            del abandoned
            _ = gc.collect()
        finally:
            loop.set_exception_handler(None)
        assert [report["message"] for report in reports] == ["Future exception was never retrieved"]
        assert str(reports[0]["exception"]) == "abandoned"

    @pytest.mark.asyncio
    async def test_cancelled_future_is_accepted(self) -> None:
        """A future that was cancelled has no exception to mark, and the helper returns quietly."""
        loop = asyncio.get_running_loop()
        cancelled: asyncio.Future[object] = loop.create_future()
        assert cancelled.cancel() is True
        assert _discard_worker_outcome(cancelled) is None
        assert cancelled.cancelled()


class TestErrorClasses:
    """The two Frida call errors carry the operations they were built with."""

    @pytest.mark.parametrize(
        ("limit", "spelled"),
        [(30.0, "30s"), (0.25, "0.25s"), (2.5, "2.5s")],
    )
    def test_timeout_error_spells_the_limit_without_trailing_zeros(self, limit: float, spelled: str) -> None:
        """The limit appears in the message in shortest form, and the details keep the number itself.

        Args:
            limit: Seconds the call was allowed.
            spelled: The same limit as the message must spell it.
        """
        error = _make_timeout_error("enumerate_processes", limit)
        assert isinstance(error, ToolError)
        assert (
            str(error) == f"Frida call timed out: enumerate_processes did not return within {spelled}; the agent or device did not answer"
        )
        assert error.details == {"operation": "enumerate_processes", "timeout_seconds": limit}

    def test_agent_unresponsive_error_names_both_calls(self) -> None:
        """The message and the details name the refused call and the earlier call that timed out."""
        error = _make_unresponsive_error("detach", "attach")
        assert isinstance(error, ToolError)
        assert str(error) == (
            "Frida agent is not answering: detach was not attempted because attach on this session timed out earlier; "
            "the agent or device did not answer"
        )
        assert error.details == {"operation": "detach", "first_timed_out_operation": "attach"}
