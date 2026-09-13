# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gates for the conditional-trace command framing (name and argument order).

x64dbg's documented ``TraceIntoConditional``/``ticnd`` and
``TraceOverConditional``/``tocnd`` commands (help.x64dbg.com tracing
commands) take ``arg1`` as the required break condition - tracing stops
the instant it evaluates to a value other than 0 - and ``[arg2]`` as the
optional maximum step count the debugger honours before giving up,
regardless of the condition.

``X64DbgBridge.trace_into``/``trace_over`` used to build the command with
those two positions swapped: ``f"TraceIntoConditional {max_steps}"``
with ``condition`` appended, quoted, only when the caller supplied one.
Every real call site in this codebase (the Trace panel's "Trace
Into"/"Trace Over" buttons, and every pre-existing test in this suite)
omits ``condition``, so the command x64dbg actually received was a bare
integer such as ``"TraceIntoConditional 50000"``. x64dbg parses a lone
argument as the BREAK CONDITION, and any nonzero value is "a value other
than 0", so tracing stopped after the very first instruction instead of
running up to ``max_steps``. The bug was invisible to every prior test
because none of them inspect the ``exec`` command text the bridge
actually sends - they only assert on the parsed return value.

These tests script an in-process fake pipe client that records every
``(command, params)`` pair the bridge emits and assert on the exact
``exec`` command string, so a reversion to the swapped argument order -
or any framing that lets ``max_steps`` land in the condition slot -
fails loudly instead of passing silently.

The same fake-pipe machinery gates ``X64DbgBridge.step_count``, which
runs a fixed number of steps by issuing a bounded conditional trace with
the always-false break condition ``0``. Its defect was a different
shape: the ``0``-then-count argument order was already correct, but the
command *name* was ``tic``/``toc``, which x64dbg registers nowhere (only
``ticnd``/``tocnd`` and the full ``TraceIntoConditional``/
``TraceOverConditional`` names exist), so a real plugin rejected the
command as unknown and no stepping ran. :class:`TestStepCountCommandName`
pins the exact documented command name alongside the ``0``-then-count
argument order.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge


if TYPE_CHECKING:
    from collections.abc import Callable


_CONDITION: Final[str] = "eax==1"
_CUSTOM_MAX_STEPS: Final[int] = 12345
_DEFAULT_MAX_STEPS: Final[int] = 50000
_STEP_COUNT: Final[int] = 7


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge emits in the
    ``sent`` instance list and returns the response produced by the
    caller-supplied ``responder`` callable. The ``is_connected``
    property always returns ``True`` so the bridge never attempts a
    real reconnect. Reproduced here rather than imported from
    ``test_x64dbg_wave2b_trace.py``, since that file belongs to a
    different domain and must not be modified or depended on.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialize the fake pipe client.

        Args:
            responder: Callable mapping ``(command, params)`` to the
                response dict the pipe layer would have returned.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Report the fake as permanently connected.

        Returns:
            bool: Always ``True``.
        """
        return True

    async def send_command(
        self,
        command: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record the request and return the scripted response.

        Args:
            command: RPC command name.
            params: Optional parameters dict.

        Returns:
            dict[str, Any]: Response produced by the responder.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class _PlaceholderProcess:
    """Sentinel satisfying ``self._process is not None`` guards in ``_send_command``."""

    def poll(self) -> int | None:
        """Report process status the way :class:`subprocess.Popen.poll` does.

        Returns:
            int | None: Always ``None``, indicating this stand-in
            debugger process is still running.
        """
        return None


def _install_fake_pipe(
    bridge: X64DbgBridge,
    responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
) -> _FakePipeClient:
    """Attach a fake pipe client to ``bridge`` and mark the plugin deployed.

    Args:
        bridge: Bridge instance under test.
        responder: Per-command response generator.

    Returns:
        _FakePipeClient: The installed fake, useful for asserting on ``sent``.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


def _running_after_exec(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
    """Answer ``exec`` with success and ``status`` as already running.

    Lets :meth:`X64DbgBridge._await_run_completion` resolve on its very
    first ``status`` poll, matching the real plugin's response once a
    trace command has started the debuggee running.

    Args:
        command: RPC command name.
        _params: Ignored parameters.

    Returns:
        dict[str, Any]: A success response for ``exec``, or a
        ``running`` debugger state for ``status``.

    Raises:
        AssertionError: If a command other than ``exec``/``status`` is sent.
    """
    if command == "exec":
        return {"id": 1, "success": True, "result": None}
    if command == "status":
        return {"id": 1, "success": True, "result": {"debugging": True, "paused": False, "initialized": True}}
    msg = f"unexpected command: {command}"
    raise AssertionError(msg)


def _paused_after_exec(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
    """Answer ``exec`` with success and ``status`` as already paused.

    Lets :meth:`X64DbgBridge.step_count` resolve on its first ``status``
    poll: unlike the open-ended trace wrappers, ``step_count`` waits for
    the debugger to return to a *paused* state once its bounded step
    budget is exhausted, matching the real plugin's response after a
    fixed-count conditional trace finishes.

    Args:
        command: RPC command name.
        _params: Ignored parameters.

    Returns:
        dict[str, Any]: A success response for ``exec``, or a ``paused``
        debugger state for ``status``.

    Raises:
        AssertionError: If a command other than ``exec``/``status`` is sent.
    """
    if command == "exec":
        return {"id": 1, "success": True, "result": None}
    if command == "status":
        return {"id": 1, "success": True, "result": {"debugging": True, "paused": True, "initialized": True}}
    msg = f"unexpected command: {command}"
    raise AssertionError(msg)


def _sole_exec_command(fake: _FakePipeClient) -> str:
    """Return the single ``exec`` command string the bridge sent.

    Args:
        fake: The fake pipe client the bridge sent commands through.

    Returns:
        str: The ``command`` field of the one ``exec`` call recorded.
    """
    exec_calls = [params["command"] for cmd, params in fake.sent if cmd == "exec" and params is not None]
    assert len(exec_calls) == 1, f"expected exactly one exec call, got {exec_calls!r}"
    return exec_calls[0]


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestTraceIntoConditionalArgumentOrder:
    """Command-framing gates for ``trace_into`` against the real ``TraceIntoConditional`` contract.

    Per help.x64dbg.com, ``TraceIntoConditional``/``ticnd`` takes
    ``arg1`` (the required break condition, stop-on-nonzero) then
    ``[arg2]`` (the optional max step count) - not the reverse the
    wrapper used to send.
    """

    async def test_condition_occupies_arg1_and_max_steps_occupies_arg2(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A supplied condition is arg1; max_steps is arg2, in that order.

        Independent oracle: ``'TraceIntoConditional "eax==1", 12345'``.
        Mutation caught: reverting to the swapped framing sends
        ``'TraceIntoConditional 12345, "eax==1"'`` instead, which fails
        every assertion below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _running_after_exec)
        result = await bridge.trace_into(condition=_CONDITION, max_steps=_CUSTOM_MAX_STEPS)
        sent_command = _sole_exec_command(fake)
        assert sent_command == f'TraceIntoConditional "{_CONDITION}", {_CUSTOM_MAX_STEPS}'
        prefix = "TraceIntoConditional "
        assert sent_command.startswith(prefix)
        arg1, _, arg2 = sent_command[len(prefix) :].partition(",")
        assert arg1.strip() == f'"{_CONDITION}"'
        assert str(_CUSTOM_MAX_STEPS) not in arg1
        assert arg2.strip() == str(_CUSTOM_MAX_STEPS)
        assert result["success"] is True
        assert result["max_steps"] == _CUSTOM_MAX_STEPS

    async def test_omitted_condition_traces_up_to_max_steps_instead_of_stopping_immediately(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """No condition supplied still traces up to max_steps, not a single instruction.

        The original defect sent a bare ``"TraceIntoConditional
        50000"``: x64dbg parses a lone argument as the CONDITION, and
        any nonzero value is "other than 0", so tracing stopped after
        one instruction. The fix sends the documented always-false
        sentinel ``0`` as the condition (x64dbg's own Conditional
        Tracing feature defines the break condition's default as ``0``,
        meaning the debuggee never breaks on it) so ``max_steps``
        genuinely gates the trace.

        Independent oracle: ``"TraceIntoConditional 0, 50000"``.
        Mutation caught: reverting to the old framing sends
        ``"TraceIntoConditional 50000"`` (no comma, no second argument)
        instead, which fails every assertion below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _running_after_exec)
        result = await bridge.trace_into(max_steps=_DEFAULT_MAX_STEPS)
        sent_command = _sole_exec_command(fake)
        assert sent_command == f"TraceIntoConditional 0, {_DEFAULT_MAX_STEPS}"
        assert sent_command != f"TraceIntoConditional {_DEFAULT_MAX_STEPS}"
        prefix = "TraceIntoConditional "
        arg1, comma, arg2 = sent_command[len(prefix) :].partition(",")
        assert comma == ","
        assert arg1.strip() == "0"
        assert arg2.strip() == str(_DEFAULT_MAX_STEPS)
        assert result["success"] is True
        assert result["max_steps"] == _DEFAULT_MAX_STEPS


@pytest.mark.asyncio
class TestTraceOverConditionalArgumentOrder:
    """Command-framing gates for ``trace_over`` against the real ``TraceOverConditional`` contract.

    Mirrors :class:`TestTraceIntoConditionalArgumentOrder` for the
    ``StepOver``-based tracing wrapper.
    """

    async def test_condition_occupies_arg1_and_max_steps_occupies_arg2(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A supplied condition is arg1; max_steps is arg2, in that order.

        Independent oracle: ``'TraceOverConditional "eax==1", 12345'``.
        Mutation caught: reverting to the swapped framing sends
        ``'TraceOverConditional 12345, "eax==1"'`` instead, which fails
        every assertion below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _running_after_exec)
        result = await bridge.trace_over(condition=_CONDITION, max_steps=_CUSTOM_MAX_STEPS)
        sent_command = _sole_exec_command(fake)
        assert sent_command == f'TraceOverConditional "{_CONDITION}", {_CUSTOM_MAX_STEPS}'
        prefix = "TraceOverConditional "
        assert sent_command.startswith(prefix)
        arg1, _, arg2 = sent_command[len(prefix) :].partition(",")
        assert arg1.strip() == f'"{_CONDITION}"'
        assert str(_CUSTOM_MAX_STEPS) not in arg1
        assert arg2.strip() == str(_CUSTOM_MAX_STEPS)
        assert result["success"] is True
        assert result["max_steps"] == _CUSTOM_MAX_STEPS

    async def test_omitted_condition_traces_up_to_max_steps_instead_of_stopping_immediately(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """No condition supplied still traces up to max_steps, not a single instruction.

        Same defect as ``trace_into``: a bare ``"TraceOverConditional
        50000"`` is parsed by x64dbg as the break condition itself, so
        any nonzero step budget stopped the trace after one
        instruction.

        Independent oracle: ``"TraceOverConditional 0, 50000"``.
        Mutation caught: reverting to the old framing sends
        ``"TraceOverConditional 50000"`` (no comma, no second argument)
        instead, which fails every assertion below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _running_after_exec)
        result = await bridge.trace_over(max_steps=_DEFAULT_MAX_STEPS)
        sent_command = _sole_exec_command(fake)
        assert sent_command == f"TraceOverConditional 0, {_DEFAULT_MAX_STEPS}"
        assert sent_command != f"TraceOverConditional {_DEFAULT_MAX_STEPS}"
        prefix = "TraceOverConditional "
        arg1, comma, arg2 = sent_command[len(prefix) :].partition(",")
        assert comma == ","
        assert arg1.strip() == "0"
        assert arg2.strip() == str(_DEFAULT_MAX_STEPS)
        assert result["success"] is True
        assert result["max_steps"] == _DEFAULT_MAX_STEPS


@pytest.mark.asyncio
class TestStepCountCommandName:
    """Command-name gates for ``step_count`` against the real conditional-trace contract.

    ``step_count`` runs a fixed number of steps by issuing a bounded
    conditional trace with the always-false break condition ``0``:
    ``TraceIntoConditional 0, <count>`` (into) or
    ``TraceOverConditional 0, <count>`` (over). It used to send ``tic 0,
    <count>`` / ``toc 0, <count>``, but ``tic``/``toc`` are registered
    nowhere in x64dbg as command names or aliases (only ``ticnd``/
    ``tocnd`` and the full names are, per help.x64dbg.com), so a real
    plugin rejected them as unknown commands and no stepping occurred.
    """

    async def test_into_sends_traceintoconditional_with_condition_zero_then_count(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``step_type="into"`` emits ``TraceIntoConditional 0, <count>``, never ``tic``.

        Independent oracle: ``"TraceIntoConditional 0, 7"``. Mutation
        caught: reverting to ``f"tic 0, {count}"`` sends the unregistered
        ``"tic 0, 7"`` instead, which fails the exact-match, the
        ``!= "tic 0, 7"``, and the ``not startswith("tic ")`` assertions.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _paused_after_exec)
        result = await bridge.step_count(_STEP_COUNT, step_type="into")
        sent_command = _sole_exec_command(fake)
        assert sent_command == f"TraceIntoConditional 0, {_STEP_COUNT}"
        assert sent_command != f"tic 0, {_STEP_COUNT}"
        assert not sent_command.startswith("tic ")
        prefix = "TraceIntoConditional "
        assert sent_command.startswith(prefix)
        arg1, comma, arg2 = sent_command[len(prefix) :].partition(",")
        assert comma == ","
        assert arg1.strip() == "0"
        assert arg2.strip() == str(_STEP_COUNT)
        assert result["success"] is True
        assert result["verified"] is True
        assert result["count"] == _STEP_COUNT
        assert result["step_type"] == "into"

    async def test_over_sends_traceoverconditional_with_condition_zero_then_count(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``step_type="over"`` emits ``TraceOverConditional 0, <count>``, never ``toc``.

        Independent oracle: ``"TraceOverConditional 0, 7"``. Mutation
        caught: reverting to ``f"toc 0, {count}"`` sends the unregistered
        ``"toc 0, 7"`` instead, which fails the exact-match, the
        ``!= "toc 0, 7"``, and the ``not startswith("toc ")`` assertions.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _paused_after_exec)
        result = await bridge.step_count(_STEP_COUNT, step_type="over")
        sent_command = _sole_exec_command(fake)
        assert sent_command == f"TraceOverConditional 0, {_STEP_COUNT}"
        assert sent_command != f"toc 0, {_STEP_COUNT}"
        assert not sent_command.startswith("toc ")
        prefix = "TraceOverConditional "
        assert sent_command.startswith(prefix)
        arg1, comma, arg2 = sent_command[len(prefix) :].partition(",")
        assert comma == ","
        assert arg1.strip() == "0"
        assert arg2.strip() == str(_STEP_COUNT)
        assert result["success"] is True
        assert result["verified"] is True
        assert result["count"] == _STEP_COUNT
        assert result["step_type"] == "over"
