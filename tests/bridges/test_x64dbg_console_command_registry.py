# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Registry gates: every console command the x64dbg bridge emits must exist.

``X64DbgBridge`` reaches x64dbg's command interpreter two ways -
``_send_command`` (which wraps the string in an ``exec`` RPC) and a direct
``_send_pipe_command("exec", ...)``. Both are parsed by the interpreter, which
accepts only names registered by ``registercommands()`` in
``src/dbg/x64dbg.cpp``.

Every command string the bridge emits was checked against three independent
sources: that ``registercommands()`` table, the per-category command reference
on help.x64dbg.com, and the literal strings compiled into the shipped
``x64dbg.dll``, ``x64dbg.exe`` and ``x64bridge.dll``. Seven names appear in
none of the three, so a real x64dbg rejects them as unknown commands:

* ``runto`` - :meth:`run_to` never moved the instruction pointer. Replaced by
  the plugin's ``run_to`` RPC, which arms ``bp <address>, ss`` then ``run``.
* ``AnimateInto``/``AnimateOver`` - :meth:`animate_start` never started
  stepping. Animation is GUI-only (Ctrl+F7/Ctrl+F8) and the table registers
  only ``AnimateWait``. Replaced by a conditional trace whose break condition
  never trips.
* ``AnimateStop`` - :meth:`animate_stop` never stopped anything. Replaced by
  ``pause``, documented as "Pause the debuggee or stop animation if animation
  is in progress".
* ``scriptabort`` - :meth:`script_abort` never aborted the running script.
  Replaced by the plugin's ``script_abort`` RPC, which calls the bridge SDK's
  ``DbgScriptAbort()``.
* ``patchrestore`` and ``pluglist`` - dead console fallbacks that reported
  success while doing nothing, masking the real RPC failure behind them. Both
  fallbacks are removed so the RPC error reaches the caller.

These gates record every ``(command, params)`` pair the bridge emits and assert
the exact replacement plus an explicit negative assertion against the
unregistered spelling, so a reversion fails loudly instead of silently issuing
a command x64dbg will reject. The fake pipe client is reproduced here rather
than imported, matching the isolation the sibling command-framing suite
documents.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


_TARGET_ADDRESS: Final[int] = 0x401000

# Proven absent from registercommands(), help.x64dbg.com and the shipped
# x64dbg binaries. No bridge method may ever emit one of these again.
_UNREGISTERED_COMMANDS: Final[frozenset[str]] = frozenset(
    {
        "runto",
        "AnimateInto",
        "AnimateOver",
        "AnimateStop",
        "scriptabort",
        "patchrestore",
        "pluglist",
    },
)


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge emits in the
    ``sent`` instance list and returns the response produced by the
    caller-supplied ``responder`` callable. The ``is_connected``
    property always returns ``True`` so the bridge never attempts a
    real reconnect.
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


def _ok(result: object = None) -> dict[str, Any]:
    """Build a successful pipe response.

    Args:
        result: Payload to return as the RPC result.

    Returns:
        dict[str, Any]: A success response envelope.
    """
    return {"id": 1, "success": True, "result": result}


def _rpc_missing(command: str) -> dict[str, Any]:
    """Build the response an older plugin returns for an unimplemented RPC.

    The ``unknown_command`` code is the single member of the bridge's
    recoverable-error set, so this is exactly the failure that used to
    trigger the removed console-command fallbacks.

    Args:
        command: RPC name the plugin does not implement.

    Returns:
        dict[str, Any]: A failure envelope carrying ``unknown_command``.
    """
    return {
        "id": 1,
        "success": False,
        "error": f"unknown command: {command}",
        "code": "unknown_command",
    }


def _exec_commands(fake: _FakePipeClient) -> list[str]:
    """Return every console command string the bridge pushed through ``exec``.

    Args:
        fake: The fake pipe client the bridge sent commands through.

    Returns:
        list[str]: The ``command`` field of each ``exec`` call, in order.
    """
    return [
        str(params["command"])
        for command, params in fake.sent
        if command == "exec" and params is not None and "command" in params
    ]


def _assert_no_unregistered_command(fake: _FakePipeClient) -> None:
    """Fail if any emitted console command names an unregistered x64dbg command.

    Args:
        fake: The fake pipe client the bridge sent commands through.
    """
    for sent in _exec_commands(fake):
        head = sent.split(" ", 1)[0].rstrip(",")
        assert head not in _UNREGISTERED_COMMANDS, (
            f"bridge emitted unregistered x64dbg command {head!r} (full command: {sent!r})"
        )


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestRunToUsesThePluginRpc:
    """``run_to`` must drive the plugin's ``run_to`` RPC, never a ``runto`` command."""

    async def test_run_to_dispatches_run_to_rpc_and_never_sends_runto(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``run_to`` sends the ``run_to`` RPC and issues no console command.

        Independent oracle: a single ``("run_to", {"address": "0x401000"})``
        call. Mutation caught: reverting to
        ``_send_pipe_command("exec", {"command": f"runto {hex(address)}"})``
        records an ``exec`` carrying the unregistered ``runto`` command and
        no ``run_to`` call, failing every assertion below.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "run_to":
                return _ok(hex(_TARGET_ADDRESS))
            if command == "reg_get":
                return _ok(hex(_TARGET_ADDRESS))
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.run_to(_TARGET_ADDRESS)

        run_to_calls = [params for command, params in fake.sent if command == "run_to"]
        assert run_to_calls == [{"address": hex(_TARGET_ADDRESS)}]
        assert _exec_commands(fake) == []
        _assert_no_unregistered_command(fake)
        assert result["success"] is True
        assert result["target"] == hex(_TARGET_ADDRESS)


@pytest.mark.asyncio
class TestAnimateStartUsesAConditionalTrace:
    """``animate_start`` must drive a conditional trace, never ``AnimateInto``/``AnimateOver``."""

    async def test_into_sends_traceintoconditional_not_animateinto(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``step_type="into"`` emits ``TraceIntoConditional 0, <budget>``.

        Independent oracle:
        ``f"TraceIntoConditional 0, {X64DbgBridge.ANIMATE_MAX_STEPS}"``.
        Mutation caught: reverting to ``"AnimateInto"`` emits a command
        x64dbg does not register, failing the equality and the explicit
        ``!= "AnimateInto"`` assertion.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return _ok()
            if command == "status":
                return _ok({"debugging": True, "paused": False, "initialized": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.animate_start(step_type="into")

        sent = _exec_commands(fake)
        assert sent == [f"TraceIntoConditional 0, {X64DbgBridge.ANIMATE_MAX_STEPS}"]
        assert sent[0] != "AnimateInto"
        _assert_no_unregistered_command(fake)
        assert result["success"] is True
        assert result["step_type"] == "into"

    async def test_over_sends_traceoverconditional_not_animateover(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``step_type="over"`` emits ``TraceOverConditional 0, <budget>``.

        Independent oracle:
        ``f"TraceOverConditional 0, {X64DbgBridge.ANIMATE_MAX_STEPS}"``.
        Mutation caught: reverting to ``"AnimateOver"`` emits a command
        x64dbg does not register, failing the equality and the explicit
        ``!= "AnimateOver"`` assertion.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return _ok()
            if command == "status":
                return _ok({"debugging": True, "paused": False, "initialized": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.animate_start(step_type="over")

        sent = _exec_commands(fake)
        assert sent == [f"TraceOverConditional 0, {X64DbgBridge.ANIMATE_MAX_STEPS}"]
        assert sent[0] != "AnimateOver"
        _assert_no_unregistered_command(fake)
        assert result["success"] is True
        assert result["step_type"] == "over"

    async def test_animate_budget_is_a_positive_step_count(self) -> None:
        """The animate trace budget must be a usable positive step count.

        A conditional trace stops at ``arg2`` steps, so a zero or negative
        budget would end the animation immediately instead of stepping
        until :meth:`animate_stop`.
        """
        assert isinstance(X64DbgBridge.ANIMATE_MAX_STEPS, int)
        assert X64DbgBridge.ANIMATE_MAX_STEPS > 0


@pytest.mark.asyncio
class TestAnimateStopUsesPause:
    """``animate_stop`` must send ``pause``, never ``AnimateStop``."""

    async def test_animate_stop_sends_pause_not_animatestop(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``animate_stop`` emits exactly ``pause``.

        Independent oracle: ``"pause"``. Mutation caught: reverting to
        ``"AnimateStop"`` emits a command absent from the shipped
        ``x64dbg.dll``, failing the equality and the explicit
        ``!= "AnimateStop"`` assertion.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return _ok()
            if command == "status":
                return _ok({"debugging": True, "paused": True, "initialized": True})
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.animate_stop()

        sent = _exec_commands(fake)
        assert sent == ["pause"]
        assert sent[0] != "AnimateStop"
        _assert_no_unregistered_command(fake)
        assert result["success"] is True


@pytest.mark.asyncio
class TestScriptAbortUsesThePluginRpc:
    """``script_abort`` must drive the ``script_abort`` RPC, never a console command."""

    async def test_script_abort_dispatches_rpc_and_never_sends_scriptabort(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``script_abort`` sends the ``script_abort`` RPC and no console command.

        Independent oracle: one ``script_abort`` RPC call, and the only
        ``eval`` being the ``script.iserror()`` verification. Mutation
        caught: reverting to ``_send_command("scriptabort")`` records an
        ``exec`` carrying the unregistered ``scriptabort`` command and no
        ``script_abort`` call.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "script_abort":
                return _ok(result=True)
            if command == "eval":
                return _ok(0)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.script_abort()

        assert [command for command, _params in fake.sent if command == "script_abort"] == ["script_abort"]
        assert _exec_commands(fake) == []
        _assert_no_unregistered_command(fake)
        assert result["success"] is True
        assert result["verified"] is True


@pytest.mark.asyncio
class TestDeadConsoleFallbacksAreGone:
    """A failing RPC must surface, never fall back to an unregistered command.

    ``restore_patch`` and ``plugin_list`` used to answer an
    ``unknown_command`` RPC failure by sending ``patchrestore`` /
    ``pluglist``. Neither is a registered x64dbg command, so the fallback
    restored nothing and listed nothing while still reporting success,
    hiding the real failure from the caller.
    """

    async def test_restore_patch_propagates_rpc_failure_without_sending_patchrestore(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A missing ``patch_restore`` RPC raises instead of sending ``patchrestore``.

        Mutation caught: restoring the ``except ToolError`` fallback
        swallows the error and emits ``patchrestore <address>``, so the
        ``pytest.raises`` and the "no exec" assertion both fail.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "patch_restore":
                return _rpc_missing("patch_restore")
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError):
            await bridge.restore_patch(_TARGET_ADDRESS)

        assert _exec_commands(fake) == []
        _assert_no_unregistered_command(fake)

    async def test_plugin_list_propagates_rpc_failure_without_sending_pluglist(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A missing ``plugin_list`` RPC raises instead of sending ``pluglist``.

        Mutation caught: restoring the ``except ToolError`` fallback
        swallows the error, emits ``pluglist`` and returns ``[]``, so the
        ``pytest.raises`` and the "no exec" assertion both fail.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "plugin_list":
                return _rpc_missing("plugin_list")
            if command == "exec":
                return _ok()
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError):
            await bridge.plugin_list()

        assert _exec_commands(fake) == []
        _assert_no_unregistered_command(fake)

    async def test_plugin_list_returns_the_roster_the_plugin_reports(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A working ``plugin_list`` RPC is marshalled straight through.

        Guards the repaired plugin handler's contract: it now returns a
        JSON array of plugin objects rather than the bare ``"true"`` the
        old ``DbgCmdExec("pluglist")`` implementation produced.

        Args:
            bridge: Fixture bridge instance.
        """
        roster: list[dict[str, str]] = [
            {"name": "intellicrack_bridge_x64", "file": "intellicrack_bridge_x64.dp64"},
        ]

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "plugin_list":
                return _ok(roster)
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.plugin_list()

        assert result == roster
        assert _exec_commands(fake) == []
