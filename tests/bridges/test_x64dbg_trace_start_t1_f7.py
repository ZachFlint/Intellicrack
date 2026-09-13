# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Tier-1 Finding #7 regression gates for ``X64DbgBridge.trace_start``.

Finding closed:
    T1-7  ``trace_start`` issued a ``TraceSetCondition {addr}, {condition}``
          form that is not a real x64dbg command under any name or alias,
          and framed ``TraceSetLog`` with an address it never accepts -
          both additionally gated on ``address is not None``, which the
          Trace tab's Condition/Log inputs never supply. The Trace tab's
          Condition/Log text was therefore silently dropped on every GUI
          call, with no error, and the debugger only ever ran a bare,
          argument-less ``StartRunTrace``.

Each test drives the real bridge method against an in-process
``_FakePipeClient`` that records every ``(command, params)`` pair sent and
returns scripted responses. Every oracle value (expected command strings,
the auto-generated trace file's parent directory and suffix) is derived
independently in this file from the real x64dbg command semantics
documented at help.x64dbg.com, never by re-invoking the production code
under test.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


if TYPE_CHECKING:
    from collections.abc import Callable


_TRACE_ADDR: Final[int] = 0x4010AB
_TRACE_CONDITION: Final[str] = "eax==1"
_TRACE_LOG_TEXT: Final[str] = "hit:eax"
_EXPECTED_TRACE_DIR: Final[Path] = Path(tempfile.gettempdir()) / "intellicrack" / "x64dbg_traces"


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge emits in the ``sent``
    instance list and returns the response produced by the caller-supplied
    ``responder`` callable. The ``is_connected`` property always returns
    ``True`` so the bridge never attempts a real reconnect.
    """

    def __init__(
        self,
        responder: Callable[[str, dict[str, Any] | None], dict[str, Any]],
    ) -> None:
        """Initialise the fake pipe client.

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
            int | None: Always ``None``, indicating this stand-in debugger
            process is still running.
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


def _always_ok(
    _command: str,
    _params: dict[str, Any] | None,
) -> dict[str, Any]:
    """Return a generic success response for any command.

    Args:
        _command: Ignored command name.
        _params: Ignored parameters.

    Returns:
        dict[str, Any]: ``{"success": True, "result": None}``.
    """
    return {"success": True, "result": None}


def _exec_commands(fake: _FakePipeClient) -> list[str]:
    """Extract the ``command`` string from every ``exec`` RPC the bridge sent.

    Args:
        fake: The fake pipe client that recorded the bridge's calls.

    Returns:
        list[str]: Command strings in send order.
    """
    return [params["command"] for name, params in fake.sent if name == "exec" and params is not None]


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached, default-64-bit bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


@pytest.mark.asyncio
class TestTraceStartLogAndConditionGenuinelyApply:
    """T1-7: ``trace_start`` must genuinely apply a supplied condition/log, or raise."""

    async def test_no_params_opens_a_real_run_trace_file(self, bridge: X64DbgBridge) -> None:
        """No condition/log still issues a valid, argument-complete ``StartRunTrace``.

        ``StartRunTrace``'s file-name argument is required (help.x64dbg.com),
        so a bare ``StartRunTrace`` with no argument - what the old code
        always sent - never actually opens a trace. This asserts the exec
        command carries a real, non-empty, quoted file path under the
        expected temp directory with the ``.trace64`` extension (default
        ``is_64bit=True``).

        Mutation caught: reverting to a bare ``"StartRunTrace"`` command
        (no file argument) fails the substring/suffix assertions below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_start()

        assert len(fake.sent) == 1
        cmd, params = fake.sent[0]
        assert cmd == "exec"
        assert params is not None
        sent_command = params["command"]
        assert sent_command.startswith('StartRunTrace "')
        assert sent_command.endswith('"')
        trace_file = Path(sent_command[len('StartRunTrace "') : -1])
        assert trace_file.parent == _EXPECTED_TRACE_DIR
        assert trace_file.suffix == ".trace64"
        assert result["success"] is True
        assert result["trace_file"] == str(trace_file)
        assert "log_text" not in result

    async def test_log_text_alone_issues_real_trace_set_log_before_start(self, bridge: X64DbgBridge) -> None:
        """``log_text`` with no condition sends ``TraceSetLog "<text>"`` then ``StartRunTrace``.

        Independent oracle: ``TraceSetLog``'s only two arguments are log
        text and log condition (help.x64dbg.com TraceSetLog) - no address
        is ever involved, unlike the old, always-suppressed
        ``TraceSetLog {hex(addr)}, {text}`` form.

        Mutation caught: omitting the ``TraceSetLog`` call, misspelling
        it, or leaving the text unquoted fails the exact-string assertion;
        sending it after ``StartRunTrace`` fails the ordering assertion.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_start(log_text=_TRACE_LOG_TEXT)

        commands = _exec_commands(fake)
        assert len(commands) == 2
        assert commands[0] == f'TraceSetLog "{_TRACE_LOG_TEXT}"'
        assert commands[1].startswith('StartRunTrace "')
        assert result["success"] is True
        assert result["log_text"] == _TRACE_LOG_TEXT
        assert result["log_condition"] is None

    async def test_condition_with_log_text_genuinely_applies_as_log_condition(self, bridge: X64DbgBridge) -> None:
        """``condition`` + ``log_text`` sends ``TraceSetLog "<text>", "<condition>"``.

        This is the core T1-7 regression gate: an operator-typed condition
        must genuinely reach x64dbg. Here it takes effect as ``TraceSetLog``'s
        second (log-condition) argument - the real, documented role a
        condition plays alongside log text - never as the fabricated
        ``TraceSetCondition`` command the old code sent.

        Mutation caught: dropping the condition from the ``TraceSetLog``
        call (the original silent-drop defect) or reintroducing
        ``TraceSetCondition`` anywhere fails these assertions.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_start(condition=_TRACE_CONDITION, log_text=_TRACE_LOG_TEXT)

        commands = _exec_commands(fake)
        assert commands[0] == f'TraceSetLog "{_TRACE_LOG_TEXT}", "{_TRACE_CONDITION}"'
        assert not any("TraceSetCondition" in c for c in commands)
        assert result["log_text"] == _TRACE_LOG_TEXT
        assert result["log_condition"] == _TRACE_CONDITION

    async def test_address_is_folded_into_the_generated_trace_file_name(self, bridge: X64DbgBridge) -> None:
        """A supplied ``address`` appears in the auto-generated trace file name.

        No real ``StartRunTrace``/``TraceSetLog`` command accepts an
        address, but ``address`` still has an observable effect here
        (operator-reference file naming) rather than being silently inert.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_start(address=_TRACE_ADDR)

        assert f"{_TRACE_ADDR:08x}" in str(result["trace_file"])
        cmd, params = fake.sent[-1]
        assert cmd == "exec"
        assert params is not None
        assert f"{_TRACE_ADDR:08x}" in params["command"]

    async def test_32bit_bridge_uses_trace32_extension(self, bridge: X64DbgBridge) -> None:
        """A 32-bit bridge names its trace file with a ``.trace32`` extension.

        Mutation caught: hard-coding the ``.trace64`` extension regardless
        of ``is_64bit`` fails this assertion.

        Args:
            bridge: Fixture bridge instance.
        """
        bridge.is_64bit = False
        fake = _install_fake_pipe(bridge, _always_ok)
        await bridge.trace_start()

        _cmd, params = fake.sent[-1]
        assert params is not None
        assert params["command"].rstrip('"').endswith(".trace32")

    async def test_condition_without_log_text_raises_instead_of_silent_unconditional_trace(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A bare condition with no log text raises rather than silently tracing unconditionally.

        This is the exact silent-success defect Finding #7 describes: an
        operator types only a Condition and clicks Start. ``TraceSetLog``
        cannot set a condition without also setting log text, and
        ``StartRunTrace`` accepts no condition of any kind, so there is no
        real command this can bind to - the fix must raise here instead of
        falling through to an unconditional ``StartRunTrace`` with no
        error, which is what the old ``address is not None`` guard did on
        every GUI call (the Trace tab has no address field).

        Mutation caught: reverting to the old silent-drop behavior sends a
        bare ``StartRunTrace`` and returns ``{"success": True}`` instead of
        raising, so ``pytest.raises`` fails and ``fake.sent`` is non-empty.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)

        with pytest.raises(ToolError, match="condition"):
            await bridge.trace_start(condition=_TRACE_CONDITION)

        assert fake.sent == []
