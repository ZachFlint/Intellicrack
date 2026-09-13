# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Wave-2b trace and run-control gates for ``intellicrack.bridges.x64dbg``.

Covers the trace, step, and navigation family that had no prior real coverage:
``trace_start``, ``trace_stop``, ``get_trace_record``, ``execute_til_return``,
``skip_instruction``, ``set_ip``, and ``goto_address``.

The following operations are in scope per the assignment but already carry
REAL gates in earlier audit files; they are excluded here to prevent
duplicate coverage:

* ``trace_into``   — TestTraceAndAnimateVerification in test_x64dbg_audit7_f0001.py
* ``trace_over``   — TestTraceAndAnimateVerification in test_x64dbg_audit7_f0001.py
* ``step_count``   — TestTraceAndAnimateVerification in test_x64dbg_audit7_f0001.py
* ``animate_start`` — TestTraceAndAnimateVerification in test_x64dbg_audit7_f0001.py
* ``animate_stop``  — TestTraceAndAnimateVerification in test_x64dbg_audit7_f0001.py
* ``run_to``        — TestRunToVerification in test_x64dbg_audit6.py

Each test in this file drives the real bridge method against an in-process
``_FakePipeClient`` that records sent ``(command, params)`` pairs and returns
scripted responses.  Assertions check BOTH the exact command framing the
bridge emitted AND the parsed return value it produced from the canned
response.  Every oracle value is derived from an independent constant
defined in this file, never re-computed via the production code under test.
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
_GOTO_ADDR: Final[int] = 0x00403210
_SKIP_IP: Final[int] = 0x00401000
_NEW_IP_1BYTE: Final[int] = 0x00401001
_NEW_IP_2BYTE: Final[int] = 0x00401002
_HIT_COUNT: Final[int] = 42
_TRACE_RECORD_ADDR: Final[int] = 0x00401234


class _FakePipeClient:
    """In-process substitute for ``NamedPipeClient``.

    Records every ``(command, params)`` pair the bridge emits in the ``sent``
    instance list and returns the response produced by the caller-supplied
    ``responder`` callable.  The ``is_connected`` property always returns
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

    Also installs a sentinel ``_process`` so wrappers that gate on
    ``self._process is not None`` (e.g. ``_send_command``) do not
    short-circuit before reaching the pipe.

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


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


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


@pytest.mark.asyncio
class TestTraceStart:
    """Command-framing gates for ``trace_start`` against its real x64dbg contract.

    x64dbg exposes no ``TraceSetCondition`` command under any name or
    alias, ``TraceSetLog`` only ever takes ``[log text]``/``[log
    condition]`` (never an address), and ``StartRunTrace``'s file-name
    argument is required, not optional (help.x64dbg.com). The oracle for
    every assertion below is that real command shape, derived
    independently from the known inputs - never the fabricated,
    address-gated framing this class used to pin.
    """

    async def test_no_params_emits_only_start_run_trace(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """No address/condition/log_text still opens a real, argument-complete trace.

        ``StartRunTrace``'s file-name argument is required, not optional
        (help.x64dbg.com StartRunTrace) - the bare, argument-less
        ``"StartRunTrace"`` this test used to pin never actually opened a
        trace file.

        Mutation caught: reverting to a bare ``"StartRunTrace"`` command,
        or emitting more than the one exec call, fails the assertions
        below.

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
        assert "TraceSetCondition" not in sent_command
        assert sent_command.startswith('StartRunTrace "')
        assert sent_command.endswith('.trace64"')
        assert str(_EXPECTED_TRACE_DIR) in sent_command
        assert result["success"] is True
        assert result["trace_file"] == sent_command[len('StartRunTrace "') : -1]
        assert "log_text" not in result
        assert "log_condition" not in result

    async def test_with_address_and_log_text_sends_trace_set_log_then_start(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Address + log_text sends a real, address-free quoted TraceSetLog, then StartRunTrace.

        ``TraceSetLog``'s only two arguments are ``[log text]`` and
        ``[log condition]`` (help.x64dbg.com TraceSetLog) - it never
        takes an address, unlike the fabricated
        ``f"TraceSetLog {hex(_TRACE_ADDR)}, {_TRACE_LOG_TEXT}"`` framing
        this test used to pin. ``address`` only folds into the generated
        trace file name, never into the ``TraceSetLog`` command itself.

        Mutation caught: reintroducing the address into the
        ``TraceSetLog`` command, leaving the log text unquoted, or
        emitting the two commands out of order fails the assertions
        below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        await bridge.trace_start(address=_TRACE_ADDR, log_text=_TRACE_LOG_TEXT)
        assert len(fake.sent) == 2
        log_cmd, log_params = fake.sent[0]
        assert log_cmd == "exec"
        assert log_params is not None
        assert log_params["command"] == f'TraceSetLog "{_TRACE_LOG_TEXT}"'
        assert hex(_TRACE_ADDR) not in log_params["command"]
        start_cmd, start_params = fake.sent[1]
        assert start_cmd == "exec"
        assert start_params is not None
        assert start_params["command"].startswith('StartRunTrace "')
        assert f"{_TRACE_ADDR:08x}" in start_params["command"]

    async def test_address_and_condition_without_log_text_raises_tool_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Address + condition with no log_text raises instead of faking a command.

        x64dbg exposes no ``TraceSetCondition`` command under any name or
        alias (help.x64dbg.com tracing command index) - the
        ``f"TraceSetCondition {hex(_TRACE_ADDR)}, {_TRACE_CONDITION}"``
        string this test used to pin was never real. Supplying
        ``address`` must not smuggle a bare condition past the guard:
        ``TraceSetLog`` cannot carry a condition without also carrying
        log text, and ``StartRunTrace`` takes no condition at all, so
        this raises before anything is sent.

        Mutation caught: reintroducing an address-gated branch that
        sends ``TraceSetCondition`` (or any command) instead of raising
        fails both assertions below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        with pytest.raises(ToolError, match="condition"):
            await bridge.trace_start(address=_TRACE_ADDR, condition=_TRACE_CONDITION)
        assert fake.sent == []

    async def test_all_params_emits_two_commands_with_condition_folded_into_log(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Address + condition + log_text -> TraceSetLog carrying the condition, then StartRunTrace.

        x64dbg has no command that binds a condition to ``trace_start``
        on its own, so a supplied ``condition`` only takes effect as
        ``TraceSetLog``'s second (log-condition) argument once
        ``log_text`` is also present - never as a separate
        ``TraceSetCondition`` exec, and never as a third command. This
        test used to pin a three-command ``TraceSetLog``,
        ``TraceSetCondition``, ``StartRunTrace`` sequence built from
        command framing that was never real.

        Mutation caught: splitting the condition back out into its own
        command, dropping it from ``TraceSetLog``, or emitting a third
        command fails the assertions below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_start(
            address=_TRACE_ADDR,
            condition=_TRACE_CONDITION,
            log_text=_TRACE_LOG_TEXT,
        )
        assert len(fake.sent) == 2
        commands = [p["command"] for _, p in fake.sent if p is not None]
        assert commands[0] == f'TraceSetLog "{_TRACE_LOG_TEXT}", "{_TRACE_CONDITION}"'
        assert commands[1].startswith('StartRunTrace "')
        assert not any("TraceSetCondition" in c for c in commands)
        assert result["log_text"] == _TRACE_LOG_TEXT
        assert result["log_condition"] == _TRACE_CONDITION

    async def test_log_text_without_address_still_sends_trace_set_log(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """log_text with no address still issues TraceSetLog, not just a bare StartRunTrace.

        The old ``if address is not None and log_text is not None``
        guard silently dropped ``log_text`` whenever no address was
        supplied - exactly the case the Trace tab's Condition/Log
        inputs always hit, since that tab carries no address field.
        ``TraceSetLog`` never took an address to begin with, so there is
        nothing left to gate on.

        Mutation caught: reintroducing any address-based guard around
        the ``TraceSetLog`` call collapses this back to a single
        ``StartRunTrace`` and fails the count/content assertions below.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_start(log_text=_TRACE_LOG_TEXT)
        assert len(fake.sent) == 2
        log_cmd, log_params = fake.sent[0]
        assert log_cmd == "exec"
        assert log_params is not None
        assert log_params["command"] == f'TraceSetLog "{_TRACE_LOG_TEXT}"'
        start_cmd, start_params = fake.sent[1]
        assert start_cmd == "exec"
        assert start_params is not None
        assert start_params["command"].startswith('StartRunTrace "')
        assert start_params["command"].endswith('.trace64"')
        assert result["success"] is True
        assert result["log_text"] == _TRACE_LOG_TEXT
        assert result["log_condition"] is None

    async def test_condition_without_log_text_raises_tool_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A bare condition with no log_text and no address raises, not a silent trace.

        This is the exact silent-success defect the fix closes: an
        operator supplies only a Condition. ``TraceSetLog`` cannot carry
        a condition without log text, and ``StartRunTrace`` accepts no
        condition at all, so there is no real command left to bind this
        to - the bridge must raise here instead of falling through to an
        unconditional, successfully-reported trace.

        Mutation caught: reverting to the old silent-drop behavior sends
        a bare ``StartRunTrace`` and reports success instead of raising,
        so ``pytest.raises`` fails and ``fake.sent`` is non-empty.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        with pytest.raises(ToolError, match="condition"):
            await bridge.trace_start(condition=_TRACE_CONDITION)
        assert fake.sent == []


@pytest.mark.asyncio
class TestTraceStop:
    """Command-framing and return-value gates for ``trace_stop``."""

    async def test_sends_stop_run_trace_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Verifies exactly one exec with command value ``"StopRunTrace"``.

        Mutation caught: substituting "StopTrace" or "StopRunning" for
        "StopRunTrace" causes the assertion to fail.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        await bridge.trace_stop()
        assert len(fake.sent) == 1
        cmd, params = fake.sent[0]
        assert cmd == "exec"
        assert params is not None
        assert params["command"] == "StopRunTrace"

    async def test_returns_success_true(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Return value is exactly ``{"success": True}``.

        Mutation caught: returning ``{"success": False}`` or adding extra
        unexpected keys changes the equality check.

        Args:
            bridge: Fixture bridge instance.
        """
        _install_fake_pipe(bridge, _always_ok)
        result = await bridge.trace_stop()
        assert result == {"success": True}


@pytest.mark.asyncio
class TestGetTraceRecord:
    """Command-framing and response-parsing gates for ``get_trace_record``."""

    async def test_emits_trace_record_rpc_with_hex_address_and_int_size(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The "trace_record" RPC is sent with ``{"address": hex(addr), "size": size}``.

        Independent oracle: ``{"address": hex(_TRACE_RECORD_ADDR), "size": 4}``.
        Mutation caught: renaming the RPC to "get_trace", encoding address as
        decimal, or using the wrong size key causes the framing assertion to fail.

        Args:
            bridge: Fixture bridge instance.
        """
        size = 4

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "trace_record":
                return {"success": True, "result": {"address": hex(_TRACE_RECORD_ADDR), "hitCount": 0}}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.get_trace_record(_TRACE_RECORD_ADDR, size)
        assert len(fake.sent) == 1
        cmd, params = fake.sent[0]
        assert cmd == "trace_record"
        assert params == {"address": hex(_TRACE_RECORD_ADDR), "size": size}

    async def test_returns_parsed_hit_count_from_canned_response(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The dict from the pipe is returned directly with the exact hitCount value.

        Independent oracle: ``_HIT_COUNT = 42``.
        Mutation caught: reading ``hitCount`` from the wrong response key or
        hard-coding a default returns 0 instead of 42.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {
                "success": True,
                "result": {"address": hex(_TRACE_RECORD_ADDR), "hitCount": _HIT_COUNT},
            }

        _install_fake_pipe(bridge, responder)
        result = await bridge.get_trace_record(_TRACE_RECORD_ADDR)
        assert result["hitCount"] == _HIT_COUNT
        assert result["address"] == hex(_TRACE_RECORD_ADDR)

    async def test_returns_zero_hit_count_on_unknown_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Plugin lacking ``trace_record`` falls back to default ``{"hitCount": 0}``.

        Mutation caught: removing the recoverable-error fallback causes the
        ``ToolError`` to propagate instead of returning the zero-hitCount dict.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Unknown command 'trace_record'"}

        _install_fake_pipe(bridge, responder)
        result = await bridge.get_trace_record(_TRACE_RECORD_ADDR)
        assert result["hitCount"] == 0
        assert result["address"] == hex(_TRACE_RECORD_ADDR)

    async def test_propagates_pipe_disconnect_as_tool_error(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A pipe-disconnect error is non-recoverable and re-raises as ToolError.

        Mutation caught: treating pipe_disconnected as recoverable would return
        the zero-hitCount fallback instead of raising.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": False, "error": "Pipe not connected"}

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="Pipe not connected"):
            await bridge.get_trace_record(_TRACE_RECORD_ADDR)

    async def test_returns_default_when_result_is_not_a_dict(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Non-dict result (e.g. a string) falls back to ``{"hitCount": 0}``.

        Mutation caught: removing the ``_is_str_obj_dict`` check would return
        the string directly, breaking callers that expect a dict.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": "unexpected-string"}

        _install_fake_pipe(bridge, responder)
        result = await bridge.get_trace_record(_TRACE_RECORD_ADDR)
        assert result["hitCount"] == 0
        assert result["address"] == hex(_TRACE_RECORD_ADDR)


@pytest.mark.asyncio
class TestExecuteTilReturn:
    """Command-framing and return-value gates for ``execute_til_return``."""

    async def test_sends_erun_via_exec_rpc(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Verifies the "erun" console command is issued via the exec RPC.

        Mutation caught: substituting "rtr" or "run" for "erun" in the
        command string causes the assertion to fail.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        await bridge.execute_til_return()
        assert len(fake.sent) == 1
        cmd, params = fake.sent[0]
        assert cmd == "exec"
        assert params is not None
        assert params["command"] == "erun"

    async def test_returns_success_true(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Return value is exactly ``{"success": True}``.

        Args:
            bridge: Fixture bridge instance.
        """
        _install_fake_pipe(bridge, _always_ok)
        result = await bridge.execute_til_return()
        assert result == {"success": True}


@pytest.mark.asyncio
class TestSkipInstruction:
    """Round-trip gates for ``skip_instruction`` using a three-RPC fake pipe.

    ``skip_instruction`` issues three RPC calls in sequence:
    1. ``reg_all`` (no params) to read the current ``rip``.
    2. ``disasm`` with ``{"address": hex(rip), "count": 1}`` to get the
       instruction byte length.
    3. ``exec`` with ``{"command": "rip=hex(new_ip)"}`` to advance the IP.

    Each test below controls all three responses and asserts on the
    exact exec command framing and the exact return-value fields.
    """

    @staticmethod
    def _make_skip_responder(
        rip: int,
        instr_bytes_nospace: str,
    ) -> Callable[[str, dict[str, Any] | None], dict[str, Any]]:
        """Build a responder for the three RPC calls ``skip_instruction`` issues.

        Args:
            rip: Value for the ``rip`` register returned by ``reg_all``.
            instr_bytes_nospace: Instruction bytes as a hex string without
                spaces (e.g. ``"90"`` for NOP, ``"31c0"`` for xor eax,eax).

        Returns:
            Callable[[str, dict[str, Any] | None], dict[str, Any]]:
            Responder function suitable for ``_install_fake_pipe``.
        """
        instr_len = len(bytes.fromhex(instr_bytes_nospace))
        new_ip = rip + instr_len

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_all":
                return {
                    "success": True,
                    "result": {
                        "rip": rip,
                        "rax": 0,
                        "rbx": 0,
                        "rcx": 0,
                        "rdx": 0,
                        "rsi": 0,
                        "rdi": 0,
                        "rbp": 0,
                        "rsp": 0,
                        "r8": 0,
                        "r9": 0,
                        "r10": 0,
                        "r11": 0,
                        "r12": 0,
                        "r13": 0,
                        "r14": 0,
                        "r15": 0,
                        "rflags": 0,
                        "cs": 0,
                        "ds": 0,
                        "es": 0,
                        "fs": 0,
                        "gs": 0,
                        "ss": 0,
                    },
                }
            if command == "disasm":
                return {
                    "success": True,
                    "result": [
                        {
                            "address": hex(rip),
                            "instruction": "nop",
                            "bytes": instr_bytes_nospace,
                            "comment": "",
                        },
                    ],
                }
            if command == "exec":
                assert params is not None
                assert params.get("command") == f"rip={hex(new_ip)}"
                return {"success": True, "result": None}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        return responder

    async def test_one_byte_nop_advances_rip_by_one(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A 1-byte NOP produces old_ip=_SKIP_IP, new_ip=_SKIP_IP+1, skipped_bytes=1.

        Independent oracle: NOP opcode 0x90 is exactly 1 byte.  If the bridge
        measured ``len(bytes_str)`` instead of ``len(bytes.fromhex(bytes_str))``
        it would compute length 2 (for "90") and set new_ip wrong.

        Args:
            bridge: Fixture bridge instance.
        """
        _install_fake_pipe(bridge, self._make_skip_responder(_SKIP_IP, "90"))
        result = await bridge.skip_instruction()
        assert result["old_ip"] == hex(_SKIP_IP)
        assert result["new_ip"] == hex(_NEW_IP_1BYTE)
        assert result["skipped_bytes"] == 1
        assert result["success"] is True

    async def test_two_byte_instruction_advances_rip_by_two(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """A 2-byte instruction (xor eax,eax: 0x31 0xc0) produces skipped_bytes=2.

        Independent oracle: ``bytes.fromhex("31c0")`` is 2 bytes, so
        ``new_ip = _SKIP_IP + 2 = _NEW_IP_2BYTE``.
        Mutation caught: hard-coding instr_len to 1 fails the new_ip assertion.

        Args:
            bridge: Fixture bridge instance.
        """
        _install_fake_pipe(bridge, self._make_skip_responder(_SKIP_IP, "31c0"))
        result = await bridge.skip_instruction()
        assert result["old_ip"] == hex(_SKIP_IP)
        assert result["new_ip"] == hex(_NEW_IP_2BYTE)
        assert result["skipped_bytes"] == 2

    async def test_64bit_exec_command_uses_rip_not_eip(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """In 64-bit mode (the default) the exec command starts with ``rip=``.

        Mutation caught: if the register name selector always returns "eip",
        the exec command does not start with "rip=" and the assertion fails.

        Args:
            bridge: Fixture bridge instance.
        """
        seen_exec: list[str] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_all":
                return {
                    "success": True,
                    "result": {
                        "rip": _SKIP_IP,
                        "rax": 0,
                        "rbx": 0,
                        "rcx": 0,
                        "rdx": 0,
                        "rsi": 0,
                        "rdi": 0,
                        "rbp": 0,
                        "rsp": 0,
                        "r8": 0,
                        "r9": 0,
                        "r10": 0,
                        "r11": 0,
                        "r12": 0,
                        "r13": 0,
                        "r14": 0,
                        "r15": 0,
                        "rflags": 0,
                        "cs": 0,
                        "ds": 0,
                        "es": 0,
                        "fs": 0,
                        "gs": 0,
                        "ss": 0,
                    },
                }
            if command == "disasm":
                return {
                    "success": True,
                    "result": [{"address": hex(_SKIP_IP), "instruction": "nop", "bytes": "90"}],
                }
            if command == "exec":
                assert params is not None
                seen_exec.append(str(params.get("command", "")))
                return {"success": True, "result": None}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        await bridge.skip_instruction()
        assert len(seen_exec) == 1
        assert seen_exec[0].startswith("rip=")

    async def test_spaced_bytes_str_computes_instruction_length_correctly(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Space-separated byte hex (e.g. "48 89 e5") must parse to 3 bytes, not 8.

        The bridge calls ``bytes_str.replace(" ", "")`` before ``bytes.fromhex``.
        If the ``.replace(" ", "")`` call is removed, ``len("48 89 e5") == 8``
        instead of 3, producing new_ip = _SKIP_IP + 8 instead of _SKIP_IP + 3.

        Args:
            bridge: Fixture bridge instance.
        """
        seen_exec: list[str] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "reg_all":
                return {
                    "success": True,
                    "result": {
                        "rip": _SKIP_IP,
                        "rax": 0,
                        "rbx": 0,
                        "rcx": 0,
                        "rdx": 0,
                        "rsi": 0,
                        "rdi": 0,
                        "rbp": 0,
                        "rsp": 0,
                        "r8": 0,
                        "r9": 0,
                        "r10": 0,
                        "r11": 0,
                        "r12": 0,
                        "r13": 0,
                        "r14": 0,
                        "r15": 0,
                        "rflags": 0,
                        "cs": 0,
                        "ds": 0,
                        "es": 0,
                        "fs": 0,
                        "gs": 0,
                        "ss": 0,
                    },
                }
            if command == "disasm":
                return {
                    "success": True,
                    "result": [
                        {"address": hex(_SKIP_IP), "instruction": "mov rbp, rsp", "bytes": "48 89 e5"},
                    ],
                }
            if command == "exec":
                assert params is not None
                seen_exec.append(str(params.get("command", "")))
                return {"success": True, "result": None}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.skip_instruction()
        assert result["skipped_bytes"] == 3
        assert result["new_ip"] == hex(_SKIP_IP + 3)
        assert len(seen_exec) == 1
        assert seen_exec[0] == f"rip={hex(_SKIP_IP + 3)}"


@pytest.mark.asyncio
class TestSetIp:
    """Command-framing and return-value gates for ``set_ip``."""

    async def test_64bit_mode_sends_rip_exec_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """64-bit mode produces an exec command exactly ``"rip=hex(address)"``.

        Independent oracle: ``f"rip={hex(target)}"`` where target is a
        known constant.
        Mutation caught: using "eip" for a 64-bit target causes the exec
        command assertion to fail.

        Args:
            bridge: Fixture bridge instance.
        """
        target = 0x00401A2B

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                assert params.get("command") == f"rip={hex(target)}"
                return {"success": True, "result": None}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        result = await bridge.set_ip(target)
        assert len(fake.sent) == 1
        assert fake.sent[0][0] == "exec"
        assert result["success"] is True
        assert result["instruction_pointer"] == hex(target)

    async def test_32bit_mode_sends_eip_exec_command(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """32-bit mode produces an exec command exactly ``"eip=hex(address)"``.

        Mutation caught: if the 32-bit register name selector is broken and
        "rip" is used instead of "eip", the framing assertion fails.

        Args:
            bridge: Fixture bridge instance.
        """
        target = 0x00401A2B
        bridge.is_64bit = False

        seen: list[str] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                assert params is not None
                seen.append(str(params.get("command", "")))
                return {"success": True, "result": None}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        await bridge.set_ip(target)
        assert len(seen) == 1
        assert seen[0] == f"eip={hex(target)}"

    async def test_instruction_pointer_field_in_return_matches_input_address(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """``instruction_pointer`` in the return dict equals ``hex(address)``.

        Independent oracle: ``hex(_TRACE_ADDR)``.
        Mutation caught: returning the old register value instead of the
        input address yields a different hex string.

        Args:
            bridge: Fixture bridge instance.
        """
        _install_fake_pipe(bridge, _always_ok)
        result = await bridge.set_ip(_TRACE_ADDR)
        assert result["instruction_pointer"] == hex(_TRACE_ADDR)
        assert result["success"] is True

    async def test_set_ip_sends_exactly_one_exec_rpc(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Exactly one RPC is sent (no read-back or verification polling).

        Mutation caught: adding an extra RPC call for verification would
        increase ``len(fake.sent)`` above 1.

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        await bridge.set_ip(0xCAFE_BABE)
        assert len(fake.sent) == 1
        assert fake.sent[0][0] == "exec"


@pytest.mark.asyncio
class TestGotoAddress:
    """Command-framing and return-value gates for ``goto_address``."""

    async def test_emits_goto_rpc_with_hex_address_param(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The "goto" RPC is issued with ``{"address": hex(address)}``.

        Independent oracle: ``("goto", {"address": hex(_GOTO_ADDR)})``.
        Mutation caught: renaming the RPC to "navigate" or encoding the
        address as decimal causes the exact-match assertion to fail.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "goto":
                assert params == {"address": hex(_GOTO_ADDR)}
                return {"success": True, "result": None}
            msg = f"unexpected command: {command!r}"
            raise AssertionError(msg)

        fake = _install_fake_pipe(bridge, responder)
        await bridge.goto_address(_GOTO_ADDR)
        assert len(fake.sent) == 1
        assert fake.sent[0] == ("goto", {"address": hex(_GOTO_ADDR)})

    async def test_returns_success_true_and_hex_address(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Return dict contains ``success=True`` and ``address=hex(_GOTO_ADDR)``.

        Mutation caught: omitting the address field or using a decimal
        encoding fails the assertion.

        Args:
            bridge: Fixture bridge instance.
        """
        _install_fake_pipe(bridge, _always_ok)
        result = await bridge.goto_address(_GOTO_ADDR)
        assert result["success"] is True
        assert result["address"] == hex(_GOTO_ADDR)

    async def test_address_field_derived_from_input_not_pipe_result(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """The returned address field is the input arg, not the pipe result (which is None).

        Mutation caught: if address were read from the pipe result instead of
        the method's ``address`` parameter, ``result["address"]`` would be
        ``None`` and fail the assertion.

        Args:
            bridge: Fixture bridge instance.
        """
        addr = 0x00600000

        def responder(_command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            return {"success": True, "result": None}

        _install_fake_pipe(bridge, responder)
        result = await bridge.goto_address(addr)
        assert result["address"] == hex(addr)

    async def test_goto_sends_exactly_one_rpc(
        self,
        bridge: X64DbgBridge,
    ) -> None:
        """Exactly one RPC is issued (no follow-up verification call).

        Args:
            bridge: Fixture bridge instance.
        """
        fake = _install_fake_pipe(bridge, _always_ok)
        await bridge.goto_address(_GOTO_ADDR)
        assert len(fake.sent) == 1
