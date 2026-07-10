# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit7 F-0001 regression tests for ``intellicrack.bridges.x64dbg``.

Each of the nineteen fire-and-forget wrappers historically returned
``{"success": True}`` without checking that the underlying x64dbg
operation actually succeeded. The bridge now adds a verification step
per wrapper (label/comment readback, ``bp_list`` enabled-state poll,
``thread_detail`` state poll, ``status`` ``is_running`` poll,
``script.iserror()`` register check, and ``plugin_list`` /
``plugin.find()`` presence check).

The tests script an in-process fake pipe client to replay deterministic
plugin responses so the wrappers' verification paths can be exercised
without launching x64dbg.exe.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from intellicrack.bridges.x64dbg import X64DbgBridge
from intellicrack.core.types import ToolError


_BP_ADDR = 0x401000
_LABEL_ADDR = 0x402000
_COMMENT_ADDR = 0x403000
_TID = 4242
_THREAD_NAME = "worker"
_SCRIPT_PATH = "C:\\scripts\\demo.txt"
_SCRIPT_LINE = 'log "hello"'
_PLUGIN_NAME = "AwesomePlugin"
_PLUGIN_PATH = "C:\\plugins\\AwesomePlugin.dp64"


_Responder = Callable[[str, dict[str, Any] | None], dict[str, Any]]


class _FakePipeClient:
    """In-process replacement for ``NamedPipeClient`` used by tests.

    Exposes the methods that ``X64DbgBridge._send_pipe_command``
    actually invokes (``is_connected`` property, ``send_command``).
    Each test scripts the ``responder`` callable to return a different
    pipe response per command. The ``sent`` attribute records every
    ``(command, params)`` pair so tests can assert that the wrapper
    invoked the expected verification RPC.
    """

    def __init__(self, responder: _Responder) -> None:
        """Initialize the fake pipe client.

        Args:
            responder: Callable that maps ``(command, params)`` to the
                response dict the named-pipe layer would have returned.
        """
        self._responder = responder
        self.sent: list[tuple[str, dict[str, Any] | None]] = []

    @property
    def is_connected(self) -> bool:
        """Always report connected.

        Returns:
            bool: True - the fake is permanently "connected".
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
            dict[str, Any]: The response dict produced by ``responder``.
        """
        self.sent.append((command, params))
        return self._responder(command, params)


class _PlaceholderProcess:
    """Sentinel stand-in used to satisfy ``self._process is not None`` checks."""


def _install_fake_pipe(bridge: X64DbgBridge, responder: _Responder) -> _FakePipeClient:
    """Attach a fake pipe client to ``bridge`` and mark the plugin deployed.

    Args:
        bridge: Bridge instance under test.
        responder: Per-command response generator.

    Returns:
        _FakePipeClient: The installed fake, useful for assertions on
        the ``sent`` list.
    """
    fake = _FakePipeClient(responder)
    setattr(bridge, "_pipe_client", fake)
    setattr(bridge, "_plugin_deployed", True)
    setattr(bridge, "_process", _PlaceholderProcess())
    return fake


def _tight_verification_window(bridge: X64DbgBridge) -> None:
    """Shrink the verification window for fast failure-path coverage.

    Args:
        bridge: Bridge instance under test.
    """
    bridge.VERIFY_TIMEOUT = 0.05
    bridge.VERIFY_POLL_INTERVAL = 0.005


@pytest.fixture
def bridge() -> X64DbgBridge:
    """Construct a fresh, unattached bridge instance.

    Returns:
        X64DbgBridge: A bridge with no attached PID.
    """
    return X64DbgBridge()


# ---------------------------------------------------------------------------
# set_label / set_comment - readback compare
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSetLabelVerification:
    """F-0001: ``set_label`` reads ``lbl_list`` back and compares text."""

    async def test_set_label_success_after_readback_matches(self, bridge: X64DbgBridge) -> None:
        """When the readback returns the expected text, the wrapper verifies.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "lbl_list":
                assert params == {"start": _LABEL_ADDR, "end": _LABEL_ADDR}
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_LABEL_ADDR), "text": "main_loop"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.set_label(_LABEL_ADDR, "main_loop")
        assert result["success"] is True
        assert result["verified"] is True
        assert result["text"] == "main_loop"

    async def test_set_label_raises_when_readback_text_differs(self, bridge: X64DbgBridge) -> None:
        """A mismatched readback raises ``ToolError`` (no fake-success).

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "lbl_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_LABEL_ADDR), "text": "different"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="set_label verification failed"):
            await bridge.set_label(_LABEL_ADDR, "main_loop")

    async def test_set_label_verified_false_when_lbl_list_unknown(self, bridge: X64DbgBridge) -> None:
        """Older plugins without ``lbl_list`` surface verified=False.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "lbl_list":
                return {"id": 1, "success": False, "error": "Unknown command 'lbl_list'"}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.set_label(_LABEL_ADDR, "main_loop")
        assert result["success"] is True
        assert result["verified"] is False


@pytest.mark.asyncio
class TestSetCommentVerification:
    """F-0001: ``set_comment`` reads ``cmt_list`` back and compares text."""

    async def test_set_comment_success_after_readback_matches(self, bridge: X64DbgBridge) -> None:
        """When the readback returns the expected text, the wrapper verifies.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "cmt_list":
                assert params == {"start": _COMMENT_ADDR, "end": _COMMENT_ADDR}
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_COMMENT_ADDR), "text": "loop body"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.set_comment(_COMMENT_ADDR, "loop body")
        assert result["verified"] is True

    async def test_set_comment_raises_on_mismatch(self, bridge: X64DbgBridge) -> None:
        """A mismatched readback raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "cmt_list":
                return {"id": 1, "success": True, "result": [{"address": hex(_COMMENT_ADDR), "text": "other"}]}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="set_comment verification failed"):
            await bridge.set_comment(_COMMENT_ADDR, "loop body")


# ---------------------------------------------------------------------------
# enable_breakpoint / disable_breakpoint - bp_list state poll
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestEnableDisableBreakpointVerification:
    """F-0001: ``enable_breakpoint`` / ``disable_breakpoint`` poll ``bp_list``."""

    async def test_enable_breakpoint_success(self, bridge: X64DbgBridge) -> None:
        """When ``bp_list`` reports ``enabled=True``, the wrapper verifies.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_BP_ADDR), "enabled": True, "type": "normal"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.enable_breakpoint(_BP_ADDR)
        assert result["success"] is True
        assert result["verified"] is True

    async def test_enable_breakpoint_raises_when_still_disabled(self, bridge: X64DbgBridge) -> None:
        """Persistently ``enabled=False`` raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_BP_ADDR), "enabled": False, "type": "normal"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="enable_breakpoint verification failed"):
            await bridge.enable_breakpoint(_BP_ADDR)

    async def test_enable_breakpoint_raises_when_bp_missing(self, bridge: X64DbgBridge) -> None:
        """Missing entry in ``bp_list`` raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {"id": 1, "success": True, "result": []}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="enable_breakpoint verification failed"):
            await bridge.enable_breakpoint(_BP_ADDR)

    async def test_disable_breakpoint_success(self, bridge: X64DbgBridge) -> None:
        """When ``bp_list`` reports ``enabled=False``, the wrapper verifies.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_BP_ADDR), "enabled": False, "type": "normal"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.disable_breakpoint(_BP_ADDR)
        assert result["verified"] is True

    async def test_disable_breakpoint_raises_when_still_enabled(self, bridge: X64DbgBridge) -> None:
        """Persistently ``enabled=True`` raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "bp_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"address": hex(_BP_ADDR), "enabled": True, "type": "normal"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="disable_breakpoint verification failed"):
            await bridge.disable_breakpoint(_BP_ADDR)


# ---------------------------------------------------------------------------
# suspend_thread / resume_thread / switch_thread / set_thread_name
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestThreadWrappersVerification:
    """F-0001: thread wrappers poll ``thread_detail`` for the post-condition."""

    async def test_suspend_thread_success(self, bridge: X64DbgBridge) -> None:
        """When ``thread_detail`` reports ``suspended=True`` for the tid, verify.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": True, "name": "alpha"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.suspend_thread(_TID)
        assert result["verified"] is True
        assert result["tid"] == _TID

    async def test_suspend_thread_raises_when_thread_still_running(self, bridge: X64DbgBridge) -> None:
        """Persistently ``suspended=False`` raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": False, "name": "alpha"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="suspend_thread verification failed"):
            await bridge.suspend_thread(_TID)

    async def test_resume_thread_success(self, bridge: X64DbgBridge) -> None:
        """When ``thread_detail`` reports ``suspended=False``, verify.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": False, "name": "alpha"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.resume_thread(_TID)
        assert result["verified"] is True

    async def test_resume_thread_raises_when_thread_still_suspended(self, bridge: X64DbgBridge) -> None:
        """Persistently ``suspended=True`` raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": True, "name": "alpha"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="resume_thread verification failed"):
            await bridge.resume_thread(_TID)

    async def test_switch_thread_success(self, bridge: X64DbgBridge) -> None:
        """When ``thread_detail`` lists the thread, the switch is verified.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": False, "name": "alpha"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.switch_thread(_TID)
        assert result["verified"] is True

    async def test_switch_thread_raises_when_thread_missing(self, bridge: X64DbgBridge) -> None:
        """When ``thread_detail`` does not list the tid, raise.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {"id": 1, "success": True, "result": []}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="switch_thread verification failed"):
            await bridge.switch_thread(_TID)

    async def test_set_thread_name_success(self, bridge: X64DbgBridge) -> None:
        """When ``thread_detail`` reports the expected name, verify.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": False, "name": _THREAD_NAME}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.set_thread_name(_TID, _THREAD_NAME)
        assert result["verified"] is True
        assert result["name"] == _THREAD_NAME

    async def test_set_thread_name_raises_on_name_mismatch(self, bridge: X64DbgBridge) -> None:
        """Persistent name mismatch raises ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "thread_detail":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"threadId": _TID, "suspended": False, "name": "stale"}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="set_thread_name verification failed"):
            await bridge.set_thread_name(_TID, _THREAD_NAME)


# ---------------------------------------------------------------------------
# trace_into / trace_over / step_count / animate_start / animate_stop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTraceAndAnimateVerification:
    """F-0001: trace/animate wrappers poll ``status`` for is_running flip."""

    async def test_trace_into_success(self, bridge: X64DbgBridge) -> None:
        """``status`` reports running=True after ``TraceIntoConditional``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": False, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.trace_into(max_steps=100)
        assert result["verified"] is True

    async def test_trace_into_raises_when_debugger_stays_paused(self, bridge: X64DbgBridge) -> None:
        """Debugger never enters running state -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": True, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="trace_into verification failed"):
            await bridge.trace_into(max_steps=100)

    async def test_trace_over_success(self, bridge: X64DbgBridge) -> None:
        """``status`` reports running=True after ``TraceOverConditional``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": False, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.trace_over(max_steps=100)
        assert result["verified"] is True

    async def test_trace_over_raises_when_debugger_stays_paused(self, bridge: X64DbgBridge) -> None:
        """Debugger never enters running state -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": True, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="trace_over verification failed"):
            await bridge.trace_over(max_steps=100)

    async def test_step_count_success(self, bridge: X64DbgBridge) -> None:
        """``status`` reports paused=True after the step budget.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": True, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.step_count(10, step_type="into")
        assert result["verified"] is True

    async def test_step_count_raises_when_debugger_still_running(self, bridge: X64DbgBridge) -> None:
        """Debugger remained running after step budget -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": False, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="step_count verification failed"):
            await bridge.step_count(10, step_type="into")

    async def test_animate_start_success(self, bridge: X64DbgBridge) -> None:
        """``status`` reports running=True after ``AnimateInto``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": False, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.animate_start("into")
        assert result["verified"] is True

    async def test_animate_start_raises_when_debugger_stays_paused(self, bridge: X64DbgBridge) -> None:
        """Debugger never entered running state -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": True, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="animate_start verification failed"):
            await bridge.animate_start("into")

    async def test_animate_stop_success(self, bridge: X64DbgBridge) -> None:
        """``status`` reports paused=True after ``AnimateStop``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": True, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.animate_stop()
        assert result["verified"] is True

    async def test_animate_stop_raises_when_debugger_still_running(self, bridge: X64DbgBridge) -> None:
        """Debugger never paused after ``AnimateStop`` -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "status":
                return {
                    "id": 1,
                    "success": True,
                    "result": {"debugging": True, "paused": False, "initialized": True},
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        _tight_verification_window(bridge)
        with pytest.raises(ToolError, match="animate_stop verification failed"):
            await bridge.animate_stop()


# script_load / script_run / script_cmd / script_abort verification tests
# query the ``script.iserror()`` register via the expression evaluator.


@pytest.mark.asyncio
class TestScriptWrappersVerification:
    """F-0001: script wrappers query the ``script.iserror()`` register."""

    async def test_script_load_success_when_iserror_clear(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 0 -> verified True.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                assert params is not None
                assert params.get("expression") == "script.iserror()"
                return {"id": 1, "success": True, "result": 0}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.script_load(_SCRIPT_PATH)
        assert result["verified"] is True
        assert result["path"] == _SCRIPT_PATH

    async def test_script_load_raises_when_iserror_set(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 1 -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 1}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="script_load verification failed"):
            await bridge.script_load(_SCRIPT_PATH)

    async def test_script_run_success_when_iserror_clear(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 0 -> verified True.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 0}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.script_run()
        assert result["verified"] is True

    async def test_script_run_raises_when_iserror_set(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 1 -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 1}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="script_run verification failed"):
            await bridge.script_run()

    async def test_script_cmd_success_when_iserror_clear(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 0 -> verified True.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 0}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.script_cmd(_SCRIPT_LINE)
        assert result["verified"] is True
        assert result["line"] == _SCRIPT_LINE

    async def test_script_cmd_raises_when_iserror_set(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 1 -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 1}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="script_cmd verification failed"):
            await bridge.script_cmd(_SCRIPT_LINE)

    async def test_script_abort_success_when_iserror_clear(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 0 -> verified True.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 0}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.script_abort()
        assert result["verified"] is True

    async def test_script_abort_raises_when_iserror_set(self, bridge: X64DbgBridge) -> None:
        """``script.iserror()`` returns 1 -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "eval":
                return {"id": 1, "success": True, "result": 1}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="script_abort verification failed"):
            await bridge.script_abort()


# plugin_load / plugin_unload verification tests use ``plugin_list``
# with a fallback to ``plugin.find()`` via the expression evaluator.


@pytest.mark.asyncio
class TestPluginWrappersVerification:
    """F-0001: plugin wrappers verify via ``plugin_list`` / ``plugin.find()``."""

    async def test_plugin_load_success_via_plugin_list(self, bridge: X64DbgBridge) -> None:
        """``plugin_list`` lists the loaded plugin -> verified True.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "plugin_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"name": _PLUGIN_NAME}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.plugin_load(_PLUGIN_PATH)
        assert result["verified"] is True
        assert result["path"] == _PLUGIN_PATH

    async def test_plugin_load_raises_when_plugin_absent(self, bridge: X64DbgBridge) -> None:
        """``plugin_list`` returns empty -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "plugin_list":
                return {"id": 1, "success": True, "result": []}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="plugin_load verification failed"):
            await bridge.plugin_load(_PLUGIN_PATH)

    async def test_plugin_load_falls_back_to_plugin_find(self, bridge: X64DbgBridge) -> None:
        """``plugin_list`` unknown -> ``plugin.find()`` returns non-zero handle.

        Args:
            bridge: Fixture bridge instance.
        """
        seen: list[str] = []

        def responder(command: str, params: dict[str, Any] | None) -> dict[str, Any]:
            seen.append(command)
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "plugin_list":
                return {"id": 1, "success": False, "error": "Unknown command 'plugin_list'"}
            if command == "eval":
                assert params is not None
                assert "plugin.find" in str(params.get("expression"))
                return {"id": 1, "success": True, "result": 0x7FF0_0000}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.plugin_load(_PLUGIN_PATH)
        assert result["verified"] is True
        assert "eval" in seen

    async def test_plugin_unload_success(self, bridge: X64DbgBridge) -> None:
        """After unload, ``plugin_list`` returns empty -> verified True.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "plugin_list":
                return {"id": 1, "success": True, "result": []}
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        result = await bridge.plugin_unload(_PLUGIN_NAME)
        assert result["verified"] is True

    async def test_plugin_unload_raises_when_plugin_still_present(self, bridge: X64DbgBridge) -> None:
        """``plugin_list`` still lists the plugin -> ``ToolError``.

        Args:
            bridge: Fixture bridge instance.
        """

        def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
            if command == "exec":
                return {"id": 1, "success": True, "result": None}
            if command == "plugin_list":
                return {
                    "id": 1,
                    "success": True,
                    "result": [{"name": _PLUGIN_NAME}],
                }
            msg = f"unexpected command: {command}"
            raise AssertionError(msg)

        _install_fake_pipe(bridge, responder)
        with pytest.raises(ToolError, match="plugin_unload verification failed"):
            await bridge.plugin_unload(_PLUGIN_NAME)


# ---------------------------------------------------------------------------
# Sanity: no wrapper returns a bare {"success": True} dict
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_wrapper_returns_bare_success_dict(bridge: X64DbgBridge) -> None:
    """Each verified wrapper exposes a ``verified`` boolean in its return.

    The regression target is the audit7 F-0001 finding: a wrapper that
    just returns ``{"success": True}`` masks plugin failures. The new
    bridge contract always carries a ``verified`` key. This test
    rejects the failure mode wholesale by checking every fire-and-
    forget wrapper now produces a result dict with ``verified``.

    Args:
        bridge: Fixture bridge instance.
    """

    def responder(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            return {"id": 1, "success": True, "result": None}
        if command == "lbl_list":
            return {"id": 1, "success": True, "result": [{"address": hex(_LABEL_ADDR), "text": "x"}]}
        if command == "cmt_list":
            return {"id": 1, "success": True, "result": [{"address": hex(_COMMENT_ADDR), "text": "x"}]}
        if command == "bp_list":
            return {
                "id": 1,
                "success": True,
                "result": [{"address": hex(_BP_ADDR), "enabled": True, "type": "normal"}],
            }
        if command == "thread_detail":
            return {
                "id": 1,
                "success": True,
                "result": [{"threadId": _TID, "suspended": True, "name": _THREAD_NAME}],
            }
        if command == "status":
            return {
                "id": 1,
                "success": True,
                "result": {"debugging": True, "paused": False, "initialized": True},
            }
        if command == "eval":
            return {"id": 1, "success": True, "result": 0}
        if command == "plugin_list":
            return {"id": 1, "success": True, "result": [{"name": _PLUGIN_NAME}]}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    _install_fake_pipe(bridge, responder)

    happy_calls: list[tuple[str, Callable[[], Awaitable[dict[str, Any]]]]] = [
        ("set_label", lambda: bridge.set_label(_LABEL_ADDR, "x")),
        ("set_comment", lambda: bridge.set_comment(_COMMENT_ADDR, "x")),
        ("enable_breakpoint", lambda: bridge.enable_breakpoint(_BP_ADDR)),
        ("trace_into", lambda: bridge.trace_into(max_steps=10)),
        ("trace_over", lambda: bridge.trace_over(max_steps=10)),
        ("animate_start", lambda: bridge.animate_start("into")),
        ("script_load", lambda: bridge.script_load(_SCRIPT_PATH)),
        ("script_run", bridge.script_run),
        ("script_cmd", lambda: bridge.script_cmd(_SCRIPT_LINE)),
        ("script_abort", bridge.script_abort),
        ("plugin_load", lambda: bridge.plugin_load(_PLUGIN_PATH)),
    ]
    for name, call in happy_calls:
        result = await call()
        assert "verified" in result, f"{name} must carry verified key"
        assert result.get("success") is True, f"{name} must surface success"

    def responder_paused(command: str, _params: dict[str, Any] | None) -> dict[str, Any]:
        if command == "exec":
            return {"id": 1, "success": True, "result": None}
        if command == "status":
            return {
                "id": 1,
                "success": True,
                "result": {"debugging": True, "paused": True, "initialized": True},
            }
        if command == "bp_list":
            return {
                "id": 1,
                "success": True,
                "result": [{"address": hex(_BP_ADDR), "enabled": False, "type": "normal"}],
            }
        if command == "thread_detail":
            return {
                "id": 1,
                "success": True,
                "result": [{"threadId": _TID, "suspended": False, "name": _THREAD_NAME}],
            }
        if command == "plugin_list":
            return {"id": 1, "success": True, "result": []}
        msg = f"unexpected command: {command}"
        raise AssertionError(msg)

    _install_fake_pipe(bridge, responder_paused)
    paused_result = await bridge.step_count(5, step_type="into")
    assert paused_result.get("verified") is True

    resume_result = await bridge.resume_thread(_TID)
    assert resume_result.get("verified") is True

    disable_result = await bridge.disable_breakpoint(_BP_ADDR)
    assert disable_result.get("verified") is True

    switch_result = await bridge.switch_thread(_TID)
    assert switch_result.get("verified") is True

    stop_result = await bridge.animate_stop()
    assert stop_result.get("verified") is True

    unload_result = await bridge.plugin_unload(_PLUGIN_NAME)
    assert unload_result.get("verified") is True
