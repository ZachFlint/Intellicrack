# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for Windows Sandbox launch-failure detection.

Previously a failed sandbox launch -- such as the native client raising its
``0x800706d9`` (``EPT_S_NOT_REGISTERED``) endpoint-mapper dialog -- left
``WindowsSandboxClient.exe`` blocked on a modal dialog while Intellicrack
waited the full dispatcher-ready timeout (120s) before reporting a generic
"dispatcher did not signal ready" error.

:meth:`WindowsSandbox._check_startup_health` now detects both an early client
exit and the native failure dialog, surfacing an actionable
:class:`SandboxError` immediately, and :meth:`WindowsSandbox.start` propagates
that specific message (instead of wrapping it in the generic
``Failed to start Windows Sandbox``) so the guidance reaches the UI.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from unittest.mock import AsyncMock, MagicMock

import pytest

import intellicrack.sandbox.windows as win_mod
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.windows import WindowsSandbox


if TYPE_CHECKING:
    from collections.abc import Callable

    from intellicrack.core.subprocess_compat import Popen


_ERR_LAUNCH_CLIENT_EXITED = cast("str", getattr(win_mod, "_ERR_LAUNCH_CLIENT_EXITED"))
_ERR_LAUNCH_DIALOG = cast("str", getattr(win_mod, "_ERR_LAUNCH_DIALOG"))
_ERR_LAUNCH_RPC_ENDPOINT = cast("str", getattr(win_mod, "_ERR_LAUNCH_RPC_ENDPOINT"))
_ERR_START_FAILED = cast("str", getattr(win_mod, "_ERR_START_FAILED"))
_classify_failure_text = cast("Callable[[str], bool]", getattr(win_mod, "_is_sandbox_failure_text"))


class _ProbeSandbox(WindowsSandbox):
    """WindowsSandbox subclass exposing protected startup hooks for testing.

    Wrapping the protected startup methods in public callables keeps the
    private-member access inside the class hierarchy where it is permitted,
    so the tests can drive them without launching a real sandbox.
    """

    async def run_startup_health(self) -> None:
        """Invoke the protected startup-health check."""
        await self._check_startup_health()

    def raise_dialog_failure(self, detail: str) -> None:
        """Invoke the protected failure-dialog raiser.

        Args:
            detail: Combined dialog text to classify and surface.
        """
        self._raise_launch_dialog_failure(detail)


def _make_probe() -> _ProbeSandbox:
    """Build a probe sandbox without launching anything.

    Returns:
        _ProbeSandbox: A fresh instance backed by a short-timeout config.
    """
    return _ProbeSandbox(SandboxConfig(timeout_seconds=5))


def _make_sandbox() -> WindowsSandbox:
    """Build a plain WindowsSandbox without launching anything.

    Returns:
        WindowsSandbox: A fresh instance backed by a short-timeout config.
    """
    return WindowsSandbox(SandboxConfig(timeout_seconds=5))


def _fake_process(*, poll_result: int | None, pid: int) -> Popen[bytes]:
    """Create a fake client process for startup-health tests.

    Args:
        poll_result: Value returned by ``poll()`` (None means still running).
        pid: Reported process id.

    Returns:
        Popen[bytes]: A MagicMock typed as the sandbox client process.
    """
    proc = MagicMock()
    proc.poll.return_value = poll_result
    proc.returncode = poll_result
    proc.pid = pid
    return cast("Popen[bytes]", proc)


def _detect_returns_rpc(_pid: int) -> str | None:
    """Fake dialog detector returning the RPC endpoint failure text.

    Args:
        _pid: Ignored client PID.

    Returns:
        str | None: Canned 0x800706d9 dialog text.
    """
    return "Windows Sandbox Error 0x800706d9 endpoint mapper"


def _detect_returns_none(_pid: int) -> str | None:
    """Fake dialog detector returning no failure.

    Args:
        _pid: Ignored client PID.

    Returns:
        str | None: Always None.
    """
    return None


class TestFailureTextClassification:
    """Behaviour of the dialog-text failure classifier."""

    @pytest.mark.parametrize(
        "text",
        [
            "Windows Sandbox\nThe connection to the sandbox could not be initialized.\nError 0x800706d9.",
            "Error 0x80004005",
            "There are no more endpoints available from the endpoint mapper.",
            "Failed to start Windows Sandbox",
            "Windows Sandbox cannot start",
        ],
    )
    def test_failure_text_detected(self, text: str) -> None:
        """Error codes and known failure phrases classify as failures.

        Args:
            text: Candidate dialog text expected to be a failure.
        """
        assert _classify_failure_text(text) is True

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "Starting Windows Sandbox",
            "Windows Sandbox",
            "Preparing your sandbox environment",
        ],
    )
    def test_benign_text_ignored(self, text: str) -> None:
        """Progress and empty text must not be classified as failures.

        Args:
            text: Candidate dialog text expected to be benign.
        """
        assert _classify_failure_text(text) is False


class TestRaiseLaunchDialogFailure:
    """Behaviour of the failure-dialog raiser."""

    def test_rpc_endpoint_code_uses_actionable_guidance(self) -> None:
        """The 0x800706d9 code maps to the reboot / single-instance guidance."""
        probe = _make_probe()
        detail = "Windows Sandbox\nThe connection to the sandbox could not be initialized.\nError 0x800706d9."
        with pytest.raises(SandboxError) as excinfo:
            probe.raise_dialog_failure(detail)
        assert str(excinfo.value) == _ERR_LAUNCH_RPC_ENDPOINT

    def test_other_code_uses_generic_message_with_detail(self) -> None:
        """A non-RPC code yields the generic message embedding the dialog text."""
        probe = _make_probe()
        detail = "Windows Sandbox\nUnexpected failure 0x80004005 occurred."
        with pytest.raises(SandboxError) as excinfo:
            probe.raise_dialog_failure(detail)
        message = str(excinfo.value)
        assert message.startswith(_ERR_LAUNCH_DIALOG)
        assert "0x80004005" in message
        assert "\n" not in message


class TestCheckStartupHealth:
    """Behaviour of the startup-health check."""

    @pytest.mark.asyncio
    async def test_no_process_is_noop(self) -> None:
        """With no launched process the check returns without raising."""
        probe = _make_probe()
        probe.process = None
        await probe.run_startup_health()

    @pytest.mark.asyncio
    async def test_early_client_exit_raises_actionable_error(self) -> None:
        """A client that exited before readiness raises the early-exit guidance."""
        probe = _make_probe()
        probe.process = _fake_process(poll_result=1, pid=4321)

        with pytest.raises(SandboxError) as excinfo:
            await probe.run_startup_health()
        message = str(excinfo.value)
        assert message.startswith(_ERR_LAUNCH_CLIENT_EXITED)
        assert "1" in message

    @pytest.mark.asyncio
    async def test_failure_dialog_surfaces_rpc_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A live client showing the 0x800706d9 dialog raises the RPC guidance.

        Args:
            monkeypatch: Pytest fixture used to stub the dialog detector.
        """
        probe = _make_probe()
        probe.process = _fake_process(poll_result=None, pid=9999)
        monkeypatch.setattr(
            WindowsSandbox,
            "_detect_client_failure_dialog",
            staticmethod(_detect_returns_rpc),
        )

        with pytest.raises(SandboxError) as excinfo:
            await probe.run_startup_health()
        assert str(excinfo.value) == _ERR_LAUNCH_RPC_ENDPOINT

    @pytest.mark.asyncio
    async def test_live_client_without_dialog_is_noop(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A healthy live client with no failure dialog does not raise.

        Args:
            monkeypatch: Pytest fixture used to stub the dialog detector.
        """
        probe = _make_probe()
        probe.process = _fake_process(poll_result=None, pid=5555)
        monkeypatch.setattr(
            WindowsSandbox,
            "_detect_client_failure_dialog",
            staticmethod(_detect_returns_none),
        )

        await probe.run_startup_health()


class TestStartPropagatesActionableError:
    """:meth:`WindowsSandbox.start` surfaces the specific failure message."""

    @pytest.mark.asyncio
    async def test_sandbox_error_propagated_verbatim(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A SandboxError from startup is re-raised unchanged, not wrapped.

        Args:
            monkeypatch: Pytest fixture used to stub the start internals.
        """
        sandbox = _make_sandbox()
        monkeypatch.setattr(
            WindowsSandbox,
            "_start_impl",
            AsyncMock(side_effect=SandboxError(_ERR_LAUNCH_RPC_ENDPOINT)),
        )
        abort = AsyncMock()
        cleanup = AsyncMock()
        monkeypatch.setattr(WindowsSandbox, "_abort_client", abort)
        monkeypatch.setattr(WindowsSandbox, "_cleanup", cleanup)

        with pytest.raises(SandboxError) as excinfo:
            await sandbox.start()

        assert str(excinfo.value) == _ERR_LAUNCH_RPC_ENDPOINT
        assert sandbox.state.status == "error"
        assert sandbox.state.last_error == _ERR_LAUNCH_RPC_ENDPOINT
        abort.assert_awaited_once()
        cleanup.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_os_error_wrapped_in_generic_start_failed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Non-sandbox OSErrors remain wrapped in the generic start message.

        Args:
            monkeypatch: Pytest fixture used to stub the start internals.
        """
        sandbox = _make_sandbox()
        monkeypatch.setattr(
            WindowsSandbox,
            "_start_impl",
            AsyncMock(side_effect=OSError("boom")),
        )
        monkeypatch.setattr(WindowsSandbox, "_abort_client", AsyncMock())
        monkeypatch.setattr(WindowsSandbox, "_cleanup", AsyncMock())

        with pytest.raises(SandboxError) as excinfo:
            await sandbox.start()

        assert str(excinfo.value) == _ERR_START_FAILED
