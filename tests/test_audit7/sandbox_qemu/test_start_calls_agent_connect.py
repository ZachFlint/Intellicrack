# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0002: ``QEMUSandbox.start`` agent connect call.

These tests drive ``QEMUSandbox.start`` through the agent step by stubbing the
heavy QEMU boot (subprocess spawn, pidfile read, QMP probe) with dependency-
injection style patches, then verify that ``GuestAgentClient.connect`` is
actually awaited and that a failed connection propagates as ``SandboxError``.
"""

from __future__ import annotations

import asyncio
import math
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import intellicrack.sandbox.qemu as qemu_mod
from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    AcceleratorType,
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from collections.abc import Iterator


def _noop_ensure_qemu_started(_pid: int | None) -> None:
    """No-op replacement for ``QEMUSandbox._ensure_qemu_started``.

    Args:
        _pid: Ignored process ID; the stub never enforces non-``None``.
    """


class _RecordingAgent(GuestAgentClient):
    """``GuestAgentClient`` subclass that records ``connect`` invocations.

    Attributes:
        connect_calls: List of ``time_limit`` values passed to ``connect``.
        connect_result: Value to return from ``connect``.
        connect_exception: Optional exception to raise from ``connect``.
        disconnect_called: True if ``disconnect`` has been invoked.
    """

    connect_calls: list[float]
    connect_result: bool
    connect_exception: BaseException | None
    disconnect_called: bool

    def __init__(
        self,
        *,
        result: bool = True,
        exception: BaseException | None = None,
        port: int = 4445,
    ) -> None:
        """Initialise a recording agent without performing any I/O.

        Args:
            result: Value returned from ``connect`` when no exception is set.
            exception: Optional exception to raise from ``connect``.
            port: Guest agent TCP port (forwarded to base class).
        """
        super().__init__(host="127.0.0.1", port=port)
        self.connect_calls = []
        self.connect_result = result
        self.connect_exception = exception
        self.disconnect_called = False

    async def connect(
        self,
        time_limit: float = 60.0,
        retry_interval: float = 2.0,
    ) -> bool:
        """Record the call, then either raise or return the canned result.

        Args:
            time_limit: Total connect timeout (recorded for assertions).
            retry_interval: Retry interval (ignored).

        Returns:
            bool: The pre-configured ``connect_result`` value.

        Raises:
            self.connect_exception: The exception passed to ``__init__``
                via ``exception=...``; only raised when that argument is
                non-``None``.
        """
        del retry_interval
        self.connect_calls.append(time_limit)
        if self.connect_exception is not None:
            raise self.connect_exception
        if self.connect_result:
            self.connected = True
        return self.connect_result

    async def disconnect(self) -> None:
        """Mark the agent disconnected; no real socket to close."""
        self.disconnect_called = True
        self.connected = False


class _StartTestSandbox(QEMUSandbox):
    """Test-only ``QEMUSandbox`` subclass exposing controlled-state setters.

    The setters intentionally mutate private state of the parent class via
    methods declared on the subclass itself. This keeps callers from
    reaching into ``_qemu_pid`` / ``_accelerator`` directly while still
    allowing tests to bypass the heavy QEMU boot.
    """

    def set_pid_for_test(self, pid: int | None) -> None:
        """Set the QEMU PID without invoking the real boot pipeline.

        Args:
            pid: Process ID to assign, or ``None`` to clear.
        """
        self._qemu_pid = pid

    def set_pidfile_for_test(self, path: Path | None) -> None:
        """Override the pidfile path so the polling loop is a no-op.

        Args:
            path: Pidfile path to assign, or ``None`` to disable polling.
        """
        self._pidfile_path = path

    def set_accelerator_for_test(self, accel: AcceleratorType) -> None:
        """Pre-populate the accelerator detection cache.

        Args:
            accel: Accelerator type to assign.
        """
        self._accelerator = accel
        self._accelerator_cached = True


class _StartHarness:
    """Reusable context manager that stubs QEMU boot internals for ``start``.

    Attributes:
        sandbox: The sandbox instance under test.
        agent_factory: Callable producing the agent client to inject.
        last_agent: The most recently constructed agent instance.
    """

    sandbox: _StartTestSandbox
    agent_factory: object
    last_agent: _RecordingAgent | None

    def __init__(
        self,
        sandbox: _StartTestSandbox,
        agent_factory: object,
    ) -> None:
        """Initialise the harness.

        Args:
            sandbox: Sandbox instance to drive through ``start``.
            agent_factory: Factory invoked in place of ``GuestAgentClient``.
        """
        self.sandbox = sandbox
        self.agent_factory = agent_factory
        self.last_agent = None

    def _agent_constructor(self, *_args: object, **_kwargs: object) -> _RecordingAgent:
        """Construct an agent via the supplied factory.

        Args:
            *_args: Positional args forwarded by ``QEMUSandbox.start``.
            **_kwargs: Keyword args forwarded by ``QEMUSandbox.start``.

        Returns:
            _RecordingAgent: The agent produced by the factory.

        Raises:
            TypeError: If the factory is not callable or returns a wrong type.
        """
        del _args, _kwargs
        factory = self.agent_factory
        if not callable(factory):
            msg = "agent_factory must be callable"
            raise TypeError(msg)
        agent = factory()
        if not isinstance(agent, _RecordingAgent):
            msg = "agent_factory must return a _RecordingAgent"
            raise TypeError(msg)
        self.last_agent = agent
        return agent

    async def run_start(self) -> None:
        """Drive ``QEMUSandbox.start`` with all heavy boot internals stubbed.

        Any exception raised by ``QEMUSandbox.start`` is allowed to
        propagate out of this coroutine unchanged so that tests can
        assert against it with ``pytest.raises``.
        """
        sb = self.sandbox

        subprocess_proc = MagicMock()
        subprocess_proc.returncode = 0
        subprocess_proc.communicate = AsyncMock(return_value=(b"", b""))

        sb.set_pid_for_test(4242)
        sb.set_pidfile_for_test(None)
        sb.set_accelerator_for_test(AcceleratorType.TCG)

        with (
            patch.object(sb, "is_available", new=AsyncMock(return_value=True)),
            patch.object(sb, "_create_guest_agent_script", new=AsyncMock()),
            patch.object(
                sb,
                "_build_qemu_command",
                new=AsyncMock(return_value=["qemu-system-x86_64"]),
            ),
            patch.object(sb, "_connect_and_verify_qmp", new=AsyncMock()),
            patch.object(sb, "_bootstrap_guest_agent", new=AsyncMock()),
            patch.object(sb, "_verify_qemu_pid", new=AsyncMock()),
            patch.object(sb, "_cleanup", new=AsyncMock()),
            patch(
                "asyncio.create_subprocess_exec",
                new=AsyncMock(return_value=subprocess_proc),
            ),
            patch(
                "intellicrack.sandbox.qemu.GuestAgentClient",
                side_effect=self._agent_constructor,
            ),
            patch(
                "intellicrack.core.process_manager.ProcessManager.get_instance",
                return_value=MagicMock(register_external_pid=MagicMock()),
            ),
            patch.object(
                QEMUSandbox,
                "_ensure_qemu_started",
                staticmethod(_noop_ensure_qemu_started),
            ),
        ):
            await sb.start()


def _make_sandbox(*, agent_timeout: float = 7.5) -> _StartTestSandbox:
    """Construct a ``_StartTestSandbox`` ready to be driven through ``start``.

    Args:
        agent_timeout: ``agent_connect_timeout`` to set on the config.

    Returns:
        _StartTestSandbox: A configured test sandbox instance.
    """
    cfg = QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        agent_connect_timeout=agent_timeout,
    )
    return _StartTestSandbox(config=SandboxConfig(), qemu_config=cfg)


def _drive_start(harness: _StartHarness) -> None:
    """Synchronously run the harness's ``run_start`` coroutine.

    Any exception raised inside the coroutine (e.g. ``SandboxError`` when
    the agent fails to connect) is allowed to propagate out of this
    function unchanged so that tests can assert against it with
    ``pytest.raises``.

    Args:
        harness: ``_StartHarness`` instance to execute.
    """
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(harness.run_start())
    finally:
        loop.close()


@pytest.fixture
def fresh_event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """Provide a fresh asyncio event loop for each test.

    Yields:
        asyncio.AbstractEventLoop: A new loop installed as the default.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield loop
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


class TestF0002StartAwaitsAgentConnect:
    """Scenario A: ``start`` awaits ``GuestAgentClient.connect`` with the configured timeout."""

    def test_start_awaits_agent_connect_with_configured_timeout(
        self,
        fresh_event_loop: asyncio.AbstractEventLoop,
    ) -> None:
        """``QEMUSandbox.start`` must call ``agent.connect(time_limit=<configured>)``.

        Pre-fix code instantiated ``GuestAgentClient`` but never called
        ``connect``; this test fails on that code because
        ``recording_agent.connect_calls`` is empty.

        Args:
            fresh_event_loop: Event loop fixture (not used directly; the
                harness creates its own loop, but this ensures the default
                loop is fresh and closable).
        """
        del fresh_event_loop

        recording: list[_RecordingAgent] = []

        def _factory() -> _RecordingAgent:
            agent = _RecordingAgent(result=True)
            recording.append(agent)
            return agent

        sb = _make_sandbox(agent_timeout=12.5)
        harness = _StartHarness(sb, _factory)

        _drive_start(harness)

        assert len(recording) == 1, f"Expected exactly one GuestAgentClient construction; got {len(recording)}"
        agent = recording[0]
        assert agent.connect_calls, "GuestAgentClient.connect was never awaited inside QEMUSandbox.start"
        assert agent.connect_calls == [12.5], (
            f"connect() must be awaited with the configured agent_connect_timeout (12.5); got {agent.connect_calls}"
        )
        assert sb.state.status == "running", f"start() should have completed; status is {sb.state.status!r}"
        assert sb.agent is agent, "QEMUSandbox.agent property must point at the connected agent"
        assert sb.agent is not None, "Agent must be installed on the sandbox after start()"
        assert sb.agent.is_connected, "agent.is_connected must be True after start() returns"


class TestF0002StartFailsIfAgentConnectFails:
    """Scenario B: ``start`` must raise ``SandboxError`` if ``connect`` fails."""

    def test_start_raises_when_agent_connect_returns_false(
        self,
        fresh_event_loop: asyncio.AbstractEventLoop,
    ) -> None:
        """``start`` must raise ``SandboxError`` when ``connect`` returns False.

        Pre-fix code never awaited ``connect`` at all, so it returned
        silent success regardless of agent reachability. This test
        therefore fails on the old code.

        Args:
            fresh_event_loop: Event loop fixture for asyncio state hygiene.
        """
        del fresh_event_loop

        recording: list[_RecordingAgent] = []

        def _factory() -> _RecordingAgent:
            agent = _RecordingAgent(result=False)
            recording.append(agent)
            return agent

        sb = _make_sandbox(agent_timeout=3.0)
        harness = _StartHarness(sb, _factory)

        with pytest.raises(SandboxError):
            _drive_start(harness)

        assert len(recording) == 1
        assert recording[0].connect_calls == [3.0], "connect() must still have been awaited with the configured timeout before failing"
        assert sb.state.status == "error", f"Failed start must transition state to 'error'; got {sb.state.status!r}"

    def test_start_raises_when_agent_connect_raises_oserror(
        self,
        fresh_event_loop: asyncio.AbstractEventLoop,
    ) -> None:
        """``start`` must convert agent ``connect`` ``OSError`` into ``SandboxError``.

        Args:
            fresh_event_loop: Event loop fixture for asyncio state hygiene.
        """
        del fresh_event_loop

        recording: list[_RecordingAgent] = []

        def _factory() -> _RecordingAgent:
            agent = _RecordingAgent(exception=OSError("guest agent socket refused"))
            recording.append(agent)
            return agent

        sb = _make_sandbox(agent_timeout=2.0)
        harness = _StartHarness(sb, _factory)

        with pytest.raises(SandboxError):
            _drive_start(harness)

        assert len(recording) == 1
        assert recording[0].connect_calls == [2.0]
        assert sb.state.status == "error"


class TestF0002QEMUConfigHasAgentConnectTimeout:
    """``QEMUConfig`` must expose ``agent_connect_timeout`` with a sensible default."""

    def test_default_value_is_60_seconds(self) -> None:
        """``QEMUConfig().agent_connect_timeout`` defaults to ``60.0`` seconds.

        The audit7 plan calls for a 60s default; verifying the value pins
        the configuration contract.
        """
        cfg = QEMUConfig()
        assert math.isclose(cfg.agent_connect_timeout, 60.0), (
            f"Expected default agent_connect_timeout == 60.0; got {cfg.agent_connect_timeout!r}"
        )

    def test_field_is_overrideable(self) -> None:
        """``QEMUConfig`` accepts a custom ``agent_connect_timeout`` value."""
        cfg = QEMUConfig(agent_connect_timeout=5.0)
        assert math.isclose(cfg.agent_connect_timeout, 5.0)


def _file_contains(path: Path, needle: str) -> bool:
    """Return True when ``needle`` appears in the UTF-8 text of ``path``.

    Args:
        path: File to inspect.
        needle: Substring to look for.

    Returns:
        bool: True if ``needle`` is present.
    """
    return needle in path.read_text(encoding="utf-8")


class TestF0002SourceContainsConnectCall:
    """Static guard: the production source actually awaits ``agent.connect``.

    A reviewer audit (audit7.md F-0002) noted that the prior fix attempt
    relied on the test calling ``connect`` itself; this test guards
    against that regression by inspecting the source string.
    """

    def test_qemu_source_awaits_agent_connect(self) -> None:
        """``qemu.py`` must contain an ``agent.connect`` await.

        The original F-0002 regression was the absence of any
        ``agent.connect`` call inside ``QEMUSandbox.start`` (or any helper
        invoked from it). This guard searches for the literal
        ``agent.connect(time_limit=`` substring and the helper invocation
        ``_ensure_agent_connected(`` to catch a future regression.
        """
        module_file = qemu_mod.__file__
        assert module_file is not None
        source_path = Path(module_file)
        assert source_path.exists()
        assert _file_contains(source_path, "agent.connect(time_limit="), (
            "qemu.py must call agent.connect(time_limit=...); F-0002 regressed."
        )
        assert _file_contains(source_path, "_ensure_agent_connected("), (
            "qemu.py must invoke _ensure_agent_connected from start(); F-0002 regressed."
        )
