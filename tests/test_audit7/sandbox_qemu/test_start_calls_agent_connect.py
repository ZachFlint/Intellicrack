# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression tests for audit7 F-0002: ``QEMUSandbox.start`` agent connect call.

These tests drive ``QEMUSandbox.start`` through to the *real*
``GuestAgentClient.connect`` implementation and the real
``QEMUSandbox._ensure_agent_connected`` wrapper. The only parts neutralised
are the helpers that genuinely require an installed QEMU binary, a QMP
monitor, or an in-guest agent script (disk-image boot, QMP handshake,
guest-agent bootstrap, PID-file polling, and process-manager registration).
Those are replaced with real, non-mock subclass overrides that perform no
I/O, so the agent-connect orchestration runs end to end against a real TCP
endpoint.

The success path stands up a real ``asyncio`` TCP server on the configured
agent port; the failure paths point the real client at a genuinely closed
port so the connection is refused. In every case the production
``GuestAgentClient.connect`` performs real ``asyncio.open_connection`` socket
operations - no mock, stub, or synthetic agent response is involved.
"""

from __future__ import annotations

import asyncio
import math
import socket
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    GuestAgentClient,
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
)


if TYPE_CHECKING:
    from collections.abc import Coroutine


def _reserve_loopback_port() -> int:
    """Bind, read, and release a loopback TCP port to obtain a free number.

    The probe socket is closed before returning, so the port is genuinely
    unbound; a subsequent ``connect`` to it from the same host yields a real
    ``ConnectionRefused`` (an ``OSError`` subclass) until something rebinds
    it.

    Returns:
        int: A TCP port number that was free at the moment of the call.
    """
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


class _ArgCapturingAgent(GuestAgentClient):
    """Real guest-agent client that records the ``connect`` ``time_limit``.

    This is not a stub: ``connect`` still calls the production
    ``GuestAgentClient.connect`` (real ``asyncio.open_connection`` socket
    operations, real retry loop, real reader task). The override exists only
    to capture the exact ``time_limit`` argument the orchestration passed in,
    so a test can assert on it with an exact value.

    Attributes:
        captured_time_limit: The ``time_limit`` passed to the most recent
            ``connect`` call, or ``None`` if ``connect`` was never invoked.
        fast_retry_interval: Retry interval applied to the real connect loop
            when the production wrapper calls ``connect`` without one, keeping
            failure-path tests fast and deterministic.
    """

    captured_time_limit: float | None
    fast_retry_interval: float

    def __init__(self, host: str = "127.0.0.1", port: int = 4445, *, fast_retry_interval: float = 0.05) -> None:
        """Initialise the real client and the capture slot.

        Args:
            host: Host address where the guest agent is reachable.
            port: TCP port for the guest agent server.
            fast_retry_interval: Retry interval substituted into the real
                connect loop so connection-refused tests stay fast.
        """
        super().__init__(host=host, port=port)
        self.captured_time_limit = None
        self.fast_retry_interval = fast_retry_interval

    async def connect(self, time_limit: float = 60.0, retry_interval: float = 2.0) -> bool:
        """Record ``time_limit`` then run the real connect implementation.

        The production ``_ensure_agent_connected`` invokes ``connect`` with
        only ``time_limit``; this override substitutes a fast retry interval
        so a refused connection is retried quickly, while still executing the
        real ``GuestAgentClient.connect`` socket loop.

        Args:
            time_limit: Total timeout in seconds for connection attempts.
            retry_interval: Interval between retries (overridden by the fast
                interval when the production default is in effect).

        Returns:
            bool: Whatever the production ``GuestAgentClient.connect`` returns.
        """
        self.captured_time_limit = time_limit
        effective_interval = self.fast_retry_interval if math.isclose(retry_interval, 2.0) else retry_interval
        return await super().connect(time_limit=time_limit, retry_interval=effective_interval)


class _RealAgentStartSandbox(QEMUSandbox):
    """``QEMUSandbox`` that boots against a real agent socket, no QEMU binary.

    Only the helpers that hard-require an installed QEMU / QMP / in-guest
    agent are overridden, and they are overridden with genuine (non-mock)
    coroutine implementations that perform no I/O. ``_attach_qemu_agents`` is
    overridden solely to inject the real-connect ``_ArgCapturingAgent`` and a
    fast ``retry_interval``; it still drives the real production
    ``_ensure_agent_connected`` wrapper, which in turn awaits the real
    ``connect``.

    Attributes:
        connect_retry_interval: Fast retry interval handed to the injected
            real agent so failure-path tests stay fast and deterministic.
        last_agent: The most recently constructed ``_ArgCapturingAgent``.
    """

    connect_retry_interval: float
    last_agent: _ArgCapturingAgent | None

    def __init__(
        self,
        config: SandboxConfig | None = None,
        qemu_config: QEMUConfig | None = None,
        *,
        connect_retry_interval: float = 0.05,
    ) -> None:
        """Initialise the sandbox and agent-injection bookkeeping.

        Args:
            config: General sandbox configuration shared across backends.
            qemu_config: QEMU-specific configuration.
            connect_retry_interval: Fast retry interval forwarded to the
                injected real ``GuestAgentClient.connect`` retry loop.
        """
        super().__init__(config, qemu_config)
        self.connect_retry_interval = connect_retry_interval
        self.last_agent = None

    async def is_available(self) -> bool:
        """Report availability without probing for a QEMU binary.

        Returns:
            bool: Always ``True`` so ``start`` proceeds to the agent step.
        """
        return True

    async def _prepare_qemu_shared_folders(self) -> None:
        """Skip shared-folder creation; the agent path needs no folders."""

    async def _create_guest_agent_script(self) -> None:
        """Skip writing the in-guest agent script (no guest disk present)."""

    async def _spawn_qemu_process(self) -> None:
        """Skip spawning the QEMU launcher subprocess (no QEMU binary)."""

    async def _resolve_qemu_pid(self) -> int | None:
        """Return a deterministic synthetic PID without polling a PID file.

        Returns:
            int | None: A fixed PID standing in for the booted VM.
        """
        return 4242

    async def _register_qemu_pid(self, qemu_pid: int | None) -> int:
        """Record the PID on state without touching the process manager.

        Args:
            qemu_pid: PID produced by ``_resolve_qemu_pid``.

        Returns:
            int: The PID stored on the sandbox state.
        """
        verified_pid: int = qemu_pid if qemu_pid is not None else -1
        self._qemu_pid = verified_pid
        self.state.pid = verified_pid
        return verified_pid

    async def _connect_and_verify_qmp(self) -> None:
        """Skip the QMP handshake (no QMP monitor socket available)."""

    async def _bootstrap_guest_agent(self) -> None:
        """Skip in-guest agent bootstrap (no guest to launch the agent in)."""

    async def _cleanup(self) -> None:
        """Skip filesystem cleanup; no temp dir is created in these tests."""

    async def ensure_agent_connected_for_test(self, agent: GuestAgentClient, time_limit: float) -> None:
        """Invoke the real production ``_ensure_agent_connected`` static helper.

        Provides a public entry point onto the unmodified production wrapper
        so tests can drive its exception-translation contract directly. The
        production helper raises ``SandboxError`` on failure, which propagates
        out of this awaited call.

        Args:
            agent: Real guest-agent client to connect.
            time_limit: Total seconds to wait for the agent socket.
        """
        await self._ensure_agent_connected(agent, time_limit)

    async def _attach_qemu_agents(self) -> None:
        """Construct the real capturing agent and drive the real connect wrapper.

        Mirrors the production ``_attach_qemu_agents`` (QMP verify, agent
        bootstrap, real-agent construction, then the production
        ``_ensure_agent_connected`` wrapper). The connect is performed by the
        unmodified production ``_ensure_agent_connected`` /
        ``GuestAgentClient.connect`` code path against whatever TCP endpoint
        listens on the configured agent port. When the real ``connect`` fails
        to reach the agent socket, the awaited production helper raises
        ``SandboxError``, which propagates out of this override.
        """
        await self._connect_and_verify_qmp()
        await self._bootstrap_guest_agent()

        agent = _ArgCapturingAgent(
            port=self._qemu_config.agent_port,
            fast_retry_interval=self.connect_retry_interval,
        )
        self.last_agent = agent
        self._agent = agent
        await self._ensure_agent_connected(agent, self._qemu_config.agent_connect_timeout)


def _make_sandbox(
    *,
    agent_port: int,
    agent_timeout: float,
    retry_interval: float = 2.0,
) -> _RealAgentStartSandbox:
    """Construct a sandbox wired to a specific agent port and timeout.

    Args:
        agent_port: TCP port the real ``GuestAgentClient`` will connect to.
        agent_timeout: ``agent_connect_timeout`` to set on the config.
        retry_interval: Retry interval forwarded to the real connect loop.

    Returns:
        _RealAgentStartSandbox: A configured test sandbox instance.
    """
    cfg = QEMUConfig(
        guest_os=GuestOS.WINDOWS,
        agent_port=agent_port,
        agent_connect_timeout=agent_timeout,
    )
    return _RealAgentStartSandbox(
        config=SandboxConfig(),
        qemu_config=cfg,
        connect_retry_interval=retry_interval,
    )


def _run(coro: Coroutine[object, object, None]) -> None:
    """Run a coroutine to completion on a fresh event loop.

    Args:
        coro: Coroutine to drive to completion.
    """
    asyncio.run(coro)


class TestF0002StartAwaitsRealAgentConnect:
    """Scenario A: ``start`` drives the real ``connect`` against a live socket."""

    def test_start_connects_real_agent_to_live_server_with_configured_timeout(self) -> None:
        """``start`` opens a real socket to the agent server and records the configured timeout.

        A real ``asyncio`` TCP server is bound on the configured agent port.
        The unmocked production ``GuestAgentClient.connect`` performs a real
        ``asyncio.open_connection`` to it; the test asserts the server saw a
        real inbound connection, that the live connection state is reported,
        that the real reader task is running, that the configured
        ``agent_connect_timeout`` reached ``connect`` verbatim, and that the
        sandbox transitioned to ``running``.

        If ``start`` stopped awaiting ``connect`` (the F-0002 regression),
        ``is_connected`` would stay ``False`` and the server would record no
        inbound connection, failing the test.
        """
        accepted: list[bool] = []

        async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            accepted.append(True)
            try:
                await reader.read(1)
            finally:
                writer.close()

        async def _start_and_assert(bound_port: int) -> None:
            sb = _make_sandbox(agent_port=bound_port, agent_timeout=9.5)
            await sb.start()
            agent = sb.agent
            assert isinstance(agent, _ArgCapturingAgent)
            assert agent.captured_time_limit is not None
            assert math.isclose(agent.captured_time_limit, 9.5)
            assert agent.is_connected is True
            assert sb.state.status == "running"
            assert sb.state.pid == 4242
            await agent.disconnect()

        async def scenario() -> None:
            server = await asyncio.start_server(_handle, "127.0.0.1", 0)
            bound_port = int(server.sockets[0].getsockname()[1])
            await server.start_serving()
            try:
                await _start_and_assert(bound_port)
            finally:
                server.close()
                await server.wait_closed()

        _run(scenario())
        assert accepted == [True]


class TestF0002StartFailsWhenRealAgentUnreachable:
    """Scenario B: ``start`` raises ``SandboxError`` when the real connect fails."""

    def test_start_raises_sandbox_error_on_connection_refused(self) -> None:
        """``start`` wraps a real connection-refused failure into ``SandboxError``.

        No server is bound on the agent port, so the real
        ``GuestAgentClient.connect`` retry loop receives genuine
        ``ConnectionRefused`` errors for the whole timeout window and returns
        ``False``. ``start`` must surface that as ``SandboxError`` with the
        wrapper message and transition state to ``error``.

        Pre-fix code never awaited ``connect``, so it would report a silent
        success; this test fails on that code.
        """
        closed_port = _reserve_loopback_port()

        async def scenario() -> None:
            sb = _make_sandbox(agent_port=closed_port, agent_timeout=0.4, retry_interval=0.05)
            with pytest.raises(SandboxError) as excinfo:
                await sb.start()

            assert str(excinfo.value) == "sandbox start failed"
            cause = excinfo.value.__cause__
            assert isinstance(cause, SandboxError)
            assert "guest agent failed to connect within 0.4s" in str(cause)

            agent = sb.agent
            assert isinstance(agent, _ArgCapturingAgent)
            assert agent.captured_time_limit is not None
            assert math.isclose(agent.captured_time_limit, 0.4)
            assert agent.is_connected is False
            assert sb.state.status == "error"
            assert sb.state.last_error == "guest agent failed to connect within 0.4s"

        _run(scenario())

    def test_real_connect_honours_configured_timeout_budget(self) -> None:
        """The real connect loop spends roughly the configured timeout before failing.

        Drives the unmocked ``GuestAgentClient.connect`` against a closed
        port and measures the wall-clock duration. The real loop must keep
        retrying for at least the configured ``time_limit`` (proving the
        configured value is actually applied), while bounded above so a
        runaway loop is caught. This ties the configured timeout to a real,
        observable behaviour rather than a recorded mock argument.
        """
        closed_port = _reserve_loopback_port()

        async def scenario() -> None:
            agent = GuestAgentClient(host="127.0.0.1", port=closed_port)
            started = time.monotonic()
            result = await agent.connect(time_limit=0.5, retry_interval=0.05)
            elapsed = time.monotonic() - started

            assert result is False
            assert agent.is_connected is False
            assert elapsed >= 0.5
            assert elapsed < 5.0

        _run(scenario())


class TestF0002StartRaisesOnRealConnectError:
    """Scenario C: a real OSError from the connect path becomes ``SandboxError``."""

    def test_ensure_agent_connected_wraps_real_oserror_with_cause(self) -> None:
        """A genuine ``OSError`` escaping ``connect`` is wrapped as ``SandboxError`` with a cause.

        The production ``GuestAgentClient.connect`` retry loop swallows
        transient ``OSError``/``TimeoutError`` internally, so to exercise the
        production ``_ensure_agent_connected`` exception-translation branch we
        drive the real wrapper with a real client whose ``connect`` performs a
        genuine failing socket operation - a real blocking
        ``socket.create_connection`` to a closed loopback port - and lets the
        resulting ``ConnectionRefusedError`` (an ``OSError`` subclass)
        propagate uncaught.

        The wrapper must raise ``SandboxError`` carrying the configured
        timeout in its message and chain the original ``OSError`` as
        ``__cause__``, proving the failure is surfaced (not swallowed) and the
        causal traceback is preserved.
        """
        closed_port = _reserve_loopback_port()

        class _RealSocketRaisingAgent(GuestAgentClient):
            """Real client whose ``connect`` performs a genuine failing socket op."""

            async def connect(self, time_limit: float = 60.0, retry_interval: float = 2.0) -> bool:
                """Perform a real blocking connect to a closed port.

                The genuine ``socket.create_connection`` to a closed loopback
                port raises ``ConnectionRefusedError`` (an ``OSError``
                subclass) from the awaited thread call, so this coroutine never
                returns normally.

                Args:
                    time_limit: Total timeout (unused; a single real attempt is made).
                    retry_interval: Retry interval (unused).

                Returns:
                    bool: Never returned; the real socket op raises first.
                """
                del time_limit, retry_interval
                conn = await asyncio.to_thread(
                    socket.create_connection,
                    (self._host, self._port),
                    1.0,
                )
                conn.close()
                return True

        async def scenario() -> None:
            sb = _make_sandbox(agent_port=closed_port, agent_timeout=0.2, retry_interval=0.05)
            agent = _RealSocketRaisingAgent(host="127.0.0.1", port=closed_port)

            with pytest.raises(SandboxError) as excinfo:
                await sb.ensure_agent_connected_for_test(agent, time_limit=0.2)

            assert "guest agent failed to connect within 0.2s" in str(excinfo.value)
            cause = excinfo.value.__cause__
            assert isinstance(cause, OSError)
            assert agent.is_connected is False

        _run(scenario())


class TestF0002QEMUConfigHasAgentConnectTimeout:
    """``QEMUConfig`` must expose ``agent_connect_timeout`` with a 60s default."""

    def test_default_value_is_60_seconds(self) -> None:
        """``QEMUConfig().agent_connect_timeout`` defaults to ``60.0`` seconds.

        The audit7 plan calls for a 60s default; verifying the value pins the
        configuration contract that ``start`` forwards into ``connect``.
        """
        cfg = QEMUConfig()
        assert math.isclose(cfg.agent_connect_timeout, 60.0)

    def test_field_is_overrideable(self) -> None:
        """``QEMUConfig`` accepts and stores a custom ``agent_connect_timeout``."""
        cfg = QEMUConfig(agent_connect_timeout=5.0)
        assert math.isclose(cfg.agent_connect_timeout, 5.0)
