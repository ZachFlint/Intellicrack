# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for audit7 F-0006: guest agent bootstrap via qemu-guest-agent.

These tests drive ``QEMUSandbox._bootstrap_guest_agent`` directly with a
real fake QMP transport (no ``unittest.mock``). The fake records every
``guest-ping`` and ``guest-exec`` command, returns canned QMP responses,
and exposes the captured invocations to the test assertions.
"""

from __future__ import annotations

import asyncio
from typing import cast

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import (
    GuestOS,
    QEMUConfig,
    QEMUSandbox,
    QMPClient,
    QMPResponse,
)


class _FakeQMPClient(QMPClient):
    """Recording fake of :class:`QMPClient` used by bootstrap tests.

    The fake mimics the public surface used by ``_bootstrap_guest_agent``:
    an async ``execute_command`` method that takes a QMP command dict and
    a timeout, and returns a ``QMPResponse``. Behaviour is fully driven by
    constructor parameters so each scenario can describe the exact reply
    sequence it expects.

    Attributes:
        invocations: Recorded ``(command_dict, time_limit)`` tuples in
            call order.
    """

    invocations: list[tuple[dict[str, object], float]]

    def __init__(
        self,
        *,
        ping_responses: list[QMPResponse],
        exec_response: QMPResponse,
    ) -> None:
        """Initialize the recording fake.

        Args:
            ping_responses: Replies for successive ``guest-ping`` calls.
                Must contain at least one entry.
            exec_response: Reply for the single ``guest-exec`` call.

        Raises:
            ValueError: If ``ping_responses`` is empty.
        """
        super().__init__()
        if not ping_responses:
            msg = "ping_responses must contain at least one entry"
            raise ValueError(msg)
        self._ping_responses: list[QMPResponse] = list(ping_responses)
        self._exec_response: QMPResponse = exec_response
        self.invocations: list[tuple[dict[str, object], float]] = []

    async def execute_command(
        self,
        command: dict[str, object],
        time_limit: float = 10.0,
    ) -> QMPResponse:
        """Record the QMP invocation and return the next canned reply.

        Args:
            command: QMP command dictionary with at least an ``execute``
                key.
            time_limit: Per-call response timeout in seconds.

        Returns:
            QMPResponse: The canned reply for the recognised command, or
            an error response for any unexpected command.
        """
        self.invocations.append((command, time_limit))
        execute = command.get("execute")
        if execute == "guest-ping":
            if len(self._ping_responses) > 1:
                return self._ping_responses.pop(0)
            return self._ping_responses[0]
        if execute == "guest-exec":
            return self._exec_response
        return QMPResponse(success=False, error=f"unexpected command: {execute!r}")


class _BootstrapTestSandbox(QEMUSandbox):
    """Test subclass exposing internal hooks needed by bootstrap tests.

    The subclass adds public accessors that avoid reaching into
    single-underscore attributes from outside the class hierarchy and
    keeps the call sites in this module type-safe.
    """

    def attach_qmp(self, client: QMPClient) -> None:
        """Attach a QMP client (real or fake subclass) for direct testing.

        Args:
            client: A :class:`QMPClient` subclass instance to use as the
                active QMP transport.
        """
        self._qmp = client

    def get_agent_guest_pid(self) -> int | None:
        """Return the recorded guest-side agent process id.

        Returns:
            int | None: PID returned by ``guest-exec`` after a successful
            bootstrap, or ``None`` if bootstrap was not executed or
            failed before recording a PID.
        """
        return self._agent_guest_pid

    async def bootstrap_for_test(self) -> None:
        """Invoke :meth:`QEMUSandbox._bootstrap_guest_agent` directly."""
        await self._bootstrap_guest_agent()

    async def wait_for_qemu_ga_for_test(
        self,
        ping_timeout: float,
        poll_interval: float,
    ) -> None:
        """Invoke :meth:`QEMUSandbox._wait_for_qemu_ga` with overrides.

        Args:
            ping_timeout: Maximum total wait time in seconds for
                ``guest-ping`` to succeed.
            poll_interval: Delay in seconds between successive
                ``guest-ping`` attempts.
        """
        await self._wait_for_qemu_ga(
            ping_timeout=ping_timeout,
            poll_interval=poll_interval,
        )


def _make_sandbox(guest_os: GuestOS) -> _BootstrapTestSandbox:
    """Build a minimal sandbox with no QEMU process attached.

    Args:
        guest_os: Guest OS family to configure on the sandbox.

    Returns:
        _BootstrapTestSandbox: Sandbox instance suitable for direct
        invocation of bootstrap helpers.
    """
    cfg = QEMUConfig(guest_os=guest_os)
    return _BootstrapTestSandbox(config=SandboxConfig(), qemu_config=cfg)


def _guest_exec_arguments(
    invocations: list[tuple[dict[str, object], float]],
) -> dict[str, object]:
    """Return the ``arguments`` payload of the first recorded guest-exec.

    Args:
        invocations: Recorded fake QMP invocations from the test client.

    Returns:
        dict[str, object]: The ``arguments`` mapping from the first
        ``guest-exec`` invocation.

    Raises:
        AssertionError: If no ``guest-exec`` invocation was recorded.
    """
    for command, _timeout in invocations:
        if command.get("execute") == "guest-exec":
            arguments: object = command.get("arguments")
            return _coerce_guest_exec_arguments(arguments)
    msg = "no guest-exec invocation recorded"
    raise AssertionError(msg)


def _coerce_guest_exec_arguments(payload: object) -> dict[str, object]:
    """Validate and narrow a ``guest-exec`` ``arguments`` payload.

    Args:
        payload: The raw value extracted from a recorded QMP command's
            ``arguments`` key. May be any object.

    Returns:
        dict[str, object]: A new dict containing the same mappings as
        ``payload`` once it has been verified to be a ``dict`` with
        string keys.

    Raises:
        TypeError: If ``payload`` is not a ``dict`` or contains a
            non-string key.
    """
    if not isinstance(payload, dict):
        msg = "guest-exec command missing 'arguments' dict"
        raise TypeError(msg)
    raw_mapping = cast("dict[object, object]", payload)
    narrowed: dict[str, object] = {}
    for raw_key, raw_value in raw_mapping.items():
        if not isinstance(raw_key, str):
            err = "guest-exec 'arguments' key was not a string"
            raise TypeError(err)
        narrowed[raw_key] = raw_value
    return narrowed


def test_bootstrap_windows_guest_exec_uses_cmd_exe_and_z_drive_script() -> None:
    """Scenario A: Windows bootstrap uses cmd.exe + Z drive launcher."""
    fake_qmp = _FakeQMPClient(
        ping_responses=[QMPResponse(success=True, data={})],
        exec_response=QMPResponse(success=True, data={"pid": 4242}),
    )
    sandbox = _make_sandbox(GuestOS.WINDOWS)
    sandbox.attach_qmp(fake_qmp)

    asyncio.run(sandbox.bootstrap_for_test())

    arguments = _guest_exec_arguments(fake_qmp.invocations)
    assert arguments["path"] == "cmd.exe"
    arg_list = arguments["arg"]
    assert isinstance(arg_list, list)
    assert arg_list == ["/c", "Z:\\monitor\\start_agent.cmd"]
    assert arguments["capture-output"] is False

    ping_calls = [cmd for cmd, _ in fake_qmp.invocations if cmd.get("execute") == "guest-ping"]
    exec_calls = [cmd for cmd, _ in fake_qmp.invocations if cmd.get("execute") == "guest-exec"]
    assert len(ping_calls) >= 1
    assert len(exec_calls) == 1
    assert sandbox.get_agent_guest_pid() == 4242


def test_bootstrap_linux_guest_exec_uses_bash_and_shared_script() -> None:
    """Scenario B: Linux bootstrap uses /bin/bash + shared-folder launcher."""
    fake_qmp = _FakeQMPClient(
        ping_responses=[QMPResponse(success=True, data={})],
        exec_response=QMPResponse(success=True, data={"pid": 17}),
    )
    sandbox = _make_sandbox(GuestOS.LINUX)
    sandbox.attach_qmp(fake_qmp)

    asyncio.run(sandbox.bootstrap_for_test())

    arguments = _guest_exec_arguments(fake_qmp.invocations)
    assert arguments["path"] == "/bin/bash"
    arg_list = arguments["arg"]
    assert isinstance(arg_list, list)
    assert arg_list == ["/mnt/shared/monitor/start_agent.sh"]
    assert arguments["capture-output"] is False

    assert sandbox.get_agent_guest_pid() == 17


def test_bootstrap_raises_sandbox_error_when_qemu_ga_never_responds() -> None:
    """Scenario C: persistent guest-ping errors raise SandboxError mentioning qemu-guest-agent."""
    fake_qmp = _FakeQMPClient(
        ping_responses=[QMPResponse(success=False, error="VQ closed")],
        exec_response=QMPResponse(success=True, data={"pid": 1}),
    )
    sandbox = _make_sandbox(GuestOS.WINDOWS)
    sandbox.attach_qmp(fake_qmp)

    with pytest.raises(SandboxError) as wait_err:
        asyncio.run(
            sandbox.wait_for_qemu_ga_for_test(ping_timeout=0.05, poll_interval=0.01),
        )
    assert "qemu-guest-agent" in str(wait_err.value)

    ping_calls = [cmd for cmd, _ in fake_qmp.invocations if cmd.get("execute") == "guest-ping"]
    exec_calls = [cmd for cmd, _ in fake_qmp.invocations if cmd.get("execute") == "guest-exec"]
    assert len(ping_calls) >= 1
    assert len(exec_calls) == 0
    assert sandbox.get_agent_guest_pid() is None


def test_bootstrap_retries_guest_ping_until_success() -> None:
    """guest-ping retries until success, then guest-exec runs exactly once."""
    fake_qmp = _FakeQMPClient(
        ping_responses=[
            QMPResponse(success=False, error="VQ closed"),
            QMPResponse(success=False, error="VQ closed"),
            QMPResponse(success=True, data={}),
        ],
        exec_response=QMPResponse(success=True, data={"pid": 99}),
    )
    sandbox = _make_sandbox(GuestOS.WINDOWS)
    sandbox.attach_qmp(fake_qmp)

    async def _drive() -> None:
        """Wait for qemu-ga with a short retry budget, then bootstrap."""
        await sandbox.wait_for_qemu_ga_for_test(ping_timeout=5.0, poll_interval=0.01)
        await sandbox.bootstrap_for_test()

    asyncio.run(_drive())

    ping_calls = [cmd for cmd, _ in fake_qmp.invocations if cmd.get("execute") == "guest-ping"]
    exec_calls = [cmd for cmd, _ in fake_qmp.invocations if cmd.get("execute") == "guest-exec"]
    assert len(ping_calls) >= 3
    assert len(exec_calls) == 1
    assert sandbox.get_agent_guest_pid() == 99


def test_bootstrap_raises_when_guest_exec_returns_no_pid() -> None:
    """A guest-exec reply lacking a pid field surfaces as SandboxError."""
    fake_qmp = _FakeQMPClient(
        ping_responses=[QMPResponse(success=True, data={})],
        exec_response=QMPResponse(success=True, data={}),
    )
    sandbox = _make_sandbox(GuestOS.WINDOWS)
    sandbox.attach_qmp(fake_qmp)

    with pytest.raises(SandboxError):
        asyncio.run(sandbox.bootstrap_for_test())

    assert sandbox.get_agent_guest_pid() is None


def test_bootstrap_raises_when_qmp_not_connected() -> None:
    """Calling bootstrap without QMP attached raises SandboxError."""
    sandbox = _make_sandbox(GuestOS.WINDOWS)

    with pytest.raises(SandboxError):
        asyncio.run(sandbox.bootstrap_for_test())
