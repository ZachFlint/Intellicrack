# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D25: a connected guest-agent channel must be a live one.

The in-guest Intellicrack agent is reached through a QEMU SLIRP port forward
(``-netdev user,...,hostfwd=tcp::4445-:4445``). SLIRP accepts the host-side TCP
connection immediately and unconditionally and only afterwards tries to reach a
listener inside the guest, so a successful ``connect()`` carries no information
about the guest at all. Measured live against a booted guest: the agent needs a
few more seconds after bootstrap to reach ``listen``, SLIRP therefore resets the
forwarded connection, and the host sees the close one log line after
``guest_agent_connected``. The sandbox nevertheless reported ``state=running``
and the GUI showed the instance as active, while every guest operation returned
``(-1, "", "Connection lost")``.

Two properties are gated here, both against real sockets:

* **Readiness is proven, not assumed.** Against a peer that accepts the
  connection and closes it without speaking - precisely what a hostfwd to a
  not-yet-listening guest does - :class:`GuestAgentClient` must not report
  itself connected, and :meth:`QEMUSandbox.start` must not report ``running``.
  The same peer coming up part-way through must still end in a usable channel,
  so "never report connected" is not a passing answer either.
* **A peer close is not silently swallowed.** Once the agent hangs up,
  ``is_connected`` has to become False so the next command reports a clear
  not-connected failure instead of the caller believing the channel is alive.

Both use the real :class:`IntellicrackAgentServer` from
:mod:`tests.sandbox.qemu.guest_agent_server`, which speaks the in-guest agent's
own ``execute``/``result`` protocol over a real loopback socket; the client
under test is the unmodified production one.

A readiness handshake only works if the guest really answers it, so the third
class here takes the ``handle_client`` the application itself generates into the
Linux guest, runs that generated source over a real socket, and lets the real
:meth:`GuestAgentClient.connect` handshake against it. The Windows half of the
same guarantee lives in :mod:`tests.sandbox.qemu.test_guest_command_protocol_s17d26`,
whose peer runs the generated ``agent.ps1``'s own readiness branch under a real
``powershell.exe``: nothing there can connect if that branch stops answering.
Without those two the servers in this module would happily answer a word no
guest speaks, and every gate here would pass over a channel that is dead in
production - the failure mode S17-D27 was caught making.
"""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import socket
import time
from typing import TYPE_CHECKING, Final, cast

import pytest

from intellicrack.sandbox.base import SandboxConfig, SandboxError
from intellicrack.sandbox.qemu import GuestAgentClient, GuestOS, QEMUConfig, QEMUSandbox
from tests.sandbox.qemu.guest_agent_server import (
    DEFAULT_GUEST_STDERR,
    DEFAULT_GUEST_STDOUT,
    IntellicrackAgentServer,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


# Larger than any number of connect attempts the budgets below allow, so the
# modelled guest never reaches listen() within the test.
_AGENT_NEVER_LISTENS: Final[int] = 10_000
# Connections the hostfwd swallows before the in-guest agent comes up, matching
# the handful of seconds measured between bootstrap and listen() on a live guest.
_DEAD_CONNECTIONS_BEFORE_LISTEN: Final[int] = 2

_DEAD_CHANNEL_BUDGET_S: Final[float] = 3.0
_RETRY_INTERVAL_S: Final[float] = 0.25
_LIVE_CHANNEL_BUDGET_S: Final[float] = 15.0
_COMMAND_BUDGET_S: Final[float] = 2.0
_CLOSE_OBSERVED_BUDGET_S: Final[float] = 5.0
_CLOSE_POLL_INTERVAL_S: Final[float] = 0.02

_EXPECTED_EXIT_CODE: Final[int] = 0
_FAILED_COMMAND_EXIT: Final[int] = -1
_NOT_CONNECTED_TEXT: Final[str] = "not connected"
_QEMU_PID_STANDIN: Final[int] = -1

_ECHO_COMMAND: Final[str] = "cmd.exe"
_ECHO_ARGS: Final[list[str]] = ["/c", "echo", "intellicrack"]

_MONITOR_DIRECTORY: Final[str] = "monitor"
_LINUX_AGENT_NAME: Final[str] = "agent.py"
_HANDLE_CLIENT_NAME: Final[str] = "handle_client"
_RECV_BUFFER_NAME: Final[str] = "RECV_BUFFER_SIZE"
_GENERATED_AGENT_ACCEPT_BUDGET_S: Final[float] = 10.0
_ERR_NO_DEFINITION: Final[str] = "the generated Linux agent defines no {name}"


class _StartPathSandbox(QEMUSandbox):
    """``QEMUSandbox`` whose QEMU-hardware steps are genuine no-ops.

    Everything the defect lives in is left untouched: ``_attach_qemu_agents``
    builds the real :class:`GuestAgentClient`, drives the real
    ``_ensure_agent_connected`` against a real socket, and the real
    :meth:`QEMUSandbox.start` decides what status that leaves behind. Only the
    steps that need a running hypervisor - launching QEMU, registering its pid,
    the QMP monitor, the shared-volume mount and the qemu-guest-agent bootstrap
    - are replaced, by subclassing rather than by patching.
    """

    async def is_available(self) -> bool:
        """Report the backend as usable without probing for a QEMU binary.

        Returns:
            bool: Always True.
        """
        return True

    async def _spawn_qemu_process(self) -> None:
        """Skip launching QEMU; no hypervisor is involved in this gate."""

    async def _resolve_qemu_pid(self) -> int | None:
        """Return the stand-in pid of the VM that was never launched.

        Returns:
            int | None: The stand-in QEMU pid.
        """
        return _QEMU_PID_STANDIN

    async def _register_qemu_pid(self, qemu_pid: int | None) -> int:
        """Record the stand-in pid without touching the process manager.

        Args:
            qemu_pid: Pid resolved for the QEMU process.

        Returns:
            int: The pid stored on the sandbox state.
        """
        resolved = _QEMU_PID_STANDIN if qemu_pid is None else qemu_pid
        self.state.pid = resolved
        return resolved

    async def _connect_and_verify_qmp(self) -> None:
        """Skip the QMP monitor; no QEMU monitor socket exists here."""

    async def _mount_guest_shared_volume(self) -> None:
        """Skip the in-guest mount; no guest exists here."""

    async def _bootstrap_guest_agent(self) -> None:
        """Skip the qemu-guest-agent bootstrap; no guest exists here."""

    async def release_agent(self) -> None:
        """Close whatever agent client the start path left behind."""
        if self._agent is not None:
            await self._agent.disconnect()
            self._agent = None


def _make_start_path_sandbox(agent_port: int, connect_timeout: float) -> _StartPathSandbox:
    """Build a sandbox whose agent channel points at the given port.

    Args:
        agent_port: Port the in-guest Intellicrack agent is reached on.
        connect_timeout: Budget the start path may spend reaching that agent.

    Returns:
        _StartPathSandbox: Sandbox ready for a real ``start`` call.
    """
    return _StartPathSandbox(
        config=SandboxConfig(),
        qemu_config=QEMUConfig(
            guest_os=GuestOS.WINDOWS,
            agent_port=agent_port,
            agent_connect_timeout=connect_timeout,
        ),
    )


async def _wait_for_channel_close(client: GuestAgentClient, budget: float) -> float:
    """Wait until the client stops reporting itself connected.

    Returning without the flag having cleared is not an error here; the
    caller's assertion on ``is_connected`` is the gate.

    Args:
        client: Guest agent client whose channel the peer has closed.
        budget: Maximum seconds to wait for the flag to clear.

    Returns:
        float: Seconds spent waiting.
    """
    started = time.monotonic()
    while time.monotonic() - started < budget:
        if not client.is_connected:
            break
        await asyncio.sleep(_CLOSE_POLL_INTERVAL_S)
    return time.monotonic() - started


class TestConnectProvesTheChannelIsLive:
    """A bare TCP connect to a hostfwd says nothing about the guest."""

    @pytest.mark.asyncio
    async def test_hostfwd_without_a_guest_listener_is_not_a_connected_agent(self) -> None:
        """A peer that accepts and hangs up must not count as connected.

        Every connect attempt reaches a real accepted socket that is closed
        before a byte crosses it, which is what SLIRP does for the whole window
        between the agent bootstrap and the in-guest ``listen``. Reporting that
        as a connected agent is what let the sandbox run on a dead channel.
        """
        server = IntellicrackAgentServer(dead_connections=_AGENT_NEVER_LISTENS)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            connected = await client.connect(
                time_limit=_DEAD_CHANNEL_BUDGET_S,
                retry_interval=_RETRY_INTERVAL_S,
            )

            assert server.accepted >= 1, f"the client never reached the modelled hostfwd; accepted={server.accepted}"
            assert connected is False, "connect() reported success over a channel the peer closed without speaking"
            assert client.connected is False, "the client is holding a dead socket open as a connected agent"
            assert client.is_connected is False, "is_connected must mirror the real state of the channel"
        finally:
            await client.disconnect()
            await server.stop()

    @pytest.mark.asyncio
    async def test_start_does_not_report_running_over_a_dead_channel(self) -> None:
        """``start`` must fail rather than declare a sandbox on a dead channel.

        This is the observed defect end to end: the sandbox reported
        ``state=running`` and the GUI listed the instance as active while every
        guest operation returned ``Connection lost``.
        """
        server = IntellicrackAgentServer(dead_connections=_AGENT_NEVER_LISTENS)
        await server.start()
        sandbox = _make_start_path_sandbox(server.port, _DEAD_CHANNEL_BUDGET_S)
        try:
            with pytest.raises(SandboxError):
                await sandbox.start()

            assert server.accepted >= 1, f"the start path never reached the modelled hostfwd; accepted={server.accepted}"
            assert sandbox.state.status != "running", (
                f"the sandbox reported status={sandbox.state.status!r} while its guest agent channel was dead"
            )
            assert sandbox.state.status == "error", f"a failed start must leave the error status behind; got {sandbox.state.status!r}"
            agent = sandbox.agent
            assert agent is None or agent.is_connected is False, "a failed start left a client claiming to be connected"
        finally:
            await sandbox.release_agent()
            await server.stop()

    @pytest.mark.asyncio
    async def test_channel_is_usable_once_the_guest_listener_comes_up(self) -> None:
        """The retries must end in a channel that really carries a command.

        The modelled hostfwd swallows the first connections and then serves the
        real agent protocol, which is the sequence a live guest produces. A
        client that refused every channel, or one that latched onto the first
        dead socket, cannot run this command.
        """
        server = IntellicrackAgentServer(dead_connections=_DEAD_CONNECTIONS_BEFORE_LISTEN)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            connected = await client.connect(
                time_limit=_LIVE_CHANNEL_BUDGET_S,
                retry_interval=_RETRY_INTERVAL_S,
            )
            assert connected is True, "the client gave up on a channel that did come up"

            exit_code, stdout, stderr = await client.send_command(
                _ECHO_COMMAND,
                _ECHO_ARGS,
                time_limit=_COMMAND_BUDGET_S,
            )

            assert server.accepted >= _DEAD_CONNECTIONS_BEFORE_LISTEN + 1, (
                f"the client must have reconnected past the dead connections; accepted={server.accepted}"
            )
            assert server.requests == [(_ECHO_COMMAND, tuple(_ECHO_ARGS))], (
                f"the command never reached the agent that was listening; requests={server.requests}"
            )
            assert exit_code == _EXPECTED_EXIT_CODE, f"the command failed on a live channel: {stderr!r}"
            assert stdout == DEFAULT_GUEST_STDOUT
            assert stderr == DEFAULT_GUEST_STDERR
            assert client.is_connected is True
        finally:
            await client.disconnect()
            await server.stop()


class _LinuxAgentScriptSandbox(QEMUSandbox):
    """``QEMUSandbox`` used only to generate the real Linux guest agent."""

    async def generate_linux_agent(self, share: Path) -> str:
        """Write the production Linux agent into ``share`` and read it back.

        Args:
            share: Host directory standing in for the guest's shared folder.

        Returns:
            str: Full source of the generated ``agent.py``.
        """
        self._shared_folder = share
        await asyncio.to_thread((share / _MONITOR_DIRECTORY).mkdir, parents=True, exist_ok=True)
        await self._create_guest_agent_script()
        return await asyncio.to_thread(
            (share / _MONITOR_DIRECTORY / _LINUX_AGENT_NAME).read_text,
            encoding="utf-8",
        )


def _generated_source_of(script: str, name: str) -> str:
    """Return the verbatim source of the generated agent's definition of ``name``.

    Args:
        script: Full source of the generated ``agent.py``.
        name: Function or module constant the caller needs.

    Returns:
        str: The defining statement, exactly as the application wrote it.

    Raises:
        AssertionError: If the generated agent defines no such name, or its
            source cannot be recovered.
    """
    for node in ast.parse(script).body:
        defines_function = isinstance(node, ast.FunctionDef) and node.name == name
        defines_constant = isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name
        if not (defines_function or defines_constant):
            continue
        segment = ast.get_source_segment(script, node)
        if segment is None:
            raise AssertionError(_ERR_NO_DEFINITION.format(name=name))
        return segment
    raise AssertionError(_ERR_NO_DEFINITION.format(name=name))


def _generated_handle_client(script: str, module_path: Path) -> Callable[[socket.socket], None]:
    """Import the generated agent's own ``handle_client`` and return it.

    Nothing about the request loop is rewritten here. Its source and the buffer
    size it reads with are lifted verbatim out of the file the application just
    wrote for the guest, given only the imports the guest's own module header
    provides, and imported as a real module - so a readiness branch that is
    missing, misspelled, or unreachable in the generated source is missing here
    too. The rest of ``agent.py`` is left out because importing it whole would
    start the guest's monitors and bind the guest's port.

    Args:
        script: Full source of the generated ``agent.py``.
        module_path: File the lifted source is written to before import.

    Returns:
        Callable[[socket.socket], None]: The generated request loop, ready to
        be handed an accepted connection.

    Raises:
        AssertionError: If the lifted source cannot be imported.
    """
    module_path.write_text(
        "\n".join([
            "from __future__ import annotations",
            "import json",
            "import logging",
            "import socket",
            "from typing import Any",
            "_logger = logging.getLogger(__name__)",
            _generated_source_of(script, _RECV_BUFFER_NAME),
            _generated_source_of(script, _HANDLE_CLIENT_NAME),
        ]),
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(module_path.stem, module_path)
    if spec is None or spec.loader is None:
        raise AssertionError(_ERR_NO_DEFINITION.format(name=_HANDLE_CLIENT_NAME))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return cast("Callable[[socket.socket], None]", getattr(module, _HANDLE_CLIENT_NAME))


def _serve_one_connection(listener: socket.socket, handler: Callable[[socket.socket], None]) -> None:
    """Accept a single connection and hand it to the generated request loop.

    Args:
        listener: Bound and listening loopback socket.
        handler: The generated agent's ``handle_client``.
    """
    listener.settimeout(_GENERATED_AGENT_ACCEPT_BUDGET_S)
    conn, _ = listener.accept()
    handler(conn)


class TestTheGuestReallyAnswersTheHandshake:
    """The generated Linux agent must answer the probe the client sends."""

    @pytest.mark.asyncio
    async def test_generated_linux_agent_completes_the_real_connect(self, tmp_path: Path) -> None:
        """The production client connects to the production-generated guest.

        Both halves are real: :meth:`QEMUSandbox._create_guest_agent_script`
        writes the guest's source, that source's own ``handle_client`` runs on
        a real accepted socket, and the unmodified
        :meth:`GuestAgentClient.connect` drives the handshake across it. Since
        the client now reports itself connected only once the handshake
        completes, ``connected is True`` here can only mean the generated guest
        parsed the probe and framed a reply the client recognised.

        Args:
            tmp_path: Directory the shared folder is created under.
        """
        sandbox = _LinuxAgentScriptSandbox(
            config=SandboxConfig(),
            qemu_config=QEMUConfig(guest_os=GuestOS.LINUX),
        )
        script = await sandbox.generate_linux_agent(tmp_path)
        handler = _generated_handle_client(script, tmp_path / "generated_agent_handler.py")

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])
        served = asyncio.create_task(asyncio.to_thread(_serve_one_connection, listener, handler))
        client = GuestAgentClient(port=port)
        try:
            connected = await client.connect(
                time_limit=_LIVE_CHANNEL_BUDGET_S,
                retry_interval=_RETRY_INTERVAL_S,
            )

            assert connected is True, "the client could not complete its handshake against the generated Linux agent"
            assert client.is_connected is True
        finally:
            await client.disconnect()
            await served
            listener.close()


class TestPeerCloseEndsTheChannel:
    """A channel the agent hung up on must stop reporting itself connected."""

    @pytest.mark.asyncio
    async def test_close_clears_connected_and_the_next_command_says_so(self) -> None:
        """After the agent hangs up the client must admit it is disconnected.

        The first command proves the channel was genuinely live, so the state
        that follows is produced by the peer's close and nothing else. The
        second command must report that plainly instead of writing into a dead
        socket and sitting out its deadline.
        """
        server = IntellicrackAgentServer(close_after_replies=1)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            assert await client.connect(time_limit=_LIVE_CHANNEL_BUDGET_S, retry_interval=_RETRY_INTERVAL_S) is True

            first = await client.send_command(_ECHO_COMMAND, _ECHO_ARGS, time_limit=_COMMAND_BUDGET_S)
            assert first[0] == _EXPECTED_EXIT_CODE, f"the channel was not live before the close: {first[2]!r}"

            waited = await _wait_for_channel_close(client, _CLOSE_OBSERVED_BUDGET_S)

            assert client.is_connected is False, (
                f"the agent closed the channel {waited:.2f}s ago and the client still reports it connected; nothing will ever reconnect it"
            )

            started = time.monotonic()
            exit_code, stdout, stderr = await client.send_command(
                _ECHO_COMMAND,
                _ECHO_ARGS,
                time_limit=_COMMAND_BUDGET_S,
            )
            elapsed = time.monotonic() - started

            assert exit_code == _FAILED_COMMAND_EXIT
            assert not stdout, f"a command on a closed channel cannot have produced output: {stdout!r}"
            assert _NOT_CONNECTED_TEXT in stderr.lower(), f"the caller was not told the channel is gone; got {stderr!r}"
            assert elapsed < _COMMAND_BUDGET_S, f"the command waited out its deadline on a channel known to be closed: {elapsed:.2f}s"
        finally:
            await client.disconnect()
            await server.stop()
