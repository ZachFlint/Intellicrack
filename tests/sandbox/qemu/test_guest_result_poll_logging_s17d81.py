# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gate for S17-D81: an idle poll slice is control flow, not an incident.

``GuestAgentClient._await_guest_result`` reads the message queue in one-second
slices so a channel that dies under a waiting command is noticed within a slice
rather than at the deadline. Every slice that expired empty - the loop's
ordinary continue path while the guest is still working - was logged with
``exc_info=True``, so the rendered log grew a full traceback per second of
guest-side work: ``asyncio/tasks.py`` in ``wait_for``, ``asyncio/queues.py`` in
``get``, a ``CancelledError`` chained into a ``TimeoutError``, and a table of
locals. Measured driving live Windows guests on 2026-08-09, several such blocks
appeared per run - including during an ordinary ``destroy`` - on runs that
finished with ``qemu_process_exited returncode=0``.

Nothing failed because of it, which is the point: a healthy run's log became
indistinguishable from a crashing one, and a real traceback had nowhere to
stand out from.

These tests render the real logging pipeline to a real file - the same
``ConsoleRenderer`` path the application writes with, which is what turns
``exc_info`` into that block - and read back what a live run would have
produced. The guest side is a real TCP server speaking the in-guest agent's
protocol, so the poll slices being counted are slices really spent waiting on a
socket, not a simulated wait.

Both directions are gated. A command the guest takes real time over must leave
no traceback behind, and the two ways a wait ends badly - the channel resetting
under it, and the guest missing its deadline - must still be reported, the
first still carrying the traceback of the exception that ended it.
"""

from __future__ import annotations

import asyncio
import json
import socket
import struct
import time
from typing import TYPE_CHECKING, Any, Final

import pytest

from intellicrack.core.logging import (
    IntellicrackLogger,
    get_logger,
    get_stdlib_root_logger,
)
from intellicrack.sandbox import qemu as qemu_module
from intellicrack.sandbox.qemu import GuestAgentClient
from tests.sandbox.qemu.guest_agent_server import (
    AGENT_MESSAGE_PONG,
    AGENT_REQUEST_EXECUTE,
    AGENT_REQUEST_PING,
    GuestAgentServerError,
    GuestCommandResult,
    IntellicrackAgentServer,
    decode_object,
)


if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

# Taken from the production module rather than restated: the slice length is
# what decides how many idle polls a wait costs, and a copy of it here would go
# on agreeing with a value the code no longer uses.
_POLL_SLICE_S: Final[float] = getattr(qemu_module, "_AGENT_POLL_TIMEOUT")
_LOST_AFTER_DISPATCH_TEMPLATE: Final[str] = str(getattr(qemu_module, "_ERR_AGENT_LOST_AFTER_DISPATCH"))
_COMMAND_TIMED_OUT: Final[str] = str(getattr(qemu_module, "_ERR_AGENT_COMMAND_TIMED_OUT"))
_REASON_FIELD: Final[str] = "{reason}"
_LOST_AFTER_DISPATCH_PREFIX: Final[str] = _LOST_AFTER_DISPATCH_TEMPLATE.split(_REASON_FIELD)[0]

# Enough slices that a per-slice log cannot be mistaken for a one-off, and few
# enough that the whole exchange stays inside a few seconds.
_IDLE_SLICES: Final[int] = 2
_SLICE_MARGIN_S: Final[float] = 0.5
_GUEST_WORK_S: Final[float] = _POLL_SLICE_S * _IDLE_SLICES + _SLICE_MARGIN_S
_COMMAND_BUDGET_S: Final[float] = _GUEST_WORK_S + 10.0
# A budget the guest is guaranteed to miss, spanning several poll slices first.
_MISSED_BUDGET_S: Final[float] = _POLL_SLICE_S * _IDLE_SLICES + _SLICE_MARGIN_S
_OVERRUN_WORK_S: Final[float] = _MISSED_BUDGET_S + 2.0
_CONNECT_BUDGET_S: Final[float] = 10.0

_COMMAND: Final[str] = "whoami"
_COMMAND_ARGS: Final[tuple[str, ...]] = ("/upn",)
_GUEST_EXIT_CODE: Final[int] = 0
_FAILED_EXIT_CODE: Final[int] = -1

_CAPTURE_LEVEL: Final[str] = "DEBUG"
_LOG_FILENAME: Final[str] = "intellicrack.log"
# Emitted by both the rich renderer structlog prefers and the plain fallback it
# uses when rich is absent, so the check does not depend on which one ran.
_TRACEBACK_MARKER: Final[str] = "Traceback (most recent call last)"
_DISPATCH_EVENT: Final[str] = "guest_send_command_called"
_READ_ERROR_EVENT: Final[str] = "agent_read_error"
_CHANNEL_CLOSED_EVENT: Final[str] = "guest_command_channel_closed_before_result"
_RESULT_TIMEOUT_EVENT: Final[str] = "guest_command_result_timeout"

_LISTEN_BACKLOG: Final[int] = 4
_READ_CHUNK: Final[int] = 4096
_NEWLINE: Final[int] = ord("\n")
# SO_LINGER with a zero timeout: close() then discards the connection with a
# reset instead of a FIN.
_LINGER_RESET: Final[bytes] = struct.pack("ii", 1, 0)
_ONE_RESET: Final[int] = 1
# A zero socket timeout is non-blocking mode, which is what the event loop's
# ``sock_*`` calls require of the sockets they are handed.
_NON_BLOCKING: Final[float] = 0.0


def _completed_guest_work(path: str, args: Sequence[str]) -> GuestCommandResult:
    """Return the outcome of the modelled guest running one command.

    Args:
        path: Command the client asked the guest to run.
        args: Argument list passed with the command.

    Returns:
        GuestCommandResult: A success whose output is the invocation itself, so
        only a reply that really travelled the agent protocol can satisfy the
        caller's assertions.
    """
    return GuestCommandResult(
        exit_code=_GUEST_EXIT_CODE,
        stdout=" ".join([path, *args]),
        stderr="",
    )


def _expected_stdout() -> str:
    """Return the output the modelled guest produces for the test command.

    Returns:
        str: The invocation as the guest echoes it back.
    """
    return _completed_guest_work(_COMMAND, _COMMAND_ARGS).stdout


class _ResettingAgentChannel:
    """Real TCP endpoint that answers the handshake, then resets the channel.

    The guest agent is reached through a QEMU SLIRP ``hostfwd``, and when that
    forwarded connection dies it dies abruptly: the host's next read fails with
    a reset rather than seeing an orderly end of stream. That distinction is
    the whole point here - an end of stream carries no exception, so only a
    reset can show whether the failure that ends a wait keeps its traceback.

    The sockets are driven through the event loop's ``sock_*`` calls rather
    than :func:`asyncio.start_server` because the stream transport shuts a
    socket down before closing it, which sends a FIN and turns the reset back
    into an ordinary end of stream no matter what ``SO_LINGER`` says.

    Exactly one reset is armed. A client that answers the lost channel by
    sending the command again therefore reaches a live endpoint and lands a
    second entry in :attr:`commands`, which is the only way to tell recovery
    from re-execution.

    Attributes:
        port: TCP port the endpoint is listening on, or 0 before ``start``.
        commands: Every command the endpoint took delivery of, in order.
        reset_sent: Set once a connection has actually been reset.
        faults: Exceptions raised while serving, re-raised by :meth:`stop`.
    """

    port: int
    commands: list[str]
    reset_sent: asyncio.Event
    faults: list[BaseException]

    def __init__(self) -> None:
        """Initialise the endpoint without binding it."""
        self.port = 0
        self.commands = []
        self.reset_sent = asyncio.Event()
        self.faults = []
        self._listener: socket.socket | None = None
        self._accept_task: asyncio.Task[None] | None = None
        self._connection_tasks: set[asyncio.Task[None]] = set()
        self._resets_left = _ONE_RESET

    async def start(self) -> int:
        """Bind a loopback port and begin accepting connections.

        Returns:
            int: The claimed TCP port.
        """
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(_LISTEN_BACKLOG)
        listener.settimeout(_NON_BLOCKING)
        self._listener = listener
        self.port = int(listener.getsockname()[1])
        self._accept_task = asyncio.create_task(self._accept_forever(listener))
        return self.port

    async def stop(self) -> None:
        """Close every socket and re-raise anything that failed while serving.

        Raises:
            GuestAgentServerError: If serving a connection raised.
        """
        if self._accept_task is not None:
            self._accept_task.cancel()
            try:
                await self._accept_task
            except asyncio.CancelledError:
                self._accept_task = None
        for task in list(self._connection_tasks):
            task.cancel()
        self._connection_tasks.clear()
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        if self.faults:
            raise GuestAgentServerError(self._fault_report())

    def _fault_report(self) -> str:
        """Summarise every exception raised while serving, for one message.

        Returns:
            str: Endpoint name followed by each recorded exception.
        """
        details = "; ".join(f"{type(fault).__name__}: {fault}" for fault in self.faults)
        return f"{type(self).__name__} failed while serving: {details}"

    async def _accept_forever(self, listener: socket.socket) -> None:
        """Accept connections until cancelled, serving each one.

        Args:
            listener: The bound listening socket.
        """
        loop = asyncio.get_running_loop()
        while True:
            connection, _ = await loop.sock_accept(listener)
            connection.settimeout(_NON_BLOCKING)
            task = asyncio.create_task(self._serve(connection))
            self._connection_tasks.add(task)
            task.add_done_callback(self._connection_tasks.discard)

    async def _serve(self, connection: socket.socket) -> None:
        """Answer requests on one connection, recording anything that fails.

        Args:
            connection: The accepted connection.
        """
        try:
            await self._read_requests(connection)
        except (ConnectionError, asyncio.CancelledError):
            return
        except OSError as fault:
            self.faults.append(fault)
        finally:
            connection.close()

    async def _read_requests(self, connection: socket.socket) -> None:
        """Frame incoming lines on one connection and answer each of them.

        Args:
            connection: The accepted connection.
        """
        loop = asyncio.get_running_loop()
        buffered = bytearray()
        while True:
            chunk: bytes = await loop.sock_recv(connection, _READ_CHUNK)
            if not chunk:
                return
            buffered.extend(chunk)
            while _NEWLINE in buffered:
                end = buffered.index(_NEWLINE)
                line = bytes(buffered[:end])
                del buffered[: end + 1]
                if await self._answer(loop, connection, line):
                    return

    async def _answer(
        self,
        loop: asyncio.AbstractEventLoop,
        connection: socket.socket,
        line: bytes,
    ) -> bool:
        """Handle one received request line.

        Args:
            loop: Running event loop, used for the socket write.
            connection: The connection the line arrived on.
            line: One request line without its trailing newline.

        Returns:
            bool: True when the connection has been reset and must not be read
            from again.
        """
        if not line:
            return False
        request: dict[str, Any] = decode_object(line)
        request_type = str(request.get("type", ""))
        if request_type == AGENT_REQUEST_PING:
            pong = json.dumps({"type": AGENT_MESSAGE_PONG, "data": {}}).encode() + b"\n"
            await loop.sock_sendall(connection, pong)
            return False
        if request_type != AGENT_REQUEST_EXECUTE:
            return False

        self.commands.append(str(request.get("command", "")))
        if self._resets_left <= 0:
            return False
        self._resets_left -= 1
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, _LINGER_RESET)
        connection.close()
        self.reset_sent.set()
        return True


@pytest.fixture
def agent_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Render the guest-agent channel's own log to a file the test can read.

    The rendering matters as much as the events: ``exc_info`` only becomes the
    traceback block seen in live logs once the production ``ConsoleRenderer``
    formats it, so the file written here is the artifact under test rather than
    a stand-in for it.

    The module's logger is rebound because structlog caches a bound logger on
    first use and never revisits that decision, so a module already used under
    an earlier test's configuration would keep writing there. The replacement
    is the same production factory's output under the same name, so what the
    file records is still what the module logs.

    Args:
        tmp_path: Per-test directory the log is written into.
        monkeypatch: Fixture used to rebind the module logger for the test.

    Yields:
        Path: The log file the production pipeline writes to.
    """
    log_dir = tmp_path / "logs"
    IntellicrackLogger.configure(
        level=_CAPTURE_LEVEL,
        log_dir=log_dir,
        file_enabled=True,
        console_enabled=False,
        json_file=False,
    )
    monkeypatch.setattr(qemu_module, "_logger", get_logger(qemu_module.__name__))
    try:
        yield log_dir / _LOG_FILENAME
    finally:
        root_logger = get_stdlib_root_logger()
        for handler in list(root_logger.handlers):
            root_logger.removeHandler(handler)
            handler.close()


def _read_log(log_file: Path) -> str:
    """Read back everything the production pipeline rendered for the test.

    Args:
        log_file: The log file the pipeline wrote to.

    Returns:
        str: The rendered log, including any traceback blocks.
    """
    assert log_file.exists(), "the logging pipeline wrote no file, so nothing was observed"
    text = log_file.read_text(encoding="utf-8")
    assert _DISPATCH_EVENT in text, (
        f"the log holds no {_DISPATCH_EVENT!r} record, so the channel under test was not writing to this file "
        "and any absence of a traceback in it proves nothing"
    )
    return text


@pytest.mark.asyncio
class TestAnIdlePollSliceIsNotAnIncident:
    """Waiting out a working guest must read as a quiet wait."""

    async def test_a_command_the_guest_takes_time_over_leaves_no_traceback(self, agent_log: Path) -> None:
        """A slow but successful command must not render a single traceback.

        Args:
            agent_log: File the production logging pipeline renders into.
        """
        server = IntellicrackAgentServer(responder=_completed_guest_work, reply_delay=_GUEST_WORK_S)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            assert await client.connect(time_limit=_CONNECT_BUDGET_S), "the agent server refused the channel"
            started = time.monotonic()
            exit_code, stdout, stderr = await client.send_command(
                _COMMAND,
                args=_COMMAND_ARGS,
                time_limit=_COMMAND_BUDGET_S,
            )
            waited = time.monotonic() - started
        finally:
            await client.disconnect()
            await server.stop()

        assert (exit_code, stdout, stderr) == (_GUEST_EXIT_CODE, _expected_stdout(), ""), (
            f"the guest's reply did not reach the caller intact: {(exit_code, stdout, stderr)!r}"
        )
        assert waited >= _POLL_SLICE_S * _IDLE_SLICES, (
            f"the reply came back after {waited:.2f}s, short of {_IDLE_SLICES} poll slices "
            f"of {_POLL_SLICE_S}s, so no idle slice was ever spent and this proves nothing"
        )

        text = _read_log(agent_log)
        assert _TRACEBACK_MARKER not in text, (
            f"a command the guest merely took {waited:.2f}s over rendered a traceback into the log:\n"
            f"{text[text.index(_TRACEBACK_MARKER) - 200 : text.index(_TRACEBACK_MARKER) + 600]}"
        )

    async def test_the_channel_closing_under_a_wait_keeps_its_traceback(self, agent_log: Path) -> None:
        """A reset channel must still be reported, exception and all.

        Args:
            agent_log: File the production logging pipeline renders into.
        """
        channel = _ResettingAgentChannel()
        await channel.start()
        client = GuestAgentClient(port=channel.port)
        try:
            assert await client.connect(time_limit=_CONNECT_BUDGET_S), "the agent endpoint refused the channel"
            exit_code, _, stderr = await client.send_command(
                _COMMAND,
                args=_COMMAND_ARGS,
                time_limit=_COMMAND_BUDGET_S,
            )
        finally:
            await client.disconnect()
            await channel.stop()

        assert channel.reset_sent.is_set(), "the endpoint never reset the channel, so no genuine failure was staged"
        assert channel.commands == [_COMMAND], (
            f"the command reached the guest {len(channel.commands)} times; a dispatched command is never re-sent"
        )
        assert exit_code == _FAILED_EXIT_CODE, f"a command lost with the channel reported exit code {exit_code}"
        assert stderr.startswith(_LOST_AFTER_DISPATCH_PREFIX), f"the caller was not told the channel was lost: {stderr!r}"

        text = _read_log(agent_log)
        assert _READ_ERROR_EVENT in text, "the read failure that killed the channel was not reported at all"
        assert _TRACEBACK_MARKER in text, (
            "the exception that ended the channel was reported without its traceback, so quietening the routine poll went too far"
        )
        assert _CHANNEL_CLOSED_EVENT in text, "the wait ended against a dead channel without saying so"

    async def test_a_guest_that_misses_its_deadline_is_reported(self, agent_log: Path) -> None:
        """A command the guest never answers in time must be reported, quietly.

        The channel is healthy throughout and no exception is raised, so this
        failure has no traceback to keep - what it must have is a record.

        Args:
            agent_log: File the production logging pipeline renders into.
        """
        server = IntellicrackAgentServer(responder=_completed_guest_work, reply_delay=_OVERRUN_WORK_S)
        await server.start()
        client = GuestAgentClient(port=server.port)
        try:
            assert await client.connect(time_limit=_CONNECT_BUDGET_S), "the agent server refused the channel"
            started = time.monotonic()
            exit_code, _, stderr = await client.send_command(
                _COMMAND,
                args=_COMMAND_ARGS,
                time_limit=_MISSED_BUDGET_S,
            )
            waited = time.monotonic() - started
        finally:
            await client.disconnect()
            await server.stop()

        assert waited >= _MISSED_BUDGET_S, f"the wait returned after {waited:.2f}s, before its own {_MISSED_BUDGET_S}s budget"
        assert exit_code == _FAILED_EXIT_CODE, f"an unanswered command reported exit code {exit_code}"
        assert stderr == _COMMAND_TIMED_OUT, f"the caller was not told the command timed out: {stderr!r}"

        text = _read_log(agent_log)
        assert _RESULT_TIMEOUT_EVENT in text, "a wait that ran out of budget left no record of having done so"
        assert _TRACEBACK_MARKER not in text, "a missed deadline raised nothing, so it must not render a traceback"
