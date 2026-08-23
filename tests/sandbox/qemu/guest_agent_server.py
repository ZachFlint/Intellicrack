# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real TCP servers speaking QEMU's QMP and qemu-guest-agent wire protocols.

These are genuine asyncio servers bound to loopback, not mocks: the client
under test opens a real socket, writes real JSON lines and parses real
replies. They are shared by every QEMU guest-agent gate so the protocol
fidelity lives in exactly one place.

The guest-agent server reproduces the parts of ``qga/main.c`` that a client
has to survive:

* the reply to ``guest-sync-delimited`` carries the leading ``0xFF`` sentinel
  byte that ``send_response`` inserts while ``delimit_response`` is set, and no
  other reply carries it;
* a freshly attached client can find whatever a previous client left in the
  output stream - a complete but stale delimiter reply and a partial object cut
  off mid-write - ahead of that sentinel;
* qemu-guest-agent emits no asynchronous events at all, so nothing
  event-shaped is ever written;
* the agent's own parser reset is honoured on the inbound half: everything up
  to and including a ``0xFF`` byte is discarded.

:class:`GuestAgentProtocolServer` accepts an optional ``responder`` which turns
it into a model of a guest filesystem: the responder decides the exit code and
captured output of every ``guest-exec`` it receives, and the server keeps those
results addressable by the guest pid it allocated, exactly as
``guest-exec-status`` does on a live agent.

:class:`IntellicrackAgentServer` is the second in-guest endpoint: the monitor
agent the sandbox stages into the share, which listens on its own TCP port and
answers the ``execute``/``result`` messages
:class:`intellicrack.sandbox.qemu.GuestAgentClient` speaks. It takes the same
kind of ``responder``, so one guest model can answer both channels.

Failures inside a connection handler are recorded and re-raised by
:meth:`_LoopbackServer.stop`, so a broken server fails its test loudly instead
of degrading into a client-side timeout.
"""

from __future__ import annotations

import asyncio
import base64
import json
import socket
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from intellicrack.sandbox.qemu import GuestAgentClient


if TYPE_CHECKING:
    from collections.abc import Sequence

FLUSH_BYTE: Final[bytes] = b"\xff"
STALE_DELIMITER_ID: Final[int] = 987654321

# Both sync commands a real agent may expose. Captured from qemu-guest-agent
# 10.0.11's own guest-info command table on a live Debian 13 guest: the names are
# "guest-sync-delimited" and "guest-sync", and only the delimited form prefixes
# its reply with the parser reset marker.
SYNC_DELIMITED_COMMAND: Final[str] = "guest-sync-delimited"
SYNC_PLAIN_COMMAND: Final[str] = "guest-sync"
SYNC_COMMANDS: Final[frozenset[str]] = frozenset({SYNC_DELIMITED_COMMAND, SYNC_PLAIN_COMMAND})
STALE_PARTIAL_LINE: Final[bytes] = b'{"return": {"pid": 31'
# First handle handed out by guest-file-open. Non-zero so a client that treats
# a falsy handle as "no handle" is not accidentally satisfied by the first one.
_FIRST_GUEST_FILE_HANDLE: Final[int] = 1000
DEFAULT_GUEST_EXEC_PID: Final[int] = 3131
DEFAULT_GUEST_STDOUT: Final[str] = "monitor agent started\n"
DEFAULT_GUEST_STDERR: Final[str] = "warning: 9p not present\n"
# A complete line - it ends in a newline - whose payload is not valid UTF-8:
# 0xFF and 0xFE cannot begin a UTF-8 sequence.
UNDECODABLE_LINE: Final[bytes] = b'{"type": "result", "data": {"stdout": "\xff\xfe"}}\n'

# The readiness handshake this in-guest agent answers is taken from the module
# that generates the real agent scripts, never restated here: a rename in
# production has to move this server with it rather than leave a double that
# still answers a word the guest no longer speaks.
AGENT_REQUEST_PING: Final[str] = GuestAgentClient.PING_REQUEST_TYPE
AGENT_MESSAGE_PONG: Final[str] = GuestAgentClient.PONG_MESSAGE_TYPE
AGENT_REQUEST_EXECUTE: Final[str] = "execute"
AGENT_MESSAGE_RESULT: Final[str] = "result"


class GuestAgentServerError(AssertionError):
    """Raised when a protocol server's connection handler failed.

    The servers here are quality gates: a fault inside one must surface as a
    loud test failure, never as a client-side timeout that reads like a
    production defect.
    """


def free_port() -> int:
    """Return an OS-assigned free TCP port by binding then releasing it.

    Returns:
        int: A free localhost TCP port number.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def decode_object(raw: bytes) -> dict[str, Any]:
    """Decode one JSON line into a mapping.

    Args:
        raw: Raw JSON bytes without the trailing newline.

    Returns:
        dict[str, Any]: Decoded mapping, or an empty mapping when the payload
        is not a JSON object.
    """
    decoded: object = json.loads(raw.decode())
    if not isinstance(decoded, dict):
        return {}
    return cast("dict[str, Any]", decoded)


def guest_file_error(description: str) -> dict[str, Any]:
    """Build the error a live guest agent returns for a refused file command.

    Args:
        description: Human-readable reason, as the agent's ``desc`` member.

    Returns:
        dict[str, Any]: QMP error envelope with the agent's own error class.
    """
    return {"error": {"class": "GenericError", "desc": description}}


def command_not_found(name: str) -> dict[str, Any]:
    """Build the exact error QEMU returns for an unknown monitor command.

    Args:
        name: Command name that was rejected.

    Returns:
        dict[str, Any]: QMP error envelope.
    """
    return {
        "error": {
            "class": "CommandNotFound",
            "desc": f"The command {name} has not been found",
        },
    }


@dataclass(frozen=True)
class GuestCommandResult:
    """Outcome a modelled guest returns for one executed command.

    Attributes:
        exit_code: Process exit status.
        stdout: Text the process wrote to standard output.
        stderr: Text the process wrote to standard error.
        stdout_truncated: Whether the agent's stdout capture buffer overflowed
            and the reply must carry ``out-truncated``.
        stderr_truncated: Whether the agent's stderr capture buffer overflowed
            and the reply must carry ``err-truncated``.
    """

    exit_code: int = 0
    stdout: str = DEFAULT_GUEST_STDOUT
    stderr: str = DEFAULT_GUEST_STDERR
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class GuestExecRecord:
    """One ``guest-exec`` request as the agent server received it.

    Attributes:
        pid: Guest pid the server allocated for the invocation.
        path: Executable the client asked the guest to run.
        args: Argument list passed with the executable.
        capture_output: Whether the client asked for buffered output.
    """

    pid: int
    path: str
    args: tuple[str, ...]
    capture_output: bool

    def command_line(self) -> str:
        """Return the invocation as a single whitespace-joined string.

        Returns:
            str: ``path`` followed by every argument.
        """
        return " ".join([self.path, *self.args])


class GuestCommandResponder(Protocol):
    """Callable deciding how a modelled guest answers one command."""

    def __call__(self, path: str, args: Sequence[str]) -> GuestCommandResult:
        """Return the guest-side outcome of running ``path`` with ``args``.

        Args:
            path: Executable the client asked the guest to run.
            args: Argument list passed with the executable.

        Returns:
            GuestCommandResult: Exit status and captured output.
        """
        ...


class _LoopbackServer:
    """Shared lifecycle for an asyncio server bound to an ephemeral port.

    :meth:`start` normally binds and listens in one step. When a listen delay
    is configured the ephemeral port is allocated and released instead, so
    connections to it are refused with a reset until the delay elapses and the
    server binds it again - what a host sees while the peer it expects has not
    come up yet.

    Attributes:
        port: TCP port the server is bound to, or 0 before ``start``.
        faults: Exceptions raised by connection handlers, re-raised by
            :meth:`stop`.
        accepted: Number of connections accepted since ``start``, counted for
            every server so a test can tell a channel that was closed and
            replaced from one that was merely kept open.
    """

    port: int
    faults: list[BaseException]
    accepted: int

    def __init__(self, listen_delay: float = 0.0, port: int = 0) -> None:
        """Initialise the server without binding it.

        Args:
            listen_delay: Seconds to wait after :meth:`start` before the server
                binds its port and listens. Connections are refused until then.
            port: TCP port to claim, or 0 to let the OS pick a free one. A
                fixed port is needed when the sandbox derives one endpoint's
                port from another's, as it does for the guest-agent channel.
        """
        self.port = port
        self.faults = []
        self.accepted = 0
        self._listen_delay = listen_delay
        self._socket: socket.socket | None = None
        self._server: asyncio.Server | None = None
        self._listen_task: asyncio.Task[None] | None = None

    async def start(self) -> int:
        """Claim the configured loopback port and begin (or schedule) listening.

        Returns:
            int: The claimed TCP port.

        Raises:
            OSError: If a fixed port was requested and is already in use.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", self.port))
        except OSError:
            sock.close()
            raise
        self.port = int(sock.getsockname()[1])
        if self._listen_delay <= 0.0:
            self._socket = sock
            await self._listen()
        else:
            sock.close()
            self._listen_task = asyncio.create_task(self._listen_after_delay())
        return self.port

    async def stop(self) -> None:
        """Close the listening socket and re-raise any recorded fault.

        Raises:
            GuestAgentServerError: If a connection handler failed while the
                server was up.
        """
        await self._cancel_pending_listen()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        elif self._socket is not None:
            self._socket.close()
        self._socket = None
        if self.faults:
            raise GuestAgentServerError(self._fault_report())

    async def _listen(self) -> None:
        """Start accepting connections on the server's port."""
        if self._socket is not None:
            self._server = await asyncio.start_server(self._handle, sock=self._socket)
            return
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)

    async def _listen_after_delay(self) -> None:
        """Wait out the configured delay, then start accepting connections."""
        await asyncio.sleep(self._listen_delay)
        await self._listen()

    async def _cancel_pending_listen(self) -> None:
        """Cancel a scheduled deferred listen, if one is still outstanding."""
        if self._listen_task is None:
            return
        self._listen_task.cancel()
        try:
            await self._listen_task
        except asyncio.CancelledError:
            self._listen_task = None
        self._listen_task = None

    def _fault_report(self) -> str:
        """Summarise every recorded handler exception for one failure message.

        Returns:
            str: Server name followed by each recorded exception.
        """
        details = "; ".join(f"{type(fault).__name__}: {fault}" for fault in self.faults)
        return f"{type(self).__name__} connection handler failed: {details}"

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Serve one accepted connection, recording any fault it raises.

        A peer that closes its socket mid-exchange is normal client behaviour
        and is not recorded; anything else is a defect in this harness and is
        both re-raised here and replayed by :meth:`stop`.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.

        Raises:
            Exception: Re-raised after being recorded, so the failure is also
                visible on the event loop.
        """
        self.accepted += 1
        try:
            await self._serve(reader, writer)
        except ConnectionError:
            return
        except Exception as fault:
            self.faults.append(fault)
            raise
        finally:
            await self._close_writer(writer)

    @staticmethod
    async def _close_writer(writer: asyncio.StreamWriter) -> None:
        """Close one connection, tolerating a peer that already vanished.

        Args:
            writer: Stream writer for the accepted connection.
        """
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            return

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle one connection; overridden by each protocol server.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.

        Raises:
            NotImplementedError: Always; subclasses must provide the protocol.
        """
        raise NotImplementedError


class QmpProtocolServer(_LoopbackServer):
    """Real TCP server speaking the QMP monitor protocol.

    Performs the greeting + ``qmp_capabilities`` handshake, answers
    ``query-status``, ``system_powerdown`` and ``quit``, and rejects any
    ``guest-*`` command the way QEMU's monitor does.

    ``system_powerdown`` and ``quit`` both answer ``{"return": {}}`` on a live
    monitor, so neither reply says anything about what became of the guest -
    the first presses the virtual ACPI power button and returns immediately,
    and only the process exiting shows whether the guest obeyed. The two
    events published here let a test wire that consequence up to a real
    process.

    Attributes:
        commands: Every ``execute`` name received, in arrival order.
        powerdown_requested: Set when ``system_powerdown`` arrives.
        quit_requested: Set when ``quit`` arrives.
    """

    commands: list[str]
    powerdown_requested: asyncio.Event
    quit_requested: asyncio.Event

    def __init__(self) -> None:
        """Initialise the server with an empty command log."""
        super().__init__()
        self.commands = []
        self.powerdown_requested = asyncio.Event()
        self.quit_requested = asyncio.Event()

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Send the greeting and answer requests until the client goes away.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        greeting: dict[str, Any] = {
            "QMP": {
                "version": {"qemu": {"major": 9, "minor": 2, "micro": 0}},
                "capabilities": [],
            },
        }
        writer.write(json.dumps(greeting).encode() + b"\n")
        await writer.drain()
        while True:
            line = await reader.readline()
            if not line:
                return
            writer.write(json.dumps(self._reply_for(line)).encode() + b"\n")
            await writer.drain()

    def _reply_for(self, line: bytes) -> dict[str, Any]:
        """Compute the QMP reply for one received command line.

        A real monitor echoes the request's optional ``id`` member verbatim on
        the reply and never puts one on an event - measured against QEMU
        10.1.0, ``{"execute":"qmp_capabilities","id":"cap"}`` comes back as
        ``{"return": {}, "id": "cap"}``. That echo is how the client tells its
        own answer from an asynchronous event, so this server reproduces it.

        Args:
            line: Raw newline-terminated request bytes.

        Returns:
            dict[str, Any]: Reply envelope to send back.
        """
        request = decode_object(line.strip())
        name = str(request.get("execute", ""))
        self.commands.append(name)
        reply = self._result_for(name)
        request_id = request.get("id")
        if request_id is not None:
            reply["id"] = request_id
        return reply

    def _result_for(self, name: str) -> dict[str, Any]:
        """Build the ``return``/``error`` body for one command name.

        Args:
            name: The ``execute`` member of the request.

        Returns:
            dict[str, Any]: Reply body without the correlation id.
        """
        if name == "qmp_capabilities":
            return {"return": {}}
        if name == "query-status":
            return {"return": {"status": "running", "running": True, "singlestep": False}}
        if name == "system_powerdown":
            self.powerdown_requested.set()
            return {"return": {}}
        if name == "quit":
            self.quit_requested.set()
            return {"return": {}}
        return command_not_found(name)


class GuestAgentProtocolServer(_LoopbackServer):
    """Real TCP server speaking the qemu-guest-agent protocol.

    Sends no greeting, negotiates no capabilities and emits no asynchronous
    events - a live qemu-guest-agent has none. What a newly attached client
    does find in the stream is the wreckage of the previous one: a complete
    delimiter reply it never read, followed by an object cut off mid-write.
    Both sit ahead of the ``0xFF`` sentinel that ``send_response`` prepends to
    the ``guest-sync-delimited`` reply, which is the only marker a client can
    use to re-frame the stream. Incoming bytes up to and including any ``0xFF``
    parser-flush marker are discarded, mirroring the agent's own parser reset.

    When a ``responder`` is supplied the server behaves as a model of a guest
    filesystem: every ``guest-exec`` is handed to the responder, the returned
    exit code and output are stored against a freshly allocated guest pid, and
    ``guest-exec-status`` replays them with base64-encoded streams - but only
    once the process is reported exited, and only when the ``guest-exec`` that
    started it asked for ``capture-output``. Both conditions are what a live
    agent enforces, and both are configurable so a client that ignores either
    can be caught.

    The same model carries the agent's file commands. ``guest-file-open`` in a
    write mode allocates a handle and an empty file, ``guest-file-write``
    appends the decoded ``buf-b64`` payload to it and answers with the byte
    count a live agent reports, and ``guest-file-close`` releases the handle.
    The resulting bytes are readable through :attr:`guest_files`, so a test can
    assert that what arrived inside the guest is exactly what left the host.

    Reading works the same way in the other direction. ``guest-file-open`` in a
    read mode refuses a path the guest does not have, and ``guest-file-read``
    returns at most ``count`` bytes from the current offset with the ``eof``
    flag a live agent sets once the offset reaches the end - so a host that
    stops at the first short read, or that never advances, is caught.

    ``guest-shutdown`` is answered with silence, because a live agent is
    already powering the guest off when the reply would have been written. The
    request is still recorded and :attr:`shutdown_requested` is set, so a test
    can wire the consequence - QEMU exiting - to a real process.

    Attributes:
        received: Every raw byte received from the client.
        commands: Every ``execute`` name received, in arrival order.
        sync_ids: Delimiter ids echoed back to the client.
        exec_arguments: ``arguments`` payload of every ``guest-exec``.
        exec_records: Structured record of every ``guest-exec``.
        exec_status_pids: Process ids queried through ``guest-exec-status``.
        guest_files: In-guest path to the bytes written there, in write order.
        file_writes: One entry per ``guest-file-write``, giving the in-guest
            path and the size of that buffer, so chunking is observable.
        file_reads: One entry per ``guest-file-read``, giving the in-guest path
            and the size of the buffer returned, so a host that never reaches
            the end of a file is observable too.
        shutdown_modes: ``mode`` argument of every ``guest-shutdown``.
        shutdown_requested: Set when the first ``guest-shutdown`` arrives.
        exec_answered: Set once a ``guest-exec`` reply has been produced, which
            is the only observable a test has for an agent coming out of a
            stall - the client that gave up waiting for it sees nothing.
        resident_commands: Executables whose process outlives the request that
            started it, so this guest never reaps it.
    """

    received: bytearray
    commands: list[str]
    sync_ids: list[int]
    exec_arguments: list[dict[str, Any]]
    exec_records: list[GuestExecRecord]
    exec_status_pids: list[int]
    guest_files: dict[str, bytearray]
    file_writes: list[tuple[str, int]]
    file_reads: list[tuple[str, int]]
    shutdown_modes: list[str]
    shutdown_requested: asyncio.Event
    exec_answered: asyncio.Event
    resident_commands: frozenset[str]

    def __init__(
        self,
        responder: GuestCommandResponder | None = None,
        base_pid: int = DEFAULT_GUEST_EXEC_PID,
        *,
        listen_delay: float = 0.0,
        stall_command: str | None = None,
        stall_seconds: float = 0.0,
        status_polls_before_exit: int = 0,
        unsupported_commands: frozenset[str] = frozenset(),
        silent_commands: frozenset[str] = frozenset(),
        resident_commands: frozenset[str] = frozenset(),
    ) -> None:
        """Initialise the server with empty recording buffers.

        Args:
            responder: Guest model deciding the outcome of each executed
                command. When omitted every command succeeds with the default
                captured output.
            base_pid: Guest pid allocated to the first ``guest-exec``;
                successive invocations increment from it.
            listen_delay: Seconds the bound port refuses connections before the
                agent starts listening, modelling a guest that has not booted.
            stall_command: Command whose first reply is held back, modelling an
                agent that answers only after the client has given up waiting.
            stall_seconds: How long that first reply is held back. The stall
                blocks the whole connection, so the late reply still reaches
                the client ahead of any reply written after it.
            status_polls_before_exit: How many ``guest-exec-status`` queries
                per pid report the process as still running before it is
                reported exited. A live agent answers ``{"exited": false}``
                and nothing else while the process is alive.
            unsupported_commands: Commands this agent build does not implement
                and answers with ``CommandNotFound``. Agent builds differ in
                which commands they carry - the sync pair and the file commands
                both vary - so a client cannot assume the one it prefers exists.
            silent_commands: Commands this agent accepts and never answers,
                without holding up anything else on the connection. A refusal
                costs a client nothing and a silence costs it a whole deadline,
                so a client that budgets as though every command it sends will
                be answered one way or the other is only caught by this.
            resident_commands: Executables whose process outlives the request
                that started it. A live agent never reaps such a child, so it
                answers ``{"exited": false}`` for its pid for as long as the
                guest runs, whatever the responder said the outcome would be.
        """
        super().__init__(listen_delay=listen_delay)
        self.unsupported_commands = unsupported_commands
        self.silent_commands = silent_commands
        self.received = bytearray()
        self.commands = []
        self.sync_ids = []
        self.exec_arguments = []
        self.exec_records = []
        self.exec_status_pids = []
        self.guest_files = {}
        self.file_writes = []
        self.file_reads = []
        self.shutdown_modes = []
        self.shutdown_requested = asyncio.Event()
        self.exec_answered = asyncio.Event()
        self._open_files: dict[int, str] = {}
        self._read_offsets: dict[int, int] = {}
        self._next_file_handle: int = _FIRST_GUEST_FILE_HANDLE
        self._responder = responder
        self._base_pid = base_pid
        self._stall_command = stall_command
        self._stall_seconds = stall_seconds
        self._stalled = False
        self._status_polls_before_exit = status_polls_before_exit
        self.resident_commands = resident_commands
        self._results: dict[int, GuestCommandResult] = {}
        self._records_by_pid: dict[int, GuestExecRecord] = {}
        self._status_polls: dict[int, int] = {}

    def command_lines(self) -> list[str]:
        """Return every executed command as a whitespace-joined string.

        Returns:
            list[str]: One entry per ``guest-exec``, in arrival order.
        """
        return [record.command_line() for record in self.exec_records]

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Emit the previous client's leftovers, then answer agent requests.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        writer.write(self._frame({"return": STALE_DELIMITER_ID}))
        writer.write(STALE_PARTIAL_LINE)
        await writer.drain()

        buffer = bytearray()
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                return
            self.received.extend(chunk)
            buffer.extend(chunk)
            buffer = self._flush_parser(buffer)
            await self._answer_lines(self._take_lines(buffer), writer)

    async def _answer_lines(self, lines: list[bytes], writer: asyncio.StreamWriter) -> None:
        """Write the replies for a batch of complete request lines.

        Args:
            lines: Complete request lines without their newline.
            writer: Stream writer for the accepted connection.
        """
        for line in lines:
            for frame in await self._replies_for(line):
                writer.write(frame)
            await writer.drain()

    @staticmethod
    def _frame(payload: dict[str, Any], *, sentinel: bool = False) -> bytes:
        """Serialise one reply the way ``qga/main.c`` send_response writes it.

        Args:
            payload: Reply envelope to serialise.
            sentinel: Whether the ``0xFF`` byte that follows a
                ``guest-sync-delimited`` request must lead the line.

        Returns:
            bytes: Complete newline-terminated wire frame.
        """
        prefix = FLUSH_BYTE if sentinel else b""
        return prefix + json.dumps(payload).encode() + b"\n"

    @staticmethod
    def _flush_parser(buffer: bytearray) -> bytearray:
        """Drop everything up to and including the last parser-flush marker.

        Args:
            buffer: Accumulated inbound bytes.

        Returns:
            bytearray: Buffer with any pre-flush junk removed.
        """
        marker = buffer.rfind(FLUSH_BYTE)
        if marker < 0:
            return buffer
        return bytearray(buffer[marker + 1 :])

    @staticmethod
    def _take_lines(buffer: bytearray) -> list[bytes]:
        """Split complete newline-terminated requests out of ``buffer``.

        Args:
            buffer: Accumulated inbound bytes; mutated in place so only the
                trailing partial request remains.

        Returns:
            list[bytes]: Complete request lines, without their newline.
        """
        lines: list[bytes] = []
        while b"\n" in buffer:
            line, _, rest = buffer.partition(b"\n")
            lines.append(bytes(line))
            buffer[:] = rest
        return lines

    async def _replies_for(self, line: bytes) -> list[bytes]:
        """Compute the guest-agent wire frames for one received request line.

        Args:
            line: Raw request bytes without the trailing newline.

        Returns:
            list[bytes]: Wire frames to write back, in order.
        """
        stripped = line.strip()
        if not stripped:
            return []
        request = decode_object(stripped)
        name = str(request.get("execute", ""))
        self.commands.append(name)
        arguments = request.get("arguments")
        args_map: dict[str, Any] = cast("dict[str, Any]", arguments) if isinstance(arguments, dict) else {}
        await self._apply_stall(name)

        # Any command can be absent from a given agent build, not only the sync
        # pair, so the refusal is decided before dispatch rather than inside one
        # branch of it.
        if name in self.unsupported_commands:
            return [self._frame(command_not_found(name))]

        # Silence is not refusal. An agent build can carry a command, accept it,
        # and never produce the reply - and unlike a refusal that costs the
        # client nothing, silence costs it whatever deadline it set. Answering
        # nothing without blocking the connection is what separates the two.
        if name in self.silent_commands:
            return []

        if name in SYNC_COMMANDS:
            sync_id = int(args_map.get("id", 0))
            self.sync_ids.append(sync_id)
            # Only the delimited form prefixes its reply with the reset marker;
            # plain guest-sync echoes the id unadorned. Verified on qemu-ga 10.0.11.
            return [self._frame({"return": sync_id}, sentinel=name == SYNC_DELIMITED_COMMAND)]
        if name == "guest-ping":
            return [self._frame({"return": {}})]
        if name == "guest-shutdown":
            # A live agent writes nothing back: it is already powering the guest
            # off when the reply would have been produced.
            self.shutdown_modes.append(str(args_map.get("mode", "")))
            self.shutdown_requested.set()
            return []
        if name == "guest-exec":
            return [self._frame({"return": {"pid": self._record_exec(args_map)}})]
        if name == "guest-exec-status":
            return [self._frame({"return": self._exec_status(int(args_map.get("pid", 0)))})]
        if name == "guest-file-open":
            return [self._frame(self._open_guest_file(args_map))]
        if name == "guest-file-write":
            return [self._frame({"return": self._write_guest_file(args_map)})]
        if name == "guest-file-read":
            return [self._frame(self._read_guest_file(args_map))]
        if name == "guest-file-close":
            handle = int(args_map.get("handle", 0))
            self._open_files.pop(handle, None)
            self._read_offsets.pop(handle, None)
            return [self._frame({"return": {}})]
        return [self._frame(command_not_found(name))]

    def _open_guest_file(self, args_map: dict[str, Any]) -> dict[str, Any]:
        """Answer one ``guest-file-open`` the way a live agent answers it.

        A write mode creates the file and truncates whatever was there; a read
        mode does neither and fails outright when the path does not exist,
        which is how the agent reports a log a collector never produced.

        Args:
            args_map: ``arguments`` payload of the request.

        Returns:
            dict[str, Any]: Envelope carrying the handle, or the agent's error
            for a file that could not be opened.
        """
        path = str(args_map.get("path", ""))
        mode = str(args_map.get("mode", "r"))
        reading = "r" in mode and "+" not in mode
        if reading and path not in self.guest_files:
            return guest_file_error(f"failed to open file '{path}', error: No such file or directory")
        handle = self._next_file_handle
        self._next_file_handle += 1
        self._open_files[handle] = path
        if reading:
            self._read_offsets[handle] = 0
        else:
            self.guest_files[path] = bytearray()
        return {"return": handle}

    def _read_guest_file(self, args_map: dict[str, Any]) -> dict[str, Any]:
        """Answer one ``guest-file-read`` from the modelled guest's bytes.

        Args:
            args_map: ``arguments`` payload of the request.

        Returns:
            dict[str, Any]: Envelope carrying the agent's ``count``/``buf-b64``
            /``eof`` payload, or its error for a handle never opened to read.
        """
        handle = int(args_map.get("handle", 0))
        if handle not in self._read_offsets:
            return guest_file_error(f"handle {handle} is not open for reading")
        path = self._open_files.get(handle, "")
        content = self.guest_files.get(path, bytearray())
        offset = self._read_offsets[handle]
        count = int(args_map.get("count", 0))
        chunk = bytes(content[offset : offset + count])
        self._read_offsets[handle] = offset + len(chunk)
        self.file_reads.append((path, len(chunk)))
        return {
            "return": {
                "count": len(chunk),
                "buf-b64": base64.b64encode(chunk).decode(),
                "eof": self._read_offsets[handle] >= len(content),
            },
        }

    def _write_guest_file(self, args_map: dict[str, Any]) -> dict[str, Any]:
        """Append one ``guest-file-write`` buffer to its open file.

        Args:
            args_map: ``arguments`` payload of the request.

        Returns:
            dict[str, Any]: The ``count``/``eof`` payload a live agent returns.
        """
        handle = int(args_map.get("handle", 0))
        path = self._open_files.get(handle, "")
        payload = base64.b64decode(str(args_map.get("buf-b64", "")))
        self.guest_files.setdefault(path, bytearray()).extend(payload)
        self.file_writes.append((path, len(payload)))
        return {"count": len(payload), "eof": False}

    async def _apply_stall(self, name: str) -> None:
        """Hold back the first reply to the configured stalled command.

        Args:
            name: ``execute`` name of the request being answered.
        """
        if self._stalled or name != self._stall_command:
            return
        self._stalled = True
        await asyncio.sleep(self._stall_seconds)

    def _record_exec(self, args_map: dict[str, Any]) -> int:
        """Run one ``guest-exec`` against the guest model and record it.

        Args:
            args_map: ``arguments`` payload of the ``guest-exec`` request.

        Returns:
            int: Guest pid allocated for the invocation.
        """
        self.exec_arguments.append(args_map)
        path = str(args_map.get("path", ""))
        raw_args: Any = args_map.get("arg")
        args = [str(item) for item in cast("list[Any]", raw_args)] if isinstance(raw_args, list) else []
        pid = self._base_pid + len(self.exec_records)
        record = GuestExecRecord(
            pid=pid,
            path=path,
            args=tuple(args),
            capture_output=bool(args_map.get("capture-output")),
        )
        self.exec_records.append(record)
        self._records_by_pid[pid] = record
        self._results[pid] = GuestCommandResult() if self._responder is None else self._responder(path, args)
        self.exec_answered.set()
        return pid

    def _exec_status(self, pid: int) -> dict[str, Any]:
        """Build the ``guest-exec-status`` return payload for one pid.

        A process that has not finished yet is reported as ``{"exited": false}``
        with no exit code and no captured output, because a live agent has none
        to report until it reaps the child - and a resident child, one that runs
        for as long as the guest does, is never reaped at all. Once it has
        exited, the captured
        streams appear only when the ``guest-exec`` that started it asked for
        ``capture-output``: without that flag the agent inherits the guest's own
        handles and buffers nothing. The truncation members are optional in the
        QGA schema and a live agent omits them unless its capture buffer
        actually overflowed.

        Args:
            pid: Guest pid the client asked about.

        Returns:
            dict[str, Any]: Status payload with base64-encoded output streams.
        """
        self.exec_status_pids.append(pid)
        polls = self._status_polls.get(pid, 0)
        self._status_polls[pid] = polls + 1
        record = self._records_by_pid.get(pid)
        if polls < self._status_polls_before_exit or (record is not None and record.path in self.resident_commands):
            return {"exited": False}

        result = self._results.get(pid, GuestCommandResult())
        payload: dict[str, Any] = {"exited": True, "exitcode": result.exit_code}
        if record is not None and not record.capture_output:
            return payload

        payload["out-data"] = base64.b64encode(result.stdout.encode()).decode()
        payload["err-data"] = base64.b64encode(result.stderr.encode()).decode()
        if result.stdout_truncated:
            payload["out-truncated"] = True
        if result.stderr_truncated:
            payload["err-truncated"] = True
        return payload


class OneShotGuestAgentChannelServer(GuestAgentProtocolServer):
    """Real server modelling QEMU's guest-agent chardev socket.

    ``-chardev socket,...,server,nowait`` is handed out **once**. QEMU accepts
    a single connection and refuses every later one with a reset for the whole
    life of the VM. Measured against QEMU 10.1.0 on Windows: with the app's
    channel closed and reopened, an independent client outside the application
    was refused three times in a row while ``Get-NetTCPConnection`` still
    showed the QEMU process listening on that port with no peer attached.

    The channel and the guest are modelled separately, because they fail for
    unrelated reasons. The channel is up from the moment QEMU binds it. The
    guest's agent is not: for the first ``silent_syncs`` resync requests this
    server writes nothing back, which is exactly what a host sees while the
    guest is still booting and no process inside it is reading the
    virtio-serial port yet.

    Attributes:
        refused_syncs: Number of resync requests deliberately left unanswered.
    """

    refused_syncs: int

    def __init__(self, silent_syncs: int = 0) -> None:
        """Initialise the channel with a guest that is not ready yet.

        Args:
            silent_syncs: How many resync requests go unanswered before the
                guest's agent starts replying.
        """
        super().__init__()
        self.refused_syncs = 0
        self._silent_syncs = silent_syncs

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Take the one connection this channel will ever accept.

        The listening socket is closed on accept, so a client that hangs up and
        reconnects finds the port refusing connections - QEMU's behaviour, and
        the whole point of this server.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        if self._server is not None:
            self._server.close()
        await super()._serve(reader, writer)

    async def _replies_for(self, line: bytes) -> list[bytes]:
        """Answer one request, staying silent while the guest is not up.

        Args:
            line: Raw request bytes without the trailing newline.

        Returns:
            list[bytes]: Wire frames to write back, empty while silent.
        """
        request = decode_object(line.strip()) if line.strip() else {}
        if str(request.get("execute", "")) in SYNC_COMMANDS and self._silent_syncs > 0:
            self._silent_syncs -= 1
            self.refused_syncs += 1
            self.commands.append(str(request.get("execute", "")))
            return []
        return await super()._replies_for(line)


class IntellicrackAgentServer(_LoopbackServer):
    """Real TCP server speaking the in-guest Intellicrack monitor protocol.

    ``agent.ps1`` listens on ``127.0.0.1:4445`` inside the guest and answers
    newline-delimited ``{"type": "execute", "command", "args"}`` requests with
    ``{"type": "result", "data": {"exit_code", "stdout", "stderr"}}``, and the
    client's readiness probe with a bare pong. That is the protocol
    :class:`intellicrack.sandbox.qemu.GuestAgentClient` speaks, so this server
    is what its ``connect`` and ``send_command`` really talk to. The outcome of
    each request comes from the same :class:`GuestCommandResponder` guest
    models the guest-agent server uses.

    The channel this agent is reached through is a QEMU SLIRP ``hostfwd``,
    which accepts the host-side TCP connection unconditionally and only then
    tries to reach the in-guest listener. ``dead_connections`` models the
    window before the in-guest agent calls ``listen``: the connection is
    accepted and immediately closed without a byte crossing it, exactly what
    SLIRP does when nothing answers inside the guest. ``close_after_replies``
    models the other end of the same channel's life - an agent that answered
    and then went away - so a client that assumes a connected socket stays
    connected can be caught.

    ``reply_delay`` models the ordinary case none of the failure knobs cover: a
    command that takes real time inside the guest. The connection stays open
    and healthy across the wait, so a client polling for the reply spends real
    poll slices on a request that is going to succeed - which is the only way
    to observe what those slices cost a caller, or a log.

    ``serve_delay`` models the agent's own service cadence, which is not the
    same thing. ``agent.ps1`` is single-threaded: every iteration of its main
    loop runs a full process and socket sweep and a one-second sleep before it
    looks at its listener again, so a connection is established by the guest's
    kernel - and by the SLIRP hostfwd in front of it - long before the agent
    reads a byte of it. Nothing about that connection is unhealthy; it is
    simply not answered yet. A host that treats its own per-attempt patience as
    the agent's deadline abandons such a connection while the agent is still
    working towards it, which is what S18-D04 was.

    ``drop_requests`` models the harder half of that failure: the request
    crossed the channel and the agent took delivery of it, and the connection
    died before any reply could come back. The command is recorded in
    :attr:`requests` and in :attr:`dropped_requests` exactly as a live agent
    would have received it, because from the guest's side it did arrive. A
    client that answers a lost channel by simply sending the command again
    therefore shows up as a second entry in :attr:`requests`, which is the only
    way to tell a genuine recovery from a re-execution.

    Attributes:
        requests: Every ``(command, args)`` pair received, in arrival order,
            whether or not a reply was ever written for it.
        dropped_requests: The subset of ``requests`` the agent took delivery of
            and then never answered because the connection went down.
        handshakes: Number of readiness probes answered since ``start``. A
            handshake is not a command, so it never lands in ``requests`` and
            never counts towards ``close_after_replies``.
    """

    requests: list[tuple[str, tuple[str, ...]]]
    dropped_requests: list[tuple[str, tuple[str, ...]]]
    handshakes: int

    def __init__(
        self,
        responder: GuestCommandResponder | None = None,
        port: int = 0,
        *,
        listen_delay: float = 0.0,
        undecodable_lines: int = 0,
        dead_connections: int = 0,
        close_after_replies: int = 0,
        drop_requests: int = 0,
        reply_delay: float = 0.0,
        serve_delay: float = 0.0,
    ) -> None:
        """Initialise the server with an empty request log.

        Args:
            responder: Guest model deciding the outcome of each command. When
                omitted every command succeeds with the default output.
            port: TCP port to claim, or 0 to let the OS pick a free one.
            listen_delay: Seconds after ``start`` before the port is bound and
                connections stop being refused, modelling a guest whose agent
                has not come up yet.
            undecodable_lines: How many replies are preceded by a complete,
                newline-terminated line whose bytes are not valid UTF-8. The
                framing around such a line is intact, so it is one message the
                client cannot read rather than a stream it can no longer follow.
            dead_connections: How many of the first accepted connections are
                closed immediately without reading or writing anything, the way
                a hostfwd behaves while the in-guest agent has not reached
                ``listen`` yet. A count above any number of attempts models a
                guest whose agent never comes up at all.
            close_after_replies: How many replies one connection carries before
                the agent hangs up. Zero leaves the connection open until the
                client closes it.
            drop_requests: How many commands the agent takes delivery of and
                then abandons, closing the connection without writing their
                reply. The budget is spent across the whole server rather than
                per connection, so a later connection answers normally.
            reply_delay: Seconds the agent spends running each command before
                its reply is written, modelling work that takes real time in
                the guest. The readiness handshake is never delayed by this
                knob, because a guest agent answers it without running anything.
            serve_delay: Seconds an established connection waits before the
                agent reads a byte of it, modelling the monitoring sweep its
                single-threaded main loop finishes before it services its
                listener again. Everything on that connection is held back,
                the readiness handshake included, because the agent has not
                looked at the socket yet.
        """
        super().__init__(listen_delay=listen_delay, port=port)
        self._serve_delay = serve_delay
        self.requests = []
        self.dropped_requests = []
        self.handshakes = 0
        self._responder = responder
        self._undecodable_lines = undecodable_lines
        self._dead_connections = dead_connections
        self._close_after_replies = close_after_replies
        self._drop_requests = drop_requests
        self._reply_delay = reply_delay

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Answer execute requests until the client or the agent goes away.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        if self._dead_connections > 0:
            self._dead_connections -= 1
            return

        if self._serve_delay > 0.0:
            await asyncio.sleep(self._serve_delay)

        replies = 0
        while True:
            line = await reader.readline()
            if not line:
                return
            reply = self._reply_for(line.strip())
            if reply is None:
                continue
            is_command_reply = str(reply.get("type", "")) == AGENT_MESSAGE_RESULT
            if is_command_reply and self._abandon_last_request():
                return
            if is_command_reply and self._reply_delay > 0.0:
                await asyncio.sleep(self._reply_delay)
            if is_command_reply and self._undecodable_lines > 0:
                self._undecodable_lines -= 1
                writer.write(UNDECODABLE_LINE)
            writer.write(json.dumps(reply).encode() + b"\n")
            await writer.drain()
            if not is_command_reply:
                continue
            replies += 1
            if 0 < self._close_after_replies <= replies:
                return

    def _abandon_last_request(self) -> bool:
        """Spend one ``drop_requests`` budget on the command just received.

        Returns:
            bool: True if this command's reply must never be written and the
            connection must go down instead.
        """
        if self._drop_requests <= 0:
            return False
        self._drop_requests -= 1
        self.dropped_requests.append(self.requests[-1])
        return True

    def _reply_for(self, payload: bytes) -> dict[str, Any] | None:
        """Compute the reply message for one received request line.

        Args:
            payload: Raw request bytes without the trailing newline.

        Returns:
            dict[str, Any] | None: Reply envelope, or None for a request type
            the agent does not answer.
        """
        if not payload:
            return None
        request = decode_object(payload)
        request_type = str(request.get("type", ""))
        if request_type == AGENT_REQUEST_PING:
            self.handshakes += 1
            return {"type": AGENT_MESSAGE_PONG, "data": {}}
        if request_type != AGENT_REQUEST_EXECUTE:
            return None
        command = str(request.get("command", ""))
        raw_args: Any = request.get("args")
        args = [str(item) for item in cast("list[Any]", raw_args)] if isinstance(raw_args, list) else []
        self.requests.append((command, tuple(args)))
        result = GuestCommandResult() if self._responder is None else self._responder(command, args)
        return {
            "type": AGENT_MESSAGE_RESULT,
            "data": {
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
        }


class SilentGuestAgentServer(_LoopbackServer):
    """Real TCP server that accepts the channel but never answers the sync.

    Models a wedged agent: the socket is up, so the connection succeeds, but
    the ``guest-sync-delimited`` reply never arrives.

    Attributes:
        open_connections: Number of accepted connections the client has not
            closed yet.
        all_closed: Set whenever no accepted connection is open, so a test can
            wait for the client to hang up instead of polling.
    """

    open_connections: int
    all_closed: asyncio.Event

    def __init__(self) -> None:
        """Initialise the server with empty connection counters."""
        super().__init__()
        self.open_connections = 0
        self.all_closed = asyncio.Event()
        self.all_closed.set()

    async def _serve(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Drain the client without ever replying.

        Args:
            reader: Stream reader for the accepted connection.
            writer: Stream writer for the accepted connection.
        """
        del writer
        self.open_connections += 1
        self.all_closed.clear()
        try:
            while await reader.read(4096):
                pass
        finally:
            self.open_connections -= 1
            if self.open_connections == 0:
                self.all_closed.set()
