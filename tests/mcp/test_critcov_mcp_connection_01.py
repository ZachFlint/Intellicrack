# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Critical-coverage tests for the failure, teardown and supervision paths of ``intellicrack.mcp.connection``.

Every test drives the real connection or the real manager. Servers are the real fixture servers under ``tests/_helpers``: the steerable
lifecycle server over stdio, Streamable HTTP and legacy SSE, and the client-features server over legacy SSE. Expected values come from the
documented behavior of the pieces involved: the protocol's ``CONNECTION_CLOSED`` contract for a request sent into a closed session,
``asyncio.timeout`` for a deadline that is already spent, the number of tools the lifecycle server registers, ``anyio``'s memory streams
for end-of-stream and closed-stream errors, and the module's own documented messages.

Where a state cannot be reached by waiting for it (a server that vanished a moment before the supervisor reacts), the test sets a private
data attribute of the real connection, such as the supervisor's ``_dropped`` event, so the real object is held in that state.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace
from typing import TYPE_CHECKING, Final, NoReturn, Protocol, Self, TextIO, cast

import anyio
import pytest
import structlog.testing
from mcp.client.auth import OAuthClientProvider
from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp import connection as connection_module
from intellicrack.mcp.auth import KeyringTokenStorage, client_metadata, issuer_for
from intellicrack.mcp.config import (
    HttpServerSpec,
    McpConfigDocument,
    McpConfigStore,
    McpServerConfig,
    McpTransportKind,
    StdioServerSpec,
)
from intellicrack.mcp.connection import (
    DISCONNECT_TIMEOUT_S,
    STDERR_LINE_MAX_CHARS,
    McpConnection,
    McpConnectionManager,
    McpHealth,
)
from intellicrack.mcp.consent import McpConsentGate, TrustStore, deny_all_launches
from intellicrack.mcp.context_events import McpContextChange, McpContextEvent
from intellicrack.mcp.errors import McpConnectionError, McpConsentDeniedError, McpProtocolError
from intellicrack.mcp.progress import ProgressKind
from tests._helpers.mcp_features_support import FEATURES_SERVER_SCRIPT, Era, features_config, features_connection, private_resolver
from tests._helpers.mcp_http_process import await_port, free_port
from tests._helpers.mcp_lifecycle_server import GROWN_TOOL_PREFIX
from tests._helpers.mcp_lifecycle_support import approving_gate, call_text, network_config, network_server, stdio_config, wait_until


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Generator, Mapping, Sequence
    from pathlib import Path

    from mcp import Client
    from mcp_types import RequestParamsMeta

    from intellicrack.mcp.consent import DangerousPattern


_CONNECT_TIMEOUT_S: Final[float] = 90.0
_TEARDOWN_TIMEOUT_S: Final[float] = 30.0
_RECOVERY_DEADLINE_S: Final[float] = 8.0
_TINY_DEADLINE_S: Final[float] = 0.0001
_SHORT_BUDGET_S: Final[float] = 0.2
_LIFECYCLE_TOOL_COUNT: Final[int] = 9
"""Tools ``mcp_lifecycle_server.py`` registers: whoami, env_keys, env_value, argv, write_probe, spawn_child, quit, crash and grow."""

_GROWN: Final[str] = f"{GROWN_TOOL_PREFIX}0"
_PROBE_URI: Final[str] = "features://notes/readme"
_OTHER_URI: Final[str] = "features://notes/other"


class _StderrApi(Protocol):
    """The part of the connection's stderr capture these tests use."""

    def open(self) -> TextIO:
        """Create the pipe and start draining it.

        Returns:
            TextIO: The writable end.
        """
        ...

    def close(self) -> None:
        """Close the pipe and stop the reader."""

    def tail(self, limit: int) -> list[str]:
        """Return the most recent captured lines.

        Args:
            limit: Maximum number of lines.

        Returns:
            list[str]: Up to ``limit`` lines, oldest first.
        """
        ...


class _WatchedApi(Protocol):
    """The read stream wrapper that reports when a transport's output ends."""

    async def receive(self) -> object:
        """Receive one item.

        Returns:
            object: The item.
        """

    def __aiter__(self) -> Self:
        """Iterate over the stream.

        Returns:
            Self: The stream.
        """
        ...

    async def __anext__(self) -> object:
        """Receive the next item.

        Returns:
            object: The item.
        """

    def close(self) -> None:
        """Close the stream."""

    async def aclose(self) -> None:
        """Close the stream."""


class _Interrupt(BaseException):
    """A failure that is not an ordinary exception, such as the interpreter shutting down."""


class _HeldPrompt:
    """A consent prompt that stays open until it is answered.

    Attributes:
        opened: Set once the prompt is showing.
        answer: Set to approve the launch.
        cancelled: Whether the prompt was cancelled before it was answered.
    """

    opened: asyncio.Event
    answer: asyncio.Event
    cancelled: bool

    def __init__(self) -> None:
        """Start closed and unanswered."""
        self.opened = asyncio.Event()
        self.answer = asyncio.Event()
        self.cancelled = False

    async def __call__(self, config: McpServerConfig, rendered: str, findings: list[DangerousPattern]) -> bool:
        """Show the prompt and wait for the answer.

        Args:
            config: The server being launched.
            rendered: The launch description.
            findings: Dangerous patterns found in the command.

        Returns:
            bool: ``True`` once answered.

        Raises:
            asyncio.CancelledError: If the prompt is cancelled before it is answered.
        """
        del config, rendered, findings
        self.opened.set()
        try:
            _ = await self.answer.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return True


def _private(obj: object, name: str) -> object:
    """Read a private attribute of a real object.

    Args:
        obj: The object.
        name: The attribute's name.

    Returns:
        object: Its value.
    """
    return getattr(obj, name)


def _assign(obj: object, name: str, value: object) -> None:
    """Set a private data attribute of a real object.

    Args:
        obj: The object.
        name: The attribute's name.
        value: The new value.
    """
    setattr(obj, name, value)


def _event(connection: McpConnection, name: str) -> asyncio.Event:
    """Read one of a connection's private events.

    Args:
        connection: The connection.
        name: The event attribute's name.

    Returns:
        asyncio.Event: The event.
    """
    return cast("asyncio.Event", _private(connection, name))


async def _heartbeat(connection: McpConnection, client: Client) -> bool:
    """Run the connection's liveness probe once.

    Args:
        connection: The connection.
        client: The entered client to probe.

    Returns:
        bool: Whether to keep probing.
    """
    probe = cast("Callable[[Client], Awaitable[bool]]", _private(connection, "_heartbeat"))
    return await probe(client)


async def _apply_log_level(connection: McpConnection, client: Client) -> None:
    """Send a connection's chosen log level to its server.

    Args:
        connection: The connection.
        client: The entered client.
    """
    apply = cast("Callable[[Client], Awaitable[None]]", _private(connection, "_apply_log_level"))
    await apply(client)


async def _restore_subscriptions(connection: McpConnection, client: Client) -> None:
    """Subscribe a connection's client to what it was subscribed to before.

    Args:
        connection: The connection.
        client: The entered client.
    """
    restore = cast("Callable[[Client], Awaitable[None]]", _private(connection, "_restore_subscriptions"))
    await restore(client)


async def _on_incoming(connection: McpConnection, message: object) -> None:
    """Hand a connection what its session tees to the message handler.

    Args:
        connection: The connection.
        message: A notification or a transport fault.
    """
    handler = cast("Callable[[object], Awaitable[None]]", _private(connection, "_on_incoming"))
    await handler(message)


async def _supervise_attempts(connection: McpConnection) -> None:
    """Run a connection's connection attempts directly.

    Args:
        connection: The connection.
    """
    supervise = cast("Callable[[], Awaitable[None]]", _private(connection, "_supervise_attempts"))
    await supervise()


async def _abandon(connection: McpConnection) -> None:
    """Abandon a connection's attempt.

    Args:
        connection: The connection.
    """
    abandon = cast("Callable[[], Awaitable[None]]", _private(connection, "_abandon"))
    await abandon()


async def _stop_follower(connection: McpConnection) -> None:
    """Stop a connection's change follower.

    Args:
        connection: The connection.
    """
    stop = cast("Callable[[], Awaitable[None]]", _private(connection, "_stop_follower"))
    await stop()


def _admits_log(connection: McpConnection, level: str) -> bool:
    """Ask a connection whether it passes on a server log message of one level.

    Args:
        connection: The connection.
        level: The message's level.

    Returns:
        bool: Whether the message is admitted.
    """
    admits = cast("Callable[[str], bool]", _private(connection, "_admits_log"))
    return admits(level)


def _request_meta(connection: McpConnection, progress_token: str | None = None) -> dict[str, object] | None:
    """Build the ``_meta`` a connection's next request carries.

    Args:
        connection: The connection.
        progress_token: The progress token, or ``None``.

    Returns:
        dict[str, object] | None: The meta, or ``None`` when there is nothing to carry.
    """
    build = cast("Callable[[str | None], dict[str, object] | None]", _private(connection, "_request_meta"))
    return build(progress_token)


def _mark_dropped(connection: McpConnection, detail: str) -> None:
    """Record that a connection's transport is gone.

    Args:
        connection: The connection.
        detail: Why.
    """
    mark = cast("Callable[[str], None]", _private(connection, "_mark_dropped"))
    mark(detail)


def _on_stream_closed(connection: McpConnection, attempt: int) -> None:
    """Report the end of one attempt's read stream.

    Args:
        connection: The connection.
        attempt: The attempt whose stream ended.
    """
    closed = cast("Callable[[int], None]", _private(connection, "_on_stream_closed"))
    closed(attempt)


def _announce_context(connection: McpConnection, change: McpContextChange, uri: str | None = None) -> None:
    """Hand a context change to a connection's listener.

    Args:
        connection: The connection.
        change: What changed.
        uri: The updated resource, for an update.
    """
    announce = cast("Callable[[McpContextChange, str | None], None]", _private(connection, "_announce_context"))
    announce(change, uri)


def _track_operator_steps(connection: McpConnection, auth: OAuthClientProvider) -> None:
    """Count an OAuth provider's interactive steps as operator time.

    Args:
        connection: The connection.
        auth: The provider.
    """
    track = cast("Callable[[OAuthClientProvider], None]", _private(connection, "_track_operator_steps"))
    track(auth)


def _http_config(
    server_id: str,
    *,
    enabled: bool = True,
    request_timeout_s: float = 60.0,
    log_level: str | None = None,
) -> McpServerConfig:
    """Build a remote server configuration that is never connected to.

    Args:
        server_id: The server id.
        enabled: Whether the server is enabled.
        request_timeout_s: The per-request timeout.
        log_level: The log level asked for.

    Returns:
        McpServerConfig: The configuration.
    """
    return McpServerConfig(
        server_id=server_id,
        kind=McpTransportKind.HTTP,
        http=HttpServerSpec(url="http://127.0.0.1:9/mcp"),
        enabled=enabled,
        request_timeout_s=request_timeout_s,
        log_level=log_level,
    )


def _stdio_connection(directory: Path, server_id: str) -> McpConnection:
    """Build an unconnected connection to the lifecycle server over stdio.

    Args:
        directory: Per-test directory for the trust store and ``.env``.
        server_id: The server id.

    Returns:
        McpConnection: The connection, with a gate that approves every launch.
    """
    return McpConnection(stdio_config(server_id), private_resolver(directory), consent=approving_gate(directory / "trust.json"))


def _manager(directory: Path, configs: list[McpServerConfig], gate: McpConsentGate) -> McpConnectionManager:
    """Build a manager over a configuration file holding the given servers.

    Args:
        directory: Per-test directory.
        configs: The servers.
        gate: The consent gate.

    Returns:
        McpConnectionManager: The manager, not yet started.
    """
    store = McpConfigStore(directory / "mcp.json")
    store.save(McpConfigDocument(servers=tuple(configs)))
    return McpConnectionManager(store, private_resolver(directory), gate)


async def _connect(connection: McpConnection) -> None:
    """Connect, bounded so a hang fails the test.

    Args:
        connection: The connection.
    """
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)


async def _disconnect(connection: McpConnection) -> None:
    """Disconnect, bounded so a hang fails the test.

    Args:
        connection: The connection.
    """
    await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


async def _transport_closed(client: Client) -> bool:
    """Report whether a client's session now answers every request with ``CONNECTION_CLOSED``.

    Args:
        client: The entered client.

    Returns:
        bool: ``True`` once its transport has closed.
    """
    session = client.session
    version = session.protocol_version
    try:
        if version in MODERN_PROTOCOL_VERSIONS:
            _ = await session.send_discover(version)
        else:
            _ = await session.send_ping()
    except MCPError as exc:
        return exc.code == CONNECTION_CLOSED
    return False


async def _pid_of(connection: McpConnection) -> int | None:
    """Ask the lifecycle server for its process id.

    Args:
        connection: The connection.

    Returns:
        int | None: The id, or ``None`` when the server cannot be asked right now.
    """
    if not connection.is_ready:
        return None
    try:
        return int(await call_text(connection, "whoami"))
    except McpConnectionError:
        return None


async def _replaced(connection: McpConnection, previous: int) -> bool:
    """Report whether a different server process now serves the connection.

    Args:
        connection: The connection.
        previous: The process id that served it before.

    Returns:
        bool: ``True`` once a new process answers.
    """
    current = await _pid_of(connection)
    return current is not None and current != previous


def _event_names(captured: Sequence[Mapping[str, object]]) -> list[str]:
    """List the event names structlog captured.

    Args:
        captured: The captured log entries.

    Returns:
        list[str]: Each entry's event name.
    """
    return [str(entry.get("event")) for entry in captured]


@contextmanager
def _tiny_deadline(connection: McpConnection) -> Generator[None]:
    """Give a connection a per-request deadline no round trip can meet, then restore it.

    Args:
        connection: The connection.

    Yields:
        None: Control passes to the block that issues the requests.
    """
    original = connection.config
    _assign(connection, "_config", replace(original, request_timeout_s=_TINY_DEADLINE_S))
    try:
        yield
    finally:
        _assign(connection, "_config", original)


@contextmanager
def _features_sse_process() -> Generator[tuple[subprocess.Popen[bytes], int]]:
    """Run the client-features server over legacy SSE, handing the process to the block.

    Yields:
        tuple[subprocess.Popen[bytes], int]: The process and its loopback port.
    """
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, str(FEATURES_SERVER_SCRIPT), "--transport", "sse", "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        await_port(port, process)
        yield process, port
    finally:
        process.terminate()
        try:
            _ = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            _ = process.wait(timeout=10)


def _stderr_capture(directory: Path) -> _StderrApi:
    """Reach the stderr capture a connection owns.

    Args:
        directory: Per-test directory.

    Returns:
        _StderrApi: The connection's real capture.
    """
    connection = McpConnection(_http_config("stderr-probe"), private_resolver(directory))
    return cast("_StderrApi", _private(connection, "_stderr"))


def _watched(inner: object, on_closed: Callable[[], None]) -> _WatchedApi:
    """Wrap a read stream in the connection's watcher.

    Args:
        inner: The read stream.
        on_closed: Called when the stream ends.

    Returns:
        _WatchedApi: The real watcher.
    """
    factory = cast("Callable[[object, Callable[[], None]], _WatchedApi]", _private(connection_module, "_WatchedReceiveStream"))
    return factory(inner, on_closed)


def test_stderr_capture_truncates_an_overlong_line(tmp_path: Path) -> None:
    """A stderr line longer than the limit is kept up to the limit and marked truncated; a short one is kept whole.

    Args:
        tmp_path: Per-test directory.
    """
    capture = _stderr_capture(tmp_path)
    writer = capture.open()
    try:
        _ = writer.write("x" * (STDERR_LINE_MAX_CHARS + 904) + "\n")
        _ = writer.write("short\n")
    finally:
        capture.close()
    assert capture.tail(10) == ["x" * STDERR_LINE_MAX_CHARS + "... [truncated]", "short"]


def test_stderr_drain_without_a_pipe_returns_at_once(tmp_path: Path) -> None:
    """A drain asked to run before any pipe exists returns without capturing anything.

    Args:
        tmp_path: Per-test directory.
    """
    capture = _stderr_capture(tmp_path)
    drain = cast("Callable[[], None]", _private(capture, "_drain"))
    drain()
    assert capture.tail(5) == []


def test_stderr_drain_survives_a_pipe_closed_under_it(tmp_path: Path) -> None:
    """A reader whose pipe was closed ends quietly instead of raising into its thread.

    Args:
        tmp_path: Per-test directory.
    """
    capture = _stderr_capture(tmp_path)
    with (tmp_path / "closed.txt").open("w", encoding="utf-8") as closed:
        pass
    _assign(capture, "_read_handle", closed)
    drain = cast("Callable[[], None]", _private(capture, "_drain"))
    drain()
    assert closed.closed
    assert capture.tail(5) == []


@pytest.mark.asyncio
async def test_watched_stream_passes_items_and_reports_the_end_of_the_stream() -> None:
    """Items pass through untouched, and a stream whose sender closed raises ``EndOfStream`` after reporting its end once."""
    ended: list[str] = []
    send, receive = anyio.create_memory_object_stream[str](1)
    watched = _watched(receive, lambda: ended.append("ended"))
    try:
        await send.send("hello")
        assert await watched.receive() == "hello"
        assert ended == []
        send.close()
        with pytest.raises(anyio.EndOfStream):
            _ = await watched.receive()
    finally:
        await watched.aclose()
        send.close()
    assert ended == ["ended"]


@pytest.mark.asyncio
async def test_watched_stream_reports_a_stream_closed_under_its_reader() -> None:
    """A read stream closed locally raises ``ClosedResourceError`` from both read paths, and each reports the end."""
    ended: list[str] = []
    send, receive = anyio.create_memory_object_stream[str](1)
    watched = _watched(receive, lambda: ended.append("ended"))
    try:
        watched.close()
        with pytest.raises(anyio.ClosedResourceError):
            _ = await watched.receive()
        assert ended == ["ended"]
        with pytest.raises(anyio.ClosedResourceError):
            _ = await anext(watched)
        assert ended == ["ended", "ended"]
    finally:
        send.close()


def test_connection_exposes_its_configuration_and_namespace(tmp_path: Path) -> None:
    """The connection hands back the configuration it was built from and the tool namespace that server owns.

    Args:
        tmp_path: Per-test directory.
    """
    config = _http_config("alpha-1")
    connection = McpConnection(config, private_resolver(tmp_path))
    assert connection.config is config
    assert connection.namespace == "mcp-alpha-1"


@pytest.mark.asyncio
async def test_a_remote_server_has_no_launch_environment(tmp_path: Path) -> None:
    """Asking a remote server for the environment it would be launched with is refused.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("remote"), private_resolver(tmp_path))
    with pytest.raises(McpConnectionError, match="is not a local server"):
        _ = await connection.resolved_environment()


@pytest.mark.asyncio
async def test_inline_environment_wins_over_the_env_file(tmp_path: Path) -> None:
    """The ``envFile`` is read first and an inline entry with the same name replaces its value.

    Args:
        tmp_path: Per-test directory.
    """
    env_file = tmp_path / "server.env"
    env_file.write_text('FROM_FILE=1\nSHARED="from-file"\n# a comment\n', encoding="utf-8")
    spec = StdioServerSpec(command=sys.executable, env={"SHARED": "inline", "INLINE_ONLY": "3"}, env_file=str(env_file))
    config = McpServerConfig(server_id="envfile", kind=McpTransportKind.STDIO, stdio=spec, enabled=True)
    connection = McpConnection(config, private_resolver(tmp_path))
    assert await connection.resolved_environment() == {"FROM_FILE": "1", "SHARED": "inline", "INLINE_ONLY": "3"}


@pytest.mark.asyncio
async def test_connecting_a_local_server_without_a_launch_command_fails(tmp_path: Path) -> None:
    """A stdio server configured without a launch description fails to connect, and says so.

    Args:
        tmp_path: Per-test directory.
    """
    config = McpServerConfig(server_id="nolaunch", kind=McpTransportKind.STDIO, enabled=True)
    connection = McpConnection(config, private_resolver(tmp_path), consent=approving_gate(tmp_path / "trust.json"))
    try:
        with pytest.raises(McpConnectionError, match="has no launch command"):
            await _connect(connection)
    finally:
        await _disconnect(connection)
    status = connection.status
    assert status.health is McpHealth.FAILED
    assert status.last_error is not None
    assert "has no launch command" in status.last_error


@pytest.mark.asyncio
async def test_a_local_server_is_never_started_without_a_consent_gate(tmp_path: Path) -> None:
    """With no consent prompt available, a local server is refused before anything is spawned.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(stdio_config("noconsent"), private_resolver(tmp_path))
    try:
        with pytest.raises(McpConnectionError, match="needs your approval"):
            await _connect(connection)
    finally:
        await _disconnect(connection)
    assert connection.status.health is McpHealth.FAILED
    assert connection.stderr_tail() == []


@pytest.mark.asyncio
async def test_connecting_a_remote_server_without_an_endpoint_fails(tmp_path: Path) -> None:
    """An HTTP server configured without a URL fails to connect, and says so.

    Args:
        tmp_path: Per-test directory.
    """
    config = McpServerConfig(server_id="noendpoint", kind=McpTransportKind.HTTP, enabled=True)
    connection = McpConnection(config, private_resolver(tmp_path))
    try:
        with pytest.raises(McpConnectionError, match="has no endpoint URL"):
            await _connect(connection)
    finally:
        await _disconnect(connection)
    assert connection.status.health is McpHealth.FAILED


@pytest.mark.asyncio
async def test_connecting_a_disabled_server_is_refused(tmp_path: Path) -> None:
    """A server turned off in configuration is not connected, and its health stays disabled.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("switched-off", enabled=False), private_resolver(tmp_path))
    with pytest.raises(McpConnectionError, match="is disabled"):
        await connection.connect()
    assert connection.status.health is McpHealth.DISABLED
    assert not connection.is_ready


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_server_that_cannot_list_its_tools_in_time_fails_to_connect(tmp_path: Path) -> None:
    """A per-request deadline too short for the first tool listing fails the connect with a timeout, and the server ends up failed.

    Args:
        tmp_path: Per-test directory.
    """
    config = replace(stdio_config("slow-list"), request_timeout_s=_TINY_DEADLINE_S)
    connection = McpConnection(config, private_resolver(tmp_path), consent=approving_gate(tmp_path / "trust.json"))
    try:
        with pytest.raises(McpConnectionError) as caught:
            await _connect(connection)
    finally:
        await _disconnect(connection)
    assert "timed out" in str(caught.value)
    assert connection.status.health is McpHealth.FAILED
    assert not connection.is_ready


@pytest.mark.asyncio
async def test_a_request_that_overruns_its_deadline_is_reported_as_a_timeout(tmp_path: Path) -> None:
    """A request whose send never completes fails with a connection error naming the operation, caused by the timeout.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("deadline", request_timeout_s=_SHORT_BUDGET_S), private_resolver(tmp_path))

    async def never() -> str:
        """Wait forever.

        Returns:
            str: Never returns.
        """
        _ = await asyncio.Event().wait()
        return "unreachable"

    with pytest.raises(McpConnectionError) as caught:
        _ = await connection.request("list resources", never)
    assert "list resources exceeded" in str(caught.value)
    assert isinstance(caught.value.__cause__, TimeoutError)


@pytest.mark.asyncio
async def test_a_request_failure_names_the_protocol_level_leaf(tmp_path: Path) -> None:
    """A transport failure carried in a group is reported by its protocol-level leaf when it has one, else by its first leaf.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("failing"), private_resolver(tmp_path))
    protocol_leaf = McpProtocolError("the server broke the contract")

    async def protocol_failure() -> str:
        """Fail with a group whose second leaf is a protocol error.

        Returns:
            str: Never returns.

        Raises:
            ExceptionGroup: Always.
        """
        await asyncio.sleep(0)
        message = "transport"
        raise ExceptionGroup(message, [OSError("plumbing broke"), protocol_leaf])

    async def plumbing_failure() -> str:
        """Fail with a group of two plain errors.

        Returns:
            str: Never returns.

        Raises:
            ExceptionGroup: Always.
        """
        await asyncio.sleep(0)
        message = "transport"
        raise ExceptionGroup(message, [OSError("first plumbing"), RuntimeError("second plumbing")])

    with pytest.raises(McpConnectionError) as protocol:
        _ = await connection.request("probe", protocol_failure)
    assert str(protocol.value) == "server 'failing': cannot probe: the server broke the contract"
    assert protocol.value.__cause__ is protocol_leaf

    with pytest.raises(McpConnectionError) as plumbing:
        _ = await connection.request("probe", plumbing_failure)
    assert str(plumbing.value) == "server 'failing': cannot probe: first plumbing"


@pytest.mark.asyncio
async def test_cancelling_a_request_is_not_reported_as_a_connection_error(tmp_path: Path) -> None:
    """A caller cancelled mid-request sees the cancellation, not a connection failure.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("cancelled"), private_resolver(tmp_path))
    started = asyncio.Event()

    async def never() -> str:
        """Signal that the request is in flight, then wait forever.

        Returns:
            str: Never returns.
        """
        started.set()
        _ = await asyncio.Event().wait()
        return "unreachable"

    task = asyncio.create_task(connection.request("probe", never))
    _ = await started.wait()
    _ = task.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await task
    assert task.cancelled()


@pytest.mark.asyncio
async def test_a_request_without_progress_reports_its_timeout(tmp_path: Path) -> None:
    """A progress-reporting request that never answers nor reports progress fails with the progress-aware timeout message.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("no-progress", request_timeout_s=_SHORT_BUDGET_S), private_resolver(tmp_path))

    async def never(meta: RequestParamsMeta | None) -> str:
        """Wait forever.

        Args:
            meta: The request's ``_meta``.

        Returns:
            str: Never returns.
        """
        del meta
        _ = await asyncio.Event().wait()
        return "unreachable"

    with pytest.raises(McpConnectionError) as caught:
        _ = await connection.request_with_progress("read resource", ProgressKind.RESOURCE, "features://x", never)
    assert "read resource exceeded" in str(caught.value)
    assert "without progress" in str(caught.value)
    assert isinstance(caught.value.__cause__, TimeoutError)


@pytest.mark.asyncio
async def test_a_progress_request_failure_names_its_leaf_and_cancellation_passes_through(tmp_path: Path) -> None:
    """A progress-reporting request reports a transport failure by its protocol leaf, and a cancelled caller sees the cancellation.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("progress-fail"), private_resolver(tmp_path))
    protocol_leaf = McpProtocolError("refused at the protocol level")
    started = asyncio.Event()

    async def failing(meta: RequestParamsMeta | None) -> str:
        """Fail with a group holding a plain error and a protocol error.

        Args:
            meta: The request's ``_meta``.

        Returns:
            str: Never returns.

        Raises:
            ExceptionGroup: Always.
        """
        del meta
        await asyncio.sleep(0)
        message = "transport"
        raise ExceptionGroup(message, [OSError("plumbing"), protocol_leaf])

    async def never(meta: RequestParamsMeta | None) -> str:
        """Signal that the request is in flight, then wait forever.

        Args:
            meta: The request's ``_meta``.

        Returns:
            str: Never returns.
        """
        del meta
        started.set()
        _ = await asyncio.Event().wait()
        return "unreachable"

    with pytest.raises(McpConnectionError) as caught:
        _ = await connection.request_with_progress("get prompt", ProgressKind.PROMPT, "greet", failing)
    assert str(caught.value) == "server 'progress-fail': cannot get prompt: refused at the protocol level"
    assert caught.value.__cause__ is protocol_leaf

    task = asyncio.create_task(connection.request_with_progress("get prompt", ProgressKind.PROMPT, "greet", never))
    _ = await started.wait()
    _ = task.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await task


def test_log_messages_are_admitted_by_level_and_by_the_connection_era(tmp_path: Path) -> None:
    """With no level chosen on a connection that is not modern every message passes; with one chosen, lower levels are dropped.

    Args:
        tmp_path: Per-test directory.
    """
    open_connection = McpConnection(_http_config("no-level"), private_resolver(tmp_path))
    assert _admits_log(open_connection, "debug")
    assert _admits_log(open_connection, "emergency")

    choosy = McpConnection(_http_config("warn-up", log_level="warning"), private_resolver(tmp_path))
    assert not _admits_log(choosy, "info")
    assert _admits_log(choosy, "warning")
    assert _admits_log(choosy, "error")
    assert _admits_log(choosy, "not-a-protocol-level")


def test_request_meta_carries_only_what_applies(tmp_path: Path) -> None:
    """A request with no progress token and no applicable log level carries no ``_meta``; a token alone is carried.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("meta", log_level="info"), private_resolver(tmp_path))
    assert _request_meta(connection) is None
    assert _request_meta(connection, "token-1") == {"progressToken": "token-1"}


@pytest.mark.asyncio
async def test_a_log_level_chosen_while_disconnected_is_kept(tmp_path: Path) -> None:
    """Choosing or clearing the log level of a server that is not connected only changes what the next connection asks for.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("quiet"), private_resolver(tmp_path))
    await connection.set_log_level("error")
    assert connection.log_level == "error"
    assert connection.config.log_level == "error"
    await connection.set_log_level(None)
    assert connection.log_level is None
    assert connection.config.log_level is None


def test_a_context_change_with_no_listener_is_dropped_and_with_one_is_delivered(tmp_path: Path) -> None:
    """Announcing a change nobody listens to does nothing; once a listener is set it receives the event with the server id.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("context"), private_resolver(tmp_path))
    _announce_context(connection, McpContextChange.RESOURCES_LISTED)
    heard: list[McpContextEvent] = []
    connection.set_context_listener(heard.append)
    _announce_context(connection, McpContextChange.RESOURCE_UPDATED, "features://notes/readme")
    assert heard == [McpContextEvent(server_id="context", change=McpContextChange.RESOURCE_UPDATED, uri="features://notes/readme")]


@pytest.mark.asyncio
async def test_requests_to_a_server_that_is_not_connected_are_refused(tmp_path: Path) -> None:
    """Every request that needs a live connection says the server is not connected when there is none.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("idle"), private_resolver(tmp_path))
    with pytest.raises(McpConnectionError, match="'idle' is not connected; cannot call 'probe'"):
        _ = await connection.call_tool("probe", {})
    with pytest.raises(McpConnectionError, match="'idle' is not connected"):
        _ = await connection.refresh_catalog()
    with pytest.raises(McpConnectionError, match="'idle' is not connected"):
        await connection.subscribe_resource("features://notes/readme")
    with pytest.raises(McpConnectionError, match="'idle' is not connected"):
        await connection.unsubscribe_resource("features://notes/readme")
    with pytest.raises(McpConnectionError, match="'idle' is not connected"):
        _ = await connection.complete(prompt=True, reference="greet", argument="person", value="a")


def test_a_stream_end_from_a_replaced_attempt_is_ignored(tmp_path: Path) -> None:
    """Only the current attempt's end of stream marks the connection dropped.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("attempts"), private_resolver(tmp_path))
    attempt = cast("int", _private(connection, "_attempt"))
    _on_stream_closed(connection, attempt + 1)
    assert connection.status.last_error is None
    assert not _event(connection, "_dropped").is_set()
    _on_stream_closed(connection, attempt)
    assert connection.status.last_error == "the server closed the connection"
    assert _event(connection, "_dropped").is_set()


def test_the_first_reason_a_connection_dropped_is_kept(tmp_path: Path) -> None:
    """A second report of a drop does not overwrite the first reason, and a stopping connection records none.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("dropped"), private_resolver(tmp_path))
    _mark_dropped(connection, "first reason")
    _mark_dropped(connection, "second reason")
    assert connection.status.last_error == "first reason"

    stopping = McpConnection(_http_config("stopping"), private_resolver(tmp_path))
    _event(stopping, "_stop").set()
    _mark_dropped(stopping, "late reason")
    assert stopping.status.last_error is None
    assert not _event(stopping, "_dropped").is_set()


@pytest.mark.asyncio
async def test_a_transport_fault_delivered_to_the_message_handler_marks_the_connection_dropped(tmp_path: Path) -> None:
    """An exception the session tees to the message handler records the drop with the exception's type and text.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("faulted"), private_resolver(tmp_path))
    await _on_incoming(connection, ValueError("stream corrupted"))
    assert connection.status.last_error == "ValueError: stream corrupted"
    assert _event(connection, "_dropped").is_set()
    assert _event(connection, "_wake").is_set()


@pytest.mark.asyncio
async def test_listening_for_changes_on_a_server_that_is_not_connected_returns_at_once(tmp_path: Path) -> None:
    """Following changes on a connection with no client does nothing and installs no listener.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("not-listening"), private_resolver(tmp_path))
    await asyncio.wait_for(connection.listen_for_changes(lambda _server_id: None), timeout=5)
    assert _private(connection, "_on_change") is None


def test_start_listening_before_connecting_only_records_the_wish(tmp_path: Path) -> None:
    """Asking to follow changes with no connection starts no follower yet, but remembers to start one on connect.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("early"), private_resolver(tmp_path))
    connection.start_listening(lambda _server_id: None)
    assert _private(connection, "_follow_changes") is True
    assert _private(connection, "_listen_task") is None


def test_oauth_steps_are_left_alone_when_the_provider_has_no_handlers(tmp_path: Path) -> None:
    """A provider with no redirect or callback handler gets none from the connection's operator-time tracking.

    Args:
        tmp_path: Per-test directory.
    """
    spec = HttpServerSpec(url="http://127.0.0.1:9/mcp")
    storage = KeyringTokenStorage(
        CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env")),
        "oauth-probe",
        issuer_for(spec),
    )
    provider = OAuthClientProvider(server_url=spec.url, client_metadata=client_metadata(spec), storage=storage)
    connection = McpConnection(_http_config("oauth-probe"), private_resolver(tmp_path))
    _track_operator_steps(connection, provider)
    assert provider.context.redirect_handler is None
    assert provider.context.callback_handler is None


@pytest.mark.asyncio
async def test_a_supervisor_that_was_already_stopped_makes_no_attempt(tmp_path: Path) -> None:
    """Running the attempt loop on a connection whose stop is already requested returns without connecting.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("pre-stopped"), private_resolver(tmp_path))
    _event(connection, "_stop").set()
    await asyncio.wait_for(_supervise_attempts(connection), timeout=5)
    assert connection.status.health is McpHealth.DISCONNECTED


@pytest.mark.asyncio
async def test_a_failure_while_stopping_does_not_schedule_a_reconnect(tmp_path: Path) -> None:
    """An attempt that fails after a stop was requested ends the supervisor without scheduling another attempt.

    Args:
        tmp_path: Per-test directory.
    """
    stop = asyncio.Event()

    def factory(_resolved: McpServerConfig) -> NoReturn:
        """Request the stop, then fail the way an unreachable endpoint does.

        Args:
            _resolved: The resolved configuration.

        Raises:
            OSError: Always.
        """
        stop.set()
        message = "endpoint refused"
        raise OSError(message)

    connection = McpConnection(_http_config("refused"), private_resolver(tmp_path), auth_factory=factory)
    _assign(connection, "_stop", stop)
    with structlog.testing.capture_logs() as captured:
        await asyncio.wait_for(_supervise_attempts(connection), timeout=_TEARDOWN_TIMEOUT_S)
    names = _event_names(captured)
    assert "mcp_server_connection_failed" in names
    assert "mcp_server_reconnect_scheduled" not in names
    status = connection.status
    assert status.health is McpHealth.FAILED
    assert status.last_error == "OSError: endpoint refused"


@pytest.mark.asyncio
async def test_a_failure_that_is_not_an_ordinary_exception_unwinds_the_supervisor(tmp_path: Path) -> None:
    """A transport failure carrying a ``BaseException`` leaf propagates as that leaf instead of being recorded and retried.

    Args:
        tmp_path: Per-test directory.
    """
    leaf = _Interrupt("the interpreter is shutting down")

    def factory(_resolved: McpServerConfig) -> NoReturn:
        """Fail with a group that carries a non-ordinary leaf.

        Args:
            _resolved: The resolved configuration.

        Raises:
            BaseExceptionGroup: Always.
        """
        message = "task group failed"
        raise BaseExceptionGroup(message, [leaf])

    connection = McpConnection(_http_config("fatal"), private_resolver(tmp_path), auth_factory=factory)
    task = asyncio.create_task(_supervise_attempts(connection))
    try:
        _ = await asyncio.wait({task}, timeout=_TEARDOWN_TIMEOUT_S)
        assert task.done()
        assert task.exception() is leaf
        cause = leaf.__cause__
        assert isinstance(cause, BaseExceptionGroup)
        group = cast("BaseExceptionGroup[BaseException]", cause)
        assert group.exceptions == (leaf,)
    finally:
        _ = task.cancel()
        _ = await asyncio.wait({task})
    assert connection.status.health is McpHealth.CONNECTING


@pytest.mark.asyncio
async def test_abandoning_an_attempt_that_already_failed_logs_the_failure(tmp_path: Path) -> None:
    """Abandoning a connection whose supervisor task already died with an error records that error and resets the connection.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("abandoned"), private_resolver(tmp_path))

    async def crashed() -> None:
        """Fail at once.

        Raises:
            RuntimeError: Always.
        """
        await asyncio.sleep(0)
        message = "attempt crashed"
        raise RuntimeError(message)

    task = asyncio.create_task(crashed())
    _ = await asyncio.wait({task})
    _assign(connection, "_task", task)
    with structlog.testing.capture_logs() as captured:
        await _abandon(connection)
    failures = [entry for entry in captured if entry.get("event") == "mcp_server_abandoned_attempt_failed"]
    assert [entry.get("error") for entry in failures] == ["attempt crashed"]
    assert _private(connection, "_task") is None
    assert connection.status.health is McpHealth.DISCONNECTED


@pytest.mark.asyncio
async def test_stopping_a_follower_that_died_logs_why(tmp_path: Path) -> None:
    """A change follower that ended with an error is forgotten, and the error is logged.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("follower"), private_resolver(tmp_path))

    async def crashed() -> None:
        """Fail at once.

        Raises:
            RuntimeError: Always.
        """
        await asyncio.sleep(0)
        message = "follower crashed"
        raise RuntimeError(message)

    task = asyncio.create_task(crashed())
    _ = await asyncio.wait({task})
    _assign(connection, "_listen_task", task)
    with structlog.testing.capture_logs() as captured:
        await _stop_follower(connection)
    failures = [entry for entry in captured if entry.get("event") == "mcp_change_follower_failed"]
    assert [entry.get("error") for entry in failures] == ["follower crashed"]
    assert _private(connection, "_listen_task") is None


@pytest.mark.asyncio
async def test_disconnect_absorbs_a_teardown_that_fails(tmp_path: Path) -> None:
    """A ready connection whose supervisor fails while shutting down still disconnects, and the failure is logged.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("teardown-error"), private_resolver(tmp_path))

    async def failing() -> None:
        """Yield once, then fail.

        Raises:
            OSError: Always.
        """
        await asyncio.sleep(0)
        message = "teardown broke"
        raise OSError(message)

    task = asyncio.create_task(failing())
    _assign(connection, "_task", task)
    _assign(connection, "_health", McpHealth.READY)
    with structlog.testing.capture_logs() as captured:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)
    errors = [entry for entry in captured if entry.get("event") == "mcp_server_teardown_error"]
    assert [entry.get("error") for entry in errors] == ["teardown broke"]
    assert isinstance(task.exception(), OSError)
    assert connection.status.health is McpHealth.DISCONNECTED


@pytest.mark.asyncio
async def test_disconnect_cancels_a_teardown_that_overruns_its_budget(tmp_path: Path) -> None:
    """A ready connection whose supervisor does not finish within the teardown budget has it cancelled, and disconnect returns.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("overrun"), private_resolver(tmp_path))

    async def hangs() -> None:
        """Wait until cancelled."""
        _ = await asyncio.Event().wait()

    task = asyncio.create_task(hangs())
    _assign(connection, "_task", task)
    _assign(connection, "_health", McpHealth.READY)
    loop = asyncio.get_running_loop()
    started = loop.time()
    with structlog.testing.capture_logs() as captured:
        await connection.disconnect()
    elapsed = loop.time() - started
    assert elapsed >= DISCONNECT_TIMEOUT_S - 0.5
    assert "mcp_server_teardown_timeout" in _event_names(captured)
    assert task.cancelled()
    assert connection.status.health is McpHealth.DISCONNECTED


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_connecting_again_keeps_the_running_server(tmp_path: Path) -> None:
    """Connecting a connection that is already up returns at once and leaves the same server process serving it.

    Args:
        tmp_path: Per-test directory.
    """
    connection = _stdio_connection(tmp_path, "twice")
    await _connect(connection)
    try:
        first = int(await call_text(connection, "whoami"))
        await _connect(connection)
        second = int(await call_text(connection, "whoami"))
        assert connection.is_ready
    finally:
        await _disconnect(connection)
    assert first == second


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_listen_for_changes_follows_a_legacy_server_until_cancelled(tmp_path: Path) -> None:
    """Following changes through the public coroutine keeps running, re-lists on a change notice and reports it to the listener.

    Args:
        tmp_path: Per-test directory.
    """
    with network_server("sse") as (_process, port):
        connection = McpConnection(network_config("listen", port, McpTransportKind.SSE), private_resolver(tmp_path))
        changes: list[str] = []
        await _connect(connection)
        try:
            follower = asyncio.create_task(connection.listen_for_changes(changes.append))
            try:
                assert await call_text(connection, "grow") == _GROWN

                def has_grown() -> bool:
                    """Report whether the catalog lists the grown tool.

                    Returns:
                        bool: ``True`` once it does.
                    """
                    catalog = connection.catalog
                    return catalog is not None and catalog.entry_by_name(_GROWN) is not None

                assert await wait_until(has_grown, timeout_s=_RECOVERY_DEADLINE_S)
                assert changes == ["listen"]
                assert not follower.done()
            finally:
                _ = follower.cancel()
                _ = await asyncio.wait({follower})
            assert follower.cancelled()
        finally:
            await _disconnect(connection)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_start_listening_before_connecting_follows_the_connection_once(tmp_path: Path) -> None:
    """A follower requested before connecting starts when the server is ready, and asking again keeps that same follower.

    Args:
        tmp_path: Per-test directory.
    """
    with network_server("sse") as (_process, port):
        connection = McpConnection(network_config("early-follow", port, McpTransportKind.SSE), private_resolver(tmp_path))
        changes: list[str] = []
        connection.start_listening(changes.append)
        await _connect(connection)
        try:
            follower = _private(connection, "_listen_task")
            assert isinstance(follower, asyncio.Task)
            assert await call_text(connection, "grow") == _GROWN
            assert await wait_until(lambda: bool(changes), timeout_s=_RECOVERY_DEADLINE_S)
            connection.start_listening(changes.append)
            assert _private(connection, "_listen_task") is follower
            assert not follower.done()
        finally:
            await _disconnect(connection)
    assert changes[0] == "early-follow"


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_refresh_catalog_reports_a_timeout_and_a_cancellation_and_stays_usable(tmp_path: Path) -> None:
    """A re-list that cannot meet its deadline fails with a timeout, a cancelled re-list is not turned into an error, and the connection recovers.

    Args:
        tmp_path: Per-test directory.
    """
    connection = _stdio_connection(tmp_path, "relist")
    await _connect(connection)
    try:
        with _tiny_deadline(connection), pytest.raises(McpConnectionError, match="listing tools exceeded"):
            _ = await connection.refresh_catalog(force=True)
        task = asyncio.create_task(connection.refresh_catalog(force=True))
        await asyncio.sleep(0)
        _ = task.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await task
        catalog = await connection.refresh_catalog(force=True)
        assert catalog.tool_count == _LIFECYCLE_TOOL_COUNT
        assert connection.is_ready
    finally:
        await _disconnect(connection)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_vanished_modern_server_fails_its_liveness_probe(tmp_path: Path) -> None:
    """A probe sent to a server that already exited reports it gone, caused by the protocol's connection-closed error.

    Args:
        tmp_path: Per-test directory.
    """
    connection = _stdio_connection(tmp_path, "gone")
    await _connect(connection)
    try:
        client = connection.client
        assert client is not None
        _event(connection, "_dropped").set()
        assert await call_text(connection, "quit") == "leaving"
        assert await wait_until(lambda: _transport_closed(client), timeout_s=_RECOVERY_DEADLINE_S)
        with pytest.raises(McpConnectionError, match="stopped responding: Connection closed") as caught:
            _ = await _heartbeat(connection, client)
        cause = caught.value.__cause__
        assert isinstance(cause, MCPError)
        assert cause.code == CONNECTION_CLOSED
    finally:
        await _disconnect(connection)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_call_that_finds_the_connection_closed_wakes_the_supervisor(tmp_path: Path) -> None:
    """A tool call that fails because the connection is closed makes the supervisor rebuild it at once, not at the next probe.

    Args:
        tmp_path: Per-test directory.
    """
    connection = _stdio_connection(tmp_path, "woken")
    await _connect(connection)
    try:
        client = connection.client
        assert client is not None
        first = int(await call_text(connection, "whoami"))
        _event(connection, "_dropped").set()
        assert await call_text(connection, "quit") == "leaving"
        assert await wait_until(lambda: _transport_closed(client), timeout_s=_RECOVERY_DEADLINE_S)
        _event(connection, "_dropped").clear()
        with (
            structlog.testing.capture_logs() as captured,
            pytest.raises(McpConnectionError, match="call to 'whoami' failed: Connection closed"),
        ):
            _ = await connection.call_tool("whoami", {})
        faults = [str(entry.get("error")) for entry in captured if entry.get("event") == "mcp_transport_fault"]
        assert faults == ["call to 'whoami' found the connection closed: Connection closed"]
        assert await wait_until(lambda: _replaced(connection, first), timeout_s=_RECOVERY_DEADLINE_S)
    finally:
        await _disconnect(connection)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_legacy_server_is_probed_with_ping_and_requests_honor_a_spent_deadline(tmp_path: Path) -> None:
    """On 2025-11-25 the probe is a ping that succeeds, and every request that cannot meet its deadline fails or is logged as a timeout.

    Args:
        tmp_path: Per-test directory.
    """
    async with features_connection(tmp_path, Era.LEGACY, log_level="info") as connection:
        client = connection.client
        assert client is not None
        assert client.protocol_version not in MODERN_PROTOCOL_VERSIONS
        assert await _heartbeat(connection, client) is True
        await connection.subscribe_resource(_PROBE_URI)
        assert connection.subscriptions == frozenset({_PROBE_URI})
        with structlog.testing.capture_logs() as captured, _tiny_deadline(connection):
            with pytest.raises(McpConnectionError, match="no answer to the liveness probe"):
                _ = await _heartbeat(connection, client)
            await _apply_log_level(connection, client)
            await _restore_subscriptions(connection, client)
            with pytest.raises(McpConnectionError, match="subscribing to 'features://notes/other' timed out"):
                await connection.subscribe_resource(_OTHER_URI)
            with pytest.raises(McpConnectionError, match="unsubscribing from 'features://notes/readme' timed out"):
                await connection.unsubscribe_resource(_PROBE_URI)
        names = _event_names(captured)
        assert "mcp_log_level_timed_out" in names
        assert "mcp_resource_resubscribe_timed_out" in names
        assert connection.subscriptions == frozenset({_PROBE_URI})
        await connection.unsubscribe_resource(_PROBE_URI)
        assert connection.subscriptions == frozenset()


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_requests_to_a_legacy_server_that_vanished_fail_with_connection_errors(tmp_path: Path) -> None:
    """With the server gone before the supervisor reacts, each request fails as a connection error caused by ``CONNECTION_CLOSED``.

    Args:
        tmp_path: Per-test directory.
    """
    with _features_sse_process() as (process, port):
        config = features_config(Era.LEGACY, server_id="vanishing", port=port, log_level="info")
        connection = McpConnection(config, private_resolver(tmp_path))
        await _connect(connection)
        try:
            client = connection.client
            assert client is not None
            await connection.subscribe_resource(_PROBE_URI)
            _event(connection, "_dropped").set()
            process.terminate()
            _ = process.wait(timeout=10)
            assert await wait_until(lambda: _transport_closed(client), timeout_s=_RECOVERY_DEADLINE_S)

            with structlog.testing.capture_logs() as captured:
                await _apply_log_level(connection, client)
                await _restore_subscriptions(connection, client)
            logged = {str(entry.get("event")): str(entry.get("error")) for entry in captured}
            assert logged["mcp_log_level_refused"] == "Connection closed"
            assert logged["mcp_resource_resubscribe_refused"] == "Connection closed"

            with pytest.raises(McpConnectionError, match="cannot subscribe to 'features://notes/other': Connection closed") as subscribing:
                await connection.subscribe_resource(_OTHER_URI)
            assert isinstance(subscribing.value.__cause__, MCPError)
            assert subscribing.value.__cause__.code == CONNECTION_CLOSED
            with pytest.raises(McpConnectionError, match="cannot unsubscribe from 'features://notes/readme': Connection closed"):
                await connection.unsubscribe_resource(_PROBE_URI)
            with pytest.raises(McpConnectionError, match="cannot list tools: Connection closed"):
                _ = await connection.refresh_catalog(force=True)
            assert connection.subscriptions == frozenset({_PROBE_URI})
        finally:
            await _disconnect(connection)


@pytest.mark.asyncio
async def test_starting_an_unconfigured_server_and_stopping_one_that_is_not_running(tmp_path: Path) -> None:
    """Starting a server nobody configured is refused by name; stopping or re-levelling one that is not running does nothing.

    Args:
        tmp_path: Per-test directory.
    """
    manager = _manager(tmp_path, [], approving_gate(tmp_path / "trust.json"))
    with pytest.raises(McpConnectionError, match="no MCP server named 'ghost' is configured"):
        _ = await manager.start_server("ghost")
    assert manager.connection("ghost") is None
    await manager.stop_server("ghost")
    await manager.set_log_level("ghost", "debug")
    assert manager.statuses() == []
    assert manager.ready_connections() == []


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_starting_a_running_server_again_replaces_its_connection_once(tmp_path: Path) -> None:
    """A second start of a running server tears the first connection down and registers one new connection, counted once.

    Args:
        tmp_path: Per-test directory.
    """
    with network_server("http") as (_process, port):
        config = network_config("restarted", port, McpTransportKind.HTTP)
        manager = _manager(tmp_path, [config], approving_gate(tmp_path / "trust.json"))
        try:
            first_status = await manager.start_server("restarted")
            first = manager.connection("restarted")
            assert first is not None
            second_status = await manager.start_server("restarted")
            second = manager.connection("restarted")
            assert second is not None
            assert second is not first
            assert first.status.health is McpHealth.DISCONNECTED
            assert first_status.health is McpHealth.READY
            assert second_status.health is McpHealth.READY
            assert second_status.tool_count == _LIFECYCLE_TOOL_COUNT
            assert manager.ready_connections() == [second]
        finally:
            await manager.stop()


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_the_manager_hears_connection_changes_and_survives_a_failing_listener(tmp_path: Path) -> None:
    """Every running connection reports its changes to the manager's listener, and a listener that raises does not break the connection.

    Args:
        tmp_path: Per-test directory.
    """
    with network_server("http") as (_process, port):
        config = network_config("heard", port, McpTransportKind.HTTP)
        manager = _manager(tmp_path, [config], approving_gate(tmp_path / "trust.json"))
        try:
            _ = await manager.start_server("heard")
            connection = manager.connection("heard")
            assert connection is not None
            heard: list[str] = []
            manager.set_change_listener(heard.append)
            await connection.disconnect()
            assert heard == ["heard"]

            raised: list[str] = []

            def failing(server_id: str) -> None:
                """Record the call, then fail.

                Args:
                    server_id: The server that changed.

                Raises:
                    RuntimeError: Always.
                """
                raised.append(server_id)
                message = "listener broke"
                raise RuntimeError(message)

            manager.set_change_listener(failing)
            with structlog.testing.capture_logs() as captured:
                await connection.disconnect()
            assert raised == ["heard"]
            failures = [entry for entry in captured if entry.get("event") == "mcp_manager_listener_failed"]
            assert [entry.get("error") for entry in failures] == ["listener broke"]
        finally:
            await manager.stop()


@pytest.mark.asyncio
async def test_a_failing_connection_listener_is_absorbed(tmp_path: Path) -> None:
    """A change listener that raises does not stop a connection from disconnecting.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("noisy"), private_resolver(tmp_path))
    calls: list[str] = []

    def failing(server_id: str) -> None:
        """Record the call, then fail.

        Args:
            server_id: The server that changed.

        Raises:
            ValueError: Always.
        """
        calls.append(server_id)
        message = "listener refused"
        raise ValueError(message)

    connection.set_change_listener(failing)
    with structlog.testing.capture_logs() as captured:
        await connection.disconnect()
    assert calls == ["noisy"]
    failures = [entry for entry in captured if entry.get("event") == "mcp_change_listener_failed"]
    assert [entry.get("error") for entry in failures] == ["listener refused"]
    assert connection.status.health is McpHealth.DISCONNECTED


@pytest.mark.asyncio
async def test_start_server_goes_on_when_the_trust_file_cannot_be_saved(tmp_path: Path) -> None:
    """An unreadable trust file does not stop the identity check from being logged, and the file is never overwritten.

    Args:
        tmp_path: Per-test directory.
    """
    trust = tmp_path / "trust.json"
    trust.write_text("{not json", encoding="utf-8")
    manager = _manager(tmp_path, [stdio_config("unsaved")], McpConsentGate(TrustStore(trust), deny_all_launches))
    try:
        with structlog.testing.capture_logs() as captured, pytest.raises(McpConnectionError) as caught:
            _ = await manager.start_server("unsaved")
        assert "cannot save the change to" in str(caught.value)
        assert "mcp_identity_check_unsaved" in _event_names(captured)
        assert trust.read_text(encoding="utf-8") == "{not json"
    finally:
        await manager.stop()


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_test_connection_reports_the_real_tool_count_and_leaves_nothing_running(tmp_path: Path) -> None:
    """Trying a candidate server reports the tools it published, registers no connection, and tears the probe down.

    Args:
        tmp_path: Per-test directory.
    """
    manager = _manager(tmp_path, [], approving_gate(tmp_path / "trust.json"))
    status = await asyncio.wait_for(manager.test_connection(stdio_config("candidate")), timeout=_CONNECT_TIMEOUT_S)
    assert status.server_id == "candidate"
    assert status.health is McpHealth.READY
    assert status.tool_count == _LIFECYCLE_TOOL_COUNT
    assert manager.connection("candidate") is None
    assert manager.ready_connections() == []


@pytest.mark.asyncio
async def test_test_connection_reports_a_refused_launch_as_a_failed_status(tmp_path: Path) -> None:
    """A candidate whose launch the operator refuses comes back as a failed status carrying the reason, not as an exception.

    Args:
        tmp_path: Per-test directory.
    """
    gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), deny_all_launches)
    manager = _manager(tmp_path, [], gate)
    status = await manager.test_connection(stdio_config("refused-candidate"))
    assert status.server_id == "refused-candidate"
    assert status.health is McpHealth.FAILED
    assert status.tool_count == 0
    assert status.last_error is not None
    assert "was not approved" in status.last_error


@pytest.mark.asyncio
async def test_cancelling_test_connection_while_a_prompt_is_open_cancels_the_prompt(tmp_path: Path) -> None:
    """Cancelling a candidate's probe while its launch prompt is open propagates the cancellation and withdraws the prompt.

    Args:
        tmp_path: Per-test directory.
    """
    prompt = _HeldPrompt()
    manager = _manager(tmp_path, [], McpConsentGate(TrustStore(tmp_path / "trust.json"), prompt))
    task = asyncio.create_task(manager.test_connection(stdio_config("held-candidate")))
    _ = await asyncio.wait_for(prompt.opened.wait(), timeout=_TEARDOWN_TIMEOUT_S)
    _ = task.cancel()
    with pytest.raises(asyncio.CancelledError):
        _ = await task
    assert prompt.cancelled


@pytest.mark.asyncio
async def test_connecting_a_denied_server_raises_the_denial_itself(tmp_path: Path) -> None:
    """A refused launch is raised as the consent denial, not as a generic connection error.

    Args:
        tmp_path: Per-test directory.
    """
    gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), deny_all_launches)
    connection = McpConnection(stdio_config("denied"), private_resolver(tmp_path), consent=gate)
    try:
        with pytest.raises(McpConsentDeniedError, match="was not approved"):
            await _connect(connection)
    finally:
        await _disconnect(connection)


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_cancelling_a_manager_stop_mid_teardown_propagates_and_finishes_the_server(tmp_path: Path) -> None:
    """A stop cancelled while a server is still shutting down raises the cancellation, and the server's own teardown still completes.

    Args:
        tmp_path: Per-test directory.
    """
    config = stdio_config("lingering", extra_args=("--linger-s", "30"))
    manager = _manager(tmp_path, [config], approving_gate(tmp_path / "trust.json"))
    await asyncio.wait_for(manager.start(), timeout=_CONNECT_TIMEOUT_S)
    connection = manager.connection("lingering")
    assert connection is not None
    assert connection.is_ready
    supervisor = cast("asyncio.Task[None]", _private(connection, "_task"))
    assert isinstance(supervisor, asyncio.Task)
    stopper = asyncio.create_task(manager.stop())
    try:
        assert await wait_until(lambda: _event(connection, "_stop").is_set(), timeout_s=_TEARDOWN_TIMEOUT_S)
        _ = stopper.cancel()
        with pytest.raises(asyncio.CancelledError):
            _ = await stopper
    finally:
        _ = await asyncio.wait({supervisor}, timeout=_TEARDOWN_TIMEOUT_S)
    assert supervisor.done()
