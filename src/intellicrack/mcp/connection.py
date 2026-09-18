# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live connections to configured Model Context Protocol servers.

A connection is owned by a supervisor task that enters the SDK client, fetches
the tool listing, publishes itself as ready, and then waits. Entering and
leaving the client inside one task is not incidental: the SDK's transports are
built on ``anyio`` task groups, whose cancel scopes must be unwound by the task
that created them. Tool calls are issued from whatever task needs them and go
through the session's dispatcher, which is designed for concurrent use.

Connections are app-lifetime rather than conversation-lifetime. A stdio server
is a process, not a session, so tearing one down between conversations would
pay a process start on every turn and discard whatever state the server had
built up.

This package stays free of Qt so it can be imported headless. Callers inside
the GUI dispatch these coroutines onto the persistent background loop from
``intellicrack.ui.panels.async_bridge``, and every coroutine belonging to one
manager must run on that single loop.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import os
import threading
from collections import deque
from collections.abc import Callable
from contextlib import ExitStack, asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, TextIO, cast

import psutil
from mcp import Client
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError
from mcp_types import METHOD_NOT_FOUND, Implementation

from intellicrack._metadata import __version__
from intellicrack.core.logging import get_logger
from intellicrack.mcp.catalog import McpToolCatalog, fetch_catalog
from intellicrack.mcp.config import McpConfigStore, McpServerConfig, McpTransportKind
from intellicrack.mcp.errors import McpConnectionError, McpConsentDeniedError, McpError
from intellicrack.mcp.sandbox_launch import SandboxedJob, build_sandboxed_startup, sandbox_supported
from intellicrack.mcp.transport import build_stdio_parameters, load_env_file, open_http_transport


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    import httpx2
    from mcp.client.session import ElicitationFnT
    from mcp_types import CallToolResult

    from intellicrack.mcp.config import McpConfigDocument
    from intellicrack.mcp.consent import McpConsentGate
    from intellicrack.mcp.secrets import McpSecretResolver


_logger = get_logger(__name__)


AuthFactory = Callable[["McpServerConfig"], "httpx2.Auth | None"]
"""Builds the authentication handler for one HTTP server, or ``None``."""

CLIENT_NAME: Final[str] = "Intellicrack"
"""Client identity sent to every server during the handshake."""

STDERR_RING_LINES: Final[int] = 2000
"""Lines of a local server's stderr kept for diagnosis."""

STDERR_LINE_MAX_CHARS: Final[int] = 4096
"""Longest stderr line kept intact, past which it is truncated."""

BACKOFF_BASE_S: Final[float] = 1.0
"""First reconnect delay."""

BACKOFF_FACTOR: Final[float] = 2.0
"""Multiplier applied to the reconnect delay after each failure."""

BACKOFF_MAX_S: Final[float] = 60.0
"""Ceiling on the reconnect delay."""

MAX_RECONNECT_ATTEMPTS: Final[int] = 8
"""Consecutive failures after which a server stops retrying by itself."""

CONNECT_TIMEOUT_S: Final[float] = 45.0
"""How long a first connection and tool listing may take."""

DISCONNECT_TIMEOUT_S: Final[float] = 10.0
"""How long a graceful teardown may take before the task is cancelled."""

STDERR_JOIN_TIMEOUT_S: Final[float] = 2.0
"""How long to wait for the stderr reader thread to finish."""

SANDBOX_ADOPT_TIMEOUT_S: Final[float] = 10.0
"""How long to look for a sandboxed child before giving up on confining it."""

SANDBOX_ADOPT_POLL_S: Final[float] = 0.05
"""How often to re-check for the sandboxed child while waiting for it."""

HEARTBEAT_INTERVAL_S: Final[float] = 15.0
"""How often a live connection pings its server.

A local server that exits cleanly closes its pipes without raising anything:
the transport's reader simply reaches EOF and stops. Nothing would notice
until the next tool call, which would then fail in front of the model. The
heartbeat turns that silent death into a prompt reconnect instead.
"""

TRANSPORT_FAILURES: Final[tuple[type[BaseException], ...]] = (
    OSError,
    RuntimeError,
    ValueError,
    TimeoutError,
    MCPError,
    McpError,
    BaseExceptionGroup,
)
"""Everything a transport can fail with.

``BaseExceptionGroup`` is in the tuple because the SDK's transports are built
on ``anyio`` task groups, which report a child task's failure as a group even
when only one task failed. Catching the leaf types alone would let a dropped
connection escape as an unhandled task exception.
"""


def failure_leaves(exc: BaseException) -> list[BaseException]:
    """Flatten an exception, or a nest of exception groups, into its leaves.

    Args:
        exc: The exception a transport raised.

    Returns:
        list[BaseException]: Every non-group exception it carries, in order.
    """
    if isinstance(exc, BaseExceptionGroup):
        group = cast("BaseExceptionGroup[BaseException]", exc)
        flattened: list[BaseException] = []
        for nested in group.exceptions:
            flattened.extend(failure_leaves(nested))
        return flattened
    return [exc]


def representative_failure(exc: BaseException) -> BaseException:
    """Pick the one leaf that best explains a transport failure.

    A protocol-level error says more than the plumbing error wrapping it, so
    it wins; otherwise the first leaf stands for the whole group.

    Args:
        exc: The exception a transport raised.

    Returns:
        BaseException: The leaf to report, or ``exc`` when it carries none.
    """
    leaves = failure_leaves(exc)
    if not leaves:
        return exc
    return next((leaf for leaf in leaves if isinstance(leaf, McpError | MCPError)), leaves[0])


def fatal_leaf(exc: BaseException) -> BaseException | None:
    """Find a leaf that must not be treated as an ordinary failure.

    Cancellation and interpreter shutdown travel as ``BaseException`` and can
    be carried inside a task group's report. Swallowing one would turn a
    cancelled teardown into a reconnect loop.

    Args:
        exc: The exception a transport raised.

    Returns:
        BaseException | None: The first leaf that is not an ordinary
        ``Exception``, or ``None`` when every leaf is one.
    """
    return next((leaf for leaf in failure_leaves(exc) if not isinstance(leaf, Exception)), None)


class McpHealth(enum.Enum):
    """Where a configured server currently stands.

    Attributes:
        DISCONNECTED: Enabled, but not currently connected.
        CONNECTING: A connection attempt is in flight.
        READY: Connected, with a tool listing in hand.
        FAILED: The last attempt failed. ``last_error`` says why.
        DISABLED: Turned off in configuration; nothing is attempted.
    """

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    READY = "ready"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class McpServerStatus:
    """A snapshot of one server's state, safe to hand to the UI.

    Attributes:
        server_id: The server's configured id.
        health: Where the server stands.
        tool_count: Tools in the current listing, zero when not connected.
        generation: Digest of the current listing, or ``None``.
        last_error: Why the last attempt failed, or ``None``.
        connected_at: When the current connection was established, or
            ``None``.
    """

    server_id: str
    health: McpHealth
    tool_count: int = 0
    generation: str | None = None
    last_error: str | None = None
    connected_at: datetime | None = None


@dataclass
class _StderrCapture:
    """An OS pipe whose contents are collected into a bounded ring buffer.

    A child process writes to a real file descriptor, so the capture cannot
    be a Python object alone. The write end is handed to the SDK as the
    server's ``errlog`` and a reader thread drains the read end, which means
    the diagnostic output survives the process that produced it -- exactly
    the case where it matters.

    Attributes:
        lines: The most recent lines the child wrote.
    """

    lines: deque[str] = field(default_factory=lambda: deque(maxlen=STDERR_RING_LINES))
    _write_handle: TextIO | None = field(default=None, repr=False)
    _read_handle: TextIO | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def open(self) -> TextIO:
        """Create the pipe and start draining it.

        Returns:
            TextIO: The writable end, to be passed to the SDK as ``errlog``.

        Raises:
            McpConnectionError: If the pipe cannot be created.
        """
        try:
            read_fd, write_fd = os.pipe()
            self._read_handle = os.fdopen(read_fd, encoding="utf-8", errors="replace", newline="")
            self._write_handle = os.fdopen(write_fd, "w", encoding="utf-8", errors="replace", buffering=1)
        except OSError as exc:
            message = f"cannot create a stderr pipe for the server process: {exc}"
            raise McpConnectionError(message) from exc
        self._thread = threading.Thread(target=self._drain, name="mcp-stderr", daemon=True)
        self._thread.start()
        return self._write_handle

    def _drain(self) -> None:
        """Read the pipe until it closes, keeping the most recent lines."""
        handle = self._read_handle
        if handle is None:
            return
        try:
            for raw_line in handle:
                line = raw_line.rstrip("\r\n")
                if len(line) > STDERR_LINE_MAX_CHARS:
                    line = f"{line[:STDERR_LINE_MAX_CHARS]}... [truncated]"
                with self._lock:
                    self.lines.append(line)
        except (OSError, ValueError):
            _logger.debug("mcp_stderr_reader_closed")

    def tail(self, limit: int) -> list[str]:
        """Return the most recent captured lines.

        Args:
            limit: Maximum number of lines to return.

        Returns:
            list[str]: Up to ``limit`` lines, oldest first.
        """
        with self._lock:
            captured = list(self.lines)
        return captured[-limit:] if limit > 0 else []

    def close(self) -> None:
        """Close both ends of the pipe and stop the reader thread."""
        write_handle = self._write_handle
        self._write_handle = None
        if write_handle is not None:
            with suppress(OSError, ValueError):
                write_handle.close()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=STDERR_JOIN_TIMEOUT_S)
        read_handle = self._read_handle
        self._read_handle = None
        if read_handle is not None:
            with suppress(OSError, ValueError):
                read_handle.close()
        self._thread = None


def build_client_info() -> Implementation:
    """Build the client identity announced to every server.

    Returns:
        Implementation: Intellicrack's name and version.
    """
    return Implementation(name=CLIENT_NAME, title=CLIENT_NAME, version=__version__)


def reconnect_delay(attempt: int) -> float:
    """Compute the delay before one reconnect attempt.

    Args:
        attempt: Zero-based index of the attempt about to be made.

    Returns:
        float: Seconds to wait, capped at :data:`BACKOFF_MAX_S`.
    """
    return min(BACKOFF_BASE_S * (BACKOFF_FACTOR**attempt), BACKOFF_MAX_S)


class McpConnection:
    """One configured server, its transport, and its current tool listing.

    A connection is inert until :meth:`connect` is awaited. It then owns a
    supervisor task that keeps the SDK client entered, reconnecting with
    bounded backoff when the server drops, until :meth:`disconnect` is
    awaited.
    """

    def __init__(
        self,
        config: McpServerConfig,
        resolver: McpSecretResolver,
        *,
        client_info: Implementation | None = None,
        elicitation_callback: ElicitationFnT | None = None,
        consent: McpConsentGate | None = None,
        auth_factory: AuthFactory | None = None,
    ) -> None:
        """Initialize the connection.

        Args:
            config: The server to connect to.
            resolver: Resolver expanding ``${input:id}`` references.
            client_info: Client identity sent during the handshake,
                defaulting to Intellicrack's own.
            elicitation_callback: Handler for server elicitation requests, or
                ``None`` to decline them.
            consent: Gate consulted before a local server is spawned. Without
                one, a local server is never started.
            auth_factory: Builds the ``httpx2`` authentication handler for an
                HTTP server, or ``None`` for unauthenticated access.
        """
        self._config = config
        self._resolver = resolver
        self._client_info = client_info if client_info is not None else build_client_info()
        self._elicitation_callback = elicitation_callback
        self._consent = consent
        self._auth_factory = auth_factory

        self._client: Client | None = None
        self._catalog: McpToolCatalog | None = None
        self._stderr = _StderrCapture()
        self._health = McpHealth.DISABLED if not config.enabled else McpHealth.DISCONNECTED
        self._last_error: str | None = None
        self._failure: BaseException | None = None
        self._connected_at: datetime | None = None
        self._task: asyncio.Task[None] | None = None
        self._listen_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._settled = asyncio.Event()
        self._call_lock = asyncio.Lock()
        self._dropped = asyncio.Event()
        self._wake = asyncio.Event()
        self._heartbeat_supported = True
        self._on_change: Callable[[str], None] | None = None

    @property
    def config(self) -> McpServerConfig:
        """The configuration this connection was built from.

        Returns:
            McpServerConfig: The server configuration.
        """
        return self._config

    @property
    def server_id(self) -> str:
        """The configured server id.

        Returns:
            str: The server id.
        """
        return self._config.server_id

    @property
    def namespace(self) -> str:
        """The tool namespace this server owns.

        Returns:
            str: ``mcp-<server_id>``.
        """
        return self._config.namespace

    @property
    def status(self) -> McpServerStatus:
        """A snapshot of this connection's current state.

        Returns:
            McpServerStatus: The snapshot.
        """
        return McpServerStatus(
            server_id=self._config.server_id,
            health=self._health,
            tool_count=self._catalog.tool_count if self._catalog is not None else 0,
            generation=self._catalog.generation if self._catalog is not None else None,
            last_error=self._last_error,
            connected_at=self._connected_at,
        )

    @property
    def client(self) -> Client | None:
        """The entered SDK client, while the connection is up.

        Returns:
            Client | None: The client, or ``None`` when the server is not
            connected. Requests issued through it from another task are
            dispatched by the session, which is designed for concurrent use.
        """
        return self._client

    @property
    def catalog(self) -> McpToolCatalog | None:
        """The tool listing currently in hand.

        Returns:
            McpToolCatalog | None: The listing, or ``None`` when the server
            has never completed a connection.
        """
        return self._catalog

    @property
    def is_ready(self) -> bool:
        """Whether the server is connected and has published its tools.

        Returns:
            bool: ``True`` when calls can be dispatched.
        """
        return self._health is McpHealth.READY and self._client is not None

    def stderr_tail(self, limit: int = 200) -> list[str]:
        """Return the most recent lines a local server wrote to stderr.

        Args:
            limit: Maximum number of lines to return.

        Returns:
            list[str]: Up to ``limit`` lines, oldest first. Empty for an HTTP
            server, which has no child process.
        """
        return self._stderr.tail(limit)

    def set_change_listener(self, listener: Callable[[str], None] | None) -> None:
        """Install the callback invoked when this server's tool listing moves.

        Args:
            listener: Callable receiving the server id, or ``None`` to
                remove the current listener.
        """
        self._on_change = listener

    async def resolved_environment(self) -> dict[str, str]:
        """Build the environment a local server would be launched with.

        The file named by ``envFile`` is read first and the inline ``env``
        entries are merged over it, so an inline entry always wins.

        Returns:
            dict[str, str]: Fully resolved environment entries.

        Raises:
            McpConnectionError: If the server is not a local one.
        """
        if self._config.stdio is None:
            message = f"server '{self.server_id}' is not a local server"
            raise McpConnectionError(message)
        from_file: dict[str, str] = {}
        if self._config.stdio.env_file is not None:
            from_file = load_env_file(Path(self._config.stdio.env_file))
        inline = await self._resolver.resolve_mapping(self._config.stdio.env)
        return {**from_file, **inline}

    @asynccontextmanager
    async def _open_transport(self) -> AsyncGenerator[Client]:
        """Open the SDK client for this server's transport.

        Yields:
            Client: An entered client, ready to issue requests.

        Raises:
            McpConnectionError: If the transport kind has no implementation.
        """
        if self._config.kind is McpTransportKind.STDIO:
            async with self._open_stdio_client() as client:
                yield client
            return
        if self._config.is_http:
            async with self._open_http_client() as client:
                yield client
            return
        message = f"server '{self.server_id}': transport {self._config.kind.value!r} is not supported"
        raise McpConnectionError(message)

    @asynccontextmanager
    async def _open_stdio_client(self) -> AsyncGenerator[Client]:
        """Spawn a local server and open a client over its stdio streams.

        Teardown is the SDK's: closing the transport closes stdin, waits out
        the grace period, and then terminates the whole process tree -- on
        Windows through the job object the child was spawned into, so a
        server that started children of its own leaves none behind.

        Yields:
            Client: An entered client.

        Raises:
            McpConnectionError: If the server has no launch description or
                no consent gate is available to ask.
        """
        spec = self._config.stdio
        if spec is None:
            message = f"server '{self.server_id}' has no launch command"
            raise McpConnectionError(message)

        env = await self.resolved_environment()
        if self._consent is None:
            message = (
                f"server '{self.server_id}' is a local program and needs your approval before it can start, "
                f"but no consent prompt is available in this process."
            )
            raise McpConnectionError(message)
        await self._consent.ensure_launch_consent(self._config, env)

        sandbox = self._config.sandbox
        launch_spec = spec
        if sandbox.enabled:
            if not sandbox_supported():
                message = (
                    f"server '{self.server_id}' is configured to run sandboxed, which Intellicrack implements "
                    f"with Windows job objects. Refusing to start it unconfined on this platform."
                )
                raise McpConnectionError(message)
            confined = build_sandboxed_startup(spec, sandbox, env)
            env = dict(confined.env)
            launch_spec = replace(spec, cwd=confined.cwd)

        parameters = build_stdio_parameters(launch_spec, env)
        errlog = self._stderr.open()
        _logger.info(
            "mcp_stdio_server_starting",
            server_id=self.server_id,
            command=parameters.command,
            argument_count=len(parameters.args),
            sandboxed=sandbox.enabled,
        )
        known_children: frozenset[int] = _child_pids() if sandbox.enabled else frozenset()
        try:
            with ExitStack() as guards:
                job = guards.enter_context(SandboxedJob(sandbox)) if sandbox.enabled else None
                async with (
                    stdio_client(parameters, errlog=errlog) as streams,
                    Client(
                        _StreamPairTransport(streams),
                        client_info=self._client_info,
                        elicitation_callback=self._elicitation_callback,
                        message_handler=self._on_incoming,
                        read_timeout_seconds=self._config.request_timeout_s,
                    ) as client,
                ):
                    if job is not None:
                        await self._confine_child(job, parameters.command, known_children)
                    yield client
        finally:
            self._stderr.close()

    @asynccontextmanager
    async def _open_http_client(self) -> AsyncGenerator[Client]:
        """Open a client against a remote HTTP server.

        Yields:
            Client: An entered client.

        Raises:
            McpConnectionError: If the server has no endpoint configured.
        """
        spec = self._config.http
        if spec is None:
            message = f"server '{self.server_id}' has no endpoint URL"
            raise McpConnectionError(message)

        headers = await self._resolver.resolve_mapping(spec.headers)
        query = await self._resolver.resolve_mapping(spec.query)
        resolved = McpServerConfig(
            server_id=self._config.server_id,
            kind=self._config.kind,
            http=type(spec)(
                url=spec.url,
                headers=headers,
                query=query,
                oauth_client_id=spec.oauth_client_id,
                oauth_metadata_url=spec.oauth_metadata_url,
            ),
            enabled=self._config.enabled,
            disabled_tools=self._config.disabled_tools,
            sandbox=self._config.sandbox,
            request_timeout_s=self._config.request_timeout_s,
        )
        auth = self._auth_factory(resolved) if self._auth_factory is not None else None

        http_spec = resolved.http
        if http_spec is None:
            message = f"server '{self.server_id}' has no endpoint URL"
            raise McpConnectionError(message)

        async with (
            open_http_transport(
                http_spec,
                headers=headers,
                auth=auth,
                timeout_s=self._config.request_timeout_s,
            ) as streams,
            Client(
                _StreamPairTransport(streams),
                client_info=self._client_info,
                elicitation_callback=self._elicitation_callback,
                message_handler=self._on_incoming,
                read_timeout_seconds=self._config.request_timeout_s,
            ) as client,
        ):
            yield client

    async def _confine_child(self, job: SandboxedJob, command: str, known: frozenset[int]) -> None:
        """Place the server process this launch just started into its job.

        The SDK owns the spawn and does not report the child's identity, so
        the new process is found by diffing this process's children around
        the spawn. When it cannot be found the launch is abandoned rather
        than continued unconfined: an operator who asked for a sandbox and
        silently did not get one is worse off than one whose server refused
        to start.

        Args:
            job: The open job the child belongs in.
            command: The launch command, used to recognise the child.
            known: Child process ids that existed before the spawn.

        Raises:
            McpConnectionError: If the child could not be identified or
                could not be confined.
        """
        expected = Path(command).stem.lower()
        deadline = asyncio.get_running_loop().time() + SANDBOX_ADOPT_TIMEOUT_S
        while asyncio.get_running_loop().time() < deadline:
            candidates = [pid for pid in _child_pids() - known if _process_matches(pid, expected)]
            if len(candidates) == 1:
                try:
                    job.adopt(candidates[0])
                except (McpError, OSError) as exc:
                    message = f"server '{self.server_id}': the sandbox could not confine the server process: {exc}"
                    raise McpConnectionError(message) from exc
                return
            await asyncio.sleep(SANDBOX_ADOPT_POLL_S)
        message = (
            f"server '{self.server_id}': the sandbox could not identify the server process it just started, "
            f"so it cannot confine it. Refusing to leave the server running unconfined."
        )
        raise McpConnectionError(message)

    async def _serve_once(self) -> None:
        """Hold one connection open until a stop is requested.

        A tool listing that cannot be retrieved propagates
        :class:`McpConnectionError` from :func:`fetch_catalog`.
        """
        async with self._open_transport() as client:
            catalog = await fetch_catalog(client, self.server_id)
            self._client = client
            self._catalog = catalog
            self._connected_at = datetime.now(tz=UTC)
            self._last_error = None
            self._health = McpHealth.READY
            self._settled.set()
            _logger.info(
                "mcp_server_ready",
                server_id=self.server_id,
                tool_count=catalog.tool_count,
                generation=catalog.generation,
            )
            self._notify_change()
            try:
                await self._hold_open(client)
            finally:
                self._client = None

    async def _on_incoming(self, message: object) -> None:
        """Record a transport-level fault the session surfaced.

        The session tees transport exceptions here as well as the server
        notifications it parses. An exception means the connection is gone,
        which wakes the supervisor immediately instead of waiting for the
        next heartbeat.

        Args:
            message: A server notification, or the exception the transport
                raised.
        """
        if isinstance(message, Exception):
            self._last_error = f"{type(message).__name__}: {message}"
            self._dropped.set()
            self._wake.set()
            _logger.warning("mcp_transport_fault", server_id=self.server_id, error=self._last_error)

    async def _hold_open(self, client: Client) -> None:
        """Keep a ready connection open, watching that it stays alive.

        Args:
            client: The entered client for this connection.

        Raises:
            McpConnectionError: If the transport reported a fault, or the
                heartbeat found the server gone.
        """
        while True:
            with suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=HEARTBEAT_INTERVAL_S)
            if self._stop.is_set():
                return
            if self._dropped.is_set():
                detail = self._last_error or "the transport reported a fault"
                message = f"server '{self.server_id}' connection dropped: {detail}"
                raise McpConnectionError(message)
            self._wake.clear()
            if not self._heartbeat_supported:
                continue
            await self._heartbeat(client)

    async def _heartbeat(self, client: Client) -> None:
        """Ping the server once to confirm the connection is still alive.

        A server that answers with "method not found" simply does not
        implement ping; heartbeats are switched off for that connection
        rather than treating the refusal as a death.

        Args:
            client: The entered client for this connection.

        Raises:
            McpConnectionError: If the ping could not be delivered, which
                means the server is gone.
            asyncio.CancelledError: If the supervisor is cancelled mid-ping.
        """
        try:
            _ = await client.session.send_ping()
        except asyncio.CancelledError:
            raise
        except MCPError as exc:
            if exc.code == METHOD_NOT_FOUND:
                self._heartbeat_supported = False
                _logger.debug("mcp_heartbeat_unsupported", server_id=self.server_id)
                return
            message = f"server '{self.server_id}' stopped responding: {exc}"
            raise McpConnectionError(message) from exc
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}' stopped responding: {failure}"
            raise McpConnectionError(message) from failure

    async def _supervise(self) -> None:
        """Keep the server connected, retrying with bounded backoff.

        Raises:
            asyncio.CancelledError: If the supervisor task is cancelled,
                which unwinds the transport in the task that opened it.
            fatal: The leaf :func:`fatal_leaf` found, when a transport
                failure carried one that is not an ordinary exception, such
                as interpreter shutdown. It is re-raised as itself, rather
                than as its type, so the loop sees the original and the
                failure unwinds instead of being recorded as a connection
                fault.
        """
        attempt = 0
        while not self._stop.is_set():
            self._health = McpHealth.CONNECTING
            self._dropped.clear()
            self._wake.clear()
            try:
                await self._serve_once()
            except asyncio.CancelledError:
                raise
            except TRANSPORT_FAILURES as exc:
                fatal = fatal_leaf(exc)
                if fatal is not None:
                    raise fatal from exc
                failure = representative_failure(exc)
                self._client = None
                self._failure = failure
                self._last_error = str(failure) if isinstance(failure, McpError) else f"{type(failure).__name__}: {failure}"
                self._health = McpHealth.FAILED
                self._settled.set()
                _logger.warning(
                    "mcp_server_connection_failed",
                    server_id=self.server_id,
                    attempt=attempt,
                    error=self._last_error,
                )
                self._notify_change()
                if isinstance(failure, McpConsentDeniedError):
                    return
            else:
                self._health = McpHealth.DISCONNECTED
                return

            if self._stop.is_set():
                return
            attempt += 1
            if attempt >= MAX_RECONNECT_ATTEMPTS:
                _logger.error(
                    "mcp_server_reconnect_exhausted",
                    server_id=self.server_id,
                    attempts=attempt,
                    error=self._last_error,
                )
                return
            delay = reconnect_delay(attempt - 1)
            _logger.info("mcp_server_reconnect_scheduled", server_id=self.server_id, attempt=attempt, delay_s=delay)
            with suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=delay)

    async def connect(self) -> None:
        """Bring the server up and wait for its first tool listing.

        Raises:
            McpConsentDeniedError: If the operator refused to let a local
                server run. Nothing was spawned.
            McpConnectionError: If the server is disabled, the first attempt
                fails for any other reason, or it does not become ready
                within :data:`CONNECT_TIMEOUT_S`.
        """
        if not self._config.enabled:
            self._health = McpHealth.DISABLED
            message = f"server '{self.server_id}' is disabled"
            raise McpConnectionError(message)
        if self._task is not None and not self._task.done():
            return

        self._stop = asyncio.Event()
        self._settled = asyncio.Event()
        self._dropped = asyncio.Event()
        self._wake = asyncio.Event()
        self._last_error = None
        self._failure = None
        self._health = McpHealth.CONNECTING
        self._task = asyncio.create_task(self._supervise(), name=f"mcp-{self.server_id}")

        try:
            await asyncio.wait_for(self._settled.wait(), timeout=CONNECT_TIMEOUT_S)
        except TimeoutError as exc:
            await self.disconnect()
            self._health = McpHealth.FAILED
            self._last_error = f"timed out after {CONNECT_TIMEOUT_S:.0f}s waiting for the server to become ready"
            message = f"server '{self.server_id}': {self._last_error}"
            raise McpConnectionError(message) from exc

        health, reported, failure = self._settled_outcome()
        if health is not McpHealth.READY:
            detail = reported or "the server did not complete its handshake"
            await self.disconnect()
            if isinstance(failure, McpConsentDeniedError):
                raise McpConsentDeniedError(str(failure)) from failure
            message = f"server '{self.server_id}': {detail}"
            raise McpConnectionError(message) from failure

    def _settled_outcome(self) -> tuple[McpHealth, str | None, BaseException | None]:
        """Read the state the supervisor task settled on.

        The supervisor runs as a separate task, so these attributes change
        underneath :meth:`connect` while it waits. Reading them together,
        once, through one call keeps the three consistent with each other.

        Returns:
            tuple[McpHealth, str | None, BaseException | None]: The health,
            the reported error text, and the exception behind it.
        """
        return self._health, self._last_error, self._failure

    async def disconnect(self) -> None:
        """Tear the connection down, leaving no child process behind.

        A connection that had already failed keeps its ``FAILED`` health and
        its recorded error, so the reason a server is not running survives
        the teardown that follows.

        Raises:
            asyncio.CancelledError: If the caller is cancelled while waiting
                for the supervisor task to finish.
        """
        listen_task = self._listen_task
        self._listen_task = None
        if listen_task is not None and not listen_task.done():
            _ = listen_task.cancel()
            with suppress(asyncio.CancelledError, *TRANSPORT_FAILURES):
                await listen_task

        self._stop.set()
        self._wake.set()
        task = self._task
        self._task = None
        if task is not None and not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=DISCONNECT_TIMEOUT_S)
            except TimeoutError:
                _logger.warning("mcp_server_teardown_timeout", server_id=self.server_id)
                _ = task.cancel()
                with suppress(asyncio.CancelledError, *TRANSPORT_FAILURES):
                    await task
            except asyncio.CancelledError:
                raise
            except TRANSPORT_FAILURES as exc:
                _logger.warning("mcp_server_teardown_error", server_id=self.server_id, error=str(exc))

        self._client = None
        self._stderr.close()
        self._connected_at = None
        if self._health is not McpHealth.FAILED:
            self._health = McpHealth.DISABLED if not self._config.enabled else McpHealth.DISCONNECTED
        _logger.info("mcp_server_stopped", server_id=self.server_id)
        self._notify_change()

    async def refresh_catalog(self) -> McpToolCatalog:
        """Re-list the server's tools, respecting its freshness hint.

        Returns:
            McpToolCatalog: The current listing. A listing still inside the
            server's own ``ttlMs`` window is returned without a second
            request.

        Raises:
            McpConnectionError: If the server is not connected, or the
                listing could not be retrieved.
            asyncio.CancelledError: If the caller is cancelled mid-request.
        """
        client = self._client
        if client is None or self._health is not McpHealth.READY:
            message = f"server '{self.server_id}' is not connected"
            raise McpConnectionError(message)
        current = self._catalog
        if current is not None and current.is_fresh(datetime.now(tz=UTC)):
            _logger.debug("mcp_catalog_still_fresh", server_id=self.server_id, ttl_ms=current.ttl_ms)
            return current
        try:
            catalog = await fetch_catalog(client, self.server_id)
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}': cannot list tools: {failure}"
            raise McpConnectionError(message) from failure
        previous = self._catalog
        self._catalog = catalog
        if previous is not None and previous.generation != catalog.generation:
            self._notify_change()
        return catalog

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        timeout_s: float | None = None,
    ) -> CallToolResult:
        """Invoke one tool on the server.

        Args:
            tool_name: The server's own tool name, without the namespace.
            arguments: Parsed arguments for the call.
            timeout_s: Per-call timeout, defaulting to the server's
                configured one.

        Returns:
            CallToolResult: The server's result, error results included. A
            tool that reports failure is a result, not an exception.

        Raises:
            McpConnectionError: If the server is not connected, the call
                times out, or the transport fails.
            asyncio.CancelledError: If the caller is cancelled mid-call.
        """
        client = self._client
        if client is None or self._health is not McpHealth.READY:
            message = f"server '{self.server_id}' is not connected; cannot call {tool_name!r}"
            raise McpConnectionError(message)
        budget = timeout_s if timeout_s is not None else self._config.request_timeout_s
        try:
            async with asyncio.timeout(budget):
                return await client.call_tool(tool_name, arguments)
        except TimeoutError as exc:
            message = f"server '{self.server_id}': call to {tool_name!r} exceeded {budget:.0f}s"
            raise McpConnectionError(message) from exc
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}': call to {tool_name!r} failed: {failure}"
            raise McpConnectionError(message) from failure

    async def listen_for_changes(self, on_change: Callable[[str], None]) -> None:
        """Follow the server's tool-list change notifications.

        Subscriptions exist only on a 2026-07-28 connection. On an older
        one this returns immediately rather than failing: the connection is
        still fully usable, it simply cannot be told about changes and the
        listing is refreshed on demand instead.

        Args:
            on_change: Callable invoked with the server id after the tool
                listing has been refetched.

        Raises:
            asyncio.CancelledError: If the listening task is cancelled.
        """
        client = self._client
        if client is None:
            return
        self.set_change_listener(on_change)
        try:
            async with client.listen(tools_list_changed=True) as subscription:
                _logger.info("mcp_change_subscription_open", server_id=self.server_id)
                async for _event in subscription:
                    with suppress(McpConnectionError):
                        _ = await self.refresh_catalog()
                    on_change(self.server_id)
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            _logger.info("mcp_change_subscription_unavailable", server_id=self.server_id, reason=str(exc))

    def start_listening(self, on_change: Callable[[str], None]) -> None:
        """Start following tool-list changes in the background.

        Args:
            on_change: Callable invoked with the server id after a change.
        """
        if self._listen_task is not None and not self._listen_task.done():
            return
        self._listen_task = asyncio.create_task(
            self.listen_for_changes(on_change),
            name=f"mcp-listen-{self.server_id}",
        )

    def _notify_change(self) -> None:
        """Invoke the change listener, absorbing a listener that raises."""
        listener = self._on_change
        if listener is None:
            return
        try:
            listener(self.server_id)
        except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
            _logger.warning("mcp_change_listener_failed", server_id=self.server_id, error=str(exc))


def _child_pids() -> frozenset[int]:
    """List the process ids of this process's direct and indirect children.

    Returns:
        frozenset[int]: The child process ids, empty when they cannot be
        enumerated.
    """
    with contextlib.suppress(psutil.Error, OSError):
        return frozenset(child.pid for child in psutil.Process().children(recursive=True))
    return frozenset()


def _process_matches(pid: int, expected_stem: str) -> bool:
    """Report whether one process looks like the server that was just started.

    Args:
        pid: The process to inspect.
        expected_stem: The launch command's file name without its extension,
            lower-cased.

    Returns:
        bool: ``True`` when the process's executable name matches.
    """
    with contextlib.suppress(psutil.Error, OSError):
        return Path(psutil.Process(pid).name()).stem.lower() == expected_stem
    return False


class _StreamPairTransport:
    """Adapts an already-open stream pair to the SDK's transport protocol.

    The HTTP transport is opened as a context manager so its client and task
    group unwind correctly. The SDK's ``Client`` wants a transport it can
    enter itself, so the open pair is wrapped in one whose entry is a no-op
    and whose exit leaves the real teardown to the surrounding context.
    """

    def __init__(self, streams: tuple[Any, Any]) -> None:
        """Initialize the adapter.

        Args:
            streams: The already-open read and write streams.
        """
        self._streams = streams

    async def __aenter__(self) -> tuple[Any, Any]:
        """Hand over the already-open streams.

        Returns:
            tuple[Any, Any]: The read stream and the write stream.
        """
        return self._streams

    async def __aexit__(self, *exc: object) -> None:
        """Leave teardown to the context that opened the streams.

        Args:
            *exc: Exception type, value and traceback, when the body raised.
        """


class McpConnectionManager:
    """Owns every configured server's connection for the life of the process.

    The manager is the single place that knows which servers exist, which
    are up, and how to bring them up or down. Every coroutine it exposes
    must be awaited on one event loop -- inside the GUI, the persistent
    background loop the async bridge owns.
    """

    def __init__(
        self,
        store: McpConfigStore,
        resolver: McpSecretResolver,
        consent: McpConsentGate,
        *,
        elicitation_factory: Callable[[str], ElicitationFnT] | None = None,
        auth_factory: AuthFactory | None = None,
    ) -> None:
        """Initialize the manager.

        Args:
            store: Configuration store the server list is read from.
            resolver: Resolver expanding ``${input:id}`` references.
            consent: Gate consulted before a local server is spawned.
            elicitation_factory: Builds the elicitation handler for one
                server. It takes the server id because the operator needs to
                be told which server is asking them for something, and the
                protocol callback itself does not carry that.
            auth_factory: Builds the authentication handler for an HTTP
                server.
        """
        self._store = store
        self._resolver = resolver
        self._consent = consent
        self._elicitation_factory = elicitation_factory
        self._auth_factory = auth_factory
        self._document: McpConfigDocument = McpConfigStore.parse_document({})
        self._connections: dict[str, McpConnection] = {}
        self._order: list[str] = []
        self._listener: Callable[[str], None] | None = None
        self._started = False

    @property
    def document(self) -> McpConfigDocument:
        """The configuration currently in effect.

        Returns:
            McpConfigDocument: The loaded document.
        """
        return self._document

    @property
    def store(self) -> McpConfigStore:
        """The configuration store this manager reads.

        Returns:
            McpConfigStore: The backing store.
        """
        return self._store

    @property
    def consent(self) -> McpConsentGate:
        """The consent gate this manager launches servers through.

        Returns:
            McpConsentGate: The gate.
        """
        return self._consent

    def _on_connection_changed(self, server_id: str) -> None:
        """React to one server's state or tool listing moving.

        The generation is re-checked here rather than only at connect,
        because a server may publish a new tool listing at any point in its
        life and the approvals the operator gave about the old one must not
        outlive it.

        Args:
            server_id: The server whose state changed.
        """
        connection = self._connections.get(server_id)
        catalog = connection.catalog if connection is not None else None
        if catalog is not None:
            _ = self._consent.note_generation(server_id, catalog.generation)
        listener = self._listener
        if listener is None:
            return
        try:
            listener(server_id)
        except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
            _logger.warning("mcp_manager_listener_failed", server_id=server_id, error=str(exc))

    def _elicitation_for(self, server_id: str) -> ElicitationFnT | None:
        """Build the elicitation handler for one server.

        Args:
            server_id: The server the handler will answer for.

        Returns:
            ElicitationFnT | None: The handler, or ``None`` when no factory
            is installed, in which case the SDK declines elicitations.
        """
        if self._elicitation_factory is None:
            return None
        return self._elicitation_factory(server_id)

    def set_change_listener(self, listener: Callable[[str], None]) -> None:
        """Install the callback invoked when any server's state moves.

        Args:
            listener: Callable receiving the server id that changed.
        """
        self._listener = listener
        for connection in self._connections.values():
            connection.set_change_listener(self._on_connection_changed)

    def reload(self) -> McpConfigDocument:
        """Re-read the configuration file without touching live connections.

        Returns:
            McpConfigDocument: The freshly loaded document.
        """
        self._document = self._store.load()
        return self._document

    async def start(self) -> None:
        """Load the configuration and bring every enabled server up.

        A server that fails to start does not stop the others: its failure
        is recorded on its own status and the remaining servers continue.
        """
        self._document = self._store.load()
        self._started = True
        for config in self._document.servers:
            if not config.enabled:
                continue
            with suppress(McpError):
                _ = await self.start_server(config.server_id)
        _logger.info(
            "mcp_manager_started",
            configured=len(self._document.servers),
            connected=sum(1 for connection in self._connections.values() if connection.is_ready),
        )

    async def stop(self) -> None:
        """Bring every server down, in reverse start order.

        Teardown is deterministic and total: every connection is torn down
        even if an earlier one raised, so no child process and no pending
        task outlives the call.

        Raises:
            asyncio.CancelledError: If the caller is cancelled mid-teardown.
        """
        for server_id in reversed(self._order):
            connection = self._connections.get(server_id)
            if connection is None:
                continue
            try:
                await connection.disconnect()
            except asyncio.CancelledError:
                raise
            except TRANSPORT_FAILURES as exc:
                _logger.warning("mcp_manager_stop_error", server_id=server_id, error=str(exc))
        self._connections.clear()
        self._order.clear()
        self._started = False
        _logger.info("mcp_manager_stopped")

    async def start_server(self, server_id: str) -> McpServerStatus:
        """Bring one configured server up.

        Args:
            server_id: The server to start.

        Returns:
            McpServerStatus: The server's state once the attempt settled.

        Raises:
            McpConnectionError: If no such server is configured, or the
                connection attempt failed.
        """
        config = self._document.server(server_id)
        if config is None:
            self._document = self._store.load()
            config = self._document.server(server_id)
        if config is None:
            message = f"no MCP server named '{server_id}' is configured"
            raise McpConnectionError(message)

        existing = self._connections.get(server_id)
        if existing is not None:
            await existing.disconnect()

        connection = McpConnection(
            config,
            self._resolver,
            elicitation_callback=self._elicitation_for(server_id),
            consent=self._consent,
            auth_factory=self._auth_factory,
        )
        connection.set_change_listener(self._on_connection_changed)
        self._connections[server_id] = connection
        if server_id not in self._order:
            self._order.append(server_id)

        await connection.connect()
        catalog = connection.catalog
        if catalog is not None:
            _ = self._consent.note_generation(server_id, catalog.generation)
        connection.start_listening(self._on_connection_changed)
        return connection.status

    async def stop_server(self, server_id: str) -> None:
        """Bring one server down and forget its connection.

        Args:
            server_id: The server to stop.
        """
        connection = self._connections.pop(server_id, None)
        if server_id in self._order:
            self._order.remove(server_id)
        if connection is not None:
            await connection.disconnect()

    async def restart_server(self, server_id: str) -> McpServerStatus:
        """Bring one server down and straight back up.

        A server that is not configured, or a fresh connection that failed,
        propagates :class:`McpConnectionError` from
        :meth:`start_server`.

        Args:
            server_id: The server to restart.

        Returns:
            McpServerStatus: The server's state after restarting.
        """
        await self.stop_server(server_id)
        self._document = self._store.load()
        return await self.start_server(server_id)

    async def test_connection(self, config: McpServerConfig) -> McpServerStatus:
        """Connect to a server once and report what it actually published.

        The candidate configuration does not have to be saved, and the
        connection is always torn down, so the settings dialog can report a
        real tool count without leaving a process running.

        Args:
            config: The candidate configuration to try.

        Returns:
            McpServerStatus: The result, carrying the real discovered tool
            count on success and the failure reason otherwise.

        Raises:
            asyncio.CancelledError: If the caller is cancelled mid-probe.
        """
        config.validate()
        probe = McpConnection(
            McpServerConfig(
                server_id=config.server_id,
                kind=config.kind,
                stdio=config.stdio,
                http=config.http,
                enabled=True,
                disabled_tools=config.disabled_tools,
                sandbox=config.sandbox,
                request_timeout_s=config.request_timeout_s,
            ),
            self._resolver,
            elicitation_callback=self._elicitation_for(config.server_id),
            consent=self._consent,
            auth_factory=self._auth_factory,
        )
        try:
            await probe.connect()
        except asyncio.CancelledError:
            raise
        except McpError as exc:
            return McpServerStatus(
                server_id=config.server_id,
                health=McpHealth.FAILED,
                last_error=str(exc),
            )
        else:
            return probe.status
        finally:
            await probe.disconnect()

    def statuses(self) -> list[McpServerStatus]:
        """Report the state of every configured server.

        A configured server that has never been started still appears, as
        disabled or disconnected, so the UI lists what exists rather than
        only what is running.

        Returns:
            list[McpServerStatus]: One status per configured server, in
            configuration order.
        """
        reports: list[McpServerStatus] = []
        for config in self._document.servers:
            connection = self._connections.get(config.server_id)
            if connection is not None:
                reports.append(connection.status)
                continue
            reports.append(
                McpServerStatus(
                    server_id=config.server_id,
                    health=McpHealth.DISCONNECTED if config.enabled else McpHealth.DISABLED,
                ),
            )
        return reports

    def connection(self, server_id: str) -> McpConnection | None:
        """Look up one live connection.

        Args:
            server_id: The server to resolve.

        Returns:
            McpConnection | None: The connection, or ``None`` when the
            server is not running.
        """
        return self._connections.get(server_id)

    def ready_connections(self) -> list[McpConnection]:
        """List every connection currently able to serve calls.

        Returns:
            list[McpConnection]: Ready connections, in start order.
        """
        return [
            connection for server_id in self._order if (connection := self._connections.get(server_id)) is not None and connection.is_ready
        ]

    def stderr_tail(self, server_id: str, limit: int = 200) -> list[str]:
        """Return a server's captured stderr.

        Args:
            server_id: The server to read.
            limit: Maximum number of lines to return.

        Returns:
            list[str]: Captured lines, empty when the server has none.
        """
        connection = self._connections.get(server_id)
        return connection.stderr_tail(limit) if connection is not None else []
