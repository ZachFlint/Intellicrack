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
import enum
import os
import threading
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, Protocol, Self, TextIO, TypeVar, cast

import anyio
from mcp.client.auth import OAuthClientProvider
from mcp.client.stdio import stdio_client
from mcp.client.subscriptions import ListenNotSupportedError, PromptsListChanged, ResourcesListChanged, ResourceUpdated, SubscriptionLost
from mcp.shared.exceptions import MCPError
from mcp_types import (
    CONNECTION_CLOSED,
    LOG_LEVEL_META_KEY,
    METHOD_NOT_FOUND,
    EmptyResult,
    Implementation,
    ProgressNotification,
    ProgressNotificationParams,
    PromptListChangedNotification,
    PromptReference,
    ResourceListChangedNotification,
    ResourceTemplateReference,
    ResourceUpdatedNotification,
    RootsListChangedNotification,
    SetLevelRequest,
    SetLevelRequestParams,
    SubscribeRequest,
    SubscribeRequestParams,
    ToolListChangedNotification,
    UnsubscribeRequest,
    UnsubscribeRequestParams,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from intellicrack._metadata import __version__
from intellicrack.core.logging import get_logger
from intellicrack.core.untrusted_text import clean_untrusted_label
from intellicrack.mcp.catalog import McpToolCatalog, fetch_catalog
from intellicrack.mcp.client_hooks import McpClientHooks
from intellicrack.mcp.client_session import McpClient, PreciseClientSession, describe_capabilities
from intellicrack.mcp.config import SERVER_LOG_LEVELS, McpConfigStore, McpServerConfig, McpTransportKind
from intellicrack.mcp.consent import McpConsentStoreError
from intellicrack.mcp.context_events import McpContextChange, McpContextEvent
from intellicrack.mcp.errors import McpConnectionError, McpConsentDeniedError, McpError, McpProtocolError
from intellicrack.mcp.operator_wait import OperatorWaitClock, RequestDeadline
from intellicrack.mcp.progress import McpProgress, ProgressFn, ProgressKind
from intellicrack.mcp.sandbox_launch import (
    build_sandboxed_startup,
    confined_stdio_client,
    revert_stale_write_grants,
    sandbox_access_guidance,
    sandbox_supported,
)
from intellicrack.mcp.transport import build_stdio_parameters, load_env_file, open_http_transport, sign_in_before_handshake


if TYPE_CHECKING:
    import contextvars
    from collections.abc import AsyncGenerator, Iterable, Mapping

    import httpx2
    from mcp import Client
    from mcp.client.session import ElicitationFnT, LoggingFnT
    from mcp.shared.message import SessionMessage
    from mcp_types import CallToolResult, CompleteResult, LoggingLevel, LoggingMessageNotificationParams, RequestParamsMeta

    from intellicrack.mcp.client_hooks import McpHooksFactory
    from intellicrack.mcp.config import McpConfigDocument
    from intellicrack.mcp.consent import McpConsentGate
    from intellicrack.mcp.context_events import McpContextListener
    from intellicrack.mcp.secrets import McpSecretResolver


_logger = get_logger(__name__)

_T = TypeVar("_T")


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

RECONNECT_RESET_AFTER_S: Final[float] = 30.0
"""How long a connection must stay ready for its next drop to start a fresh series.

A drop after a ready period at least this long is a new incident, so the
attempt count starts again from zero. A server that fails again sooner is
still in the same series, which keeps a server that crashes right after its
handshake from retrying forever.
"""

CONNECT_TIMEOUT_S: Final[float] = 45.0
"""How long a first connection and tool listing may take.

Time the operator spends answering a prompt the connection raised -- the
launch consent dialog, an interactive OAuth sign-in -- is not counted: the
operator is not the server, and a dialog left open for a minute is not a
server that failed to start.
"""

DISCONNECT_TIMEOUT_S: Final[float] = 10.0
"""How long a graceful teardown may take before the task is cancelled."""

STDERR_JOIN_TIMEOUT_S: Final[float] = 2.0
"""How long to wait for the stderr reader thread to finish."""

HEARTBEAT_INTERVAL_S: Final[float] = 15.0
"""How often a live connection probes its server.

The 2026-07-28 protocol has no ``ping``; a modern connection is probed with
``server/discover``, which every such server must answer, and a handshake-era
connection with ``ping``. The probe is what notices a remote server that
went away without closing anything; a local server that exits is noticed at
once, because its output stream ends.
"""

LISTEN_RETRY_S: Final[float] = 5.0
"""Delay before a change subscription the server ended is opened again."""

_GUIDANCE_STDERR_LINES: Final[int] = 200
"""How much of a sandboxed server's last stderr is searched for a refused access when it fails."""

_FAILURE_TEXT_LIMIT: Final[int] = 4096
"""Longest failure text kept in a message or a log record."""

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

``BaseExceptionGroup`` is in the tuple because the SDK's transports are built on ``anyio`` task groups, which report a child task's failure
as a group even when only one task failed. Catching the leaf types alone would let a dropped connection escape as an unhandled task
exception.
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
    if leaves := failure_leaves(exc):
        return next((leaf for leaf in leaves if isinstance(leaf, McpError | MCPError)), leaves[0])
    return exc


def failure_text(failure: BaseException) -> str:
    """Render a failure for a message or a log, cleaned of what a server could hide in it.

    A protocol error carries the server's own message, which may hold
    terminal escapes, bidirectional overrides or a forged fence marker.

    Args:
        failure: The failure.

    Returns:
        str: Its text, cleaned and bounded.
    """
    return clean_untrusted_label(str(failure), limit=_FAILURE_TEXT_LIMIT)


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
        protocol_version: The protocol version the current connection
            negotiated, or ``None`` when not connected.
        server_capabilities: What the server declared it offers, one line
            per capability, empty when not connected.
        client_capabilities: What Intellicrack declared to the server on the
            negotiated version, one line per capability, empty when not
            connected.
    """

    server_id: str
    health: McpHealth
    tool_count: int = 0
    generation: str | None = None
    last_error: str | None = None
    connected_at: datetime | None = None
    protocol_version: str | None = None
    server_capabilities: tuple[str, ...] = ()
    client_capabilities: tuple[str, ...] = ()


class _ProgressTracker:
    """Follows the progress notices for one request.

    A notice that reports more progress than any before it renews the
    request's deadline; every notice is handed on to whoever is showing it.
    """

    def __init__(
        self,
        server_id: str,
        kind: ProgressKind,
        subject: str,
        deadline: RequestDeadline,
        on_progress: ProgressFn | None,
    ) -> None:
        """Start following one request.

        Args:
            server_id: The server the request went to.
            kind: The kind of request.
            subject: What the request is for.
            deadline: The request's deadline.
            on_progress: Receives each notice, or ``None``.
        """
        self._server_id = server_id
        self._kind = kind
        self._subject = subject
        self._deadline = deadline
        self._on_progress = on_progress
        self._last: float | None = None

    def receive(self, params: ProgressNotificationParams) -> None:
        """Take one progress notice.

        Args:
            params: The notice's parameters.
        """
        if self._last is None or params.progress > self._last:
            self._last = params.progress
            _ = self._deadline.renew()
        if self._on_progress is not None:
            self._on_progress(
                McpProgress.from_wire(
                    self._server_id,
                    self._kind,
                    self._subject,
                    progress=params.progress,
                    total=params.total,
                    message=params.message,
                ),
            )


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


def is_connection_loss(failure: BaseException) -> bool:
    """Report whether a request failed because the connection itself is gone.

    A server that answers with a protocol error is alive and still
    connected; only a closed connection, or the operating system refusing to
    reach the peer, means the transport must be rebuilt.

    Args:
        failure: The representative failure of a request.

    Returns:
        bool: ``True`` for ``CONNECTION_CLOSED`` and for an OS-level error.
    """
    if isinstance(failure, MCPError):
        return failure.code == CONNECTION_CLOSED
    return isinstance(failure, OSError)


class _MessageReceiveStream(Protocol):
    """The receive side of a transport's stream pair, as the session reads it."""

    async def receive(self) -> SessionMessage | Exception:
        """Receive one item.

        Returns:
            SessionMessage | Exception: A message, or a transport fault.
        """
        ...

    async def __anext__(self) -> SessionMessage | Exception:
        """Receive the next item.

        Returns:
            SessionMessage | Exception: A message, or a transport fault.
        """
        ...

    def close(self) -> None:
        """Close the stream."""
        ...

    async def aclose(self) -> None:
        """Close the stream."""
        ...


class _WatchedReceiveStream:
    """A transport's read stream that reports when it ends.

    When a server's output ends -- a local server exited, a legacy SSE
    stream was cut -- the session's dispatcher simply stops reading; nothing
    is raised anywhere. This wrapper sits between the transport and the
    dispatcher and turns that end into a callback, so the connection learns
    at once that its server is gone.
    """

    def __init__(self, inner: _MessageReceiveStream, on_closed: Callable[[], None]) -> None:
        """Wrap a read stream.

        Args:
            inner: The transport's read stream.
            on_closed: Called once the stream has ended.
        """
        self._inner = inner
        self._on_closed = on_closed

    @property
    def last_context(self) -> contextvars.Context | None:
        """The sender's context for the last item, when the transport records one.

        Returns:
            contextvars.Context | None: The context, or ``None``.
        """
        return cast("contextvars.Context | None", getattr(self._inner, "last_context", None))

    def _ended(self) -> None:
        """Report the end of the stream."""
        self._on_closed()

    async def receive(self) -> SessionMessage | Exception:
        """Receive one item.

        Returns:
            SessionMessage | Exception: A message, or a transport fault.

        Raises:
            anyio.EndOfStream: If the stream has ended.
            anyio.ClosedResourceError: If the stream was closed.
            anyio.BrokenResourceError: If the sending side broke.
        """
        try:
            return await self._inner.receive()
        except anyio.EndOfStream:
            self._ended()
            raise
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            self._ended()
            raise

    def __aiter__(self) -> Self:
        """Iterate over the stream.

        Returns:
            Self: This stream.
        """
        return self

    async def __anext__(self) -> SessionMessage | Exception:
        """Receive the next item.

        Returns:
            SessionMessage | Exception: A message, or a transport fault.

        Raises:
            StopAsyncIteration: If the stream has ended.
            anyio.ClosedResourceError: If the stream was closed.
            anyio.BrokenResourceError: If the sending side broke.
        """
        try:
            return await self._inner.__anext__()
        except StopAsyncIteration:
            self._ended()
            raise
        except (anyio.ClosedResourceError, anyio.BrokenResourceError):
            self._ended()
            raise

    def close(self) -> None:
        """Close the stream."""
        self._inner.close()

    async def aclose(self) -> None:
        """Close the stream."""
        await self._inner.aclose()

    async def __aenter__(self) -> Self:
        """Enter the stream's context.

        Returns:
            Self: This stream.
        """
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Close the stream on leaving its context.

        Args:
            *exc: Exception type, value and traceback, when the body raised.
        """
        await self._inner.aclose()


class McpConnection:
    """One configured server, its transport, and its current tool listing.

    A connection is inert until :meth:`connect` is awaited. It then owns a supervisor task that keeps the SDK client entered, reconnecting
    with bounded backoff when the server drops, until :meth:`disconnect` is awaited.
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
        hooks: McpClientHooks | None = None,
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
            hooks: The sampling, roots and logging callbacks this server is
                offered; each one left out is not advertised.
        """
        self._config = config
        self._resolver = resolver
        self._client_info = client_info if client_info is not None else build_client_info()
        self._operator_wait = OperatorWaitClock()
        self._elicitation_callback = self._operator_wait.pause_during(elicitation_callback) if elicitation_callback is not None else None
        self._hooks = hooks if hooks is not None else McpClientHooks()
        self._log_level: LoggingLevel | None = cast("LoggingLevel | None", config.log_level)
        self._consent = consent
        self._auth_factory = auth_factory

        self._client: Client | None = None
        self._catalog: McpToolCatalog | None = None
        self._stderr = _StderrCapture()
        self._health = McpHealth.DISCONNECTED if config.enabled else McpHealth.DISABLED
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
        self._on_change: Callable[[str], None] | None = None
        self._attempt = 0
        self._ready_since: float | None = None
        self._follow_changes = False
        self._change_notice = asyncio.Event()
        self._progress: dict[str, _ProgressTracker] = {}
        self._subscriptions: set[str] = set()
        self._listen_filter_changed = asyncio.Event()
        self._on_context: McpContextListener | None = None

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
        client = self._client if self._health is McpHealth.READY else None
        session = client.session if client is not None else None
        declared = session.declared_capabilities() if isinstance(session, PreciseClientSession) else None
        return McpServerStatus(
            server_id=self._config.server_id,
            health=self._health,
            tool_count=self._catalog.tool_count if self._catalog is not None else 0,
            generation=self._catalog.generation if self._catalog is not None else None,
            last_error=self._last_error,
            connected_at=self._connected_at,
            protocol_version=client.protocol_version if client is not None else None,
            server_capabilities=describe_capabilities(client.server_capabilities) if client is not None else (),
            client_capabilities=describe_capabilities(declared) if declared is not None else (),
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
    async def _open_transport(self, attempt: int) -> AsyncGenerator[Client]:
        """Open the SDK client for this server's transport.

        Args:
            attempt: The connection attempt this transport belongs to, so an
                end-of-stream report from a transport already replaced is
                ignored.

        Yields:
            Client: An entered client, ready to issue requests.

        Raises:
            McpConnectionError: If the transport kind has no implementation.
        """
        on_closed = partial(self._on_stream_closed, attempt)
        if self._config.kind is McpTransportKind.STDIO:
            async with self._open_stdio_client(on_closed) as client:
                yield client
            return
        if self._config.is_http:
            async with self._open_http_client(on_closed) as client:
                yield client
            return
        message = f"server '{self.server_id}': transport {self._config.kind.value!r} is not supported"
        raise McpConnectionError(message)

    def _build_client(self, streams: tuple[Any, Any], on_closed: Callable[[], None], *, legacy: bool = False) -> Client:
        """Build the SDK client over an open stream pair.

        Args:
            streams: The transport's read and write streams.
            on_closed: Called when the read stream ends.
            legacy: Whether to drive the session in the SDK's ``legacy``
                mode, with the ``initialize`` handshake, rather than
                negotiating the protocol version.

        The SDK's own per-request read timeout is off. It runs on the SDK's
        clock, which knows nothing of the operator: a legacy server that asks
        the operator something in the middle of ``tools/call`` would have the
        call fail under it however long the question's own timeout was. Every
        request Intellicrack sends is bounded instead by a deadline on this
        connection's :class:`~intellicrack.mcp.operator_wait.OperatorWaitClock`,
        which stops while the operator is being asked.

        Returns:
            Client: The client, not yet entered.
        """
        hooks = self._hooks
        return McpClient(
            _StreamPairTransport(streams, on_closed),
            client_info=self._client_info,
            elicitation_callback=self._elicitation_callback,
            sampling_callback=self._operator_wait.pause_sampling(hooks.sampling) if hooks.sampling is not None else None,
            sampling_capabilities=hooks.sampling_capabilities,
            list_roots_callback=hooks.list_roots,
            logging_callback=self._filtered_logging() if hooks.logging is not None else None,
            log_level=self._log_level,
            message_handler=self._on_incoming,
            read_timeout_seconds=None,
            mode="legacy" if legacy else "auto",
        )

    @asynccontextmanager
    async def _open_stdio_client(self, on_closed: Callable[[], None]) -> AsyncGenerator[Client]:
        """Spawn a local server and open a client over its stdio streams.

        An unconfined server is spawned by the SDK, whose teardown closes
        stdin, waits out the grace period, and then terminates the whole
        process tree. A sandboxed server is spawned by
        :func:`~intellicrack.mcp.sandbox_launch.confined_stdio_client`,
        suspended inside its job with a restricted token, so the server and
        everything it starts are confined from their first instruction; its
        teardown terminates the job.

        Args:
            on_closed: Called when the server's output stream ends.

        Yields:
            Client: An entered client.

        Raises:
            McpConnectionError: If the server has no launch description,
                no consent gate is available to ask, or it is configured to
                run sandboxed on a platform with no sandbox.
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
        async with self._operator_wait.operator_turn():
            await self._consent.ensure_launch_consent(self._config, env)

        sandbox = self._config.sandbox
        launch_spec = replace(spec, args=await self._resolver.resolve_sequence(spec.args, field="args"))
        if sandbox.enabled and not sandbox_supported():
            message = (
                f"server '{self.server_id}' is configured to run sandboxed, which Intellicrack implements "
                f"with Windows job objects, restricted tokens and integrity levels. Refusing to start it unconfined on this platform."
            )
            raise McpConnectionError(message)

        parameters = build_stdio_parameters(launch_spec, env)
        errlog = self._stderr.open()
        _logger.info(
            "mcp_stdio_server_starting",
            server_id=self.server_id,
            command=parameters.command,
            argument_count=len(parameters.args),
            sandboxed=sandbox.enabled,
        )
        try:
            if sandbox.enabled:
                launch = build_sandboxed_startup(launch_spec, sandbox, env, server_id=self.server_id)
                async with (
                    confined_stdio_client(launch, sandbox, errlog) as streams,
                    self._build_client(streams, on_closed) as client,
                ):
                    yield client
            else:
                async with (
                    stdio_client(parameters, errlog=errlog) as streams,
                    self._build_client(streams, on_closed) as client,
                ):
                    yield client
        finally:
            self._stderr.close()

    @asynccontextmanager
    async def _open_http_client(self, on_closed: Callable[[], None]) -> AsyncGenerator[Client]:
        """Open a client against a remote HTTP server.

        A server declared ``sse`` is spoken to over the SDK's legacy HTTP+SSE
        transport with the session in ``legacy`` mode; one declared ``http``
        over Streamable HTTP, negotiating the protocol version.

        An OAuth-protected Streamable HTTP server is signed in to first,
        through :func:`~intellicrack.mcp.transport.sign_in_before_handshake`,
        so the handshake's own requests never wait on the operator. An SSE
        server needs no such step: its transport opens the event stream, and
        so completes any sign-in, before it hands over the streams the
        handshake runs on.

        Args:
            on_closed: Called when the transport's read stream ends.

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
        resolved = replace(self._config, http=replace(spec, headers=headers, query=query))
        auth = self._auth_factory(resolved) if self._auth_factory is not None else None
        if isinstance(auth, OAuthClientProvider):
            self._track_operator_steps(auth)

        http_spec = resolved.http
        if http_spec is None:
            message = f"server '{self.server_id}' has no endpoint URL"
            raise McpConnectionError(message)

        if isinstance(auth, OAuthClientProvider) and self._config.kind is McpTransportKind.HTTP:
            _ = await sign_in_before_handshake(
                http_spec,
                headers=headers,
                auth=auth,
                timeout_s=self._config.request_timeout_s,
                client_info=self._client_info,
            )

        async with (
            open_http_transport(
                http_spec,
                headers=headers,
                auth=auth,
                timeout_s=self._config.request_timeout_s,
                kind=self._config.kind,
            ) as streams,
            self._build_client(streams, on_closed, legacy=self._config.kind is McpTransportKind.SSE) as client,
        ):
            yield client

    def _track_operator_steps(self, auth: OAuthClientProvider) -> None:
        """Count an OAuth sign-in's interactive steps as operator time.

        Opening the authorization page and waiting for its redirect are the
        steps that wait on a person; the token exchange around them does not,
        and stays inside the connect timeout.

        Args:
            auth: The OAuth handler about to sign this connection's requests.
        """
        context = auth.context
        if context.redirect_handler is not None:
            context.redirect_handler = self._operator_wait.pause_while(context.redirect_handler)
        if context.callback_handler is not None:
            context.callback_handler = self._operator_wait.pause_while(context.callback_handler)

    def request_deadline(self, budget_s: float | None = None) -> AbstractAsyncContextManager[RequestDeadline]:
        """Bound one request to this server by the server's time alone.

        Time spent waiting on the operator -- a question the server asked in
        the middle of the request, an interactive sign-in -- is not counted.

        Args:
            budget_s: Seconds the request may take, defaulting to the
                server's configured per-request timeout.

        Returns:
            AbstractAsyncContextManager[RequestDeadline]: A context that
            interrupts its block with :class:`TimeoutError` once the budget
            is spent, yielding the deadline so progress can renew it.
        """
        return self._operator_wait.deadline(budget_s if budget_s is not None else self._config.request_timeout_s)

    async def request(self, operation: str, send: Callable[[], Awaitable[_T]]) -> _T:
        """Send one request to this server under its per-request deadline.

        Args:
            operation: What the request does, for the error message, such as
                ``"list resources"``.
            send: Sends the request and returns its result.

        Returns:
            _T: What ``send`` returned.

        Raises:
            McpConnectionError: If the server did not answer within its
                per-request timeout, not counting time spent waiting on the
                operator, or the transport failed.
            asyncio.CancelledError: If the caller is cancelled mid-request.
        """
        budget = self._config.request_timeout_s
        try:
            async with self.request_deadline(budget):
                return await send()
        except TimeoutError as exc:
            message = f"server '{self.server_id}': {operation} exceeded {budget:.0f}s"
            raise McpConnectionError(message) from exc
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}': cannot {operation}: {failure_text(failure)}"
            raise McpConnectionError(message) from failure

    async def request_with_progress(
        self,
        operation: str,
        kind: ProgressKind,
        subject: str,
        send: Callable[[RequestParamsMeta | None], Awaitable[_T]],
        on_progress: ProgressFn | None = None,
    ) -> _T:
        """Send one request that asks the server to report its progress.

        The request carries a ``progressToken``; each notice that reports more
        progress than before renews the request's deadline, as
        :mod:`intellicrack.mcp.operator_wait` sets out, and every notice is
        handed to ``on_progress``.

        Args:
            operation: What the request does, for the error message.
            kind: The kind of request.
            subject: What it is for.
            send: Sends the request with the ``_meta`` it is given.
            on_progress: Receives each progress notice, or ``None``.

        Returns:
            _T: What ``send`` returned.

        Raises:
            McpConnectionError: If the server went a whole budget without
                reporting progress, not counting time spent waiting on the
                operator, ran past the cap progress can stretch it to, or the
                transport failed.
            asyncio.CancelledError: If the caller is cancelled mid-request.
        """
        budget = self._config.request_timeout_s
        try:
            async with self._tracked(kind, subject, budget, on_progress) as meta:
                return await send(meta)
        except TimeoutError as exc:
            message = f"server '{self.server_id}': {operation} exceeded {budget:.0f}s without progress, or its progress limit"
            raise McpConnectionError(message) from exc
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}': cannot {operation}: {failure_text(failure)}"
            raise McpConnectionError(message) from failure

    async def _serve_once(self) -> None:
        """Hold one connection open until a stop is requested.

        Opening the transport, the handshake and the first tool listing
        together get :data:`CONNECT_TIMEOUT_S` of the server's time; a launch
        consent prompt or an interactive sign-in inside them stops the clock.
        This bound holds on every attempt, including the reconnects no caller
        is waiting on.

        A tool listing that cannot be retrieved propagates
        :class:`McpConnectionError` from :func:`fetch_catalog`.

        Raises:
            McpConnectionError: If the server did not complete its handshake
                and first tool listing within :data:`CONNECT_TIMEOUT_S`.
        """
        self._attempt += 1
        budget = CONNECT_TIMEOUT_S
        async with AsyncExitStack() as stack:
            try:
                async with self._operator_wait.deadline(budget):
                    client = await stack.enter_async_context(self._open_transport(self._attempt))
                    catalog = await fetch_catalog(client, self.server_id, request_deadline=self.request_deadline)
            except TimeoutError as exc:
                message = f"server '{self.server_id}' timed out after {budget:.0f}s without completing its handshake and tool listing"
                raise McpConnectionError(message) from exc
            self._client = client
            self._catalog = catalog
            await self._apply_log_level(client)
            await self._restore_subscriptions(client)
            self._connected_at = datetime.now(tz=UTC)
            self._ready_since = asyncio.get_running_loop().time()
            self._last_error = None
            self._health = McpHealth.READY
            self._settled.set()
            _logger.info(
                "mcp_server_ready",
                server_id=self.server_id,
                tool_count=catalog.tool_count,
                generation=catalog.generation,
                protocol_version=client.protocol_version,
            )
            self._notify_change()
            self._start_follower(client)
            try:
                await self._hold_open(client)
            finally:
                self._client = None
                await self._stop_follower()

    @property
    def log_level(self) -> str | None:
        """The lowest severity of the server's log messages this connection asks for.

        Returns:
            str | None: The level, or ``None`` when none is asked for.
        """
        return self._log_level

    def _admits_log(self, level: str) -> bool:
        """Decide whether a log message the server sent is one this connection asked for.

        A 2025-11-25 server built on the SDK logs at every level whatever
        ``logging/setLevel`` said, and a 2026-07-28 server may ignore the
        opt-in, so the level is enforced here as well. With no level chosen,
        a 2026-07-28 connection asked for nothing, while an earlier one keeps
        the server's own default.

        Args:
            level: The message's level.

        Returns:
            bool: ``True`` when the message is at or above the chosen level;
            a level the protocol does not define is let through.
        """
        wanted = self._log_level
        if wanted is None:
            return not self._is_modern(self._client)
        if level not in SERVER_LOG_LEVELS:
            return True
        return SERVER_LOG_LEVELS.index(level) >= SERVER_LOG_LEVELS.index(wanted)

    def _filtered_logging(self) -> LoggingFnT:
        """Wrap the logging hook so it only receives the messages this connection asked for.

        Returns:
            LoggingFnT: The filtering callback.
        """
        inner = self._hooks.logging

        async def _receive(params: LoggingMessageNotificationParams) -> None:
            """Pass one log message on when it is at or above the chosen level.

            Args:
                params: The notification's parameters.
            """
            if inner is not None and self._admits_log(params.level):
                await inner(params)

        return _receive

    def _request_meta(self, progress_token: str | None = None) -> RequestParamsMeta | None:
        """Build the ``_meta`` a request carries.

        On a 2026-07-28 connection a server logs only for requests that carry
        a ``logLevel``; the client stamps the level it was built with, and
        this stamps the current one, so a level chosen since the connection
        opened applies to the next request. A request that wants progress
        carries its ``progressToken``.

        Args:
            progress_token: The token the server reports progress under, or
                ``None``.

        Returns:
            RequestParamsMeta | None: The meta, or ``None`` when there is
            nothing to carry.
        """
        meta: dict[str, object] = {}
        if self._log_level is not None and self._is_modern(self._client):
            meta[LOG_LEVEL_META_KEY] = self._log_level
        if progress_token is not None:
            meta["progressToken"] = progress_token
        return cast("RequestParamsMeta", meta) if meta else None

    @asynccontextmanager
    async def _tracked(
        self,
        kind: ProgressKind,
        subject: str,
        budget_s: float,
        on_progress: ProgressFn | None,
    ) -> AsyncGenerator[RequestParamsMeta | None]:
        """Run one request under its deadline, following the progress the server reports on it.

        Args:
            kind: The kind of request.
            subject: What the request is for.
            budget_s: The request's budget.
            on_progress: Receives each progress notice, or ``None``.

        Yields:
            RequestParamsMeta | None: The ``_meta`` the request must carry.
        """
        token = f"intellicrack-{uuid.uuid4().hex}"
        async with self._operator_wait.deadline(budget_s) as deadline:
            self._progress[token] = _ProgressTracker(self.server_id, kind, subject, deadline, on_progress)
            try:
                yield self._request_meta(progress_token=token)
            finally:
                _ = self._progress.pop(token, None)

    async def _apply_log_level(self, client: Client) -> None:
        """Ask a handshake-era server for its log messages at the chosen level.

        A 2025-11-25 connection is governed by ``logging/setLevel`` instead of
        a per-request opt-in. A server that does not offer logging is not
        asked, and one that refuses is logged, not treated as a failed
        connection.

        Args:
            client: The connected client.
        """
        capabilities = client.server_capabilities
        if self._log_level is None or self._is_modern(client) or capabilities.logging is None:
            return
        try:
            async with self.request_deadline():
                request = SetLevelRequest(params=SetLevelRequestParams(level=self._log_level))
                _ = await client.session.send_request(request, EmptyResult)
        except TimeoutError:
            _logger.warning("mcp_log_level_timed_out", server_id=self.server_id, level=self._log_level)
        except MCPError as exc:
            _logger.warning("mcp_log_level_refused", server_id=self.server_id, level=self._log_level, error=clean_untrusted_label(str(exc)))

    async def set_log_level(self, level: str | None) -> None:
        """Change the lowest severity of the server's log messages this connection asks for.

        The level applies at once: a handshake-era server is sent
        ``logging/setLevel``, and on a 2026-07-28 connection every later
        request carries the new level. ``None`` stops asking on a 2026-07-28
        connection; a handshake-era server keeps the last level it was sent,
        since the protocol has no way to switch its logging off.

        Args:
            level: One of :data:`~intellicrack.mcp.config.SERVER_LOG_LEVELS`,
                or ``None``.
        """
        self._log_level = cast("LoggingLevel | None", level)
        self._config = replace(self._config, log_level=level)
        client = self._client
        if client is not None and self._health is McpHealth.READY:
            await self._apply_log_level(client)
        _logger.info("mcp_log_level_set", server_id=self.server_id, level=level)

    def set_context_listener(self, listener: McpContextListener | None) -> None:
        """Choose who hears about changes to this server's resources and prompts.

        Args:
            listener: Receives each change, or ``None``.
        """
        self._on_context = listener

    def _announce_context(self, change: McpContextChange, uri: str | None = None) -> None:
        """Hand one announced change to the context listener.

        Args:
            change: What changed.
            uri: The updated resource, for an update.
        """
        _logger.info("mcp_context_changed", server_id=self.server_id, change=change.value, uri=clean_untrusted_label(uri) if uri else None)
        listener = self._on_context
        if listener is not None:
            listener(McpContextEvent(server_id=self.server_id, change=change, uri=uri))

    @property
    def subscriptions(self) -> frozenset[str]:
        """The resources this connection asked to hear about.

        Returns:
            frozenset[str]: Their URIs.
        """
        return frozenset(self._subscriptions)

    def _require_subscribable(self) -> Client:
        """Check the server lets a client subscribe to its resources.

        Returns:
            Client: The entered client.

        Raises:
            McpConnectionError: If the server is not connected.
            McpProtocolError: If it does not offer resource subscriptions.
        """
        client = self._client
        if client is None or self._health is not McpHealth.READY:
            message = f"server '{self.server_id}' is not connected"
            raise McpConnectionError(message)
        resources = client.server_capabilities.resources
        if resources is None or not resources.subscribe:
            message = f"server '{self.server_id}' does not offer resource subscriptions"
            raise McpProtocolError(message)
        return client

    async def subscribe_resource(self, uri: str) -> None:
        """Ask to hear whenever one of the server's resources changes.

        On 2025-11-25 the server is sent ``resources/subscribe``; on
        2026-07-28 the ``subscriptions/listen`` stream is re-opened with the
        resource in its filter. The subscription is kept across reconnects.

        Args:
            uri: The resource's URI, exactly as the server gave it.

        Raises:
            McpConnectionError: If the server is not connected, did not
                answer, or the transport failed.
        """
        client = self._require_subscribable()
        if not self._is_modern(client):
            try:
                async with self.request_deadline():
                    _ = await client.session.send_request(SubscribeRequest(params=SubscribeRequestParams(uri=uri)), EmptyResult)
            except TimeoutError as exc:
                message = f"server '{self.server_id}': subscribing to {uri!r} timed out"
                raise McpConnectionError(message) from exc
            except TRANSPORT_FAILURES as exc:
                message = f"server '{self.server_id}': cannot subscribe to {uri!r}: {failure_text(representative_failure(exc))}"
                raise McpConnectionError(message) from exc
        self._subscriptions.add(uri)
        self._listen_filter_changed.set()
        _logger.info("mcp_resource_subscribed", server_id=self.server_id, uri=clean_untrusted_label(uri))

    async def unsubscribe_resource(self, uri: str) -> None:
        """Stop hearing about one of the server's resources.

        Args:
            uri: The resource's URI.

        Raises:
            McpConnectionError: If the server is not connected, did not
                answer, or the transport failed.
        """
        client = self._require_subscribable()
        if not self._is_modern(client) and uri in self._subscriptions:
            try:
                async with self.request_deadline():
                    _ = await client.session.send_request(UnsubscribeRequest(params=UnsubscribeRequestParams(uri=uri)), EmptyResult)
            except TimeoutError as exc:
                message = f"server '{self.server_id}': unsubscribing from {uri!r} timed out"
                raise McpConnectionError(message) from exc
            except TRANSPORT_FAILURES as exc:
                message = f"server '{self.server_id}': cannot unsubscribe from {uri!r}: {failure_text(representative_failure(exc))}"
                raise McpConnectionError(message) from exc
        self._subscriptions.discard(uri)
        self._listen_filter_changed.set()
        _logger.info("mcp_resource_unsubscribed", server_id=self.server_id, uri=clean_untrusted_label(uri))

    async def complete(
        self,
        *,
        prompt: bool,
        reference: str,
        argument: str,
        value: str,
        context: Mapping[str, str] | None = None,
    ) -> CompleteResult:
        """Ask the server to suggest values for one argument of a prompt or a resource template.

        Args:
            prompt: Whether the argument is a prompt's rather than a template's.
            reference: The prompt's name, or the template's URI template.
            argument: The argument.
            value: What has been typed of it so far.
            context: The values already chosen for the other arguments.

        Returns:
            CompleteResult: The server's suggestions.

        Raises:
            McpConnectionError: If the server is not connected, did not
                answer, or the transport failed.
        """
        client = self._client
        if client is None or self._health is not McpHealth.READY:
            message = f"server '{self.server_id}' is not connected"
            raise McpConnectionError(message)
        ref: PromptReference | ResourceTemplateReference = (
            PromptReference(type="ref/prompt", name=reference) if prompt else ResourceTemplateReference(type="ref/resource", uri=reference)
        )
        chosen = dict(context) if context else None
        return await self.request(f"complete {argument!r}", partial(client.complete, ref, {"name": argument, "value": value}, chosen))

    async def _restore_subscriptions(self, client: Client) -> None:
        """Subscribe a new 2025-11-25 connection to what the last one was subscribed to.

        A 2026-07-28 connection carries its subscriptions in the filter of
        the stream it opens, so it has nothing to restore here. A server that
        refuses one keeps the others.

        Args:
            client: The connected client.
        """
        resources = client.server_capabilities.resources
        if self._is_modern(client) or not self._subscriptions or resources is None or not resources.subscribe:
            return
        for uri in sorted(self._subscriptions):
            try:
                async with self.request_deadline():
                    _ = await client.session.send_request(SubscribeRequest(params=SubscribeRequestParams(uri=uri)), EmptyResult)
            except TimeoutError:
                _logger.warning("mcp_resource_resubscribe_timed_out", server_id=self.server_id, uri=clean_untrusted_label(uri))
            except MCPError as exc:
                _logger.warning("mcp_resource_resubscribe_refused", server_id=self.server_id, error=clean_untrusted_label(str(exc)))

    async def announce_roots_changed(self) -> bool:
        """Tell a 2025-11-25 server that the roots it was given have changed.

        A 2026-07-28 server asks for roots with each request that needs
        them, so it always has the current set and has nothing to be told;
        a server this connection offers no roots is not told either.

        Returns:
            bool: Whether ``notifications/roots/list_changed`` was sent.
        """
        client = self._client
        if client is None or self._health is not McpHealth.READY or self._hooks.list_roots is None or self._is_modern(client):
            return False
        try:
            await client.session.send_notification(RootsListChangedNotification())
        except TRANSPORT_FAILURES as exc:
            _logger.warning("mcp_roots_change_not_sent", server_id=self.server_id, error=failure_text(representative_failure(exc)))
            return False
        _logger.info("mcp_roots_change_sent", server_id=self.server_id)
        return True

    def _on_stream_closed(self, attempt: int) -> None:
        """Record that one attempt's transport stopped delivering messages.

        Args:
            attempt: The attempt whose read stream ended.
        """
        if attempt == self._attempt:
            self._mark_dropped("the server closed the connection")

    def _mark_dropped(self, detail: str) -> None:
        """Wake the supervisor because the current connection is gone.

        Args:
            detail: Why the connection is considered gone.
        """
        if self._stop.is_set() or self._dropped.is_set():
            return
        self._last_error = detail
        self._dropped.set()
        self._wake.set()
        _logger.warning("mcp_transport_fault", server_id=self.server_id, error=detail)

    async def _on_incoming(self, message: object) -> None:
        """Handle what the session tees to the message handler.

        An exception means the transport faulted, which wakes the supervisor
        immediately instead of waiting for the next heartbeat. A
        ``notifications/progress`` goes to the request it names, if that
        request is still running. A change to the server's resources or
        prompts goes to the context listener. A ``notifications/tools/list_changed`` on a
        handshake-era connection, which has no subscription stream, is queued
        for a real re-list.

        Args:
            message: A server notification, or the exception the transport
                raised.
        """
        if isinstance(message, Exception):
            self._mark_dropped(f"{type(message).__name__}: {message}")
            return
        if isinstance(message, ProgressNotification):
            tracker = self._progress.get(str(message.params.progress_token))
            if tracker is not None:
                tracker.receive(message.params)
            return
        if isinstance(message, ResourceUpdatedNotification):
            self._announce_context(McpContextChange.RESOURCE_UPDATED, str(message.params.uri))
            return
        if isinstance(message, ResourceListChangedNotification):
            self._announce_context(McpContextChange.RESOURCES_LISTED)
            return
        if isinstance(message, PromptListChangedNotification):
            self._announce_context(McpContextChange.PROMPTS_LISTED)
            return
        if isinstance(message, ToolListChangedNotification) and not self._is_modern(self._client):
            _logger.info("mcp_tools_list_changed_notice", server_id=self.server_id)
            self._change_notice.set()

    @staticmethod
    def _is_modern(client: Client | None) -> bool:
        """Report whether a client negotiated the 2026-07-28 protocol or later.

        Args:
            client: The entered client, or ``None``.

        Returns:
            bool: ``True`` when change notices arrive through a subscription.
        """
        if client is None:
            return False
        return client.session.protocol_version in MODERN_PROTOCOL_VERSIONS

    async def _hold_open(self, client: Client) -> None:
        """Keep a ready connection open, watching that it stays alive.

        Whether the server answers the liveness probe at all is decided per
        connection: a handshake-era server that refuses ``ping`` stops being
        probed on this connection only, and the next connection probes again.

        Args:
            client: The entered client for this connection.

        Raises:
            McpConnectionError: If the transport reported a fault, the
                server's stream ended, or the probe found the server gone.
        """
        probing = True
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
            if probing:
                probing = await self._heartbeat(client)

    async def _heartbeat(self, client: Client) -> bool:
        """Probe the server once to confirm the connection is still alive.

        ``ping`` does not exist in the 2026-07-28 protocol, so a modern
        connection is probed with ``server/discover``, which is stateless,
        changes nothing on either side, and must be answered by every modern
        server. A handshake-era connection is probed with ``ping``; a server
        of that era that answers "method not found" simply does not
        implement it, and is not probed again on this connection.

        Args:
            client: The entered client for this connection.

        Returns:
            bool: Whether to keep probing this connection.

        Raises:
            McpConnectionError: If the probe could not be delivered or
                answered, which means the server is gone.
            asyncio.CancelledError: If the supervisor is cancelled mid-probe.
        """
        session = client.session
        version = session.protocol_version
        modern = version in MODERN_PROTOCOL_VERSIONS
        try:
            async with self.request_deadline():
                if version in MODERN_PROTOCOL_VERSIONS:
                    _ = await session.send_discover(version)
                else:
                    _ = await session.send_ping()
        except TimeoutError as exc:
            message = f"server '{self.server_id}' stopped responding: no answer to the liveness probe within {self._config.request_timeout_s:.0f}s"
            raise McpConnectionError(message) from exc
        except asyncio.CancelledError:
            raise
        except MCPError as exc:
            if exc.code == METHOD_NOT_FOUND and not modern:
                _logger.debug("mcp_heartbeat_unsupported", server_id=self.server_id, protocol_version=version)
                return False
            message = f"server '{self.server_id}' stopped responding: {exc}"
            raise McpConnectionError(message) from exc
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}' stopped responding: {failure_text(failure)}"
            raise McpConnectionError(message) from failure
        return True

    def _drop_was_isolated(self) -> bool:
        """Report whether the connection that just ended had been healthy.

        Returns:
            bool: ``True`` when it had been ready for at least
            :data:`RECONNECT_RESET_AFTER_S`, so its end starts a new series
            of attempts rather than continuing the previous one.
        """
        ready_since = self._ready_since
        self._ready_since = None
        if ready_since is None:
            return False
        return asyncio.get_running_loop().time() - ready_since >= RECONNECT_RESET_AFTER_S

    async def _supervise(self) -> None:
        """Keep the server connected, retrying with bounded backoff.

        Consecutive failures are counted, and :data:`MAX_RECONNECT_ATTEMPTS`
        of them stop the retries. A connection that had been ready for
        :data:`RECONNECT_RESET_AFTER_S` resets the count when it drops, so a
        server that stays healthy between occasional drops keeps being
        reconnected for the life of the process.

        However the supervisor ends -- a stop, a refused launch, exhausted
        retries, cancellation -- the first attempt counts as settled, so a
        :meth:`connect` still waiting learns the outcome at once instead of
        waiting out :data:`CONNECT_TIMEOUT_S`.

        Cancellation of the supervisor task, which unwinds the transport in
        the task that opened it, and a non-ordinary leaf of a transport
        failure, such as interpreter shutdown, both propagate from
        :meth:`_supervise_attempts`.
        """
        try:
            await self._supervise_attempts()
        finally:
            self._settled.set()

    async def _supervise_attempts(self) -> None:
        """Run connection attempts until one ends by a stop, a refusal or exhaustion.

        Raises:
            asyncio.CancelledError: If the supervisor task is cancelled.
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
            self._ready_since = None
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
                self._last_error = str(failure) if isinstance(failure, McpError) else f"{type(failure).__name__}: {failure_text(failure)}"
                if self._config.sandbox.enabled and (guidance := sandbox_access_guidance(self._stderr.tail(_GUIDANCE_STDERR_LINES))):
                    self._last_error = f"{self._last_error} {guidance}"
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
            if self._drop_was_isolated():
                attempt = 0
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

    async def _await_settled(self) -> bool:
        """Wait for the first attempt to settle, excluding operator time.

        The budget is :data:`CONNECT_TIMEOUT_S` of time not spent waiting on
        the operator: the deadline is suspended for as long as a consent
        prompt or an interactive sign-in is open, however long the operator
        takes.

        Returns:
            bool: ``True`` when the attempt settled, ``False`` when the
            budget ran out first.
        """
        try:
            async with self._operator_wait.deadline(CONNECT_TIMEOUT_S):
                _ = await self._settled.wait()
        except TimeoutError:
            return False
        return True

    async def connect(self) -> None:
        """Bring the server up and wait for its first tool listing.

        Time spent waiting on the operator -- the launch consent prompt, an
        interactive OAuth sign-in -- does not count against
        :data:`CONNECT_TIMEOUT_S`.

        Cancelling the caller abandons the attempt: the supervisor is
        cancelled with it, so nothing the attempt was waiting on -- a consent
        prompt, a sign-in, a handshake -- can bring the server up afterwards.

        Raises:
            McpConsentDeniedError: If the operator refused to let a local
                server run. Nothing was spawned.
            McpConnectionError: If the server is disabled, was stopped while
                connecting, the first attempt fails for any other reason, or
                it does not become ready within :data:`CONNECT_TIMEOUT_S` of
                its own time.
            asyncio.CancelledError: If the caller is cancelled; the attempt
                has been abandoned by the time it propagates.
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
        self._change_notice = asyncio.Event()
        self._last_error = None
        self._failure = None
        self._health = McpHealth.CONNECTING
        self._task = asyncio.create_task(self._supervise(), name=f"mcp-{self.server_id}")

        try:
            settled = await self._await_settled()
        except asyncio.CancelledError:
            await asyncio.shield(self._abandon())
            raise
        if self._stop.is_set():
            message = f"server '{self.server_id}' was stopped before it became ready"
            raise McpConnectionError(message)
        if not settled:
            await self.disconnect()
            self._health = McpHealth.FAILED
            self._last_error = f"timed out after {CONNECT_TIMEOUT_S:.0f}s waiting for the server to become ready"
            message = f"server '{self.server_id}': {self._last_error}"
            raise McpConnectionError(message)

        health, reported, failure = self._settled_outcome()
        if health is not McpHealth.READY:
            detail = reported or "the server did not complete its handshake"
            await self.disconnect()
            if isinstance(failure, McpConsentDeniedError):
                raise McpConsentDeniedError(str(failure)) from failure
            message = f"server '{self.server_id}': {detail}"
            raise McpConnectionError(message) from failure

    async def _abandon(self) -> None:
        """Cancel a connection attempt nobody is waiting for any more.

        Unlike :meth:`disconnect`, nothing is waited out gracefully: the
        attempt has not produced a ready connection, so whatever it is blocked
        on -- a prompt, a sign-in, a handshake -- is cancelled at once, and
        the transport it opened is unwound in the supervisor's own task.
        """
        self._stop.set()
        self._wake.set()
        await self._stop_follower()
        task = self._task
        self._task = None
        if task is not None and not task.done():
            _ = task.cancel()
            _ = await asyncio.wait({task})
        if task is not None and not task.cancelled() and (failure := task.exception()) is not None:
            _logger.info("mcp_server_abandoned_attempt_failed", server_id=self.server_id, error=str(failure))
        self._client = None
        self._connected_at = None
        self._health = McpHealth.DISCONNECTED if self._config.enabled else McpHealth.DISABLED
        self._stderr.close()
        _logger.info("mcp_server_attempt_abandoned", server_id=self.server_id)
        self._notify_change()

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

        A ready connection is closed gracefully, with up to
        :data:`DISCONNECT_TIMEOUT_S` for the server to go. One that is not
        ready -- still waiting on a consent prompt, an OAuth sign-in in the
        browser or a handshake, or between reconnect attempts -- has nothing
        to close gracefully, and is cancelled at once, which ends any such
        wait.

        A connection that had already failed keeps its ``FAILED`` health and
        its recorded error, so the reason a server is not running survives
        the teardown that follows.

        Raises:
            asyncio.CancelledError: If the caller is cancelled while waiting
                for the supervisor task to finish.
        """
        await self._stop_follower()

        ready = self._health is McpHealth.READY
        self._stop.set()
        self._wake.set()
        task = self._task
        self._task = None
        if task is not None and not task.done() and not ready:
            _ = task.cancel()
            _ = await asyncio.wait({task})
        elif task is not None and not task.done():
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
            self._health = McpHealth.DISCONNECTED if self._config.enabled else McpHealth.DISABLED
        _logger.info("mcp_server_stopped", server_id=self.server_id)
        self._notify_change()

    async def refresh_catalog(self, *, force: bool = False) -> McpToolCatalog:
        """Re-list the server's tools.

        Without ``force`` the server's freshness hint is respected: a listing
        still inside its ``ttlMs`` window is returned without a request. With
        ``force`` the server is always asked, and the SDK's own response
        cache is refreshed too. A change notification forces: the server
        has just said the listing it gave is out of date, whatever its
        freshness hint promised.

        Args:
            force: Whether to ask the server even while the listing in hand
                is still fresh.

        Returns:
            McpToolCatalog: The current listing.

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
        if not force and current is not None and current.is_fresh(datetime.now(tz=UTC)):
            _logger.debug("mcp_catalog_still_fresh", server_id=self.server_id, ttl_ms=current.ttl_ms)
            return current
        try:
            catalog = await fetch_catalog(
                client,
                self.server_id,
                cache_mode="refresh" if force else "use",
                request_deadline=self.request_deadline,
            )
        except TimeoutError as exc:
            message = f"server '{self.server_id}': listing tools exceeded {self._config.request_timeout_s:.0f}s"
            raise McpConnectionError(message) from exc
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            message = f"server '{self.server_id}': cannot list tools: {failure_text(failure)}"
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
        on_progress: ProgressFn | None = None,
    ) -> CallToolResult:
        """Invoke one tool on the server.

        The call asks the server to report its progress. Each notice that
        reports more progress than before gives the call its full timeout
        again, up to the cap :mod:`intellicrack.mcp.operator_wait` sets, and
        every notice is handed to ``on_progress``. Cancelling the caller
        cancels the call on the server too.

        Args:
            tool_name: The server's own tool name, without the namespace.
            arguments: Parsed arguments for the call.
            timeout_s: Per-call timeout, defaulting to the server's
                configured one.
            on_progress: Receives each progress notice, or ``None``.

        Returns:
            CallToolResult: The server's result, error results included. A
            tool that reports failure is a result, not an exception.

        A call that finds the connection closed also wakes the supervisor,
        which rebuilds the connection instead of waiting for the next
        liveness probe to notice.

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
            async with self._tracked(ProgressKind.TOOL, tool_name, budget, on_progress) as meta:
                return await client.call_tool(tool_name, arguments, meta=meta)
        except TimeoutError as exc:
            message = f"server '{self.server_id}': call to {tool_name!r} exceeded {budget:.0f}s without progress, or its progress limit"
            raise McpConnectionError(message) from exc
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            failure = representative_failure(exc)
            if is_connection_loss(failure) and self._client is client:
                self._mark_dropped(f"call to {tool_name!r} found the connection closed: {failure_text(failure)}")
            message = f"server '{self.server_id}': call to {tool_name!r} failed: {failure_text(failure)}"
            raise McpConnectionError(message) from failure

    async def listen_for_changes(self, on_change: Callable[[str], None]) -> None:
        """Follow the current connection's tool-list change notices.

        On a 2026-07-28 connection the notices arrive on a
        ``subscriptions/listen`` stream, which is re-opened if the server
        ends it. On an older connection they arrive as
        ``notifications/tools/list_changed`` through the message handler.
        Either way each notice forces a real re-list, whatever the listing's
        freshness hint said. This runs for as long as the current connection
        lasts; :meth:`start_listening` is what keeps following across
        reconnects.

        Args:
            on_change: Callable invoked with the server id whenever a
                re-list moves the listing.
        """
        client = self._client
        if client is None:
            return
        self.set_change_listener(on_change)
        await self._follow(client)

    def start_listening(self, on_change: Callable[[str], None]) -> None:
        """Follow tool-list changes in the background, across reconnects.

        The follower belongs to one connection and ends with it; every later
        connection starts its own as soon as it is ready.

        Args:
            on_change: Callable invoked with the server id after a change.
        """
        self.set_change_listener(on_change)
        self._follow_changes = True
        client = self._client
        if client is not None and self._health is McpHealth.READY:
            self._start_follower(client)

    def _start_follower(self, client: Client) -> None:
        """Start following change notices for one ready connection.

        Args:
            client: The connection's entered client.
        """
        if not self._follow_changes:
            return
        task = self._listen_task
        if task is not None and not task.done():
            return
        self._listen_task = asyncio.create_task(self._follow(client), name=f"mcp-listen-{self.server_id}")

    async def _stop_follower(self) -> None:
        """Stop the change follower of the connection that is ending.

        The follower is awaited through :func:`asyncio.wait`, so its own
        cancellation is absorbed while a cancellation of the caller still
        propagates.
        """
        task = self._listen_task
        self._listen_task = None
        if task is None:
            return
        if not task.done():
            _ = task.cancel()
            _ = await asyncio.wait({task})
        if not task.cancelled() and (failure := task.exception()) is not None:
            _logger.info("mcp_change_follower_failed", server_id=self.server_id, error=str(failure))

    async def _follow(self, client: Client) -> None:
        """Follow change notices for one connection until it ends.

        Args:
            client: The connection's entered client.
        """
        if self._is_modern(client):
            await self._follow_subscription(client)
        else:
            await self._follow_notices()

    async def _follow_notices(self) -> None:
        """Re-list after each change notice a handshake-era server sends."""
        while True:
            _ = await self._change_notice.wait()
            self._change_notice.clear()
            await self._refresh_after_notice()

    async def _follow_subscription(self, client: Client) -> None:
        """Hold a ``subscriptions/listen`` stream open and re-list on each event.

        A stream the server ends, gracefully or not, is re-opened after
        :data:`LISTEN_RETRY_S`, and the listing is re-read on re-opening
        because events sent while no stream was open are not replayed. A
        server that refuses the subscription outright is not asked again on
        this connection.

        Args:
            client: The connection's entered client.

        Raises:
            asyncio.CancelledError: If the follower is cancelled.
        """
        reopened = False
        while True:
            try:
                if await self._consume_until_refiltered(client, reopened=reopened):
                    reopened = True
                    continue
            except asyncio.CancelledError:
                raise
            except SubscriptionLost as exc:
                _logger.info("mcp_change_subscription_lost", server_id=self.server_id, reason=str(exc))
            except ListenNotSupportedError as exc:
                _logger.info("mcp_change_subscription_unavailable", server_id=self.server_id, reason=str(exc))
                return
            except TRANSPORT_FAILURES as exc:
                _logger.info("mcp_change_subscription_unavailable", server_id=self.server_id, reason=str(exc))
                return
            reopened = True
            await asyncio.sleep(LISTEN_RETRY_S)

    async def _consume_until_refiltered(self, client: Client, *, reopened: bool) -> bool:
        """Hold one stream open until the server ends it or the resources subscribed to change.

        Args:
            client: The connection's entered client.
            reopened: Whether an earlier stream on this connection ended.

        Returns:
            bool: ``True`` when the stream was closed to re-open it with a new
            filter; ``False`` when the server ended it.
        """
        self._listen_filter_changed.clear()
        stream = asyncio.create_task(self._consume_subscription(client, reopened=reopened), name=f"mcp-listen-stream-{self.server_id}")
        refiltered = asyncio.create_task(self._listen_filter_changed.wait(), name=f"mcp-listen-filter-{self.server_id}")
        try:
            done, _ = await asyncio.wait({stream, refiltered}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (stream, refiltered):
                if not task.done():
                    _ = task.cancel()
            _ = await asyncio.gather(stream, refiltered, return_exceptions=True)
        if stream in done and not stream.cancelled():
            stream.result()
            return False
        _logger.info("mcp_change_subscription_refiltered", server_id=self.server_id, resources=len(self._subscriptions))
        return True

    async def _consume_subscription(self, client: Client, *, reopened: bool) -> None:
        """Hold one ``subscriptions/listen`` stream open until the server ends it.

        Args:
            client: The connection's entered client.
            reopened: Whether an earlier stream on this connection ended, so
                events may have been missed and the listing is re-read first.
        """
        async with AsyncExitStack() as stack:
            async with self.request_deadline():
                subscription = await stack.enter_async_context(
                    client.listen(
                        tools_list_changed=True,
                        prompts_list_changed=True,
                        resources_list_changed=True,
                        resource_subscriptions=sorted(self._subscriptions),
                    ),
                )
            _logger.info("mcp_change_subscription_open", server_id=self.server_id)
            if reopened:
                await self._refresh_after_notice()
            async for event in subscription:
                if isinstance(event, ResourceUpdated):
                    self._announce_context(McpContextChange.RESOURCE_UPDATED, event.uri)
                elif isinstance(event, ResourcesListChanged):
                    self._announce_context(McpContextChange.RESOURCES_LISTED)
                elif isinstance(event, PromptsListChanged):
                    self._announce_context(McpContextChange.PROMPTS_LISTED)
                else:
                    await self._refresh_after_notice()
        _logger.info("mcp_change_subscription_closed", server_id=self.server_id)

    async def _refresh_after_notice(self) -> None:
        """Re-list the server's tools because it said they changed."""
        try:
            _ = await self.refresh_catalog(force=True)
        except McpConnectionError as exc:
            _logger.warning("mcp_catalog_refresh_failed", server_id=self.server_id, error=str(exc))

    def _notify_change(self) -> None:
        """Invoke the change listener, absorbing a listener that raises."""
        listener = self._on_change
        if listener is None:
            return
        try:
            listener(self.server_id)
        except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
            _logger.warning("mcp_change_listener_failed", server_id=self.server_id, error=str(exc))


class _StreamPairTransport:
    """Adapts an already-open stream pair to the SDK's transport protocol.

    The transports are opened as context managers so their clients and task groups unwind correctly. The SDK's ``Client`` wants a
    transport it can enter itself, so the open pair is wrapped in one whose entry is a no-op and whose exit leaves the real teardown to the
    surrounding context. The read stream is watched on the way through, so the end of the server's output is reported.
    """

    def __init__(self, streams: tuple[Any, Any], on_closed: Callable[[], None] | None = None) -> None:
        """Initialize the adapter.

        Args:
            streams: The already-open read and write streams.
            on_closed: Called when the read stream ends, or ``None`` to leave
                it unwatched.
        """
        read_stream, write_stream = streams
        watched: Any = read_stream if on_closed is None else _WatchedReceiveStream(read_stream, on_closed)
        self._streams: tuple[Any, Any] = (watched, write_stream)

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

    The manager is the single place that knows which servers exist, which are up, and how to bring them up or down. Every coroutine it
    exposes must be awaited on one event loop -- inside the GUI, the persistent background loop the async bridge owns.
    """

    def __init__(
        self,
        store: McpConfigStore,
        resolver: McpSecretResolver,
        consent: McpConsentGate,
        *,
        elicitation_factory: Callable[[str], ElicitationFnT] | None = None,
        auth_factory: AuthFactory | None = None,
        hooks_factory: McpHooksFactory | None = None,
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
            hooks_factory: Builds the sampling, roots and logging callbacks
                one server is offered. Without one, none are offered.
        """
        self._store = store
        self._resolver = resolver
        self._consent = consent
        self._elicitation_factory = elicitation_factory
        self._auth_factory = auth_factory
        self._hooks_factory = hooks_factory
        self._document: McpConfigDocument = McpConfigStore.parse_document({})
        self._connections: dict[str, McpConnection] = {}
        self._order: list[str] = []
        self._listener: Callable[[str], None] | None = None
        self._context_listener: McpContextListener | None = None
        self._started = False
        self._stopped = False

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

    def _hooks_for(self, config: McpServerConfig) -> McpClientHooks | None:
        """Build the client-side callbacks one server is offered.

        Args:
            config: The server.

        Returns:
            McpClientHooks | None: The callbacks, or ``None`` when no factory
            is installed.
        """
        return self._hooks_factory(config) if self._hooks_factory is not None else None

    async def set_log_level(self, server_id: str, level: str | None) -> None:
        """Change the log level a running server is asked for.

        The saved configuration is the caller's to update; this applies the
        level to the live connection, if there is one.

        Args:
            server_id: The server.
            level: The level, or ``None``.
        """
        connection = self._connections.get(server_id)
        if connection is not None:
            await connection.set_log_level(level)

    async def announce_roots_changed(self, server_ids: Iterable[str]) -> list[str]:
        """Tell running servers that their roots have changed.

        Args:
            server_ids: The servers whose roots moved.

        Returns:
            list[str]: The servers that were sent
            ``notifications/roots/list_changed``; one on 2026-07-28 needs no
            notice, and one that is not running has nobody to tell.
        """
        told: list[str] = []
        for server_id in server_ids:
            connection = self._connections.get(server_id)
            if connection is not None and await connection.announce_roots_changed():
                told.append(server_id)
        return told

    def set_context_listener(self, listener: McpContextListener | None) -> None:
        """Choose who hears about changes to any server's resources and prompts.

        Args:
            listener: Receives each change, or ``None``.
        """
        self._context_listener = listener
        for connection in self._connections.values():
            connection.set_context_listener(listener)

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
        Servers are started concurrently, so one waiting on the operator -- a
        launch-consent prompt or an OAuth sign-in in the browser -- does not
        hold back every server configured after it.

        Starting the manager again after :meth:`stop` is allowed; it is what
        lifts the refusal :meth:`stop` puts on :meth:`start_server`.
        """
        self._document = self._store.load()
        self._stopped = False
        self._started = True
        reverted = await asyncio.to_thread(revert_stale_write_grants)
        if reverted:
            _logger.warning("mcp_stale_sandbox_grants_reverted", count=reverted)
        async with asyncio.TaskGroup() as group:
            for config in self._document.servers:
                if config.enabled:
                    _ = group.create_task(self._start_quietly(config.server_id), name=f"mcp-start-{config.server_id}")
        _logger.info(
            "mcp_manager_started",
            configured=len(self._document.servers),
            connected=sum(bool(connection.is_ready) for connection in self._connections.values()),
        )

    async def _start_quietly(self, server_id: str) -> None:
        """Start one server, leaving its failure on its own status.

        Args:
            server_id: The server to start.
        """
        with suppress(McpError):
            _ = await self.start_server(server_id)

    async def stop(self) -> None:
        """Bring every server down at once.

        Teardown is total: every connection is torn down even if another one
        raised, so no child process and no pending task outlives the call.
        The servers are torn down concurrently, so the call takes as long as
        the slowest server rather than the sum of them, and a server still
        connecting -- waiting on a prompt or an OAuth sign-in in the browser
        -- is cancelled at once rather than waited on.

        From here on :meth:`start_server` refuses, until :meth:`start` is
        called again: a start queued behind the stop, such as one the
        settings dialog submitted, never brings a server back up.

        A caller cancelled mid-teardown propagates
        :class:`asyncio.CancelledError` once every teardown has been
        cancelled with it.
        """
        self._stopped = True
        connections = [(server_id, connection) for server_id, connection in self._connections.items()]
        self._connections.clear()
        self._order.clear()
        async with asyncio.TaskGroup() as group:
            for server_id, connection in connections:
                _ = group.create_task(self._stop_quietly(server_id, connection), name=f"mcp-stop-{server_id}")
        self._started = False
        _logger.info("mcp_manager_stopped", servers=len(connections))

    @staticmethod
    async def _stop_quietly(server_id: str, connection: McpConnection) -> None:
        """Tear one connection down, logging a failure rather than raising it.

        Args:
            server_id: The server's id.
            connection: Its connection.

        Raises:
            asyncio.CancelledError: If the stop is cancelled.
        """
        try:
            await connection.disconnect()
        except asyncio.CancelledError:
            raise
        except TRANSPORT_FAILURES as exc:
            _logger.warning("mcp_manager_stop_error", server_id=server_id, error=str(exc))

    def _refuse_if_stopped(self, server_id: str) -> None:
        """Refuse to bring a server up once the manager has been stopped.

        Args:
            server_id: The server that was to be started.

        Raises:
            McpConnectionError: If :meth:`stop` has run and :meth:`start` has
                not run since.
        """
        if self._stopped:
            message = f"server '{server_id}' was not started: MCP has been shut down"
            raise McpConnectionError(message)

    async def start_server(self, server_id: str) -> McpServerStatus:
        """Bring one configured server up.

        Args:
            server_id: The server to start.

        Returns:
            McpServerStatus: The server's state once the attempt settled.

        Raises:
            McpConnectionError: If no such server is configured, the manager
                has been stopped, or the connection attempt failed.
        """
        self._refuse_if_stopped(server_id)
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
        self._refuse_if_stopped(server_id)

        try:
            _ = self._consent.note_identity(config)
        except McpConsentStoreError as exc:
            _logger.warning("mcp_identity_check_unsaved", server_id=server_id, error=str(exc))

        connection = McpConnection(
            config,
            self._resolver,
            elicitation_callback=self._elicitation_for(server_id),
            consent=self._consent,
            auth_factory=self._auth_factory,
            hooks=self._hooks_for(config),
        )
        connection.set_change_listener(self._on_connection_changed)
        connection.set_context_listener(self._context_listener)
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
            replace(config, enabled=True),
            self._resolver,
            elicitation_callback=self._elicitation_for(config.server_id),
            consent=self._consent,
            auth_factory=self._auth_factory,
            hooks=self._hooks_for(config),
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
