# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Second-pass critical-coverage tests for ``intellicrack.mcp.connection``.

These cover what the first pass left: a stderr pipe the operating system cannot create, a server that offers no resource subscriptions,
a handshake-era server that does not implement ``ping``, the reconnect budget running out, a change subscription that the server ends
gracefully, loses, or cannot serve, the manager reporting stale sandbox grants, and the manager absorbing a change listener that fails
while it stops a server.

Servers are real. Where a fixture server cannot be steered into a state, the test builds a real SDK ``Server`` from the SDK's own
handlers (a ``ping`` handler that answers "method not found", the SDK's ``ListenHandler`` whose ``close`` ends every listen stream
gracefully) and connects the product's own ``McpClient`` to it in-process. Expected values come from the SDK's documented behavior
(``ListenHandler.close`` ends streams with a result, ``Subscription`` raises ``SubscriptionLost`` on an abrupt drop,
``ListenNotSupportedError`` names the protocol version it requires), from the doubling backoff the module documents, and from the
Windows C runtime's fixed table of low-level file descriptors.

Where a state cannot be reached by waiting for it, the test sets a private data attribute of the real connection (its ``_client`` and
``_health`` to put an in-process client behind it, or its ``_stop`` event to skip a backoff wait) and says so.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Final, NoReturn, Protocol, TextIO, cast

import pytest
import structlog.testing
from mcp.server import Server
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR, METHOD_NOT_FOUND
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

from intellicrack.core.config import get_config_file
from intellicrack.mcp.client_session import McpClient
from intellicrack.mcp.config import HttpServerSpec, McpConfigDocument, McpConfigStore, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import (
    LISTEN_RETRY_S,
    MAX_RECONNECT_ATTEMPTS,
    McpConnection,
    McpConnectionManager,
    McpHealth,
)
from intellicrack.mcp.consent import McpConsentGate, TrustStore, deny_all_launches
from intellicrack.mcp.errors import McpConnectionError, McpConsentDeniedError, McpProtocolError
from intellicrack.mcp.sandbox_launch import GRANTS_FILENAME
from tests._helpers.mcp_features_support import private_resolver
from tests._helpers.mcp_lifecycle_support import approving_gate, call_text, network_config, network_server, stdio_config, wait_until


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Awaitable, Callable, Coroutine, Mapping, Sequence
    from pathlib import Path

    from mcp import Client
    from mcp.server import ServerRequestContext
    from mcp_types import EmptyResult, ListToolsResult, PaginatedRequestParams, RequestParams


_CONNECT_TIMEOUT_S: Final[float] = 90.0
_TEARDOWN_TIMEOUT_S: Final[float] = 30.0
_EVENT_DEADLINE_S: Final[float] = 30.0
_RECOVERY_DEADLINE_S: Final[float] = 8.0
_DESCRIPTOR_CAP: Final[int] = 100_000
_BACKOFF_CEILING_S: Final[float] = 60.0


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


def _http_config(server_id: str) -> McpServerConfig:
    """Build a remote server configuration that is never connected to.

    Args:
        server_id: The server id.

    Returns:
        McpServerConfig: The configuration.
    """
    return McpServerConfig(
        server_id=server_id,
        kind=McpTransportKind.HTTP,
        http=HttpServerSpec(url="http://127.0.0.1:9/mcp"),
        enabled=True,
    )


def _event_names(captured: Sequence[Mapping[str, object]]) -> list[str]:
    """List the event names structlog captured.

    Args:
        captured: The captured log entries.

    Returns:
        list[str]: Each entry's event name.
    """
    return [str(entry.get("event")) for entry in captured]


def _logged(captured: Sequence[Mapping[str, object]], event: str) -> list[Mapping[str, object]]:
    """Pick the captured log entries of one event.

    Args:
        captured: The captured log entries.
        event: The event name.

    Returns:
        list[Mapping[str, object]]: The matching entries, in order.
    """
    return [entry for entry in captured if entry.get("event") == event]


def _write_stale_ledger(directory: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the configuration directory into a test directory and record one write grant a crashed run left behind.

    The recorded directory no longer exists, so reverting the grant needs no change to any label.

    Args:
        directory: Per-test directory.
        monkeypatch: Redirects the configuration directory.

    Returns:
        Path: The grant ledger file.
    """
    state = directory / "state"
    state.mkdir()
    monkeypatch.setenv("INTELLICRACK_STATE_DIR", str(state))
    ledger = get_config_file(GRANTS_FILENAME)
    assert ledger.resolve().is_relative_to(directory.resolve())
    ledger.parent.mkdir(parents=True, exist_ok=True)
    gone = directory / "write-path-that-no-longer-exists"
    recorded = {os.path.normcase(str(gone)): {"directory": str(gone), "originalLabel": "S:", "existing": False}}
    _ = ledger.write_text(json.dumps(recorded), encoding="utf-8")
    return ledger


def _read_ledger(ledger: Path) -> object:
    """Decode the grant ledger file.

    Args:
        ledger: The ledger file.

    Returns:
        object: The decoded document.
    """
    return cast("object", json.loads(ledger.read_text(encoding="utf-8")))


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


async def _follow_subscription(connection: McpConnection, client: Client) -> None:
    """Run a connection's change-subscription follower directly.

    Args:
        connection: The connection.
        client: The entered client to follow.
    """
    follow = cast("Callable[[Client], Awaitable[None]]", _private(connection, "_follow_subscription"))
    await follow(client)


async def _supervise_attempts(connection: McpConnection) -> None:
    """Run a connection's connection attempts directly.

    Args:
        connection: The connection.
    """
    supervise = cast("Callable[[], Awaitable[None]]", _private(connection, "_supervise_attempts"))
    await supervise()


def _release_backoff(connection: McpConnection) -> None:
    """End the reconnect delay the supervisor is waiting out without requesting a stop.

    The supervisor waits out its delay on the connection's stop event. The event it waits on is set, and a fresh unset one takes its
    place before the supervisor looks again, so the wait ends and the loop goes on.

    Args:
        connection: The connection whose supervisor is waiting.
    """
    waited_on = _event(connection, "_stop")
    _assign(connection, "_stop", asyncio.Event())
    waited_on.set()


async def _refuse_ping(_ctx: ServerRequestContext[Any, Any], _params: RequestParams | None) -> EmptyResult:
    """Answer ``ping`` with "method not found", as a server that does not implement it does.

    Args:
        _ctx: The request context.
        _params: The request's parameters.

    Returns:
        EmptyResult: Never returns.

    Raises:
        MCPError: Always, with the ``METHOD_NOT_FOUND`` code.
    """
    await asyncio.sleep(0)
    message = "ping is not implemented"
    raise MCPError(code=METHOD_NOT_FOUND, message=message)


@asynccontextmanager
async def _legacy_client_without_ping() -> AsyncGenerator[Client]:
    """Connect the product's client, in the handshake era, to a real SDK server that does not implement ``ping``.

    Yields:
        Client: The entered client.
    """
    server: Server[dict[str, Any]] = Server("pingless", on_ping=_refuse_ping)
    async with McpClient(server, mode="legacy") as client:
        yield client


async def _refuse_listing(_ctx: ServerRequestContext[Any, Any], _params: PaginatedRequestParams | None) -> ListToolsResult:
    """Refuse every tool listing.

    Args:
        _ctx: The request context.
        _params: The request's parameters.

    Returns:
        ListToolsResult: Never returns.

    Raises:
        MCPError: Always, with the ``INTERNAL_ERROR`` code.
    """
    await asyncio.sleep(0)
    message = "listing refused"
    raise MCPError(code=INTERNAL_ERROR, message=message)


def test_a_stderr_pipe_the_system_cannot_create_is_a_connection_error(tmp_path: Path) -> None:
    """With every low-level file descriptor in use, creating the stderr pipe fails as a connection error, and works again once some are free.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("no-descriptors"), private_resolver(tmp_path))
    capture = cast("_StderrApi", _private(connection, "_stderr"))
    held: list[int] = []
    exhausted = False
    try:
        for _ in range(_DESCRIPTOR_CAP):
            try:
                held.append(os.open(os.devnull, os.O_RDONLY))
            except OSError:
                exhausted = True
                break
        with pytest.raises(McpConnectionError) as caught:
            _ = capture.open()
    finally:
        for descriptor in held:
            os.close(descriptor)
    assert exhausted
    assert str(caught.value).startswith("cannot create a stderr pipe for the server process: ")
    assert isinstance(caught.value.__cause__, OSError)
    assert _private(capture, "_thread") is None
    writer = capture.open()
    try:
        _ = writer.write("recovered\n")
    finally:
        capture.close()
    assert capture.tail(5) == ["recovered"]


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_server_without_resource_subscriptions_refuses_both_subscription_requests(tmp_path: Path) -> None:
    """A handshake-era server that declares no resource subscriptions is refused both a subscribe and an unsubscribe, naming the protocol breach.

    Args:
        tmp_path: Per-test directory.
    """
    with network_server("sse") as (_process, port):
        connection = McpConnection(network_config("no-subscribe", port, McpTransportKind.SSE), private_resolver(tmp_path))
        await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
        try:
            client = connection.client
            assert client is not None
            resources = client.server_capabilities.resources
            assert resources is None or not resources.subscribe
            with pytest.raises(McpProtocolError, match="'no-subscribe' does not offer resource subscriptions"):
                await connection.subscribe_resource("lifecycle://anything")
            with pytest.raises(McpProtocolError, match="'no-subscribe' does not offer resource subscriptions"):
                await connection.unsubscribe_resource("lifecycle://anything")
            assert connection.subscriptions == frozenset()
        finally:
            await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


@pytest.mark.asyncio
async def test_a_server_that_does_not_implement_ping_is_not_probed_again(tmp_path: Path) -> None:
    """A handshake-era server answering "method not found" to ``ping`` ends the probing: the probe reports it and does not fail the connection.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("pingless"), private_resolver(tmp_path))
    async with _legacy_client_without_ping() as client:
        negotiated = client.protocol_version
        assert negotiated not in MODERN_PROTOCOL_VERSIONS
        with structlog.testing.capture_logs() as captured:
            keep_probing = await _heartbeat(connection, client)
    assert keep_probing is False
    unsupported = _logged(captured, "mcp_heartbeat_unsupported")
    assert [entry.get("server_id") for entry in unsupported] == ["pingless"]
    assert [entry.get("protocol_version") for entry in unsupported] == [negotiated]


@pytest.mark.asyncio
async def test_a_connection_stops_probing_once_the_server_has_no_ping(tmp_path: Path) -> None:
    """A held-open connection to a server without ``ping`` sends one probe, then wakes again without sending another, and ends on a stop.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("holding"), private_resolver(tmp_path))
    wake = _event(connection, "_wake")
    stop = _event(connection, "_stop")
    hold_open = cast("Callable[[Client], Coroutine[Any, Any, None]]", _private(connection, "_hold_open"))
    async with _legacy_client_without_ping() as client:
        wake.set()
        holder = asyncio.create_task(hold_open(client))
        try:
            with structlog.testing.capture_logs() as captured:
                assert await wait_until(lambda: "mcp_heartbeat_unsupported" in _event_names(captured), timeout_s=_RECOVERY_DEADLINE_S)
                wake.set()
                assert await wait_until(lambda: not wake.is_set(), timeout_s=_RECOVERY_DEADLINE_S)
                stop.set()
                wake.set()
                _ = await asyncio.wait_for(holder, timeout=_RECOVERY_DEADLINE_S)
        finally:
            _ = holder.cancel()
            _ = await asyncio.wait({holder})
    assert _event_names(captured).count("mcp_heartbeat_unsupported") == 1


@pytest.mark.asyncio
async def test_the_reconnect_budget_runs_out_after_the_documented_backoff(tmp_path: Path) -> None:
    """A server that fails every attempt is retried with doubling delays capped at the ceiling, then given up on after the attempt budget.

    The delay waits are ended early by swapping the connection's private ``_stop`` event; the attempt counting and the delays computed
    and logged are the module's own.

    Args:
        tmp_path: Per-test directory.
    """

    def factory(_resolved: McpServerConfig) -> NoReturn:
        """Fail the way an unreachable endpoint does.

        Args:
            _resolved: The resolved configuration.

        Raises:
            OSError: Always.
        """
        message = "endpoint refused"
        raise OSError(message)

    connection = McpConnection(_http_config("exhausted"), private_resolver(tmp_path), auth_factory=factory)
    retries = MAX_RECONNECT_ATTEMPTS - 1
    with structlog.testing.capture_logs() as captured:
        task = asyncio.create_task(_supervise_attempts(connection))
        try:
            for scheduled in range(1, retries + 1):
                assert await wait_until(
                    lambda wanted=scheduled: len(_logged(captured, "mcp_server_reconnect_scheduled")) == wanted,
                    timeout_s=_EVENT_DEADLINE_S,
                )
                _release_backoff(connection)
            _ = await asyncio.wait_for(task, timeout=_EVENT_DEADLINE_S)
        finally:
            _ = task.cancel()
            _ = await asyncio.wait({task})
    scheduled_entries = _logged(captured, "mcp_server_reconnect_scheduled")
    assert [entry.get("attempt") for entry in scheduled_entries] == list(range(1, retries + 1))
    assert [entry.get("delay_s") for entry in scheduled_entries] == [min(2.0**index, _BACKOFF_CEILING_S) for index in range(retries)]
    assert len(_logged(captured, "mcp_server_connection_failed")) == MAX_RECONNECT_ATTEMPTS
    exhausted = _logged(captured, "mcp_server_reconnect_exhausted")
    assert [entry.get("attempts") for entry in exhausted] == [MAX_RECONNECT_ATTEMPTS]
    assert [entry.get("error") for entry in exhausted] == ["OSError: endpoint refused"]
    assert connection.status.health is McpHealth.FAILED


@pytest.mark.asyncio
async def test_a_subscription_the_server_ends_gracefully_is_opened_again_and_the_listing_re_read(tmp_path: Path) -> None:
    """When the server closes a listen stream with its result, the follower says so, waits, opens a new stream and re-reads the tool listing.

    The connection is given an in-process client by setting its private ``_client`` and ``_health``, so the follower runs on a connection
    whose server is a real SDK server holding the SDK's ``ListenHandler``.

    Args:
        tmp_path: Per-test directory.
    """
    handler = ListenHandler(InMemorySubscriptionBus())
    server: Server[dict[str, Any]] = Server("listener", on_list_tools=_refuse_listing, on_subscriptions_listen=handler)
    connection = McpConnection(_http_config("in-process"), private_resolver(tmp_path))
    async with McpClient(server) as client:
        assert client.protocol_version in MODERN_PROTOCOL_VERSIONS
        _assign(connection, "_client", client)
        _assign(connection, "_health", McpHealth.READY)
        with structlog.testing.capture_logs() as captured:
            follower = asyncio.create_task(connection.listen_for_changes(lambda _server_id: None))
            try:
                assert await wait_until(lambda: len(_logged(captured, "mcp_change_subscription_open")) == 1, timeout_s=_EVENT_DEADLINE_S)
                assert _logged(captured, "mcp_catalog_refresh_failed") == []
                handler.close()
                assert await wait_until(lambda: "mcp_change_subscription_closed" in _event_names(captured), timeout_s=_EVENT_DEADLINE_S)
                assert not follower.done()
                assert await wait_until(
                    lambda: (
                        len(_logged(captured, "mcp_change_subscription_open")) == 2
                        and bool(_logged(captured, "mcp_catalog_refresh_failed"))
                    ),
                    timeout_s=LISTEN_RETRY_S + _EVENT_DEADLINE_S,
                )
            finally:
                _ = follower.cancel()
                _ = await asyncio.wait({follower})
    refresh = _logged(captured, "mcp_catalog_refresh_failed")
    assert [entry.get("error") for entry in refresh] == ["server 'in-process': cannot list tools: listing refused"]
    assert follower.cancelled()


@pytest.mark.asyncio
async def test_a_change_subscription_is_not_attempted_on_a_handshake_era_connection(tmp_path: Path) -> None:
    """Asking a handshake-era connection to follow a ``subscriptions/listen`` stream ends the follower with the SDK's reason, logged once.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(_http_config("era"), private_resolver(tmp_path))
    async with _legacy_client_without_ping() as client:
        negotiated = client.protocol_version
        with structlog.testing.capture_logs() as captured:
            await asyncio.wait_for(_follow_subscription(connection, client), timeout=_RECOVERY_DEADLINE_S)
    unavailable = _logged(captured, "mcp_change_subscription_unavailable")
    assert len(unavailable) == 1
    reason = str(unavailable[0].get("reason"))
    assert "it requires 2026-07-28" in reason
    assert repr(negotiated) in reason


@pytest.mark.spawns_process
@pytest.mark.asyncio
async def test_a_follower_whose_server_vanished_logs_the_lost_subscription_and_gives_up(tmp_path: Path) -> None:
    """When the server process exits under an open listen stream, the follower logs the lost subscription, waits, finds no session and ends.

    Args:
        tmp_path: Per-test directory.
    """
    connection = McpConnection(stdio_config("vanishing"), private_resolver(tmp_path), consent=approving_gate(tmp_path / "trust.json"))
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        client = connection.client
        assert client is not None
        assert client.protocol_version in MODERN_PROTOCOL_VERSIONS
        with structlog.testing.capture_logs() as captured:
            follower = asyncio.create_task(connection.listen_for_changes(lambda _server_id: None))
            try:
                assert await wait_until(lambda: "mcp_change_subscription_open" in _event_names(captured), timeout_s=_EVENT_DEADLINE_S)
                assert await call_text(connection, "quit") == "leaving"
                assert await wait_until(lambda: "mcp_change_subscription_lost" in _event_names(captured), timeout_s=_EVENT_DEADLINE_S)
                done, _pending = await asyncio.wait({follower}, timeout=LISTEN_RETRY_S + _EVENT_DEADLINE_S)
                assert follower in done
                assert follower.exception() is None
            finally:
                _ = follower.cancel()
                _ = await asyncio.wait({follower})
        assert len(_logged(captured, "mcp_change_subscription_lost")) == 1
        assert len(_logged(captured, "mcp_change_subscription_unavailable")) == 1
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


@pytest.mark.asyncio
async def test_starting_the_manager_reports_the_stale_sandbox_grants_it_reverted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A write grant a crashed run left in the ledger, whose directory is gone, is reverted at start, counted in the log and dropped from the ledger.

    Args:
        tmp_path: Per-test directory.
        monkeypatch: Redirects the configuration directory into the test's directory.
    """
    ledger = _write_stale_ledger(tmp_path, monkeypatch)
    manager = _manager(tmp_path, [], approving_gate(tmp_path / "trust.json"))
    try:
        with structlog.testing.capture_logs() as captured:
            await asyncio.wait_for(manager.start(), timeout=_CONNECT_TIMEOUT_S)
    finally:
        await manager.stop()
    assert [entry.get("count") for entry in _logged(captured, "mcp_stale_sandbox_grants_reverted")] == [1]
    assert _read_ledger(ledger) == {}


@pytest.mark.asyncio
async def test_stopping_the_manager_absorbs_a_change_listener_that_fails_with_an_os_error(tmp_path: Path) -> None:
    """A change listener raising ``OSError`` while a server is torn down is logged by the manager's stop and does not break it.

    Args:
        tmp_path: Per-test directory.
    """
    gate = McpConsentGate(TrustStore(tmp_path / "trust.json"), deny_all_launches)
    manager = _manager(tmp_path, [stdio_config("listened")], gate)
    with pytest.raises(McpConsentDeniedError):
        _ = await manager.start_server("listened")
    assert manager.connection("listened") is not None

    def failing(_server_id: str) -> None:
        """Fail the way a broken output does.

        Args:
            _server_id: The server that changed.

        Raises:
            OSError: Always.
        """
        message = "listener broke"
        raise OSError(message)

    manager.set_change_listener(failing)
    with structlog.testing.capture_logs() as captured:
        await asyncio.wait_for(manager.stop(), timeout=_TEARDOWN_TIMEOUT_S)
    errors = _logged(captured, "mcp_manager_stop_error")
    assert [(entry.get("server_id"), entry.get("error")) for entry in errors] == [("listened", "listener broke")]
    assert manager.connection("listened") is None
