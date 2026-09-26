# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for OAuth state that has to survive a restart, and for the loopback redirect.

Every gate runs the SDK's real OAuth client against a real authorization server and a real MCP resource server on a *different* origin
(``tests/_helpers/mcp_oauth_split_server.py``). A "restart" is a new connection, a new token storage and a new OAuth provider reading the
same keyring, which is exactly what a new Intellicrack process does.

Covered: a configured pre-registered client id is used instead of registering; a registration made with a separate authorization server
is reused after a restart; an expired access token is refreshed after a restart instead of forcing a new sign-in; a step-up after a
restart asks only for scopes the server named; and concurrent sign-ins each get their own loopback port, with stray requests to that port
ignored.
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from mcp.shared.auth import AuthorizationCodeResult
from pydantic import AnyHttpUrl, ConfigDict, TypeAdapter

from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.auth import KeyringTokenStorage, build_oauth_provider, credential_key, issuer_for
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_oauth_split_server import ADMIN_SCOPE, BASE_SCOPE, AuthorizationState, SplitOAuthServers, free_port
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_CONNECT_TIMEOUT_S = 90.0
_TEARDOWN_TIMEOUT_S = 15.0
_PREREGISTERED_ID = "intellicrack-desktop"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CredentialStore]:
    """A credential store over a private file keyring.

    Args:
        tmp_path: Per-test directory.

    Yields:
        CredentialStore: The store.
    """
    with installed_keyring(private_file_keyring(tmp_path / "keyring_pass.cfg")):
        yield CredentialStore()


class _HeadlessBrowser:
    """Plays the browser: follows the authorization URL and hands the code back directly.

    Attributes:
        visits: How many times the authorization page was opened.
        pending: The captured redirect parameters.
    """

    def __init__(self) -> None:
        """Start with nothing captured."""
        self.visits = 0
        self.pending: dict[str, str] = {}

    async def redirect(self, authorization_url: str) -> None:
        """Open the authorization URL and capture the redirect.

        Args:
            authorization_url: Where a browser would be sent.
        """
        self.visits += 1
        async with httpx2.AsyncClient(follow_redirects=False) as client:
            response = await client.get(authorization_url)
        query = parse_qs(urlparse(response.headers.get("location", "")).query)
        self.pending = {name: values[0] for name, values in query.items()}

    async def callback(self) -> AuthorizationCodeResult:
        """Return what the authorization server redirected with.

        Returns:
            AuthorizationCodeResult: The code, state and issuer.

        Raises:
            RuntimeError: If the authorization server issued no code.
        """
        if "code" not in self.pending:
            message = f"the authorization server issued no code: {self.pending}"
            raise RuntimeError(message)
        return AuthorizationCodeResult(code=self.pending["code"], state=self.pending.get("state"), iss=self.pending.get("iss"))


def _connection(
    server_id: str,
    spec: HttpServerSpec,
    store: CredentialStore,
    browser: _HeadlessBrowser,
) -> McpConnection:
    """Build a connection whose OAuth provider reads and writes ``store``.

    Args:
        server_id: The configured server id.
        spec: The endpoint.
        store: The credential store standing in for the OS keyring.
        browser: The headless browser.

    Returns:
        McpConnection: An unconnected connection.
    """
    config = McpServerConfig(server_id=server_id, kind=McpTransportKind.HTTP, http=spec, enabled=True, request_timeout_s=30.0)

    def factory(_config: McpServerConfig) -> httpx2.Auth:
        """Build a fresh provider over fresh storage, as a new process would.

        Args:
            _config: The resolved server configuration.

        Returns:
            httpx2.Auth: The OAuth handler.
        """
        storage = KeyringTokenStorage(store, server_id, issuer_for(spec))
        return build_oauth_provider(spec, storage, redirect_handler=browser.redirect, callback_handler=browser.callback)

    return McpConnection(config, McpSecretResolver(store), auth_factory=factory)


async def _session(connection: McpConnection) -> int:
    """Connect, read the catalog and disconnect.

    Args:
        connection: The connection.

    Returns:
        int: The number of tools the server published.
    """
    await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
    try:
        catalog = connection.catalog
        assert catalog is not None
        return catalog.tool_count
    finally:
        await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)


class TestPreregisteredClient:
    """A configured ``oauthClientId`` is the identity the flow uses."""

    def test_preregistered_client_id_is_used_without_registration(self, store: CredentialStore) -> None:
        """An authorization server with no registration endpoint accepts the configured client id.

        Args:
            store: Private credential store.
        """
        state = AuthorizationState(allow_registration=False, preregistered={_PREREGISTERED_ID})
        with SplitOAuthServers(state) as servers:
            spec = HttpServerSpec(url=servers.mcp_url, oauth_client_id=_PREREGISTERED_ID)
            browser = _HeadlessBrowser()
            count = asyncio.run(_session(_connection("prereg", spec, store, browser)))
        assert count > 0
        assert state.registrations == []
        assert state.authorize_requests
        assert {request.get("client_id") for request in state.authorize_requests} == {_PREREGISTERED_ID}
        assert {request.get("client_id") for request in state.grants("authorization_code")} == {_PREREGISTERED_ID}


class TestRegistrationSurvivesRestart:
    """A registration made with an authorization server on another origin is reused after a restart."""

    def test_registration_is_reused_by_the_next_process(self, store: CredentialStore) -> None:
        """The second process signs in again with the stored client id and registers nothing.

        Args:
            store: Private credential store.
        """
        with SplitOAuthServers() as servers:
            spec = HttpServerSpec(url=servers.mcp_url)
            assert issuer_for(spec) != servers.authorization_origin
            first = _HeadlessBrowser()
            assert asyncio.run(_session(_connection("split", spec, store, first))) > 0
            assert len(servers.state.registrations) == 1

            reloaded = asyncio.run(KeyringTokenStorage(store, "split", issuer_for(spec)).get_client_info())
            assert reloaded is not None, "the stored registration was discarded on reload"
            assert reloaded.client_id == servers.state.registrations[0]

            servers.state.revoke_access_tokens()
            second = _HeadlessBrowser()
            assert asyncio.run(_session(_connection("split", spec, store, second))) > 0
            assert second.visits == 1
            assert len(servers.state.registrations) == 1, "the second process registered a new client"
            assert servers.state.authorize_requests[-1].get("client_id") == servers.state.registrations[0]

    def test_origin_drops_default_ports_like_the_sdk(self) -> None:
        """``https://host:443`` and ``https://HOST`` file credentials under the SDK's rendering of the origin."""
        adapter = TypeAdapter(AnyHttpUrl, config=ConfigDict(url_preserve_empty_path=True))
        explicit = issuer_for(HttpServerSpec(url="https://Example.COM:443/mcp"))
        implicit = issuer_for(HttpServerSpec(url="https://example.com/mcp"))
        assert explicit == implicit == str(adapter.validate_python("https://example.com")) == "https://example.com"
        assert issuer_for(HttpServerSpec(url="http://127.0.0.1:8080/mcp")) == "http://127.0.0.1:8080"
        assert credential_key("s", explicit, "tokens") == credential_key("s", implicit, "tokens")


class TestRefreshAfterRestart:
    """An expired access token is refreshed after a restart rather than forcing a new sign-in."""

    def test_expired_token_is_refreshed_by_the_next_process(self, store: CredentialStore) -> None:
        """The second process uses the refresh token at the authorization server's token endpoint.

        Args:
            store: Private credential store.
        """
        with SplitOAuthServers(AuthorizationState(expires_in=2)) as servers:
            spec = HttpServerSpec(url=servers.mcp_url)
            first = _HeadlessBrowser()
            assert asyncio.run(_session(_connection("refresh", spec, store, first))) > 0
            assert first.visits == 1
            refreshes_before = len(servers.state.grants("refresh_token"))
            time.sleep(2.5)

            second = _HeadlessBrowser()
            assert asyncio.run(_session(_connection("refresh", spec, store, second))) > 0
            assert second.visits == 0, "the expired token forced a new interactive sign-in"
            assert len(servers.state.grants("refresh_token")) > refreshes_before
            assert len(servers.state.grants("authorization_code")) == 1


class TestScopeIsNeverInvented:
    """Scope comes only from what the servers named."""

    def test_step_up_after_restart_requests_only_server_scopes(self, store: CredentialStore) -> None:
        """A step-up in a new process asks for the granted scope plus the challenged one, nothing else.

        Args:
            store: Private credential store.
        """
        with SplitOAuthServers() as servers:
            spec = HttpServerSpec(url=servers.mcp_url)
            assert asyncio.run(_session(_connection("scoped", spec, store, _HeadlessBrowser()))) > 0
            assert servers.state.authorize_requests[0].get("scope") == BASE_SCOPE

            servers.state.required_scopes = (BASE_SCOPE, ADMIN_SCOPE)
            second = _HeadlessBrowser()
            assert asyncio.run(_session(_connection("scoped", spec, store, second))) > 0
            assert second.visits == 1
            requested = servers.state.authorize_requests[-1].get("scope", "").split()
            assert sorted(requested) == sorted([BASE_SCOPE, ADMIN_SCOPE])


class _LoopbackBrowser:
    """Plays the browser against the real loopback listener, with stray requests first.

    Attributes:
        redirect_uris: The redirect URI each authorization request named.
        stray_statuses: Status codes the listener gave the stray requests.
    """

    def __init__(self, barrier: asyncio.Barrier) -> None:
        """Start with nothing captured.

        Args:
            barrier: Held until every concurrent flow has its listener open.
        """
        self._barrier = barrier
        self.redirect_uris: list[str] = []
        self.stray_statuses: list[int] = []

    async def redirect(self, authorization_url: str) -> None:
        """Hit the listener with unrelated requests, then deliver the real redirect.

        Args:
            authorization_url: Where a browser would be sent.
        """
        async with httpx2.AsyncClient(follow_redirects=False) as client:
            response = await client.get(authorization_url)
            location = response.headers["location"]
            target = urlparse(location)
            self.redirect_uris.append(f"{target.scheme}://{target.netloc}{target.path}")
            _ = await asyncio.wait_for(self._barrier.wait(), timeout=30.0)
            base = f"{target.scheme}://{target.netloc}"
            for stray in ("/favicon.ico", "/", "/callback?code=forged&state=wrong", "/callback?error=access_denied"):
                self.stray_statuses.append((await client.get(base + stray)).status_code)
            await asyncio.sleep(0.2)
            _ = await client.get(location)


class TestLoopbackRedirect:
    """Concurrent sign-ins each own a loopback port and ignore stray requests."""

    def test_concurrent_flows_get_separate_ports_and_ignore_strays(self, store: CredentialStore) -> None:
        """Two servers sign in at once through the default loopback listener; both complete.

        Args:
            store: Private credential store.
        """
        preferred = free_port()
        with SplitOAuthServers() as servers:
            spec = HttpServerSpec(url=servers.mcp_url)

            async def run() -> tuple[list[int], _LoopbackBrowser, _LoopbackBrowser]:
                barrier = asyncio.Barrier(2)
                browsers = (_LoopbackBrowser(barrier), _LoopbackBrowser(barrier))
                connections: list[McpConnection] = []
                for server_id, browser in zip(("loop-a", "loop-b"), browsers, strict=True):
                    config = McpServerConfig(
                        server_id=server_id,
                        kind=McpTransportKind.HTTP,
                        http=spec,
                        enabled=True,
                        request_timeout_s=30.0,
                    )

                    def factory(_config: McpServerConfig, server_id: str = server_id, browser: _LoopbackBrowser = browser) -> httpx2.Auth:
                        storage = KeyringTokenStorage(store, server_id, issuer_for(spec))
                        return build_oauth_provider(
                            spec,
                            storage,
                            redirect_handler=browser.redirect,
                            callback_port=preferred,
                            callback_timeout_s=30.0,
                        )

                    connections.append(McpConnection(config, McpSecretResolver(store), auth_factory=factory))
                counts = await asyncio.gather(*(_session(connection) for connection in connections))
                return list(counts), browsers[0], browsers[1]

            counts, first, second = asyncio.run(run())
        assert all(count > 0 for count in counts)
        ports = {urlparse(uri).port for uri in first.redirect_uris + second.redirect_uris}
        assert len(ports) == 2, "two concurrent sign-ins shared one loopback port"
        assert preferred in ports
        assert all(status in {400, 404} for status in first.stray_statuses + second.stray_statuses)
        assert {request.get("redirect_uri", "").rsplit(":", 1)[-1] for request in servers.state.authorize_requests} == {
            f"{port}/callback" for port in ports
        }
