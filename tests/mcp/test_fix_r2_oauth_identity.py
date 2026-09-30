# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 22: a configured client id wins over a stored registration, and credentials filed under an old ``:443`` key are kept.

The client id gates run the SDK's real OAuth client against a real authorization server and a real MCP resource server on different
loopback origins, over a private keyring. A registration made dynamically before ``oauthClientId`` was configured no longer beats it, and a
stored registration the SDK discards for naming another issuer no longer sends the flow to dynamic registration when a client id is
configured. The migration gates file artefacts under the key an earlier release computed for an explicit default port and read them back
through the functions the settings dialog and the connection use.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Final
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthToken

from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.store import CredentialStore
from intellicrack.mcp.auth import (
    KeyringTokenStorage,
    build_oauth_provider,
    credential_key,
    has_stored_credentials,
    issuer_for,
    legacy_issuers_for,
    sign_out,
)
from intellicrack.mcp.config import HttpServerSpec, McpServerConfig, McpTransportKind
from intellicrack.mcp.connection import McpConnection
from intellicrack.mcp.secrets import McpSecretResolver
from tests._helpers.mcp_oauth_split_server import AuthorizationState, SplitOAuthServers
from tests._helpers.private_keyring import installed_keyring, private_file_keyring


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_CONNECT_TIMEOUT_S: Final[float] = 90.0
_TEARDOWN_TIMEOUT_S: Final[float] = 15.0
_CONFIGURED_ID: Final[str] = "intellicrack-configured"
_OTHER_ISSUER: Final[str] = "http://127.0.0.1:9"
_DEFAULT_PORT_URL: Final[str] = "https://Example.COM:443/mcp"
_EARLIER_ORIGIN: Final[str] = "https://example.com:443"


@pytest.fixture
def store(tmp_path: Path) -> Iterator[CredentialStore]:
    """A credential store over a private file keyring and a private ``.env``.

    Args:
        tmp_path: Per-test directory.

    Yields:
        CredentialStore: The store.
    """
    with installed_keyring(private_file_keyring(tmp_path / "keyring_pass.cfg")):
        yield CredentialStore(fallback_loader=CredentialLoader(env_path=tmp_path / ".env"))


class _HeadlessBrowser:
    """Plays the browser: follows the authorization URL and hands the code back directly.

    Attributes:
        visits: How many times the authorization page was opened.
        pending: The captured redirect parameters.
    """

    visits: int
    pending: dict[str, str]

    def __init__(self) -> None:
        """Start with nothing captured."""
        self.visits = 0
        self.pending = {}

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


def _session(server_id: str, spec: HttpServerSpec, store: CredentialStore, browser: _HeadlessBrowser) -> int:
    """Connect as a fresh process would, read the catalog and disconnect.

    Args:
        server_id: The configured server id.
        spec: The endpoint.
        store: The credential store standing in for the OS keyring.
        browser: The headless browser.

    Returns:
        int: The number of tools the server published.
    """
    config = McpServerConfig(server_id=server_id, kind=McpTransportKind.HTTP, http=spec, enabled=True, request_timeout_s=30.0)

    def factory(_config: McpServerConfig) -> httpx2.Auth:
        """Build a fresh provider over fresh storage.

        Args:
            _config: The resolved server configuration.

        Returns:
            httpx2.Auth: The OAuth handler.
        """
        storage = KeyringTokenStorage(store, server_id, issuer_for(spec), legacy_issuers=legacy_issuers_for(spec))
        return build_oauth_provider(spec, storage, redirect_handler=browser.redirect, callback_handler=browser.callback)

    connection = McpConnection(config, McpSecretResolver(store), auth_factory=factory)

    async def run() -> int:
        """Connect, count the tools, disconnect.

        Returns:
            int: The tool count.
        """
        await asyncio.wait_for(connection.connect(), timeout=_CONNECT_TIMEOUT_S)
        try:
            catalog = connection.catalog
            assert catalog is not None
            return catalog.tool_count
        finally:
            await asyncio.wait_for(connection.disconnect(), timeout=_TEARDOWN_TIMEOUT_S)

    return asyncio.run(run())


def test_configured_client_id_replaces_a_stored_registration(store: CredentialStore) -> None:
    """Configuring ``oauthClientId`` after a dynamic registration signs in with the configured id, and the old registration is gone.

    Args:
        store: Private credential store.
    """
    state = AuthorizationState(preregistered={_CONFIGURED_ID})
    with SplitOAuthServers(state) as servers:
        assert _session("switch", HttpServerSpec(url=servers.mcp_url), store, _HeadlessBrowser()) > 0
        assert len(state.registrations) == 1

        configured = HttpServerSpec(url=servers.mcp_url, oauth_client_id=_CONFIGURED_ID)
        browser = _HeadlessBrowser()
        assert _session("switch", configured, store, browser) > 0
    assert browser.visits == 1
    assert len(state.registrations) == 1
    assert state.authorize_requests[-1].get("client_id") == _CONFIGURED_ID
    assert state.grants("authorization_code")[-1].get("client_id") == _CONFIGURED_ID
    stored = asyncio.run(KeyringTokenStorage(store, "switch", issuer_for(configured)).get_client_info())
    assert stored is None or stored.client_id == _CONFIGURED_ID


def test_discarded_registration_falls_back_to_the_configured_id(store: CredentialStore) -> None:
    """A stored registration bound to another issuer, which the SDK discards, is replaced by the configured id, not a new registration.

    Args:
        store: Private credential store.
    """
    state = AuthorizationState(preregistered={_CONFIGURED_ID})
    with SplitOAuthServers(state) as servers:
        plain = HttpServerSpec(url=servers.mcp_url)
        assert _session("rebound", plain, store, _HeadlessBrowser()) > 0
        storage = KeyringTokenStorage(store, "rebound", issuer_for(plain))
        registered = asyncio.run(storage.get_client_info())
        assert registered is not None

        async def rebind() -> None:
            """Leave only a registration bound to another authorization server, as a moved server would."""
            _ = await storage.clear()
            moved = OAuthClientInformationFull.model_validate({**registered.model_dump(mode="json"), "issuer": _OTHER_ISSUER})
            await storage.set_client_info(moved)

        asyncio.run(rebind())
        browser = _HeadlessBrowser()
        assert _session("rebound", HttpServerSpec(url=servers.mcp_url, oauth_client_id=_CONFIGURED_ID), store, browser) > 0
    assert len(state.registrations) == 1
    assert state.authorize_requests[-1].get("client_id") == _CONFIGURED_ID


def _file_as_earlier_release(store: CredentialStore, server_id: str, suffix: str, payload: str) -> None:
    """Store one artefact under the key an earlier release computed for ``https://example.com:443``.

    Args:
        store: The credential store.
        server_id: The server.
        suffix: ``tokens`` or ``client``.
        payload: The artefact's JSON, as that release wrote it.
    """
    asyncio.run(store.set(credential_key(server_id, _EARLIER_ORIGIN, suffix), ProviderCredentials(api_key=payload), key_name=suffix))


def _held(store: CredentialStore, key: str) -> str | None:
    """Read what one credential-store key holds.

    Args:
        store: The credential store.
        key: The key.

    Returns:
        str | None: The stored value, or ``None``.
    """
    found = asyncio.run(store.get_secret(key))
    return found.api_key if found is not None else None


def test_credentials_under_the_earlier_default_port_key_are_moved(store: CredentialStore) -> None:
    """Tokens and a registration filed under ``https://example.com:443`` are found, moved under the current key, and used from there.

    Args:
        store: Private credential store.
    """
    spec = HttpServerSpec(url=_DEFAULT_PORT_URL)
    assert legacy_issuers_for(spec) == (_EARLIER_ORIGIN,)
    assert issuer_for(spec) == "https://example.com"
    token = OAuthToken(access_token="earlier-access", token_type="Bearer", refresh_token="earlier-refresh")
    registration = OAuthClientInformationFull(client_id="dcr-earlier", redirect_uris=None)
    _file_as_earlier_release(store, "moved", "tokens", token.model_dump_json(exclude_none=True))
    _file_as_earlier_release(store, "moved", "client", registration.model_dump_json(exclude_none=True))

    assert asyncio.run(has_stored_credentials(store, "moved", issuer_for(spec), legacy_issuers=legacy_issuers_for(spec)))
    assert _held(store, credential_key("moved", _EARLIER_ORIGIN, "tokens")) is None
    assert _held(store, credential_key("moved", issuer_for(spec), "tokens")) is not None

    storage = KeyringTokenStorage(store, "moved", issuer_for(spec), legacy_issuers=legacy_issuers_for(spec))
    loaded = asyncio.run(storage.get_tokens())
    client = asyncio.run(storage.get_client_info())
    assert loaded is not None
    assert loaded.access_token == "earlier-access"
    assert loaded.refresh_token == "earlier-refresh"
    assert client is not None
    assert client.client_id == "dcr-earlier"
    assert _held(store, credential_key("moved", _EARLIER_ORIGIN, "client")) is None


def test_sign_out_clears_the_earlier_key_too(store: CredentialStore) -> None:
    """Signing out removes artefacts still filed under the earlier key, so no old token outlives it.

    Args:
        store: Private credential store.
    """
    spec = HttpServerSpec(url=_DEFAULT_PORT_URL)
    token = OAuthToken(access_token="earlier-access", token_type="Bearer")
    _file_as_earlier_release(store, "leaving", "tokens", token.model_dump_json(exclude_none=True))

    assert asyncio.run(sign_out(store, "leaving", issuer_for(spec), legacy_issuers=legacy_issuers_for(spec))) is True
    assert _held(store, credential_key("leaving", _EARLIER_ORIGIN, "tokens")) is None
    assert not asyncio.run(has_stored_credentials(store, "leaving", issuer_for(spec), legacy_issuers=legacy_issuers_for(spec)))
