# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, item 22: a provider's OAuth sign-in completes whatever loopback path and port its redirect URI names.

The gates run :meth:`OAuthManager.run_authorization_flow` against a real authorization server with PKCE and a real token endpoint. The
browser is played by a thread that follows the authorization page's redirect to the real loopback callback server, exactly as a browser
tab would. A redirect URI with its own path and port, and the default one, both end in a token; one naming a host the callback server
cannot listen on is refused before any page is opened.
"""

from __future__ import annotations

import asyncio
import threading
import webbrowser
from typing import TYPE_CHECKING, Final

import httpx
import pytest

from intellicrack.credentials import oauth as oauth_module
from intellicrack.credentials.oauth import OAuthCallbackError, OAuthConfig, OAuthManager, OAuthProvider
from tests._helpers.mcp_oauth_split_server import BASE_SCOPE, AuthorizationState, SplitOAuthServers, free_port


if TYPE_CHECKING:
    from collections.abc import Iterator


_CLIENT_ID: Final[str] = "provider-desktop"
_FLOW_TIMEOUT_S: Final[float] = 60.0
_REQUEST_TIMEOUT_S: Final[float] = 10.0


class _ThreadedBrowser:
    """Plays the browser on its own thread: opens the authorization page and follows its redirect to the loopback callback.

    Attributes:
        opened: Every URL handed to the browser.
        callbacks: Every callback URL the authorization server redirected to.
        errors: Anything that went wrong while following them.
    """

    opened: list[str]
    callbacks: list[str]
    errors: list[str]

    def __init__(self) -> None:
        """Start with nothing opened."""
        self.opened = []
        self.callbacks = []
        self.errors = []

    def open(self, url: str, *_options: object) -> bool:
        """Start following an authorization URL, as a browser tab would.

        Args:
            url: The authorization URL.
            *_options: Window placement and raise flags, ignored.

        Returns:
            bool: Always ``True``.
        """
        self.opened.append(url)
        threading.Thread(target=self._follow, args=(url,), daemon=True).start()
        return True

    def _follow(self, url: str) -> None:
        """Open the authorization page, then the callback it redirects to.

        Args:
            url: The authorization URL.
        """
        try:
            with httpx.Client(follow_redirects=False, timeout=_REQUEST_TIMEOUT_S, trust_env=False) as client:
                location = client.get(url).headers.get("location", "")
                self.callbacks.append(location)
                _ = client.get(location)
        except httpx.HTTPError as exc:
            self.errors.append(str(exc))


@pytest.fixture
def browser(monkeypatch: pytest.MonkeyPatch) -> _ThreadedBrowser:
    """Route the OAuth module's browser launch to the threaded browser.

    Args:
        monkeypatch: Replaces the browser launcher.

    Returns:
        _ThreadedBrowser: The browser.
    """
    player = _ThreadedBrowser()
    monkeypatch.setattr(webbrowser, "open", player.open)
    assert oauth_module.webbrowser is webbrowser
    return player


@pytest.fixture
def servers() -> Iterator[SplitOAuthServers]:
    """Run a real authorization server that knows the provider's client id.

    Yields:
        SplitOAuthServers: The running servers.
    """
    with SplitOAuthServers(AuthorizationState(allow_registration=False, preregistered={_CLIENT_ID})) as running:
        yield running


def _config(servers: SplitOAuthServers, redirect_uri: str) -> OAuthConfig:
    """Describe the provider's OAuth client against the running authorization server.

    Args:
        servers: The running servers.
        redirect_uri: The redirect URI the provider registered.

    Returns:
        OAuthConfig: The configuration.
    """
    return OAuthConfig(
        provider=OAuthProvider.HUGGINGFACE,
        client_id=_CLIENT_ID,
        client_secret=None,
        authorization_url=f"{servers.authorization_origin}/authorize",
        token_url=f"{servers.authorization_origin}/token",
        scopes=(BASE_SCOPE,),
        redirect_uri=redirect_uri,
    )


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_flow_completes_on_the_redirect_uris_own_path_and_port(
    browser: _ThreadedBrowser,
    servers: SplitOAuthServers,
    host: str,
) -> None:
    """A redirect URI naming its own path and port receives the code there, and the flow ends with a token.

    Args:
        browser: The threaded browser.
        servers: The running authorization server.
        host: The loopback host the redirect URI names.
    """
    redirect_port = free_port()
    manager = OAuthManager(credential_store=None, callback_port=free_port())
    redirect_uri = f"http://{host}:{redirect_port}/oauth2/redirect"
    token = asyncio.run(asyncio.wait_for(manager.run_authorization_flow(_config(servers, redirect_uri)), timeout=_FLOW_TIMEOUT_S))
    assert browser.errors == []
    assert token.access_token
    assert browser.callbacks[0].startswith(f"{redirect_uri}?")
    assert servers.state.grants("authorization_code")[-1].get("redirect_uri") == redirect_uri


def test_default_redirect_uri_still_uses_the_managers_port(browser: _ThreadedBrowser, servers: SplitOAuthServers) -> None:
    """The built-in default redirect URI is still moved to the manager's callback port and completes on ``/callback``.

    Args:
        browser: The threaded browser.
        servers: The running authorization server.
    """
    port = free_port()
    manager = OAuthManager(credential_store=None, callback_port=port)
    token = asyncio.run(
        asyncio.wait_for(manager.run_authorization_flow(_config(servers, "http://localhost:8080/callback")), timeout=_FLOW_TIMEOUT_S),
    )
    assert browser.errors == []
    assert token.access_token
    assert browser.callbacks[0].startswith(f"http://localhost:{port}/callback?")


@pytest.mark.parametrize("redirect_uri", ["https://app.example/oauth/callback", "http://[::1]:8765/callback", "http://10.0.0.5:8765/cb"])
def test_unreachable_redirect_uri_is_refused_before_the_browser_opens(
    browser: _ThreadedBrowser,
    servers: SplitOAuthServers,
    redirect_uri: str,
) -> None:
    """A redirect URI the callback server cannot listen on is refused at once instead of waiting out the callback timeout.

    Args:
        browser: The threaded browser.
        servers: The running authorization server.
        redirect_uri: The redirect URI.
    """
    manager = OAuthManager(credential_store=None, callback_port=free_port())
    with pytest.raises(OAuthCallbackError, match="loopback"):
        asyncio.run(asyncio.wait_for(manager.run_authorization_flow(_config(servers, redirect_uri)), timeout=_FLOW_TIMEOUT_S))
    assert browser.opened == []
