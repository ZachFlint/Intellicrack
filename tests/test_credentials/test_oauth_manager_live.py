# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Live end-to-end tests for the OAuth manager.

These tests cover:

* Thread-safe singleton construction under concurrency.
* PKCE code_verifier / code_challenge roundtrip validation.
* Full OAuth callback path using an in-process mock HTTP server that
  stands in for an OAuth provider. No external network calls are made.
* Token-refresh error path including the 401/403 distinction.

The singleton is reset between tests via :func:`importlib.reload` rather
than reaching into private attributes.
"""

from __future__ import annotations

import asyncio
import http.server
import importlib
import json
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from types import ModuleType
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import parse_qs, urlencode

import httpx
import pytest

from intellicrack.credentials import oauth as oauth_module


if TYPE_CHECKING:
    from collections.abc import Iterator


_UNAUTHORIZED = 401
_OK = 200
_LIVE_ACCESS_MARKER = "live-access-token"
_LIVE_REFRESH_MARKER = "live-refresh-token"


def _find_free_port() -> int:
    """Ask the OS for a free TCP port on loopback.

    Returns:
        int: An available TCP port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _MockOAuthProviderHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that emulates a minimal OAuth provider.

    Supports ``/token`` for authorization-code and refresh-token grants and
    ``/token/authfail`` which always returns HTTP 401 to simulate a rejected
    refresh token.
    """

    exchange_log: ClassVar[list[dict[str, object]]] = []
    auth_fail: ClassVar[bool] = False

    def do_POST(self) -> None:
        """Handle POST requests for token exchange or refresh."""
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        _MockOAuthProviderHandler.exchange_log.append(
            {"path": self.path, "form": form},
        )

        if self.path.startswith("/token/authfail") or _MockOAuthProviderHandler.auth_fail:
            self.send_response(_UNAUTHORIZED)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "invalid_grant"}).encode("utf-8"),
            )
            return

        payload: dict[str, object] = {
            "access_token": _LIVE_ACCESS_MARKER,
            "refresh_token": form.get("refresh_token", _LIVE_REFRESH_MARKER),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "scope1 scope2",
        }
        self.send_response(_OK)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def log_message(self, format: str, *args: object) -> None:
        """Silence default HTTP logging.

        Args:
            format: Unused format string from stdlib signature.
            *args: Unused arguments from stdlib signature.
        """
        del self, format, args


@pytest.fixture
def mock_oauth_provider() -> Iterator[tuple[str, list[dict[str, object]]]]:
    """Spin up an in-process mock OAuth provider.

    Yields:
        tuple[str, list[dict[str, object]]]: The base URL of the mock
        provider and the shared exchange log mutated by the handler.
    """
    _MockOAuthProviderHandler.exchange_log = []
    _MockOAuthProviderHandler.auth_fail = False
    port = _find_free_port()
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", port),
        _MockOAuthProviderHandler,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", _MockOAuthProviderHandler.exchange_log
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.fixture
def reloaded_oauth_module() -> Iterator[ModuleType]:
    """Reload the oauth module so singleton state is fresh per test.

    Yields:
        ModuleType: The freshly reloaded module.
    """
    module = importlib.reload(oauth_module)
    try:
        yield module
    finally:
        importlib.reload(oauth_module)


def test_singleton_thread_safety(reloaded_oauth_module: ModuleType) -> None:
    """Concurrent callers must receive exactly one OAuthManager instance.

    Args:
        reloaded_oauth_module: The freshly reloaded oauth module.
    """
    call_count = 32

    def call(_: int) -> Any:
        return reloaded_oauth_module.get_oauth_manager()

    with ThreadPoolExecutor(max_workers=call_count) as executor:
        results = list(executor.map(call, range(call_count)))

    assert len(results) == call_count
    first = results[0]
    for instance in results[1:]:
        assert instance is first


def test_pkce_roundtrip(reloaded_oauth_module: ModuleType) -> None:
    """PKCE generator and verifier must agree on challenge derivation.

    Args:
        reloaded_oauth_module: The freshly reloaded oauth module.
    """
    code_verifier, code_challenge = reloaded_oauth_module.generate_pkce_pair()

    assert code_verifier
    assert code_challenge
    assert code_verifier != code_challenge
    assert reloaded_oauth_module.verify_pkce_pair(code_verifier, code_challenge)
    assert not reloaded_oauth_module.verify_pkce_pair(
        code_verifier + "x",
        code_challenge,
    )


def test_full_callback_path_with_mock_provider(
    reloaded_oauth_module: ModuleType,
    mock_oauth_provider: tuple[str, list[dict[str, object]]],
) -> None:
    """Drive authorize -> local callback -> token exchange against the mock.

    Args:
        reloaded_oauth_module: The freshly reloaded oauth module.
        mock_oauth_provider: Base URL and exchange log of the mock server.
    """
    base_url, exchange_log = mock_oauth_provider
    callback_port = _find_free_port()

    config = reloaded_oauth_module.OAuthConfig(
        provider=reloaded_oauth_module.OAuthProvider.GOOGLE,
        client_id="test-client",
        client_secret=None,
        authorization_url=f"{base_url}/authorize",
        token_url=f"{base_url}/token",
        scopes=("scope1", "scope2"),
        redirect_uri=f"http://127.0.0.1:{callback_port}/callback",
        use_pkce=True,
        revoke_url=None,
    )

    manager = reloaded_oauth_module.OAuthManager(
        credential_store=None,
        callback_port=callback_port,
    )

    async def drive() -> Any:
        auth_url, oauth_state = await manager.start_authorization_flow(
            config,
            open_browser=False,
        )
        assert auth_url.startswith(f"{base_url}/authorize?")
        server = reloaded_oauth_module.OAuthCallbackServer(
            port=callback_port,
            expected_state=oauth_state.state,
        )
        server.start()
        try:

            def fire_callback() -> None:
                query = urlencode({"code": "auth-code-xyz", "state": oauth_state.state})
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(
                        f"http://127.0.0.1:{callback_port}/callback?{query}",
                    )
                    assert resp.status_code == _OK

            firing_thread = threading.Thread(target=fire_callback, daemon=True)
            firing_thread.start()
            code, state = await asyncio.to_thread(server.wait_for_callback)
            firing_thread.join(timeout=2.0)
            assert code == "auth-code-xyz"
            assert state == oauth_state.state
            return await manager.handle_callback(code, state)
        finally:
            server.stop()

    try:
        token = asyncio.run(drive())
    finally:
        asyncio.run(manager.close())

    assert token.access_token == _LIVE_ACCESS_MARKER
    assert token.refresh_token == _LIVE_REFRESH_MARKER
    token_exchange_forms = [
        entry["form"] for entry in exchange_log if entry["path"] == "/token"
    ]
    assert len(token_exchange_forms) == 1
    form = token_exchange_forms[0]
    assert isinstance(form, dict)
    assert form["grant_type"] == "authorization_code"
    assert form["code"] == "auth-code-xyz"
    assert form["code_verifier"]


def test_state_mismatch_is_rejected(
    reloaded_oauth_module: ModuleType,
) -> None:
    """Callbacks with a mismatched state must be refused with CSRF error.

    Args:
        reloaded_oauth_module: The freshly reloaded oauth module.
    """
    callback_port = _find_free_port()

    expected_state = "expected-state-value"
    reloaded_oauth_module.OAuthCallbackHandler.callback_code = None
    reloaded_oauth_module.OAuthCallbackHandler.callback_state = None
    reloaded_oauth_module.OAuthCallbackHandler.callback_error = None

    server = reloaded_oauth_module.OAuthCallbackServer(
        port=callback_port,
        expected_state=expected_state,
    )
    server.start()
    try:
        query = urlencode({"code": "c", "state": "different-state"})
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(
                f"http://127.0.0.1:{callback_port}/callback?{query}",
            )
            assert resp.status_code == 400
        with pytest.raises(reloaded_oauth_module.OAuthCallbackError):
            server.wait_for_callback()
    finally:
        server.stop()


def _prime_cached_token(
    module: ModuleType,
    manager: Any,
    provider: Any,
) -> None:
    """Seed a manager's in-memory token cache without going through keyring.

    Args:
        module: The reloaded oauth module.
        manager: An :class:`OAuthManager` instance to seed.
        provider: The :class:`OAuthProvider` value keying the cached token.
    """
    token_cls = module.OAuthToken
    token = token_cls(
        access_token="old",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=None,
    )
    cache = manager._token_cache
    cache[provider] = token


def test_refresh_token_rejected_raises_refresh_error(
    reloaded_oauth_module: ModuleType,
    mock_oauth_provider: tuple[str, list[dict[str, object]]],
) -> None:
    """A 401 on the refresh endpoint must surface as OAuthTokenRefreshError.

    Args:
        reloaded_oauth_module: The freshly reloaded oauth module.
        mock_oauth_provider: Base URL and exchange log of the mock server.
    """
    base_url, _log = mock_oauth_provider
    manager = reloaded_oauth_module.OAuthManager(credential_store=None)

    provider = reloaded_oauth_module.OAuthProvider.GOOGLE
    _prime_cached_token(reloaded_oauth_module, manager, provider)

    config = reloaded_oauth_module.OAuthConfig(
        provider=provider,
        client_id="client",
        client_secret=None,
        authorization_url=f"{base_url}/authorize",
        token_url=f"{base_url}/token/authfail",
        scopes=("s",),
        use_pkce=False,
    )

    async def go() -> None:
        with pytest.raises(reloaded_oauth_module.OAuthTokenRefreshError):
            await manager.refresh_token(provider, config)
        await manager.close()

    asyncio.run(go())


def test_refresh_token_transient_error_raises_plain_token_error(
    reloaded_oauth_module: ModuleType,
    mock_oauth_provider: tuple[str, list[dict[str, object]]],
) -> None:
    """Non-auth errors must raise the generic OAuthTokenError, not refresh.

    Args:
        reloaded_oauth_module: The freshly reloaded oauth module.
        mock_oauth_provider: Base URL and exchange log of the mock server.
    """
    base_url, _log = mock_oauth_provider
    manager = reloaded_oauth_module.OAuthManager(credential_store=None)

    provider = reloaded_oauth_module.OAuthProvider.GOOGLE
    _prime_cached_token(reloaded_oauth_module, manager, provider)

    config = reloaded_oauth_module.OAuthConfig(
        provider=provider,
        client_id="client",
        client_secret=None,
        authorization_url=f"{base_url}/authorize",
        token_url="http://127.0.0.1:1/does-not-exist",
        scopes=("s",),
        use_pkce=False,
    )

    async def go() -> None:
        with pytest.raises(reloaded_oauth_module.OAuthTokenError) as exc_info:
            await manager.refresh_token(provider, config)
        assert not isinstance(
            exc_info.value,
            reloaded_oauth_module.OAuthTokenRefreshError,
        )
        await manager.close()

    asyncio.run(go())
