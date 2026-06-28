# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Wave-5 gate tests for Group-09 open OAuth findings.

Closes findings #1, #2, #12, #13, #15, #17, #18, #20, #24, #31, #32,
#34, #35, #36, #38, #39, #42, #43, #44, #45, #46, #49, #53, #54, #55,
#57, #58, #60, #61, #62, #63 from the section-11-credentials-oauth audit.
"""

from __future__ import annotations

import asyncio
import http.client
import http.server
import json
import socket
import threading
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

import pytest

import intellicrack.credentials.oauth as _oauth_mod
import intellicrack.credentials.store as _store_mod
from intellicrack.core.types import ProviderCredentials, ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.oauth import (
    OAUTH_CONFIGS,
    OAuthAuthorizationError,
    OAuthCallbackError,
    OAuthCallbackServer,
    OAuthConfig,
    OAuthManager,
    OAuthProvider,
    OAuthToken,
    OAuthTokenError,
    OAuthTokenRefreshError,
    _OAUTH_TO_PROVIDER_NAME,
    _oauth_provider_to_name,
    authorize_google,
)
from intellicrack.credentials.store import CredentialStore


if TYPE_CHECKING:
    from collections.abc import Iterator


# ---------------------------------------------------------------------------
# Module-level capability check
# ---------------------------------------------------------------------------


def _loopback_tcp_available() -> bool:
    """Return True if loopback TCP sockets can be bound in this environment.

    Returns:
        bool: True if a loopback TCP socket can bind and listen.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
        return True
    except OSError:
        return False


_requires_loopback = pytest.mark.skipif(
    not _loopback_tcp_available(),
    reason="loopback TCP unavailable in this container; OAuthCallbackServer tests skipped",
)


# ---------------------------------------------------------------------------
# In-process HTTP server handlers
# ---------------------------------------------------------------------------

_TOKEN_200_BODY: Final[bytes] = json.dumps({
    "access_token": "tok_access_200",
    "refresh_token": "tok_refresh_200",
    "token_type": "Bearer",
    "expires_in": 3600,
}).encode("utf-8")


class _Always200Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that returns 200 with a canned token JSON for any POST."""

    def do_POST(self) -> None:
        """Return 200 OK with canned token JSON body."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(_TOKEN_200_BODY)))
        self.end_headers()
        self.wfile.write(_TOKEN_200_BODY)

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Suppress HTTP access log.

        Args:
            *args: Unused positional arguments from stdlib signature.
            **kwargs: Unused keyword arguments for forward compatibility.
        """
        del args, kwargs


class _Always400Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that returns 400 Bad Request for any POST."""

    def do_POST(self) -> None:
        """Return 400 Bad Request with JSON error body."""
        body = b'{"error": "bad_request", "error_description": "invalid code"}'
        self.send_response(400)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Suppress HTTP access log.

        Args:
            *args: Unused positional arguments from stdlib signature.
            **kwargs: Unused keyword arguments for forward compatibility.
        """
        del args, kwargs


class _Always500Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that returns 500 Internal Server Error for any POST."""

    def do_POST(self) -> None:
        """Return 500 Internal Server Error with JSON body."""
        body = b'{"error": "server_error"}'
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Suppress HTTP access log.

        Args:
            *args: Unused positional arguments from stdlib signature.
            **kwargs: Unused keyword arguments for forward compatibility.
        """
        del args, kwargs


class _Always403Handler(http.server.BaseHTTPRequestHandler):
    """HTTP handler that returns 403 Forbidden for any POST."""

    def do_POST(self) -> None:
        """Return 403 Forbidden with JSON error body."""
        body = json.dumps({"error": "forbidden"}).encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Suppress HTTP access log.

        Args:
            *args: Unused positional arguments from stdlib signature.
            **kwargs: Unused keyword arguments for forward compatibility.
        """
        del args, kwargs


# ---------------------------------------------------------------------------
# Fake keyring module (in-memory backend for store tests)
# ---------------------------------------------------------------------------


class _FakeKeyringGoodBackend:
    """Backend that passes all _check_keyring validation checks.

    Attributes:
        priority: Non-zero positive priority accepted by _check_keyring.
    """

    priority: ClassVar[float] = 5.0


class _FakeKeyringModule:
    """In-memory substitute for the keyring library module.

    Stores passwords in a class-level dict so set_password / get_password /
    delete_password work without touching the OS credential store.

    Attributes:
        _passwords: Mapping of (service, username) -> password.
    """

    _passwords: ClassVar[dict[tuple[str, str], str]] = {}

    @classmethod
    def get_keyring(cls) -> _FakeKeyringGoodBackend:
        """Return a well-behaved fake backend.

        Returns:
            _FakeKeyringGoodBackend: Backend instance that passes priority and name checks.
        """
        return _FakeKeyringGoodBackend()

    @classmethod
    def get_password(cls, service: str, username: str) -> str | None:
        """Return stored password or None.

        Args:
            service: Keyring service name.
            username: Keyring username / key.

        Returns:
            str | None: Stored value or None if absent.
        """
        return cls._passwords.get((service, username))

    @classmethod
    def set_password(cls, service: str, username: str, password: str) -> None:
        """Store a password.

        Args:
            service: Keyring service name.
            username: Keyring username / key.
            password: Value to store.
        """
        cls._passwords[(service, username)] = password

    @classmethod
    def delete_password(cls, service: str, username: str) -> None:
        """Delete a stored password (no-op if absent).

        Args:
            service: Keyring service name.
            username: Keyring username / key.
        """
        cls._passwords.pop((service, username), None)


class FailKeyring:
    """Fake backend whose class name matches the FailKeyring sentinel exactly.

    The name must be exactly ``FailKeyring`` (no underscore) so that
    ``type(backend).__name__`` matches the ``{"Keyring", "FailKeyring", "NullKeyring"}``
    sentinel set in ``CredentialStore._check_keyring``.

    Attributes:
        priority: Non-positive priority (irrelevant; the name check fires first).
    """

    priority: ClassVar[float] = -1.0


class _FailKeyringModule:
    """Fake keyring module whose get_keyring() returns a FailKeyring backend."""

    @classmethod
    def get_keyring(cls) -> FailKeyring:
        """Return a FailKeyring-named backend.

        Returns:
            FailKeyring: Backend instance whose class name triggers the fail check.
        """
        return FailKeyring()

    @classmethod
    def get_password(cls, service: str, username: str) -> str | None:
        """Return None (never used when check fails).

        Args:
            service: Keyring service name.
            username: Keyring username / key.

        Returns:
            str | None: Always None.
        """
        return None

    @classmethod
    def set_password(cls, service: str, username: str, password: str) -> None:
        """No-op (never used when check fails).

        Args:
            service: Keyring service name.
            username: Keyring username / key.
            password: Value to store (unused).
        """

    @classmethod
    def delete_password(cls, service: str, username: str) -> None:
        """No-op (never used when check fails).

        Args:
            service: Keyring service name.
            username: Keyring username / key.
        """


class _ZeroPriorityBackend:
    """Fake backend with zero priority; should fail the _check_keyring guard.

    Attributes:
        priority: Zero — fails the ``priority <= 0`` check.
    """

    priority: ClassVar[float] = 0.0


class _ZeroPriorityModule:
    """Fake keyring module whose get_keyring() returns a zero-priority backend."""

    @classmethod
    def get_keyring(cls) -> _ZeroPriorityBackend:
        """Return a backend with zero priority.

        Returns:
            _ZeroPriorityBackend: Backend that fails the priority check.
        """
        return _ZeroPriorityBackend()

    @classmethod
    def get_password(cls, service: str, username: str) -> str | None:
        """Return None.

        Args:
            service: Keyring service name.
            username: Keyring username / key.

        Returns:
            str | None: Always None.
        """
        return None

    @classmethod
    def set_password(cls, service: str, username: str, password: str) -> None:
        """No-op.

        Args:
            service: Keyring service name.
            username: Keyring username / key.
            password: Value to store (unused).
        """

    @classmethod
    def delete_password(cls, service: str, username: str) -> None:
        """No-op.

        Args:
            service: Keyring service name.
            username: Keyring username / key.
        """


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Return an OS-allocated free TCP port on loopback.

    Returns:
        int: An available TCP port number.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return cast(int, s.getsockname()[1])


def _minimal_config(
    base_url: str,
    token_path: str = "/token",
    *,
    use_pkce: bool = False,
    revoke_url: str | None = None,
) -> OAuthConfig:
    """Build a minimal OAuthConfig pointing at a local server URL.

    Args:
        base_url: Base URL of the local mock server.
        token_path: Token endpoint path relative to base_url.
        use_pkce: Whether to enable PKCE in the config.
        revoke_url: Optional revoke URL to embed in the config.

    Returns:
        OAuthConfig: Configuration suitable for unit tests.
    """
    return OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="test-client",
        client_secret=None,
        authorization_url=f"{base_url}/authorize",
        token_url=f"{base_url}{token_path}",
        scopes=("s1",),
        redirect_uri="http://127.0.0.1:9999/callback",
        use_pkce=use_pkce,
        revoke_url=revoke_url,
    )


def _make_keyring_free_store(env_entries: dict[str, str] | None = None) -> CredentialStore:
    """Create a CredentialStore with keyring disabled and optional env entries.

    Bypasses the cached_property before it can cache True.

    Args:
        env_entries: Mapping of env-variable name to value injected into the
            fallback CredentialLoader without touching os.environ or disk.

    Returns:
        CredentialStore: A store that uses only the injected env fallback.
    """
    loader = CredentialLoader(env_path=Path("/__nonexistent_wave5_test__/.env"))
    if env_entries:
        loader_any = cast(Any, loader)
        env_vars: dict[str, str] = loader_any._env_vars
        env_vars.update(env_entries)
    store = CredentialStore(fallback_loader=loader)
    store_any = cast(Any, store)
    store_any._keyring_checked = True
    store_any._keyring_available = False
    return store


def _make_store_with_fake_keyring() -> CredentialStore:
    """Create a CredentialStore backed by _FakeKeyringModule.

    The caller must monkeypatch ``_store_mod._keyring_module`` to
    ``_FakeKeyringModule`` before calling this function.

    Returns:
        CredentialStore: Fresh store that will call _check_keyring with the
        monkeypatched fake keyring module on first access.
    """
    loader = CredentialLoader(env_path=Path("/__nonexistent_wave5_test__/.env"))
    return CredentialStore(fallback_loader=loader)


def _seed_token_cache(
    manager: OAuthManager,
    provider: OAuthProvider,
    token: OAuthToken,
) -> None:
    """Directly insert a token into the manager's in-memory cache.

    Args:
        manager: The OAuthManager instance whose cache to populate.
        provider: Cache key (the OAuth provider).
        token: Token value to store.
    """
    manager_any = cast(Any, manager)
    cache: dict[OAuthProvider, OAuthToken] = manager_any._token_cache
    cache[provider] = token


def _make_outer_cred_json(inner_api_key: str) -> str:
    """Serialise a ProviderCredentials payload as stored in the keyring.

    Args:
        inner_api_key: Value for the ``api_key`` field of ProviderCredentials.

    Returns:
        str: JSON string that _deserialize_credentials can parse back.
    """
    return json.dumps({
        "api_key": inner_api_key,
        "api_base": None,
        "organization_id": None,
        "project_id": None,
    })


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _start_server(handler_cls: type[http.server.BaseHTTPRequestHandler]) -> tuple[http.server.ThreadingHTTPServer, str, threading.Thread]:
    """Spin up a ThreadingHTTPServer on a free loopback port.

    Args:
        handler_cls: Handler class to instantiate for each request.

    Returns:
        tuple[http.server.ThreadingHTTPServer, str, threading.Thread]:
            The server object, its base URL, and the background thread.
    """
    port = _find_free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}", thread


@pytest.fixture()
def mock_200_server() -> Iterator[str]:
    """Yield base URL of an in-process server returning 200 with token JSON.

    Yields:
        str: Base URL of the mock server.
    """
    server, base_url, thread = _start_server(_Always200Handler)
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.fixture()
def mock_400_server() -> Iterator[str]:
    """Yield base URL of an in-process server returning 400 Bad Request.

    Yields:
        str: Base URL of the mock server.
    """
    server, base_url, thread = _start_server(_Always400Handler)
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.fixture()
def mock_500_server() -> Iterator[str]:
    """Yield base URL of an in-process server returning 500 Internal Server Error.

    Yields:
        str: Base URL of the mock server.
    """
    server, base_url, thread = _start_server(_Always500Handler)
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.fixture()
def mock_403_server() -> Iterator[str]:
    """Yield base URL of an in-process server returning 403 Forbidden.

    Yields:
        str: Base URL of the mock server.
    """
    server, base_url, thread = _start_server(_Always403Handler)
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


@pytest.fixture()
def _with_fake_keyring(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Monkeypatch _store_mod._keyring_module with _FakeKeyringModule.

    Clears the in-memory password store before and after the test.

    Args:
        monkeypatch: Pytest monkeypatch fixture.

    Yields:
        None: Nothing; effect is the monkeypatched module attribute.
    """
    _FakeKeyringModule._passwords.clear()
    monkeypatch.setattr(_store_mod, "_keyring_module", _FakeKeyringModule)
    yield
    _FakeKeyringModule._passwords.clear()


# ---------------------------------------------------------------------------
# Finding #1 — _oauth_provider_to_name happy path (oauth.py:109)
# ---------------------------------------------------------------------------


def test_oauth_provider_to_name_google_returns_provider_google() -> None:
    """_oauth_provider_to_name(GOOGLE) must return ProviderName.GOOGLE exactly.

    Mutation: changing the mapping entry to ProviderName.ANTHROPIC would fail.
    """
    result = _oauth_provider_to_name(OAuthProvider.GOOGLE)
    assert result == ProviderName.GOOGLE


def test_oauth_provider_to_name_anthropic_returns_provider_anthropic() -> None:
    """_oauth_provider_to_name(ANTHROPIC) must return ProviderName.ANTHROPIC exactly.

    Mutation: removing the ANTHROPIC entry would raise KeyError.
    """
    result = _oauth_provider_to_name(OAuthProvider.ANTHROPIC)
    assert result == ProviderName.ANTHROPIC


def test_oauth_provider_to_name_huggingface_returns_provider_huggingface() -> None:
    """_oauth_provider_to_name(HUGGINGFACE) must return ProviderName.HUGGINGFACE exactly.

    Mutation: mapping HUGGINGFACE to the wrong ProviderName would fail.
    """
    result = _oauth_provider_to_name(OAuthProvider.HUGGINGFACE)
    assert result == ProviderName.HUGGINGFACE


# ---------------------------------------------------------------------------
# Finding #2 — _oauth_provider_to_name KeyError path (oauth.py:121)
# ---------------------------------------------------------------------------


def test_oauth_provider_to_name_all_enum_members_have_mapping() -> None:
    """Every OAuthProvider member must appear in _OAUTH_TO_PROVIDER_NAME.

    Mutation: adding a new OAuthProvider member without a mapping entry would
    cause this coverage-invariant test to fail and expose the dead KeyError branch.
    """
    for provider in OAuthProvider:
        assert provider in _OAUTH_TO_PROVIDER_NAME, (
            f"OAuthProvider.{provider.name} has no entry in _OAUTH_TO_PROVIDER_NAME"
        )


def test_oauth_provider_to_name_raises_key_error_for_unmapped_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_oauth_provider_to_name must raise KeyError for a provider absent from the map.

    Temporarily removes one entry from the mapping to exercise the KeyError branch.

    Mutation: removing the ``if provider not in _OAUTH_TO_PROVIDER_NAME`` guard
    would cause a KeyError from the dict lookup itself rather than the documented
    guarded raise — the message text would differ.

    Args:
        monkeypatch: Pytest fixture used to replace the mapping dict temporarily.
    """
    reduced: dict[OAuthProvider, ProviderName] = {
        k: v for k, v in _OAUTH_TO_PROVIDER_NAME.items() if k != OAuthProvider.HUGGINGFACE
    }
    monkeypatch.setattr(_oauth_mod, "_OAUTH_TO_PROVIDER_NAME", reduced)

    with pytest.raises(KeyError, match="No provider name mapping"):
        _oauth_provider_to_name(OAuthProvider.HUGGINGFACE)


# ---------------------------------------------------------------------------
# Finding #12 — OAuthCallbackHandler.do_GET error in params (oauth.py:402)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_callback_handler_error_param_returns_400_and_sets_callback_error() -> None:
    """do_GET with ?error=access_denied must send HTTP 400 and set callback_error.

    Mutation: removing the ``if "error" in params:`` branch would fall through to
    the missing-code-or-state else clause and set no callback_error attribute.
    """
    port = _find_free_port()
    server = OAuthCallbackServer(port=port, timeout=5.0)
    server.start()
    server_any = cast(Any, server)
    event: threading.Event = server_any._event

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        conn.request("GET", "/callback?error=access_denied")
        resp = conn.getresponse()
        status = resp.status
        resp.read()
    finally:
        conn.close()

    assert event.wait(timeout=3.0), "callback handler did not fire the event"

    tcp_server = server_any._server
    assert tcp_server is not None
    assert status == 400
    assert tcp_server.callback_error == "access_denied"
    server.stop()


# ---------------------------------------------------------------------------
# Finding #13 — OAuthCallbackHandler.do_GET missing code/state (oauth.py:419)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_callback_handler_missing_params_returns_400() -> None:
    """do_GET with no recognised params must send HTTP 400.

    Mutation: removing the else clause that sets status=400 for missing params
    would cause the handler to try accessing missing dict keys.
    """
    port = _find_free_port()
    server = OAuthCallbackServer(port=port, timeout=5.0)
    server.start()
    server_any = cast(Any, server)
    event: threading.Event = server_any._event

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        conn.request("GET", "/callback?unknown=param")
        resp = conn.getresponse()
        status = resp.status
        resp.read()
    finally:
        conn.close()

    assert event.wait(timeout=3.0), "callback handler did not fire the event"
    assert status == 400


# ---------------------------------------------------------------------------
# Finding #15 — OAuthCallbackServer.start OSError on bind (oauth.py:510)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_callback_server_start_raises_callback_error_when_port_occupied() -> None:
    """start() must raise OAuthCallbackError when the port is already bound.

    SO_EXCLUSIVEADDRUSE (Windows constant 12) prevents any other socket from
    binding to the held port, overriding allow_reuse_address=True that the SUT
    sets globally before calling bind().

    Mutation: removing the OSError catch in start() would let the OSError
    propagate as-is rather than as OAuthCallbackError.
    """
    port = _find_free_port()
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    _SO_EXCLUSIVEADDRUSE: Final[int] = 12
    holder.setsockopt(socket.SOL_SOCKET, _SO_EXCLUSIVEADDRUSE, 1)
    try:
        holder.bind(("127.0.0.1", port))
        holder.listen(1)
        server = OAuthCallbackServer(port=port)
        with pytest.raises(OAuthCallbackError, match=r"[Bb]ind|port|Failed"):
            server.start()
    finally:
        holder.close()


# ---------------------------------------------------------------------------
# Finding #17 — OAuthCallbackServer.wait_for_callback timeout (oauth.py:543)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_wait_for_callback_timeout_raises_callback_error() -> None:
    """wait_for_callback must raise OAuthCallbackError after the timeout elapses.

    Mutation: removing the ``if not self._event.wait(timeout=...)`` guard and
    raising OAuthCallbackError unconditionally would still pass; removing it and
    proceeding without a guard would return None instead of raising.
    """
    port = _find_free_port()
    server = OAuthCallbackServer(port=port, timeout=0.05)
    server.start()
    try:
        with pytest.raises(OAuthCallbackError, match=r"[Tt]imeout"):
            server.wait_for_callback()
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Finding #18 — OAuthCallbackServer.wait_for_callback denied (oauth.py:556)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_wait_for_callback_access_denied_raises_authorization_error() -> None:
    """wait_for_callback must raise OAuthAuthorizationError for access_denied callbacks.

    A background thread sends ``?error=access_denied`` to the callback server;
    wait_for_callback detects "denied" in the error code and raises.

    Mutation: removing the ``"denied" in error_msg.lower()`` guard would raise a
    generic OAuthCallbackError instead of OAuthAuthorizationError.
    """
    port = _find_free_port()
    server = OAuthCallbackServer(port=port, timeout=5.0)
    server.start()

    def _send_denied() -> None:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
            conn.request("GET", "/callback?error=access_denied")
            resp = conn.getresponse()
            resp.read()
            conn.close()
        except (OSError, http.client.HTTPException):
            pass

    sender = threading.Thread(target=_send_denied, daemon=True)
    sender.start()

    try:
        with pytest.raises(OAuthAuthorizationError, match=r"[Dd]enied|access_denied"):
            server.wait_for_callback()
    finally:
        server.stop()
        sender.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Finding #20 — OAuthCallbackServer.wait_for_callback missing code/state (oauth.py:566)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_wait_for_callback_missing_code_and_state_raises_callback_error() -> None:
    """wait_for_callback must raise OAuthCallbackError when callback has no code or state.

    A background thread sends a GET with unrecognised params; the handler fires
    the event without setting code/state, triggering the null-check guard.

    Mutation: removing ``if not code or not state:`` would return (None, None)
    instead of raising.
    """
    port = _find_free_port()
    server = OAuthCallbackServer(port=port, timeout=5.0)
    server.start()

    def _send_no_code() -> None:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
            conn.request("GET", "/callback?junk=true")
            resp = conn.getresponse()
            resp.read()
            conn.close()
        except (OSError, http.client.HTTPException):
            pass

    sender = threading.Thread(target=_send_no_code, daemon=True)
    sender.start()

    try:
        with pytest.raises(OAuthCallbackError, match=r"[Cc]ode|[Ss]tate|[Ii]nvalid"):
            server.wait_for_callback()
    finally:
        server.stop()
        sender.join(timeout=3.0)


# ---------------------------------------------------------------------------
# Finding #24 — OAuthManager.build_authorization_url PKCE disabled (oauth.py:701)
# ---------------------------------------------------------------------------


def test_build_authorization_url_pkce_disabled_omits_code_challenge() -> None:
    """build_authorization_url with use_pkce=False must not include code_challenge.

    Oracle: urllib.parse.parse_qs on the returned URL — code_challenge absent.
    Mutation: unconditionally adding code_challenge regardless of use_pkce would
    add the param and fail the ``not in`` assertion.
    """
    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="pkce-off-client",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=("openid",),
        use_pkce=False,
    )
    manager = OAuthManager(credential_store=None)
    url, state = manager.build_authorization_url(config)

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    assert "code_challenge" not in params
    assert "code_challenge_method" not in params
    assert params["client_id"] == ["pkce-off-client"]
    assert params["response_type"] == ["code"]
    assert state.code_verifier is None


def test_build_authorization_url_pkce_enabled_includes_s256_challenge() -> None:
    """build_authorization_url with use_pkce=True must include S256 code_challenge.

    Mutation: omitting code_challenge when use_pkce=True would fail the
    ``in params`` assertion; setting method to plain instead of S256 would also fail.
    """
    from intellicrack.credentials.oauth import verify_pkce_pair

    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="pkce-on-client",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=("openid",),
        use_pkce=True,
    )
    manager = OAuthManager(credential_store=None)
    url, state = manager.build_authorization_url(config)

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    assert "code_challenge" in params
    assert params["code_challenge_method"] == ["S256"]
    assert state.code_verifier is not None
    assert verify_pkce_pair(state.code_verifier, params["code_challenge"][0])


# ---------------------------------------------------------------------------
# Finding #31 — _exchange_code_for_token HTTP error (oauth.py:901)
# ---------------------------------------------------------------------------


def test_exchange_code_for_token_http_error_raises_oauth_token_error(
    mock_400_server: str,
) -> None:
    """_exchange_code_for_token must raise OAuthTokenError on a non-2xx HTTP response.

    Mutation: removing the ``except httpx.HTTPStatusError`` block would let the
    raw httpx exception propagate rather than the documented OAuthTokenError.

    Args:
        mock_400_server: Base URL of the mock server returning HTTP 400.
    """
    config = _minimal_config(mock_400_server, use_pkce=False)
    manager = OAuthManager(credential_store=None)

    async def go() -> None:
        try:
            with pytest.raises(OAuthTokenError, match=r"400|[Ee]xchange"):
                await manager._exchange_code_for_token(config, "some_auth_code", None)
        finally:
            await manager.close()

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Finding #32 — _exchange_code_for_token network error (oauth.py:906)
# ---------------------------------------------------------------------------


def test_exchange_code_for_token_network_error_raises_oauth_token_error() -> None:
    """_exchange_code_for_token must raise OAuthTokenError when the server is unreachable.

    Uses a port with no listener so httpx raises a ConnectError (subclass of
    RequestError / OSError), which the SUT wraps in OAuthTokenError.

    Mutation: removing the ``except (OSError, ..., httpx.RequestError)`` block
    would let the raw connection error propagate without the documented wrapping.
    """
    dead_port = _find_free_port()
    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="c",
        client_secret=None,
        authorization_url=f"http://127.0.0.1:{dead_port}/auth",
        token_url=f"http://127.0.0.1:{dead_port}/token",
        scopes=(),
        use_pkce=False,
    )
    manager = OAuthManager(credential_store=None)

    async def go() -> None:
        try:
            with pytest.raises(OAuthTokenError, match=r"[Ff]ailed|[Cc]onnect"):
                await manager._exchange_code_for_token(config, "code", None)
        finally:
            await manager.close()

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Finding #34 — _store_token keyring unavailable (oauth.py:924)
# ---------------------------------------------------------------------------


def test_store_token_keyring_unavailable_returns_without_raising() -> None:
    """_store_token with keyring-unavailable store must log a warning, not raise.

    Oracle: the in-memory cache is NOT modified by _store_token; confirming
    the token is absent from cache after the call proves the unavailable-keyring
    early-return path was taken without an exception.

    Mutation: raising KeyringUnavailableError instead of returning would cause
    the test to fail with an unexpected exception.
    """
    store = _make_keyring_free_store()
    manager = OAuthManager(credential_store=store)
    token = OAuthToken(
        access_token="unavail_acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )

    async def go() -> None:
        await manager._store_token(OAuthProvider.ANTHROPIC, token)

    asyncio.run(go())

    manager_any = cast(Any, manager)
    cache: dict[OAuthProvider, OAuthToken] = manager_any._token_cache
    assert OAuthProvider.ANTHROPIC not in cache


# ---------------------------------------------------------------------------
# Finding #35 — _store_token keyring success (oauth.py:935)
# ---------------------------------------------------------------------------


def test_store_token_keyring_available_serializes_exact_json(
    _with_fake_keyring: None,
) -> None:
    """_store_token must serialize the token as JSON and write it to the keyring.

    Oracle: the exact ``access_token`` field from the stored JSON read back
    from _FakeKeyringModule._passwords matches the original token's access_token.

    Mutation: serialising the wrong field (e.g. refresh_token) would make the
    read-back access_token value differ.

    Args:
        _with_fake_keyring: Fixture that monkeypatches the keyring module.
    """
    store = _make_store_with_fake_keyring()
    manager = OAuthManager(credential_store=store)
    token = OAuthToken(
        access_token="stored_exact_acc",
        refresh_token="stored_rt",
        token_type="Bearer",
        expires_at=None,
    )

    async def go() -> None:
        _ = store.keyring_available
        await manager._store_token(OAuthProvider.GOOGLE, token)

    asyncio.run(go())

    keyring_key = f"intellicrack_google"
    raw = _FakeKeyringModule._passwords.get(("intellicrack", keyring_key))
    assert raw is not None, "keyring entry was not written"
    outer = json.loads(raw)
    inner_api_key: str = outer["api_key"]
    token_data = json.loads(inner_api_key)
    assert token_data["access_token"] == "stored_exact_acc"
    assert token_data["refresh_token"] == "stored_rt"
    assert token_data["token_type"] == "Bearer"


# ---------------------------------------------------------------------------
# Finding #36 — _load_token_from_store (oauth.py:953)
# ---------------------------------------------------------------------------


def test_load_token_from_store_returns_correct_token_when_present(
    _with_fake_keyring: None,
) -> None:
    """_load_token_from_store must deserialise and return the stored token.

    Oracle: access_token read back from the returned OAuthToken matches the
    value pre-seeded in the fake keyring.

    Mutation: returning None for all keys would fail the ``assert token is not None``
    check and the access_token assertion.

    Args:
        _with_fake_keyring: Fixture that monkeypatches the keyring module.
    """
    token = OAuthToken(
        access_token="from_store_acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    inner_json = json.dumps(token.to_dict())
    outer_json = _make_outer_cred_json(inner_json)
    _FakeKeyringModule._passwords[("intellicrack", "intellicrack_google")] = outer_json

    store = _make_store_with_fake_keyring()
    manager = OAuthManager(credential_store=store)

    async def go() -> OAuthToken | None:
        _ = store.keyring_available
        return await manager._load_token_from_store(OAuthProvider.GOOGLE)

    result = asyncio.run(go())
    assert result is not None
    assert result.access_token == "from_store_acc"


def test_load_token_from_store_returns_none_when_absent(
    _with_fake_keyring: None,
) -> None:
    """_load_token_from_store must return None when no credential is stored.

    Oracle: fake keyring is empty for GOOGLE; None is the documented return.

    Mutation: returning a placeholder token for every provider would fail the
    ``result is None`` assertion.

    Args:
        _with_fake_keyring: Fixture that monkeypatches the keyring module.
    """
    store = _make_store_with_fake_keyring()
    manager = OAuthManager(credential_store=store)

    async def go() -> OAuthToken | None:
        _ = store.keyring_available
        return await manager._load_token_from_store(OAuthProvider.GOOGLE)

    result = asyncio.run(go())
    assert result is None


# ---------------------------------------------------------------------------
# Finding #38 — _load_token cache miss, keyring load (oauth.py:1006)
# ---------------------------------------------------------------------------


def test_load_token_cache_miss_falls_through_to_keyring(
    _with_fake_keyring: None,
) -> None:
    """_load_token must load from the credential store when the in-memory cache misses.

    Oracle: no pre-seeded cache entry; fake keyring has a stored token; the
    returned token's access_token matches the keyring value.

    Mutation: short-circuiting the store lookup after a cache miss (returning
    None unconditionally) would fail the access_token assertion.

    Args:
        _with_fake_keyring: Fixture that monkeypatches the keyring module.
    """
    token = OAuthToken(
        access_token="cache_miss_loaded",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    inner_json = json.dumps(token.to_dict())
    _FakeKeyringModule._passwords[("intellicrack", "intellicrack_google")] = _make_outer_cred_json(inner_json)

    store = _make_store_with_fake_keyring()
    manager = OAuthManager(credential_store=store)

    async def go() -> OAuthToken | None:
        _ = store.keyring_available
        return await manager._load_token(OAuthProvider.GOOGLE)

    result = asyncio.run(go())
    assert result is not None
    assert result.access_token == "cache_miss_loaded"


# ---------------------------------------------------------------------------
# Finding #39 — _load_token JSON decode error (oauth.py:1020)
# ---------------------------------------------------------------------------


def test_load_token_json_decode_error_returns_none(
    _with_fake_keyring: None,
) -> None:
    """_load_token must return None when the stored token blob is not valid JSON.

    The fake keyring stores a valid outer ProviderCredentials JSON whose
    ``api_key`` contains malformed token JSON, triggering json.JSONDecodeError
    inside _load_token_from_store, which _load_token catches and maps to None.

    Mutation: not catching json.JSONDecodeError in _load_token would propagate
    the exception to the caller instead of returning None.

    Args:
        _with_fake_keyring: Fixture that monkeypatches the keyring module.
    """
    malformed_token_json = "NOT_VALID_JSON{{{"
    _FakeKeyringModule._passwords[("intellicrack", "intellicrack_google")] = _make_outer_cred_json(malformed_token_json)

    store = _make_store_with_fake_keyring()
    manager = OAuthManager(credential_store=store)

    async def go() -> OAuthToken | None:
        _ = store.keyring_available
        return await manager._load_token(OAuthProvider.GOOGLE)

    result = asyncio.run(go())
    assert result is None


# ---------------------------------------------------------------------------
# Finding #42 — get_token needs_refresh + auto_refresh=True (oauth.py:1052)
# ---------------------------------------------------------------------------


def test_get_token_needs_refresh_auto_refresh_returns_refreshed_token(
    mock_200_server: str,
) -> None:
    """get_token with auto_refresh=True must return the refreshed token.

    A token expiring in 7 minutes is within the 10-minute needs_refresh buffer
    but outside the 5-minute is_expired buffer.  With auto_refresh=True the
    manager calls refresh_token() which hits the mock 200 server.

    Mutation: skipping the refresh branch regardless of needs_refresh would
    return the stale token whose access_token != "tok_access_200".

    Args:
        mock_200_server: Base URL of the 200 token server.
    """
    now = datetime.now(UTC)
    stale_token = OAuthToken(
        access_token="stale_7min",
        refresh_token="rt_7min",
        token_type="Bearer",
        expires_at=now + timedelta(minutes=7),
    )
    config = _minimal_config(mock_200_server, use_pkce=False)
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, stale_token)

    async def go() -> OAuthToken | None:
        try:
            return await manager.get_token(OAuthProvider.GOOGLE, config, auto_refresh=True)
        finally:
            await manager.close()

    result = asyncio.run(go())
    assert result is not None
    assert result.access_token == "tok_access_200"
    assert result.access_token != "stale_7min"


# ---------------------------------------------------------------------------
# Finding #43 — get_token OAuthTokenRefreshError path (oauth.py:1056)
# ---------------------------------------------------------------------------


def test_get_token_returns_none_when_refresh_raises_token_refresh_error(
    mock_403_server: str,
) -> None:
    """get_token must return None when refresh_token raises OAuthTokenRefreshError.

    A 403 from the token endpoint causes refresh_token() to raise
    OAuthTokenRefreshError, which get_token catches and maps to None.

    Mutation: propagating OAuthTokenRefreshError instead of catching it would
    raise rather than returning None.

    Args:
        mock_403_server: Base URL of the 403 token server.
    """
    now = datetime.now(UTC)
    needs_refresh_token = OAuthToken(
        access_token="needs_refresh_acc",
        refresh_token="rt_refresh",
        token_type="Bearer",
        expires_at=now + timedelta(minutes=7),
    )
    config = _minimal_config(mock_403_server, use_pkce=False)
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, needs_refresh_token)

    async def go() -> OAuthToken | None:
        try:
            return await manager.get_token(OAuthProvider.GOOGLE, config, auto_refresh=True)
        finally:
            await manager.close()

    result = asyncio.run(go())
    assert result is None


# ---------------------------------------------------------------------------
# Finding #44 — get_token OAuthTokenError, not expired (oauth.py:1059)
# ---------------------------------------------------------------------------


def test_get_token_returns_stale_token_when_refresh_raises_token_error_not_expired(
    mock_500_server: str,
) -> None:
    """get_token must return the stale token when refresh fails with OAuthTokenError and token is not expired.

    A 500 from the token endpoint causes OAuthTokenError (not RefreshError).
    The token expiring in 7 minutes has is_expired=False, so get_token returns it.

    Mutation: returning None on any OAuthTokenError would fail the not-None assertion.

    Args:
        mock_500_server: Base URL of the 500 token server.
    """
    now = datetime.now(UTC)
    stale = OAuthToken(
        access_token="stale_not_expired",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(minutes=7),
    )
    config = _minimal_config(mock_500_server, use_pkce=False)
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, stale)

    async def go() -> OAuthToken | None:
        try:
            return await manager.get_token(OAuthProvider.GOOGLE, config, auto_refresh=True)
        finally:
            await manager.close()

    result = asyncio.run(go())
    assert result is not None
    assert result.access_token == "stale_not_expired"


# ---------------------------------------------------------------------------
# Finding #45 — get_token expired after failed refresh (oauth.py:1090)
# ---------------------------------------------------------------------------


def test_get_token_returns_none_when_refresh_raises_token_error_and_token_expired(
    mock_500_server: str,
) -> None:
    """get_token must return None when refresh fails and the token is already expired.

    A token expiring in 3 minutes is within both the needs_refresh (10-min) and
    is_expired (5-min) buffers.  After a 500 OAuthTokenError, token.is_expired is
    True so get_token returns None.

    Mutation: returning the expired token (not None) when refresh fails would
    fail the ``result is None`` assertion.

    Args:
        mock_500_server: Base URL of the 500 token server.
    """
    now = datetime.now(UTC)
    expired = OAuthToken(
        access_token="expired_after_fail",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(minutes=3),
    )
    config = _minimal_config(mock_500_server, use_pkce=False)
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, expired)

    async def go() -> OAuthToken | None:
        try:
            return await manager.get_token(OAuthProvider.GOOGLE, config, auto_refresh=True)
        finally:
            await manager.close()

    result = asyncio.run(go())
    assert result is None


# ---------------------------------------------------------------------------
# Finding #46 — _post_token_refresh happy path (oauth.py:816)
# ---------------------------------------------------------------------------


def test_post_token_refresh_happy_path_parses_exact_fields(
    mock_200_server: str,
) -> None:
    """A successful refresh POST must return a token with exact field values.

    Exercises _post_token_refresh via refresh_token().  The 200 server returns
    the canned _TOKEN_200_BODY; the test asserts exact field values.

    Mutation: parsing access_token from the wrong JSON key would fail the
    exact-value assertion.

    Args:
        mock_200_server: Base URL of the 200 token server.
    """
    current = OAuthToken(
        access_token="old_acc",
        refresh_token="old_rt",
        token_type="Bearer",
        expires_at=None,
    )
    config = _minimal_config(mock_200_server, use_pkce=False)
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, current)

    before = datetime.now(UTC)

    async def go() -> OAuthToken:
        try:
            return await manager.refresh_token(OAuthProvider.GOOGLE, config)
        finally:
            await manager.close()

    result = asyncio.run(go())

    assert result.access_token == "tok_access_200"
    assert result.refresh_token == "tok_refresh_200"
    assert result.token_type == "Bearer"
    assert result.expires_at is not None
    expires_in_seconds = (result.expires_at - before).total_seconds()
    assert 3590.0 <= expires_in_seconds <= 3620.0


# ---------------------------------------------------------------------------
# Finding #49 — refresh_token other HTTP error 500 (oauth.py:1181)
# ---------------------------------------------------------------------------


def test_refresh_token_500_raises_oauth_token_error(
    mock_500_server: str,
) -> None:
    """A 500 response from the token endpoint must raise OAuthTokenError.

    500 is not in {401, 403}; it must raise the generic OAuthTokenError, NOT
    OAuthTokenRefreshError.

    Mutation: treating all non-2xx as OAuthTokenRefreshError would raise the
    wrong type and the specific ``not pytest.raises(OAuthTokenRefreshError)``
    semantics would be violated.

    Args:
        mock_500_server: Base URL of the 500 token server.
    """
    manager = OAuthManager(credential_store=None)
    token = OAuthToken(
        access_token="old_acc",
        refresh_token="old_rt",
        token_type="Bearer",
        expires_at=None,
    )
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)
    config = _minimal_config(mock_500_server, use_pkce=False)

    async def go() -> None:
        try:
            with pytest.raises(OAuthTokenError, match=r"500|[Ff]ailed"):
                await manager.refresh_token(OAuthProvider.GOOGLE, config)
        finally:
            await manager.close()

    asyncio.run(go())


# ---------------------------------------------------------------------------
# Finding #53 — revoke_token no revoke_url with credential_store (oauth.py:1213)
# ---------------------------------------------------------------------------


def test_revoke_token_no_revoke_url_calls_credential_store_delete(
    _with_fake_keyring: None,
) -> None:
    """revoke_token with no revoke_url must delete the token from the credential store.

    ANTHROPIC has revoke_url=None in OAUTH_CONFIGS; only the keyring-delete
    path runs.  The pre-seeded fake keyring entry is verified to be absent
    after revocation.

    Mutation: removing ``await self._credential_store.delete(provider_name)``
    would leave the sentinel data in the fake keyring.

    Args:
        _with_fake_keyring: Fixture that monkeypatches the keyring module.
    """
    credential_key = ("intellicrack", "intellicrack_anthropic")
    _FakeKeyringModule._passwords[credential_key] = "sentinel_to_be_deleted"

    store = _make_store_with_fake_keyring()
    manager = OAuthManager(credential_store=store)
    token = OAuthToken(
        access_token="revoke_acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=None,
    )
    _seed_token_cache(manager, OAuthProvider.ANTHROPIC, token)

    async def go() -> bool:
        _ = store.keyring_available
        try:
            return await manager.revoke_token(OAuthProvider.ANTHROPIC)
        finally:
            await manager.close()

    result = asyncio.run(go())

    assert result is True
    assert credential_key not in _FakeKeyringModule._passwords


# ---------------------------------------------------------------------------
# Finding #54 — revoke_token with revoke_url, success (oauth.py:1218)
# ---------------------------------------------------------------------------


def test_revoke_token_with_revoke_url_success_returns_true(
    mock_200_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """revoke_token must return True and clear cache when the revoke endpoint returns 200.

    Monkeypatches OAUTH_CONFIGS[GOOGLE].revoke_url to point to the 200 server.

    Mutation: not calling ``raise_for_status()`` would leave revoke_succeeded=False
    regardless of the response, returning False instead of True.

    Args:
        mock_200_server: Base URL of the 200 server to act as the revoke endpoint.
        monkeypatch: Pytest fixture used to patch OAUTH_CONFIGS.
    """
    revoke_config = _minimal_config(
        mock_200_server,
        use_pkce=False,
        revoke_url=f"{mock_200_server}/revoke",
    )
    monkeypatch.setitem(_oauth_mod.OAUTH_CONFIGS, OAuthProvider.GOOGLE, revoke_config)

    token = OAuthToken(
        access_token="revoke_success_acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    async def go() -> bool:
        try:
            return await manager.revoke_token(OAuthProvider.GOOGLE)
        finally:
            await manager.close()

    result = asyncio.run(go())

    assert result is True
    manager_any = cast(Any, manager)
    cache: dict[OAuthProvider, OAuthToken] = manager_any._token_cache
    assert OAuthProvider.GOOGLE not in cache


# ---------------------------------------------------------------------------
# Finding #55 — revoke_token revoke HTTP error (oauth.py:1230)
# ---------------------------------------------------------------------------


def test_revoke_token_revoke_http_error_returns_false(
    mock_500_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """revoke_token must return False when the revoke endpoint returns a non-2xx status.

    Mutation: not checking raise_for_status() would leave revoke_succeeded=True
    despite the 500, returning True instead of False.

    Args:
        mock_500_server: Base URL of the 500 server to act as the revoke endpoint.
        monkeypatch: Pytest fixture used to patch OAUTH_CONFIGS.
    """
    revoke_config = _minimal_config(
        mock_500_server,
        use_pkce=False,
        revoke_url=f"{mock_500_server}/revoke",
    )
    monkeypatch.setitem(_oauth_mod.OAUTH_CONFIGS, OAuthProvider.GOOGLE, revoke_config)

    token = OAuthToken(
        access_token="revoke_fail_acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    async def go() -> bool:
        try:
            return await manager.revoke_token(OAuthProvider.GOOGLE)
        finally:
            await manager.close()

    result = asyncio.run(go())
    assert result is False


# ---------------------------------------------------------------------------
# Finding #57 — OAuthManager.to_provider_credentials (oauth.py:1268)
# ---------------------------------------------------------------------------


def test_to_provider_credentials_api_key_equals_access_token() -> None:
    """to_provider_credentials must return ProviderCredentials whose api_key is the access_token.

    Mutation: setting api_key to token.refresh_token or None would fail the
    exact-value assertion.
    """
    now = datetime.now(UTC)
    token = OAuthToken(
        access_token="creds_acc_57",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(hours=1),
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    async def go() -> ProviderCredentials | None:
        try:
            return await manager.to_provider_credentials(OAuthProvider.GOOGLE)
        finally:
            await manager.close()

    creds = asyncio.run(go())
    assert creds is not None
    assert creds.api_key == "creds_acc_57"


# ---------------------------------------------------------------------------
# Finding #58 — OAuthManager.run_authorization_flow (oauth.py:1290)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_run_authorization_flow_returns_token_from_fake_server(
    mock_200_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_authorization_flow must complete the full OAuth round-trip and return a token.

    The fake browser function reads the state from the authorization URL and
    sends a real GET to the local callback server, triggering handle_callback
    which exchanges the code against the mock 200 token server.

    Mutation: not calling handle_callback after wait_for_callback would skip
    the token exchange and raise rather than returning a token.

    Args:
        mock_200_server: Base URL of the 200 token server.
        monkeypatch: Pytest fixture used to suppress webbrowser.open.
    """
    callback_port = _find_free_port()
    config = _minimal_config(mock_200_server, use_pkce=False)
    manager = OAuthManager(credential_store=None, callback_port=callback_port)

    def _fake_browser(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        state_val = params["state"][0]

        def _send() -> None:
            try:
                safe_state = urllib.parse.quote(state_val, safe="")
                conn = http.client.HTTPConnection("127.0.0.1", callback_port, timeout=5.0)
                conn.request("GET", f"/callback?code=test_auth_code&state={safe_state}")
                resp = conn.getresponse()
                resp.read()
                conn.close()
            except (OSError, http.client.HTTPException):
                pass

        threading.Thread(target=_send, daemon=True).start()

    monkeypatch.setattr("webbrowser.open", _fake_browser)

    async def go() -> OAuthToken:
        try:
            return await manager.run_authorization_flow(config)
        finally:
            await manager.close()

    token = asyncio.run(go())
    assert token.access_token == "tok_access_200"
    assert token.token_type == "Bearer"


# ---------------------------------------------------------------------------
# Finding #60 — authorize_google (oauth.py:1368)
# ---------------------------------------------------------------------------


@_requires_loopback
def test_authorize_google_returns_provider_credentials_with_access_token(
    mock_200_server: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """authorize_google must return ProviderCredentials whose api_key is the issued access_token.

    Monkeypatches OAUTH_CONFIGS[GOOGLE] to point the token_url at the 200 server,
    and the global OAuthManager singleton to a controlled instance.  The fake
    browser sends the callback with the state extracted from the auth URL.

    Mutation: returning ProviderCredentials(api_key=None) would fail the exact
    api_key assertion.

    Args:
        mock_200_server: Base URL of the 200 token server.
        monkeypatch: Pytest fixture used to patch OAUTH_CONFIGS and webbrowser.open.
    """
    callback_port = _find_free_port()
    controlled_manager = OAuthManager(credential_store=None, callback_port=callback_port)

    monkeypatch.setattr(_oauth_mod._OAuthManagerHolder, "instance", controlled_manager)

    google_config_patched = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="google-test-client",
        client_secret=None,
        authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url=f"{mock_200_server}/token",
        scopes=OAUTH_CONFIGS[OAuthProvider.GOOGLE].scopes,
        use_pkce=False,
        revoke_url=None,
    )
    monkeypatch.setitem(_oauth_mod.OAUTH_CONFIGS, OAuthProvider.GOOGLE, google_config_patched)

    def _fake_browser(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        state_val = params["state"][0]

        def _send() -> None:
            try:
                safe_state = urllib.parse.quote(state_val, safe="")
                conn = http.client.HTTPConnection("127.0.0.1", callback_port, timeout=5.0)
                conn.request("GET", f"/callback?code=google_auth_code&state={safe_state}")
                resp = conn.getresponse()
                resp.read()
                conn.close()
            except (OSError, http.client.HTTPException):
                pass

        threading.Thread(target=_send, daemon=True).start()

    monkeypatch.setattr("webbrowser.open", _fake_browser)

    async def go() -> ProviderCredentials:
        try:
            return await authorize_google(client_id="google-test-client")
        finally:
            await controlled_manager.close()

    creds = asyncio.run(go())
    assert creds.api_key == "tok_access_200"


# ---------------------------------------------------------------------------
# Finding #61 — CredentialStore._check_keyring library not installed (store.py:147)
# ---------------------------------------------------------------------------


def test_check_keyring_library_not_installed_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_keyring must return False when _keyring_module is None.

    Monkeypatches the module-level _keyring_module to None, then creates a
    fresh CredentialStore whose _check_keyring has never been called.

    Mutation: removing the ``if _keyring_module is None: return False`` guard
    would cause an AttributeError from calling get_keyring() on None.

    Args:
        monkeypatch: Pytest fixture used to set _keyring_module to None.
    """
    monkeypatch.setattr(_store_mod, "_keyring_module", None)
    store = CredentialStore()
    result = store._check_keyring()
    assert result is False


# ---------------------------------------------------------------------------
# Finding #62 — CredentialStore._check_keyring fail/null backend (store.py:161)
# ---------------------------------------------------------------------------


def test_check_keyring_fail_keyring_backend_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_keyring must return False when the backend class name is FailKeyring.

    Oracle: CredentialStore._UNUSABLE_BACKEND_NAMES and the backend_name
    sentinel check ``backend_name in {"Keyring", "FailKeyring", "NullKeyring"}``.

    Mutation: removing ``"FailKeyring"`` from the sentinel set would let the
    backend pass and _check_keyring would return True instead of False.

    Args:
        monkeypatch: Pytest fixture used to inject the FailKeyring module.
    """
    monkeypatch.setattr(_store_mod, "_keyring_module", _FailKeyringModule)
    store = CredentialStore()
    result = store._check_keyring()
    assert result is False


def test_check_keyring_null_keyring_name_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_keyring must return False when the backend class name is NullKeyring.

    Uses a dynamically created class named NullKeyring to exercise the
    ``backend_name in {"Keyring", "FailKeyring", "NullKeyring"}`` branch.

    Mutation: removing ``"NullKeyring"`` from the sentinel set would let the
    backend pass and return True.

    Args:
        monkeypatch: Pytest fixture used to inject a NullKeyring-named module.
    """
    class NullKeyring:
        """Fake backend with NullKeyring name and positive priority."""

        priority: ClassVar[float] = 1.0

    class _NullKeyringModule:
        @classmethod
        def get_keyring(cls) -> NullKeyring:
            return NullKeyring()

        @classmethod
        def get_password(cls, service: str, username: str) -> str | None:
            return None

        @classmethod
        def set_password(cls, service: str, username: str, password: str) -> None:
            pass

        @classmethod
        def delete_password(cls, service: str, username: str) -> None:
            pass

    monkeypatch.setattr(_store_mod, "_keyring_module", _NullKeyringModule)
    store = CredentialStore()
    result = store._check_keyring()
    assert result is False


# ---------------------------------------------------------------------------
# Finding #63 — CredentialStore._check_keyring priority <= 0 (store.py:169)
# ---------------------------------------------------------------------------


def test_check_keyring_zero_priority_backend_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_keyring must return False when the backend priority is zero or negative.

    _ZeroPriorityBackend passes the name checks but has priority=0.0, which
    fails the ``priority <= 0`` guard.

    Mutation: changing the guard to ``priority < 0`` would let priority=0.0
    through and return True instead of False.

    Args:
        monkeypatch: Pytest fixture used to inject the zero-priority module.
    """
    monkeypatch.setattr(_store_mod, "_keyring_module", _ZeroPriorityModule)
    store = CredentialStore()
    result = store._check_keyring()
    assert result is False


def test_check_keyring_negative_priority_backend_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_check_keyring must return False for a backend with negative priority.

    Args:
        monkeypatch: Pytest fixture used to inject a negative-priority module.
    """
    class _NegPriorityBackend:
        priority: ClassVar[float] = -2.5

    class _NegPriorityModule:
        @classmethod
        def get_keyring(cls) -> _NegPriorityBackend:
            return _NegPriorityBackend()

        @classmethod
        def get_password(cls, service: str, username: str) -> str | None:
            return None

        @classmethod
        def set_password(cls, service: str, username: str, password: str) -> None:
            pass

        @classmethod
        def delete_password(cls, service: str, username: str) -> None:
            pass

    monkeypatch.setattr(_store_mod, "_keyring_module", _NegPriorityModule)
    store = CredentialStore()
    result = store._check_keyring()
    assert result is False
