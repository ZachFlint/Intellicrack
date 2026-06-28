# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Section 11 deterministic gate tests for OAuth and CredentialStore.

Covers the boundary math and decision-tree branches identified in the
section-11 audit: expiry buffers, serialisation round-trips, handle_callback
error paths, get_token decision branches, revoke_token cache guarantee,
refresh_token 403 path, CredentialStore.get_or_raise, and malformed-JSON
deserialisation.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from intellicrack.core.types import ProviderName
from intellicrack.credentials.env_loader import CredentialLoader
from intellicrack.credentials.oauth import (
    OAuthCallbackError,
    OAuthConfig,
    OAuthManager,
    OAuthProvider,
    OAuthState,
    OAuthToken,
    OAuthTokenError,
    OAuthTokenRefreshError,
)
from intellicrack.credentials.store import (
    CredentialNotFoundError,
    CredentialStore,
    CredentialStoreError,
)


if TYPE_CHECKING:
    from collections.abc import Iterator

_HTTP_FORBIDDEN = 403
_HTTP_OK = 200


def _find_free_port() -> int:
    """Return an OS-allocated free TCP port on loopback.

    Returns:
        int: An available TCP port number.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Always403Handler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that always responds 403 to POST requests."""

    def do_POST(self) -> None:
        """Return 403 Forbidden with a JSON error body."""
        self.send_response(_HTTP_FORBIDDEN)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": "forbidden"}).encode("utf-8"))

    def log_message(self, *args: object, **kwargs: object) -> None:
        """Suppress access log output.

        Args:
            *args: Unused positional arguments from the stdlib signature.
            **kwargs: Unused keyword arguments for forward compatibility.
        """
        del args, kwargs


@pytest.fixture
def mock_403_server() -> Iterator[str]:
    """Spin up an in-process server that always returns 403 to POST requests.

    Yields:
        str: Base URL of the mock server (e.g. ``http://127.0.0.1:PORT``).
    """
    port = _find_free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Always403Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def _minimal_config(
    base_url: str,
    token_path: str = "/token",
    *,
    use_pkce: bool = False,
) -> OAuthConfig:
    """Build a minimal OAuthConfig pointing at a local URL.

    Args:
        base_url: Base URL for the mock server.
        token_path: Token endpoint path relative to base_url.
        use_pkce: Whether to enable PKCE.

    Returns:
        OAuthConfig: A configuration suitable for unit tests.
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
        revoke_url=None,
    )


def _make_keyring_free_store(env_entries: dict[str, str] | None = None) -> CredentialStore:
    """Create a CredentialStore with keyring disabled and optional env entries.

    The keyring-available check is bypassed before the cached_property caches
    its result so every subsequent call to ``keyring_available`` returns False.

    Args:
        env_entries: Mapping of env-variable name → value to inject into the
            fallback CredentialLoader without touching os.environ or disk.

    Returns:
        CredentialStore: A store that uses only the injected env fallback.
    """
    loader = CredentialLoader(env_path=Path("/__nonexistent_gate_test__/.env"))
    if env_entries:
        loader_any = cast("Any", loader)
        env_vars: dict[str, str] = loader_any._env_vars
        env_vars.update(env_entries)
    store = CredentialStore(fallback_loader=loader)
    store_any = cast("Any", store)
    store_any._keyring_checked = True
    store_any._keyring_available = False
    return store


def _seed_token_cache(
    manager: OAuthManager,
    provider: OAuthProvider,
    token: OAuthToken,
) -> None:
    """Directly place a token into the manager's in-memory cache.

    Args:
        manager: The OAuthManager instance to mutate.
        provider: The provider key for the cache entry.
        token: The OAuthToken to store.
    """
    manager_any = cast("Any", manager)
    cache: dict[OAuthProvider, OAuthToken] = manager_any._token_cache
    cache[provider] = token


# ---------------------------------------------------------------------------
# OAuthToken.is_expired_at — 5-minute buffer boundary
# ---------------------------------------------------------------------------


def test_is_expired_at_past_expiry() -> None:
    """Token that expired 10 seconds ago must report is_expired_at=True.

    Mutation: changing ``>=`` to ``>`` in is_expired_at lets an
    exactly-at-boundary token appear valid.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now - timedelta(seconds=10)
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.is_expired_at(now) is True


def test_is_expired_at_within_5min_buffer() -> None:
    """Token expiring in 3 minutes is inside the 5-minute buffer, so expired.

    Mutation: raising the buffer from 5 to 0 minutes would let this token
    appear valid.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now + timedelta(minutes=3)
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.is_expired_at(now) is True


def test_is_expired_at_exact_5min_boundary() -> None:
    """Token expiring in exactly 5 minutes sits on the >= boundary, so expired.

    The oracle: ``now >= (now+5min - 5min) = now >= now`` is True.
    Mutation: using ``>`` instead of ``>=`` would return False here.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now + timedelta(minutes=5)
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.is_expired_at(now) is True


def test_is_expired_at_outside_5min_buffer() -> None:
    """Token expiring in 6 minutes is outside the 5-minute buffer, not expired.

    Oracle: ``now >= (now+6min - 5min) = now >= now+1min`` is False.
    Mutation: lowering the buffer to 6+ minutes would make this return True.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now + timedelta(minutes=6)
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.is_expired_at(now) is False


def test_is_expired_at_no_expiry() -> None:
    """Token with expires_at=None must never be considered expired.

    Mutation: removing the ``None`` guard would cause a TypeError instead of
    returning False.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    assert token.is_expired_at(now) is False


# ---------------------------------------------------------------------------
# OAuthToken.needs_refresh_at — 10-minute buffer boundary
# ---------------------------------------------------------------------------


def test_needs_refresh_at_past_expiry() -> None:
    """Expired token must also need a refresh.

    Mutation: raising the needs_refresh buffer to 0 minutes would return False.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now - timedelta(seconds=10)
    token = OAuthToken(
        access_token="acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.needs_refresh_at(now) is True


def test_needs_refresh_at_within_10min_buffer_not_in_5min() -> None:
    """Token expiring in 7 minutes needs refresh but is not yet is_expired_at.

    Oracle for needs_refresh_at: ``now >= (now+7min - 10min) = now >= now-3min`` True.
    Oracle for is_expired_at: ``now >= (now+7min - 5min) = now >= now+2min`` False.
    Mutation: changing the 10-minute buffer to 6 minutes would make this False.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now + timedelta(minutes=7)
    token = OAuthToken(
        access_token="acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.needs_refresh_at(now) is True
    assert token.is_expired_at(now) is False


def test_needs_refresh_at_exact_10min_boundary() -> None:
    """Token expiring in exactly 10 minutes sits on the boundary, so needs refresh.

    Oracle: ``now >= (now+10min - 10min) = now >= now`` is True.
    Mutation: using ``>`` instead of ``>=`` would return False here.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now + timedelta(minutes=10)
    token = OAuthToken(
        access_token="acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.needs_refresh_at(now) is True


def test_needs_refresh_at_outside_10min_buffer() -> None:
    """Token expiring in 11 minutes is outside the buffer, no refresh needed.

    Oracle: ``now >= (now+11min - 10min) = now >= now+1min`` is False.
    Mutation: raising the buffer from 10 to 11+ minutes would return True.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    expires_at = now + timedelta(minutes=11)
    token = OAuthToken(
        access_token="acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=expires_at,
    )
    assert token.needs_refresh_at(now) is False


def test_needs_refresh_at_no_expiry() -> None:
    """Token with expires_at=None must never need a refresh via the timed path.

    Mutation: removing the ``None`` guard would cause a TypeError.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    token = OAuthToken(
        access_token="acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=None,
    )
    assert token.needs_refresh_at(now) is False


# ---------------------------------------------------------------------------
# OAuthToken.to_dict — exact field mapping
# ---------------------------------------------------------------------------


def test_to_dict_exact_field_keys_and_values() -> None:
    """to_dict must emit exactly the six documented keys with correct values.

    Mutation: renaming a key (e.g. ``access_token`` → ``token``) in to_dict
    would cause this assertion to fail.
    """
    expires_at = datetime(2030, 6, 1, 0, 0, 0, tzinfo=UTC)
    token = OAuthToken(
        access_token="acc123",
        refresh_token="rt456",
        token_type="Bearer",
        expires_at=expires_at,
        scopes=("read", "write"),
        id_token="id789",
    )
    result = token.to_dict()

    assert result["access_token"] == "acc123"
    assert result["refresh_token"] == "rt456"
    assert result["token_type"] == "Bearer"
    assert result["expires_at"] == "2030-06-01T00:00:00+00:00"
    assert result["scopes"] == ["read", "write"]
    assert result["id_token"] == "id789"
    assert set(result.keys()) == {
        "access_token",
        "refresh_token",
        "token_type",
        "expires_at",
        "scopes",
        "id_token",
    }


def test_to_dict_none_values_preserved() -> None:
    """None refresh_token and id_token must appear as None in the dict, not absent.

    Mutation: using ``dict.pop`` to drop None values would make these keys absent.
    """
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
        id_token=None,
    )
    result = token.to_dict()

    assert result["refresh_token"] is None
    assert result["expires_at"] is None
    assert result["id_token"] is None


def test_to_dict_scopes_converted_to_list() -> None:
    """Scopes tuple must be converted to a list in to_dict output.

    Mutation: emitting a tuple instead of list would break JSON round-trip
    when callers expect a list type.
    """
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
        scopes=("openid", "profile"),
    )
    result = token.to_dict()

    assert result["scopes"] == ["openid", "profile"]
    assert isinstance(result["scopes"], list)


def test_to_dict_empty_scopes_to_empty_list() -> None:
    """Empty scopes tuple must produce an empty list, not omit the key.

    Mutation: omitting the scopes key when empty would break from_dict
    round-trip contracts.
    """
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    result = token.to_dict()

    assert result["scopes"] == []
    assert "scopes" in result


# ---------------------------------------------------------------------------
# OAuthToken.from_dict — round-trip and malformed input
# ---------------------------------------------------------------------------


def test_from_dict_round_trip_identity() -> None:
    """from_dict(to_dict(token)) must reproduce the original token field-by-field.

    Mutation: dropping a field in to_dict (e.g. id_token) would make the
    round-trip token have id_token=None instead of the original value.
    """
    expires_at = datetime(2031, 3, 15, 8, 30, 0, tzinfo=UTC)
    original = OAuthToken(
        access_token="orig_acc",
        refresh_token="orig_rt",
        token_type="Bearer",
        expires_at=expires_at,
        scopes=("s1", "s2"),
        id_token="orig_id",
    )
    restored = OAuthToken.from_dict(original.to_dict())

    assert restored.access_token == original.access_token
    assert restored.refresh_token == original.refresh_token
    assert restored.token_type == original.token_type
    assert restored.expires_at == original.expires_at
    assert restored.scopes == original.scopes
    assert restored.id_token == original.id_token


def test_from_dict_empty_dict_applies_defaults() -> None:
    """from_dict({}) must return a usable token with documented default values.

    Mutation: changing the default token_type to None in from_dict would
    break callers that expect a non-None string.
    """
    token = OAuthToken.from_dict({})

    assert len(token.access_token) == 0
    assert token.refresh_token is None
    assert token.token_type == "Bearer"
    assert token.expires_at is None
    assert token.scopes == ()
    assert token.id_token is None


def test_from_dict_wrong_access_token_type_falls_back_to_empty() -> None:
    """Non-string access_token in dict must fall back to empty string, not raise.

    Mutation: removing the isinstance guard in from_dict would cause int 42
    to be stored as the access_token, producing a type-incorrect token.
    """
    data: dict[str, str | list[str] | None] = {"access_token": None}
    token = OAuthToken.from_dict(data)

    assert len(token.access_token) == 0


def test_from_dict_bad_expires_at_string_raises_value_error() -> None:
    """Non-ISO expires_at string must raise ValueError from fromisoformat.

    This is the documented propagation path: ValueError surfaces to
    _load_token which catches it and returns None.
    Mutation: adding a bare ``except Exception`` in from_dict would silently
    swallow the error and return a token with expires_at=None.
    """
    with pytest.raises(ValueError, match="not-a-datetime"):
        OAuthToken.from_dict({"expires_at": "not-a-datetime"})


# ---------------------------------------------------------------------------
# OAuthState.is_expired_at — 10-minute state timeout
# ---------------------------------------------------------------------------


def test_oauth_state_is_expired_at_past() -> None:
    """State created 11 minutes ago must be expired.

    Mutation: changing the 10-minute timeout to 12 minutes would return False.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    created_at = now - timedelta(minutes=11)
    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="c",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=(),
        use_pkce=False,
    )
    state = OAuthState(
        state="s",
        code_verifier=None,
        redirect_uri="http://localhost/cb",
        created_at=created_at,
        provider=OAuthProvider.GOOGLE,
        config=config,
    )
    assert state.is_expired_at(now) is True


def test_oauth_state_is_expired_at_exact_boundary() -> None:
    """State created exactly 10 minutes ago is on the >= boundary, so expired.

    Oracle: ``now >= (now-10min + 10min) = now >= now`` is True.
    Mutation: using ``>`` instead of ``>=`` would return False.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    created_at = now - timedelta(minutes=10)
    config = OAuthConfig(
        provider=OAuthProvider.ANTHROPIC,
        client_id="c",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=(),
        use_pkce=False,
    )
    state = OAuthState(
        state="s",
        code_verifier=None,
        redirect_uri="http://localhost/cb",
        created_at=created_at,
        provider=OAuthProvider.ANTHROPIC,
        config=config,
    )
    assert state.is_expired_at(now) is True


def test_oauth_state_is_expired_at_recent() -> None:
    """State created 9 minutes ago must not yet be expired.

    Oracle: ``now >= (now-9min + 10min) = now >= now+1min`` is False.
    Mutation: lowering the timeout to 8 minutes would return True.
    """
    now = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
    created_at = now - timedelta(minutes=9)
    config = OAuthConfig(
        provider=OAuthProvider.HUGGINGFACE,
        client_id="c",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=(),
        use_pkce=False,
    )
    state = OAuthState(
        state="s",
        code_verifier=None,
        redirect_uri="http://localhost/cb",
        created_at=created_at,
        provider=OAuthProvider.HUGGINGFACE,
        config=config,
    )
    assert state.is_expired_at(now) is False


# ---------------------------------------------------------------------------
# OAuthManager.handle_callback — error paths
# ---------------------------------------------------------------------------


def test_handle_callback_unknown_state_raises() -> None:
    """handle_callback with a state not in _pending_states must raise OAuthCallbackError.

    Mutation: removing the ``oauth_state is None`` guard in handle_callback
    would allow code exchange for an unrecognised state.
    """
    manager = OAuthManager(credential_store=None)

    with pytest.raises(OAuthCallbackError, match="Unknown state"):
        asyncio.run(manager.handle_callback("code", "state_that_was_never_registered"))


def test_handle_callback_expired_state_raises() -> None:
    """handle_callback with an expired OAuthState must raise OAuthCallbackError.

    Mutation: removing the ``oauth_state.is_expired`` guard would allow
    authorization flows that started more than 10 minutes ago.
    """
    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="c",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=(),
        use_pkce=False,
    )
    expired_state = OAuthState(
        state="state_key_expired",
        code_verifier=None,
        redirect_uri="http://localhost/cb",
        created_at=datetime.now(UTC) - timedelta(minutes=11),
        provider=OAuthProvider.GOOGLE,
        config=config,
    )
    manager = OAuthManager(credential_store=None)
    manager_any = cast("Any", manager)
    pending: dict[str, OAuthState] = manager_any._pending_states
    pending["state_key_expired"] = expired_state

    with pytest.raises(OAuthCallbackError, match=r"[Ee]xpired"):
        asyncio.run(manager.handle_callback("code", "state_key_expired"))


def test_handle_callback_pkce_verifier_missing_raises() -> None:
    """handle_callback with use_pkce=True but code_verifier=None must raise OAuthCallbackError.

    Mutation: removing the ``not oauth_state.code_verifier`` guard would
    silently attempt the code exchange without a PKCE verifier.
    """
    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="c",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=(),
        use_pkce=True,
    )
    fresh_state = OAuthState(
        state="state_key_pkce",
        code_verifier=None,
        redirect_uri="http://localhost/cb",
        created_at=datetime.now(UTC),
        provider=OAuthProvider.GOOGLE,
        config=config,
    )
    manager = OAuthManager(credential_store=None)
    manager_any = cast("Any", manager)
    pending: dict[str, OAuthState] = manager_any._pending_states
    pending["state_key_pkce"] = fresh_state

    with pytest.raises(OAuthCallbackError, match=r"[Pp]KCE|pkce|verifier"):
        asyncio.run(manager.handle_callback("code", "state_key_pkce"))


# ---------------------------------------------------------------------------
# OAuthManager.get_token — decision-tree branches
# ---------------------------------------------------------------------------


def test_get_token_returns_none_when_no_token_in_cache() -> None:
    """get_token must return None when no token exists and no store is provided.

    Mutation: returning a placeholder token instead of None when the cache
    is empty would break callers that test ``if token is None``.
    """
    manager = OAuthManager(credential_store=None)

    result = asyncio.run(manager.get_token(OAuthProvider.GOOGLE))
    assert result is None


def test_get_token_returns_valid_token_without_refresh() -> None:
    """get_token must return the cached token unchanged when it is not near expiry.

    Mutation: always triggering a refresh regardless of needs_refresh would
    cause an unnecessary network call and this assertion to fail on the
    token identity check.
    """
    now = datetime.now(UTC)
    token = OAuthToken(
        access_token="valid_acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(hours=1),
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    result = asyncio.run(manager.get_token(OAuthProvider.GOOGLE, auto_refresh=False))

    assert result is not None
    assert result.access_token == "valid_acc"


def test_get_token_returns_none_when_token_is_expired_and_no_auto_refresh() -> None:
    """get_token with auto_refresh=False must return None for an is_expired token.

    Oracle: token expiring in 3 minutes satisfies is_expired (within 5-min buffer).
    Mutation: returning the expired token instead of None would expose an
    unusable token to callers.
    """
    now = datetime.now(UTC)
    token = OAuthToken(
        access_token="expired_acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(minutes=3),
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    result = asyncio.run(manager.get_token(OAuthProvider.GOOGLE, auto_refresh=False))

    assert result is None


def test_get_token_returns_stale_token_when_needs_refresh_not_expired_and_no_auto_refresh() -> None:
    """get_token with auto_refresh=False must return the stale but not-expired token.

    Oracle: token expiring in 7 minutes satisfies needs_refresh (within 10-min
    buffer) but NOT is_expired (outside 5-min buffer). With auto_refresh=False
    the refresh is skipped and the stale token is returned.
    Mutation: returning None for all needs_refresh tokens regardless of
    auto_refresh would break this.
    """
    now = datetime.now(UTC)
    token = OAuthToken(
        access_token="stale_acc",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(minutes=7),
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    result = asyncio.run(manager.get_token(OAuthProvider.GOOGLE, auto_refresh=False))

    assert result is not None
    assert result.access_token == "stale_acc"


# ---------------------------------------------------------------------------
# OAuthManager.revoke_token
# ---------------------------------------------------------------------------


def test_revoke_token_returns_false_when_no_token() -> None:
    """revoke_token must return False immediately when no token is cached.

    Mutation: returning True or raising when there is no token would break the
    documented ``False`` return contract.
    """
    manager = OAuthManager(credential_store=None)

    result = asyncio.run(manager.revoke_token(OAuthProvider.ANTHROPIC))

    assert result is False


def test_revoke_token_always_clears_cache() -> None:
    """revoke_token must clear the in-memory cache even when no revoke_url is configured.

    ANTHROPIC has ``revoke_url=None`` in OAUTH_CONFIGS, so only the cache-clear
    path executes. The combined_success must be True (no keyring, no remote call).
    Mutation: removing ``self._token_cache.pop(provider, None)`` would leave the
    stale token in cache.
    """
    now = datetime.now(UTC)
    token = OAuthToken(
        access_token="acc_to_revoke",
        refresh_token="rt",
        token_type="Bearer",
        expires_at=now + timedelta(hours=1),
    )
    manager = OAuthManager(credential_store=None)
    _seed_token_cache(manager, OAuthProvider.ANTHROPIC, token)

    manager_any = cast("Any", manager)
    cache_before: dict[OAuthProvider, OAuthToken] = manager_any._token_cache
    assert OAuthProvider.ANTHROPIC in cache_before

    result = asyncio.run(manager.revoke_token(OAuthProvider.ANTHROPIC))

    assert result is True
    cache_after: dict[OAuthProvider, OAuthToken] = manager_any._token_cache
    assert OAuthProvider.ANTHROPIC not in cache_after


# ---------------------------------------------------------------------------
# OAuthManager.refresh_token — 403 must raise OAuthTokenRefreshError
# ---------------------------------------------------------------------------


def test_refresh_token_403_raises_oauth_token_refresh_error(
    mock_403_server: str,
) -> None:
    """A 403 response from the token endpoint must raise OAuthTokenRefreshError.

    Both 401 and 403 are in the ``{_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN}`` set.
    Mutation: removing 403 from that set would raise OAuthTokenError instead,
    which a caller catching OAuthTokenRefreshError would not see.

    Args:
        mock_403_server: Base URL of the mock server returning HTTP 403.
    """
    manager = OAuthManager(credential_store=None)
    token = OAuthToken(
        access_token="old_acc",
        refresh_token="old_rt",
        token_type="Bearer",
        expires_at=None,
    )
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    config = _minimal_config(mock_403_server, use_pkce=False)

    async def go() -> None:
        with pytest.raises(OAuthTokenRefreshError, match="403"):
            await manager.refresh_token(OAuthProvider.GOOGLE, config)
        await manager.close()

    asyncio.run(go())


# ---------------------------------------------------------------------------
# OAuthManager.refresh_token — no refresh token raises OAuthTokenError
# ---------------------------------------------------------------------------


def test_refresh_token_no_refresh_token_raises_token_error() -> None:
    """refresh_token must raise OAuthTokenError when the cached token has no refresh_token.

    Mutation: silently returning without raising would make the caller think
    the refresh succeeded.
    """
    manager = OAuthManager(credential_store=None)
    token = OAuthToken(
        access_token="acc",
        refresh_token=None,
        token_type="Bearer",
        expires_at=None,
    )
    _seed_token_cache(manager, OAuthProvider.GOOGLE, token)

    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id="c",
        client_secret=None,
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        scopes=(),
        use_pkce=False,
    )

    async def go() -> None:
        with pytest.raises(OAuthTokenError, match=r"[Nn]o refresh token"):
            await manager.refresh_token(OAuthProvider.GOOGLE, config)
        await manager.close()

    asyncio.run(go())


# ---------------------------------------------------------------------------
# CredentialStore.get_or_raise
# ---------------------------------------------------------------------------


def test_credential_store_get_or_raise_not_found_raises_credential_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_or_raise must raise CredentialNotFoundError containing the provider name.

    The fallback ``CredentialLoader._get_var`` reads ``os.environ`` after its
    injected ``_env_vars`` dict, so the ambient Ollama variables are removed to
    guarantee the keyring-free store resolves nothing for the provider.

    Mutation: raising a generic Exception instead of CredentialNotFoundError
    would break callers that catch the specific type.

    Args:
        monkeypatch: Pytest fixture used to delete the Ollama credential
            environment variables for the duration of the test.
    """
    monkeypatch.delenv("OLLAMA_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    store = _make_keyring_free_store()

    with pytest.raises(CredentialNotFoundError, match="ollama"):
        asyncio.run(store.get_or_raise(ProviderName.OLLAMA))


def test_credential_store_get_or_raise_found_returns_credentials() -> None:
    """get_or_raise must return the ProviderCredentials when the env fallback finds them.

    The env_vars dict is injected directly without touching disk or os.environ.
    Mutation: returning None when a credential exists would contradict the
    documented non-None return type.
    """
    store = _make_keyring_free_store({"OLLAMA_API_KEY": "gate_test_key_section11"})

    creds = asyncio.run(store.get_or_raise(ProviderName.OLLAMA))

    assert creds.api_key == "gate_test_key_section11"


# ---------------------------------------------------------------------------
# CredentialStore._deserialize_credentials — malformed JSON
# ---------------------------------------------------------------------------


def test_credential_store_deserialize_malformed_json_raises_store_error() -> None:
    """_deserialize_credentials with malformed JSON must raise CredentialStoreError.

    Mutation: catching json.JSONDecodeError silently (returning None or
    ProviderCredentials()) would hide data corruption from callers.
    """
    store_cls = cast("Any", CredentialStore)
    with pytest.raises(CredentialStoreError, match=r"[Dd]eserializ|[Ff]ailed"):
        store_cls._deserialize_credentials("not valid json {{{")
