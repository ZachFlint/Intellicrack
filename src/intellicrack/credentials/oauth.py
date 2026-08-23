# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OAuth 2.0 flow handling for Intellicrack providers.

This module handles OAuth 2.0 authorization flows for providers that support it, including authorization code flow with PKCE, token refresh,
and secure storage.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.server
import json
import os
import secrets
import socketserver
import threading
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, ClassVar, Final, cast

import httpx

from intellicrack.core.logging import get_logger
from intellicrack.core.types import IntellicrackError, ProviderCredentials, ProviderName
from intellicrack.credentials.store import CredentialSource, get_credential_store


if TYPE_CHECKING:
    from intellicrack.credentials.store import CredentialStore

_logger = get_logger(__name__)

try:
    import keyring.errors as _keyring_errors

    _KeyringError: type[Exception] = _keyring_errors.KeyringError
except ImportError:
    _logger.debug("keyring_errors_import_failed", exc_info=True)
    _KeyringError = OSError

_GOOGLE_OAUTH_ENDPOINT: Final = "https://oauth2.googleapis.com/token"
_ANTHROPIC_OAUTH_AUTHORIZE_URL: Final = "https://claude.ai/oauth/authorize"
_ANTHROPIC_OAUTH_EXCHANGE_URL: Final = "https://console.anthropic.com/v1/oauth/token"
_HUGGINGFACE_OAUTH_AUTHORIZE_URL: Final = "https://huggingface.co/oauth/authorize"
_HUGGINGFACE_OAUTH_EXCHANGE_URL: Final = "https://huggingface.co/oauth/token"
_HTTP_OK: Final = 200
_HTTP_UNAUTHORIZED: Final = 401
_HTTP_FORBIDDEN: Final = 403


class OAuthError(IntellicrackError):
    """Base error for OAuth operations."""


class OAuthConfigurationError(OAuthError):
    """OAuth configuration is invalid or incomplete."""


class OAuthAuthorizationError(OAuthError):
    """Authorization failed or was denied."""


class OAuthTokenError(OAuthError):
    """Token operation failed (exchange, refresh, etc.)."""


class OAuthTokenRefreshError(OAuthTokenError):
    """Token refresh failed due to an authentication error (401/403)."""


class OAuthCallbackError(OAuthError):
    """Error during OAuth callback handling."""


class OAuthFlowType(Enum):
    """Supported OAuth 2.0 flow types."""

    AUTHORIZATION_CODE = "authorization_code"


class OAuthProvider(Enum):
    """Providers that support OAuth authentication.

    OpenAI is intentionally absent: the OpenAI Platform exposes only API
    keys, not a public OAuth flow for API access, so users must register a
    static API key via the credential store instead.
    """

    GOOGLE = "google"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"


_OAUTH_TO_PROVIDER_NAME: dict[OAuthProvider, ProviderName] = {
    OAuthProvider.GOOGLE: ProviderName.GOOGLE,
    OAuthProvider.ANTHROPIC: ProviderName.ANTHROPIC,
    OAuthProvider.HUGGINGFACE: ProviderName.HUGGINGFACE,
}


def _oauth_provider_to_name(provider: OAuthProvider) -> ProviderName:
    """Map an OAuthProvider to the corresponding ProviderName.

    Args:
        provider: The OAuth provider enum value.

    Returns:
        ProviderName: The matching ProviderName.

    Raises:
        KeyError: If the provider has no mapping.
    """
    if provider not in _OAUTH_TO_PROVIDER_NAME:
        _logger.error("oauth_provider_mapping_missing", provider_name=provider.value)
        msg = f"No provider name mapping for {provider!r}"
        raise KeyError(msg)
    return _OAUTH_TO_PROVIDER_NAME[provider]


@dataclass(frozen=True)
class OAuthConfig:
    """OAuth 2.0 configuration for a provider.

    Attributes:
        provider: The OAuth provider.
        client_id: OAuth client ID.
        client_secret: OAuth client secret (None for PKCE flows).
        authorization_url: URL for authorization endpoint.
        token_url: URL for token endpoint.
        scopes: Tuple of OAuth scopes to request.
        redirect_uri: Redirect URI for callback.
        use_pkce: Whether to use PKCE (Proof Key for Code Exchange).
        revoke_url: URL for token revocation endpoint.
    """

    provider: OAuthProvider
    client_id: str
    client_secret: str | None
    authorization_url: str
    token_url: str
    scopes: tuple[str, ...]
    redirect_uri: str = "http://localhost:8080/callback"
    use_pkce: bool = True
    revoke_url: str | None = None


@dataclass
class OAuthToken:
    """OAuth 2.0 token data.

    Attributes:
        access_token: The access token for API calls.
        refresh_token: Token used to get new access tokens.
        token_type: Usually "Bearer".
        expires_at: When the access token expires.
        scopes: Scopes granted by this token.
        id_token: OpenID Connect ID token if available.
    """

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_at: datetime | None
    scopes: tuple[str, ...] = field(default_factory=tuple)
    id_token: str | None = None

    def is_expired_at(self, now: datetime) -> bool:
        """Check if the access token is expired at a reference instant.

        Args:
            now: Reference datetime to evaluate the 5-minute expiry buffer against.

        Returns:
            bool: True if expires_at is set and now >= (expires_at - 5 minutes).
        """
        if self.expires_at is None:
            return False
        return now >= (self.expires_at - timedelta(minutes=5))

    @property
    def is_expired(self) -> bool:
        """Check if the access token is expired.

        Returns:
            bool: True if expired or will expire within 5 minutes.
        """
        return self.is_expired_at(datetime.now(UTC))

    def needs_refresh_at(self, now: datetime) -> bool:
        """Check if the token should be refreshed soon at a reference instant.

        Args:
            now: Reference datetime to evaluate the 10-minute refresh buffer against.

        Returns:
            bool: True if expires_at is set and now >= (expires_at - 10 minutes).
        """
        if self.expires_at is None:
            return False
        return now >= (self.expires_at - timedelta(minutes=10))

    @property
    def needs_refresh(self) -> bool:
        """Check if the token should be refreshed soon.

        Returns:
            bool: True if token will expire within 10 minutes.
        """
        return self.needs_refresh_at(datetime.now(UTC))

    def to_dict(self) -> dict[str, str | list[str] | None]:
        """Convert token to dictionary for storage.

        Returns:
            dict[str, str | list[str] | None]: Dictionary representation.
        """
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "scopes": list(self.scopes),
            "id_token": self.id_token,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str | list[str] | None]) -> OAuthToken:
        """Create token from dictionary.

        Args:
            data: Dictionary with token data.

        Returns:
            OAuthToken: OAuthToken instance.
        """
        expires_at = None
        expires_at_raw = data.get("expires_at")
        if isinstance(expires_at_raw, str) and expires_at_raw:
            expires_at = datetime.fromisoformat(expires_at_raw)

        access_token_raw = data.get("access_token", "")
        access_token = access_token_raw if isinstance(access_token_raw, str) else ""

        refresh_raw = data.get("refresh_token")
        refresh_token = refresh_raw if isinstance(refresh_raw, str) else None

        token_type_raw = data.get("token_type", "Bearer")
        token_type = token_type_raw if isinstance(token_type_raw, str) else "Bearer"

        scopes_raw = data.get("scopes", [])
        scopes_list: list[str] = scopes_raw if isinstance(scopes_raw, list) else []

        id_token_raw = data.get("id_token")
        id_token = id_token_raw if isinstance(id_token_raw, str) else None

        _logger.debug(
            "oauth_token_deserialized",
            has_refresh=bool(refresh_token),
            has_expiry=expires_at is not None,
        )
        return cls(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type,
            expires_at=expires_at,
            scopes=tuple(scopes_list),
            id_token=id_token,
        )


@dataclass
class OAuthState:
    """State for tracking an OAuth authorization flow.

    Attributes:
        state: Random state parameter for CSRF protection.
        code_verifier: PKCE code verifier, or None if not using PKCE.
        redirect_uri: Redirect URI used for this authorization flow.
        created_at: When the authorization flow was initiated.
        provider: The OAuth provider for this flow.
        config: OAuth configuration for this flow.
    """

    state: str
    code_verifier: str | None
    redirect_uri: str
    created_at: datetime
    provider: OAuthProvider
    config: OAuthConfig

    def is_expired_at(self, now: datetime) -> bool:
        """Check if this state has expired at a reference instant.

        Args:
            now: Reference datetime to evaluate the 10-minute state timeout against.

        Returns:
            bool: True if now >= (created_at + 10 minutes).
        """
        return now >= (self.created_at + timedelta(minutes=10))

    @property
    def is_expired(self) -> bool:
        """Check if this state has expired (10 minute timeout).

        Returns:
            bool: True if the state is older than 10 minutes.
        """
        return self.is_expired_at(datetime.now(UTC))


OAUTH_CONFIGS: dict[OAuthProvider, OAuthConfig] = {
    OAuthProvider.GOOGLE: OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id=os.environ.get("GOOGLE_OAUTH_CLIENT_ID", ""),
        client_secret=os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET"),
        authorization_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url=_GOOGLE_OAUTH_ENDPOINT,
        scopes=(
            "https://www.googleapis.com/auth/generative-language.retriever",
            "https://www.googleapis.com/auth/cloud-platform",
        ),
        use_pkce=True,
        revoke_url="https://oauth2.googleapis.com/revoke",
    ),
    OAuthProvider.ANTHROPIC: OAuthConfig(
        provider=OAuthProvider.ANTHROPIC,
        client_id=os.environ.get("ANTHROPIC_OAUTH_CLIENT_ID", ""),
        client_secret=os.environ.get("ANTHROPIC_OAUTH_CLIENT_SECRET"),
        authorization_url=_ANTHROPIC_OAUTH_AUTHORIZE_URL,
        token_url=_ANTHROPIC_OAUTH_EXCHANGE_URL,
        scopes=(
            "user:inference",
            "user:profile",
        ),
        use_pkce=True,
        revoke_url=None,
    ),
    OAuthProvider.HUGGINGFACE: OAuthConfig(
        provider=OAuthProvider.HUGGINGFACE,
        client_id=os.environ.get("HUGGINGFACE_OAUTH_CLIENT_ID", ""),
        client_secret=os.environ.get("HUGGINGFACE_OAUTH_CLIENT_SECRET"),
        authorization_url=_HUGGINGFACE_OAUTH_AUTHORIZE_URL,
        token_url=_HUGGINGFACE_OAUTH_EXCHANGE_URL,
        scopes=(
            "openid",
            "profile",
            "inference-api",
        ),
        use_pkce=True,
        revoke_url=None,
    ),
}


def generate_pkce_pair() -> tuple[str, str]:
    """Generate a PKCE code verifier and its S256 code challenge.

    This is the public entry point used by callers that need to drive the
    PKCE extension (RFC 7636) outside of :class:`OAuthManager`, for example
    when building an authorization URL from a test harness.

    Returns:
        tuple[str, str]: ``(code_verifier, code_challenge)``.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return code_verifier, code_challenge


def verify_pkce_pair(code_verifier: str, code_challenge: str) -> bool:
    """Check that ``code_verifier`` hashes (S256) to ``code_challenge``.

    Args:
        code_verifier: The PKCE code verifier.
        code_challenge: The PKCE code challenge to verify against.

    Returns:
        bool: True if the verifier matches the challenge.
    """
    digest = hashlib.sha256(code_verifier.encode()).digest()
    recomputed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return secrets.compare_digest(recomputed, code_challenge)


class _OAuthCallbackTCPServer(socketserver.TCPServer):
    """TCPServer that carries per-instance OAuth callback state.

    The callback handler stores the received authorization code, state, and
    error string on the server instance so concurrent OAuth flows running
    different ``_OAuthCallbackTCPServer`` instances cannot stomp each
    other's results via shared class state.

    Attributes:
        callback_code: Authorization code received from the OAuth provider.
        callback_state: State parameter echoed back by the provider.
        callback_error: Error string if authorization failed.
        callback_event: Event signalled once a callback has been recorded.
        expected_state: State value the handler should accept (CSRF check).
    """

    callback_code: str | None = None
    callback_state: str | None = None
    callback_error: str | None = None
    callback_event: threading.Event | None = None
    expected_state: str | None = None


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for OAuth callbacks.

    Reads CSRF/state context from the ``_OAuthCallbackTCPServer`` instance that owns the handler so concurrent OAuth flows on different
    ports do not share class-level state.
    """

    def do_GET(self) -> None:
        """Handle GET request from OAuth redirect."""
        _logger.debug("oauth_callback_received")
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        server = cast("_OAuthCallbackTCPServer", self.server)

        if "error" in params:
            server.callback_error = params["error"][0]
            status = 400
            message = f"Authorization failed: {params['error'][0]}. You can close this window."
        elif "code" in params and "state" in params:
            received_state = params["state"][0]
            expected = server.expected_state
            if expected is not None and not secrets.compare_digest(received_state, expected):
                server.callback_error = "state_mismatch"
                status = 400
                message = "State parameter mismatch. Possible CSRF attempt."
            else:
                server.callback_code = params["code"][0]
                server.callback_state = received_state
                status = 200
                message = "Authorization successful! You can close this window."
        else:
            status = 400
            message = "Invalid callback parameters."

        event = server.callback_event

        self._send_response(status, message)

        if event is not None:
            event.set()

    def _send_response(self, status: int, message: str) -> None:
        """Send an HTML response.

        Args:
            status: HTTP status code.
            message: Message to display.
        """
        self.send_response(status)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack OAuth</title>
    <style>
        body {{ font-family: system-ui, sans-serif; text-align: center; padding: 50px; }}
        h1 {{ color: {"#22c55e" if status == _HTTP_OK else "#ef4444"}; }}
    </style>
</head>
<body>
    <h1>{"Success" if status == _HTTP_OK else "Error"}</h1>
    <p>{message}</p>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        """Suppress default HTTP request logging.

        Args:
            code: HTTP status code (unused).
            size: Response size (unused).
        """
        del self, code, size


class OAuthCallbackServer:
    """Local HTTP server for receiving OAuth callbacks.

    Runs in a background thread and waits for the OAuth redirect.
    """

    def __init__(
        self,
        port: int = 8080,
        timeout: float = 300.0,
        expected_state: str | None = None,
    ) -> None:
        """Initialize the OAuthCallbackServer with the given port and timeout.

        Args:
            port: Port to listen on for OAuth callbacks.
            timeout: Timeout in seconds to wait for the callback.
            expected_state: Optional state value for CSRF validation.
        """
        self._port = port
        self._timeout = timeout
        self._expected_state = expected_state
        self._server: _OAuthCallbackTCPServer | None = None
        self._thread: threading.Thread | None = None
        self._event = threading.Event()
        _logger.debug(
            "oauth_callback_server_initialized",
            port=port,
            timeout_seconds=timeout,
            has_expected_state=bool(expected_state),
        )

    def start(self) -> None:
        """Start the callback server in a background thread.

        Raises:
            OAuthCallbackError: If the local bind socket cannot be opened.
        """
        socketserver.TCPServer.allow_reuse_address = True
        try:
            self._server = _OAuthCallbackTCPServer(
                ("127.0.0.1", self._port),
                OAuthCallbackHandler,
            )
        except OSError as exc:
            _logger.warning("oauth_callback_server_bind_failed", port=self._port, error=str(exc))
            msg = f"Failed to bind OAuth callback server on port {self._port}: {exc}"
            raise OAuthCallbackError(msg) from exc

        server = self._server
        server.callback_code = None
        server.callback_state = None
        server.callback_error = None
        server.callback_event = self._event
        server.expected_state = self._expected_state

        def serve() -> None:
            """Handle a single OAuth callback HTTP request on the background thread."""
            try:
                server.handle_request()
            except OSError:
                _logger.exception("oauth_callback_server_serve_error")

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        _logger.info("oauth_callback_server_started", port=self._port)

    def wait_for_callback(self) -> tuple[str, str]:
        """Wait for OAuth callback and return code and state.

        Returns:
            tuple[str, str]: Tuple of (code, state) from callback.

        Raises:
            OAuthCallbackError: If timeout or a non-denial error occurs.
            OAuthAuthorizationError: If the user denied authorization.
        """
        if not self._event.wait(timeout=self._timeout):
            _logger.warning("oauth_callback_wait_timeout", timeout_seconds=self._timeout)
            msg = "Timeout waiting for OAuth callback"
            raise OAuthCallbackError(msg)

        server = self._server
        if server is None:
            _logger.warning("oauth_callback_server_not_running")
            msg = "Callback server is not running"
            raise OAuthCallbackError(msg)

        if server.callback_error:
            error_msg = server.callback_error
            if "denied" in error_msg.lower() or "access_denied" in error_msg.lower():
                _logger.warning("oauth_callback_authorization_denied", error_code=error_msg)
                msg = f"Authorization denied: {error_msg}"
                raise OAuthAuthorizationError(msg)
            _logger.warning("oauth_callback_error_received", error_code=error_msg)
            msg = f"OAuth error: {error_msg}"
            raise OAuthCallbackError(msg)

        code = server.callback_code
        state = server.callback_state

        if not code or not state:
            _logger.warning("oauth_callback_invalid_params", has_code=bool(code), has_state=bool(state))
            msg = "Invalid callback: missing code or state"
            raise OAuthCallbackError(msg)

        return code, state

    def stop(self) -> None:
        """Stop the callback server and release the bound socket.

        The server thread uses ``handle_request`` (single-shot) rather than ``serve_forever``; therefore ``shutdown`` is not called here —
        doing so would block on ``__is_shut_down`` which is only set by ``serve_forever``. We close the socket and wake any blocking
        ``handle_request`` call via ``server_close``.
        """
        server = self._server
        if server is not None:
            server.callback_event = None
            server.expected_state = None
            try:
                server.server_close()
            except OSError:
                _logger.exception("oauth_callback_server_close_error")
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None
        _logger.info("oauth_callback_server_stopped")


class OAuthManager:
    """Manages OAuth 2.0 flows for Intellicrack providers.

    Handles authorization code flow with local callback server,
    token storage via CredentialStore, and automatic token refresh.

    Attributes:
        DEFAULT_CALLBACK_PORT: Default port for local callback server.
    """

    DEFAULT_CALLBACK_PORT: ClassVar[int] = 8080

    def __init__(
        self,
        credential_store: CredentialStore | None = None,
        callback_port: int = DEFAULT_CALLBACK_PORT,
    ) -> None:
        """Initialize the OAuthManager with credential storage and callback configuration.

        Args:
            credential_store: Store for persisting OAuth tokens. If None, tokens are not persisted.
            callback_port: Port for the local OAuth callback server.
        """
        self._credential_store = credential_store
        self._callback_port = callback_port
        self._pending_states: dict[str, OAuthState] = {}
        self._lock = asyncio.Lock()
        self._token_cache_lock = asyncio.Lock()
        self._token_cache: dict[OAuthProvider, OAuthToken] = {}
        self._http_client: httpx.AsyncClient | None = None
        _logger.debug(
            "oauth_manager_initialized",
            callback_port=callback_port,
            has_credential_store=credential_store is not None,
        )

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client.

        Returns:
            httpx.AsyncClient: Shared HTTP client for OAuth token requests.
        """
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
        return self._http_client

    async def close(self) -> None:
        """Close resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    @staticmethod
    def _generate_state() -> str:
        """Generate a cryptographically secure state parameter.

        Returns:
            str: Random URL-safe state string.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def _generate_pkce_pair() -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            tuple[str, str]: Tuple of (code_verifier, code_challenge).
        """
        return generate_pkce_pair()

    @staticmethod
    def _verify_pkce_pair(code_verifier: str, code_challenge: str) -> bool:
        """Verify that a PKCE code_verifier matches the given code_challenge.

        Uses the S256 method specified in RFC 7636.

        Args:
            code_verifier: The PKCE code verifier.
            code_challenge: The PKCE code challenge to verify against.

        Returns:
            bool: True if the verifier hashes to the challenge.
        """
        return verify_pkce_pair(code_verifier, code_challenge)

    def build_authorization_url(self, config: OAuthConfig) -> tuple[str, OAuthState]:
        """Build authorization URL for OAuth flow.

        Args:
            config: OAuth configuration.

        Returns:
            tuple[str, OAuthState]: Tuple of (authorization_url, state object).

        Raises:
            OAuthConfigurationError: If configuration is invalid.
        """
        if not config.client_id:
            _logger.warning("oauth_authorization_url_invalid_config", provider_name=config.provider.value, reason="missing_client_id")
            msg = "client_id is required"
            raise OAuthConfigurationError(msg)

        state = self._generate_state()
        code_verifier: str | None = None
        code_challenge: str | None = None

        if config.use_pkce:
            code_verifier, code_challenge = self._generate_pkce_pair()

        params: dict[str, str] = {
            "client_id": config.client_id,
            "response_type": "code",
            "redirect_uri": config.redirect_uri,
            "scope": " ".join(config.scopes),
            "state": state,
            "access_type": "offline",
            "prompt": "consent",
        }

        if config.use_pkce and code_challenge:
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        auth_url = f"{config.authorization_url}?{urllib.parse.urlencode(params)}"

        oauth_state = OAuthState(
            state=state,
            code_verifier=code_verifier,
            redirect_uri=config.redirect_uri,
            created_at=datetime.now(UTC),
            provider=config.provider,
            config=config,
        )

        return auth_url, oauth_state

    async def start_authorization_flow(
        self,
        config: OAuthConfig,
        *,
        open_browser: bool = True,
    ) -> tuple[str, OAuthState]:
        """Start an OAuth authorization code flow.

        Generates authorization URL and optionally opens browser.

        Args:
            config: OAuth configuration.
            open_browser: Whether to open the browser automatically.

        Returns:
            tuple[str, OAuthState]: The authorization URL and its associated state object.
        """
        auth_url, oauth_state = self.build_authorization_url(config)

        async with self._lock:
            self._pending_states[oauth_state.state] = oauth_state

        _logger.info("oauth_flow_started", provider=config.provider.value)

        if open_browser:
            _logger.info("oauth_browser_opening", provider=config.provider.value, auth_url=auth_url)
            webbrowser.open(auth_url)

        return auth_url, oauth_state

    async def handle_callback(
        self,
        code: str,
        state: str,
    ) -> OAuthToken:
        """Handle the OAuth callback with authorization code.

        Exchanges code for tokens and stores them. Validates the CSRF
        state parameter and, when PKCE is enabled, ensures the code_verifier
        bound to the pending state is present before exchanging the code.

        Args:
            code: Authorization code from callback.
            state: State parameter for validation.

        Returns:
            OAuthToken: The obtained OAuth token.

        Raises:
            OAuthCallbackError: If state is invalid, expired, or PKCE
                verifier is missing when required by the flow.
        """
        async with self._lock:
            oauth_state = self._pending_states.pop(state, None)

        if oauth_state is None:
            _logger.warning("oauth_callback_unknown_state")
            msg = f"Unknown state parameter: {state}"
            raise OAuthCallbackError(msg)

        if oauth_state.is_expired:
            _logger.warning("oauth_callback_state_expired", provider_name=oauth_state.provider.value)
            msg = "Authorization flow expired"
            raise OAuthCallbackError(msg)

        if oauth_state.config.use_pkce and not oauth_state.code_verifier:
            _logger.warning("oauth_callback_pkce_verifier_missing", provider_name=oauth_state.provider.value)
            msg = "PKCE flow missing code_verifier"
            raise OAuthCallbackError(msg)

        token = await self._exchange_code_for_token(
            oauth_state.config,
            code,
            oauth_state.code_verifier,
        )

        async with self._token_cache_lock:
            self._token_cache[oauth_state.provider] = token

        await self._store_token(oauth_state.provider, token)
        _logger.info("oauth_flow_completed", provider=oauth_state.provider.value)

        return token

    @staticmethod
    async def _post_token_exchange(
        *,
        client: httpx.AsyncClient,
        config: OAuthConfig,
        data: dict[str, str],
    ) -> OAuthToken:
        """POST the authorization-code exchange request and build the token.

        Propagates ``httpx.HTTPStatusError`` from ``raise_for_status`` when
        the provider returns a non-2xx response, ``httpx.RequestError`` when
        the transport fails, and ``OSError`` / ``ConnectionError`` /
        ``TimeoutError`` from the underlying socket layer.

        Args:
            client: Open ``httpx.AsyncClient`` used for the POST.
            config: OAuth configuration providing the token endpoint and
                provider tag for logging.
            data: ``application/x-www-form-urlencoded`` form payload.

        Returns:
            OAuthToken: The parsed token returned by the provider.
        """
        _logger.debug("oauth_code_exchange_request", token_url=config.token_url, provider=config.provider.value)
        response = await client.post(
            config.token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        token_data: dict[str, Any] = response.json()

        expires_at: datetime | None = None
        if "expires_in" in token_data:
            expires_at = datetime.now(UTC) + timedelta(seconds=int(token_data["expires_in"]))

        token = OAuthToken(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            token_type=token_data.get("token_type", "Bearer"),
            expires_at=expires_at,
            scopes=tuple(str(token_data.get("scope", "")).split()),
            id_token=token_data.get("id_token"),
        )
        _logger.debug(
            "oauth_code_exchange_success",
            has_refresh_token=token.refresh_token is not None,
        )
        return token

    async def _exchange_code_for_token(
        self,
        config: OAuthConfig,
        code: str,
        code_verifier: str | None,
    ) -> OAuthToken:
        """Exchange authorization code for tokens.

        Args:
            config: OAuth configuration.
            code: Authorization code.
            code_verifier: PKCE code verifier if used.

        Returns:
            OAuthToken: OAuthToken with access and refresh tokens.

        Raises:
            OAuthTokenError: If token exchange fails.
        """
        data: dict[str, str] = {
            "client_id": config.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirect_uri,
        }

        if config.client_secret:
            data["client_secret"] = config.client_secret

        if code_verifier:
            data["code_verifier"] = code_verifier

        client = await self._get_http_client()

        try:
            token = await OAuthManager._post_token_exchange(client=client, config=config, data=data)
        except httpx.HTTPStatusError as e:
            _logger.warning("oauth_code_exchange_http_error", status_code=e.response.status_code, error=str(e))
            error_body = e.response.text
            msg = f"Token exchange failed: {e.response.status_code} - {error_body}"
            raise OAuthTokenError(msg) from e
        except (OSError, ConnectionError, TimeoutError, httpx.RequestError) as e:
            _logger.warning("oauth_code_exchange_failed", error=str(e))
            msg = f"Token exchange failed: {e}"
            raise OAuthTokenError(msg) from e
        else:
            return token

    async def _store_token(self, provider: OAuthProvider, token: OAuthToken) -> None:
        """Store OAuth token in credential store.

        Args:
            provider: OAuth provider.
            token: Token to store.
        """
        if self._credential_store is None:
            _logger.warning("oauth_token_store_unavailable", reason="no_credential_store")
            return

        if not self._credential_store.keyring_available:
            _logger.warning("oauth_token_store_unavailable", reason="keyring_unavailable")
            return

        try:
            creds = ProviderCredentials(
                api_key=json.dumps(token.to_dict()),
            )

            provider_name = _oauth_provider_to_name(provider)

            await self._credential_store.set(
                provider_name,
                creds,
                key_name=f"oauth_{provider.value}",
                source=CredentialSource.OAUTH,
            )
            _logger.debug("oauth_token_store_success", provider=provider.value)
            _logger.info("oauth_token_stored", provider=provider.value)
        except _KeyringError as exc:
            _logger.warning(
                "oauth_token_store_failed",
                provider=provider.value,
                error=str(exc),
                reason="keyring_error",
            )
        except (OSError, KeyError, ValueError) as exc:
            _logger.warning("oauth_token_store_failed", provider=provider.value, error=str(exc))

    async def _load_token_from_store(self, provider: OAuthProvider) -> OAuthToken | None:
        """Fetch and deserialise a stored OAuth token.

        Assumes ``self._credential_store`` is not ``None`` (the caller
        verifies this). Propagates ``_KeyringError`` from the credential
        store backend, ``OSError`` when the underlying store cannot be read,
        ``KeyError`` and ``ValueError`` from token deserialisation when the
        payload is malformed, and ``json.JSONDecodeError`` when the stored
        blob is not valid JSON.

        Args:
            provider: OAuth provider whose token should be loaded.

        Returns:
            OAuthToken | None: The cached token, or ``None`` when no
            credentials are persisted for ``provider``.

        Raises:
            RuntimeError: If the credential store is unavailable.
        """
        if self._credential_store is None:
            _logger.error(
                "oauth_token_load_credential_store_unavailable",
                provider=provider.value,
            )
            msg = "credential store is unavailable"
            raise RuntimeError(msg)
        provider_name = _oauth_provider_to_name(provider)

        creds = await self._credential_store.get(provider_name)
        if creds is None or not creds.api_key:
            return None

        token_data = json.loads(creds.api_key)
        token = OAuthToken.from_dict(token_data)
        async with self._token_cache_lock:
            self._token_cache[provider] = token
        _logger.debug("oauth_token_load_success", provider=provider.value)
        return token

    async def _load_token(self, provider: OAuthProvider) -> OAuthToken | None:
        """Load OAuth token from credential store.

        Args:
            provider: OAuth provider.

        Returns:
            OAuthToken | None: OAuthToken or None if not found.
        """
        async with self._token_cache_lock:
            cached = self._token_cache.get(provider)
        if cached is not None:
            return cached

        if self._credential_store is None:
            return None

        try:
            return await self._load_token_from_store(provider)
        except _KeyringError as exc:
            _logger.warning(
                "oauth_token_load_failed",
                provider=provider.value,
                error=str(exc),
                reason="keyring_error",
            )
            return None
        except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
            _logger.warning("oauth_token_load_failed", provider=provider.value, error=str(exc))
            return None

    async def get_token(
        self,
        provider: OAuthProvider,
        config: OAuthConfig | None = None,
        *,
        auto_refresh: bool = True,
    ) -> OAuthToken | None:
        """Get a valid OAuth token for a provider.

        Uses the 10-minute ``needs_refresh`` buffer to refresh tokens
        proactively before they actually expire so callers never observe a
        token within the refresh window unless the refresh itself failed.

        Args:
            provider: The OAuth provider.
            config: OAuth config for refresh (uses default if None).
            auto_refresh: Whether to refresh expired tokens.

        Returns:
            OAuthToken | None: Valid OAuthToken or None if not available.
        """
        _logger.debug("oauth_get_token_started", provider=provider.value, auto_refresh=auto_refresh)
        token = await self._load_token(provider)
        if token is None:
            _logger.debug("oauth_get_token_no_token", provider=provider.value)
            return None

        effective_config = config or OAUTH_CONFIGS.get(provider)
        if effective_config and token.needs_refresh and auto_refresh and token.refresh_token:
            try:
                token = await self.refresh_token(provider, effective_config)
            except OAuthTokenRefreshError:
                _logger.exception("token_refresh_auth_failed", provider=provider.value)
                return None
            except OAuthTokenError:
                _logger.exception("token_refresh_failed", provider=provider.value)
                return None if token.is_expired else token

        return None if token.is_expired else token

    async def _post_token_refresh(
        self,
        *,
        client: httpx.AsyncClient,
        config: OAuthConfig,
        provider: OAuthProvider,
        data: dict[str, str],
        current_token: OAuthToken,
    ) -> OAuthToken:
        """POST the refresh-token request and update the local cache.

        Propagates ``httpx.HTTPStatusError`` from ``raise_for_status`` when
        the provider returns a non-2xx response, ``httpx.RequestError`` when
        the transport fails, and ``OSError`` / ``ConnectionError`` /
        ``TimeoutError`` from the underlying socket layer.

        Args:
            client: Open ``httpx.AsyncClient`` used for the POST.
            config: OAuth configuration providing the token endpoint.
            provider: OAuth provider used for cache keying and log records.
            data: ``application/x-www-form-urlencoded`` form payload.
            current_token: The currently stored token. Its ``refresh_token``
                is reused when the provider does not return a new one and its
                ``scopes`` are preserved on the refreshed token.

        Returns:
            OAuthToken: The refreshed token that has been cached and
            persisted via :meth:`_store_token`.
        """
        _logger.debug("oauth_token_refresh_request", token_url=config.token_url, provider=provider.value)
        response = await client.post(
            config.token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        token_data: dict[str, Any] = response.json()

        expires_at: datetime | None = None
        if "expires_in" in token_data:
            expires_at = datetime.now(UTC) + timedelta(seconds=int(token_data["expires_in"]))

        new_token = OAuthToken(
            access_token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token", current_token.refresh_token),
            token_type=token_data.get("token_type", "Bearer"),
            expires_at=expires_at,
            scopes=current_token.scopes,
            id_token=token_data.get("id_token"),
        )

        async with self._token_cache_lock:
            self._token_cache[provider] = new_token

        await self._store_token(provider, new_token)
        _logger.info("oauth_token_refreshed", provider=provider.value)
        return new_token

    async def refresh_token(
        self,
        provider: OAuthProvider,
        config: OAuthConfig,
    ) -> OAuthToken:
        """Refresh an OAuth token.

        A 401 or 403 response from the token endpoint indicates the refresh
        token is no longer valid and is surfaced as an
        :class:`OAuthTokenRefreshError`. Other HTTP errors raise a generic
        :class:`OAuthTokenError` so callers can retry without dropping the
        existing refresh token.

        Args:
            provider: The OAuth provider.
            config: OAuth configuration.

        Returns:
            OAuthToken: The refreshed OAuthToken.

        Raises:
            OAuthTokenError: If refresh fails for a non-authentication reason.
            OAuthTokenRefreshError: If the refresh token is rejected (401/403).
        """
        _logger.info("oauth_refresh_token_started", provider=provider.value)
        current_token = await self._load_token(provider)
        if current_token is None or current_token.refresh_token is None:
            msg = "No refresh token available"
            raise OAuthTokenError(msg)

        data: dict[str, str] = {
            "client_id": config.client_id,
            "grant_type": "refresh_token",
            "refresh_token": current_token.refresh_token,
        }

        if config.client_secret:
            data["client_secret"] = config.client_secret

        client = await self._get_http_client()

        try:
            new_token = await self._post_token_refresh(
                client=client,
                config=config,
                provider=provider,
                data=data,
                current_token=current_token,
            )
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            _logger.warning(
                "oauth_token_refresh_http_error",
                status_code=status_code,
                error=str(e),
            )
            if status_code in {_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN}:
                msg = f"Refresh token rejected by provider ({status_code})"
                raise OAuthTokenRefreshError(msg) from e
            msg = f"Token refresh failed: HTTP {status_code}"
            raise OAuthTokenError(msg) from e
        except (OSError, ConnectionError, TimeoutError, httpx.RequestError) as e:
            _logger.warning("oauth_token_refresh_failed", error=str(e))
            msg = f"Token refresh failed: {e}"
            raise OAuthTokenError(msg) from e
        else:
            return new_token

    async def revoke_token(self, provider: OAuthProvider) -> bool:
        """Revoke and delete OAuth token.

        The returned bool reflects whether *both* the optional remote
        revocation call (when the provider exposes a ``revoke_url``) and the
        local keyring delete succeeded.  When no remote endpoint is
        configured the result reflects only the keyring delete.  The
        in-memory token cache is always cleared so subsequent ``get_token``
        calls do not return a stale token even if revocation reports false.

        Args:
            provider: The OAuth provider.

        Returns:
            bool: True if both the remote revocation (if any) and the
            keyring deletion succeeded.
        """
        _logger.info("oauth_revoke_token_started", provider=provider.value)
        token = await self._load_token(provider)
        if token is None:
            return False

        revoke_succeeded = True
        config = OAUTH_CONFIGS.get(provider)
        if config and config.revoke_url:
            revoke_succeeded = False
            client = await self._get_http_client()
            try:
                _logger.debug("oauth_token_revoke_request", revoke_url=config.revoke_url, provider=provider.value)
                revoke_response = await client.post(
                    config.revoke_url,
                    data={"token": token.access_token},
                )
                revoke_response.raise_for_status()
                revoke_succeeded = True
                _logger.info(
                    "oauth_token_revoked",
                    provider=provider.value,
                    status_code=revoke_response.status_code,
                )
            except httpx.HTTPStatusError as http_exc:
                _logger.warning(
                    "oauth_token_revocation_http_error",
                    status_code=http_exc.response.status_code,
                    error=str(http_exc),
                )
            except (OSError, ConnectionError, TimeoutError, httpx.RequestError) as e:
                _logger.warning("oauth_token_revocation_failed", error=str(e))

        async with self._token_cache_lock:
            self._token_cache.pop(provider, None)

        keyring_succeeded = True
        if self._credential_store:
            keyring_succeeded = False
            provider_name = _oauth_provider_to_name(provider)
            try:
                keyring_succeeded = await self._credential_store.delete(provider_name)
            except _KeyringError as exc:
                _logger.warning(
                    "oauth_token_delete_failed",
                    provider=provider.value,
                    error=str(exc),
                    reason="keyring_error",
                )
            except (OSError, KeyError, ValueError) as exc:
                _logger.warning("oauth_token_delete_failed", provider=provider.value, error=str(exc))

        combined_success = revoke_succeeded and keyring_succeeded
        _logger.info(
            "oauth_token_revoke_completed",
            provider=provider.value,
            revoke_succeeded=revoke_succeeded,
            keyring_succeeded=keyring_succeeded,
            combined_success=combined_success,
        )
        return combined_success

    async def to_provider_credentials(
        self,
        provider: OAuthProvider,
        config: OAuthConfig | None = None,
    ) -> ProviderCredentials | None:
        """Convert OAuth token to ProviderCredentials.

        Gets a valid token and creates ProviderCredentials with it.

        Args:
            provider: The OAuth provider.
            config: OAuth config for refresh.

        Returns:
            ProviderCredentials | None: ProviderCredentials with OAuth token, or None.
        """
        token = await self.get_token(provider, config, auto_refresh=True)
        if token is None:
            return None

        return ProviderCredentials(api_key=token.access_token)

    async def run_authorization_flow(
        self,
        config: OAuthConfig,
    ) -> OAuthToken:
        """Run a complete authorization code flow.

        Opens browser, waits for callback, and exchanges code for tokens.
        The local callback server is always shut down and its socket closed
        in the ``finally`` block so the bind port is released even if the
        user cancels or the callback times out.

        Args:
            config: OAuth configuration.

        Returns:
            OAuthToken: The obtained OAuthToken.
        """
        callback_config = config
        if config.redirect_uri == "http://localhost:8080/callback":
            callback_config = OAuthConfig(
                provider=config.provider,
                client_id=config.client_id,
                client_secret=config.client_secret,
                authorization_url=config.authorization_url,
                token_url=config.token_url,
                scopes=config.scopes,
                redirect_uri=f"http://localhost:{self._callback_port}/callback",
                use_pkce=config.use_pkce,
                revoke_url=config.revoke_url,
            )

        auth_url, oauth_state = await self.start_authorization_flow(
            callback_config,
            open_browser=False,
        )

        server = OAuthCallbackServer(
            port=self._callback_port,
            expected_state=oauth_state.state,
        )
        server.start()

        try:
            _logger.info("oauth_browser_opening", provider=callback_config.provider.value, auth_url=auth_url)
            webbrowser.open(auth_url)
            code, state = server.wait_for_callback()
            return await self.handle_callback(code, state)
        finally:
            server.stop()


_oauth_lock: threading.Lock = threading.Lock()


class _OAuthManagerHolder:
    """Module-level singleton holder for the shared OAuthManager."""

    instance: ClassVar[OAuthManager | None] = None


def get_oauth_manager() -> OAuthManager:
    """Get the global OAuth manager instance.

    Uses double-checked locking so concurrent callers construct exactly one
    :class:`OAuthManager`.

    Returns:
        OAuthManager: The singleton OAuthManager instance.
    """
    if _OAuthManagerHolder.instance is None:
        with _oauth_lock:
            if _OAuthManagerHolder.instance is None:
                _OAuthManagerHolder.instance = OAuthManager(
                    credential_store=get_credential_store(),
                )
    return _OAuthManagerHolder.instance


async def authorize_google(
    client_id: str,
    client_secret: str | None = None,
    scopes: tuple[str, ...] | None = None,
) -> ProviderCredentials:
    """Authorize with Google and return provider credentials.

    Args:
        client_id: Google OAuth client ID.
        client_secret: Client secret (optional for PKCE).
        scopes: OAuth scopes (uses defaults if None).

    Returns:
        ProviderCredentials: ProviderCredentials with OAuth access token.
    """
    base_config = OAUTH_CONFIGS[OAuthProvider.GOOGLE]

    config = OAuthConfig(
        provider=OAuthProvider.GOOGLE,
        client_id=client_id,
        client_secret=client_secret,
        authorization_url=base_config.authorization_url,
        token_url=base_config.token_url,
        scopes=scopes or base_config.scopes,
        use_pkce=base_config.use_pkce,
        revoke_url=base_config.revoke_url,
    )

    manager = get_oauth_manager()
    token = await manager.run_authorization_flow(config)

    return ProviderCredentials(api_key=token.access_token)
