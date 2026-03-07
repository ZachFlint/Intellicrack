# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""OAuth 2.0 flow handling for Intellicrack providers.

This module handles OAuth 2.0 authorization flows for providers that support it,
including authorization code flow with PKCE, token refresh, and secure storage.
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
from typing import TYPE_CHECKING, Any, Final

import httpx

from ..core.logging import get_logger
from ..core.types import IntellicrackError, ProviderCredentials, ProviderName
from .store import CredentialSource, get_credential_store


if TYPE_CHECKING:
    from .store import CredentialStore

_logger = get_logger("credentials.oauth")

_GOOGLE_OAUTH_ENDPOINT: Final = "https://oauth2.googleapis.com/token"
_HTTP_OK: Final = 200


class OAuthError(IntellicrackError):
    """Base error for OAuth operations."""

    pass


class OAuthConfigurationError(OAuthError):
    """OAuth configuration is invalid or incomplete."""

    pass


class OAuthAuthorizationError(OAuthError):
    """Authorization failed or was denied."""

    pass


class OAuthTokenError(OAuthError):
    """Token operation failed (exchange, refresh, etc.)."""

    pass


class OAuthCallbackError(OAuthError):
    """Error during OAuth callback handling."""

    pass


class OAuthFlowType(Enum):
    """Supported OAuth 2.0 flow types."""

    AUTHORIZATION_CODE = "authorization_code"


class OAuthProvider(Enum):
    """Providers that support OAuth authentication."""

    GOOGLE = "google"


_OAUTH_TO_PROVIDER_NAME: dict[OAuthProvider, ProviderName] = {
    OAuthProvider.GOOGLE: ProviderName.GOOGLE,
}


def _oauth_provider_to_name(provider: OAuthProvider) -> ProviderName:
    """Map an OAuthProvider to the corresponding ProviderName.

    Args:
        provider: The OAuth provider enum value.

    Returns:
        The matching ProviderName.

    Raises:
        KeyError: If the provider has no mapping.
    """
    if provider not in _OAUTH_TO_PROVIDER_NAME:
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

    @property
    def is_expired(self) -> bool:
        """Check if the access token is expired.

        Returns:
            True if expired or will expire within 5 minutes.
        """
        if self.expires_at is None:
            return False
        buffer = timedelta(minutes=5)
        return datetime.now(UTC) >= (self.expires_at - buffer)

    @property
    def needs_refresh(self) -> bool:
        """Check if the token should be refreshed soon.

        Returns:
            True if token will expire within 10 minutes.
        """
        if self.expires_at is None:
            return False
        buffer = timedelta(minutes=10)
        return datetime.now(UTC) >= (self.expires_at - buffer)

    def to_dict(self) -> dict[str, Any]:
        """Convert token to dictionary for storage.

        Returns:
            Dictionary representation.
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
    def from_dict(cls, data: dict[str, Any]) -> OAuthToken:
        """Create token from dictionary.

        Args:
            data: Dictionary with token data.

        Returns:
            OAuthToken instance.
        """
        expires_at = None
        if data.get("expires_at"):
            expires_at = datetime.fromisoformat(data["expires_at"])

        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            token_type=data.get("token_type", "Bearer"),
            expires_at=expires_at,
            scopes=tuple(data.get("scopes", [])),
            id_token=data.get("id_token"),
        )


@dataclass
class OAuthState:
    """State for tracking an OAuth authorization flow.

    Attributes:
        state: Random state parameter for CSRF protection.
        code_verifier: PKCE code verifier (if using PKCE).
        redirect_uri: Redirect URI used for this flow.
        created_at: When the flow was initiated.
        provider: The OAuth provider.
        config: OAuth configuration.
    """

    state: str
    code_verifier: str | None
    redirect_uri: str
    created_at: datetime
    provider: OAuthProvider
    config: OAuthConfig

    @property
    def is_expired(self) -> bool:
        """Check if this state has expired (10 minute timeout).

        Returns:
            True if the state is older than 10 minutes.
        """
        timeout = timedelta(minutes=10)
        return datetime.now(UTC) >= (self.created_at + timeout)


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
}


class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for OAuth callbacks."""

    callback_code: str | None = None
    callback_state: str | None = None
    callback_error: str | None = None
    callback_event: threading.Event | None = None

    def do_GET(self) -> None:
        """Handle GET request from OAuth redirect."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "error" in params:
            OAuthCallbackHandler.callback_error = params["error"][0]
            self._send_response(
                400,
                f"Authorization failed: {params['error'][0]}. You can close this window.",
            )
        elif "code" in params and "state" in params:
            OAuthCallbackHandler.callback_code = params["code"][0]
            OAuthCallbackHandler.callback_state = params["state"][0]
            self._send_response(
                200,
                "Authorization successful! You can close this window.",
            )
        else:
            self._send_response(400, "Invalid callback parameters.")

        if OAuthCallbackHandler.callback_event:
            OAuthCallbackHandler.callback_event.set()

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

    def __init__(self, port: int = 8080, timeout: float = 300.0) -> None:
        """Initialize callback server.

        Args:
            port: Port to listen on.
            timeout: Timeout in seconds to wait for callback.
        """
        self._port = port
        self._timeout = timeout
        self._server: socketserver.TCPServer | None = None
        self._thread: threading.Thread | None = None
        self._event = threading.Event()

    def start(self) -> None:
        """Start the callback server in a background thread."""
        OAuthCallbackHandler.callback_code = None
        OAuthCallbackHandler.callback_state = None
        OAuthCallbackHandler.callback_error = None
        OAuthCallbackHandler.callback_event = self._event

        socketserver.TCPServer.allow_reuse_address = True
        self._server = socketserver.TCPServer(("127.0.0.1", self._port), OAuthCallbackHandler)

        def serve() -> None:
            if self._server:
                self._server.handle_request()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        _logger.info("oauth_callback_server_started", extra={"port": self._port})

    def wait_for_callback(self) -> tuple[str, str]:
        """Wait for OAuth callback and return code and state.

        Returns:
            Tuple of (code, state) from callback.

        Raises:
            OAuthCallbackError: If timeout or a non-denial error occurs.
            OAuthAuthorizationError: If the user denied authorization.
        """
        if not self._event.wait(timeout=self._timeout):
            msg = "Timeout waiting for OAuth callback"
            raise OAuthCallbackError(msg)

        if OAuthCallbackHandler.callback_error:
            error_msg = OAuthCallbackHandler.callback_error
            if "denied" in error_msg.lower() or "access_denied" in error_msg.lower():
                msg = f"Authorization denied: {error_msg}"
                raise OAuthAuthorizationError(msg)
            msg = f"OAuth error: {error_msg}"
            raise OAuthCallbackError(msg)

        code = OAuthCallbackHandler.callback_code
        state = OAuthCallbackHandler.callback_state

        if not code or not state:
            msg = "Invalid callback: missing code or state"
            raise OAuthCallbackError(msg)

        return code, state

    def stop(self) -> None:
        """Stop the callback server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
        _logger.info("oauth_callback_server_stopped", extra={})


class OAuthManager:
    """Manages OAuth 2.0 flows for Intellicrack providers.

    Handles authorization code flow with local callback server,
    token storage via CredentialStore, and automatic token refresh.

    Attributes:
        DEFAULT_CALLBACK_PORT: Default port for local callback server.
    """

    DEFAULT_CALLBACK_PORT: Final[int] = 8080

    def __init__(
        self,
        credential_store: CredentialStore | None = None,
        callback_port: int = DEFAULT_CALLBACK_PORT,
    ) -> None:
        """Initialize the OAuth manager.

        Args:
            credential_store: Store for persisting tokens.
            callback_port: Port for local callback server.
        """
        self._credential_store = credential_store
        self._callback_port = callback_port
        self._pending_states: dict[str, OAuthState] = {}
        self._lock = asyncio.Lock()
        self._http_client: httpx.AsyncClient | None = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client.

        Returns:
            httpx.AsyncClient instance.
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
            Random URL-safe state string.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def _generate_pkce_pair() -> tuple[str, str]:
        """Generate PKCE code verifier and challenge.

        Returns:
            Tuple of (code_verifier, code_challenge).
        """
        code_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return code_verifier, code_challenge

    def build_authorization_url(self, config: OAuthConfig) -> tuple[str, OAuthState]:
        """Build authorization URL for OAuth flow.

        Args:
            config: OAuth configuration.

        Returns:
            Tuple of (authorization_url, state object).

        Raises:
            OAuthConfigurationError: If configuration is invalid.
        """
        if not config.client_id:
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
        open_browser: bool = True,
    ) -> str:
        """Start an OAuth authorization code flow.

        Generates authorization URL and optionally opens browser.

        Args:
            config: OAuth configuration.
            open_browser: Whether to open the browser automatically.

        Returns:
            The authorization URL for the user.
        """
        auth_url, oauth_state = self.build_authorization_url(config)

        async with self._lock:
            self._pending_states[oauth_state.state] = oauth_state

        _logger.info("oauth_flow_started", extra={"provider": config.provider.value})

        if open_browser:
            webbrowser.open(auth_url)

        return auth_url

    async def handle_callback(
        self,
        code: str,
        state: str,
    ) -> OAuthToken:
        """Handle the OAuth callback with authorization code.

        Exchanges code for tokens and stores them.

        Args:
            code: Authorization code from callback.
            state: State parameter for validation.

        Returns:
            The obtained OAuth token.

        Raises:
            OAuthCallbackError: If state is invalid or expired.
        """
        async with self._lock:
            oauth_state = self._pending_states.pop(state, None)

        if oauth_state is None:
            msg = f"Unknown state parameter: {state}"
            raise OAuthCallbackError(msg)

        if oauth_state.is_expired:
            msg = "Authorization flow expired"
            raise OAuthCallbackError(msg)

        token = await self._exchange_code_for_token(
            oauth_state.config,
            code,
            oauth_state.code_verifier,
        )

        await self._store_token(oauth_state.provider, token)
        _logger.info("oauth_flow_completed", extra={"provider": oauth_state.provider.value})

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
            OAuthToken with access and refresh tokens.

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
            response = await client.post(
                config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()

            expires_at: datetime | None = None
            if "expires_in" in token_data:
                expires_at = datetime.now(UTC) + timedelta(seconds=token_data["expires_in"])

            token = OAuthToken(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token"),
                token_type=token_data.get("token_type", "Bearer"),
                expires_at=expires_at,
                scopes=tuple(token_data.get("scope", "").split()),
                id_token=token_data.get("id_token"),
            )
            _logger.debug(
                "oauth_code_exchange_success",
                extra={"has_refresh_token": token.refresh_token is not None},
            )
        except httpx.HTTPStatusError as e:
            error_body = e.response.text
            msg = f"Token exchange failed: {e.response.status_code} - {error_body}"
            raise OAuthTokenError(msg) from e
        except Exception as e:
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
            _logger.warning("oauth_token_store_unavailable", extra={"reason": "no_credential_store"})
            return

        if not self._credential_store.keyring_available:
            _logger.warning("oauth_token_store_unavailable", extra={"reason": "keyring_unavailable"})
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
            _logger.debug("oauth_token_store_success", extra={"provider": provider.value})
            _logger.info("oauth_token_stored", extra={"provider": provider.value})
        except Exception:
            _logger.exception("oauth_token_store_failed")

    async def _load_token(self, provider: OAuthProvider) -> OAuthToken | None:
        """Load OAuth token from credential store.

        Args:
            provider: OAuth provider.

        Returns:
            OAuthToken or None if not found.
        """
        if self._credential_store is None:
            return None

        try:
            provider_name = _oauth_provider_to_name(provider)

            creds = await self._credential_store.get(provider_name)
            if creds is None or not creds.api_key:
                return None

            token_data = json.loads(creds.api_key)
            token = OAuthToken.from_dict(token_data)
            _logger.debug("oauth_token_load_success", extra={"provider": provider.value})
        except Exception:
            _logger.exception("oauth_token_load_failed")
            return None
        else:
            return token

    async def get_token(
        self,
        provider: OAuthProvider,
        config: OAuthConfig | None = None,
        auto_refresh: bool = True,
    ) -> OAuthToken | None:
        """Get a valid OAuth token for a provider.

        Args:
            provider: The OAuth provider.
            config: OAuth config for refresh (uses default if None).
            auto_refresh: Whether to refresh expired tokens.

        Returns:
            Valid OAuthToken or None if not available.
        """
        token = await self._load_token(provider)
        if token is None:
            return None

        if (effective_config := config or OAUTH_CONFIGS.get(provider)) and token.is_expired and auto_refresh and token.refresh_token:
            try:
                token = await self.refresh_token(provider, effective_config)
            except OAuthTokenError:
                return None

        return None if token.is_expired else token

    async def refresh_token(
        self,
        provider: OAuthProvider,
        config: OAuthConfig,
    ) -> OAuthToken:
        """Refresh an OAuth token.

        Args:
            provider: The OAuth provider.
            config: OAuth configuration.

        Returns:
            The refreshed OAuthToken.

        Raises:
            OAuthTokenError: If refresh fails.
        """
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
            response = await client.post(
                config.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            token_data = response.json()

            expires_at: datetime | None = None
            if "expires_in" in token_data:
                expires_at = datetime.now(UTC) + timedelta(seconds=token_data["expires_in"])

            new_token = OAuthToken(
                access_token=token_data["access_token"],
                refresh_token=token_data.get("refresh_token", current_token.refresh_token),
                token_type=token_data.get("token_type", "Bearer"),
                expires_at=expires_at,
                scopes=current_token.scopes,
                id_token=token_data.get("id_token"),
            )

            await self._store_token(provider, new_token)
            _logger.info("oauth_token_refreshed", extra={"provider": provider.value})
        except httpx.HTTPStatusError as e:
            msg = f"Token refresh failed: {e.response.status_code}"
            raise OAuthTokenError(msg) from e
        except Exception as e:
            msg = f"Token refresh failed: {e}"
            raise OAuthTokenError(msg) from e
        else:
            return new_token

    async def revoke_token(self, provider: OAuthProvider) -> bool:
        """Revoke and delete OAuth token.

        Args:
            provider: The OAuth provider.

        Returns:
            True if token was revoked/deleted.
        """
        token = await self._load_token(provider)
        if token is None:
            return False

        config = OAUTH_CONFIGS.get(provider)
        if config and config.revoke_url:
            client = await self._get_http_client()
            try:
                await client.post(
                    config.revoke_url,
                    data={"token": token.access_token},
                )
                _logger.info("oauth_token_revoked", extra={"provider": provider.value})
            except Exception as e:
                _logger.warning("oauth_token_revocation_failed", extra={"error": str(e)})

        if self._credential_store:
            provider_name = _oauth_provider_to_name(provider)
            try:
                await self._credential_store.delete(provider_name)
            except Exception:
                _logger.exception("oauth_token_delete_failed", extra={"provider": provider.value})

        return True

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
            ProviderCredentials with OAuth token, or None.
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

        Args:
            config: OAuth configuration.

        Returns:
            The obtained OAuthToken.
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

        server = OAuthCallbackServer(port=self._callback_port)
        server.start()

        try:
            await self.start_authorization_flow(callback_config, open_browser=True)
            code, state = server.wait_for_callback()
            return await self.handle_callback(code, state)
        finally:
            server.stop()


class _OAuthManagerHolder:
    instance: OAuthManager | None = None


_oauth_holder = _OAuthManagerHolder()


def get_oauth_manager() -> OAuthManager:
    """Get the global OAuth manager instance.

    Returns:
        The singleton OAuthManager instance.
    """
    if _oauth_holder.instance is None:
        _oauth_holder.instance = OAuthManager(credential_store=get_credential_store())
    return _oauth_holder.instance


async def authorize_google(
    client_id: str,
    client_secret: str | None = None,
    scopes: tuple[str, ...] | None = None,
) -> ProviderCredentials:
    """Convenience function to authorize with Google.

    Args:
        client_id: Google OAuth client ID.
        client_secret: Client secret (optional for PKCE).
        scopes: OAuth scopes (uses defaults if None).

    Returns:
        ProviderCredentials with OAuth access token.
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
