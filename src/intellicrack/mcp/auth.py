# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OAuth for Model Context Protocol servers reached over HTTP.

Only HTTP servers authorize this way. A local server inherits its credentials
from the environment Intellicrack launches it with, and the specification says
plainly that a stdio server should not use OAuth, so nothing here applies to
one.

Two rules shape the storage layout. Tokens are keyed per server *and* per
issuer, so a token minted for one server can never be presented to another,
and a server that moves to a different authorization server cannot silently
reuse the credentials it held under the old one. Client registrations are
checked with the SDK's own :func:`credentials_match_issuer` before they are
handed back, which is the RFC 9207 mix-up defence.

Client identity is resolved in the order the specification prefers: a Client
ID Metadata Document when one is configured and the authorization server
supports it, then a pre-registered client id, and only then dynamic client
registration, which is deprecated and logged as such.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import webbrowser
from typing import TYPE_CHECKING, Final

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.auth.utils import create_client_info_from_metadata_url, credentials_match_issuer, is_valid_client_metadata_url
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl, ValidationError

from intellicrack.core.json_payload import is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.oauth import OAuthCallbackError, OAuthCallbackServer
from intellicrack.credentials.store import CredentialStoreError
from intellicrack.mcp.errors import McpAuthError
from intellicrack.mcp.secrets import MCP_SECRET_NAMESPACE


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from intellicrack.credentials.store import CredentialStore
    from intellicrack.mcp.config import HttpServerSpec


_logger = get_logger(__name__)


CLIENT_NAME: Final[str] = "Intellicrack"
"""Client name presented to an authorization server."""

CALLBACK_PORT: Final[int] = 8724
"""Loopback port the authorization redirect comes back on."""

CALLBACK_TIMEOUT_S: Final[float] = 300.0
"""How long an interactive sign-in may take before it is abandoned."""

DEFAULT_SCOPE: Final[str] = "openid profile"
"""Scope requested when the server advertises no required scope."""

_ISSUER_DIGEST_BYTES: Final[int] = 8

_PUBLIC_CLIENT_AUTH: Final[str] = "none"
"""Token-endpoint authentication method for a public native client.

Intellicrack runs on the operator's machine and can hold no client secret, so
it authenticates the token endpoint with PKCE alone.
"""

_URL_PARTS: Final[int] = 2
"""Parts a URL splits into around its scheme separator."""

_TOKENS_SUFFIX: Final[str] = "tokens"
_CLIENT_SUFFIX: Final[str] = "client"


def redirect_uri() -> str:
    """The loopback address an authorization response is returned to.

    Returns:
        str: The fixed loopback redirect URI.
    """
    return f"http://127.0.0.1:{CALLBACK_PORT}/callback"


def issuer_for(spec: HttpServerSpec) -> str:
    """Derive the issuer identifier a server's credentials are filed under.

    The endpoint's own origin is used, which is what the SDK falls back to
    when protected-resource metadata names no separate authorization server.

    Args:
        spec: The server's endpoint configuration.

    Returns:
        str: ``scheme://authority`` for the configured URL.
    """
    remainder = spec.url.split("://", maxsplit=1)
    if len(remainder) != _URL_PARTS:
        return spec.url
    scheme, rest = remainder
    authority = rest.split("/", maxsplit=1)[0]
    return f"{scheme.lower()}://{authority.lower()}"


def credential_key(server_id: str, issuer: str, suffix: str) -> str:
    """Build the credential-store key one OAuth artefact is held under.

    The issuer is folded into a short digest rather than written out, because
    the key is a keyring entry name and an issuer URL is neither a valid nor a
    readable one.

    Args:
        server_id: The server the artefact belongs to.
        issuer: The authorization server it was obtained from.
        suffix: Which artefact, ``tokens`` or ``client``.

    Returns:
        str: The credential-store key.
    """
    digest = hashlib.blake2b(issuer.encode("utf-8"), digest_size=_ISSUER_DIGEST_BYTES).hexdigest()
    return f"{MCP_SECRET_NAMESPACE}:oauth:{server_id}:{digest}:{suffix}"


def client_metadata(spec: HttpServerSpec, scope: str | None = None) -> OAuthClientMetadata:
    """Build the client metadata presented during registration or sign-in.

    Args:
        spec: The server's endpoint configuration.
        scope: Scope to request, or ``None`` for :data:`DEFAULT_SCOPE`.

    Returns:
        OAuthClientMetadata: Metadata describing Intellicrack as a native
        client using the loopback redirect.
    """
    del spec
    return OAuthClientMetadata(
        client_name=CLIENT_NAME,
        redirect_uris=[AnyUrl(redirect_uri())],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method=_PUBLIC_CLIENT_AUTH,
        application_type="native",
        scope=scope or DEFAULT_SCOPE,
    )


class KeyringTokenStorage(TokenStorage):
    """Holds one server's OAuth artefacts in the operating system keyring.

    Every read and write is scoped to ``(server_id, issuer)``. A stored
    client registration bound to a different issuer is refused rather than
    returned, so credentials obtained from one authorization server can never
    be replayed against another.
    """

    def __init__(self, store: CredentialStore, server_id: str, issuer: str) -> None:
        """Initialize the storage.

        Args:
            store: The credential store holding the artefacts.
            server_id: The server the artefacts belong to.
            issuer: The authorization server they were obtained from.
        """
        self._store = store
        self._server_id = server_id
        self._issuer = issuer
        self._metadata_url: str | None = None

    @property
    def issuer(self) -> str:
        """The authorization server these artefacts belong to.

        Returns:
            str: The issuer identifier.
        """
        return self._issuer

    def bind_metadata_url(self, metadata_url: str | None) -> None:
        """Record the configured CIMD URL for the issuer-binding check.

        A URL-based client id is portable across authorization servers, so it
        is exempt from the issuer check. The check needs to know which URL
        that is in order to recognise it.

        Args:
            metadata_url: The configured Client ID Metadata Document URL.
        """
        self._metadata_url = metadata_url

    async def _read(self, suffix: str) -> str | None:
        """Read one stored artefact.

        Args:
            suffix: Which artefact, ``tokens`` or ``client``.

        Returns:
            str | None: The stored JSON, or ``None`` when absent.

        Raises:
            McpAuthError: If the keyring is unusable.
        """
        key = credential_key(self._server_id, self._issuer, suffix)
        try:
            credentials = await self._store.get(key)
        except CredentialStoreError as exc:
            message = f"cannot read OAuth {suffix} for MCP server '{self._server_id}': {exc}"
            raise McpAuthError(message) from exc
        return credentials.api_key if credentials is not None and credentials.api_key else None

    async def _write(self, suffix: str, payload: str) -> None:
        """Store one artefact.

        Args:
            suffix: Which artefact, ``tokens`` or ``client``.
            payload: The JSON to store.

        Raises:
            McpAuthError: If the keyring is unusable, so nothing was stored.
        """
        key = credential_key(self._server_id, self._issuer, suffix)
        try:
            await self._store.set(key, ProviderCredentials(api_key=payload), key_name=f"MCP OAuth {suffix} for {self._server_id}")
        except CredentialStoreError as exc:
            message = (
                f"cannot store OAuth {suffix} for MCP server '{self._server_id}': {exc}. Without a working keyring "
                f"Intellicrack will not hold this credential, and will not connect unauthenticated."
            )
            raise McpAuthError(message) from exc

    async def get_tokens(self) -> OAuthToken | None:
        """Read the stored access and refresh tokens.

        Returns:
            OAuthToken | None: The tokens, or ``None`` when none are stored
            or the stored value can no longer be parsed.

        Raises:
            McpAuthError: If the keyring is unusable.
        """
        payload = await self._read(_TOKENS_SUFFIX)
        if payload is None:
            return None
        try:
            return OAuthToken.model_validate_json(payload)
        except ValidationError as exc:
            _logger.warning("mcp_oauth_tokens_unreadable", server_id=self._server_id, error=str(exc))
            return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store access and refresh tokens.

        Args:
            tokens: The tokens to store.

        Raises:
            McpAuthError: If the keyring is unusable.
        """
        await self._write(_TOKENS_SUFFIX, tokens.model_dump_json(exclude_none=True))
        _logger.info("mcp_oauth_tokens_stored", server_id=self._server_id)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        """Read the stored client registration.

        Returns:
            OAuthClientInformationFull | None: The registration, or ``None``
            when none is stored, it cannot be parsed, or it is bound to a
            different authorization server than the one now in use.

        Raises:
            McpAuthError: If the keyring is unusable.
        """
        payload = await self._read(_CLIENT_SUFFIX)
        if payload is None:
            return None
        try:
            info = OAuthClientInformationFull.model_validate_json(payload)
        except ValidationError as exc:
            _logger.warning("mcp_oauth_client_unreadable", server_id=self._server_id, error=str(exc))
            return None
        if not credentials_match_issuer(info, self._issuer, self._metadata_url):
            _logger.warning(
                "mcp_oauth_client_issuer_mismatch",
                server_id=self._server_id,
                expected_issuer=self._issuer,
                stored_issuer=info.issuer,
            )
            return None
        return info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store a client registration, binding it to the current issuer.

        Args:
            client_info: The registration to store.

        Raises:
            McpAuthError: If the keyring is unusable.
        """
        bound = client_info.model_copy(update={"issuer": client_info.issuer or self._issuer})
        await self._write(_CLIENT_SUFFIX, bound.model_dump_json(exclude_none=True))
        _logger.info("mcp_oauth_client_stored", server_id=self._server_id, client_id=bound.client_id)

    async def clear(self) -> None:
        """Remove every artefact stored for this server and issuer.

        Raises:
            McpAuthError: If the keyring is unusable.
        """
        for suffix in (_TOKENS_SUFFIX, _CLIENT_SUFFIX):
            key = credential_key(self._server_id, self._issuer, suffix)
            try:
                _ = await self._store.delete(key)
            except CredentialStoreError as exc:
                message = f"cannot remove OAuth {suffix} for MCP server '{self._server_id}': {exc}"
                raise McpAuthError(message) from exc
        _logger.info("mcp_oauth_cleared", server_id=self._server_id, issuer=self._issuer)


async def resolve_client_identity(
    spec: HttpServerSpec,
    metadata_url: str | None,
    storage: KeyringTokenStorage | None = None,
) -> OAuthClientInformationFull:
    """Resolve how this client identifies itself to an authorization server.

    A registration already stored for this issuer wins, so a client that has
    registered once does not register again. Otherwise a Client ID Metadata
    Document is preferred: the URL itself is the client id, nothing has to be
    registered, and the same identity works against every authorization
    server. A pre-registered id comes next. Dynamic client registration is
    last and deprecated; it is left to the SDK, which performs it during the
    flow when neither of the first two is available.

    Args:
        spec: The server's endpoint configuration.
        metadata_url: The configured Client ID Metadata Document URL, or
            ``None``.
        storage: Keyring storage to consult for an existing registration, or
            ``None`` to skip that step.

    Returns:
        OAuthClientInformationFull: The resolved client identity.

    Raises:
        McpAuthError: If a CIMD URL is configured but is not a valid HTTPS
            URL with a path, and no pre-registered id is available either.
    """
    if storage is not None:
        storage.bind_metadata_url(metadata_url)
        stored = await storage.get_client_info()
        if stored is not None and stored.client_id:
            _logger.debug("mcp_oauth_identity_stored", client_id=stored.client_id)
            return stored

    if metadata_url is not None:
        if not is_valid_client_metadata_url(metadata_url):
            message = f"OAuth metadata URL {metadata_url!r} is not usable as a client id: it must be an HTTPS URL with a non-root path."
            raise McpAuthError(message)
        _logger.info("mcp_oauth_identity_cimd", metadata_url=metadata_url)
        return create_client_info_from_metadata_url(metadata_url, [AnyUrl(redirect_uri())])

    if spec.oauth_client_id:
        _logger.info("mcp_oauth_identity_preregistered", client_id=spec.oauth_client_id)
        return OAuthClientInformationFull(
            client_id=spec.oauth_client_id,
            token_endpoint_auth_method=_PUBLIC_CLIENT_AUTH,
            redirect_uris=[AnyUrl(redirect_uri())],
        )

    _logger.warning(
        "mcp_oauth_identity_dynamic_registration",
        url=issuer_for(spec),
        note="dynamic client registration is deprecated; configure oauthMetadataUrl or oauthClientId instead",
    )
    return OAuthClientInformationFull(client_id="", token_endpoint_auth_method=_PUBLIC_CLIENT_AUTH, redirect_uris=[AnyUrl(redirect_uri())])


async def open_authorization_page(url: str) -> None:
    """Send the operator to the authorization page in their browser.

    Launching a browser blocks for as long as the platform's handler takes
    to return, so it runs off the event loop.

    Args:
        url: The authorization URL the SDK built.
    """
    _logger.info("mcp_oauth_browser_opened", host=url.split("/", maxsplit=3)[2] if "//" in url else "")
    _ = await asyncio.to_thread(webbrowser.open, url)


async def await_authorization_callback() -> AuthorizationCodeResult:
    """Run the loopback server and wait for the authorization redirect.

    The wait is minutes long and blocking, so it runs on a worker thread. On
    the event loop it would freeze every other MCP server, every tool call and
    the whole GUI for the duration of the sign-in.

    Returns:
        AuthorizationCodeResult: The authorization code, the echoed state,
        and the RFC 9207 issuer when the authorization server supplied one.

    Raises:
        McpAuthError: If the redirect never arrived, or arrived as an error.
    """
    server = OAuthCallbackServer(port=CALLBACK_PORT, timeout=CALLBACK_TIMEOUT_S)
    server.start()
    try:
        code, state = await asyncio.to_thread(server.wait_for_callback)
        issuer = server.received_issuer
    except OAuthCallbackError as exc:
        message = f"OAuth sign-in did not complete: {exc}"
        raise McpAuthError(message) from exc
    finally:
        await asyncio.to_thread(server.stop)
    return AuthorizationCodeResult(code=code, state=state, iss=issuer)


def build_oauth_provider(
    spec: HttpServerSpec,
    storage: KeyringTokenStorage,
    *,
    redirect_handler: Callable[[str], Awaitable[None]] | None = None,
    callback_handler: Callable[[], Awaitable[AuthorizationCodeResult]] | None = None,
) -> OAuthClientProvider:
    """Build the ``httpx2`` auth handler that signs requests to one server.

    Args:
        spec: The server's endpoint configuration.
        storage: Keyring-backed storage for this server's artefacts.
        redirect_handler: Opens the authorization page, defaulting to the
            operator's browser.
        callback_handler: Waits for the redirect, defaulting to the loopback
            server.

    Returns:
        OAuthClientProvider: The handler to attach to the HTTP client.

    Raises:
        McpAuthError: If a configured CIMD URL is not usable as a client id.
    """
    metadata_url = spec.oauth_metadata_url
    if metadata_url is not None and not is_valid_client_metadata_url(metadata_url):
        message = f"OAuth metadata URL {metadata_url!r} must be an HTTPS URL with a non-root path"
        raise McpAuthError(message)
    storage.bind_metadata_url(metadata_url)
    return OAuthClientProvider(
        server_url=spec.url,
        client_metadata=client_metadata(spec),
        storage=storage,
        redirect_handler=redirect_handler if redirect_handler is not None else open_authorization_page,
        callback_handler=callback_handler if callback_handler is not None else await_authorization_callback,
        client_metadata_url=metadata_url,
    )


async def sign_out(store: CredentialStore, server_id: str, issuer: str | None = None) -> bool:
    """Remove a server's stored OAuth credentials.

    Args:
        store: The credential store holding them.
        server_id: The server to sign out of.
        issuer: The authorization server the credentials belong to. When
            ``None``, nothing is removed, because a token can only be found
            under the issuer it was filed against.

    Returns:
        bool: ``True`` when a credential was removed.

    Raises:
        McpAuthError: If the keyring is unusable.
    """
    if issuer is None:
        _logger.warning("mcp_oauth_sign_out_without_issuer", server_id=server_id)
        return False
    removed = False
    for suffix in (_TOKENS_SUFFIX, _CLIENT_SUFFIX):
        key = credential_key(server_id, issuer, suffix)
        try:
            removed = await store.delete(key) or removed
        except CredentialStoreError as exc:
            message = f"cannot sign out of MCP server '{server_id}': {exc}"
            raise McpAuthError(message) from exc
    _logger.info("mcp_oauth_signed_out", server_id=server_id, removed=removed)
    return removed


async def has_stored_credentials(store: CredentialStore, server_id: str, issuer: str) -> bool:
    """Report whether a server currently holds an access token.

    Args:
        store: The credential store to query.
        server_id: The server to check.
        issuer: The authorization server the token would be filed under.

    Returns:
        bool: ``True`` when a token is stored.

    Raises:
        McpAuthError: If the keyring is unusable, so the answer is unknown.
    """
    key = credential_key(server_id, issuer, _TOKENS_SUFFIX)
    try:
        credentials = await store.get(key)
    except CredentialStoreError as exc:
        message = f"cannot check OAuth state for MCP server '{server_id}': {exc}"
        raise McpAuthError(message) from exc
    if credentials is None or not credentials.api_key:
        return False
    try:
        decoded: object = json.loads(credentials.api_key)
    except json.JSONDecodeError:
        return False
    return is_json_object(decoded) and bool(decoded.get("access_token"))
