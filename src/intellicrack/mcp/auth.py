# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""OAuth for Model Context Protocol servers reached over HTTP.

Only HTTP servers authorize this way. A local server inherits its credentials from the environment Intellicrack launches it with, and the
specification says plainly that a stdio server should not use OAuth, so nothing here applies to one.

Storage is keyed per server *and* per resource origin, so a token minted for one server is never presented to another. The authorization
server a registration was obtained from is recorded on the registration itself (``client_info.issuer``, stamped by the SDK), and the SDK's
own :func:`credentials_match_issuer` check drops a registration, and the tokens issued with it, as soon as discovery names a different
authorization server. That is the RFC 9207 / SEP-2352 mix-up defence. The issuer is deliberately not part of the storage key: it is only
known after discovery, and keying by it would lose every registration whose authorization server lives on another host.

Tokens are stored with their absolute expiry and with the authorization server metadata they were obtained under, so after a restart an
expired access token is refreshed at the right token endpoint instead of being sent and answered with a full re-authorization.

Client identity is resolved in this order: a registration already stored for this server, then a configured pre-registered client id, then
a Client ID Metadata Document when one is configured and the authorization server supports it, and only then dynamic client registration,
which is deprecated and logged as such. The last two are decided by the SDK once it has the authorization server's metadata.

Scope is never invented. The SDK selects it the way the specification prescribes (the ``WWW-Authenticate`` challenge, then the protected
resource's ``scopes_supported``, then the authorization server's), and omits it when none of those names one.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, override
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.auth.utils import credentials_match_issuer, is_valid_client_metadata_url
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthMetadata, OAuthToken
from pydantic import AnyHttpUrl, AnyUrl, ConfigDict, TypeAdapter, ValidationError

from intellicrack.core.json_payload import is_json_object
from intellicrack.core.logging import get_logger
from intellicrack.core.types import ProviderCredentials
from intellicrack.credentials.oauth import OAuthAuthorizationError, OAuthCallbackError, OAuthCallbackServer
from intellicrack.credentials.store import CredentialStoreError
from intellicrack.mcp.errors import McpAuthError
from intellicrack.mcp.secrets import MCP_SECRET_NAMESPACE
from intellicrack.mcp.transport import is_web_url, open_web_url


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from intellicrack.credentials.store import CredentialStore
    from intellicrack.mcp.config import HttpServerSpec


_logger = get_logger(__name__)


CLIENT_NAME: Final[str] = "Intellicrack"
"""Client name presented to an authorization server."""

CALLBACK_PORT: Final[int] = 8724
"""Loopback port the authorization redirect prefers to come back on.

When another sign-in already holds it, the redirect uses a port the operating system assigns instead; RFC 8252 section 7.3 requires an
authorization server to accept any port on a loopback redirect URI.
"""

CALLBACK_PATH: Final[str] = "/callback"
"""Path of the loopback redirect URI."""

CALLBACK_TIMEOUT_S: Final[float] = 300.0
"""How long an interactive sign-in may take before it is abandoned."""

_ISSUER_DIGEST_BYTES: Final[int] = 8

_PUBLIC_CLIENT_AUTH: Final[str] = "none"
"""Token-endpoint authentication method for a public native client.

Intellicrack runs on the operator's machine and can hold no client secret, so it authenticates the token endpoint with PKCE alone.
"""

_URL_PARTS: Final[int] = 2
"""Parts a URL splits into around its scheme separator."""

_TOKENS_SUFFIX: Final[str] = "tokens"
_CLIENT_SUFFIX: Final[str] = "client"

_RECORD_GRANT: Final[str] = "token"
_RECORD_EXPIRES_AT: Final[str] = "expires_at"
_RECORD_AUTHORIZATION_SERVER: Final[str] = "authorization_server"

_ORIGIN_URL: Final[TypeAdapter[AnyHttpUrl]] = TypeAdapter(AnyHttpUrl, config=ConfigDict(url_preserve_empty_path=True))
"""Renders an origin exactly as the SDK renders an issuer: host lower-cased, default port dropped, no trailing slash added."""


def redirect_uri(port: int = CALLBACK_PORT) -> str:
    """The loopback address an authorization response is returned to.

    Args:
        port: The loopback port the callback server listens on.

    Returns:
        str: The loopback redirect URI.
    """
    return f"http://127.0.0.1:{port}{CALLBACK_PATH}"


def issuer_for(spec: HttpServerSpec) -> str:
    """Derive the origin a server's OAuth artefacts are filed under.

    This is the resource server's origin rendered the way the SDK renders
    the issuer it falls back to when protected-resource metadata names no
    separate authorization server: lower-case host and the scheme's default
    port dropped, so ``https://host:443/mcp`` and ``https://host/mcp`` share
    their credentials.

    Args:
        spec: The server's endpoint configuration.

    Returns:
        str: ``scheme://authority`` for the configured URL.
    """
    parsed = urlparse(spec.url)
    if parsed.scheme and parsed.netloc:
        try:
            return str(_ORIGIN_URL.validate_python(f"{parsed.scheme}://{parsed.netloc}"))
        except ValidationError:
            _logger.debug("mcp_oauth_origin_unparsable", url=spec.url)
    remainder = spec.url.split("://", maxsplit=1)
    if len(remainder) != _URL_PARTS:
        return spec.url
    scheme, rest = remainder
    authority = rest.split("/", maxsplit=1)[0]
    return f"{scheme.lower()}://{authority.lower()}"


def credential_key(server_id: str, issuer: str, suffix: str) -> str:
    """Build the credential-store key one OAuth artefact is held under.

    The origin is folded into a short digest rather than written out, because
    the key is a keyring entry name and a URL is neither a valid nor a
    readable one.

    Args:
        server_id: The server the artefact belongs to.
        issuer: The origin from :func:`issuer_for` the artefact is filed under.
        suffix: Which artefact, ``tokens`` or ``client``.

    Returns:
        str: The credential-store key.
    """
    digest = hashlib.blake2b(issuer.encode("utf-8"), digest_size=_ISSUER_DIGEST_BYTES).hexdigest()
    return f"{MCP_SECRET_NAMESPACE}:oauth:{server_id}:{digest}:{suffix}"


def client_metadata(spec: HttpServerSpec, scope: str | None = None, *, port: int = CALLBACK_PORT) -> OAuthClientMetadata:
    """Build the client metadata presented during registration or sign-in.

    Args:
        spec: The server's endpoint configuration.
        scope: Scope to request, or ``None`` to leave the choice to the SDK,
            which takes it from the server's challenge or metadata and omits
            it when neither names one.
        port: The loopback port the redirect URI names.

    Returns:
        OAuthClientMetadata: Metadata describing Intellicrack as a native
        client using the loopback redirect.
    """
    del spec
    return OAuthClientMetadata(
        client_name=CLIENT_NAME,
        redirect_uris=[AnyUrl(redirect_uri(port))],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method=_PUBLIC_CLIENT_AUTH,
        application_type="native",
        scope=scope,
    )


@dataclass(frozen=True, slots=True)
class StoredTokens:
    """Tokens as stored, with what is needed to use them after a restart.

    Attributes:
        token: The access and refresh tokens.
        expires_at: Absolute expiry of the access token as a Unix timestamp,
            or ``None`` when the authorization server gave no lifetime.
        authorization_server: Metadata of the authorization server that issued
            them, which names the token endpoint a refresh goes to.
    """

    token: OAuthToken
    expires_at: float | None
    authorization_server: OAuthMetadata | None


def _parse_token_record(payload: str) -> StoredTokens:
    """Decode a stored token record.

    Args:
        payload: The stored JSON.

    Returns:
        StoredTokens: The decoded record. A record written before expiry and
        authorization server metadata were kept decodes with neither.

    Raises:
        ValueError: If the payload is not a token record in either format.
    """
    decoded: object = json.loads(payload)
    if not is_json_object(decoded):
        message = "token record is not a JSON object"
        raise ValueError(message)
    raw_token = decoded.get(_RECORD_GRANT)
    if raw_token is None:
        return StoredTokens(token=OAuthToken.model_validate(decoded), expires_at=None, authorization_server=None)
    raw_expiry = decoded.get(_RECORD_EXPIRES_AT)
    expires_at = float(raw_expiry) if isinstance(raw_expiry, int | float) and not isinstance(raw_expiry, bool) else None
    raw_server = decoded.get(_RECORD_AUTHORIZATION_SERVER)
    authorization_server = OAuthMetadata.model_validate(raw_server) if raw_server is not None else None
    return StoredTokens(token=OAuthToken.model_validate(raw_token), expires_at=expires_at, authorization_server=authorization_server)


class KeyringTokenStorage(TokenStorage):
    """Holds one server's OAuth artefacts in the operating system keyring.

    Every read and write is scoped to ``(server_id, origin)``. A stored client registration bound to a different authorization server than
    the one its tokens were last obtained from is refused rather than returned.
    """

    def __init__(self, store: CredentialStore, server_id: str, issuer: str) -> None:
        """Initialize the storage.

        Args:
            store: The credential store holding the artefacts.
            server_id: The server the artefacts belong to.
            issuer: The origin from :func:`issuer_for` they are filed under.
        """
        self._store = store
        self._server_id = server_id
        self._issuer = issuer
        self._metadata_url: str | None = None
        self._authorization_server_source: Callable[[], OAuthMetadata | None] | None = None
        self._loaded: StoredTokens | None = None

    @property
    def issuer(self) -> str:
        """The origin these artefacts are filed under.

        Returns:
            str: The origin from :func:`issuer_for`.
        """
        return self._issuer

    @property
    def loaded(self) -> StoredTokens | None:
        """The token record the last :meth:`get_tokens` call read.

        Returns:
            StoredTokens | None: The record, or ``None`` when none was read.
        """
        return self._loaded

    def bind_metadata_url(self, metadata_url: str | None) -> None:
        """Record the configured CIMD URL for the issuer-binding check.

        A URL-based client id is portable across authorization servers, so it
        is exempt from the issuer check. The check needs to know which URL
        that is in order to recognise it.

        Args:
            metadata_url: The configured Client ID Metadata Document URL.
        """
        self._metadata_url = metadata_url

    def track_authorization_server(self, source: Callable[[], OAuthMetadata | None]) -> None:
        """Say where to find the authorization server metadata in use when tokens are stored.

        Args:
            source: Returns the metadata the flow discovered, or ``None``.
        """
        self._authorization_server_source = source

    async def _read(self, suffix: str) -> str | None:
        """Read one stored artefact.

        Args:
            suffix: Which artefact, ``tokens`` or ``client``.

        Returns:
            str | None: The stored JSON, or ``None`` when absent.

        Raises:
            McpAuthError: If the keyring is unusable or holds the artefact but
                cannot read it.
        """
        key = credential_key(self._server_id, self._issuer, suffix)
        try:
            credentials = await self._store.get_secret(key)
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

    async def read_stored_tokens(self) -> StoredTokens | None:
        """Read the stored token record.

        Returns:
            StoredTokens | None: The record, or ``None`` when none is stored or
            the stored value can no longer be parsed.

        An unusable keyring propagates :class:`McpAuthError` from the read.
        """
        payload = await self._read(_TOKENS_SUFFIX)
        if payload is None:
            return None
        try:
            return _parse_token_record(payload)
        except (ValueError, ValidationError) as exc:
            _logger.warning("mcp_oauth_tokens_unreadable", server_id=self._server_id, error=str(exc))
            return None

    async def get_tokens(self) -> OAuthToken | None:
        """Read the stored access and refresh tokens.

        The whole record is kept in :attr:`loaded`, so the provider can restore
        the expiry and the token endpoint alongside the tokens.

        Returns:
            OAuthToken | None: The tokens, or ``None`` when none are stored
            or the stored value can no longer be parsed.

        An unusable keyring propagates :class:`McpAuthError` from the read.
        """
        self._loaded = await self.read_stored_tokens()
        return self._loaded.token if self._loaded is not None else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store access and refresh tokens with their absolute expiry.

        ``expires_in`` is relative to the moment the token was issued, which
        is meaningless after a restart, so the absolute time is recorded too.
        The authorization server metadata in use is recorded with them, so a
        refresh after a restart reaches the token endpoint that issued them.

        An unusable keyring propagates :class:`McpAuthError` from the write.

        Args:
            tokens: The tokens to store.
        """
        expires_at = time.time() + tokens.expires_in if tokens.expires_in is not None else None
        authorization_server = self._authorization_server_source() if self._authorization_server_source is not None else None
        record: dict[str, object] = {
            _RECORD_GRANT: tokens.model_dump(mode="json", exclude_none=True),
            _RECORD_EXPIRES_AT: expires_at,
            _RECORD_AUTHORIZATION_SERVER: (
                authorization_server.model_dump(mode="json", exclude_none=True) if authorization_server is not None else None
            ),
        }
        await self._write(_TOKENS_SUFFIX, json.dumps(record))
        self._loaded = StoredTokens(token=tokens, expires_at=expires_at, authorization_server=authorization_server)
        _logger.info("mcp_oauth_tokens_stored", server_id=self._server_id, has_expiry=expires_at is not None)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        """Read the stored client registration.

        Returns:
            OAuthClientInformationFull | None: The registration, or ``None``
            when none is stored, it cannot be parsed, or it is bound to a
            different authorization server than the one the stored tokens
            were issued by.

        An unusable keyring propagates :class:`McpAuthError` from the read.
        """
        payload = await self._read(_CLIENT_SUFFIX)
        if payload is None:
            return None
        try:
            info = OAuthClientInformationFull.model_validate_json(payload)
        except ValidationError as exc:
            _logger.warning("mcp_oauth_client_unreadable", server_id=self._server_id, error=str(exc))
            return None
        stored = self._loaded if self._loaded is not None else await self.read_stored_tokens()
        authorization_server = stored.authorization_server if stored is not None else None
        if authorization_server is not None and not credentials_match_issuer(info, str(authorization_server.issuer), self._metadata_url):
            _logger.warning(
                "mcp_oauth_client_issuer_mismatch",
                server_id=self._server_id,
                expected_issuer=str(authorization_server.issuer),
                stored_issuer=info.issuer,
            )
            return None
        return info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store a client registration as the SDK bound it.

        The SDK stamps ``issuer`` with the authorization server the
        registration was made with, and leaves it empty when it could not
        establish one. Either is stored unchanged: stamping the resource
        origin instead would bind the registration to a server that never
        issued it, and the SDK would then discard it on the next discovery.

        An unusable keyring propagates :class:`McpAuthError` from the write.

        Args:
            client_info: The registration to store.
        """
        await self._write(_CLIENT_SUFFIX, client_info.model_dump_json(exclude_none=True))
        _logger.info("mcp_oauth_client_stored", server_id=self._server_id, client_id=client_info.client_id, issuer=client_info.issuer)

    async def clear(self) -> None:
        """Remove every artefact stored for this server.

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
        self._loaded = None
        _logger.info("mcp_oauth_cleared", server_id=self._server_id, issuer=self._issuer)


async def resolve_client_identity(
    spec: HttpServerSpec,
    metadata_url: str | None,
    storage: KeyringTokenStorage | None = None,
) -> OAuthClientInformationFull | None:
    """Resolve the client identity to start a flow with, before discovery.

    A registration already stored for this server wins, so a client that has
    registered once does not register again. A configured pre-registered
    client id comes next: it is the identity the operator arranged with the
    authorization server, and using it means no registration happens at all.
    Otherwise ``None`` is returned and the SDK decides once it holds the
    authorization server's metadata: a Client ID Metadata Document when one
    is configured and the server supports it, else dynamic client
    registration, which is deprecated.

    Args:
        spec: The server's endpoint configuration.
        metadata_url: The configured Client ID Metadata Document URL, or
            ``None``.
        storage: Keyring storage to consult for an existing registration, or
            ``None`` to skip that step.

    Returns:
        OAuthClientInformationFull | None: The identity to use, or ``None``
        to let the SDK use CIMD or register dynamically.

    Raises:
        McpAuthError: If a CIMD URL is configured but is not a valid HTTPS
            URL with a path.
    """
    if metadata_url is not None and not is_valid_client_metadata_url(metadata_url):
        message = f"OAuth metadata URL {metadata_url!r} is not usable as a client id: it must be an HTTPS URL with a non-root path."
        raise McpAuthError(message)

    if storage is not None:
        storage.bind_metadata_url(metadata_url)
        stored = await storage.get_client_info()
        if stored is not None and stored.client_id:
            _logger.debug("mcp_oauth_identity_stored", client_id=stored.client_id)
            return stored

    if spec.oauth_client_id:
        _logger.info("mcp_oauth_identity_preregistered", client_id=spec.oauth_client_id)
        return OAuthClientInformationFull(
            client_id=spec.oauth_client_id,
            token_endpoint_auth_method=_PUBLIC_CLIENT_AUTH,
            redirect_uris=[AnyUrl(redirect_uri())],
        )

    if metadata_url is not None:
        _logger.info("mcp_oauth_identity_cimd_if_supported", metadata_url=metadata_url)
    else:
        _logger.warning(
            "mcp_oauth_identity_dynamic_registration",
            url=issuer_for(spec),
            note="dynamic client registration is deprecated; configure oauthMetadataUrl or oauthClientId instead",
        )
    return None


async def open_authorization_page(url: str) -> None:
    """Send the operator to the authorization page in their browser.

    Launching a browser blocks for as long as the platform's handler takes
    to return, so it runs off the event loop. The URL is built from metadata
    the authorization server published, so it goes through
    :func:`~intellicrack.mcp.transport.open_web_url` rather than straight to
    the platform handler.

    Args:
        url: The authorization URL the SDK built.

    Raises:
        McpAuthError: If the URL is not an ``http`` or ``https`` address, so
            the operator was never sent anywhere.
    """
    if not is_web_url(url):
        message = f"the authorization server asked Intellicrack to open {url[:64]!r}, which is not a web address"
        raise McpAuthError(message)
    _logger.info("mcp_oauth_browser_opened", host=url.split("/", maxsplit=3)[2] if "//" in url else "")
    _ = await asyncio.to_thread(open_web_url, url)


async def await_authorization_callback(server: OAuthCallbackServer) -> AuthorizationCodeResult:
    """Wait on a running loopback server for the authorization redirect.

    The wait is minutes long and blocking, so it runs on a worker thread. On
    the event loop it would freeze every other MCP server, every tool call and
    the whole GUI for the duration of the sign-in.

    Args:
        server: The started callback server.

    Returns:
        AuthorizationCodeResult: The authorization code, the echoed state,
        and the RFC 9207 issuer when the authorization server supplied one.

    Raises:
        McpAuthError: If the redirect never arrived, or arrived as an error.
    """
    try:
        code, state = await asyncio.to_thread(server.wait_for_callback)
    except (OAuthCallbackError, OAuthAuthorizationError) as exc:
        message = f"OAuth sign-in did not complete: {exc}"
        raise McpAuthError(message) from exc
    return AuthorizationCodeResult(code=code, state=state, iss=server.received_issuer)


class LoopbackCallback:
    """One sign-in's loopback redirect listener.

    Each flow binds its own socket, exclusively, so two sign-ins in progress at once never share a port: the first takes
    :data:`CALLBACK_PORT` and the next gets a port from the operating system. The ``state`` of the authorization request is read from the
    authorization URL before the browser is sent there, and only a redirect carrying it ends the wait.
    """

    def __init__(self, *, preferred_port: int = CALLBACK_PORT, timeout: float = CALLBACK_TIMEOUT_S) -> None:
        """Initialize the listener without binding anything yet.

        Args:
            preferred_port: Port tried first.
            timeout: How long to wait for the redirect.
        """
        self._preferred_port = preferred_port
        self._timeout = timeout
        self._server: OAuthCallbackServer | None = None

    @property
    def port(self) -> int | None:
        """The port the listener is bound to.

        Returns:
            int | None: The port while a flow is open, otherwise ``None``.
        """
        return self._server.port if self._server is not None else None

    def open(self) -> str:
        """Bind the listener for one flow.

        Returns:
            str: The redirect URI naming the bound port.

        Raises:
            McpAuthError: If no loopback port could be bound at all.
        """
        self.close()
        for port in (self._preferred_port, 0):
            server = OAuthCallbackServer(port=port, timeout=self._timeout, callback_path=CALLBACK_PATH, require_state=True)
            try:
                server.start()
            except OAuthCallbackError as exc:
                if port == 0:
                    message = f"cannot open a loopback port for the OAuth redirect: {exc}"
                    raise McpAuthError(message) from exc
                _logger.info("mcp_oauth_callback_port_busy", preferred_port=port)
                continue
            self._server = server
            return redirect_uri(server.port)
        message = "cannot open a loopback port for the OAuth redirect"
        raise McpAuthError(message)

    async def redirect(self, url: str, opener: Callable[[str], Awaitable[None]]) -> None:
        """Arm the listener with the request's ``state`` and send the operator to the authorization page.

        Args:
            url: The authorization URL the SDK built.
            opener: Sends the operator to ``url``.

        Raises:
            McpAuthError: If no listener is open, or the URL carries no ``state``.
        """
        server = self._server
        if server is None:
            message = "the OAuth redirect listener is not open"
            raise McpAuthError(message)
        states = parse_qs(urlparse(url).query).get("state")
        if not states:
            message = "the authorization URL carries no state, so its redirect cannot be told apart from a forged one"
            raise McpAuthError(message)
        server.expect_state(states[0])
        await opener(url)

    async def callback(self) -> AuthorizationCodeResult:
        """Wait for the redirect on the open listener.

        Returns:
            AuthorizationCodeResult: The redirect's code, state and issuer.

        Raises:
            McpAuthError: If no listener is open.
        """
        server = self._server
        if server is None:
            message = "the OAuth redirect listener is not open"
            raise McpAuthError(message)
        return await await_authorization_callback(server)

    def close(self) -> None:
        """Release the listener's port."""
        server = self._server
        self._server = None
        if server is not None:
            server.stop()


class McpOAuthClientProvider(OAuthClientProvider):
    """The SDK's OAuth provider, restoring what a restart would otherwise lose.

    Three things are added to the SDK flow. The stored expiry and authorization server metadata are restored with the tokens, so an expired
    access token is refreshed rather than sent. A configured pre-registered client id is used when no registration is stored. And when a
    loopback listener is supplied, it is bound for each authorization and the redirect URI is pointed at the port it got.
    """

    def __init__(
        self,
        spec: HttpServerSpec,
        storage: KeyringTokenStorage,
        *,
        redirect_handler: Callable[[str], Awaitable[None]],
        callback_handler: Callable[[], Awaitable[AuthorizationCodeResult]],
        loopback: LoopbackCallback | None,
        callback_port: int,
    ) -> None:
        """Initialize the provider.

        Args:
            spec: The server's endpoint configuration.
            storage: Keyring-backed storage for this server's artefacts.
            redirect_handler: Sends the operator to the authorization page.
            callback_handler: Waits for the redirect.
            loopback: The listener bound for each authorization, or ``None``
                when ``callback_handler`` receives the redirect itself.
            callback_port: The port the default redirect URI names.
        """
        super().__init__(
            server_url=spec.url,
            client_metadata=client_metadata(spec, port=callback_port),
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
            client_metadata_url=spec.oauth_metadata_url,
        )
        self._spec = spec
        self._storage = storage
        self._loopback = loopback
        storage.bind_metadata_url(spec.oauth_metadata_url)
        storage.track_authorization_server(self._current_authorization_server)

    def _current_authorization_server(self) -> OAuthMetadata | None:
        """The authorization server metadata the flow is using.

        Returns:
            OAuthMetadata | None: The discovered or restored metadata.
        """
        return self.context.oauth_metadata

    @override
    async def _initialize(self) -> None:
        """Load stored tokens, their expiry and issuer metadata, and the client identity."""
        await super()._initialize()
        stored = self._storage.loaded
        if stored is not None and self.context.current_tokens is not None:
            self.context.token_expiry_time = stored.expires_at
            if self.context.oauth_metadata is None and stored.authorization_server is not None:
                self.context.oauth_metadata = stored.authorization_server
        if self.context.client_info is None:
            self.context.client_info = await resolve_client_identity(self._spec, self._spec.oauth_metadata_url)

    @override
    async def _perform_authorization_code_grant(self) -> tuple[str, str]:
        """Run the browser half of the flow on a freshly bound loopback listener.

        Returns:
            tuple[str, str]: The authorization code and the PKCE verifier.
        """
        loopback = self._loopback
        if loopback is None:
            return await super()._perform_authorization_code_grant()
        self.context.client_metadata.redirect_uris = [AnyUrl(loopback.open())]
        try:
            return await super()._perform_authorization_code_grant()
        finally:
            loopback.close()


def build_oauth_provider(
    spec: HttpServerSpec,
    storage: KeyringTokenStorage,
    *,
    redirect_handler: Callable[[str], Awaitable[None]] | None = None,
    callback_handler: Callable[[], Awaitable[AuthorizationCodeResult]] | None = None,
    callback_port: int = CALLBACK_PORT,
    callback_timeout_s: float = CALLBACK_TIMEOUT_S,
) -> OAuthClientProvider:
    """Build the ``httpx2`` auth handler that signs requests to one server.

    Args:
        spec: The server's endpoint configuration.
        storage: Keyring-backed storage for this server's artefacts.
        redirect_handler: Opens the authorization page, defaulting to the
            operator's browser.
        callback_handler: Waits for the redirect. When ``None``, a loopback
            listener is bound for each authorization and only the redirect
            carrying that authorization's ``state`` ends the wait.
        callback_port: Port the loopback listener tries first.
        callback_timeout_s: How long the loopback listener waits.

    Returns:
        OAuthClientProvider: The handler to attach to the HTTP client.

    Raises:
        McpAuthError: If a configured CIMD URL is not usable as a client id.
    """
    metadata_url = spec.oauth_metadata_url
    if metadata_url is not None and not is_valid_client_metadata_url(metadata_url):
        message = f"OAuth metadata URL {metadata_url!r} must be an HTTPS URL with a non-root path"
        raise McpAuthError(message)
    opener = redirect_handler if redirect_handler is not None else open_authorization_page
    if callback_handler is not None:
        return McpOAuthClientProvider(
            spec,
            storage,
            redirect_handler=opener,
            callback_handler=callback_handler,
            loopback=None,
            callback_port=callback_port,
        )
    loopback = LoopbackCallback(preferred_port=callback_port, timeout=callback_timeout_s)

    async def redirect(url: str) -> None:
        """Arm the loopback listener, then open the authorization page.

        Args:
            url: The authorization URL the SDK built.
        """
        await loopback.redirect(url, opener)

    return McpOAuthClientProvider(
        spec,
        storage,
        redirect_handler=redirect,
        callback_handler=loopback.callback,
        loopback=loopback,
        callback_port=callback_port,
    )


async def sign_out(store: CredentialStore, server_id: str, issuer: str | None = None) -> bool:
    """Remove a server's stored OAuth credentials.

    Args:
        store: The credential store holding them.
        server_id: The server to sign out of.
        issuer: The origin from :func:`issuer_for` the credentials are filed
            under. When ``None``, nothing is removed, because a token can only
            be found under the origin it was filed against.

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
        issuer: The origin from :func:`issuer_for` the token would be filed
            under.

    Returns:
        bool: ``True`` when a token is stored.

    Raises:
        McpAuthError: If the keyring is unusable or holds the token but cannot
            read it, so the answer is unknown.
    """
    key = credential_key(server_id, issuer, _TOKENS_SUFFIX)
    try:
        credentials = await store.get_secret(key)
    except CredentialStoreError as exc:
        message = f"cannot check OAuth state for MCP server '{server_id}': {exc}"
        raise McpAuthError(message) from exc
    if credentials is None or not credentials.api_key:
        return False
    try:
        return bool(_parse_token_record(credentials.api_key).token.access_token)
    except (ValueError, ValidationError):
        return False
