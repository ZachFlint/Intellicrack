# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real OAuth 2.1 authorization server and a separate real MCP resource server, run in-process.

The two listen on different loopback ports, so the authorization server's issuer is a different origin from the MCP endpoint -- the layout
where client registrations used to be discarded on every restart. The authorization server implements dynamic registration (switchable),
pre-registered clients, PKCE-verified authorization codes, access-token expiry and the refresh-token grant. The resource server serves the
SDK's real Streamable HTTP ``MCPServer`` behind a bearer check that answers ``401`` for a missing, unknown or expired token and ``403
insufficient_scope`` for a token lacking a required scope.

Both record what they were asked, so a test can assert on the wire traffic: how many registrations, which client ids, which scopes and
redirect URIs reached the authorization endpoint, and which grants reached the token endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self
from urllib.parse import urlencode

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route

from tests._helpers.mcp_server_main import build_server


if TYPE_CHECKING:
    from types import TracebackType

    from starlette.requests import Request
    from starlette.types import ASGIApp, Receive, Scope, Send


BASE_SCOPE = "mcp:tools"
"""Scope the resource advertises and asks for first."""

ADMIN_SCOPE = "mcp:admin"
"""Extra scope a step-up challenge asks for."""

_BOOT_TIMEOUT_S = 30.0


@dataclass
class _Grant:
    """One outstanding authorization code.

    Attributes:
        challenge: The PKCE code challenge.
        redirect_uri: Where the code was sent.
        client_id: The client it was issued to.
        scope: The scope that was authorized.
    """

    challenge: str
    redirect_uri: str
    client_id: str
    scope: str


@dataclass
class AuthorizationState:
    """Everything the two servers share and record.

    Attributes:
        allow_registration: Whether the registration endpoint exists.
        preregistered: Client ids the authorization server knows without registration.
        expires_in: Lifetime given to each access token, in seconds.
        required_scopes: Scopes the resource demands of a token.
        registrations: Client ids issued by dynamic registration, in order.
        authorize_requests: Query parameters of every authorization request.
        token_requests: Form fields of every token request.
        access_tokens: Live access tokens to their scope and absolute expiry.
        refresh_tokens: Live refresh tokens to their client id and scope.
        codes: Outstanding authorization codes.
        lock: Serialises updates from the server threads.
    """

    allow_registration: bool = True
    preregistered: set[str] = field(default_factory=set[str])
    expires_in: int = 3600
    required_scopes: tuple[str, ...] = (BASE_SCOPE,)
    registrations: list[str] = field(default_factory=list[str])
    authorize_requests: list[dict[str, str]] = field(default_factory=list[dict[str, str]])
    token_requests: list[dict[str, str]] = field(default_factory=list[dict[str, str]])
    access_tokens: dict[str, tuple[str, float]] = field(default_factory=dict[str, tuple[str, float]])
    refresh_tokens: dict[str, tuple[str, str]] = field(default_factory=dict[str, tuple[str, str]])
    codes: dict[str, _Grant] = field(default_factory=dict[str, _Grant])
    lock: threading.Lock = field(default_factory=threading.Lock)

    def known_client(self, client_id: str) -> bool:
        """Report whether a client id may use the authorization server.

        Args:
            client_id: The presented client id.

        Returns:
            bool: ``True`` for a registered or pre-registered client.
        """
        return client_id in self.preregistered or client_id in self.registrations

    def revoke_access_tokens(self) -> None:
        """Invalidate every access token, as a server restart or revocation would."""
        with self.lock:
            self.access_tokens.clear()

    def grants(self, grant_type: str) -> list[dict[str, str]]:
        """List the token requests of one grant type.

        Args:
            grant_type: ``authorization_code`` or ``refresh_token``.

        Returns:
            list[dict[str, str]]: The matching token requests.
        """
        return [entry for entry in self.token_requests if entry.get("grant_type") == grant_type]


def _verify_pkce(verifier: str, challenge: str) -> bool:
    """Check a PKCE verifier against its S256 challenge.

    Args:
        verifier: The ``code_verifier``.
        challenge: The ``code_challenge``.

    Returns:
        bool: ``True`` when they match.
    """
    derived = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return secrets.compare_digest(derived, challenge)


def _issue_tokens(state: AuthorizationState, client_id: str, scope: str) -> dict[str, object]:
    """Mint an access and refresh token pair.

    Args:
        state: Shared server state.
        client_id: The client they are issued to.
        scope: The granted scope.

    Returns:
        dict[str, object]: The token response body.
    """
    access = secrets.token_urlsafe(24)
    refresh = secrets.token_urlsafe(24)
    with state.lock:
        state.access_tokens[access] = (scope, time.time() + state.expires_in)
        state.refresh_tokens[refresh] = (client_id, scope)
    return {"access_token": access, "token_type": "Bearer", "expires_in": state.expires_in, "scope": scope, "refresh_token": refresh}


def build_authorization_server(origin: str, state: AuthorizationState) -> Starlette:
    """Build the authorization server.

    Args:
        origin: Its own origin, which is also its issuer.
        state: Shared server state.

    Returns:
        Starlette: The application.
    """

    def metadata(_request: Request) -> Response:
        """Publish RFC 8414 metadata.

        Args:
            _request: The request.

        Returns:
            Response: The metadata.
        """
        body: dict[str, object] = {
            "issuer": origin,
            "authorization_endpoint": f"{origin}/authorize",
            "token_endpoint": f"{origin}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [BASE_SCOPE, ADMIN_SCOPE],
        }
        if state.allow_registration:
            body["registration_endpoint"] = f"{origin}/register"
        return JSONResponse(body)

    async def register(request: Request) -> Response:
        """Register a client dynamically.

        Args:
            request: The registration request.

        Returns:
            Response: The registration, or 404 when registration is off.
        """
        if not state.allow_registration:
            return JSONResponse({"error": "registration_not_supported"}, status_code=404)
        body: dict[str, object] = await request.json()
        client_id = f"dcr-{secrets.token_hex(4)}"
        with state.lock:
            state.registrations.append(client_id)
        return JSONResponse(
            {"client_id": client_id, "redirect_uris": body.get("redirect_uris", []), "token_endpoint_auth_method": "none"},
            status_code=201,
        )

    def authorize(request: Request) -> Response:
        """Issue a code to a known client and redirect back.

        Args:
            request: The authorization request.

        Returns:
            Response: A redirect carrying ``code``, ``state`` and ``iss``, or 400 for an unknown client.
        """
        params = dict(request.query_params)
        with state.lock:
            state.authorize_requests.append(params)
        client_id = params.get("client_id", "")
        if not state.known_client(client_id):
            return JSONResponse({"error": "unauthorized_client"}, status_code=400)
        code = secrets.token_urlsafe(16)
        with state.lock:
            state.codes[code] = _Grant(
                challenge=params.get("code_challenge", ""),
                redirect_uri=params.get("redirect_uri", ""),
                client_id=client_id,
                scope=params.get("scope", BASE_SCOPE),
            )
        query = urlencode({"code": code, "state": params.get("state", ""), "iss": origin})
        return RedirectResponse(f"{params.get('redirect_uri', '')}?{query}", status_code=302)

    async def token(request: Request) -> Response:
        """Redeem an authorization code or a refresh token.

        Args:
            request: The token request.

        Returns:
            Response: New tokens, or an OAuth error.
        """
        form = {key: str(value) for key, value in (await request.form()).items()}
        with state.lock:
            state.token_requests.append(form)
        grant_type = form.get("grant_type")
        if grant_type == "authorization_code":
            with state.lock:
                grant = state.codes.pop(form.get("code", ""), None)
            if (
                grant is None
                or grant.client_id != form.get("client_id")
                or grant.redirect_uri != form.get("redirect_uri")
                or not _verify_pkce(form.get("code_verifier", ""), grant.challenge)
            ):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return JSONResponse(_issue_tokens(state, grant.client_id, grant.scope))
        if grant_type == "refresh_token":
            with state.lock:
                held = state.refresh_tokens.pop(form.get("refresh_token", ""), None)
            if held is None or held[0] != form.get("client_id"):
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return JSONResponse(_issue_tokens(state, held[0], held[1]))
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    return Starlette(
        routes=[
            Route("/.well-known/oauth-authorization-server", metadata),
            Route("/register", register, methods=["POST"]),
            Route("/authorize", authorize),
            Route("/token", token, methods=["POST"]),
        ],
    )


class _BearerGuard:
    """ASGI middleware enforcing the resource's token and scope rules."""

    def __init__(self, app: ASGIApp, *, resource_metadata_url: str, state: AuthorizationState) -> None:
        """Guard an application.

        Args:
            app: The MCP application.
            resource_metadata_url: Advertised in the ``401`` challenge.
            state: Shared server state.
        """
        self._app = app
        self._metadata_url = resource_metadata_url
        self._state = state

    async def _reject(self, send: Send, status: int, challenge: str) -> None:
        """Send a challenge response.

        Args:
            send: ASGI send callable.
            status: ``401`` or ``403``.
            challenge: The ``WWW-Authenticate`` value.
        """
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"text/plain"), (b"www-authenticate", challenge.encode("latin-1"))],
        })
        await send({"type": "http.response.body", "body": b"denied"})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass a request with a live, sufficiently scoped token; challenge anything else.

        Args:
            scope: ASGI connection scope.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        presented = headers.get(b"authorization", b"").decode("latin-1").removeprefix("Bearer ")
        with self._state.lock:
            held = self._state.access_tokens.get(presented)
            required = self._state.required_scopes
        if held is None or held[1] < time.time():
            await self._reject(send, 401, f'Bearer resource_metadata="{self._metadata_url}", scope="{BASE_SCOPE}"')
            return
        missing = [item for item in required if item not in held[0].split()]
        if missing:
            await self._reject(send, 403, f'Bearer error="insufficient_scope", scope="{" ".join(missing)}"')
            return
        await self._app(scope, receive, send)


def build_resource_server(origin: str, authorization_origin: str, state: AuthorizationState) -> Starlette:
    """Build the protected MCP resource server.

    Args:
        origin: Its own origin.
        authorization_origin: The authorization server it names.
        state: Shared server state.

    Returns:
        Starlette: The application.
    """
    metadata_url = f"{origin}/.well-known/oauth-protected-resource"

    def protected_resource_metadata(_request: Request) -> Response:
        """Publish RFC 9728 metadata naming the separate authorization server.

        Args:
            _request: The request.

        Returns:
            Response: The metadata.
        """
        return JSONResponse({
            "resource": f"{origin}/mcp",
            "authorization_servers": [authorization_origin],
            "scopes_supported": [BASE_SCOPE],
        })

    inner = build_server("well_behaved").streamable_http_app()
    return Starlette(
        routes=[
            Route("/.well-known/oauth-protected-resource", protected_resource_metadata),
            Route("/.well-known/oauth-protected-resource/mcp", protected_resource_metadata),
            Mount("/", app=_BearerGuard(inner, resource_metadata_url=metadata_url, state=state)),
        ],
        lifespan=inner.router.lifespan_context,
    )


def free_port() -> int:
    """Find a loopback port that is free right now.

    Returns:
        int: The port.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class _ServedApp:
    """One application served by uvicorn on a background thread."""

    def __init__(self, app: Starlette, port: int) -> None:
        """Prepare the server.

        Args:
            app: The application.
            port: Loopback port to listen on.
        """
        self._server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", lifespan="on"))
        self._thread = threading.Thread(target=self._server.run, name=f"oauth-split-{port}", daemon=True)

    def start(self) -> None:
        """Start serving and wait until the socket accepts.

        Raises:
            RuntimeError: If the server never starts.
        """
        self._thread.start()
        deadline = time.monotonic() + _BOOT_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._server.started:
                return
            if not self._thread.is_alive():
                break
            time.sleep(0.05)
        message = "the in-process OAuth test server never started"
        raise RuntimeError(message)

    def stop(self) -> None:
        """Stop serving and wait for the thread."""
        self._server.should_exit = True
        self._thread.join(timeout=15.0)


class SplitOAuthServers:
    """An authorization server and a resource server on different loopback origins.

    Attributes:
        state: What both servers share and record.
        authorization_origin: The authorization server's origin and issuer.
        resource_origin: The resource server's origin.
    """

    state: AuthorizationState
    authorization_origin: str
    resource_origin: str

    def __init__(self, state: AuthorizationState | None = None) -> None:
        """Prepare both servers.

        Args:
            state: Initial shared state, defaulting to dynamic registration on.
        """
        self.state = state if state is not None else AuthorizationState()
        authorization_port = free_port()
        resource_port = free_port()
        self.authorization_origin = f"http://127.0.0.1:{authorization_port}"
        self.resource_origin = f"http://127.0.0.1:{resource_port}"
        self._authorization = _ServedApp(build_authorization_server(self.authorization_origin, self.state), authorization_port)
        self._resource = _ServedApp(build_resource_server(self.resource_origin, self.authorization_origin, self.state), resource_port)

    @property
    def mcp_url(self) -> str:
        """The MCP endpoint URL.

        Returns:
            str: The endpoint.
        """
        return f"{self.resource_origin}/mcp"

    def __enter__(self) -> Self:
        """Start both servers.

        Returns:
            Self: The running pair.

        Raises:
            RuntimeError: If either server does not start.
        """
        self._authorization.start()
        try:
            self._resource.start()
        except RuntimeError:
            self._authorization.stop()
            raise
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None) -> None:
        """Stop both servers.

        Args:
            exc_type: Exception type, if any.
            exc: Exception, if any.
            traceback: Traceback, if any.
        """
        self._resource.stop()
        self._authorization.stop()
