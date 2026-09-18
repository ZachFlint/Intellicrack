# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""A real OAuth 2.1 authorization server guarding a real MCP resource.

One process serves both halves so the client's whole authorization path runs
for real: protected-resource metadata discovery (RFC 9728), authorization
server metadata discovery (RFC 8414), an authorization endpoint that enforces
PKCE, a token endpoint, and an MCP endpoint that answers ``401`` with a
``WWW-Authenticate`` challenge until a bearer token arrives.

``--issuer-mode mismatched`` makes the metadata advertise an issuer that is not
this server, which is what RFC 9207 issuer validation exists to reject.

Run it as ``python mcp_oauth_server.py --port N [--issuer-mode mismatched]``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import secrets
import sys
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Mount, Route

from tests._helpers.mcp_server_main import build_server


if TYPE_CHECKING:
    from collections.abc import Sequence

    from starlette.requests import Request
    from starlette.types import ASGIApp, Receive, Scope, Send


FOREIGN_ISSUER = "https://issuer.invalid"
"""Issuer the mismatched mode advertises instead of its own origin."""

ACCESS_TOKEN = "test-access-token"
"""The single bearer token this server accepts."""

SUPPORTED_SCOPE = "mcp:tools"
"""Scope advertised in metadata and required by the challenge."""


class _Grants:
    """Authorization codes issued but not yet redeemed.

    Attributes:
        codes: Issued code to its PKCE challenge and redirect target.
    """

    def __init__(self) -> None:
        """Start with no outstanding codes."""
        self.codes: dict[str, tuple[str, str]] = {}


def _verify_pkce(verifier: str, challenge: str) -> bool:
    """Check a PKCE verifier against the challenge it must satisfy.

    Args:
        verifier: The ``code_verifier`` presented at the token endpoint.
        challenge: The ``code_challenge`` recorded at authorization time.

    Returns:
        bool: ``True`` when the verifier hashes to the challenge under S256.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    derived = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return secrets.compare_digest(derived, challenge)


class _BearerGuard:
    """ASGI middleware challenging any MCP request without a bearer token."""

    def __init__(self, app: ASGIApp, resource_metadata_url: str) -> None:
        """Guard an application behind a bearer-token check.

        Args:
            app: The MCP application to guard.
            resource_metadata_url: URL advertised in the challenge so the
                client can discover which authorization server to use.
        """
        self._app = app
        self._challenge = f'Bearer resource_metadata="{resource_metadata_url}", scope="{SUPPORTED_SCOPE}"'

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Answer ``401`` without a valid token, else pass the request through.

        Args:
            scope: ASGI connection scope.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            presented = headers.get(b"authorization", b"").decode("latin-1")
            if presented != f"Bearer {ACCESS_TOKEN}":
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"www-authenticate", self._challenge.encode("latin-1")),
                    ],
                })
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self._app(scope, receive, send)


def build_app(*, origin: str, issuer_mode: str) -> Starlette:
    """Build the combined authorization server and protected MCP resource.

    Args:
        origin: This server's own origin, e.g. ``http://127.0.0.1:8000``.
        issuer_mode: ``matched`` to advertise ``origin`` as the issuer, or
            ``mismatched`` to advertise :data:`FOREIGN_ISSUER`.

    Returns:
        Starlette: The application to serve.
    """
    grants = _Grants()
    issuer = origin if issuer_mode == "matched" else FOREIGN_ISSUER
    resource_metadata_url = f"{origin}/.well-known/oauth-protected-resource"

    def protected_resource_metadata(_request: Request) -> Response:
        """Advertise which authorization server guards this resource.

        Args:
            _request: The incoming request.

        Returns:
            Response: RFC 9728 protected-resource metadata.
        """
        return JSONResponse({
            "resource": f"{origin}/mcp",
            "authorization_servers": [origin],
            "scopes_supported": [SUPPORTED_SCOPE],
        })

    def authorization_server_metadata(_request: Request) -> Response:
        """Advertise this authorization server's endpoints.

        Args:
            _request: The incoming request.

        Returns:
            Response: RFC 8414 authorization server metadata.
        """
        return JSONResponse({
            "issuer": issuer,
            "authorization_endpoint": f"{origin}/authorize",
            "token_endpoint": f"{origin}/token",
            "registration_endpoint": f"{origin}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": [SUPPORTED_SCOPE],
        })

    async def register(request: Request) -> Response:
        """Accept a dynamic client registration.

        Args:
            request: The registration request.

        Returns:
            Response: The registered client's identifiers.
        """
        body: dict[str, Any] = await request.json()
        return JSONResponse(
            {
                "client_id": "test-client",
                "redirect_uris": body.get("redirect_uris", []),
                "token_endpoint_auth_method": "none",
            },
            status_code=201,
        )

    def authorize(request: Request) -> Response:
        """Issue an authorization code and redirect back to the client.

        Args:
            request: The authorization request.

        Returns:
            Response: A redirect carrying ``code``, ``state`` and ``iss``.
        """
        params = request.query_params
        redirect_uri = params.get("redirect_uri", "")
        challenge = params.get("code_challenge", "")
        code = secrets.token_urlsafe(16)
        grants.codes[code] = (challenge, redirect_uri)
        query = {"code": code, "state": params.get("state", ""), "iss": issuer}
        return RedirectResponse(f"{redirect_uri}?{urlencode(query)}", status_code=302)

    async def token(request: Request) -> Response:
        """Exchange a PKCE-verified authorization code for an access token.

        Args:
            request: The token request.

        Returns:
            Response: The access token, or an error when PKCE fails.
        """
        form = await request.form()
        code = str(form.get("code", ""))
        verifier = str(form.get("code_verifier", ""))
        recorded = grants.codes.pop(code, None)
        if recorded is None or not _verify_pkce(verifier, recorded[0]):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return JSONResponse({
            "access_token": ACCESS_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": SUPPORTED_SCOPE,
        })

    inner = build_server("well_behaved").streamable_http_app()
    return Starlette(
        routes=[
            Route("/.well-known/oauth-protected-resource", protected_resource_metadata),
            Route("/.well-known/oauth-protected-resource/mcp", protected_resource_metadata),
            Route("/.well-known/oauth-authorization-server", authorization_server_metadata),
            Route("/register", register, methods=["POST"]),
            Route("/authorize", authorize),
            Route("/token", token, methods=["POST"]),
            Mount("/", app=_BearerGuard(inner, resource_metadata_url)),
        ],
        lifespan=inner.router.lifespan_context,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Serve the authorization server and protected resource on loopback.

    Args:
        argv: Command-line arguments, defaulting to ``sys.argv[1:]``.

    Returns:
        int: Process exit status.
    """
    parser = argparse.ArgumentParser(description="A real OAuth-protected MCP server for the Intellicrack gates.")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--issuer-mode", choices=("matched", "mismatched"), default="matched")
    arguments = parser.parse_args(argv)

    origin = f"http://127.0.0.1:{arguments.port}"
    uvicorn.run(build_app(origin=origin, issuer_mode=arguments.issuer_mode), host="127.0.0.1", port=arguments.port, log_level="error")
    return 0


if __name__ == "__main__":
    sys.exit(main())
