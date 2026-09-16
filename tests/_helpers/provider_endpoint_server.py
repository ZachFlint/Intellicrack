# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Loopback HTTP server speaking the model-listing dialects of LLM provider APIs.

Provider connect probes and model refreshes issue a single authenticated
``GET`` against a model-listing endpoint. This server answers those requests
over the loopback interface in the exact wire formats the real services use, so
tests can drive the real ``openai``/``anthropic``/``google-genai`` SDK clients
and Intellicrack's own ``httpx`` clients end to end without reaching the
internet. Every request is recorded with its path and headers so tests can
assert on what actually reached the wire.

Endpoints, relative to the server origin:

* ``/api/v1/models`` -- OpenAI-compatible listing (OpenAI, Grok, OpenRouter and
  gateways such as Venice), authenticated with ``Authorization: Bearer <key>``.
* ``/anthropic/v1/models`` -- Anthropic listing, authenticated with ``x-api-key``.
* ``/gemini/v1beta/models`` -- Gemini listing, authenticated with ``x-goog-api-key``.
* ``/ollama/api/tags`` -- Ollama local model tags, unauthenticated.

A request carrying any key other than ``accepted_key`` receives the provider's
real ``401`` error shape; any other path receives ``404``.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Final, Self
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from types import TracebackType


OPENAI_COMPATIBLE_MODELS_PATH: Final[str] = "/api/v1/models"
ANTHROPIC_MODELS_PATH: Final[str] = "/anthropic/v1/models"
GEMINI_MODELS_PATH: Final[str] = "/gemini/v1beta/models"
OLLAMA_TAGS_PATH: Final[str] = "/ollama/api/tags"

_HTTP_OK: Final[int] = 200
_HTTP_UNAUTHORIZED: Final[int] = 401
_HTTP_NOT_FOUND: Final[int] = 404
_SHUTDOWN_JOIN_SECONDS: Final[float] = 5.0


@dataclass(frozen=True)
class RecordedRequest:
    """One request received by :class:`ProviderEndpointServer`.

    Attributes:
        method: HTTP method.
        path: Request path without the query string.
        headers: Request headers keyed by lower-cased header name.
    """

    method: str
    path: str
    headers: dict[str, str]


def _openai_models_body(model_ids: Sequence[str]) -> bytes:
    """Build an OpenAI-compatible ``GET /models`` response body.

    Args:
        model_ids: Model identifiers to list.

    Returns:
        bytes: UTF-8 JSON body.
    """
    data = [{"id": model_id, "object": "model", "created": 1_700_000_000, "owned_by": "loopback"} for model_id in model_ids]
    return json.dumps({"object": "list", "data": data}).encode()


def _anthropic_models_body(model_ids: Sequence[str]) -> bytes:
    """Build an Anthropic ``GET /v1/models`` response body.

    Args:
        model_ids: Model identifiers to list.

    Returns:
        bytes: UTF-8 JSON body.
    """
    data = [{"id": model_id, "type": "model", "display_name": model_id, "created_at": "2025-11-01T00:00:00Z"} for model_id in model_ids]
    return json.dumps(
        {
            "data": data,
            "has_more": False,
            "first_id": model_ids[0] if model_ids else None,
            "last_id": model_ids[-1] if model_ids else None,
        },
    ).encode()


def _gemini_models_body(model_ids: Sequence[str]) -> bytes:
    """Build a Gemini ``GET /v1beta/models`` response body.

    Args:
        model_ids: Model identifiers to list.

    Returns:
        bytes: UTF-8 JSON body.
    """
    models = [
        {
            "name": f"models/{model_id}",
            "displayName": model_id,
            "inputTokenLimit": 1_048_576,
            "outputTokenLimit": 65_536,
            "supportedGenerationMethods": ["generateContent"],
        }
        for model_id in model_ids
    ]
    return json.dumps({"models": models}).encode()


def _ollama_tags_body(model_ids: Sequence[str]) -> bytes:
    """Build an Ollama ``GET /api/tags`` response body.

    Args:
        model_ids: Model names to list.

    Returns:
        bytes: UTF-8 JSON body.
    """
    models = [
        {
            "name": model_id,
            "model": model_id,
            "modified_at": "2026-01-01T00:00:00Z",
            "size": 1024,
            "digest": "0" * 64,
            "details": {"family": "loopback", "parameter_size": "1B", "quantization_level": "Q4_0"},
        }
        for model_id in model_ids
    ]
    return json.dumps({"models": models}).encode()


def _unauthorized_body(message: str) -> bytes:
    """Build a provider-style authentication error body.

    Args:
        message: Error message to embed.

    Returns:
        bytes: UTF-8 JSON body understood by the OpenAI and Anthropic SDKs.
    """
    return json.dumps(
        {
            "type": "error",
            "error": {"type": "authentication_error", "message": message, "code": "invalid_api_key"},
        },
    ).encode()


class ProviderEndpointServer:
    """Loopback server answering provider model-listing requests.

    Attributes:
        accepted_key: The only API key the authenticated endpoints accept.
        model_ids: Model identifiers every endpoint lists.
    """

    accepted_key: str
    model_ids: tuple[str, ...]

    def __init__(self, *, accepted_key: str, model_ids: Sequence[str]) -> None:
        """Start serving on an ephemeral loopback port.

        Args:
            accepted_key: The only API key the authenticated endpoints accept.
            model_ids: Model identifiers every endpoint lists.
        """
        self.accepted_key = accepted_key
        self.model_ids = tuple(model_ids)
        self._requests: list[RecordedRequest] = []
        self._lock = threading.Lock()
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                """Record the request and answer it in the matching provider dialect."""
                path = urlsplit(self.path).path
                headers = {name.lower(): value for name, value in self.headers.items()}
                server.record(RecordedRequest(method="GET", path=path, headers=headers))
                status, body = server.respond(path, headers)
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                _ = self.wfile.write(body)

            def log_message(self, *args: object, **kwargs: object) -> None:
                """Suppress the default stderr request logging.

                Args:
                    *args: Positional log arguments (unused).
                    **kwargs: Keyword log arguments (unused).
                """

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="provider-endpoint-server", daemon=True)
        self._thread.start()

    @property
    def origin(self) -> str:
        """The server origin, for example ``http://127.0.0.1:50123``.

        Returns:
            str: Scheme, host and port without a trailing slash.
        """
        host, port = self._server.server_address[0], self._server.server_address[1]
        return f"http://{host!s}:{port}"

    @property
    def openai_compatible_base_url(self) -> str:
        """Base URL for OpenAI-compatible clients (OpenAI, Grok, OpenRouter, gateways).

        Returns:
            str: Base URL whose ``/models`` child this server answers.
        """
        return f"{self.origin}/api/v1"

    @property
    def anthropic_base_url(self) -> str:
        """Base URL for the Anthropic SDK client.

        Returns:
            str: Base URL whose ``/v1/models`` child this server answers.
        """
        return f"{self.origin}/anthropic"

    @property
    def gemini_base_url(self) -> str:
        """Base URL for the google-genai client.

        Returns:
            str: Base URL whose ``/v1beta/models`` child this server answers.
        """
        return f"{self.origin}/gemini"

    @property
    def ollama_base_url(self) -> str:
        """Base URL for an Ollama host.

        Returns:
            str: Base URL whose ``/api/tags`` child this server answers.
        """
        return f"{self.origin}/ollama"

    def record(self, request: RecordedRequest) -> None:
        """Store a received request.

        Args:
            request: The request to store.
        """
        with self._lock:
            self._requests.append(request)

    def requests(self, path: str | None = None) -> list[RecordedRequest]:
        """Return a snapshot of received requests.

        Args:
            path: Only return requests for this exact path when given.

        Returns:
            list[RecordedRequest]: Requests in arrival order.
        """
        with self._lock:
            snapshot = list(self._requests)
        return snapshot if path is None else [request for request in snapshot if request.path == path]

    def respond(self, path: str, headers: dict[str, str]) -> tuple[int, bytes]:
        """Compute the response for a request.

        Args:
            path: Request path without the query string.
            headers: Request headers keyed by lower-cased name.

        Returns:
            tuple[int, bytes]: HTTP status code and JSON body.
        """
        if path == OLLAMA_TAGS_PATH:
            return _HTTP_OK, _ollama_tags_body(self.model_ids)
        if path == OPENAI_COMPATIBLE_MODELS_PATH:
            return self._authorized(
                accepted=headers.get("authorization") == f"Bearer {self.accepted_key}",
                body_builder=_openai_models_body,
            )
        if path == ANTHROPIC_MODELS_PATH:
            return self._authorized(accepted=headers.get("x-api-key") == self.accepted_key, body_builder=_anthropic_models_body)
        if path == GEMINI_MODELS_PATH:
            return self._authorized(accepted=headers.get("x-goog-api-key") == self.accepted_key, body_builder=_gemini_models_body)
        return _HTTP_NOT_FOUND, json.dumps({"error": {"message": f"no route for {path}"}}).encode()

    def _authorized(self, *, accepted: bool, body_builder: Callable[[Sequence[str]], bytes]) -> tuple[int, bytes]:
        """Answer an authenticated endpoint.

        Args:
            accepted: Whether the request presented the accepted key.
            body_builder: Builds the success body from the model identifiers.

        Returns:
            tuple[int, bytes]: ``200`` with the listing, or ``401`` with an error body.
        """
        if not accepted:
            return _HTTP_UNAUTHORIZED, _unauthorized_body("Incorrect API key provided")
        return _HTTP_OK, body_builder(self.model_ids)

    def shutdown(self) -> None:
        """Stop serving and release the port."""
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=_SHUTDOWN_JOIN_SECONDS)

    def __enter__(self) -> Self:
        """Enter the context manager.

        Returns:
            Self: This running server.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Shut the server down when leaving the context manager.

        Args:
            exc_type: Exception type raised inside the block, if any.
            exc_value: Exception raised inside the block, if any.
            traceback: Traceback of that exception, if any.
        """
        self.shutdown()
