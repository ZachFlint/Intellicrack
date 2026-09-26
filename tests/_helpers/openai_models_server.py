# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Loopback OpenAI-compatible model-listing server for provider-instance tests.

Serves the one request a model refresh, a connection test and
:meth:`ConfigurableProvider.list_models` make against an OpenAI-compatible
endpoint -- ``GET <base>/models`` -- in the real OpenAI wire format. Unlike
:class:`tests._helpers.provider_endpoint_server.ProviderEndpointServer` it can
run keyless, the way vLLM, LM Studio and a LiteLLM proxy do, and it also
answers as a plain HTTP forward proxy (absolute-URI request targets), so a test
can route a request addressed to a *public* plain-HTTP host to loopback and
observe exactly which headers would have left the machine.

Routes (by request path, whatever host the request names):

* ``/v1/models`` -- the model list; ``401`` when a key is required and the
  request does not carry it as ``Authorization: Bearer <key>``.
* ``/broken/v1/models`` -- ``500``, for a provider whose own listing fails.
* anything else -- ``404``.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Final, Self
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from collections.abc import Sequence
    from types import TracebackType


MODELS_PATH: Final[str] = "/v1/models"
BROKEN_MODELS_PATH: Final[str] = "/broken/v1/models"

_HTTP_OK: Final[int] = 200
_HTTP_UNAUTHORIZED: Final[int] = 401
_HTTP_NOT_FOUND: Final[int] = 404
_HTTP_SERVER_ERROR: Final[int] = 500
_SHUTDOWN_JOIN_SECONDS: Final[float] = 5.0


@dataclass(frozen=True)
class ModelsRequest:
    """One request the server received.

    Attributes:
        target: The raw request target, absolute when the request came through
            the server acting as a proxy.
        path: The request path without the query string.
        headers: Request headers keyed by lower-cased name.
    """

    target: str
    path: str
    headers: dict[str, str]


class OpenAIModelsServer:
    """Loopback OpenAI-compatible ``GET /models`` endpoint and forward proxy.

    Attributes:
        accepted_key: The only key accepted, or ``None`` for a keyless endpoint.
        model_ids: Model identifiers the listing returns.
    """

    accepted_key: str | None
    model_ids: tuple[str, ...]

    def __init__(self, *, model_ids: Sequence[str], accepted_key: str | None = None) -> None:
        """Start serving on an ephemeral loopback port.

        Args:
            model_ids: Model identifiers the listing returns.
            accepted_key: The only key accepted, or ``None`` for a keyless endpoint.
        """
        self.accepted_key = accepted_key
        self.model_ids = tuple(model_ids)
        self._requests: list[ModelsRequest] = []
        self._lock = threading.Lock()
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                """Record the request and answer it."""
                headers = {name.lower(): value for name, value in self.headers.items()}
                request = ModelsRequest(target=self.path, path=urlsplit(self.path).path, headers=headers)
                server.record(request)
                status, body = server.respond(request)
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
        self._thread = threading.Thread(target=self._server.serve_forever, name="openai-models-server", daemon=True)
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
    def base_url(self) -> str:
        """Base URL whose ``/models`` child lists the models.

        Returns:
            str: ``<origin>/v1``.
        """
        return f"{self.origin}/v1"

    @property
    def broken_base_url(self) -> str:
        """Base URL whose ``/models`` child fails with ``500``.

        Returns:
            str: ``<origin>/broken/v1``.
        """
        return f"{self.origin}/broken/v1"

    def record(self, request: ModelsRequest) -> None:
        """Store a received request.

        Args:
            request: The request to store.
        """
        with self._lock:
            self._requests.append(request)

    def requests(self) -> list[ModelsRequest]:
        """Return a snapshot of received requests.

        Returns:
            list[ModelsRequest]: Requests in arrival order.
        """
        with self._lock:
            return list(self._requests)

    def respond(self, request: ModelsRequest) -> tuple[int, bytes]:
        """Compute the response for a request.

        Args:
            request: The received request.

        Returns:
            tuple[int, bytes]: HTTP status code and JSON body.
        """
        if request.path == BROKEN_MODELS_PATH:
            return _HTTP_SERVER_ERROR, json.dumps({"error": {"message": "listing unavailable"}}).encode()
        if request.path != MODELS_PATH:
            return _HTTP_NOT_FOUND, json.dumps({"error": {"message": f"no route for {request.path}"}}).encode()
        if self.accepted_key is not None and request.headers.get("authorization") != f"Bearer {self.accepted_key}":
            return _HTTP_UNAUTHORIZED, json.dumps({"error": {"message": "Incorrect API key provided", "code": "invalid_api_key"}}).encode()
        data = [{"id": model_id, "object": "model", "created": 1_700_000_000, "owned_by": "loopback"} for model_id in self.model_ids]
        return _HTTP_OK, json.dumps({"object": "list", "data": data}).encode()

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
            exc_type: Exception type raised in the ``with`` block, if any.
            exc_value: Exception raised in the ``with`` block, if any.
            traceback: Traceback of that exception, if any.
        """
        self.shutdown()
