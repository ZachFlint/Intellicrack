# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for cross-event-loop HTTP client handling.

Providers backed by a raw ``httpx.AsyncClient`` (OpenRouter and Ollama)
connect on the application bootstrap event loop but run model discovery
and chat traffic on the persistent background bridge loop. httpcore binds
a connection pool's internal asyncio synchronization primitives to the
loop on which the client first issues a request, so reusing that client
from a different running loop raises ``RuntimeError: ... is bound to a
different event loop``.

These tests reproduce the connect-loop to discovery-loop transition
against a local stub HTTP server (no network, no API keys) and assert
that each provider transparently rebinds its client to the active loop.
They also assert that the discovery layer reports ``ProviderError`` (the
documented ``list_models`` failure type) as a failed discovery event
instead of letting it escape.
"""

from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self, cast

from intellicrack.core.types import ProviderCredentials
from intellicrack.providers.discovery import ModelDiscovery
from intellicrack.providers.ollama import OllamaProvider
from intellicrack.providers.openrouter import OpenRouterProvider
from intellicrack.providers.registry import ProviderRegistry


_Route = tuple[int, dict[str, Any]]

_OPENROUTER_MODELS: dict[str, Any] = {
    "data": [
        {
            "id": "openai/gpt-4o",
            "name": "GPT-4o",
            "context_length": 128000,
            "pricing": {"prompt": "0.000005", "completion": "0.000015"},
            "architecture": {"modality": "text+image"},
            "supported_parameters": ["tools", "tool_choice"],
        },
        {
            "id": "anthropic/claude-3.5-sonnet",
            "name": "Claude 3.5 Sonnet",
            "context_length": 200000,
            "pricing": {"prompt": "0.000003", "completion": "0.000015"},
            "architecture": {"modality": "text"},
            "supported_parameters": ["tools"],
        },
    ],
}

_OLLAMA_TAGS: dict[str, Any] = {"models": [{"name": "llama3.1:8b"}]}
_OLLAMA_SHOW: dict[str, Any] = {
    "parameters": "num_ctx                        8192",
    "template": "{{ if .Tools }}{{ .Tools }}{{ end }}{{ .Prompt }}",
}

_LOOP_JOIN_TIMEOUT = 5.0


class _StubHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying canned per-route responses.

    Attributes:
        routes: Mapping of ``(method, path)`` to an ordered list of
            ``(status_code, json_body)`` responses. Each request consumes
            the next response in the list; the final entry repeats for any
            further requests to the same route.
        call_counts: Mapping of ``(method, path)`` to the number of times
            that route has been served, used to advance through ``routes``.
    """

    routes: dict[tuple[str, str], list[_Route]]
    call_counts: dict[tuple[str, str], int]

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        routes: dict[tuple[str, str], list[_Route]],
    ) -> None:
        """Initialize the stub server with its route table.

        Args:
            server_address: ``(host, port)`` to bind; port ``0`` selects
                an ephemeral free port.
            handler: Request handler class to instantiate per request.
            routes: Mapping of ``(method, path)`` to ordered responses.
        """
        super().__init__(server_address, handler)
        self.routes = routes
        self.call_counts = {}
        self._counts_lock = threading.Lock()

    def next_response(self, method: str, path: str) -> _Route | None:
        """Return the next canned response for a route, advancing its cursor.

        Args:
            method: HTTP method of the request (``"GET"`` or ``"POST"``).
            path: Request path including any query string-free URI.

        Returns:
            _Route | None: The ``(status_code, json_body)`` tuple to send,
            or ``None`` when the route is not registered.
        """
        key = (method, path)
        responses = self.routes.get(key)
        if not responses:
            return None
        with self._counts_lock:
            index = self.call_counts.get(key, 0)
            self.call_counts[key] = index + 1
        return responses[min(index, len(responses) - 1)]


class _StubHandler(BaseHTTPRequestHandler):
    """Request handler that serves canned JSON from the stub server."""

    def _respond(self, method: str) -> None:
        """Serve the next canned response for the current request.

        Args:
            method: HTTP method of the request being handled.
        """
        if content_length := int(self.headers.get("Content-Length") or 0):
            _ = self.rfile.read(content_length)

        server = cast("_StubHTTPServer", self.server)
        response = server.next_response(method, self.path)
        if response is None:
            self.send_error(404)
            return

        status, body = response
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        _ = self.wfile.write(payload)

    def do_GET(self) -> None:
        """Handle a GET request by serving the next canned response."""
        self._respond("GET")

    def do_POST(self) -> None:
        """Handle a POST request by serving the next canned response."""
        self._respond("POST")


class _StubServer:
    """Context manager running a :class:`_StubHTTPServer` in a thread."""

    def __init__(self, routes: dict[tuple[str, str], list[_Route]]) -> None:
        """Create the server bound to an ephemeral localhost port.

        Args:
            routes: Mapping of ``(method, path)`` to ordered responses.
        """
        self._server = _StubHTTPServer(("127.0.0.1", 0), _StubHandler, routes)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        """Start serving in the background thread.

        Returns:
            Self: This server instance.
        """
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Stop the server and join its background thread.

        Args:
            *exc_info: Exception type, value, and traceback (unused).
        """
        _ = exc_info
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=_LOOP_JOIN_TIMEOUT)

    @property
    def base_url(self) -> str:
        """The ``http://host:port`` base URL for the bound server.

        Returns:
            str: The base URL clients should target.
        """
        host, port = cast("tuple[str, int]", self._server.server_address)
        return f"http://{host}:{port}"


class _TempEventLoop:
    """Context manager providing a fresh event loop, closed on exit.

    Each ``with`` block models one phase (connect or discovery) running on
    its own event loop, reproducing the bootstrap-loop to bridge-loop
    transition that triggers the cross-loop client-binding failure.
    """

    def __init__(self) -> None:
        """Initialize the context manager without an active loop."""
        self._loop: asyncio.AbstractEventLoop | None = None

    def __enter__(self) -> asyncio.AbstractEventLoop:
        """Create and return a fresh event loop.

        Returns:
            asyncio.AbstractEventLoop: A new event loop for this phase.
        """
        self._loop = asyncio.new_event_loop()
        return self._loop

    def __exit__(self, *exc_info: object) -> None:
        """Close the event loop created in :meth:`__enter__`.

        Args:
            *exc_info: Exception type, value, and traceback (unused).
        """
        _ = exc_info
        if self._loop is not None:
            self._loop.close()


class TestOpenRouterLoopRebind:
    """Cross-event-loop behaviour of :class:`OpenRouterProvider`."""

    @staticmethod
    def test_list_models_succeeds_across_event_loops() -> None:
        """list_models on a different loop rebinds the client and succeeds.

        Without the rebind, reusing the connect-loop client on the
        discovery loop raises ``RuntimeError: ... bound to a different
        event loop`` before any request is issued.
        """
        routes = {("GET", "/api/v1/models"): [(200, _OPENROUTER_MODELS)]}
        with (
            _StubServer(routes) as server,
            _TempEventLoop() as connect_loop,
            _TempEventLoop() as discovery_loop,
        ):
            provider = OpenRouterProvider()
            credentials = ProviderCredentials(api_key="test-key", api_base=f"{server.base_url}/api/v1")

            connect_loop.run_until_complete(provider.connect(credentials))
            client_before = provider.client
            assert client_before is not None

            models = discovery_loop.run_until_complete(provider.list_models())

            assert len(models) == len(_OPENROUTER_MODELS["data"])
            assert provider.client is not client_before
            discovery_loop.run_until_complete(provider.disconnect())

    @staticmethod
    def test_same_loop_does_not_rebind() -> None:
        """Reuse on the same loop must not rebuild the client needlessly."""
        routes = {("GET", "/api/v1/models"): [(200, _OPENROUTER_MODELS)]}
        with _StubServer(routes) as server, _TempEventLoop() as loop:
            provider = OpenRouterProvider()
            credentials = ProviderCredentials(api_key="test-key", api_base=f"{server.base_url}/api/v1")

            loop.run_until_complete(provider.connect(credentials))
            client_before = provider.client

            models = loop.run_until_complete(provider.list_models())

            assert models
            assert provider.client is client_before
            loop.run_until_complete(provider.disconnect())


class TestOllamaLoopRebind:
    """Cross-event-loop behaviour of :class:`OllamaProvider`."""

    @staticmethod
    def test_list_models_succeeds_across_event_loops() -> None:
        """Local list_models on a different loop rebinds the client.

        Mirrors the OpenRouter scenario for Ollama's local client, which
        is also a raw ``httpx.AsyncClient`` created during connect.
        """
        routes = {
            ("GET", "/api/tags"): [(200, _OLLAMA_TAGS)],
            ("POST", "/api/show"): [(200, _OLLAMA_SHOW)],
        }
        with (
            _StubServer(routes) as server,
            _TempEventLoop() as connect_loop,
            _TempEventLoop() as discovery_loop,
        ):
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)

            connect_loop.run_until_complete(provider.connect(credentials))
            assert provider.local_available
            local_client_before = getattr(provider, "_local_client")
            assert local_client_before is not None

            models = discovery_loop.run_until_complete(provider.list_models())

            assert models, "expected at least one local model"
            assert all(model.id.startswith("local/") for model in models)
            assert models[0].context_window == 8192
            assert models[0].supports_tools is True
            assert getattr(provider, "_local_client") is not local_client_before
            discovery_loop.run_until_complete(provider.disconnect())


class TestDiscoveryProviderErrorHandling:
    """Discovery layer resilience to ``ProviderError`` from list_models."""

    @staticmethod
    def _stub_credentials(base_url: str) -> ProviderCredentials:
        """Return credentials pointing OpenRouter at the stub server.

        Paired with a stub that answers the connect probe with HTTP 200
        and the subsequent discovery request with HTTP 401, so
        ``list_models`` raises a ``ProviderError`` after a successful
        connect.

        Args:
            base_url: Base URL of the running stub server.

        Returns:
            ProviderCredentials: Credentials whose ``api_base`` targets the
            stub's OpenRouter-compatible endpoint.
        """
        return ProviderCredentials(api_key="test-key", api_base=f"{base_url}/api/v1")

    def test_discover_provider_handles_provider_error(self) -> None:
        """discover_provider returns [] instead of propagating ProviderError."""
        routes = {
            ("GET", "/api/v1/models"): [
                (200, _OPENROUTER_MODELS),
                (401, {"error": {"message": "Invalid API key"}}),
            ],
        }
        with _StubServer(routes) as server:
            provider = OpenRouterProvider()
            registry = ProviderRegistry()
            discovery = ModelDiscovery(registry)

            with _TempEventLoop() as loop:
                loop.run_until_complete(provider.connect(self._stub_credentials(server.base_url)))
                registry.register(provider)

                models = loop.run_until_complete(
                    discovery.discover_provider(provider.name, use_cache=False),
                )

                assert models == []
                loop.run_until_complete(provider.disconnect())

    def test_discover_all_records_failed_event_for_provider_error(self) -> None:
        """discover_all records a failed event rather than crashing."""
        routes = {
            ("GET", "/api/v1/models"): [
                (200, _OPENROUTER_MODELS),
                (401, {"error": {"message": "Invalid API key"}}),
            ],
        }
        with _StubServer(routes) as server:
            provider = OpenRouterProvider()
            registry = ProviderRegistry()
            discovery = ModelDiscovery(registry)

            with _TempEventLoop() as loop:
                loop.run_until_complete(provider.connect(self._stub_credentials(server.base_url)))
                registry.register(provider)

                results = loop.run_until_complete(discovery.discover_all(use_cache=False))

                assert results.get(provider.name) == []
                events = discovery.get_discovery_events()
                assert any(event.provider == provider.name and not event.success for event in events)
                loop.run_until_complete(provider.disconnect())
