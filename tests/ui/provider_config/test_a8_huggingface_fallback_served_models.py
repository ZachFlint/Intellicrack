# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression test for the HuggingFace model-dropdown fallback served-model gap (A8 / S16-D03 residual).

``HuggingFaceProvider.list_models`` (``src/intellicrack/providers/huggingface.py``)
already intersects the Hub text-generation catalog against the HuggingFace
Inference Providers router's own served-model set, fetched from ``GET
{ROUTER_BASE_URL}/v1/models``. But ``ModelRefreshWorker._fetch_huggingface_models``
(``src/intellicrack/ui/provider_config.py``) -- the fallback the provider-config
dialog uses whenever it refreshes the HuggingFace model dropdown without a
connected provider instance -- queried only the general Hub search API and
returned every Hub-tagged model regardless of whether any Inference Provider
actually served it for chat completion.

The fix factors the served-id fetch into one shared helper,
``intellicrack.providers.huggingface.fetch_router_served_model_ids``, used by
both ``HuggingFaceProvider._fetch_served_model_ids`` and this dialog fallback,
and has the fallback intersect its Hub catalog against that shared helper's
result before returning models to the dropdown.

This test stands up a real local stdlib HTTP server that serves both the Hub
catalog endpoint (a strict superset) and the router served-model endpoint (a
smaller subset), points the fallback at it, and asserts the fallback returns
exactly the intersection -- specifically that a catalog model absent from the
served set is excluded. It also covers the router-unreachable degradation
path: the fallback must fail cleanly instead of hanging or raising, and must
never fall back to returning the unfiltered (and potentially unservable)
catalog.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, cast

import httpx
import pytest

from intellicrack.ui.provider_config import ModelRefreshWorker


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from PyQt6.QtWidgets import QApplication


_SERVED_MODEL_A = "intellicrack-test-org/served-model-a"
_SERVED_MODEL_B = "intellicrack-test-org/served-model-b"
_UNSERVED_MODEL_C = "intellicrack-test-org/unserved-model-c"

_CATALOG_PAYLOAD: list[dict[str, str]] = [
    {"id": _SERVED_MODEL_A, "pipeline_tag": "text-generation"},
    {"id": _SERVED_MODEL_B, "pipeline_tag": "conversational"},
    {"id": _UNSERVED_MODEL_C, "pipeline_tag": "text-generation"},
]
_SERVED_PAYLOAD: dict[str, object] = {
    "object": "list",
    "data": [
        {"id": _SERVED_MODEL_A, "object": "model"},
        {"id": _SERVED_MODEL_B, "object": "model"},
    ],
}


class _CatalogAndRouterHandler(BaseHTTPRequestHandler):
    """Serves the Hub catalog superset at ``/api/models`` and the router served-model subset at ``/v1/models``."""

    def do_GET(self) -> None:
        """Respond to the Hub-catalog and router served-model endpoints with fixed JSON bodies."""
        path = self.path.split("?", 1)[0]
        if path == "/api/models":
            body = json.dumps(_CATALOG_PAYLOAD).encode("utf-8")
        elif path == "/v1/models":
            body = json.dumps(_SERVED_PAYLOAD).encode("utf-8")
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, log_format: str, *log_args: object) -> None:
        """Suppress the default per-request stderr logging.

        Args:
            log_format: printf-style log format string (stdlib handler signature).
            *log_args: Values to interpolate into ``log_format``.
        """
        del log_format, log_args


def _bind_and_release_free_port() -> int:
    """Reserve then immediately release a free TCP port on localhost.

    Returns:
        int: A port number nothing is listening on immediately after this
        call returns, so a connection attempt fails fast with a real
        connection-refused error instead of hanging.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return cast("int", probe.getsockname()[1])


def _fetch_huggingface_models(
    worker: ModelRefreshWorker,
    timeout: httpx.Timeout,
) -> tuple[bool, list[str], str]:
    """Invoke the private ``ModelRefreshWorker._fetch_huggingface_models`` without a dotted private-attribute access.

    Args:
        worker: The worker instance under test.
        timeout: HTTP timeout configuration to pass through.

    Returns:
        tuple[bool, list[str], str]: The (success, model_list, message) result.
    """
    method: object = getattr(worker, "_fetch_huggingface_models")
    fn = cast("Callable[[httpx.Timeout], tuple[bool, list[str], str]]", method)
    return fn(timeout)


@pytest.fixture
def catalog_and_router_server() -> Iterator[int]:
    """Start a real local HTTP server serving both the Hub catalog and router served-model endpoints.

    Yields:
        int: The TCP port the server listens on at ``127.0.0.1``.
    """
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CatalogAndRouterHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5.0)


@pytest.fixture
def redirect_hub_catalog_to(monkeypatch: pytest.MonkeyPatch) -> Callable[[int], None]:
    """Return a function that redirects the fallback's hardcoded Hub-catalog URL to a local port.

    ``ModelRefreshWorker._fetch_huggingface_models`` queries the real Hub
    catalog at a hardcoded ``https://huggingface.co/api/models`` URL that
    takes no override parameter -- unlike the router served-model query,
    which already accepts a base URL. Redirecting at the ``httpx.Client.get``
    boundary (rather than mocking the fallback's return value) keeps the
    test exercising the real HTTP request/response/JSON-decode path end to
    end against a real local server, for the one call site whose target
    host is not independently configurable.

    Args:
        monkeypatch: Pytest's monkeypatch fixture.

    Returns:
        Callable[[int], None]: Call with the local server's port to activate the redirect.
    """
    original_get = httpx.Client.get

    def _activate(port: int) -> None:
        """Install the redirect for the given local server port.

        Args:
            port: The local server's TCP port on ``127.0.0.1``.
        """
        catalog_url = f"http://127.0.0.1:{port}/api/models"

        def _redirecting_get(
            self: httpx.Client,
            url: httpx.URL | str,
            *args: object,
            **kwargs: object,
        ) -> httpx.Response:
            """Redirect the hardcoded Hub-catalog URL to the local test server.

            Args:
                self: The ``httpx.Client`` instance the call was made on.
                url: The request URL, redirected when it targets the real Hub catalog.
                *args: Additional positional arguments forwarded unchanged.
                **kwargs: Additional keyword arguments forwarded unchanged.

            Returns:
                httpx.Response: The real response from whichever URL was requested.
            """
            target = catalog_url if str(url) == "https://huggingface.co/api/models" else url
            return original_get(self, target, *args, **kwargs)

        monkeypatch.setattr(httpx.Client, "get", _redirecting_get)

    return _activate


class TestHuggingFaceFallbackHonorsServedModelsContract:
    """The disconnected-provider fallback must intersect the Hub catalog against the router's served set."""

    @staticmethod
    def test_catalog_model_absent_from_served_set_is_excluded(
        qapp: QApplication,
        catalog_and_router_server: int,
        redirect_hub_catalog_to: Callable[[int], None],
    ) -> None:
        """A Hub-catalog model the router does not serve must not appear in the fallback's result.

        Args:
            qapp: Session-scoped Qt application fixture (the worker under
                test is a ``QThread`` subclass).
            catalog_and_router_server: Port of the real local test server.
            redirect_hub_catalog_to: Activates the Hub-catalog URL redirect.
        """
        del qapp
        port = catalog_and_router_server
        redirect_hub_catalog_to(port)

        worker = ModelRefreshWorker(
            "huggingface",
            "test-token",
            f"http://127.0.0.1:{port}",
            provider=None,
            parent=None,
        )

        success, models, message = _fetch_huggingface_models(worker, httpx.Timeout(5.0))

        assert success, f"expected the fallback to succeed, got failure message: {message!r}"
        assert set(models) == {_SERVED_MODEL_A, _SERVED_MODEL_B}, (
            f"the fallback must return exactly the router-served intersection of the Hub catalog, got: {models}"
        )
        assert _UNSERVED_MODEL_C not in models, (
            f"a catalog model absent from the router's served-model set must be excluded, but it was present in: {models}"
        )

    @staticmethod
    def test_router_unreachable_degrades_gracefully(
        qapp: QApplication,
        catalog_and_router_server: int,
        redirect_hub_catalog_to: Callable[[int], None],
    ) -> None:
        """The refresh must fail cleanly, not hang or raise, when the router is unreachable.

        Args:
            qapp: Session-scoped Qt application fixture.
            catalog_and_router_server: Port of the real local test server (Hub catalog side).
            redirect_hub_catalog_to: Activates the Hub-catalog URL redirect.
        """
        del qapp
        port = catalog_and_router_server
        redirect_hub_catalog_to(port)
        closed_port = _bind_and_release_free_port()

        worker = ModelRefreshWorker(
            "huggingface",
            "test-token",
            f"http://127.0.0.1:{closed_port}",
            provider=None,
            parent=None,
        )

        success, models, message = _fetch_huggingface_models(worker, httpx.Timeout(5.0))

        assert success is False, "an unreachable router must not report success"
        assert models == [], "an unreachable router must never fall back to the unfiltered Hub catalog"
        assert message, "the failure must carry an explanatory message"
