# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression tests for S16-D09: Ollama discovery loop-rebind after Set-Active + Pull.

After Set-Active(Ollama) followed by a model Pull, background model discovery
would intermittently drop a model from the list and log ``discovery_failed
provider=ollama`` immediately after an ``ollama_local_client_rebound`` /
``ollama_cloud_client_rebound`` debug line, with the underlying cause being
``RuntimeError: <asyncio.locks.Event object at ...> is bound to a different
event loop``.

The root cause was a check-then-use race in
:meth:`~intellicrack.providers.ollama.OllamaProvider._ensure_clients_on_loop`.
Ollama's bootstrap connect, a long-running ``pull_model`` stream, and
background model discovery each run on their own event loop (and often their
own OS thread: bootstrap loop, persistent bridge loop, dedicated pull
stream). The old implementation rebuilt ``self._local_client`` /
``self._cloud_client`` in place and returned nothing; every call site then
re-read those instance attributes *after* calling
``_ensure_clients_on_loop()``. Because that second read was not protected by
anything, a concurrent caller on a different loop could rebind the shared
attributes in between, leaving the first caller to issue its request through
an ``httpx.AsyncClient`` whose connection-pool internals (including an
``asyncio.Event`` used by httpcore to signal an acquired connection) were
never established for its own loop.

The fix makes ``_ensure_clients_on_loop`` return the exact client references
valid for the *calling* coroutine's loop, computed under
``self._client_rebind_lock`` (a :class:`threading.Lock`, since the racing
callers can be on different OS threads and ``asyncio.Lock`` is itself
loop-bound), and updates every call site (``list_models``, ``_fetch_local_models``,
``_fetch_cloud_models``, ``_get_source_client``, ``_get_client_and_model``,
``pull_model``, ``_iter_pull_progress``) to thread that returned reference
through rather than re-reading the mutable instance attributes.

These tests reproduce the vulnerable window deterministically (no timing-
dependent thread races, which proved unreliable against real httpcore
internals during investigation) by simulating the worst case a concurrent
rebind can produce: another caller nukes ``self._local_client`` /
``self._cloud_client`` to ``None`` immediately after
``_ensure_clients_on_loop`` returns a value to the current caller. Against
the pre-fix implementation (verified against the pre-fix source during
investigation) this reproduces the exact failure class -- ``pull_model``
raises ``ProviderError`` and ``list_models`` returns an incomplete result --
because those call sites re-read the now-``None`` attribute. Against the
fixed implementation both complete successfully because they use the value
``_ensure_clients_on_loop`` returned to them.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self, cast

import pytest

from intellicrack.core.types import ProviderCredentials
from intellicrack.providers.ollama import OllamaProvider


_Route = tuple[int, dict[str, Any]]

_OLLAMA_TAGS: dict[str, Any] = {"models": [{"name": "llama3.1:8b"}]}
_OLLAMA_SHOW: dict[str, Any] = {
    "parameters": "num_ctx                        8192",
    "template": "{{ if .Tools }}{{ .Tools }}{{ end }}{{ .Prompt }}",
}
_PULL_STATUS_LINES: tuple[str, ...] = ("pulling manifest", "success")

_LOOP_JOIN_TIMEOUT = 5.0
_EVENT_BIND_TIMEOUT = 0.05


class _StubHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying canned per-route responses.

    Attributes:
        routes: Mapping of ``(method, path)`` to a ``(status_code, json_body)``
            response served to every request on that route.
    """

    routes: dict[tuple[str, str], _Route]

    def __init__(
        self,
        server_address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        routes: dict[tuple[str, str], _Route],
    ) -> None:
        """Initialize the stub server with its route table.

        Args:
            server_address: ``(host, port)`` to bind; port ``0`` selects an
                ephemeral free port.
            handler: Request handler class to instantiate per request.
            routes: Mapping of ``(method, path)`` to the response served.
        """
        super().__init__(server_address, handler)
        self.routes = routes


class _StubHandler(BaseHTTPRequestHandler):
    """Request handler serving canned JSON, or NDJSON for ``/api/pull``."""

    def _respond_json(self, method: str) -> None:
        """Serve the canned JSON response for the current request's route.

        Args:
            method: HTTP method of the request being handled.
        """
        if content_length := int(self.headers.get("Content-Length") or 0):
            _ = self.rfile.read(content_length)

        server = cast("_StubHTTPServer", self.server)
        route = server.routes.get((method, self.path))
        if route is None:
            self.send_error(404)
            return

        status, body = route
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        _ = self.wfile.write(payload)

    def do_GET(self) -> None:
        """Handle a GET request by serving the next canned response."""
        self._respond_json("GET")

    def do_POST(self) -> None:
        """Handle a POST request, streaming NDJSON for ``/api/pull``."""
        if self.path == "/api/pull":
            if content_length := int(self.headers.get("Content-Length") or 0):
                _ = self.rfile.read(content_length)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            for status in _PULL_STATUS_LINES:
                _ = self.wfile.write((json.dumps({"status": status}) + "\n").encode())
                self.wfile.flush()
            return
        self._respond_json("POST")


class _StubServer:
    """Context manager running a :class:`_StubHTTPServer` in a thread."""

    def __init__(self, routes: dict[tuple[str, str], _Route]) -> None:
        """Create the server bound to an ephemeral localhost port.

        Args:
            routes: Mapping of ``(method, path)`` to the response served.
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
    """Context manager providing a fresh event loop, closed on exit."""

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


def _install_concurrent_rebind_wipe(provider: OllamaProvider) -> None:
    """Patch ``provider`` to simulate a concurrent rebind racing every caller.

    Replaces ``provider._ensure_clients_on_loop`` with a wrapper that calls
    the real implementation (performing the genuine per-loop rebind and
    returning the correct client references for the calling coroutine), then
    immediately clears ``self._local_client`` / ``self._cloud_client`` /
    their loop attributes to ``None``. This models the worst case of a
    concurrent caller on another loop swapping those attributes out from
    under the current caller between the ``_ensure_clients_on_loop()`` call
    and the point where its result is actually used.

    A caller that (per the fix) uses the tuple returned from
    ``_ensure_clients_on_loop()`` is unaffected. A caller that (per the
    pre-fix implementation) re-reads ``self._local_client`` /
    ``self._cloud_client`` afterward will find ``None`` and fail. Verified
    directly against the pre-fix implementation during investigation.

    Args:
        provider: The connected :class:`OllamaProvider` instance to patch.
    """
    original = getattr(OllamaProvider, "_ensure_clients_on_loop")

    def wrapper(self: OllamaProvider) -> tuple[Any, Any]:
        local_client, cloud_client = original(self)
        setattr(self, "_local_client", None)
        setattr(self, "_local_client_loop", None)
        setattr(self, "_cloud_client", None)
        setattr(self, "_cloud_client_loop", None)
        return local_client, cloud_client

    setattr(provider, "_ensure_clients_on_loop", wrapper.__get__(provider, OllamaProvider))


class TestRawEventCrossLoopFailureClass:
    """Deterministic reproduction of the exact production symptom class."""

    @staticmethod
    def test_event_created_and_awaited_on_one_loop_raises_when_awaited_on_another() -> None:
        """An asyncio.Event bound to loop A raises when awaited from loop B.

        This is the literal failure captured in the ``discovery_failed
        provider=ollama`` incident: ``RuntimeError: <asyncio.locks.Event
        object at ...> is bound to a different event loop``. An
        ``asyncio.Event`` binds to whichever running loop first calls
        ``.wait()`` on it (construction alone does not bind it); httpcore's
        connection-pool synchronization primitive (``httpcore.AsyncEvent``)
        wraps exactly this object, which is why a raw httpx client rebuilt
        in place but re-read afterward is unsafe across loops.
        """
        event = asyncio.Event()

        loop_a = asyncio.new_event_loop()

        async def _bind_on_loop_a() -> None:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(event.wait(), timeout=_EVENT_BIND_TIMEOUT)

        try:
            loop_a.run_until_complete(_bind_on_loop_a())
        finally:
            loop_a.close()

        loop_b = asyncio.new_event_loop()

        async def _wait_on_loop_b() -> None:
            await event.wait()

        try:
            with pytest.raises(RuntimeError, match="different event loop"):
                loop_b.run_until_complete(_wait_on_loop_b())
        finally:
            loop_b.close()


class TestEnsureClientsOnLoopStableAcrossConcurrentRebind:
    """The fixed ``_ensure_clients_on_loop`` returns a stable, usable reference."""

    @staticmethod
    def test_returned_local_client_remains_usable_after_concurrent_rebind() -> None:
        """A caller's captured client stays valid after another loop rebinds it.

        Simulates the exact interleaving that broke discovery: caller A
        (representing a long-running ``pull_model`` on its own loop) obtains
        a client from ``_ensure_clients_on_loop()``. Before caller A uses it,
        caller B (representing a concurrent discovery poll on a different
        loop) also calls ``_ensure_clients_on_loop()``, which rebuilds and
        overwrites ``provider._local_client`` with a *different* object.
        Caller A's captured reference must remain a distinct, still-usable
        client -- proving callers are not required to (and must not) re-read
        the mutable instance attribute after the call.
        """
        routes: dict[tuple[str, str], _Route] = {("GET", "/api/tags"): (200, _OLLAMA_TAGS)}
        with (
            _StubServer(routes) as server,
            _TempEventLoop() as connect_loop,
            _TempEventLoop() as loop_a,
            _TempEventLoop() as loop_b,
        ):
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            connect_loop.run_until_complete(provider.connect(credentials))

            async def _ensure() -> tuple[Any, Any]:
                await asyncio.sleep(0)
                return getattr(provider, "_ensure_clients_on_loop")()

            local_client_a, _cloud_client_a = loop_a.run_until_complete(_ensure())
            assert local_client_a is not None

            loop_b.run_until_complete(_ensure())
            local_client_attr = getattr(provider, "_local_client")
            assert local_client_attr is not local_client_a, (
                "test setup invalid: caller B's ensure() call did not rebind the shared attribute"
            )

            async def _use_captured_client() -> int:
                response = await local_client_a.get(f"{server.base_url}/api/tags")
                return response.status_code

            status_code = loop_a.run_until_complete(_use_captured_client())
            assert status_code == 200

            loop_b.run_until_complete(provider.disconnect())


class TestPullModelSurvivesConcurrentDiscoveryRebind:
    """Real ``pull_model`` / ``list_models`` entry points thread the client through."""

    @staticmethod
    def test_pull_model_completes_despite_concurrent_attribute_wipe() -> None:
        """pull_model uses the client _ensure_clients_on_loop returned to it.

        Installs :func:`_install_concurrent_rebind_wipe`, which -- immediately
        after ``pull_model``'s own ``_ensure_clients_on_loop()`` call returns
        -- sets ``self._local_client`` to ``None``, modeling a concurrent
        discovery caller stealing the attribute away. Verified during
        investigation that this exact scenario raises ``ProviderError:
        Local Ollama not available for model pull`` against the pre-fix
        implementation (which re-read ``self._local_client`` inside
        ``_iter_pull_progress``) and completes successfully against the fix
        (which threads the captured client through as a parameter).
        """
        routes: dict[tuple[str, str], _Route] = {("GET", "/api/tags"): (200, _OLLAMA_TAGS)}
        with _StubServer(routes) as server, _TempEventLoop() as connect_loop, _TempEventLoop() as pull_loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            connect_loop.run_until_complete(provider.connect(credentials))

            _install_concurrent_rebind_wipe(provider)

            async def _run_pull() -> list[str]:
                return [status async for status in provider.pull_model("llama3.1:8b")]

            statuses = pull_loop.run_until_complete(_run_pull())

            assert statuses == list(_PULL_STATUS_LINES)
            pull_loop.run_until_complete(provider.disconnect())

    @staticmethod
    def test_list_models_completes_despite_concurrent_attribute_wipe() -> None:
        """list_models uses the client _ensure_clients_on_loop returned to it.

        Mirrors the pull_model regression for the discovery path itself --
        the exact call that logged ``discovery_failed provider=ollama`` and
        dropped a model from the 8/8 result set in the field incident.
        """
        routes: dict[tuple[str, str], _Route] = {
            ("GET", "/api/tags"): (200, _OLLAMA_TAGS),
            ("POST", "/api/show"): (200, _OLLAMA_SHOW),
        }
        with _StubServer(routes) as server, _TempEventLoop() as connect_loop, _TempEventLoop() as discovery_loop:
            provider = OllamaProvider()
            credentials = ProviderCredentials(api_key=None, api_base=server.base_url)
            connect_loop.run_until_complete(provider.connect(credentials))

            _install_concurrent_rebind_wipe(provider)

            models = discovery_loop.run_until_complete(provider.list_models())

            assert len(models) == len(_OLLAMA_TAGS["models"])
            assert models[0].id == "local/llama3.1:8b"
            discovery_loop.run_until_complete(provider.disconnect())
