# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The HTTP surface over a real socket, with a real client on the other end.

Everything else in this package drives :class:`~hexbench.api.Application` by
value, which is fast and deterministic and skips the whole socket layer. This
module deliberately does not. It binds port zero, starts
:class:`~hexbench.server.BenchHTTPServer` on a thread and talks to it with
:mod:`http.client`, because several of the properties worth defending only exist
once bytes are involved: the ``Host`` header a client sends by itself, the path
a client puts on the wire before anything unquotes it, and the response the
grid's scroll path gets back while another thread is holding the document.

Four of the tests are security tests rather than behaviour tests. This process
reads and writes arbitrary files for whoever reaches it, so a request must carry
the session token, must address the server as loopback on the port it actually
bound, and must not be able to name a file outside the asset directory however
the path is spelled. Each of those is checked against a positive control in the
same test -- a request that should succeed, and does -- so a rejection cannot be
mistaken for a route that was simply broken.

Assertions are made through the package's shared vocabulary in
:class:`hexbench.tests._support.Assertions`, which every case here inherits and
which documents why neither of the two obvious spellings is available.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Final
from urllib.parse import urlsplit

from intellicrack_hexcore import HexDocument

from hexbench.api import Application
from hexbench.catalog import build_catalog
from hexbench.jobs import JobQueue
from hexbench.registry import BusyError, Registry
from hexbench.server import BenchHTTPServer, bound_url, build_server

from ._support import AUTH_HEADER, INDEX_PATH, PACKAGE_ROOT, SESSION_TOKEN, STATIC_ROOT, Assertions


if TYPE_CHECKING:
    from collections.abc import Generator, Mapping
    from pathlib import Path

    from hexbench.codec import JsonValue
    from hexbench.registry import DocumentSlot


_HOST: Final = "127.0.0.1"
"""Interface the test server binds, and the only one it will answer for."""

_HTTP_TIMEOUT: Final = 20.0
"""Seconds a client waits for a response before giving up."""

_POLL_INTERVAL: Final = 0.05
"""How often the serving loop checks whether it has been asked to stop."""

_JOIN_TIMEOUT: Final = 15.0
"""Seconds to wait for the serving thread during teardown."""

_STOP_TIMEOUT: Final = 10.0
"""Seconds to wait for the serving thread after asking the server to stop."""

_WORKERS: Final = 2
"""Background job workers; nothing here submits a job, so two is plenty."""

_OK: Final = 200
"""Success."""

_FORBIDDEN: Final = 403
"""Refused for want of a token, a matching host, or containment."""

_NOT_FOUND: Final = 404
"""Nothing at that address."""

_SCROLL_DEADLINE: Final = 5.0
"""Seconds a window request may take while another thread is holding the document.

Serving one takes about a quarter of a second in that state, which is the timed
acquire :meth:`~hexbench.registry.DocumentSlot.info` makes for the generation
counter before falling back to its cached reading. The deadline is twenty times
that, so it fails on a route that queues behind the holder rather than on a
loaded machine.
"""

_BRIEF_ACQUIRE: Final = 0.25
"""Seconds the control writer waits for the document before calling it busy."""

_ONE_WRITER: Final = 1
"""Threads the control needs, since a reentrant lock cannot exclude its owner."""

_HTML_TYPE: Final = "text/html; charset=utf-8"
"""Content type the application document is served as."""

_FORBIDDEN_KIND: Final = "forbidden"
"""Error slug returned for an unauthenticated, misaddressed or escaping request."""

_MISSING_ASSET_KIND: Final = "no_such_asset"
"""Error slug returned for an asset that is simply not there."""

_ERROR_KEY: Final = "error"
"""Key the application wraps every failure in."""

_KIND_KEY: Final = "kind"
"""Key naming the machine-readable class of a failure."""

_CATALOG_PATH: Final = "/api/catalog"
"""The simplest authenticated route, used wherever a test needs one."""

_OPERATIONS_KEY: Final = "operations"
"""Key the catalogue lists its operations under."""

_DOCUMENT_SIZE: Final = 2 << 20
"""Bytes in the document the window tests read, chosen to exceed the window cap."""

_BYTE_VALUES: Final = 256
"""Distinct byte values used to fill that document."""

_TAIL: Final = 4
"""Bytes of the document the clamping test asks for at the very end."""

_GENEROUS_LENGTH: Final = 4 << 20
"""A window request larger than both the cap and the document itself."""

_PAST_THE_END: Final = 4096
"""How far beyond the last byte the out-of-range window request reaches."""

_EMPTY: Final = 0
"""The length of a window that starts at or after the end of the document."""

_FIRST_GENERATION: Final = 0

_ONE_BUMP: Final = 1
"""How far a single change moves a generation counter."""

_EDIT: Final = b"\xa5"
"""A byte written to move the engine's counter, distinct from the sample data."""
"""Generation of a document nothing has yet mutated."""

_WRONG_CREDENTIAL: Final = "not-the-one-this-session-minted"
"""A session credential of the right shape and the wrong value."""

_FOREIGN_HOST: Final = "evil.example"
"""A ``Host`` header naming somebody else entirely."""

_FOREIGN_ORIGIN: Final = "http://evil.example"
"""An ``Origin`` header naming somebody else entirely."""

_ORIGIN_HEADER: Final = "Origin"
"""Header a browser attaches when a page makes the request."""

_HOST_HEADER: Final = "Host"
"""Header naming the server the client believes it is talking to."""

_CONTENT_TYPE: Final = "content-type"
"""Response header naming the media type, matched in lower case."""

_MISSING_ASSET: Final = "/static/there-is-no-such-file.js"
"""An asset path inside the served directory that names nothing."""

_UNSERVED_ASSET: Final = "/static/there-is-no-such-file.py"
"""An asset path inside the served directory whose extension is not served."""

_UNSERVED_KIND: Final = "unsupported_asset"
"""Error slug returned for an extension the application will not serve.

It differs from :data:`_FORBIDDEN_KIND`, which is what makes the traversal test
above a real check: a containment failure and an extension failure are told
apart, so a refusal cannot be credited to the wrong rule.
"""

_ESCAPES: Final[tuple[tuple[str, str], ...]] = (
    ("/static/../api.py", "api.py"),
    ("/static/..%2fserver.py", "server.py"),
    ("/static/..%5ccatalog.py", "catalog.py"),
)
"""Traversal attempts and the package file each one is reaching for.

All three targets live inside the hexbench package and outside its asset
directory, so the check stays self-contained: deleting the package deletes both
the test and everything it points at. The three spellings cover a plain dot
segment, a percent-encoded forward slash and a percent-encoded backslash, since
the server unquotes the path before it ever splits it.
"""

_ORIGIN_LABEL: Final = "open_bytes"
"""Origin recorded for the documents these tests register by hand."""

_SERVED_SUFFIX: Final = ".css"
"""Extension of the asset used as the positive control for the static route."""


def _document_bytes() -> bytes:
    """Build the body of the document the window tests read.

    Returns:
        bytes: A flat spread of every byte value, repeated to the required size.
    """
    return bytes(range(_BYTE_VALUES)) * (_DOCUMENT_SIZE // _BYTE_VALUES)


def _served_asset() -> Path:
    """Find an asset the application is willing to serve.

    Returns:
        Path: A real file inside the asset directory, chosen from what is there
        rather than named here.

    Raises:
        FileNotFoundError: If the asset directory holds nothing servable, which
            would mean the positive control had quietly stopped controlling
            anything.
    """
    for candidate in sorted(STATIC_ROOT.iterdir()):
        if candidate.is_file() and candidate.suffix == _SERVED_SUFFIX:
            return candidate
    message = f"no {_SERVED_SUFFIX} asset in {STATIC_ROOT} to serve as the positive control"
    raise FileNotFoundError(message)


@dataclass(frozen=True, slots=True)
class _Reply:
    """One response, read off the socket in full.

    Attributes:
        status: HTTP status code.
        headers: Response headers, keyed in lower case.
        body: The complete response body.
    """

    status: int
    headers: dict[str, str] = field(default_factory=dict[str, str])
    body: bytes = b""


def _fetch(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes = b"",
    headers: Mapping[str, str] | None = None,
    token: str | None = None,
    authenticate: bool = True,
) -> _Reply:
    """Perform one request against the running server and read the whole reply.

    A fresh connection is used each time and closed afterwards, so no test can
    inherit another's keep-alive state.

    Args:
        port: Port the server is listening on.
        method: HTTP method to send.
        path: Request target, sent exactly as given so traversal spellings
            survive the trip.
        body: Request body.
        headers: Extra headers; a ``Host`` given here replaces the one
            :mod:`http.client` would generate.
        token: Session token to present, defaulting to the suite's own.
        authenticate: Whether to send a token header at all.

    Returns:
        _Reply: Status, headers and body of the response.
    """
    sent: dict[str, str] = {}
    if authenticate:
        sent[AUTH_HEADER] = SESSION_TOKEN if token is None else token
    if headers is not None:
        sent.update(headers)
    connection = http.client.HTTPConnection(_HOST, port, timeout=_HTTP_TIMEOUT)
    try:
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        return _Reply(
            status=response.status,
            headers={name.lower(): value for name, value in response.getheaders()},
            body=response.read(),
        )
    finally:
        connection.close()


def _payload(reply: _Reply) -> dict[str, JsonValue]:
    """Parse a reply body as a JSON object.

    Args:
        reply: Reply to parse.

    Returns:
        dict[str, JsonValue]: The decoded object.

    Raises:
        TypeError: If the body is valid JSON but is not an object.
    """
    decoded: JsonValue = json.loads(reply.body)
    if not isinstance(decoded, dict):
        message = f"expected a JSON object from the server, got {type(decoded).__name__}"
        raise TypeError(message)
    return decoded


def _error_kind(reply: _Reply) -> JsonValue:
    """Read the machine-readable class out of a failure reply.

    Args:
        reply: Reply to read.

    Returns:
        JsonValue: The failure's slug.

    Raises:
        TypeError: If the reply carries no error object.
    """
    error = _payload(reply).get(_ERROR_KEY)
    if not isinstance(error, dict):
        message = f"reply {reply.status} carries no error object: {reply.body[:200]!r}"
        raise TypeError(message)
    return error.get(_KIND_KEY)


def _integer(payload: Mapping[str, JsonValue], key: str) -> int:
    """Read one integer field out of a JSON object.

    Args:
        payload: Object to read from.
        key: Field name.

    Returns:
        int: The field's value.

    Raises:
        TypeError: If the field is absent or is not an integer.
    """
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        message = f"{key} is {value!r}, which is not an integer"
        raise TypeError(message)
    return value


def _window_bytes(payload: Mapping[str, JsonValue]) -> bytes:
    """Decode the hexadecimal window a document read returned.

    Args:
        payload: The window object.

    Returns:
        bytes: The bytes the server read.

    Raises:
        TypeError: If the window carries no hexadecimal text.
    """
    value = payload.get("data")
    if not isinstance(value, str):
        message = f"the window carries {type(value).__name__} where hexadecimal text belongs"
        raise TypeError(message)
    return bytes.fromhex(value)


def _measure_through_a_borrow(slot: DocumentSlot) -> int:
    """Hold a document exclusively for a moment and read its length through the hold.

    The read is incidental. What this reports is whether the write lock could be
    taken at all, which is why it waits only :data:`_BRIEF_ACQUIRE` and why it
    must be called from a thread other than the one already holding the slot:
    the lock is reentrant, so an owner asking again is granted it immediately.

    Propagates :class:`~hexbench.registry.BusyError` when the document was still
    held once that wait expired, which is the answer the caller is usually after.

    Args:
        slot: Slot to acquire.

    Returns:
        int: Length of the document, read while the lock was held.
    """
    with slot.borrow(timeout=_BRIEF_ACQUIRE) as document:
        return document.length()


class _Stopper:
    """The shutdown callable, handed to the application before a server exists."""

    def __init__(self) -> None:
        """Create a stopper that is not yet attached to a server."""
        self._server: BenchHTTPServer | None = None

    def attach(self, server: BenchHTTPServer) -> None:
        """Bind this stopper to the server it should stop.

        Args:
            server: The bound server.
        """
        self._server = server

    def __call__(self) -> None:
        """Stop the attached server, if one has been attached yet."""
        server = self._server
        if server is not None:
            server.shutdown()


class _LiveServer:
    """A hexbench session listening on a real loopback socket."""

    def __init__(self, registry: Registry, jobs: JobQueue, server: BenchHTTPServer) -> None:
        """Wire a bound server to the state it serves.

        Args:
            registry: Registry owning the session's documents.
            jobs: Queue the application submits background work to.
            server: The already bound, not yet serving, server.
        """
        self._registry = registry
        self._jobs = jobs
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": _POLL_INTERVAL},
            name="hexbench-test-server",
            daemon=True,
        )

    @property
    def port(self) -> int:
        """Report the port the operating system assigned.

        Returns:
            int: The bound port.
        """
        return self._server.bound_address[1]

    @property
    def registry(self) -> Registry:
        """The registry holding this server's open documents.

        Returns:
            Registry: The session's registry.
        """
        return self._registry

    @property
    def url(self) -> str:
        """The address a browser would be sent to, token and all.

        Returns:
            str: The complete URL of the application document.
        """
        return bound_url(self._server, SESSION_TOKEN)

    def start(self) -> None:
        """Begin serving on a background thread."""
        self._thread.start()

    def serving(self) -> bool:
        """Report whether the serving loop is still running.

        Returns:
            bool: ``True`` while the thread is alive.
        """
        return self._thread.is_alive()

    def wait_until_stopped(self, timeout: float) -> bool:
        """Wait for the serving loop to end of its own accord.

        Args:
            timeout: Seconds to wait.

        Returns:
            bool: ``True`` if the thread finished within the wait.
        """
        self._thread.join(timeout)
        return not self._thread.is_alive()

    def open_bytes(self, data: bytes, label: str) -> str:
        """Register an in-memory document with this server's registry.

        Args:
            data: Complete contents of the new document.
            label: Tab label for the new document.

        Returns:
            str: Handle of the new document.
        """
        return self._registry.create(HexDocument.open_bytes(data), origin=_ORIGIN_LABEL, label=label).handle

    def close(self) -> None:
        """Stop serving and release everything the session holds."""
        self._server.shutdown()
        self._thread.join(_JOIN_TIMEOUT)
        self._server.server_close()
        self._jobs.shutdown()
        self._registry.shutdown()


@contextmanager
def _live_server() -> Generator[_LiveServer]:
    """Bind a server on a free port, serve it, and shut it down afterwards.

    Yields:
        _LiveServer: The running server, stopped and closed when the block ends.
    """
    registry = Registry()
    jobs = JobQueue(_WORKERS)
    stopper = _Stopper()
    application = Application(registry, jobs, static_root=STATIC_ROOT, token=SESSION_TOKEN, shutdown=stopper)
    server = build_server(application, _HOST, 0)
    stopper.attach(server)
    application.bind(server.bound_address[1])
    live = _LiveServer(registry, jobs, server)
    live.start()
    try:
        yield live
    finally:
        live.close()


class _ServerCase(Assertions, unittest.TestCase):
    """A running server plus the shared assertion vocabulary.

    The assertion helpers come from
    :class:`~hexbench.tests._support.Assertions`; this case adds only the
    server itself.

    Attributes:
        live: The server under test, stopped when the test ends.
    """

    live: _LiveServer

    def setUp(self) -> None:
        """Start a server for the test."""
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.live = stack.enter_context(_live_server())

    def fetch(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
        authenticate: bool = True,
    ) -> _Reply:
        """Perform one request against this test's server.

        Args:
            method: HTTP method to send.
            path: Request target, sent exactly as given.
            headers: Extra headers to send.
            token: Session token to present, defaulting to the suite's own.
            authenticate: Whether to send a token header at all.

        Returns:
            _Reply: What the server answered.
        """
        return _fetch(self.live.port, method, path, headers=headers, token=token, authenticate=authenticate)


class ApplicationDocument(_ServerCase):
    """The one route a browser reaches before it knows anything."""

    def test_the_index_is_served_with_the_session_token_substituted(self) -> None:
        """The page the browser loads carries the token the file on disk does not."""
        target = urlsplit(self.live.url)
        reply = self.fetch("GET", f"{target.path}?{target.query}", authenticate=False)
        self.equal(reply.status, _OK)
        self.equal(reply.headers.get(_CONTENT_TYPE), _HTML_TYPE)
        stored = INDEX_PATH.read_bytes()
        token = SESSION_TOKEN.encode("ascii")
        self.absent(token, stored)
        self.contains(token, reply.body)
        self.unequal(reply.body, stored)

    def test_the_index_refuses_a_missing_or_wrong_token(self) -> None:
        """Neither an absent token nor a plausible wrong one opens the page."""
        target = urlsplit(self.live.url)
        for query in ("", "token=", f"token={_WRONG_CREDENTIAL}"):
            with self.subTest(query=query):
                reply = self.fetch("GET", f"{target.path}?{query}", authenticate=False)
                self.equal(reply.status, _FORBIDDEN)
                self.equal(_error_kind(reply), _FORBIDDEN_KIND)
                self.absent(SESSION_TOKEN.encode("ascii"), reply.body)


class ApiAuthentication(_ServerCase):
    """What has to be true of a request before any route runs."""

    def test_the_api_refuses_a_request_without_the_session_token(self) -> None:
        """The same route answers with the token and refuses without it."""
        refused = self.fetch("GET", _CATALOG_PATH, authenticate=False)
        self.equal(refused.status, _FORBIDDEN)
        self.equal(_error_kind(refused), _FORBIDDEN_KIND)
        self.absent(_OPERATIONS_KEY.encode("ascii"), refused.body)
        allowed = self.fetch("GET", _CATALOG_PATH)
        self.equal(allowed.status, _OK)
        operations = _payload(allowed).get(_OPERATIONS_KEY)
        if not isinstance(operations, list):
            self.fail(f"the catalogue listed {type(operations).__name__} instead of an array of operations")
        self.equal(len(operations), len(build_catalog()))

    def test_the_api_refuses_a_wrong_session_token(self) -> None:
        """A token of the right shape and the wrong value is no better than none."""
        reply = self.fetch("GET", _CATALOG_PATH, token=_WRONG_CREDENTIAL)
        self.equal(reply.status, _FORBIDDEN)
        self.equal(_error_kind(reply), _FORBIDDEN_KIND)

    def test_the_api_refuses_a_host_header_naming_somebody_else(self) -> None:
        """A rebinding attack fails even though the token travels with it."""
        reply = self.fetch("GET", _CATALOG_PATH, headers={_HOST_HEADER: _FOREIGN_HOST})
        self.equal(reply.status, _FORBIDDEN)
        self.equal(_error_kind(reply), _FORBIDDEN_KIND)
        self.absent(_OPERATIONS_KEY.encode("ascii"), reply.body)

    def test_the_api_refuses_loopback_on_the_wrong_port(self) -> None:
        """Naming the right interface is not enough; the port has to match too."""
        wrong = self.fetch("GET", _CATALOG_PATH, headers={_HOST_HEADER: f"{_HOST}:{self.live.port + 1}"})
        self.equal(wrong.status, _FORBIDDEN)
        right = self.fetch("GET", _CATALOG_PATH, headers={_HOST_HEADER: f"{_HOST}:{self.live.port}"})
        self.equal(right.status, _OK)

    def test_the_api_refuses_an_origin_from_another_page(self) -> None:
        """A page in another tab cannot spend this session's token."""
        foreign = self.fetch("GET", _CATALOG_PATH, headers={_ORIGIN_HEADER: _FOREIGN_ORIGIN})
        self.equal(foreign.status, _FORBIDDEN)
        self.equal(_error_kind(foreign), _FORBIDDEN_KIND)
        own = self.fetch("GET", _CATALOG_PATH, headers={_ORIGIN_HEADER: f"http://{_HOST}:{self.live.port}"})
        self.equal(own.status, _OK)


class StaticAssets(_ServerCase):
    """Serving the browser's own files, and only those."""

    def test_a_real_asset_is_served(self) -> None:
        """The positive control: the route works and returns the file verbatim."""
        asset = _served_asset()
        reply = self.fetch("GET", f"/static/{asset.name}", authenticate=False)
        self.equal(reply.status, _OK)
        self.equal(reply.body, asset.read_bytes())

    def test_an_absent_asset_is_reported_missing(self) -> None:
        """A name inside the directory that matches no file is simply not found."""
        reply = self.fetch("GET", _MISSING_ASSET, authenticate=False)
        self.equal(reply.status, _NOT_FOUND)
        self.equal(_error_kind(reply), _MISSING_ASSET_KIND)

    def test_a_traversal_cannot_reach_a_file_outside_the_asset_directory(self) -> None:
        """Three spellings of the same escape, none of which discloses anything."""
        for path, target in _ESCAPES:
            with self.subTest(path=path):
                stored = (PACKAGE_ROOT / target).read_bytes()
                reply = self.fetch("GET", path, authenticate=False)
                self.unequal(reply.status, _OK)
                self.equal(reply.status, _FORBIDDEN)
                self.equal(_error_kind(reply), _FORBIDDEN_KIND)
                self.unequal(reply.body, stored)
                self.absent(stored[: len(stored) // 2], reply.body)

    def test_a_dot_segment_that_stays_inside_the_directory_is_served(self) -> None:
        """Containment is checked against where the path lands, not how it reads."""
        asset = _served_asset()
        reply = self.fetch("GET", f"/static/../static/{asset.name}", authenticate=False)
        self.equal(reply.status, _OK)
        self.equal(reply.body, asset.read_bytes())

    def test_an_unservable_extension_is_refused_on_its_own_grounds(self) -> None:
        """The refusal above came from containment, not from the extension list."""
        reply = self.fetch("GET", _UNSERVED_ASSET, authenticate=False)
        self.equal(reply.status, _FORBIDDEN)
        self.equal(_error_kind(reply), _UNSERVED_KIND)

    def test_the_files_a_traversal_reaches_for_really_are_there(self) -> None:
        """Without this, the traversal test would pass against absent files."""
        for _, target in _ESCAPES:
            with self.subTest(target=target):
                self.truthy((PACKAGE_ROOT / target).is_file())
                self.falsy((STATIC_ROOT / target).exists())


class DocumentWindows(_ServerCase):
    """The grid's scroll path, which clamps rather than raising."""

    def window(self, handle: str, offset: int, length: int) -> dict[str, JsonValue]:
        """Read one window over the wire.

        Args:
            handle: Document to read.
            offset: First byte wanted.
            length: Number of bytes wanted.

        Returns:
            dict[str, JsonValue]: The window object the server returned.
        """
        reply = self.fetch("GET", f"/api/documents/{handle}/window?offset={offset}&length={length}")
        self.equal(reply.status, _OK)
        return _payload(reply)

    def test_a_window_at_the_end_of_the_document_is_clamped_to_what_remains(self) -> None:
        """Asking for more than is left returns exactly what is left."""
        data = _document_bytes()
        handle = self.live.open_bytes(data, "clamped")
        start = len(data) - _TAIL
        payload = self.window(handle, start, _GENEROUS_LENGTH)
        self.equal(_integer(payload, "offset"), start)
        self.equal(_integer(payload, "length"), _TAIL)
        self.equal(_integer(payload, "document_length"), len(data))
        self.equal(_window_bytes(payload), data[start:])
        self.equal(_integer(payload, "generation"), _FIRST_GENERATION)

    def test_a_window_past_the_end_of_the_document_comes_back_empty(self) -> None:
        """An offset beyond the last byte is pulled back to the end, not refused."""
        data = _document_bytes()
        handle = self.live.open_bytes(data, "beyond")
        payload = self.window(handle, len(data) + _PAST_THE_END, _TAIL)
        self.equal(_integer(payload, "offset"), len(data))
        self.equal(_integer(payload, "length"), _EMPTY)
        self.equal(_window_bytes(payload), b"")

    def test_a_window_larger_than_the_cap_is_cut_down_to_it(self) -> None:
        """A client asking for the whole file gets a bounded answer instead."""
        data = _document_bytes()
        handle = self.live.open_bytes(data, "capped")
        payload = self.window(handle, 0, _GENEROUS_LENGTH)
        served = _integer(payload, "length")
        if not _EMPTY < served < len(data):
            self.fail(f"a request for {_GENEROUS_LENGTH} bytes returned {served} of a {len(data)} byte document, which is no cap at all")
        self.equal(_window_bytes(payload), data[:served])
        self.equal(len(_window_bytes(payload)), served)

    def test_the_window_generation_counts_byte_changes_not_bookkeeping(self) -> None:
        """A window is versioned by the engine's counter, not the registry's.

        The two count different things. The registry advances on every mutating
        operation, bookmarks and saves included, while the engine advances only
        when the bytes change. A window carries bytes, so tagging it with the
        registry's number would tell a client its cached bytes were stale every
        time somebody dropped a bookmark on the document.
        """
        data = _document_bytes()
        handle = self.live.open_bytes(data, "counters")
        slot = self.live.registry.slot(handle)
        slot.bump()
        payload = self.window(handle, 0, _TAIL)
        self.equal(_integer(payload, "generation"), _FIRST_GENERATION)
        self.equal(slot.info().generation, _FIRST_GENERATION + _ONE_BUMP)

    def test_the_window_generation_does_move_when_the_bytes_do(self) -> None:
        """Without this the test above would pass against a counter stuck at zero."""
        data = _document_bytes()
        handle = self.live.open_bytes(data, "edited")
        slot = self.live.registry.slot(handle)
        with slot.borrow() as document:
            document.write_bytes(0, _EDIT)
        payload = self.window(handle, 0, _TAIL)
        self.equal(_integer(payload, "generation"), _FIRST_GENERATION + _ONE_BUMP)
        self.equal(_window_bytes(payload)[: len(_EDIT)], _EDIT)

    def test_an_unknown_handle_is_reported_rather_than_served(self) -> None:
        """A window over a document that was never opened is a miss, not a crash."""
        reply = self.fetch("GET", "/api/documents/there-is-no-such-handle/window")
        self.equal(reply.status, _NOT_FOUND)
        self.equal(_error_kind(reply), "no_such_document")


class HeldDocuments(_ServerCase):
    """What the scroll path does while somebody else holds the document."""

    def test_a_held_document_still_serves_the_window_request(self) -> None:
        """The grid scrolls through a document a writer is holding, without waiting for it."""
        data = _document_bytes()
        handle = self.live.open_bytes(data, "held")
        slot = self.live.registry.slot(handle)
        started = time.monotonic()
        with slot.borrow():
            reply = self.fetch("GET", f"/api/documents/{handle}/window?offset=0&length={_TAIL}")
        elapsed = time.monotonic() - started
        self.equal(reply.status, _OK)
        payload = _payload(reply)
        self.equal(_window_bytes(payload), data[:_TAIL])
        self.equal(_integer(payload, "length"), _TAIL)
        self.equal(_integer(payload, "generation"), _FIRST_GENERATION)
        self.require(
            elapsed < _SCROLL_DEADLINE,
            f"the window took {elapsed:.2f}s to come back while the document was held, which is a queue rather than a read",
        )

    def test_the_hold_that_window_read_through_really_excludes_a_writer(self) -> None:
        """Without this the test above would pass against a lock that admits everybody."""
        data = _document_bytes()
        handle = self.live.open_bytes(data, "excluded")
        slot = self.live.registry.slot(handle)
        with ThreadPoolExecutor(max_workers=_ONE_WRITER) as pool, slot.borrow():
            pending = pool.submit(_measure_through_a_borrow, slot)
            self.raises(
                BusyError,
                "a second writer while the document is held",
                partial(pending.result, timeout=_SCROLL_DEADLINE),
            )
        self.equal(_measure_through_a_borrow(slot), len(data))


class ServerLifetime(_ServerCase):
    """Binding, and unbinding."""

    def test_the_server_is_bound_to_loopback_on_the_port_it_reports(self) -> None:
        """The address the browser is given is the address that answers."""
        target = urlsplit(self.live.url)
        self.equal(target.hostname, _HOST)
        self.equal(target.port, self.live.port)
        self.truthy(self.live.serving())

    def test_the_shutdown_route_really_stops_the_serving_loop(self) -> None:
        """The route answers first and the loop ends by itself immediately after."""
        reply = self.fetch("POST", "/api/shutdown")
        self.equal(reply.status, _OK)
        self.equal(_payload(reply), {})
        self.truthy(self.live.wait_until_stopped(_STOP_TIMEOUT))
        self.falsy(self.live.serving())
