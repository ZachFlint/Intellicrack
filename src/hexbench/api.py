# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The whole HTTP surface, expressed as a function from request to response.

Nothing in this module touches a socket. :meth:`Application.handle` takes a
:class:`Request` value and returns a :class:`Response` value, so every route can
be driven in-process without binding a port, and :mod:`hexbench.server` is left
with no responsibility beyond moving bytes.

Two routes are worth reading closely. ``/api/op/<name>`` looks an operation up in
the catalogue and does nothing else: there is no allow-list and no per-operation
branch anywhere in this file, so a method added to the Rust crate becomes
reachable without a line changing here. ``/api/documents/<handle>/window`` is
deliberately not spelled ``/api/op/read``, because it is the grid's scroll path:
it clamps at the end of the document instead of raising, and it reports the
generation counter so a client can discard stale windows. It takes no lock: the
engine synchronises concurrent access itself, so a scroll is served while a long
analysis is still running rather than waiting for one or reporting itself busy.
That reply is assembled by the engine in one acquisition rather than here from
several, so the bytes, the length and the generation cannot come from different
moments of a document another thread is busy rewriting.

Every ``/api`` route is authenticated. This process can read and write arbitrary
files on behalf of whoever reaches it, so a request must carry the session token,
must address the server by its loopback host and port, and must either omit
``Origin`` or state exactly this server's own. That combination defeats both a
stray page in another tab and a DNS rebinding attack against the bound port.
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from functools import lru_cache, partial
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

from intellicrack_hexcore import HexDocument

from hexbench import reference
from hexbench.catalog import Receiver, ValueKind, build_catalog
from hexbench.dispatch import DispatchError, Invocation, encode_document, invoke, operation_for, translate_exception


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from pathlib import Path

    from hexbench.catalog import Operation, Parameter
    from hexbench.codec import JsonValue
    from hexbench.dispatch import InvocationResult
    from hexbench.jobs import JobQueue, JobRecord
    from hexbench.registry import Registry


__all__ = ["Application", "Request", "Response"]

_STATUS_OK: Final = 200
_STATUS_ACCEPTED: Final = 202
_STATUS_BAD_REQUEST: Final = 400
_STATUS_FORBIDDEN: Final = 403
_STATUS_NOT_FOUND: Final = 404
_STATUS_METHOD_NOT_ALLOWED: Final = 405

_GET: Final = "GET"
_POST: Final = "POST"
_DELETE: Final = "DELETE"

_JSON_TYPE: Final = "application/json; charset=utf-8"
_OCTET_TYPE: Final = "application/octet-stream"
_HTML_TYPE: Final = "text/html; charset=utf-8"

_API_ROOT: Final = "api"
_ASSET_ROOT: Final = "static"
_INDEX_NAME: Final = "index.html"
_SESSION_MARKER: Final = "__HEXBENCH_TOKEN__"

_AUTH_HEADER: Final = "x-hexbench-token"
_HOST_HEADER: Final = "host"
_ORIGIN_HEADER: Final = "origin"
_AUTH_QUERY: Final = "token"
_MODE_QUERY: Final = "mode"
_RAW_QUERY: Final = "raw"
_LIMIT_QUERY: Final = "limit"
_OFFSET_QUERY: Final = "offset"
_LENGTH_QUERY: Final = "length"

_LOOPBACK_ADDRESS: Final = "127.0.0.1"
_ORIGIN_SCHEME: Final = "http://"
_LOOPBACK_HOST: Final[re.Pattern[str]] = re.compile(r"127\.0\.0\.1:\d{1,5}")

_ASYNC_MODE: Final = "async"
_TRUE_QUERY: Final[frozenset[str]] = frozenset({"", "1", "true", "yes", "on"})

_DEFAULT_WINDOW: Final = 4096
_MAX_WINDOW: Final = 1 << 20
_EMPTY_WINDOW: Final = 0
_SYNC_TIMEOUT: Final = 30.0
_DEFAULT_JOB_LIMIT: Final = 100
_SHUTDOWN_DELAY: Final = 0.25

_NEW_ORIGIN: Final = "new"
_NEW_LABEL: Final = "untitled"
_NO_STORE: Final[tuple[tuple[str, str], ...]] = (("Cache-Control", "no-store"),)

_CONTENT_TYPES: Final[Mapping[str, str]] = MappingProxyType({
    ".html": _HTML_TYPE,
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
})

_HANDLED_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
    ArithmeticError,
    AttributeError,
    DispatchError,
    LookupError,
    MemoryError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


@dataclass(frozen=True, slots=True)
class Request:
    """One inbound HTTP request, reduced to the parts any route can need.

    Attributes:
        method: Uppercase HTTP method.
        path: Percent-decoded path, without the query string.
        query: Parsed query string, each name mapped to all its values.
        headers: Request headers; names are matched case-insensitively.
        body: Raw request body, empty for methods that carry none.
    """

    method: str
    path: str
    query: Mapping[str, Sequence[str]]
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class Response:
    """One outbound HTTP response, fully rendered.

    Attributes:
        status: HTTP status code.
        body: Complete response body; its length is the content length.
        content_type: Value of the ``Content-Type`` header.
        headers: Additional headers to send alongside the content type.
    """

    status: int
    body: bytes
    content_type: str
    headers: tuple[tuple[str, str], ...] = ()


def _json_body(payload: JsonValue) -> bytes:
    """Render a JSON value as a response body.

    Args:
        payload: Value to serialise.

    Returns:
        bytes: Compact UTF-8 encoded JSON.
    """
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _json_response(payload: JsonValue, status: int = _STATUS_OK) -> Response:
    """Build a JSON response.

    Args:
        payload: Value to serialise into the body.
        status: HTTP status code to send.

    Returns:
        Response: The rendered response.
    """
    return Response(status=status, body=_json_body(payload), content_type=_JSON_TYPE)


def _failure(message: str, *, kind: str, status: int) -> Response:
    """Build the standard error response.

    Args:
        message: Human readable description of the failure.
        kind: Stable slug a client can branch on.
        status: HTTP status code to send.

    Returns:
        Response: A JSON response whose body is ``{"error": {...}}``.
    """
    error: dict[str, JsonValue] = {"kind": kind, "status": status, "message": message}
    return _json_response({"error": error}, status=status)


def _error_response(error: DispatchError) -> Response:
    """Render a classified failure as a response.

    Args:
        error: The classified failure.

    Returns:
        Response: A JSON response carrying the failure's slug and message.
    """
    return _failure(str(error), kind=error.kind, status=error.status)


def _method_not_allowed(allowed: tuple[str, ...]) -> Response:
    """Reject a request whose method the route does not implement.

    Args:
        allowed: Methods the route does implement.

    Returns:
        Response: A 405 response carrying an ``Allow`` header.
    """
    joined = ", ".join(allowed)
    message = f"method not allowed; this route accepts {joined}"
    error: dict[str, JsonValue] = {"kind": "method_not_allowed", "status": _STATUS_METHOD_NOT_ALLOWED, "message": message}
    return Response(
        status=_STATUS_METHOD_NOT_ALLOWED,
        body=_json_body({"error": error}),
        content_type=_JSON_TYPE,
        headers=(("Allow", joined),),
    )


def _no_route(request: Request) -> Response:
    """Reject a request for a path no route matches.

    Args:
        request: The unmatched request.

    Returns:
        Response: A 404 response naming the method and path.
    """
    message = f"no route for {request.method} {request.path}"
    return _failure(message, kind="no_such_route", status=_STATUS_NOT_FOUND)


def _first(query: Mapping[str, Sequence[str]], name: str) -> str | None:
    """Read the first value of a query parameter.

    Args:
        query: Parsed query string.
        name: Parameter name.

    Returns:
        str | None: The first value, or ``None`` when the parameter is absent.
    """
    values = query.get(name)
    if not values:
        return None
    return values[0]


def _flag(query: Mapping[str, Sequence[str]], name: str) -> bool:
    """Read a boolean query parameter.

    A parameter present with no value counts as true, so ``?raw`` and ``?raw=1``
    mean the same thing.

    Args:
        query: Parsed query string.
        name: Parameter name.

    Returns:
        bool: Whether the parameter is present and truthy.
    """
    value = _first(query, name)
    if value is None:
        return False
    return value.strip().casefold() in _TRUE_QUERY


def _int_query(query: Mapping[str, Sequence[str]], name: str, default: int) -> int:
    """Read an integer query parameter, accepting any base prefix.

    Args:
        query: Parsed query string.
        name: Parameter name.
        default: Value to use when the parameter is absent or empty.

    Returns:
        int: The parsed value.

    Raises:
        DispatchError: If the parameter is present but is not an integer.
    """
    raw = _first(query, name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw.strip(), 0)
    except ValueError as exc:
        message = f"{name}: expected an integer, got {raw!r}"
        raise DispatchError(message, kind="decode", status=_STATUS_BAD_REQUEST) from exc


def _request_object(body: bytes) -> dict[str, JsonValue]:
    """Parse a request body as a JSON object.

    Args:
        body: Raw request body; an empty body means an empty object.

    Returns:
        dict[str, JsonValue]: The parsed object.

    Raises:
        DispatchError: If the body is not valid JSON, or is not an object.
    """
    if not body.strip():
        return {}
    try:
        decoded: object = json.loads(body)
    except ValueError as exc:
        message = f"request body is not valid JSON: {exc}"
        raise DispatchError(message, kind="decode", status=_STATUS_BAD_REQUEST) from exc
    if not isinstance(decoded, dict):
        message = f"request body must be a JSON object, got {type(decoded).__name__}"
        raise DispatchError(message, kind="decode", status=_STATUS_BAD_REQUEST)
    return cast("dict[str, JsonValue]", decoded)


def _payload_handle(payload: dict[str, JsonValue]) -> str | None:
    """Read the target document handle out of a request payload.

    Args:
        payload: Parsed request body.

    Returns:
        str | None: The handle, or ``None`` when the request names no document.

    Raises:
        DispatchError: If the handle is present but is not a string.
    """
    value = payload.get("handle")
    if value is None:
        return None
    if not isinstance(value, str):
        message = f"handle must be a string, got {type(value).__name__}"
        raise DispatchError(message, kind="decode", status=_STATUS_BAD_REQUEST)
    return value


def _payload_arguments(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Read the operation arguments out of a request payload.

    Args:
        payload: Parsed request body.

    Returns:
        dict[str, JsonValue]: Arguments keyed by parameter name, empty when the
        request supplied none.

    Raises:
        DispatchError: If the arguments are present but are not an object.
    """
    value = payload.get("arguments")
    if value is None:
        return {}
    if not isinstance(value, dict):
        message = f"arguments must be a JSON object, got {type(value).__name__}"
        raise DispatchError(message, kind="decode", status=_STATUS_BAD_REQUEST)
    return value


def _requested_mode(request: Request, payload: dict[str, JsonValue]) -> str:
    """Decide whether an invocation runs on the request thread or in the background.

    Args:
        request: The inbound request, whose query string wins when both say.
        payload: Parsed request body.

    Returns:
        str: The requested mode, folded to lower case.
    """
    mode = _first(request.query, _MODE_QUERY)
    if mode is None:
        from_body = payload.get(_MODE_QUERY)
        mode = from_body if isinstance(from_body, str) else None
    return (mode or "").strip().casefold()


def _encode_parameter(parameter: Parameter) -> JsonValue:
    """Render one catalogued parameter as JSON.

    Args:
        parameter: The parameter to render.

    Returns:
        JsonValue: Object carrying the name, stub annotation and value kind.
    """
    return {"name": parameter.name, "annotation": parameter.annotation, "kind": parameter.kind.value}


def _encode_operation(operation: Operation) -> JsonValue:
    """Render one catalogued operation as JSON.

    Args:
        operation: The operation to render.

    Returns:
        JsonValue: Object carrying everything a client needs to build a form for
        the operation and to decide how to invoke it.
    """
    return {
        "name": operation.name,
        "receiver": operation.receiver.value,
        "group": operation.group,
        "returns": operation.returns,
        "mutating": operation.mutating,
        "parameters": [_encode_parameter(parameter) for parameter in operation.parameters],
    }


@lru_cache(maxsize=1)
def _catalog_body() -> bytes:
    """Render the operation catalogue once and keep the bytes.

    Returns:
        bytes: Serialised catalogue carrying every operation, the set of group
        labels in display order, the value kinds and the receiver kinds.
    """
    operations = build_catalog()
    payload: dict[str, JsonValue] = {
        "operations": [_encode_operation(operation) for operation in operations],
        "groups": _json_strings(sorted({operation.group for operation in operations})),
        "value_kinds": _json_strings([kind.value for kind in ValueKind]),
        "receivers": _json_strings([receiver.value for receiver in Receiver]),
    }
    return _json_body(payload)


def _encode_job(record: JobRecord) -> JsonValue:
    """Render one job record as JSON.

    Args:
        record: The record to render.

    Returns:
        JsonValue: Object carrying the job's identity, state, timings and
        outcome.
    """
    return {
        "job_id": record.job_id,
        "operation": record.operation,
        "handle": record.handle,
        "state": record.state,
        "submitted_at": record.submitted_at,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "result": record.result,
        "error": record.error,
    }


def _result_json(result: InvocationResult) -> JsonValue:
    """Render an invocation result as JSON.

    Args:
        result: The result to render.

    Returns:
        JsonValue: Object carrying the return value, the timing, the state of any
        document involved, and whether an untruncated binary payload can be
        downloaded by repeating the call with ``raw=1``.
    """
    return {
        "operation": result.operation,
        "value": result.value,
        "duration_ms": result.duration_ms,
        "created_handle": result.created_handle,
        "document": encode_document(result.document) if result.document is not None else None,
        "raw_length": len(result.raw) if result.raw is not None else 0,
        "raw_available": result.raw is not None,
    }


def _attachment(name: str) -> tuple[tuple[str, str], ...]:
    """Build the headers that offer a binary payload as a download.

    Args:
        name: Base name of the suggested file, without an extension.

    Returns:
        tuple[tuple[str, str], ...]: The content disposition and cache headers.
    """
    disposition = ("Content-Disposition", f'attachment; filename="{name}.bin"')
    return (disposition, *_NO_STORE)


def _json_strings(values: Sequence[str]) -> list[JsonValue]:
    """Widen a sequence of strings into a JSON array.

    Args:
        values: Strings to place in the array.

    Returns:
        list[JsonValue]: The same strings as JSON values.
    """
    return list(values)


def _window_payload(document: HexDocument, offset: int, requested: int) -> dict[str, JsonValue]:
    """Read one clamped byte window from a document the caller already holds.

    Every member of the reply comes from one acquisition inside the engine, so
    the window describes a single moment. Assembling it from separate calls to
    ``length``, ``read`` and the slot's cached state let a write landing between
    them pair the bytes with a length or a generation they never had, and left a
    scroll clamped against a stale length able to ask for an offset the document
    no longer reaches.

    Args:
        document: The document to read, in use by the caller.
        offset: Requested first byte, clamped into the document.
        requested: Requested byte count, clamped to the window limit and to the
            bytes actually remaining.

    Returns:
        dict[str, JsonValue]: The window, the generation it was read at, and the
        document's length at that same moment.
    """
    span = min(max(requested, 0), _MAX_WINDOW)
    start = max(offset, 0)
    try:
        data, _, generation, total = document.read_window(start, span)
    except ValueError:
        data, _, generation, total = document.read_window(_EMPTY_WINDOW, _EMPTY_WINDOW)
        start = total
    return {
        "offset": start,
        "length": len(data),
        "generation": generation,
        "document_length": total,
        "data": data.hex(),
    }


def _read_file(path: Path) -> bytes | None:
    """Read a file, treating any read failure as absence.

    Args:
        path: File to read.

    Returns:
        bytes | None: The file's contents, or ``None`` if it could not be read.
    """
    try:
        return path.read_bytes()
    except OSError:
        return None


class Application:
    """Every route the browser can reach, as one request-to-response function."""

    def __init__(self, registry: Registry, jobs: JobQueue, *, static_root: Path, token: str, shutdown: Callable[[], None]) -> None:
        """Assemble the routing table over a session's state.

        Args:
            registry: Registry owning the session's open documents.
            jobs: Queue running background invocations and holding the run log.
            static_root: Directory holding the browser assets.
            token: Session token every request must present.
            shutdown: Callable that stops the server; invoked shortly after the
                shutdown route has answered, so the response is flushed first.
        """
        self._registry = registry
        self._jobs = jobs
        self._static_root = static_root.resolve()
        self._token = token
        self._stop = shutdown
        self._port: int | None = None
        self._state = threading.Lock()
        self._heartbeat = time.monotonic()
        self._exercised: set[str] = set()

    def bind(self, port: int) -> None:
        """Record the port the server ended up listening on.

        The ``Host`` header of every API request is then required to name
        exactly this port. Until a port is recorded any loopback port is
        accepted, which is what lets the routing table be exercised in-process
        without binding a socket at all.

        Args:
            port: The port the listening socket was assigned.
        """
        with self._state:
            self._port = port

    def note_heartbeat(self) -> None:
        """Record that the client is still there."""
        with self._state:
            self._heartbeat = time.monotonic()

    def seconds_since_heartbeat(self) -> float:
        """Report how long the client has been silent.

        Returns:
            float: Seconds since the last request from the client.
        """
        with self._state:
            return time.monotonic() - self._heartbeat

    def handle(self, request: Request) -> Response:
        """Route one request and produce its response.

        Args:
            request: The inbound request.

        Returns:
            Response: The response to send, including for failures; every
            outcome this module anticipates is rendered rather than raised.
        """
        segments = tuple(part for part in request.path.split("/") if part)
        if not segments:
            return self._index(request)
        if segments[0] == _ASSET_ROOT:
            return self._asset(request, segments[1:])
        if segments[0] != _API_ROOT:
            return _no_route(request)
        denial = self._authorize(request)
        if denial is not None:
            return denial
        self.note_heartbeat()
        try:
            return self._api(request, segments[1:])
        except _HANDLED_EXCEPTIONS as exc:
            return _error_response(translate_exception(exc))

    def _authorize(self, request: Request) -> Response | None:
        """Check that a request is entitled to reach the API.

        Args:
            request: The inbound request.

        Returns:
            Response | None: A rejection, or ``None`` when the request may
            proceed.
        """
        headers = {name.lower(): value for name, value in request.headers.items()}
        supplied = headers.get(_AUTH_HEADER, "")
        if not supplied.isascii() or not secrets.compare_digest(supplied, self._token):
            return _failure("the session token is missing or incorrect", kind="forbidden", status=_STATUS_FORBIDDEN)
        host = headers.get(_HOST_HEADER, "")
        if not self._host_allowed(host):
            return _failure(f"unexpected Host header {host!r}", kind="forbidden", status=_STATUS_FORBIDDEN)
        origin = headers.get(_ORIGIN_HEADER)
        if origin is not None and origin != _ORIGIN_SCHEME + host:
            return _failure(f"unexpected Origin header {origin!r}", kind="forbidden", status=_STATUS_FORBIDDEN)
        return None

    def _host_allowed(self, host: str) -> bool:
        """Check the ``Host`` header names this server on the loopback interface.

        Args:
            host: Value of the ``Host`` header.

        Returns:
            bool: Whether the header is acceptable.
        """
        with self._state:
            port = self._port
        if port is not None:
            return host == f"{_LOOPBACK_ADDRESS}:{port}"
        return _LOOPBACK_HOST.fullmatch(host) is not None

    def _api(self, request: Request, rest: tuple[str, ...]) -> Response:
        """Route one authorised request beneath ``/api``.

        Args:
            request: The inbound request.
            rest: Path segments after ``/api``.

        Returns:
            Response: The response for the matched route.
        """
        match rest:
            case ("catalog",):
                if request.method != _GET:
                    return _method_not_allowed((_GET,))
                return Response(status=_STATUS_OK, body=_catalog_body(), content_type=_JSON_TYPE)
            case ("reference",):
                if request.method != _GET:
                    return _method_not_allowed((_GET,))
                return _json_response(reference.as_json())
            case ("documents",):
                return self._documents(request)
            case ("documents", handle):
                return self._document(request, handle)
            case ("documents", handle, "window"):
                return self._window(request, handle)
            case ("op", name):
                return self._operation(request, name)
            case ("jobs",):
                return self._job_list(request)
            case ("jobs", job_id):
                return self._job(request, job_id)
            case ("jobs", job_id, "raw"):
                return self._job_raw(request, job_id)
            case ("heartbeat",):
                if request.method != _POST:
                    return _method_not_allowed((_POST,))
                return _json_response({"ok": True})
            case ("shutdown",):
                if request.method != _POST:
                    return _method_not_allowed((_POST,))
                return self._shutdown()
            case _:
                return _no_route(request)

    def _documents(self, request: Request) -> Response:
        """List the open documents, or open an empty one.

        Args:
            request: The inbound request.

        Returns:
            Response: The document list, or the newly created document.
        """
        if request.method == _GET:
            listed: list[JsonValue] = [encode_document(info) for info in self._registry.snapshot()]
            return _json_response(listed)
        if request.method == _POST:
            info = self._registry.create(HexDocument(), origin=_NEW_ORIGIN, label=_NEW_LABEL)
            return _json_response(encode_document(info))
        return _method_not_allowed((_GET, _POST))

    def _document(self, request: Request, handle: str) -> Response:
        """Describe or close one open document.

        Args:
            request: The inbound request.
            handle: Handle naming the document.

        Returns:
            Response: The document's state, or confirmation that it was closed.
        """
        if request.method == _GET:
            return _json_response(encode_document(self._registry.slot(handle).info()))
        if request.method == _DELETE:
            if not self._registry.close(handle):
                message = f"no open document with handle {handle!r}"
                return _failure(message, kind="no_such_document", status=_STATUS_NOT_FOUND)
            return _json_response({"handle": handle, "closed": True})
        return _method_not_allowed((_GET, _DELETE))

    def _window(self, request: Request, handle: str) -> Response:
        """Read the byte window the grid is currently showing.

        Args:
            request: The inbound request.
            handle: Handle naming the document.

        Returns:
            Response: The clamped window together with the generation counter it
            was read at.
        """
        if request.method != _GET:
            return _method_not_allowed((_GET,))
        slot = self._registry.slot(handle)
        offset = _int_query(request.query, _OFFSET_QUERY, 0)
        requested = _int_query(request.query, _LENGTH_QUERY, _DEFAULT_WINDOW)
        with slot.read() as document:
            payload = _window_payload(document, offset, requested)
        return _json_response(payload)

    def _operation(self, request: Request, name: str) -> Response:
        """Run one catalogued operation.

        The only lookup here is the catalogue's, so this route reaches every
        callable the engine exposes without naming any of them.

        Args:
            request: The inbound request.
            name: Operation name taken from the path.

        Returns:
            Response: The invocation's result, a job identifier when the client
            asked for background execution, or the untruncated binary payload
            when it asked for the raw form.
        """
        if request.method != _POST:
            return _method_not_allowed((_POST,))
        operation = operation_for(name)
        payload = _request_object(request.body)
        handle = _payload_handle(payload)
        invocation = Invocation(operation=operation, handle=handle, arguments=_payload_arguments(payload))

        if _requested_mode(request, payload) == _ASYNC_MODE:
            run = partial(invoke, self._registry, invocation, timeout=_SYNC_TIMEOUT)
            job_id = self._jobs.submit(run, operation=operation.name, handle=handle)
            return _json_response({"job_id": job_id, "operation": operation.name, "handle": handle}, status=_STATUS_ACCEPTED)

        result = invoke(self._registry, invocation, timeout=_SYNC_TIMEOUT)
        self._note_exercised(result.operation)
        if _flag(request.query, _RAW_QUERY):
            if result.raw is None:
                message = f"{operation.name} does not return binary data"
                return _failure(message, kind="not_binary", status=_STATUS_BAD_REQUEST)
            return Response(status=_STATUS_OK, body=result.raw, content_type=_OCTET_TYPE, headers=_attachment(operation.name))
        return _json_response(_result_json(result))

    def _job_list(self, request: Request) -> Response:
        """List the recent jobs and the coverage the session has reached.

        Args:
            request: The inbound request.

        Returns:
            Response: The run log, the names of every operation exercised so far,
            and the total number of catalogued operations.
        """
        if request.method != _GET:
            return _method_not_allowed((_GET,))
        limit = _int_query(request.query, _LIMIT_QUERY, _DEFAULT_JOB_LIMIT)
        with self._state:
            exercised = set(self._exercised)
        exercised |= self._jobs.exercised()
        return _json_response({
            "jobs": [_encode_job(record) for record in self._jobs.recent(limit)],
            "exercised": _json_strings(sorted(exercised)),
            "operation_count": len(build_catalog()),
        })

    def _job(self, request: Request, job_id: str) -> Response:
        """Report the state of one job.

        Args:
            request: The inbound request.
            job_id: Identifier of the job to poll.

        Returns:
            Response: The job's record.
        """
        if request.method != _GET:
            return _method_not_allowed((_GET,))
        return _json_response(_encode_job(self._jobs.poll(job_id)))

    def _job_raw(self, request: Request, job_id: str) -> Response:
        """Hand over the untruncated binary payload a job produced.

        Args:
            request: The inbound request.
            job_id: Identifier of the job whose payload is wanted.

        Returns:
            Response: The payload as an attachment, or a failure when the job
            produced none or its payload has already been collected.
        """
        if request.method != _GET:
            return _method_not_allowed((_GET,))
        record = self._jobs.poll(job_id)
        payload = self._jobs.take_raw(job_id)
        if payload is None:
            message = f"job {job_id!r} has no binary payload waiting to be collected"
            return _failure(message, kind="no_raw_payload", status=_STATUS_NOT_FOUND)
        return Response(status=_STATUS_OK, body=payload, content_type=_OCTET_TYPE, headers=_attachment(record.operation))

    def _shutdown(self) -> Response:
        """Answer the shutdown route and then stop the server.

        Returns:
            Response: An empty JSON object, sent before the server stops.
        """
        stopper = threading.Thread(target=self._delayed_stop, name="hexbench-shutdown", daemon=True)
        stopper.start()
        return _json_response({})

    def _delayed_stop(self) -> None:
        """Give the shutdown response time to reach the client, then stop."""
        time.sleep(_SHUTDOWN_DELAY)
        self._stop()

    def _note_exercised(self, name: str) -> None:
        """Count an operation as exercised by a request-thread invocation.

        Args:
            name: Name of the operation that succeeded.
        """
        with self._state:
            self._exercised.add(name)

    def _index(self, request: Request) -> Response:
        """Serve the application document.

        The session token is carried as a query parameter on this one request,
        which is how the page comes to know it. Any occurrence of the literal
        marker ``__HEXBENCH_TOKEN__`` in the document is replaced by the token,
        so the page can also pick it up without reading its own address.

        Args:
            request: The inbound request.

        Returns:
            Response: The application document.
        """
        if request.method != _GET:
            return _method_not_allowed((_GET,))
        supplied = _first(request.query, _AUTH_QUERY) or ""
        if not supplied.isascii() or not secrets.compare_digest(supplied, self._token):
            return _failure("the session token is missing or incorrect", kind="forbidden", status=_STATUS_FORBIDDEN)
        document = _read_file(self._static_root / _INDEX_NAME)
        if document is None:
            message = f"{_INDEX_NAME} is missing from {self._static_root}"
            return _failure(message, kind="no_such_asset", status=_STATUS_NOT_FOUND)
        body = document.replace(_SESSION_MARKER.encode("ascii"), self._token.encode("ascii"))
        return Response(status=_STATUS_OK, body=body, content_type=_HTML_TYPE, headers=_NO_STORE)

    def _asset(self, request: Request, rest: tuple[str, ...]) -> Response:
        """Serve one browser asset from the static directory.

        The resolved path is required to lie inside the static directory, so no
        arrangement of dot segments, drive letters or separators can reach a file
        outside it, and only a short list of extensions is served at all.

        Args:
            request: The inbound request.
            rest: Path segments after ``/static``.

        Returns:
            Response: The asset, or a failure when it is absent or not servable.
        """
        if request.method != _GET:
            return _method_not_allowed((_GET,))
        if not rest:
            return _no_route(request)
        try:
            resolved = self._static_root.joinpath(*rest).resolve()
        except OSError:
            return _failure(f"{request.path} cannot be resolved", kind="no_such_asset", status=_STATUS_NOT_FOUND)
        if not resolved.is_relative_to(self._static_root):
            return _failure(f"{request.path} is outside the asset directory", kind="forbidden", status=_STATUS_FORBIDDEN)
        content_type = _CONTENT_TYPES.get(resolved.suffix.lower())
        if content_type is None:
            return _failure(f"{resolved.suffix!r} assets are not served", kind="unsupported_asset", status=_STATUS_FORBIDDEN)
        body = _read_file(resolved) if resolved.is_file() else None
        if body is None:
            return _failure(f"{request.path} was not found", kind="no_such_asset", status=_STATUS_NOT_FOUND)
        return Response(status=_STATUS_OK, body=body, content_type=content_type, headers=_NO_STORE)
