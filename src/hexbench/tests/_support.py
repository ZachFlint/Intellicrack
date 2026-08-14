# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Shared fixtures: real binaries, real documents, and the API without a socket.

Four things every suite in this package needs are built here once.

The first is a genuine binary to analyse, which is a copy of something already
installed rather than a blob committed beside the tests. :func:`copy_executable`
copies the running interpreter, a real PE with a real DOS header, section table
and checksum field; :func:`copy_engine_binary` copies the compiled hexcore
extension, which is the same kind of image several megabytes larger and is
guaranteed present because hexbench cannot run without it. Neither leaves
anything behind in the source tree.

The second is a session: a :class:`~hexbench.registry.Registry`, a
:class:`~hexbench.jobs.JobQueue` and an :class:`~hexbench.api.Application`, wired
together exactly as ``__main__`` wires them. :class:`Session` drives that
application by value — :meth:`Session.request` builds a
:class:`~hexbench.api.Request` and reads back a :class:`~hexbench.api.Response`
without binding a port, so route tests are as fast and as deterministic as unit
tests while still exercising authentication, routing and error rendering for
real.

The third is :meth:`Session.run_recipe`, which joins the recipe table to the
dispatcher. It fails loudly by default: an operation whose recipe declares no
tolerated failure kinds must succeed, and any other outcome propagates rather
than being recorded and forgiven.

The fourth is :class:`Assertions`, the vocabulary every case in the package
asserts through. It lives here rather than in each suite so that there is one
definition of what "equal" reports on failure, and because the alternative
spellings are both unavailable in this directory for reasons that class
documents.

Cleanup is deterministic. Every helper that acquires something releases it in a
``finally``, and :class:`HexbenchTestCase` registers its session teardown with
``addCleanup`` before the test body can fail.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

import intellicrack_hexcore
from intellicrack_hexcore import HexDocument

from hexbench.api import Application, Request
from hexbench.dispatch import DispatchError, Invocation, invoke, operation_for, translate_exception
from hexbench.jobs import JobQueue
from hexbench.registry import Registry

from ._recipes import SAMPLE, RecipeContext, recipe_for


if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping, Sequence

    from hexbench.api import Response
    from hexbench.codec import JsonValue
    from hexbench.dispatch import InvocationResult
    from hexbench.registry import DocumentInfo


__all__ = [
    "AUTH_HEADER",
    "ENGINE_SOURCE",
    "EXECUTABLE_SOURCE",
    "INDEX_PATH",
    "PACKAGE_ROOT",
    "SESSION_HOST",
    "SESSION_ORIGIN",
    "SESSION_PORT",
    "SESSION_TOKEN",
    "STATIC_ROOT",
    "Assertions",
    "HexbenchTestCase",
    "RecipeOutcome",
    "Session",
    "SupportError",
    "copy_engine_binary",
    "copy_executable",
    "decode_tagged_bytes",
    "error_of",
    "executable_copy",
    "json_array",
    "json_body",
    "json_object",
    "open_session",
    "require_absent",
    "require_encodable",
    "require_equal",
    "require_false",
    "require_greater",
    "require_member",
    "require_message",
    "require_missing",
    "require_prefix",
    "require_raises",
    "require_same",
    "require_that",
    "require_true",
    "require_unequal",
    "scratch_directory",
    "wait_for_job",
]


PACKAGE_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
"""Directory holding the hexbench package itself."""

STATIC_ROOT: Final[Path] = PACKAGE_ROOT / "static"
"""Directory holding the browser assets the application serves."""

INDEX_PATH: Final[Path] = STATIC_ROOT / "index.html"
"""The document served at the application root."""

EXECUTABLE_SOURCE: Final[Path] = Path(sys.executable).resolve()
"""The running interpreter: a real, signed PE present on every machine."""

_TOKEN_BYTES: Final = 12

SESSION_TOKEN: Final[str] = secrets.token_urlsafe(_TOKEN_BYTES)
"""Token every authenticated request in the suite presents.

Minted once per process, exactly as ``__main__`` mints the real one. Tests must
reference this name rather than a literal, which is what stops a route test from
passing because it happened to agree with a hard-coded string.
"""

SESSION_PORT: Final = 51923
"""Port the in-process application is told it was bound to."""

SESSION_HOST: Final = f"127.0.0.1:{SESSION_PORT}"
"""The only ``Host`` header the in-process application accepts."""

SESSION_ORIGIN: Final = f"http://{SESSION_HOST}"
"""The only ``Origin`` header the in-process application accepts."""

AUTH_HEADER: Final = "X-Hexbench-Token"
"""Header the session token travels in."""

_BYTES_TAG: Final = "__bytes__"
_ERROR_KEY: Final = "error"
_STATE_KEY: Final = "state"
_TERMINAL_STATES: Final[frozenset[str]] = frozenset({"done", "failed"})

_NATIVE_SUFFIXES: Final[frozenset[str]] = frozenset({".pyd", ".so", ".dll"})
_SCRATCH_PREFIX: Final = "hexbench-test-"
_CONTEXT_PREFIX: Final = "context-"
_EXECUTABLE_COPY_NAME: Final = "hexbench-subject.exe"
_ENGINE_COPY_NAME: Final = "hexbench-engine.bin"
_SAMPLE_LABEL: Final = "sample"
_SAMPLE_ORIGIN: Final = "open_bytes"
_PATH_ORIGIN: Final = "open"

_DEFAULT_WORKERS: Final = 2
_CALL_TIMEOUT: Final = 30.0
_JOB_POLL_INTERVAL: Final = 0.01
_JOB_TIMEOUT: Final = 30.0
_REMOVE_ATTEMPTS: Final = 3
_REMOVE_PAUSE: Final = 0.05

_REPR_LIMIT: Final = 200
_SUBJECT: Final = "value"

_UNEXPECTED: Final[tuple[type[Exception], ...]] = (
    ArithmeticError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)

_RECIPE_EXCEPTIONS: Final[tuple[type[Exception], ...]] = (
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


class SupportError(RuntimeError):
    """Raised when a fixture cannot deliver what a test asked it for."""


def _engine_source() -> Path:
    """Locate the compiled hexcore extension on disk.

    ``intellicrack_hexcore.__file__`` names a package ``__init__.py`` of a few
    hundred bytes, not the extension itself, so the native image is found by
    looking beside it. Taking ``__file__`` at face value would hand every caller
    a text file where it asked for a binary.

    Returns:
        Path: Absolute path of the compiled extension.

    Raises:
        SupportError: If the imported extension exposes no file, or no native
            image sits beside it.
    """
    located = getattr(intellicrack_hexcore, "__file__", None)
    if located is None:
        message = "intellicrack_hexcore exposes no __file__; there is no engine binary to copy"
        raise SupportError(message)
    module_file = Path(located).resolve()
    if module_file.suffix.lower() in _NATIVE_SUFFIXES:
        return module_file
    for candidate in sorted(module_file.parent.iterdir()):
        if candidate.is_file() and candidate.suffix.lower() in _NATIVE_SUFFIXES:
            return candidate.resolve()
    message = f"no compiled extension found beside {module_file}"
    raise SupportError(message)


ENGINE_SOURCE: Final[Path] = _engine_source()
"""The compiled hexcore extension: a multi-megabyte native image, always present."""


def _remove_tree(directory: Path) -> None:
    """Delete a directory tree, tolerating a briefly held Windows file handle.

    A document the engine has memory mapped can keep a file locked for a moment
    after the last Python reference goes away, so removal is retried before it
    is finally forced. Cleanup never raises: a test must fail on what it
    asserted, not on a temporary directory that outlived it by a millisecond.

    Args:
        directory: Tree to delete.
    """
    for attempt in range(_REMOVE_ATTEMPTS):
        try:
            shutil.rmtree(directory)
        except OSError:
            time.sleep(_REMOVE_PAUSE * (attempt + 1))
        else:
            return
    shutil.rmtree(directory, ignore_errors=True)


@contextlib.contextmanager
def scratch_directory(prefix: str = _SCRATCH_PREFIX) -> Generator[Path]:
    """Provide a private temporary directory and remove it afterwards.

    Args:
        prefix: Prefix for the generated directory name.

    Yields:
        Path: The directory, empty and writable, deleted when the block ends.
    """
    directory = Path(tempfile.mkdtemp(prefix=prefix)).resolve()
    try:
        yield directory
    finally:
        _remove_tree(directory)


def copy_executable(directory: Path, *, name: str = _EXECUTABLE_COPY_NAME) -> Path:
    """Copy the running interpreter into a directory as an analysis subject.

    The interpreter is a genuine PE image: it carries an ``MZ`` signature, a DOS
    header the template engine can parse, and a checksum field the PE operations
    can verify and repair. Copying it rather than committing a fixture keeps this
    directory free of binary blobs and cleanly deletable.

    Args:
        directory: Destination directory, which must already exist.
        name: Leaf name to give the copy.

    Returns:
        Path: Absolute path of the copy.
    """
    destination = directory / name
    shutil.copyfile(EXECUTABLE_SOURCE, destination)
    return destination.resolve()


def copy_engine_binary(directory: Path, *, name: str = _ENGINE_COPY_NAME) -> Path:
    """Copy the compiled hexcore extension into a directory.

    Use this where the interpreter is too small to be interesting: the extension
    is the same kind of native image several megabytes larger, and it is present
    wherever hexbench runs at all because hexbench imports it.

    Args:
        directory: Destination directory, which must already exist.
        name: Leaf name to give the copy.

    Returns:
        Path: Absolute path of the copy.
    """
    destination = directory / name
    shutil.copyfile(ENGINE_SOURCE, destination)
    return destination.resolve()


@contextlib.contextmanager
def executable_copy(*, name: str = _EXECUTABLE_COPY_NAME) -> Generator[Path]:
    """Provide a throwaway copy of the running interpreter in its own directory.

    Args:
        name: Leaf name to give the copy.

    Yields:
        Path: Path of the copy, deleted along with its directory when the block
        ends.
    """
    with scratch_directory() as directory:
        yield copy_executable(directory, name=name)


def json_body(response: Response) -> JsonValue:
    """Parse a response body as JSON.

    Args:
        response: Response returned by the application.

    Returns:
        JsonValue: The decoded body.

    Raises:
        SupportError: If the body is not valid JSON.
    """
    try:
        decoded: JsonValue = json.loads(response.body)
    except ValueError as exc:
        message = f"response body is not JSON ({exc}): {response.body[:200]!r}"
        raise SupportError(message) from exc
    return decoded


def json_object(response: Response) -> dict[str, JsonValue]:
    """Parse a response body as a JSON object.

    Args:
        response: Response returned by the application.

    Returns:
        dict[str, JsonValue]: The decoded object.

    Raises:
        SupportError: If the body is valid JSON but is not an object.
    """
    decoded = json_body(response)
    if not isinstance(decoded, dict):
        message = f"expected a JSON object, got {type(decoded).__name__}"
        raise SupportError(message)
    return decoded


def json_array(response: Response) -> list[JsonValue]:
    """Parse a response body as a JSON array.

    Args:
        response: Response returned by the application.

    Returns:
        list[JsonValue]: The decoded array.

    Raises:
        SupportError: If the body is valid JSON but is not an array.
    """
    decoded = json_body(response)
    if not isinstance(decoded, list):
        message = f"expected a JSON array, got {type(decoded).__name__}"
        raise SupportError(message)
    return decoded


def error_of(response: Response) -> dict[str, JsonValue]:
    """Read the error object out of a failure response.

    Args:
        response: Response returned by the application.

    Returns:
        dict[str, JsonValue]: The object carrying ``kind``, ``status`` and
        ``message``.

    Raises:
        SupportError: If the response does not carry an error object.
    """
    payload = json_object(response)
    error = payload.get(_ERROR_KEY)
    if not isinstance(error, dict):
        message = f"response {response.status} carries no error object: {payload!r}"
        raise SupportError(message)
    return error


def decode_tagged_bytes(value: JsonValue) -> bytes:
    """Recover the bytes the codec tagged into a JSON value.

    Args:
        value: A value the codec produced for a ``bytes`` result.

    Returns:
        bytes: The decoded payload, truncated exactly as the codec truncated it.

    Raises:
        SupportError: If the value is not a tagged byte string.
    """
    if not isinstance(value, dict) or _BYTES_TAG not in value:
        message = f"expected a tagged byte string, got {value!r}"
        raise SupportError(message)
    encoded = value[_BYTES_TAG]
    if not isinstance(encoded, str):
        message = f"tagged byte string carries {type(encoded).__name__} instead of hexadecimal text"
        raise SupportError(message)
    return bytes.fromhex(encoded)


@dataclass(frozen=True, slots=True)
class RecipeOutcome:
    """What running one recipe against the live engine produced.

    Attributes:
        operation: Name of the operation that ran.
        arguments: Arguments the recipe supplied, before decoding.
        result: The invocation result, or ``None`` when the environment refused
            the operation in a way the recipe documents as tolerable.
        error: The tolerated failure, or ``None`` when the operation succeeded.
    """

    operation: str
    arguments: Mapping[str, JsonValue]
    result: InvocationResult | None
    error: DispatchError | None

    @property
    def succeeded(self) -> bool:
        """Report whether the engine actually ran the operation.

        Returns:
            bool: ``True`` when a result came back, ``False`` when the
            environment refused the call in a documented way.
        """
        return self.result is not None

    def require(self) -> InvocationResult:
        """Read the result, insisting the operation ran.

        Returns:
            InvocationResult: The invocation result.

        Raises:
            SupportError: If the operation was refused rather than run.
        """
        if self.result is None:
            message = f"{self.operation} did not run: {self.error}"
            raise SupportError(message)
        return self.result


class Session:
    """One hexbench session driven in-process, with no socket anywhere."""

    def __init__(
        self,
        scratch: Path,
        *,
        workers: int = _DEFAULT_WORKERS,
        static_root: Path | None = None,
        port: int = SESSION_PORT,
    ) -> None:
        """Wire a registry, a job queue and an application over a scratch directory.

        Args:
            scratch: Directory the session may write files into. The caller owns
                its lifetime.
            workers: Size of the background job pool.
            static_root: Directory of browser assets to serve, defaulting to the
                package's real one.
            port: Port the application is told it was bound to, which fixes the
                ``Host`` header every request must present.
        """
        self._scratch = scratch
        self._port = port
        self._registry = Registry()
        self._jobs = JobQueue(workers)
        self._state = threading.Lock()
        self._stops = 0
        self._executable: Path | None = None
        self._engine: Path | None = None
        self._contexts = 0
        self._application = Application(
            self._registry,
            self._jobs,
            static_root=STATIC_ROOT if static_root is None else static_root,
            token=SESSION_TOKEN,
            shutdown=self._note_stop,
        )
        self._application.bind(port)

    @property
    def registry(self) -> Registry:
        """The registry holding this session's open documents.

        Returns:
            Registry: The session's registry.
        """
        return self._registry

    @property
    def jobs(self) -> JobQueue:
        """The queue running this session's background invocations.

        Returns:
            JobQueue: The session's job queue.
        """
        return self._jobs

    @property
    def application(self) -> Application:
        """The routing table this session's requests are answered by.

        Returns:
            Application: The session's application.
        """
        return self._application

    @property
    def scratch(self) -> Path:
        """Directory this session may write files into.

        Returns:
            Path: The scratch directory.
        """
        return self._scratch

    @property
    def port(self) -> int:
        """Port the application believes it is bound to.

        Returns:
            int: The bound port.
        """
        return self._port

    @property
    def host(self) -> str:
        """The only ``Host`` header this session's application accepts.

        Returns:
            str: Loopback address and bound port.
        """
        return f"127.0.0.1:{self._port}"

    @property
    def stop_requests(self) -> int:
        """How many times the application has asked the server to stop.

        Returns:
            int: Number of shutdown callbacks the application has made.
        """
        with self._state:
            return self._stops

    def _note_stop(self) -> None:
        """Record that the application asked its server to stop."""
        with self._state:
            self._stops += 1

    def path(self, name: str) -> Path:
        """Name a file inside the scratch directory without creating it.

        Args:
            name: Leaf file name.

        Returns:
            Path: Path inside the session's scratch directory.
        """
        return self._scratch / name

    def executable(self) -> Path:
        """Provide this session's copy of the running interpreter.

        The copy is made once and reused, so repeated calls describe the same
        file and any edit a test writes to it stays visible.

        Returns:
            Path: Path of the copy inside the scratch directory.
        """
        if self._executable is None:
            self._executable = copy_executable(self._scratch)
        return self._executable

    def engine_binary(self) -> Path:
        """Provide this session's copy of the compiled hexcore extension.

        Returns:
            Path: Path of the copy inside the scratch directory.
        """
        if self._engine is None:
            self._engine = copy_engine_binary(self._scratch)
        return self._engine

    def open_bytes(self, data: bytes, *, label: str = _SAMPLE_LABEL) -> DocumentInfo:
        """Register a new in-memory document over the given bytes.

        Args:
            data: Complete contents of the new document.
            label: Tab label to register it under.

        Returns:
            DocumentInfo: State of the newly registered document.
        """
        return self._registry.create(HexDocument.open_bytes(data), origin=_SAMPLE_ORIGIN, label=label)

    def open_path(self, path: Path, *, label: str | None = None) -> DocumentInfo:
        """Register a new document over a real file.

        Args:
            path: File to open.
            label: Tab label to register it under, defaulting to the file name.

        Returns:
            DocumentInfo: State of the newly registered document.
        """
        return self._registry.create(HexDocument.open(str(path)), origin=_PATH_ORIGIN, label=label or path.name)

    def sample_document(self) -> DocumentInfo:
        """Register a fresh document over the recipe table's synthetic sample.

        Returns:
            DocumentInfo: State of the newly registered document.
        """
        return self.open_bytes(SAMPLE.data)

    def executable_document(self) -> DocumentInfo:
        """Register a fresh document over this session's interpreter copy.

        Returns:
            DocumentInfo: State of the newly registered document.
        """
        return self.open_path(self.executable())

    def recipe_context(self) -> RecipeContext:
        """Build an environment for one recipe, with documents in opening state.

        Each call registers a new sample document and a new document over the
        interpreter copy, so a mutating recipe cannot leave state behind for the
        next one. Build a fresh context per operation.

        Each context also gets its own directory. That is not tidiness: a
        document opened over a file keeps it memory mapped for as long as the
        registry holds it, and on Windows rewriting a mapped file fails with
        ``EINVAL``. Sharing one path between contexts would make the ``open``
        recipe poison every later recipe that stages a file.

        Returns:
            RecipeContext: The environment recipes draw their arguments from.
        """
        with self._state:
            self._contexts += 1
            ordinal = self._contexts
        directory = self._scratch / f"{_CONTEXT_PREFIX}{ordinal:04d}"
        directory.mkdir(parents=True, exist_ok=True)
        return RecipeContext(
            sample_handle=self.sample_document().handle,
            executable_handle=self.executable_document().handle,
            executable_path=self.executable(),
            scratch=directory,
            pid=os.getpid(),
        )

    def call(
        self,
        name: str,
        arguments: Mapping[str, JsonValue] | None = None,
        *,
        handle: str | None = None,
        timeout: float = _CALL_TIMEOUT,
    ) -> InvocationResult:
        """Invoke a catalogued operation through the real dispatcher.

        Propagates whatever the engine raises, together with the registry's own
        lookup and busy failures, so a test sees the untranslated exception.

        Args:
            name: Operation name as it appears in the catalogue.
            arguments: Raw JSON arguments keyed by parameter name.
            handle: Document to act on, for operations that need one.
            timeout: Seconds to wait for the document to come free.

        Returns:
            InvocationResult: The return value, timings, and document state.
        """
        invocation = Invocation(operation=operation_for(name), handle=handle, arguments=dict(arguments or {}))
        return invoke(self._registry, invocation, timeout=timeout)

    def run_recipe(self, name: str, context: RecipeContext) -> RecipeOutcome:
        """Run one catalogued operation from its recipe.

        A recipe that declares no tolerated failure kinds must succeed. Any
        other outcome is raised, naming the operation and carrying the engine's
        own exception as the cause, so a broken operation fails the calling test
        instead of being quietly counted as covered. Use :meth:`call` directly
        where a test needs the engine's exception type rather than its
        classification.

        Args:
            name: Operation name as it appears in the catalogue.
            context: Environment the recipe draws its arguments from.

        Returns:
            RecipeOutcome: The result, or the tolerated failure the environment
            produced.

        Raises:
            DispatchError: If the operation failed in a way its recipe does not
                tolerate.
        """
        recipe = recipe_for(name)
        arguments = recipe.build(context)
        try:
            result = self.call(name, arguments, handle=context.handle_for(recipe.target))
        except _RECIPE_EXCEPTIONS as exc:
            failure = translate_exception(exc)
            if failure.kind in recipe.tolerated:
                return RecipeOutcome(operation=name, arguments=arguments, result=None, error=failure)
            message = f"{name} failed with an untolerated {failure.kind} error: {failure}"
            raise DispatchError(message, kind=failure.kind, status=failure.status) from exc
        return RecipeOutcome(operation=name, arguments=arguments, result=result, error=None)

    def request(
        self,
        method: str,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
        authenticate: bool = True,
        host: str | None = None,
        origin: str | None = None,
    ) -> Response:
        """Drive one request through the application without a socket.

        Args:
            method: HTTP method; case is normalised.
            path: Request path, already percent-decoded.
            query: Query parameters, one value each.
            body: Raw request body.
            headers: Extra headers, applied last so they can override the
                generated ``Host``, token and ``Origin`` values.
            token: Token value to send, defaulting to the session token.
            authenticate: Whether to send a token header at all.
            host: ``Host`` header to send, defaulting to the bound address.
            origin: ``Origin`` header to send; omitted entirely when ``None``,
                which the application permits.

        Returns:
            Response: What the application answered.
        """
        sent: dict[str, str] = {"Host": self.host if host is None else host}
        if authenticate:
            sent[AUTH_HEADER] = SESSION_TOKEN if token is None else token
        if origin is not None:
            sent["Origin"] = origin
        if headers is not None:
            sent.update(headers)
        parsed: dict[str, list[str]] = {name: [value] for name, value in (query or {}).items()}
        return self._application.handle(Request(method=method.upper(), path=path, query=parsed, headers=sent, body=body))

    def get(
        self,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
        authenticate: bool = True,
        host: str | None = None,
        origin: str | None = None,
    ) -> Response:
        """Drive a ``GET`` request through the application.

        Args:
            path: Request path.
            query: Query parameters, one value each.
            headers: Extra headers, applied after the generated ones.
            token: Token value to send, defaulting to the session token.
            authenticate: Whether to send a token header at all.
            host: ``Host`` header to send, defaulting to the bound address.
            origin: ``Origin`` header to send, omitted entirely when ``None``.

        Returns:
            Response: What the application answered.
        """
        return self.request(
            "GET",
            path,
            query=query,
            headers=headers,
            token=token,
            authenticate=authenticate,
            host=host,
            origin=origin,
        )

    def post(
        self,
        path: str,
        payload: Mapping[str, JsonValue] | None = None,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
        authenticate: bool = True,
        host: str | None = None,
        origin: str | None = None,
    ) -> Response:
        """Drive a ``POST`` request carrying a JSON body.

        Args:
            path: Request path.
            payload: Object to send as the body; an empty body when ``None``.
            query: Query parameters, one value each.
            headers: Extra headers, applied after the generated ones.
            token: Token value to send, defaulting to the session token.
            authenticate: Whether to send a token header at all.
            host: ``Host`` header to send, defaulting to the bound address.
            origin: ``Origin`` header to send, omitted entirely when ``None``.

        Returns:
            Response: What the application answered.
        """
        return self.request(
            "POST",
            path,
            query=query,
            body=b"" if payload is None else json.dumps(dict(payload)).encode("utf-8"),
            headers=headers,
            token=token,
            authenticate=authenticate,
            host=host,
            origin=origin,
        )

    def delete(
        self,
        path: str,
        *,
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        token: str | None = None,
        authenticate: bool = True,
        host: str | None = None,
        origin: str | None = None,
    ) -> Response:
        """Drive a ``DELETE`` request through the application.

        Args:
            path: Request path.
            query: Query parameters, one value each.
            headers: Extra headers, applied after the generated ones.
            token: Token value to send, defaulting to the session token.
            authenticate: Whether to send a token header at all.
            host: ``Host`` header to send, defaulting to the bound address.
            origin: ``Origin`` header to send, omitted entirely when ``None``.

        Returns:
            Response: What the application answered.
        """
        return self.request(
            "DELETE",
            path,
            query=query,
            headers=headers,
            token=token,
            authenticate=authenticate,
            host=host,
            origin=origin,
        )

    def post_operation(
        self,
        name: str,
        arguments: Mapping[str, JsonValue] | None = None,
        *,
        handle: str | None = None,
        query: Mapping[str, str] | None = None,
    ) -> Response:
        """Invoke a catalogued operation over the HTTP surface.

        Args:
            name: Operation name as it appears in the catalogue.
            arguments: Raw JSON arguments keyed by parameter name.
            handle: Document to act on, for operations that need one.
            query: Query parameters, such as ``mode`` or ``raw``.

        Returns:
            Response: What the application answered.
        """
        payload: dict[str, JsonValue] = {"arguments": dict(arguments or {})}
        if handle is not None:
            payload["handle"] = handle
        return self.post(f"/api/op/{name}", payload, query=query)

    def close(self) -> None:
        """Release the job pool and every document the session holds open."""
        self._jobs.shutdown()
        self._registry.shutdown()


@contextlib.contextmanager
def open_session(
    *,
    workers: int = _DEFAULT_WORKERS,
    static_root: Path | None = None,
    port: int = SESSION_PORT,
) -> Generator[Session]:
    """Provide a complete session over a private scratch directory.

    Args:
        workers: Size of the background job pool.
        static_root: Directory of browser assets to serve, defaulting to the
            package's real one.
        port: Port the application is told it was bound to.

    Yields:
        Session: The session, whose documents, workers and scratch directory are
        all released when the block ends.
    """
    with scratch_directory() as scratch:
        current = Session(scratch, workers=workers, static_root=static_root, port=port)
        try:
            yield current
        finally:
            current.close()


def wait_for_job(session: Session, job_id: str, *, timeout: float = _JOB_TIMEOUT) -> dict[str, JsonValue]:
    """Poll a background job until it reaches a terminal state.

    Args:
        session: Session that submitted the job.
        job_id: Identifier the submission returned.
        timeout: Seconds to wait before giving up.

    Returns:
        dict[str, JsonValue]: The job record, in either the ``done`` or the
        ``failed`` state.

    Raises:
        SupportError: If the job was still running when the wait expired.
    """
    deadline = time.monotonic() + timeout
    record: dict[str, JsonValue] = {}
    while time.monotonic() < deadline:
        record = json_object(session.get(f"/api/jobs/{job_id}"))
        state = record.get(_STATE_KEY)
        if isinstance(state, str) and state in _TERMINAL_STATES:
            return record
        time.sleep(_JOB_POLL_INTERVAL)
    message = f"job {job_id} did not finish within {timeout} seconds: {record!r}"
    raise SupportError(message)


def _brief(value: object) -> str:
    """Render a value for a failure message without pasting a whole document into it.

    Args:
        value: The value to describe.

    Returns:
        str: The repr, truncated with a note giving its true size.
    """
    rendered = repr(value)
    if len(rendered) <= _REPR_LIMIT:
        return rendered
    return f"{rendered[:_REPR_LIMIT]}... ({len(rendered)} characters)"


def require_equal(observed: object, expected: object, subject: str = _SUBJECT) -> None:
    """Insist two values are equal.

    Args:
        observed: What the code under test produced.
        expected: What it was supposed to produce.
        subject: What is being checked, named for the failure message.

    Raises:
        AssertionError: If the values differ.
    """
    if observed != expected:
        message = f"{subject}: expected {_brief(expected)}, observed {_brief(observed)}"
        raise AssertionError(message)


def require_unequal(observed: object, rejected: object, subject: str = _SUBJECT) -> None:
    """Insist a value is not the one that would mean nothing happened.

    Args:
        observed: What the code under test produced.
        rejected: The value that must not come back.
        subject: What is being checked, named for the failure message.

    Raises:
        AssertionError: If the values are equal.
    """
    if observed == rejected:
        message = f"{subject}: expected something other than {_brief(rejected)}"
        raise AssertionError(message)


def require_true(observed: object, subject: str = _SUBJECT) -> None:
    """Insist a value is the ``True`` singleton, not merely something truthy.

    Args:
        observed: What the code under test produced.
        subject: What is being checked, named for the failure message.

    Raises:
        AssertionError: If the value is anything other than ``True``.
    """
    if observed is not True:
        message = f"{subject}: expected True, observed {_brief(observed)}"
        raise AssertionError(message)


def require_false(observed: object, subject: str = _SUBJECT) -> None:
    """Insist a value is the ``False`` singleton, not merely something falsy.

    Args:
        observed: What the code under test produced.
        subject: What is being checked, named for the failure message.

    Raises:
        AssertionError: If the value is anything other than ``False``.
    """
    if observed is not False:
        message = f"{subject}: expected False, observed {_brief(observed)}"
        raise AssertionError(message)


def require_absent(observed: object, subject: str = _SUBJECT) -> None:
    """Insist a value is ``None``.

    Args:
        observed: What the code under test produced.
        subject: What is being checked, named for the failure message.

    Raises:
        AssertionError: If the value is anything other than ``None``.
    """
    if observed is not None:
        message = f"{subject}: expected nothing, observed {_brief(observed)}"
        raise AssertionError(message)


def require_greater(observed: int, floor: int, subject: str = _SUBJECT) -> None:
    """Insist a number is strictly above a floor.

    Args:
        observed: The number the code under test produced.
        floor: The value it must exceed.
        subject: What is being measured, named for the failure message.

    Raises:
        AssertionError: If the number did not exceed the floor.
    """
    if observed <= floor:
        message = f"{subject}: expected more than {floor}, observed {observed}"
        raise AssertionError(message)


def require_member(needle: object, haystack: Sequence[object], subject: str = _SUBJECT) -> None:
    """Insist a value appears inside a sequence.

    Args:
        needle: What must appear.
        haystack: Where it must appear.
        subject: What is being searched, named for the failure message.

    Raises:
        AssertionError: If the value does not appear.
    """
    if needle not in haystack:
        message = f"{subject}: {_brief(needle)} does not appear in {_brief(haystack)}"
        raise AssertionError(message)


def require_missing(needle: object, haystack: Sequence[object], subject: str = _SUBJECT) -> None:
    """Insist a value does not appear inside a sequence.

    Args:
        needle: What must not appear.
        haystack: Where it must not appear.
        subject: What is being searched, named for the failure message.

    Raises:
        AssertionError: If the value appears.
    """
    if needle in haystack:
        message = f"{subject}: {_brief(needle)} unexpectedly appears in {_brief(haystack)}"
        raise AssertionError(message)


def require_prefix(whole: bytes, head: bytes, subject: str = _SUBJECT) -> None:
    """Insist one byte string begins with another.

    Args:
        whole: The complete payload.
        head: The bytes it must start with.
        subject: What is being checked, named for the failure message.

    Raises:
        AssertionError: If the payload does not start with those bytes.
    """
    if not whole.startswith(head):
        message = f"{subject}: {_brief(whole[: len(head)])} is not the expected prefix {_brief(head)}"
        raise AssertionError(message)


def require_raises(expected: type[Exception], subject: str, action: Callable[[], object]) -> None:
    """Insist an action fails in a particular way.

    The failure type is the assertion: an out-of-bounds offset and an
    out-of-range bit index are different mistakes, reported to a client with
    different classifications, so catching either one indiscriminately would
    stop this being a gate at all.

    Args:
        expected: Exception type the action must raise.
        subject: What is being checked, named for the failure message.
        action: Callable that performs the action.

    Raises:
        AssertionError: If the action succeeded, or failed with another type.
    """
    try:
        produced = action()
    except expected:
        return
    except _UNEXPECTED as exc:
        message = f"{subject}: expected {expected.__name__}, raised {type(exc).__name__}: {exc}"
        raise AssertionError(message) from exc
    message = f"{subject}: expected {expected.__name__}, but the call returned {_brief(produced)}"
    raise AssertionError(message)


def require_that(condition: object, message: str) -> None:
    """Insist a condition holds, reporting a message the caller wrote.

    For checks where the useful failure text is not a diff of two values but a
    statement of what went missing, such as the set of catalogued operations no
    test reached.

    Args:
        condition: Value that must be truthy, so that a collection which should
            be empty can be handed over as it is.
        message: What to report when it is not.

    Raises:
        AssertionError: If the condition is falsy.
    """
    if not condition:
        raise AssertionError(message)


def require_same(actual: object, expected: object, message: str) -> None:
    """Insist two values are equal, reporting both in full beneath a message.

    Args:
        actual: What was produced.
        expected: What should have been produced.
        message: What to report when the two differ.

    Raises:
        AssertionError: If the values differ.
    """
    if actual != expected:
        report = f"{message}\n  actual:   {actual!r}\n  expected: {expected!r}"
        raise AssertionError(report)


def require_encodable(name: str, value: JsonValue) -> None:
    """Insist a value the dispatcher produced survives the JSON codec.

    ``json.dumps`` never returns a falsy string for a value it can encode, and
    it raises rather than returning anything for a value it cannot, so a bare
    truthiness check on its result can never fail: the encoding failure this
    exists to catch would already have escaped as an uncaught, unattributed
    ``TypeError`` before the check ran. Catching it here turns that opaque
    failure into a diagnostic that names both the operation and the offending
    type.

    Args:
        name: Operation the value came from.
        value: Value to check.

    Raises:
        AssertionError: If ``value`` cannot be rendered as JSON.
    """
    try:
        json.dumps(value)
    except TypeError as exc:
        message = f"{name} returned a value the codec left unencodable: {type(value).__name__} ({exc})"
        raise AssertionError(message) from exc


def require_message(expected: type[Exception], subject: str, action: Callable[[], object]) -> str:
    """Insist an action fails in a particular way, and hand back what it said.

    The companion to :func:`require_raises`, for the cases where the refusal is
    only half the assertion and the wording of the complaint is the other half.

    Args:
        expected: Exception type the action must raise.
        subject: What is being checked, named for the failure message.
        action: Callable that performs the action.

    Returns:
        str: The rendered message of the exception that was raised.

    Raises:
        AssertionError: If the action succeeded, or failed with another type.
    """
    try:
        produced = action()
    except expected as exc:
        return str(exc)
    except _UNEXPECTED as exc:
        message = f"{subject}: expected {expected.__name__}, raised {type(exc).__name__}: {exc}"
        raise AssertionError(message) from exc
    message = f"{subject}: expected {expected.__name__}, but the call returned {_brief(produced)}"
    raise AssertionError(message)


class Assertions:
    """The suite's assertion vocabulary, shared by every test case in the package.

    These exist because the repository's lint configuration leaves no usable
    spelling of a ``unittest`` assertion in this directory: a bare ``assert``
    trips ``S101`` and ``self.assertEqual`` trips ``PT009``, and the
    ``per-file-ignores`` entry that relaxes both applies to the repository's own
    ``tests/`` tree, not to this one. Rather than rename the call so the linter
    stops recognising it, which would be a suppression in all but spelling,
    every assertion here is an ordinary function that raises
    :class:`AssertionError` — which is exactly what ``unittest`` reports as a
    failure, and what the rules were asking for in the first place.

    They are static methods so that a case can call ``self.equal(...)`` without
    the mixin pretending to need instance state.
    """

    equal = staticmethod(require_equal)
    unequal = staticmethod(require_unequal)
    truthy = staticmethod(require_true)
    falsy = staticmethod(require_false)
    is_none = staticmethod(require_absent)
    contains = staticmethod(require_member)
    absent = staticmethod(require_missing)
    exceeds = staticmethod(require_greater)
    raises = staticmethod(require_raises)
    refusal = staticmethod(require_message)
    require = staticmethod(require_that)
    require_same = staticmethod(require_same)


class HexbenchTestCase(Assertions, unittest.TestCase):
    """Base case giving every test a fresh session and a clean scratch directory."""

    session: Session

    def setUp(self) -> None:
        """Open a session for the test and register its teardown."""
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.session = stack.enter_context(open_session())
