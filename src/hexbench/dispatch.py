# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Catalogue-driven invocation of every callable the engine exposes.

:func:`invoke` branches on nothing except :attr:`~hexbench.catalog.Operation.receiver`,
which has four members. There is no per-operation code anywhere in this module,
so an operation is reachable the instant the catalogue lists it and complete
coverage of the engine is a structural property rather than a checklist.

Two details are load-bearing. The first is :attr:`InvocationResult.raw`: the JSON
encoder truncates byte strings, which is right for display and catastrophic for a
patch export or a classification map, so operations that return ``bytes`` also
carry the untruncated value out of band. The second is
:func:`resolve_references`, a pre-pass that lets an argument name another open
document instead of carrying its bytes through the browser. It runs to
completion before the receiver is engaged at all, so a thread is never inside
two documents at once and the lock-ordering cycle a pair of crossed invocations
would otherwise form cannot close.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePath
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, cast

import intellicrack_hexcore
from intellicrack_hexcore import HexDocument

from hexbench.catalog import Operation, Parameter, Receiver, ValueKind, build_catalog
from hexbench.codec import DecodeError, decode_argument, decode_arguments, encode_result
from hexbench.reference import raw_capable_operations
from hexbench.registry import BusyError, DocumentInfo, DocumentSlot, Registry, RegistryError


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from hexbench.codec import JsonValue


__all__ = [
    "DispatchError",
    "Invocation",
    "InvocationResult",
    "encode_document",
    "invoke",
    "operation_for",
    "resolve_references",
    "translate_exception",
]

_STATUS_BAD_REQUEST: Final = 400
_STATUS_NOT_FOUND: Final = 404
_STATUS_BUSY: Final = 503
_STATUS_INTERNAL: Final = 500
_STATUS_INSUFFICIENT_STORAGE: Final = 507

_REFERENCE_TAG: Final = "__document__"
_TO_END: Final = -1
_WAIT_FOREVER: Final = -1.0
_REFERENCE_TIMEOUT: Final = 30.0
_MS_PER_SECOND: Final = 1000.0


class DispatchError(Exception):
    """A failure that already knows how it should be reported to a client."""

    def __init__(self, message: str, *, kind: str, status: int) -> None:
        """Record a failure together with its machine-readable classification.

        Args:
            message: Human readable description of what went wrong.
            kind: Stable slug a client can branch on.
            status: HTTP status code that best expresses the failure.
        """
        super().__init__(message)
        self.kind = kind
        self.status = status


_EXCEPTION_RULES: Final[tuple[tuple[type[BaseException], str, int], ...]] = (
    (DecodeError, "decode", _STATUS_BAD_REQUEST),
    (RegistryError, "no_such_document", _STATUS_NOT_FOUND),
    (BusyError, "busy", _STATUS_BUSY),
    (OSError, "io", _STATUS_BAD_REQUEST),
    (IndexError, "index", _STATUS_BAD_REQUEST),
    (OverflowError, "value", _STATUS_BAD_REQUEST),
    (ValueError, "value", _STATUS_BAD_REQUEST),
    (RuntimeError, "runtime", _STATUS_BAD_REQUEST),
    (MemoryError, "memory", _STATUS_INSUFFICIENT_STORAGE),
)

_OFFSET_PARAMETER: Final = Parameter(name="offset", annotation="int", kind=ValueKind.INT)
_LENGTH_PARAMETER: Final = Parameter(name="length", annotation="int", kind=ValueKind.INT)


@dataclass(frozen=True, slots=True)
class Invocation:
    """One request to run a catalogued operation.

    Attributes:
        operation: Catalogue entry describing what to run.
        handle: Document to run it against, or ``None`` for operations that do
            not act on an open document.
        arguments: Raw JSON arguments keyed by parameter name, before reference
            resolution and decoding.
    """

    operation: Operation
    handle: str | None
    arguments: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class InvocationResult:
    """The outcome of one successful invocation.

    Attributes:
        operation: Name of the operation that ran.
        value: JSON-safe rendering of the return value.
        raw: Untruncated bytes for operations that return binary, else ``None``.
        duration_ms: Wall clock time the engine call itself took.
        created_handle: Handle of a document the call brought into existence.
        document: State of the document the call acted on or created.
    """

    operation: str
    value: JsonValue
    raw: bytes | None
    duration_ms: float
    created_handle: str | None
    document: DocumentInfo | None


@lru_cache(maxsize=1)
def _operation_index() -> Mapping[str, Operation]:
    """Index the catalogue by operation name.

    Returns:
        Mapping[str, Operation]: Read-only mapping from name to catalogue entry.
    """
    return MappingProxyType({operation.name: operation for operation in build_catalog()})


def operation_for(name: str) -> Operation:
    """Look up a catalogued operation by name.

    Args:
        name: Operation name supplied by the client.

    Returns:
        Operation: The catalogue entry for that name.

    Raises:
        DispatchError: If the engine exposes no operation with that name.
    """
    operation = _operation_index().get(name)
    if operation is None:
        message = f"unknown operation {name!r}"
        raise DispatchError(message, kind="unknown_operation", status=_STATUS_NOT_FOUND)
    return operation


def encode_document(info: DocumentInfo) -> dict[str, JsonValue]:
    """Render a document description as a JSON object.

    Args:
        info: Document state to render.

    Returns:
        dict[str, JsonValue]: The description as plain JSON values.
    """
    return {
        "handle": info.handle,
        "label": info.label,
        "origin": info.origin,
        "path": info.path,
        "length": info.length,
        "modified": info.modified,
        "can_undo": info.can_undo,
        "can_redo": info.can_redo,
        "generation": info.generation,
    }


def _reference_of(value: JsonValue) -> dict[str, JsonValue] | None:
    """Recognise a value that names another open document instead of carrying bytes.

    Args:
        value: Raw JSON value taken from the request payload.

    Returns:
        dict[str, JsonValue] | None: The reference object, or ``None`` when the
        value is an ordinary literal.
    """
    if isinstance(value, dict) and _REFERENCE_TAG in value:
        return value
    return None


def _reference_int(parameter: Parameter, reference: dict[str, JsonValue], default: int) -> int:
    """Read one optional integer field out of a document reference.

    Propagates :class:`~hexbench.codec.DecodeError` when the field is present but
    is not an integer in any accepted spelling.

    Args:
        parameter: Field descriptor used for decoding and error messages.
        reference: The reference object being read.
        default: Value to use when the field is absent or null.

    Returns:
        int: The decoded field value.
    """
    raw = reference.get(parameter.name)
    if raw is None:
        return default
    return cast("int", decode_argument(parameter, raw))


def _read_reference(registry: Registry, reference: dict[str, JsonValue], parameter: str) -> str:
    """Read a byte window out of a referenced document and hex encode it.

    The referenced document is entered and left entirely inside this call, which
    is what keeps the caller free to engage the receiver afterwards without ever
    being inside two documents at once.

    Args:
        registry: Registry holding the referenced document.
        reference: Reference object carrying the handle and optional window.
        parameter: Parameter name, used in error messages.

    Returns:
        str: Hexadecimal encoding of the referenced bytes.

    Raises:
        DispatchError: If the handle is not a string, or the requested window
            starts before the document or has a negative length.
    """
    handle = reference[_REFERENCE_TAG]
    if not isinstance(handle, str):
        message = f"{parameter}: document reference handle must be a string, got {type(handle).__name__}"
        raise DispatchError(message, kind="decode", status=_STATUS_BAD_REQUEST)

    offset = _reference_int(_OFFSET_PARAMETER, reference, 0)
    requested = _reference_int(_LENGTH_PARAMETER, reference, _TO_END)
    if offset < 0:
        message = f"{parameter}: document reference offset {offset} is negative"
        raise DispatchError(message, kind="value", status=_STATUS_BAD_REQUEST)
    if requested < _TO_END:
        message = f"{parameter}: document reference length {requested} is negative"
        raise DispatchError(message, kind="value", status=_STATUS_BAD_REQUEST)

    slot = registry.slot(handle)
    with slot.read() as document:
        total = document.length()
        span = max(total - offset, 0) if requested == _TO_END else requested
        data = document.read(offset, span)
    return data.hex()


def resolve_references(registry: Registry, parameters: tuple[Parameter, ...], payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Replace document references in a payload with the bytes they name.

    Any binary argument may be written as ``{"__document__": handle, "offset": 0,
    "length": -1}``, where a length of ``-1`` means "to the end of the document".
    Rewriting these into hexadecimal here means the codec never has to know that
    references exist, and lets a multi-megabyte source image be handed to
    ``diff_bytes`` or ``export_patches_bps`` without a round trip through the
    browser. Call this before engaging the receiver, never inside it: a
    reference resolved while the receiver is held would put the calling thread
    inside two documents at once.

    Propagates :class:`~hexbench.registry.RegistryError` for an unknown handle
    and :class:`~hexbench.registry.BusyError` when a referenced document does not
    come free in time.

    Args:
        registry: Registry holding any referenced documents.
        parameters: Ordered catalogued parameters for the operation.
        payload: Raw JSON arguments keyed by parameter name.

    Returns:
        dict[str, JsonValue]: A new payload with every reference replaced by a
        hexadecimal string.
    """
    resolved = dict(payload)
    for parameter in parameters:
        value = resolved.get(parameter.name)
        if parameter.kind is ValueKind.BYTES:
            reference = _reference_of(value)
            if reference is not None:
                resolved[parameter.name] = _read_reference(registry, reference, parameter.name)
        elif parameter.kind is ValueKind.BYTES_MAP and isinstance(value, dict):
            resolved[parameter.name] = {key: _resolve_entry(registry, key, item, parameter.name) for key, item in value.items()}
    return resolved


def _resolve_entry(registry: Registry, key: str, value: JsonValue, parameter: str) -> JsonValue:
    """Resolve one entry of a mapping of binary parameters.

    Args:
        registry: Registry holding any referenced documents.
        key: Key of the entry within the mapping.
        value: Raw JSON value for the entry.
        parameter: Parameter name, used in error messages.

    Returns:
        JsonValue: The entry with any document reference replaced by hexadecimal.
    """
    reference = _reference_of(value)
    if reference is None:
        return value
    return _read_reference(registry, reference, f"{parameter}[{key!r}]")


def _call(target: object, name: str, arguments: Sequence[object]) -> object:
    """Invoke a named member of the engine.

    Args:
        target: Object or module owning the member.
        name: Member name taken from the catalogue.
        arguments: Positional arguments already decoded to native values.

    Returns:
        object: Whatever the engine returned.

    Raises:
        DispatchError: If the named member is not callable, which means the
            catalogue and the compiled engine have diverged.
    """
    member = getattr(target, name)
    if not callable(member):
        message = f"{name} is not callable on {type(target).__name__}; the catalogue and the engine have diverged"
        raise DispatchError(message, kind="internal", status=_STATUS_INTERNAL)
    return member(*arguments)


def _receiver_slot(registry: Registry, handle: str | None, name: str) -> DocumentSlot:
    """Resolve the document an instance method should run against.

    Args:
        registry: Registry holding the document.
        handle: Handle supplied with the request, possibly absent.
        name: Operation name, used in the error message.

    Returns:
        DocumentSlot: The slot to borrow for the call.

    Raises:
        DispatchError: If the request carried no handle at all.
    """
    if handle is None:
        message = f"{name} acts on an open document but the request supplied no handle"
        raise DispatchError(message, kind="missing_document", status=_STATUS_BAD_REQUEST)
    return registry.slot(handle)


def _factory_label(operation: Operation, arguments: Sequence[object]) -> str:
    """Choose a tab label for a document an operation has just created.

    Args:
        operation: The factory operation that produced the document.
        arguments: Positional arguments it was called with.

    Returns:
        str: The leaf name of the first textual argument, falling back to the
        operation name for factories that take no text.
    """
    for parameter, argument in zip(operation.parameters, arguments, strict=False):
        if parameter.kind is ValueKind.TEXT and isinstance(argument, str) and argument:
            return PurePath(argument).name or argument
    return operation.name


def _register(registry: Registry, operation: Operation, arguments: Sequence[object], created: object) -> DocumentInfo:
    """Take ownership of a document a factory operation produced.

    Args:
        registry: Registry to register the document with.
        operation: The factory operation that produced it.
        arguments: Positional arguments it was called with.
        created: The value the engine returned.

    Returns:
        DocumentInfo: State of the newly registered document.

    Raises:
        DispatchError: If the operation did not in fact return a document.
    """
    if not isinstance(created, HexDocument):
        message = f"{operation.name} is catalogued as a factory but returned {type(created).__name__}"
        raise DispatchError(message, kind="internal", status=_STATUS_INTERNAL)
    return registry.create(created, origin=operation.name, label=_factory_label(operation, arguments))


def invoke(registry: Registry, invocation: Invocation, *, timeout: float = _WAIT_FOREVER) -> InvocationResult:
    """Run one catalogued operation and package its result.

    Propagates whatever the engine raises, along with
    :class:`~hexbench.registry.RegistryError` and
    :class:`~hexbench.registry.BusyError`; callers turn those into a client
    response with :func:`translate_exception`.

    Args:
        registry: Registry owning the documents this call may touch.
        invocation: The operation, target document and raw arguments.
        timeout: Seconds to wait for the receiving document to come free. Any
            negative value waits indefinitely.

    Returns:
        InvocationResult: The return value, timings, and the state of any
        document the call acted on or created.
    """
    operation = invocation.operation
    payload = resolve_references(registry, operation.parameters, invocation.arguments)
    arguments = decode_arguments(operation.parameters, payload)

    value: object = None
    created_handle: str | None = None
    document: DocumentInfo | None = None
    started = time.perf_counter()
    match operation.receiver:
        case Receiver.DOCUMENT:
            slot = _receiver_slot(registry, invocation.handle, operation.name)
            if operation.mutating:
                with slot.borrow(timeout=timeout) as target:
                    value = _call(target, operation.name, arguments)
                slot.bump()
            else:
                with slot.read() as target:
                    value = _call(target, operation.name, arguments)
            document = slot.info()
        case Receiver.FACTORY:
            document = _register(registry, operation, arguments, _call(HexDocument, operation.name, arguments))
            created_handle = document.handle
            value = encode_document(document)
        case Receiver.STATIC:
            value = _call(HexDocument, operation.name, arguments)
        case Receiver.MODULE:
            value = _call(intellicrack_hexcore, operation.name, arguments)
    elapsed = (time.perf_counter() - started) * _MS_PER_SECOND

    raw = value if isinstance(value, bytes) and operation.name in raw_capable_operations() else None
    return InvocationResult(
        operation=operation.name,
        value=encode_result(value),
        raw=raw,
        duration_ms=elapsed,
        created_handle=created_handle,
        document=document,
    )


def translate_exception(exc: BaseException) -> DispatchError:
    """Classify any failure as a client-facing error.

    The order of the rules matters: ``DecodeError`` derives from ``ValueError``
    and ``BusyError`` from ``RuntimeError``, so each is matched before its base.

    Args:
        exc: The exception raised while serving a request.

    Returns:
        DispatchError: The failure with a stable slug and a status code. An
        exception that is already a :class:`DispatchError` is returned unchanged.
    """
    if isinstance(exc, DispatchError):
        return exc
    for exception_type, kind, status in _EXCEPTION_RULES:
        if isinstance(exc, exception_type):
            return DispatchError(_describe(exc), kind=kind, status=status)
    return DispatchError(_describe(exc), kind="internal", status=_STATUS_INTERNAL)


def _describe(exc: BaseException) -> str:
    """Render an exception as a message that always says something.

    Args:
        exc: The exception to describe.

    Returns:
        str: The exception's message, or its class name when it carries none.
    """
    text = str(exc).strip()
    return text or type(exc).__name__
