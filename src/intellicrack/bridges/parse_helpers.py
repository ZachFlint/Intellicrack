# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared parsing helpers for Intellicrack bridge modules.

This module centralises two recurring patterns from the bridge layer:

1. ``safe_int_from_str`` parses an integer from a string and emits a
   structured debug log when parsing fails instead of silently swallowing
   the :class:`ValueError`. This is the canonical replacement for the
   ``except ValueError: return None / 0 / continue / pass`` idiom that
   bridge code historically used when reading plugin response payloads,
   x64dbg address strings, label/comment lists, and similar
   serialised-integer fields.

2. ``safe_call`` invokes a zero-argument callable and returns a configured
   default when one of the expected exception types is raised. The
   exception is logged at debug level with the supplied call-site
   context. It is the analogue of ``safe_int_from_str`` for non-integer
   parse sites (``struct.unpack_from`` payload reads, Win32 mitigation
   policy probes, ``ctypes.ArgumentError`` decode failures, etc.).

Both helpers log via the :mod:`intellicrack.core.logging` ``structlog``
binding, so every captured failure is observable through the project's
JSON log aggregation pipeline.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, overload

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable


_logger: Final = get_logger(__name__)


def safe_int_from_str(
    value: object,
    *,
    base: int = 0,
    context: str,
    default: int | None = None,
) -> int | None:
    """Parse an integer from a value, logging at debug level on failure.

    The helper accepts ``int`` directly (returned unchanged unless it is
    a ``bool``, which is rejected to match the historical
    ``_coerce_address``/``_coerce_hex_int`` semantics) and any string or
    bytes-like object that ``int(value, base)`` can consume. Boolean
    values are treated as invalid because Python's ``bool`` subclasses
    ``int`` and would otherwise be silently coerced to ``0`` or ``1``
    for fields that expect numeric strings.

    Args:
        value: Raw payload to parse. Accepts ``int`` (returned as-is)
            or ``str``/``bytes``/``bytearray`` (parsed with the
            requested base). Any other type is treated as a parse
            failure and ``default`` is returned.
        base: Numeric base passed to ``int()``. ``0`` (default) requests
            auto-detection from a ``0x``/``0o``/``0b`` prefix, matching
            the behaviour expected by x64dbg plugin payloads.
        context: Snake_case identifier of the call site
            (e.g. ``"x64dbg_coerce_address"``). Recorded as a structured
            log field so failures can be correlated to the originating
            bridge method.
        default: Value to return when parsing fails. Defaults to
            ``None``; callers that semantically require a sentinel
            integer (for example ``_coerce_address`` returning ``0``)
            pass it explicitly.

    Returns:
        int | None: Parsed integer, or ``default`` when the value cannot
            be parsed.
    """
    if isinstance(value, bool):
        _logger.debug(
            "safe_int_parse_failed",
            context=context,
            raw_repr=repr(value),
            base=base,
            error="bool rejected",
        )
        return default
    if isinstance(value, int):
        return value
    if not isinstance(value, (str, bytes, bytearray)):
        _logger.debug(
            "safe_int_parse_failed",
            context=context,
            raw_repr=repr(value),
            base=base,
            error="unsupported type",
            value_type=type(value).__name__,
        )
        return default
    try:
        return int(value, base)
    except (ValueError, TypeError) as exc:
        _logger.debug(
            "safe_int_parse_failed",
            context=context,
            raw_repr=repr(value),
            base=base,
            error=str(exc),
        )
        return default


@overload
def safe_call[T, D](
    func: Callable[[], T],
    *,
    exceptions: type[BaseException],
    context: str,
    default: D,
) -> T | D: ...


@overload
def safe_call[T, D](
    func: Callable[[], T],
    *,
    exceptions: tuple[type[BaseException], ...],
    context: str,
    default: D,
) -> T | D: ...


def safe_call(
    func: Callable[[], object],
    *,
    exceptions: type[BaseException] | tuple[type[BaseException], ...],
    context: str,
    default: object,
) -> object:
    """Call ``func`` and return ``default`` on any of the listed exceptions.

    The captured exception is logged at debug level with the call-site
    ``context`` so silent-swallow failures become observable without
    raising. Useful for replacing
    ``except (struct.error, OSError): return <sentinel>`` blocks that
    previously discarded failures from struct unpacks, ctypes calls,
    Win32 policy probes, and similar small-scope operations.

    Args:
        func: Zero-argument callable that performs the guarded
            operation. Use a ``lambda`` or ``functools.partial`` when
            the underlying API needs arguments.
        exceptions: Exception class or tuple of exception classes that
            should be caught and converted to ``default``. Any other
            exception propagates to the caller unchanged.
        context: Snake_case identifier of the call site, recorded as a
            structured log field on failure.
        default: Value to return when one of ``exceptions`` is raised.

    Returns:
        object: Result of ``func()`` on success, otherwise ``default``.
    """
    try:
        return func()
    except exceptions as exc:
        _logger.debug(
            "safe_call_failed",
            context=context,
            exc_type=type(exc).__name__,
            exc_info=True,
        )
        return default
