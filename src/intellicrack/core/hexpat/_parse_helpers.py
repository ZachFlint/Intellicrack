# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Shared parsing helpers for the hexpat runtime.

The hexpat standard-library and runtime layers historically contained
``except ValueError: return PatternValue(value=0)`` style blocks that
silently absorbed parse and conversion failures from
:func:`time.localtime`, :func:`time.gmtime`, :func:`time.strftime`,
``int(...)`` calls, ``format()`` calls, and the format-string regex
fallback. Per the audit, every except handler must log at least at
debug level so pattern-execution failures remain observable from the
structured log stream.

This module exposes ``safe_int_from_str`` and ``safe_call`` helpers
scoped to the hexpat package so the runtime does not need to depend on
the bridge layer for trivial parse utilities. The implementations are
functionally identical to the bridge variants but use a hexpat-specific
logger name so failures can be filtered by subsystem.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from intellicrack.core.logging import get_logger


if TYPE_CHECKING:
    from collections.abc import Callable


_logger: Final = get_logger("core.hexpat._parse_helpers")


def safe_int_from_str(
    value: object,
    *,
    base: int = 0,
    context: str,
    default: int | None = None,
) -> int | None:
    """Parse an integer from a value, logging at debug level on failure.

    Mirrors :func:`intellicrack.bridges._parse_helpers.safe_int_from_str`
    but emits structured logs under the ``core.hexpat._parse_helpers``
    logger so hexpat-pattern parse failures can be filtered independently
    of bridge-side failures.

    Args:
        value: Raw value to parse. Accepts ``int`` directly (returned
            as-is) or ``str``/``bytes``/``bytearray`` (parsed with the
            requested base). Any other type is treated as a parse
            failure and ``default`` is returned.
        base: Numeric base passed to ``int()``. ``0`` requests
            auto-detection from a ``0x``/``0o``/``0b`` prefix.
        context: Snake_case identifier of the call site
            (e.g. ``"hexpat_format_string_index"``).
        default: Value to return when parsing fails. Defaults to
            ``None``.

    Returns:
        int | None: Parsed integer, or ``default`` when the value cannot
            be parsed.
    """
    if isinstance(value, bool):
        _logger.debug(
            "safe_int_parse_failed",
            context=context,
            raw=repr(value),
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
            raw=repr(value),
            base=base,
            error=f"unsupported type {type(value).__name__}",
        )
        return default
    try:
        return int(value, base)
    except (ValueError, TypeError) as exc:
        _logger.debug(
            "safe_int_parse_failed",
            context=context,
            raw=repr(value),
            base=base,
            error=str(exc),
        )
        return default


def safe_call[_T, _D](
    func: Callable[[], _T],
    *,
    exceptions: type[BaseException] | tuple[type[BaseException], ...],
    context: str,
    default: _D,
) -> _T | _D:
    """Call ``func`` and return ``default`` on any of the listed exceptions.

    Mirrors :func:`intellicrack.bridges._parse_helpers.safe_call`. The
    captured exception is logged at debug level under the hexpat
    helpers logger.

    Args:
        func: Zero-argument callable that performs the guarded
            operation.
        exceptions: Exception class or tuple of exception classes that
            should be caught. Any other exception propagates to the
            caller.
        context: Snake_case identifier of the call site, recorded as a
            structured log field on failure.
        default: Value to return when one of ``exceptions`` is raised.

    Returns:
        _T | _D: Result of ``func()`` on success, otherwise ``default``.
    """
    try:
        return func()
    except exceptions as exc:
        _logger.debug(
            "safe_call_failed",
            context=context,
            exc_type=type(exc).__name__,
            error=str(exc),
        )
        return default
