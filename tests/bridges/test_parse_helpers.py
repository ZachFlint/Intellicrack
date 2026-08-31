# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the shared bridge parsing helpers.

These tests cover both the happy path and every silent-return branch of
``safe_int_from_str`` and ``safe_call``. Failure paths additionally
verify that a structured log record is emitted at debug level so the
audit constraint ``every except must log at least at debug`` is upheld.
"""

from __future__ import annotations

import struct

import pytest

from intellicrack.bridges import parse_helpers
from intellicrack.bridges.parse_helpers import safe_call, safe_int_from_str


class TestSafeIntFromStr:
    """Cover the public surface of ``safe_int_from_str``."""

    def test_parses_hex_string_with_prefix(self) -> None:
        """A ``0x``-prefixed string parses with the default base of 0."""
        assert safe_int_from_str("0xdeadbeef", context="unit_hex_prefix") == 0xDEADBEEF

    def test_parses_decimal_string(self) -> None:
        """A decimal string parses with the default base of 0."""
        assert safe_int_from_str("42", context="unit_decimal") == 42

    def test_parses_binary_with_explicit_base(self) -> None:
        """An explicit ``base=2`` argument is honoured."""
        assert safe_int_from_str("1011", base=2, context="unit_binary") == 0b1011

    def test_returns_int_unchanged(self) -> None:
        """An ``int`` input is returned without re-parsing."""
        assert safe_int_from_str(123, context="unit_int_passthrough") == 123

    def test_rejects_bool_values(self) -> None:
        """A ``bool`` value never coerces silently to 0/1."""
        true_value: bool = True
        assert safe_int_from_str(true_value, context="unit_bool_reject") is None

    def test_rejects_bool_with_explicit_default(self) -> None:
        """The ``default`` argument is returned for bool input."""
        false_value: bool = False
        assert safe_int_from_str(false_value, context="unit_bool_default", default=-1) == -1

    def test_returns_default_on_parse_failure(self) -> None:
        """A non-parseable string returns the ``default`` value."""
        assert safe_int_from_str("not-a-number", context="unit_unparseable", default=0) == 0

    def test_returns_none_by_default_on_failure(self) -> None:
        """The default ``default`` is ``None`` on parse failure."""
        assert safe_int_from_str("zzz", context="unit_unparseable_none") is None

    def test_rejects_unsupported_type(self) -> None:
        """An object that is not int/str/bytes returns ``default``."""
        assert safe_int_from_str([1, 2, 3], context="unit_unsupported_type", default=-99) == -99

    def test_logs_at_debug_on_parse_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed parse emits a ``safe_int_parse_failed`` debug event."""
        events: list[tuple[str, dict[str, object]]] = []

        def _record(event: str, **kwargs: object) -> None:
            events.append((event, kwargs))

        logger = vars(parse_helpers)["_logger"]
        monkeypatch.setattr(logger, "debug", _record)
        result = safe_int_from_str("bogus", context="unit_logging_check")
        assert result is None
        matching = [(name, kwargs) for name, kwargs in events if name == "safe_int_parse_failed"]
        assert matching, f"expected debug event emitted, got: {events!r}"
        assert matching[0][1]["context"] == "unit_logging_check"

    def test_logs_at_debug_on_bool_rejection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A bool input emits a ``safe_int_parse_failed`` debug event."""
        events: list[tuple[str, dict[str, object]]] = []

        def _record(event: str, **kwargs: object) -> None:
            events.append((event, kwargs))

        logger = vars(parse_helpers)["_logger"]
        monkeypatch.setattr(logger, "debug", _record)
        true_value: bool = True
        safe_int_from_str(true_value, context="unit_bool_logging")
        assert any(name == "safe_int_parse_failed" for name, _ in events), "bool rejection should log a debug event"

    def test_parses_bytes_input(self) -> None:
        """A ``bytes`` input is accepted just like ``str``."""
        assert safe_int_from_str(b"0x10", context="unit_bytes_input") == 0x10

    def test_negative_decimal_string_parses(self) -> None:
        """Negative decimal strings parse correctly."""
        assert safe_int_from_str("-7", context="unit_negative") == -7


class TestSafeCall:
    """Cover the public surface of ``safe_call``."""

    def test_returns_result_on_success(self) -> None:
        """The success path returns the callable's value."""
        result = safe_call(
            lambda: 42,
            exceptions=ValueError,
            context="unit_success",
            default=None,
        )
        assert result == 42

    def test_returns_default_on_caught_exception(self) -> None:
        """A caught exception returns the configured ``default``."""
        msg = "boom"

        def _raise() -> int:
            raise ValueError(msg)

        result = safe_call(
            _raise,
            exceptions=ValueError,
            context="unit_caught_value_error",
            default=-1,
        )
        assert result == -1

    def test_returns_default_on_struct_error(self) -> None:
        """``struct.error`` is captured when listed in ``exceptions``."""

        def _bad_unpack() -> int:
            return int(struct.unpack_from("<I", b"\x00", 0)[0])

        result = safe_call(
            _bad_unpack,
            exceptions=struct.error,
            context="unit_struct_error",
            default=-2,
        )
        assert result == -2

    def test_returns_default_with_tuple_exceptions(self) -> None:
        """A tuple of exception classes is accepted."""
        msg = "nope"

        def _raise_os_error() -> None:
            raise OSError(msg)

        result = safe_call(
            _raise_os_error,
            exceptions=(OSError, ValueError),
            context="unit_tuple_exceptions",
            default="fallback",
        )
        assert result == "fallback"

    def test_propagates_uncaught_exception(self) -> None:
        """Exceptions not listed in ``exceptions`` propagate to the caller."""
        msg = "uncaught"

        def _raise_runtime() -> None:
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="uncaught"):
            safe_call(
                _raise_runtime,
                exceptions=ValueError,
                context="unit_uncaught",
                default=None,
            )

    def test_logs_at_debug_on_caught_exception(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A caught exception emits a ``safe_call_failed`` debug event."""
        events: list[tuple[str, dict[str, object]]] = []

        def _record(event: str, **kwargs: object) -> None:
            events.append((event, kwargs))

        logger = vars(parse_helpers)["_logger"]
        monkeypatch.setattr(logger, "debug", _record)
        msg = "nope"

        def _raise() -> None:
            raise ValueError(msg)

        safe_call(
            _raise,
            exceptions=ValueError,
            context="unit_logging_check",
            default=None,
        )

        matching = [(name, kwargs) for name, kwargs in events if name == "safe_call_failed"]
        assert matching, f"expected debug event emitted, got: {events!r}"
        assert matching[0][1]["context"] == "unit_logging_check"
        assert matching[0][1]["exc_type"] == "ValueError"
