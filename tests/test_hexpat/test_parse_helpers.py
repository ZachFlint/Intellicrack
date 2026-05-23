# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the hexpat-scoped parsing helpers.

The helpers are functionally identical to their bridge counterparts but
emit log records under the ``core.hexpat._parse_helpers`` logger. These
tests confirm both the happy path and the debug-logging contract so the
hexpat runtime never silently swallows parse failures again.
"""

from __future__ import annotations

import pytest

from intellicrack.core.hexpat import _parse_helpers
from intellicrack.core.hexpat._parse_helpers import safe_call, safe_int_from_str


class TestHexpatSafeIntFromStr:
    """Cover the public surface of the hexpat ``safe_int_from_str``."""

    def test_parses_decimal_string(self) -> None:
        """Decimal strings parse with the default base of 0."""
        assert safe_int_from_str("123", context="unit_decimal") == 123

    def test_explicit_base_10_parses_decimal(self) -> None:
        """``base=10`` accepts strings without a prefix."""
        assert safe_int_from_str("42", base=10, context="unit_base10") == 42

    def test_returns_default_on_failure(self) -> None:
        """A non-parseable string returns ``default``."""
        assert safe_int_from_str("xx", context="unit_failure", default=-1) == -1

    def test_returns_int_unchanged(self) -> None:
        """An ``int`` input is passed through."""
        assert safe_int_from_str(7, context="unit_int") == 7

    def test_rejects_bool_input(self) -> None:
        """A ``bool`` input is rejected."""
        true_value: bool = True
        assert safe_int_from_str(true_value, context="unit_bool") is None

    def test_logs_at_debug_on_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed parse emits a debug-level structured record."""
        events: list[tuple[str, dict[str, object]]] = []

        def _record(event: str, **kwargs: object) -> None:
            events.append((event, kwargs))

        logger = vars(_parse_helpers)["_logger"]
        monkeypatch.setattr(logger, "debug", _record)
        safe_int_from_str("not-a-number", context="unit_log")
        assert any(name == "safe_int_parse_failed" for name, _ in events), f"expected debug event emitted, got: {events!r}"
        for name, kwargs in events:
            if name == "safe_int_parse_failed":
                assert kwargs["context"] == "unit_log"
                break


class TestHexpatSafeCall:
    """Cover the public surface of the hexpat ``safe_call``."""

    def test_returns_value_on_success(self) -> None:
        """Success path returns the callable's return value."""
        assert (
            safe_call(
                lambda: "ok",
                exceptions=ValueError,
                context="unit_success",
                default=None,
            )
            == "ok"
        )

    def test_returns_default_on_value_error(self) -> None:
        """``ValueError`` returns the configured ``default``."""
        msg = "bad"

        def _raise() -> int:
            raise ValueError(msg)

        assert (
            safe_call(
                _raise,
                exceptions=ValueError,
                context="unit_value_error",
                default=-1,
            )
            == -1
        )

    def test_returns_default_on_overflow(self) -> None:
        """``OverflowError`` is captured when listed in ``exceptions``."""
        msg = "big"

        def _raise() -> int:
            raise OverflowError(msg)

        assert (
            safe_call(
                _raise,
                exceptions=(OverflowError, ValueError),
                context="unit_overflow",
                default=0,
            )
            == 0
        )

    def test_propagates_uncaught_exception(self) -> None:
        """Exceptions not listed propagate."""
        msg = "nope"

        def _raise() -> None:
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="nope"):
            safe_call(
                _raise,
                exceptions=ValueError,
                context="unit_propagate",
                default=None,
            )

    def test_logs_at_debug_on_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Caught exception emits a ``safe_call_failed`` debug record."""
        events: list[tuple[str, dict[str, object]]] = []

        def _record(event: str, **kwargs: object) -> None:
            events.append((event, kwargs))

        logger = vars(_parse_helpers)["_logger"]
        monkeypatch.setattr(logger, "debug", _record)
        msg = "debug-log-check"

        def _raise() -> None:
            raise ValueError(msg)

        safe_call(
            _raise,
            exceptions=ValueError,
            context="unit_log",
            default=None,
        )
        assert any(name == "safe_call_failed" for name, _ in events), f"expected debug event emitted, got: {events!r}"
