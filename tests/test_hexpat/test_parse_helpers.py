# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for the hexpat-scoped parsing helpers.

The helpers are functionally identical to their bridge counterparts but
emit log records under the ``core.hexpat.parse_helpers`` logger. These
tests confirm both the happy path and the debug-logging contract so the
hexpat runtime never silently swallows parse failures again.
"""

from __future__ import annotations

import pytest
from structlog.testing import capture_logs

from intellicrack.core.hexpat.parse_helpers import safe_call, safe_int_from_str


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

    def test_emits_structured_event_on_failure(self) -> None:
        """A failed parse emits a ``safe_int_parse_failed`` structured event.

        Uses :func:`structlog.testing.capture_logs` to observe the real logging
        pipeline rather than patching the module's private logger, so the test
        exercises the genuine structured-event emission contract.
        """
        with capture_logs() as records:
            result = safe_int_from_str("not-a-number", context="unit_log")
        assert result is None
        matches = [record for record in records if record.get("event") == "safe_int_parse_failed"]
        assert matches, f"expected structured event emitted, got: {records!r}"
        assert matches[0]["context"] == "unit_log"


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

    def test_emits_structured_event_on_failure(self) -> None:
        """A caught exception emits a ``safe_call_failed`` structured event.

        Observes the real logging pipeline via
        :func:`structlog.testing.capture_logs` instead of patching the private
        module logger.
        """
        msg = "structured-event-check"

        def _raise() -> None:
            raise ValueError(msg)

        with capture_logs() as records:
            result = safe_call(
                _raise,
                exceptions=ValueError,
                context="unit_log",
                default=None,
            )
        assert result is None
        matches = [record for record in records if record.get("event") == "safe_call_failed"]
        assert matches, f"expected structured event emitted, got: {records!r}"
        assert matches[0]["context"] == "unit_log"
