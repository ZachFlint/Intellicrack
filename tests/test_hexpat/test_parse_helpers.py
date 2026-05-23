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

import logging

import pytest

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

    def test_logs_at_debug_on_failure(self, caplog: pytest.LogCaptureFixture) -> None:
        """A failed parse emits a debug-level structured record."""
        caplog.set_level(logging.DEBUG, logger="intellicrack.core.hexpat._parse_helpers")
        safe_int_from_str("not-a-number", context="unit_log")
        matching = [r for r in caplog.records if "safe_int_parse_failed" in r.getMessage()]
        assert matching, "expected hexpat helper to log on failure"


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

        def _raise() -> int:
            raise ValueError("bad")

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

        def _raise() -> int:
            raise OverflowError("too big")

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

        def _raise() -> None:
            raise RuntimeError("nope")

        with pytest.raises(RuntimeError, match="nope"):
            safe_call(
                _raise,
                exceptions=ValueError,
                context="unit_propagate",
                default=None,
            )

    def test_logs_at_debug_on_failure(self, caplog: pytest.LogCaptureFixture) -> None:
        """Caught exception emits a ``safe_call_failed`` debug record."""
        caplog.set_level(logging.DEBUG, logger="intellicrack.core.hexpat._parse_helpers")

        def _raise() -> None:
            raise ValueError("debug-log-check")

        safe_call(
            _raise,
            exceptions=ValueError,
            context="unit_log",
            default=None,
        )
        matching = [r for r in caplog.records if "safe_call_failed" in r.getMessage()]
        assert matching, "expected hexpat helper to log on failure"
