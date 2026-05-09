# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Audit 5 u4 / F-0023 - parser surfaces every collected parse error.

Before remediation, ``HexPatParser.parse()`` collected each recovered error
into ``self._errors`` but only re-raised the first one wrapped in a fresh
``HexPatParseError``. Callers that wanted to inspect all syntax errors in a
single file had no way to retrieve them; the message of the raised exception
mentioned just the first error and any secondary errors were silently lost.

The remediation introduces ``HexPatAggregateParseError`` (a subclass of
``HexPatParseError`` so existing handlers continue to catch it) which carries
the full tuple of collected errors via the ``errors`` attribute and surfaces
all of them in the aggregate message.
"""

from __future__ import annotations

import pytest

from intellicrack.core.hexpat.errors import HexPatParseError
from intellicrack.core.hexpat.lexer import HexPatLexer
from intellicrack.core.hexpat.parser import HexPatAggregateParseError, HexPatParser


def _parse_source(source: str) -> HexPatParser:
    """Return a parser instance that has been driven over ``source``.

    Args:
        source: HexPat DSL source code.

    Returns:
        HexPatParser: A parser instance whose ``parse()`` has been invoked
        once. The caller may inspect ``parser.errors`` after the call.
    """
    lexer = HexPatLexer(source)
    tokens = lexer.tokenize()
    return HexPatParser(tokens)


class TestAggregateParseError:
    """F-0023: ``parse()`` surfaces every collected parse error to the caller."""

    def test_single_error_still_raises_hexpatparseerror(self) -> None:
        """A single parse error continues to raise ``HexPatParseError``.

        The legacy behaviour for the single-error case must be preserved so
        existing call sites catching ``HexPatParseError`` keep working.
        """
        parser = _parse_source("struct {")
        with pytest.raises(HexPatParseError):
            parser.parse()

    def test_single_error_aggregate_exposes_one_entry(self) -> None:
        """The aggregate ``errors`` attribute holds exactly one entry for one error."""
        parser = _parse_source("struct {")
        with pytest.raises(HexPatAggregateParseError) as excinfo:
            parser.parse()
        assert len(excinfo.value.errors) == 1

    def test_multiple_errors_all_collected(self) -> None:
        """Multiple parse errors are collected and surfaced via ``errors``."""
        # Two malformed top-level declarations separated by ``;`` so the
        # parser can synchronise and continue past the first error.
        source = "struct ; struct ; struct ;"
        parser = _parse_source(source)
        with pytest.raises(HexPatAggregateParseError) as excinfo:
            parser.parse()
        # Pre-fix behaviour would have surfaced only the first error; the fix
        # must surface them all.
        assert len(excinfo.value.errors) >= 2

    def test_aggregate_is_subclass_of_hexpatparseerror(self) -> None:
        """``HexPatAggregateParseError`` must subclass ``HexPatParseError``.

        Existing call sites use ``except HexPatParseError`` and the aggregate
        must remain catchable through that handler so no caller silently
        misses parse failures.
        """
        assert issubclass(HexPatAggregateParseError, HexPatParseError)

    def test_aggregate_message_enumerates_every_error(self) -> None:
        """The aggregate's stringified message references every collected error."""
        source = "struct ; struct ; struct ;"
        parser = _parse_source(source)
        with pytest.raises(HexPatAggregateParseError) as excinfo:
            parser.parse()
        text: str = str(excinfo.value)
        for err in excinfo.value.errors:
            assert err.message in text

    def test_parser_errors_property_matches_raised_aggregate(self) -> None:
        """``parser.errors`` returns the same list that the aggregate carries."""
        source = "struct ; struct ;"
        parser = _parse_source(source)
        with pytest.raises(HexPatAggregateParseError) as excinfo:
            parser.parse()
        assert tuple(parser.errors) == excinfo.value.errors

    def test_aggregate_preserves_first_error_location(self) -> None:
        """The aggregate's ``line``/``column`` headline match the first collected error."""
        source = "\n\nstruct ; struct ;"
        parser = _parse_source(source)
        with pytest.raises(HexPatAggregateParseError) as excinfo:
            parser.parse()
        first = excinfo.value.errors[0]
        assert excinfo.value.line == first.line
        assert excinfo.value.column == first.column

    def test_aggregate_constructor_rejects_empty_errors(self) -> None:
        """Constructing an aggregate with no errors is a programming error."""
        with pytest.raises(ValueError, match="at least one collected error"):
            HexPatAggregateParseError(())

    def test_clean_source_returns_nodes_without_raising(self) -> None:
        """A syntactically valid program parses without raising any error."""
        source = "struct Hdr { u32 magic; };"
        parser = _parse_source(source)
        nodes = parser.parse()
        assert len(nodes) == 1
        assert parser.errors == []
