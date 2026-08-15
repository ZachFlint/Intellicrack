# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""What the stylesheet sweep was allowed to remove, and what it was not.

``static/app.css`` carried tokens nothing read and rules nothing rendered, and
the sweep that removed them had to distinguish two things that look identical
from inside the stylesheet: a token no file anywhere references, and a token
referenced only from outside CSS. ``--hb-chart-ink`` was the first kind and is
gone. ``--hb-chart-axis`` is the second -- ``static/charts.js`` reads it through
``getComputedStyle`` to paint a canvas axis, so nothing in the stylesheet
mentions it and deleting it would leave the axis grey with no error anywhere.

So the gate runs in both directions. Every deleted name is asserted absent, and
every surviving name that *looks* deletable is asserted both still defined here
and still read by the file that actually reads it, proved by reading that file
rather than by assuming it does. The rule checks are symmetric for the same
reason: ``.hb-strip-cell`` and ``.hb-minimap`` had to go, ``.hb-strip-axis`` and
the whole histogram block had to stay, and over-deleting is exactly as much a
regression as under-deleting.

Each scanner carries a control, because a matcher that has silently stopped
matching anything reports a clean stylesheet.
"""

from __future__ import annotations

import re
import unittest
from typing import Final

from ._support import PACKAGE_ROOT, STATIC_ROOT, Assertions


_ENCODING: Final = "utf-8"

_APP_CSS: Final = (STATIC_ROOT / "app.css").read_text(encoding=_ENCODING)
"""The canonical stylesheet, read once with line endings normalised to LF."""

_CONSUMERS: Final[dict[str, str]] = {
    "static/charts.js": (STATIC_ROOT / "charts.js").read_text(encoding=_ENCODING),
    "design/build_cards.py": (PACKAGE_ROOT / "design" / "build_cards.py").read_text(encoding=_ENCODING),
}
"""Every non-CSS file this gate holds a surviving token's reference against."""

_DELETED_TOKENS: Final[tuple[str, ...]] = ("--hb-space-0", "--hb-ease-in", "--hb-chart-ink")
"""Names the sweep removed outright: no definition and no reference may return."""

_LIVE_CUSTOM_PROPERTY: Final = "--hb-space-1"
"""A name that is certainly still present, so the name scanner cannot match nothing and pass."""

_EXTERNALLY_CONSUMED: Final[tuple[tuple[str, str], ...]] = (
    ("--hb-chart-axis", "static/charts.js"),
    ("--hb-chart-fill", "design/build_cards.py"),
    ("--hb-fs-xl", "design/build_cards.py"),
    ("--hb-fs-2xl", "design/build_cards.py"),
)
"""Tokens defined here, referenced nowhere in CSS, and read by the named file."""

_BLANK_SCREEN_CONSUMED: Final[tuple[tuple[str, str], ...]] = (
    ("--hb-fs-3xl", ".hb-blank-title"),
    ("--hb-fs-lg", ".hb-blank-lede"),
)
"""Tokens the blank screen brought back into use, named with the rule that uses them."""

_DELETED_RULES: Final[tuple[str, ...]] = (".hb-strip-cell", ".hb-minimap")
"""Selectors the sweep removed; neither has a renderer left anywhere."""

_SURVIVING_RULES: Final[tuple[str, ...]] = (
    ".hb-strip-axis",
    ".hb-histogram",
    ".hb-histogram-bar",
    ".hb-histogram-bar:hover",
    ".hb-histogram-bar.bc-null",
    ".hb-histogram-bar.bc-print",
    ".hb-histogram-bar.bc-ctrl",
    ".hb-histogram-bar.bc-high",
)
"""Selectors the design cards still render, which the sweep had to leave alone."""

_HISTOGRAM_BAR_HEIGHT: Final = "calc(var(--hb-bar, 0) * 1%)"
"""What makes the histogram block load-bearing rather than an empty shell."""

_DELETED_VAR_REFERENCES: Final[tuple[str, ...]] = (
    "--hb-marker-start",
    "--hb-marker-width",
    "--hb-band-start",
    "--hb-band-width",
    "--hb-cursor",
)
"""Custom properties whose only readers were the deleted rules."""

_LIVE_VAR_REFERENCE: Final = "--hb-bar"
"""A custom property still read through var(), so the var() scanner has a control."""


def _token_mentioned(text: str, token: str) -> bool:
    """Report whether a text names a custom property, whole rather than as a prefix.

    ``--hb-ease-in`` is a prefix of a perfectly legitimate ``--hb-ease-in-out``,
    so a plain substring search would report a deleted name as still present the
    moment a longer one is introduced. The lookahead ends the match at the token
    boundary CSS itself uses.

    Args:
        text: File contents to search.
        token: Custom property name, including its leading dashes.

    Returns:
        bool: True when the exact name occurs.
    """
    return re.search(rf"{re.escape(token)}(?![\w-])", text) is not None


def _token_defined(token: str) -> bool:
    """Report whether the stylesheet declares a custom property.

    Args:
        token: Custom property name, including its leading dashes.

    Returns:
        bool: True when at least one declaration of the name occurs.
    """
    return re.search(rf"^\s*{re.escape(token)}\s*:", _APP_CSS, re.MULTILINE) is not None


def _var_referenced(text: str, token: str) -> bool:
    """Report whether a text reads a custom property through ``var()``.

    Args:
        text: File contents to search.
        token: Custom property name, including its leading dashes.

    Returns:
        bool: True when the name occurs inside a ``var()`` reference.
    """
    return re.search(rf"var\(\s*{re.escape(token)}(?![\w-])", text) is not None


def _rule_body(selector: str) -> str | None:
    """Read the declaration block of one stylesheet rule.

    The selector must begin a line and be followed only by whitespace and the
    opening brace, so ``.hb-histogram`` never matches ``.hb-histogram-bar``.

    Args:
        selector: Complete selector text, such as ``.hb-blank-title``.

    Returns:
        str | None: The declarations between the braces, or ``None`` when no
        such rule exists.
    """
    found = re.search(rf"^{re.escape(selector)}\s*\{{([^}}]*)\}}", _APP_CSS, re.MULTILINE)
    return None if found is None else found.group(1)


class DeletedTokensStayDeletedTests(Assertions, unittest.TestCase):
    """The three names the sweep removed must not reappear under any spelling."""

    def test_no_deleted_token_appears_anywhere_in_the_stylesheet(self) -> None:
        """Neither a definition nor a reference may survive for a removed name."""
        surviving = sorted(token for token in _DELETED_TOKENS if _token_mentioned(_APP_CSS, token))
        self.require_same(surviving, [], "these deleted tokens are named in app.css again; nothing reads them, so they are dead weight")

    def test_the_name_scanner_still_matches_a_token_that_is_present(self) -> None:
        """The control: a scanner that matches nothing would pass the check above vacuously."""
        self.truthy(
            _token_mentioned(_APP_CSS, _LIVE_CUSTOM_PROPERTY),
            f"the name scanner failed to find {_LIVE_CUSTOM_PROPERTY}, so it is reading nothing",
        )

    def test_the_name_scanner_stops_at_a_token_boundary(self) -> None:
        """The control: a longer name that merely starts with a deleted one must not count as it."""
        self.falsy(
            _token_mentioned("--hb-ease-in-out: linear;", "--hb-ease-in"),
            "the name scanner matched --hb-ease-in inside --hb-ease-in-out",
        )
        self.truthy(
            _token_mentioned("--hb-ease-in: linear;", "--hb-ease-in"),
            "the name scanner missed an exact declaration of --hb-ease-in",
        )


class TokensWithNoCssReaderSurviveTests(Assertions, unittest.TestCase):
    """A token read only from outside CSS looks unused from inside it and must not be swept."""

    def test_every_externally_consumed_token_is_still_defined(self) -> None:
        """Deleting one of these leaves its reader silently falling back to a default."""
        missing = sorted(token for token, _consumer in _EXTERNALLY_CONSUMED if not _token_defined(token))
        self.require_same(missing, [], "these tokens are no longer declared in app.css, but a file outside CSS still reads them")

    def test_every_externally_consumed_token_is_still_read_by_its_named_consumer(self) -> None:
        """The other half: a token kept for a reader that no longer reads it is dead weight."""
        unread = sorted(
            f"{token} in {consumer}" for token, consumer in _EXTERNALLY_CONSUMED if not _token_mentioned(_CONSUMERS[consumer], token)
        )
        self.require_same(unread, [], "these tokens are declared for a consumer that no longer names them, so the pair has drifted")

    def test_no_externally_consumed_token_is_read_from_css_after_all(self) -> None:
        """A control on the premise: these four are exactly the ones CSS itself never reads.

        If one of them gained a ``var()`` reference in the stylesheet it would no
        longer be at risk from a sweep, and this gate would be guarding a token
        that no longer needs guarding.
        """
        self_read = sorted(token for token, _consumer in _EXTERNALLY_CONSUMED if _var_referenced(_APP_CSS, token))
        self.require_same(self_read, [], "these tokens are now read from CSS as well, so this gate no longer describes why they survive")

    def test_the_type_scale_card_renders_its_tokens_rather_than_only_listing_them(self) -> None:
        """``--hb-fs-xl`` and ``--hb-fs-2xl`` survive because a card renders them into a style attribute."""
        generator = _CONSUMERS["design/build_cards.py"]
        self.contains("font-size: var({token})", generator, "the type scale card no longer interpolates its token into a var() reference")

    def test_the_chart_axis_token_is_read_as_a_computed_colour(self) -> None:
        """``--hb-chart-axis`` survives because charts.js resolves it against a live element."""
        charts = _CONSUMERS["static/charts.js"]
        self.contains("cssColor(container, '--hb-chart-axis'", charts, "charts.js no longer resolves the axis colour from the token")


class BlankScreenTokensSurviveTests(Assertions, unittest.TestCase):
    """The two type-scale steps the blank screen brought back into use."""

    def test_every_blank_screen_token_is_still_defined(self) -> None:
        """A rule reading an undeclared token renders at the browser's default size."""
        missing = sorted(token for token, _rule in _BLANK_SCREEN_CONSUMED if not _token_defined(token))
        self.require_same(missing, [], "these tokens are read by a blank-screen rule but no longer declared")

    def test_every_blank_screen_token_is_read_by_the_rule_that_names_it(self) -> None:
        """The reference has to be in the blank-screen rule, not merely somewhere in the file."""
        for token, selector in _BLANK_SCREEN_CONSUMED:
            body = _rule_body(selector)
            self.require(body is not None, f"{selector} is missing from app.css, so the blank screen has lost a rule")
            self.require(
                body is not None and _var_referenced(body, token),
                f"{selector} no longer reads {token}; the blank screen is the reason that step of the type scale survives",
            )


class DeletedRulesStayDeletedTests(Assertions, unittest.TestCase):
    """The sweep had to remove two rule families and leave two others untouched."""

    def test_no_deleted_rule_family_reappears(self) -> None:
        """Nothing renders these selectors, so a stylesheet naming them is carrying dead rules."""
        surviving = sorted(selector for selector in _DELETED_RULES if selector in _APP_CSS)
        self.require_same(surviving, [], "these selectors are back in app.css; nothing in the application or the cards renders them")

    def test_every_surviving_rule_still_has_a_declaration_block(self) -> None:
        """Deleting too much is as much a regression as deleting too little."""
        lost = sorted(selector for selector in _SURVIVING_RULES if _rule_body(selector) is None)
        self.require_same(lost, [], "these rules were swept away with the dead ones, but the design cards still render them")

    def test_the_histogram_bar_still_takes_its_height_from_its_own_custom_property(self) -> None:
        """A surviving block that no longer does anything is a deletion in all but spelling."""
        body = _rule_body(".hb-histogram-bar")
        self.require(body is not None, ".hb-histogram-bar is missing from app.css")
        self.contains(_HISTOGRAM_BAR_HEIGHT, body or "", "the histogram bar no longer sizes itself from --hb-bar")

    def test_the_rule_scanner_distinguishes_a_selector_from_a_longer_one(self) -> None:
        """The control: ``.hb-histogram`` and ``.hb-histogram-bar`` must not read as the same rule."""
        block = _rule_body(".hb-histogram")
        bar = _rule_body(".hb-histogram-bar")
        self.require(block is not None and bar is not None, "the rule scanner could not read both histogram rules")
        self.unequal(block, bar, "the rule scanner returned one body for two different selectors")


class DeletedCustomPropertyReferencesTests(Assertions, unittest.TestCase):
    """The custom properties whose only readers were the deleted rules."""

    def test_no_var_reference_survives_to_a_removed_custom_property(self) -> None:
        """A ``var()`` reading a property nothing sets resolves to nothing at all."""
        surviving = sorted(token for token in _DELETED_VAR_REFERENCES if _var_referenced(_APP_CSS, token))
        self.require_same(surviving, [], "these var() references outlived the rules that set them, so they resolve to nothing")

    def test_no_removed_custom_property_is_declared_either(self) -> None:
        """Setting a property nothing reads is the same dead weight from the other end."""
        declared = sorted(token for token in _DELETED_VAR_REFERENCES if _token_defined(token))
        self.require_same(declared, [], "these custom properties are declared again with nothing left to read them")

    def test_the_var_scanner_still_finds_a_reference_that_is_present(self) -> None:
        """The control: a var() scanner matching nothing would pass both checks above vacuously."""
        self.truthy(
            _var_referenced(_APP_CSS, _LIVE_VAR_REFERENCE),
            f"the var() scanner failed to find var({_LIVE_VAR_REFERENCE}), so it is reading nothing",
        )


if __name__ == "__main__":
    unittest.main()
