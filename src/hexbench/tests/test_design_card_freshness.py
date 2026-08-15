# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The generated design cards on disk must be what the generator would write today.

``design/cards`` holds thirty-seven committed HTML files, every one of them
produced by ``design/build_cards.py`` and every one of them inlining
``static/app.css`` verbatim. Nothing forces the two to agree: editing a card's
copy, adding a specimen, or -- most easily missed -- changing a single colour
token in the stylesheet leaves every card on disk describing a design system
that no longer exists, and the gallery goes on rendering the old one without a
complaint from anywhere.

This gate is deliberately not written as "run the generator, then check the
output". Calling :func:`hexbench.design.build_cards.build_cards` *writes*, so a
gate that began by rebuilding the tree it was about to inspect could never fail:
it would repair the drift it exists to report and then congratulate itself. It
renders each card in memory instead and compares those bytes against the file
already committed.

The comparison is anchored at import time for the same reason. Another suite in
this directory rebuilds the cards in ``setUpClass``, and :mod:`unittest`
discovery imports every module before running any of them, so the bytes read
here are the ones that were on disk when the run started regardless of which
suite executes first.
"""

from __future__ import annotations

import unittest
from importlib import import_module
from typing import TYPE_CHECKING, Final, Protocol, cast

from ._support import Assertions


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_GENERATOR_MODULE: Final = "hexbench.design.build_cards"

_ENCODING: Final = "utf-8"

_LINE_SEPARATOR: Final = "\r\n"
"""The terminator ``build_cards`` writes with, and the repository's own policy."""

_EXPECTED_CARD_COUNT: Final = 37
"""How many cards the gallery holds; a comparison covering fewer proves nothing."""

_CONTEXT_BYTES: Final = 120
"""How much of each side of a mismatch to quote, so the report is actionable."""

_MARKER: Final = b'<!-- @dsCard group="'
"""The first bytes of every rendered card, used to catch a render that produced nothing."""


class _CardLike(Protocol):
    """The one attribute of a generated card this gate reads.

    Attributes:
        filename: File name the card is written into ``design/cards`` under.
    """

    filename: str


_NAMESPACE: Final[dict[str, object]] = vars(import_module(_GENERATOR_MODULE))
"""The generator's module namespace.

The card table, the stylesheet reader and the renderer bound below are the
generator's own internals, and the only public entry point that reaches them is
``build_cards``, which writes. Naming them in an ``import`` statement would be a
private-symbol import the type checker rejects outright, so they are looked up
in the module namespace and given the signatures they actually have. Nothing
here reimplements the generator: every byte this gate compares against still
comes out of the generator's own code.
"""

_cards_directory: Final = cast("Path", _NAMESPACE["_CARDS_DIR"])
_all_cards: Final = cast("Callable[[], tuple[_CardLike, ...]]", _NAMESPACE["_all_cards"])
_stylesheet: Final = cast("Callable[[], str]", _NAMESPACE["_css"])
_render: Final = cast("Callable[[_CardLike, str], str]", _NAMESPACE["_render"])

_CARDS: Final = _all_cards()
"""Every card the generator would write, built once for this module."""

_STYLESHEET: Final = _stylesheet()
"""``static/app.css`` as the generator reads it, inlined into every card."""

_RENDERED: Final[dict[str, bytes]] = {
    card.filename: _render(card, _STYLESHEET).replace("\n", _LINE_SEPARATOR).encode(_ENCODING) for card in _CARDS
}
"""What each card file would contain if the generator ran right now.

The rendered text is joined with ``\\n`` and written through ``newline="\\r\\n"``,
so translating the separators here reproduces the bytes the generator commits
rather than merely its characters.
"""


def _committed_bytes(filename: str) -> bytes | None:
    """Read one card file as it stands on disk.

    Args:
        filename: Name of the card file inside the cards directory.

    Returns:
        bytes | None: The file's contents, or ``None`` when no such file exists.
    """
    path = _cards_directory / filename
    return path.read_bytes() if path.is_file() else None


_COMMITTED: Final[dict[str, bytes | None]] = {card.filename: _committed_bytes(card.filename) for card in _CARDS}
"""What each card file contained before any suite in this run could rewrite it."""


def _quote(payload: bytes, start: int) -> str:
    """Render a window of a card file for a failure message.

    Args:
        payload: Complete file contents.
        start: Byte offset the window begins at.

    Returns:
        str: The window decoded loosely, since a mismatch may fall mid-character.
    """
    return payload[start : start + _CONTEXT_BYTES].decode(_ENCODING, errors="replace")


def _describe_difference(filename: str, committed: bytes, rendered: bytes) -> str:
    """Report where a committed card stops matching a fresh render.

    Args:
        filename: Name of the card being compared.
        committed: Bytes currently on disk.
        rendered: Bytes the generator would write now.

    Returns:
        str: A message naming the card, the byte offset, both lengths, and the
        text on either side of the divergence.
    """
    shared = min(len(committed), len(rendered))
    offset = next((index for index in range(shared) if committed[index] != rendered[index]), shared)
    return (
        f"{filename} is stale: it differs from a fresh render at byte {offset} "
        f"(on disk {len(committed)} bytes, freshly rendered {len(rendered)} bytes). "
        f"Regenerate with `python -m hexbench.design.build_cards`.\n"
        f"  on disk:  {_quote(committed, offset)!r}\n"
        f"  rendered: {_quote(rendered, offset)!r}"
    )


class CommittedCardsMatchAFreshRenderTests(Assertions, unittest.TestCase):
    """Every card in ``design/cards`` must be byte-identical to what the generator produces."""

    def test_every_card_file_exists(self) -> None:
        """A card the generator would write but that is absent from the tree is drift too."""
        missing = sorted(name for name, payload in _COMMITTED.items() if payload is None)
        self.require_same(missing, [], "these cards are catalogued by the generator but no file exists for them in design/cards")

    def test_every_committed_card_is_byte_identical_to_a_fresh_render(self) -> None:
        """The drift gate itself: the first stale card is named, with the bytes that diverged."""
        for name, rendered in _RENDERED.items():
            committed = _COMMITTED[name]
            if committed is None:
                continue
            self.require(committed == rendered, _describe_difference(name, committed, rendered))

    def test_the_cards_directory_holds_nothing_the_generator_would_not_write(self) -> None:
        """A renamed card leaves its predecessor behind, and the gallery goes on showing both."""
        on_disk = sorted(path.name for path in _cards_directory.glob("*.html"))
        self.require_same(
            on_disk,
            sorted(_RENDERED),
            "design/cards holds card files the generator no longer writes, or is missing ones it does",
        )


class TheComparisonWasNotVacuousTests(Assertions, unittest.TestCase):
    """A comparison of nothing against nothing passes; these checks are why it was not."""

    def test_the_generator_catalogued_every_card_the_gallery_holds(self) -> None:
        """All thirty-seven cards must have taken part, not merely whichever ones survived a glob."""
        self.equal(len(_CARDS), _EXPECTED_CARD_COUNT, "number of cards the generator catalogues")
        self.equal(len(_RENDERED), _EXPECTED_CARD_COUNT, "number of cards rendered in memory")
        self.equal(len(_COMMITTED), _EXPECTED_CARD_COUNT, "number of cards read from disk")

    def test_every_card_has_a_distinct_filename(self) -> None:
        """Two cards sharing a name would silently collapse the comparison to thirty-six."""
        self.equal(len({card.filename for card in _CARDS}), _EXPECTED_CARD_COUNT, "number of distinct card filenames")

    def test_every_rendered_card_is_a_complete_document(self) -> None:
        """A render that produced an empty string would match nothing and be reported as drift, not as a bug here."""
        empty = sorted(name for name, payload in _RENDERED.items() if not payload.startswith(_MARKER))
        self.require_same(empty, [], "these cards rendered without the @dsCard marker that begins every card file")

    def test_the_render_inlines_the_live_stylesheet(self) -> None:
        """Each card carries app.css verbatim, which is what makes a token edit stale every card at once."""
        stylesheet = _STYLESHEET.replace("\n", _LINE_SEPARATOR).encode(_ENCODING)
        self.exceeds(len(stylesheet), 0, "length of the inlined stylesheet")
        without = sorted(name for name, payload in _RENDERED.items() if stylesheet not in payload)
        self.require_same(without, [], "these cards no longer inline app.css verbatim, so a stylesheet edit would not show up as drift")


if __name__ == "__main__":
    unittest.main()
