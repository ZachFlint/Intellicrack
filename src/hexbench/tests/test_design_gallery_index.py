# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""The gallery has to stay live, complete, and grouped the way the stylesheet is.

``design/index.html`` exists because thirty-seven cards each carrying their own
copy of ``static/app.css`` meant the design system was only ever visible as it
had been at the moment the generator last ran. The gallery links the stylesheet
instead, so what a browser draws is what the file says now. That property is one
attribute away from being lost -- inline the stylesheet again, or point the href
somewhere that also happens to exist, and the page still renders perfectly while
quietly going back to being a snapshot -- so it is asserted here directly, with a
control proving the needle used to detect inlining is a needle that can be found.

Two more things decay silently. A card added to the generator lands in
``design/cards`` and never appears in the gallery, because nothing links the two
beyond the table that writes both; so every card file on disk is required to have
a nav entry and an article. And the twelve numbered sections the nav is grouped
by live in ``app.css``, not here: renaming one, or renumbering them, would leave
the nav describing a structure the stylesheet no longer has. The sections are
therefore read back out of the stylesheet by this module, and the line spans the
gallery prints are checked against where those banners actually sit.

The committed bytes are read at import time. Another suite in this directory
rebuilds the whole gallery in ``setUpClass``, and :mod:`unittest` discovery
imports every module before running any of them, so the bytes compared here are
the ones that were on disk when the run started regardless of suite order.
"""

from __future__ import annotations

import re
import unittest
from typing import Final

from hexbench.design.build_cards import render_gallery_index

from ._support import PACKAGE_ROOT, STATIC_ROOT, Assertions


_ENCODING: Final = "utf-8"

_LINE_SEPARATOR: Final = "\r\n"
"""The terminator the generator writes with, and the repository's own policy."""

_DESIGN_ROOT: Final = PACKAGE_ROOT / "design"
_INDEX_PATH: Final = _DESIGN_ROOT / "index.html"
_CARDS_DIR: Final = _DESIGN_ROOT / "cards"
_STYLESHEET_PATH: Final = STATIC_ROOT / "app.css"

_EXPECTED_CARDS: Final = 37
"""How many specimens the gallery holds; a comparison covering fewer proves nothing."""

_MINIMUM_SECTIONS: Final = 12
"""Fewest numbered sections ``app.css`` can hold.

The stylesheet had twelve when the gallery was written and has since grown a
thirteenth for forced colours. Pinning the exact number made the generator's own
growth a test failure, so what is checked instead is that the gallery renders one
group per section the stylesheet actually declares - two independently derived
counts - with this floor underneath so an empty or truncated parse cannot satisfy
that equality trivially.
"""

_NEEDLE_LENGTH: Final = 400
"""How much of the stylesheet to look for when asking whether it was inlined."""

_MINIMUM_INDEX_LENGTH: Final = 100_000
"""A floor on the rendered page, so an empty render cannot satisfy the absence checks."""

_SECTION_BANNER: Final = re.compile(r"^/\* =+ (\d+)\. (.+?) \*/$")
_STYLESHEET_LINK: Final = re.compile(r'<link rel="stylesheet" href="([^"]+)">')
_CARD_TITLE: Final = re.compile(r"<title>hexbench &middot; (.+?)</title>")
_NAV_GROUP: Final = re.compile(r'<div class="ds-nav-group">(.*?)</div>', re.DOTALL)
_NAV_SECTION: Final = re.compile(r'<a class="ds-nav-section" href="#ds-section-(\d+)">(\d+)\. ([^<]+)</a>')
_NAV_LINK: Final = re.compile(r'<a class="ds-nav-link" href="#ds-card-([^"]+)">([^<]+)</a>')
_GROUP_START: Final = re.compile(r'<section class="ds-group" id="ds-section-(\d+)">')
_GROUP_TITLE: Final = re.compile(r'<h2 class="ds-group-title">(\d+)\. ([^<]+)</h2>')
_GROUP_META: Final = re.compile(r'<p class="ds-group-meta">app\.css lines (\d+)&ndash;(\d+) &middot; ([^<]+)</p>')
_CARD_ARTICLE: Final = re.compile(r'<article class="ds-card" id="ds-card-([^"]+)">')
_CARD_FILE_LINK: Final = re.compile(r'<a class="ds-card-file" href="cards/([^"]+)">')

_STYLESHEET: Final = _STYLESHEET_PATH.read_text(encoding=_ENCODING)
"""``static/app.css`` as a browser would receive it, read once for this module."""

_NEEDLE: Final = _STYLESHEET[len(_STYLESHEET) // 2 : len(_STYLESHEET) // 2 + _NEEDLE_LENGTH]
"""A slice from the middle of the stylesheet, present verbatim in anything that inlines it."""

_RENDERED: Final = render_gallery_index()
"""What ``design/index.html`` would contain if the generator ran right now."""

_COMMITTED: Final[bytes | None] = _INDEX_PATH.read_bytes() if _INDEX_PATH.is_file() else None
"""What ``design/index.html`` contained before any suite in this run could rewrite it."""


def _card_files() -> tuple[str, ...]:
    """List the standalone card files the generator has written.

    Returns:
        tuple[str, ...]: Every card file name in ``design/cards``, sorted.
    """
    return tuple(sorted(path.name for path in _CARDS_DIR.glob("*.html")))


def _card_titles() -> dict[str, str]:
    """Read each card's own title out of the card file.

    The gallery's nav labels each specimen with the same title the standalone
    card carries, so taking the expected labels from the card files rather than
    from the generator's table keeps the two derivations independent.

    Returns:
        dict[str, str]: Card file name mapped to the title it declares.

    Raises:
        AssertionError: If a card file carries no title element.
    """
    titles: dict[str, str] = {}
    for name in _card_files():
        found = _CARD_TITLE.search((_CARDS_DIR / name).read_text(encoding=_ENCODING))
        if found is None:
            message = f"{name} carries no <title>, so the gallery's label for it cannot be checked"
            raise AssertionError(message)
        titles[name] = found.group(1)
    return titles


def _stylesheet_sections() -> tuple[tuple[int, str, int, int], ...]:
    """Locate the stylesheet's numbered section banners, independently of the generator.

    Returns:
        tuple[tuple[int, str, int, int], ...]: Section number, name, the line
        the banner sits on and the last line the section covers.
    """
    lines = _STYLESHEET.splitlines()
    banners = [
        (int(found.group(1)), found.group(2).strip(), number)
        for number, line in enumerate(lines, start=1)
        if (found := _SECTION_BANNER.match(line)) is not None
    ]
    ends = [start - 1 for _section, _name, start in banners[1:]] + [len(lines)]
    return tuple((section, name, start, end) for (section, name, start), end in zip(banners, ends, strict=True))


def _rendered_groups() -> tuple[tuple[int, str], ...]:
    """Split the gallery into its rendered section groups.

    Returns:
        tuple[tuple[int, str], ...]: Section number and the markup of that
        group, in the order the page renders them.
    """
    starts = [(int(found.group(1)), found.start()) for found in _GROUP_START.finditer(_RENDERED)]
    edges = [start for _section, start in starts[1:]] + [len(_RENDERED)]
    return tuple((section, _RENDERED[start:edge]) for (section, start), edge in zip(starts, edges, strict=True))


def _nav_groups() -> tuple[tuple[int, tuple[str, ...]], ...]:
    """Read the nav's grouping of specimens under sections.

    Returns:
        tuple[tuple[int, tuple[str, ...]], ...]: Section number and the card
        anchors listed beneath it, in nav order.
    """
    groups: list[tuple[int, tuple[str, ...]]] = []
    for block in _NAV_GROUP.finditer(_RENDERED):
        heading = _NAV_SECTION.search(block.group(1))
        if heading is None:
            continue
        groups.append((int(heading.group(1)), tuple(slug for slug, _label in _NAV_LINK.findall(block.group(1)))))
    return tuple(groups)


_SECTIONS: Final = _stylesheet_sections()
_TITLES: Final = _card_titles()
_GROUPS: Final = _rendered_groups()
_NAV: Final = _nav_groups()


class TheGalleryRendersTheLiveStylesheetTests(Assertions, unittest.TestCase):
    """The one property the gallery exists for: it shows the stylesheet as it is now."""

    def test_the_index_links_the_canonical_stylesheet(self) -> None:
        """The href has to resolve to ``static/app.css`` itself, not merely to something that loads."""
        found = _STYLESHEET_LINK.search(_RENDERED)
        self.require(found is not None, "the gallery declares no stylesheet link at all")
        linked = (_INDEX_PATH.parent / (found.group(1) if found else "")).resolve()
        self.equal(linked, _STYLESHEET_PATH.resolve(), "the file the gallery's stylesheet href resolves to")
        self.truthy(linked.is_file(), "the linked stylesheet exists on disk")

    def test_the_index_does_not_inline_the_stylesheet(self) -> None:
        """Inlining it again would restore the very snapshot the gallery replaced."""
        self.absent(_NEEDLE, _RENDERED, "the gallery carries the stylesheet's text, so it is a copy again rather than a link")

    def test_the_index_on_disk_is_what_the_generator_would_write_now(self) -> None:
        """A gallery nobody regenerated describes a set of sections and specimens that has moved on."""
        expected = _RENDERED.replace("\n", _LINE_SEPARATOR).encode(_ENCODING)
        committed = _COMMITTED
        self.require(committed is not None, f"{_INDEX_PATH} does not exist; run `python -m hexbench.design.build_cards`")
        self.require(
            committed == expected,
            f"{_INDEX_PATH.name} is stale: on disk {len(committed or b'')} bytes, freshly rendered {len(expected)} bytes. "
            "Regenerate with `python -m hexbench.design.build_cards`.",
        )


class TheGalleryHoldsEverySpecimenTests(Assertions, unittest.TestCase):
    """A card that exists but is not in the gallery is a card nobody will see."""

    def test_every_card_file_has_an_article_in_the_gallery(self) -> None:
        """The articles are the gallery; a missing one is a specimen silently dropped."""
        rendered = sorted(f"{slug}.html" for slug in _CARD_ARTICLE.findall(_RENDERED))
        self.require_same(rendered, list(_TITLES), "the gallery's articles and the card files on disk have drifted apart")

    def test_every_card_file_has_a_nav_entry_labelled_the_way_the_card_titles_itself(self) -> None:
        """The nav is how a specimen is found, and its label has to be the specimen's own name."""
        labelled = {f"{slug}.html": label for slug, label in _NAV_LINK.findall(_RENDERED)}
        self.require_same(labelled, _TITLES, "the gallery's nav labels no longer match the titles the card files declare")

    def test_every_article_links_the_standalone_card_beside_it(self) -> None:
        """The cards stay: two suites read them and the handoff cites four by path."""
        linked = sorted(_CARD_FILE_LINK.findall(_RENDERED))
        self.require_same(linked, list(_TITLES), "the gallery no longer links every standalone card file")

    def test_no_specimen_is_rendered_twice(self) -> None:
        """A card filed under two sections would render twice and be counted once."""
        slugs = _CARD_ARTICLE.findall(_RENDERED)
        self.equal(len(slugs), len(set(slugs)), "the number of distinct card anchors in the gallery")


class TheGalleryIsGroupedByTheStylesheetsOwnSectionsTests(Assertions, unittest.TestCase):
    """The nav is a map of ``app.css``; a map of something else would be worse than none."""

    def test_the_gallery_groups_are_exactly_the_stylesheet_sections_in_order(self) -> None:
        """Twelve groups, numbered and named as the stylesheet numbers and names them."""
        rendered = [(int(number), name) for number, name in _GROUP_TITLE.findall(_RENDERED)]
        expected = [(section, name) for section, name, _first, _last in _SECTIONS]
        self.require_same(rendered, expected, "the gallery's section headings are not the ones app.css declares")

    def test_the_nav_lists_the_same_sections_as_the_page(self) -> None:
        """A nav that has drifted from the page sends the reader to an anchor that is not there."""
        self.require_same(
            [section for section, _links in _NAV],
            [section for section, _markup in _GROUPS],
            "the nav's sections and the page's sections disagree",
        )

    def test_every_group_states_the_lines_that_section_actually_covers(self) -> None:
        """The spans are read out of the stylesheet, so a stale one means the gallery was not regenerated."""
        printed: list[tuple[int, int, int]] = []
        for section, markup in _GROUPS:
            meta = _GROUP_META.search(markup)
            self.require(meta is not None, f"section {section} renders no line span")
            if meta is not None:
                printed.append((section, int(meta.group(1)), int(meta.group(2))))
        expected = [(section, first, last) for section, _name, first, last in _SECTIONS]
        self.require_same(printed, expected, "the line spans the gallery prints are not where app.css puts its section banners")

    def test_every_group_counts_the_specimens_it_actually_renders(self) -> None:
        """The wording under each heading is a claim about the page it sits on."""
        for section, markup in _GROUPS:
            meta = _GROUP_META.search(markup)
            held = len(_CARD_ARTICLE.findall(markup))
            expected = "no specimen" if held == 0 else f"{held} specimen{'s' if held > 1 else ''}"
            self.require(meta is not None, f"section {section} renders no specimen count")
            if meta is not None:
                self.equal(meta.group(3), expected, f"the specimen count section {section} states")

    def test_every_nav_entry_sits_under_the_section_its_specimen_renders_in(self) -> None:
        """Grouping is the feature: a link filed under the wrong section is a wrong map."""
        navigated = dict(_NAV)
        rendered = {section: tuple(_CARD_ARTICLE.findall(markup)) for section, markup in _GROUPS}
        self.require_same(navigated, rendered, "the nav files specimens under sections the page renders them somewhere else in")


class TheComparisonWasNotVacuousTests(Assertions, unittest.TestCase):
    """Every check above is an absence, a count or a comparison; these are why they mean something."""

    def test_the_stylesheet_needle_is_one_that_can_be_found(self) -> None:
        """The absence check is only evidence if the same slice turns up in a page that does inline the stylesheet."""
        self.equal(len(_NEEDLE), _NEEDLE_LENGTH, "length of the slice taken from the stylesheet")
        inlined = (_CARDS_DIR / "foundations-colour.html").read_text(encoding=_ENCODING)
        self.contains(_NEEDLE, inlined, "the standalone cards no longer inline the stylesheet, so the needle proves nothing")

    def test_the_gallery_is_a_whole_page(self) -> None:
        """An empty render would satisfy every absence check in this module."""
        self.exceeds(len(_RENDERED), _MINIMUM_INDEX_LENGTH, "length of the rendered gallery")
        self.equal(len(_GROUPS), len(_SECTIONS), "section groups rendered, against section banners declared in app.css")
        self.require(
            len(_SECTIONS) >= _MINIMUM_SECTIONS,
            f"app.css declares {len(_SECTIONS)} numbered sections, fewer than the {_MINIMUM_SECTIONS} it has held since the "
            f"gallery was written, so the parse found less of the stylesheet than there is",
        )
        self.equal(len(_TITLES), _EXPECTED_CARDS, "number of card files read from design/cards")
        self.equal(len(_CARD_ARTICLE.findall(_RENDERED)), _EXPECTED_CARDS, "number of specimens rendered in the gallery")

    def test_the_render_is_deterministic(self) -> None:
        """gate.ps1 regenerates and then fails on a dirty tree, so a wobbling render fails the build."""
        self.equal(render_gallery_index(), _RENDERED, "a second render of the gallery")


if __name__ == "__main__":
    unittest.main()
