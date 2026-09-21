# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Regression gate for ``_pdf_render_bookmarks``'s offset formatting.

Covers the 2026-09-20 Qodana ``PyStringFormatInspection`` finding:
``bookmarks: list[dict[str, object]]`` means ``bm.get("offset", 0)`` types as
bare ``object``, which does not support the ``:X`` format spec. The function
now coerces the raw value to ``int`` (falling back to ``0`` for a
non-``int`` offset) before formatting it, so a malformed bookmark entry from
an untrusted or hand-edited bookmark list renders ``0x0`` instead of raising
``TypeError`` and aborting the whole PDF export mid-document.

Exercises the real, module-private ``_pdf_render_bookmarks`` function
(invoked via ``getattr``, bypassing ``reportPrivateUsage``, the project's
established pattern for testing private module internals -- see
``tests/bridges/test_process_bridge.py``) against a real,
fully-conforming ``_FPDFProtocol`` double, recording every ``cell`` call's
text so the test asserts on exactly what would be drawn onto the PDF page.
"""

from __future__ import annotations

from typing import Any

from intellicrack.bridges import hex_editor as hex_editor_module


_ATTR_PDF_RENDER_BOOKMARKS = "_pdf_render_bookmarks"


class _RecordingFPDF:
    """Fully ``_FPDFProtocol``-conforming double recording every ``cell`` call's text."""

    def __init__(self, **kwargs: str) -> None:
        """No-op constructor matching the protocol signature.

        Args:
            **kwargs: Constructor keyword arguments, ignored.
        """
        _ = (self, kwargs)
        self.cell_texts: list[str] = []

    def set_auto_page_break(self, *, auto: bool, margin: float = 0) -> None:
        """No-op page-break setter matching the protocol signature.

        Args:
            auto: Whether to automatically page-break.
            margin: Bottom margin at which to break in user units.
        """
        _ = (self, auto, margin)

    def add_page(self) -> None:
        """No-op page-add matching the protocol signature."""
        _ = self

    def set_font(self, family: str, style: str = "", size: float = 0) -> None:
        """No-op font setter matching the protocol signature.

        Args:
            family: Font family name.
            style: Font style.
            size: Font size in points.
        """
        _ = (self, family, style, size)

    def cell(
        self,
        w: float,
        h: float = 0,
        txt: str = "",
        border: int | str = 0,
        ln: int = 0,
        align: str = "",
        *,
        fill: bool = False,
        link: str = "",
        new_x: str = "RIGHT",
        new_y: str = "TOP",
    ) -> None:
        """Record the cell's text content.

        Args:
            w: Cell width in user units.
            h: Cell height in user units.
            txt: Cell text content.
            border: Border specification.
            ln: Line break flag.
            align: Horizontal alignment.
            fill: Whether to fill the cell background.
            link: Optional link target.
            new_x: Cursor X advance directive.
            new_y: Cursor Y advance directive.
        """
        _ = (self, w, h, border, ln, align, fill, link, new_x, new_y)
        self.cell_texts.append(txt)

    def ln(self, h: float = 0) -> None:
        """No-op line-advance matching the protocol signature.

        Args:
            h: Line height in user units.
        """
        _ = (self, h)

    def set_fill_color(self, r: int, g: int = 0, b: int = 0) -> None:
        """No-op fill-color setter matching the protocol signature.

        Args:
            r: Red component (0-255).
            g: Green component (0-255).
            b: Blue component (0-255).
        """
        _ = (self, r, g, b)

    def output(self, name: str = "", dest: str = "") -> bytes | bytearray | str | None:
        """No-op document writer matching the protocol signature.

        Args:
            name: Output filename or path.
            dest: Destination mode.

        Returns:
            bytes | bytearray | str | None: Always None.
        """
        _ = (self, name, dest)
        return None


def _render_bookmarks(pdf: _RecordingFPDF, bookmarks: list[dict[str, Any]]) -> None:
    """Invoke ``hex_editor._pdf_render_bookmarks`` via ``getattr``, bypassing ``reportPrivateUsage``.

    Args:
        pdf: The recording FPDF double.
        bookmarks: Bookmark metadata dicts to render.

    Raises:
        TypeError: If the resolved attribute is not callable.
    """
    fn: object = getattr(hex_editor_module, _ATTR_PDF_RENDER_BOOKMARKS)
    if not callable(fn):
        msg = f"hex_editor.{_ATTR_PDF_RENDER_BOOKMARKS} is not callable"
        raise TypeError(msg)
    fn(pdf, bookmarks)


def test_int_offset_renders_as_uppercase_hex() -> None:
    """A well-formed int ``offset`` renders as uppercase hex."""
    pdf = _RecordingFPDF()
    bookmarks: list[dict[str, Any]] = [{"label": "entry_point", "offset": 0x1000, "length": 16}]

    _render_bookmarks(pdf, bookmarks)

    assert pdf.cell_texts == ["Bookmarks:", "  entry_point: 0x1000 (16 bytes)"]


def test_missing_offset_defaults_to_zero() -> None:
    """A bookmark with no ``offset`` key renders ``0x0`` via the ``.get`` default."""
    pdf = _RecordingFPDF()
    bookmarks: list[dict[str, Any]] = [{"label": "no_offset", "length": 4}]

    _render_bookmarks(pdf, bookmarks)

    assert pdf.cell_texts == ["Bookmarks:", "  no_offset: 0x0 (4 bytes)"]


def test_non_int_offset_falls_back_to_zero_without_crashing() -> None:
    """A malformed non-int ``offset`` must not reach ``:X}`` and must fall back to 0x0.

    Regression target: reverting the ``isinstance(raw_offset, int)`` coercion
    back to a bare ``bm.get("offset", 0)`` would let this string reach
    ``f"...:X}"`` and raise ``TypeError``, aborting the PDF export.
    """
    pdf = _RecordingFPDF()
    bookmarks: list[dict[str, Any]] = [{"label": "corrupted", "offset": "not-an-int", "length": 8}]

    _render_bookmarks(pdf, bookmarks)

    assert pdf.cell_texts == ["Bookmarks:", "  corrupted: 0x0 (8 bytes)"]


def test_duplicate_labels_render_once_each_with_their_own_offsets() -> None:
    """Distinct labels each render their own offset; a repeated label is skipped."""
    pdf = _RecordingFPDF()
    bookmarks: list[dict[str, Any]] = [
        {"label": "a", "offset": 0x10, "length": 1},
        {"label": "b", "offset": 0x20, "length": 2},
        {"label": "a", "offset": 0x30, "length": 3},
    ]

    _render_bookmarks(pdf, bookmarks)

    assert pdf.cell_texts == ["Bookmarks:", "  a: 0x10 (1 bytes)", "  b: 0x20 (2 bytes)"]


def test_empty_bookmarks_renders_nothing() -> None:
    """An empty bookmark list renders no cells at all."""
    pdf = _RecordingFPDF()

    _render_bookmarks(pdf, [])

    assert pdf.cell_texts == []
