# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression test for finding M10: search/replace encoding must come from currentData.

Pre-fix, ``_on_search`` and ``_replace_encoding`` computed the codec as
``combo.currentText().lower().replace("-", "")`` -- the *display label*. For the
item labelled ``"ASCII (7-bit)"`` that produced ``"ascii (7bit)"``, an invalid
codec name that raises ``LookupError`` when handed to ``bytes.decode`` or the
Rust backend, so the text search silently failed. The correct codec is stored in
the item's user data (``"ascii"``). This test builds a real ``QComboBox`` whose
label differs from its user data and asserts both the search and replace codec
resolvers return the valid codec name from ``currentData``.
"""

from __future__ import annotations

import codecs
from typing import TYPE_CHECKING, Final

import pytest
from PyQt6.QtWidgets import QApplication, QComboBox, QWidget

from intellicrack.ui.panels.hex_editor.search import SearchMixin


if TYPE_CHECKING:
    from collections.abc import Iterator


_ASCII_LABEL: Final[str] = "ASCII (7-bit)"
_ASCII_CODEC: Final[str] = "ascii"
_BUGGY_MUNGED_LABEL: Final[str] = "ascii (7bit)"


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Provide a process-wide ``QApplication`` for Qt widget construction.

    Yields:
        QApplication: The active Qt application for the test process.
    """
    existing = QApplication.instance()
    if existing is not None and isinstance(existing, QApplication):
        yield existing
        return
    yield QApplication([])


class _EncodingHarness(QWidget):
    """Harness exposing the production encoding resolvers over a real combo box.

    Builds a ``QComboBox`` whose display label (``"ASCII (7-bit)"``) differs from
    its codec user data (``"ascii"``), then borrows ``_selected_search_encoding``
    and ``_replace_encoding`` from :class:`SearchMixin` via ``getattr``.
    """

    def __init__(self) -> None:
        """Initialise the harness with an ASCII combo item whose label != user data."""
        super().__init__()
        combo = QComboBox()
        combo.addItem(_ASCII_LABEL, userData=_ASCII_CODEC)
        combo.setCurrentIndex(0)
        self._encoding_combo: QComboBox | None = combo

    def _selected_search_encoding(self) -> str:
        """Delegate to the production search-encoding resolver.

        Provides the bound method that the borrowed ``_replace_encoding``
        chains to through ``self``.

        Returns:
            str: The resolved codec name from the production resolver.
        """
        return getattr(SearchMixin, "_selected_search_encoding")(self)

    def selected_search_encoding(self) -> str:
        """Return the codec resolved for the text-search path.

        Returns:
            str: Resolved codec name from the production resolver.
        """
        return getattr(SearchMixin, "_selected_search_encoding")(self)

    def replace_encoding(self) -> str:
        """Return the codec resolved for the replace path.

        Returns:
            str: Resolved codec name from the production resolver.
        """
        return getattr(SearchMixin, "_replace_encoding")(self)


@pytest.mark.usefixtures("qapp")
class TestSearchEncodingResolution:
    """M10: encoding must be read from currentData, yielding a valid codec name."""

    @staticmethod
    def test_search_encoding_is_codec_from_user_data(qapp: QApplication) -> None:
        """Assert the search codec is the user-data value, not the munged label.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        resolved = _EncodingHarness().selected_search_encoding()
        assert resolved == _ASCII_CODEC, f"search encoding must be the codec {_ASCII_CODEC!r} from currentData, got {resolved!r}"
        assert resolved != _BUGGY_MUNGED_LABEL, f"search encoding must not be the munged label {_BUGGY_MUNGED_LABEL!r}"

    @staticmethod
    def test_replace_encoding_is_codec_from_user_data(qapp: QApplication) -> None:
        """Assert the replace codec is the user-data value, not the munged label.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        resolved = _EncodingHarness().replace_encoding()
        assert resolved == _ASCII_CODEC, f"replace encoding must be the codec {_ASCII_CODEC!r} from currentData, got {resolved!r}"

    @staticmethod
    def test_resolved_search_encoding_is_a_valid_codec(qapp: QApplication) -> None:
        """Assert the resolved search codec looks up without ``LookupError``.

        The pre-fix value ``"ascii (7bit)"`` raises ``LookupError`` here; the
        fixed value ``"ascii"`` resolves cleanly.

        Args:
            qapp: Qt application fixture (kept alive for widget construction).
        """
        del qapp
        resolved = _EncodingHarness().selected_search_encoding()
        info = codecs.lookup(resolved)
        assert info.name, f"resolved search encoding {resolved!r} must be a valid codec"

    @staticmethod
    def test_munged_label_would_raise_lookup_error() -> None:
        """Assert the pre-fix munged label is genuinely an invalid codec.

        Anchors the regression: proves ``"ascii (7bit)"`` (what the old
        ``currentText`` path produced) is not a resolvable codec, so the fix is
        load-bearing rather than cosmetic.
        """
        with pytest.raises(LookupError):
            codecs.lookup(_BUGGY_MUNGED_LABEL)
