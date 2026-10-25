# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Tests for SessionManagerDialog table column policy and detail label elision.

Covers two behaviours:

* Session table column policy. Column 0 stretches, and ``stretchLastSection`` is disabled so the trailing numeric
"Messages" column does not double-stretch the table and squeeze the date columns. The Messages column sizes to its contents.
* Detail label elision. Long provider names and model identifiers in fixed-width detail labels are elided, with the full value
stored as a tooltip so they never clip silently.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import pytest
from PyQt6.QtWidgets import QHeaderView, QLabel, QTableWidget

from intellicrack.ui.session_manager import SessionManagerDialog


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from PyQt6.QtWidgets import QApplication


@pytest.fixture
def session_dialog(qapp: QApplication) -> Iterator[SessionManagerDialog]:
    """Create a SessionManagerDialog instance.

    Args:
        qapp: Session-scoped Qt application fixture.

    Yields:
        SessionManagerDialog: A live dialog instance.
    """
    del qapp
    dialog = SessionManagerDialog()
    yield dialog
    dialog.deleteLater()


class TestSessionTableColumnPolicy:
    """The session table must not double-stretch and must size numerics to content."""

    def test_no_double_stretch_and_messages_sizes_to_contents(self, session_dialog: SessionManagerDialog) -> None:
        """Column 0 stretches, the last section does not, and Messages sizes to contents.

        Args:
            session_dialog: SessionManagerDialog fixture.
        """
        table_obj: object = getattr(session_dialog, "_session_table")
        table = cast("QTableWidget", table_obj)
        header = table.horizontalHeader()
        assert header is not None, "session table must have a horizontal header"

        assert not header.stretchLastSection(), (
            "stretchLastSection must be disabled so it does not double-stretch with the Stretch column 0"
        )
        assert header.sectionResizeMode(0) == QHeaderView.ResizeMode.Stretch, "the name column must stretch to absorb spare width"
        assert header.sectionResizeMode(3) == QHeaderView.ResizeMode.ResizeToContents, (
            "the numeric Messages column must size to its contents rather than waste width"
        )


class TestDetailLabelElision:
    """Long detail values must remain readable via a full-text tooltip."""

    def test_long_value_sets_full_text_tooltip(self, qapp: QApplication) -> None:
        """A long model id sets a tooltip equal to the full untruncated text.

        Args:
            qapp: Session-scoped Qt application fixture.
        """
        del qapp
        label = QLabel()
        label.resize(80, 20)
        long_value = "anthropic/claude-fable-5-20260101-extended-context-1m-preview-build"

        setter_obj: object = getattr(SessionManagerDialog, "_set_elided_detail")
        setter = cast("Callable[[QLabel, str], None]", setter_obj)
        setter(label, long_value)

        assert label.toolTip() == long_value, (
            f"the full model id must be preserved as the label tooltip so it is not silently clipped; got tooltip {label.toolTip()!r}"
        )
