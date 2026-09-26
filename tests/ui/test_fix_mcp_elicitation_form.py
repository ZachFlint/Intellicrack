# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Gates for the elicitation form following the schema the server sent.

Each gate builds the real dialog from a real protocol request, fills its real
widgets the way an operator would, presses Send, and reads the answer the
dialog would return to the server. Nothing about the dialog is replaced.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp_types import ElicitRequestFormParams, ElicitRequestURLParams
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QComboBox, QLabel, QLineEdit, QListWidget, QPushButton, QWidget

from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


def _dialog(qtbot: QtBot, properties: dict[str, Any], required: list[str] | None = None) -> McpElicitationDialog:
    """Build the dialog for a form request with the given fields.

    Args:
        qtbot: pytest-qt bot.
        properties: The requested schema's properties.
        required: The requested schema's required fields.

    Returns:
        McpElicitationDialog: The dialog, not yet answered.
    """
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required is not None:
        schema["required"] = required
    dialog = McpElicitationDialog("srv", ElicitRequestFormParams(message="Fill this in.", requested_schema=schema))
    qtbot.addWidget(dialog)
    return dialog


def _field[W: QWidget](dialog: McpElicitationDialog, name: str, kind: type[W]) -> W:
    """Find the editor for one field.

    Args:
        dialog: The dialog.
        name: The field name.
        kind: The editor class expected.

    Returns:
        W: The editor.
    """
    editor = dialog.findChild(kind, f"mcp_elicit_field_{name}")
    assert editor is not None, f"no {kind.__name__} for field {name!r}"
    return editor


def _send(dialog: McpElicitationDialog) -> None:
    """Press Send.

    Args:
        dialog: The dialog.
    """
    button = dialog.findChild(QPushButton, "mcp_elicit_accept")
    assert button is not None
    button.click()


def _error_text(dialog: McpElicitationDialog, name: str) -> str | None:
    """Read the problem shown beside one field.

    Args:
        dialog: The dialog.
        name: The field name.

    Returns:
        str | None: The message, or ``None`` when none is shown.
    """
    label = dialog.findChild(QLabel, f"mcp_elicit_error_{name}")
    assert label is not None
    return label.text() if not label.isHidden() else None


class TestBoundsAreEnforced:
    """Every bound the schema states is checked before anything is sent."""

    def test_number_outside_its_range_is_refused(self, qtbot: QtBot) -> None:
        """A value above ``maximum`` is refused, one inside the range is sent as an integer.

        Args:
            qtbot: pytest-qt bot.
        """
        dialog = _dialog(qtbot, {"count": {"type": "integer", "minimum": 1, "maximum": 10}}, ["count"])
        _field(dialog, "count", QLineEdit).setText("20")
        _send(dialog)
        assert dialog.action == "cancel", "a value above the maximum was sent"
        assert _error_text(dialog, "count") is not None

        _field(dialog, "count", QLineEdit).setText("5")
        _send(dialog)
        assert dialog.action == "accept"
        assert dialog.to_result().content == {"count": 5}

    def test_text_shorter_than_min_length_or_off_pattern_is_refused(self, qtbot: QtBot) -> None:
        """``minLength`` and ``pattern`` are both enforced.

        Args:
            qtbot: pytest-qt bot.
        """
        dialog = _dialog(qtbot, {"slug": {"type": "string", "minLength": 3, "pattern": "^[a-z]+$"}}, ["slug"])
        editor = _field(dialog, "slug", QLineEdit)
        editor.setText("ab")
        _send(dialog)
        assert dialog.action == "cancel", "text shorter than minLength was sent"
        editor.setText("ABC")
        _send(dialog)
        assert dialog.action == "cancel", "text that does not match the pattern was sent"
        editor.setText("abc")
        _send(dialog)
        assert dialog.to_result().content == {"slug": "abc"}

    def test_missing_required_field_is_reported_beside_it(self, qtbot: QtBot) -> None:
        """A blank required field shows its problem in the form, not only in the title.

        Args:
            qtbot: pytest-qt bot.
        """
        dialog = _dialog(qtbot, {"name": {"type": "string", "title": "Name"}}, ["name"])
        title = dialog.windowTitle()
        _send(dialog)
        assert dialog.action == "cancel"
        assert _error_text(dialog, "name") == "an answer is required"
        summary = dialog.findChild(QLabel, "mcp_elicit_errors")
        assert summary is not None
        assert not summary.isHidden()
        assert "Name" in summary.text()
        assert dialog.windowTitle() == title


class TestOptionalFieldsAreOmitted:
    """An optional field the operator leaves alone is not sent with an invented value."""

    def test_untouched_optional_number_and_enum_are_omitted(self, qtbot: QtBot) -> None:
        """Only the answered field is sent.

        Args:
            qtbot: pytest-qt bot.
        """
        dialog = _dialog(
            qtbot,
            {
                "name": {"type": "string"},
                "retries": {"type": "integer"},
                "ratio": {"type": "number"},
                "colour": {"type": "string", "enum": ["red", "green"]},
            },
            ["name"],
        )
        _field(dialog, "name", QLineEdit).setText("probe")
        _send(dialog)
        assert dialog.to_result().content == {"name": "probe"}


class TestChoicesFollowTheSchema:
    """Titled single-selects and multi-selects get real choice editors."""

    def test_titled_one_of_offers_titles_and_sends_the_const(self, qtbot: QtBot) -> None:
        """A ``oneOf`` of ``const``/``title`` pairs shows titles and sends the chosen value.

        Args:
            qtbot: pytest-qt bot.
        """
        dialog = _dialog(
            qtbot,
            {"level": {"type": "string", "oneOf": [{"const": "lo", "title": "Low"}, {"const": "hi", "title": "High"}]}},
            ["level"],
        )
        combo = _field(dialog, "level", QComboBox)
        assert [combo.itemText(index) for index in range(1, combo.count())] == ["Low", "High"]
        combo.setCurrentIndex(combo.findData("hi"))
        _send(dialog)
        assert dialog.to_result().content == {"level": "hi"}

    @pytest.mark.parametrize(
        "items",
        [
            {"type": "string", "enum": ["a", "b", "c"]},
            {"anyOf": [{"const": "a", "title": "A"}, {"const": "b", "title": "B"}, {"const": "c", "title": "C"}]},
        ],
    )
    def test_multi_select_sends_a_list(self, qtbot: QtBot, items: dict[str, Any]) -> None:
        """Ticking two choices sends a list of both values, and ``maxItems`` is enforced.

        Args:
            qtbot: pytest-qt bot.
            items: The array's ``items`` schema.
        """
        dialog = _dialog(qtbot, {"tags": {"type": "array", "items": items, "maxItems": 2}}, ["tags"])
        listing = _field(dialog, "tags", QListWidget)
        for row in range(listing.count()):
            item = listing.item(row)
            assert item is not None
            item.setCheckState(Qt.CheckState.Checked)
        _send(dialog)
        assert dialog.action == "cancel", "more items than maxItems were sent"

        last = listing.item(2)
        assert last is not None
        last.setCheckState(Qt.CheckState.Unchecked)
        _send(dialog)
        assert dialog.to_result().content == {"tags": ["a", "b"]}


class TestUrlRequest:
    """A URL-mode acceptance carries no content."""

    def test_url_send_has_no_content(self, qtbot: QtBot) -> None:
        """Pressing Send on a URL request accepts without a content field.

        Args:
            qtbot: pytest-qt bot.
        """
        dialog = McpElicitationDialog(
            "srv",
            ElicitRequestURLParams(message="Sign in, please.", url="https://example.invalid/login", elicitation_id="e1"),
        )
        qtbot.addWidget(dialog)
        _send(dialog)
        result = dialog.to_result()
        assert result.action == "accept"
        assert result.content is None
        assert "content" not in result.model_dump(exclude_none=True)
