# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Round 2, items 14 and 44: the elicitation form sends only what the operator gave, as the protocol's types and formats define it.

Each gate builds the real dialog from a real protocol request, fills its real widgets as an operator would, presses Send, and reads what
the dialog returns to the server: the action and the content. An optional yes/no question left alone is omitted, not sent as ``false``;
``nan``, ``inf`` and other text JSON cannot carry are refused as numbers; dates, date-times and addresses must be written as RFC 3339 and
RFC 3986 write them; and a legacy ``enumNames`` list captions the choices while the value sent stays the enum's.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from mcp_types import ElicitRequestFormParams, ElicitResult
from PyQt6.QtWidgets import QCheckBox, QComboBox, QLineEdit, QPushButton, QWidget

from intellicrack.ui.mcp_elicitation_dialog import McpElicitationDialog


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


def _dialog(qtbot: QtBot, properties: dict[str, Any], required: list[str] | None = None) -> McpElicitationDialog:
    """Build the dialog for a form request with the given fields.

    Args:
        qtbot: The Qt test driver.
        properties: The requested schema's properties.
        required: The requested schema's required fields.

    Returns:
        McpElicitationDialog: The dialog, not yet answered.
    """
    schema: dict[str, Any] = {"type": "object", "properties": properties, "required": required or []}
    dialog = McpElicitationDialog("srv", ElicitRequestFormParams(message="Fill this in.", requested_schema=schema))
    qtbot.addWidget(dialog)
    return dialog


def _editor[W: QWidget](dialog: McpElicitationDialog, name: str, kind: type[W]) -> W:
    """Find one field's editor.

    Args:
        dialog: The dialog.
        name: The field name.
        kind: The editor class.

    Returns:
        W: The editor.
    """
    editor = dialog.findChild(kind, f"mcp_elicit_field_{name}")
    assert editor is not None, f"no {kind.__name__} for {name!r}"
    return editor


def _send(dialog: McpElicitationDialog) -> ElicitResult:
    """Press Send and read what would go back to the server.

    Args:
        dialog: The dialog.

    Returns:
        ElicitResult: The answer.
    """
    button = dialog.findChild(QPushButton, "mcp_elicit_accept")
    assert button is not None
    button.click()
    return dialog.to_result()


def _typed(qtbot: QtBot, schema: dict[str, Any], text: str) -> ElicitResult:
    """Type one answer into a required field and press Send.

    Args:
        qtbot: The Qt test driver.
        schema: The field's schema.
        text: What the operator types.

    Returns:
        ElicitResult: The answer; ``cancel`` with no content when Send was refused.
    """
    dialog = _dialog(qtbot, {"field": schema}, ["field"])
    _editor(dialog, "field", QLineEdit).setText(text)
    return _send(dialog)


class TestOptionalBoolean:
    """An optional yes/no question can be left unanswered, and then is not sent."""

    def test_untouched_optional_boolean_is_omitted(self, qtbot: QtBot) -> None:
        """Leaving an optional boolean with no default alone sends nothing for it.

        Args:
            qtbot: The Qt test driver.
        """
        dialog = _dialog(qtbot, {"subscribe": {"type": "boolean"}, "name": {"type": "string"}}, ["name"])
        _editor(dialog, "name", QLineEdit).setText("Ada")

        result = _send(dialog)

        assert result.action == "accept"
        assert result.content == {"name": "Ada"}

    @pytest.mark.parametrize(("caption", "expected"), [("Yes", {"subscribe": True}), ("No", {"subscribe": False})])
    def test_optional_boolean_answer_is_sent(self, qtbot: QtBot, caption: str, expected: dict[str, bool]) -> None:
        """Choosing Yes or No sends ``true`` or ``false``.

        Args:
            qtbot: The Qt test driver.
            caption: The choice made.
            expected: What must be sent.
        """
        dialog = _dialog(qtbot, {"subscribe": {"type": "boolean"}})
        answer = _editor(dialog, "subscribe", QComboBox)
        answer.setCurrentIndex(answer.findText(caption))

        assert _send(dialog).content == expected

    def test_optional_boolean_starts_at_its_default(self, qtbot: QtBot) -> None:
        """A default is offered as the starting answer and sent when left alone.

        Args:
            qtbot: The Qt test driver.
        """
        dialog = _dialog(qtbot, {"subscribe": {"type": "boolean", "default": True}})

        assert _send(dialog).content == {"subscribe": True}

    def test_required_boolean_is_a_check_box_and_always_sent(self, qtbot: QtBot) -> None:
        """A required boolean is answered with a check box, and unticked sends ``false``.

        Args:
            qtbot: The Qt test driver.
        """
        dialog = _dialog(qtbot, {"agree": {"type": "boolean"}}, ["agree"])
        assert not _editor(dialog, "agree", QCheckBox).isChecked()

        assert _send(dialog).content == {"agree": False}


class TestNumbers:
    """Only what JSON can carry is accepted as a number."""

    @pytest.mark.parametrize("text", ["nan", "NaN", "inf", "-inf", "Infinity", "1e999", "1_000", "0x10", "+5", "05"])
    def test_non_json_numbers_are_refused(self, qtbot: QtBot, text: str) -> None:
        """Text JSON has no number for is refused and nothing is sent.

        Args:
            qtbot: The Qt test driver.
            text: What the operator typed.
        """
        result = _typed(qtbot, {"type": "number"}, text)

        assert result.action == "cancel"
        assert result.content is None

    @pytest.mark.parametrize(("text", "value"), [("12", 12), ("-0.5", -0.5), ("6.02e23", 6.02e23), ("0", 0)])
    def test_json_numbers_are_sent(self, qtbot: QtBot, text: str, value: float) -> None:
        """A number written as JSON writes it is sent as that number.

        Args:
            qtbot: The Qt test driver.
            text: What the operator typed.
            value: What must be sent.
        """
        assert _typed(qtbot, {"type": "number"}, text).content == {"field": value}

    @pytest.mark.parametrize("text", ["1.5", "1e3", "nan"])
    def test_integer_refuses_fractions_and_exponents(self, qtbot: QtBot, text: str) -> None:
        """An integer field takes only a whole number written as digits.

        Args:
            qtbot: The Qt test driver.
            text: What the operator typed.
        """
        assert _typed(qtbot, {"type": "integer"}, text).content is None


class TestFormats:
    """Dates, date-times and addresses are checked against RFC 3339 and RFC 3986."""

    @pytest.mark.parametrize(
        ("declared", "text"),
        [
            ("date", "20260131"),
            ("date", "2026-1-31"),
            ("date", "2026-02-30"),
            ("date-time", "2026-01-31"),
            ("date-time", "2026-01-31 10:00"),
            ("date-time", "2026-01-31T10:00"),
            ("date-time", "2026-01-31T10:00:00"),
            ("date-time", "2026-01-31T25:00:00Z"),
            ("uri", "a:b"),
            ("uri", "C:\\\\data"),
            ("uri", "https://"),
            ("uri", "https://exa mple.com"),
            ("uri", "example.com/page"),
            ("uri", "https://example.com/%zz"),
        ],
    )
    def test_lax_forms_are_refused(self, qtbot: QtBot, declared: str, text: str) -> None:
        """Text the format's specification does not allow is refused.

        Args:
            qtbot: The Qt test driver.
            declared: The ``format`` keyword.
            text: What the operator typed.
        """
        result = _typed(qtbot, {"type": "string", "format": declared}, text)

        assert result.action == "cancel"
        assert result.content is None

    @pytest.mark.parametrize(
        ("declared", "text"),
        [
            ("date", "2026-01-31"),
            ("date-time", "2026-01-31T10:00:00Z"),
            ("date-time", "2026-01-31t10:00:00.25+05:30"),
            ("uri", "https://example.com/page?q=1#top"),
            ("uri", "mailto:someone@example.com"),
            ("uri", "urn:isbn:0451450523"),
        ],
    )
    def test_conforming_forms_are_sent(self, qtbot: QtBot, declared: str, text: str) -> None:
        """Text that conforms is sent unchanged.

        Args:
            qtbot: The Qt test driver.
            declared: The ``format`` keyword.
            text: What the operator typed.
        """
        assert _typed(qtbot, {"type": "string", "format": declared}, text).content == {"field": text}


class TestLegacyEnumNames:
    """``enumNames`` captions the choices; the value sent is the enum's."""

    def test_captions_come_from_enum_names_and_values_from_enum(self, qtbot: QtBot) -> None:
        """The operator picks by caption and the server receives the matching enum value.

        Args:
            qtbot: The Qt test driver.
        """
        schema = {"type": "string", "enum": ["lo", "hi"], "enumNames": ["Low priority", "High priority"]}
        dialog = _dialog(qtbot, {"priority": schema}, ["priority"])
        choice = _editor(dialog, "priority", QComboBox)
        captions = [choice.itemText(index) for index in range(choice.count())]
        choice.setCurrentIndex(choice.findText("High priority"))

        result = _send(dialog)

        assert captions[1:] == ["Low priority", "High priority"]
        assert result.content == {"priority": "hi"}
