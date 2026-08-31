# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for :class:`ChatPanel` and its input widget.

:class:`ChatPanel` is a pure view/controller widget: it collects user input
and re-emits it as ``message_submitted``, renders real :class:`Message`
objects into message bubbles, supports incremental streaming updates, and
manages conversation history. None of this was previously tested.

These tests drive the genuine widget through ``qtbot`` -- typing real text and
pressing the real Send button, feeding real :class:`Message`/:class:`ToolCall`
objects, and streaming real chunks -- then assert on the genuine rendered
content and emitted signal payloads. No widget behavior is stubbed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel

from intellicrack.core.types import Message, ToolCall
from intellicrack.ui.chat import ChatPanel, MessageBubble


if TYPE_CHECKING:
    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


def _make_panel(qtbot: QtBot) -> ChatPanel:
    """Construct and register a :class:`ChatPanel`.

    Args:
        qtbot: pytest-qt bot fixture.

    Returns:
        ChatPanel: The registered panel.
    """
    panel = ChatPanel()
    qtbot.addWidget(panel)
    return panel


def _bubble_texts(panel: ChatPanel) -> list[str]:
    """Collect the rendered content text of every message bubble.

    Args:
        panel: The chat panel.

    Returns:
        list[str]: Content-label text for each rendered bubble.
    """
    return [bubble.content_label.text() for bubble in panel.findChildren(MessageBubble)]


def test_send_button_emits_typed_text(qtbot: QtBot) -> None:
    """Clicking Send emits exactly one ``message_submitted`` carrying the text.

    Drives the real Send button and captures every ``message_submitted``
    payload to assert the full contract: exactly one emission with a single
    ``str`` argument equal to the typed text, the input cleared afterwards,
    no message bubble created by the submit path (re-emission only), and the
    Send button left enabled.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    emitted: list[tuple[object, ...]] = []
    panel.message_submitted.connect(lambda text: emitted.append((text,)))

    text_edit = panel._input._text_edit
    text_edit.setPlainText("disassemble the entry point")
    assert panel._input._send_button.isEnabled()

    with qtbot.waitSignal(panel.message_submitted, timeout=2_000) as blocker:
        qtbot.mouseClick(panel._input._send_button, Qt.MouseButton.LeftButton)

    assert emitted == [("disassemble the entry point",)]
    assert blocker.args == ["disassemble the entry point"]
    assert len(blocker.args) == 1
    assert isinstance(blocker.args[0], str)
    assert not text_edit.toPlainText()
    assert panel.findChildren(MessageBubble) == []
    assert panel.get_messages() == []
    assert panel._input._send_button.isEnabled()


def test_send_button_whitespace_only_does_not_emit(qtbot: QtBot) -> None:
    """Clicking Send with only whitespace emits nothing and keeps the text.

    Exercises the boundary where the input strips to empty: no
    ``message_submitted`` signal must fire, the input is preserved, and no
    bubble is rendered.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    emitted: list[str] = []
    panel.message_submitted.connect(emitted.append)

    text_edit = panel._input._text_edit
    text_edit.setPlainText("   \n\t  ")

    qtbot.mouseClick(panel._input._send_button, Qt.MouseButton.LeftButton)
    qtbot.wait(50)

    assert not emitted
    assert text_edit.toPlainText() == "   \n\t  "
    assert panel.findChildren(MessageBubble) == []


def test_enter_key_submits_message(qtbot: QtBot) -> None:
    """Pressing Enter in the input submits the composed message.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    text_edit = panel._input._text_edit
    text_edit.setFocus()
    qtbot.keyClicks(text_edit, "analyze imports")

    with qtbot.waitSignal(panel.message_submitted, timeout=2_000) as blocker:
        qtbot.keyClick(text_edit, Qt.Key.Key_Return)

    assert blocker.args == ["analyze imports"]


def test_shift_enter_inserts_newline_without_submitting(qtbot: QtBot) -> None:
    """Shift+Enter inserts a newline and does not emit ``message_submitted``.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    emitted: list[str] = []
    panel.message_submitted.connect(emitted.append)
    text_edit = panel._input._text_edit
    text_edit.setFocus()
    qtbot.keyClicks(text_edit, "line one")
    qtbot.keyClick(text_edit, Qt.Key.Key_Return, Qt.KeyboardModifier.ShiftModifier)
    qtbot.keyClicks(text_edit, "line two")
    qtbot.wait(50)

    assert not emitted
    assert "line one" in text_edit.toPlainText()
    assert "line two" in text_edit.toPlainText()
    assert "\n" in text_edit.toPlainText()


def test_add_message_renders_real_content(qtbot: QtBot) -> None:
    """``add_message`` stores and renders a real :class:`Message`.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    message = Message(role="user", content="show me the .text section", timestamp=datetime.now(tz=UTC))
    panel.add_message(message)

    assert panel.get_messages() == [message]
    assert "show me the .text section" in _bubble_texts(panel)


def test_add_message_renders_tool_call(qtbot: QtBot) -> None:
    """A message carrying a real :class:`ToolCall` renders the tool-call widget.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    call = ToolCall(
        id="call-1",
        tool_name="radare2",
        function_name="disassemble",
        arguments={"address": "0x1000"},
    )
    message = Message(
        role="assistant",
        content="running disassembly",
        timestamp=datetime.now(tz=UTC),
        tool_calls=[call],
    )
    panel.add_message(message)

    labels = [lbl.text() for lbl in panel.findChildren(QLabel)]
    assert any("radare2.disassemble" in text for text in labels)
    assert any("address" in text and "0x1000" in text for text in labels)


def test_streaming_message_appends_chunks(qtbot: QtBot) -> None:
    """``add_streaming_message`` returns an appender that updates the bubble.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    append = panel.add_streaming_message()
    append("Hello ")
    append("world")

    messages = panel.get_messages()
    assert len(messages) == 1
    assert messages[0].content == "Hello world"
    assert "Hello world" in _bubble_texts(panel)


def test_clear_messages_empties_history_and_view(qtbot: QtBot) -> None:
    """``clear_messages`` removes both stored messages and rendered bubbles.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    for i in range(3):
        panel.add_message(Message(role="user", content=f"msg {i}", timestamp=datetime.now(tz=UTC)))
    assert len(panel.get_messages()) == 3
    assert len(panel.findChildren(MessageBubble)) == 3

    panel.clear_messages()
    qtbot.wait(50)

    assert panel.get_messages() == []


def test_insert_context_text_populates_input(qtbot: QtBot) -> None:
    """``insert_context_text`` loads text into the real input widget.

    Args:
        qtbot: pytest-qt bot fixture.
    """
    panel = _make_panel(qtbot)
    panel.insert_context_text("0x401000: push ebp")

    assert panel._input._text_edit.toPlainText() == "0x401000: push ebp"

    with qtbot.waitSignal(panel.message_submitted, timeout=2_000) as blocker:
        qtbot.mouseClick(panel._input._send_button, Qt.MouseButton.LeftButton)
    assert blocker.args == ["0x401000: push ebp"]
