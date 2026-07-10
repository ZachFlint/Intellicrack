# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Regression gate for the 2026-07-02 GUI audit fix in ``chat.py``.

* ``test_m39_*`` (M39): truncated tool-call arguments and tool-result text
  must expose the full untruncated value via ``QToolTip`` so users can
  recover content that was cut off by the ``_MAX_ARGS_DISPLAY_LEN`` /
  ``_MAX_RESULT_DISPLAY_LEN`` character caps. Short (non-truncated) values
  must not carry a stray tooltip.

All tests build a real :class:`~intellicrack.ui.chat.MessageBubble` from a
real :class:`~intellicrack.core.types.Message` under an offscreen
``QApplication`` and inspect the actual child ``QLabel`` widgets it
constructs -- no mocks or stubs stand in for the widget-construction logic.
"""

from __future__ import annotations

from datetime import UTC, datetime

from PyQt6.QtWidgets import QLabel

from intellicrack.core.types import Message, ToolCall, ToolResult
from intellicrack.ui.chat import (
    _MAX_ARGS_DISPLAY_LEN,
    _MAX_RESULT_DISPLAY_LEN,
    MessageBubble,
)


def _find_label(bubble: MessageBubble, object_name: str) -> QLabel:
    """Locate a child ``QLabel`` of ``bubble`` by its Qt object name.

    Args:
        bubble: The message bubble to search.
        object_name: The ``objectName`` set on the target label.

    Returns:
        QLabel: The matching label.

    Raises:
        AssertionError: If no matching label is found.
    """
    for label in bubble.findChildren(QLabel):
        if label.objectName() == object_name:
            return label
    msg = f"no QLabel with objectName={object_name!r} found in bubble"
    raise AssertionError(msg)


def test_m39_truncated_tool_call_args_expose_full_text_via_tooltip(qapp: object) -> None:
    """Truncated tool-call argument text must carry the full value as a tooltip.

    Before the fix, ``args_text`` was overwritten in place by the truncation
    branch, so the only string available to the widget (and to
    ``setToolTip``, which was never called) was the already-clipped
    ellipsis-terminated string. This asserts the real ``QLabel`` built by
    ``MessageBubble`` displays the truncated text but exposes the complete,
    untruncated argument string through ``toolTip()``.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    long_path = "C:\\Users\\analyst\\Desktop\\samples\\" + ("payload_segment_" * 6) + "final.bin"
    call = ToolCall(
        id="call-1",
        tool_name="filesystem",
        function_name="read_file",
        arguments={"path": long_path},
    )
    message = Message(role="assistant", content="", tool_calls=[call])

    bubble = MessageBubble(message)

    full_args_text = f"path={long_path!r}"
    assert len(full_args_text) > _MAX_ARGS_DISPLAY_LEN

    args_label = _find_label(bubble, "tool_call_args")

    assert args_label.text() == f"{full_args_text[: _MAX_ARGS_DISPLAY_LEN - 3]}..."
    assert args_label.text() != full_args_text
    assert args_label.toolTip() == full_args_text


def test_m39_short_tool_call_args_have_no_stray_tooltip(qapp: object) -> None:
    """Short (non-truncated) tool-call arguments must not gain a tooltip.

    Guards against a naive fix that unconditionally calls ``setToolTip`` on
    every args label -- doing so would attach a redundant tooltip that just
    repeats visible text. The fix must only attach a tooltip when the
    displayed text differs from the full text.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    call = ToolCall(
        id="call-2",
        tool_name="calculator",
        function_name="add",
        arguments={"a": 1, "b": 2},
    )
    message = Message(role="assistant", content="", tool_calls=[call])

    bubble = MessageBubble(message)

    args_label = _find_label(bubble, "tool_call_args")

    assert len(args_label.text()) <= _MAX_ARGS_DISPLAY_LEN
    assert not args_label.toolTip()


def test_m39_truncated_tool_result_exposes_full_text_via_tooltip(qapp: object) -> None:
    """Truncated tool-result text must carry the full value as a tooltip.

    Before the fix, ``result_text`` was overwritten by the truncation
    branch, so the label held only the clipped string and no tooltip was
    ever attached, permanently hiding the rest of a long decompiled
    snippet or string list. This drives the real
    ``_create_tool_result_widget`` path via ``MessageBubble`` and asserts
    the rendered label's ``toolTip()`` recovers the complete result text.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    long_result = "\n".join(f"string_{i:04d}: possible license marker" for i in range(20))
    result = ToolResult(
        call_id="call-3",
        success=True,
        result=long_result,
        error=None,
        duration_ms=12.5,
    )
    message = Message(role="tool", content="", tool_results=[result])

    bubble = MessageBubble(message)

    full_result_text = str(long_result)
    assert len(full_result_text) > _MAX_RESULT_DISPLAY_LEN

    result_label = _find_label(bubble, "result_text")

    assert result_label.text() == f"{full_result_text[: _MAX_RESULT_DISPLAY_LEN - 3]}..."
    assert result_label.text() != full_result_text
    assert result_label.toolTip() == full_result_text


def test_m39_short_tool_result_has_no_stray_tooltip(qapp: object) -> None:
    """Short (non-truncated) tool-result text must not gain a tooltip.

    Guards against a naive fix that unconditionally calls ``setToolTip`` on
    every result label regardless of whether truncation actually occurred.

    Args:
        qapp: Session-scoped offscreen QApplication fixture.
    """
    _ = qapp
    result = ToolResult(
        call_id="call-4",
        success=True,
        result="ok",
        error=None,
        duration_ms=1.0,
    )
    message = Message(
        role="tool",
        content="",
        tool_results=[result],
        timestamp=datetime.now(tz=UTC),
    )

    bubble = MessageBubble(message)

    result_label = _find_label(bubble, "result_text")

    assert result_label.text() == "ok"
    assert not result_label.toolTip()
