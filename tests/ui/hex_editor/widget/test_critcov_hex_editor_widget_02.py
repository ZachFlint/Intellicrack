# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Coverage for the paste, mouse, wheel, selection, copy-as, context-menu and highlight paths of the hex editor widget.

Every test drives a real ``HexEditorWidget`` that displays a genuine ``intellicrack_hexcore.HexDocument``. Pasting is driven by the
Ctrl+V key event with real text on the application clipboard, selection by real mouse press, move and release events and wheel events
delivered to the viewport, and the context menu through a real context-menu event whose menu is inspected and triggered from inside the
menu's own event loop. Expected values come from byte arithmetic, the documented labels of each export format, hand-computed Base64
and the geometry of the widget's own font metrics, never from re-running the code under test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, NamedTuple

import intellicrack_hexcore
import pytest
from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt, QTimer
from PyQt6.QtGui import QAction, QClipboard, QContextMenuEvent, QMouseEvent, QWheelEvent
from PyQt6.QtWidgets import QApplication, QMenu, QScrollBar, QWidget

from intellicrack.ui.panels.async_bridge import drain_bridge_workers, drain_bridge_workers_for
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget
from tests.ui.conftest import SignalRecorder


if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pytestqt.qtbot import QtBot


pytestmark = pytest.mark.usefixtures("qapp")


_ROW: int = 16
_WIDTH: int = 800
_HEIGHT: int = 400
_BIG_LEN: int = 1595
_BIG: bytes = bytes(i % 251 for i in range(_BIG_LEN))
_SAMPLE16: bytes = bytes(range(16))
_SHORT: bytes = bytes(range(20))
_TEXT_DOC: bytes = bytes(range(0x30, 0x58))
_MENU_DOC: bytes = bytes([0x41, 0x7F, 0x80, 0xFF, 0x00, 0x42])
_FMT_DATA: bytes = bytes([0x41, 0x7F, 0x80, 0xFF])
_HEX8_STRIDE: int = 4
_CTRL: Qt.KeyboardModifier = Qt.KeyboardModifier.ControlModifier
_Dynamic = Any

_EXPECTED_FORMATS: dict[str, str] = {
    "hex": "41 7F 80 FF",
    "hex_string_no_spaces": "417F80FF",
    "c_array": "{0x41, 0x7F, 0x80, 0xFF}",
    "python": 'b"\\x41\\x7f\\x80\\xff"',
    "base64": "QX+A/w==",
    "rust_array": "[0x41_u8, 0x7F, 0x80, 0xFF]",
    "csharp_array": "new byte[] { 0x41, 0x7F, 0x80, 0xFF }",
    "java_array": "new byte[] { 0x41, 0x7F, (byte)0x80, (byte)0xFF }",
    "javascript_array": "new Uint8Array([0x41, 0x7F, 0x80, 0xFF])",
    "go_slice": "[]byte{0x41, 0x7F, 0x80, 0xFF}",
    "nasm_db": "db 0x41, 0x7F, 0x80, 0xFF",
    "markdown_table": "| Offset | Hex | ASCII |\n|--------|-----|-------|\n| 0x00000000 | 41 7F 80 FF | A... |",
}

_COPY_LABELS: list[tuple[str, str]] = [
    ("Hex (4D 5A 90)", "hex"),
    ("Hex no spaces (4D5A90)", "hex_string_no_spaces"),
    ("C array ({0x4D, 0x5A})", "c_array"),
    ('Python (b"\\x4d\\x5a")', "python"),
    ("Base64", "base64"),
    ("Rust array ([0x4D_u8, ...])", "rust_array"),
    ("C# array (new byte[] {...})", "csharp_array"),
    ("Java array (new byte[] {...})", "java_array"),
    ("JavaScript (new Uint8Array([...]))", "javascript_array"),
    ("Go slice ([]byte{...})", "go_slice"),
    ("NASM db (db 0x4D, 0x5A)", "nasm_db"),
    ("Markdown table", "markdown_table"),
]

_MODE_LABELS: list[tuple[str, str]] = [
    ("Hex 8-bit", "hex8"),
    ("Hex 16-bit LE", "hex16_le"),
    ("Hex 16-bit BE", "hex16_be"),
    ("Hex 32-bit LE", "hex32_le"),
    ("Hex 32-bit BE", "hex32_be"),
    ("Hex 64-bit LE", "hex64_le"),
    ("Hex 64-bit BE", "hex64_be"),
    ("Decimal u8", "dec_u8"),
    ("Decimal u16", "dec_u16"),
    ("Decimal u32", "dec_u32"),
    ("Decimal s8", "dec_s8"),
    ("Decimal s16", "dec_s16"),
    ("Decimal s32", "dec_s32"),
    ("Float 32-bit", "float32"),
    ("Float 64-bit", "float64"),
    ("RGBA color", "rgba8"),
    ("HexII", "hexii"),
    ("Binary", "binary"),
]


class _Rig(NamedTuple):
    """A hex editor widget together with the real document it displays.

    Attributes:
        widget: Shown widget with the document attached.
        document: Hexcore document attached to the widget.
    """

    widget: HexEditorWidget
    document: intellicrack_hexcore.HexDocument


def _priv(obj: object, name: str) -> _Dynamic:
    """Read a private attribute or method of a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.

    Returns:
        _Dynamic: The attribute value.
    """
    return getattr(obj, name)


def _set_priv(obj: object, name: str, value: object) -> None:
    """Assign a private data attribute on a product object.

    Args:
        obj: Object that owns the attribute.
        name: Attribute name.
        value: Value to store.
    """
    setattr(obj, name, value)


def _record(signal: _Dynamic) -> SignalRecorder:
    """Connect a recorder to a signal.

    Args:
        signal: Bound signal to observe.

    Returns:
        SignalRecorder: Recorder that stores every emission's arguments.
    """
    recorder = SignalRecorder()
    signal.connect(recorder)
    return recorder


def _viewport(widget: HexEditorWidget) -> QWidget:
    """Return the viewport widget that receives the mouse events of a scroll area.

    Args:
        widget: Scroll area whose viewport is wanted.

    Returns:
        QWidget: The viewport.
    """
    viewport = widget.viewport()
    assert viewport is not None
    return viewport


def _scrollbar(widget: HexEditorWidget) -> QScrollBar:
    """Return the vertical scroll bar of a widget.

    Args:
        widget: Widget that owns the scroll bar.

    Returns:
        QScrollBar: The vertical scroll bar.
    """
    bar = widget.verticalScrollBar()
    assert bar is not None
    return bar


def _row_y(widget: HexEditorWidget, row: int) -> int:
    """Compute a viewport y coordinate in the middle of a visible row.

    Args:
        widget: Widget whose line height defines the row geometry.
        row: Row index counted from the first visible row.

    Returns:
        int: Vertical pixel position inside that row.
    """
    line_height: int = _priv(widget, "_line_height")
    return row * line_height + line_height // 2


def _hex_x(widget: HexEditorWidget, group_index: int, stride: int) -> int:
    """Compute a viewport x coordinate inside one group cell of the hex column.

    Args:
        widget: Widget whose column geometry is used.
        group_index: Index of the group cell within the row.
        stride: Width of one group cell in characters, including the gap that follows it.

    Returns:
        int: Horizontal pixel position inside the cell.
    """
    char_width: int = _priv(widget, "_char_width")
    hex_col_x: int = _priv(widget, "_hex_col_x")
    return hex_col_x + group_index * stride * char_width + char_width


def _ascii_x(widget: HexEditorWidget, col: int) -> int:
    """Compute a viewport x coordinate inside one character cell of the ASCII column.

    Args:
        widget: Widget whose column geometry is used.
        col: Character column within the row.

    Returns:
        int: Horizontal pixel position inside the cell.
    """
    char_width: int = _priv(widget, "_char_width")
    ascii_col_x: int = _priv(widget, "_ascii_col_x")
    return ascii_col_x + col * char_width + char_width // 2


def _hex_xy(widget: HexEditorWidget, offset: int) -> tuple[int, int]:
    """Compute the viewport point of a byte in the hex column of the one-byte-per-group mode.

    Args:
        widget: Widget showing the first rows of its document.
        offset: Byte offset to locate.

    Returns:
        tuple[int, int]: Horizontal and vertical pixel position.
    """
    row, col = divmod(offset, _ROW)
    return (_hex_x(widget, col, _HEX8_STRIDE), _row_y(widget, row))


def _mouse(widget: HexEditorWidget, kind: QEvent.Type, x: int, y: int, *, shift: bool = False) -> None:
    """Deliver one real left-button mouse event to the viewport of a widget.

    Args:
        widget: Widget whose viewport receives the event.
        kind: Press, move or release event type.
        x: Horizontal position in viewport coordinates.
        y: Vertical position in viewport coordinates.
        shift: Whether the Shift modifier is held.
    """
    viewport = _viewport(widget)
    local = QPointF(x, y)
    global_pos = QPointF(viewport.mapToGlobal(QPoint(x, y)))
    modifier = Qt.KeyboardModifier.ShiftModifier if shift else Qt.KeyboardModifier.NoModifier
    if kind == QEvent.Type.MouseButtonPress:
        button = Qt.MouseButton.LeftButton
        buttons = Qt.MouseButton.LeftButton
    elif kind == QEvent.Type.MouseButtonRelease:
        button = Qt.MouseButton.LeftButton
        buttons = Qt.MouseButton.NoButton
    else:
        button = Qt.MouseButton.NoButton
        buttons = Qt.MouseButton.LeftButton
    _ = QApplication.sendEvent(viewport, QMouseEvent(kind, local, global_pos, button, buttons, modifier))


def _press_at(widget: HexEditorWidget, x: int, y: int, *, shift: bool = False) -> None:
    """Deliver a left-button press to the viewport.

    Args:
        widget: Widget whose viewport receives the press.
        x: Horizontal position in viewport coordinates.
        y: Vertical position in viewport coordinates.
        shift: Whether the Shift modifier is held.
    """
    _mouse(widget, QEvent.Type.MouseButtonPress, x, y, shift=shift)


def _move_to(widget: HexEditorWidget, x: int, y: int) -> None:
    """Deliver a mouse move with the left button held to the viewport.

    Args:
        widget: Widget whose viewport receives the move.
        x: Horizontal position in viewport coordinates.
        y: Vertical position in viewport coordinates.
    """
    _mouse(widget, QEvent.Type.MouseMove, x, y)


def _release_at(widget: HexEditorWidget, x: int, y: int) -> None:
    """Deliver a left-button release to the viewport.

    Args:
        widget: Widget whose viewport receives the release.
        x: Horizontal position in viewport coordinates.
        y: Vertical position in viewport coordinates.
    """
    _mouse(widget, QEvent.Type.MouseButtonRelease, x, y)


def _wheel(widget: HexEditorWidget, angle_delta_y: int) -> None:
    """Deliver one real wheel event to the viewport.

    Args:
        widget: Widget whose viewport receives the wheel event.
        angle_delta_y: Vertical wheel angle in eighths of a degree; negative scrolls down.
    """
    viewport = _viewport(widget)
    local = QPointF(10, 10)
    global_pos = QPointF(viewport.mapToGlobal(QPoint(10, 10)))
    inverted = False
    event = QWheelEvent(
        local,
        global_pos,
        QPoint(0, 0),
        QPoint(0, angle_delta_y),
        Qt.MouseButton.NoButton,
        Qt.KeyboardModifier.NoModifier,
        Qt.ScrollPhase.NoScrollPhase,
        inverted,
    )
    _ = QApplication.sendEvent(viewport, event)


def _press(
    qtbot: QtBot,
    widget: QWidget,
    key: Qt.Key | str,
    modifier: Qt.KeyboardModifier = Qt.KeyboardModifier.NoModifier,
) -> None:
    """Deliver one real key press and release to a widget.

    Args:
        qtbot: pytest-qt fixture that sends the event.
        widget: Widget that receives the key.
        key: Key to press, or a single character.
        modifier: Modifiers held while the key is pressed.
    """
    _priv(qtbot, "keyClick")(widget, key, modifier)


def _type(qtbot: QtBot, widget: QWidget, text: str) -> None:
    """Deliver a sequence of real character key events to a widget.

    Args:
        qtbot: pytest-qt fixture that sends the events.
        widget: Widget that receives the characters.
        text: Characters to type.
    """
    _priv(qtbot, "keyClicks")(widget, text)


def _find_action(menu: QMenu, text: str) -> QAction:
    """Find a menu entry by its caption.

    Args:
        menu: Menu to search.
        text: Caption of the wanted entry.

    Returns:
        QAction: The matching entry.

    Raises:
        LookupError: If no entry has that caption.
    """
    for action in menu.actions():
        if action.text() == text:
            return action
    msg = f"no menu entry captioned {text!r}"
    raise LookupError(msg)


def _submenu(menu: QMenu, title: str) -> QMenu:
    """Find the submenu behind a menu entry.

    Args:
        menu: Menu that holds the entry.
        title: Caption of the submenu entry.

    Returns:
        QMenu: The submenu.

    Raises:
        LookupError: If no submenu has that title.
    """
    for sub in menu.findChildren(QMenu, options=Qt.FindChildOption.FindDirectChildrenOnly):
        if sub.title() == title:
            return sub
    msg = f"no submenu titled {title!r}"
    raise LookupError(msg)


def _entries(menu: QMenu) -> list[tuple[str, bool, bool]]:
    """Describe every non-separator entry of a menu.

    Args:
        menu: Menu to describe.

    Returns:
        list[tuple[str, bool, bool]]: Caption, enabled state and checked state of each entry in order.
    """
    return [(action.text(), action.isEnabled(), action.isChecked()) for action in menu.actions() if not action.isSeparator()]


def _open_menu(widget: HexEditorWidget, drive: Callable[[QMenu], None]) -> None:
    """Open the widget's context menu and drive it from inside the menu's own event loop.

    ``contextMenuEvent`` ends in ``QMenu.exec``, which returns only once the menu closes. A zero-delay timer therefore runs ``drive`` on the
    menu the handler just built and always closes the menu afterwards; failures raised by ``drive`` are re-raised once the handler returns.

    Args:
        widget: Widget whose context menu is opened.
        drive: Callback that inspects or triggers entries of the open menu.

    Raises:
        ExceptionGroup: Every failure raised by ``drive``, after the menu has been closed.
    """
    failures: list[Exception] = []

    def _run() -> None:
        """Run the callback against the newest menu and close every menu afterwards."""
        menus = widget.findChildren(QMenu, options=Qt.FindChildOption.FindDirectChildrenOnly)
        try:
            drive(menus[-1])
        except (AssertionError, LookupError, RuntimeError, TypeError, ValueError) as exc:
            failures.append(exc)
        finally:
            for popup in menus:
                popup.close()

    QTimer.singleShot(0, _run)
    viewport = _viewport(widget)
    point = QPoint(5, 5)
    widget.contextMenuEvent(QContextMenuEvent(QContextMenuEvent.Reason.Mouse, point, viewport.mapToGlobal(point)))
    if failures:
        msg = "the context-menu callback failed"
        raise ExceptionGroup(msg, failures)


@pytest.fixture
def rig_factory(qtbot: QtBot) -> Generator[Callable[[bytes], _Rig]]:
    """Provide a factory of shown hex editor widgets whose background workers are joined on teardown.

    Args:
        qtbot: pytest-qt fixture that owns every widget the factory builds.

    Yields:
        Callable[[bytes], _Rig]: Factory that opens a document over given bytes and shows a widget on it.
    """
    created: list[HexEditorWidget] = []

    def _make(data: bytes) -> _Rig:
        """Build a shown widget over a document holding the given bytes.

        Args:
            data: Content of the document.

        Returns:
            _Rig: The widget and its document.
        """
        document = intellicrack_hexcore.HexDocument.open_bytes(data)
        widget = HexEditorWidget()
        qtbot.addWidget(widget)
        widget.resize(_WIDTH, _HEIGHT)
        widget.set_document(document)
        widget.show()
        qtbot.waitExposed(widget)
        widget.clearFocus()
        QApplication.processEvents()
        created.append(widget)
        return _Rig(widget, document)

    try:
        yield _make
    finally:
        for widget in created:
            drain_bridge_workers_for(widget)
        drain_bridge_workers()


@pytest.fixture
def rig(rig_factory: Callable[[bytes], _Rig]) -> _Rig:
    """Build a shown widget over the shared 1595-byte sample document.

    Args:
        rig_factory: Factory of shown widgets.

    Returns:
        _Rig: Widget and document over ``_BIG``.
    """
    return rig_factory(_BIG)


@pytest.fixture
def bare(qtbot: QtBot) -> Generator[HexEditorWidget]:
    """Provide a shown hex editor widget that has no document attached.

    Args:
        qtbot: pytest-qt fixture that owns the widget.

    Yields:
        HexEditorWidget: Widget without a document.
    """
    widget = HexEditorWidget()
    qtbot.addWidget(widget)
    widget.resize(_WIDTH, _HEIGHT)
    widget.show()
    qtbot.waitExposed(widget)
    widget.clearFocus()
    QApplication.processEvents()
    try:
        yield widget
    finally:
        drain_bridge_workers_for(widget)
        drain_bridge_workers()


@pytest.fixture
def clipboard() -> Generator[QClipboard]:
    """Provide the application clipboard, emptied before and after the test.

    Yields:
        QClipboard: The empty application clipboard.
    """
    board = QApplication.clipboard()
    assert board is not None
    board.clear()
    try:
        yield board
    finally:
        board.clear()


def test_paste_without_a_document_changes_nothing(bare: HexEditorWidget, clipboard: QClipboard) -> None:
    """Pasting into a widget that shows no document announces no edit and marks nothing.

    Args:
        bare: Shown widget without a document.
        clipboard: Application clipboard.
    """
    clipboard.setText("41 42")
    about = _record(bare.about_to_modify)
    changed = _record(bare.data_changed)
    moved = _record(bare.cursor_moved)
    _priv(bare, "_do_paste")()
    assert about.times_called == 0
    assert changed.times_called == 0
    assert moved.times_called == 0
    assert _priv(bare, "_modified_offsets") == set()


@pytest.mark.parametrize("text", ["", "   ", " \n  \n "], ids=["empty", "spaces", "spaces-and-newlines"])
def test_paste_of_blank_clipboard_text_changes_nothing(qtbot: QtBot, rig: _Rig, clipboard: QClipboard, text: str) -> None:
    """Ctrl+V with an empty or whitespace-only clipboard leaves the document and the edit signals untouched.

    Args:
        qtbot: pytest-qt fixture used to deliver the key.
        rig: Widget over the sample document.
        clipboard: Application clipboard.
        text: Clipboard text that holds no bytes.
    """
    clipboard.setText(text)
    about = _record(rig.widget.about_to_modify)
    changed = _record(rig.widget.data_changed)
    _press(qtbot, rig.widget, Qt.Key.Key_V, _CTRL)
    assert about.times_called == 0
    assert changed.times_called == 0
    assert rig.document.read(0, _BIG_LEN) == _BIG
    assert rig.document.can_undo() is False


@pytest.mark.parametrize("text", ["DE AD BE EF", "deadbeef", "DE AD\nBE EF"], ids=["spaced", "compact-lowercase", "newline-separated"])
def test_paste_of_hex_text_overwrites_the_bytes_at_the_cursor(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
    clipboard: QClipboard,
    text: str,
) -> None:
    """Hex text on the clipboard is decoded to bytes and written over the document at the cursor, which then moves past them.

    Args:
        qtbot: pytest-qt fixture used to deliver the keys.
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
        text: Clipboard text that spells the bytes DE AD BE EF.
    """
    rig = rig_factory(_SAMPLE16)
    widget = rig.widget
    clipboard.setText(text)
    widget.goto_offset(2)
    about = _record(widget.about_to_modify)
    changed = _record(widget.data_changed)
    moved = _record(widget.cursor_moved)
    _press(qtbot, widget, Qt.Key.Key_V, _CTRL)
    expected = bytearray(_SAMPLE16)
    expected[2:6] = b"\xde\xad\xbe\xef"
    assert rig.document.read(0, _ROW) == bytes(expected)
    assert rig.document.length() == _ROW
    assert _priv(widget, "_modified_offsets") == {2, 3, 4, 5}
    assert _priv(widget, "_marks_undo") == [set()]
    assert about.calls == [(2,), (3,), (4,), (5,)]
    assert changed.times_called == 1
    assert moved.calls == [(6,)]
    _press(qtbot, widget, Qt.Key.Key_Z, _CTRL)
    assert rig.document.read(0, _ROW) == _SAMPLE16
    assert _priv(widget, "_modified_offsets") == set()


@pytest.mark.parametrize(
    ("text", "expected_bytes"),
    [
        ("ABC", b"ABC"),
        ("xyz!", b"xyz!"),
        ("é", b"\xc3\xa9"),
        ("AB CD E", b"AB CD E"),
    ],
    ids=["odd-length-hex", "non-hex-text", "non-ascii-text", "odd-hex-with-spaces"],
)
def test_paste_of_non_hex_text_writes_its_utf8_encoding(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
    clipboard: QClipboard,
    text: str,
    expected_bytes: bytes,
) -> None:
    """Clipboard text that is not an even run of hex digits is pasted as its UTF-8 bytes.

    Args:
        qtbot: pytest-qt fixture used to deliver the key.
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
        text: Clipboard text.
        expected_bytes: Bytes the text encodes to in UTF-8, written out by hand.
    """
    rig = rig_factory(_SAMPLE16)
    widget = rig.widget
    clipboard.setText(text)
    moved = _record(widget.cursor_moved)
    _press(qtbot, widget, Qt.Key.Key_V, _CTRL)
    count = len(expected_bytes)
    expected = bytearray(_SAMPLE16)
    expected[:count] = expected_bytes
    assert rig.document.read(0, _ROW) == bytes(expected)
    assert _priv(widget, "_modified_offsets") == set(range(count))
    assert moved.calls == [(count,)]


def test_paste_in_insert_mode_inserts_bytes_and_shifts_later_marks(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
    clipboard: QClipboard,
) -> None:
    """With the Insert key toggled, a paste grows the document and moves modified marks that follow the insertion point.

    Args:
        qtbot: pytest-qt fixture used to deliver the keys.
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
    """
    rig = rig_factory(_SAMPLE16)
    widget = rig.widget
    _type(qtbot, widget, "ff")
    widget.goto_offset(9)
    _type(qtbot, widget, "ee")
    assert _priv(widget, "_modified_offsets") == {0, 9}
    mode_changes = _record(widget.edit_mode_changed)
    _press(qtbot, widget, Qt.Key.Key_Insert)
    assert mode_changes.calls == [("insert",)]
    widget.goto_offset(4)
    clipboard.setText("11 22 33")
    moved = _record(widget.cursor_moved)
    _press(qtbot, widget, Qt.Key.Key_V, _CTRL)
    expected = bytearray(_SAMPLE16)
    expected[0] = 0xFF
    expected[9] = 0xEE
    expected[4:4] = b"\x11\x22\x33"
    assert rig.document.length() == _ROW + 3
    assert rig.document.read(0, _ROW + 3) == bytes(expected)
    assert _priv(widget, "_modified_offsets") == {0, 4, 5, 6, 12}
    assert moved.calls == [(7,)]


def test_paste_in_insert_mode_past_the_end_keeps_the_document_intact(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
    clipboard: QClipboard,
) -> None:
    """An insertion the document rejects leaves its bytes and the modified marks untouched and clamps the cursor.

    Args:
        qtbot: pytest-qt fixture used to deliver the keys.
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
    """
    rig = rig_factory(_SAMPLE16)
    widget = rig.widget
    _press(qtbot, widget, Qt.Key.Key_Insert)
    _set_priv(widget, "_cursor_offset", 100)
    clipboard.setText("41")
    _press(qtbot, widget, Qt.Key.Key_V, _CTRL)
    assert rig.document.read(0, _ROW) == _SAMPLE16
    assert rig.document.length() == _ROW
    assert _priv(widget, "_modified_offsets") == set()
    assert _priv(widget, "_marks_undo") == []
    assert _priv(widget, "_cursor_offset") == _ROW - 1


def test_paste_over_an_empty_document_is_rejected_without_marks(rig_factory: Callable[[bytes], _Rig], clipboard: QClipboard) -> None:
    """Overwriting into a document with no bytes fails inside the document and records no modification.

    Args:
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
    """
    rig = rig_factory(b"")
    clipboard.setText("41")
    _priv(rig.widget, "_do_paste")()
    assert rig.document.length() == 0
    assert _priv(rig.widget, "_modified_offsets") == set()
    assert _priv(rig.widget, "_marks_undo") == []


def test_paste_overwrite_past_the_end_marks_only_bytes_that_exist(
    qtbot: QtBot,
    rig_factory: Callable[[bytes], _Rig],
    clipboard: QClipboard,
) -> None:
    """A paste that runs past the end writes only the bytes that fit, and only those bytes are marked as modified.

    Args:
        qtbot: pytest-qt fixture used to deliver the key.
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
    """
    rig = rig_factory(_SAMPLE16)
    widget = rig.widget
    widget.goto_offset(14)
    clipboard.setText("AA BB CC DD EE FF")
    _press(qtbot, widget, Qt.Key.Key_V, _CTRL)
    assert rig.document.length() == _ROW
    assert rig.document.read(14, 2) == b"\xaa\xbb"
    assert _priv(widget, "_modified_offsets") == {14, 15}


@pytest.mark.parametrize(
    ("mode", "stride", "group_size", "group_index"),
    [("hex8", 4, 1, 5), ("hex16_le", 6, 2, 3), ("hex32_le", 10, 4, 2), ("hex64_be", 18, 8, 1)],
    ids=["hex8", "hex16", "hex32", "hex64"],
)
def test_press_in_the_hex_column_selects_the_byte_of_the_group_cell(
    qtbot: QtBot,
    rig: _Rig,
    mode: str,
    stride: int,
    group_size: int,
    group_index: int,
) -> None:
    """A press inside a group cell of the hex column moves the cursor to the first byte of that group in the clicked row.

    Args:
        qtbot: pytest-qt fixture used to deliver the pending nibble.
        rig: Widget over the sample document.
        mode: Display mode that sets the cell width.
        stride: Width of one group cell in characters, including the gap after it.
        group_size: Bytes shown in one group cell.
        group_index: Group cell that is clicked.
    """
    widget = rig.widget
    widget.set_display_mode(mode)
    _type(qtbot, widget, "a")
    assert _priv(widget, "_nibble_index") == 1
    moved = _record(widget.cursor_moved)
    expected = 2 * _ROW + group_index * group_size
    _press_at(widget, _hex_x(widget, group_index, stride), _row_y(widget, 2))
    assert moved.calls == [(expected,)]
    assert _priv(widget, "_cursor_offset") == expected
    assert _priv(widget, "_selection_start") == expected
    assert _priv(widget, "_selection_end") == expected
    assert _priv(widget, "_selecting") is True
    assert _priv(widget, "_nibble_index") == 0
    assert _priv(widget, "_active_column") == "hex"


def test_press_in_the_ascii_column_selects_that_character_and_activates_the_column(rig: _Rig) -> None:
    """A press inside the ASCII column picks the byte under the character and makes the ASCII column the editing target.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    moved = _record(widget.cursor_moved)
    _press_at(widget, _ascii_x(widget, 9), _row_y(widget, 1))
    assert moved.calls == [(_ROW + 9,)]
    assert _priv(widget, "_cursor_offset") == _ROW + 9
    assert _priv(widget, "_active_column") == "ascii"


def test_press_outside_the_data_columns_is_ignored(rig: _Rig) -> None:
    """Presses in the offset margin, between the hex and ASCII columns, or right of the ASCII column do nothing.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    widget.goto_offset(7)
    moved = _record(widget.cursor_moved)
    hex_x: int = _priv(widget, "_hex_col_x")
    hex_w: int = _priv(widget, "_hex_col_width")
    ascii_x: int = _priv(widget, "_ascii_col_x")
    ascii_w: int = _priv(widget, "_ascii_col_width")
    offset_x: int = _priv(widget, "_offset_col_x")
    for x in (offset_x + 1, hex_x + hex_w + 1, ascii_x + ascii_w + 1):
        _press_at(widget, x, _row_y(widget, 1))
        _release_at(widget, x, _row_y(widget, 1))
    assert moved.times_called == 0
    assert _priv(widget, "_cursor_offset") == 7
    assert _priv(widget, "_selection_start") == -1
    assert _priv(widget, "_selecting") is False


@pytest.mark.parametrize(
    ("row", "col"),
    [(1, 10), (7, 3), (7, 15)],
    ids=["partial-last-row", "row-below-the-data", "far-corner-below-the-data"],
)
def test_press_past_the_last_byte_selects_the_last_byte(rig_factory: Callable[[bytes], _Rig], row: int, col: int) -> None:
    """A press on a cell beyond the end of the data lands on the last byte of the document.

    Args:
        rig_factory: Factory of shown widgets.
        row: Clicked row, counted from the top of the viewport.
        col: Clicked byte column within the row.
    """
    rig = rig_factory(_SHORT)
    widget = rig.widget
    moved = _record(widget.cursor_moved)
    _press_at(widget, _hex_x(widget, col, _HEX8_STRIDE), _row_y(widget, row))
    assert moved.calls == [(len(_SHORT) - 1,)]
    assert _priv(widget, "_cursor_offset") == len(_SHORT) - 1


def test_press_after_scrolling_counts_rows_from_the_first_visible_row(rig: _Rig) -> None:
    """With the view scrolled, the clicked row is added to the first visible row to find the offset.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    bar = _scrollbar(widget)
    bar.setValue(3)
    assert bar.value() == 3
    moved = _record(widget.cursor_moved)
    _press_at(widget, _hex_x(widget, 5, _HEX8_STRIDE), _row_y(widget, 0))
    assert moved.calls == [(3 * _ROW + 5,)]


def test_press_on_an_empty_document_is_ignored(rig_factory: Callable[[bytes], _Rig]) -> None:
    """A press in the data area of a document without bytes selects nothing.

    Args:
        rig_factory: Factory of shown widgets.
    """
    rig = rig_factory(b"")
    widget = rig.widget
    moved = _record(widget.cursor_moved)
    _press_at(widget, _hex_x(widget, 0, _HEX8_STRIDE), _row_y(widget, 0))
    assert moved.times_called == 0
    assert _priv(widget, "_selecting") is False
    assert _priv(widget, "_selection_start") == -1


def test_press_without_an_event_or_a_document_is_ignored(rig: _Rig, bare: HexEditorWidget) -> None:
    """The press handler returns quietly when it gets no event, and when no document is attached.

    Args:
        rig: Widget over the sample document.
        bare: Widget without a document.
    """
    moved = _record(rig.widget.cursor_moved)
    rig.widget.mousePressEvent(None)
    assert moved.times_called == 0
    assert _priv(rig.widget, "_selecting") is False
    bare_moved = _record(bare.cursor_moved)
    _press_at(bare, _hex_x(bare, 1, _HEX8_STRIDE), _row_y(bare, 0))
    assert bare_moved.times_called == 0
    assert _priv(bare, "_selecting") is False


def test_plain_click_starts_a_selection_that_the_release_discards(rig: _Rig) -> None:
    """A press starts a one-byte selection that is dropped again when the button is released without dragging.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    selection = _record(widget.selection_changed)
    x, y = _hex_xy(widget, 21)
    _press_at(widget, x, y)
    assert _priv(widget, "_selection_start") == 21
    assert _priv(widget, "_selection_end") == 21
    assert _priv(widget, "_selecting") is True
    _release_at(widget, x, y)
    assert _priv(widget, "_selecting") is False
    assert _priv(widget, "_selection_start") == -1
    assert _priv(widget, "_selection_end") == -1
    assert _priv(widget, "_cursor_offset") == 21
    assert selection.times_called == 0


def test_release_without_an_event_keeps_the_drag_state(rig: _Rig) -> None:
    """A release handler that receives no event does not end the drag that a press began.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    x, y = _hex_xy(widget, 4)
    _press_at(widget, x, y)
    widget.mouseReleaseEvent(None)
    assert _priv(widget, "_selecting") is True
    _release_at(widget, x, y)
    assert _priv(widget, "_selecting") is False


def test_release_without_any_selection_changes_nothing(rig: _Rig) -> None:
    """Releasing the button when nothing is selected leaves the selection empty.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    x, y = _hex_xy(widget, 4)
    _release_at(widget, x, y)
    assert _priv(widget, "_selection_start") == -1
    assert _priv(widget, "_selection_end") == -1
    assert _priv(widget, "_selecting") is False


@pytest.mark.parametrize(("press_offset", "move_offset"), [(2, 25), (25, 2)], ids=["forward", "backward"])
def test_drag_selects_the_range_and_reports_it_in_ascending_order(rig: _Rig, press_offset: int, move_offset: int) -> None:
    """Dragging from one byte to another selects every byte between them and reports the range low end first.

    Args:
        rig: Widget over the sample document.
        press_offset: Offset where the button goes down.
        move_offset: Offset the pointer is dragged to.
    """
    widget = rig.widget
    selection = _record(widget.selection_changed)
    moved = _record(widget.cursor_moved)
    px, py = _hex_xy(widget, press_offset)
    mx, my = _hex_xy(widget, move_offset)
    _press_at(widget, px, py)
    _move_to(widget, mx, my)
    assert selection.calls == [(2, 25)]
    assert moved.calls == [(press_offset,), (move_offset,)]
    assert _priv(widget, "_selection_start") == press_offset
    assert _priv(widget, "_selection_end") == move_offset
    assert _priv(widget, "_cursor_offset") == move_offset
    _release_at(widget, mx, my)
    assert _priv(widget, "_selection_start") == press_offset
    assert _priv(widget, "_selection_end") == move_offset
    assert widget.get_selection_bytes() == _BIG[2:26]


def test_move_without_a_press_is_ignored(rig: _Rig) -> None:
    """Pointer movement with no preceding press changes neither the selection nor the cursor.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    selection = _record(widget.selection_changed)
    moved = _record(widget.cursor_moved)
    x, y = _hex_xy(widget, 30)
    _move_to(widget, x, y)
    assert selection.times_called == 0
    assert moved.times_called == 0
    assert _priv(widget, "_selection_end") == -1
    assert _priv(widget, "_cursor_offset") == 0


def test_move_during_a_drag_ignores_events_and_gaps_that_hit_no_byte(rig: _Rig) -> None:
    """While dragging, a missing event or a pointer over the gap between columns leaves the selection where it was.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    x, y = _hex_xy(widget, 5)
    _press_at(widget, x, y)
    selection = _record(widget.selection_changed)
    widget.mouseMoveEvent(None)
    hex_x: int = _priv(widget, "_hex_col_x")
    hex_w: int = _priv(widget, "_hex_col_width")
    _move_to(widget, hex_x + hex_w + 1, y)
    assert selection.times_called == 0
    assert _priv(widget, "_selection_end") == 5
    assert _priv(widget, "_cursor_offset") == 5


def test_shift_click_extends_the_selection_from_the_cursor(rig: _Rig) -> None:
    """A Shift-press selects from the current cursor to the clicked byte, and a second one keeps the same anchor.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    widget.goto_offset(10)
    selection = _record(widget.selection_changed)
    moved = _record(widget.cursor_moved)
    x1, y1 = _hex_xy(widget, 19)
    _press_at(widget, x1, y1, shift=True)
    assert selection.calls == [(10, 19)]
    assert _priv(widget, "_selection_start") == 10
    assert _priv(widget, "_selection_end") == 19
    assert _priv(widget, "_cursor_offset") == 19
    assert moved.calls == [(19,)]
    _release_at(widget, x1, y1)
    assert _priv(widget, "_selection_start") == 10
    x2, y2 = _hex_xy(widget, 2)
    _press_at(widget, x2, y2, shift=True)
    assert selection.calls == [(10, 19), (2, 10)]
    assert _priv(widget, "_selection_start") == 10
    assert _priv(widget, "_selection_end") == 2
    assert widget.get_selection_bytes() == _BIG[2:11]


def test_wheel_scrolls_three_rows_per_notch_and_stops_at_the_top(rig: _Rig) -> None:
    """Each wheel notch moves the view three rows, downward for a negative angle and upward for a positive one.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    bar = _scrollbar(widget)
    assert bar.value() == 0
    assert bar.maximum() >= 6
    _wheel(widget, -120)
    assert bar.value() == 3
    _wheel(widget, -120)
    assert bar.value() == 6
    _wheel(widget, 120)
    assert bar.value() == 3
    _wheel(widget, 120)
    _wheel(widget, 120)
    assert bar.value() == 0


def test_wheel_handler_without_an_event_does_not_scroll(rig: _Rig) -> None:
    """A wheel handler that receives no event leaves the scroll position alone.

    Args:
        rig: Widget over the sample document.
    """
    bar = _scrollbar(rig.widget)
    bar.setValue(5)
    rig.widget.wheelEvent(None)
    assert bar.value() == 5


def test_set_selection_range_on_an_empty_document_clears_the_selection(rig_factory: Callable[[bytes], _Rig]) -> None:
    """With no bytes to select, a requested range is discarded and a cleared range is announced.

    Args:
        rig_factory: Factory of shown widgets.
    """
    rig = rig_factory(b"")
    widget = rig.widget
    _set_priv(widget, "_selection_start", 5)
    _set_priv(widget, "_selection_end", 7)
    selection = _record(widget.selection_changed)
    widget.set_selection_range(3, 9)
    assert selection.calls == [(-1, -1)]
    assert _priv(widget, "_selection_start") == -1
    assert _priv(widget, "_selection_end") == -1


def test_selection_bytes_are_empty_without_a_document_or_a_selection(bare: HexEditorWidget, rig: _Rig) -> None:
    """There are no selected bytes when no document is attached, nor when nothing is selected.

    Args:
        bare: Widget without a document.
        rig: Widget over the sample document.
    """
    assert bare.get_selection_bytes() == b""
    assert rig.widget.get_selection_bytes() == b""


@pytest.mark.parametrize(
    ("start", "end", "expected"),
    [(3, 7, _BIG[3:8]), (7, 3, _BIG[3:8]), (5, 5, _BIG[5:6]), (100, 200, _BIG[100:201])],
    ids=["ascending", "descending", "single-byte", "long-range"],
)
def test_selection_bytes_cover_both_ends_inclusively(rig: _Rig, start: int, end: int, expected: bytes) -> None:
    """The selected bytes run from the lower to the higher selection end, both included, whichever order they were set in.

    Args:
        rig: Widget over the sample document.
        start: First selection end.
        end: Second selection end.
        expected: Bytes of the document between the two ends, inclusive.
    """
    rig.widget.set_selection_range(start, end)
    assert rig.widget.get_selection_bytes() == expected


def test_copy_as_uses_the_selection_and_falls_back_to_the_cursor_byte(rig: _Rig) -> None:
    """Copy-as formats the selected bytes, or the single byte under the cursor when nothing is selected.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    widget.set_selection_range(4, 7)
    assert widget.copy_as("hex") == "04 05 06 07"
    widget.goto_offset(10)
    assert widget.get_selection_bytes() == b""
    assert widget.copy_as("hex") == "0A"
    assert widget.copy_as("c_array") == "{0x0A}"
    assert widget.copy_as() == "0A"


def test_copy_as_yields_nothing_without_data_to_copy(rig: _Rig, rig_factory: Callable[[bytes], _Rig], bare: HexEditorWidget) -> None:
    """Copy-as returns an empty string when there is no document, no bytes, or the cursor lies past the data.

    Args:
        rig: Widget over the sample document.
        rig_factory: Factory of shown widgets.
        bare: Widget without a document.
    """
    assert not bare.copy_as("hex")
    assert not rig_factory(b"").widget.copy_as("hex")
    _set_priv(rig.widget, "_cursor_offset", _BIG_LEN + 100)
    assert not rig.widget.copy_as("hex")


@pytest.mark.parametrize(("fmt", "expected"), list(_EXPECTED_FORMATS.items()), ids=list(_EXPECTED_FORMATS))
def test_copy_as_format_renders_each_export_format(rig: _Rig, fmt: str, expected: str) -> None:
    """Every export format renders the bytes 41 7F 80 FF exactly as its language or tool spells them.

    Args:
        rig: Widget over the sample document.
        fmt: Export format key.
        expected: Text the format must produce, written out by hand.
    """
    assert rig.widget.copy_as_format(fmt, _FMT_DATA) == expected


def test_copy_as_format_rejects_unknown_formats_and_empty_data(rig: _Rig) -> None:
    """An unknown format key, or empty data, produces no text.

    Args:
        rig: Widget over the sample document.
    """
    assert not rig.widget.copy_as_format("no_such_format", _FMT_DATA)
    assert not rig.widget.copy_as_format("hex", b"")


def test_copy_as_format_defaults_to_the_selection(rig: _Rig) -> None:
    """Without explicit data the export formats the current selection, and nothing when nothing is selected.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    assert not widget.copy_as_format("hex")
    widget.set_selection_range(1, 3)
    assert widget.copy_as_format("hex") == "01 02 03"
    assert widget.copy_as_format("base64") == "AQID"


def test_markdown_table_rows_hold_sixteen_bytes_and_start_at_the_selection(rig_factory: Callable[[bytes], _Rig]) -> None:
    """The Markdown export splits the selection into 16-byte rows labeled with absolute offsets and printable-ASCII text.

    Args:
        rig_factory: Factory of shown widgets.
    """
    rig = rig_factory(_TEXT_DOC)
    widget = rig.widget
    widget.set_selection_range(2, 21)
    expected = (
        "| Offset | Hex | ASCII |\n"
        "|--------|-----|-------|\n"
        "| 0x00000002 | 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F 40 41 | 23456789:;<=>?@A |\n"
        "| 0x00000012 | 42 43 44 45 | BCDE |"
    )
    assert widget.copy_as("markdown_table") == expected


def test_copy_as_action_puts_the_formatted_selection_on_the_clipboard(
    rig: _Rig,
    rig_factory: Callable[[bytes], _Rig],
    clipboard: QClipboard,
) -> None:
    """The copy-as action writes the formatted selection to the clipboard and leaves it alone when there is nothing to copy.

    Args:
        rig: Widget over the sample document.
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
    """
    rig.widget.set_selection_range(0, 2)
    _priv(rig.widget, "_copy_as_action")("base64")
    assert clipboard.text() == "AAEC"
    clipboard.setText("sentinel")
    _priv(rig_factory(b"").widget, "_copy_as_action")("base64")
    assert clipboard.text() == "sentinel"


def test_clear_highlights_removes_one_source_and_keeps_the_others(rig: _Rig) -> None:
    """Clearing a highlight source drops only its regions from the merged list, and an unknown source changes nothing.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    widget.highlight_offsets([(0, 4, "#ff0000")], "first")
    widget.highlight_offsets([(8, 2, "#00ff00")], "second")
    assert _priv(widget, "_highlights") == [(0, 4, "#ff0000"), (8, 2, "#00ff00")]
    widget.clear_highlights("first")
    assert _priv(widget, "_highlights") == [(8, 2, "#00ff00")]
    assert list(_priv(widget, "_highlight_sources")) == ["second"]
    widget.clear_highlights("never-registered")
    assert _priv(widget, "_highlights") == [(8, 2, "#00ff00")]


def test_context_menu_lists_the_copy_display_and_minimap_entries(rig_factory: Callable[[bytes], _Rig]) -> None:
    """The context menu offers Copy As, Display Mode and the minimap toggle, with the active display mode checked.

    Args:
        rig_factory: Factory of shown widgets.
    """
    widget = rig_factory(_MENU_DOC).widget
    seen: dict[str, list[tuple[str, bool, bool]]] = {}

    def _capture(menu: QMenu) -> None:
        """Record the entries of the menu and of its submenus.

        Args:
            menu: The open context menu.
        """
        seen["top"] = _entries(menu)
        seen["copy"] = _entries(_submenu(menu, "Copy As"))
        seen["display"] = _entries(_submenu(menu, "Display Mode"))

    _open_menu(widget, _capture)
    assert [text for text, _enabled, _checked in seen["top"]] == ["Copy As", "Display Mode", "Show Entropy Minimap"]
    assert seen["top"][2][2] is False
    assert seen["copy"] == [(label, True, False) for label, _key in _COPY_LABELS]
    assert seen["display"] == [(label, True, key == "hex8") for label, key in _MODE_LABELS]
    widget.set_display_mode("hex32_le")
    _open_menu(widget, _capture)
    assert seen["display"] == [(label, True, key == "hex32_le") for label, key in _MODE_LABELS]


def test_context_menu_copy_entries_copy_the_selection_in_their_format(rig_factory: Callable[[bytes], _Rig], clipboard: QClipboard) -> None:
    """Triggering each Copy As entry puts the selection on the clipboard in the format its caption names.

    Args:
        rig_factory: Factory of shown widgets.
        clipboard: Application clipboard.
    """
    widget = rig_factory(_MENU_DOC).widget
    widget.set_selection_range(0, 3)
    copied: dict[str, str] = {}

    def _trigger_all(menu: QMenu) -> None:
        """Trigger every Copy As entry and record what lands on the clipboard.

        Args:
            menu: The open context menu.
        """
        copy_menu = _submenu(menu, "Copy As")
        for label, key in _COPY_LABELS:
            clipboard.clear()
            _find_action(copy_menu, label).trigger()
            copied[key] = clipboard.text()

    _open_menu(widget, _trigger_all)
    assert copied == _EXPECTED_FORMATS


def test_context_menu_display_entries_switch_the_display_mode(rig: _Rig) -> None:
    """Triggering each Display Mode entry switches the hex view to the mode its caption names.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    widget.set_display_mode("binary")
    chosen: dict[str, str] = {}

    def _trigger_all(menu: QMenu) -> None:
        """Trigger every Display Mode entry and record the resulting mode.

        Args:
            menu: The open context menu.
        """
        display_menu = _submenu(menu, "Display Mode")
        for label, key in _MODE_LABELS:
            _find_action(display_menu, label).trigger()
            chosen[key] = _priv(widget, "_display_mode")

    _open_menu(widget, _trigger_all)
    assert chosen == {key: key for _label, key in _MODE_LABELS}


def test_context_menu_minimap_entry_toggles_the_minimap(rig: _Rig) -> None:
    """The minimap entry shows the entropy minimap when unchecked and hides it again when checked.

    Args:
        rig: Widget over the sample document.
    """
    widget = rig.widget
    minimap: QWidget = _priv(widget, "_minimap")
    assert minimap.isVisible() is False
    states: list[bool] = []

    def _toggle(menu: QMenu) -> None:
        """Record the checked state of the minimap entry and trigger it.

        Args:
            menu: The open context menu.
        """
        action = _find_action(menu, "Show Entropy Minimap")
        states.append(action.isChecked())
        action.trigger()

    _open_menu(widget, _toggle)
    assert minimap.isVisible() is True
    _open_menu(widget, _toggle)
    assert minimap.isVisible() is False
    assert states == [False, True]


def test_context_menu_without_a_document_has_no_copy_entries(bare: HexEditorWidget) -> None:
    """With no document attached the Copy As submenu is empty while the display modes are still offered.

    Args:
        bare: Widget without a document.
    """
    seen: dict[str, int] = {}

    def _count(menu: QMenu) -> None:
        """Record how many entries each submenu holds.

        Args:
            menu: The open context menu.
        """
        seen["copy"] = len(_submenu(menu, "Copy As").actions())
        seen["display"] = len(_submenu(menu, "Display Mode").actions())

    _open_menu(bare, _count)
    assert seen == {"copy": 0, "display": len(_MODE_LABELS)}


def test_context_menu_event_without_an_event_builds_no_menu(bare: HexEditorWidget) -> None:
    """A context-menu handler that receives no event creates no menu.

    Args:
        bare: Widget without a document.
    """
    bare.contextMenuEvent(None)
    assert bare.findChildren(QMenu, options=Qt.FindChildOption.FindDirectChildrenOnly) == []
