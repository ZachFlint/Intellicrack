# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-Qt coverage for three zero-coverage UI modules.

Covers (section 15): StackFrame / StackFrameTable / StackViewerPanel - full
structural and text-content assertions against known stack-frame inputs drive
the real offscreen widget.

Covers (section 14): Five syntax highlighters - exact QTextLayout format-range
colour and bold/italic assertions for single-line constructs, plus multi-line
block-state propagation (C/JS/HexPat ``/* */`` comments, Python triple-quote
strings) checked via ``QTextBlock.userState()``.

Covers (section 14): ``_screen_compat`` bootstrap helpers - exact return-type
structure from ``get_screen_geometry``, exact widget position after
``move_widget``, and exact ``AttributeError`` contract from ``_resolve``.

Every assertion names the production mutation it would catch.
"""

from __future__ import annotations

import pytest
from PyQt6.QtGui import QFont, QTextDocument
from PyQt6.QtWidgets import QApplication, QComboBox, QTableWidget, QWidget

from intellicrack.ui import _screen_compat
from intellicrack.ui.highlighter import (
    AssemblySyntaxHighlighter,
    CSyntaxHighlighter,
    HexPatSyntaxHighlighter,
    JavaScriptSyntaxHighlighter,
    PythonSyntaxHighlighter,
    get_highlighter_for_language,
)
from intellicrack.ui.panels.stack_viewer import (
    StackFrame,
    StackFrameTable,
    StackViewerPanel,
)


_KEYWORD_COLOR: str = "#569CD6"
_TYPE_COLOR: str = "#4EC9B0"
_STRING_COLOR: str = "#CE9178"
_NUMBER_COLOR: str = "#B5CEA8"
_COMMENT_COLOR: str = "#6A9955"
_REGISTER_COLOR: str = "#9CDCFE"
_ANNOTATION_COLOR: str = "#D7BA7D"

_BOLD = QFont.Weight.Bold

_BLOCK_STATE_NORMAL: int = 0
_BLOCK_STATE_IN_MULTILINE: int = 1
_BLOCK_STATE_TRIPLE_DOUBLE: int = 1
_BLOCK_STATE_TRIPLE_SINGLE: int = 2


def _color_at(doc: QTextDocument, block_num: int, char_pos: int) -> str | None:
    """Return the last-applied foreground color at a character position after syntax highlighting.

    Inspects ``QTextLayout.formats()`` which stores the format ranges applied
    by ``QSyntaxHighlighter.setFormat``.  Returns the uppercase hex string for
    the last range covering ``char_pos``, or ``None`` if no highlight covers it.

    Args:
        doc: The QTextDocument whose highlighted layout is inspected.
        block_num: Zero-based block (line) index within the document.
        char_pos: Zero-based character index within that block.

    Returns:
        str | None: Uppercase hex color such as ``'#569CD6'``, or None.
    """
    block = doc.findBlockByNumber(block_num)
    if not block.isValid():
        return None
    layout = block.layout()
    if layout is None:
        return None
    result: str | None = None
    for fmt_range in layout.formats():
        if fmt_range.start <= char_pos < fmt_range.start + fmt_range.length:
            color = fmt_range.format.foreground().color()
            if color.isValid():
                result = color.name().upper()
    return result


def _is_bold_at(doc: QTextDocument, block_num: int, char_pos: int) -> bool:
    """Return whether any syntax-highlight format at a character position is bold.

    Args:
        doc: The QTextDocument to inspect.
        block_num: Zero-based block index.
        char_pos: Zero-based character index within the block.

    Returns:
        bool: True if a bold format range covers char_pos.
    """
    block = doc.findBlockByNumber(block_num)
    if not block.isValid():
        return False
    layout = block.layout()
    if layout is None:
        return False
    for fmt_range in layout.formats():
        if fmt_range.start <= char_pos < fmt_range.start + fmt_range.length and fmt_range.format.fontWeight() == _BOLD:
            return True
    return False


def _is_italic_at(doc: QTextDocument, block_num: int, char_pos: int) -> bool:
    """Return whether any syntax-highlight format at a character position is italic.

    Args:
        doc: The QTextDocument to inspect.
        block_num: Zero-based block index.
        char_pos: Zero-based character index within the block.

    Returns:
        bool: True if an italic format range covers char_pos.
    """
    block = doc.findBlockByNumber(block_num)
    if not block.isValid():
        return False
    layout = block.layout()
    if layout is None:
        return False
    for fmt_range in layout.formats():
        if fmt_range.start <= char_pos < fmt_range.start + fmt_range.length and fmt_range.format.fontItalic():
            return True
    return False


def _block_user_state(doc: QTextDocument, block_num: int) -> int:
    """Return the user state set by a QSyntaxHighlighter on a text block.

    ``QSyntaxHighlighter.setCurrentBlockState(state)`` stores the value in
    ``block.userState()``.  This helper exposes that value for block-state
    continuity assertions (multi-line comment / triple-quote propagation).

    Args:
        doc: The QTextDocument to inspect.
        block_num: Zero-based block index.

    Returns:
        int: The block user state, or -1 if the block is invalid.
    """
    block = doc.findBlockByNumber(block_num)
    if not block.isValid():
        return -1
    return block.userState()


@pytest.mark.usefixtures("qapp")
class TestStackFrameTable:
    """Gate tests for StackFrameTable: exact structural and text-content assertions."""

    @staticmethod
    def test_column_count_is_seven() -> None:
        """StackFrameTable must have exactly 7 columns.

        Mutation caught: changing ``setColumnCount(7)`` to any other value.
        """
        table = StackFrameTable()
        assert table.columnCount() == 7, f"Expected 7 columns, got {table.columnCount()}"

    @staticmethod
    def test_column_headers_exact() -> None:
        """Column headers must match the exact documented labels in order.

        Mutation caught: renaming or reordering any header label.
        """
        table = StackFrameTable()
        header = table.horizontalHeader()
        assert header is not None
        expected = ["#", "Return Address", "Function", "Module", "Offset", "FP", "SP"]
        actual = [table.horizontalHeaderItem(i).text() if table.horizontalHeaderItem(i) else "" for i in range(7)]
        assert actual == expected, f"Header mismatch.\n  expected: {expected}\n  actual:   {actual}"

    @staticmethod
    def test_row_count_matches_input_length() -> None:
        """Row count must equal the number of frames fed to set_frames.

        Mutation caught: passing a wrong length to setRowCount.
        """
        table = StackFrameTable()
        frames = [
            StackFrame(index=0, return_address=0x1000, function_name="main", module_name="app.exe"),
            StackFrame(index=1, return_address=0x2000, function_name="sub", module_name="lib.dll"),
        ]
        table.set_frames(frames)
        assert table.rowCount() == 2, f"Expected rowCount 2, got {table.rowCount()}"

    @staticmethod
    def test_index_column_text_is_str_of_index() -> None:
        """Column 0 must hold str(frame.index) for each row.

        Mutation caught: formatting index differently (e.g. adding padding).
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="f", module_name="m")]
        table.set_frames(frames)
        item = table.item(0, 0)
        assert item is not None
        assert item.text() == "0", f"Expected index text '0', got {item.text()!r}"

    @staticmethod
    def test_address_column_is_zero_padded_16_digit_hex() -> None:
        """Column 1 (Return Address) must use the exact format ``0x{:016X}``.

        Oracle: address 0x12AB → ``"0x00000000000012AB"`` (16 uppercase hex digits
        zero-padded, ``0x`` prefix, total 18 chars).

        Mutation caught: changing ``:016X`` to ``:08X`` or removing zero-padding.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0x12AB, function_name="f", module_name="m")]
        table.set_frames(frames)
        item = table.item(0, 1)
        assert item is not None
        expected = "0x00000000000012AB"
        assert item.text() == expected, f"Address format mismatch.\n  expected: {expected!r}\n  actual:   {item.text()!r}"

    @staticmethod
    def test_function_name_column_text() -> None:
        """Column 2 (Function) must contain exactly frame.function_name.

        Mutation caught: replacing function_name with a different attribute.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="NtOpenFile", module_name="m")]
        table.set_frames(frames)
        item = table.item(0, 2)
        assert item is not None
        assert item.text() == "NtOpenFile", f"Function name mismatch: {item.text()!r}"

    @staticmethod
    def test_module_name_column_text() -> None:
        """Column 3 (Module) must contain exactly frame.module_name.

        Mutation caught: using function_name instead of module_name.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="f", module_name="ntdll.dll")]
        table.set_frames(frames)
        item = table.item(0, 3)
        assert item is not None
        assert item.text() == "ntdll.dll", f"Module name mismatch: {item.text()!r}"

    @staticmethod
    def test_offset_nonzero_uses_plus_prefix() -> None:
        """Column 4 (Offset) with a positive offset must produce ``+0x{offset:X}``.

        Oracle: offset 16 (0x10) → ``"+0x10"``.

        Mutation caught: removing the ``+`` prefix or changing the hex format.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="f", module_name="m", offset=0x10)]
        table.set_frames(frames)
        item = table.item(0, 4)
        assert item is not None
        assert item.text() == "+0x10", f"Offset text mismatch: {item.text()!r}"

    @staticmethod
    def test_offset_zero_is_empty_string() -> None:
        """Column 4 (Offset) with offset == 0 must be an empty string.

        Mutation caught: formatting zero offset as ``+0x0`` instead of ``""``.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="f", module_name="m", offset=0)]
        table.set_frames(frames)
        item = table.item(0, 4)
        assert item is not None
        assert not item.text(), f"Expected empty offset for zero, got {item.text()!r}"

    @staticmethod
    def test_frame_pointer_nonzero_format() -> None:
        """Column 5 (FP) with a nonzero frame pointer must use ``0x{:016X}``.

        Oracle: fp=0x1000 → ``"0x0000000000001000"`` (16-digit zero-padded).

        Mutation caught: changing the format string to fewer digits.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="f", module_name="m", frame_pointer=0x1000)]
        table.set_frames(frames)
        item = table.item(0, 5)
        assert item is not None
        assert item.text() == "0x0000000000001000", f"FP text mismatch: {item.text()!r}"

    @staticmethod
    def test_stack_pointer_zero_is_empty_string() -> None:
        """Column 6 (SP) with stack_pointer == 0 must be empty string.

        Mutation caught: formatting zero SP as ``"0x0000000000000000"`` instead of ``""``.
        """
        table = StackFrameTable()
        frames = [StackFrame(index=0, return_address=0, function_name="f", module_name="m", stack_pointer=0)]
        table.set_frames(frames)
        item = table.item(0, 6)
        assert item is not None
        assert not item.text(), f"Expected empty SP for zero, got {item.text()!r}"


@pytest.mark.usefixtures("qapp")
class TestStackViewerPanel:
    """Gate tests for StackViewerPanel: construction state and public-API contracts."""

    @staticmethod
    def test_source_combo_has_x64dbg_and_frida() -> None:
        """The source combo must contain exactly 'x64dbg' and 'Frida' after construction.

        Mutation caught: renaming a default source key or adding/removing sources.
        """
        panel = StackViewerPanel()
        combo = panel.findChild(QComboBox)
        assert combo is not None, "Could not find QComboBox child of StackViewerPanel"
        texts = [combo.itemText(i) for i in range(combo.count())]
        assert "x64dbg" in texts, f"'x64dbg' missing from source combo items: {texts}"
        assert "Frida" in texts, f"'Frida' missing from source combo items: {texts}"
        assert len(texts) == 2, f"Expected 2 source items, got {len(texts)}: {texts}"

    @staticmethod
    def test_status_label_not_connected_initially() -> None:
        """status_label must read 'Not connected' when no bridge is attached.

        Mutation caught: changing the default status text or initializing in
        connected state.
        """
        panel = StackViewerPanel()
        assert panel.status_label.text() == "Not connected", (
            f"Expected 'Not connected', got {panel.status_label.text()!r}"
        )

    @staticmethod
    def test_frame_table_initially_empty() -> None:
        """The frame table must have zero rows after construction (no bridge data).

        Mutation caught: pre-populating the table with placeholder rows.
        """
        panel = StackViewerPanel()
        table = panel.findChild(QTableWidget)
        assert table is not None
        assert table.rowCount() == 0, f"Expected 0 rows initially, got {table.rowCount()}"

    @staticmethod
    def test_clear_empties_frame_table() -> None:
        """clear() must set rowCount to 0 even if set_frames had populated the table.

        Mutation caught: removing the ``setRowCount(0)`` call from clear().
        """
        panel = StackViewerPanel()
        frame_table = panel.findChild(StackFrameTable)
        assert frame_table is not None
        frames = [StackFrame(index=0, return_address=0x1, function_name="f", module_name="m")]
        frame_table.set_frames(frames)
        assert frame_table.rowCount() == 1, "Pre-condition: expected 1 row before clear"

        panel.clear()
        assert frame_table.rowCount() == 0, (
            f"Expected 0 rows after clear(), got {frame_table.rowCount()}"
        )


@pytest.mark.usefixtures("qapp")
class TestCSyntaxHighlighter:
    """Gate tests for CSyntaxHighlighter: keyword, number, and block-comment state."""

    @staticmethod
    def test_keyword_int_has_keyword_color() -> None:
        """The keyword 'int' at position 0 must receive the keyword foreground color.

        Oracle: _KEYWORD_COLOR = '#569CD6' (hardcoded in _create_format call).

        Mutation caught: removing 'int' from KEYWORDS or changing the keyword color.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("int x = 0;")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _KEYWORD_COLOR, (
            f"Expected keyword color {_KEYWORD_COLOR!r} at 'int'[0], got {color!r}"
        )

    @staticmethod
    def test_keyword_is_bold() -> None:
        """The keyword 'int' must be rendered bold.

        Mutation caught: removing ``bold=True`` from the keyword format creation.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("int x;")
        hl.rehighlight()
        assert _is_bold_at(doc, 0, 0), "Expected bold weight at 'int'[0] but was not bold"

    @staticmethod
    def test_hex_number_has_number_color() -> None:
        """A hex literal '0x1A' must receive the number foreground color.

        Oracle: _NUMBER_COLOR = '#B5CEA8'.

        Mutation caught: removing the hex-number rule from _setup_rules.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("0x1A")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _NUMBER_COLOR, (
            f"Expected number color {_NUMBER_COLOR!r} at '0x1A'[0], got {color!r}"
        )

    @staticmethod
    def test_single_line_comment_is_italic() -> None:
        """A single-line '//' comment must be rendered italic.

        Mutation caught: removing ``italic=True`` from the comment format creation.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("// comment text")
        hl.rehighlight()
        assert _is_italic_at(doc, 0, 0), "Expected italic at '//'[0] but was not italic"

    @staticmethod
    def test_multiline_comment_open_sets_block_state_1() -> None:
        """An unclosed '/*' comment must leave block userState == 1.

        Oracle: state 1 == in-comment, matching the ``setCurrentBlockState(1)`` call
        when no closing '*/' is found.

        Mutation caught: removing ``setCurrentBlockState(1)`` from the unclosed-comment
        branch of highlightBlock.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("code /* open comment")
        hl.rehighlight()
        state = _block_user_state(doc, 0)
        assert state == _BLOCK_STATE_IN_MULTILINE, (
            f"Expected block state 1 (in-comment) after unclosed /*, got {state}"
        )

    @staticmethod
    def test_multiline_comment_continues_across_lines() -> None:
        """The continuation line of a '/* ... */' comment must be fully highlighted.

        When previousBlockState == 1, the ENTIRE second line must receive comment color.

        Mutation caught: changing ``previousBlockState() != 1`` condition so the
        continuation branch is skipped.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("x /* start\nmiddle\nend */ y")
        hl.rehighlight()
        middle_color = _color_at(doc, 1, 0)
        assert middle_color == _COMMENT_COLOR, (
            f"Expected comment color {_COMMENT_COLOR!r} at middle-line[0], got {middle_color!r}"
        )

    @staticmethod
    def test_multiline_comment_state_resets_after_close() -> None:
        """A line containing '*/' must leave block userState == 0.

        Oracle: state 0 == normal, set by ``setCurrentBlockState(0)`` when '*/' is found.

        Mutation caught: removing the ``setCurrentBlockState(0)`` call in the
        found-end-comment branch of highlightBlock.
        """
        doc = QTextDocument()
        hl = CSyntaxHighlighter(doc)
        doc.setPlainText("code /* open\nmiddle\nend */ back")
        hl.rehighlight()
        state = _block_user_state(doc, 2)
        assert state == _BLOCK_STATE_NORMAL, (
            f"Expected block state 0 (normal) after '*/' close, got {state}"
        )


@pytest.mark.usefixtures("qapp")
class TestAssemblySyntaxHighlighter:
    """Gate tests for AssemblySyntaxHighlighter: instruction, register, and comment."""

    @staticmethod
    def test_instruction_mnemonic_has_instruction_color() -> None:
        """The mnemonic 'mov' must receive the instruction foreground color.

        Oracle: _KEYWORD_COLOR = '#569CD6' (shared with keyword color).

        Mutation caught: removing 'mov' from INSTRUCTIONS.
        """
        doc = QTextDocument()
        hl = AssemblySyntaxHighlighter(doc)
        doc.setPlainText("mov rax, 0")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _KEYWORD_COLOR, (
            f"Expected instruction color {_KEYWORD_COLOR!r} at 'mov'[0], got {color!r}"
        )

    @staticmethod
    def test_instruction_is_bold() -> None:
        """Assembly instructions must be bold.

        Mutation caught: removing ``bold=True`` from the instruction format creation.
        """
        doc = QTextDocument()
        hl = AssemblySyntaxHighlighter(doc)
        doc.setPlainText("mov rax, 0")
        hl.rehighlight()
        assert _is_bold_at(doc, 0, 0), "Expected bold weight at 'mov'[0]"

    @staticmethod
    def test_register_has_register_color() -> None:
        """The register 'rax' must receive the register foreground color.

        Oracle: _REGISTER_COLOR = '#9CDCFE'.

        Mutation caught: removing 'rax' from REGISTERS or changing register color.
        """
        doc = QTextDocument()
        hl = AssemblySyntaxHighlighter(doc)
        doc.setPlainText("mov rax, 0")
        hl.rehighlight()
        color = _color_at(doc, 0, 4)
        assert color == _REGISTER_COLOR, (
            f"Expected register color {_REGISTER_COLOR!r} at 'rax'[0] (pos 4), got {color!r}"
        )

    @staticmethod
    def test_semicolon_comment_is_italic() -> None:
        """A ';' comment must be rendered italic.

        Mutation caught: removing ``italic=True`` from the assembly comment format.
        """
        doc = QTextDocument()
        hl = AssemblySyntaxHighlighter(doc)
        doc.setPlainText("nop ; no operation")
        hl.rehighlight()
        assert _is_italic_at(doc, 0, 4), "Expected italic at ';'[0] (pos 4)"


@pytest.mark.usefixtures("qapp")
class TestPythonSyntaxHighlighter:
    """Gate tests for PythonSyntaxHighlighter: keyword, builtin, triple-quote state."""

    @staticmethod
    def test_keyword_def_has_keyword_color() -> None:
        """The keyword 'def' must receive the keyword foreground color.

        Mutation caught: removing 'def' from KEYWORDS.
        """
        doc = QTextDocument()
        hl = PythonSyntaxHighlighter(doc)
        doc.setPlainText("def foo():")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _KEYWORD_COLOR, (
            f"Expected keyword color {_KEYWORD_COLOR!r} at 'def'[0], got {color!r}"
        )

    @staticmethod
    def test_builtin_len_has_type_color() -> None:
        """The builtin 'len' must receive the builtin foreground color.

        Oracle: _TYPE_COLOR = '#4EC9B0' (shared builtin/type color in Python highlighter).

        Mutation caught: removing 'len' from BUILTINS.
        """
        doc = QTextDocument()
        hl = PythonSyntaxHighlighter(doc)
        doc.setPlainText("n = len(x)")
        hl.rehighlight()
        color = _color_at(doc, 0, 4)
        assert color == _TYPE_COLOR, (
            f"Expected builtin color {_TYPE_COLOR!r} at 'len'[0] (pos 4), got {color!r}"
        )

    @staticmethod
    def test_triple_double_quote_sets_block_state() -> None:
        """An unclosed triple-double-quoted string must set block userState == 1.

        Oracle: _BLOCK_STATE_TRIPLE_DOUBLE == 1 == _DELIM_STATE_MAP[0].

        Mutation caught: removing the state assignment in _highlight_triple_quotes
        when the end delimiter is not found on the opening line.
        """
        doc = QTextDocument()
        hl = PythonSyntaxHighlighter(doc)
        doc.setPlainText('x = """open string')
        hl.rehighlight()
        state = _block_user_state(doc, 0)
        assert state == _BLOCK_STATE_TRIPLE_DOUBLE, (
            f'Expected block state {_BLOCK_STATE_TRIPLE_DOUBLE} after unclosed """, got {state}'
        )

    @staticmethod
    def test_triple_quote_continuation_receives_string_color() -> None:
        """The continuation line of a triple-quoted string must receive string color.

        When previousBlockState == 1 (inside triple-double-quote), the entire
        continuation line must be formatted with the string color.

        Mutation caught: removing the ``prev_state == _BLOCK_STATE_DOUBLE_QUOTE``
        branch in _highlight_triple_quotes.
        """
        doc = QTextDocument()
        hl = PythonSyntaxHighlighter(doc)
        doc.setPlainText('x = """open\nmiddle\nend"""')
        hl.rehighlight()
        color = _color_at(doc, 1, 0)
        assert color == _STRING_COLOR, (
            f"Expected string color {_STRING_COLOR!r} at middle-line[0], got {color!r}"
        )

    @staticmethod
    def test_triple_quote_state_resets_after_close() -> None:
        """The closing line of a triple-quoted string must leave block state == 0.

        Mutation caught: not calling ``setCurrentBlockState(_BLOCK_STATE_NORMAL)``
        after finding the closing delimiter.
        """
        doc = QTextDocument()
        hl = PythonSyntaxHighlighter(doc)
        doc.setPlainText('x = """open\nmiddle\nend""" extra')
        hl.rehighlight()
        state = _block_user_state(doc, 2)
        assert state == _BLOCK_STATE_NORMAL, (
            f'Expected block state {_BLOCK_STATE_NORMAL} after closing """, got {state}'
        )

    @staticmethod
    def test_triple_single_quote_sets_block_state_2() -> None:
        """An unclosed triple-single-quoted string must set block userState == 2.

        Oracle: _BLOCK_STATE_TRIPLE_SINGLE == 2 == _DELIM_STATE_MAP[1].

        Mutation caught: swapping _DELIM_STATE_MAP entries or wrong state for '''.
        """
        doc = QTextDocument()
        hl = PythonSyntaxHighlighter(doc)
        doc.setPlainText("x = '''open string")
        hl.rehighlight()
        state = _block_user_state(doc, 0)
        assert state == _BLOCK_STATE_TRIPLE_SINGLE, (
            f"Expected block state {_BLOCK_STATE_TRIPLE_SINGLE} after unclosed ''', got {state}"
        )


@pytest.mark.usefixtures("qapp")
class TestHexPatSyntaxHighlighter:
    """Gate tests for HexPatSyntaxHighlighter: keyword, type, and block-comment state."""

    @staticmethod
    def test_keyword_struct_has_keyword_color() -> None:
        """The keyword 'struct' must receive the keyword foreground color.

        Mutation caught: removing 'struct' from HexPatSyntaxHighlighter.KEYWORDS.
        """
        doc = QTextDocument()
        hl = HexPatSyntaxHighlighter(doc)
        doc.setPlainText("struct MyStruct {")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _KEYWORD_COLOR, (
            f"Expected keyword color {_KEYWORD_COLOR!r} at 'struct'[0], got {color!r}"
        )

    @staticmethod
    def test_type_u8_has_type_color() -> None:
        """The primitive type 'u8' must receive the type foreground color.

        Oracle: _TYPE_COLOR = '#4EC9B0'.

        Mutation caught: removing 'u8' from HexPatSyntaxHighlighter.TYPES.
        """
        doc = QTextDocument()
        hl = HexPatSyntaxHighlighter(doc)
        doc.setPlainText("u8 field;")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _TYPE_COLOR, (
            f"Expected type color {_TYPE_COLOR!r} at 'u8'[0], got {color!r}"
        )

    @staticmethod
    def test_multiline_comment_sets_block_state_1() -> None:
        """An unclosed HexPat '/*' comment must leave block userState == 1.

        Mutation caught: removing ``setCurrentBlockState(1)`` from the unclosed-comment
        branch in HexPatSyntaxHighlighter.highlightBlock.
        """
        doc = QTextDocument()
        hl = HexPatSyntaxHighlighter(doc)
        doc.setPlainText("u8 x; /* open comment")
        hl.rehighlight()
        state = _block_user_state(doc, 0)
        assert state == _BLOCK_STATE_IN_MULTILINE, (
            f"Expected block state 1 after unclosed /*, got {state}"
        )

    @staticmethod
    def test_multiline_comment_continuation_line_color() -> None:
        """A line inside a HexPat multi-line comment must receive comment color.

        Mutation caught: condition error that skips continuation-line comment format.
        """
        doc = QTextDocument()
        hl = HexPatSyntaxHighlighter(doc)
        doc.setPlainText("u8 x; /* open\nmiddle\nend */ u16 y;")
        hl.rehighlight()
        color = _color_at(doc, 1, 0)
        assert color == _COMMENT_COLOR, (
            f"Expected comment color at middle-line[0], got {color!r}"
        )


@pytest.mark.usefixtures("qapp")
class TestJavaScriptSyntaxHighlighter:
    """Gate tests for JavaScriptSyntaxHighlighter: keyword, Frida global, block-comment state."""

    @staticmethod
    def test_keyword_const_has_keyword_color() -> None:
        """The keyword 'const' must receive the keyword foreground color.

        Mutation caught: removing 'const' from JavaScriptSyntaxHighlighter.KEYWORDS.
        """
        doc = QTextDocument()
        hl = JavaScriptSyntaxHighlighter(doc)
        doc.setPlainText("const x = 1;")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _KEYWORD_COLOR, (
            f"Expected keyword color {_KEYWORD_COLOR!r} at 'const'[0], got {color!r}"
        )

    @staticmethod
    def test_frida_global_process_has_frida_color() -> None:
        """The Frida global 'Process' must receive the type/frida foreground color.

        Oracle: _TYPE_COLOR = '#4EC9B0' (Frida globals use the same color as types).

        Mutation caught: removing 'Process' from FRIDA_GLOBALS.
        """
        doc = QTextDocument()
        hl = JavaScriptSyntaxHighlighter(doc)
        doc.setPlainText("Process.enumerate()")
        hl.rehighlight()
        color = _color_at(doc, 0, 0)
        assert color == _TYPE_COLOR, (
            f"Expected Frida global color {_TYPE_COLOR!r} at 'Process'[0], got {color!r}"
        )

    @staticmethod
    def test_multiline_comment_js_sets_block_state_1() -> None:
        """An unclosed JS '/*' comment must leave block userState == 1.

        Mutation caught: removing ``setCurrentBlockState(1)`` in
        JavaScriptSyntaxHighlighter.highlightBlock.
        """
        doc = QTextDocument()
        hl = JavaScriptSyntaxHighlighter(doc)
        doc.setPlainText("let x; /* open")
        hl.rehighlight()
        state = _block_user_state(doc, 0)
        assert state == _BLOCK_STATE_IN_MULTILINE, (
            f"Expected block state 1 after unclosed /*, got {state}"
        )

    @staticmethod
    def test_multiline_comment_js_continuation_receives_comment_color() -> None:
        """A line inside a JS multi-line comment must receive comment color at pos 0.

        Mutation caught: condition error skipping continuation-line comment highlighting.
        """
        doc = QTextDocument()
        hl = JavaScriptSyntaxHighlighter(doc)
        doc.setPlainText("let x; /* open\ncontinuation\nend */")
        hl.rehighlight()
        color = _color_at(doc, 1, 0)
        assert color == _COMMENT_COLOR, (
            f"Expected comment color at continuation-line[0], got {color!r}"
        )


@pytest.mark.usefixtures("qapp")
class TestGetHighlighterForLanguage:
    """Gate tests for the get_highlighter_for_language factory function."""

    @staticmethod
    def test_c_language_returns_c_highlighter() -> None:
        """'c' must return a CSyntaxHighlighter instance.

        Mutation caught: returning AssemblySyntaxHighlighter for 'c'.
        """
        h = get_highlighter_for_language("c")
        assert isinstance(h, CSyntaxHighlighter), f"Expected CSyntaxHighlighter, got {type(h).__name__}"

    @staticmethod
    def test_cpp_alias_returns_c_highlighter() -> None:
        """'cpp' must also return a CSyntaxHighlighter instance.

        Mutation caught: removing 'cpp' from the C-language alias set.
        """
        h = get_highlighter_for_language("cpp")
        assert isinstance(h, CSyntaxHighlighter), f"Expected CSyntaxHighlighter for 'cpp', got {type(h).__name__}"

    @staticmethod
    def test_asm_language_returns_assembly_highlighter() -> None:
        """'asm' must return an AssemblySyntaxHighlighter instance.

        Mutation caught: returning CSyntaxHighlighter for 'asm'.
        """
        h = get_highlighter_for_language("asm")
        assert isinstance(h, AssemblySyntaxHighlighter), f"Expected AssemblySyntaxHighlighter, got {type(h).__name__}"

    @staticmethod
    def test_python_language_returns_python_highlighter() -> None:
        """'python' must return a PythonSyntaxHighlighter instance.

        Mutation caught: returning CSyntaxHighlighter for 'python'.
        """
        h = get_highlighter_for_language("python")
        assert isinstance(h, PythonSyntaxHighlighter), f"Expected PythonSyntaxHighlighter, got {type(h).__name__}"

    @staticmethod
    def test_py_alias_returns_python_highlighter() -> None:
        """'py' alias must return a PythonSyntaxHighlighter instance.

        Mutation caught: removing 'py' from the Python-language alias set.
        """
        h = get_highlighter_for_language("py")
        assert isinstance(h, PythonSyntaxHighlighter), f"Expected PythonSyntaxHighlighter for 'py', got {type(h).__name__}"

    @staticmethod
    def test_javascript_language_returns_js_highlighter() -> None:
        """'javascript' must return a JavaScriptSyntaxHighlighter instance.

        Mutation caught: returning CSyntaxHighlighter for 'javascript'.
        """
        h = get_highlighter_for_language("javascript")
        assert isinstance(h, JavaScriptSyntaxHighlighter), f"Expected JavaScriptSyntaxHighlighter, got {type(h).__name__}"

    @staticmethod
    def test_frida_alias_returns_js_highlighter() -> None:
        """'frida' alias must return a JavaScriptSyntaxHighlighter instance.

        Mutation caught: not including 'frida' in the JavaScript alias set.
        """
        h = get_highlighter_for_language("frida")
        assert isinstance(h, JavaScriptSyntaxHighlighter), f"Expected JavaScriptSyntaxHighlighter for 'frida', got {type(h).__name__}"

    @staticmethod
    def test_hexpat_language_returns_hexpat_highlighter() -> None:
        """'hexpat' must return a HexPatSyntaxHighlighter instance.

        Mutation caught: returning CSyntaxHighlighter for 'hexpat'.
        """
        h = get_highlighter_for_language("hexpat")
        assert isinstance(h, HexPatSyntaxHighlighter), f"Expected HexPatSyntaxHighlighter, got {type(h).__name__}"

    @staticmethod
    def test_unknown_language_returns_none() -> None:
        """An unrecognised language string must return None.

        Mutation caught: returning a default highlighter instead of None for unknown input.
        """
        h = get_highlighter_for_language("cobol")
        assert h is None, f"Expected None for unknown language, got {type(h).__name__ if h else h}"


class TestScreenCompat:
    """Gate tests for _screen_compat helpers: get_screen_geometry, move_widget, _resolve."""

    @staticmethod
    def test_get_screen_geometry_returns_4_tuple_of_ints(qapp: QApplication) -> None:
        """get_screen_geometry must return a 4-tuple of ints (x, y, w, h) in offscreen mode.

        The offscreen Qt platform always provides a primary screen, so the
        function must not return None in this environment.

        Mutation caught: returning a 3-tuple or a non-tuple object.

        Args:
            qapp: The active QApplication fixture.
        """
        result = _screen_compat.get_screen_geometry(qapp)
        assert result is not None, "Expected a tuple from get_screen_geometry in offscreen mode"
        assert isinstance(result, tuple), f"Expected tuple, got {type(result).__name__}"
        assert len(result) == 4, f"Expected 4-element tuple, got {len(result)}"
        x, y, w, h = result
        assert isinstance(x, int), f"x must be int, got {type(x).__name__}"
        assert isinstance(y, int), f"y must be int, got {type(y).__name__}"
        assert isinstance(w, int), f"width must be int, got {type(w).__name__}"
        assert isinstance(h, int), f"height must be int, got {type(h).__name__}"

    @staticmethod
    def test_get_screen_geometry_positive_dimensions(qapp: QApplication) -> None:
        """The width and height returned by get_screen_geometry must be positive.

        Oracle: a valid screen always has non-zero dimensions.

        Mutation caught: returning 0 or negative dimensions.

        Args:
            qapp: The active QApplication fixture.
        """
        result = _screen_compat.get_screen_geometry(qapp)
        assert result is not None
        _, _, w, h = result
        assert w > 0, f"Screen width must be positive, got {w}"
        assert h > 0, f"Screen height must be positive, got {h}"

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_move_widget_sets_exact_position() -> None:
        """move_widget(widget, 100, 200) must result in widget.pos() == QPoint(100, 200).

        Oracle: QWidget.move(x, y) followed by pos() returns the exact coordinates
        set. In offscreen mode there is no window manager to adjust the position.

        Mutation caught: calling move() with swapped x/y or a wrong attribute name
        (e.g. changing _MOVE from 'move' to 'position').
        """
        widget = QWidget()
        _screen_compat.move_widget(widget, 100, 200)
        pos = widget.pos()
        assert pos.x() == 100, f"Expected x=100, got x={pos.x()}"
        assert pos.y() == 200, f"Expected y=200, got y={pos.y()}"

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_resolve_raises_attribute_error_for_absent_method() -> None:
        """_resolve must raise AttributeError when the requested method does not exist.

        Mutation caught: removing the ``raise AttributeError`` call or replacing
        it with a silent return.
        """
        widget = QWidget()
        with pytest.raises(AttributeError, match="no method"):
            _screen_compat._resolve(widget, "definitelyAbsentMethod")

    @staticmethod
    @pytest.mark.usefixtures("qapp")
    def test_resolve_error_message_contains_class_name() -> None:
        """The AttributeError from _resolve must contain the target object's class name.

        Oracle: error message format is ``"{ClassName} has no method '{name}';…"``.

        Mutation caught: omitting the class name from the error message, which would
        make diagnostics harder and break the documented contract.
        """
        widget = QWidget()
        with pytest.raises(AttributeError, match="QWidget"):
            _screen_compat._resolve(widget, "nonExistentMethod")
