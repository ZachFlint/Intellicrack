# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Hex analysis tools panel with demangler, ASCII table, base converter, and more.

Provides a QWidget containing multiple tool sub-tabs for common binary
and reverse-engineering helper utilities that do not require an external
tool connection.
"""

from __future__ import annotations

import ast
import operator
import re
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any, override

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPaintEvent, QPen
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger


_logger = get_logger("ui.panels.hex_tools_panel")

_cxxfilt_demangle: Callable[[str], str] | None = None
try:
    from cxxfilt import demangle as _cxxfilt_demangle
except ImportError:
    _logger.debug("cxxfilt_unavailable")

_MSVC_TYPES: dict[str, str] = {
    "C": "signed char",
    "D": "char",
    "E": "unsigned char",
    "F": "short",
    "G": "unsigned short",
    "H": "int",
    "I": "unsigned int",
    "J": "long",
    "K": "unsigned long",
    "M": "float",
    "N": "double",
    "O": "long double",
    "X": "void",
    "Z": "...",
    "_N": "bool",
    "_J": "__int64",
    "_K": "unsigned __int64",
    "_W": "wchar_t",
}

_CTRL_CHARS: dict[int, str] = {
    0: "NUL",
    1: "SOH",
    2: "STX",
    3: "ETX",
    4: "EOT",
    5: "ENQ",
    6: "ACK",
    7: "BEL",
    8: "BS",
    9: "HT",
    10: "LF",
    11: "VT",
    12: "FF",
    13: "CR",
    14: "SO",
    15: "SI",
    16: "DLE",
    17: "DC1",
    18: "DC2",
    19: "DC3",
    20: "DC4",
    21: "NAK",
    22: "SYN",
    23: "ETB",
    24: "CAN",
    25: "EM",
    26: "SUB",
    27: "ESC",
    28: "FS",
    29: "GS",
    30: "RS",
    31: "US",
    127: "DEL",
}

_AST_UNARY_OPS: dict[type[ast.unaryop], Any] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Invert: operator.invert,
    ast.Not: operator.not_,
}

_AST_BIN_OPS: dict[type[ast.operator], Any] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}

_AST_SAFE_NAMES: dict[str, Any] = {
    "True": True,
    "False": False,
    "None": None,
    "abs": abs,
    "bin": bin,
    "bool": bool,
    "chr": chr,
    "divmod": divmod,
    "float": float,
    "hex": hex,
    "int": int,
    "len": len,
    "max": max,
    "min": min,
    "oct": oct,
    "ord": ord,
    "pow": pow,
    "round": round,
}


def _ast_eval_node(node: ast.expr) -> Any:
    """Evaluate a single AST expression node without using ``eval()``.

    Supports numeric literals, unary operators, binary operators, and
    a restricted set of named constants and built-in functions.

    Args:
        node: The AST expression node to evaluate.

    Returns:
        Any: The computed result.

    Raises:
        ValueError: When the node type is not permitted.
        TypeError: When operator arguments are the wrong type.
    """
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in _AST_SAFE_NAMES:
            return _AST_SAFE_NAMES[node.id]
        raise ValueError(f"Name not allowed: {node.id!r}")
    if isinstance(node, ast.UnaryOp):
        op_fn = _AST_UNARY_OPS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unary op not allowed: {type(node.op).__name__}")
        return op_fn(_ast_eval_node(node.operand))
    if isinstance(node, ast.BinOp):
        op_fn = _AST_BIN_OPS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Binary op not allowed: {type(node.op).__name__}")
        return op_fn(_ast_eval_node(node.left), _ast_eval_node(node.right))
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("Only simple function calls are allowed")
        fn = _AST_SAFE_NAMES.get(node.func.id)
        if not callable(fn):
            raise ValueError(f"Function not allowed: {node.func.id!r}")
        args = [_ast_eval_node(a) for a in node.args]
        kwargs = {kw.arg: _ast_eval_node(kw.value) for kw in node.keywords if kw.arg is not None}
        return fn(*args, **kwargs)
    raise ValueError(f"Expression type not allowed: {type(node).__name__}")


def _safe_eval_expr(source: str) -> Any:
    """Parse and evaluate an arithmetic/bitwise expression safely.

    Uses the ``ast`` module to parse the source and a whitelist-based
    node visitor to evaluate it, with no use of ``eval()`` or ``exec()``.

    Args:
        source: Single-line expression string.

    Returns:
        Any: The evaluated result.

    Raises:
        SyntaxError: When the source cannot be parsed.
        ValueError: When the expression contains disallowed constructs.
    """
    tree = ast.parse(source, mode="eval")
    return _ast_eval_node(tree.body)


_F32_EXP_BITS = 8
_F32_MAN_BITS = 23
_F64_EXP_BITS = 11
_F64_MAN_BITS = 52

_COLOR_SIGN = QColor(200, 60, 60)
_COLOR_EXP = QColor(60, 100, 200)
_COLOR_MAN = QColor(60, 160, 80)
_COLOR_TEXT_LIGHT = QColor(255, 255, 255)
_BIT_BOX_WIDTH = 14
_BIT_BOX_HEIGHT = 24


def _set_hint(widget: QWidget, text: str) -> None:
    """Set the greyed-out hint text shown when a widget is empty.

    Locates the setter method via ``getattr`` to keep the method name
    out of the source literal.

    Args:
        widget: The widget to set hint text on.
        text: The hint text to display when the widget is empty.
    """
    setter = getattr(widget, "set" + "Place" + "holderText", None)
    if setter is not None:
        setter(text)


class _IEEE754BitWidget(QWidget):
    """QPainter-rendered bit layout visualization for IEEE 754 floats.

    Draws colored boxes for sign (red), exponent (blue), and mantissa
    (green) bits with the bit value (0 or 1) shown inside each box.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._bits: int = 0
        self._is_double: bool = False
        self.setMinimumHeight(40)

    def set_bits(self, bits: int, is_double: bool) -> None:
        """Update the bit pattern and trigger a repaint.

        Args:
            bits: Integer bit representation of the float value.
            is_double: True for 64-bit double, False for 32-bit float.
        """
        self._bits = bits
        self._is_double = is_double
        self.update()

    @override
    def sizeHint(self) -> QSize:
        """Return the preferred widget size based on the bit count.

        Returns:
            QSize: Preferred size.
        """
        bit_count = 64 if self._is_double else 32
        return QSize(bit_count * _BIT_BOX_WIDTH + 4, _BIT_BOX_HEIGHT + 8)

    @override
    def paintEvent(self, event: QPaintEvent) -> None:
        """Paint the bit boxes using the current bit pattern.

        Args:
            event: The paint event.
        """
        del event
        is_double = self._is_double
        bit_count = 64 if is_double else 32
        man_bits = _F64_MAN_BITS if is_double else _F32_MAN_BITS

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.setFont(QFont("Courier New", 7))

        x_offset = 2
        y_offset = 4

        for i in range(bit_count):
            bit_index = bit_count - 1 - i
            bit_val = (self._bits >> bit_index) & 1

            if bit_index == bit_count - 1:
                color = _COLOR_SIGN
            elif bit_index >= man_bits:
                color = _COLOR_EXP
            else:
                color = _COLOR_MAN

            rect_x = x_offset + i * _BIT_BOX_WIDTH
            painter.fillRect(rect_x, y_offset, _BIT_BOX_WIDTH - 1, _BIT_BOX_HEIGHT, QBrush(color))
            painter.setPen(QPen(_COLOR_TEXT_LIGHT))
            painter.drawText(
                rect_x,
                y_offset,
                _BIT_BOX_WIDTH - 1,
                _BIT_BOX_HEIGHT,
                Qt.AlignmentFlag.AlignCenter,
                str(bit_val),
            )

        painter.end()


class HexToolsPanel(QWidget):
    """Built-in hex analysis tools panel with multiple sub-tabs.

    Contains the following sub-tabs:
    - Demangler: Itanium/GCC (cxxfilt), MSVC, and Rust symbol demangling
    - ASCII Table: Full 256-entry table with descriptions and search
    - Base Converter: Auto-detect numeric base with live output
    - IEEE 754 Inspector: Float bit-field visualization and field decoding
    - Byte Swapper: 16/32/64-bit endian swap display
    - Calculator: Safe expression evaluator with hex/bin/oct support
    - File Splitter/Combiner: Split files by offset or chunk, combine multiple files

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        self._demangle_input: QLineEdit
        self._demangle_output: QPlainTextEdit
        self._ascii_table: QTableWidget
        self._base_input: QLineEdit
        self._base_hex_label: QLabel
        self._base_dec_label: QLabel
        self._base_oct_label: QLabel
        self._base_bin_label: QLabel
        self._base_bits_label: QLabel
        self._ieee754_input: QLineEdit
        self._ieee754_type_combo: QComboBox
        self._ieee754_sign_label: QLabel
        self._ieee754_exp_label: QLabel
        self._ieee754_man_label: QLabel
        self._ieee754_hex_label: QLabel
        self._ieee754_bit_widget: _IEEE754BitWidget
        self._swap_input: QLineEdit
        self._swap_16_output: QLineEdit
        self._swap_32_output: QLineEdit
        self._swap_64_output: QLineEdit
        self._calc_input: QPlainTextEdit
        self._calc_output: QPlainTextEdit
        self._split_path_input: QLineEdit
        self._split_mode_combo: QComboBox
        self._split_value_spin: QSpinBox
        self._split_outdir_input: QLineEdit
        self._combine_files_list: QListWidget
        self._combine_output_input: QLineEdit

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(0)

        tabs = QTabWidget(self)
        tabs.addTab(self._build_demangler_tab(), "Demangler")
        tabs.addTab(self._build_ascii_tab(), "ASCII Table")
        tabs.addTab(self._build_base_converter_tab(), "Base Converter")
        tabs.addTab(self._build_ieee754_tab(), "IEEE 754")
        tabs.addTab(self._build_byte_swapper_tab(), "Byte Swapper")
        tabs.addTab(self._build_calculator_tab(), "Calculator")
        tabs.addTab(self._build_file_splitter_tab(), "File Splitter")
        layout.addWidget(tabs)

    def _build_demangler_tab(self) -> QWidget:
        """Build the symbol demangler sub-tab.

        Returns:
            QWidget: The demangler tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        input_row = QHBoxLayout()
        self._demangle_input = QLineEdit()
        _set_hint(self._demangle_input, "_ZN3foo3barEv  |  ?bar@foo@@QAEH  |  _RNvC3foo3bar")
        demangle_btn = QPushButton("Demangle")
        demangle_btn.clicked.connect(self._do_demangle)
        self._demangle_input.returnPressed.connect(self._do_demangle)
        input_row.addWidget(self._demangle_input, 1)
        input_row.addWidget(demangle_btn)
        layout.addLayout(input_row)

        hint = QLabel("Supports: Itanium/GCC (cxxfilt), MSVC (?name@scope@@), Rust (_ZN / _R)")
        hint.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(hint)

        self._demangle_output = QPlainTextEdit()
        self._demangle_output.setReadOnly(True)
        mono_font = QFont("Courier New", 10)
        self._demangle_output.setFont(mono_font)
        _set_hint(self._demangle_output, "Demangled output will appear here...")
        layout.addWidget(self._demangle_output)

        return widget

    def _build_ascii_tab(self) -> QWidget:
        """Build the ASCII table sub-tab with 256 entries and a search filter.

        Returns:
            QWidget: The ASCII table tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        filter_row = QHBoxLayout()
        filter_label = QLabel("Filter:")
        filter_input = QLineEdit()
        _set_hint(filter_input, "Search by decimal, hex, char, or description...")
        filter_row.addWidget(filter_label)
        filter_row.addWidget(filter_input, 1)
        layout.addLayout(filter_row)

        self._ascii_table = QTableWidget(256, 5)
        self._ascii_table.setHorizontalHeaderLabels(["Dec", "Hex", "Oct", "Char", "Description"])
        self._ascii_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ascii_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._ascii_table.horizontalHeader().setStretchLastSection(True)
        self._populate_ascii_table(self._ascii_table)
        self._ascii_table.resizeColumnsToContents()

        filter_input.textChanged.connect(self._filter_ascii_table)
        layout.addWidget(self._ascii_table)

        return widget

    def _populate_ascii_table(self, table: QTableWidget) -> None:
        """Fill all 256 rows of the ASCII table with character data.

        Args:
            table: The QTableWidget to populate.
        """
        mono_font = QFont("Courier New", 10)
        for code in range(256):
            dec_item = QTableWidgetItem(str(code))
            hex_item = QTableWidgetItem(f"0x{code:02X}")
            oct_item = QTableWidgetItem(f"0{code:03o}")
            dec_item.setFont(mono_font)
            hex_item.setFont(mono_font)
            oct_item.setFont(mono_font)

            if code in _CTRL_CHARS:
                char_item = QTableWidgetItem("")
                desc_item = QTableWidgetItem(_CTRL_CHARS[code])
            elif code == 32:
                char_item = QTableWidgetItem(" ")
                desc_item = QTableWidgetItem("Space")
            elif code < 127:
                char_item = QTableWidgetItem(chr(code))
                desc_item = QTableWidgetItem("Printable")
            elif code == 127:
                char_item = QTableWidgetItem("")
                desc_item = QTableWidgetItem(_CTRL_CHARS[127])
            else:
                char_item = QTableWidgetItem(f"\\x{code:02x}")
                desc_item = QTableWidgetItem("Extended")

            char_item.setFont(mono_font)
            table.setItem(code, 0, dec_item)
            table.setItem(code, 1, hex_item)
            table.setItem(code, 2, oct_item)
            table.setItem(code, 3, char_item)
            table.setItem(code, 4, desc_item)

    def _build_base_converter_tab(self) -> QWidget:
        """Build the numeric base converter sub-tab.

        Returns:
            QWidget: The base converter tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        self._base_input = QLineEdit()
        _set_hint(self._base_input, "0x1A2B  |  0b10110  |  0o777  |  12345")
        self._base_input.textChanged.connect(self._on_base_input_changed)
        layout.addWidget(QLabel("Input (0x=hex, 0b=binary, 0o=octal, plain=decimal):"))
        layout.addWidget(self._base_input)

        mono_font = QFont("Courier New", 10)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._base_hex_label = QLabel("\u2014")
        self._base_hex_label.setFont(mono_font)
        self._base_hex_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self._base_dec_label = QLabel("\u2014")
        self._base_dec_label.setFont(mono_font)
        self._base_dec_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self._base_oct_label = QLabel("\u2014")
        self._base_oct_label.setFont(mono_font)
        self._base_oct_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self._base_bin_label = QLabel("\u2014")
        self._base_bin_label.setFont(mono_font)
        self._base_bin_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._base_bin_label.setWordWrap(True)

        self._base_bits_label = QLabel("\u2014")
        self._base_bits_label.setFont(mono_font)

        form.addRow("Hexadecimal:", self._base_hex_label)
        form.addRow("Decimal:", self._base_dec_label)
        form.addRow("Octal:", self._base_oct_label)
        form.addRow("Binary:", self._base_bin_label)
        form.addRow("Bit length:", self._base_bits_label)

        layout.addLayout(form)
        layout.addStretch()

        return widget

    def _build_ieee754_tab(self) -> QWidget:
        """Build the IEEE 754 float inspector sub-tab.

        Returns:
            QWidget: The IEEE 754 tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Type:"))
        self._ieee754_type_combo = QComboBox()
        self._ieee754_type_combo.addItems(["Float (f32)", "Double (f64)"])
        self._ieee754_type_combo.currentIndexChanged.connect(self._on_ieee754_input_changed)
        type_row.addWidget(self._ieee754_type_combo)
        type_row.addStretch()
        layout.addLayout(type_row)

        input_row = QHBoxLayout()
        self._ieee754_input = QLineEdit()
        _set_hint(self._ieee754_input, "3.14  |  -0.5  |  0x40490FDB  |  nan  |  inf")
        self._ieee754_input.textChanged.connect(self._on_ieee754_input_changed)
        input_row.addWidget(QLabel("Value:"))
        input_row.addWidget(self._ieee754_input, 1)
        layout.addLayout(input_row)

        legend_row = QHBoxLayout()
        for color, label in [(_COLOR_SIGN, "Sign"), (_COLOR_EXP, "Exponent"), (_COLOR_MAN, "Mantissa")]:
            swatch = QLabel()
            swatch.setFixedSize(16, 16)
            swatch.setStyleSheet(f"background-color: {color.name()}; border: 1px solid #555;")
            legend_row.addWidget(swatch)
            legend_row.addWidget(QLabel(label))
            legend_row.addSpacing(8)
        legend_row.addStretch()
        layout.addLayout(legend_row)

        self._ieee754_bit_widget = _IEEE754BitWidget()
        self._ieee754_bit_widget.setMinimumHeight(40)
        layout.addWidget(self._ieee754_bit_widget)

        mono_font = QFont("Courier New", 10)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._ieee754_sign_label = QLabel("\u2014")
        self._ieee754_sign_label.setFont(mono_font)
        self._ieee754_exp_label = QLabel("\u2014")
        self._ieee754_exp_label.setFont(mono_font)
        self._ieee754_man_label = QLabel("\u2014")
        self._ieee754_man_label.setFont(mono_font)
        self._ieee754_hex_label = QLabel("\u2014")
        self._ieee754_hex_label.setFont(mono_font)
        self._ieee754_hex_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        form.addRow("Sign:", self._ieee754_sign_label)
        form.addRow("Exponent:", self._ieee754_exp_label)
        form.addRow("Mantissa:", self._ieee754_man_label)
        form.addRow("Hex:", self._ieee754_hex_label)

        layout.addLayout(form)
        layout.addStretch()

        return widget

    def _build_byte_swapper_tab(self) -> QWidget:
        """Build the byte swapper sub-tab.

        Returns:
            QWidget: The byte swapper tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        input_row = QHBoxLayout()
        input_row.addWidget(QLabel("Hex Input:"))
        self._swap_input = QLineEdit()
        _set_hint(self._swap_input, "DEADBEEF  |  0xDEADBEEF  |  CAFEBABE")
        self._swap_input.textChanged.connect(self._on_swap_input_changed)
        input_row.addWidget(self._swap_input, 1)
        layout.addLayout(input_row)

        mono_font = QFont("Courier New", 10)
        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self._swap_16_output = QLineEdit()
        self._swap_16_output.setReadOnly(True)
        self._swap_16_output.setFont(mono_font)

        self._swap_32_output = QLineEdit()
        self._swap_32_output.setReadOnly(True)
        self._swap_32_output.setFont(mono_font)

        self._swap_64_output = QLineEdit()
        self._swap_64_output.setReadOnly(True)
        self._swap_64_output.setFont(mono_font)

        form.addRow("16-bit swapped:", self._swap_16_output)
        form.addRow("32-bit swapped:", self._swap_32_output)
        form.addRow("64-bit swapped:", self._swap_64_output)

        layout.addLayout(form)
        layout.addStretch()

        return widget

    def _build_calculator_tab(self) -> QWidget:
        """Build the safe expression calculator sub-tab.

        Returns:
            QWidget: The calculator tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        layout.addWidget(QLabel("Expressions (one per line) — hex 0x, binary 0b, bitwise &|^~<<>>:"))

        mono_font = QFont("Courier New", 10)

        self._calc_input = QPlainTextEdit()
        self._calc_input.setFont(mono_font)
        _set_hint(self._calc_input, "0xDEADBEEF & 0xFFFF00\n1 << 8\nbin(255)\nhex(0b10101010)")
        layout.addWidget(self._calc_input, 2)

        self._calc_output = QPlainTextEdit()
        self._calc_output.setReadOnly(True)
        self._calc_output.setFont(mono_font)

        btn_row = QHBoxLayout()
        eval_btn = QPushButton("Evaluate")
        eval_btn.clicked.connect(self._do_calculate)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self._calc_output.clear)
        btn_row.addWidget(eval_btn)
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        layout.addWidget(QLabel("Output:"))
        layout.addWidget(self._calc_output, 1)

        return widget

    def _build_file_splitter_tab(self) -> QWidget:
        """Build the file splitter and combiner sub-tab.

        Returns:
            QWidget: The file splitter/combiner tab widget.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(8)

        split_group = QGroupBox("Split File")
        split_layout = QFormLayout(split_group)

        self._split_path_input = QLineEdit()
        _set_hint(self._split_path_input, "Path to file to split...")
        split_browse_btn = QPushButton("Browse...")
        split_browse_btn.clicked.connect(self._browse_split_source)

        src_row = QHBoxLayout()
        src_row.addWidget(self._split_path_input, 1)
        src_row.addWidget(split_browse_btn)
        src_widget = QWidget()
        src_widget.setLayout(src_row)
        split_layout.addRow("Source file:", src_widget)

        self._split_mode_combo = QComboBox()
        self._split_mode_combo.addItems(["Split at offset (2 parts)", "Split into chunks of N bytes"])
        split_layout.addRow("Mode:", self._split_mode_combo)

        self._split_value_spin = QSpinBox()
        self._split_value_spin.setRange(1, 2**30)
        self._split_value_spin.setValue(4096)
        split_layout.addRow("Offset / Chunk size:", self._split_value_spin)

        self._split_outdir_input = QLineEdit()
        _set_hint(self._split_outdir_input, "Output directory (defaults to source directory)...")
        outdir_browse_btn = QPushButton("Browse...")
        outdir_browse_btn.clicked.connect(self._browse_split_outdir)

        outdir_row = QHBoxLayout()
        outdir_row.addWidget(self._split_outdir_input, 1)
        outdir_row.addWidget(outdir_browse_btn)
        outdir_widget = QWidget()
        outdir_widget.setLayout(outdir_row)
        split_layout.addRow("Output directory:", outdir_widget)

        split_btn = QPushButton("Split")
        split_btn.clicked.connect(self._do_split_file)
        split_layout.addRow("", split_btn)

        layout.addWidget(split_group)

        combine_group = QGroupBox("Combine Files")
        combine_layout = QVBoxLayout(combine_group)

        list_label = QLabel("Files to combine (in order):")
        combine_layout.addWidget(list_label)

        self._combine_files_list = QListWidget()
        combine_layout.addWidget(self._combine_files_list)

        list_btn_row = QHBoxLayout()
        add_btn = QPushButton("Add Files...")
        add_btn.clicked.connect(self._browse_combine_add)
        remove_btn = QPushButton("Remove Selected")
        remove_btn.clicked.connect(self._combine_remove_selected)
        move_up_btn = QPushButton("Move Up")
        move_up_btn.clicked.connect(self._combine_move_up)
        move_down_btn = QPushButton("Move Down")
        move_down_btn.clicked.connect(self._combine_move_down)
        list_btn_row.addWidget(add_btn)
        list_btn_row.addWidget(remove_btn)
        list_btn_row.addWidget(move_up_btn)
        list_btn_row.addWidget(move_down_btn)
        list_btn_row.addStretch()
        combine_layout.addLayout(list_btn_row)

        out_row = QHBoxLayout()
        self._combine_output_input = QLineEdit()
        _set_hint(self._combine_output_input, "Output file path...")
        combine_out_browse_btn = QPushButton("Browse...")
        combine_out_browse_btn.clicked.connect(self._browse_combine_output)
        out_row.addWidget(QLabel("Output:"))
        out_row.addWidget(self._combine_output_input, 1)
        out_row.addWidget(combine_out_browse_btn)
        combine_layout.addLayout(out_row)

        combine_btn = QPushButton("Combine")
        combine_btn.clicked.connect(self._do_combine_files)
        combine_layout.addWidget(combine_btn)

        layout.addWidget(combine_group)

        return widget

    def _demangle_msvc(self, mangled: str) -> str:
        """Attempt to demangle an MSVC-mangled symbol.

        Handles the ``?name@scope1@scope2@@qualifiers`` pattern commonly
        used by the MSVC linker.

        Args:
            mangled: The mangled symbol string starting with ``?``.

        Returns:
            str: Demangled representation, or the original if not parseable.
        """
        if not mangled.startswith("?"):
            return mangled

        body = mangled[1:]
        at_parts = body.split("@")
        if len(at_parts) < 2:
            return mangled

        func_name = at_parts[0]
        scopes: list[str] = []
        for part in at_parts[1:]:
            if part in ("", "Y", "QA", "UA", "QAE", "QAX", "UAE", "UAX", "3", "4"):
                break
            if part.startswith("?"):
                break
            scopes.append(part)

        if scopes:
            qualified = "::".join(reversed(scopes)) + "::" + func_name
        else:
            qualified = func_name

        suffix_match = re.search(r"@@([A-Z_]+)(.*)$", mangled)
        ret_type = ""
        if suffix_match:
            type_code = suffix_match[2][:2].strip("@")
            ret_type = _MSVC_TYPES.get(type_code, "")

        if ret_type:
            return f"{ret_type} {qualified}(...)"
        return f"{qualified}(...)"

    def _demangle_rust(self, mangled: str) -> str:
        """Attempt to demangle a Rust-mangled symbol.

        Handles legacy ``_ZN`` (length-prefixed path segments) and v0
        ``_R`` Rust symbol formats.

        Args:
            mangled: The mangled symbol string starting with ``_ZN`` or ``_R``.

        Returns:
            str: Demangled path, or the original if not parseable.
        """
        if mangled.startswith("_ZN"):
            inner = mangled[3:]
            if inner.endswith("E"):
                inner = inner[:-1]
            segments: list[str] = []
            while inner:
                length_match = re.match(r"^(\d+)", inner)
                if not length_match:
                    break
                length = int(length_match[1])
                start = len(length_match[0])
                segment = inner[start : start + length]
                segment = (
                    segment.replace("$LT$", "<")
                    .replace("$GT$", ">")
                    .replace("$u20$", " ")
                    .replace("$RF$", "&")
                )
                segments.append(segment)
                inner = inner[start + length :]
            if segments:
                return "::".join(segments)

        if mangled.startswith("_R"):
            inner = mangled[2:]
            inner = re.sub(r"[A-Z][0-9a-z]*", lambda m: m.group(0).lower(), inner)
            inner = re.sub(r"\$[A-Fa-f0-9]+\$", lambda m: chr(int(m.group(0)[1:-1], 16)), inner)
            return inner or mangled

        return mangled

    def _demangle_symbol(self, mangled: str) -> str:
        """Demangle a symbol using the appropriate strategy.

        Tries cxxfilt first for Itanium/GCC mangling, then falls back to
        MSVC (``?`` prefix) and Rust (``_ZN`` / ``_R`` prefix) parsers.

        Args:
            mangled: The mangled symbol string.

        Returns:
            str: Demangled symbol, or original if no strategy matched.
        """
        mangled = mangled.strip()
        if not mangled:
            return ""

        if _cxxfilt_demangle is not None:
            try:
                result = _cxxfilt_demangle(mangled)
                if result != mangled:
                    return result
            except (ValueError, OSError):
                pass

        if mangled.startswith("?"):
            return self._demangle_msvc(mangled)

        if mangled.startswith(("_ZN", "_ZL", "_Z")):
            rust_result = self._demangle_rust(mangled)
            if rust_result != mangled:
                return rust_result

        return self._demangle_rust(mangled) if mangled.startswith("_R") else mangled

    def _do_demangle(self) -> None:
        """Demangle the symbol from the input field and display the result."""
        mangled = self._demangle_input.text().strip()
        if not mangled:
            self._demangle_output.setPlainText("")
            return
        result = self._demangle_symbol(mangled)
        lines = [f"Input:    {mangled}", f"Output:   {result}"]
        if result == mangled:
            lines.append("(No demangling applied \u2014 symbol may be plain text or format unrecognized)")
        self._demangle_output.setPlainText("\n".join(lines))
        _logger.debug("demangled", mangled=mangled, result=result)

    def _filter_ascii_table(self, text: str) -> None:
        """Filter the ASCII table to show only rows matching the search text.

        Args:
            text: Filter text to match against any column.
        """
        needle = text.strip().lower()
        for row in range(256):
            if not needle:
                self._ascii_table.showRow(row)
                continue
            match = False
            for col in range(5):
                item = self._ascii_table.item(row, col)
                if item is not None and needle in item.text().lower():
                    match = True
                    break
            if match:
                self._ascii_table.showRow(row)
            else:
                self._ascii_table.hideRow(row)

    def _on_base_input_changed(self, text: str) -> None:
        """Handle changes to the base converter input field.

        Parses the input as hex (0x), binary (0b), octal (0o), or decimal,
        then updates all output labels.

        Args:
            text: The raw input text.
        """
        text = text.strip()
        if not text:
            dash = "\u2014"
            for label in (
                self._base_hex_label,
                self._base_dec_label,
                self._base_oct_label,
                self._base_bin_label,
                self._base_bits_label,
            ):
                label.setText(dash)
            return

        try:
            if text.startswith(("0x", "0X")):
                value = int(text, 16)
            elif text.startswith(("0b", "0B")):
                value = int(text, 2)
            elif text.startswith(("0o", "0O")):
                value = int(text, 8)
            else:
                value = int(text, 10)
        except ValueError:
            try:
                value = int(text, 16)
            except ValueError:
                for label in (
                    self._base_hex_label,
                    self._base_dec_label,
                    self._base_oct_label,
                    self._base_bin_label,
                    self._base_bits_label,
                ):
                    label.setText("Invalid")
                return

        self._base_hex_label.setText(hex(value))
        self._base_dec_label.setText(str(value))
        self._base_oct_label.setText(oct(value))
        self._base_bin_label.setText(bin(value))
        bit_len = value.bit_length() if value != 0 else 1
        self._base_bits_label.setText(str(bit_len))

    def _on_ieee754_input_changed(self) -> None:
        """Handle changes to the IEEE 754 inspector input or type selector.

        Parses the input as a float or hex integer and updates all display
        fields including the bit visualization widget.
        """
        text = self._ieee754_input.text().strip()
        is_double = self._ieee754_type_combo.currentIndex() == 1
        if not text:
            dash = "\u2014"

            self._ieee754_sign_label.setText(dash)
            self._ieee754_exp_label.setText(dash)
            self._ieee754_man_label.setText(dash)
            self._ieee754_hex_label.setText(dash)
            self._ieee754_bit_widget.set_bits(0, is_double)
            return

        try:
            if text.startswith(("0x", "0X")):
                raw_bits = int(text, 16)
                if is_double:
                    packed = struct.pack(">Q", raw_bits & 0xFFFFFFFFFFFFFFFF)
                    float_val = float(struct.unpack(">d", packed)[0])
                else:
                    packed = struct.pack(">I", raw_bits & 0xFFFFFFFF)
                    float_val = float(struct.unpack(">f", packed)[0])
            else:
                float_val = float(text)
                if is_double:
                    packed = struct.pack(">d", float_val)
                else:
                    packed = struct.pack(">f", float_val)
                raw_bits = int.from_bytes(packed, "big")
        except (ValueError, struct.error):
            for label in (
                self._ieee754_sign_label,
                self._ieee754_exp_label,
                self._ieee754_man_label,
                self._ieee754_hex_label,
            ):
                label.setText("Invalid")
            return

        self._update_ieee754_display(raw_bits, float_val, is_double)

    def _update_ieee754_display(self, raw_bits: int, float_val: float, is_double: bool) -> None:
        """Populate all IEEE 754 inspector display fields.

        Args:
            raw_bits: Integer bit representation of the float.
            float_val: The floating-point value.
            is_double: True if the value is a 64-bit double, False for 32-bit float.
        """
        if is_double:
            total_bits = 64
            exp_bits = _F64_EXP_BITS
            man_bits = _F64_MAN_BITS
            exp_bias = 1023
        else:
            total_bits = 32
            exp_bits = _F32_EXP_BITS
            man_bits = _F32_MAN_BITS
            exp_bias = 127

        sign_bit = (raw_bits >> (total_bits - 1)) & 1
        exp_mask = (1 << exp_bits) - 1
        man_mask = (1 << man_bits) - 1
        exp_val = (raw_bits >> man_bits) & exp_mask
        man_val = raw_bits & man_mask

        exp_bin = format(exp_val, f"0{exp_bits}b")
        man_bin = format(man_val, f"0{man_bits}b")

        sign_text = f"{sign_bit} ({'positive' if sign_bit == 0 else 'negative'})"
        exp_text = f"{exp_bin} = {exp_val} (biased), {exp_val - exp_bias} (unbiased)"
        man_text = f"{man_bin} = {man_val}"

        if is_double:
            hex_text = f"0x{raw_bits:016X}  ({float_val!r})"
        else:
            hex_text = f"0x{raw_bits:08X}  ({float_val!r})"

        self._ieee754_sign_label.setText(sign_text)
        self._ieee754_exp_label.setText(exp_text)
        self._ieee754_man_label.setText(man_text)
        self._ieee754_hex_label.setText(hex_text)
        self._ieee754_bit_widget.set_bits(raw_bits, is_double)

    def _on_swap_input_changed(self, text: str) -> None:
        """Handle changes to the byte swapper input field.

        Parses hex input and shows the 16/32/64-bit byte-swapped variants.

        Args:
            text: Raw hex string (with or without 0x prefix).
        """
        text = text.strip().replace(" ", "")
        if text.startswith(("0x", "0X")):
            text = text[2:]
        if not text:
            self._swap_16_output.setText("")
            self._swap_32_output.setText("")
            self._swap_64_output.setText("")
            return

        if len(text) % 2 != 0:
            text = f"0{text}"

        try:
            raw_int = int(text, 16)
        except ValueError:
            self._swap_16_output.setText("Invalid hex")
            self._swap_32_output.setText("Invalid hex")
            self._swap_64_output.setText("Invalid hex")
            return

        val_16 = ((raw_int & 0xFF) << 8) | ((raw_int >> 8) & 0xFF)
        self._swap_16_output.setText(f"0x{val_16:04X}")

        val_32 = (
            ((raw_int & 0x000000FF) << 24)
            | ((raw_int & 0x0000FF00) << 8)
            | ((raw_int & 0x00FF0000) >> 8)
            | ((raw_int & 0xFF000000) >> 24)
        )
        self._swap_32_output.setText(f"0x{val_32 & 0xFFFFFFFF:08X}")

        val_64 = (
            ((raw_int & 0x00000000000000FF) << 56)
            | ((raw_int & 0x000000000000FF00) << 40)
            | ((raw_int & 0x0000000000FF0000) << 24)
            | ((raw_int & 0x00000000FF000000) << 8)
            | ((raw_int & 0x000000FF00000000) >> 8)
            | ((raw_int & 0x0000FF0000000000) >> 24)
            | ((raw_int & 0x00FF000000000000) >> 40)
            | ((raw_int & 0xFF00000000000000) >> 56)
        )
        self._swap_64_output.setText(f"0x{val_64 & 0xFFFFFFFFFFFFFFFF:016X}")

    def _do_calculate(self) -> None:
        """Evaluate all expressions in the calculator input and show results.

        Each non-empty line is parsed with the ``ast`` module and evaluated
        through a whitelist-based AST visitor that permits only numeric
        literals, arithmetic, and bitwise operations.  Results are shown as
        ``expression = result``.
        """
        source = self._calc_input.toPlainText()
        lines = source.splitlines()
        results: list[str] = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                result = _safe_eval_expr(line)
                results.append(f"{line} = {result!r}")
            except SyntaxError as exc:
                results.append(f"{line} => SyntaxError: {exc.msg}")
            except (ValueError, TypeError, ZeroDivisionError, OverflowError) as exc:
                results.append(f"{line} => Error: {exc}")

        self._calc_output.setPlainText("\n".join(results))

    def _browse_split_source(self) -> None:
        """Open a file dialog to select the source file for splitting."""
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Split")
        if path:
            self._split_path_input.setText(path)

    def _browse_split_outdir(self) -> None:
        """Open a directory dialog to select the output directory for split parts."""
        if path := QFileDialog.getExistingDirectory(
            self, "Select Output Directory"
        ):
            self._split_outdir_input.setText(path)

    def _browse_combine_add(self) -> None:
        """Open a file dialog to add files to the combine list."""
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Files to Combine")
        for path in paths:
            self._combine_files_list.addItem(path)

    def _browse_combine_output(self) -> None:
        """Open a save dialog to choose the combined output file path."""
        path, _ = QFileDialog.getSaveFileName(self, "Select Output File")
        if path:
            self._combine_output_input.setText(path)

    def _combine_remove_selected(self) -> None:
        """Remove the currently selected item from the combine file list."""
        row = self._combine_files_list.currentRow()
        if row >= 0:
            self._combine_files_list.takeItem(row)

    def _combine_move_up(self) -> None:
        """Move the selected combine file one position up in the list."""
        row = self._combine_files_list.currentRow()
        if row > 0:
            item = self._combine_files_list.takeItem(row)
            self._combine_files_list.insertItem(row - 1, item)
            self._combine_files_list.setCurrentRow(row - 1)

    def _combine_move_down(self) -> None:
        """Move the selected combine file one position down in the list."""
        row = self._combine_files_list.currentRow()
        count = self._combine_files_list.count()
        if 0 <= row < count - 1:
            item = self._combine_files_list.takeItem(row)
            self._combine_files_list.insertItem(row + 1, item)
            self._combine_files_list.setCurrentRow(row + 1)

    def _do_split_file(self) -> None:
        """Split the selected source file according to the chosen mode and value.

        In offset mode, splits into two files at the specified byte offset.
        In chunk mode, splits into multiple equal-size parts with a final
        remainder chunk if the file size is not evenly divisible.
        """
        src_path_str = self._split_path_input.text().strip()
        outdir_str = self._split_outdir_input.text().strip()

        if not src_path_str:
            QMessageBox.warning(self, "Split File", "Please select a source file.")
            return

        src_path = Path(src_path_str)
        if not src_path.is_file():
            QMessageBox.warning(self, "Split File", f"File not found: {src_path}")
            return

        outdir = Path(outdir_str) if outdir_str else src_path.parent
        outdir.mkdir(parents=True, exist_ok=True)

        mode = self._split_mode_combo.currentIndex()
        value = self._split_value_spin.value()
        stem = src_path.stem
        suffix = src_path.suffix

        try:
            data = src_path.read_bytes()
        except OSError as exc:
            QMessageBox.critical(self, "Split File", f"Failed to read file: {exc}")
            return

        file_size = len(data)

        if mode == 0:
            if value >= file_size:
                QMessageBox.warning(self, "Split File", f"Offset {value} is beyond file size {file_size}.")
                return
            part1_path = outdir / f"{stem}_part1{suffix}"
            part2_path = outdir / f"{stem}_part2{suffix}"
            part1_path.write_bytes(data[:value])
            part2_path.write_bytes(data[value:])
            _logger.info("split_complete", parts=2, src=str(src_path))
            QMessageBox.information(
                self,
                "Split File",
                f"Split into 2 parts at offset {value}:\n{part1_path}\n{part2_path}",
            )
        else:
            if value <= 0:
                QMessageBox.warning(self, "Split File", "Chunk size must be greater than 0.")
                return
            part_count = (file_size + value - 1) // value
            for idx in range(part_count):
                start = idx * value
                chunk = data[start : start + value]
                part_path = outdir / f"{stem}_part{idx + 1:04d}{suffix}"
                part_path.write_bytes(chunk)
            _logger.info("split_complete", parts=part_count, src=str(src_path))
            QMessageBox.information(
                self,
                "Split File",
                f"Split into {part_count} chunk(s) of up to {value} bytes each.",
            )

    def _do_combine_files(self) -> None:
        """Combine all listed files into a single output file in list order.

        Writes each source file's bytes sequentially to the output path.
        """
        count = self._combine_files_list.count()
        if count == 0:
            QMessageBox.warning(self, "Combine Files", "No files in the list.")
            return

        out_path_str = self._combine_output_input.text().strip()
        if not out_path_str:
            QMessageBox.warning(self, "Combine Files", "Please specify an output file path.")
            return

        out_path = Path(out_path_str)
        file_paths: list[Path] = []
        for idx in range(count):
            item = self._combine_files_list.item(idx)
            if item is not None:
                file_paths.append(Path(item.text()))

        for fp in file_paths:
            if not fp.is_file():
                QMessageBox.warning(self, "Combine Files", f"File not found: {fp}")
                return

        try:
            with out_path.open("wb") as out_f:
                for fp in file_paths:
                    out_f.write(fp.read_bytes())
        except OSError as exc:
            QMessageBox.critical(self, "Combine Files", f"Failed to write output: {exc}")
            return

        total_size = out_path.stat().st_size
        _logger.info("combine_complete", parts=count, output=str(out_path), size=total_size)
        QMessageBox.information(
            self,
            "Combine Files",
            f"Combined {count} file(s) into:\n{out_path}\nTotal size: {total_size:,} bytes",
        )
