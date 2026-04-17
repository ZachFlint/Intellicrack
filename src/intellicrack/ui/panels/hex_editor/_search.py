# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Search mixin and background workers for the hex editor panel."""

from __future__ import annotations

import struct
from typing import Any, Final, override

from PyQt6.QtCore import QRegularExpression, QThread, pyqtSignal
from PyQt6.QtGui import QRegularExpressionValidator
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QWidget,
)

from intellicrack.ui.panels.hex_editor._base import MAX_SEARCH_RESULTS, logger
from intellicrack.ui.resources.theme_manager import ThemeManager


_LAYOUT_MARGIN: Final[int] = 4
_LAYOUT_SPACING: Final[int] = 6
_VALUE_INPUT_WIDTH: Final[int] = 120
_ALIGN_SPIN_WIDTH: Final[int] = 50
_MAX_INPUT_WIDTH: Final[int] = 100
_HIGHLIGHT_DARK: Final[str] = "#FFAA00"
_HIGHLIGHT_LIGHT: Final[str] = "#FF8800"


def _get_highlight_color() -> str:
    """Return a theme-appropriate highlight color for search results.

    Returns:
        str: Hex color string suitable for the active theme.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return _HIGHLIGHT_DARK
    return _HIGHLIGHT_LIGHT


class SearchWorker(QThread):
    """Background worker for hex/text/regex search operations.

    Executes document search FFI calls on a background thread to
    avoid blocking the Qt main thread on large files.

    Args:
        document: The hex document to search.
        mode: Search mode string (``Hex``, ``Text``, or ``Regex``).
        query: The search query string.
        encoding: Text encoding for text mode searches.
        max_results: Maximum number of results to return.
        parent: Parent QObject for lifecycle management.

    Attributes:
        search_finished: Signal emitted with results on success.
        search_error: Signal emitted with the exception on failure.
    """

    search_finished: pyqtSignal = pyqtSignal(list)
    search_error: pyqtSignal = pyqtSignal(object)

    def __init__(
        self,
        document: object,
        mode: str,
        query: str,
        encoding: str,
        max_results: int,
        parent: QThread | None = None,
    ) -> None:
        """Initialize the SearchWorker with search parameters.

        Args:
            document: Hex document to search within.
            mode: Search mode (``"hex"``, ``"text"``, ``"regex"``).
            query: Search query string.
            encoding: Text encoding for text-mode search.
            max_results: Maximum number of results to return.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._document: Any = document
        self._mode: str = mode
        self.query: str = query
        self._encoding: str = encoding
        self.max_results: int = max_results
        _: object = self.finished.connect(self.deleteLater)

    @override
    def run(self) -> None:
        """Execute the search on the background thread."""
        try:
            results = self._execute_search()
            self.search_finished.emit(results)
        except (RuntimeError, OSError, ValueError) as exc:
            logger.debug("search_worker_failed", error=str(exc))
            self.search_error.emit(exc)

    def _execute_search(self) -> list[tuple[int, int]]:
        """Dispatch to the appropriate document search method.

        Returns:
            list[tuple[int, int]]: List of (offset, length) match tuples.
        """
        if self._mode == "Hex":
            raw = self._document.search_hex(self.query, self.max_results)
        elif self._mode == "Text":
            if hasattr(self._document, "search_text_encoded"):
                raw = self._document.search_text_encoded(
                    self.query,
                    self._encoding,
                    case_sensitive=True,
                    max_results=self.max_results,
                )
            else:
                raw = self._document.search_text(
                    self.query,
                    self._encoding,
                    case_sensitive=True,
                    max_results=self.max_results,
                )
        elif self._mode == "Regex":
            raw = self._document.search_regex(self.query, self.max_results)
        else:
            return []
        return [(r[0], r[1]) for r in raw]


class NumericSearchWorker(QThread):
    """Background worker for numeric value search with Python fallback.

    Scans the document chunk-by-chunk for numeric values matching
    the given range, running entirely on a background thread.

    Args:
        document: The hex document to search.
        min_val: Minimum value to match (inclusive).
        max_val: Maximum value to match (inclusive).
        fmt: struct format string for unpacking.
        byte_width: Number of bytes per value.
        alignment: Required byte alignment of search results.
        max_results: Maximum number of results to return.
        use_native: If True, try the native ``search_numeric`` FFI first.
        size: Byte size of numeric values (1, 2, 4, or 8) for the native path.
        signed: Whether the value is signed for the native path.
        big_endian: Whether to use big-endian byte order for the native path.
        is_range: Whether this is a range search (min != max).
        parent: Parent QObject for lifecycle management.

    Attributes:
        search_finished: Signal emitted with results on success.
        search_error: Signal emitted with the exception on failure.
    """

    search_finished: pyqtSignal = pyqtSignal(list)
    search_error: pyqtSignal = pyqtSignal(object)

    def __init__(
        self,
        document: object,
        min_val: float,
        max_val: float,
        fmt: str,
        byte_width: int,
        alignment: int,
        max_results: int,
        *,
        use_native: bool,
        size: int = 4,
        signed: bool = False,
        big_endian: bool = False,
        is_range: bool = False,
        parent: QThread | None = None,
    ) -> None:
        """Initialize the NumericSearchWorker with numeric search parameters.

        Args:
            document: Hex document to search within.
            min_val: Minimum numeric value to match.
            max_val: Maximum numeric value to match.
            fmt: Struct format string for packing/unpacking.
            byte_width: Width in bytes of the numeric type.
            alignment: Byte alignment for scan positions.
            max_results: Maximum number of results to return.
            use_native: Whether to use native Rust search backend.
            size: Size of the numeric type in bytes.
            signed: Whether to interpret values as signed.
            big_endian: Whether to use big-endian byte order.
            is_range: Whether to search for a range of values.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._document: Any = document
        self._min_val: float = min_val
        self._max_val: float = max_val
        self._fmt: str = fmt
        self._byte_width: int = byte_width
        self._alignment: int = alignment
        self.max_results: int = max_results
        self._use_native: bool = use_native
        self._size: int = size
        self._signed: bool = signed
        self._big_endian: bool = big_endian
        self._is_range: bool = is_range
        _: object = self.finished.connect(self.deleteLater)

    @override
    def run(self) -> None:
        """Execute the numeric search on the background thread."""
        try:
            results = self._search_native() if self._use_native else self._search_fallback()
            self.search_finished.emit(results)
        except (RuntimeError, OSError, ValueError) as exc:
            logger.debug("numeric_search_worker_failed", error=str(exc))
            self.search_error.emit(exc)

    def _search_native(self) -> list[tuple[int, int]]:
        """Use the document's native numeric search FFI methods.

        Dispatches to ``search_numeric_range`` for range queries or
        ``search_numeric`` for exact-value queries, with correct Rust
        FFI argument order.

        Returns:
            list[tuple[int, int]]: List of (offset, byte_width) match tuples.
        """
        if self._is_range and hasattr(self._document, "search_numeric_range"):
            raw = self._document.search_numeric_range(
                (int(self._min_val), int(self._max_val)),
                self._size,
                self._signed,
                self._big_endian,
                self._alignment,
                self.max_results,
            )
        elif hasattr(self._document, "search_numeric"):
            raw = self._document.search_numeric(
                int(self._min_val),
                self._size,
                self._signed,
                self._big_endian,
                self._alignment,
                self.max_results,
            )
        else:
            return self._search_fallback()
        return [(r[0], self._byte_width) for r in raw]

    def _search_fallback(self) -> list[tuple[int, int]]:
        """Scan the document chunk-by-chunk for matching numeric values.

        Returns:
            list[tuple[int, int]]: List of (offset, byte_width) match tuples.
        """
        results: list[tuple[int, int]] = []
        doc_len: int = self._document.length()
        chunk_size = 65536
        offset = 0
        while offset < doc_len and len(results) < self.max_results:
            read_len = min(chunk_size, doc_len - offset)
            raw: bytes | bytearray | list[int] = self._document.read(offset, read_len)
            chunk = raw if isinstance(raw, bytes) else bytes(raw)
            for i in range(len(chunk) - self._byte_width + 1):
                abs_off = offset + i
                if self._alignment > 1 and abs_off % self._alignment != 0:
                    continue
                try:
                    (val,) = struct.unpack_from(self._fmt, chunk, i)
                    fval = float(val)
                    if self._min_val <= fval <= self._max_val:
                        results.append((abs_off, self._byte_width))
                        if len(results) >= self.max_results:
                            break
                except struct.error:
                    continue
            offset += max(1, read_len - self._byte_width + 1)
        return results


class SearchMixin:
    """Mixin providing hex/text/regex/numeric search for the hex editor panel."""

    _document: Any | None
    _hex_widget: Any | None
    _search_input: QLineEdit | None
    _search_mode_combo: QComboBox | None
    _encoding_combo: QComboBox | None
    _search_results: list[tuple[int, int]]
    _search_index: int
    _search_worker: SearchWorker | None
    _numeric_search_worker: NumericSearchWorker | None
    _search_status_label: QLabel | None
    _numeric_search_frame: QFrame | None
    _numeric_value_input: QLineEdit | None
    _numeric_size_combo: QComboBox | None
    _numeric_type_combo: QComboBox | None
    _numeric_endian_combo: QComboBox | None
    _numeric_align_spin: QSpinBox | None
    _numeric_range_check: QCheckBox | None
    _numeric_max_input: QLineEdit | None

    def _on_search(self) -> None:
        """Execute a search based on current mode and input."""
        if self._document is None or self._search_input is None or self._search_mode_combo is None:
            return

        query = self._search_input.text().strip()
        if not query:
            return

        mode = self._search_mode_combo.currentText()
        if mode == "Numeric":
            self._on_numeric_search()
            return

        if self._search_worker is not None and self._search_worker.isRunning():
            return

        encoding = "utf-8"
        if self._encoding_combo is not None:
            enc_text = self._encoding_combo.currentText()
            encoding = enc_text.lower().replace("-", "")

        self._search_input.setEnabled(False)

        self._search_worker = SearchWorker(
            self._document,
            mode,
            query,
            encoding,
            MAX_SEARCH_RESULTS,
        )
        self._search_worker.search_finished.connect(self._on_search_finished)
        self._search_worker.search_error.connect(self._on_search_error)
        self._search_worker.start()

    def _on_search_finished(self, results: list[tuple[int, int]]) -> None:
        """Handle completed search results from the background worker.

        Args:
            results: List of (offset, length) match tuples.
        """
        if self._search_input is not None:
            self._search_input.setEnabled(True)

        self._search_results = results
        self._search_index = 0

        if results and self._hex_widget is not None:
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(results[0][0])

            highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
            if callable(highlight_fn):
                color = _get_highlight_color()
                highlights = [(off, length, color) for off, length in results]
                try:
                    highlight_fn(highlights, "search")
                except (TypeError, AttributeError) as exc:
                    logger.warning("search_highlight_failed", error=str(exc))

        if self._search_status_label is not None:
            if not results:
                self._search_status_label.setText("No results found")
            elif len(results) >= MAX_SEARCH_RESULTS:
                self._search_status_label.setText(f"Showing {MAX_SEARCH_RESULTS}+ results (capped)")
            else:
                self._search_status_label.setText(f"Found {len(results)} results")

        logger.info("search_completed", result_count=len(results))

    def _on_search_error(self, exc: object) -> None:
        """Handle search failure from the background worker.

        Args:
            exc: The exception that occurred during search.
        """
        if self._search_input is not None:
            self._search_input.setEnabled(True)
        logger.debug("search_failed", error=str(exc))

    def _on_find_next(self) -> None:
        """Navigate to the next search result with wrap-around."""
        if not self._search_results or self._hex_widget is None:
            return
        self._search_index = (self._search_index + 1) % len(self._search_results)
        offset, _length = self._search_results[self._search_index]
        goto_fn = getattr(self._hex_widget, "goto_offset", None)
        if callable(goto_fn):
            goto_fn(offset)

    def _on_find_prev(self) -> None:
        """Navigate to the previous search result with wrap-around."""
        if not self._search_results or self._hex_widget is None:
            return
        self._search_index = (self._search_index - 1) % len(self._search_results)
        offset, _length = self._search_results[self._search_index]
        goto_fn = getattr(self._hex_widget, "goto_offset", None)
        if callable(goto_fn):
            goto_fn(offset)

    def _build_numeric_search_panel(self) -> QFrame:
        """Build the collapsible numeric search panel.

        Returns:
            QFrame: Frame containing the numeric search controls.
        """
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(_LAYOUT_MARGIN, _LAYOUT_MARGIN, _LAYOUT_MARGIN, _LAYOUT_MARGIN)
        layout.setSpacing(_LAYOUT_SPACING)

        self._numeric_value_input = QLineEdit()
        self._numeric_value_input.setToolTip("Decimal (255) or hex (0xFF) numeric value to search for")
        self._numeric_value_input.setFixedWidth(_VALUE_INPUT_WIDTH)
        numeric_validator = QRegularExpressionValidator(
            QRegularExpression(r"-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?)"),
            frame,
        )
        self._numeric_value_input.setValidator(numeric_validator)
        layout.addWidget(QLabel("Value:"))
        layout.addWidget(self._numeric_value_input)

        self._numeric_size_combo = QComboBox()
        self._numeric_size_combo.addItems(["8-bit", "16-bit", "32-bit", "64-bit"])
        self._numeric_size_combo.setCurrentText("32-bit")
        layout.addWidget(QLabel("Size:"))
        layout.addWidget(self._numeric_size_combo)

        self._numeric_type_combo = QComboBox()
        self._numeric_type_combo.addItems(["Unsigned Int", "Signed Int", "Float"])
        layout.addWidget(QLabel("Type:"))
        layout.addWidget(self._numeric_type_combo)

        self._numeric_endian_combo = QComboBox()
        self._numeric_endian_combo.addItems(["Little Endian", "Big Endian"])
        layout.addWidget(QLabel("Endian:"))
        layout.addWidget(self._numeric_endian_combo)

        layout.addWidget(QLabel("Align:"))
        self._numeric_align_spin = QSpinBox()
        self._numeric_align_spin.setRange(1, 8)
        self._numeric_align_spin.setValue(1)
        self._numeric_align_spin.setFixedWidth(_ALIGN_SPIN_WIDTH)
        layout.addWidget(self._numeric_align_spin)

        self._numeric_range_check = QCheckBox("Range")

        def _range_toggled_slot(c: int) -> None:
            self._on_numeric_range_toggled(checked=bool(c))

        self._numeric_range_check.toggled.connect(_range_toggled_slot)
        layout.addWidget(self._numeric_range_check)

        self._numeric_max_input = QLineEdit()
        self._numeric_max_input.setToolTip("Maximum value for range search (inclusive)")
        self._numeric_max_input.setFixedWidth(_MAX_INPUT_WIDTH)
        self._numeric_max_input.setValidator(
            QRegularExpressionValidator(
                QRegularExpression(r"-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?)"),
                frame,
            ),
        )
        self._numeric_max_input.setVisible(visible=False)
        layout.addWidget(self._numeric_max_input)

        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._on_numeric_search)
        layout.addWidget(search_btn)
        layout.addStretch()
        return frame

    def _on_numeric_range_toggled(self, *, checked: bool) -> None:
        """Show or hide the max value field when range search is toggled.

        Args:
            checked: True if range search is enabled.
        """
        if self._numeric_max_input is not None:
            self._numeric_max_input.setVisible(checked)

    def _on_search_mode_changed(self, mode: str) -> None:
        """Show or hide the numeric search panel and apply input validators based on mode.

        When the mode is ``Hex``, a hex-byte validator is attached to the
        search input.  For all other modes, any existing validator is cleared.

        Args:
            mode: The newly selected search mode string.
        """
        show_numeric = mode == "Numeric"
        if self._numeric_search_frame is not None:
            self._numeric_search_frame.setVisible(show_numeric)
        if self._search_input is not None:
            self._search_input.setEnabled(not show_numeric)
            if mode == "Hex":
                hex_validator = QRegularExpressionValidator(
                    QRegularExpression(r"[0-9a-fA-F ]*"),
                    self._search_input,
                )
                self._search_input.setValidator(hex_validator)
            else:
                self._search_input.setValidator(None)

    def _on_numeric_search(self) -> None:
        """Execute a numeric value search using the current panel settings."""
        if self._document is None or self._numeric_value_input is None:
            return

        if self._numeric_search_worker is not None and self._numeric_search_worker.isRunning():
            return

        value_text = self._numeric_value_input.text().strip()
        if not value_text:
            return

        size_text = self._numeric_size_combo.currentText() if self._numeric_size_combo is not None else "32-bit"
        type_text = self._numeric_type_combo.currentText() if self._numeric_type_combo is not None else "Unsigned Int"
        endian_text = self._numeric_endian_combo.currentText() if self._numeric_endian_combo is not None else "Little Endian"
        alignment = self._numeric_align_spin.value() if self._numeric_align_spin is not None else 1
        range_mode = self._numeric_range_check.isChecked() if self._numeric_range_check is not None else False
        max_text = self._numeric_max_input.text().strip() if (range_mode and self._numeric_max_input is not None) else ""

        bit_width = int(size_text.replace("-bit", ""))
        byte_width = bit_width // 8
        big_endian = endian_text == "Big Endian"
        endian_char = ">" if big_endian else "<"
        is_float = type_text == "Float"
        is_signed = type_text == "Signed Int"

        fmt_map: dict[tuple[int, bool, bool], str] = {
            (1, False, False): "B",
            (1, True, False): "b",
            (2, False, False): "H",
            (2, True, False): "h",
            (4, False, False): "I",
            (4, True, False): "i",
            (8, False, False): "Q",
            (8, True, False): "q",
            (4, False, True): "f",
            (4, True, True): "f",
            (8, False, True): "d",
            (8, True, True): "d",
        }
        fmt_char = fmt_map.get((byte_width, is_signed, is_float), "I")
        fmt = endian_char + fmt_char

        try:
            if is_float:
                min_val = float(value_text)
                max_val = float(max_text) if max_text else min_val
            else:
                min_val_int = int(value_text, 0)
                max_val_int = int(max_text, 0) if max_text else min_val_int
                min_val = float(min_val_int)
                max_val = float(max_val_int)
        except ValueError as exc:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Numeric Search", f"Invalid value: {exc}")
            return

        use_native = hasattr(self._document, "search_numeric")

        self._numeric_value_input.setEnabled(False)

        self._numeric_search_worker = NumericSearchWorker(
            self._document,
            min_val,
            max_val,
            fmt,
            byte_width,
            alignment,
            MAX_SEARCH_RESULTS,
            use_native=use_native,
            size=byte_width,
            signed=is_signed,
            big_endian=big_endian,
            is_range=(range_mode and bool(max_text)),
        )
        self._numeric_search_worker.search_finished.connect(self._on_numeric_search_finished)
        self._numeric_search_worker.search_error.connect(self._on_numeric_search_error)
        self._numeric_search_worker.start()

    def _on_numeric_search_finished(self, results: list[tuple[int, int]]) -> None:
        """Handle completed numeric search results from the background worker.

        Args:
            results: List of (offset, byte_width) match tuples.
        """
        if self._numeric_value_input is not None:
            self._numeric_value_input.setEnabled(True)

        self._search_results = results
        self._search_index = 0
        if results and self._hex_widget is not None:
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(results[0][0])
            highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
            if callable(highlight_fn):
                color = _get_highlight_color()
                highlights = [(off, length, color) for off, length in results]
                try:
                    highlight_fn(highlights, "search")
                except (TypeError, AttributeError) as exc:
                    logger.warning("search_highlight_failed", error=str(exc))

        if self._search_status_label is not None:
            if not results:
                self._search_status_label.setText("No results found")
            elif len(results) >= MAX_SEARCH_RESULTS:
                self._search_status_label.setText(f"Showing {MAX_SEARCH_RESULTS}+ results (capped)")
            else:
                self._search_status_label.setText(f"Found {len(results)} results")

        logger.info("numeric_search_completed", result_count=len(results))

    def _on_numeric_search_error(self, exc: object) -> None:
        """Handle numeric search failure from the background worker.

        Args:
            exc: The exception that occurred during search.
        """
        if self._numeric_value_input is not None:
            self._numeric_value_input.setEnabled(True)
        logger.debug("numeric_search_failed", error=str(exc))
        parent = self if isinstance(self, QWidget) else None
        QMessageBox.warning(parent, "Numeric Search", f"Search failed:\n{exc}")
