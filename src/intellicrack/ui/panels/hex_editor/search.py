# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Search mixin and background workers for the hex editor panel."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Final, cast

from PyQt6.QtCore import QRegularExpression
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

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.base import MAX_SEARCH_RESULTS
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


_LAYOUT_MARGIN: Final[int] = 4
_LAYOUT_SPACING: Final[int] = 6
_VALUE_INPUT_WIDTH: Final[int] = 120
_ALIGN_SPIN_WIDTH: Final[int] = 50
_MAX_INPUT_WIDTH: Final[int] = 100
_HIGHLIGHT_DARK: Final[str] = "#FFAA00"
_HIGHLIGHT_LIGHT: Final[str] = "#FF8800"
_NUMERIC_SCAN_CHUNK_SIZE: Final[int] = 65536


_NUMERIC_FORMAT_MAP: Final[dict[tuple[int, bool, bool], str]] = {
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


@dataclass(frozen=True)
class _NumericSearchParams:
    """Decoded numeric-search form inputs for a single search dispatch.

    Attributes:
        size_text: Bit-size combo selection (e.g. ``"32-bit"``).
        type_text: Type combo selection (``"Unsigned Int"``, ``"Signed Int"``,
            or ``"Float"``).
        endian_text: Endian combo selection (``"Big Endian"`` or
            ``"Little Endian"``).
        alignment: Stride between candidate offsets in bytes.
        range_mode: ``True`` when the user enabled range search.
        value_text: Minimum-bound text (also the equality value).
        max_text: Maximum-bound text. Empty string for single-value search.
    """

    size_text: str
    type_text: str
    endian_text: str
    alignment: int
    range_mode: bool
    value_text: str
    max_text: str


@dataclass(frozen=True)
class _NumericSearchFormat:
    """Resolved struct format and numeric flags derived from form inputs.

    Attributes:
        fmt: ``struct`` format string (endian prefix + type code).
        byte_width: Number of bytes per scanned element.
        bit_width: Number of bits per scanned element.
        is_signed: ``True`` for the signed-integer type.
        is_float: ``True`` for the float type.
        big_endian: ``True`` when the user selected big-endian byte order.
    """

    fmt: str
    byte_width: int
    bit_width: int
    is_signed: bool
    is_float: bool
    big_endian: bool


def _resolve_numeric_search_format(params: _NumericSearchParams) -> _NumericSearchFormat:
    """Resolve form inputs into a struct format and numeric flag bundle.

    Args:
        params: Decoded form inputs from the numeric search panel.

    Returns:
        _NumericSearchFormat: Struct format and derived numeric flags.
    """
    bit_width = int(params.size_text.replace("-bit", ""))
    byte_width = bit_width // 8
    big_endian = params.endian_text == "Big Endian"
    endian_char = ">" if big_endian else "<"
    is_float = params.type_text == "Float"
    is_signed = params.type_text == "Signed Int"
    fmt_char = _NUMERIC_FORMAT_MAP.get((byte_width, is_signed, is_float), "I")
    return _NumericSearchFormat(
        fmt=endian_char + fmt_char,
        byte_width=byte_width,
        bit_width=bit_width,
        is_signed=is_signed,
        is_float=is_float,
        big_endian=big_endian,
    )


def _get_highlight_color() -> str:
    """Return a theme-appropriate highlight color for search results.

    Returns:
        str: Hex color string suitable for the active theme.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return _HIGHLIGHT_DARK
    return _HIGHLIGHT_LIGHT


def execute_text_search(
    document: object,
    mode: str,
    query: str,
    encoding: str,
    max_results: int,
) -> list[tuple[int, int]]:
    """Run a hex/text/regex search against the supplied document.

    Args:
        document: Hex document object exposing ``search_hex``, ``search_text``,
            ``search_text_encoded``, and/or ``search_regex``.
        mode: Search mode label (``"Hex"``, ``"Text"``, ``"Regex"``).
        query: Search query string.
        encoding: Text encoding name for text-mode searches.
        max_results: Maximum number of matches to return.

    Returns:
        list[tuple[int, int]]: List of ``(offset, length)`` match tuples.
            An empty list is returned for unrecognised modes.
    """
    doc: Any = document
    if mode == "Hex":
        raw = doc.search_hex(query, max_results)
    elif mode == "Regex":
        raw = doc.search_regex(query, max_results)
    elif mode == "Text":
        raw = (
            doc.search_text_encoded(
                query,
                encoding,
                case_sensitive=True,
                max_results=max_results,
            )
            if hasattr(doc, "search_text_encoded")
            else doc.search_text(
                query,
                encoding,
                case_sensitive=True,
                max_results=max_results,
            )
        )
    else:
        return []
    return [(r[0], r[1]) for r in raw]


def execute_numeric_search(
    document: object,
    min_val: float,
    max_val: float,
    fmt: str,
    byte_width: int,
    alignment: int,
    max_results: int,
    *,
    use_native: bool,
    size: int,
    signed: bool,
    big_endian: bool,
    is_range: bool,
) -> list[tuple[int, int]]:
    """Run a numeric value search using native FFI when available.

    Dispatches to the document's ``search_numeric_range`` or
    ``search_numeric`` FFI methods when ``use_native`` is true and they
    are available, otherwise falls back to a chunked Python scan.

    Args:
        document: Hex document object.
        min_val: Minimum numeric value to match (inclusive).
        max_val: Maximum numeric value to match (inclusive).
        fmt: ``struct`` format string used by the Python fallback.
        byte_width: Width in bytes of the numeric type.
        alignment: Byte alignment for scan positions.
        max_results: Maximum number of matches to return.
        use_native: Whether to attempt the native FFI methods first.
        size: Size of the numeric type in bytes (used by FFI).
        signed: Whether to interpret values as signed.
        big_endian: Whether to use big-endian byte order.
        is_range: Whether to search for a range of values.

    Returns:
        list[tuple[int, int]]: List of ``(offset, byte_width)`` match tuples.
    """
    doc: Any = document
    if use_native:
        if is_range and hasattr(doc, "search_numeric_range"):
            raw = doc.search_numeric_range(
                (int(min_val), int(max_val)),
                size,
                signed,
                big_endian,
                alignment,
                max_results,
            )
            return [(r[0], byte_width) for r in raw]
        if hasattr(doc, "search_numeric"):
            raw = doc.search_numeric(
                int(min_val),
                size,
                signed,
                big_endian,
                alignment,
                max_results,
            )
            return [(r[0], byte_width) for r in raw]
    return _numeric_search_fallback(
        document,
        min_val,
        max_val,
        fmt,
        byte_width,
        alignment,
        max_results,
    )


def _numeric_search_fallback(
    document: object,
    min_val: float,
    max_val: float,
    fmt: str,
    byte_width: int,
    alignment: int,
    max_results: int,
) -> list[tuple[int, int]]:
    """Scan the document chunk-by-chunk for matching numeric values.

    Args:
        document: Hex document object exposing ``length`` and ``read``.
        min_val: Minimum numeric value to match (inclusive).
        max_val: Maximum numeric value to match (inclusive).
        fmt: ``struct`` format string used to unpack each candidate.
        byte_width: Width in bytes of the numeric type.
        alignment: Byte alignment for scan positions.
        max_results: Maximum number of matches to return.

    Returns:
        list[tuple[int, int]]: List of ``(offset, byte_width)`` match tuples.
    """
    doc: Any = document
    results: list[tuple[int, int]] = []
    doc_len: int = doc.length()
    offset = 0
    while offset < doc_len and len(results) < max_results:
        read_len = min(_NUMERIC_SCAN_CHUNK_SIZE, doc_len - offset)
        raw: bytes | bytearray | list[int] = doc.read(offset, read_len)
        chunk = raw if isinstance(raw, bytes) else bytes(raw)
        for i in range(len(chunk) - byte_width + 1):
            abs_off = offset + i
            if alignment > 1 and abs_off % alignment != 0:
                continue
            try:
                (val,) = struct.unpack_from(fmt, chunk, i)
                fval = float(val)
            except struct.error:
                _logger.exception("numeric_search_unpack_failed", offset=abs_off)
                continue
            if min_val <= fval <= max_val:
                results.append((abs_off, byte_width))
                if len(results) >= max_results:
                    break
        offset += max(1, read_len - byte_width + 1)
    return results


class SearchMixin:
    """Mixin providing hex/text/regex/numeric search for the hex editor panel."""

    _hex_widget: Any | None
    _search_input: QLineEdit | None
    _search_mode_combo: QComboBox | None
    _encoding_combo: QComboBox | None
    _search_results: list[tuple[int, int]]
    _search_index: int
    _search_worker: GenericCallableWorker | None
    _numeric_search_worker: GenericCallableWorker | None
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
        document: Any = getattr(self, "document", None)
        if document is None or self._search_input is None or self._search_mode_combo is None:
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

        _logger.info(
            "search_started",
            mode=mode,
            encoding=encoding,
            query_length=len(query),
            max_results=MAX_SEARCH_RESULTS,
        )

        self._search_worker = GenericCallableWorker(
            execute_text_search,
            document,
            mode,
            query,
            encoding,
            MAX_SEARCH_RESULTS,
        )
        _: object = self._search_worker.call_finished.connect(self._on_search_finished_obj)
        _ = self._search_worker.call_error.connect(self._on_search_error)
        self._search_worker.start()

    def _on_search_finished_obj(self, results: object) -> None:
        """Forward results from the generic worker to the typed handler.

        Args:
            results: Raw object emitted by ``GenericCallableWorker.call_finished``.
        """
        if isinstance(results, list):
            self._on_search_finished(cast("list[tuple[int, int]]", results))

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
                highlight_fn(highlights, "search")

        if self._search_status_label is not None:
            if not results:
                self._search_status_label.setText("No results found")
            elif len(results) >= MAX_SEARCH_RESULTS:
                self._search_status_label.setText(f"Showing {MAX_SEARCH_RESULTS}+ results (capped)")
            else:
                self._search_status_label.setText(f"Found {len(results)} results")

        _logger.info("search_completed", result_count=len(results))

    def _on_search_error(self, exc: object) -> None:
        """Handle search failure from the background worker.

        Args:
            exc: The exception that occurred during search.
        """
        if self._search_input is not None:
            self._search_input.setEnabled(True)
        _logger.warning("search_failed", error=str(exc), error_type=type(exc).__name__)

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
        self._numeric_max_input.setVisible(False)
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

    def _reset_search_state(self) -> None:
        """Clear search results, highlights, and status for a new search context."""
        self._search_results = []
        self._search_index = 0
        if self._hex_widget is not None:
            clear_fn = getattr(self._hex_widget, "clear_highlights", None)
            if callable(clear_fn):
                clear_fn("search")
        if self._search_status_label is not None:
            self._search_status_label.setText("")

    def _setup_search_signals(self) -> None:
        """Wire search-input text changes to reset stale results."""
        if self._search_input is not None:
            self._search_input.textChanged.connect(self._on_search_input_changed)
        if self._search_mode_combo is not None:
            self._search_mode_combo.currentIndexChanged.connect(self._on_search_mode_index_changed)

    def _on_search_input_changed(self, _text: str) -> None:
        """Reset search state when the search input text is modified.

        Args:
            _text: The new text in the search input (unused; triggers state reset).
        """
        self._reset_search_state()

    def _on_search_mode_index_changed(self, _index: int) -> None:
        """Reset search state when the mode combo selection changes.

        Args:
            _index: The new combo-box index (unused; triggers state reset).
        """
        self._reset_search_state()

    def _on_search_mode_changed(self, mode: str) -> None:
        """Show or hide the numeric search panel and apply input validators based on mode.

        When the mode is ``Hex``, a hex-byte validator is attached to the
        search input.  For all other modes, any existing validator is cleared.

        Args:
            mode: The newly selected search mode string.
        """
        self._reset_search_state()
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

    @staticmethod
    def _parse_numeric_search_bounds(value_text: str, max_text: str, *, is_float: bool) -> tuple[float, float]:
        """Parse the min / max numeric search inputs.

        Args:
            value_text: Minimum-bound text (also used as the equality value when
                ``max_text`` is empty).
            max_text: Maximum-bound text. Empty string means single-value search.
            is_float: ``True`` to parse using ``float()``; otherwise the inputs
                are decoded as integers via ``int(text, 0)`` before being
                widened to ``float``.

        Returns:
            tuple[float, float]: ``(min_val, max_val)`` pair as floats.
        """
        if is_float:
            min_val = float(value_text)
            max_val = float(max_text) if max_text else min_val
            return min_val, max_val
        min_val_int = int(value_text, 0)
        max_val_int = int(max_text, 0) if max_text else min_val_int
        return float(min_val_int), float(max_val_int)

    def _read_numeric_search_params(self, value_text: str) -> _NumericSearchParams:
        """Read the numeric-search form widgets into a parameter dataclass.

        Falls back to sensible defaults whenever an individual widget is
        missing (for example before the panel has been fully built).

        Args:
            value_text: Pre-stripped value-input text supplied by the caller.

        Returns:
            _NumericSearchParams: Snapshot of the form's current state.
        """
        size_text = self._numeric_size_combo.currentText() if self._numeric_size_combo is not None else "32-bit"
        type_text = self._numeric_type_combo.currentText() if self._numeric_type_combo is not None else "Unsigned Int"
        endian_text = self._numeric_endian_combo.currentText() if self._numeric_endian_combo is not None else "Little Endian"
        alignment = self._numeric_align_spin.value() if self._numeric_align_spin is not None else 1
        range_mode = self._numeric_range_check.isChecked() if self._numeric_range_check is not None else False
        max_text = self._numeric_max_input.text().strip() if (range_mode and self._numeric_max_input is not None) else ""
        return _NumericSearchParams(
            size_text=size_text,
            type_text=type_text,
            endian_text=endian_text,
            alignment=alignment,
            range_mode=range_mode,
            value_text=value_text,
            max_text=max_text,
        )

    def _on_numeric_search(self) -> None:
        """Execute a numeric value search using the current panel settings."""
        document: Any = getattr(self, "document", None)
        if document is None or self._numeric_value_input is None:
            return

        if self._numeric_search_worker is not None and self._numeric_search_worker.isRunning():
            return

        value_text = self._numeric_value_input.text().strip()
        if not value_text:
            return

        params = self._read_numeric_search_params(value_text)
        fmt_info = _resolve_numeric_search_format(params)

        try:
            min_val, max_val = self._parse_numeric_search_bounds(
                params.value_text,
                params.max_text,
                is_float=fmt_info.is_float,
            )
        except ValueError as exc:
            _logger.warning(
                "hex_editor_numeric_search_invalid_input",
                input_text=params.value_text,
                max_text=params.max_text,
                is_float=fmt_info.is_float,
                error=str(exc),
            )
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Numeric Search", f"Invalid value: {exc}")
            return

        use_native = hasattr(document, "search_numeric")
        self._numeric_value_input.setEnabled(False)

        _logger.info(
            "numeric_search_started",
            size_bits=fmt_info.bit_width,
            type=params.type_text,
            endian=params.endian_text,
            alignment=params.alignment,
            range_mode=params.range_mode,
            min=min_val,
            max=max_val,
            use_native=use_native,
            max_results=MAX_SEARCH_RESULTS,
        )

        self._numeric_search_worker = GenericCallableWorker(
            execute_numeric_search,
            document,
            min_val,
            max_val,
            fmt_info.fmt,
            fmt_info.byte_width,
            params.alignment,
            MAX_SEARCH_RESULTS,
            use_native=use_native,
            size=fmt_info.byte_width,
            signed=fmt_info.is_signed,
            big_endian=fmt_info.big_endian,
            is_range=(params.range_mode and bool(params.max_text)),
        )
        _: object = self._numeric_search_worker.call_finished.connect(self._on_numeric_search_finished_obj)
        _ = self._numeric_search_worker.call_error.connect(self._on_numeric_search_error)
        self._numeric_search_worker.start()

    def _on_numeric_search_finished_obj(self, results: object) -> None:
        """Forward numeric search results from the generic worker to the typed handler.

        Args:
            results: Raw object emitted by ``GenericCallableWorker.call_finished``.
        """
        if isinstance(results, list):
            self._on_numeric_search_finished(cast("list[tuple[int, int]]", results))

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
                highlight_fn(highlights, "search")

        if self._search_status_label is not None:
            if not results:
                self._search_status_label.setText("No results found")
            elif len(results) >= MAX_SEARCH_RESULTS:
                self._search_status_label.setText(f"Showing {MAX_SEARCH_RESULTS}+ results (capped)")
            else:
                self._search_status_label.setText(f"Found {len(results)} results")

        _logger.info("numeric_search_completed", result_count=len(results))

    def _on_numeric_search_error(self, exc: object) -> None:
        """Handle numeric search failure from the background worker.

        Args:
            exc: The exception that occurred during search.
        """
        if self._numeric_value_input is not None:
            self._numeric_value_input.setEnabled(True)
        _logger.error(
            "numeric_search_failed",
            error_type=type(exc).__name__,
            error=str(exc),
        )
        parent = self if isinstance(self, QWidget) else None
        QMessageBox.warning(parent, "Numeric Search", f"Search failed:\n{exc}")
