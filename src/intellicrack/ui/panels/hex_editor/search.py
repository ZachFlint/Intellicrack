# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Search mixin and background workers for the hex editor panel."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, cast

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
from intellicrack.ui.dialogs_helpers import show_warning
from intellicrack.ui.panels.async_bridge import GenericCallableWorker, run_bridge_coroutine_logged
from intellicrack.ui.panels.hex_editor.base import MAX_SEARCH_RESULTS
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


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


def pack_numeric_value(value_text: str, fmt_info: _NumericSearchFormat) -> bytes:
    """Pack a numeric-search text value into raw bytes for byte-pattern replacement.

    Args:
        value_text: Decimal (``"255"``) or hex-prefixed (``"0xFF"``) numeric
            literal to encode.
        fmt_info: Resolved struct format describing the target size, sign,
            float-ness, and byte order.

    Returns:
        bytes: The packed byte representation of ``value_text``.

    Note:
        Callers should be prepared to handle ``ValueError`` (unparseable
        ``value_text``) and ``struct.error`` (parsed value out of range for
        the resolved format) propagating from this call.
    """
    value: float = float(value_text) if fmt_info.is_float else int(value_text, 0)
    return struct.pack(fmt_info.fmt, value)


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
    is_float: bool,
) -> list[tuple[int, int]]:
    """Run a numeric value search using native FFI when available.

    Integer searches dispatch to the document's ``search_numeric_range`` or
    ``search_numeric`` FFI methods when ``use_native`` is true and they are
    available. Single-value float/double searches dispatch to the native
    ``search_numeric_float`` method (which matches the IEEE-754 byte pattern
    exactly rather than truncating the value to an integer); float range
    searches, and any case where the required native method is missing, fall
    back to the chunked Python scan using the ``struct`` format ``fmt``.

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
        is_float: Whether the values are IEEE-754 floating point rather than
            integers. Float values must never be coerced with ``int()``.

    Returns:
        list[tuple[int, int]]: List of ``(offset, byte_width)`` match tuples.
    """
    doc: Any = document
    if use_native and is_float:
        if not is_range and hasattr(doc, "search_numeric_float"):
            raw = doc.search_numeric_float(
                float(min_val),
                size,
                big_endian,
                0.0,
                alignment,
                max_results,
            )
            return [(r[0], byte_width) for r in raw]
    elif use_native:
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


async def _replace_all_text_bytes(
    bridge: HexEditorBridge,
    query: str,
    replace_text: str,
    encoding: str,
) -> int:
    """Encode a Text-mode find/replace pair through the bridge codec and replace every match.

    Both ``encode_text`` calls and the final ``replace_bytes`` call run as a
    single coroutine dispatched via :func:`~intellicrack.ui.panels.async_bridge.run_bridge_coroutine_logged`,
    so none of the three bridge round-trips ever blocks the Qt GUI thread.

    Args:
        bridge: Hex editor bridge used to encode text and perform the replace.
        query: The search-field text to encode into a byte-pattern needle.
        replace_text: The replacement-field text to encode into replacement bytes.
        encoding: The hexcore codec name shared by both ``encode_text`` calls.

    Returns:
        int: The number of occurrences replaced.
    """
    pattern_hex = await bridge.encode_text(query, encoding)
    replacement_hex = await bridge.encode_text(replace_text, encoding)
    return await bridge.replace_bytes(pattern_hex, replacement_hex)


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
    _replace_input: QLineEdit | None
    _numeric_replace_input: QLineEdit | None
    _bridge: HexEditorBridge | None
    document: Any | None
    state_holder: Any | None

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

        encoding = self._selected_search_encoding()

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

        layout.addWidget(QLabel("Replace With:"))
        self._numeric_replace_input = QLineEdit()
        self._numeric_replace_input.setToolTip("Decimal (255) or hex (0xFF) numeric value to write in place of matches")
        self._numeric_replace_input.setFixedWidth(_VALUE_INPUT_WIDTH)
        self._numeric_replace_input.setValidator(
            QRegularExpressionValidator(
                QRegularExpression(r"-?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d*)?)"),
                frame,
            ),
        )
        layout.addWidget(self._numeric_replace_input)

        numeric_replace_btn = QPushButton("Replace All")
        numeric_replace_btn.clicked.connect(self._on_replace_all)
        layout.addWidget(numeric_replace_btn)

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
        if self._replace_input is not None:
            self._replace_input.setEnabled(not show_numeric)

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
            is_float=fmt_info.is_float,
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

    def _selected_search_encoding(self) -> str:
        """Resolve the hexcore codec name selected in the toolbar encoding combo.

        The codec name is stored as each item's user data (e.g. ``"ascii"``)
        while the display text is a human-readable label (e.g.
        ``"ASCII (7-bit)"``). Reading the label instead of the user data
        yields an invalid codec such as ``"ascii (7bit)"`` that raises
        ``LookupError`` when passed to ``bytes.decode`` or the Rust backend,
        so the codec is always taken from ``currentData``.

        Returns:
            str: The selected codec name, or ``"utf-8"`` when the combo is
                unavailable or carries no codec user data.
        """
        if self._encoding_combo is None:
            return "utf-8"
        data = self._encoding_combo.currentData()
        return data if isinstance(data, str) and data else "utf-8"

    def _replace_encoding(self) -> str:
        """Return the hexcore codec name selected in the toolbar encoding combo.

        Returns:
            str: The selected codec name, or ``"utf-8"`` when the combo is
                unavailable or carries no codec user data.
        """
        return self._selected_search_encoding()

    def _resolve_hex_replace_pair(self, mode: str, query: str, replace_text: str) -> tuple[str, str] | None:
        """Resolve a Hex- or Numeric-mode find/replace pair into byte-pattern hex strings.

        Hex mode uses the raw hex-digit inputs directly. Numeric mode packs
        both values using the numeric-search panel's resolved struct format
        so the replacement matches the found value's byte width, sign, and
        endianness. Text mode requires an async bridge round-trip through
        ``encode_text`` and is resolved separately by the caller via
        :func:`_replace_all_text_bytes` so the GUI thread is never blocked.

        Args:
            mode: Search mode label (``"Hex"`` or ``"Numeric"``). Any other
                mode has no synchronous byte-pattern equivalent and returns
                ``None``.
            query: The search/find field text.
            replace_text: The replacement field text.

        Returns:
            tuple[str, str] | None: ``(pattern_hex, replacement_hex)`` pair,
                or ``None`` when ``mode`` has no synchronous byte-pattern
                equivalent.

        Note:
            Numeric mode may propagate ``ValueError`` or ``struct.error``
            from :func:`pack_numeric_value` when a value cannot be parsed
            for, or does not fit, the resolved format.
        """
        if mode == "Hex":
            return query.replace(" ", ""), replace_text.replace(" ", "")

        if mode == "Numeric":
            value_text = query.strip()
            replace_value_text = replace_text.strip()
            params = self._read_numeric_search_params(value_text)
            fmt_info = _resolve_numeric_search_format(params)
            pattern_bytes = pack_numeric_value(value_text, fmt_info)
            replacement_bytes = pack_numeric_value(replace_value_text, fmt_info)
            return pattern_bytes.hex(), replacement_bytes.hex()

        return None

    def _replace_query_and_value(self, mode: str) -> tuple[str, str] | None:
        """Read the raw find/replace text for the given search mode.

        Args:
            mode: Search mode label (``"Hex"``, ``"Text"``, ``"Regex"``,
                ``"Numeric"``).

        Returns:
            tuple[str, str] | None: ``(query, replace_text)`` pair, or
                ``None`` when the required input widgets are unavailable
                or empty.
        """
        if mode == "Numeric":
            if self._numeric_value_input is None or self._numeric_replace_input is None:
                return None
            query = self._numeric_value_input.text().strip()
            replace_text = self._numeric_replace_input.text().strip()
        else:
            if self._search_input is None or self._replace_input is None:
                return None
            query = self._search_input.text().strip()
            replace_text = self._replace_input.text()
        return (query, replace_text) if query else None

    def _on_replace_all(self) -> None:
        """Replace every occurrence of the current find pattern with the replace value.

        Hex and Numeric modes resolve the find/replace pair into fixed-width byte patterns synchronously and dispatch a single
        ``HexEditorBridge.replace_bytes`` call via :func:`~intellicrack.ui.panels.async_bridge.run_bridge_coroutine_logged`, which
        replaces every occurrence in one native pass without blocking the GUI thread. Text mode additionally needs two async
        ``encode_text`` round-trips before the replace, so those are folded into the single :func:`_replace_all_text_bytes` coroutine
        dispatched the same non-blocking way. Regex mode has no fixed-width byte pattern to hand the bridge, so it instead replaces every
        cached search-result offset directly via ``document.write_bytes`` -- this requires the replacement to be the exact same byte
        length as each match (a genuine constraint of in-place replacement, since resizing per-match would invalidate subsequent offsets),
        and the user is warned and the operation aborted if it is not.
        """
        document: Any = getattr(self, "document", None)
        if document is None or self._search_mode_combo is None:
            return

        parent = self if isinstance(self, QWidget) else None
        mode = self._search_mode_combo.currentText()

        if mode == "Regex":
            self._replace_all_regex_matches(parent)
            return

        query_pair = self._replace_query_and_value(mode)
        if query_pair is None:
            return
        query, replace_text = query_pair

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            show_warning(parent, "Replace All", "Hex editor bridge not available.")
            return

        if mode == "Text":
            encoding = self._replace_encoding()
            run_bridge_coroutine_logged(
                _replace_all_text_bytes(bridge, query, replace_text, encoding),
                self._on_replace_all_succeeded,
                lambda exc: self._on_replace_all_failed(parent, exc),
                self if isinstance(self, QWidget) else None,
                event="replace_all",
                logger=_logger,
                level="info",
                mode=mode,
            )
            return

        try:
            hex_pair = self._resolve_hex_replace_pair(mode, query, replace_text)
        except (ValueError, struct.error, OverflowError) as exc:
            _logger.warning("replace_all_resolve_failed", mode=mode, error=str(exc))
            show_warning(parent, "Replace All", f"Could not resolve replacement: {exc}")
            return
        if hex_pair is None:
            return
        pattern_hex, replacement_hex = hex_pair

        run_bridge_coroutine_logged(
            bridge.replace_bytes(pattern_hex, replacement_hex),
            self._on_replace_all_succeeded,
            lambda exc: self._on_replace_all_failed(parent, exc),
            self if isinstance(self, QWidget) else None,
            event="replace_all",
            logger=_logger,
            level="info",
            mode=mode,
        )

    def _on_replace_all_succeeded(self, result: object) -> None:
        """Apply a completed Replace All result to the search UI state.

        Args:
            result: The match count returned by ``HexEditorBridge.replace_bytes``.
        """
        replaced = result if isinstance(result, int) else 0
        self._reset_search_state()
        if self._search_status_label is not None:
            self._search_status_label.setText(f"Replaced {replaced} occurrence(s)")

    @staticmethod
    def _on_replace_all_failed(parent: QWidget | None, exc: object) -> None:
        """Surface a failed Replace All dispatch to the user.

        Args:
            parent: Parent widget for the warning dialog, or ``None``.
            exc: The exception raised by the bridge coroutine.
        """
        show_warning(parent, "Replace All", f"Replace failed: {exc}")

    def _replace_all_regex_matches(self, parent: QWidget | None) -> None:
        """Replace every cached regex search-result offset with fixed-length replacement bytes.

        The replacement text is encoded through the hex-editor bridge's ``encode_text`` via
        :func:`~intellicrack.ui.panels.async_bridge.run_bridge_coroutine_logged` so the async round-trip never blocks the GUI thread;
        the per-match byte writes themselves are local, synchronous document mutations dispatched from
        :meth:`_apply_regex_replace_all` once the encoded bytes are available.

        Args:
            parent: Parent widget for warning dialogs, or ``None``.
        """
        document: Any = getattr(self, "document", None)
        if document is None:
            return
        if self._search_input is None or self._replace_input is None:
            return
        query = self._search_input.text().strip()
        if not query:
            return
        replace_text = self._replace_input.text()

        bridge = getattr(self, "_bridge", None)
        if bridge is None:
            show_warning(parent, "Replace All", "Hex editor bridge not available.")
            return

        encoding = self._replace_encoding()
        run_bridge_coroutine_logged(
            bridge.encode_text(replace_text, encoding),
            lambda result: self._apply_regex_replace_all(document, query, result, parent),
            lambda exc: self._on_replace_all_regex_encode_failed(parent, exc),
            self if isinstance(self, QWidget) else None,
            event="replace_all_regex_encode",
            logger=_logger,
            level="info",
        )

    @staticmethod
    def _on_replace_all_regex_encode_failed(parent: QWidget | None, exc: object) -> None:
        """Surface a failed regex-replace ``encode_text`` dispatch to the user.

        Args:
            parent: Parent widget for the warning dialog, or ``None``.
            exc: The exception raised by the bridge coroutine.
        """
        show_warning(parent, "Replace All", f"Could not encode replacement text: {exc}")

    def _apply_regex_replace_all(
        self,
        document: object,
        query: str,
        replacement_hex: object,
        parent: QWidget | None,
    ) -> None:
        """Apply bridge-encoded replacement bytes to every cached regex match offset.

        Args:
            document: The active hex document exposing ``search_regex`` and ``write_bytes``.
            query: The regex search-field text used to re-locate matches.
            replacement_hex: The hex-encoded replacement bytes returned by ``encode_text``.
            parent: Parent widget for warning dialogs, or ``None``.
        """
        if not isinstance(replacement_hex, str):
            show_warning(parent, "Replace All", "encode_text did not return a hex string.")
            return
        replacement_bytes = bytes.fromhex(replacement_hex)

        doc: Any = document
        matches: list[tuple[int, int]] = doc.search_regex(query, MAX_SEARCH_RESULTS)
        if not matches:
            if self._search_status_label is not None:
                self._search_status_label.setText("No results found")
            return

        if mismatched := [length for _offset, length in matches if length != len(replacement_bytes)]:
            show_warning(
                parent,
                "Replace All",
                "Regex replace requires the replacement text to be the same byte "
                f"length as every match ({len(replacement_bytes)} bytes); "
                f"{len(mismatched)} of {len(matches)} match(es) differ in length.",
            )
            return

        _logger.info("replace_all_regex_started", match_count=len(matches))
        for offset, _length in matches:
            doc.write_bytes(offset, replacement_bytes)

        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            notify = getattr(state_holder, "notify_data_modified", None)
            if callable(notify):
                for offset, _length in matches:
                    notify(offset, len(replacement_bytes), source="hex-editor.search.replace_regex")

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

        _logger.info("replace_all_regex_completed", replaced=len(matches))
        self._reset_search_state()
        if self._search_status_label is not None:
            self._search_status_label.setText(f"Replaced {len(matches)} occurrence(s)")

    def _resolve_single_replacement_bytes(self, mode: str, replace_text: str) -> bytes | None:
        """Resolve the raw replacement bytes for a single-match Hex or Numeric replace.

        Text and Regex modes require an async bridge round-trip through
        ``encode_text`` and are resolved separately by :meth:`_on_replace`
        via :meth:`_apply_encoded_single_replacement` so the GUI thread is
        never blocked.

        Args:
            mode: Search mode label (``"Hex"`` or ``"Numeric"``).
            replace_text: The replacement field text.

        Returns:
            bytes | None: The resolved replacement bytes, or ``None`` when
                the required numeric-value input widget is unavailable.

        Note:
            Numeric mode may propagate ``ValueError`` or ``struct.error``
            from :func:`pack_numeric_value`, and Hex mode may propagate
            ``ValueError`` from :func:`bytes.fromhex`, when the replacement
            text cannot be parsed for the active mode.
        """
        if mode == "Numeric":
            if self._numeric_value_input is None:
                return None
            params = self._read_numeric_search_params(self._numeric_value_input.text().strip())
            fmt_info = _resolve_numeric_search_format(params)
            return pack_numeric_value(replace_text.strip(), fmt_info)
        return bytes.fromhex(replace_text.replace(" ", ""))

    def _apply_single_replacement(self, document: object, offset: int, length: int, replacement_bytes: bytes) -> None:
        """Write ``replacement_bytes`` at ``offset`` and propagate the change to the GUI.

        Args:
            document: The active hex document exposing ``write_bytes``.
            offset: Byte offset of the match being replaced.
            length: Byte length of the match (equal to ``len(replacement_bytes)``).
            replacement_bytes: The bytes to write in place of the match.
        """
        write_fn = getattr(document, "write_bytes", None)
        if callable(write_fn):
            write_fn(offset, replacement_bytes)

        state_holder = getattr(self, "state_holder", None)
        if state_holder is not None:
            notify = getattr(state_holder, "notify_data_modified", None)
            if callable(notify):
                notify(offset, length, source="hex-editor.search.replace")

        if self._hex_widget is not None:
            update_fn = getattr(self._hex_widget, "_update_viewport", None)
            if callable(update_fn):
                update_fn()

    def _on_replace(self) -> None:
        """Replace only the currently-selected search result with the replace value.

        Advances through :attr:`_search_results` the same way :meth:`_on_find_next` does, but instead of merely navigating, overwrites the
        bytes at the current match offset with the encoded replacement value via ``document.write_bytes``. Hex and Numeric modes resolve
        the replacement bytes synchronously; Text and Regex modes dispatch an async ``encode_text`` bridge call via
        :func:`~intellicrack.ui.panels.async_bridge.run_bridge_coroutine_logged` so the GUI thread is never blocked, with the write
        completed in :meth:`_apply_encoded_single_replacement` once the result arrives. The replacement must be the same byte length as
        the match (an in-place, non-resizing write); the user is warned otherwise.
        """
        document: Any = getattr(self, "document", None)
        if document is None or self._search_mode_combo is None:
            return
        if not self._search_results:
            return

        parent = self if isinstance(self, QWidget) else None
        mode = self._search_mode_combo.currentText()
        offset, length = self._search_results[self._search_index]

        query_pair = self._replace_query_and_value(mode)
        if query_pair is None:
            return
        _query, replace_text = query_pair

        if mode in {"Text", "Regex"}:
            bridge = getattr(self, "_bridge", None)
            if bridge is None:
                show_warning(parent, "Replace", "Hex editor bridge not available.")
                return
            encoding = self._replace_encoding()
            run_bridge_coroutine_logged(
                bridge.encode_text(replace_text, encoding),
                lambda result: self._apply_encoded_single_replacement(document, mode, offset, length, result, parent),
                lambda exc: self._on_replace_single_encode_failed(parent, exc),
                self if isinstance(self, QWidget) else None,
                event="replace_single_encode",
                logger=_logger,
                level="info",
            )
            return

        try:
            replacement_bytes = self._resolve_single_replacement_bytes(mode, replace_text)
        except (ValueError, struct.error, OverflowError) as exc:
            _logger.warning("replace_single_resolve_failed", mode=mode, error=str(exc))
            show_warning(parent, "Replace", f"Could not resolve replacement: {exc}")
            return
        if replacement_bytes is None:
            return

        self._finish_single_replacement(document, mode, offset, length, replacement_bytes, parent)

    @staticmethod
    def _on_replace_single_encode_failed(parent: QWidget | None, exc: object) -> None:
        """Surface a failed single-replace ``encode_text`` dispatch to the user.

        Args:
            parent: Parent widget for the warning dialog, or ``None``.
            exc: The exception raised by the bridge coroutine.
        """
        show_warning(parent, "Replace", f"Could not encode replacement text: {exc}")

    def _apply_encoded_single_replacement(
        self,
        document: object,
        mode: str,
        offset: int,
        length: int,
        replacement_hex: object,
        parent: QWidget | None,
    ) -> None:
        """Decode a bridge-encoded replacement and finish a single-match replace.

        Args:
            document: The active hex document exposing ``write_bytes``.
            mode: Search mode label the replace was dispatched under.
            offset: Byte offset of the match being replaced.
            length: Byte length of the match.
            replacement_hex: The hex-encoded replacement bytes returned by ``encode_text``.
            parent: Parent widget for warning dialogs, or ``None``.
        """
        if not isinstance(replacement_hex, str):
            show_warning(parent, "Replace", "encode_text did not return a hex string.")
            return
        replacement_bytes = bytes.fromhex(replacement_hex)
        self._finish_single_replacement(document, mode, offset, length, replacement_bytes, parent)

    def _finish_single_replacement(
        self,
        document: object,
        mode: str,
        offset: int,
        length: int,
        replacement_bytes: bytes,
        parent: QWidget | None,
    ) -> None:
        """Validate the replacement length, write it, and advance to the next match.

        Args:
            document: The active hex document exposing ``write_bytes``.
            mode: Search mode label the replace was dispatched under.
            offset: Byte offset of the match being replaced.
            length: Byte length of the match (must equal ``len(replacement_bytes)``).
            replacement_bytes: The bytes to write in place of the match.
            parent: Parent widget for warning dialogs, or ``None``.
        """
        if len(replacement_bytes) != length:
            show_warning(
                parent,
                "Replace",
                f"Replacement is {len(replacement_bytes)} byte(s) but the match is {length} byte(s). "
                "Use Replace All for variable-length replacement via the byte-pattern engine.",
            )
            return

        self._apply_single_replacement(document, offset, length, replacement_bytes)

        _logger.info("replace_single_completed", mode=mode, offset=offset, length=length)
        if self._search_status_label is not None:
            self._search_status_label.setText(f"Replaced match at 0x{offset:08X}")

        self._on_find_next()
