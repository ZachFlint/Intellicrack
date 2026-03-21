# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""Hex editor panel with data inspector, bookmarks, and structure templates.

Provides a complete hex editing environment combining the custom
HexEditorWidget with side panels for data inspection, bookmarks,
sections, imports, exports, strings, statistics, and templates.
"""


from __future__ import annotations

import hashlib
import math
import struct
import zlib
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from PyQt6.QtCore import QRect, Qt, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QKeySequence,
    QMouseEvent,
    QPaintEvent,
    QPainter,
    QPen,
    QShortcut,
)
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QToolBar,
    QToolTip,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.highlighter import HexPatSyntaxHighlighter
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.panels.hex_editor_widget import HexEditorWidget


if TYPE_CHECKING:
    from intellicrack.bridges.hex_state import HexDocumentState

_logger = get_logger("ui.panels.hex_editor_panel")

_hexpat_mod: Any = None
_hexpat_available: bool = False

try:
    import importlib as _importlib

    _hexpat_mod = _importlib.import_module("intellicrack.core.hexpat_compiler")
    _hexpat_available = True
except Exception:
    _logger.debug("hexpat_compiler_import_unavailable")

try:
    import pefile

    _pefile_available: bool = True
except ImportError:
    pefile = None
    _pefile_available = False

_xxhash_mod: Any = None
_xxhash_available: bool = False
try:
    import xxhash as _xxhash_import

    _xxhash_mod = _xxhash_import
    _xxhash_available = True
except ImportError:
    pass

_hexcore: Any = None
_hexcore_available: bool = False

try:
    import intellicrack_hexcore as _hexcore_mod

    _hexcore = _hexcore_mod
    _hexcore_available = True
except ImportError:
    _logger.debug("hexcore_import_unavailable")

_HexDocumentEvent: Any = None
_hex_state_available: bool = False
try:
    from intellicrack.bridges.hex_state import HexDocumentEvent as _HexDocumentEvent

    _hex_state_available = True
except ImportError:
    _logger.debug("hex_state_import_unavailable")

_HexDisassembler: Any = None
_disassembler_available: bool = False
try:
    from intellicrack.core.disassembler import HexDisassembler as _HexDisassembler

    _disassembler_available = True
except ImportError:
    _logger.debug("disassembler_import_unavailable")

_YaraScanner: Any = None
_yara_scanner_available: bool = False
try:
    from intellicrack.core.yara_scanner import YaraScanner as _YaraScanner

    _yara_scanner_available = True
except ImportError:
    _logger.debug("yara_scanner_import_unavailable")

_get_all_transform_nodes: Any = None
_transform_pipeline_available: bool = False
try:
    from intellicrack.core.transform_pipeline import (
        get_all_transform_nodes as _get_all_transform_nodes,
    )

    _transform_pipeline_available = True
except ImportError:
    _logger.debug("transform_pipeline_import_unavailable")


_KB = 1024
_MB = _KB**2
_GB = _MB * _KB
_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E

_ENTROPY_LOW_THRESHOLD: float = 3.5
_ENTROPY_HIGH_THRESHOLD: float = 6.5
_ENTROPY_MAX: float = 8.0
_BYTE_VALUES_COUNT: int = 256
_ENTROPY_BLOCK_SIZE: int = 4096
_PREVIEW_BYTES: int = 256
_CURSOR_CONTEXT_BYTES: int = 128
_HEX_ROW_WIDTH: int = 16
_MAX_SEARCH_RESULTS: int = 100
_MAX_INSN_BYTES: int = 15
_DESCRIPTION_TRUNCATE_LEN: int = 80
_SPLITTER_MAIN_RATIO: float = 0.65
_SPLITTER_PATTERN_RATIO: float = 0.35
_BYTE_TYPE_DIST_MIN_LEN: int = 4
_IPS_OFFSET_SIZE: int = 3
_IPS32_OFFSET_SIZE: int = 4
_IPS_LENGTH_FIELD_SIZE: int = 2
_IPS_HEADER_SIZE: int = 5
_YARA_MATCH_DISPLAY_BYTES: int = 32
_DEFAULT_DISASM_COUNT: int = 50


def _format_size(size: int) -> str:
    """Format a byte size as a human-readable string.

    Args:
        size: Size in bytes.

    Returns:
        str: Formatted size string (e.g. "1.5 MB").
    """
    if size < _KB:
        return f"{size} B"
    if size < _MB:
        return f"{size / _KB:.1f} KB"
    return f"{size / _MB:.1f} MB" if size < _GB else f"{size / _GB:.2f} GB"


def _reflect_bits(value: int, width: int) -> int:
    """Reflect (reverse) the bit order of an integer.

    Args:
        value: Integer value to reflect.
        width: Bit width of the value.

    Returns:
        int: Bit-reversed integer.
    """
    result = 0
    for _ in range(width):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def _compute_custom_crc(
    data: bytes,
    width: int,
    poly: int,
    init: int,
    ref_in: bool,
    ref_out: bool,
    xor_out: int,
) -> int:
    """Compute a parametric CRC checksum.

    Args:
        data: Input bytes.
        width: CRC bit width (8, 16, 32, or 64).
        poly: Generator polynomial.
        init: Initial CRC value.
        ref_in: Reflect each input byte before processing.
        ref_out: Reflect the final CRC value before XOR-out.
        xor_out: Value to XOR with the final CRC.

    Returns:
        int: Computed CRC value.
    """
    mask = (1 << width) - 1
    msb_mask = 1 << (width - 1)
    crc = init & mask
    for byte in data:
        b = _reflect_bits(byte, 8) if ref_in else byte
        for i in range(7, -1, -1):
            bit = (b >> i) & 1
            crc = ((crc << 1) | bit) ^ poly if crc & msb_mask else (crc << 1) | bit
            crc &= mask
    if ref_out:
        crc = _reflect_bits(crc, width)
    return (crc ^ xor_out) & mask


def _compute_hash_stdlib(algo: str, data: bytes) -> str | None:
    """Compute a hash using stdlib hashlib algorithms.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex digest, or None if the algorithm is not handled here.
    """
    stdlib_map: dict[str, str] = {
        "MD5": "md5",
        "SHA-1": "sha1",
    }
    if algo in stdlib_map:
        return hashlib.new(stdlib_map[algo], data).hexdigest()
    attr_map: dict[str, Any] = {
        "SHA-224": hashlib.sha224,
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-512": hashlib.sha3_512,
    }
    if algo in attr_map:
        return attr_map[algo](data).hexdigest()
    if algo == "Blake2b-256":
        return hashlib.blake2b(data, digest_size=32).hexdigest()
    if algo == "Blake2s-256":
        return hashlib.blake2s(data, digest_size=32).hexdigest()
    return None


def _compute_hash_xxhash(algo: str, data: bytes) -> str | None:
    """Compute a hash using the xxhash library.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex digest, or an error string, or None if not an xxhash algo.
    """
    if algo not in {"XXHash32", "XXHash64", "XXH3-64"}:
        return None
    if not _xxhash_available or _xxhash_mod is None:
        return "Error: xxhash not installed"
    if algo == "XXHash32":
        return str(_xxhash_mod.xxh32(data).hexdigest())
    if algo == "XXHash64":
        return str(_xxhash_mod.xxh64(data).hexdigest())
    return str(_xxhash_mod.xxh3_64(data).hexdigest())


def _compute_hash_siphash(algo: str, data: bytes) -> str | None:
    """Compute a SipHash digest.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex digest, or an error string, or None if not a SipHash algo.
    """
    sip_attr_map: dict[str, str] = {
        "SipHash64": "siphash13",
        "SipHash128": "siphash24",
    }
    if algo not in sip_attr_map:
        return None
    sip_fn = getattr(hashlib, sip_attr_map[algo], None)
    if sip_fn is None:
        return "Error: SipHash not available (Python 3.12+ required)"
    return sip_fn(b"\x00" * 16, data).hex()


def _compute_hash_checksums(algo: str, data: bytes) -> str | None:
    """Compute CRC or Adler checksum.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex checksum string, or None if not a checksum algo.
    """
    if algo == "Adler32":
        return f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"
    if algo == "CRC-8":
        crc = _compute_custom_crc(data, 8, 0x07, 0x00, False, False, 0x00)
        return f"{crc:02x}"
    if algo == "CRC-16":
        crc = _compute_custom_crc(data, 16, 0x8005, 0x0000, True, True, 0x0000)
        return f"{crc:04x}"
    if algo == "CRC-32":
        return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    if algo == "CRC-64":
        crc = _compute_custom_crc(
            data, 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF, False, False, 0xFFFFFFFFFFFFFFFF
        )
        return f"{crc:016x}"
    return None


def _compute_hash_fnv(algo: str, data: bytes) -> str | None:
    """Compute an FNV hash.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str | None: Hex hash string, or None if not an FNV algo.
    """
    fnv32_prime = 16777619
    fnv64_prime = 1099511628211
    fnv32_offset = 2166136261
    fnv64_offset = 14695981039346656037
    fnv32_mask = 0xFFFFFFFF
    fnv64_mask = 0xFFFFFFFFFFFFFFFF

    if algo == "FNV1-32":
        h = fnv32_offset
        for b in data:
            h = ((h * fnv32_prime) ^ b) & fnv32_mask
        return f"{h:08x}"
    if algo == "FNV1-64":
        h = fnv64_offset
        for b in data:
            h = ((h * fnv64_prime) ^ b) & fnv64_mask
        return f"{h:016x}"
    if algo == "FNV1a-32":
        h = fnv32_offset
        for b in data:
            h = ((h ^ b) * fnv32_prime) & fnv32_mask
        return f"{h:08x}"
    if algo == "FNV1a-64":
        h = fnv64_offset
        for b in data:
            h = ((h ^ b) * fnv64_prime) & fnv64_mask
        return f"{h:016x}"
    return None


def _compute_hash(algo: str, data: bytes) -> str:
    """Compute a hash or checksum of data using the specified algorithm.

    Args:
        algo: Algorithm name string.
        data: Input bytes to hash.

    Returns:
        str: Hex-encoded hash result, or an error message prefixed with "Error:".
    """
    try:
        result = _compute_hash_stdlib(algo, data)
        if result is not None:
            return result
        result = _compute_hash_xxhash(algo, data)
        if result is not None:
            return result
        result = _compute_hash_siphash(algo, data)
        if result is not None:
            return result
        result = _compute_hash_checksums(algo, data)
        if result is not None:
            return result
        result = _compute_hash_fnv(algo, data)
        return result if result is not None else f"Error: unknown algorithm {algo}"
    except Exception as exc:
        return f"Error: {exc}"


_HASH_ALGORITHMS: list[str] = [
    "MD5",
    "SHA-1",
    "SHA-224",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
    "SHA3-512",
    "Blake2b-256",
    "Blake2s-256",
    "XXHash32",
    "XXHash64",
    "XXH3-64",
    "SipHash64",
    "SipHash128",
    "Adler32",
    "CRC-8",
    "CRC-16",
    "CRC-32",
    "CRC-64",
    "FNV1-32",
    "FNV1-64",
    "FNV1a-32",
    "FNV1a-64",
]

_ENCODING_ENTRIES: list[str] = [
    "UTF-8",
    "ASCII",
    "UTF-16LE",
    "UTF-16BE",
    "--- Western ---",
    "Windows-1252",
    "ISO-8859-1",
    "ISO-8859-15",
    "--- Central European ---",
    "Windows-1250",
    "ISO-8859-2",
    "--- Cyrillic ---",
    "Windows-1251",
    "KOI8-R",
    "KOI8-U",
    "ISO-8859-5",
    "--- Greek ---",
    "Windows-1253",
    "ISO-8859-7",
    "--- Turkish ---",
    "Windows-1254",
    "--- Japanese ---",
    "Shift-JIS",
    "EUC-JP",
    "ISO-2022-JP",
    "--- Chinese ---",
    "GBK",
    "GB18030",
    "Big5",
    "--- Korean ---",
    "EUC-KR",
    "--- Other ---",
    "EBCDIC",
]


class EntropyGraphWidget(QWidget):
    """Line-chart widget visualising per-block Shannon entropy.

    Renders a polyline where the X axis maps to block offset and the
    Y axis maps to entropy in [0, 8] bits/byte.  Colour bands show
    green for low entropy, yellow for medium, and red for high.
    Clicking on the graph emits ``block_clicked`` with the byte offset
    of the block that was clicked.

    Args:
        parent: Parent widget.

    Attributes:
        block_clicked: Signal emitted with the byte offset of the clicked block.
    """

    block_clicked: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._entropy_values: list[float] = []
        self._block_size: int = 4096
        self.setMinimumHeight(120)
        self.setMouseTracking(True)

    def set_data(self, entropy_values: list[float], block_size: int) -> None:
        """Load new entropy data and trigger a repaint.

        Args:
            entropy_values: Per-block entropy values in [0, 8].
            block_size: Size of each block in bytes.
        """
        self._entropy_values = entropy_values
        self._block_size = block_size
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        """Render the entropy line chart.

        Args:
            event: The paint event (unused directly).
        """
        _ = event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        pad = 4

        painter.fillRect(0, 0, w, h, QColor("#1E1E1E"))

        band_data: list[tuple[float, float, QColor]] = [
            (0.0, _ENTROPY_LOW_THRESHOLD, QColor("#1B3A1F")),
            (_ENTROPY_LOW_THRESHOLD, _ENTROPY_HIGH_THRESHOLD, QColor("#3A3A1B")),
            (_ENTROPY_HIGH_THRESHOLD, _ENTROPY_MAX, QColor("#3A1B1B")),
        ]
        for lo, hi, colour in band_data:
            y1 = h - pad - int((lo / _ENTROPY_MAX) * (h - 2 * pad))
            y2 = h - pad - int((hi / _ENTROPY_MAX) * (h - 2 * pad))
            painter.fillRect(pad, y2, w - 2 * pad, y1 - y2, colour)

        values = self._entropy_values
        if not values:
            painter.end()
            return

        usable_w = max(w - 2 * pad, 1)
        usable_h = h - 2 * pad

        def x_coord(idx: int) -> int:
            return pad + int(idx * usable_w / max(len(values) - 1, 1))

        def y_coord(val: float) -> int:
            return h - pad - int((val / _ENTROPY_MAX) * usable_h)

        for i in range(len(values) - 1):
            v = values[i]
            if v < _ENTROPY_LOW_THRESHOLD:
                colour_line = QColor("#4CAF50")
            elif v < _ENTROPY_HIGH_THRESHOLD:
                colour_line = QColor("#FFC107")
            else:
                colour_line = QColor("#F44336")
            pen = QPen(colour_line, 1)
            painter.setPen(pen)
            painter.drawLine(x_coord(i), y_coord(values[i]), x_coord(i + 1), y_coord(values[i + 1]))

        axis_pen = QPen(QColor("#888888"), 1)
        painter.setPen(axis_pen)
        painter.drawRect(pad, pad, w - 2 * pad, h - 2 * pad)
        painter.end()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        """Navigate to the clicked block offset.

        Args:
            event: The mouse press event.
        """
        values = self._entropy_values
        if not values:
            return
        w = self.width()
        pad = 4
        x = event.position().x()
        idx = int((x - pad) / max(w - 2 * pad, 1) * (len(values) - 1) + 0.5)
        idx = max(0, min(len(values) - 1, idx))
        self.block_clicked.emit(idx * self._block_size)


class ByteDistributionWidget(QWidget):
    """Histogram widget showing the frequency of each of the 256 byte values.

    Renders 256 vertical bars, one per byte value.  Supports optional
    logarithmic scale.  Hovering over a bar shows a tooltip with the
    byte value and count.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._counts: list[int] = [0] * 256
        self._log_scale: bool = False
        self._hovered_bar: int = -1
        self.setMinimumHeight(100)
        self.setMouseTracking(True)

    def set_data(self, counts: list[int]) -> None:
        """Load byte frequency data and repaint.

        Args:
            counts: List of 256 integers, one per byte value.
        """
        self._counts = list(counts) if len(counts) == _BYTE_VALUES_COUNT else ([0] * _BYTE_VALUES_COUNT)
        self.update()

    def toggle_log_scale(self) -> None:
        """Toggle between linear and logarithmic Y scale."""
        self._log_scale = not self._log_scale
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        """Render the 256-bar histogram.

        Args:
            event: The paint event (unused directly).
        """
        _ = event
        painter = QPainter(self)
        w = self.width()
        h = self.height()
        pad = 2
        painter.fillRect(0, 0, w, h, QColor("#1E1E1E"))

        counts = self._counts
        if not counts or max(counts) == 0:
            painter.end()
            return

        max_val = max(counts)
        bar_w = max(1.0, (w - 2 * pad) / _BYTE_VALUES_COUNT)

        def bar_h(count: int) -> int:
            if count == 0:
                return 0
            if self._log_scale:
                return int((math.log1p(count) / math.log1p(max_val)) * (h - 2 * pad))
            return int((count / max_val) * (h - 2 * pad))

        for i, count in enumerate(counts):
            bh = bar_h(count)
            if bh == 0:
                continue
            x = pad + int(i * bar_w)
            colour = QColor("#4CAF50") if i == self._hovered_bar else QColor("#2196F3")
            painter.fillRect(QRect(x, h - pad - bh, max(1, int(bar_w)), bh), QBrush(colour))

        painter.end()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        """Update tooltip and hover highlight on mouse movement.

        Args:
            event: The mouse move event.
        """
        w = self.width()
        pad = 2
        x = event.position().x()
        bar_w = max(1.0, (w - 2 * pad) / _BYTE_VALUES_COUNT)
        idx = int((x - pad) / bar_w)
        idx = max(0, min(_BYTE_VALUES_COUNT - 1, idx))
        self._hovered_bar = idx
        count = self._counts[idx] if self._counts else 0
        QToolTip.showText(
            event.globalPosition().toPoint(),
            f"Byte 0x{idx:02X} ({idx}): {count} occurrences",
            self,
        )
        self.update()


class CustomCrcDialog(QDialog):
    """Dialog for computing a custom parametric CRC.

    Provides input fields for width, polynomial, initial value,
    reflection options, and XOR-out value, then computes the CRC
    over the supplied data when the user clicks Calculate.

    Args:
        data: The byte data to compute the CRC over.
        parent: Parent widget.
    """

    def __init__(self, data: bytes, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._data = data
        self.setWindowTitle("Custom CRC Calculator")
        self.setMinimumWidth(360)

        layout = QVBoxLayout(self)

        form = QFormLayout()
        self._width_spin = QSpinBox()
        self._width_spin.setRange(8, 64)
        self._width_spin.setSingleStep(8)
        self._width_spin.setValue(32)
        form.addRow("Width (bits):", self._width_spin)

        self._poly_edit = QLineEdit("04C11DB7")
        form.addRow("Polynomial (hex):", self._poly_edit)

        self._init_edit = QLineEdit("FFFFFFFF")
        form.addRow("Init Value (hex):", self._init_edit)

        self._ref_in_check = QCheckBox("Reflect Input")
        self._ref_in_check.setChecked(True)
        form.addRow(self._ref_in_check)

        self._ref_out_check = QCheckBox("Reflect Output")
        self._ref_out_check.setChecked(True)
        form.addRow(self._ref_out_check)

        self._xor_out_edit = QLineEdit("FFFFFFFF")
        form.addRow("XOR Out (hex):", self._xor_out_edit)

        layout.addLayout(form)

        self._result_label = QLabel("Result: \u2014")
        layout.addWidget(self._result_label)

        calc_btn = QPushButton("Calculate")
        calc_btn.clicked.connect(self._calculate)
        layout.addWidget(calc_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _calculate(self) -> None:
        """Compute the CRC with the current parameters and display the result."""
        try:
            width = self._width_spin.value()
            poly = int(self._poly_edit.text().strip(), 16)
            init = int(self._init_edit.text().strip(), 16)
            ref_in = self._ref_in_check.isChecked()
            ref_out = self._ref_out_check.isChecked()
            xor_out = int(self._xor_out_edit.text().strip(), 16)
            result = _compute_custom_crc(self._data, width, poly, init, ref_in, ref_out, xor_out)
        except ValueError as exc:
            self._result_label.setText(f"Error: {exc}")
        else:
            hex_digits = (width + 3) // 4
            self._result_label.setText(f"Result: 0x{result:0{hex_digits}X}")


class HexEditorPanel(AnalysisPanelBase):
    """Hex editor panel with integrated side panels.

    Combines the custom HexEditorWidget with data inspector,
    bookmarks, sections, imports, exports, strings, statistics,
    and template panels in a split layout.

    Args:
        parent: Parent widget.

    Attributes:
        context_push_requested: Signal emitted with context dict when hex data is pushed to AI chat.
    """

    context_push_requested: pyqtSignal = pyqtSignal(dict)

    def __init__(self, parent: QWidget | None = None) -> None:
        self._hex_widget: Any | None = None
        self._document: Any | None = None
        self._file_path: Path | None = None

        self._data_inspector_tree: QTreeWidget | None = None
        self._bookmarks_tree: QTreeWidget | None = None
        self._sections_tree: QTreeWidget | None = None
        self._imports_tree: QTreeWidget | None = None
        self._exports_tree: QTreeWidget | None = None
        self._strings_tree: QTreeWidget | None = None
        self._statistics_tree: QTreeWidget | None = None
        self._templates_tree: QTreeWidget | None = None
        self._template_combo: QComboBox | None = None
        self._patches_tree: QTreeWidget | None = None
        self._search_input: QLineEdit | None = None
        self._search_mode_combo: QComboBox | None = None
        self._offset_input: QLineEdit | None = None
        self._mode_label: QLabel | None = None
        self._file_info_label: QLabel | None = None
        self._encoding_combo: QComboBox | None = None
        self._undo_btn: QPushButton | None = None
        self._redo_btn: QPushButton | None = None
        self._side_tabs: QTabWidget | None = None

        self._search_results: list[tuple[int, int]] = []
        self._search_index: int = 0
        self._original_data_cache: dict[int, int] = {}
        self._state_holder: HexDocumentState | None = None
        self._find_next_btn: QPushButton | None = None
        self._find_prev_btn: QPushButton | None = None

        self._pattern_frame: QFrame | None = None
        self._pattern_dsl_editor: QPlainTextEdit | None = None
        self._pattern_json_preview: QPlainTextEdit | None = None
        self._pattern_library_tree: QTreeWidget | None = None
        self._pattern_error_display: QPlainTextEdit | None = None
        self._pattern_status_label: QLabel | None = None
        self._pattern_visible: bool = False
        self._compiled_json: str = ""
        self._main_vsplit: QSplitter | None = None

        self._disasm_arch_combo: QComboBox | None = None
        self._disasm_mode_combo: QComboBox | None = None
        self._disasm_count_spin: QSpinBox | None = None
        self._disasm_follow_cursor: QCheckBox | None = None
        self._disasm_table: QTableWidget | None = None

        self._yara_rule_files: list[str] = []
        self._yara_file_count_label: QLabel | None = None
        self._yara_inline_editor: QPlainTextEdit | None = None
        self._yara_results_tree: QTreeWidget | None = None

        self._transform_node_combo: QComboBox | None = None
        self._transform_params_form: QFormLayout | None = None
        self._transform_params_widget: QWidget | None = None
        self._transform_preview_pane: QPlainTextEdit | None = None
        self._transform_pipeline_list: QListWidget | None = None
        self._transform_pipeline: list[tuple[str, dict[str, str]]] = []
        self._transform_nodes_cache: list[Any] = []

        self._entropy_graph: EntropyGraphWidget | None = None
        self._byte_dist_widget: ByteDistributionWidget | None = None
        self._entropy_label: QLabel | None = None
        self._null_pct_label: QLabel | None = None
        self._printable_pct_label: QLabel | None = None
        self._control_pct_label: QLabel | None = None
        self._high_pct_label: QLabel | None = None
        self._classification_label: QLabel | None = None
        self._hash_algo_combo: QComboBox | None = None
        self._hash_result_label: QLabel | None = None
        self._numeric_search_frame: QFrame | None = None
        self._numeric_value_input: QLineEdit | None = None
        self._numeric_size_combo: QComboBox | None = None
        self._numeric_type_combo: QComboBox | None = None
        self._numeric_endian_combo: QComboBox | None = None
        self._numeric_align_spin: QSpinBox | None = None
        self._numeric_range_check: QCheckBox | None = None
        self._numeric_max_input: QLineEdit | None = None

        super().__init__(parent)

    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add hex editor controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        self._add_tool_button(toolbar, "Open", self._on_open_file)
        self._add_secondary_button(toolbar, "Save", self._on_save)
        self._add_secondary_button(toolbar, "Save As", self._on_save_as)
        toolbar.addSeparator()

        self._mode_label = QLabel("OVR")
        self._mode_label.setFixedWidth(30)
        toolbar.addWidget(self._mode_label)
        toolbar.addSeparator()

        self._offset_input = self._add_toolbar_input(toolbar, "Offset (hex)", max_width=100)
        self._add_secondary_button(toolbar, "Go", self._on_goto_offset)
        toolbar.addSeparator()

        self._search_input = self._add_toolbar_input(toolbar, "Search...", max_width=180)

        self._search_mode_combo = QComboBox()
        self._search_mode_combo.addItems(["Hex", "Text", "Regex", "Numeric"])
        self._search_mode_combo.setFixedWidth(80)
        toolbar.addWidget(self._search_mode_combo)

        self._add_secondary_button(toolbar, "Find", self._on_search)
        self._find_next_btn = self._add_secondary_button(toolbar, "Next", self._on_find_next)
        self._find_prev_btn = self._add_secondary_button(toolbar, "Prev", self._on_find_prev)
        toolbar.addSeparator()

        self._undo_btn = self._add_secondary_button(toolbar, "Undo", self._on_undo)
        self._redo_btn = self._add_secondary_button(toolbar, "Redo", self._on_redo)
        toolbar.addSeparator()

        self._encoding_combo = QComboBox()
        self._encoding_combo.setFixedWidth(120)
        for enc_entry in _ENCODING_ENTRIES:
            self._encoding_combo.addItem(enc_entry)
            if enc_entry.startswith("---"):
                idx = self._encoding_combo.count() - 1
                model = self._encoding_combo.model()
                if model is not None:
                    item = model.item(idx)
                    if item is not None:
                        item.setEnabled(False)
        toolbar.addWidget(self._encoding_combo)

        self._add_secondary_button(toolbar, "Send to AI", self._on_send_to_ai)
        toolbar.addSeparator()
        self._add_secondary_button(toolbar, "Pattern Editor", self._toggle_pattern_editor)

        self._file_info_label = QLabel("")
        toolbar.addWidget(self._file_info_label)

    def _create_content(self) -> QWidget:
        """Create the main content with hex widget, side panels, and pattern editor.

        Returns:
            QWidget: Vertical splitter containing hex editor area and pattern editor.
        """
        self._main_vsplit = QSplitter(Qt.Orientation.Vertical)

        hsplit = QSplitter(Qt.Orientation.Horizontal)

        self._hex_widget = HexEditorWidget()
        self._hex_widget.cursor_moved.connect(self._on_cursor_moved)
        self._hex_widget.data_changed.connect(self._on_data_changed)
        self._hex_widget.edit_mode_changed.connect(self._on_edit_mode_changed)
        hsplit.addWidget(self._hex_widget)

        self._side_tabs = QTabWidget()
        self._build_side_panels()
        hsplit.addWidget(self._side_tabs)

        hsplit.setStretchFactor(0, 3)
        hsplit.setStretchFactor(1, 1)

        self._main_vsplit.addWidget(hsplit)

        self._pattern_frame = self._build_pattern_editor()
        self._pattern_frame.setVisible(False)
        self._main_vsplit.addWidget(self._pattern_frame)

        self._numeric_search_frame = self._build_numeric_search_panel()
        self._numeric_search_frame.setVisible(False)
        self._main_vsplit.addWidget(self._numeric_search_frame)

        if self._search_mode_combo is not None:
            self._search_mode_combo.currentTextChanged.connect(self._on_search_mode_changed)

        self._setup_shortcuts()

        return self._main_vsplit

    def _setup_shortcuts(self) -> None:
        """Configure keyboard shortcuts for the hex editor panel."""
        sc_find = QShortcut(QKeySequence("Ctrl+F"), self)
        sc_find.activated.connect(self._focus_search)
        sc_goto = QShortcut(QKeySequence("Ctrl+G"), self)
        sc_goto.activated.connect(self._focus_goto)
        sc_save = QShortcut(QKeySequence("Ctrl+S"), self)
        sc_save.activated.connect(self._on_save)
        sc_find_next = QShortcut(QKeySequence("F3"), self)
        sc_find_next.activated.connect(self._on_find_next)
        sc_find_prev = QShortcut(QKeySequence("Shift+F3"), self)
        sc_find_prev.activated.connect(self._on_find_prev)
        sc_pattern = QShortcut(QKeySequence("Ctrl+Shift+P"), self)
        sc_pattern.activated.connect(self._toggle_pattern_editor)
        sc_compile = QShortcut(QKeySequence("Ctrl+Shift+B"), self)
        sc_compile.activated.connect(self._on_pattern_compile)
        sc_apply_pattern = QShortcut(QKeySequence("Ctrl+Shift+Return"), self)
        sc_apply_pattern.activated.connect(self._on_pattern_apply)

    def _focus_search(self) -> None:
        """Focus the search input field."""
        if self._search_input is not None:
            self._search_input.setFocus()
            self._search_input.selectAll()

    def _focus_goto(self) -> None:
        """Focus the goto-offset input field."""
        if self._offset_input is not None:
            self._offset_input.setFocus()
            self._offset_input.selectAll()

    def _build_side_panels(self) -> None:
        """Create all side panel tabs."""
        if self._side_tabs is None:
            return

        self._data_inspector_tree = self._make_tree(["Type", "Value"])
        self._side_tabs.addTab(self._data_inspector_tree, "Inspector")

        bookmarks_container = QWidget()
        bm_layout = QVBoxLayout(bookmarks_container)
        bm_layout.setContentsMargins(0, 0, 0, 0)
        self._bookmarks_tree = self._make_tree(["Offset", "Length", "Label"])
        bm_layout.addWidget(self._bookmarks_tree)
        bm_btn_layout = QHBoxLayout()
        add_bm_btn = QPushButton("Add")
        add_bm_btn.clicked.connect(self._on_add_bookmark)
        bm_btn_layout.addWidget(add_bm_btn)
        rm_bm_btn = QPushButton("Remove")
        rm_bm_btn.clicked.connect(self._on_remove_bookmark)
        bm_btn_layout.addWidget(rm_bm_btn)
        bm_layout.addLayout(bm_btn_layout)
        self._side_tabs.addTab(bookmarks_container, "Bookmarks")

        self._sections_tree = self._make_tree(["Name", "VAddr", "VSize", "RawSize"])
        self._side_tabs.addTab(self._sections_tree, "Sections")

        self._imports_tree = self._make_tree(["Library", "Function", "Address"])
        self._side_tabs.addTab(self._imports_tree, "Imports")

        self._exports_tree = self._make_tree(["Name", "Address", "Ordinal"])
        self._side_tabs.addTab(self._exports_tree, "Exports")

        self._strings_tree = self._make_tree(["Offset", "Length", "String"])
        self._side_tabs.addTab(self._strings_tree, "Strings")

        stats_container = QWidget()
        stats_layout = QVBoxLayout(stats_container)
        stats_layout.setContentsMargins(2, 2, 2, 2)
        stats_layout.setSpacing(4)
        self._entropy_graph = EntropyGraphWidget()
        self._entropy_graph.block_clicked.connect(self.goto_offset)
        stats_layout.addWidget(self._entropy_graph)
        dist_header = QHBoxLayout()
        dist_header.addWidget(QLabel("Byte Distribution"))
        log_btn = QPushButton("Log Scale")
        log_btn.setFixedWidth(70)
        log_btn.setCheckable(True)
        self._byte_dist_widget = ByteDistributionWidget()
        dist_ref = self._byte_dist_widget
        log_btn.toggled.connect(lambda _checked: dist_ref.toggle_log_scale())
        dist_header.addWidget(log_btn)
        stats_layout.addLayout(dist_header)
        stats_layout.addWidget(self._byte_dist_widget)
        summary_box = QGroupBox("Summary")
        summary_form = QFormLayout(summary_box)
        self._entropy_label = QLabel("\u2014")
        summary_form.addRow("Overall entropy:", self._entropy_label)
        self._null_pct_label = QLabel("\u2014")
        summary_form.addRow("Null bytes:", self._null_pct_label)
        self._printable_pct_label = QLabel("\u2014")
        summary_form.addRow("Printable:", self._printable_pct_label)
        self._control_pct_label = QLabel("\u2014")
        summary_form.addRow("Control:", self._control_pct_label)
        self._high_pct_label = QLabel("\u2014")
        summary_form.addRow("High bytes:", self._high_pct_label)
        self._classification_label = QLabel("\u2014")
        summary_form.addRow("Classification:", self._classification_label)
        stats_layout.addWidget(summary_box)
        self._statistics_tree = self._make_tree(["Byte", "Count", "Percentage"])
        stats_layout.addWidget(self._statistics_tree)
        self._side_tabs.addTab(stats_container, "Statistics")

        templates_container = QWidget()
        tmpl_layout = QVBoxLayout(templates_container)
        tmpl_layout.setContentsMargins(0, 0, 0, 0)
        tmpl_top = QHBoxLayout()
        self._template_combo = QComboBox()
        tmpl_top.addWidget(self._template_combo)
        tmpl_apply_btn = QPushButton("Apply")
        tmpl_apply_btn.clicked.connect(self._on_apply_template)
        tmpl_top.addWidget(tmpl_apply_btn)
        tmpl_layout.addLayout(tmpl_top)
        self._templates_tree = self._make_tree(["Field", "Offset", "Size", "Value"])
        tmpl_layout.addWidget(self._templates_tree)
        self._side_tabs.addTab(templates_container, "Templates")

        patches_container = QWidget()
        patches_layout = QVBoxLayout(patches_container)
        patches_layout.setContentsMargins(0, 0, 0, 0)
        self._patches_tree = self._make_tree(["Offset", "Original", "New"])
        patches_layout.addWidget(self._patches_tree)
        patches_btn_layout = QHBoxLayout()
        export_patches_btn = QPushButton("Export Patches...")
        export_patches_btn.clicked.connect(self._on_export_patches)
        patches_btn_layout.addWidget(export_patches_btn)
        import_patches_btn = QPushButton("Import Patches...")
        import_patches_btn.clicked.connect(self._on_import_patches)
        patches_btn_layout.addWidget(import_patches_btn)
        patches_layout.addLayout(patches_btn_layout)
        self._side_tabs.addTab(patches_container, "Patches")

        hashes_container = QWidget()
        hashes_layout = QVBoxLayout(hashes_container)
        hashes_layout.setContentsMargins(4, 4, 4, 4)
        hashes_layout.setSpacing(6)
        hash_row = QHBoxLayout()
        self._hash_algo_combo = QComboBox()
        self._hash_algo_combo.addItems(_HASH_ALGORITHMS)
        hash_row.addWidget(self._hash_algo_combo)
        hash_calc_btn = QPushButton("Calculate")
        hash_calc_btn.clicked.connect(self._on_calculate_hash)
        hash_row.addWidget(hash_calc_btn)
        custom_crc_btn = QPushButton("Custom CRC...")
        custom_crc_btn.clicked.connect(self._on_custom_crc)
        hash_row.addWidget(custom_crc_btn)
        hashes_layout.addLayout(hash_row)
        self._hash_result_label = QLabel("")
        self._hash_result_label.setWordWrap(True)
        self._hash_result_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        hashes_layout.addWidget(self._hash_result_label)
        hashes_layout.addStretch()
        self._side_tabs.addTab(hashes_container, "Hashes")

        self._side_tabs.addTab(self._create_disassembly_tab(), "Disassembly")
        self._side_tabs.addTab(self._create_yara_tab(), "YARA")
        self._side_tabs.addTab(self._create_transforms_tab(), "Transforms")

    @staticmethod
    def _make_tree(headers: list[str]) -> QTreeWidget:
        """Create a QTreeWidget with the given column headers.

        Args:
            headers: Column header labels.

        Returns:
            QTreeWidget: Configured QTreeWidget.
        """
        tree = QTreeWidget()
        tree.setHeaderLabels(headers)
        tree.setRootIsDecorated(False)
        tree.setAlternatingRowColors(True)
        return tree

    def load_file(self, file_path: Path | str) -> bool:
        """Load a binary file into the hex editor.

        Args:
            file_path: Path to the file to open.

        Returns:
            bool: True if the file was loaded successfully.
        """
        if not _hexcore_available or _hexcore is None:
            QMessageBox.warning(
                self,
                "Hex Core Not Available",
                "The intellicrack_hexcore Rust extension is not installed.\n"
                "Build it with: cd src/intellicrack-hexcore && maturin develop --release",
            )
            return False

        path = Path(file_path) if isinstance(file_path, str) else file_path

        try:
            self._document = _hexcore.HexDocument.open(str(path))
            self._file_path = path

            if self._hex_widget is not None:
                set_doc = getattr(self._hex_widget, "set_document", None)
                if callable(set_doc):
                    set_doc(self._document)

            if self._document is None:
                return False
            doc_len: int = self._document.length()
            if self._file_info_label is not None:
                self._file_info_label.setText(f"  {path.name} ({_format_size(doc_len)})")

            self._populate_template_combo()
            self._auto_detect_file_type()
            self._populate_sections()
            self._populate_imports()
            self._populate_exports()
            self._populate_strings()
            self._update_statistics()
            self._original_data_cache.clear()
            self._search_results.clear()
            self._search_index = 0

            if self._state_holder is not None:
                self._state_holder.set_document(self._document, path, source="panel")

        except Exception as exc:
            _logger.warning("file_load_failed", path=str(path), error=str(exc))
            QMessageBox.warning(self, "Load Failed", f"Failed to open file:\n{exc}")
            return False
        else:
            _logger.info("file_loaded", path=str(path), size=doc_len)
            return True

    def _on_cursor_moved(self, offset: int) -> None:
        """Handle cursor movement to update side panels.

        Args:
            offset: New cursor byte offset.
        """
        self._update_data_inspector(offset)
        self._on_cursor_moved_disasm(offset)

    def _on_data_changed(self) -> None:
        """Handle data modification events."""
        if self._document is not None and self._file_info_label is not None:
            modified_mark = " *" if self._document.is_modified() else ""
            name = self._file_path.name if self._file_path is not None else "untitled"
            size = self._document.length()
            self._file_info_label.setText(f"  {name}{modified_mark} ({_format_size(size)})")
        self._update_patches()

    def _on_edit_mode_changed(self, mode: str) -> None:
        """Handle edit mode toggle.

        Args:
            mode: New mode string ("overwrite" or "insert").
        """
        if self._mode_label is not None:
            self._mode_label.setText("INS" if mode == "insert" else "OVR")

    def _update_data_inspector(self, offset: int) -> None:
        """Update the data inspector tree for the given offset.

        Args:
            offset: Byte offset to inspect.
        """
        if self._data_inspector_tree is None or self._document is None:
            return

        self._data_inspector_tree.clear()
        try:
            result = self._document.inspect_at(offset)
            if not isinstance(result, dict):
                return
            typed_result = cast("dict[str, object]", result)

            display_order = [
                "int8",
                "uint8",
                "ascii_char",
                "utf8_char",
                "int16_le",
                "uint16_le",
                "int16_be",
                "uint16_be",
                "int32_le",
                "uint32_le",
                "int32_be",
                "uint32_be",
                "float32_le",
                "float32_be",
                "int64_le",
                "uint64_le",
                "int64_be",
                "uint64_be",
                "float64_le",
                "float64_be",
                "unix_timestamp",
                "dos_date",
                "dos_time",
                "filetime",
            ]

            for key in display_order:
                if key in typed_result:
                    item = QTreeWidgetItem([key, str(typed_result[key])])
                    self._data_inspector_tree.addTopLevelItem(item)

            for key, val in sorted(typed_result.items()):
                if key not in display_order:
                    item = QTreeWidgetItem([key, str(val)])
                    self._data_inspector_tree.addTopLevelItem(item)

        except Exception as exc:
            _logger.debug("inspector_update_failed", error=str(exc))

    def _on_open_file(self) -> None:
        """Open a file selection dialog and load the chosen file."""
        file_path_result = QFileDialog.getOpenFileName(
            self,
            "Open Binary File",
            "",
            "All Files (*)",
        )
        file_path_str = file_path_result[0] if file_path_result else ""
        if file_path_str:
            self.load_file(file_path_str)

    def _on_save(self) -> None:
        """Save the current document."""
        if self._document is None:
            return
        try:
            file_path = self._document.file_path()
            if file_path is not None:
                self._document.save(file_path)
            else:
                self._on_save_as()
                return
        except Exception as exc:
            QMessageBox.warning(self, "Save Failed", f"Failed to save:\n{exc}")
        else:
            self._on_data_changed()
            _logger.info("file_saved", path=file_path)

    def _on_save_as(self) -> None:
        """Save the current document to a new path."""
        if self._document is None:
            return
        result = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*)")
        save_path = result[0] if result else ""
        if save_path:
            try:
                self._document.save(save_path)
            except Exception as exc:
                QMessageBox.warning(self, "Save Failed", f"Failed to save:\n{exc}")
            else:
                self._file_path = Path(save_path)
                self._on_data_changed()
                _logger.info("file_saved_as", path=save_path)

    def _on_goto_offset(self) -> None:
        """Navigate to the offset entered in the toolbar input."""
        if self._offset_input is None or self._hex_widget is None:
            return
        text = self._offset_input.text().strip()
        if not text:
            return
        goto_fn = getattr(self._hex_widget, "goto_offset", None)
        if not callable(goto_fn):
            return
        try:
            offset = int(text, 16) if text.lower().startswith("0x") else int(text)
        except ValueError:
            _logger.debug("invalid_offset_input", text=text)
        else:
            goto_fn(offset)

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

        try:
            if mode == "Hex":
                raw_results = self._document.search_hex(query, _MAX_SEARCH_RESULTS)
                results: list[tuple[int, int]] = [(r[0], r[1]) for r in raw_results]
            elif mode == "Text":
                encoding = "utf-8"
                if self._encoding_combo is not None:
                    enc_text = self._encoding_combo.currentText()
                    encoding = enc_text.lower().replace("-", "")
                raw_results = self._document.search_text(query, encoding, True, _MAX_SEARCH_RESULTS)
                results = [(r[0], r[1]) for r in raw_results]
            elif mode == "Regex":
                raw_results = self._document.search_regex(query, _MAX_SEARCH_RESULTS)
                results = [(r[0], r[1]) for r in raw_results]
            else:
                results = []
        except Exception as exc:
            _logger.debug("search_failed", error=str(exc))
        else:
            self._search_results = results
            self._search_index = 0

            if results and self._hex_widget is not None:
                goto_fn = getattr(self._hex_widget, "goto_offset", None)
                if callable(goto_fn):
                    goto_fn(results[0][0])

                highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
                if callable(highlight_fn):
                    highlights = [(off, length, "#FFAA00") for off, length in results]
                    highlight_fn(highlights)

            _logger.info("search_completed", mode=mode, result_count=len(results))

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

    def _on_send_to_ai(self) -> None:
        """Emit context for AI analysis from the current hex editor state."""
        if self._document is None:
            return

        context: dict[str, Any] = {
            "file_path": str(self._file_path) if self._file_path else None,
            "size": self._document.length(),
        }
        context["modified"] = self._document.is_modified()

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
        context["cursor"] = cursor_offset

        try:
            read_start = max(0, cursor_offset - _CURSOR_CONTEXT_BYTES)
            read_len = min(_PREVIEW_BYTES, self._document.length() - read_start)
            raw = self._document.read(read_start, read_len) if read_len > 0 else None
        except Exception:
            _logger.debug("ai_context_bytes_read_failed")
        else:
            if raw is not None:
                context["bytes_at_cursor"] = " ".join(f"{b:02X}" for b in raw)
                context["bytes_offset"] = read_start

        try:
            inspection = self._document.inspect_at(cursor_offset)
        except Exception:
            _logger.debug("ai_context_inspection_failed")
        else:
            if isinstance(inspection, dict):
                context["inspection"] = {k: str(v) for k, v in cast("dict[str, object]", inspection).items()}

        self.context_push_requested.emit(context)

    def _on_undo(self) -> None:
        """Undo the last edit operation."""
        if self._document is not None:
            self._document.undo()
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()

    def _on_redo(self) -> None:
        """Redo the last undone operation."""
        if self._document is not None:
            self._document.redo()
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()

    def _on_apply_template(self) -> None:
        """Apply the selected struct template at the current cursor offset."""
        if self._document is None or self._template_combo is None or self._templates_tree is None:
            return

        template_name = self._template_combo.currentText()
        if not template_name:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            result = self._document.apply_template(template_name, cursor_offset)
        except Exception as exc:
            _logger.debug("template_apply_failed", error=str(exc))
        else:
            self._templates_tree.clear()

            if isinstance(result, list):
                typed_fields = cast("list[dict[str, object]]", result)
                self._populate_template_tree(typed_fields)
                self._highlight_template_fields(typed_fields)

            _logger.info("template_applied", template=template_name)

    def _populate_template_tree(self, fields: list[dict[str, object]]) -> None:
        """Populate the templates tree with parsed field data.

        Args:
            fields: List of field dictionaries from the template engine.
        """
        if self._templates_tree is None:
            return

        for field_data in fields:
            item = QTreeWidgetItem([
                str(field_data.get("name", "")),
                str(field_data.get("offset", "")),
                str(field_data.get("size", "")),
                str(field_data.get("display_value", "")),
            ])
            self._templates_tree.addTopLevelItem(item)

            children_raw = field_data.get("children")
            if not isinstance(children_raw, list):
                continue
            children = cast("list[dict[str, object]]", children_raw)
            for child in children:
                child_item = QTreeWidgetItem([
                    str(child.get("name", "")),
                    str(child.get("offset", "")),
                    str(child.get("size", "")),
                    str(child.get("display_value", "")),
                ])
                item.addChild(child_item)

    def _highlight_template_fields(self, fields: list[dict[str, object]]) -> None:
        """Apply highlight overlays for template field regions.

        Args:
            fields: List of field dictionaries from the template engine.
        """
        if self._hex_widget is None:
            return

        highlights: list[tuple[int, int, str]] = []
        for field_data in fields:
            f_offset = field_data.get("offset")
            f_size = field_data.get("size")
            if isinstance(f_offset, int) and isinstance(f_size, int):
                highlights.append((f_offset, f_size, "#44FF44"))

        highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
        if callable(highlight_fn):
            highlight_fn(highlights)

    def _on_add_bookmark(self) -> None:
        """Add a bookmark at the current cursor position."""
        if self._document is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        self._document.add_bookmark(cursor_offset, 1, "Bookmark", "#FFFF00")
        self._refresh_bookmarks()

    def _on_remove_bookmark(self) -> None:
        """Remove the selected bookmark."""
        if self._document is None or self._bookmarks_tree is None:
            return

        current = self._bookmarks_tree.currentItem()
        if current is None:
            return

        index = self._bookmarks_tree.indexOfTopLevelItem(current)
        if index >= 0:
            self._document.remove_bookmark(index)
            self._refresh_bookmarks()

    def _refresh_bookmarks(self) -> None:
        """Refresh the bookmarks tree from the document."""
        if self._bookmarks_tree is None or self._document is None:
            return

        self._bookmarks_tree.clear()
        bookmarks = self._document.list_bookmarks()
        for bm in bookmarks:
            offset_str = f"0x{bm[0]:08X}"
            length_str = str(bm[1])
            label = str(bm[2])
            item = QTreeWidgetItem([offset_str, length_str, label])
            self._bookmarks_tree.addTopLevelItem(item)

    def _populate_template_combo(self) -> None:
        """Populate the template combo box with available templates."""
        if self._template_combo is None or self._document is None:
            return

        self._template_combo.clear()
        templates = self._document.list_templates()
        for name, _description in templates:
            self._template_combo.addItem(str(name))

    def _populate_sections(self) -> None:
        """Populate the sections tree using pefile."""
        if self._sections_tree is None or self._file_path is None:
            return

        self._sections_tree.clear()

        if not _pefile_available or pefile is None:
            _logger.debug("pefile_not_available")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
        except Exception as exc:
            _logger.debug("sections_parse_failed", error=str(exc))
            return

        try:
            sections = getattr(pe, "sections", None)
            if sections is not None:
                for section in sections:
                    name = section.Name.decode("utf-8", errors="replace").rstrip("\x00")
                    vaddr = f"0x{section.VirtualAddress:08X}"
                    vsize = f"0x{section.Misc_VirtualSize:08X}"
                    rawsize = f"0x{section.SizeOfRawData:08X}"
                    item = QTreeWidgetItem([name, vaddr, vsize, rawsize])
                    self._sections_tree.addTopLevelItem(item)
        except Exception as exc:
            _logger.debug("sections_parse_failed", error=str(exc))
        finally:
            pe.close()

    def _populate_imports(self) -> None:
        """Populate the imports tree using pefile."""
        if self._imports_tree is None or self._file_path is None:
            return

        self._imports_tree.clear()

        if not _pefile_available or pefile is None:
            _logger.debug("pefile_not_available_for_imports")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
        except Exception as exc:
            _logger.debug("imports_parse_failed", error=str(exc))
            return

        try:
            dir_entry: dict[str, int] = getattr(pefile, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry.get("IMAGE_DIRECTORY_ENTRY_IMPORT", 1)])
            import_dir = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
            if import_dir is not None:
                for entry in import_dir:
                    dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else "unknown"
                    for imp in entry.imports:
                        func_name = imp.name.decode("utf-8", errors="replace") if imp.name else f"Ordinal {imp.ordinal}"
                        addr = f"0x{imp.address:08X}" if imp.address else "N/A"
                        item = QTreeWidgetItem([dll_name, func_name, addr])
                        self._imports_tree.addTopLevelItem(item)
        except Exception as exc:
            _logger.debug("imports_parse_failed", error=str(exc))
        finally:
            pe.close()

    def _populate_exports(self) -> None:
        """Populate the exports tree using pefile."""
        if self._exports_tree is None or self._file_path is None:
            return

        self._exports_tree.clear()

        if not _pefile_available or pefile is None:
            _logger.debug("pefile_not_available_for_exports")
            return

        try:
            pe = pefile.PE(str(self._file_path), fast_load=True)
        except Exception as exc:
            _logger.debug("exports_parse_failed", error=str(exc))
            return

        try:
            dir_entry_exp: dict[str, int] = getattr(pefile, "DIRECTORY_ENTRY", {})
            pe.parse_data_directories(directories=[dir_entry_exp.get("IMAGE_DIRECTORY_ENTRY_EXPORT", 0)])
            export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if export_dir is not None:
                symbols = getattr(export_dir, "symbols", None)
                if symbols is not None:
                    for exp in symbols:
                        name = exp.name.decode("utf-8", errors="replace") if exp.name else f"Ordinal {exp.ordinal}"
                        addr = f"0x{exp.address:08X}" if exp.address else "N/A"
                        ordinal = str(exp.ordinal) if exp.ordinal is not None else "N/A"
                        item = QTreeWidgetItem([name, addr, ordinal])
                        self._exports_tree.addTopLevelItem(item)
        except Exception as exc:
            _logger.debug("exports_parse_failed", error=str(exc))
        finally:
            pe.close()

    def _update_statistics(self) -> None:
        """Update the statistics tab with entropy graph, histogram, and byte tree."""
        if self._document is None:
            return

        if self._statistics_tree is not None:
            self._statistics_tree.clear()

        try:
            stats = self._document.byte_statistics()
            total = sum(s[1] for s in stats)
        except Exception as exc:
            _logger.debug("statistics_update_failed", error=str(exc))
            return

        if total == 0:
            return

        entropy = 0.0
        for _byte_val, count in stats:
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)

        if self._statistics_tree is not None:
            entropy_item = QTreeWidgetItem(["Entropy", f"{entropy:.4f}", "bits/byte"])
            self._statistics_tree.addTopLevelItem(entropy_item)
            for byte_val, count in stats:
                if count > 0:
                    pct = f"{(count / total) * 100:.2f}%"
                    item = QTreeWidgetItem([f"0x{byte_val:02X}", str(count), pct])
                    self._statistics_tree.addTopLevelItem(item)

        if self._entropy_label is not None:
            self._entropy_label.setText(f"{entropy:.4f} bits/byte")

        entropy_map_fn = getattr(self._document, "entropy_map", None)
        if callable(entropy_map_fn):
            try:
                raw_map = entropy_map_fn(_ENTROPY_BLOCK_SIZE)
            except Exception as exc:
                _logger.debug("entropy_map_failed", error=str(exc))
            else:
                entropy_values: list[float] = [float(v) for v in raw_map] if raw_map else []
                if self._entropy_graph is not None:
                    self._entropy_graph.set_data(entropy_values, _ENTROPY_BLOCK_SIZE)

        dist_fn = getattr(self._document, "byte_distribution_full", None)
        if callable(dist_fn):
            try:
                raw_dist = dist_fn()
            except Exception as exc:
                _logger.debug("byte_distribution_failed", error=str(exc))
            else:
                dist_counts: list[int] = [int(v) for v in raw_dist] if raw_dist else [0] * _BYTE_VALUES_COUNT
                if self._byte_dist_widget is not None:
                    self._byte_dist_widget.set_data(dist_counts)

        type_fn = getattr(self._document, "byte_type_distribution", None)
        if callable(type_fn):
            try:
                type_dist = type_fn()
            except Exception as exc:
                _logger.debug("byte_type_distribution_failed", error=str(exc))
            else:
                if isinstance(type_dist, tuple) and len(type_dist) >= _BYTE_TYPE_DIST_MIN_LEN:
                    null_c = int(type_dist[0])
                    printable_c = int(type_dist[1])
                    control_c = int(type_dist[2])
                    high_c = int(type_dist[3])
                    total_b = max(null_c + printable_c + control_c + high_c, 1)
                    if self._null_pct_label is not None:
                        self._null_pct_label.setText(f"{null_c / total_b * 100:.1f}% ({null_c})")
                    if self._printable_pct_label is not None:
                        self._printable_pct_label.setText(f"{printable_c / total_b * 100:.1f}% ({printable_c})")
                    if self._control_pct_label is not None:
                        self._control_pct_label.setText(f"{control_c / total_b * 100:.1f}% ({control_c})")
                    if self._high_pct_label is not None:
                        self._high_pct_label.setText(f"{high_c / total_b * 100:.1f}% ({high_c})")

        class_fn = getattr(self._document, "content_classification", None)
        if callable(class_fn):
            try:
                classification = class_fn(_ENTROPY_BLOCK_SIZE)
            except Exception as exc:
                _logger.debug("content_classification_failed", error=str(exc))
            else:
                if isinstance(classification, list):
                    class_names = {0: "null", 1: "text", 2: "structured", 3: "encrypted", 4: "code"}
                    counts: dict[str, int] = {}
                    for c_val in classification:
                        label = class_names.get(int(c_val), "unknown")
                        counts[label] = counts.get(label, 0) + 1
                    parts = [f"{k}: {v}" for k, v in counts.items()]
                    if self._classification_label is not None:
                        self._classification_label.setText(", ".join(parts))

    def goto_offset(self, offset: int) -> None:
        """Navigate the hex widget to a specific offset.

        Args:
            offset: Target byte offset.
        """
        if self._hex_widget is not None:
            goto_fn = getattr(self._hex_widget, "goto_offset", None)
            if callable(goto_fn):
                goto_fn(offset)

    def set_state_holder(self, state_holder: HexDocumentState) -> None:
        """Attach a shared state holder for bridge-GUI synchronization.

        Args:
            state_holder: The shared HexDocumentState instance.
        """
        self._state_holder = state_holder

        def on_state_event(event_type: Any, data: dict[str, Any]) -> None:
            evt = _HexDocumentEvent
            if evt is None:
                return
            if event_type == evt.DOCUMENT_OPENED:
                file_path_str = data.get("file_path")
                if file_path_str and self._document is None:
                    self.load_file(file_path_str)
            elif event_type == evt.CURSOR_MOVED:
                offset = data.get("offset", 0)
                if self._hex_widget is not None:
                    goto_fn = getattr(self._hex_widget, "goto_offset", None)
                    if callable(goto_fn):
                        goto_fn(offset)
                self._update_data_inspector(offset)
            elif event_type == evt.DATA_MODIFIED:
                if self._hex_widget is not None:
                    update_fn = getattr(self._hex_widget, "_update_viewport", None)
                    if callable(update_fn):
                        update_fn()
                self._on_data_changed()
            elif event_type == evt.SELECTION_CHANGED:
                start = data.get("start", -1)
                end = data.get("end", -1)
                if self._hex_widget is not None and start >= 0 and end >= 0:
                    widget = self._hex_widget
                    widget._selection_start = start
                    widget._selection_end = end
                    update_fn = getattr(widget, "_update_viewport", None)
                    if callable(update_fn):
                        update_fn()
            elif event_type == evt.TEMPLATE_REGISTERED:
                self._populate_template_combo()

        state_holder.register_callback(on_state_event, source_id="panel")

    def _auto_detect_file_type(self) -> None:
        """Detect the file type from magic bytes and auto-select the template."""
        if self._document is None or self._template_combo is None:
            return

        try:
            magic_raw: object = self._document.read(0, 4)
        except Exception as exc:
            _logger.debug("auto_detect_failed", error=str(exc))
            return

        if isinstance(magic_raw, bytes):
            magic = magic_raw
        elif isinstance(magic_raw, bytearray):
            magic = bytes(magic_raw)
        elif isinstance(magic_raw, list):
            magic_list = cast("list[int]", magic_raw)
            magic = bytes(magic_list)
        else:
            magic = b""

        detected = ""
        pe_magic = b"\x4d\x5a"
        elf_magic = b"\x7fELF"
        zip_magic = b"\x50\x4b\x03\x04"
        macho_magics = {
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
        }
        if len(magic) >= len(pe_magic) and magic[:2] == pe_magic:
            detected = "PE"
            self._select_template("IMAGE_DOS_HEADER")
        elif len(magic) >= len(elf_magic) and magic[:4] == elf_magic:
            detected = "ELF"
            self._select_template("ELF_HEADER_64")
        elif len(magic) >= len(elf_magic) and magic[:4] in macho_magics:
            detected = "Mach-O"
            self._select_template("MACH_HEADER_64")
        elif len(magic) >= len(zip_magic) and magic[:4] == zip_magic:
            detected = "ZIP"
            self._select_template("ZIP_LOCAL_FILE_HEADER")

        if detected and self._file_info_label is not None:
            current = self._file_info_label.text()
            self._file_info_label.setText(f"{current} [{detected}]")

    def _select_template(self, template_name: str) -> None:
        """Select a template by name in the combo box.

        Args:
            template_name: Template name to select.
        """
        if self._template_combo is None:
            return
        idx = self._template_combo.findText(template_name)
        if idx >= 0:
            self._template_combo.setCurrentIndex(idx)

    def _populate_strings(self) -> None:
        """Scan the document for printable ASCII strings and populate the strings tab."""
        if self._strings_tree is None or self._document is None:
            return

        self._strings_tree.clear()
        chunk_size = 65536
        min_string_len = 4
        max_strings = 5000
        max_display_len = _PREVIEW_BYTES

        doc_len: int = self._document.length()
        string_count = 0
        current_string_start = -1
        current_chars: list[str] = []
        offset = 0

        while offset < doc_len and string_count < max_strings:
            chunk_len = min(chunk_size, doc_len - offset)
            raw = self._document.read(offset, chunk_len)
            if isinstance(raw, (list, bytearray)):
                raw = bytes(raw)

            for i, byte_val in enumerate(raw):
                abs_offset = offset + i
                if _PRINTABLE_MIN <= byte_val <= _PRINTABLE_MAX:
                    if current_string_start < 0:
                        current_string_start = abs_offset
                    current_chars.append(chr(byte_val))
                else:
                    if len(current_chars) >= min_string_len:
                        string_val = "".join(current_chars)
                        display = string_val[:max_display_len]
                        item = QTreeWidgetItem([
                            f"0x{current_string_start:08X}",
                            str(len(string_val)),
                            display,
                        ])
                        self._strings_tree.addTopLevelItem(item)
                        string_count += 1
                        if string_count >= max_strings:
                            break
                    current_string_start = -1
                    current_chars.clear()

            offset += chunk_len

        if len(current_chars) >= min_string_len and string_count < max_strings:
            string_val = "".join(current_chars)
            display = string_val[:max_display_len]
            item = QTreeWidgetItem([
                f"0x{current_string_start:08X}",
                str(len(string_val)),
                display,
            ])
            self._strings_tree.addTopLevelItem(item)

        self._strings_tree.itemDoubleClicked.connect(self._on_string_double_clicked)

    def _on_string_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the string offset when double-clicked.

        Args:
            item: The clicked tree item.
            column: The clicked column index.
        """
        _ = column
        offset_text = item.text(0)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            pass
        else:
            self.goto_offset(offset)

    def _update_patches(self) -> None:
        """Update the patches tree by comparing modified offsets to originals."""
        if self._patches_tree is None or self._document is None or self._hex_widget is None:
            return

        modified_offsets: set[int] = getattr(self._hex_widget, "_modified_offsets", set())
        if not modified_offsets:
            return

        for off in sorted(modified_offsets):
            if off not in self._original_data_cache:
                continue

            original_byte = self._original_data_cache[off]
            current_byte: int = -1
            try:
                raw_patch: object = self._document.read(off, 1)
                if (isinstance(raw_patch, bytes) and len(raw_patch) > 0) or (isinstance(raw_patch, bytearray) and len(raw_patch) > 0):
                    current_byte = raw_patch[0]
                elif isinstance(raw_patch, list):
                    if patch_list := cast("list[int]", raw_patch):
                        current_byte = patch_list[0]
            except Exception:
                _logger.debug("patch_read_failed", offset=off)
                continue

            if current_byte < 0:
                continue

            if current_byte != original_byte:
                existing = False
                for i in range(self._patches_tree.topLevelItemCount()):
                    tree_item = self._patches_tree.topLevelItem(i)
                    if tree_item is not None and tree_item.text(0) == f"0x{off:08X}":
                        tree_item.setText(2, f"0x{current_byte:02X}")
                        existing = True
                        break
                if not existing:
                    patch_item = QTreeWidgetItem([
                        f"0x{off:08X}",
                        f"0x{original_byte:02X}",
                        f"0x{current_byte:02X}",
                    ])
                    self._patches_tree.addTopLevelItem(patch_item)

    def _cache_original_byte(self, offset: int) -> None:
        """Cache the original byte value before first modification.

        Args:
            offset: Byte offset to cache.
        """
        if offset in self._original_data_cache or self._document is None:
            return
        try:
            raw = self._document.read(offset, 1)
        except Exception:
            _logger.debug("cache_original_byte_failed", offset=offset)
        else:
            if isinstance(raw, (list, bytes, bytearray)):
                self._original_data_cache[offset] = raw[0] if raw else 0

    def _build_pattern_editor(self) -> QFrame:
        """Build the collapsible pattern editor panel.

        Returns:
            QFrame: Frame containing the pattern editor UI.
        """
        frame = QFrame()
        frame_layout = QHBoxLayout(frame)
        frame_layout.setContentsMargins(2, 2, 2, 2)

        editor_splitter = QSplitter(Qt.Orientation.Horizontal)

        self._pattern_library_tree = QTreeWidget()
        self._pattern_library_tree.setHeaderLabels(["Templates"])
        self._pattern_library_tree.setMaximumWidth(200)
        self._pattern_library_tree.itemClicked.connect(self._on_pattern_library_clicked)
        editor_splitter.addWidget(self._pattern_library_tree)

        right_area = QWidget()
        right_layout = QVBoxLayout(right_area)
        right_layout.setContentsMargins(0, 0, 0, 0)

        editor_tabs = QTabWidget()

        self._pattern_dsl_editor = QPlainTextEdit()
        self._pattern_dsl_editor.setPlainText(
            "struct MY_HEADER {\n"
            "    le u16 magic [[validate(0x5A4D)]];\n"
            "    le u32 size;\n"
            "};\n"
        )
        font = self._pattern_dsl_editor.font()
        font.setFamily("Consolas")
        font.setPointSize(10)
        self._pattern_dsl_editor.setFont(font)
        HexPatSyntaxHighlighter(self._pattern_dsl_editor.document())
        editor_tabs.addTab(self._pattern_dsl_editor, "DSL")

        self._pattern_json_preview = QPlainTextEdit()
        self._pattern_json_preview.setReadOnly(True)
        self._pattern_json_preview.setFont(font)
        editor_tabs.addTab(self._pattern_json_preview, "JSON")

        right_layout.addWidget(editor_tabs, stretch=3)

        action_bar = QHBoxLayout()
        compile_btn = QPushButton("Compile")
        compile_btn.clicked.connect(self._on_pattern_compile)
        action_bar.addWidget(compile_btn)

        apply_btn = QPushButton("Apply at Cursor")
        apply_btn.clicked.connect(self._on_pattern_apply)
        action_bar.addWidget(apply_btn)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._on_pattern_save)
        action_bar.addWidget(save_btn)

        open_btn = QPushButton("Open")
        open_btn.clicked.connect(self._on_pattern_open)
        action_bar.addWidget(open_btn)

        new_btn = QPushButton("New")
        new_btn.clicked.connect(self._on_pattern_new)
        action_bar.addWidget(new_btn)

        self._pattern_status_label = QLabel("")
        action_bar.addWidget(self._pattern_status_label)
        action_bar.addStretch()

        right_layout.addLayout(action_bar)

        self._pattern_error_display = QPlainTextEdit()
        self._pattern_error_display.setReadOnly(True)
        self._pattern_error_display.setMaximumHeight(60)
        right_layout.addWidget(self._pattern_error_display)

        editor_splitter.addWidget(right_area)
        editor_splitter.setStretchFactor(0, 1)
        editor_splitter.setStretchFactor(1, 4)

        frame_layout.addWidget(editor_splitter)
        return frame

    def _toggle_pattern_editor(self) -> None:
        """Toggle the pattern editor panel visibility."""
        self._pattern_visible = not self._pattern_visible
        if self._pattern_frame is not None:
            self._pattern_frame.setVisible(self._pattern_visible)
        if self._pattern_visible and self._main_vsplit is not None:
            total = self._main_vsplit.height()
            n = self._main_vsplit.count()
            numeric_panel_idx = 2
            numeric_size = self._main_vsplit.sizes()[numeric_panel_idx] if n > numeric_panel_idx else 0
            remaining = total - numeric_size
            tail = [numeric_size] if n > numeric_panel_idx else []
            sizes = [
                int(remaining * _SPLITTER_MAIN_RATIO),
                int(remaining * _SPLITTER_PATTERN_RATIO),
                *tail,
            ]
            self._main_vsplit.setSizes(sizes)
            self._populate_pattern_library()

    def _on_pattern_compile(self) -> None:
        """Compile the DSL source to JSON and show in preview."""
        if self._pattern_dsl_editor is None:
            return

        source = self._pattern_dsl_editor.toPlainText()
        if not source.strip():
            return

        if not _hexpat_available or _hexpat_mod is None:
            if self._pattern_error_display is not None:
                self._pattern_error_display.setPlainText("HexPat compiler not available")
            return

        compiler_cls: type[Any] | None = getattr(_hexpat_mod, "HexPatCompiler", None)
        error_cls: type[Any] | None = getattr(_hexpat_mod, "HexPatError", None)
        if compiler_cls is None:
            return

        try:
            compiler_inst: Any = compiler_cls()
            compiled: str = compiler_inst.compile(source)
        except Exception as exc:
            is_hexpat_error = error_cls is not None and isinstance(exc, error_cls)
            self._compiled_json = ""
            if is_hexpat_error:
                line_num = getattr(exc, "line", 0)
                col_num = getattr(exc, "column", 0)
                msg = getattr(exc, "message", str(exc))
                if self._pattern_error_display is not None:
                    self._pattern_error_display.setPlainText(
                        f"Line {line_num}, Col {col_num}: {msg}"
                    )
            elif self._pattern_error_display is not None:
                self._pattern_error_display.setPlainText(str(exc))
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Compilation failed")
            _logger.debug("pattern_compile_failed", error=str(exc))
        else:
            self._compiled_json = compiled

            if self._pattern_json_preview is not None:
                self._pattern_json_preview.setPlainText(compiled)

            if self._pattern_error_display is not None:
                self._pattern_error_display.clear()

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Compiled successfully")

            _logger.info("pattern_compiled")

    def _on_pattern_apply(self) -> None:
        """Apply the compiled template at the current cursor offset."""
        if self._document is None:
            return

        if not self._compiled_json:
            self._on_pattern_compile()
        if not self._compiled_json:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        try:
            name: str = self._document.register_json_template(self._compiled_json)
            result = self._document.apply_template(name, cursor_offset)
        except Exception as exc:
            if self._pattern_error_display is not None:
                self._pattern_error_display.setPlainText(f"Apply failed: {exc}")
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Apply failed")
            _logger.debug("pattern_apply_failed", error=str(exc))
        else:
            if self._templates_tree is not None:
                self._templates_tree.clear()
                if isinstance(result, list):
                    typed_fields = cast("list[dict[str, object]]", result)
                    self._populate_template_tree(typed_fields)
                    self._highlight_template_fields(typed_fields)

            self._populate_template_combo()

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Applied '{name}' at offset {cursor_offset}")

            if self._state_holder is not None:
                self._state_holder.notify_template_registered(name, source="panel")

            _logger.info("pattern_applied", template_name=name, offset=cursor_offset)

    def _on_pattern_save(self) -> None:
        """Save the current pattern to a file."""
        if not self._compiled_json and self._pattern_dsl_editor is not None:
            source = self._pattern_dsl_editor.toPlainText()
            if source.strip():
                self._on_pattern_compile()

        result = QFileDialog.getSaveFileName(
            self,
            "Save Pattern",
            "",
            "HexPat Files (*.hexpat);;JSON Templates (*.json);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if not save_path:
            return

        try:
            path = Path(save_path)
            if path.suffix == ".json" and self._compiled_json:
                path.write_text(self._compiled_json, encoding="utf-8")
            elif self._pattern_dsl_editor is not None:
                path.write_text(
                    self._pattern_dsl_editor.toPlainText(),
                    encoding="utf-8",
                )
        except Exception as exc:
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Save failed")
            _logger.debug("pattern_save_failed", error=str(exc))
        else:
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Saved to {path.name}")
            _logger.info("pattern_saved", path=str(path))

    def _on_pattern_open(self) -> None:
        """Open a pattern file from disk."""
        result = QFileDialog.getOpenFileName(
            self,
            "Open Pattern",
            "",
            "Pattern Files (*.hexpat *.json);;All Files (*)",
        )
        file_path_str = result[0] if result else ""
        if not file_path_str:
            return

        try:
            path = Path(file_path_str)
            content = path.read_text(encoding="utf-8")
        except Exception as exc:
            if self._pattern_status_label is not None:
                self._pattern_status_label.setText("Open failed")
            _logger.debug("pattern_open_failed", error=str(exc))
        else:
            if path.suffix == ".json":
                self._compiled_json = content
                if self._pattern_json_preview is not None:
                    self._pattern_json_preview.setPlainText(content)
                if self._pattern_status_label is not None:
                    self._pattern_status_label.setText(f"Loaded JSON: {path.name}")
            else:
                if self._pattern_dsl_editor is not None:
                    self._pattern_dsl_editor.setPlainText(content)
                if self._pattern_status_label is not None:
                    self._pattern_status_label.setText(f"Loaded: {path.name}")

            _logger.info("pattern_opened", path=str(path))

    def _on_pattern_new(self) -> None:
        """Clear the pattern editor with a starter skeleton."""
        if self._pattern_dsl_editor is not None:
            self._pattern_dsl_editor.setPlainText(
                "struct MY_HEADER {\n"
                "    le u16 magic;\n"
                "    le u32 size;\n"
                "};\n"
            )
        if self._pattern_json_preview is not None:
            self._pattern_json_preview.clear()
        if self._pattern_error_display is not None:
            self._pattern_error_display.clear()
        self._compiled_json = ""
        if self._pattern_status_label is not None:
            self._pattern_status_label.setText("New pattern")

    def _on_pattern_library_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Load the selected template from the library into the editors.

        Args:
            item: The clicked tree widget item.
            column: The clicked column index.
        """
        _ = column
        if self._document is None:
            return

        template_name = item.text(0)
        parent_item = item.parent()
        if parent_item is None:
            return

        try:
            json_str_val: str = self._document.export_template_json(template_name)
        except Exception as exc:
            _logger.debug("pattern_library_load_failed", error=str(exc))
        else:
            self._compiled_json = json_str_val

            if self._pattern_json_preview is not None:
                self._pattern_json_preview.setPlainText(json_str_val)

            if self._pattern_status_label is not None:
                self._pattern_status_label.setText(f"Loaded: {template_name}")

            _logger.debug("pattern_library_loaded", template_name=template_name)

    def _populate_pattern_library(self) -> None:
        """Populate the pattern library tree with available templates."""
        if self._pattern_library_tree is None or self._document is None:
            return

        self._pattern_library_tree.clear()

        try:
            templates = self._document.list_templates()
        except Exception as exc:
            _logger.debug("pattern_library_populate_failed", error=str(exc))
            return

        categories: dict[str, QTreeWidgetItem] = {}

        builtin_root = QTreeWidgetItem(["Built-in"])
        self._pattern_library_tree.addTopLevelItem(builtin_root)

        user_root = QTreeWidgetItem(["User"])
        self._pattern_library_tree.addTopLevelItem(user_root)

        for tpl_entry in templates:
            name_val = str(tpl_entry[0])
            desc_val = str(tpl_entry[1])
            name_upper = name_val.upper()
            if any(name_upper.startswith(p) for p in ("ELF", "ELF32", "ELF64")):
                category = "ELF"
            elif any(name_upper.startswith(p) for p in ("MACH", "LOAD_COMMAND", "SEGMENT")):
                category = "Mach-O"
            elif name_upper.startswith("ZIP"):
                category = "ZIP"
            elif name_upper in {"GUID", "FILETIME"}:
                category = "Common"
            elif name_upper.startswith("IMAGE") or name_upper.startswith("PE") or name_upper.startswith("DOS"):
                category = "PE"
            else:
                category = "Other"

            if category not in categories:
                cat_item = QTreeWidgetItem([category])
                builtin_root.addChild(cat_item)
                categories[category] = cat_item

            template_item = QTreeWidgetItem([name_val])
            template_item.setToolTip(0, desc_val)
            categories[category].addChild(template_item)

        builtin_root.setExpanded(True)

    def _refresh_template_combo(self) -> None:
        """Refresh the template combo box after registration changes."""
        self._populate_template_combo()

    def _create_disassembly_tab(self) -> QWidget:
        """Create the Disassembly side panel tab widget.

        Returns:
            QWidget: Container widget with disassembly toolbar and table.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        toolbar_row = QHBoxLayout()

        self._disasm_arch_combo = QComboBox()
        self._disasm_arch_combo.addItems([
            "Auto Detect", "x86", "ARM", "ARM64", "MIPS", "PPC", "SPARC", "SystemZ", "RISC-V",
        ])
        toolbar_row.addWidget(self._disasm_arch_combo)

        self._disasm_mode_combo = QComboBox()
        self._disasm_mode_combo.addItems(["64-bit", "32-bit", "16-bit", "ARM", "Thumb"])
        toolbar_row.addWidget(self._disasm_mode_combo)

        self._disasm_count_spin = QSpinBox()
        self._disasm_count_spin.setRange(1, 500)
        self._disasm_count_spin.setValue(_DEFAULT_DISASM_COUNT)
        self._disasm_count_spin.setFixedWidth(60)
        toolbar_row.addWidget(self._disasm_count_spin)

        self._disasm_follow_cursor = QCheckBox("Follow Cursor")
        self._disasm_follow_cursor.setChecked(True)
        toolbar_row.addWidget(self._disasm_follow_cursor)

        disasm_btn = QPushButton("Disassemble")
        disasm_btn.clicked.connect(self._on_disassemble)
        toolbar_row.addWidget(disasm_btn)
        toolbar_row.addStretch()

        layout.addLayout(toolbar_row)

        self._disasm_table = QTableWidget(0, 4)
        self._disasm_table.setHorizontalHeaderLabels(["Address", "Hex Bytes", "Mnemonic", "Operands"])
        self._disasm_table.setSelectionBehavior(self._disasm_table.SelectionBehavior.SelectRows)
        self._disasm_table.setEditTriggers(self._disasm_table.EditTrigger.NoEditTriggers)
        self._disasm_table.setAlternatingRowColors(True)
        table_font = self._disasm_table.font()
        table_font.setFamily("Consolas")
        table_font.setPointSize(9)
        self._disasm_table.setFont(table_font)
        self._disasm_table.horizontalHeader().setStretchLastSection(True)
        self._disasm_table.verticalHeader().setVisible(False)
        self._disasm_table.cellDoubleClicked.connect(self._on_disasm_row_double_clicked)
        layout.addWidget(self._disasm_table)

        return container

    def _on_disassemble(self) -> None:
        """Disassemble bytes at the current cursor offset and populate the table."""
        if self._document is None or self._disasm_table is None:
            return

        if not _disassembler_available or _HexDisassembler is None:
            _logger.debug("disasm_capstone_unavailable")
            return

        count = self._disasm_count_spin.value() if self._disasm_count_spin is not None else _DEFAULT_DISASM_COUNT
        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        read_len = count * _MAX_INSN_BYTES
        try:
            doc_len: int = self._document.length()
            available = doc_len - cursor_offset
            if available <= 0:
                return
            read_len = min(read_len, available)
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except Exception as exc:
            _logger.debug("disasm_read_failed", error=str(exc))
            return

        disassembler = _HexDisassembler()
        if not disassembler.available:
            _logger.debug("disasm_capstone_unavailable")
            return

        arch_text = self._disasm_arch_combo.currentText() if self._disasm_arch_combo is not None else "Auto Detect"
        mode_text = self._disasm_mode_combo.currentText() if self._disasm_mode_combo is not None else "64-bit"

        mode_map: dict[str, str] = {
            "64-bit": "64",
            "32-bit": "32",
            "16-bit": "16",
            "ARM": "arm",
            "Thumb": "thumb",
        }
        mode_str = mode_map.get(mode_text, "64")

        if arch_text == "Auto Detect":
            arch_str, mode_str = disassembler.auto_detect_arch(data)
        else:
            arch_map: dict[str, str] = {
                "x86": "x86",
                "ARM": "arm",
                "ARM64": "arm64",
                "MIPS": "mips",
                "PPC": "ppc",
                "SPARC": "sparc",
                "SystemZ": "systemz",
                "RISC-V": "riscv",
            }
            arch_str = arch_map.get(arch_text, "x86")

        try:
            instructions = disassembler.disassemble(
                data, base_addr=cursor_offset, arch=arch_str, mode=mode_str, count=count
            )
        except Exception as exc:
            _logger.debug("disasm_failed", error=str(exc))
            return

        self._disasm_table.setRowCount(0)
        for insn in instructions:
            row = self._disasm_table.rowCount()
            self._disasm_table.insertRow(row)
            hex_str = " ".join(f"{b:02x}" for b in insn.raw_bytes)
            self._disasm_table.setItem(row, 0, QTableWidgetItem(f"0x{insn.address:08X}"))
            self._disasm_table.setItem(row, 1, QTableWidgetItem(hex_str))
            self._disasm_table.setItem(row, 2, QTableWidgetItem(insn.mnemonic))
            self._disasm_table.setItem(row, 3, QTableWidgetItem(insn.op_str))

        _logger.debug("disasm_complete", instruction_count=len(instructions))

    def _on_cursor_moved_disasm(self, offset: int) -> None:
        """Auto-disassemble when Follow Cursor is active.

        Args:
            offset: New cursor byte offset.
        """
        _ = offset
        if self._disasm_follow_cursor is not None and self._disasm_follow_cursor.isChecked():
            self._on_disassemble()

    def _on_disasm_row_double_clicked(self, row: int, column: int) -> None:
        """Navigate the hex view to the instruction address on double-click.

        Args:
            row: The double-clicked row index.
            column: The double-clicked column index.
        """
        _ = column
        if self._disasm_table is None:
            return
        addr_item = self._disasm_table.item(row, 0)
        if addr_item is None:
            return
        addr_text = addr_item.text()
        try:
            offset = int(addr_text, 16)
        except ValueError:
            pass
        else:
            self.goto_offset(offset)

    def _create_yara_tab(self) -> QWidget:
        """Create the YARA scanner side panel tab widget.

        Returns:
            QWidget: Container widget with YARA rule input and results tree.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        file_row = QHBoxLayout()
        select_files_btn = QPushButton("Select Rule Files...")
        select_files_btn.clicked.connect(self._on_yara_select_files)
        file_row.addWidget(select_files_btn)
        self._yara_file_count_label = QLabel("No files selected")
        file_row.addWidget(self._yara_file_count_label)
        file_row.addStretch()
        layout.addLayout(file_row)

        self._yara_inline_editor = QPlainTextEdit()
        yara_font = self._yara_inline_editor.font()
        yara_font.setFamily("Consolas")
        yara_font.setPointSize(9)
        self._yara_inline_editor.setFont(yara_font)
        self._yara_inline_editor.setToolTip(
            "Enter inline YARA rule source. If empty, compiled rule files are used instead."
        )
        self._yara_inline_editor.setMaximumHeight(140)
        layout.addWidget(self._yara_inline_editor)

        scan_btn = QPushButton("Scan")
        scan_btn.clicked.connect(self._on_yara_scan)
        layout.addWidget(scan_btn)

        self._yara_results_tree = QTreeWidget()
        self._yara_results_tree.setHeaderLabels(["Rule", "Offset", "Identifier", "Match Data"])
        self._yara_results_tree.setAlternatingRowColors(True)
        self._yara_results_tree.itemDoubleClicked.connect(self._on_yara_result_double_clicked)
        layout.addWidget(self._yara_results_tree)

        return container

    def _on_yara_select_files(self) -> None:
        """Open a file dialog to select YARA rule files."""
        result = QFileDialog.getOpenFileNames(
            self,
            "Select YARA Rule Files",
            "",
            "YARA Rules (*.yar *.yara);;All Files (*)",
        )
        files = result[0] if result else []
        if files:
            self._yara_rule_files = list(files)
            if self._yara_file_count_label is not None:
                self._yara_file_count_label.setText(f"{len(self._yara_rule_files)} file(s) selected")

    def _on_yara_scan(self) -> None:
        """Compile YARA rules and scan the current document."""
        if self._document is None or self._yara_results_tree is None:
            return

        if not _yara_scanner_available or _YaraScanner is None:
            _logger.debug("yara_unavailable")
            return

        scanner = _YaraScanner()
        if not scanner.available:
            _logger.debug("yara_unavailable")
            return

        inline_source = ""
        if self._yara_inline_editor is not None:
            inline_source = self._yara_inline_editor.toPlainText().strip()

        matches: Any = None
        try:
            if inline_source:
                compiled_rules = scanner.compile_source(inline_source)
            elif self._yara_rule_files:
                compiled_rules = scanner.compile_rules(self._yara_rule_files)
            else:
                return

            doc_len: int = self._document.length()
            raw: object = self._document.read(0, doc_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return

            matches = scanner.scan_data(data, compiled_rules)

        except Exception as exc:
            _logger.debug("yara_scan_failed", error=str(exc))
            return

        if matches is None:
            return

        self._yara_results_tree.clear()
        all_match_offsets: list[tuple[int, int]] = []

        for match in matches:
            rule_item = QTreeWidgetItem([match.rule_name, "", "", ""])
            self._yara_results_tree.addTopLevelItem(rule_item)
            for string_match in match.strings:
                match_hex = " ".join(f"{b:02X}" for b in string_match.data[:_YARA_MATCH_DISPLAY_BYTES])
                child = QTreeWidgetItem([
                    "",
                    f"0x{string_match.offset:08X}",
                    string_match.identifier,
                    match_hex,
                ])
                rule_item.addChild(child)
                match_len = len(string_match.data)
                all_match_offsets.append((string_match.offset, match_len))
            rule_item.setExpanded(True)

        if all_match_offsets and self._hex_widget is not None:
            highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
            if callable(highlight_fn):
                highlights = [(off, length, "#AA44FF") for off, length in all_match_offsets]
                highlight_fn(highlights)

        _logger.debug("yara_scan_complete", match_count=len(matches))

    def _on_yara_result_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Navigate to the YARA match offset when a result child is double-clicked.

        Args:
            item: The double-clicked tree widget item.
            column: The double-clicked column index.
        """
        _ = column
        if item.parent() is None:
            return
        offset_text = item.text(1)
        try:
            offset = int(offset_text, 16)
        except ValueError:
            pass
        else:
            self.goto_offset(offset)

    def _create_transforms_tab(self) -> QWidget:
        """Create the Transforms side panel tab widget.

        Returns:
            QWidget: Container widget with transform selector, parameters,
                preview pane, and pipeline controls.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)

        self._transform_nodes_cache = _get_all_transform_nodes() if _get_all_transform_nodes is not None else []

        node_row = QHBoxLayout()
        node_row.addWidget(QLabel("Transform:"))
        self._transform_node_combo = QComboBox()
        for node in self._transform_nodes_cache:
            label = f"{node.name} [{node.category}]" if node.category else node.name
            self._transform_node_combo.addItem(label)
        self._transform_node_combo.currentIndexChanged.connect(self._on_transform_node_changed)
        node_row.addWidget(self._transform_node_combo)
        node_row.addStretch()
        layout.addLayout(node_row)

        self._transform_params_widget = QWidget()
        self._transform_params_form = QFormLayout(self._transform_params_widget)
        self._transform_params_form.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._transform_params_widget)

        action_row = QHBoxLayout()
        preview_btn = QPushButton("Preview")
        preview_btn.clicked.connect(self._on_transform_preview)
        action_row.addWidget(preview_btn)
        apply_btn = QPushButton("Apply")
        apply_btn.clicked.connect(self._on_transform_apply)
        action_row.addWidget(apply_btn)
        action_row.addStretch()
        layout.addLayout(action_row)

        self._transform_preview_pane = QPlainTextEdit()
        self._transform_preview_pane.setReadOnly(True)
        preview_font = self._transform_preview_pane.font()
        preview_font.setFamily("Consolas")
        preview_font.setPointSize(9)
        self._transform_preview_pane.setFont(preview_font)
        self._transform_preview_pane.setMaximumHeight(120)
        layout.addWidget(self._transform_preview_pane)

        layout.addWidget(QLabel("Pipeline:"))

        self._transform_pipeline_list = QListWidget()
        self._transform_pipeline_list.setMaximumHeight(100)
        layout.addWidget(self._transform_pipeline_list)

        pipeline_btn_row = QHBoxLayout()
        add_step_btn = QPushButton("Add Step")
        add_step_btn.clicked.connect(self._on_pipeline_add_step)
        pipeline_btn_row.addWidget(add_step_btn)
        remove_step_btn = QPushButton("Remove Step")
        remove_step_btn.clicked.connect(self._on_pipeline_remove_step)
        pipeline_btn_row.addWidget(remove_step_btn)
        move_up_btn = QPushButton("Move Up")
        move_up_btn.clicked.connect(self._on_pipeline_move_up)
        pipeline_btn_row.addWidget(move_up_btn)
        move_down_btn = QPushButton("Move Down")
        move_down_btn.clicked.connect(self._on_pipeline_move_down)
        pipeline_btn_row.addWidget(move_down_btn)
        layout.addLayout(pipeline_btn_row)

        execute_btn = QPushButton("Execute Pipeline")
        execute_btn.clicked.connect(self._on_pipeline_execute)
        layout.addWidget(execute_btn)

        layout.addStretch()

        self._on_transform_node_changed(0)

        return container

    def _on_transform_node_changed(self, index: int) -> None:
        """Rebuild the parameter form when the selected transform changes.

        Args:
            index: Index of the newly selected transform in the combo box.
        """
        if self._transform_params_form is None or self._transform_params_widget is None:
            return

        while self._transform_params_form.rowCount() > 0:
            self._transform_params_form.removeRow(0)

        if not self._transform_nodes_cache or index < 0 or index >= len(self._transform_nodes_cache):
            return

        node = self._transform_nodes_cache[index]

        node_param_specs: dict[str, list[str]] = {
            "xor": ["key"],
            "rot": ["amount"],
            "add": ["value"],
            "sub": ["value"],
            "rc4": ["key"],
            "base64_encode": [],
            "base64_decode": [],
            "zlib_compress": [],
            "zlib_decompress": [],
            "reverse": [],
            "hex_encode": [],
            "hex_decode": [],
            "regex_replace": ["pattern", "replacement"],
            "custom_expression": ["expression"],
            "repeat": ["count"],
            "truncate": ["length"],
            "pad": ["length", "byte"],
        }

        param_names = node_param_specs.get(node.name, [])

        if not param_names and node.description:
            self._transform_params_form.addRow(
                QLabel(
                    node.description[:_DESCRIPTION_TRUNCATE_LEN]
                    if len(node.description) > _DESCRIPTION_TRUNCATE_LEN
                    else node.description
                )
            )

        for param_name in param_names:
            param_edit = QLineEdit()
            param_edit.setObjectName(f"transform_param_{param_name}")
            param_edit.setToolTip(f"Value for '{param_name}' parameter")
            self._transform_params_form.addRow(QLabel(f"{param_name}:"), param_edit)

    def _collect_transform_params(self) -> dict[str, str]:
        """Collect current parameter values from the transform params form.

        Returns:
            dict[str, str]: Mapping of parameter names to their string values.
        """
        params: dict[str, str] = {}
        if self._transform_params_form is None:
            return params
        for row in range(self._transform_params_form.rowCount()):
            label_item = self._transform_params_form.itemAt(row, QFormLayout.ItemRole.LabelRole)
            field_item = self._transform_params_form.itemAt(row, QFormLayout.ItemRole.FieldRole)
            if label_item is None or field_item is None:
                continue
            label_widget = label_item.widget()
            field_widget = field_item.widget()
            if not isinstance(label_widget, QLabel) or not isinstance(field_widget, QLineEdit):
                continue
            label_text = label_widget.text().rstrip(":")
            params[label_text] = field_widget.text()
        return params

    def _run_single_transform(self, data: bytes) -> bytes | None:
        """Apply the currently selected single transform to data.

        Args:
            data: Input bytes to transform.

        Returns:
            bytes | None: Transformed bytes, or None on failure.
        """
        if self._transform_node_combo is None or not self._transform_nodes_cache:
            return None
        idx = self._transform_node_combo.currentIndex()
        if idx < 0 or idx >= len(self._transform_nodes_cache):
            return None
        node = self._transform_nodes_cache[idx]
        raw_params = self._collect_transform_params()
        try:
            return node.process(data, raw_params)
        except Exception as exc:
            _logger.debug("transform_single_failed", error=str(exc))
            return None

    def _on_transform_preview(self) -> None:
        """Apply the selected transform to the cursor region and show a hex dump preview."""
        if self._document is None or self._transform_preview_pane is None:
            return

        cursor_offset = 0
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)

        preview_len = _PREVIEW_BYTES
        try:
            doc_len: int = self._document.length()
            read_len = min(preview_len, doc_len - cursor_offset)
            if read_len <= 0:
                return
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except Exception as exc:
            _logger.debug("transform_preview_read_failed", error=str(exc))
            return

        result = self._run_single_transform(data)
        if result is None:
            return

        lines: list[str] = []
        for row_start in range(0, min(len(result), _PREVIEW_BYTES), _HEX_ROW_WIDTH):
            chunk = result[row_start : row_start + _HEX_ROW_WIDTH]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if _PRINTABLE_MIN <= b <= _PRINTABLE_MAX else "." for b in chunk)
            lines.append(f"{cursor_offset + row_start:08X}  {hex_part:<48}  {ascii_part}")

        self._transform_preview_pane.setPlainText("\n".join(lines))

    def _on_transform_apply(self) -> None:
        """Apply the selected transform to the current selection or cursor region and write to document."""
        if self._document is None:
            return

        cursor_offset = 0
        apply_len = _PREVIEW_BYTES
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
            sel_start: int = getattr(self._hex_widget, "_selection_start", -1)
            sel_end: int = getattr(self._hex_widget, "_selection_end", -1)
            if sel_start >= 0 and sel_end >= 0 and sel_end > sel_start:
                cursor_offset = sel_start
                apply_len = sel_end - sel_start

        try:
            doc_len: int = self._document.length()
            read_len = min(apply_len, doc_len - cursor_offset)
            if read_len <= 0:
                return
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except Exception as exc:
            _logger.debug("transform_apply_read_failed", error=str(exc))
            return

        result = self._run_single_transform(data)
        if result is None:
            return

        write_len = min(len(result), read_len)
        try:
            self._document.write_bytes(cursor_offset, result[:write_len])
        except Exception as exc:
            _logger.debug("transform_apply_write_failed", error=str(exc))
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()
            _logger.debug("transform_applied", offset=cursor_offset, length=write_len)

    def _on_pipeline_add_step(self) -> None:
        """Add the currently selected transform as a new pipeline step."""
        if self._transform_node_combo is None or not self._transform_nodes_cache:
            return
        idx = self._transform_node_combo.currentIndex()
        if idx < 0 or idx >= len(self._transform_nodes_cache):
            return
        node = self._transform_nodes_cache[idx]
        params = self._collect_transform_params()
        self._transform_pipeline.append((node.name, params))
        if self._transform_pipeline_list is not None:
            param_summary = ", ".join(f"{k}={v}" for k, v in params.items() if v)
            label = f"{node.name}({param_summary})" if param_summary else node.name
            self._transform_pipeline_list.addItem(label)

    def _on_pipeline_remove_step(self) -> None:
        """Remove the selected step from the pipeline."""
        if self._transform_pipeline_list is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row < 0 or row >= len(self._transform_pipeline):
            return
        self._transform_pipeline.pop(row)
        self._transform_pipeline_list.takeItem(row)

    def _on_pipeline_move_up(self) -> None:
        """Move the selected pipeline step one position earlier."""
        if self._transform_pipeline_list is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row <= 0 or row >= len(self._transform_pipeline):
            return
        self._transform_pipeline[row - 1], self._transform_pipeline[row] = (
            self._transform_pipeline[row],
            self._transform_pipeline[row - 1],
        )
        item = self._transform_pipeline_list.takeItem(row)
        self._transform_pipeline_list.insertItem(row - 1, item)
        self._transform_pipeline_list.setCurrentRow(row - 1)

    def _on_pipeline_move_down(self) -> None:
        """Move the selected pipeline step one position later."""
        if self._transform_pipeline_list is None:
            return
        row = self._transform_pipeline_list.currentRow()
        if row < 0 or row >= len(self._transform_pipeline) - 1:
            return
        self._transform_pipeline[row], self._transform_pipeline[row + 1] = (
            self._transform_pipeline[row + 1],
            self._transform_pipeline[row],
        )
        item = self._transform_pipeline_list.takeItem(row)
        self._transform_pipeline_list.insertItem(row + 1, item)
        self._transform_pipeline_list.setCurrentRow(row + 1)

    def _on_pipeline_execute(self) -> None:
        """Execute all pipeline steps on the current document region and write results."""
        if self._document is None or not self._transform_pipeline:
            return

        if _get_all_transform_nodes is None:
            _logger.debug("transform_pipeline_unavailable")
            return

        all_nodes = {n.name: n for n in _get_all_transform_nodes()}

        cursor_offset = 0
        apply_len = 65536
        if self._hex_widget is not None:
            cursor_offset = getattr(self._hex_widget, "_cursor_offset", 0)
            sel_start: int = getattr(self._hex_widget, "_selection_start", -1)
            sel_end: int = getattr(self._hex_widget, "_selection_end", -1)
            if sel_start >= 0 and sel_end >= 0 and sel_end > sel_start:
                cursor_offset = sel_start
                apply_len = sel_end - sel_start

        try:
            doc_len: int = self._document.length()
            read_len = min(apply_len, doc_len - cursor_offset)
            if read_len <= 0:
                return
            raw: object = self._document.read(cursor_offset, read_len)
            if isinstance(raw, (list, bytearray)):
                data = bytes(cast("list[int]", raw) if isinstance(raw, list) else raw)
            elif isinstance(raw, bytes):
                data = raw
            else:
                return
        except Exception as exc:
            _logger.debug("pipeline_read_failed", error=str(exc))
            return

        result = data
        for node_name, params in self._transform_pipeline:
            node = all_nodes.get(node_name)
            if node is None:
                _logger.debug("pipeline_node_not_found", node_name=node_name)
                continue
            try:
                result = node.process(result, params)
            except Exception as exc:
                _logger.debug("pipeline_step_failed", node_name=node_name, error=str(exc))
                return

        write_len = min(len(result), read_len)
        try:
            self._document.write_bytes(cursor_offset, result[:write_len])
        except Exception as exc:
            _logger.debug("pipeline_write_failed", error=str(exc))
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()
            _logger.debug("pipeline_executed", offset=cursor_offset, length=write_len)

    def _on_calculate_hash(self) -> None:
        """Calculate the hash of the current document and display the result."""
        if self._document is None or self._hash_algo_combo is None or self._hash_result_label is None:
            return
        algo = self._hash_algo_combo.currentText()
        try:
            doc_len: int = self._document.length()
            raw = self._document.read(0, doc_len)
            if isinstance(raw, (list, bytearray)) or not isinstance(raw, bytes):
                data = bytes(raw)
            else:
                data = raw
            result = _compute_hash(algo, data)
        except Exception as exc:
            self._hash_result_label.setText(f"Error: {exc}")
            _logger.debug("hash_calculate_failed", error=str(exc))
        else:
            self._hash_result_label.setText(f"{algo}: {result}")
            _logger.info("hash_calculated", algo=algo)

    def _on_custom_crc(self) -> None:
        """Open the custom CRC dialog with the current document data."""
        if self._document is None:
            return
        try:
            doc_len: int = self._document.length()
            raw = self._document.read(0, doc_len)
            if isinstance(raw, (list, bytearray)) or not isinstance(raw, bytes):
                data = bytes(raw)
            else:
                data = raw
        except Exception as exc:
            QMessageBox.warning(self, "Custom CRC", f"Failed to read document data:\n{exc}")
        else:
            dlg = CustomCrcDialog(data, self)
            dlg.exec()

    def _on_export_patches(self) -> None:
        """Export current patches to an IPS or IPS32 patch file."""
        if self._patches_tree is None or self._document is None:
            return
        patch_count = self._patches_tree.topLevelItemCount()
        if patch_count == 0:
            QMessageBox.information(self, "Export Patches", "No patches to export.")
            return
        result = QFileDialog.getSaveFileName(
            self,
            "Export Patches",
            "",
            "IPS Patches (*.ips);;IPS32 Patches (*.ips32);;All Files (*)",
        )
        save_path = result[0] if result else ""
        if not save_path:
            return
        use_ips32 = save_path.lower().endswith(".ips32")
        try:
            records: list[bytes] = []
            for i in range(patch_count):
                tree_item = self._patches_tree.topLevelItem(i)
                if tree_item is None:
                    continue
                offset_text = tree_item.text(0).strip()
                new_text = tree_item.text(2).strip()
                if not offset_text or not new_text:
                    continue
                offset_val = int(offset_text, 16)
                new_byte = int(new_text, 16)
                if use_ips32:
                    records.append(struct.pack(">I", offset_val))
                else:
                    records.append(struct.pack(">I", offset_val)[1:])
                records.extend((struct.pack(">H", 1), bytes([new_byte])))
            patch_data = b"PATCH" + b"".join(records) + b"EOF"
            Path(save_path).write_bytes(patch_data)
        except Exception as exc:
            _logger.debug("patches_export_failed", error=str(exc))
            QMessageBox.warning(self, "Export Patches", f"Export failed:\n{exc}")
        else:
            _logger.info("patches_exported", path=save_path, count=patch_count)
            QMessageBox.information(self, "Export Patches", f"Exported {patch_count} patch(es).")

    def _on_import_patches(self) -> None:
        """Import patches from an IPS or IPS32 file and apply them to the document."""
        if self._document is None:
            return
        result = QFileDialog.getOpenFileName(
            self,
            "Import Patches",
            "",
            "Patch Files (*.ips *.ips32);;All Files (*)",
        )
        file_path_str = result[0] if result else ""
        if not file_path_str:
            return
        try:
            patch_bytes = Path(file_path_str).read_bytes()
        except Exception as exc:
            _logger.debug("patches_import_failed", error=str(exc))
            QMessageBox.warning(self, "Import Patches", f"Import failed:\n{exc}")
            return

        use_ips32 = file_path_str.lower().endswith(".ips32")
        if not patch_bytes.startswith(b"PATCH"):
            QMessageBox.warning(self, "Import Patches", "Not a valid IPS file (missing PATCH header).")
            return

        pos = _IPS_HEADER_SIZE
        applied = 0
        eof_marker = b"EOF"
        offset_size = _IPS32_OFFSET_SIZE if use_ips32 else _IPS_OFFSET_SIZE
        try:
            while pos + offset_size + _IPS_LENGTH_FIELD_SIZE <= len(patch_bytes) and patch_bytes[pos:pos + _IPS_OFFSET_SIZE] != eof_marker:
                if use_ips32:
                    (patch_offset,) = struct.unpack(">I", patch_bytes[pos:pos + _IPS32_OFFSET_SIZE])
                    pos += _IPS32_OFFSET_SIZE
                else:
                    (patch_offset,) = struct.unpack(">I", b"\x00" + patch_bytes[pos:pos + _IPS_OFFSET_SIZE])
                    pos += _IPS_OFFSET_SIZE
                (length,) = struct.unpack(">H", patch_bytes[pos:pos + _IPS_LENGTH_FIELD_SIZE])
                pos += _IPS_LENGTH_FIELD_SIZE
                if length == 0:
                    if pos + _IPS_LENGTH_FIELD_SIZE > len(patch_bytes):
                        break
                    (rle_len,) = struct.unpack(">H", patch_bytes[pos:pos + _IPS_LENGTH_FIELD_SIZE])
                    pos += _IPS_LENGTH_FIELD_SIZE
                    rle_byte = patch_bytes[pos]
                    pos += 1
                    data_to_write = bytes([rle_byte] * rle_len)
                else:
                    if pos + length > len(patch_bytes):
                        break
                    data_to_write = patch_bytes[pos:pos + length]
                    pos += length
                self._document.write_bytes(patch_offset, bytes(data_to_write))
                applied += 1
        except Exception as exc:
            _logger.debug("patches_import_failed", error=str(exc))
            QMessageBox.warning(self, "Import Patches", f"Import failed:\n{exc}")
        else:
            if self._hex_widget is not None:
                update_fn = getattr(self._hex_widget, "_update_viewport", None)
                if callable(update_fn):
                    update_fn()
            self._on_data_changed()
            _logger.info("patches_imported", path=file_path_str, count=applied)
            QMessageBox.information(self, "Import Patches", f"Applied {applied} patch record(s).")

    def _build_numeric_search_panel(self) -> QFrame:
        """Build the collapsible numeric search panel.

        Returns:
            QFrame: Frame containing the numeric search controls.
        """
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        self._numeric_value_input = QLineEdit()
        self._numeric_value_input.setToolTip("Decimal (255) or hex (0xFF) numeric value to search for")
        self._numeric_value_input.setFixedWidth(120)
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
        self._numeric_align_spin.setFixedWidth(50)
        layout.addWidget(self._numeric_align_spin)

        self._numeric_range_check = QCheckBox("Range")
        self._numeric_range_check.toggled.connect(self._on_numeric_range_toggled)
        layout.addWidget(self._numeric_range_check)

        self._numeric_max_input = QLineEdit()
        self._numeric_max_input.setToolTip("Maximum value for range search (inclusive)")
        self._numeric_max_input.setFixedWidth(100)
        self._numeric_max_input.setVisible(False)
        layout.addWidget(self._numeric_max_input)

        search_btn = QPushButton("Search")
        search_btn.clicked.connect(self._on_numeric_search)
        layout.addWidget(search_btn)
        layout.addStretch()
        return frame

    def _on_numeric_range_toggled(self, checked: bool) -> None:
        """Show or hide the max value field when range search is toggled.

        Args:
            checked: True if range search is enabled.
        """
        if self._numeric_max_input is not None:
            self._numeric_max_input.setVisible(checked)

    def _on_search_mode_changed(self, mode: str) -> None:
        """Show or hide the numeric search panel based on current mode.

        Args:
            mode: The newly selected search mode string.
        """
        show_numeric = mode == "Numeric"
        if self._numeric_search_frame is not None:
            self._numeric_search_frame.setVisible(show_numeric)
        if self._search_input is not None:
            self._search_input.setEnabled(not show_numeric)

    def _on_numeric_search(self) -> None:
        """Execute a numeric value search using the current panel settings."""
        if self._document is None or self._numeric_value_input is None:
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
            (1, False, False): "B", (1, True, False): "b",
            (2, False, False): "H", (2, True, False): "h",
            (4, False, False): "I", (4, True, False): "i",
            (8, False, False): "Q", (8, True, False): "q",
            (4, False, True): "f", (4, True, True): "f",
            (8, False, True): "d", (8, True, True): "d",
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
            QMessageBox.warning(self, "Numeric Search", f"Invalid value: {exc}")
            return

        search_fn = getattr(self._document, "search_numeric", None)
        try:
            if callable(search_fn):
                raw_results = search_fn(min_val, max_val, fmt, alignment, _MAX_SEARCH_RESULTS)
                found_results: list[tuple[int, int]] = [(r[0], byte_width) for r in raw_results]
            else:
                found_results = self._numeric_search_fallback(
                    min_val, max_val, fmt, byte_width, alignment
                )
        except Exception as exc:
            _logger.debug("numeric_search_failed", error=str(exc))
            QMessageBox.warning(self, "Numeric Search", f"Search failed:\n{exc}")
        else:
            self._search_results = found_results
            self._search_index = 0
            if found_results and self._hex_widget is not None:
                goto_fn = getattr(self._hex_widget, "goto_offset", None)
                if callable(goto_fn):
                    goto_fn(found_results[0][0])
                highlight_fn = getattr(self._hex_widget, "highlight_offsets", None)
                if callable(highlight_fn):
                    highlights = [(off, length, "#FFAA00") for off, length in found_results]
                    highlight_fn(highlights)
            _logger.info("numeric_search_completed", result_count=len(found_results))

    def _numeric_search_fallback(
        self,
        min_val: float,
        max_val: float,
        fmt: str,
        byte_width: int,
        alignment: int,
    ) -> list[tuple[int, int]]:
        """Scan the document for numeric values within the given range.

        Args:
            min_val: Minimum value to match (inclusive).
            max_val: Maximum value to match (inclusive).
            fmt: struct format string for unpacking.
            byte_width: Number of bytes per value.
            alignment: Required byte alignment of search results.

        Returns:
            list[tuple[int, int]]: List of (offset, byte_width) tuples for each match.
        """
        if self._document is None:
            return []
        results: list[tuple[int, int]] = []
        doc_len: int = self._document.length()
        chunk_size = 65536
        max_results = _MAX_SEARCH_RESULTS
        offset = 0
        while offset < doc_len and len(results) < max_results:
            read_len = min(chunk_size, doc_len - offset)
            raw = self._document.read(offset, read_len)
            if isinstance(raw, (list, bytearray)) or not isinstance(raw, bytes):
                chunk = bytes(raw)
            else:
                chunk = raw
            for i in range(len(chunk) - byte_width + 1):
                abs_off = offset + i
                if alignment > 1 and abs_off % alignment != 0:
                    continue
                try:
                    (val,) = struct.unpack_from(fmt, chunk, i)
                    fval = float(val)
                    if min_val <= fval <= max_val:
                        results.append((abs_off, byte_width))
                        if len(results) >= max_results:
                            break
                except struct.error:
                    continue
            offset += read_len - byte_width + 1
        return results

    def _cleanup(self) -> None:
        """Release resources when the panel is closed."""
        self._document = None
        self._file_path = None
        self._original_data_cache.clear()
        self._search_results.clear()
        if self._hex_widget is not None:
            set_doc = getattr(self._hex_widget, "set_document", None)
            if callable(set_doc):
                set_doc(None)
        _logger.debug("hex_editor_panel_cleanup")
