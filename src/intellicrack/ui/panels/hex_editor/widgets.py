# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Standalone widget classes for the hex editor panel."""

from __future__ import annotations

import math
from typing import override

from PyQt6.QtCore import QRect, QSize, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPen,
)
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import GenericCallableWorker
from intellicrack.ui.panels.hex_editor.base import (
    BYTE_VALUES_COUNT,
    ENTROPY_HIGH_THRESHOLD,
    ENTROPY_LOW_THRESHOLD,
    ENTROPY_MAX,
    compute_streaming_custom_crc,
)
from intellicrack.ui.resources.theme_manager import ThemeManager


_logger = get_logger(__name__)


def _get_widget_colors() -> dict[str, QColor]:
    """Return theme-appropriate colors for hex editor graph widgets.

    Returns:
        dict[str, QColor]: Mapping of color role names to QColor instances.
    """
    if ThemeManager.get_instance().is_dark_theme():
        return {
            "bg": QColor("#1E1E1E"),
            "entropy_low": QColor("#4CAF50"),
            "entropy_mid": QColor("#FFC107"),
            "entropy_high": QColor("#F44336"),
            "axis": QColor("#888888"),
            "bar_normal": QColor("#2196F3"),
            "bar_hovered": QColor("#4CAF50"),
            "gradient_low": QColor("#1B3A1F"),
            "gradient_mid": QColor("#3A3A1B"),
            "gradient_high": QColor("#3A1B1B"),
        }
    return {
        "bg": QColor("#FFFFFF"),
        "entropy_low": QColor("#2E7D32"),
        "entropy_mid": QColor("#EF6C00"),
        "entropy_high": QColor("#C62828"),
        "axis": QColor("#5a6370"),
        "bar_normal": QColor("#1565C0"),
        "bar_hovered": QColor("#2E7D32"),
        "gradient_low": QColor("#E8F5E9"),
        "gradient_mid": QColor("#FFF3E0"),
        "gradient_high": QColor("#FFEBEE"),
    }


class EntropyGraphWidget(QWidget):
    """Line-chart widget visualising per-block Shannon entropy.

    Renders a polyline where the X axis maps to block offset and the
    Y axis maps to entropy in [0, 8] bits/byte.  Colour bands show
    green for low entropy, yellow for medium, and red for high.
    Clicking on the graph emits ``block_clicked`` with the byte offset
    of the block that was clicked.

    Attributes:
        block_clicked: Signal emitted with the byte offset of the clicked block.
    """

    block_clicked: pyqtSignal = pyqtSignal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the EntropyGraphWidget.

        Args:
            parent: Parent widget.
        """
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

    def entropy_values(self) -> list[float]:
        """Return the per-block entropy values currently displayed.

        Returns:
            list[float]: A copy of the loaded per-block entropy values.
        """
        return list(self._entropy_values)

    def block_size(self) -> int:
        """Return the block size currently used to map clicks to offsets.

        Returns:
            int: Block size in bytes.
        """
        return self._block_size

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Render the entropy line chart.

        Args:
            a0: The paint event.
        """
        _ = a0
        colors = _get_widget_colors()
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = self.width()
        h = self.height()
        pad = 4

        painter.fillRect(0, 0, w, h, colors["bg"])

        band_data: list[tuple[float, float, QColor]] = [
            (0.0, ENTROPY_LOW_THRESHOLD, colors["gradient_low"]),
            (ENTROPY_LOW_THRESHOLD, ENTROPY_HIGH_THRESHOLD, colors["gradient_mid"]),
            (ENTROPY_HIGH_THRESHOLD, ENTROPY_MAX, colors["gradient_high"]),
        ]
        for lo, hi, colour in band_data:
            y1 = h - pad - int((lo / ENTROPY_MAX) * (h - 2 * pad))
            y2 = h - pad - int((hi / ENTROPY_MAX) * (h - 2 * pad))
            painter.fillRect(pad, y2, w - 2 * pad, y1 - y2, colour)

        values = self._entropy_values
        if not values:
            painter.end()
            return

        usable_w = max(w - 2 * pad, 1)
        usable_h = h - 2 * pad

        def x_coord(idx: int) -> int:
            """Map an entropy sample index to a pixel X coordinate.

            Args:
                idx: Zero-based index into the entropy sample list.

            Returns:
                int: Horizontal pixel position within the paint area.
            """
            return pad + int(idx * usable_w / max(len(values) - 1, 1))

        def y_coord(val: float) -> int:
            """Map an entropy sample value to a pixel Y coordinate.

            Args:
                val: Entropy reading in the unit interval scaled by ``ENTROPY_MAX``.

            Returns:
                int: Vertical pixel position within the paint area.
            """
            return h - pad - int((val / ENTROPY_MAX) * usable_h)

        for i in range(len(values) - 1):
            v = values[i]
            if v < ENTROPY_LOW_THRESHOLD:
                colour_line = colors["entropy_low"]
            elif v < ENTROPY_HIGH_THRESHOLD:
                colour_line = colors["entropy_mid"]
            else:
                colour_line = colors["entropy_high"]
            pen = QPen(colour_line, 1)
            painter.setPen(pen)
            painter.drawLine(x_coord(i), y_coord(values[i]), x_coord(i + 1), y_coord(values[i + 1]))

        painter.setPen(QPen(colors["axis"], 1))
        painter.drawRect(pad, pad, w - 2 * pad, h - 2 * pad)
        painter.end()

    @override
    def mousePressEvent(self, a0: QMouseEvent | None) -> None:
        """Navigate to the clicked block offset.

        Args:
            a0: The mouse press event.
        """
        values = self._entropy_values
        if not values or a0 is None:
            return
        w = self.width()
        pad = 4
        x = a0.position().x()
        idx = int((x - pad) / max(w - 2 * pad, 1) * (len(values) - 1) + 0.5)
        idx = max(0, min(len(values) - 1, idx))
        self.block_clicked.emit(idx * self._block_size)


class ByteDistributionWidget(QWidget):
    """Histogram widget showing the frequency of each of the 256 byte values.

    Renders 256 vertical bars, one per byte value.  Supports optional logarithmic scale.  Hovering over a bar shows a tooltip with the byte
    value and count.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the ByteDistributionWidget.

        Args:
            parent: Parent widget.
        """
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
        self._counts = list(counts) if len(counts) == BYTE_VALUES_COUNT else ([0] * BYTE_VALUES_COUNT)
        self.update()

    def counts(self) -> list[int]:
        """Return the byte-frequency counts currently displayed.

        Returns:
            list[int]: A copy of the 256-element histogram counts.
        """
        return list(self._counts)

    def log_scale(self) -> bool:
        """Return whether the histogram is currently in logarithmic scale.

        Returns:
            bool: ``True`` when the logarithmic Y scale is active.
        """
        return self._log_scale

    def toggle_log_scale(self) -> None:
        """Toggle between linear and logarithmic Y scale."""
        self._log_scale = not self._log_scale
        self.update()

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Render the 256-bar histogram.

        Args:
            a0: The paint event.
        """
        _ = a0
        colors = _get_widget_colors()
        painter = QPainter(self)
        w = self.width()
        h = self.height()
        pad = 2
        painter.fillRect(0, 0, w, h, colors["bg"])

        counts = self._counts
        if not counts or max(counts) == 0:
            painter.end()
            return

        max_val = max(counts)
        bar_w = max(1.0, (w - 2 * pad) / BYTE_VALUES_COUNT)

        def bar_h(count: int) -> int:
            """Compute a histogram bar height for a byte-value frequency.

            Args:
                count: Occurrence count for one byte value.

            Returns:
                int: Bar height in pixels, or ``0`` when ``count`` is zero.
            """
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
            colour = colors["bar_hovered"] if i == self._hovered_bar else colors["bar_normal"]
            painter.fillRect(QRect(x, h - pad - bh, max(1, int(bar_w)), bh), QBrush(colour))

        painter.end()

    @override
    def mouseMoveEvent(self, a0: QMouseEvent | None) -> None:
        """Update tooltip and hover highlight on mouse movement.

        Args:
            a0: The mouse move event.
        """
        if a0 is None:
            return
        w = self.width()
        pad = 2
        x = a0.position().x()
        bar_w = max(1.0, (w - 2 * pad) / BYTE_VALUES_COUNT)
        idx = int((x - pad) / bar_w)
        idx = max(0, min(BYTE_VALUES_COUNT - 1, idx))
        self._hovered_bar = idx
        count = self._counts[idx] if self._counts else 0
        QToolTip.showText(
            a0.globalPosition().toPoint(),
            f"Byte 0x{idx:02X} ({idx}): {count} occurrences",
            self,
        )
        self.update()


def _stream_crc_from_source(
    file_path: str | None,
    document: object,
    length: int,
    width: int,
    poly: int,
    init: int,
    *,
    ref_in: bool,
    ref_out: bool,
    xor_out: int,
) -> int:
    """Worker entry point that delegates to the streaming CRC helper.

    The dialog's ``GenericCallableWorker`` invokes this from a worker
    thread; bridge work is delegated to :func:`compute_streaming_custom_crc`.

    Args:
        file_path: When non-``None`` and pointing at a readable file,
            the helper mmaps the file instead of paging through
            ``document.read``.
        document: Fallback hexcore-style document used when
            ``file_path`` is ``None``.
        length: Total number of bytes to stream when paging via the
            document API. Forwarded to the helper as a chunk-size hint.
        width: CRC bit width.
        poly: Generator polynomial.
        init: Initial CRC value.
        ref_in: Reflect each input byte before processing.
        ref_out: Reflect the final CRC value before XOR-out.
        xor_out: Value to XOR with the final CRC.

    Returns:
        int: Computed CRC value.
    """
    del length
    return compute_streaming_custom_crc(
        file_path,
        document,
        width,
        poly,
        init,
        ref_in=ref_in,
        ref_out=ref_out,
        xor_out=xor_out,
    )


class CustomCrcDialog(QDialog):
    """Dialog for computing a custom parametric CRC.

    Provides input fields for width, polynomial, initial value, reflection options, and XOR-out value, then computes the CRC over the
    supplied source when the user clicks Calculate.

    The CRC is always computed on a :class:`GenericCallableWorker` background thread so the UI stays responsive even on multi-hundred-
    megabyte files. The worker streams from an mmap'd file when the document is file-backed and falls back to chunked ``document.read``
    calls otherwise; in both cases the UI thread never holds more than one chunk of the document body.
    """

    crc_computed = pyqtSignal("PyQt_PyObject")

    def __init__(
        self,
        *,
        file_path: str | None,
        document: object,
        length: int,
        parent: QWidget | None = None,
        worker_parent: QWidget | None = None,
    ) -> None:
        """Initialize the dialog with the source the worker will stream.

        Args:
            file_path: Optional file path; when set and readable the
                worker mmaps the file instead of going through the
                document API. ``None`` means "go through the document".
            document: Hexcore-style document exposing
                ``read(offset, length)``. Used when ``file_path`` is
                ``None`` or when the file becomes unreadable.
            length: Number of bytes the document currently holds.
            parent: Parent widget for the dialog.
            worker_parent: Parent for the :class:`GenericCallableWorker`.
                Defaults to the dialog itself; pass ``None`` explicitly
                to keep the worker unparented (only useful in tests).
        """
        super().__init__(parent)
        self._file_path: str | None = file_path
        self._document: object = document
        self._length: int = length
        self._worker_parent: QWidget | None = worker_parent if worker_parent is not None else self
        self._worker: GenericCallableWorker | None = None

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
        self._result_label.setWordWrap(True)
        self._result_label.setToolTip("Result: \u2014")
        layout.addWidget(self._result_label)

        calc_btn = QPushButton("Calculate")
        calc_btn.clicked.connect(self._calculate)
        layout.addWidget(calc_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def worker(self) -> GenericCallableWorker | None:
        """Return the in-flight CRC worker, or ``None`` if no calculation is running.

        Returns:
            GenericCallableWorker | None: The active worker thread.
        """
        return self._worker

    def _read_crc_inputs(self) -> tuple[int, int, int, bool, bool, int]:
        """Read and parse the CRC parameter inputs.

        Returns:
            tuple[int, int, int, bool, bool, int]:
                ``(width, poly, init, ref_in, ref_out, xor_out)`` values.
        """
        width = self._width_spin.value()
        poly = int(self._poly_edit.text().strip(), 16)
        init = int(self._init_edit.text().strip(), 16)
        ref_in = self._ref_in_check.isChecked()
        ref_out = self._ref_out_check.isChecked()
        xor_out = int(self._xor_out_edit.text().strip(), 16)
        return width, poly, init, ref_in, ref_out, xor_out

    def _calculate(self) -> None:
        """Spawn a worker that streams the CRC computation off the UI thread."""
        try:
            width, poly, init, ref_in, ref_out, xor_out = self._read_crc_inputs()
        except ValueError as exc:
            _logger.warning("custom_crc_invalid_input", error=str(exc))
            error_text = f"Error: {exc}"
            self._result_label.setText(error_text)
            self._result_label.setToolTip(error_text)
            return

        if self._worker is not None and self._worker.isRunning():
            return

        self._result_label.setText("Computing\u2026")
        self._result_label.setToolTip("Computing\u2026")
        worker = GenericCallableWorker(
            _stream_crc_from_source,
            self._file_path,
            self._document,
            self._length,
            width,
            poly,
            init,
            ref_in=ref_in,
            ref_out=ref_out,
            xor_out=xor_out,
            parent=self._worker_parent,
        )
        _: object = worker.call_finished.connect(self._on_worker_finished)
        _ = worker.call_error.connect(self._on_worker_error)
        self._worker = worker
        worker.start()

    def _on_worker_finished(self, result: object) -> None:
        """Display the computed CRC and emit ``crc_computed`` for observers.

        Args:
            result: Worker result object; expected to be an integer CRC value.
        """
        self._worker = None
        if not isinstance(result, int):
            error_text = "Error: worker returned non-integer result"
            self._result_label.setText(error_text)
            self._result_label.setToolTip(error_text)
            _logger.warning("custom_crc_unexpected_result_type", result_type=type(result).__name__)
            return
        width = self._width_spin.value()
        hex_digits = (width + 3) // 4
        result_text = f"Result: 0x{result:0{hex_digits}X}"
        self._result_label.setText(result_text)
        self._result_label.setToolTip(result_text)
        self.crc_computed.emit(result)

    def _on_worker_error(self, exc: object) -> None:
        """Display the worker error and clear the in-flight worker handle.

        Args:
            exc: Exception object the worker raised.
        """
        self._worker = None
        error_text = f"Error: {exc}"
        self._result_label.setText(error_text)
        self._result_label.setToolTip(error_text)
        _logger.error(
            "custom_crc_worker_failed",
            error_type=type(exc).__name__,
            error=str(exc),
        )


_DIGRAM_SIZE: int = 256
_DIGRAM_MIN_WIDGET_SIZE: int = 512
_DIGRAM_DIALOG_MIN: int = 600


class _DigramMatrixWidget(QWidget):
    """Custom widget rendering a 256x256 byte pair frequency heatmap.

    Each pixel at (row, col) represents the frequency of the byte pair ``row -> col`` in the analyzed document.
    """

    def __init__(
        self,
        matrix_data: list[int],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the _DigramMatrixWidget with bigram count data.

        Args:
            matrix_data: Flat list of 65536 integers (256 x 256 bigram counts).
            parent: Parent widget.
        """
        super().__init__(parent)
        self._matrix = matrix_data
        self._max_val = max(matrix_data, default=1)
        self.setMinimumSize(QSize(_DIGRAM_MIN_WIDGET_SIZE, _DIGRAM_MIN_WIDGET_SIZE))
        self.setMouseTracking(True)

    @override
    def minimumSizeHint(self) -> QSize:
        """Return the minimum recommended size for the widget.

        Returns:
            QSize: Minimum size of 512x512 pixels.
        """
        return QSize(_DIGRAM_MIN_WIDGET_SIZE, _DIGRAM_MIN_WIDGET_SIZE)

    @staticmethod
    def _cell_color(count: int, max_val: int) -> QColor:
        """Compute the heatmap color for a digram cell count.

        Args:
            count: The digram frequency count for this cell.
            max_val: Maximum count across all cells, used for normalization.

        Returns:
            QColor: Black for zero counts; HSV-interpolated color otherwise.
        """
        if count == 0:
            return QColor(0, 0, 0)
        intensity = count / max_val
        hue = int((1.0 - intensity) * 240)
        val = int(55 + intensity * 200)
        return QColor.fromHsv(hue, 255, val)

    @override
    def paintEvent(self, a0: QPaintEvent | None) -> None:
        """Render the 256x256 digram heatmap.

        Colors range from black (zero) through blue/yellow to white
        (maximum frequency) using HSV interpolation.

        Args:
            a0: The paint event.
        """
        _ = a0
        painter = QPainter(self)
        w = self.width()
        h = self.height()
        cell_w = w / _DIGRAM_SIZE
        cell_h = h / _DIGRAM_SIZE
        max_val = max(self._max_val, 1)

        for row in range(_DIGRAM_SIZE):
            for col in range(_DIGRAM_SIZE):
                count = self._matrix[row * _DIGRAM_SIZE + col]
                colour = self._cell_color(count, max_val)
                x = int(col * cell_w)
                y = int(row * cell_h)
                cw = max(1, int((col + 1) * cell_w) - x)
                ch = max(1, int((row + 1) * cell_h) - y)
                painter.fillRect(x, y, cw, ch, QBrush(colour))

        painter.end()

    @override
    def mouseMoveEvent(self, a0: QMouseEvent | None) -> None:
        """Show a tooltip with the byte pair and count at the cursor position.

        Args:
            a0: The mouse move event.
        """
        if a0 is None:
            return
        w = self.width()
        h = self.height()
        col = int(a0.position().x() / max(w, 1) * _DIGRAM_SIZE)
        row = int(a0.position().y() / max(h, 1) * _DIGRAM_SIZE)
        col = max(0, min(_DIGRAM_SIZE - 1, col))
        row = max(0, min(_DIGRAM_SIZE - 1, row))
        count = self._matrix[row * _DIGRAM_SIZE + col]
        QToolTip.showText(
            a0.globalPosition().toPoint(),
            f"0x{row:02X} -> 0x{col:02X}: {count} occurrences",
            self,
        )


class DigramMatrixDialog(QDialog):
    """Dialog displaying a 256x256 byte pair frequency heatmap.

    Visualises the digram matrix as a color-coded 2D grid where each cell represents how often one byte follows another.
    """

    def __init__(
        self,
        matrix_data: list[int],
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the DigramMatrixDialog with bigram count data.

        Args:
            matrix_data: Flat list of 65536 integers (256 x 256 bigram counts).
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("Digram Matrix")
        self.setMinimumSize(QSize(_DIGRAM_DIALOG_MIN, _DIGRAM_DIALOG_MIN))

        layout = QVBoxLayout(self)
        layout.addWidget(_DigramMatrixWidget(matrix_data, self))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


_DEFAULT_CHUNK_KB: int = 4096
_MIN_CHUNK_KB: int = 64
_MAX_CHUNK_KB: int = 65536
_DEFAULT_BUDGET_MB: int = 512
_MIN_BUDGET_MB: int = 64
_MAX_BUDGET_MB: int = 4096


class LargeFileSettingsDialog(QDialog):
    """Dialog for configuring large file memory and chunk settings.

    Provides controls for chunk size, memory budget, and prefetch behavior used when working with memory-mapped large files.
    """

    def __init__(
        self,
        current_chunk_kb: int,
        current_budget_mb: int,
        current_usage_mb: float,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the LargeFileSettingsDialog with current memory settings.

        Args:
            current_chunk_kb: Current chunk size in kilobytes.
            current_budget_mb: Current memory budget in megabytes.
            current_usage_mb: Current memory usage in megabytes.
            parent: Parent widget.
        """
        super().__init__(parent)
        self.setWindowTitle("Large File Settings")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._chunk_spin = QSpinBox()
        self._chunk_spin.setRange(_MIN_CHUNK_KB, _MAX_CHUNK_KB)
        self._chunk_spin.setValue(current_chunk_kb)
        self._chunk_spin.setSuffix(" KB")
        self._chunk_spin.setSingleStep(256)
        form.addRow("Chunk size:", self._chunk_spin)

        self._budget_spin = QSpinBox()
        self._budget_spin.setRange(_MIN_BUDGET_MB, _MAX_BUDGET_MB)
        self._budget_spin.setValue(current_budget_mb)
        self._budget_spin.setSuffix(" MB")
        self._budget_spin.setSingleStep(64)
        form.addRow("Memory budget:", self._budget_spin)

        self._prefetch_check = QCheckBox("Prefetch on scroll")
        self._prefetch_check.setChecked(True)
        form.addRow(self._prefetch_check)

        usage_label = QLabel(f"{current_usage_mb:.1f} MB")
        form.addRow("Current usage:", usage_label)

        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def chunk_size_kb(self) -> int:
        """Selected chunk size in kilobytes.

        Returns:
            int: Chunk size in KB.
        """
        return self._chunk_spin.value()

    @property
    def memory_budget_mb(self) -> int:
        """Selected memory budget in megabytes.

        Returns:
            int: Memory budget in MB.
        """
        return self._budget_spin.value()

    @property
    def prefetch_on_scroll(self) -> bool:
        """Selected prefetch-on-scroll setting.

        Returns:
            bool: True if prefetch on scroll is enabled.
        """
        return self._prefetch_check.isChecked()
