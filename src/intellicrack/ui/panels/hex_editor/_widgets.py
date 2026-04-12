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

from intellicrack.ui.panels.hex_editor._base import (
    BYTE_VALUES_COUNT,
    ENTROPY_HIGH_THRESHOLD,
    ENTROPY_LOW_THRESHOLD,
    ENTROPY_MAX,
    compute_custom_crc,
)
from intellicrack.ui.resources.theme_manager import ThemeManager


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
        "axis": QColor("#757575"),
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
        self.setMouseTracking(enable=True)

    def set_data(self, entropy_values: list[float], block_size: int) -> None:
        """Load new entropy data and trigger a repaint.

        Args:
            entropy_values: Per-block entropy values in [0, 8].
            block_size: Size of each block in bytes.
        """
        self._entropy_values = entropy_values
        self._block_size = block_size
        self.update()

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
            return pad + int(idx * usable_w / max(len(values) - 1, 1))

        def y_coord(val: float) -> int:
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
        self.setMouseTracking(enable=True)

    def set_data(self, counts: list[int]) -> None:
        """Load byte frequency data and repaint.

        Args:
            counts: List of 256 integers, one per byte value.
        """
        self._counts = list(counts) if len(counts) == BYTE_VALUES_COUNT else ([0] * BYTE_VALUES_COUNT)
        self.update()

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
            result = compute_custom_crc(
                self._data,
                width,
                poly,
                init,
                ref_in=ref_in,
                ref_out=ref_out,
                xor_out=xor_out,
            )
        except ValueError as exc:
            self._result_label.setText(f"Error: {exc}")
        else:
            hex_digits = (width + 3) // 4
            self._result_label.setText(f"Result: 0x{result:0{hex_digits}X}")


_DIGRAM_SIZE: int = 256
_DIGRAM_MIN_WIDGET_SIZE: int = 512
_DIGRAM_DIALOG_MIN: int = 600


class _DigramMatrixWidget(QWidget):
    """Custom widget rendering a 256x256 byte pair frequency heatmap.

    Each pixel at (row, col) represents the frequency of the byte
    pair ``row -> col`` in the analyzed document.

    Args:
        matrix_data: Flat list of 65536 integers (256 x 256 bigram counts).
        parent: Parent widget.
    """

    def __init__(
        self,
        matrix_data: list[int],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._matrix = matrix_data
        self._max_val = max(matrix_data) if matrix_data else 1
        self.setMinimumSize(QSize(_DIGRAM_MIN_WIDGET_SIZE, _DIGRAM_MIN_WIDGET_SIZE))
        self.setMouseTracking(enable=True)

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

    Visualises the digram matrix as a color-coded 2D grid where
    each cell represents how often one byte follows another.

    Args:
        matrix_data: Flat list of 65536 integers (256 x 256 bigram counts).
        parent: Parent widget.
    """

    def __init__(
        self,
        matrix_data: list[int],
        parent: QWidget | None = None,
    ) -> None:
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

    Provides controls for chunk size, memory budget, and prefetch
    behavior used when working with memory-mapped large files.

    Args:
        current_chunk_kb: Current chunk size in kilobytes.
        current_budget_mb: Current memory budget in megabytes.
        current_usage_mb: Current memory usage in megabytes.
        parent: Parent widget.
    """

    def __init__(
        self,
        current_chunk_kb: int,
        current_budget_mb: int,
        current_usage_mb: float,
        parent: QWidget | None = None,
    ) -> None:
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
        """Get the selected chunk size in kilobytes.

        Returns:
            int: Chunk size in KB.
        """
        return self._chunk_spin.value()

    @property
    def memory_budget_mb(self) -> int:
        """Get the selected memory budget in megabytes.

        Returns:
            int: Memory budget in MB.
        """
        return self._budget_spin.value()

    @property
    def prefetch_on_scroll(self) -> bool:
        """Get the prefetch on scroll setting.

        Returns:
            bool: True if prefetch on scroll is enabled.
        """
        return self._prefetch_check.isChecked()
