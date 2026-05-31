# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Real-data coverage for the hex editor visualization widgets.

The audit (shard 13) flagged ``widgets.py`` as having no dedicated test
coverage for the entropy graph, byte-distribution histogram, digram heatmap
colouring, and large-file settings dialog. These tests feed the widgets with
REAL statistics computed from a genuine Windows PE binary (via the real
``intellicrack_hexcore`` backend and :func:`compute_statistics`) and assert
both the public interaction contract (block-click offset mapping) and that the
widgets render non-trivial painted output for that real data.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QEvent, QPointF, Qt
from PyQt6.QtGui import QImage, QMouseEvent, QPainter
from PyQt6.QtWidgets import QApplication, QWidget

from intellicrack.ui.panels.hex_editor.statistics import compute_statistics
from intellicrack.ui.panels.hex_editor.widgets import (
    ByteDistributionWidget,
    DigramMatrixDialog,
    EntropyGraphWidget,
    LargeFileSettingsDialog,
)


if TYPE_CHECKING:
    from pathlib import Path


hexcore = pytest.importorskip(
    "intellicrack_hexcore",
    reason="intellicrack_hexcore backend required for real document statistics",
)


pytestmark = pytest.mark.integration


_ENTROPY_BLOCK_SIZE: int = 4096
_WIDGET_W: int = 400
_WIDGET_H: int = 160


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Provide a shared QApplication for the widget tests.

    Returns:
        QApplication: The Qt application instance.
    """
    existing = QApplication.instance()
    if isinstance(existing, QApplication):
        return existing
    return QApplication([])


def _count_foreground_colors(widget: QWidget, width: int, height: int) -> int:
    """Render ``widget`` and count the distinct non-background colours painted.

    The widgets fill their whole surface with an opaque background, so the
    meaningful signal of "real data was drawn" is the number of distinct
    colours that are not the dominant (background) colour.

    Args:
        widget: A QWidget instance to render.
        width: Render width in pixels.
        height: Render height in pixels.

    Returns:
        int: Count of sampled pixels whose colour differs from the most
            common (background) colour.
    """
    image = QImage(width, height, QImage.Format.Format_ARGB32)
    image.fill(0)
    painter = QPainter(image)
    widget.render(painter)
    painter.end()
    samples: list[int] = [
        image.pixelColor(x, y).rgb()
        for y in range(0, height, 4)
        for x in range(0, width, 4)
    ]
    if not samples:
        return 0
    background = max(set(samples), key=samples.count)
    return sum(1 for value in samples if value != background)


class TestEntropyGraphWidget:
    """The entropy graph must map real per-block entropy to clicks and pixels."""

    def _click_at(self, widget: EntropyGraphWidget, x: float) -> int:
        """Synthesize a left-click at ``x`` and return the emitted offset.

        Args:
            widget: The entropy graph widget under test.
            x: Horizontal click position in widget coordinates.

        Returns:
            int: The byte offset emitted by ``block_clicked``.
        """
        captured: list[int] = []
        _ = widget.block_clicked.connect(captured.append)
        point = QPointF(x, _WIDGET_H / 2)
        event = QMouseEvent(
            QEvent.Type.MouseButtonPress,
            point,
            point,
            Qt.MouseButton.LeftButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        )
        widget.mousePressEvent(event)
        assert len(captured) == 1
        return captured[0]

    def test_block_click_maps_to_real_offset(self, qapp: QApplication, real_pe_dll: Path) -> None:
        """Verify clicking the graph emits the byte offset of the chosen block.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Real PE DLL fixture path.
        """
        _ = qapp
        result = compute_statistics(hexcore.HexDocument.open(str(real_pe_dll)), _ENTROPY_BLOCK_SIZE)
        assert result.entropy_values is not None
        block_count = len(result.entropy_values)
        widget = EntropyGraphWidget()
        widget.resize(_WIDGET_W, _WIDGET_H)
        widget.set_data(result.entropy_values, _ENTROPY_BLOCK_SIZE)

        left_offset = self._click_at(widget, 0.0)
        assert left_offset == 0

        right_offset = self._click_at(widget, float(_WIDGET_W))
        assert right_offset == (block_count - 1) * _ENTROPY_BLOCK_SIZE
        assert right_offset % _ENTROPY_BLOCK_SIZE == 0

    def test_renders_real_entropy_curve(self, qapp: QApplication, real_pe_dll: Path) -> None:
        """Verify the graph paints a non-trivial curve for real entropy data.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Real PE DLL fixture path.
        """
        _ = qapp
        result = compute_statistics(hexcore.HexDocument.open(str(real_pe_dll)), _ENTROPY_BLOCK_SIZE)
        assert result.entropy_values is not None
        widget = EntropyGraphWidget()
        widget.resize(_WIDGET_W, _WIDGET_H)
        widget.set_data(result.entropy_values, _ENTROPY_BLOCK_SIZE)
        assert _count_foreground_colors(widget, _WIDGET_W, _WIDGET_H) > 0


class TestByteDistributionWidget:
    """The histogram must render real byte frequencies in both scales."""

    def test_renders_real_distribution(self, qapp: QApplication, real_pe_dll: Path) -> None:
        """Verify the histogram paints bars for a real byte distribution.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Real PE DLL fixture path.
        """
        _ = qapp
        result = compute_statistics(hexcore.HexDocument.open(str(real_pe_dll)), _ENTROPY_BLOCK_SIZE)
        assert result.dist_counts is not None
        widget = ByteDistributionWidget()
        widget.resize(_WIDGET_W, _WIDGET_H)
        widget.set_data(result.dist_counts)
        linear_samples = _count_foreground_colors(widget, _WIDGET_W, _WIDGET_H)
        assert linear_samples > 0

        widget.toggle_log_scale()
        log_samples = _count_foreground_colors(widget, _WIDGET_W, _WIDGET_H)
        assert log_samples > 0

    def test_rejects_wrong_length_data(self, qapp: QApplication) -> None:
        """Verify set_data falls back to a 256-zero buffer for bad lengths.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        widget = ByteDistributionWidget()
        widget.resize(_WIDGET_W, _WIDGET_H)
        widget.set_data([1, 2, 3])
        assert _count_foreground_colors(widget, _WIDGET_W, _WIDGET_H) == 0


class TestDigramMatrixDialog:
    """The digram heatmap dialog must render a real byte-pair matrix."""

    def test_renders_real_digram_matrix(self, qapp: QApplication, real_pe_dll: Path) -> None:
        """Verify the dialog paints a heatmap from a real document digram matrix.

        Args:
            qapp: Qt application fixture.
            real_pe_dll: Real PE DLL fixture path.
        """
        _ = qapp
        document = hexcore.HexDocument.open(str(real_pe_dll))
        raw_matrix = [int(v) for v in document.digram_matrix()]
        assert len(raw_matrix) == 256 * 256
        assert max(raw_matrix) > 0

        dialog = DigramMatrixDialog(raw_matrix)
        assert dialog.windowTitle() == "Digram Matrix"
        dialog.resize(512, 512)
        assert _count_foreground_colors(dialog, 512, 512) > 0


class TestLargeFileSettingsDialog:
    """The large-file settings dialog must round-trip its configuration."""

    def test_properties_reflect_inputs(self, qapp: QApplication) -> None:
        """Verify the dialog properties return the values it was constructed with.

        Args:
            qapp: Qt application fixture.
        """
        _ = qapp
        dialog = LargeFileSettingsDialog(
            current_chunk_kb=2048,
            current_budget_mb=256,
            current_usage_mb=12.5,
        )
        assert dialog.chunk_size_kb == 2048
        assert dialog.memory_budget_mb == 256
        assert dialog.prefetch_on_scroll is True
