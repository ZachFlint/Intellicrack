# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""
XPU status dialog for the Help menu.

Provides a live-updating dialog displaying Intel XPU device status, memory utilization, model cache state, and Windows system requirements.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger
from intellicrack.ui.resources.theme_manager import ThemeManager


if TYPE_CHECKING:
    from PyQt6.QtGui import QCloseEvent


try:
    from intellicrack.providers.xpu_utils import (
        check_windows_requirements,
        get_optimal_dtype_for_xpu,
        get_xpu_device_info,
        get_xpu_memory_info,
        is_xpu_available,
    )
except ImportError:
    get_logger("ui.xpu_status").debug("xpu_utils_unavailable")
    check_windows_requirements = None
    get_optimal_dtype_for_xpu = None
    get_xpu_device_info = None
    get_xpu_memory_info = None
    is_xpu_available = None

try:
    from intellicrack.providers.model_loader import get_global_model_cache
except ImportError:
    get_logger("ui.xpu_status").debug("model_loader_unavailable")
    get_global_model_cache = None


_logger = get_logger("ui.xpu_status")

_BYTES_PER_GB: Final[float] = 1024.0 * 1024.0 * 1024.0
_BYTES_PER_MB: Final[float] = 1024.0 * 1024.0
_LIVE_REFRESH_MS: Final[int] = 2000
_DIALOG_WIDTH: Final[int] = 480
_DIALOG_HEIGHT: Final[int] = 520
_WARNINGS_MAX_HEIGHT: Final[int] = 100


def _restyle(widget: QWidget) -> None:
    """
    Force QSS re-evaluation after dynamic property change.

    Args:
        widget: Widget to re-polish.
    """
    s = widget.style()
    if s is not None:
        s.unpolish(widget)
        s.polish(widget)


class XPUStatusDialog(QDialog):
    """
    Live XPU status dialog accessible from the Help menu.

    Displays device information, memory utilization, model cache state,
    and Windows system requirement checks with periodic auto-refresh
    for memory metrics.

    Args:
        parent: Parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("XPU Status")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_live_data)

        self._setup_ui()
        self._refresh_all()
        self.refresh_timer.start(_LIVE_REFRESH_MS)

    def _setup_ui(self) -> None:
        """Build the dialog layout with four group boxes and a button row."""
        root = QVBoxLayout(self)

        root.addWidget(self._build_device_group())
        root.addWidget(self._build_memory_group())
        root.addWidget(self._build_cache_group())
        root.addWidget(self._build_requirements_group())
        root.addLayout(self._build_button_row())

    def _build_device_group(self) -> QGroupBox:
        """
        Build the Device Status group box.

        Returns:
            QGroupBox: The constructed group box widget.
        """
        group = QGroupBox("Device Status")
        form = QFormLayout()

        self._status_label = QLabel("Checking...")
        form.addRow("Status:", self._status_label)

        self.device_name_label = QLabel("--")
        form.addRow("Device:", self.device_name_label)

        self.driver_label = QLabel("--")
        form.addRow("Driver:", self.driver_label)

        self._dtype_label = QLabel("--")
        form.addRow("Optimal Dtype:", self._dtype_label)

        self.caps_label = QLabel("--")
        form.addRow("Capabilities:", self.caps_label)

        group.setLayout(form)
        return group

    def _build_memory_group(self) -> QGroupBox:
        """
        Build the Memory Usage group box.

        Returns:
            QGroupBox: The constructed group box widget.
        """
        group = QGroupBox("Memory Usage")
        layout = QVBoxLayout()

        self.memory_bar = QProgressBar()
        self.memory_bar.setRange(0, 100)
        self.memory_bar.setValue(0)
        layout.addWidget(self.memory_bar)

        self.memory_text = QLabel("--")
        layout.addWidget(self.memory_text)

        group.setLayout(layout)
        return group

    def _build_cache_group(self) -> QGroupBox:
        """
        Build the Model Cache group box.

        Returns:
            QGroupBox: The constructed group box widget.
        """
        group = QGroupBox("Model Cache")
        form = QFormLayout()

        self.cache_usage_label = QLabel("--")
        form.addRow("Current Usage:", self.cache_usage_label)

        self.cache_limit_label = QLabel("--")
        form.addRow("Limit:", self.cache_limit_label)

        group.setLayout(form)
        return group

    def _build_requirements_group(self) -> QGroupBox:
        """
        Build the System Requirements group box.

        Returns:
            QGroupBox: The constructed group box widget.
        """
        group = QGroupBox("System Requirements")
        layout = QVBoxLayout()

        self.requirements_text = QTextEdit()
        self.requirements_text.setReadOnly(True)
        self.requirements_text.setMaximumHeight(_WARNINGS_MAX_HEIGHT)
        layout.addWidget(self.requirements_text)

        group.setLayout(layout)
        return group

    def _build_button_row(self) -> QHBoxLayout:
        """
        Build the bottom button row.

        Returns:
            QHBoxLayout: Layout containing the action buttons.
        """
        row = QHBoxLayout()

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self._refresh_all)
        row.addWidget(refresh_btn)

        row.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        row.addWidget(close_btn)

        return row

    def _refresh_all(self) -> None:
        """Run a full refresh of all status fields including expensive checks."""
        self._refresh_device_info()
        self._refresh_live_data()
        self._refresh_requirements()

    def _refresh_device_info(self) -> None:
        """Refresh static device information (name, driver, dtype, caps)."""
        if is_xpu_available is None:
            self._status_label.setText("XPU utilities not available")
            self._status_label.setProperty("status", "error")
            _restyle(self._status_label)
            return

        try:
            available = is_xpu_available()
        except (RuntimeError, OSError):
            _logger.debug("xpu_availability_check_failed", exc_info=True)
            available = False

        if not available:
            self._status_label.setText("CPU Only")
            self._status_label.setProperty("status", "warning")
            _restyle(self._status_label)
            self.device_name_label.setText("No XPU device detected")
            self.driver_label.setText("N/A")
            self._dtype_label.setText("float32")
            self.caps_label.setText("N/A")
            return

        self._status_label.setText("XPU Active")
        self._status_label.setProperty("status", "success")
        _restyle(self._status_label)

        self._refresh_device_details()
        self._refresh_dtype()

    def _refresh_device_details(self) -> None:
        """Populate device name, driver version, and capability flags."""
        if get_xpu_device_info is None:
            return

        try:
            info: object = get_xpu_device_info(0)
        except (RuntimeError, OSError):
            _logger.debug("xpu_device_info_failed", exc_info=True)
            return

        if info is None:
            self.device_name_label.setText("Unknown device")
            return

        self.device_name_label.setText(str(info.device_name))
        self.driver_label.setText(str(info.driver_version) if info.driver_version else "Unknown")

        caps_parts: list[str] = []
        if info.supports_fp16:
            caps_parts.append("FP16")
        if info.supports_bf16:
            caps_parts.append("BF16")
        if info.supports_int8:
            caps_parts.append("INT8")
        self.caps_label.setText(" / ".join(caps_parts) if caps_parts else "None detected")

    def _refresh_dtype(self) -> None:
        """Detect and display the optimal dtype."""
        if get_optimal_dtype_for_xpu is None:
            return

        try:
            dtype = get_optimal_dtype_for_xpu()
            self._dtype_label.setText(dtype)
        except (RuntimeError, OSError):
            _logger.debug("xpu_dtype_detection_failed", exc_info=True)
            self._dtype_label.setText("Detection failed")

    def _refresh_live_data(self) -> None:
        """Refresh memory and cache metrics (cheap, timer-safe)."""
        self._refresh_memory()
        self._refresh_cache()

    def _refresh_memory(self) -> None:
        """Update memory usage bar and text."""
        if get_xpu_memory_info is None or is_xpu_available is None:
            self.memory_text.setText("XPU memory info not available")
            self.memory_text.setProperty("status", "idle")
            _restyle(self.memory_text)
            return

        try:
            if not is_xpu_available():
                self.memory_bar.setValue(0)
                self.memory_text.setText("No XPU device")
                self.memory_text.setProperty("status", "idle")
                _restyle(self.memory_text)
                return

            allocated, total = get_xpu_memory_info(0)
        except (RuntimeError, OSError):
            _logger.debug("xpu_memory_info_failed", exc_info=True)
            self.memory_bar.setValue(0)
            self.memory_text.setText("Failed to read memory")
            return

        if total > 0:
            pct = int((allocated / total) * 100)
            self.memory_bar.setValue(pct)
            alloc_gb = allocated / _BYTES_PER_GB
            total_gb = total / _BYTES_PER_GB
            self.memory_text.setText(f"{alloc_gb:.2f} GB / {total_gb:.2f} GB ({pct}%)")
            self.memory_text.setProperty("status", "")
        else:
            self.memory_bar.setValue(0)
            self.memory_text.setText("Unable to determine memory size")
            self.memory_text.setProperty("status", "idle")

        _restyle(self.memory_text)

    def _refresh_cache(self) -> None:
        """Update model cache usage and limit labels."""
        if get_global_model_cache is None:
            self.cache_usage_label.setText("Model cache not available")
            self.cache_usage_label.setProperty("status", "idle")
            _restyle(self.cache_usage_label)
            self.cache_limit_label.setText("N/A")
            return

        try:
            cache = get_global_model_cache()
            usage_bytes = cache.get_memory_usage()
            limit_bytes = cache.max_memory_bytes

            usage_mb = usage_bytes / _BYTES_PER_MB
            limit_mb = limit_bytes / _BYTES_PER_MB

            self.cache_usage_label.setText(f"{usage_mb:.1f} MB")
            self.cache_usage_label.setProperty("status", "")
            _restyle(self.cache_usage_label)
            self.cache_limit_label.setText(f"{limit_mb:.0f} MB")
        except (RuntimeError, AttributeError):
            _logger.debug("cache_info_failed", exc_info=True)
            self.cache_usage_label.setText("Error reading cache")
            self.cache_limit_label.setText("Error")

    def _refresh_requirements(self) -> None:
        """
        Run Windows requirements check and display results.

        This calls PowerShell subprocesses so it is only invoked on dialog open and manual refresh, never on the periodic timer.
        """
        if check_windows_requirements is None:
            self.requirements_text.setPlainText("Requirements check not available.")
            return

        try:
            all_met, warnings = check_windows_requirements()
        except (RuntimeError, OSError):
            _logger.debug("requirements_check_failed", exc_info=True)
            self.requirements_text.setPlainText("Failed to check requirements.")
            return

        colors = ThemeManager.get_instance().get_analysis_colors()
        success_hex = colors["success"].name()
        warning_hex = colors["warning"].name()

        if all_met and not warnings:
            self.requirements_text.setHtml(f'<span style="color: {success_hex}; font-weight: bold;">All system requirements met.</span>')
        else:
            lines = [
                f'<span style="color: {warning_hex}; font-weight: bold;">Warnings:</span><ul>',
                *[f"<li>{w}</li>" for w in warnings],
                "</ul>",
            ]
            self.requirements_text.setHtml("".join(lines))

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """
        Stop the refresh timer when the dialog closes.

        Args:
            a0: The close event.
        """
        self.refresh_timer.stop()
        super().closeEvent(a0)
