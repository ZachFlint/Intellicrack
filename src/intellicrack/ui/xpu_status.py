# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""XPU status dialog for the Help menu.

Provides a live-updating dialog displaying Intel XPU device status, memory utilization, model cache state, and Windows system requirements.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, override

from PyQt6.QtCore import QThread, QTimer, pyqtSignal
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

    from intellicrack.providers.model_loader import ModelCache
    from intellicrack.providers.xpu_utils import XPUDeviceInfo


_logger = get_logger(__name__)


try:
    from intellicrack.providers.xpu_utils import (
        check_windows_requirements,
        get_optimal_dtype_for_xpu,
        get_xpu_device_info,
        get_xpu_memory_info,
        is_xpu_available,
    )
except ImportError:
    _logger.debug("xpu_utils_unavailable")
    check_windows_requirements = None
    get_optimal_dtype_for_xpu = None
    get_xpu_device_info = None
    get_xpu_memory_info = None
    is_xpu_available = None

try:
    from intellicrack.providers.model_loader import get_global_model_cache
except ImportError:
    _logger.debug("model_loader_unavailable")
    get_global_model_cache = None

_BYTES_PER_GB: Final[float] = 1024.0 * 1024.0 * 1024.0
_BYTES_PER_MB: Final[float] = 1024.0 * 1024.0
_LIVE_REFRESH_MS: Final[int] = 2000
_DIALOG_WIDTH: Final[int] = 480
_DIALOG_HEIGHT: Final[int] = 520
_WARNINGS_MAX_HEIGHT: Final[int] = 100
_REQUIREMENTS_WORKER_WAIT_MS: Final[int] = 5000


@dataclass(frozen=True)
class _RequirementsResult:
    """Result payload emitted by :class:`_RequirementsCheckWorker`.

    Attributes:
        all_met: True when every checked requirement was satisfied.
        warnings: Human-readable warning strings to display, in order.
    """

    all_met: bool
    warnings: list[str]


@dataclass(frozen=True)
class _StatusSnapshot:
    """Immutable snapshot of the discrete XPU status fields used for change detection.

    Equality across two snapshots determines whether the dialog re-emits a status log line. Volatile live metrics (allocated VRAM, cache
    usage) are deliberately excluded so steady-state polling stays silent; only meaningful device-state transitions trigger a new log entry.

    Attributes:
        available: True when an XPU device is currently usable.
        device_name: Resolved device name, or a status marker string when unavailable.
        driver_version: Driver version string, or ``N/A`` when unavailable.
        optimal_dtype: Detected optimal dtype name.
        capabilities: Human-readable capability summary (e.g. ``FP16 / BF16 / INT8``).
        total_memory_bytes: Total device VRAM in bytes (0 when unknown).
        requirements_met: Windows requirements outcome, or None before the first check completes.
        requirements_warnings: Ordered requirement warning strings.
    """

    available: bool
    device_name: str
    driver_version: str
    optimal_dtype: str
    capabilities: str
    total_memory_bytes: int
    requirements_met: bool | None
    requirements_warnings: tuple[str, ...]


class _RequirementsCheckWorker(QThread):
    """Background worker that runs :func:`check_windows_requirements` off the GUI thread.

    Emits :attr:`result_ready` with a :class:`_RequirementsResult` on success and :attr:`check_failed` with an error message on exception.
    The worker is intended to be one-shot per dialog open or manual refresh.
    """

    result_ready = pyqtSignal(object)
    check_failed = pyqtSignal(str)

    @override
    def run(self) -> None:
        """Execute the Windows requirements probe and emit the result.

        Catches :class:`RuntimeError` / :class:`OSError` raised by subprocess invocation or PCI BAR enumeration so the GUI thread always
        receives exactly one terminal signal regardless of failure mode.
        """
        if check_windows_requirements is None:
            self.check_failed.emit("Requirements check is not available in this build")
            return
        try:
            all_met, warnings = check_windows_requirements()
        except (RuntimeError, OSError) as exc:
            _logger.exception("requirements_check_failed_in_thread")
            self.check_failed.emit(str(exc))
            return
        self.result_ready.emit(_RequirementsResult(all_met=all_met, warnings=list(warnings)))


def _restyle(widget: QWidget) -> None:
    """Force QSS re-evaluation after dynamic property change.

    Args:
        widget: Widget to re-polish.
    """
    s = widget.style()
    if s is not None:
        s.unpolish(widget)
        s.polish(widget)


class XPUStatusDialog(QDialog):
    """Live XPU status dialog accessible from the Help menu.

    Displays device information, memory utilization, model cache state, and Windows system requirement checks with periodic auto-refresh for
    memory metrics.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the XPUStatusDialog with device and memory status display.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        _logger.info("xpu_status_dialog_opened")
        self.setWindowTitle("XPU Status")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_live_data)

        self._requirements_worker: _RequirementsCheckWorker | None = None

        self._last_logged_snapshot: _StatusSnapshot | None = None
        self._cur_available: bool = False
        self._cur_device_name: str = ""
        self._cur_driver_version: str = ""
        self._cur_optimal_dtype: str = ""
        self._cur_capabilities: str = ""
        self._cur_total_memory_bytes: int = 0
        self._cur_requirements_met: bool | None = None
        self._cur_requirements_warnings: tuple[str, ...] = ()

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
        """Build the Device Status group box.

        Returns:
            QGroupBox: The constructed group box widget.
        """
        group = QGroupBox("Device Status")
        form = QFormLayout()

        self.status_label = QLabel("Checking...")
        form.addRow("Status:", self.status_label)

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
        """Build the Memory Usage group box.

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
        """Build the Model Cache group box.

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
        """Build the System Requirements group box.

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
        """Build the bottom button row.

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
        """Run a full refresh of all status fields including expensive checks.

        Called on dialog open and whenever the user presses Refresh; both are treated as an explicit request, so the resulting status is
        always logged even when it is identical to the previously logged snapshot.
        """
        self._refresh_device_info()
        self._refresh_live_data()
        self._refresh_requirements()
        self._log_status_if_changed(forced=True)

    def _build_status_snapshot(self) -> _StatusSnapshot:
        """Assemble a :class:`_StatusSnapshot` from the current accumulator values.

        Returns:
            _StatusSnapshot: The discrete status snapshot for change detection and logging.
        """
        return _StatusSnapshot(
            available=self._cur_available,
            device_name=self._cur_device_name,
            driver_version=self._cur_driver_version,
            optimal_dtype=self._cur_optimal_dtype,
            capabilities=self._cur_capabilities,
            total_memory_bytes=self._cur_total_memory_bytes,
            requirements_met=self._cur_requirements_met,
            requirements_warnings=self._cur_requirements_warnings,
        )

    def _log_status_if_changed(self, *, forced: bool) -> None:
        """Emit a status log line when the discrete status changed or a log was explicitly requested.

        Args:
            forced: When True, always log (used for the initial open and manual Refresh). When False, log only if the snapshot differs from
                the last logged one (used by the auto-refresh timer and asynchronous requirement completion).
        """
        snapshot = self._build_status_snapshot()
        if not forced and snapshot == self._last_logged_snapshot:
            return
        self._last_logged_snapshot = snapshot
        _logger.info(
            "xpu_status",
            available=snapshot.available,
            device=snapshot.device_name,
            driver=snapshot.driver_version,
            optimal_dtype=snapshot.optimal_dtype,
            capabilities=snapshot.capabilities,
            total_memory_gb=round(snapshot.total_memory_bytes / _BYTES_PER_GB, 2),
            requirements_met=snapshot.requirements_met,
            warning_count=len(snapshot.requirements_warnings),
        )

    def _refresh_device_info(self) -> None:
        """Refresh static device information (name, driver, dtype, caps)."""
        if is_xpu_available is None:
            self.status_label.setText("XPU utilities not available")
            self.status_label.setProperty("status", "error")
            _restyle(self.status_label)
            self._set_unavailable_device_state("XPU utilities not available")
            return

        try:
            available = is_xpu_available()
        except (RuntimeError, OSError):
            _logger.exception("xpu_availability_check_failed")
            available = False

        if not available:
            self.status_label.setText("CPU Only")
            self.status_label.setProperty("status", "warning")
            _restyle(self.status_label)
            self.device_name_label.setText("No XPU device detected")
            self.driver_label.setText("N/A")
            self._dtype_label.setText("float32")
            self.caps_label.setText("N/A")
            self._set_unavailable_device_state("No XPU device detected")
            return

        self.status_label.setText("XPU Active")
        self.status_label.setProperty("status", "success")
        _restyle(self.status_label)
        self._cur_available = True

        self._refresh_device_details()
        self._refresh_dtype()

    def _set_unavailable_device_state(self, device_name: str) -> None:
        """Record accumulator values for a state with no usable XPU device.

        Args:
            device_name: Status marker describing why no device is active.
        """
        self._cur_available = False
        self._cur_device_name = device_name
        self._cur_driver_version = "N/A"
        self._cur_optimal_dtype = "float32"
        self._cur_capabilities = "N/A"

    def _refresh_device_details(self) -> None:
        """Populate device name, driver version, and capability flags."""
        if get_xpu_device_info is None:
            self._cur_device_name = "Device info unavailable"
            self._cur_driver_version = "Unknown"
            self._cur_capabilities = "Unknown"
            return

        try:
            info: XPUDeviceInfo | None = get_xpu_device_info(0)
        except (RuntimeError, OSError):
            _logger.exception("xpu_device_info_failed")
            self._cur_device_name = "Unknown device"
            self._cur_driver_version = "Unknown"
            self._cur_capabilities = "Unknown"
            return

        if info is None:
            self.device_name_label.setText("Unknown device")
            self._cur_device_name = "Unknown device"
            self._cur_driver_version = "Unknown"
            self._cur_capabilities = "Unknown"
            return

        device_name = str(info.device_name)
        driver_version = str(info.driver_version) if info.driver_version else "Unknown"
        self.device_name_label.setText(device_name)
        self.driver_label.setText(driver_version)

        caps_parts: list[str] = []
        if info.supports_fp16:
            caps_parts.append("FP16")
        if info.supports_bf16:
            caps_parts.append("BF16")
        if info.supports_int8:
            caps_parts.append("INT8")
        capabilities = " / ".join(caps_parts) if caps_parts else "None detected"
        self.caps_label.setText(capabilities)

        self._cur_device_name = device_name
        self._cur_driver_version = driver_version
        self._cur_capabilities = capabilities

    def _refresh_dtype(self) -> None:
        """Detect and display the optimal dtype."""
        if get_optimal_dtype_for_xpu is None:
            self._cur_optimal_dtype = "Unknown"
            return

        try:
            dtype = get_optimal_dtype_for_xpu()
            self._dtype_label.setText(dtype)
            self._cur_optimal_dtype = dtype
        except (RuntimeError, OSError):
            _logger.exception("xpu_dtype_detection_failed")
            self._dtype_label.setText("Detection failed")
            self._cur_optimal_dtype = "Detection failed"

    def _refresh_live_data(self) -> None:
        """Refresh memory and cache metrics (cheap, timer-safe).

        After refreshing the volatile metrics this performs a cheap availability probe. When XPU availability has flipped since the last
        full device probe (for example, the discrete GPU was physically removed or re-attached) a full device refresh is triggered and the
        resulting state change is logged. Steady-state ticks where nothing meaningful changed stay silent.
        """
        self._refresh_memory()
        self._refresh_cache()
        self._detect_availability_change()

    def _detect_availability_change(self) -> None:
        """Re-probe XPU availability and refresh device info only when it has changed."""
        if is_xpu_available is None:
            return
        try:
            available = is_xpu_available()
        except (RuntimeError, OSError):
            _logger.exception("xpu_availability_check_failed")
            return
        if available != self._cur_available:
            self._refresh_device_info()
            self._log_status_if_changed(forced=False)

    @staticmethod
    def _read_xpu_allocation() -> tuple[int, int] | None:
        """Resolve the active XPU device and read its memory usage.

        Returns:
            tuple[int, int] | None: Tuple of ``(allocated_bytes, total_bytes)``
            when an XPU device is available, or ``None`` when no device is available.
        """
        if is_xpu_available is None or get_xpu_memory_info is None:
            return None
        if not is_xpu_available():
            return None
        return get_xpu_memory_info(0)

    def _refresh_memory(self) -> None:
        """Update memory usage bar and text."""
        if get_xpu_memory_info is None or is_xpu_available is None:
            self.memory_text.setText("XPU memory info not available")
            self.memory_text.setProperty("status", "idle")
            _restyle(self.memory_text)
            self._cur_total_memory_bytes = 0
            return

        try:
            allocation = self._read_xpu_allocation()
        except (RuntimeError, OSError):
            _logger.exception("xpu_memory_info_failed")
            self.memory_bar.setValue(0)
            self.memory_text.setText("Failed to read memory")
            self._cur_total_memory_bytes = 0
            return

        if allocation is None:
            self.memory_bar.setValue(0)
            self.memory_text.setText("No XPU device")
            self.memory_text.setProperty("status", "idle")
            _restyle(self.memory_text)
            self._cur_total_memory_bytes = 0
            return

        allocated, total = allocation
        self._cur_total_memory_bytes = total

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

    def _apply_cache_info(self, cache: ModelCache) -> None:
        """Apply ``cache`` usage and limits to the UI labels.

        Args:
            cache: The global model cache instance.
        """
        usage_bytes = cache.get_memory_usage()
        limit_bytes = cache.max_memory_bytes

        usage_mb = usage_bytes / _BYTES_PER_MB
        limit_mb = limit_bytes / _BYTES_PER_MB

        self.cache_usage_label.setText(f"{usage_mb:.1f} MB")
        self.cache_usage_label.setProperty("status", "")
        _restyle(self.cache_usage_label)
        self.cache_limit_label.setText(f"{limit_mb:.0f} MB")

    def _refresh_cache(self) -> None:
        """Update model cache usage and limit labels."""
        if get_global_model_cache is None:
            self.cache_usage_label.setText("Model cache not available")
            self.cache_usage_label.setProperty("status", "idle")
            _restyle(self.cache_usage_label)
            self.cache_limit_label.setText("N/A")
            return

        try:
            self._apply_cache_info(get_global_model_cache())
        except (RuntimeError, AttributeError):
            _logger.exception("cache_info_failed")
            self.cache_usage_label.setText("Error reading cache")
            self.cache_limit_label.setText("Error")

    def _refresh_requirements(self) -> None:
        """Launch the Windows requirements check on a background thread.

        The previous synchronous implementation spawned three PowerShell subprocesses on the GUI thread, freezing the dialog for ~20
        seconds. Work is now dispatched to :class:`_RequirementsCheckWorker`; results are delivered via :meth:`_on_requirements_ready` /
        :meth:`_on_requirements_failed`. Concurrent invocations (e.g., rapid Refresh clicks) are debounced by checking
        :meth:`QThread.isRunning`.
        """
        if check_windows_requirements is None:
            self.requirements_text.setPlainText("Requirements check not available.")
            return

        existing = self._requirements_worker
        if existing is not None and existing.isRunning():
            _logger.debug("requirements_refresh_debounced")
            return

        self.requirements_text.setPlainText("Checking system requirements...")

        worker = _RequirementsCheckWorker(self)
        worker.result_ready.connect(self._on_requirements_ready)
        worker.check_failed.connect(self._on_requirements_failed)
        worker.finished.connect(self._on_requirements_worker_finished)
        worker.finished.connect(worker.deleteLater)
        self._requirements_worker = worker
        worker.start()

    def _on_requirements_ready(self, result: object) -> None:
        """Render requirements result delivered from the background worker.

        Args:
            result: The :class:`_RequirementsResult` emitted by the worker. Typed as ``object`` because :class:`pyqtSignal` only carries
                primitive Qt types or generic ``object`` payloads.
        """
        if not isinstance(result, _RequirementsResult):
            _logger.warning("requirements_result_unexpected_type", actual_type=type(result).__name__)
            return

        self._cur_requirements_met = result.all_met
        self._cur_requirements_warnings = tuple(result.warnings)
        self._log_status_if_changed(forced=False)

        colors = ThemeManager.get_instance().get_analysis_colors()
        success_hex = colors["success"].name()
        warning_hex = colors["warning"].name()

        if result.all_met and not result.warnings:
            self.requirements_text.setHtml(f'<span style="color: {success_hex}; font-weight: bold;">All system requirements met.</span>')
            return

        lines = [
            f'<span style="color: {warning_hex}; font-weight: bold;">Warnings:</span><ul>',
            *[f"<li>{w}</li>" for w in result.warnings],
            "</ul>",
        ]
        self.requirements_text.setHtml("".join(lines))

    def _on_requirements_failed(self, error: str) -> None:
        """Render a failure message when the background check raises.

        Args:
            error: Human-readable description of the failure surfaced by the worker.
        """
        _logger.warning("requirements_check_failed", error=error)
        self._cur_requirements_met = None
        self._cur_requirements_warnings = (f"Requirements check failed: {error}",)
        self.requirements_text.setPlainText(f"Failed to check requirements: {error}")

    def _on_requirements_worker_finished(self) -> None:
        """Clear the worker reference once the QThread emits ``finished``."""
        self._requirements_worker = None

    @override
    def closeEvent(self, a0: QCloseEvent | None) -> None:
        """Stop the refresh timer and join the requirements worker on close.

        Args:
            a0: The close event.
        """
        self.refresh_timer.stop()
        worker = self._requirements_worker
        if worker is not None and worker.isRunning():
            try:
                worker.result_ready.disconnect(self._on_requirements_ready)
                worker.check_failed.disconnect(self._on_requirements_failed)
                worker.finished.disconnect(self._on_requirements_worker_finished)
            except TypeError:
                _logger.debug("requirements_worker_signals_already_disconnected", exc_info=True)
            if not worker.wait(_REQUIREMENTS_WORKER_WAIT_MS):
                _logger.warning("requirements_worker_did_not_finish", timeout_ms=_REQUIREMENTS_WORKER_WAIT_MS)
        self._requirements_worker = None
        super().closeEvent(a0)
