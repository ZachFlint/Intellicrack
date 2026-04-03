# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""HxD hex editor panel for Intellicrack.

Provides HxD executable detection, process-based embedding into a Qt panel, file loading, and lifecycle management for the HxD hex editor on
Windows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QProcess, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger


if sys.platform == "win32" or TYPE_CHECKING:
    import winreg


_logger = get_logger("ui.panels.hxd_panel")

_HXD_REGISTRY_PATHS: Final[list[str]] = [
    r"SOFTWARE\mh-nexus\HxD\CurrentVersion",
    r"SOFTWARE\WOW6432Node\mh-nexus\HxD\CurrentVersion",
]

_HXD_COMMON_DIRS: Final[list[str]] = [
    r"C:\Program Files\HxD",
    r"C:\Program Files (x86)\HxD",
]

_HXD_EXE_NAME: Final[str] = "HxD.exe"
_EMBED_POLL_INTERVAL_MS: Final[int] = 500
_EMBED_MAX_RETRIES: Final[int] = 15
_PROCESS_TERM_TIMEOUT_MS: Final[int] = 3000


def _find_hxd_executable() -> Path | None:
    """Locate the HxD executable on the system.

    Checks Windows registry entries first, then common installation
    directories, and finally PATH environment variable.

    Returns:
        Path | None: Path to HxD.exe or None if not found.
    """
    if sys.platform != "win32":
        return None

    for reg_path in _HXD_REGISTRY_PATHS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                candidate = Path(str(install_dir)) / _HXD_EXE_NAME
                if candidate.exists() and candidate.is_file():
                    return candidate
        except (FileNotFoundError, OSError):
            continue

    for common_dir in _HXD_COMMON_DIRS:
        candidate = Path(common_dir) / _HXD_EXE_NAME
        if candidate.exists() and candidate.is_file():
            return candidate

    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    for dir_str in path_dirs:
        candidate = Path(dir_str) / _HXD_EXE_NAME
        if candidate.exists() and candidate.is_file():
            return candidate

    return None


def find_hxd_executable() -> Path | None:
    """Locate the HxD executable on the system.

    Checks Windows registry entries first, then common installation
    directories, and finally PATH environment variable.

    Returns:
        Path | None: Path to HxD.exe or None if not found.
    """
    return _find_hxd_executable()


class HxDPanel(QWidget):
    """Panel that embeds the HxD hex editor into Intellicrack.

    Detects HxD installation, launches HxD as a subprocess, and
    provides file loading and lifecycle management.

    Args:
        parent: Parent widget.

    Attributes:
        tool_started: Signal emitted when HxD starts.
        tool_closed: Signal emitted when HxD closes.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.hxd_exe: Path | None = _find_hxd_executable()
        self.current_file: Path | None = None
        self.process: QProcess | None = None
        self.embedded_container: QWidget | None = None
        self.embed_info_label: QLabel = QLabel("HxD not launched")
        self.status_label: QLabel = QLabel()

        self._embed_host = QWidget(self)
        self._embed_timer: QTimer | None = None

        self._setup_ui()
        self._update_status_label()

    def _setup_ui(self) -> None:
        """Set up the panel layout and toolbar."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self.status_label.setStyleSheet("font-weight: bold;")
        toolbar.addWidget(self.status_label)

        toolbar.addStretch()

        open_btn = QPushButton("Open File")
        open_btn.setToolTip("Open a file in HxD")
        open_btn.clicked.connect(self._on_open_file)
        toolbar.addWidget(open_btn)

        layout.addLayout(toolbar)

        self.embed_info_label.setAlignment(
            __import__("PyQt6.QtCore", fromlist=["Qt"]).Qt.AlignmentFlag.AlignCenter,
        )
        layout.addWidget(self.embed_info_label)
        layout.addWidget(self._embed_host, stretch=1)

    @property
    def embed_host(self) -> QWidget:
        """Get the embed host widget.

        Returns:
            QWidget: The widget used to embed HxD.
        """
        return self._embed_host

    def _update_status_label(self) -> None:
        """Update the status label to reflect HxD availability."""
        if self.hxd_exe is None:
            self.status_label.setText("HxD: not found")
        else:
            self.status_label.setText(f"HxD: {self.hxd_exe}")

    def _on_open_file(self) -> None:
        """Handle file open button click."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open File in HxD",
            "",
            "All Files (*)",
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, path: str | Path) -> bool:
        """Load a file in HxD.

        Args:
            path: Path to the file to open.

        Returns:
            bool: True if the file was loaded successfully, False otherwise.
        """
        if self.hxd_exe is None:
            _logger.warning("hxd_not_installed")
            return False

        file_path = Path(path) if isinstance(path, str) else path
        if not file_path.exists():
            _logger.warning("hxd_file_not_found", path=str(file_path))
            return False

        self.current_file = file_path
        self._terminate_existing()

        try:
            self.process = QProcess(self)
            self.process.setProgram(str(self.hxd_exe))
            self.process.setArguments([str(file_path)])
            self.process.start()

            if not self.process.waitForStarted(_PROCESS_TERM_TIMEOUT_MS):
                _logger.warning("hxd_start_failed", path=str(file_path))
                self.process = None
                return False

            self.embed_info_label.setText(f"HxD: {file_path.name}")
            self.tool_started.emit()
            _logger.info("hxd_file_loaded", path=str(file_path))
        except (OSError, RuntimeError) as e:
            _logger.warning("hxd_launch_failed", error=str(e))
            self.process = None
            return False
        else:
            return True

    def start_tool(self) -> bool:
        """Start HxD without a specific file.

        Returns:
            bool: True if HxD started successfully.
        """
        if self.hxd_exe is None:
            _logger.warning("hxd_not_installed")
            return False

        self._terminate_existing()

        try:
            self.process = QProcess(self)
            self.process.setProgram(str(self.hxd_exe))
            self.process.start()

            if not self.process.waitForStarted(_PROCESS_TERM_TIMEOUT_MS):
                self.process = None
                return False

            self.embed_info_label.setText("HxD running")
            self.tool_started.emit()
        except (OSError, RuntimeError) as e:
            _logger.warning("hxd_start_failed", error=str(e))
            self.process = None
            return False
        else:
            return True

    def stop_tool(self) -> bool:
        """Stop HxD and clean up.

        Returns:
            bool: True always (idempotent).
        """
        self._terminate_existing()
        self.embed_info_label.setText("HxD not launched")
        self.tool_closed.emit()
        return True

    def terminate_existing(self) -> None:
        """Terminate any running HxD process and clean up containers."""
        self._terminate_existing()

    def _terminate_existing(self) -> None:
        """Terminate any running HxD process and clean up containers."""
        if self.process is not None:
            try:
                if self.process.state() != QProcess.ProcessState.NotRunning:
                    self.process.terminate()
                    if not self.process.waitForFinished(_PROCESS_TERM_TIMEOUT_MS):
                        self.process.kill()
                        self.process.waitForFinished(_PROCESS_TERM_TIMEOUT_MS)
            except RuntimeError:
                pass
            self.process = None

        if self.embedded_container is not None:
            try:
                self.embedded_container.setParent(None)
                self.embedded_container.deleteLater()
            except RuntimeError:
                pass
            self.embedded_container = None

        if self._embed_timer is not None:
            self._embed_timer.stop()
            self._embed_timer = None

    def cleanup(self) -> None:
        """Perform full cleanup of the HxD panel."""
        self._terminate_existing()
