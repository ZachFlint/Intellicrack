# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.

"""HxD hex editor panel for Intellicrack.

Embeds the real HxD.exe application window inside the Intellicrack
GUI using Win32 window capture.  Falls back to an error dialog with
download instructions if HxD is not installed.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import override

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QLabel,
    QMessageBox,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core._subprocess import Popen
from intellicrack.core.logging import get_logger
from intellicrack.core.process_manager import ProcessManager, ProcessType
from intellicrack.ui.panels.base_panel import AnalysisPanelBase
from intellicrack.ui.win32_embed import poll_and_embed


_logger = get_logger("ui.panels.hxd")

_HXD_DOWNLOAD_URL = "https://mh-nexus.de/en/hxd/"

_COMMON_HXD_PATHS: list[Path] = [
    Path(os.environ.get("PROGRAMFILES", "C:\\Program Files")) / "HxD" / "HxD.exe",
    Path(os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")) / "HxD" / "HxD.exe",
    Path(os.environ.get("LOCALAPPDATA", "")) / "HxD" / "HxD.exe",
    Path("D:\\Tools\\HxD\\HxD.exe"),
]


def _find_hxd_executable() -> Path | None:
    """Locate the HxD.exe executable on the system.

    Checks common installation paths and the system PATH.

    Returns:
        Path | None: Path to HxD.exe if found, None otherwise.
    """
    for candidate in _COMMON_HXD_PATHS:
        if candidate.exists():
            return candidate

    path_result = shutil.which("HxD")
    if path_result is not None:
        return Path(path_result)

    path_result_lower = shutil.which("hxd")
    return Path(path_result_lower) if path_result_lower is not None else None


class HxDPanel(AnalysisPanelBase):
    """Panel that embeds the real HxD hex editor application.

    Launches HxD.exe as a subprocess, captures its Win32 window,
    and embeds it inside the panel using QWindow.fromWinId.

    Args:
        parent: Parent widget.

    Attributes:
        tool_started: Signal emitted when HxD starts.
        tool_closed: Signal emitted when HxD closes.
    """

    tool_started: pyqtSignal = pyqtSignal()
    tool_closed: pyqtSignal = pyqtSignal()

    def __init__(self, parent: QWidget | None = None) -> None:
        self._hxd_exe: Path | None = _find_hxd_executable()
        self._process: Popen[bytes] | None = None
        self._embedded_container: QWidget | None = None
        self._current_file: Path | None = None
        super().__init__(parent)

    @override
    def _populate_toolbar(self, toolbar: QToolBar) -> None:
        """Add HxD-specific controls to the toolbar.

        Args:
            toolbar: The toolbar to populate.
        """
        if self._hxd_exe is not None:
            self._status_label = self._add_toolbar_label(toolbar, f"HxD: {self._hxd_exe}")
        else:
            self._status_label = self._add_toolbar_label(toolbar, "HxD: not found")

    @override
    def _create_content(self) -> QWidget:
        """Create the HxD embedding area.

        Returns:
            QWidget: Host widget for the embedded HxD window.
        """
        self._embed_host = QWidget()
        layout = QVBoxLayout(self._embed_host)
        layout.setContentsMargins(0, 0, 0, 0)

        self._embed_info_label = QLabel("HxD not launched")
        self._embed_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._embed_info_label.setFont(QFont("Segoe UI", 10))
        layout.addWidget(self._embed_info_label)

        return self._embed_host

    @override
    def _cleanup(self) -> None:
        """Terminate HxD process and clean up embedded window."""
        self.stop_tool()

    def load_file(self, file_path: Path | str) -> bool:
        """Open a file in HxD.

        Terminates any existing HxD instance and launches a new one
        with the specified file.

        Args:
            file_path: Path to the file to open in the hex editor.

        Returns:
            bool: True if HxD was launched successfully.
        """
        path = Path(file_path) if isinstance(file_path, str) else file_path

        if self._hxd_exe is None:
            self._show_not_installed_dialog()
            return False

        if not path.exists():
            _logger.warning("hxd_file_not_found", path=str(path))
            return False

        self._terminate_existing()

        try:
            self._process = Popen([str(self._hxd_exe), str(path)])

            process_manager = ProcessManager.get_instance()
            process_manager.register(
                self._process,
                name="hxd",
                process_type=ProcessType.EXTERNAL_TOOL,
                metadata={"file": str(path)},
            )

            self._current_file = path
            self._embed_info_label.setText(f"Loading: {path.name}")

            def _on_embedded(container: QWidget) -> None:
                layout = self._embed_host.layout()
                if layout is not None:
                    while layout.count():
                        item = layout.takeAt(0)
                        widget = item.widget() if item is not None else None
                        if widget is not None:
                            widget.setParent(None)
                    layout.addWidget(container)
                self._embedded_container = container
                self.tool_started.emit()
                _logger.info("hxd_window_embedded", file=str(path))

            poll_and_embed(
                pid=self._process.pid,
                parent=self._embed_host,
                callback=_on_embedded,
                max_retries=20,
                interval_ms=500,
            )

            _logger.info("hxd_launched", file=str(path))

        except Exception:
            _logger.exception("hxd_launch_failed", path=str(path))
            return False
        else:
            return True

    def start_tool(self) -> bool:
        """Launch HxD without a specific file.

        Returns:
            bool: True if HxD was launched successfully.
        """
        if self._hxd_exe is None:
            self._show_not_installed_dialog()
            return False

        self._terminate_existing()

        try:
            self._process = Popen([str(self._hxd_exe)])

            process_manager = ProcessManager.get_instance()
            process_manager.register(
                self._process,
                name="hxd",
                process_type=ProcessType.EXTERNAL_TOOL,
                metadata={},
            )

            self._embed_info_label.setText("Launching HxD...")

            def _on_embedded(container: QWidget) -> None:
                layout = self._embed_host.layout()
                if layout is not None:
                    while layout.count():
                        item = layout.takeAt(0)
                        widget = item.widget() if item is not None else None
                        if widget is not None:
                            widget.setParent(None)
                    layout.addWidget(container)
                self._embedded_container = container
                self.tool_started.emit()

            poll_and_embed(
                pid=self._process.pid,
                parent=self._embed_host,
                callback=_on_embedded,
                max_retries=20,
                interval_ms=500,
            )

        except Exception:
            _logger.exception("hxd_start_failed", tool="HxD")
            return False
        else:
            return True

    def stop_tool(self) -> bool:
        """Terminate HxD process.

        Returns:
            bool: True if the process was stopped.
        """
        self._terminate_existing()
        self.tool_closed.emit()
        return True

    def _terminate_existing(self) -> None:
        """Terminate any running HxD process and clear the embedded window."""
        if self._embedded_container is not None:
            self._embedded_container.setParent(None)
            self._embedded_container = None

        if self._process is not None:
            process_pid = self._process.pid
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                    self._process.wait(timeout=3)
                except Exception:
                    _logger.debug("hxd_kill_failed", exc_info=True)

            process_manager = ProcessManager.get_instance()
            process_manager.unregister(process_pid)

            self._process = None
            _logger.debug("hxd_process_terminated", pid=process_pid)

    def _show_not_installed_dialog(self) -> None:
        """Show a dialog informing the user that HxD is not installed."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("HxD Not Found")
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setText(
            "HxD hex editor is not installed on this system.\n\n"
            f"Download HxD from:\n{_HXD_DOWNLOAD_URL}\n\n"
            "Install HxD, then restart Intellicrack."
        )
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()
        _logger.warning("hxd_not_installed_shown", download_url=_HXD_DOWNLOAD_URL)
