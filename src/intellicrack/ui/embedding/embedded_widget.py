"""Base class for embedded external tool widgets.

Provides the foundation for embedding external applications (HxD, x64dbg,
Cutter, etc.) within Qt container widgets using Win32 window parenting.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import QTimer, pyqtSignal
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget

from intellicrack.ui.embedding.win32_helper import Win32WindowHelper


if TYPE_CHECKING:
    from subprocess import Popen

    from PyQt6.QtGui import QCloseEvent, QFocusEvent, QResizeEvent

_logger = logging.getLogger(__name__)

_SW_SHOW = 5
_SW_HIDE = 0


class EmbeddedToolWidget(QWidget):
    """Base widget for embedding external tool windows.

    Manages the lifecycle of an external process and embeds its main
    window as a child of this Qt widget, forwarding resize events
    and handling cleanup on close. Subclasses override the tool-specific
    methods to customize behavior for different applications.
    """

    tool_started = pyqtSignal()
    tool_embedded = pyqtSignal()
    tool_closed = pyqtSignal()
    tool_error = pyqtSignal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the embedded tool widget.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)
        self._process: Popen[bytes] | None = None
        self._embedded_hwnd: int = 0
        self._original_parent: int = 0
        self._container_hwnd: int = 0
        self._poll_timer: QTimer | None = None
        self._loaded_file: Path | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the initial loading UI shown before tool embedding completes."""
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)

        self._status_label = QLabel(f"Loading {self.get_tool_display_name()}...")
        self._status_label.setStyleSheet("color: #888; font-size: 14px; padding: 20px;")
        self._layout.addWidget(self._status_label)

    def get_executable_path(self) -> Path | None:
        """Get the path to the tool executable.

        Subclasses must override this method to return the actual tool path.

        Returns:
            Path to the executable, or None if not configured.
        """
        return None

    def get_window_search_params(self) -> dict[str, str | None]:
        """Get parameters for finding the tool's main window.

        Subclasses should override to provide tool-specific search criteria.

        Returns:
            Dictionary with 'class_name' and/or 'title_contains' keys.
        """
        return {"class_name": None, "title_contains": None}

    def get_tool_display_name(self) -> str:
        """Get the display name of the tool.

        Subclasses should override to provide the actual tool name.

        Returns:
            Human-readable tool name.
        """
        return "External Tool"

    def prepare_launch_args(self, binary_path: Path | None = None) -> list[str]:
        """Prepare command-line arguments for launching the tool.

        Subclasses should override to provide tool-specific arguments.

        Args:
            binary_path: Optional path to binary to open.

        Returns:
            List of command-line arguments starting with executable path.
        """
        exe_path = self.get_executable_path()
        if not exe_path:
            return []
        args = [str(exe_path)]
        if binary_path:
            args.append(str(binary_path))
        return args

    def start_tool(self, binary_path: Path | None = None) -> bool:
        """Start the external tool and embed its window.

        Args:
            binary_path: Optional path to binary to open in the tool.

        Returns:
            True if tool was started successfully, False otherwise.
        """
        exe_path = self.get_executable_path()
        if not exe_path or not exe_path.exists():
            error_msg = f"Executable not found: {exe_path}"
            _logger.error("executable_not_found", extra={"path": str(exe_path)})
            self.tool_error.emit(error_msg)
            self._status_label.setText(f"{self.get_tool_display_name()} not found")
            return False

        args = self.prepare_launch_args(binary_path)
        self._loaded_file = binary_path

        try:
            self._process = self._launch_process(args)
            self.tool_started.emit()
            _logger.info(
                "tool_started",
                extra={"executable": exe_path.name, "pid": self._process.pid},
            )
        except (OSError, subprocess.SubprocessError) as e:
            error_msg = f"Failed to start {exe_path.name}: {e}"
            _logger.exception(
                "tool_start_failed",
                extra={"executable": exe_path.name},
            )
            self.tool_error.emit(error_msg)
            self._status_label.setText(f"Failed to start {self.get_tool_display_name()}")
            return False

        QTimer.singleShot(500, self._attempt_embedding)
        return True

    def _launch_process(self, args: list[str]) -> Popen[bytes]:
        """Launch the tool process.

        Args:
            args: Command-line arguments including executable path.

        Returns:
            Popen object for the launched process.
        """
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = _SW_HIDE

        return subprocess.Popen(
            args,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )

    def _attempt_embedding(self) -> None:
        """Attempt to find and embed the tool window."""
        if not self._process or self._process.poll() is not None:
            self._status_label.setText(f"{self.get_tool_display_name()} process ended")
            self.tool_closed.emit()
            return

        search_params = self.get_window_search_params()
        hwnd = Win32WindowHelper.find_window_by_pid(
            self._process.pid,
            timeout=8.0,
            class_name=search_params.get("class_name"),
            title_contains=search_params.get("title_contains"),
        )

        if not hwnd:
            _logger.warning(
                "window_not_found",
                extra={"tool": self.get_tool_display_name()},
            )
            self._status_label.setText(f"Waiting for {self.get_tool_display_name()} window...")
            QTimer.singleShot(1000, self._attempt_embedding)
            return

        self._embed_window(hwnd)

    def _embed_window(self, hwnd: int) -> bool:
        """Embed an external window into this widget.

        Args:
            hwnd: Handle to the window to embed.

        Returns:
            True if embedding succeeded, False otherwise.
        """
        if not Win32WindowHelper.is_window_valid(hwnd):
            return False

        self._embedded_hwnd = hwnd
        self._container_hwnd = int(self.winId())

        Win32WindowHelper.remove_window_borders(hwnd)
        self._original_parent = Win32WindowHelper.set_parent(hwnd, self._container_hwnd)

        Win32WindowHelper.show_window(hwnd, _SW_SHOW)

        self._resize_embedded()

        self._status_label.hide()

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_window)
        self._poll_timer.start(500)

        self.tool_embedded.emit()
        _logger.info(
            "window_embedded",
            extra={"tool": self.get_tool_display_name(), "hwnd": hex(hwnd)},
        )
        return True

    def _resize_embedded(self) -> None:
        """Resize the embedded window to fill this widget."""
        if not self._embedded_hwnd:
            return

        width = self.width()
        height = self.height()

        Win32WindowHelper.move_window(self._embedded_hwnd, 0, 0, width, height)

    def _poll_window(self) -> None:
        """Check if the embedded window is still valid."""
        if not self._embedded_hwnd:
            return

        if not Win32WindowHelper.is_window_valid(self._embedded_hwnd):
            _logger.info(
                "window_closed",
                extra={"tool": self.get_tool_display_name()},
            )
            self._embedded_hwnd = 0
            self._cleanup_timer()
            self.tool_closed.emit()

    def _cleanup_timer(self) -> None:
        """Stop and clean up the poll timer."""
        if self._poll_timer:
            self._poll_timer.stop()
            self._poll_timer.deleteLater()
            self._poll_timer = None

    def _restore_window(self) -> None:
        """Restore the embedded window to its original state."""
        if not self._embedded_hwnd:
            return

        if not Win32WindowHelper.is_window_valid(self._embedded_hwnd):
            self._embedded_hwnd = 0
            return

        parent_hwnd = self._original_parent if self._original_parent else 0
        Win32WindowHelper.set_parent(self._embedded_hwnd, parent_hwnd)

        Win32WindowHelper.restore_window_borders(self._embedded_hwnd)
        Win32WindowHelper.show_window(self._embedded_hwnd, _SW_SHOW)

        self._embedded_hwnd = 0
        self._original_parent = 0

    def stop_tool(self) -> None:
        """Stop the embedded tool and clean up."""
        self._cleanup_timer()

        if self._embedded_hwnd and Win32WindowHelper.is_window_valid(self._embedded_hwnd):
            Win32WindowHelper.close_window(self._embedded_hwnd)

        self._embedded_hwnd = 0

        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
            except Exception as e:
                _logger.warning(
                    "process_termination_error",
                    extra={"error": str(e)},
                )

        self._process = None
        self._loaded_file = None

    def cleanup(self) -> None:
        """Full cleanup including restoring window state."""
        self._cleanup_timer()
        self._restore_window()

        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self._process.kill()
            except Exception:
                _logger.debug("cleanup_exception_ignored")

        self._process = None

    def is_tool_running(self) -> bool:
        """Check if the tool process is running.

        Returns:
            True if the tool is running, False otherwise.
        """
        return self._process is not None and self._process.poll() is None

    def is_embedded(self) -> bool:
        """Check if a window is currently embedded.

        Returns:
            True if a window is embedded, False otherwise.
        """
        return self._embedded_hwnd != 0 and Win32WindowHelper.is_window_valid(self._embedded_hwnd)

    def get_loaded_file(self) -> Path | None:
        """Get the currently loaded file path.

        Returns:
            Path to the loaded file, or None if no file loaded.
        """
        return self._loaded_file

    def resizeEvent(self, event: QResizeEvent | None) -> None:
        """Handle resize events by forwarding to embedded window.

        Args:
            event: Resize event object.
        """
        super().resizeEvent(event)
        self._resize_embedded()

    def focusInEvent(self, event: QFocusEvent | None) -> None:
        """Handle focus events by forwarding to embedded window.

        Args:
            event: Focus event object.
        """
        super().focusInEvent(event)
        if self._embedded_hwnd and Win32WindowHelper.is_window_valid(self._embedded_hwnd):
            Win32WindowHelper.set_foreground_window(self._embedded_hwnd)

    def closeEvent(self, event: QCloseEvent | None) -> None:
        """Handle close events by cleaning up the embedded tool.

        Args:
            event: Close event object.
        """
        self.cleanup()
        super().closeEvent(event)
