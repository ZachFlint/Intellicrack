"""Sandbox configuration dialog for Intellicrack.

This module provides the UI for configuring Windows Sandbox settings,
including isolation options, resource limits, and execution policies.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.process_manager import ProcessManager, ProcessType

from .resources import IconManager


_logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from intellicrack.sandbox.manager import SandboxManager


class SandboxTestWorker(QThread):
    """Worker thread for testing Windows Sandbox.

    Launches Windows Sandbox with a test configuration and monitors
    its execution without blocking the UI.

    Attributes:
        finished: Signal emitted when test completes with (success, message).
        output: Signal emitted with sandbox output messages.
    """

    finished: ClassVar[pyqtSignal] = pyqtSignal(bool, str)
    output: ClassVar[pyqtSignal] = pyqtSignal(str)

    def __init__(
        self,
        network_enabled: bool = False,
        memory_limit_mb: int = 2048,
        shared_folder: str | None = None,
        read_only: bool = False,
        parent: QThread | None = None,
    ) -> None:
        """Initialize the sandbox test worker.

        Args:
            network_enabled: Whether networking is enabled.
            memory_limit_mb: Memory limit in MB.
            shared_folder: Path to shared folder.
            read_only: Whether shared folder is read-only.
            parent: Parent QThread.
        """
        super().__init__(parent)
        self._network_enabled = network_enabled
        self._memory_limit_mb = memory_limit_mb
        self._shared_folder = shared_folder
        self._read_only = read_only
        self._wsb_file: Path | None = None
        self._process: subprocess.Popen[bytes] | None = None

    def run(self) -> None:
        """Execute the sandbox test."""
        if sys.platform != "win32":
            self.finished.emit(False, "Windows Sandbox is only available on Windows")
            return

        try:
            self.output.emit("Creating sandbox configuration...")
            wsb_content = self._generate_wsb_config()

            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".wsb",
                delete=False,
                encoding="utf-8",
            ) as wsb_file:
                wsb_file.write(wsb_content)
                self._wsb_file = Path(wsb_file.name)

            self.output.emit(f"Configuration file: {self._wsb_file}")
            self.output.emit("Launching Windows Sandbox...")

            self._process = subprocess.Popen(
                ["WindowsSandbox.exe", str(self._wsb_file)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )

            process_manager = ProcessManager.get_instance()
            process_manager.register(
                self._process,
                name="sandbox-test",
                process_type=ProcessType.SANDBOX,
                metadata={"wsb_config": str(self._wsb_file)},
            )

            self.output.emit("Windows Sandbox launched successfully")
            self.output.emit("Waiting for sandbox to initialize (10 seconds)...")

            try:
                self._process.wait(timeout=10)
                if self._process.returncode != 0:
                    stderr_output = self._process.stderr.read().decode("utf-8", errors="replace") if self._process.stderr else ""
                    self.finished.emit(False, f"Sandbox exited with error: {stderr_output}")
                    return
            except subprocess.TimeoutExpired:
                self.output.emit("Sandbox is running normally")

            self.finished.emit(True, "Windows Sandbox test completed successfully")

        except FileNotFoundError:
            self.finished.emit(
                False,
                "WindowsSandbox.exe not found. Windows Sandbox may not be installed.",
            )
        except PermissionError:
            self.finished.emit(
                False,
                "Permission denied. Administrator rights may be required.",
            )
        except OSError as e:
            self.finished.emit(False, f"Failed to launch sandbox: {e}")
        finally:
            if self._wsb_file and self._wsb_file.exists():
                with contextlib.suppress(OSError):
                    self._wsb_file.unlink()

    def _generate_wsb_config(self) -> str:
        """Generate Windows Sandbox .wsb configuration XML.

        Returns:
            XML configuration string.
        """
        config_lines = ["<Configuration>"]

        config_lines.append("  <VGpu>Enable</VGpu>")

        if self._network_enabled:
            config_lines.append("  <Networking>Enable</Networking>")
        else:
            config_lines.append("  <Networking>Disable</Networking>")

        if self._memory_limit_mb > 0:
            config_lines.append(f"  <MemoryInMB>{self._memory_limit_mb}</MemoryInMB>")

        if self._shared_folder:
            shared_path = Path(self._shared_folder)
            if shared_path.exists():
                config_lines.append("  <MappedFolders>")
                config_lines.append("    <MappedFolder>")
                config_lines.append(f"      <HostFolder>{shared_path}</HostFolder>")
                config_lines.append("      <SandboxFolder>C:\\Shared</SandboxFolder>")
                config_lines.append(f"      <ReadOnly>{'true' if self._read_only else 'false'}</ReadOnly>")
                config_lines.append("    </MappedFolder>")
                config_lines.append("  </MappedFolders>")

        config_lines.append("  <LogonCommand>")
        config_lines.append('    <Command>cmd.exe /c "echo Intellicrack Sandbox Test &amp;&amp; timeout /t 5"</Command>')
        config_lines.append("  </LogonCommand>")

        config_lines.append("</Configuration>")

        return "\n".join(config_lines)

    def stop(self) -> None:
        """Stop the sandbox test and terminate the process."""
        if self._process:
            process_manager = ProcessManager.get_instance()
            process_manager.unregister(self._process.pid)

            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                with contextlib.suppress(OSError):
                    self._process.kill()


class SandboxConfigDialog(QDialog):
    """Dialog for configuring Windows Sandbox.

    Allows users to configure sandbox isolation settings, resource
    limits, network access, and shared folders.

    Attributes:
        settings_updated: Signal emitted when settings change.
    """

    settings_updated: ClassVar[pyqtSignal] = pyqtSignal()

    CONFIG_DIR = Path.home() / ".intellicrack"
    CONFIG_FILE = CONFIG_DIR / "sandbox.json"

    def __init__(
        self,
        sandbox_manager: SandboxManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the sandbox configuration dialog.

        Args:
            sandbox_manager: Sandbox manager instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._manager = sandbox_manager
        self._is_available = False
        self._test_worker: SandboxTestWorker | None = None
        self._progress_dialog: QProgressDialog | None = None

        self._setup_ui()
        self._check_availability()
        self._load_settings()

        self.setWindowTitle("Sandbox Settings")
        self.resize(550, 500)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QVBoxLayout(self)

        self._status_frame = QFrame()
        self._status_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        status_layout = QHBoxLayout(self._status_frame)

        self._status_icon = QLabel()
        status_layout.addWidget(self._status_icon)

        self._status_label = QLabel("Checking Windows Sandbox availability...")
        status_layout.addWidget(self._status_label)
        status_layout.addStretch()

        layout.addWidget(self._status_frame)

        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()

        self._enabled_checkbox = QCheckBox("Enable sandbox for binary execution")
        self._enabled_checkbox.setChecked(True)
        general_layout.addRow(self._enabled_checkbox)

        self._auto_cleanup_checkbox = QCheckBox("Auto-cleanup after execution")
        self._auto_cleanup_checkbox.setChecked(True)
        general_layout.addRow(self._auto_cleanup_checkbox)

        general_group.setLayout(general_layout)
        layout.addWidget(general_group)

        resources_group = QGroupBox("Resource Limits")
        resources_layout = QFormLayout()

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(30, 3600)
        self._timeout_spin.setValue(300)
        self._timeout_spin.setSuffix(" seconds")
        resources_layout.addRow("Execution Timeout:", self._timeout_spin)

        self._memory_spin = QSpinBox()
        self._memory_spin.setRange(512, 16384)
        self._memory_spin.setValue(2048)
        self._memory_spin.setSuffix(" MB")
        self._memory_spin.setSingleStep(256)
        resources_layout.addRow("Memory Limit:", self._memory_spin)

        resources_group.setLayout(resources_layout)
        layout.addWidget(resources_group)

        network_group = QGroupBox("Network Settings")
        network_layout = QFormLayout()

        self._network_enabled_checkbox = QCheckBox("Enable networking in sandbox")
        self._network_enabled_checkbox.setChecked(False)
        self._network_enabled_checkbox.setToolTip("WARNING: Enabling networking allows sandbox to access external resources")
        network_layout.addRow(self._network_enabled_checkbox)

        self._block_telemetry_checkbox = QCheckBox("Block telemetry endpoints")
        self._block_telemetry_checkbox.setChecked(True)
        network_layout.addRow(self._block_telemetry_checkbox)

        network_group.setLayout(network_layout)
        layout.addWidget(network_group)

        folders_group = QGroupBox("Shared Folders")
        folders_layout = QVBoxLayout()

        folder_row = QHBoxLayout()
        self._shared_folder_input = QLineEdit()
        self._shared_folder_input.setReadOnly(True)
        folder_row.addWidget(self._shared_folder_input)

        self._browse_folder_btn = QPushButton("Browse...")
        self._browse_folder_btn.clicked.connect(self._browse_shared_folder)
        folder_row.addWidget(self._browse_folder_btn)

        folders_layout.addLayout(folder_row)

        self._read_only_checkbox = QCheckBox("Mount shared folder as read-only")
        self._read_only_checkbox.setChecked(False)
        folders_layout.addWidget(self._read_only_checkbox)

        folders_group.setLayout(folders_layout)
        layout.addWidget(folders_group)

        button_layout = QHBoxLayout()

        self._test_btn = QPushButton("Test Sandbox")
        self._test_btn.clicked.connect(self._test_sandbox)
        button_layout.addWidget(self._test_btn)

        button_layout.addStretch()

        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel | QDialogButtonBox.StandardButton.Apply
        )
        button_box.accepted.connect(self._on_accept)
        button_box.rejected.connect(self.reject)

        apply_button = button_box.button(QDialogButtonBox.StandardButton.Apply)
        if apply_button:
            apply_button.clicked.connect(self._on_apply)

        button_layout.addWidget(button_box)

        layout.addLayout(button_layout)

    def _check_availability(self) -> None:
        """Check if Windows Sandbox is available."""
        if sys.platform != "win32":
            _logger.info(
                "sandbox_config_validated",
                extra={"valid": False, "reason": "non_windows_platform", "platform": sys.platform},
            )
            self._set_unavailable("Windows Sandbox is only available on Windows")
            return

        try:
            process_manager = ProcessManager.get_instance()
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            result = process_manager.run_tracked(
                [
                    "powershell",
                    "-Command",
                    "Get-WindowsOptionalFeature -FeatureName Containers-DisposableClientVM -Online",
                ],
                name="powershell-sandbox-check",
                check=False,
                timeout=10,
                creationflags=creation_flags,
            )
            if "Enabled" in result.stdout:
                _logger.info(
                    "sandbox_config_validated",
                    extra={"valid": True, "sandbox_available": True},
                )
                self._set_available()
            else:
                _logger.info(
                    "sandbox_config_validated",
                    extra={"valid": False, "reason": "feature_not_enabled"},
                )
                self._set_unavailable("Windows Sandbox feature is not enabled")
        except subprocess.TimeoutExpired:
            _logger.exception(
                "sandbox_config_error",
                extra={"operation": "availability_check", "error": "timeout"},
            )
            self._set_unavailable("Timeout checking Windows Sandbox status")
        except FileNotFoundError:
            _logger.exception(
                "sandbox_config_error",
                extra={"operation": "availability_check", "error": "powershell_not_found"},
            )
            self._set_unavailable("PowerShell not found")
        except OSError as e:
            _logger.exception(
                "sandbox_config_error",
                extra={"operation": "availability_check", "error": str(e)},
            )
            self._set_unavailable(f"Could not determine Windows Sandbox status: {e}")

    def _set_available(self) -> None:
        """Update UI for sandbox available state."""
        self._is_available = True
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_success", 16))
        self._status_label.setText("Windows Sandbox is available")
        self._status_label.setProperty("status", "success")
        style = self._status_label.style()
        if style is not None:
            style.unpolish(self._status_label)
            style.polish(self._status_label)
        self._status_frame.setProperty("toolResult", "success")
        frame_style = self._status_frame.style()
        if frame_style is not None:
            frame_style.unpolish(self._status_frame)
            frame_style.polish(self._status_frame)
        self._set_controls_enabled(True)

    def _set_unavailable(self, reason: str) -> None:
        """Update UI for sandbox unavailable state.

        Args:
            reason: Reason sandbox is unavailable.
        """
        self._is_available = False
        icon_manager = IconManager.get_instance()
        self._status_icon.setPixmap(icon_manager.get_pixmap("status_error", 16))
        self._status_label.setText(f"Windows Sandbox unavailable: {reason}")
        self._status_label.setProperty("status", "error")
        style = self._status_label.style()
        if style is not None:
            style.unpolish(self._status_label)
            style.polish(self._status_label)
        self._status_frame.setProperty("toolResult", "error")
        frame_style = self._status_frame.style()
        if frame_style is not None:
            frame_style.unpolish(self._status_frame)
            frame_style.polish(self._status_frame)
        self._set_controls_enabled(False)

    def _set_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable all configuration controls.

        Args:
            enabled: Whether controls should be enabled.
        """
        self._enabled_checkbox.setEnabled(enabled)
        self._auto_cleanup_checkbox.setEnabled(enabled)
        self._timeout_spin.setEnabled(enabled)
        self._memory_spin.setEnabled(enabled)
        self._network_enabled_checkbox.setEnabled(enabled)
        self._block_telemetry_checkbox.setEnabled(enabled)
        self._browse_folder_btn.setEnabled(enabled)
        self._read_only_checkbox.setEnabled(enabled)
        self._test_btn.setEnabled(enabled)

    def _load_settings(self) -> None:
        """Load settings from config file."""
        default_shared = Path("D:/Intellicrack/sandbox_shared")

        if self.CONFIG_FILE.exists():
            try:
                with open(self.CONFIG_FILE, encoding="utf-8") as f:
                    settings = json.load(f)

                self._enabled_checkbox.setChecked(settings.get("enabled", True))
                self._auto_cleanup_checkbox.setChecked(settings.get("auto_cleanup", True))
                self._timeout_spin.setValue(settings.get("timeout_seconds", 300))
                self._memory_spin.setValue(settings.get("memory_limit_mb", 2048))
                self._network_enabled_checkbox.setChecked(settings.get("network_enabled", False))
                self._block_telemetry_checkbox.setChecked(settings.get("block_telemetry", True))
                self._shared_folder_input.setText(settings.get("shared_folder", str(default_shared)))
                self._read_only_checkbox.setChecked(settings.get("shared_folder_read_only", False))

                _logger.info(
                    "sandbox_config_loaded",
                    extra={"config_file": str(self.CONFIG_FILE), "settings_count": len(settings)},
                )

            except (json.JSONDecodeError, OSError) as e:
                _logger.exception(
                    "sandbox_config_error",
                    extra={"operation": "load", "error": str(e), "config_file": str(self.CONFIG_FILE)},
                )
                self._shared_folder_input.setText(str(default_shared))
        else:
            self._shared_folder_input.setText(str(default_shared))

    def _browse_shared_folder(self) -> None:
        """Open folder browser for shared folder."""
        path = QFileDialog.getExistingDirectory(
            self,
            "Select Shared Folder",
            self._shared_folder_input.text(),
        )
        if path:
            self._shared_folder_input.setText(path)

    def _test_sandbox(self) -> None:
        """Test sandbox by launching a simple instance."""
        if not self._is_available:
            QMessageBox.warning(
                self,
                "Sandbox Unavailable",
                "Windows Sandbox is not available on this system.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Test Sandbox",
            "This will launch Windows Sandbox to verify it's working.\n\nThe sandbox will open briefly for testing.\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        self._test_btn.setEnabled(False)
        self._test_btn.setText("Testing...")

        self._progress_dialog = QProgressDialog(
            "Testing Windows Sandbox...",
            "Cancel",
            0,
            0,
            self,
        )
        self._progress_dialog.setWindowTitle("Sandbox Test")
        self._progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self._progress_dialog.setMinimumDuration(0)
        self._progress_dialog.canceled.connect(self._cancel_test)

        self._test_worker = SandboxTestWorker(
            network_enabled=self._network_enabled_checkbox.isChecked(),
            memory_limit_mb=self._memory_spin.value(),
            shared_folder=self._shared_folder_input.text(),
            read_only=self._read_only_checkbox.isChecked(),
        )
        self._test_worker.finished.connect(self._on_test_finished)
        self._test_worker.output.connect(self._on_test_output)
        self._test_worker.start()

    def _cancel_test(self) -> None:
        """Cancel the sandbox test."""
        if self._test_worker and self._test_worker.isRunning():
            self._test_worker.stop()
            self._test_worker.wait(5000)
            self._test_btn.setEnabled(True)
            self._test_btn.setText("Test Sandbox")

    def _on_test_output(self, message: str) -> None:
        """Handle test output messages.

        Args:
            message: Output message from the test worker.
        """
        if self._progress_dialog:
            self._progress_dialog.setLabelText(message)

    def _on_test_finished(self, success: bool, message: str) -> None:
        """Handle test completion.

        Args:
            success: Whether the test succeeded.
            message: Result message.
        """
        self._test_btn.setEnabled(True)
        self._test_btn.setText("Test Sandbox")

        if self._progress_dialog:
            self._progress_dialog.close()
            self._progress_dialog = None

        if success:
            QMessageBox.information(
                self,
                "Test Complete",
                f"Sandbox test passed!\n\n{message}",
            )
        else:
            QMessageBox.warning(
                self,
                "Test Failed",
                f"Sandbox test failed:\n\n{message}",
            )

    def _on_accept(self) -> None:
        """Handle dialog acceptance."""
        self._save_settings()
        self.accept()

    def _on_apply(self) -> None:
        """Handle apply button click."""
        self._save_settings()

    def _save_settings(self) -> None:
        """Save current settings to config file."""
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        settings = self.get_settings()

        try:
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(settings, f, indent=2)

            shared_folder = Path(settings["shared_folder"])
            if not shared_folder.exists():
                with contextlib.suppress(OSError):
                    shared_folder.mkdir(parents=True, exist_ok=True)

            _logger.info(
                "sandbox_config_saved",
                extra={"config_file": str(self.CONFIG_FILE), "settings_count": len(settings)},
            )

            self.settings_updated.emit()

        except OSError as e:
            _logger.exception(
                "sandbox_config_error",
                extra={"operation": "save", "error": str(e), "config_file": str(self.CONFIG_FILE)},
            )
            QMessageBox.warning(
                self,
                "Save Error",
                f"Failed to save sandbox settings:\n{e}",
            )

    def get_settings(self) -> dict[str, Any]:
        """Get current settings as a dictionary.

        Returns:
            Dictionary of current settings.
        """
        return {
            "enabled": self._enabled_checkbox.isChecked(),
            "auto_cleanup": self._auto_cleanup_checkbox.isChecked(),
            "timeout_seconds": self._timeout_spin.value(),
            "memory_limit_mb": self._memory_spin.value(),
            "network_enabled": self._network_enabled_checkbox.isChecked(),
            "block_telemetry": self._block_telemetry_checkbox.isChecked(),
            "shared_folder": self._shared_folder_input.text(),
            "shared_folder_read_only": self._read_only_checkbox.isChecked(),
        }

    def is_sandbox_available(self) -> bool:
        """Check if sandbox is available.

        Returns:
            True if sandbox is available.
        """
        return self._is_available


class SandboxMonitorWidget(QFrame):
    """Widget for monitoring active sandbox sessions.

    Displays information about running sandbox instances and
    allows control over them.

    Attributes:
        sandbox_stopped: Signal emitted when sandbox is stopped.
    """

    sandbox_stopped: ClassVar[pyqtSignal] = pyqtSignal()

    def __init__(
        self,
        sandbox_manager: SandboxManager | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the sandbox monitor widget.

        Args:
            sandbox_manager: Sandbox manager instance.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._manager = sandbox_manager
        self._sandbox_pid: int | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Set up the widget UI."""
        layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()

        title = QLabel("<b>Sandbox Monitor</b>")
        header_layout.addWidget(title)

        header_layout.addStretch()

        icon_manager = IconManager.get_instance()
        self._status_indicator = QLabel()
        self._status_indicator.setPixmap(icon_manager.get_pixmap("status_idle", 16))
        self._status_indicator.setFixedSize(20, 20)
        header_layout.addWidget(self._status_indicator)

        self._status_text = QLabel("No active sandbox")
        self._status_text.setObjectName("status_text")
        header_layout.addWidget(self._status_text)

        layout.addLayout(header_layout)

        self._output_text = QTextEdit()
        self._output_text.setReadOnly(True)
        self._output_text.setMaximumHeight(150)
        self._output_text.setObjectName("sandbox_output")
        layout.addWidget(self._output_text)

        control_layout = QHBoxLayout()

        self._stop_btn = QPushButton("Stop Sandbox")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_sandbox)
        control_layout.addWidget(self._stop_btn)

        self._clear_btn = QPushButton("Clear Output")
        self._clear_btn.clicked.connect(self._output_text.clear)
        control_layout.addWidget(self._clear_btn)

        control_layout.addStretch()

        layout.addLayout(control_layout)

    def set_running(self, is_running: bool, binary_name: str = "", pid: int | None = None) -> None:
        """Update the running state display.

        Args:
            is_running: Whether sandbox is currently running.
            binary_name: Name of binary being executed.
            pid: Process ID of the sandbox.
        """
        self._sandbox_pid = pid if is_running else None
        icon_manager = IconManager.get_instance()

        if is_running:
            self._status_indicator.setPixmap(icon_manager.get_pixmap("status_success", 16))
            self._status_text.setText(f"Running: {binary_name}")
            self._stop_btn.setEnabled(True)
        else:
            self._status_indicator.setPixmap(icon_manager.get_pixmap("status_idle", 16))
            self._status_text.setText("No active sandbox")
            self._stop_btn.setEnabled(False)

    def append_output(self, text: str) -> None:
        """Append text to the output display.

        Args:
            text: Text to append.
        """
        self._output_text.append(text)

    def _stop_sandbox(self) -> None:
        """Stop the running sandbox."""
        if self._manager is not None:
            try:
                asyncio.run(self._manager.destroy_all())
                self.append_output("[Sandbox stopped via manager]")
            except Exception as e:
                self.append_output(f"[Error stopping sandbox: {e}]")
        elif self._sandbox_pid is not None:
            try:
                if sys.platform == "win32":
                    process_manager = ProcessManager.get_instance()
                    creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
                    process_manager.run_tracked(
                        ["taskkill", "/F", "/PID", str(self._sandbox_pid)],
                        name="taskkill-sandbox-pid",
                        check=False,
                        timeout=10,
                        creationflags=creation_flags,
                    )
                    self.append_output(f"[Sandbox process {self._sandbox_pid} terminated]")
                else:
                    os.kill(self._sandbox_pid, 9)
                    self.append_output(f"[Sandbox process {self._sandbox_pid} killed]")
            except (subprocess.TimeoutExpired, OSError, ProcessLookupError) as e:
                self.append_output(f"[Error terminating sandbox: {e}]")
        else:
            self._terminate_sandbox_by_name()

        self.set_running(False)
        self.sandbox_stopped.emit()

    def _terminate_sandbox_by_name(self) -> None:
        """Terminate Windows Sandbox by process name."""
        if sys.platform != "win32":
            self.append_output("[Cannot terminate sandbox on non-Windows platform]")
            return

        try:
            process_manager = ProcessManager.get_instance()
            creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            result = process_manager.run_tracked(
                ["taskkill", "/F", "/IM", "WindowsSandbox.exe"],
                name="taskkill-sandbox-name",
                check=False,
                timeout=10,
                creationflags=creation_flags,
            )
            if result.returncode == 0:
                self.append_output("[Windows Sandbox terminated]")
            else:
                self.append_output("[No Windows Sandbox process found]")
        except (subprocess.TimeoutExpired, OSError) as e:
            self.append_output(f"[Error: {e}]")
