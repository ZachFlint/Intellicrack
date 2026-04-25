# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox operations mixin for the hex editor panel."""

from __future__ import annotations

import asyncio
import posixpath
import shutil
from pathlib import Path
from typing import Any, Final, override

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.logging import get_logger


_logger = get_logger(__name__)


_DEFAULT_TIMEOUT: Final[int] = 30
_MIN_TIMEOUT: Final[int] = 5
_MAX_TIMEOUT: Final[int] = 300
_WDAG_PATH: Final[str] = r"C:\Users\WDAGUtilityAccount\Desktop"
_CONTAINER_TMP_PREFIX: Final[str] = posixpath.join("/", "tmp")


async def _run_command(
    args: list[str],
    max_seconds: int,
) -> tuple[int, str, str]:
    """Run a command asynchronously and return its exit code and output.

    Args:
        args: Command and arguments list.
        max_seconds: Maximum execution time in seconds.

    Returns:
        tuple[int, str, str]: Exit code, stdout, and stderr strings.

    Raises:
        TimeoutError: If the process exceeds the time limit.
    """
    _logger.info(
        "sandbox_subprocess_invoke",
        argv=args,
        timeout=max_seconds,
    )
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=float(max_seconds),
        )
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return (
        proc.returncode if proc.returncode is not None else -1,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


class SandboxWorker(QThread):
    """Background worker for sandbox operations.

    Runs sandbox save or test operations in a background thread to
    avoid blocking the Qt main thread during subprocess execution.

    Attributes:
        finished_signal: Emitted with result dict on success.
        error_signal: Emitted with error message on failure.
    """

    finished_signal: pyqtSignal = pyqtSignal(dict)
    error_signal: pyqtSignal = pyqtSignal(str)

    def __init__(
        self,
        operation: str,
        file_path: str,
        sandbox_type: str,
        dest_path: str,
        command_args: str,
        timeout: int,
        parent: QThread | None = None,
    ) -> None:
        """Initialize the SandboxWorker with operation parameters.

        Args:
            operation: Either ``"save"`` or ``"test"``.
            file_path: Path to the binary file.
            sandbox_type: Sandbox backend (``"docker"``, ``"qemu"``, ``"windows_sandbox"``).
            dest_path: Destination path inside the sandbox.
            command_args: Command-line arguments for test execution.
            timeout: Maximum wait time in seconds.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._operation = operation
        self._file_path = file_path
        self._sandbox_type = sandbox_type
        self._dest_path = dest_path
        self._command_args = command_args
        self._timeout = timeout

    @override
    def run(self) -> None:
        """Execute the sandbox operation in the background thread."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                self._do_save() if self._operation == "save" else self._do_test(),
            )
            self.finished_signal.emit(result)
        except (OSError, ValueError, TimeoutError, RuntimeError) as exc:
            self.error_signal.emit(str(exc))
        finally:
            loop.close()

    async def _do_save(self) -> dict[str, Any]:
        """Copy the file into the sandbox environment.

        Returns:
            dict[str, Any]: Result with sandbox_path and status.

        Raises:
            FileNotFoundError: If the source file does not exist.
            OSError: If the copy operation fails.
        """
        src = Path(self._file_path)
        src_exists = await asyncio.get_event_loop().run_in_executor(None, src.exists)
        if not src_exists:
            msg = f"Source file not found: {self._file_path}"
            raise FileNotFoundError(msg)

        if self._sandbox_type == "docker":
            container_name = "intellicrack_sandbox"
            dest = self._dest_path or f"{_CONTAINER_TMP_PREFIX}/{src.name}"
            exit_code, _, stderr = await _run_command(
                ["docker", "cp", str(src), f"{container_name}:{dest}"],
                self._timeout,
            )
            if exit_code != 0:
                msg = f"docker cp failed: {stderr.strip()}"
                raise OSError(msg)
            return {"sandbox_path": dest, "status": "copied"}

        if self._sandbox_type == "qemu":
            dest = self._dest_path or f"{_CONTAINER_TMP_PREFIX}/{src.name}"
            exit_code, _, stderr = await _run_command(
                ["scp", "-o", "StrictHostKeyChecking=no", str(src), f"localhost:{dest}"],
                self._timeout,
            )
            if exit_code != 0:
                msg = f"scp failed: {stderr.strip()}"
                raise OSError(msg)
            return {"sandbox_path": dest, "status": "copied"}

        dest_dir = Path(self._dest_path) if self._dest_path else Path(_WDAG_PATH)
        dest_file = dest_dir / src.name
        shutil.copy2(str(src), str(dest_file))
        return {"sandbox_path": str(dest_file), "status": "copied"}

    async def _do_test(self) -> dict[str, Any]:
        """Execute the binary inside the sandbox and capture output.

        Returns:
            dict[str, Any]: Result with exit_code, stdout, and stderr.
        """
        if self._sandbox_type == "docker":
            container_name = "intellicrack_sandbox"
            dest = self._dest_path or f"{_CONTAINER_TMP_PREFIX}/{Path(self._file_path).name}"
            cmd = ["docker", "exec", container_name, dest]
            if self._command_args:
                cmd.extend(self._command_args.split())
        elif self._sandbox_type == "qemu":
            dest = self._dest_path or f"{_CONTAINER_TMP_PREFIX}/{Path(self._file_path).name}"
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "localhost", dest]
            if self._command_args:
                cmd.extend(self._command_args.split())
        else:
            dest = self._dest_path or str(Path(_WDAG_PATH) / Path(self._file_path).name)
            cmd = [dest]
            if self._command_args:
                cmd.extend(self._command_args.split())

        exit_code, stdout, stderr = await _run_command(cmd, self._timeout)
        return {
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
        }


class SandboxMixin:
    """Mixin providing sandbox save and test operations for the hex editor panel."""

    document: Any | None
    file_path: Path | None
    _sandbox_type_combo: QComboBox | None
    _sandbox_dest_input: QLineEdit | None
    _sandbox_args_input: QLineEdit | None
    _sandbox_timeout_spin: QSpinBox | None
    _sandbox_output: QPlainTextEdit | None
    _sandbox_status: QLabel | None
    _sandbox_worker: SandboxWorker | None

    def _create_sandbox_tab(self) -> QWidget:
        """Create the Sandbox side panel tab widget.

        Returns:
            QWidget: Container widget with sandbox type selector,
                destination path, command args, timeout, and output console.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Type:"))
        self._sandbox_type_combo = QComboBox()
        self._sandbox_type_combo.addItems(["docker", "qemu", "windows_sandbox"])
        type_row.addWidget(self._sandbox_type_combo)
        layout.addLayout(type_row)

        layout.addWidget(QLabel("Destination path:"))
        self._sandbox_dest_input = QLineEdit()
        self._sandbox_dest_input.setToolTip("Path inside the sandbox (leave blank for default)")
        layout.addWidget(self._sandbox_dest_input)

        save_btn = QPushButton("Save to Sandbox")
        save_btn.clicked.connect(self._on_save_to_sandbox)
        layout.addWidget(save_btn)

        layout.addWidget(QLabel("Command args:"))
        self._sandbox_args_input = QLineEdit()
        layout.addWidget(self._sandbox_args_input)

        timeout_row = QHBoxLayout()
        timeout_row.addWidget(QLabel("Timeout (s):"))
        self._sandbox_timeout_spin = QSpinBox()
        self._sandbox_timeout_spin.setRange(_MIN_TIMEOUT, _MAX_TIMEOUT)
        self._sandbox_timeout_spin.setValue(_DEFAULT_TIMEOUT)
        timeout_row.addWidget(self._sandbox_timeout_spin)
        timeout_row.addStretch()
        layout.addLayout(timeout_row)

        test_btn = QPushButton("Test in Sandbox")
        test_btn.clicked.connect(self._on_test_in_sandbox)
        layout.addWidget(test_btn)

        self._sandbox_status = QLabel("")
        layout.addWidget(self._sandbox_status)

        self._sandbox_output = QPlainTextEdit()
        self._sandbox_output.setReadOnly(True)
        out_font = self._sandbox_output.font()
        out_font.setFamily("Consolas")
        out_font.setPointSize(9)
        self._sandbox_output.setFont(out_font)
        layout.addWidget(self._sandbox_output)

        self._sandbox_worker = None
        return container

    def _on_save_to_sandbox(self) -> None:
        """Copy the current file to the selected sandbox environment."""
        if self.file_path is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No file is loaded.")
            return

        self._launch_sandbox_worker("save")

    def _on_test_in_sandbox(self) -> None:
        """Execute the current binary in the sandbox and display output."""
        if self.file_path is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No file is loaded.")
            return

        self._launch_sandbox_worker("test")

    def _launch_sandbox_worker(self, operation: str) -> None:
        """Create and start a SandboxWorker for the given operation.

        Args:
            operation: Either ``"save"`` or ``"test"``.
        """
        if self._sandbox_worker is not None and self._sandbox_worker.isRunning():
            return

        sandbox_type = self._sandbox_type_combo.currentText() if self._sandbox_type_combo else "docker"
        dest_path = self._sandbox_dest_input.text().strip() if self._sandbox_dest_input else ""
        command_args = self._sandbox_args_input.text().strip() if self._sandbox_args_input else ""
        timeout = self._sandbox_timeout_spin.value() if self._sandbox_timeout_spin else _DEFAULT_TIMEOUT

        if self._sandbox_status is not None:
            self._sandbox_status.setText(f"Running {operation}...")

        worker = SandboxWorker(
            operation=operation,
            file_path=str(self.file_path),
            sandbox_type=sandbox_type,
            dest_path=dest_path,
            command_args=command_args,
            timeout=timeout,
        )
        worker.finished_signal.connect(self._on_sandbox_finished)
        worker.error_signal.connect(self._on_sandbox_error)
        self._sandbox_worker = worker
        worker.start()

    def _on_sandbox_finished(self, result: dict[str, Any]) -> None:
        """Handle successful sandbox operation completion.

        Args:
            result: Result dictionary from the sandbox worker.
        """
        if self._sandbox_status is not None:
            self._sandbox_status.setText("Done")

        if self._sandbox_output is not None:
            lines: list[str] = [f"{key}: {val}" for key, val in result.items()]
            self._sandbox_output.setPlainText("\n".join(lines))

        _logger.info("sandbox_operation_complete", result_keys=list(result.keys()))

    def _on_sandbox_error(self, error: str) -> None:
        """Handle sandbox operation failure.

        Args:
            error: Error message from the sandbox worker.
        """
        if self._sandbox_status is not None:
            self._sandbox_status.setText("Error")

        if self._sandbox_output is not None:
            self._sandbox_output.setPlainText(f"Error: {error}")

        _logger.warning("sandbox_operation_failed", error=error)
