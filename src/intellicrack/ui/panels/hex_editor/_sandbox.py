# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Sandbox operations mixin for the hex editor panel."""

from __future__ import annotations

import posixpath
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

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
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_async


if TYPE_CHECKING:
    from intellicrack.bridges.sandbox_bridge import SandboxBridge


_logger = get_logger(__name__)


_DEFAULT_TIMEOUT: Final[int] = 30
_MIN_TIMEOUT: Final[int] = 5
_MAX_TIMEOUT: Final[int] = 300
_CONTAINER_TMP_PREFIX: Final[str] = posixpath.join("/", "tmp")
_BRIDGE_SANDBOX_TYPES: Final[tuple[str, str]] = ("windows", "qemu")


class SandboxMixin:
    """Mixin providing sandbox save and test operations for the hex editor panel."""

    document: object
    file_path: Path | None
    _sandbox_type_combo: QComboBox | None
    _sandbox_instance_combo: QComboBox | None
    _sandbox_dest_input: QLineEdit | None
    _sandbox_args_input: QLineEdit | None
    _sandbox_timeout_spin: QSpinBox | None
    _sandbox_output: QPlainTextEdit | None
    _sandbox_status: QLabel | None
    _sandbox_bridge: SandboxBridge | None

    def set_sandbox_bridge(self, bridge: SandboxBridge) -> None:
        """Attach a SandboxBridge to this mixin for all sandbox operations.

        Args:
            bridge: SandboxBridge instance whose ``copy_to`` and ``execute``
                methods will be called for save and test operations.
        """
        self._sandbox_bridge = bridge

    def _create_sandbox_tab(self) -> QWidget:
        """Create the Sandbox side panel tab widget.

        Returns:
            QWidget: Container widget with sandbox type selector,
                instance selector, destination path, command args,
                timeout, and output console.
        """
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(4)

        type_row = QHBoxLayout()
        type_row.addWidget(QLabel("Type:"))
        self._sandbox_type_combo = QComboBox()
        self._sandbox_type_combo.addItems(list(_BRIDGE_SANDBOX_TYPES))
        type_row.addWidget(self._sandbox_type_combo)
        layout.addLayout(type_row)

        layout.addWidget(QLabel("Instance ID:"))
        self._sandbox_instance_combo = QComboBox()
        self._sandbox_instance_combo.setEditable(True)
        self._sandbox_instance_combo.setInsertPolicy(QComboBox.InsertPolicy.InsertAtTop)
        self._sandbox_instance_combo.setToolTip("Active sandbox instance ID (from SandboxBridge)")
        layout.addWidget(self._sandbox_instance_combo)

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

        self._sandbox_bridge = None
        return container

    def _on_save_to_sandbox(self) -> None:
        """Copy the current file to the selected sandbox environment."""
        if self.file_path is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No file is loaded.")
            return

        bridge = getattr(self, "_sandbox_bridge", None)
        if bridge is None or not hasattr(bridge, "copy_to"):
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No sandbox bridge is attached.")
            return

        instance_id = self._sandbox_instance_combo.currentText().strip() if self._sandbox_instance_combo else ""
        if not instance_id:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No sandbox instance ID specified.")
            return

        file_path = Path(self.file_path)
        src = str(file_path)
        dest_path = self._sandbox_dest_input.text().strip() if self._sandbox_dest_input else ""
        if not dest_path:
            dest_path = posixpath.join(_CONTAINER_TMP_PREFIX, file_path.name)
        timeout = self._sandbox_timeout_spin.value() if self._sandbox_timeout_spin else _DEFAULT_TIMEOUT

        if self._sandbox_status is not None:
            self._sandbox_status.setText("Saving to sandbox...")

        _logger.info("sandbox_save_dispatched", instance_id=instance_id, source=src, dest=dest_path)

        copy_to_fn: SandboxBridge = cast("SandboxBridge", bridge)
        run_bridge_coroutine_async(
            copy_to_fn.copy_to(instance_id, src, dest_path),
            on_success=self._on_sandbox_finished_obj,
            on_error=self._on_sandbox_error_obj,
            parent=self if isinstance(self, QWidget) else None,
        )
        _ = timeout

    def _on_test_in_sandbox(self) -> None:
        """Execute the current binary in the sandbox and display output."""
        if self.file_path is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No file is loaded.")
            return

        bridge = getattr(self, "_sandbox_bridge", None)
        if bridge is None or not hasattr(bridge, "execute"):
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No sandbox bridge is attached.")
            return

        instance_id = self._sandbox_instance_combo.currentText().strip() if self._sandbox_instance_combo else ""
        if not instance_id:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No sandbox instance ID specified.")
            return

        dest_path = self._sandbox_dest_input.text().strip() if self._sandbox_dest_input else ""
        if not dest_path:
            dest_path = posixpath.join(_CONTAINER_TMP_PREFIX, self.file_path.name)
        command_args = self._sandbox_args_input.text().strip() if self._sandbox_args_input else ""
        timeout = self._sandbox_timeout_spin.value() if self._sandbox_timeout_spin else _DEFAULT_TIMEOUT

        command = dest_path
        if command_args:
            command = f"{dest_path} {command_args}"

        if self._sandbox_status is not None:
            self._sandbox_status.setText("Testing in sandbox...")

        _logger.info("sandbox_test_dispatched", instance_id=instance_id, command=command)

        execute_fn: SandboxBridge = cast("SandboxBridge", bridge)
        run_bridge_coroutine_async(
            execute_fn.execute(instance_id, command, time_limit=timeout),
            on_success=self._on_sandbox_finished_obj,
            on_error=self._on_sandbox_error_obj,
            parent=self if isinstance(self, QWidget) else None,
        )

    def _on_sandbox_finished_obj(self, result: object) -> None:
        """Forward worker results to the typed sandbox handler.

        Args:
            result: Raw object emitted by the bridge coroutine on success.
        """
        if isinstance(result, dict):
            self._on_sandbox_finished(cast("dict[str, Any]", result))

    def _on_sandbox_error_obj(self, exc: object) -> None:
        """Forward worker exceptions to the typed sandbox error handler.

        Args:
            exc: Exception object emitted on bridge coroutine failure.
        """
        self._on_sandbox_error(str(exc))

    def _on_sandbox_finished(self, result: dict[str, Any]) -> None:
        """Handle successful sandbox operation completion.

        Args:
            result: Result dictionary from the sandbox bridge coroutine.
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
            error: Error message from the sandbox bridge coroutine.
        """
        if self._sandbox_status is not None:
            self._sandbox_status.setText("Error")

        if self._sandbox_output is not None:
            self._sandbox_output.setPlainText(f"Error: {error}")

        _logger.warning("sandbox_operation_failed", error=error)
