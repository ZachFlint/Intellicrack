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
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine_logged
from intellicrack.ui.resources.font_manager import FontManager


if TYPE_CHECKING:
    from intellicrack.bridges.hex_editor import HexEditorBridge


_logger = get_logger(__name__)


_DEFAULT_TIMEOUT: Final[int] = 30
_MIN_TIMEOUT: Final[int] = 5
_MAX_TIMEOUT: Final[int] = 300
_CONTAINER_TMP_PREFIX: Final[str] = posixpath.join("/", "tmp")
_BRIDGE_SANDBOX_TYPES: Final[tuple[str, str]] = ("windows", "qemu")


class SandboxMixin:
    """Mixin providing sandbox save and test operations for the hex editor panel."""

    document: Any | None
    file_path: Path | None
    _bridge: HexEditorBridge | None
    _sandbox_type_combo: QComboBox | None
    _sandbox_instance_combo: QComboBox | None
    _sandbox_dest_input: QLineEdit | None
    _sandbox_args_input: QLineEdit | None
    _sandbox_timeout_spin: QSpinBox | None
    _sandbox_output: QPlainTextEdit | None
    _sandbox_status: QLabel | None

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
        self._sandbox_instance_combo.setToolTip(
            "Sandbox instance ID auto-provisioned by the hex editor bridge for the last save/test operation",
        )
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
        out_font = FontManager.get_instance().get_code_font(9)
        self._sandbox_output.setFont(out_font)
        layout.addWidget(self._sandbox_output)

        return container

    def _on_save_to_sandbox(self) -> None:
        """Save the current document into a sandbox via ``HexEditorBridge.save_to_sandbox``.

        Routes through the hex-editor bridge instead of a generic sandbox bridge call so the bridge's auto-provisioning of a sandbox
        instance, orphan-instance cleanup on failure, and unsaved/ in-memory document handling all apply here too. The bridge provisions its
        own instance, so no pre-existing Instance ID is required; the field is populated with the auto-created instance ID once the save
        completes.
        """
        if self.document is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No file is loaded.")
            return

        bridge = self._bridge
        if bridge is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "Hex editor bridge is not attached.")
            return

        sandbox_type = self._sandbox_type_combo.currentText().strip() if self._sandbox_type_combo else "windows"
        default_name = Path(self.file_path).name if self.file_path is not None else "document.bin"
        dest_path = (self._sandbox_dest_input.text().strip() if self._sandbox_dest_input else "") or posixpath.join(
            _CONTAINER_TMP_PREFIX,
            default_name,
        )

        if self._sandbox_status is not None:
            self._sandbox_status.setText("Saving to sandbox...")

        _logger.info("sandbox_save_dispatched", sandbox_type=sandbox_type, dest=dest_path)

        run_bridge_coroutine_logged(
            bridge.save_to_sandbox(dest_path, sandbox_type=sandbox_type),
            on_success=self._on_sandbox_finished_obj,
            on_error=self._on_sandbox_error_obj,
            parent=self if isinstance(self, QWidget) else None,
            event="hex_editor_sandbox_save",
            logger=_logger,
            level="info",
            sandbox_type=sandbox_type,
            dest=dest_path,
        )

    def _on_test_in_sandbox(self) -> None:
        """Execute the current document in a sandbox via ``HexEditorBridge.test_in_sandbox``.

        Routes through the hex-editor bridge instead of a generic sandbox bridge call so the bridge's end-to-end ``run_binary``
        orchestration (instance creation, file copy, execution) is used instead of a raw ``execute`` call against a pre-selected instance.
        Requires the document to already be saved to a file on disk, matching the bridge method's own requirement.
        """
        if self.file_path is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "No file is loaded. Save the document before testing in a sandbox.")
            return

        bridge = self._bridge
        if bridge is None:
            parent = self if isinstance(self, QWidget) else None
            QMessageBox.warning(parent, "Sandbox", "Hex editor bridge is not attached.")
            return

        sandbox_type = self._sandbox_type_combo.currentText().strip() if self._sandbox_type_combo else "windows"
        command_args = self._sandbox_args_input.text().strip() if self._sandbox_args_input else ""
        timeout = self._sandbox_timeout_spin.value() if self._sandbox_timeout_spin else _DEFAULT_TIMEOUT

        if self._sandbox_status is not None:
            self._sandbox_status.setText("Testing in sandbox...")

        _logger.info("sandbox_test_dispatched", sandbox_type=sandbox_type, args=command_args, timeout_s=timeout)

        run_bridge_coroutine_logged(
            bridge.test_in_sandbox(command_args, sandbox_type=sandbox_type, time_limit=timeout),
            on_success=self._on_sandbox_finished_obj,
            on_error=self._on_sandbox_error_obj,
            parent=self if isinstance(self, QWidget) else None,
            event="hex_editor_sandbox_test",
            logger=_logger,
            level="info",
            sandbox_type=sandbox_type,
            args=command_args,
            timeout_s=timeout,
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

        instance_id = result.get("instance_id")
        if isinstance(instance_id, str) and instance_id and self._sandbox_instance_combo is not None:
            if self._sandbox_instance_combo.findText(instance_id) < 0:
                self._sandbox_instance_combo.insertItem(0, instance_id)
            self._sandbox_instance_combo.setCurrentText(instance_id)

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
