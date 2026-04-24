# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Zachary Flint
#
# This file is part of Intellicrack. See LICENSE for details.
"""Session manager dialog for Intellicrack.

This module provides the UI for managing analysis sessions, including listing, loading, saving, and deleting sessions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, cast

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from intellicrack.core.config import get_config_dir
from intellicrack.core.logging import get_logger
from intellicrack.ui.panels.async_bridge import run_bridge_coroutine


_logger = get_logger("ui.session_manager")

_DIALOG_WIDTH: Final[int] = 800
_DIALOG_HEIGHT: Final[int] = 500
_SPLIT_LEFT: Final[int] = 450
_SPLIT_RIGHT: Final[int] = 350
_CONFIRM_DIALOG_WIDTH: Final[int] = 400
_CONFIRM_DIALOG_HEIGHT: Final[int] = 200

if TYPE_CHECKING:
    from intellicrack.core.session import SessionManager, SessionMetadata

MESSAGE_PREVIEW_MAX_LENGTH = 100


class SessionManagerDialog(QDialog):
    """Dialog for managing analysis sessions.

    Allows users to:
    - View list of saved sessions
    - Load previous sessions
    - Save current session
    - Delete old sessions
    - Export/import sessions

    Attributes:
        session_loaded: Signal emitted when a session is loaded.
        session_deleted: Signal emitted when a session is deleted.
        SESSIONS_DIR: Directory where serialized session files are stored.
    """

    session_loaded: ClassVar[pyqtSignal] = pyqtSignal(str)
    session_deleted: ClassVar[pyqtSignal] = pyqtSignal(str)

    SESSIONS_DIR: ClassVar[Path] = get_config_dir() / "sessions"

    def __init__(
        self,
        session_manager: SessionManager | None = None,
        current_session_id: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        """Initialize the SessionManagerDialog with session state.

        Args:
            session_manager: Session manager for loading and saving sessions.
            current_session_id: ID of the currently active session.
            parent: Parent widget.
        """
        super().__init__(parent)
        self._manager = session_manager
        self._current_session_id = current_session_id
        self._sessions: list[dict[str, object]] = []

        self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        self._setup_ui()
        self._load_sessions()

        self.setWindowTitle("Session Manager")
        self.resize(_DIALOG_WIDTH, _DIALOG_HEIGHT)

    def _setup_ui(self) -> None:
        """Set up the dialog UI layout."""
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._create_left_panel())
        splitter.addWidget(self._create_right_panel())
        splitter.setSizes([_SPLIT_LEFT, _SPLIT_RIGHT])
        layout.addWidget(splitter)
        layout.addLayout(self._create_bottom_buttons())

    def _create_left_panel(self) -> QWidget:
        """Create the left panel with session table.

        Returns:
            QWidget: Widget containing the session table and action buttons.
        """
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        self._setup_session_table()
        panel_layout.addWidget(self._session_table)
        panel_layout.addLayout(self._create_table_buttons())
        return panel

    def _setup_session_table(self) -> None:
        """Initialize and configure the session table widget."""
        self._session_table = QTableWidget()
        self._session_table.setColumnCount(4)
        self._session_table.setHorizontalHeaderLabels(["Name", "Created", "Modified", "Messages"])
        self._session_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._session_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._session_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        sm_v_header = self._session_table.verticalHeader()
        if sm_v_header is not None:
            sm_v_header.setVisible(v=False)
        header = self._session_table.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(stretch=True)
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._session_table.itemSelectionChanged.connect(self._on_selection_changed)
        self._session_table.itemDoubleClicked.connect(self._on_double_click)

    def _create_table_buttons(self) -> QHBoxLayout:
        """Create refresh and delete buttons for the table.

        Returns:
            QHBoxLayout: Layout containing the table action buttons.
        """
        layout = QHBoxLayout()
        self._refresh_btn = QPushButton("Refresh")
        self._refresh_btn.clicked.connect(self._load_sessions)
        layout.addWidget(self._refresh_btn)
        self._delete_btn = QPushButton("Delete")
        self._delete_btn.setEnabled(False)
        self._delete_btn.clicked.connect(self._delete_session)
        layout.addWidget(self._delete_btn)
        layout.addStretch()
        return layout

    def _create_right_panel(self) -> QWidget:
        """Create the right panel with details and preview.

        Returns:
            QWidget: Widget containing session details and preview.
        """
        panel = QWidget()
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.addWidget(self._create_details_group())
        panel_layout.addWidget(self._create_preview_group())
        return panel

    def _create_details_group(self) -> QGroupBox:
        """Create the session details group box.

        Returns:
            QGroupBox: Group box containing session detail labels.
        """
        group = QGroupBox("Session Details")
        form = QFormLayout()
        self._id_label = QLabel("-")
        self._id_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        form.addRow("ID:", self._id_label)
        self._created_label = QLabel("-")
        form.addRow("Created:", self._created_label)
        self._modified_label = QLabel("-")
        form.addRow("Modified:", self._modified_label)
        self._provider_label = QLabel("-")
        form.addRow("Provider:", self._provider_label)
        self._model_label = QLabel("-")
        form.addRow("Model:", self._model_label)
        self._messages_label = QLabel("-")
        form.addRow("Messages:", self._messages_label)
        self._binaries_label = QLabel("-")
        form.addRow("Binaries:", self._binaries_label)
        group.setLayout(form)
        return group

    def _create_preview_group(self) -> QGroupBox:
        """Create the preview group box.

        Returns:
            QGroupBox: Group box containing the preview text widget.
        """
        group = QGroupBox("Preview")
        layout = QVBoxLayout()
        self._preview_text = QTextEdit()
        self._preview_text.setReadOnly(ro=True)
        self._preview_text.setStyleSheet("font-family: 'Consolas', 'Courier New', monospace; font-size: 10px;")
        layout.addWidget(self._preview_text)
        group.setLayout(layout)
        return group

    def _create_bottom_buttons(self) -> QHBoxLayout:
        """Create the bottom button row.

        Returns:
            QHBoxLayout: Layout containing export, import, load and close buttons.
        """
        layout = QHBoxLayout()
        export_btn = QPushButton("Export...")
        export_btn.clicked.connect(self._export_session)
        layout.addWidget(export_btn)
        import_btn = QPushButton("Import...")
        import_btn.clicked.connect(self._import_session)
        layout.addWidget(import_btn)
        layout.addStretch()
        self._load_btn = QPushButton("Load Session")
        self._load_btn.setEnabled(False)
        self._load_btn.clicked.connect(self._load_selected_session)
        layout.addWidget(self._load_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        layout.addWidget(close_btn)
        return layout

    def _load_sessions(self) -> None:
        """Load sessions from the session manager or filesystem."""
        self._session_table.setRowCount(0)
        self._sessions = []

        if self._manager is not None:
            try:
                metadata_list = self._manager.list_sessions()
                for metadata in metadata_list:
                    session_data = self._metadata_to_dict(metadata)
                    self._sessions.append(session_data)
            except (AttributeError, TypeError) as e:
                _logger.warning("session_list_failed_using_disk_fallback", error=str(e))
                self._load_sessions_from_disk()
        else:
            self._load_sessions_from_disk()

        for session in self._sessions:
            row = self._session_table.rowCount()
            self._session_table.insertRow(row)

            name_item = QTableWidgetItem(str(session["name"]))
            name_item.setData(Qt.ItemDataRole.UserRole, session["id"])
            self._session_table.setItem(row, 0, name_item)

            created_at = session.get("created_at")
            if isinstance(created_at, datetime):
                created_str = created_at.strftime("%Y-%m-%d %H:%M")
            elif isinstance(created_at, str):
                created_str = created_at[:16]
            else:
                created_str = "-"
            self._session_table.setItem(row, 1, QTableWidgetItem(created_str))

            updated_at = session.get("updated_at")
            if isinstance(updated_at, datetime):
                modified_str = updated_at.strftime("%Y-%m-%d %H:%M")
            elif isinstance(updated_at, str):
                modified_str = updated_at[:16]
            else:
                modified_str = "-"
            self._session_table.setItem(row, 2, QTableWidgetItem(modified_str))

            msg_count = str(session.get("message_count", 0))
            self._session_table.setItem(row, 3, QTableWidgetItem(msg_count))

            if session["id"] == self._current_session_id:
                for col in range(4):
                    if item := self._session_table.item(row, col):
                        font = item.font()
                        font.setBold(enable=True)
                        item.setFont(font)

        _logger.info("session_list_refreshed", count=len(self._sessions))

    def _load_sessions_from_disk(self) -> None:
        """Load sessions from disk storage."""
        if not self.SESSIONS_DIR.exists():
            return

        for session_file in self.SESSIONS_DIR.glob("*.json"):
            try:
                with session_file.open(encoding="utf-8") as f:
                    session_data = json.load(f)

                if "id" not in session_data:
                    session_data["id"] = session_file.stem

                if "name" not in session_data:
                    session_data["name"] = session_file.stem

                if "created_at" in session_data and isinstance(session_data["created_at"], str):
                    try:
                        session_data["created_at"] = datetime.fromisoformat(session_data["created_at"])
                    except ValueError as e:
                        _logger.debug("session_datetime_parse_failed", error=str(e))
                        session_data["created_at"] = datetime.now(tz=UTC)

                if "updated_at" in session_data and isinstance(session_data["updated_at"], str):
                    try:
                        session_data["updated_at"] = datetime.fromisoformat(session_data["updated_at"])
                    except ValueError as e:
                        _logger.debug("session_datetime_parse_failed", error=str(e))
                        session_data["updated_at"] = datetime.now(tz=UTC)

                self._sessions.append(session_data)

            except (json.JSONDecodeError, OSError) as e:
                _logger.warning(
                    "session_file_load_failed",
                    file=str(session_file),
                    error=str(e),
                )
                continue

        sort_sentinel = datetime.min.replace(tzinfo=UTC)

        def _sort_key(s: dict[str, object]) -> datetime:
            val = s.get("updated_at")
            return val if isinstance(val, datetime) else sort_sentinel

        self._sessions.sort(key=_sort_key, reverse=True)

    @staticmethod
    def _metadata_to_dict(metadata: SessionMetadata) -> dict[str, object]:
        """Convert a SessionMetadata object to a dictionary.

        Args:
            metadata: SessionMetadata object to convert.

        Returns:
            dict[str, object]: Dictionary representation of the session metadata.
        """
        try:
            return {
                "id": metadata.id,
                "name": metadata.name,
                "created_at": metadata.created_at,
                "updated_at": metadata.updated_at,
                "message_count": metadata.message_count,
                "provider": str(metadata.provider.value) if hasattr(metadata.provider, "value") else str(metadata.provider),
                "model": metadata.model,
                "binaries": [],
                "binary_count": metadata.binary_count,
            }
        except (AttributeError, TypeError) as e:
            _logger.warning("metadata_conversion_failed", error=str(e))
            return {
                "id": str(metadata) if metadata else "unknown",
                "name": "Unknown Session",
                "created_at": datetime.now(tz=UTC),
                "updated_at": datetime.now(tz=UTC),
                "message_count": 0,
                "provider": "-",
                "model": "-",
                "binaries": [],
                "binary_count": 0,
            }

    def _on_selection_changed(self) -> None:
        """Handle session selection change."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        if selected_rows := sel_model.selectedRows():
            row = selected_rows[0].row()
            name_item = self._session_table.item(row, 0)
            if name_item is None:
                return
            session_id = name_item.data(Qt.ItemDataRole.UserRole)

            if session := next((s for s in self._sessions if s["id"] == session_id), None):
                self._update_details(session)
                self._load_btn.setEnabled(True)
                self._delete_btn.setEnabled(session["id"] != self._current_session_id)
                _logger.info("session_selected", session_id=session_id)
        else:
            self._clear_details()
            self._load_btn.setEnabled(False)
            self._delete_btn.setEnabled(False)

    def _on_double_click(self, _item: QTableWidgetItem) -> None:
        """Handle double-click on session.

        Args:
            _item: The double-clicked item.
        """
        self._load_selected_session()

    def _update_details(self, session: dict[str, object]) -> None:
        """Update the details panel with session info.

        Args:
            session: Session data dictionary.
        """
        self._id_label.setText(str(session["id"]))

        created_at = session.get("created_at")
        if isinstance(created_at, datetime):
            self._created_label.setText(created_at.strftime("%Y-%m-%d %H:%M:%S"))
        elif isinstance(created_at, str):
            self._created_label.setText(created_at)
        else:
            self._created_label.setText("-")

        updated_at = session.get("updated_at")
        if isinstance(updated_at, datetime):
            self._modified_label.setText(updated_at.strftime("%Y-%m-%d %H:%M:%S"))
        elif isinstance(updated_at, str):
            self._modified_label.setText(updated_at)
        else:
            self._modified_label.setText("-")

        provider_val = session.get("provider")
        self._provider_label.setText(str(provider_val) if isinstance(provider_val, str) else "-")
        model_val = session.get("model")
        self._model_label.setText(str(model_val) if isinstance(model_val, str) else "-")
        self._messages_label.setText(str(session.get("message_count", 0)))

        binaries_raw = session.get("binaries")
        binaries: list[str] = [str(b) for b in cast("list[object]", binaries_raw)] if isinstance(binaries_raw, list) else []
        self._binaries_label.setText(", ".join(binaries) if binaries else "-")

        preview_text = f"Session: {session['name']}\n"
        preview_text += f"Provider: {provider_val or 'N/A'}\n"
        preview_text += f"Model: {model_val or 'N/A'}\n"
        preview_text += "\nBinaries analyzed:\n"
        for binary in binaries:
            preview_text += f"  - {binary}\n"
        preview_text += f"\nTotal messages: {session.get('message_count', 0)}"

        messages_raw = session.get("messages")
        if isinstance(messages_raw, list) and messages_raw:
            preview_text += "\n\nRecent messages:\n"
            recent_messages = cast("list[object]", messages_raw[-3:])
            for msg_obj in recent_messages:
                if isinstance(msg_obj, dict):
                    msg_dict = cast("dict[str, object]", msg_obj)
                    role = str(msg_dict.get("role", "unknown"))
                    content_raw = msg_dict.get("content", "")
                    content_str = str(content_raw) if content_raw else ""
                    if len(content_str) > MESSAGE_PREVIEW_MAX_LENGTH:
                        content_str = f"{content_str[:MESSAGE_PREVIEW_MAX_LENGTH]}..."
                    preview_text += f"  [{role}]: {content_str}\n"

        self._preview_text.setText(preview_text)

    def _clear_details(self) -> None:
        """Clear the details panel."""
        self._id_label.setText("-")
        self._created_label.setText("-")
        self._modified_label.setText("-")
        self._provider_label.setText("-")
        self._model_label.setText("-")
        self._messages_label.setText("-")
        self._binaries_label.setText("-")
        self._preview_text.clear()

    def _load_selected_session(self) -> None:
        """Load the currently selected session."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        selected_rows = sel_model.selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        name_item = self._session_table.item(row, 0)
        if name_item is None:
            return
        session_id: str = name_item.data(Qt.ItemDataRole.UserRole)

        if session_id == self._current_session_id:
            QMessageBox.information(
                self,
                "Session Active",
                "This session is already active.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Load Session",
            "Load this session? Current session progress will be saved.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            _logger.debug("session_load_requested", session_id=session_id)
            self.session_loaded.emit(session_id)
            self.accept()

    def _delete_session(self) -> None:
        """Delete the currently selected session."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        selected_rows = sel_model.selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        name_item = self._session_table.item(row, 0)
        if name_item is None:
            return
        session_id: str = name_item.data(Qt.ItemDataRole.UserRole)
        session_name: str = name_item.text()

        if session_id == self._current_session_id:
            QMessageBox.warning(
                self,
                "Cannot Delete",
                "Cannot delete the currently active session.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Delete Session",
            f"Delete session '{session_name}'?\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes and self._delete_session_sync(session_id):
            _logger.info("session_deleted", session_id=session_id)
            self.session_deleted.emit(session_id)
            self._load_sessions()

    def _delete_session_sync(self, session_id: str) -> bool:
        """Delete a session synchronously.

        When a session manager is available the deletion is routed through
        ``SessionManager.delete`` via the shared bridge event loop so it is
        reflected in the backing ``SessionStore``. When no manager is
        provided, the on-disk sidecar fallback is used instead.

        Args:
            session_id: Session identifier.

        Returns:
            bool: True if deleted successfully.
        """
        if self._manager is not None:
            try:
                result = run_bridge_coroutine(self._manager.delete(session_id))
            except (OSError, RuntimeError, ValueError) as e:
                _logger.warning(
                    "session_delete_failed",
                    session_id=session_id,
                    error=str(e),
                )
                QMessageBox.warning(
                    self,
                    "Delete Failed",
                    f"Failed to delete session:\n{e}",
                )
                return False
            if result is None:
                return True
            return bool(result)

        session_file = self.SESSIONS_DIR / f"{session_id}.json"
        if session_file.exists():
            try:
                session_file.unlink()
            except OSError as e:
                _logger.warning(
                    "session_delete_failed",
                    session_id=session_id,
                    error=str(e),
                )
                QMessageBox.warning(
                    self,
                    "Delete Failed",
                    f"Failed to delete session file:\n{e}",
                )
                return False
            else:
                return True
        return True

    def _export_session(self) -> None:
        """Export selected session to file."""
        sel_model = self._session_table.selectionModel()
        if sel_model is None:
            return
        selected_rows = sel_model.selectedRows()
        if not selected_rows:
            QMessageBox.information(
                self,
                "Export Session",
                "Please select a session to export.",
            )
            return

        row = selected_rows[0].row()
        name_item = self._session_table.item(row, 0)
        if name_item is None:
            return
        session_id: str = name_item.data(Qt.ItemDataRole.UserRole)
        session_name: str = name_item.text()

        session_data = next((s for s in self._sessions if s["id"] == session_id), None)
        if session_data is None:
            QMessageBox.warning(
                self,
                "Export Failed",
                "Could not find session data.",
            )
            return

        safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in session_name)
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Session",
            f"{safe_name}.json",
            "JSON Files (*.json);;All Files (*)",
        )

        if path:
            try:
                export_data = self._prepare_export_data(session_data)

                with Path(path).open("w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, default=str)

                _logger.debug(
                    "session_exported",
                    session_id=session_id,
                    path=path,
                )
                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Session exported to:\n{path}",
                )
            except (OSError, TypeError) as e:
                _logger.warning(
                    "session_export_failed",
                    session_id=session_id,
                    error=str(e),
                )
                QMessageBox.warning(
                    self,
                    "Export Failed",
                    f"Failed to export session:\n{e}",
                )

    @staticmethod
    def _prepare_export_data(session_data: dict[str, object]) -> dict[str, object]:
        """Prepare session data for export.

        Args:
            session_data: Raw session data.

        Returns:
            dict[str, object]: Cleaned session data suitable for JSON export.
        """
        export_data = {
            "id": session_data.get("id"),
            "name": session_data.get("name"),
            "provider": session_data.get("provider"),
            "model": session_data.get("model"),
            "message_count": session_data.get("message_count", 0),
            "binaries": session_data.get("binaries", []),
            "export_version": "1.0",
            "exported_at": datetime.now(tz=UTC).isoformat(),
        }

        created_at = session_data.get("created_at")
        if isinstance(created_at, datetime):
            export_data["created_at"] = created_at.isoformat()
        elif created_at:
            export_data["created_at"] = str(created_at)

        updated_at = session_data.get("updated_at")
        if isinstance(updated_at, datetime):
            export_data["updated_at"] = updated_at.isoformat()
        elif updated_at:
            export_data["updated_at"] = str(updated_at)

        messages_export_raw = session_data.get("messages")
        if isinstance(messages_export_raw, list):
            messages_export: list[dict[str, object]] = []
            msg_items = cast("list[object]", messages_export_raw)
            for msg_item in msg_items:
                if isinstance(msg_item, dict):
                    messages_export.append(cast("dict[str, object]", msg_item))
                elif hasattr(msg_item, "__dict__"):
                    messages_export.append(cast("dict[str, object]", msg_item.__dict__))
            export_data["messages"] = messages_export

        if "tool_states" in session_data:
            export_data["tool_states"] = session_data["tool_states"]

        if "patches" in session_data:
            export_data["patches"] = session_data["patches"]

        return export_data

    def _import_session(self) -> None:
        """Import session from file.

        When a session manager is available, the import is routed through
        ``SessionManager.import_json`` so the imported session lands in the
        backing ``SessionStore``. Without a manager, the legacy disk-sidecar
        fallback is used.
        """
        path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Import Session",
            "",
            "JSON Files (*.json);;All Files (*)",
        )

        if not path_str:
            return

        path = Path(path_str)

        if self._manager is not None:
            self._import_via_manager(path)
        else:
            self._import_to_disk(path)

    def _import_via_manager(self, path: Path) -> None:
        """Import a session JSON file through the session manager.

        Handles duplicate-ID prompts, malformed JSON, missing files and
        manager-level errors with user-facing dialogs.

        Args:
            path: Path to the session JSON file to import.
        """
        manager = self._manager
        if manager is None:
            return

        valid, import_id = self._peek_session_id(path)
        if not valid:
            return

        replace = False
        if import_id is not None and self._session_id_exists(import_id):
            if not self._confirm_replace(import_id):
                return
            replace = True

        try:
            run_bridge_coroutine(manager.import_json(path, replace=replace))
        except FileNotFoundError as e:
            self._report_import_error(
                path,
                e,
                event="session_import_file_missing",
                title="Import Failed",
                message=f"File not found:\n{path}",
            )
            return
        except ValueError as e:
            self._report_import_error(
                path,
                e,
                event="session_import_invalid",
                title="Import Failed",
                message=f"Invalid session file:\n{e}",
            )
            return
        except (OSError, RuntimeError) as e:
            _logger.exception("session_import_failed", path=str(path))
            QMessageBox.warning(self, "Import Failed", f"Failed to import session:\n{e}")
            return

        _logger.debug("session_imported", session_id=import_id, path=str(path))
        QMessageBox.information(self, "Import Complete", f"Session imported from:\n{path}")
        self._load_sessions()

    def _session_id_exists(self, session_id: str) -> bool:
        """Check whether a session ID is already present in the listed sessions.

        Args:
            session_id: Candidate session identifier.

        Returns:
            bool: True if the ID already exists in ``self._sessions``.
        """
        return any(s["id"] == session_id for s in self._sessions)

    def _confirm_replace(self, session_id: str) -> bool:
        """Prompt the user to confirm replacement of an existing session.

        Args:
            session_id: Identifier of the conflicting session.

        Returns:
            bool: True if the user confirmed replacement.
        """
        reply = QMessageBox.question(
            self,
            "Session Exists",
            f"A session with ID '{session_id}' already exists.\n\nDo you want to replace it?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _report_import_error(self, path: Path, error: BaseException, *, event: str, title: str, message: str) -> None:
        """Log an import failure and show a warning dialog to the user.

        Args:
            path: Path that was being imported.
            error: Exception that was raised.
            event: Structured-logging event name.
            title: Dialog title.
            message: Dialog body text.
        """
        _logger.warning(event, path=str(path), error=str(error))
        QMessageBox.warning(self, title, message)

    def _peek_session_id(self, path: Path) -> tuple[bool, str | None]:
        """Peek at a session JSON file to extract its session identifier.

        Handles both wrapped (``{"session": {...}}``) and unwrapped top-level
        session forms consistent with ``SessionStore.import_from_json``.

        Args:
            path: Path to the session JSON file.

        Returns:
            tuple[bool, str | None]: ``(True, session_id)`` when the file is
                valid and a string ID could be extracted, ``(True, None)``
                when the file is valid but has no recognizable ID, and
                ``(False, None)`` when the file is missing or malformed. In
                the ``False`` case, a user-facing error dialog has already
                been shown.
        """
        try:
            with path.open(encoding="utf-8") as f:
                raw_data: object = json.load(f)
        except FileNotFoundError as e:
            self._report_import_error(
                path,
                e,
                event="session_import_file_missing",
                title="Import Failed",
                message=f"File not found:\n{path}",
            )
            return False, None
        except json.JSONDecodeError as e:
            self._report_import_error(
                path,
                e,
                event="session_import_json_invalid",
                title="Import Failed",
                message=f"Invalid JSON file:\n{e}",
            )
            return False, None
        except OSError as e:
            self._report_import_error(
                path,
                e,
                event="session_import_read_failed",
                title="Import Failed",
                message=f"Failed to read file:\n{e}",
            )
            return False, None

        if not isinstance(raw_data, dict):
            QMessageBox.warning(self, "Import Failed", "Invalid session file format.")
            return False, None

        outer = cast("dict[str, object]", raw_data)
        inner_raw = outer.get("session", outer)
        if not isinstance(inner_raw, dict):
            return True, None

        inner = cast("dict[str, object]", inner_raw)
        id_val = inner.get("id")
        return True, (id_val if isinstance(id_val, str) else None)

    def _import_to_disk(self, path: Path) -> None:
        """Import a session JSON file into the on-disk sidecar store.

        This fallback is only used when no session manager has been wired
        into the dialog; it preserves the sidecar JSON purely as an
        export-compatible artifact for non-managed instances.

        Args:
            path: Path to the session JSON file to import.
        """
        try:
            with path.open(encoding="utf-8") as f:
                raw_data: object = json.load(f)
        except json.JSONDecodeError as e:
            self._report_import_error(path, e, event="session_import_failed", title="Import Failed", message=f"Invalid JSON file:\n{e}")
            return
        except OSError as e:
            self._report_import_error(path, e, event="session_import_failed", title="Import Failed", message=f"Failed to read file:\n{e}")
            return

        if not isinstance(raw_data, dict):
            QMessageBox.warning(self, "Import Failed", "Invalid session file format.")
            return

        import_data = cast("dict[str, object]", raw_data)

        required_fields = {"id", "name"}
        if not required_fields.issubset(import_data.keys()):
            import_data["id"] = path.stem
            import_data["name"] = path.stem

        candidate_id = import_data["id"]
        if isinstance(candidate_id, str) and self._session_id_exists(candidate_id) and not self._confirm_replace(candidate_id):
            return

        import_data["imported_at"] = datetime.now(tz=UTC).isoformat()

        try:
            self._save_session_to_disk(import_data)
        except OSError as e:
            self._report_import_error(
                path,
                e,
                event="session_import_failed",
                title="Import Failed",
                message=f"Failed to write session file:\n{e}",
            )
            return

        _logger.debug("session_imported", session_id=import_data.get("id"), path=str(path))
        QMessageBox.information(self, "Import Complete", f"Session imported from:\n{path}")
        self._load_sessions()

    def _save_session_to_disk(self, session_data: dict[str, object]) -> None:
        """Save session data to disk.

        Args:
            session_data: Session data to save.
        """
        self.SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

        session_id = session_data.get("id", datetime.now(tz=UTC).strftime("%Y%m%d_%H%M%S"))
        session_file = self.SESSIONS_DIR / f"{session_id}.json"

        with session_file.open("w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, default=str)

        _logger.debug(
            "session_saved_to_disk",
            session_id=session_id,
            file=str(session_file),
        )

    def get_selected_session_id(self) -> str | None:
        """Get the ID of the currently selected session.

        Returns:
            str | None: Selected session ID or None.
        """
        sel_model = self._session_table.selectionModel()
        if sel_model is not None and (selected_rows := sel_model.selectedRows()):
            row = selected_rows[0].row()
            item = self._session_table.item(row, 0)
            if item is not None:
                session_id: str | None = item.data(Qt.ItemDataRole.UserRole)
                return session_id
        return None


class NewSessionDialog(QDialog):
    """Dialog for creating a new session.

    Allows users to specify session name and initial settings.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        """Initialize the NewSessionDialog.

        Args:
            parent: Parent widget.
        """
        super().__init__(parent)

        self._setup_ui()

        self.setWindowTitle("New Session")
        self.resize(_CONFIRM_DIALOG_WIDTH, _CONFIRM_DIALOG_HEIGHT)

    def _setup_ui(self) -> None:
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        form_layout = QFormLayout()

        self._name_input = QLineEdit()
        self._name_input.setText(f"Session {datetime.now(tz=UTC).strftime('%Y-%m-%d %H:%M')}")
        form_layout.addRow("Session Name:", self._name_input)

        self._description_input = QLineEdit()
        form_layout.addRow("Description:", self._description_input)

        layout.addLayout(form_layout)
        layout.addStretch()

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._on_accepted)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_accepted(self) -> None:
        """Handle dialog acceptance and log session creation."""
        session_name = self.get_session_name()
        _logger.info("session_created", session_id=session_name)
        self.accept()

    def get_session_name(self) -> str:
        """Get the entered session name.

        Returns:
            str: Session name.
        """
        return str(self._name_input.text()).strip()

    def get_description(self) -> str:
        """Get the entered description.

        Returns:
            str: Session description.
        """
        return str(self._description_input.text()).strip()
